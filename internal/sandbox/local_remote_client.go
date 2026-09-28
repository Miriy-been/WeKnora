// Package sandbox: provider-neutral Local backend.
//
// LocalRemoteClient implements RemoteSandboxClient with zero external
// runtimes. One "sandbox" is a directory tree materialised from the image-
// baked template (/sandbox-rootfs) on local disk; execution runs inside a
// user-namespace + chroot jail driven entirely by os/exec SysProcAttr (see
// local_exec_linux.go for the Linux core and local_exec_other.go for the
// compile-time stub).
//
// State semantics match the other session-scoped backends: a sandbox is its
// rootfs directory. Create copies the template, Connect finds the directory,
// Delete removes it, and every file API maps sandbox paths onto that
// directory from the host side — no round trip into the jail is needed
// because the files are ordinary host files.
//
// What Local deliberately does NOT do:
//
//   - Networking: every sandbox gets an empty network namespace. There is no
//     toggle; sharing the host stack would erase the isolation the backend
//     exists to provide.
//   - Snapshots and volume mounts: unsupported, so skill installs fall back
//     to the base template behaviour via SnapshotManagerFrom.
//   - Desktop and interactive terminals: unsupported (no envd/PTY daemon
//     inside the jail).
package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// localSandboxIDPrefix marks a Local sandbox rootfs directory. List and the
// orphan sweep only consider directories carrying it, so a stray user file in
// the base directory can never be mistaken for a sandbox.
const localSandboxIDPrefix = "lsbx-"

// localMetadataFile sits at the rootfs root and records creation facts.
const localMetadataFile = "weknora-sandbox.json"

// LocalSandboxHandle is the provider-issued reference to one materialised
// rootfs. It is safe to hold across executions: the directory, not a network
// endpoint, is the state.
type LocalSandboxHandle struct {
	id         string
	rootfs     string
	templateID string
	metadata   map[string]string
	env        map[string]string
}

func (h *LocalSandboxHandle) ID() string                     { return h.id }
func (h *LocalSandboxHandle) Provider() RemoteProvider       { return SandboxTypeLocal }
func (h *LocalSandboxHandle) Metadata() map[string]string    { return h.metadata }
func (h *LocalSandboxHandle) Rootfs() string                 { return h.rootfs }
func (h *LocalSandboxHandle) Env() map[string]string         { return h.env }
func (h *LocalSandboxHandle) TemplateID() string             { return h.templateID }

// LocalRemoteClient is constructed per resolve, mirroring the other adapters.
type LocalRemoteClient struct {
	cfg *Config
}

// NewLocalRemoteClient builds the Local adapter. The config is filled with
// built-in defaults here as well as on the resolve path: throwaway clients
// (the connectivity probe) may arrive without having gone through
// ResolveEffectiveConfig's default switch.
func NewLocalRemoteClient(cfg *Config) (*LocalRemoteClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("sandbox/local: config is required")
	}
	if err := EnsureLocalBackendAllowed(cfg.Type); err != nil {
		return nil, err
	}
	applyLocalRuntimeDefaults(cfg)
	if !cfg.LocalAllowNetwork {
		// Unconditionally force the offline contract, even on a hand-built
		// config that skipped ResolveEffectiveConfig. A nil-check here would
		// leak through: the resolver materialises AllowInternetAccess=&true by
		// default, and the jail has no network stack to grant regardless —
		// DeniesEgressByDefault and the deep connectivity probe read this
		// field. With AllowNetwork the admin opted out of the jail, so the
		// stored policy stands and the egress probe runs for real.
		offline := false
		public := false
		cfg.Network.AllowInternetAccess = &offline
		cfg.Network.AllowPublicTraffic = &public
	}
	// The sweep is cooldown-guarded at package level, so calling it on every
	// construction is cheap and self-heals unreferenced session directories.
	client := &LocalRemoteClient{cfg: cfg}
	if base, err := client.rootfsPath(); err == nil {
		maybeSweepLocalOrphans(base, LocalOrphanSandboxTTL)
	}
	return client, nil
}

func localErr(op string, kind RemoteErrorKind, format string, args ...any) error {
	return NewRemoteError(SandboxTypeLocal, op, kind, fmt.Sprintf(format, args...), nil)
}

func localErrWrapped(op string, kind RemoteErrorKind, cause error, format string, args ...any) error {
	return NewRemoteError(SandboxTypeLocal, op, kind, fmt.Sprintf(format, args...), cause)
}

// Provider identifies the backend.
func (c *LocalRemoteClient) Provider() RemoteProvider { return SandboxTypeLocal }

// Capabilities advertises what this client supports natively. Reconnect is
// inherent (the directory is the state); pause/resume and timeout refresh are
// not — Delete is the only reclamation, guarded by the orphan sweep.
// Snapshots are directory-tree copies (see local_snapshot.go), which is what
// makes the skill install/remove flow a first-class citizen here.
func (c *LocalRemoteClient) Capabilities() RemoteSandboxCapabilities {
	return RemoteSandboxCapabilities{
		SupportsReconnect:      true,
		SupportsMetadata:       true,
		SupportsListSandboxes:  true,
		SupportsSnapshots:      true,
	}
}

// Health verifies the backend can actually run: the template rootfs must
// exist with a working /bin/sh, and the kernel must still allow unprivileged
// user namespaces. It is deliberately cheap — a real probe happens at first
// Exec, and SessionBoundManager calls Health on every resolve.
func (c *LocalRemoteClient) Health(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return localErr("Health", RemoteErrorKindTimeout, "context cancelled before probe")
	default:
	}
	template := c.cfg.LocalTemplatePath
	if fi, err := os.Stat(filepath.Join(template, "bin", "sh")); err != nil || fi.IsDir() {
		return localErr("Health", RemoteErrorKindUnavailable,
			"local template %s is missing a /bin/sh — the image build must create /sandbox-rootfs", template)
	}
	if err := checkUserNamespaceSupport(); err != nil {
		return localErrWrapped("Health", RemoteErrorKindUnavailable, err,
			"kernel does not allow unprivileged user namespaces")
	}
	return nil
}

// --- lifecycle ---

// localCreateRecord is the metadata.json payload persisted at the rootfs root.
type localCreateRecord struct {
	ID        string            `json:"id"`
	Template  string            `json:"template"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	CreatedAt string            `json:"created_at"`
}

// Create materialises a session sandbox: copy the template, record the
// metadata, return the handle. Volume mounts are refused — Local has no
// mount machinery by design.
func (c *LocalRemoteClient) Create(
	ctx context.Context,
	req RemoteCreateRequest,
) (RemoteSandboxHandle, error) {
	if len(req.VolumeMounts) > 0 {
		return nil, localErr("Create", RemoteErrorKindUnsupported,
			"local backend does not support volume mounts")
	}
	if len(req.Metadata) > 0 && !c.Capabilities().SupportsMetadata {
		return nil, localErr("Create", RemoteErrorKindUnsupported, "metadata not supported")
	}

	rootfs, err := c.rootfsPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return nil, localErrWrapped("Create", RemoteErrorKindInternal, err,
			"create sandbox base %s", rootfs)
	}

	id, err := newLocalSandboxID()
	if err != nil {
		return nil, localErrWrapped("Create", RemoteErrorKindInternal, err, "generate sandbox id")
	}
	dir := filepath.Join(rootfs, id)
	// The template is either the pristine /sandbox-rootfs or, when the skill
	// flow boots a session from an installed-skills image, a snapshot copy.
	srcDir, err := c.resolveSnapshotSource(req.TemplateID)
	if err != nil {
		return nil, err
	}
	if err := copyTree(srcDir, dir); err != nil {
		_ = os.RemoveAll(dir)
		return nil, localErrWrapped("Create", RemoteErrorKindInternal, err,
			"materialise rootfs from %s", srcDir)
	}

	record := localCreateRecord{
		ID:        id,
		Template:  req.TemplateID,
		Metadata:  cloneMetadata(req.Metadata),
		Env:       cloneMetadata(req.EnvVars),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	blob, err := json.Marshal(record)
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, localMetadataFile), blob, 0o644)
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, localErrWrapped("Create", RemoteErrorKindInternal, err, "write sandbox metadata")
	}
	return &LocalSandboxHandle{
		id:         id,
		rootfs:     dir,
		templateID: req.TemplateID,
		metadata:   record.Metadata,
		env:        record.Env,
	}, nil
}

// Connect re-attaches to an existing rootfs. The binding store holds the id
// across WeKnora restarts; as long as the directory survived the restart the
// sandbox is fully operable, otherwise it classifies as NotFound so the
// coordinator can re-provision.
func (c *LocalRemoteClient) Connect(
	ctx context.Context,
	req RemoteConnectRequest,
) (RemoteSandboxHandle, error) {
	handle, err := c.loadHandle(req.SandboxID)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

// Get returns the lifecycle summary for one sandbox.
func (c *LocalRemoteClient) Get(ctx context.Context, sandboxID string) (*RemoteSandboxSummary, error) {
	handle, err := c.loadHandle(sandboxID)
	if err != nil {
		return nil, err
	}
	return c.summaryOf(handle), nil
}

// List enumerates materialised sandboxes under the base directory. Metadata
// and state filters apply client-side, matching the RemoteListFilter contract.
func (c *LocalRemoteClient) List(
	ctx context.Context,
	filter RemoteListFilter,
) ([]RemoteSandboxSummary, error) {
	rootfs, err := c.rootfsPath()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(rootfs)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, localErrWrapped("List", RemoteErrorKindInternal, err, "read %s", rootfs)
	}
	summaries := make([]RemoteSandboxSummary, 0)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), localSandboxIDPrefix) {
			continue
		}
		handle, err := c.loadHandle(entry.Name())
		if err != nil {
			continue
		}
		summary := c.summaryOf(handle)
		if !localFilterMatches(filter, summary) {
			continue
		}
		summaries = append(summaries, *summary)
	}
	return summaries, nil
}

// Delete removes the sandbox rootfs. Deleting an unknown id is NotFound —
// callers treat that as success, mirroring every other adapter.
func (c *LocalRemoteClient) Delete(ctx context.Context, sandboxID string) error {
	if !validLocalSandboxID(sandboxID) {
		return localErr("Delete", RemoteErrorKindInvalidRequest, "malformed sandbox id %q", sandboxID)
	}
	dir := filepath.Join(c.mustRootfsPath(), sandboxID)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return localErr("Delete", RemoteErrorKindNotFound, "sandbox %s not found", sandboxID)
	}
	if err := os.RemoveAll(dir); err != nil {
		return localErrWrapped("Delete", RemoteErrorKindInternal, err, "remove %s", dir)
	}
	return nil
}

// --- filesystem ---
//
// All five operations map sandbox paths onto the host rootfs directly. There
// is no in-jail agent to talk to: the files are ordinary host files, and the
// exec jail already constrains what the sandboxed process can touch.

// WriteFile creates path including parents; overwriting an existing file is
// the normal script-upload flow.
func (c *LocalRemoteClient) WriteFile(
	ctx context.Context,
	handle RemoteSandboxHandle,
	path string,
	content []byte,
) error {
	if _, target, err := c.resolveInside(handle, "WriteFile", path); err != nil {
		return err
	} else if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return localErrWrapped("WriteFile", RemoteErrorKindInternal, err,
			"create parent dirs for %s", path)
	} else if err := os.WriteFile(target, content, 0o644); err != nil {
		return localErrWrapped("WriteFile", RemoteErrorKindInternal, err, "write %s", path)
	}
	return nil
}

// ReadFile reads a file back out of the sandbox.
func (c *LocalRemoteClient) ReadFile(
	ctx context.Context,
	handle RemoteSandboxHandle,
	path string,
) ([]byte, error) {
	_, target, err := c.resolveInside(handle, "ReadFile", path)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(target)
	if os.IsNotExist(err) {
		return nil, localErr("ReadFile", RemoteErrorKindNotFound, "%s not found", path)
	}
	if err != nil {
		return nil, localErrWrapped("ReadFile", RemoteErrorKindInternal, err, "read %s", path)
	}
	return content, nil
}

// ListDir lists one directory level, matching the Docker adapter's
// find -maxdepth 1 contract. Recursion is the caller's concern.
func (c *LocalRemoteClient) ListDir(
	ctx context.Context,
	handle RemoteSandboxHandle,
	dirPath string,
) ([]RemoteDirEntry, error) {
	_, target, err := c.resolveInside(handle, "ListDir", dirPath)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(target)
	if os.IsNotExist(err) {
		return nil, localErr("ListDir", RemoteErrorKindNotFound, "%s not found", dirPath)
	}
	if err != nil {
		return nil, localErrWrapped("ListDir", RemoteErrorKindInternal, err, "list %s", dirPath)
	}
	result := make([]RemoteDirEntry, 0, len(entries))
	for _, entry := range entries {
		info, ierr := entry.Info()
		if ierr != nil {
			continue
		}
		kind := RemoteEntryOther
		switch {
		case info.IsDir():
			kind = RemoteEntryDir
		case info.Mode().IsRegular():
			kind = RemoteEntryFile
		}
		result = append(result, RemoteDirEntry{
			Name:    entry.Name(),
			Path:    joinLocalSandboxPath(dirPath, entry.Name()),
			Type:    kind,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	return result, nil
}

// MakeDir creates path including parents. An existing directory is success —
// the interface contract demands mkdir -p semantics even though envd's
// MakeDir is stricter.
func (c *LocalRemoteClient) MakeDir(
	ctx context.Context,
	handle RemoteSandboxHandle,
	path string,
) error {
	_, target, err := c.resolveInside(handle, "MakeDir", path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0o755); err != nil && !os.IsExist(err) {
		return localErrWrapped("MakeDir", RemoteErrorKindInternal, err, "mkdir %s", path)
	}
	return nil
}

// Remove deletes a file or directory tree inside the sandbox.
func (c *LocalRemoteClient) Remove(
	ctx context.Context,
	handle RemoteSandboxHandle,
	path string,
) error {
	_, target, err := c.resolveInside(handle, "Remove", path)
	if err != nil {
		return err
	}
	if _, serr := os.Lstat(target); os.IsNotExist(serr) {
		return localErr("Remove", RemoteErrorKindNotFound, "%s not found", path)
	}
	if err := os.RemoveAll(target); err != nil {
		return localErrWrapped("Remove", RemoteErrorKindInternal, err, "remove %s", path)
	}
	return nil
}

// Stat returns metadata for one path.
func (c *LocalRemoteClient) Stat(
	ctx context.Context,
	handle RemoteSandboxHandle,
	path string,
) (*RemoteStatEntry, error) {
	_, target, err := c.resolveInside(handle, "Stat", path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(target)
	if os.IsNotExist(err) {
		return nil, localErr("Stat", RemoteErrorKindNotFound, "%s not found", path)
	}
	if err != nil {
		return nil, localErrWrapped("Stat", RemoteErrorKindInternal, err, "stat %s", path)
	}
	kind := RemoteEntryOther
	switch {
	case info.IsDir():
		kind = RemoteEntryDir
	case info.Mode().IsRegular():
		kind = RemoteEntryFile
	}
	return &RemoteStatEntry{
		Path:    path,
		Type:    kind,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}, nil
}

// --- internals ---

// rootfsPath resolves (and does not create) the sandbox base directory.
func (c *LocalRemoteClient) rootfsPath() (string, error) {
	base := strings.TrimSpace(c.cfg.LocalRootfsBase)
	if base == "" {
		return "", localErr("resolve", RemoteErrorKindInternal, "local rootfs base is empty")
	}
	return base, nil
}

func (c *LocalRemoteClient) mustRootfsPath() string {
	base, _ := c.rootfsPath()
	return base
}

// loadHandle rebuilds a handle from a persisted sandbox id.
func (c *LocalRemoteClient) loadHandle(sandboxID string) (*LocalSandboxHandle, error) {
	if !validLocalSandboxID(sandboxID) {
		return nil, localErr("load", RemoteErrorKindInvalidRequest, "malformed sandbox id %q", sandboxID)
	}
	dir := filepath.Join(c.mustRootfsPath(), sandboxID)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, localErr("load", RemoteErrorKindNotFound, "sandbox %s not found", sandboxID)
	}
	handle := &LocalSandboxHandle{id: sandboxID, rootfs: dir}
	blob, err := os.ReadFile(filepath.Join(dir, localMetadataFile))
	if err == nil {
		var record localCreateRecord
		if json.Unmarshal(blob, &record) == nil {
			handle.templateID = record.Template
			handle.metadata = record.Metadata
			handle.env = record.Env
		}
	}
	return handle, nil
}

func (c *LocalRemoteClient) summaryOf(handle *LocalSandboxHandle) *RemoteSandboxSummary {
	summary := &RemoteSandboxSummary{
		ID:         handle.id,
		TemplateID: handle.templateID,
		State:      RemoteStateRunning,
		RawState:   "materialised",
		Metadata:   handle.metadata,
	}
	if fi, err := os.Stat(filepath.Join(handle.rootfs, localMetadataFile)); err == nil {
		summary.StartedAt = fi.ModTime()
	}
	return summary
}

// resolveInside maps a sandbox-absolute path onto the host rootfs. Paths
// containing any ".." component are refused outright (before Clean can
// silently collapse them), so the result can never escape the rootfs prefix.
func (c *LocalRemoteClient) resolveInside(
	handle RemoteSandboxHandle,
	op string,
	path string,
) (root string, target string, err error) {
	local, ok := handle.(*LocalSandboxHandle)
	if !ok || handle == nil {
		return "", "", localErr(op, RemoteErrorKindInvalidRequest, "non-local handle")
	}
	if local.rootfs == "" {
		return "", "", localErr(op, RemoteErrorKindInvalidRequest, "handle has no rootfs")
	}
	// Component-level traversal check BEFORE Clean: filepath.Clean silently
	// collapses "/../x" onto "/x", so a Clean-based check would silently
	// accept (and rewrite) escape attempts instead of refusing them.
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return "", "", localErr(op, RemoteErrorKindInvalidRequest,
				"path %q escapes the sandbox", path)
		}
	}
	clean := filepath.Clean("/" + strings.TrimPrefix(filepath.ToSlash(path), "/"))
	return local.rootfs, filepath.Join(local.rootfs, clean), nil
}

// newLocalSandboxID returns a fresh "lsbx-<hex>" identifier.
func newLocalSandboxID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return localSandboxIDPrefix + hex.EncodeToString(buf), nil
}

// validLocalSandboxID guards Delete/Connect/List against traversal through a
// crafted id: only our own generation format passes.
func validLocalSandboxID(id string) bool {
	if !strings.HasPrefix(id, localSandboxIDPrefix) {
		return false
	}
	rest := strings.TrimPrefix(id, localSandboxIDPrefix)
	if len(rest) != 32 {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// localFilterMatches applies the RemoteListFilter client-side.
func localFilterMatches(filter RemoteListFilter, summary *RemoteSandboxSummary) bool {
	if len(filter.Metadata) > 0 {
		for key, want := range filter.Metadata {
			if summary.Metadata[key] != want {
				return false
			}
		}
	}
	if len(filter.States) > 0 {
		found := false
		for _, state := range filter.States {
			if state == summary.State {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// joinLocalSandboxPath builds the sandbox-absolute path reported in listings.
func joinLocalSandboxPath(dir, name string) string {
	if strings.HasSuffix(dir, "/") {
		return dir + name
	}
	return dir + "/" + name
}

// copyTree deep-copies src into dst, preserving directories, regular files,
// permissions and symlinks. Symlink targets are copied verbatim — relative
// links stay relative inside the new root, and absolute links keep pointing
// at the same chroot-internal paths. This is the mount-free substitute for
// the overlay the jail cannot build.
func copyTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	return copyEntry(src, dst, info)
}

func copyEntry(src, dst string, info os.FileInfo) error {
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(src)
		if err != nil {
			return fmt.Errorf("readlink %s: %w", src, err)
		}
		if err := os.Symlink(target, dst); err != nil && !os.IsExist(err) {
			return fmt.Errorf("symlink %s: %w", dst, err)
		}
		return nil
	case info.IsDir():
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return fmt.Errorf("mkdir %s: %w", dst, err)
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return fmt.Errorf("readdir %s: %w", src, err)
		}
		for _, entry := range entries {
			childSrc := filepath.Join(src, entry.Name())
			childDst := filepath.Join(dst, entry.Name())
			childInfo, err := os.Lstat(childSrc)
			if err != nil {
				return fmt.Errorf("lstat %s: %w", childSrc, err)
			}
			if err := copyEntry(childSrc, childDst, childInfo); err != nil {
				return err
			}
		}
		return nil
	case info.Mode().IsRegular():
		if err := copyFileContents(src, dst, info.Mode().Perm()); err != nil {
			return err
		}
		return nil
	default:
		// Devices, sockets, fifos: the template build creates its own static
		// /dev, so there is nothing legitimate to copy here. Skipping keeps
		// the copier portable.
		return nil
	}
}

func copyFileContents(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}

// --- orphan sweep ---
//
// Managers are built per request, so a per-client goroutine would leak. One
// package-level sweep runs at most once per cooldown, on the first client
// construction after the window elapses.

var (
	localSweepMu      sync.Mutex
	localSweepLastRun time.Time
)

const localSweepCooldown = time.Hour

// maybeSweepLocalOrphans removes sandbox directories whose rootfs mtime is
// older than LocalOrphanSandboxTTL. The rootfs mtime doubles as a last-use
// marker: every Exec and file write touches something inside it.
func maybeSweepLocalOrphans(base string, ttl time.Duration) {
	localSweepMu.Lock()
	if time.Since(localSweepLastRun) < localSweepCooldown {
		localSweepMu.Unlock()
		return
	}
	localSweepLastRun = time.Now()
	localSweepMu.Unlock()

	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-ttl)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), localSandboxIDPrefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(base, entry.Name()))
	}
}

