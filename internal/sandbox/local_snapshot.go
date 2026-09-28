// Package sandbox: Local backend skill snapshots.
//
// A Local "snapshot" is a full copy of a session's rootfs directory tree,
// stored under <LocalRootfsBase>/snapshots/<lsnap-hex>/. The skill install
// path runs its maintenance commands inside the session sandbox, takes a
// snapshot when done, and later sessions boot FROM the snapshot instead of
// the pristine template — the same lifecycle Cube/E2B/Docker follow with
// their provider-side images.
//
// Directory-tree copies (not tars) keep the whole mechanism mount-free and
// stdlib-only, matching the backend's constraints. A fresh session sandbox
// is ~150MB on the container's local disk, so CreateSnapshot costs one cp
// (~1-2s); snapshots live under their own prefix, so the orphan sweep for
// session directories (lsbx-) never touches them — snapshot lifetime is
// owned by the skill install/remove flow.
package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// localSnapshotIDPrefix marks a Local skill snapshot directory under
// <base>/snapshots/. Distinct from the session prefix (lsbx-) so a template
// ID always reveals whether it names a snapshot or the pristine template.
const localSnapshotIDPrefix = "lsnap-"

// localSnapshotsDirName is the subdirectory of the rootfs base that holds
// skill snapshots.
const localSnapshotsDirName = "snapshots"

// snapshotsDir resolves the snapshots directory (created on demand).
func (c *LocalRemoteClient) snapshotsDir() string {
	return filepath.Join(c.mustRootfsPath(), localSnapshotsDirName)
}

// snapshotDir returns the directory for one snapshot id.
func (c *LocalRemoteClient) snapshotDir(snapshotID string) string {
	return filepath.Join(c.snapshotsDir(), snapshotID)
}

// newLocalSnapshotID returns a fresh "lsnap-<hex>" identifier.
func newLocalSnapshotID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return localSnapshotIDPrefix + hex.EncodeToString(buf), nil
}

// validLocalSnapshotID guards the snapshot id against traversal through a
// crafted template id: only our own generation format passes.
func validLocalSnapshotID(id string) bool {
	if !strings.HasPrefix(id, localSnapshotIDPrefix) {
		return false
	}
	rest := strings.TrimPrefix(id, localSnapshotIDPrefix)
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

// isLocalSnapshotTemplateID reports whether a RemoteCreateRequest.TemplateID
// names a Local snapshot rather than the pristine template.
func isLocalSnapshotTemplateID(templateID string) bool {
	return strings.HasPrefix(templateID, localSnapshotIDPrefix)
}

// CreateSnapshot copies the session sandbox's rootfs into a new snapshot
// directory. The source sandbox itself is untouched: the skill flow pauses
// nothing for Local (there is no billing to pause), and concurrent execution
// during the copy would at worst yield a slightly torn file inside the
// snapshot — the install path serialises against chat turns anyway.
func (c *LocalRemoteClient) CreateSnapshot(
	ctx context.Context,
	sandboxID string,
	name string,
) (RemoteSnapshotRef, error) {
	handle, err := c.loadHandle(sandboxID)
	if err != nil {
		return RemoteSnapshotRef{}, err
	}
	id, err := newLocalSnapshotID()
	if err != nil {
		return RemoteSnapshotRef{}, localErrWrapped("CreateSnapshot", RemoteErrorKindInternal, err,
			"generate snapshot id")
	}
	dir := c.snapshotDir(id)
	if err := os.MkdirAll(c.snapshotsDir(), 0o755); err != nil {
		return RemoteSnapshotRef{}, localErrWrapped("CreateSnapshot", RemoteErrorKindInternal, err,
			"create snapshots dir")
	}
	if err := copyTree(handle.rootfs, dir); err != nil {
		_ = os.RemoveAll(dir)
		return RemoteSnapshotRef{}, localErrWrapped("CreateSnapshot", RemoteErrorKindInternal, err,
			"copy session rootfs %s into snapshot", handle.rootfs)
	}
	names := []string{}
	if strings.TrimSpace(name) != "" {
		names = append(names, name)
	}
	return RemoteSnapshotRef{ID: id, Names: names}, nil
}

// DeleteSnapshot removes a snapshot directory. A missing snapshot is NOT an
// error — the interface contract treats delete as idempotent.
func (c *LocalRemoteClient) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	if !validLocalSnapshotID(snapshotID) {
		return localErr("DeleteSnapshot", RemoteErrorKindInvalidRequest,
			"malformed snapshot id %q", snapshotID)
	}
	dir := c.snapshotDir(snapshotID)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return localErrWrapped("DeleteSnapshot", RemoteErrorKindInternal, err, "remove %s", dir)
	}
	return nil
}

// ListSnapshots enumerates snapshot directories. An empty sandboxID lists
// all of them; Local ignores the filter (snapshots are not per-sandbox
// addressable beyond their id).
func (c *LocalRemoteClient) ListSnapshots(
	ctx context.Context,
	sandboxID string,
) ([]RemoteSnapshotRef, error) {
	entries, err := os.ReadDir(c.snapshotsDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, localErrWrapped("ListSnapshots", RemoteErrorKindInternal, err,
			"read %s", c.snapshotsDir())
	}
	refs := make([]RemoteSnapshotRef, 0)
	for _, entry := range entries {
		if !entry.IsDir() || !validLocalSnapshotID(entry.Name()) {
			continue
		}
		refs = append(refs, RemoteSnapshotRef{ID: entry.Name()})
	}
	return refs, nil
}

// resolveSnapshotSource maps a Create TemplateID onto the directory the new
// sandbox rootfs is copied from: the pristine template, or a skill snapshot.
func (c *LocalRemoteClient) resolveSnapshotSource(templateID string) (string, error) {
	if !isLocalSnapshotTemplateID(templateID) {
		return c.cfg.LocalTemplatePath, nil
	}
	if !validLocalSnapshotID(templateID) {
		return "", localErr("Create", RemoteErrorKindInvalidRequest,
			"malformed snapshot id %q", templateID)
	}
	dir := c.snapshotDir(templateID)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return "", localErr("Create", RemoteErrorKindNotFound, "snapshot %s not found", templateID)
	}
	return dir, nil
}
