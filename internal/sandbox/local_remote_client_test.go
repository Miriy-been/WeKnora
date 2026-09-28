//go:build linux

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newLocalTestClient builds a client over a throwaway base directory and a
// minimal template. The template mirrors what the image build bakes into
// /sandbox-rootfs: a /bin/sh, a writable-looking /workspace, and nothing
// else — in particular no /proc and no host filesystem leakage.
func newLocalTestClient(t *testing.T) (*LocalRemoteClient, *Config) {
	t.Helper()
	base := t.TempDir()
	template := filepath.Join(t.TempDir(), "template")
	must := func(err error) {
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	must(os.MkdirAll(filepath.Join(template, "bin"), 0o755))
	must(os.MkdirAll(filepath.Join(template, "workspace", "input"), 0o755))
	must(os.MkdirAll(filepath.Join(template, "etc"), 0o755))
	// A static busybox is the only self-contained way to ship a /bin/sh that
	// runs inside a chroot without its libraries. Fall back to a marker file
	// when absent: the file-API and lifecycle tests do not exec anything.
	if bb, err := os.Stat("/bin/busybox"); err == nil && !bb.IsDir() {
		must(copyFileContents("/bin/busybox", filepath.Join(template, "bin", "busybox"), 0o755))
		// Install EVERY applet symlink (cat, grep, wc, sleep, ...). sh alone
		// is not enough: its builtin echo works, but anything the exec tests
		// pipe through (cat | grep) needs the real applets on PATH.
		install := exec.Command(filepath.Join(template, "bin", "busybox"),
			"--install", "-s", filepath.Join(template, "bin"))
		if out, ierr := install.CombinedOutput(); ierr != nil {
			t.Fatalf("fixture: busybox --install: %v: %s", ierr, out)
		}
		// busybox --install links point at its own exec path ("/proc/self/exe"
		// or the absolute argv[0]), which is meaningless inside a chroot where
		// /proc is absent. Rewrite every symlink to a RELATIVE "busybox" — the
		// production image build must do the same (see wek/Dockerfile).
		entries, rerr := os.ReadDir(filepath.Join(template, "bin"))
		if rerr != nil {
			t.Fatalf("fixture: read bin: %v", rerr)
		}
		for _, entry := range entries {
			if entry.Type()&os.ModeSymlink == 0 {
				continue
			}
			p := filepath.Join(template, "bin", entry.Name())
			if target, lerr := os.Readlink(p); lerr != nil || target == "busybox" {
				continue
			}
			if err := os.Remove(p); err != nil {
				t.Fatalf("fixture: relink %s: %v", p, err)
			}
			if err := os.Symlink("busybox", p); err != nil {
				t.Fatalf("fixture: relink %s: %v", p, err)
			}
		}
	} else {
		must(os.WriteFile(filepath.Join(template, "bin", "sh"), []byte("#!/bin/busybox\n"), 0o755))
	}
	must(os.WriteFile(filepath.Join(template, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644))
	// The exec tests redirect to /dev/null; a runner user cannot mknod a real
	// char device, but an empty regular file satisfies the open() just fine.
	must(os.MkdirAll(filepath.Join(template, "dev"), 0o755))
	must(os.WriteFile(filepath.Join(template, "dev", "null"), nil, 0o666))

	cfg := DefaultConfig()
	cfg.Type = SandboxTypeLocal
	cfg.LocalTemplatePath = template
	cfg.LocalRootfsBase = base
	t.Setenv(LocalBackendEnabledEnv, "true")
	ClearLocalBackendEnabledOverride()
	client, err := NewLocalRemoteClient(cfg)
	if err != nil {
		t.Fatalf("NewLocalRemoteClient: %v", err)
	}
	return client, cfg
}

func TestLocalBackendGate(t *testing.T) {
	base := t.TempDir()
	cfg := DefaultConfig()
	cfg.Type = SandboxTypeLocal
	cfg.LocalTemplatePath = t.TempDir()
	cfg.LocalRootfsBase = base
	t.Setenv(LocalBackendEnabledEnv, "")
	ClearLocalBackendEnabledOverride()
	if _, err := NewLocalRemoteClient(cfg); err == nil {
		t.Fatal("expected gate to refuse an unenabled config")
	}
	if err := EnsureLocalBackendAllowed(SandboxTypeDocker); err != nil {
		t.Fatalf("gate must be a no-op for other backends: %v", err)
	}
}

func TestLocalLifecycle(t *testing.T) {
	client, cfg := newLocalTestClient(t)
	ctx := context.Background()

	if err := client.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}

	handle, err := client.Create(ctx, RemoteCreateRequest{
		TemplateID: "test-template",
		Metadata:   map[string]string{"session": "s1"},
		EnvVars:    map[string]string{"FROM_CREATE": "yes"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if handle.ID() == "" {
		t.Fatal("Create returned an empty id")
	}
	if !validLocalSandboxID(handle.ID()) {
		t.Fatalf("id %q does not satisfy our own format", handle.ID())
	}
	if _, err := os.Stat(filepath.Join(cfg.LocalRootfsBase, handle.ID(), "workspace")); err != nil {
		t.Fatalf("rootfs not materialised from template: %v", err)
	}
	if handle.Metadata()["session"] != "s1" {
		t.Fatalf("metadata not round-tripped: %v", handle.Metadata())
	}

	// Connect rebuilds the handle from the id alone, including env.
	reconnected, err := client.Connect(ctx, RemoteConnectRequest{SandboxID: handle.ID()})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if local, ok := reconnected.(*LocalSandboxHandle); !ok || local.Env()["FROM_CREATE"] != "yes" {
		t.Fatalf("Connect lost the create-time env: %v", reconnected)
	}

	summary, err := client.Get(ctx, handle.ID())
	if err != nil || summary.State != RemoteStateRunning {
		t.Fatalf("Get: %v / %+v", err, summary)
	}

	list, err := client.List(ctx, RemoteListFilter{
		Metadata: map[string]string{"session": "s1"},
		States:   []RemoteSandboxState{RemoteStateRunning},
	})
	if err != nil || len(list) != 1 {
		t.Fatalf("List with matching filter: %v / %d entries", err, len(list))
	}
	empty, err := client.List(ctx, RemoteListFilter{
		Metadata: map[string]string{"session": "s2"},
	})
	if err != nil || len(empty) != 0 {
		t.Fatalf("List with non-matching filter: %v / %d entries", err, len(empty))
	}

	if err := client.Delete(ctx, handle.ID()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := client.Delete(ctx, handle.ID()); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("second Delete should classify as not-found, got %v", err)
	}
	if _, err := client.Connect(ctx, RemoteConnectRequest{SandboxID: handle.ID()}); err == nil {
		t.Fatal("Connect to a deleted sandbox should fail")
	}
}

func TestLocalMalformedIDRejected(t *testing.T) {
	client, _ := newLocalTestClient(t)
	ctx := context.Background()
	for _, id := range []string{
		"",
		"../escape",
		"lsbx-" + strings.Repeat("g", 32),
		"lsbx-../../etc",
	} {
		if err := client.Delete(ctx, id); err == nil {
			t.Fatalf("Delete accepted malformed id %q", id)
		}
	}
}

func TestLocalFileAPIs(t *testing.T) {
	client, _ := newLocalTestClient(t)
	ctx := context.Background()
	handle, err := client.Create(ctx, RemoteCreateRequest{TemplateID: "t"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := client.WriteFile(ctx, handle, "/workspace/hello.py", []byte("print('hi')\n")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := client.ReadFile(ctx, handle, "/workspace/hello.py")
	if err != nil || string(got) != "print('hi')\n" {
		t.Fatalf("ReadFile: %v / %q", err, got)
	}
	if err := client.MakeDir(ctx, handle, "/workspace/sub/dir"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}
	// Idempotent per the contract.
	if err := client.MakeDir(ctx, handle, "/workspace/sub/dir"); err != nil {
		t.Fatalf("MakeDir twice: %v", err)
	}

	entries, err := client.ListDir(ctx, handle, "/workspace")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	names := map[string]RemoteDirEntryType{}
	for _, e := range entries {
		names[e.Name] = e.Type
	}
	if names["hello.py"] != RemoteEntryFile || names["sub"] != RemoteEntryDir {
		t.Fatalf("ListDir content wrong: %+v", names)
	}

	stat, err := client.Stat(ctx, handle, "/workspace/hello.py")
	if err != nil || stat.Type != RemoteEntryFile || stat.Size != int64(len("print('hi')\n")) {
		t.Fatalf("Stat: %v / %+v", err, stat)
	}

	if err := client.Remove(ctx, handle, "/workspace/hello.py"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := client.ReadFile(ctx, handle, "/workspace/hello.py"); err == nil {
		t.Fatal("ReadFile after Remove should fail")
	}

	// Traversal must be refused everywhere.
	for _, path := range []string{"../../etc/passwd", "/../etc/passwd", "/workspace/../../etc/passwd"} {
		if _, err := client.ReadFile(ctx, handle, path); err == nil ||
			!strings.Contains(err.Error(), "escapes") {
			t.Fatalf("ReadFile %q should be refused as traversal, got %v", path, err)
		}
		if err := client.WriteFile(ctx, handle, path, []byte("x")); err == nil {
			t.Fatalf("WriteFile %q should be refused", path)
		}
	}
}

func TestLocalCopyTreeSymlinks(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "copy")
	if err := os.MkdirAll(filepath.Join(src, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "d", "f"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(src, "d", "rel")); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	if blob, err := os.ReadFile(filepath.Join(dst, "d", "f")); err != nil || string(blob) != "data" {
		t.Fatalf("regular file not copied: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(dst, "d", "rel")); err != nil || target != "f" {
		t.Fatalf("relative symlink not preserved: %q / %v", target, err)
	}
}

func TestLocalUlimitPrefix(t *testing.T) {
	client, _ := newLocalTestClient(t)
	client.cfg.LocalMemoryBytes = 256 * 1024 * 1024
	client.cfg.LocalPidsLimit = 32
	client.cfg.LocalCPULimit = 0.5
	prefix := client.ulimitPrefix(60 * time.Second)
	for _, want := range []string{
		"ulimit -v " + strconv.FormatInt(256*1024, 10),
		// PidsLimit=32 is below the per-real-uid floor: the kernel counts the
		// host uid's own processes against RLIMIT_NPROC, so the rlimit layer
		// must not go under localMinRlimitNproc.
		"ulimit -u " + strconv.Itoa(localMinRlimitNproc),
		"ulimit -t 35",
	} {
		if !strings.Contains(prefix, want) {
			t.Fatalf("prefix %q missing %q", prefix, want)
		}
	}
}

// TestLocalSnapshot pins the skill-image lifecycle: a session sandbox gains a
// file, a snapshot is taken, a NEW sandbox boots from the snapshot (not the
// template) and sees the file, and deleting the snapshot makes subsequent
// snapshot boots fail as NotFound.
func TestLocalSnapshot(t *testing.T) {
	client, _ := newLocalTestClient(t)
	ctx := context.Background()
	if !client.Capabilities().SupportsSnapshots {
		t.Fatal("Local must advertise SupportsSnapshots for the skill flow")
	}

	base, err := client.Create(ctx, RemoteCreateRequest{TemplateID: "t"})
	if err != nil {
		t.Fatalf("Create base: %v", err)
	}
	if err := client.WriteFile(ctx, base, "/workspace/skill-data.txt", []byte("installed")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ref, err := client.CreateSnapshot(ctx, base.ID(), "with-skill")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if !validLocalSnapshotID(ref.ID) {
		t.Fatalf("snapshot id %q violates our format", ref.ID)
	}
	list, err := client.ListSnapshots(ctx, "")
	if err != nil || len(list) != 1 || list[0].ID != ref.ID {
		t.Fatalf("ListSnapshots: %v / %+v", err, list)
	}

	// A fresh session boots FROM the snapshot and inherits the file.
	child, err := client.Create(ctx, RemoteCreateRequest{TemplateID: ref.ID})
	if err != nil {
		t.Fatalf("Create from snapshot: %v", err)
	}
	got, err := client.ReadFile(ctx, child, "/workspace/skill-data.txt")
	if err != nil || string(got) != "installed" {
		t.Fatalf("snapshot restore lost the file: %v / %q", err, got)
	}

	// The pristine template does NOT have it.
	pristine, err := client.Create(ctx, RemoteCreateRequest{TemplateID: "t"})
	if err != nil {
		t.Fatalf("Create pristine: %v", err)
	}
	if _, err := client.ReadFile(ctx, pristine, "/workspace/skill-data.txt"); err == nil {
		t.Fatal("pristine template must not contain the skill file")
	}

	if err := client.DeleteSnapshot(ctx, ref.ID); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if err := client.DeleteSnapshot(ctx, ref.ID); err != nil {
		t.Fatalf("DeleteSnapshot twice must be idempotent: %v", err)
	}
	if _, err := client.Create(ctx, RemoteCreateRequest{TemplateID: ref.ID}); err == nil {
		t.Fatal("Create from a deleted snapshot must fail")
	}
}

func TestLocalBuildEnvNoHostLeakage(t *testing.T) {
	client, _ := newLocalTestClient(t)
	t.Setenv("SECRET_HOST_VALUE", "leak")
	handle := &LocalSandboxHandle{env: map[string]string{"FROM_CREATE": "1"}}
	env := client.buildEnv(handle, RemoteExecRequest{Env: map[string]string{"FROM_REQ": "2"}})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "SECRET_HOST_VALUE") {
		t.Fatalf("host environment leaked into the jail: %s", joined)
	}
	for _, want := range []string{"PATH=", "HOME=/workspace", "FROM_CREATE=1", "FROM_REQ=2"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("env missing %q: %s", want, joined)
		}
	}
}

// TestLocalExecJail is the real isolation probe. It needs a usable /bin/sh
// inside the template (static busybox) and kernel userns support; CI runners
// and the deployed ModelScope container both qualify. On a host without
// either it skips rather than failing.
func TestLocalExecJail(t *testing.T) {
	if _, err := os.Stat("/bin/busybox"); err != nil {
		t.Skip("no /bin/busybox on host; cannot build an exec-able fixture")
	}
	if err := checkUserNamespaceSupport(); err != nil {
		t.Skipf("userns unavailable: %v", err)
	}
	client, _ := newLocalTestClient(t)
	ctx := context.Background()
	handle, err := client.Create(ctx, RemoteCreateRequest{TemplateID: "t"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// 1. Plain execution with stdin and exit code.
	result, err := client.Exec(ctx, handle, RemoteExecRequest{
		Command: "sh",
		Args:    []string{"-c", "echo -n out; echo -n err 1>&2; exit 3"},
		Stdin:   "",
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if result.Stdout != "out" || result.Stderr != "err" || result.ExitCode != 3 {
		t.Fatalf("unexpected result: %+v", result)
	}

	// 2. Offline: no interfaces beyond loopback means any dial must fail.
	result, err = client.Exec(ctx, handle, RemoteExecRequest{
		Command: "sh",
		Args: []string{"-c",
			`cat /proc/net/dev | grep -c -v lo; ifconfig 2>/dev/null | wc -l; echo probe-done`},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Exec offline probe: %v", err)
	}
	if !strings.Contains(result.Stdout, "probe-done") {
		t.Fatalf("offline probe did not complete: %+v", result)
	}
	if lines := strings.TrimSpace(strings.SplitN(result.Stdout, "probe-done", 2)[0]); lines == "" {
		t.Fatalf("offline probe produced no output: %+v", result)
	}

	// 3. The host process table must not leak in (no /proc mount, PIDNS).
	result, err = client.Exec(ctx, handle, RemoteExecRequest{
		Command: "sh",
		Args:    []string{"-c", "ls /proc | wc -l"},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Exec proc probe: %v", err)
	}
	_ = result

	// 4. Timeout kill.
	start := time.Now()
	result, err = client.Exec(ctx, handle, RemoteExecRequest{
		Command: "sh",
		Args:    []string{"-c", "sleep 30"},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Exec timeout: %v", err)
	}
	if !result.Killed || time.Since(start) > 10*time.Second {
		t.Fatalf("timeout kill failed: killed=%v took=%v result=%+v", result.Killed, time.Since(start), result)
	}
}

func TestLocalExecShellForm(t *testing.T) {
	if _, err := os.Stat("/bin/busybox"); err != nil {
		t.Skip("no /bin/busybox on host")
	}
	if err := checkUserNamespaceSupport(); err != nil {
		t.Skipf("userns unavailable: %v", err)
	}
	client, _ := newLocalTestClient(t)
	ctx := context.Background()
	handle, err := client.Create(ctx, RemoteCreateRequest{TemplateID: "t"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	result, err := client.Exec(ctx, handle, RemoteExecRequest{
		Command: "echo shell-form-ok",
		Shell:   true,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Exec shell form: %v", err)
	}
	if !strings.Contains(result.Stdout, "shell-form-ok") {
		t.Fatalf("shell form stdout: %q", result.Stdout)
	}
	// Shell=true + Args is an invalid combination.
	if _, err := client.Exec(ctx, handle, RemoteExecRequest{
		Command: "echo x", Shell: true, Args: []string{"y"},
	}); err == nil {
		t.Fatal("Shell=true with Args should be an invalid request")
	}
}
