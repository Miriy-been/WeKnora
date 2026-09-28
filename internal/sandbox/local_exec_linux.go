//go:build linux

// Package sandbox: the Local backend's Linux execution core.
//
// Exec runs one command inside the session's rootfs under a five-namespace
// jail assembled purely from os/exec SysProcAttr — the only isolation
// mechanism a shared PaaS container can provide without a Docker socket,
// TUN device, or KVM:
//
//   - CLONE_NEWUSER re-roots capabilities inside the new namespace so the
//     chroot syscall is available, and namespaces created in the same clone
//     are owned by the new userns. The uid/gid maps are identity maps
//     (host root → jail root) because WeKnora itself already runs as root;
//     the sandbox account is not a tenant boundary (see
//     DefaultSandboxExecUser) — host isolation lives at the namespace and
//     rootfs boundary.
//   - CLONE_NEWPID + chroot without a /proc mount: the jail has no view of
//     the host process table at all, not even through /proc.
//   - CLONE_NEWNET with no interfaces: always offline. There is no toggle.
//   - CLONE_NEWUTS / CLONE_NEWIPC: hostname and SysV isolation.
//
// Resource ceilings are two independent layers:
//
//   - rlimits via a shell prefix (`ulimit -v/-t/-u` then `exec "$@"`): the
//     limits survive the exec because the shell replaces its image with the
//     target process.
//   - cgroup v1 best-effort (memory / cpu / pids controllers) when the
//     container has them mounted writable. Failure degrades to rlimits-only.
//
// A process that dies inside the jail cannot leak: the exec'd process is
// PID 1 of the PID namespace, and when PID 1 exits the kernel tears the
// namespace — and every process in it — down.
package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// localJailShell is the argv[0] wrapper shell inside the rootfs. The template
// build installs busybox with /bin/sh wired up.
const localJailShell = "/bin/sh"

// localJailWorkspace is the default working directory inside the jail,
// matching remoteScriptDir on the other backends.
const localJailWorkspace = "/workspace"

// Exec runs req's command inside the jail. See RemoteSandboxClient.Exec for
// the Shell/Args contract.
func (c *LocalRemoteClient) Exec(
	ctx context.Context,
	handle RemoteSandboxHandle,
	req RemoteExecRequest,
) (*RemoteExecResult, error) {
	local, ok := handle.(*LocalSandboxHandle)
	if !ok || local == nil {
		return nil, localErr("Exec", RemoteErrorKindInvalidRequest, "non-local handle")
	}
	if err := EnsureLocalBackendAllowed(SandboxTypeLocal); err != nil {
		return nil, err
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if req.Shell && len(req.Args) > 0 {
		return nil, localErr("Exec", RemoteErrorKindInvalidRequest,
			"Shell=true combined with Args is not a valid request")
	}

	argv, err := c.buildArgv(local, req, timeout)
	if err != nil {
		return nil, err
	}
	workDir, err := c.resolveWorkDir(local, req.WorkDir)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = workDir
	cmd.Env = c.buildEnv(local, req)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNET |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		// Own process group so a later kill reaches the whole jail tree even
		// before namespace teardown; PID 1 exit then guarantees it anyway.
		Setpgid: true,
		Chroot:  local.rootfs,
	}

	attach, cleanup := c.applyCgroupLimits(local)
	defer cleanup()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, localErrWrapped("Exec", RemoteErrorKindInternal, err, "stdin pipe")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, localErrWrapped("Exec", RemoteErrorKindInternal, err, "stdout pipe")
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, localErrWrapped("Exec", RemoteErrorKindInternal, err, "stderr pipe")
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, localErrWrapped("Exec", RemoteErrorKindUnavailable, err,
			"start jailed process (template %s)", c.cfg.LocalTemplatePath)
	}

	// Write the pid into the freshly created cgroups (best-effort). There is
	// a tiny window where a fast-exiting process is gone before the write;
	// the error is ignored and the rlimit layer still held during it.
	if attach != nil {
		attach(cmd.Process.Pid)
	}

	if req.Stdin != "" {
		go func() {
			_, _ = io.WriteString(stdin, req.Stdin)
			_ = stdin.Close()
		}()
	} else {
		_ = stdin.Close()
	}

	var (
		outBuf, errBuf bytes.Buffer
		streamWG       sync.WaitGroup
	)
	collect := func(input io.Reader, buf *bytes.Buffer, stream string) {
		defer streamWG.Done()
		chunk := make([]byte, 4096)
		for {
			n, rerr := input.Read(chunk)
			if n > 0 {
				buf.Write(chunk[:n])
				if req.OnOutput != nil {
					req.OnOutput(stream, chunk[:n])
				}
			}
			if rerr != nil {
				return
			}
		}
	}
	streamWG.Add(2)
	go collect(stdout, &outBuf, "stdout")
	go collect(stderr, &errBuf, "stderr")

	// Two triggers can request the kill: the wall-clock timer and ctx
	// cancellation. The atomic flag records "someone killed it" without a
	// data race; both goroutines racing on the kill itself is harmless.
	var killedByGuard atomic.Bool
	timer := time.AfterFunc(timeout, func() {
		killedByGuard.Store(true)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	})
	if ctxDone := ctx.Done(); ctxDone != nil {
		go func() {
			<-ctxDone
			killedByGuard.Store(true)
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}()
	}

	waitErr := cmd.Wait()
	timer.Stop()
	streamWG.Wait()

	result := &RemoteExecResult{
		Stdout:   outBuf.String(),
		Stderr:   errBuf.String(),
		Duration: time.Since(start),
	}
	if killedByGuard.Load() && waitErr != nil {
		result.Killed = true
		result.ExitCode = -1
		return result, nil
	}
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, localErrWrapped("Exec", RemoteErrorKindInternal, waitErr, "wait jailed process")
		}
	}
	return result, nil
}

// buildArgv assembles the jail's argv. The rlimit prefix runs inside the
// jail's own /bin/sh (busybox ash), applies the ceilings, then execs the
// real command so the limits survive the image swap. Every ulimit operand is
// a number this function generates — script content never reaches the prefix.
func (c *LocalRemoteClient) buildArgv(handle *LocalSandboxHandle, req RemoteExecRequest, timeout time.Duration) ([]string, error) {
	var target []string
	if req.Shell {
		target = []string{localJailShell, "-c", req.Command}
	} else {
		bin, err := localLookPath(handle.rootfs, req.Command)
		if err != nil {
			return nil, localErr("Exec", RemoteErrorKindInvalidRequest, "%v", err)
		}
		target = append([]string{bin}, req.Args...)
	}

	prefix := c.ulimitPrefix(timeout)
	if prefix == "" {
		return target, nil
	}
	// exec "$@" re-execs the target argv after the ulimit builtins, with the
	// conventional "sh" argv[0] placeholder.
	args := append([]string{localJailShell, "-c", prefix + `; exec "$@"`, "sh"}, target...)
	return args, nil
}

// ulimitPrefix renders the rlimit shell builtins. RLIMIT_CPU derives from the
// effective timeout — the wall-clock kill is the primary guard, the CPU
// limit is the second line against a busy loop that somehow survives it.
func (c *LocalRemoteClient) ulimitPrefix(timeout time.Duration) string {
	var parts []string
	if c.cfg.LocalMemoryBytes > 0 {
		// -v is in KiB.
		parts = append(parts, "ulimit -v "+strconv.FormatInt(c.cfg.LocalMemoryBytes/1024, 10))
	}
	if c.cfg.LocalPidsLimit > 0 {
		parts = append(parts, "ulimit -u "+strconv.FormatInt(c.cfg.LocalPidsLimit, 10))
	}
	if c.cfg.LocalCPULimit > 0 {
		cpuSeconds := int(c.cfg.LocalCPULimit*timeout.Seconds()) + 5
		parts = append(parts, "ulimit -t "+strconv.Itoa(cpuSeconds))
	}
	return strings.Join(parts, "; ")
}

// localLookPath resolves a bare command name against the rootfs's own PATH,
// because os/exec's LookPath would search the HOST filesystem and produce a
// path that is meaningless after the chroot. The returned path is the
// jail-internal absolute path, which the kernel resolves against the new
// root after SysProcAttr.Chroot is applied.
func localLookPath(rootfs, command string) (string, error) {
	if strings.ContainsRune(command, '/') {
		clean := filepath.Clean("/" + strings.TrimPrefix(command, "/"))
		if strings.Contains(clean, "..") {
			return "", fmt.Errorf("command path %q escapes the sandbox", command)
		}
		if _, err := os.Stat(filepath.Join(rootfs, clean)); err != nil {
			return "", fmt.Errorf("executable %s not found in sandbox", command)
		}
		return clean, nil
	}
	for _, dir := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		candidate := filepath.Join(rootfs, dir, command)
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return filepath.Join(dir, command), nil
		}
	}
	return "", fmt.Errorf("executable %q not found in sandbox PATH", command)
}

// resolveWorkDir validates the requested working directory against the
// rootfs. A missing directory fails early instead of surfacing as a cryptic
// execve error from inside the jail.
func (c *LocalRemoteClient) resolveWorkDir(handle *LocalSandboxHandle, workDir string) (string, error) {
	if strings.TrimSpace(workDir) == "" {
		return localJailWorkspace, nil
	}
	clean := filepath.Clean("/" + strings.TrimPrefix(filepath.ToSlash(workDir), "/"))
	if strings.Contains(clean, "..") {
		return "", localErr("Exec", RemoteErrorKindInvalidRequest,
			"workdir %q escapes the sandbox", workDir)
	}
	if fi, err := os.Stat(filepath.Join(handle.rootfs, clean)); err != nil || !fi.IsDir() {
		return "", localErr("Exec", RemoteErrorKindInvalidRequest,
			"workdir %s does not exist in the sandbox", workDir)
	}
	return clean, nil
}

// buildEnv assembles the jail environment: a minimal fixed base (no host
// leakage), the create-time EnvVars, then the per-request Env last so the
// caller wins.
func (c *LocalRemoteClient) buildEnv(handle *LocalSandboxHandle, req RemoteExecRequest) []string {
	base := map[string]string{
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME": localJailWorkspace,
		"LANG": "C.UTF-8",
		"TERM": "dumb",
	}
	for k, v := range handle.env {
		base[k] = v
	}
	for k, v := range req.Env {
		base[k] = v
	}
	env := make([]string, 0, len(base))
	for k, v := range base {
		env = append(env, k+"="+v)
	}
	return env
}

// --- cgroup v1 best-effort ---

// applyCgroupLimits provisions a per-sandbox cgroup on each writable v1
// controller. It returns (attach, cleanup): attach writes a pid into the
// groups right after the process starts, cleanup removes the groups once the
// execution finishes. Any failure downgrades silently to the rlimit layer;
// the jail's isolation never depends on cgroups.
func (c *LocalRemoteClient) applyCgroupLimits(handle *LocalSandboxHandle) (func(int), func()) {
	groups := make([]string, 0, 3)
	register := func(controller string, files map[string]string) {
		dir := filepath.Join("/sys/fs/cgroup", controller, handle.id)
		if err := os.Mkdir(dir, 0o755); err != nil {
			return
		}
		for file, value := range files {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(value), 0o644); err != nil {
				_ = os.Remove(dir)
				return
			}
		}
		groups = append(groups, dir)
	}
	if c.cfg.LocalMemoryBytes > 0 {
		register("memory", map[string]string{
			"memory.limit_in_bytes": strconv.FormatInt(c.cfg.LocalMemoryBytes, 10),
		})
	}
	if c.cfg.LocalCPULimit > 0 {
		period := 100000
		quota := int(c.cfg.LocalCPULimit * float64(period))
		if quota < 1000 {
			quota = 1000
		}
		register("cpu", map[string]string{
			"cpu.cfs_period_us": strconv.Itoa(period),
			"cpu.cfs_quota_us":  strconv.Itoa(quota),
		})
	}
	if c.cfg.LocalPidsLimit > 0 {
		register("pids", map[string]string{
			"pids.max": strconv.FormatInt(c.cfg.LocalPidsLimit, 10),
		})
	}
	attach := func(pid int) {
		for _, dir := range groups {
			_ = os.WriteFile(
				filepath.Join(dir, "cgroup.procs"),
				[]byte(strconv.Itoa(pid)), 0o644)
		}
	}
	cleanup := func() {
		for _, dir := range groups {
			_ = os.Remove(dir)
		}
	}
	return attach, cleanup
}

// checkUserNamespaceSupport reports whether unprivileged user namespaces are
// available. Debian exposes the hard off-switch as
// /proc/sys/kernel/unprivileged_userns_clone=0; the generic pool size lives
// at /proc/sys/user/max_user_namespaces.
func checkUserNamespaceSupport() error {
	if blob, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(blob)) == "0" {
			return fmt.Errorf("unprivileged_userns_clone is disabled")
		}
	}
	if blob, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		if n, perr := strconv.Atoi(strings.TrimSpace(string(blob))); perr == nil && n <= 0 {
			return fmt.Errorf("max_user_namespaces is %d", n)
		}
	}
	return nil
}
