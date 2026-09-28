//go:build !linux

// Package sandbox: the Local backend's execution stub for non-Linux hosts.
//
// The jail's clone/chroot/rlimit machinery lives in local_exec_linux.go and
// only compiles on Linux. This file keeps the rest of the package (and the
// Windows desktop build, which never executes Local sandboxes) building: the
// Exec method exists and reports the operation as unsupported at runtime
// instead of failing the compile.
package sandbox

import (
	"context"
	"fmt"
	"runtime"
)

// Exec refuses to run on non-Linux hosts.
func (c *LocalRemoteClient) Exec(
	ctx context.Context,
	handle RemoteSandboxHandle,
	req RemoteExecRequest,
) (*RemoteExecResult, error) {
	return nil, NewRemoteError(SandboxTypeLocal, "Exec", RemoteErrorKindUnsupported,
		fmt.Sprintf("the local sandbox backend requires Linux (running %s)", runtime.GOOS), nil)
}

// checkUserNamespaceSupport is only meaningful on Linux; other platforms
// never reach it because Health is backed by Exec-time checks that already
// refuse to run.
func checkUserNamespaceSupport() error {
	return fmt.Errorf("the local sandbox backend requires Linux")
}
