package sandbox

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// LocalBackendEnabledEnv is the process-level fallback for the Local sandbox
// backend. System Settings (sandbox.local_enabled) override it when a row has
// been pushed by SystemSettingService.
//
// The Local backend runs untrusted scripts under user namespaces on the host
// kernel. It isolates less than Docker or the MicroVM backends, and a
// deployment that never opted in should not start hosting script execution
// just because the binary ships with the backend compiled in. Like the Docker
// backend it is therefore off until a SystemAdmin or deployer opts in.
const LocalBackendEnabledEnv = "WEKNORA_SANDBOX_LOCAL_ENABLED"

// LocalBackendEnabledSettingKey is the system_settings registry key.
const LocalBackendEnabledSettingKey = "sandbox.local_enabled"

// ErrLocalBackendDisabled is returned when a Local sandbox config is saved,
// probed, or resolved and the process has not opted in.
var ErrLocalBackendDisabled = errors.New(
	"sandbox: local backend is disabled; enable it in System Settings or set WEKNORA_SANDBOX_LOCAL_ENABLED=true",
)

// localBackendEnabledOverride is the runtime-tunable source. Nil means
// "SystemSettingService has not pushed yet"; LocalBackendEnabled then reads
// the env, matching the preload window and tests that only Setenv.
var localBackendEnabledOverride atomic.Pointer[bool]

// SetLocalBackendEnabled records the resolved 3-tier value (DB > env > false).
// Called at system_settings preload, Update, Reset, and pubsub reload.
func SetLocalBackendEnabled(enabled bool) {
	v := enabled
	localBackendEnabledOverride.Store(&v)
}

// ClearLocalBackendEnabledOverride restores env-only resolution. Tests that
// construct SystemSettingService can otherwise leak a preload push into later
// Setenv-based cases in the same package.
func ClearLocalBackendEnabledOverride() {
	localBackendEnabledOverride.Store(nil)
}

// LocalBackendEnabled reports whether this process may run the Local sandbox
// backend. Empty or unparsable env values are false.
func LocalBackendEnabled() bool {
	if p := localBackendEnabledOverride.Load(); p != nil {
		return *p
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(LocalBackendEnabledEnv)))
	return err == nil && parsed
}

// EnsureLocalBackendAllowed is the choke point for every path that would run
// a Local sandbox on behalf of a workspace config.
func EnsureLocalBackendAllowed(t SandboxType) error {
	if t != SandboxTypeLocal {
		return nil
	}
	if LocalBackendEnabled() {
		return nil
	}
	return ErrLocalBackendDisabled
}
