package sandbox

// Runtime tuning has safe built-in defaults. Unlike endpoints, credentials,
// and templates, these values do not identify an external backend.
func applyCubeRuntimeDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.CubeSandboxTTL <= 0 {
		cfg.CubeSandboxTTL = DefaultCubeSandboxTTL
	}
	if cfg.CubeHTTPTimeout <= 0 {
		cfg.CubeHTTPTimeout = DefaultCubeHTTPTimeout
	}
}

func applyDockerRuntimeDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	// The image is deliberately not defaulted here: it is this backend's
	// template, and a config that fails to name one must be reported as
	// incomplete rather than silently pointed at whatever image the release
	// happens to ship.
	if cfg.DockerHost == "" {
		cfg.DockerHost = DetectLocalDockerHost()
	}
	if cfg.DockerCPULimit <= 0 {
		cfg.DockerCPULimit = DefaultDockerCPULimit
	}
	if cfg.DockerMemoryBytes <= 0 {
		cfg.DockerMemoryBytes = DefaultDockerMemoryLimit
	}
	if cfg.DockerPidsLimit <= 0 {
		cfg.DockerPidsLimit = DefaultDockerPidsLimit
	}
	if cfg.DockerIdleTTL <= 0 {
		cfg.DockerIdleTTL = DefaultDockerIdleTTL
	}
	if cfg.DockerHTTPTimeout <= 0 {
		cfg.DockerHTTPTimeout = DefaultDockerHTTPTimeout
	}
}

func applyE2BRuntimeDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.E2BSandboxTTL <= 0 {
		cfg.E2BSandboxTTL = DefaultE2BSandboxTTL
	}
	if cfg.E2BHTTPTimeout <= 0 {
		cfg.E2BHTTPTimeout = DefaultE2BHTTPTimeout
	}
}

// applyLocalRuntimeDefaults fills the Local backend's paths and ceilings.
// Unlike the Docker image, the template path IS defaulted here: it is baked
// into the release at a fixed location and an admin has no way to discover
// or override it through the form, so demanding it would be a constant the
// config could never verify.
func applyLocalRuntimeDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.LocalTemplatePath == "" {
		cfg.LocalTemplatePath = DefaultLocalTemplatePath
	}
	if cfg.LocalRootfsBase == "" {
		cfg.LocalRootfsBase = DefaultLocalRootfsBase
	}
	if cfg.LocalCPULimit <= 0 {
		cfg.LocalCPULimit = DefaultLocalCPULimit
	}
	if cfg.LocalMemoryBytes <= 0 {
		cfg.LocalMemoryBytes = DefaultLocalMemoryLimit
	}
	if cfg.LocalPidsLimit <= 0 {
		cfg.LocalPidsLimit = DefaultLocalPidsLimit
	}
}
