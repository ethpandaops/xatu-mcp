package sandbox

import (
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/go-units"
)

// SecurityConfig holds security settings for container execution.
type SecurityConfig struct {
	// User to run the container as (e.g., "nobody").
	User string
	// ReadonlyRootfs makes the root filesystem read-only.
	ReadonlyRootfs bool
	// DropCapabilities lists Linux capabilities to drop.
	DropCapabilities []string
	// SecurityOpts are additional security options (e.g., "no-new-privileges:true").
	SecurityOpts []string
	// PidsLimit restricts the number of processes in the container.
	PidsLimit int64
	// MemoryLimit in bytes.
	MemoryLimit int64
	// CPUQuota as a percentage of one CPU (100000 = 1 CPU).
	CPUQuota int64
	// CPUPeriod is the CPU CFS scheduler period.
	CPUPeriod int64
	// TmpfsSize is the size of the /tmp tmpfs mount.
	TmpfsSize string
	// Runtime specifies the container runtime (e.g., "" for default, "runsc" for gVisor).
	Runtime string
}

// DefaultSecurityConfig returns the default security configuration for sandboxed execution.
func DefaultSecurityConfig(memoryLimit string, cpuLimit float64) *SecurityConfig {
	memBytes, err := units.RAMInBytes(memoryLimit)
	if err != nil {
		// Fallback to 2GB if parsing fails.
		memBytes = 2 * 1024 * 1024 * 1024
	}

	return &SecurityConfig{
		User:           "nobody",
		ReadonlyRootfs: true,
		DropCapabilities: []string{
			"ALL",
		},
		SecurityOpts: []string{
			"no-new-privileges:true",
		},
		PidsLimit:   100,
		MemoryLimit: memBytes,
		CPUQuota:    int64(100000 * cpuLimit),
		CPUPeriod:   100000,
		TmpfsSize:   "100M",
		Runtime:     "",
	}
}

// GVisorSecurityConfig returns security configuration for gVisor-based execution.
func GVisorSecurityConfig(memoryLimit string, cpuLimit float64) *SecurityConfig {
	cfg := DefaultSecurityConfig(memoryLimit, cpuLimit)
	cfg.Runtime = "runsc"

	return cfg
}

// ApplyToHostConfig applies security settings to a Docker HostConfig.
func (s *SecurityConfig) ApplyToHostConfig(hostConfig *container.HostConfig) {
	// Resource limits.
	hostConfig.Resources.Memory = s.MemoryLimit
	hostConfig.Resources.CPUQuota = s.CPUQuota
	hostConfig.Resources.CPUPeriod = s.CPUPeriod
	hostConfig.Resources.PidsLimit = &s.PidsLimit

	// Security hardening.
	hostConfig.ReadonlyRootfs = s.ReadonlyRootfs
	hostConfig.SecurityOpt = s.SecurityOpts
	hostConfig.CapDrop = s.DropCapabilities

	// Runtime (for gVisor).
	if s.Runtime != "" {
		hostConfig.Runtime = s.Runtime
	}

	// Writable /tmp as tmpfs.
	if s.TmpfsSize != "" {
		hostConfig.Tmpfs = map[string]string{
			"/tmp": "size=" + s.TmpfsSize + ",mode=1777",
		}
	}
}

// CreateMounts creates the volume mounts for sandbox execution.
// sharedDir is mounted read-only at /shared (contains the script).
// outputDir is mounted read-write at /output (for generated files).
func CreateMounts(sharedDir, outputDir string) []mount.Mount {
	return []mount.Mount{
		{
			Type:     mount.TypeBind,
			Source:   sharedDir,
			Target:   "/shared",
			ReadOnly: true,
		},
		{
			Type:     mount.TypeBind,
			Source:   outputDir,
			Target:   "/output",
			ReadOnly: false,
		},
	}
}

// SandboxEnvDefaults returns default environment variables for sandbox execution.
// These ensure proper operation as the "nobody" user with no home directory.
func SandboxEnvDefaults() map[string]string {
	return map[string]string{
		"HOME":           "/tmp",
		"MPLCONFIGDIR":   "/tmp",
		"XDG_CACHE_HOME": "/tmp",
	}
}
