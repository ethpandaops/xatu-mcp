// Package sandbox provides secure code execution in isolated containers.
package sandbox

import (
	"context"
	"fmt"
	"time"

	"github.com/ethpandaops/xatu-mcp/pkg/config"
	"github.com/sirupsen/logrus"
)

// Service defines the interface for sandbox code execution backends.
type Service interface {
	// Start initializes the sandbox backend (e.g., connecting to Docker).
	Start(ctx context.Context) error
	// Stop cleans up resources and any active containers.
	Stop(ctx context.Context) error
	// Execute runs Python code in an isolated container.
	Execute(ctx context.Context, req ExecuteRequest) (*ExecutionResult, error)
	// Name returns the backend name for logging/metrics.
	Name() string
}

// ExecuteRequest contains the parameters for code execution.
type ExecuteRequest struct {
	// Code is the Python code to execute.
	Code string
	// Env contains additional environment variables to set in the sandbox.
	Env map[string]string
	// Timeout overrides the default execution timeout. If zero, uses the config default.
	Timeout time.Duration
}

// ExecutionResult contains the output from code execution.
type ExecutionResult struct {
	// Stdout contains the standard output from execution.
	Stdout string
	// Stderr contains the standard error from execution.
	Stderr string
	// ExitCode is the process exit code (0 = success).
	ExitCode int
	// ExecutionID is a unique identifier for this execution.
	ExecutionID string
	// OutputFiles lists file names created in /output directory.
	OutputFiles []string
	// Metrics contains any metrics reported by the executed code.
	Metrics map[string]any
	// DurationSeconds is the wall-clock execution time.
	DurationSeconds float64
}

// BackendType represents the available sandbox backend types.
type BackendType string

const (
	// BackendDocker uses standard Docker containers.
	BackendDocker BackendType = "docker"
	// BackendGVisor uses Docker with gVisor runtime for enhanced isolation.
	BackendGVisor BackendType = "gvisor"
)

// New creates a new sandbox service based on the configuration.
func New(cfg config.SandboxConfig, log logrus.FieldLogger) (Service, error) {
	backendType := BackendType(cfg.Backend)

	switch backendType {
	case BackendDocker:
		return NewDockerBackend(cfg, log)
	case BackendGVisor:
		return NewGVisorBackend(cfg, log)
	default:
		return nil, fmt.Errorf("unsupported sandbox backend: %s", cfg.Backend)
	}
}

// Compile-time interface compliance checks.
var (
	_ Service = (*DockerBackend)(nil)
	_ Service = (*GVisorBackend)(nil)
)
