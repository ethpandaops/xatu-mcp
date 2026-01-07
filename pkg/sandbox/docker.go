package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/ethpandaops/xatu-mcp/pkg/config"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// DockerBackend implements sandbox execution using standard Docker containers.
type DockerBackend struct {
	cfg    config.SandboxConfig
	log    logrus.FieldLogger
	client *client.Client

	// activeContainers tracks running containers for cleanup on timeout/shutdown.
	activeContainers map[string]string // executionID -> containerID
	mu               sync.RWMutex
}

// NewDockerBackend creates a new Docker sandbox backend.
func NewDockerBackend(cfg config.SandboxConfig, log logrus.FieldLogger) (*DockerBackend, error) {
	return &DockerBackend{
		cfg:              cfg,
		log:              log.WithField("component", "sandbox.docker"),
		activeContainers: make(map[string]string, 16),
	}, nil
}

// Name returns the backend name.
func (b *DockerBackend) Name() string {
	return "docker"
}

// Start initializes the Docker client and verifies connectivity.
func (b *DockerBackend) Start(ctx context.Context) error {
	b.log.Info("Starting Docker sandbox backend")

	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}

	// Verify Docker is accessible.
	if _, err := dockerClient.Ping(ctx); err != nil {
		return fmt.Errorf("connecting to docker daemon: %w", err)
	}

	b.client = dockerClient

	// Ensure the sandbox image is available.
	if err := b.ensureImage(ctx); err != nil {
		return fmt.Errorf("ensuring sandbox image: %w", err)
	}

	b.log.WithField("image", b.cfg.Image).Info("Docker sandbox backend started")

	return nil
}

// Stop cleans up any active containers and closes the Docker client.
func (b *DockerBackend) Stop(ctx context.Context) error {
	b.log.Info("Stopping Docker sandbox backend")

	// Kill all active containers.
	b.mu.Lock()
	containersToClean := make(map[string]string, len(b.activeContainers))
	for k, v := range b.activeContainers {
		containersToClean[k] = v
	}
	b.activeContainers = make(map[string]string, 16)
	b.mu.Unlock()

	for execID, containerID := range containersToClean {
		if err := b.forceRemoveContainer(ctx, containerID); err != nil {
			b.log.WithFields(logrus.Fields{
				"execution_id": execID,
				"container_id": containerID,
				"error":        err,
			}).Warn("Failed to remove container during shutdown")
		}
	}

	if b.client != nil {
		if err := b.client.Close(); err != nil {
			return fmt.Errorf("closing docker client: %w", err)
		}
	}

	b.log.Info("Docker sandbox backend stopped")

	return nil
}

// Execute runs Python code in a Docker container.
func (b *DockerBackend) Execute(ctx context.Context, req ExecuteRequest) (*ExecutionResult, error) {
	if b.client == nil {
		return nil, fmt.Errorf("docker client not initialized, call Start() first")
	}

	executionID := uuid.New().String()[:8]
	timeout := req.Timeout
	if timeout == 0 {
		timeout = time.Duration(b.cfg.Timeout) * time.Second
	}

	log := b.log.WithField("execution_id", executionID)
	log.Debug("Starting code execution")

	// Create temporary directories for this execution.
	baseDir, err := b.createExecutionDirs(executionID)
	if err != nil {
		return nil, fmt.Errorf("creating execution directories: %w", err)
	}

	defer func() {
		if err := os.RemoveAll(baseDir); err != nil {
			log.WithError(err).Warn("Failed to cleanup execution directory")
		}
	}()

	sharedDir := filepath.Join(baseDir, "shared")
	outputDir := filepath.Join(baseDir, "output")

	// Write the script to execute.
	scriptPath := filepath.Join(sharedDir, "script.py")
	if err := os.WriteFile(scriptPath, []byte(req.Code), 0644); err != nil {
		return nil, fmt.Errorf("writing script file: %w", err)
	}

	// Build container configuration.
	containerConfig, hostConfig := b.buildContainerConfig(sharedDir, outputDir, req.Env)

	// Create execution context with timeout.
	execCtx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()

	// Create container.
	resp, err := b.client.ContainerCreate(execCtx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return nil, fmt.Errorf("creating container: %w", err)
	}

	containerID := resp.ID
	b.trackContainer(executionID, containerID)

	defer func() {
		b.untrackContainer(executionID)
		if err := b.forceRemoveContainer(context.Background(), containerID); err != nil {
			log.WithError(err).Warn("Failed to remove container")
		}
	}()

	// Start container.
	startTime := time.Now()
	if err := b.client.ContainerStart(execCtx, containerID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("starting container: %w", err)
	}

	log.Debug("Container started")

	// Wait for container to finish or timeout.
	result, err := b.waitForContainer(execCtx, containerID, timeout)
	if err != nil {
		// On timeout, force kill the container.
		log.Warn("Container execution timed out, force killing")

		if killErr := b.forceKillContainer(context.Background(), containerID); killErr != nil {
			log.WithError(killErr).Warn("Failed to force kill container")
		}

		return nil, fmt.Errorf("container execution: %w", err)
	}

	duration := time.Since(startTime).Seconds()

	// Collect output files.
	outputFiles, err := b.collectOutputFiles(outputDir)
	if err != nil {
		log.WithError(err).Warn("Failed to collect output files")
	}

	// Read metrics if present.
	metrics := b.readMetrics(outputDir)

	log.WithFields(logrus.Fields{
		"exit_code": result.exitCode,
		"duration":  duration,
	}).Debug("Container execution completed")

	return &ExecutionResult{
		Stdout:          result.stdout,
		Stderr:          result.stderr,
		ExitCode:        result.exitCode,
		ExecutionID:     executionID,
		OutputFiles:     outputFiles,
		Metrics:         metrics,
		DurationSeconds: duration,
	}, nil
}

// containerResult holds the output from container execution.
type containerResult struct {
	stdout   string
	stderr   string
	exitCode int
}

// createExecutionDirs creates the temporary directories for an execution.
func (b *DockerBackend) createExecutionDirs(executionID string) (string, error) {
	var baseDir string

	if b.cfg.HostSharedPath != "" {
		// Docker-in-Docker mode: use host-visible path.
		baseDir = filepath.Join(b.cfg.HostSharedPath, executionID)
	} else {
		// Direct mode: use temp directory.
		baseDir = filepath.Join(os.TempDir(), "xatu-sandbox-"+executionID)
	}

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return "", fmt.Errorf("creating base directory: %w", err)
	}

	sharedDir := filepath.Join(baseDir, "shared")
	outputDir := filepath.Join(baseDir, "output")

	if err := os.MkdirAll(sharedDir, 0755); err != nil {
		return "", fmt.Errorf("creating shared directory: %w", err)
	}

	// Output dir needs 777 permissions for "nobody" user to write.
	if err := os.MkdirAll(outputDir, 0777); err != nil {
		return "", fmt.Errorf("creating output directory: %w", err)
	}

	return baseDir, nil
}

// buildContainerConfig creates the container and host configurations.
func (b *DockerBackend) buildContainerConfig(
	sharedDir, outputDir string,
	env map[string]string,
) (*container.Config, *container.HostConfig) {
	// Merge environment variables with defaults.
	containerEnv := SandboxEnvDefaults()
	for k, v := range env {
		containerEnv[k] = v
	}

	// Convert map to slice for Docker API.
	envSlice := make([]string, 0, len(containerEnv))
	for k, v := range containerEnv {
		envSlice = append(envSlice, k+"="+v)
	}

	containerConfig := &container.Config{
		Image: b.cfg.Image,
		Cmd:   []string{"python", "/shared/script.py"},
		Env:   envSlice,
		User:  "nobody",
	}

	// Determine the source paths for mounts.
	// In Docker-in-Docker mode, HostSharedPath is the path visible to the Docker daemon.
	var hostSharedDir, hostOutputDir string

	if b.cfg.HostSharedPath != "" {
		// Extract the execution ID from the directory path.
		execID := filepath.Base(filepath.Dir(sharedDir))
		hostSharedDir = filepath.Join(b.cfg.HostSharedPath, execID, "shared")
		hostOutputDir = filepath.Join(b.cfg.HostSharedPath, execID, "output")
	} else {
		hostSharedDir = sharedDir
		hostOutputDir = outputDir
	}

	hostConfig := &container.HostConfig{
		NetworkMode: container.NetworkMode(b.cfg.Network),
		Mounts:      CreateMounts(hostSharedDir, hostOutputDir),
	}

	// Apply security configuration.
	securityCfg := b.getSecurityConfig()
	securityCfg.ApplyToHostConfig(hostConfig)

	return containerConfig, hostConfig
}

// getSecurityConfig returns the security configuration for this backend.
// Subclasses can override this to use different security settings.
func (b *DockerBackend) getSecurityConfig() *SecurityConfig {
	return DefaultSecurityConfig(b.cfg.MemoryLimit, b.cfg.CPULimit)
}

// waitForContainer waits for a container to finish and returns its output.
func (b *DockerBackend) waitForContainer(
	ctx context.Context,
	containerID string,
	timeout time.Duration,
) (*containerResult, error) {
	// Create a timeout context for waiting.
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Wait for container to exit.
	statusCh, errCh := b.client.ContainerWait(waitCtx, containerID, container.WaitConditionNotRunning)

	select {
	case err := <-errCh:
		if err != nil {
			return nil, fmt.Errorf("waiting for container: %w", err)
		}
	case status := <-statusCh:
		// Container exited, get logs.
		stdout, stderr, err := b.getContainerLogs(ctx, containerID)
		if err != nil {
			return nil, fmt.Errorf("getting container logs: %w", err)
		}

		return &containerResult{
			stdout:   stdout,
			stderr:   stderr,
			exitCode: int(status.StatusCode),
		}, nil
	case <-waitCtx.Done():
		return nil, fmt.Errorf("execution timed out after %s", timeout)
	}

	return nil, fmt.Errorf("unexpected wait state")
}

// getContainerLogs retrieves stdout and stderr from a container.
func (b *DockerBackend) getContainerLogs(ctx context.Context, containerID string) (string, string, error) {
	logReader, err := b.client.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return "", "", fmt.Errorf("reading container logs: %w", err)
	}
	defer logReader.Close()

	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, logReader); err != nil {
		return "", "", fmt.Errorf("demultiplexing container logs: %w", err)
	}

	return stdout.String(), stderr.String(), nil
}

// collectOutputFiles lists files in the output directory.
func (b *DockerBackend) collectOutputFiles(outputDir string) ([]string, error) {
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, fmt.Errorf("reading output directory: %w", err)
	}

	files := make([]string, 0, len(entries))

	for _, entry := range entries {
		if !entry.IsDir() && entry.Name()[0] != '.' {
			files = append(files, entry.Name())
		}
	}

	return files, nil
}

// readMetrics reads the metrics file if present.
func (b *DockerBackend) readMetrics(outputDir string) map[string]any {
	metricsPath := filepath.Join(outputDir, ".metrics.json")

	data, err := os.ReadFile(metricsPath)
	if err != nil {
		return nil
	}

	var metrics map[string]any
	if err := json.Unmarshal(data, &metrics); err != nil {
		b.log.WithError(err).Warn("Failed to parse metrics file")

		return nil
	}

	return metrics
}

// trackContainer adds a container to the active containers map.
func (b *DockerBackend) trackContainer(executionID, containerID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.activeContainers[executionID] = containerID
}

// untrackContainer removes a container from the active containers map.
func (b *DockerBackend) untrackContainer(executionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.activeContainers, executionID)
}

// forceKillContainer forcefully kills a running container.
func (b *DockerBackend) forceKillContainer(ctx context.Context, containerID string) error {
	if err := b.client.ContainerKill(ctx, containerID, "SIGKILL"); err != nil {
		// Ignore "not running" errors.
		if !client.IsErrNotFound(err) {
			return fmt.Errorf("killing container: %w", err)
		}
	}

	return nil
}

// forceRemoveContainer forcefully removes a container.
func (b *DockerBackend) forceRemoveContainer(ctx context.Context, containerID string) error {
	if err := b.client.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
		if !client.IsErrNotFound(err) {
			return fmt.Errorf("removing container: %w", err)
		}
	}

	return nil
}

// ensureImage ensures the sandbox image is available locally.
func (b *DockerBackend) ensureImage(ctx context.Context) error {
	_, _, err := b.client.ImageInspectWithRaw(ctx, b.cfg.Image)
	if err == nil {
		return nil
	}

	if !client.IsErrNotFound(err) {
		return fmt.Errorf("inspecting image: %w", err)
	}

	// Image not found, try to pull it.
	b.log.WithField("image", b.cfg.Image).Info("Pulling sandbox image")

	reader, err := b.client.ImagePull(ctx, b.cfg.Image, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("pulling image: %w", err)
	}
	defer reader.Close()

	// Consume the pull output.
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("reading pull output: %w", err)
	}

	return nil
}
