package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethpandaops/mcp/pkg/config"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

// Kubernetes pod label keys for identifying and managing sandbox pods.
const (
	// LabelK8sManagedBy identifies pods managed by ethpandaops-mcp.
	LabelK8sManagedBy = "app.kubernetes.io/managed-by"
	// LabelK8sSessionID stores the session ID for session pods.
	LabelK8sSessionID = "mcp.ethpandaops.io/session-id"
	// LabelK8sOwnerID stores the owner ID (GitHub user ID) if auth is enabled.
	LabelK8sOwnerID = "mcp.ethpandaops.io/owner-id"
	// LabelK8sCreatedAt stores the Unix timestamp when the pod was created.
	LabelK8sCreatedAt = "mcp.ethpandaops.io/created-at"

	// AnnotationK8sDescription provides a human-readable description.
	AnnotationK8sDescription = "mcp.ethpandaops.io/description"

	// ManagedByValue is the value for the managed-by label.
	ManagedByValue = "ethpandaops-mcp"

	// SandboxContainerName is the name of the container in sandbox pods.
	SandboxContainerName = "sandbox"
)

// KubernetesBackend implements sandbox execution using Kubernetes pods.
// Session state is stored in pod labels, making it accessible cluster-wide.
type KubernetesBackend struct {
	cfg    config.SandboxConfig
	log    logrus.FieldLogger
	client kubernetes.Interface
	config *rest.Config

	// sessionManager handles persistent session lifecycle.
	sessionManager *SessionManager

	// activeExecutions tracks running executions for cleanup on timeout/shutdown.
	activeExecutions map[string]string // executionID -> podName
	mu               sync.RWMutex

	done chan struct{}
	wg   sync.WaitGroup
}

// NewKubernetesBackend creates a new Kubernetes sandbox backend.
func NewKubernetesBackend(cfg config.SandboxConfig, log logrus.FieldLogger) (*KubernetesBackend, error) {
	backend := &KubernetesBackend{
		cfg:              cfg,
		log:              log.WithField("component", "sandbox.kubernetes"),
		activeExecutions: make(map[string]string, 16),
		done:             make(chan struct{}),
	}

	// Create session manager with callbacks for pod queries and cleanup.
	backend.sessionManager = NewSessionManager(
		cfg.Sessions,
		log,
		backend.getSessionPod,
		backend.listAllSessionPods,
		func(ctx context.Context, podName string) error {
			if backend.client == nil {
				return nil
			}

			return backend.deletePod(ctx, podName)
		},
	)

	return backend, nil
}

// Name returns the backend name.
func (b *KubernetesBackend) Name() string {
	return "kubernetes"
}

// Start initializes the Kubernetes client and verifies connectivity.
func (b *KubernetesBackend) Start(ctx context.Context) error {
	b.log.Info("Starting Kubernetes sandbox backend")

	// Try in-cluster config first, fall back to kubeconfig.
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		b.log.Debug("Not running in-cluster, trying kubeconfig")

		k8sConfig, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		if err != nil {
			return fmt.Errorf("building kubernetes config: %w", err)
		}
	}

	b.config = k8sConfig

	client, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	b.client = client

	// Verify connectivity by checking namespace exists.
	namespace := b.cfg.Kubernetes.Namespace

	_, err = b.client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("sandbox namespace %q does not exist", namespace)
		}

		return fmt.Errorf("checking sandbox namespace: %w", err)
	}

	b.log.WithField("namespace", namespace).Info("Connected to Kubernetes cluster")

	// Clean up expired orphaned pods from previous runs.
	if err := b.cleanupExpiredPods(ctx); err != nil {
		b.log.WithError(err).Warn("Failed to cleanup expired pods")
	}

	// Start session manager if enabled.
	if err := b.sessionManager.Start(ctx); err != nil {
		return fmt.Errorf("starting session manager: %w", err)
	}

	b.log.WithFields(logrus.Fields{
		"namespace": namespace,
		"image":     b.cfg.Image,
	}).Info("Kubernetes sandbox backend started")

	return nil
}

// Stop cleans up any active pods and closes connections.
func (b *KubernetesBackend) Stop(ctx context.Context) error {
	b.log.Info("Stopping Kubernetes sandbox backend")

	close(b.done)
	b.wg.Wait()

	// Stop session manager first (this will cleanup session pods).
	if err := b.sessionManager.Stop(ctx); err != nil {
		b.log.WithError(err).Warn("Failed to stop session manager")
	}

	b.log.Info("Kubernetes sandbox backend stopped")

	return nil
}

// Execute runs Python code in a Kubernetes pod.
func (b *KubernetesBackend) Execute(ctx context.Context, req ExecuteRequest) (*ExecutionResult, error) {
	if b.client == nil {
		return nil, fmt.Errorf("kubernetes client not initialized, call Start() first")
	}

	// If a session ID is provided, execute in the existing session.
	if req.SessionID != "" {
		return b.executeInSession(ctx, req)
	}

	// If sessions are enabled, create a new session.
	if b.sessionManager.Enabled() {
		return b.executeWithNewSession(ctx, req)
	}

	// Ephemeral execution (create pod, run code, delete pod).
	return b.executeEphemeral(ctx, req)
}

// executeEphemeral runs code in a new pod that is destroyed after execution.
func (b *KubernetesBackend) executeEphemeral(ctx context.Context, req ExecuteRequest) (*ExecutionResult, error) {
	executionID := uuid.New().String()
	timeout := req.Timeout

	if timeout == 0 {
		timeout = time.Duration(b.cfg.Timeout) * time.Second
	}

	log := b.log.WithField("execution_id", executionID)
	log.Debug("Starting ephemeral code execution")

	// Create ephemeral pod.
	podName := fmt.Sprintf("mcp-ephemeral-%s", executionID[:12])

	pod, err := b.createPod(ctx, podName, "", req.OwnerID, req.Env)
	if err != nil {
		return nil, fmt.Errorf("creating ephemeral pod: %w", err)
	}

	b.trackExecution(executionID, podName)

	defer func() {
		b.untrackExecution(executionID)

		if err := b.deletePod(context.Background(), podName); err != nil {
			log.WithError(err).Warn("Failed to delete ephemeral pod")
		}
	}()

	// Wait for pod to be running.
	if err := b.waitForPodRunning(ctx, podName, 60*time.Second); err != nil {
		return nil, fmt.Errorf("waiting for pod to be running: %w", err)
	}

	// Execute the code.
	startTime := time.Now()

	result, err := b.execInPod(ctx, pod.Name, req.Code, timeout, req.Env, executionID)
	if err != nil {
		return nil, fmt.Errorf("executing code: %w", err)
	}

	result.ExecutionID = executionID
	result.DurationSeconds = time.Since(startTime).Seconds()

	log.WithFields(logrus.Fields{
		"exit_code": result.ExitCode,
		"duration":  result.DurationSeconds,
	}).Debug("Ephemeral execution completed")

	return result, nil
}

// executeWithNewSession creates a new session pod and executes code in it.
func (b *KubernetesBackend) executeWithNewSession(ctx context.Context, req ExecuteRequest) (*ExecutionResult, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = time.Duration(b.cfg.Timeout) * time.Second
	}

	// Generate session ID.
	sessionID := b.sessionManager.GenerateSessionID()

	log := b.log.WithFields(logrus.Fields{
		"mode":       "new-session",
		"session_id": sessionID,
	})
	log.Debug("Creating new session pod")

	// Create the session pod.
	podName := fmt.Sprintf("mcp-session-%s", sessionID)

	pod, err := b.createPod(ctx, podName, sessionID, req.OwnerID, req.Env)
	if err != nil {
		return nil, fmt.Errorf("creating session pod: %w", err)
	}

	// Wait for pod to be running.
	if err := b.waitForPodRunning(ctx, podName, 60*time.Second); err != nil {
		// Cleanup on failure.
		_ = b.deletePod(ctx, podName)

		return nil, fmt.Errorf("waiting for session pod to be running: %w", err)
	}

	// Record initial access time for TTL tracking.
	b.sessionManager.RecordAccess(sessionID)

	log.Info("Created new session")

	// Build session object for execution.
	session := &Session{
		ID:        sessionID,
		OwnerID:   req.OwnerID,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	// Execute the code in the session.
	executionID := uuid.New().String()

	result, err := b.execInPod(ctx, pod.Name, req.Code, timeout, req.Env, executionID)
	if err != nil {
		return nil, fmt.Errorf("executing in session: %w", err)
	}

	result.ExecutionID = executionID

	// Populate session info.
	result.SessionID = sessionID
	result.SessionTTLRemaining = b.sessionManager.TTLRemaining(sessionID)
	result.SessionFiles = b.collectSessionFiles(ctx, podName, session)

	return result, nil
}

// executeInSession executes code in an existing session pod.
func (b *KubernetesBackend) executeInSession(ctx context.Context, req ExecuteRequest) (*ExecutionResult, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = time.Duration(b.cfg.Timeout) * time.Second
	}

	log := b.log.WithFields(logrus.Fields{
		"mode":       "existing-session",
		"session_id": req.SessionID,
	})

	// Get the session (this also updates LastUsed and verifies ownership).
	session, err := b.sessionManager.Get(ctx, req.SessionID, req.OwnerID)
	if err != nil {
		return nil, fmt.Errorf("getting session: %w", err)
	}

	log.Debug("Executing in existing session")

	// Execute the code in the session.
	podName := fmt.Sprintf("mcp-session-%s", session.ID)
	executionID := uuid.New().String()

	result, err := b.execInPod(ctx, podName, req.Code, timeout, req.Env, executionID)
	if err != nil {
		return nil, fmt.Errorf("executing in session: %w", err)
	}

	result.ExecutionID = executionID

	// Populate session info.
	result.SessionID = session.ID
	result.SessionTTLRemaining = b.sessionManager.TTLRemaining(session.ID)
	result.SessionFiles = b.collectSessionFiles(ctx, podName, session)

	return result, nil
}

// createPod creates a new sandbox pod.
func (b *KubernetesBackend) createPod(
	ctx context.Context,
	name, sessionID, ownerID string,
	env map[string]string,
) (*corev1.Pod, error) {
	namespace := b.cfg.Kubernetes.Namespace

	// Build labels.
	labels := map[string]string{
		LabelK8sManagedBy: ManagedByValue,
		LabelK8sCreatedAt: strconv.FormatInt(time.Now().Unix(), 10),
	}

	if sessionID != "" {
		labels[LabelK8sSessionID] = sessionID
	}

	if ownerID != "" {
		labels[LabelK8sOwnerID] = ownerID
	}

	// Merge user-configured labels.
	for k, v := range b.cfg.Kubernetes.Labels {
		labels[k] = v
	}

	// Build annotations.
	annotations := map[string]string{
		AnnotationK8sDescription: "Sandbox execution pod for ethpandaops-mcp",
	}

	for k, v := range b.cfg.Kubernetes.Annotations {
		annotations[k] = v
	}

	// Build environment variables.
	containerEnv := SandboxEnvDefaults()
	for k, v := range filterSessionEnv(env) {
		containerEnv[k] = v
	}

	envVars := make([]corev1.EnvVar, 0, len(containerEnv))
	for k, v := range containerEnv {
		envVars = append(envVars, corev1.EnvVar{Name: k, Value: v})
	}

	// Parse resource limits.
	memLimit, err := resource.ParseQuantity(b.cfg.MemoryLimit)
	if err != nil {
		return nil, fmt.Errorf("parsing memory limit: %w", err)
	}

	cpuLimit := resource.MustParse(fmt.Sprintf("%dm", int(b.cfg.CPULimit*1000)))

	// Build pod spec.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			RestartPolicy:                 corev1.RestartPolicyNever,
			AutomountServiceAccountToken:  ptr(false),
			EnableServiceLinks:            ptr(false),
			TerminationGracePeriodSeconds: ptr(int64(10)),
			Containers: []corev1.Container{
				{
					Name:            SandboxContainerName,
					Image:           b.cfg.Image,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         []string{"sleep", "infinity"},
					Env:             envVars,
					WorkingDir:      "/workspace",
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: memLimit,
							corev1.ResourceCPU:    cpuLimit,
						},
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("128Mi"),
							corev1.ResourceCPU:    resource.MustParse("100m"),
						},
					},
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot:             ptr(true),
						RunAsUser:                ptr(int64(65534)), // nobody
						RunAsGroup:               ptr(int64(65534)),
						ReadOnlyRootFilesystem:   ptr(false), // Need writable for /workspace
						AllowPrivilegeEscalation: ptr(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "workspace",
							MountPath: "/workspace",
						},
						{
							Name:      "output",
							MountPath: "/output",
						},
						{
							Name:      "tmp",
							MountPath: "/tmp",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "workspace",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							SizeLimit: ptr(resource.MustParse("1Gi")),
						},
					},
				},
				{
					Name: "output",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							SizeLimit: ptr(resource.MustParse("1Gi")),
						},
					},
				},
				{
					Name: "tmp",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							SizeLimit: ptr(resource.MustParse("100Mi")),
						},
					},
				},
			},
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: ptr(true),
				RunAsUser:    ptr(int64(65534)),
				RunAsGroup:   ptr(int64(65534)),
				FSGroup:      ptr(int64(65534)),
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
		},
	}

	// Apply optional RuntimeClass.
	if b.cfg.Kubernetes.RuntimeClassName != "" {
		pod.Spec.RuntimeClassName = ptr(b.cfg.Kubernetes.RuntimeClassName)
	}

	// Apply optional ServiceAccount.
	if b.cfg.Kubernetes.ServiceAccountName != "" {
		pod.Spec.ServiceAccountName = b.cfg.Kubernetes.ServiceAccountName
	}

	// Apply optional NodeSelector.
	if len(b.cfg.Kubernetes.NodeSelector) > 0 {
		pod.Spec.NodeSelector = b.cfg.Kubernetes.NodeSelector
	}

	// Apply optional Tolerations.
	for _, t := range b.cfg.Kubernetes.Tolerations {
		toleration := corev1.Toleration{
			Key:      t.Key,
			Value:    t.Value,
			Operator: corev1.TolerationOperator(t.Operator),
			Effect:   corev1.TaintEffect(t.Effect),
		}

		if t.TolerationSeconds != nil {
			toleration.TolerationSeconds = t.TolerationSeconds
		}

		pod.Spec.Tolerations = append(pod.Spec.Tolerations, toleration)
	}

	// Create the pod.
	created, err := b.client.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("creating pod: %w", err)
	}

	return created, nil
}

// waitForPodRunning waits for a pod to be in the Running phase.
func (b *KubernetesBackend) waitForPodRunning(ctx context.Context, name string, timeout time.Duration) error {
	namespace := b.cfg.Kubernetes.Namespace

	deadline := time.Now().Add(timeout)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for pod %s to be running", name)
		}

		pod, err := b.client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("getting pod: %w", err)
		}

		switch pod.Status.Phase {
		case corev1.PodRunning:
			// Check container is ready.
			for _, cs := range pod.Status.ContainerStatuses {
				if cs.Name == SandboxContainerName && cs.Ready {
					return nil
				}
			}
		case corev1.PodFailed, corev1.PodSucceeded:
			return fmt.Errorf("pod %s is in terminal phase: %s", name, pod.Status.Phase)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
			// Continue polling.
		}
	}
}

// execInPod executes Python code inside a running pod.
func (b *KubernetesBackend) execInPod(
	ctx context.Context,
	podName, code string,
	timeout time.Duration,
	env map[string]string,
	executionID string,
) (*ExecutionResult, error) {
	startTime := time.Now()

	log := b.log.WithFields(logrus.Fields{
		"pod":          podName,
		"execution_id": executionID,
	})

	// Create execution context with timeout.
	execCtx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()

	// Write the script to the pod.
	scriptPath := fmt.Sprintf("/tmp/script_%s.py", executionID)

	writeCmd := []string{"sh", "-c", fmt.Sprintf("cat > %s << 'MCP_EOF'\n%s\nMCP_EOF", scriptPath, code)}

	if err := b.execCommand(execCtx, podName, writeCmd, nil); err != nil {
		return nil, fmt.Errorf("writing script to pod: %w", err)
	}

	// Build environment variables for execution.
	execEnv := make([]string, 0, len(env)+1)
	for k, v := range env {
		if k == "ETHPANDAOPS_EXECUTION_ID" {
			continue
		}

		execEnv = append(execEnv, fmt.Sprintf("%s=%s", k, v))
	}

	execEnv = append(execEnv, fmt.Sprintf("ETHPANDAOPS_EXECUTION_ID=%s", executionID))

	// Execute the script.
	pythonCmd := []string{"python", scriptPath}
	stdout, stderr, exitCode, err := b.execCommandWithOutput(execCtx, podName, pythonCmd, execEnv)

	if err != nil {
		// Check if it's a timeout.
		if execCtx.Err() == context.DeadlineExceeded {
			log.Warn("Execution timed out")

			// Cleanup script file.
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()

			_ = b.execCommand(cleanupCtx, podName, []string{"rm", "-f", scriptPath}, nil)

			return nil, fmt.Errorf("execution timed out after %s", timeout)
		}

		return nil, fmt.Errorf("executing script: %w", err)
	}

	duration := time.Since(startTime).Seconds()

	// Cleanup script file.
	_ = b.execCommand(ctx, podName, []string{"rm", "-f", scriptPath}, nil)

	log.WithFields(logrus.Fields{
		"exit_code": exitCode,
		"duration":  duration,
	}).Debug("Execution completed")

	return &ExecutionResult{
		Stdout:          stdout,
		Stderr:          stderr,
		ExitCode:        exitCode,
		DurationSeconds: duration,
	}, nil
}

// execCommand runs a command in a pod without capturing output.
func (b *KubernetesBackend) execCommand(ctx context.Context, podName string, cmd, env []string) error {
	_, _, _, err := b.execCommandWithOutput(ctx, podName, cmd, env)

	return err
}

// execCommandWithOutput runs a command in a pod and captures output.
func (b *KubernetesBackend) execCommandWithOutput(
	ctx context.Context,
	podName string,
	cmd, env []string,
) (stdout, stderr string, exitCode int, err error) {
	namespace := b.cfg.Kubernetes.Namespace

	execOpts := &corev1.PodExecOptions{
		Container: SandboxContainerName,
		Command:   cmd,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}

	req := b.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(execOpts, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(b.config, "POST", req.URL())
	if err != nil {
		return "", "", -1, fmt.Errorf("creating executor: %w", err)
	}

	var stdoutBuf, stderrBuf bytes.Buffer

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdoutBuf,
		Stderr: &stderrBuf,
	})

	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if err != nil {
		// Try to extract exit code from error.
		if exitErr, ok := err.(interface{ ExitStatus() int }); ok {
			return stdout, stderr, exitErr.ExitStatus(), nil
		}

		// Check for exec.CodeExitError.
		if strings.Contains(err.Error(), "command terminated with exit code") {
			var code int
			if _, scanErr := fmt.Sscanf(err.Error(), "command terminated with exit code %d", &code); scanErr == nil {
				return stdout, stderr, code, nil
			}
		}

		return stdout, stderr, -1, err
	}

	return stdout, stderr, 0, nil
}

// collectSessionFiles lists files in the session's /workspace directory.
func (b *KubernetesBackend) collectSessionFiles(ctx context.Context, podName string, _ *Session) []SessionFile {
	cmd := []string{"find", "/workspace", "-maxdepth", "1", "-type", "f", "-printf", "%f\\t%s\\t%T@\\n"}

	stdout, _, _, err := b.execCommandWithOutput(ctx, podName, cmd, nil)
	if err != nil {
		b.log.WithError(err).Debug("Failed to list session files")

		return nil
	}

	files := make([]SessionFile, 0)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			continue
		}

		var size int64
		var modTime float64

		if _, err := fmt.Sscanf(parts[1], "%d", &size); err != nil {
			continue
		}

		if _, err := fmt.Sscanf(parts[2], "%f", &modTime); err != nil {
			continue
		}

		files = append(files, SessionFile{
			Name:     parts[0],
			Size:     size,
			Modified: time.Unix(int64(modTime), 0),
		})
	}

	return files
}

// deletePod deletes a pod by name.
func (b *KubernetesBackend) deletePod(ctx context.Context, name string) error {
	namespace := b.cfg.Kubernetes.Namespace

	err := b.client.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{
		GracePeriodSeconds: ptr(int64(0)),
	})

	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting pod %s: %w", name, err)
	}

	return nil
}

// getSessionPod queries Kubernetes for a session pod by session ID.
func (b *KubernetesBackend) getSessionPod(ctx context.Context, sessionID string) (*SessionContainer, error) {
	if b.client == nil {
		return nil, fmt.Errorf("kubernetes client not initialized")
	}

	namespace := b.cfg.Kubernetes.Namespace
	labelSelector := fmt.Sprintf("%s=%s,%s=%s", LabelK8sManagedBy, ManagedByValue, LabelK8sSessionID, sessionID)

	pods, err := b.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, nil
	}

	pod := pods.Items[0]

	// Check if pod is still running.
	if pod.Status.Phase != corev1.PodRunning {
		return nil, nil
	}

	createdAt := parseK8sCreatedAt(pod.Labels, pod.CreationTimestamp.Time)

	return &SessionContainer{
		ContainerID: pod.Name, // Use pod name as container ID.
		SessionID:   sessionID,
		OwnerID:     pod.Labels[LabelK8sOwnerID],
		CreatedAt:   createdAt,
	}, nil
}

// listAllSessionPods queries Kubernetes for all session pods.
func (b *KubernetesBackend) listAllSessionPods(ctx context.Context) ([]*SessionContainer, error) {
	if b.client == nil {
		return nil, fmt.Errorf("kubernetes client not initialized")
	}

	namespace := b.cfg.Kubernetes.Namespace
	labelSelector := fmt.Sprintf("%s=%s,%s", LabelK8sManagedBy, ManagedByValue, LabelK8sSessionID)

	pods, err := b.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	result := make([]*SessionContainer, 0, len(pods.Items))

	for _, pod := range pods.Items {
		sessionID := pod.Labels[LabelK8sSessionID]
		if sessionID == "" {
			continue
		}

		// Only include running pods.
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}

		createdAt := parseK8sCreatedAt(pod.Labels, pod.CreationTimestamp.Time)

		result = append(result, &SessionContainer{
			ContainerID: pod.Name,
			SessionID:   sessionID,
			OwnerID:     pod.Labels[LabelK8sOwnerID],
			CreatedAt:   createdAt,
		})
	}

	return result, nil
}

// parseK8sCreatedAt extracts the creation time from pod labels.
func parseK8sCreatedAt(labels map[string]string, k8sCreated time.Time) time.Time {
	if createdAtStr, ok := labels[LabelK8sCreatedAt]; ok {
		if createdAtUnix, err := strconv.ParseInt(createdAtStr, 10, 64); err == nil {
			return time.Unix(createdAtUnix, 0)
		}
	}

	return k8sCreated
}

// ListSessions returns all active sessions.
func (b *KubernetesBackend) ListSessions(ctx context.Context, ownerID string) ([]SessionInfo, error) {
	if b.client == nil {
		return nil, fmt.Errorf("kubernetes client not initialized")
	}

	if !b.sessionManager.Enabled() {
		return nil, fmt.Errorf("sessions are disabled")
	}

	pods, err := b.listAllSessionPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing session pods: %w", err)
	}

	sessions := make([]SessionInfo, 0, len(pods))

	for _, p := range pods {
		// Filter by owner if specified.
		if ownerID != "" && p.OwnerID != "" && p.OwnerID != ownerID {
			continue
		}

		// Get last used time from session manager.
		lastUsed := b.sessionManager.GetLastUsed(p.SessionID)
		if lastUsed.IsZero() {
			lastUsed = p.CreatedAt
		}

		// Collect workspace files.
		podName := fmt.Sprintf("mcp-session-%s", p.SessionID)
		workspaceFiles := b.collectSessionFiles(ctx, podName, nil)

		sessions = append(sessions, SessionInfo{
			ID:             p.SessionID,
			CreatedAt:      p.CreatedAt,
			LastUsed:       lastUsed,
			TTLRemaining:   b.sessionManager.TTLRemaining(p.SessionID),
			WorkspaceFiles: workspaceFiles,
		})
	}

	return sessions, nil
}

// CreateSession creates a new empty session and returns its ID.
func (b *KubernetesBackend) CreateSession(ctx context.Context, ownerID string, env map[string]string) (string, error) {
	if b.client == nil {
		return "", fmt.Errorf("kubernetes client not initialized")
	}

	if !b.sessionManager.Enabled() {
		return "", fmt.Errorf("sessions are disabled")
	}

	// Check if we can create a new session.
	canCreate, count, maxAllowed := b.sessionManager.CanCreateSession(ctx, ownerID)
	if !canCreate {
		return "", fmt.Errorf(
			"maximum sessions limit reached (%d/%d). Use manage_session with operation 'list' to see sessions, then 'destroy' to free up a slot",
			count, maxAllowed,
		)
	}

	// Generate session ID.
	sessionID := b.sessionManager.GenerateSessionID()
	podName := fmt.Sprintf("mcp-session-%s", sessionID)

	log := b.log.WithFields(logrus.Fields{
		"session_id": sessionID,
		"owner_id":   ownerID,
	})
	log.Debug("Creating new session")

	// Create the session pod.
	_, err := b.createPod(ctx, podName, sessionID, ownerID, env)
	if err != nil {
		return "", fmt.Errorf("creating session pod: %w", err)
	}

	// Wait for pod to be running.
	if err := b.waitForPodRunning(ctx, podName, 60*time.Second); err != nil {
		_ = b.deletePod(ctx, podName)

		return "", fmt.Errorf("waiting for session pod: %w", err)
	}

	// Record initial access time for TTL tracking.
	b.sessionManager.RecordAccess(sessionID)

	log.Info("Created new session")

	return sessionID, nil
}

// DestroySession destroys a session by ID.
func (b *KubernetesBackend) DestroySession(ctx context.Context, sessionID, ownerID string) error {
	if b.client == nil {
		return fmt.Errorf("kubernetes client not initialized")
	}

	if !b.sessionManager.Enabled() {
		return fmt.Errorf("sessions are disabled")
	}

	return b.sessionManager.Destroy(ctx, sessionID, ownerID)
}

// CanCreateSession checks if a new session can be created.
func (b *KubernetesBackend) CanCreateSession(ctx context.Context, ownerID string) (bool, int, int) {
	if !b.sessionManager.Enabled() {
		return false, 0, 0
	}

	return b.sessionManager.CanCreateSession(ctx, ownerID)
}

// SessionsEnabled returns whether sessions are enabled.
func (b *KubernetesBackend) SessionsEnabled() bool {
	return b.sessionManager.Enabled()
}

// cleanupExpiredPods removes sandbox pods that have exceeded max session duration.
func (b *KubernetesBackend) cleanupExpiredPods(ctx context.Context) error {
	namespace := b.cfg.Kubernetes.Namespace
	labelSelector := fmt.Sprintf("%s=%s", LabelK8sManagedBy, ManagedByValue)

	pods, err := b.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("listing managed pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil
	}

	maxAge := b.cfg.Sessions.MaxDuration
	if maxAge == 0 {
		maxAge = 4 * time.Hour
	}

	now := time.Now()
	var cleaned int

	for _, pod := range pods.Items {
		createdAt := parseK8sCreatedAt(pod.Labels, pod.CreationTimestamp.Time)
		if now.Sub(createdAt) <= maxAge {
			continue
		}

		sessionID := pod.Labels[LabelK8sSessionID]
		ownerID := pod.Labels[LabelK8sOwnerID]

		b.log.WithFields(logrus.Fields{
			"pod":        pod.Name,
			"session_id": sessionID,
			"owner_id":   ownerID,
		}).Info("Removing expired orphaned pod")

		if err := b.deletePod(ctx, pod.Name); err != nil {
			b.log.WithFields(logrus.Fields{
				"pod":   pod.Name,
				"error": err,
			}).Warn("Failed to remove expired pod")

			continue
		}

		cleaned++
	}

	if cleaned > 0 {
		b.log.WithField("count", cleaned).Info("Cleaned up expired orphaned pods")
	}

	return nil
}

// trackExecution adds an execution to the active executions map.
func (b *KubernetesBackend) trackExecution(executionID, podName string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.activeExecutions[executionID] = podName
}

// untrackExecution removes an execution from the active executions map.
func (b *KubernetesBackend) untrackExecution(executionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.activeExecutions, executionID)
}

// ptr returns a pointer to the given value.
func ptr[T any](v T) *T {
	return &v
}

// Compile-time interface compliance check.
var _ Service = (*KubernetesBackend)(nil)
