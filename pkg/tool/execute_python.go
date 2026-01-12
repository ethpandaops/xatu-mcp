package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethpandaops/xatu-mcp/pkg/auth"
	"github.com/ethpandaops/xatu-mcp/pkg/config"
	"github.com/ethpandaops/xatu-mcp/pkg/sandbox"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

const (
	// resourceTipCacheMaxSize is the maximum number of entries in the resource tip cache.
	resourceTipCacheMaxSize = 1000
	// resourceTipCacheMaxAge is the maximum age of entries in the resource tip cache.
	resourceTipCacheMaxAge = 4 * time.Hour
)

// resourceTipCache tracks sessions that have already seen the resource tip.
// It's a bounded cache with automatic cleanup of old entries.
type resourceTipCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

var sessionsWithResourceTip = &resourceTipCache{
	entries: make(map[string]time.Time, 64),
}

// markShown marks a session as having seen the resource tip.
// Returns true if this is the first time the session has seen the tip.
func (c *resourceTipCache) markShown(sessionKey string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already shown.
	if _, exists := c.entries[sessionKey]; exists {
		return false
	}

	// Clean up old entries if cache is too large.
	if len(c.entries) >= resourceTipCacheMaxSize {
		c.cleanupLocked()
	}

	c.entries[sessionKey] = time.Now()

	return true
}

// cleanupLocked removes entries older than resourceTipCacheMaxAge.
// Must be called with mu held.
func (c *resourceTipCache) cleanupLocked() {
	cutoff := time.Now().Add(-resourceTipCacheMaxAge)

	for key, ts := range c.entries {
		if ts.Before(cutoff) {
			delete(c.entries, key)
		}
	}
}

// resourceTipMessage is shown after the first execution in a session to guide users to MCP resources.
const resourceTipMessage = `
TIP: Read these MCP resources for available datasources and schemas:
   - datasources://list - available datasources by type
   - datasources://clickhouse - ClickHouse clusters only
   - clickhouse://tables - list all tables (if schema discovery enabled)
   - clickhouse://tables/{table} - table schema details
   - api://xatu - Python library documentation
   - networks://active - available networks`

const (
	// ExecutePythonToolName is the name of the execute_python tool.
	ExecutePythonToolName = "execute_python"
	// DefaultTimeout is the default execution timeout in seconds.
	DefaultTimeout = 60
	// MaxTimeout is the maximum allowed execution timeout in seconds.
	// This matches config.MaxSandboxTimeout.
	MaxTimeout = 600
	// MinTimeout is the minimum allowed execution timeout in seconds.
	MinTimeout = 1
)

// executePythonDescription is the description of the execute_python tool.
const executePythonDescription = `Execute Python code in a sandboxed environment with the xatu library pre-installed.

Read xatu://getting-started first, then api://xatu for library docs, datasources://clickhouse for UIDs.

Key modules: clickhouse, prometheus, loki, storage

**Sessions**: Files in /workspace/ persist across calls within a session. Pass the session_id from responses to continue a session. Sessions expire after inactivity - check the ttl in responses. For important outputs, use storage.upload() immediately to get a permanent URL.

**Output**: Response includes [session] id=X ttl=Xm showing remaining session time.`

// NewExecutePythonTool creates the execute_python tool definition.
func NewExecutePythonTool(
	log logrus.FieldLogger,
	sandboxSvc sandbox.Service,
	cfg *config.Config,
) Definition {
	return Definition{
		Tool: mcp.Tool{
			Name:        ExecutePythonToolName,
			Description: executePythonDescription,
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"code": map[string]any{
						"type":        "string",
						"description": "Python code to execute",
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "Execution timeout in seconds (default: from config, max: 600)",
						"minimum":     MinTimeout,
						"maximum":     MaxTimeout,
					},
					"session_id": map[string]any{
						"type":        "string",
						"description": "Optional session ID to reuse a persistent container. If omitted, a new session is created (when sessions are enabled).",
					},
				},
				Required: []string{"code"},
			},
		},
		Handler: newExecutePythonHandler(log, sandboxSvc, cfg),
	}
}

// newExecutePythonHandler creates the handler function for execute_python.
func newExecutePythonHandler(
	log logrus.FieldLogger,
	sandboxSvc sandbox.Service,
	cfg *config.Config,
) Handler {
	handlerLog := log.WithField("tool", ExecutePythonToolName)

	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract code from arguments using mcp-go helper methods.
		code, err := request.RequireString("code")
		if err != nil {
			return CallToolError(fmt.Errorf("invalid arguments: %w", err)), nil
		}

		if code == "" {
			return CallToolError(fmt.Errorf("code is required")), nil
		}

		// Extract timeout from arguments using mcp-go helper with default.
		timeout := request.GetInt("timeout", cfg.Sandbox.Timeout)

		// Validate timeout.
		if timeout < MinTimeout || timeout > MaxTimeout {
			return CallToolError(
				fmt.Errorf("timeout must be between %d and %d seconds", MinTimeout, MaxTimeout),
			), nil
		}

		// Extract optional session_id.
		sessionID := request.GetString("session_id", "")

		// Extract owner ID from auth context for session binding.
		var ownerID string
		if user := auth.GetAuthUser(ctx); user != nil {
			ownerID = fmt.Sprintf("%d", user.GitHubID)
		}

		handlerLog.WithFields(logrus.Fields{
			"code_length": len(code),
			"timeout":     timeout,
			"backend":     sandboxSvc.Name(),
			"session_id":  sessionID,
			"owner_id":    ownerID,
		}).Info("Executing Python code")

		// Build environment variables for the sandbox.
		env, err := buildSandboxEnv(cfg)
		if err != nil {
			handlerLog.WithError(err).Error("Failed to build sandbox environment")

			return CallToolError(fmt.Errorf("failed to configure sandbox: %w", err)), nil
		}

		// Execute the code in the sandbox.
		result, err := sandboxSvc.Execute(ctx, sandbox.ExecuteRequest{
			Code:      code,
			Env:       env,
			Timeout:   time.Duration(timeout) * time.Second,
			SessionID: sessionID,
			OwnerID:   ownerID,
		})
		if err != nil {
			handlerLog.WithError(err).Error("Execution failed")

			return CallToolError(fmt.Errorf("execution error: %w", err)), nil
		}

		// Format the response.
		response := formatExecutionResult(result, cfg)

		// Show resource tip after the first execution in a session.
		sessionKey := result.SessionID
		if sessionKey == "" {
			sessionKey = result.ExecutionID // Use execution ID if no session
		}

		if sessionsWithResourceTip.markShown(sessionKey) {
			response += resourceTipMessage
		}

		handlerLog.WithFields(logrus.Fields{
			"execution_id": result.ExecutionID,
			"exit_code":    result.ExitCode,
			"duration":     result.DurationSeconds,
			"output_files": result.OutputFiles,
			"session_id":   result.SessionID,
		}).Info("Execution completed")

		return CallToolSuccess(response), nil
	}
}

// formatExecutionResult formats the execution result into a string.
func formatExecutionResult(result *sandbox.ExecutionResult, cfg *config.Config) string {
	var parts []string

	if result.Stdout != "" {
		parts = append(parts, fmt.Sprintf("[stdout]\n%s", result.Stdout))
	}

	if result.Stderr != "" {
		parts = append(parts, fmt.Sprintf("[stderr]\n%s", result.Stderr))
	}

	if len(result.OutputFiles) > 0 {
		parts = append(parts, fmt.Sprintf("[files] %s", strings.Join(result.OutputFiles, ", ")))
	}

	// Include session info if available.
	if result.SessionID != "" {
		sessionInfo := fmt.Sprintf("[session] id=%s ttl=%s",
			result.SessionID, result.SessionTTLRemaining.Round(time.Second))

		if len(result.SessionFiles) > 0 {
			workspaceFiles := make([]string, 0, len(result.SessionFiles))
			for _, f := range result.SessionFiles {
				workspaceFiles = append(workspaceFiles, fmt.Sprintf("%s(%s)", f.Name, formatSize(f.Size)))
			}

			sessionInfo += fmt.Sprintf(" workspace=[%s]", strings.Join(workspaceFiles, ", "))
		}

		parts = append(parts, sessionInfo)
	}

	parts = append(parts, fmt.Sprintf("[exit=%d duration=%.2fs id=%s]",
		result.ExitCode, result.DurationSeconds, result.ExecutionID))

	// Add note about localhost URLs if storage is configured with localhost.
	if cfg.Storage != nil && strings.Contains(cfg.Storage.PublicURLPrefix, "localhost") {
		if strings.Contains(result.Stdout, "localhost") {
			parts = append(parts, "[note] Storage URLs use localhost - these are accessible to the user.")
		}
	}

	return strings.Join(parts, "\n")
}

// formatSize formats a byte size into a human-readable string.
func formatSize(bytes int64) string {
	const unit = 1024

	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// buildSandboxEnv creates the environment variables map for the sandbox.
func buildSandboxEnv(cfg *config.Config) (map[string]string, error) {
	env := make(map[string]string, 8)

	// ClickHouse configs as JSON array.
	if len(cfg.ClickHouse) > 0 {
		chConfigs, err := json.Marshal(cfg.ClickHouse)
		if err != nil {
			return nil, fmt.Errorf("marshaling ClickHouse configs: %w", err)
		}

		env["XATU_CLICKHOUSE_CONFIGS"] = string(chConfigs)
	}

	// Prometheus configs as JSON array.
	if len(cfg.Prometheus) > 0 {
		promConfigs, err := json.Marshal(cfg.Prometheus)
		if err != nil {
			return nil, fmt.Errorf("marshaling Prometheus configs: %w", err)
		}

		env["XATU_PROMETHEUS_CONFIGS"] = string(promConfigs)
	}

	// Loki configs as JSON array.
	if len(cfg.Loki) > 0 {
		lokiConfigs, err := json.Marshal(cfg.Loki)
		if err != nil {
			return nil, fmt.Errorf("marshaling Loki configs: %w", err)
		}

		env["XATU_LOKI_CONFIGS"] = string(lokiConfigs)
	}

	// S3 Storage.
	if cfg.Storage != nil {
		env["XATU_S3_ENDPOINT"] = cfg.Storage.Endpoint
		env["XATU_S3_ACCESS_KEY"] = cfg.Storage.AccessKey
		env["XATU_S3_SECRET_KEY"] = cfg.Storage.SecretKey
		env["XATU_S3_BUCKET"] = cfg.Storage.Bucket
		env["XATU_S3_REGION"] = cfg.Storage.Region

		if cfg.Storage.PublicURLPrefix != "" {
			env["XATU_S3_PUBLIC_URL_PREFIX"] = cfg.Storage.PublicURLPrefix
		}
	}

	return env, nil
}
