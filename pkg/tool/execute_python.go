package tool

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ethpandaops/xatu-mcp/pkg/auth"
	"github.com/ethpandaops/xatu-mcp/pkg/config"
	"github.com/ethpandaops/xatu-mcp/pkg/sandbox"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

const (
	// ExecutePythonToolName is the name of the execute_python tool.
	ExecutePythonToolName = "execute_python"
	// DefaultTimeout is the default execution timeout in seconds.
	DefaultTimeout = 60
	// MaxTimeout is the maximum allowed execution timeout in seconds.
	MaxTimeout = 300
	// MinTimeout is the minimum allowed execution timeout in seconds.
	MinTimeout = 1
)

// executePythonDescription is the detailed description of the execute_python tool.
const executePythonDescription = `Execute Python code in a sandboxed environment.

The xatu library is pre-installed for querying Ethereum network data via Grafana:

` + "```python" + `
from xatu import clickhouse, prometheus, loki, storage

# First, list available datasources
datasources = clickhouse.list_datasources()  # Returns available ClickHouse datasources

# Query ClickHouse via Grafana proxy (datasource_uid, sql)
df = clickhouse.query("datasource-uid", "SELECT * FROM beacon_api_eth_v1_events_block LIMIT 10")

# Query Prometheus via Grafana proxy
result = prometheus.query("datasource-uid", "up")

# Query Loki via Grafana proxy
logs = loki.query("datasource-uid", '{app="beacon-node"}', limit=100)

# Generate and save charts
import matplotlib.pyplot as plt
plt.figure(figsize=(10, 6))
plt.plot(df['slot'], df['block_root'])
plt.savefig('/output/chart.png')

# Upload to get a URL
url = storage.upload('/output/chart.png')
print(f"Chart: {url}")
` + "```" + `

Use the datasources://list resource to discover available datasources and their UIDs.

## Sessions (Persistent Workspaces)

When sessions are enabled, the execution environment persists between calls:
- Files written to /workspace/ persist across executions in the same session
- The first execution returns a session_id in the response that can be reused
- Sessions auto-expire after inactivity (default: 10 minutes)

Example workflow:
1. First call (no session_id): Query data and save to /workspace/
2. Response includes session_id (e.g., "abc123")
3. Second call with session_id="abc123": Files from step 1 are available

` + "```python" + `
# In first execution - save data to workspace
df = clickhouse.query("datasource-uid", "SELECT * FROM ... LIMIT 1000")
df.to_parquet('/workspace/data.parquet')
print("Data saved!")

# In second execution (pass session_id from first response) - data persists
import pandas as pd
df = pd.read_parquet('/workspace/data.parquet')  # File exists!
print(f"Loaded {len(df)} rows")
` + "```" + `

All output files should be written to /output/ directory.
Data stays in the sandbox - Claude only sees stdout, file metadata, and URLs.`

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
						"description": "Execution timeout in seconds (default: from config, max: 300)",
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
		env := buildSandboxEnv(cfg)

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
		response := formatExecutionResult(result)

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
func formatExecutionResult(result *sandbox.ExecutionResult) string {
	var parts []string

	if result.Stdout != "" {
		parts = append(parts, fmt.Sprintf("=== STDOUT ===\n%s", result.Stdout))
	}

	if result.Stderr != "" {
		parts = append(parts, fmt.Sprintf("=== STDERR ===\n%s", result.Stderr))
	}

	if len(result.OutputFiles) > 0 {
		filesList := make([]string, 0, len(result.OutputFiles))
		for _, f := range result.OutputFiles {
			filesList = append(filesList, fmt.Sprintf("  - %s", f))
		}

		parts = append(parts,
			fmt.Sprintf("=== OUTPUT FILES ===\n%s\n"+
				"Note: Use storage.upload('/output/filename') in code to get URLs",
				strings.Join(filesList, "\n")),
		)
	}

	// Include session info if available.
	if result.SessionID != "" {
		sessionInfo := fmt.Sprintf("=== SESSION ===\nSession ID: %s\nTTL Remaining: %s",
			result.SessionID, result.SessionTTLRemaining.Round(time.Second))

		if len(result.SessionFiles) > 0 {
			sessionInfo += "\nWorkspace Files:"

			for _, f := range result.SessionFiles {
				sessionInfo += fmt.Sprintf("\n  - %s (%s, modified %s)",
					f.Name, formatSize(f.Size), f.Modified.Format(time.RFC3339))
			}
		}

		sessionInfo += "\n\nTip: Pass session_id in subsequent calls to reuse this session"
		parts = append(parts, sessionInfo)
	}

	parts = append(parts, fmt.Sprintf("=== EXIT CODE: %d ===", result.ExitCode))
	parts = append(parts, fmt.Sprintf("=== EXECUTION ID: %s ===", result.ExecutionID))
	parts = append(parts, fmt.Sprintf("=== DURATION: %.2fs ===", result.DurationSeconds))

	return strings.Join(parts, "\n\n")
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
func buildSandboxEnv(cfg *config.Config) map[string]string {
	env := make(map[string]string, 8)

	// Grafana configuration - all datasource queries route through Grafana.
	env["XATU_GRAFANA_URL"] = cfg.Grafana.URL
	env["XATU_GRAFANA_TOKEN"] = cfg.Grafana.ServiceToken
	env["XATU_HTTP_TIMEOUT"] = strconv.Itoa(cfg.Grafana.Timeout)

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

	return env
}
