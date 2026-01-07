package tool

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ethpandaops/xatu-mcp/pkg/config"
	"github.com/ethpandaops/xatu-mcp/pkg/sandbox"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

const (
	// ExecutePythonToolName is the name of the execute_python tool.
	ExecutePythonToolName = "execute_python"
	// ExecutePythonScope is the required OAuth scope for this tool.
	ExecutePythonScope = "execute_python"
	// DefaultTimeout is the default execution timeout in seconds.
	DefaultTimeout = 60
	// MaxTimeout is the maximum allowed execution timeout in seconds.
	MaxTimeout = 300
	// MinTimeout is the minimum allowed execution timeout in seconds.
	MinTimeout = 1
)

// executePythonDescription is the detailed description of the execute_python tool.
const executePythonDescription = `Execute Python code in a sandboxed environment.

The xatu library is pre-installed for querying Ethereum network data:

` + "```python" + `
from xatu import clickhouse, prometheus, loki, storage

# Query ClickHouse for blockchain data
df = clickhouse.query("mainnet", "SELECT * FROM beacon_api_eth_v1_events_block LIMIT 10")

# Query Prometheus metrics
result = prometheus.query("up")

# Generate and save charts
import matplotlib.pyplot as plt
plt.figure(figsize=(10, 6))
plt.plot(df['slot'], df['block_root'])
plt.savefig('/output/chart.png')

# Upload to get a URL
url = storage.upload('/output/chart.png')
print(f"Chart: {url}")
` + "```" + `

Available ClickHouse clusters:
- "xatu": Production raw data (mainnet, sepolia, holesky, hoodi)
- "xatu-experimental": Devnet raw data
- "xatu-cbt": Aggregated/CBT tables

All output files should be written to /output/ directory.
Data stays in the sandbox - Claude only sees stdout and file URLs.`

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
				},
				Required: []string{"code"},
			},
		},
		Handler: newExecutePythonHandler(log, sandboxSvc, cfg),
		Scope:   ExecutePythonScope,
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

		handlerLog.WithFields(logrus.Fields{
			"code_length": len(code),
			"timeout":     timeout,
			"backend":     sandboxSvc.Name(),
		}).Info("Executing Python code")

		// Build environment variables for the sandbox.
		env := buildSandboxEnv(cfg)

		// Execute the code in the sandbox.
		result, err := sandboxSvc.Execute(ctx, sandbox.ExecuteRequest{
			Code:    code,
			Env:     env,
			Timeout: time.Duration(timeout) * time.Second,
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

	parts = append(parts, fmt.Sprintf("=== EXIT CODE: %d ===", result.ExitCode))
	parts = append(parts, fmt.Sprintf("=== EXECUTION ID: %s ===", result.ExecutionID))
	parts = append(parts, fmt.Sprintf("=== DURATION: %.2fs ===", result.DurationSeconds))

	return strings.Join(parts, "\n\n")
}

// buildSandboxEnv creates the environment variables map for the sandbox.
func buildSandboxEnv(cfg *config.Config) map[string]string {
	env := make(map[string]string, 32)

	// ClickHouse clusters.
	if cfg.ClickHouse.Xatu != nil {
		env["XATU_CLICKHOUSE_HOST"] = cfg.ClickHouse.Xatu.Host
		env["XATU_CLICKHOUSE_PORT"] = fmt.Sprintf("%d", cfg.ClickHouse.Xatu.Port)
		env["XATU_CLICKHOUSE_PROTOCOL"] = cfg.ClickHouse.Xatu.Protocol
		env["XATU_CLICKHOUSE_USER"] = cfg.ClickHouse.Xatu.User
		env["XATU_CLICKHOUSE_PASSWORD"] = cfg.ClickHouse.Xatu.Password
		env["XATU_CLICKHOUSE_DATABASE"] = cfg.ClickHouse.Xatu.Database
	}

	if cfg.ClickHouse.XatuExperimental != nil {
		env["XATU_EXPERIMENTAL_CLICKHOUSE_HOST"] = cfg.ClickHouse.XatuExperimental.Host
		env["XATU_EXPERIMENTAL_CLICKHOUSE_PORT"] = fmt.Sprintf("%d", cfg.ClickHouse.XatuExperimental.Port)
		env["XATU_EXPERIMENTAL_CLICKHOUSE_PROTOCOL"] = cfg.ClickHouse.XatuExperimental.Protocol
		env["XATU_EXPERIMENTAL_CLICKHOUSE_USER"] = cfg.ClickHouse.XatuExperimental.User
		env["XATU_EXPERIMENTAL_CLICKHOUSE_PASSWORD"] = cfg.ClickHouse.XatuExperimental.Password
		env["XATU_EXPERIMENTAL_CLICKHOUSE_DATABASE"] = cfg.ClickHouse.XatuExperimental.Database
	}

	if cfg.ClickHouse.XatuCBT != nil {
		env["XATU_CBT_CLICKHOUSE_HOST"] = cfg.ClickHouse.XatuCBT.Host
		env["XATU_CBT_CLICKHOUSE_PORT"] = fmt.Sprintf("%d", cfg.ClickHouse.XatuCBT.Port)
		env["XATU_CBT_CLICKHOUSE_PROTOCOL"] = cfg.ClickHouse.XatuCBT.Protocol
		env["XATU_CBT_CLICKHOUSE_USER"] = cfg.ClickHouse.XatuCBT.User
		env["XATU_CBT_CLICKHOUSE_PASSWORD"] = cfg.ClickHouse.XatuCBT.Password
		env["XATU_CBT_CLICKHOUSE_DATABASE"] = cfg.ClickHouse.XatuCBT.Database
	}

	// Prometheus.
	if cfg.Prometheus != nil {
		env["XATU_PROMETHEUS_URL"] = cfg.Prometheus.URL
	}

	// Loki.
	if cfg.Loki != nil {
		env["XATU_LOKI_URL"] = cfg.Loki.URL
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

	return env
}
