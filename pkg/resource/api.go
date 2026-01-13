package resource

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

// FunctionDoc describes a function in the xatu library.
type FunctionDoc struct {
	Signature   string            `json:"signature"`
	Description string            `json:"description"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	Returns     string            `json:"returns,omitempty"`
	Example     string            `json:"example,omitempty"`
}

// ModuleDoc describes a module in the xatu library.
type ModuleDoc struct {
	Description string                 `json:"description"`
	Functions   map[string]FunctionDoc `json:"functions"`
}

// APIOverview describes the xatu library overview.
type APIOverview struct {
	Description string `json:"description"`
	Import      string `json:"import"`
}

// xatuAPIDocs contains the API documentation for the xatu Python library.
//
//nolint:lll // Examples and descriptions are naturally long.
var xatuAPIDocs = struct {
	Overview APIOverview          `json:"overview"`
	Modules  map[string]ModuleDoc `json:"modules"`
}{
	Overview: APIOverview{
		Description: "Python library for querying Ethereum data. Pre-installed in the sandbox. For query examples, use the search_examples tool or read examples://queries.",
		Import:      "from xatu import clickhouse, prometheus, loki, storage",
	},
	Modules: map[string]ModuleDoc{
		"clickhouse": {
			Description: "Query ClickHouse databases for Ethereum blockchain data. Use search_examples tool for query patterns.",
			Functions: map[string]FunctionDoc{
				"list_datasources": {
					Signature:   "clickhouse.list_datasources() -> list[dict]",
					Description: "List available ClickHouse clusters. Prefer datasources://clickhouse resource instead.",
					Returns:     "List of dicts with 'name', 'description', 'database' keys",
				},
				"query": {
					Signature:   "clickhouse.query(cluster: str, sql: str) -> pandas.DataFrame",
					Description: "Execute SQL query, return DataFrame",
					Parameters: map[string]string{
						"cluster": "'xatu' or 'xatu-cbt' - see xatu://getting-started for syntax differences",
						"sql":     "SQL query string",
					},
					Returns: "pandas.DataFrame",
				},
				"query_raw": {
					Signature:   "clickhouse.query_raw(cluster: str, sql: str) -> tuple[list[tuple], list[str]]",
					Description: "Execute SQL query, return raw tuples",
					Parameters: map[string]string{
						"cluster": "'xatu' or 'xatu-cbt'",
						"sql":     "SQL query string",
					},
					Returns: "(rows, column_names)",
				},
			},
		},
		"prometheus": {
			Description: "Query Prometheus metrics",
			Functions: map[string]FunctionDoc{
				"list_datasources": {
					Signature:   "prometheus.list_datasources() -> list[dict]",
					Description: "List available Prometheus datasources. Prefer datasources://prometheus resource.",
					Returns:     "List of dicts with 'name', 'description', 'url' keys",
				},
				"query": {
					Signature:   "prometheus.query(datasource: str, promql: str, time: str = None) -> dict",
					Description: "Execute instant PromQL query",
					Parameters: map[string]string{
						"datasource": "Datasource name from datasources://prometheus",
						"promql":     "PromQL query string",
						"time":       "Optional: RFC3339, unix timestamp, or 'now-1h' format",
					},
					Returns: "Dict with 'resultType' and 'result' keys",
				},
				"query_range": {
					Signature:   "prometheus.query_range(datasource: str, promql: str, start: str, end: str, step: str) -> dict",
					Description: "Execute range PromQL query",
					Parameters: map[string]string{
						"datasource": "Datasource name",
						"promql":     "PromQL query string",
						"start":      "Start time (RFC3339, unix, or 'now-1h')",
						"end":        "End time (RFC3339, unix, or 'now')",
						"step":       "Resolution step (e.g., '1m', '5m')",
					},
					Returns: "Dict with time series data",
				},
				"get_labels": {
					Signature:   "prometheus.get_labels(datasource: str) -> list[str]",
					Description: "Get all label names",
					Parameters: map[string]string{
						"datasource": "Datasource name",
					},
					Returns: "List of label names",
				},
				"get_label_values": {
					Signature:   "prometheus.get_label_values(datasource: str, label: str) -> list[str]",
					Description: "Get all values for a label",
					Parameters: map[string]string{
						"datasource": "Datasource name",
						"label":      "Label name",
					},
					Returns: "List of label values",
				},
			},
		},
		"loki": {
			Description: "Query Loki for log data",
			Functions: map[string]FunctionDoc{
				"list_datasources": {
					Signature:   "loki.list_datasources() -> list[dict]",
					Description: "List available Loki datasources. Prefer datasources://loki resource.",
					Returns:     "List of dicts with 'name', 'description', 'url' keys",
				},
				"query": {
					Signature:   "loki.query(datasource: str, logql: str, limit: int = 100, start: str = None, end: str = None, direction: str = 'backward') -> list[dict]",
					Description: "Execute LogQL range query",
					Parameters: map[string]string{
						"datasource": "Datasource name from datasources://loki",
						"logql":      "LogQL query string",
						"limit":      "Max entries to return (default: 100)",
						"start":      "Start time (default: now-1h)",
						"end":        "End time (default: now)",
						"direction":  "'forward' or 'backward' (default)",
					},
					Returns: "List of dicts with 'timestamp', 'labels', 'line' keys",
				},
				"query_instant": {
					Signature:   "loki.query_instant(datasource: str, logql: str, time: str = None, limit: int = 100, direction: str = 'backward') -> list[dict]",
					Description: "Execute instant LogQL query",
					Parameters: map[string]string{
						"datasource": "Datasource name",
						"logql":      "LogQL query string",
						"time":       "Evaluation timestamp (default: now)",
						"limit":      "Max entries (default: 100)",
						"direction":  "'forward' or 'backward'",
					},
					Returns: "List of dicts with 'timestamp', 'labels', 'line' keys",
				},
				"get_labels": {
					Signature:   "loki.get_labels(datasource: str, start: str = None, end: str = None) -> list[str]",
					Description: "Get all label names",
					Parameters: map[string]string{
						"datasource": "Datasource name",
						"start":      "Optional start time",
						"end":        "Optional end time",
					},
					Returns: "List of label names",
				},
				"get_label_values": {
					Signature:   "loki.get_label_values(datasource: str, label: str, start: str = None, end: str = None) -> list[str]",
					Description: "Get all values for a label",
					Parameters: map[string]string{
						"datasource": "Datasource name",
						"label":      "Label name",
						"start":      "Optional start time",
						"end":        "Optional end time",
					},
					Returns: "List of label values",
				},
			},
		},
		"storage": {
			Description: "Upload files to S3 storage. Files must be in /workspace/ first.",
			Functions: map[string]FunctionDoc{
				"upload": {
					Signature:   "storage.upload(local_path: str, remote_name: str = None) -> str",
					Description: "Upload a file from /workspace/ and return its public URL",
					Parameters: map[string]string{
						"local_path":  "Path to file (must be in /workspace/)",
						"remote_name": "Optional custom filename in S3",
					},
					Returns: "Public URL string",
				},
				"list_files": {
					Signature:   "storage.list_files(prefix: str = '') -> list[dict]",
					Description: "List files in the S3 bucket",
					Parameters: map[string]string{
						"prefix": "Optional prefix filter",
					},
					Returns: "List of dicts with 'key', 'size', 'last_modified' keys",
				},
				"get_url": {
					Signature:   "storage.get_url(key: str) -> str",
					Description: "Get public URL for a file by its S3 key",
					Parameters: map[string]string{
						"key": "S3 object key",
					},
					Returns: "Public URL string",
				},
			},
		},
	},
}

// RegisterPythonResources registers the python:// resources with the registry.
func RegisterPythonResources(log logrus.FieldLogger, reg Registry) {
	log = log.WithField("resource", "python")

	reg.RegisterStatic(StaticResource{
		Resource: mcp.NewResource(
			"python://xatu",
			"Xatu Python Library",
			mcp.WithResourceDescription("Function signatures for the xatu Python library (clickhouse, prometheus, loki, storage modules)"),
			mcp.WithMIMEType("application/json"),
			mcp.WithAnnotations([]mcp.Role{mcp.RoleAssistant}, 0.9),
		),
		Handler: func(_ context.Context, _ string) (string, error) {
			data, err := json.MarshalIndent(xatuAPIDocs, "", "  ")
			if err != nil {
				return "", err
			}

			return string(data), nil
		},
	})

	log.Debug("Registered python resources")
}
