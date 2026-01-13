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

// PatternDoc describes a common usage pattern.
type PatternDoc struct {
	Description string `json:"description"`
	Example     string `json:"example"`
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
	Overview       APIOverview           `json:"overview"`
	Modules        map[string]ModuleDoc  `json:"modules"`
	CommonPatterns map[string]PatternDoc `json:"common_patterns"`
	BestPractices  []string              `json:"best_practices"`
}{
	Overview: APIOverview{
		Description: "The xatu library provides easy access to Ethereum network data through ClickHouse, Prometheus, and Loki. It is pre-installed in the sandbox environment. Use the datasources://clickhouse resource to discover available cluster names.",
		Import:      "from xatu import clickhouse, prometheus, loki, storage",
	},
	Modules: map[string]ModuleDoc{
		"clickhouse": {
			Description: "Query ClickHouse databases for Ethereum blockchain data",
			Functions: map[string]FunctionDoc{
				"list_datasources": {
					Signature:   "clickhouse.list_datasources() -> list[dict]",
					Description: "List available ClickHouse clusters (prefer using datasources://clickhouse resource instead)",
					Returns:     "List of cluster info dictionaries with name, description, and database",
					Example: `from xatu import clickhouse

# List available ClickHouse clusters
clusters = clickhouse.list_datasources()
for c in clusters:
    print(f"{c['name']}: {c['description']}")`,
				},
				"query": {
					Signature:   "clickhouse.query(cluster_name: str, sql: str) -> pandas.DataFrame",
					Description: "Execute a SQL query and return results as a pandas DataFrame",
					Parameters: map[string]string{
						"cluster_name": "The cluster name: 'xatu' (raw events) or 'xatu-cbt' (pre-aggregated). See datasources://clickhouse for details.",
						"sql":          "The SQL query to execute",
					},
					Returns: "pandas.DataFrame with query results",
					Example: `from xatu import clickhouse

# Query pre-aggregated data from xatu-cbt cluster
# Note: xatu-cbt uses database prefix (mainnet.) instead of WHERE filter
df = clickhouse.query('xatu-cbt', '''
    SELECT slot, MIN(seen_slot_start_diff) as first_seen_ms
    FROM mainnet.fct_block_first_seen_by_node
    WHERE slot_start_date_time >= now() - INTERVAL 1 HOUR
    GROUP BY slot
    LIMIT 100
''')

# Query raw events from xatu cluster
# Note: xatu uses WHERE meta_network_name filter
df = clickhouse.query('xatu', '''
    SELECT slot, block_root
    FROM beacon_api_eth_v1_events_block
    WHERE meta_network_name = 'mainnet'
      AND slot_start_date_time >= now() - INTERVAL 1 HOUR
    LIMIT 100
''')`,
				},
				"query_raw": {
					Signature:   "clickhouse.query_raw(cluster_name: str, sql: str) -> tuple[list[tuple], list[str]]",
					Description: "Execute a SQL query and return raw results as (rows, column_names)",
					Parameters: map[string]string{
						"cluster_name": "The cluster name: 'xatu' or 'xatu-cbt'",
						"sql":          "The SQL query to execute",
					},
					Returns: "Tuple of (rows, column_names)",
					Example: `from xatu import clickhouse

rows, columns = clickhouse.query_raw('xatu-cbt', '''
    SELECT slot, MIN(seen_slot_start_diff) as first_seen_ms
    FROM mainnet.fct_block_first_seen_by_node
    WHERE slot_start_date_time >= now() - INTERVAL 1 HOUR
    GROUP BY slot
    LIMIT 10
''')
print(f"Columns: {columns}")
for row in rows:
    print(row)`,
				},
			},
		},
		"prometheus": {
			Description: "Query Prometheus metrics for monitoring data",
			Functions: map[string]FunctionDoc{
				"list_datasources": {
					Signature:   "prometheus.list_datasources() -> list[dict]",
					Description: "List available Prometheus datasources",
					Returns:     "List of datasource info dictionaries with name, description, and url",
				},
				"query": {
					Signature:   "prometheus.query(datasource_name: str, promql: str, time: str | None = None) -> dict",
					Description: "Execute an instant PromQL query",
					Parameters: map[string]string{
						"datasource_name": "The Prometheus datasource name (see datasources://prometheus)",
						"promql":          "The PromQL query string",
						"time":            "Optional timestamp (RFC3339, Unix timestamp, or 'now-1h' format). Default: now",
					},
					Returns: "Dictionary with 'resultType' and 'result' keys",
					Example: `from xatu import prometheus

# Query using datasource name
result = prometheus.query("prometheus-mainnet", "up")
print(result)

# Query with specific time
result = prometheus.query("prometheus-mainnet", "up", time="now-1h")`,
				},
				"query_range": {
					Signature:   "prometheus.query_range(datasource_name: str, promql: str, start: str, end: str, step: str) -> dict",
					Description: "Execute a range PromQL query",
					Parameters: map[string]string{
						"datasource_name": "The Prometheus datasource name",
						"promql":          "The PromQL query string",
						"start":           "Start time (RFC3339, Unix timestamp, or 'now-1h' format)",
						"end":             "End time (RFC3339, Unix timestamp, or 'now' format)",
						"step":            "Query resolution step (e.g., '1m', '5m', '1h')",
					},
					Returns: "Dictionary with time series data",
					Example: `from xatu import prometheus

result = prometheus.query_range(
    "prometheus-mainnet",
    "rate(http_requests_total[5m])",
    start="now-1h",
    end="now",
    step="1m"
)`,
				},
				"get_labels": {
					Signature:   "prometheus.get_labels(datasource_name: str) -> list[str]",
					Description: "Get all label names from a Prometheus datasource",
					Parameters: map[string]string{
						"datasource_name": "The Prometheus datasource name",
					},
					Returns: "List of label names",
				},
				"get_label_values": {
					Signature:   "prometheus.get_label_values(datasource_name: str, label: str) -> list[str]",
					Description: "Get all values for a specific label",
					Parameters: map[string]string{
						"datasource_name": "The Prometheus datasource name",
						"label":           "Label name to get values for",
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
					Description: "List available Loki datasources",
					Returns:     "List of datasource info dictionaries with name, description, and url",
				},
				"query": {
					Signature:   "loki.query(datasource_name: str, logql: str, limit: int = 100, start: str | None = None, end: str | None = None, direction: str = 'backward') -> list[dict]",
					Description: "Execute a LogQL range query",
					Parameters: map[string]string{
						"datasource_name": "The Loki datasource name (see datasources://loki)",
						"logql":           "The LogQL query string",
						"limit":           "Maximum number of log entries to return (default: 100)",
						"start":           "Start time (RFC3339, Unix timestamp, or 'now-1h' format). Default: now-1h",
						"end":             "End time (RFC3339, Unix timestamp, or 'now' format). Default: now",
						"direction":       "Sort direction: 'forward' (oldest first) or 'backward' (newest first)",
					},
					Returns: "List of log entries with 'timestamp', 'labels', and 'line' keys",
					Example: `from xatu import loki

# Query recent logs using datasource name
logs = loki.query("loki-mainnet", '{app="beacon-node"} |= "error"', limit=100)
for log in logs:
    print(log['timestamp'], log['line'])`,
				},
				"query_instant": {
					Signature:   "loki.query_instant(datasource_name: str, logql: str, time: str | None = None, limit: int = 100, direction: str = 'backward') -> list[dict]",
					Description: "Execute an instant LogQL query",
					Parameters: map[string]string{
						"datasource_name": "The Loki datasource name",
						"logql":           "The LogQL query string",
						"time":            "Evaluation timestamp. Default: now",
						"limit":           "Maximum number of log entries to return (default: 100)",
						"direction":       "Sort direction: 'forward' or 'backward'",
					},
					Returns: "List of log entries with 'timestamp', 'labels', and 'line' keys",
				},
				"get_labels": {
					Signature:   "loki.get_labels(datasource_name: str, start: str | None = None, end: str | None = None) -> list[str]",
					Description: "Get all label names from a Loki datasource",
					Parameters: map[string]string{
						"datasource_name": "The Loki datasource name",
						"start":           "Optional start time for label discovery",
						"end":             "Optional end time for label discovery",
					},
					Returns: "List of label names",
				},
				"get_label_values": {
					Signature:   "loki.get_label_values(datasource_name: str, label: str, start: str | None = None, end: str | None = None) -> list[str]",
					Description: "Get all values for a specific label",
					Parameters: map[string]string{
						"datasource_name": "The Loki datasource name",
						"label":           "Label name to get values for",
						"start":           "Optional start time",
						"end":             "Optional end time",
					},
					Returns: "List of label values",
				},
			},
		},
		"storage": {
			Description: "Upload files to S3-compatible storage and get public URLs",
			Functions: map[string]FunctionDoc{
				"upload": {
					Signature:   "storage.upload(local_path: str, remote_name: str | None = None) -> str",
					Description: "Upload a file and return its public URL",
					Parameters: map[string]string{
						"local_path":  "Path to the file to upload (should be in /workspace/)",
						"remote_name": "Optional name for the file in S3 (defaults to local filename)",
					},
					Returns: "Public URL of the uploaded file",
					Example: `import matplotlib.pyplot as plt
from xatu import storage

# Create a chart
plt.figure(figsize=(10, 6))
plt.plot([1, 2, 3], [1, 4, 9])
plt.title("Example Chart")
plt.savefig('/workspace/chart.png')
plt.close()

# Upload and get URL
url = storage.upload('/workspace/chart.png')
print(f"Chart available at: {url}")

# Upload with custom name
url = storage.upload('/workspace/data.csv', remote_name='analysis_results.csv')`,
				},
				"list_files": {
					Signature:   "storage.list_files(prefix: str = '') -> list[dict]",
					Description: "List files in the S3 bucket",
					Parameters: map[string]string{
						"prefix": "Optional prefix to filter files",
					},
					Returns: "List of file info dictionaries with 'key', 'size', 'last_modified'",
				},
				"get_url": {
					Signature:   "storage.get_url(key: str) -> str",
					Description: "Get the public URL for a file by its S3 key",
					Parameters: map[string]string{
						"key": "S3 object key",
					},
					Returns: "Public URL for the file",
				},
			},
		},
	},
	CommonPatterns: map[string]PatternDoc{
		"visualization": {
			Description: "Creating and uploading visualizations",
			Example: `import matplotlib.pyplot as plt
import pandas as pd
from xatu import clickhouse, storage

# Query block timing data from xatu-cbt cluster (pre-aggregated)
df = clickhouse.query('xatu-cbt', '''
    SELECT
        toStartOfHour(slot_start_date_time) as hour,
        avg(seen_slot_start_diff) as avg_arrival_ms
    FROM mainnet.fct_block_first_seen_by_node
    WHERE slot_start_date_time >= now() - INTERVAL 24 HOUR
    GROUP BY hour
    ORDER BY hour
''')

# Create visualization
plt.figure(figsize=(12, 6))
plt.plot(df['hour'], df['avg_arrival_ms'])
plt.xlabel('Time')
plt.ylabel('Average Arrival Time (ms)')
plt.title('Block Arrival Times - Last 24 Hours')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('/workspace/block_timing.png', dpi=150)
plt.close()

url = storage.upload('/workspace/block_timing.png')
print(f"Chart: {url}")`,
		},
		"data_export": {
			Description: "Exporting query results for further analysis",
			Example: `from xatu import clickhouse, storage

# Query raw events from xatu cluster
df = clickhouse.query('xatu', '''
    SELECT slot, block_root, proposer_index, slot_start_date_time
    FROM beacon_api_eth_v1_events_block
    WHERE meta_network_name = 'mainnet'
      AND slot_start_date_time >= now() - INTERVAL 1 HOUR
    LIMIT 10000
''')

# Save and upload as Parquet for efficient storage
df.to_parquet('/workspace/blocks_export.parquet')
url = storage.upload('/workspace/blocks_export.parquet')
print(f"Data export: {url}")`,
		},
		"multi_cluster_analysis": {
			Description: "Comparing data across xatu and xatu-cbt clusters",
			Example: `from xatu import clickhouse

# Query raw events from xatu cluster
raw_df = clickhouse.query('xatu', '''
    SELECT slot, count() as raw_count
    FROM beacon_api_eth_v1_events_block
    WHERE meta_network_name = 'mainnet'
      AND slot_start_date_time >= now() - INTERVAL 1 HOUR
    GROUP BY slot
    ORDER BY slot DESC
    LIMIT 100
''')

# Query pre-aggregated data from xatu-cbt cluster
cbt_df = clickhouse.query('xatu-cbt', '''
    SELECT slot, MIN(seen_slot_start_diff) as first_seen_ms
    FROM mainnet.fct_block_first_seen_by_node
    WHERE slot_start_date_time >= now() - INTERVAL 1 HOUR
    GROUP BY slot
    ORDER BY slot DESC
    LIMIT 100
''')

# Merge and analyze
merged = raw_df.merge(cbt_df, on='slot')
print(merged.head())`,
		},
	},
	BestPractices: []string{
		"Use datasources://clickhouse to discover available cluster names",
		"Always use LIMIT clauses to avoid fetching too much data",
		"Use time-based filters (slot_start_date_time) to limit query scope",
		"Prefer aggregations over fetching raw data when possible",
		"Write output files to /workspace/ directory before uploading",
		"Close matplotlib figures after saving to free memory",
		"For Loki queries, always filter by labels to avoid scanning all logs",
		"Time parameters accept 'now-1h' format, RFC3339, or Unix timestamps",
	},
}

// RegisterAPIResources registers the api:// resources with the registry.
func RegisterAPIResources(log logrus.FieldLogger, reg Registry) {
	log = log.WithField("resource", "api")

	// Register static api://xatu resource
	reg.RegisterStatic(StaticResource{
		Resource: mcp.NewResource(
			"api://xatu",
			"Xatu Library API",
			mcp.WithResourceDescription("API documentation for the xatu Python library available in the sandbox"),
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

	log.Debug("Registered API resources")
}
