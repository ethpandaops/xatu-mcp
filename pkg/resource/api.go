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
		Description: "The xatu library provides easy access to Ethereum network data through ClickHouse, Prometheus, and Loki via Grafana proxy. It is pre-installed in the sandbox environment. Use the datasources://list resource to discover available datasource UIDs.",
		Import:      "from xatu import clickhouse, prometheus, loki, storage",
	},
	Modules: map[string]ModuleDoc{
		"clickhouse": {
			Description: "Query ClickHouse databases for Ethereum blockchain data via Grafana proxy",
			Functions: map[string]FunctionDoc{
				"list_datasources": {
					Signature:   "clickhouse.list_datasources() -> list[dict]",
					Description: "List available ClickHouse datasources from Grafana",
					Returns:     "List of datasource info dictionaries with uid, name, and type",
					Example: `from xatu import clickhouse

# List available ClickHouse datasources
datasources = clickhouse.list_datasources()
for ds in datasources:
    print(f"{ds['name']}: {ds['uid']}")`,
				},
				"query": {
					Signature:   "clickhouse.query(datasource_uid: str, sql: str) -> pandas.DataFrame",
					Description: "Execute a SQL query via Grafana proxy and return results as a pandas DataFrame",
					Parameters: map[string]string{
						"datasource_uid": "The Grafana datasource UID for the ClickHouse instance (use list_datasources() or datasources://list to find UIDs)",
						"sql":            "The SQL query to execute",
					},
					Returns: "pandas.DataFrame with query results",
					Example: `from xatu import clickhouse

# First, find the datasource UID (or use datasources://list resource)
datasources = clickhouse.list_datasources()
uid = datasources[0]['uid']  # e.g., "PDF61E9E97939C7ED"

# Query recent blocks
df = clickhouse.query(uid, '''
    SELECT slot, block_root, proposer_index
    FROM beacon_api_eth_v1_events_block
    WHERE meta_network_name = 'mainnet'
    ORDER BY slot DESC
    LIMIT 100
''')

print(df.head())`,
				},
				"query_raw": {
					Signature:   "clickhouse.query_raw(datasource_uid: str, sql: str) -> tuple[list[tuple], list[str]]",
					Description: "Execute a SQL query and return raw results as (rows, column_names)",
					Parameters: map[string]string{
						"datasource_uid": "The Grafana datasource UID for the ClickHouse instance",
						"sql":            "The SQL query to execute",
					},
					Returns: "Tuple of (rows, column_names)",
					Example: `from xatu import clickhouse

rows, columns = clickhouse.query_raw("PDF61E9E97939C7ED", "SELECT slot, block_root FROM beacon_api_eth_v1_events_block LIMIT 10")
print(f"Columns: {columns}")
for row in rows:
    print(row)`,
				},
			},
		},
		"prometheus": {
			Description: "Query Prometheus metrics for monitoring data via Grafana proxy",
			Functions: map[string]FunctionDoc{
				"list_datasources": {
					Signature:   "prometheus.list_datasources() -> list[dict]",
					Description: "List available Prometheus datasources from Grafana",
					Returns:     "List of datasource info dictionaries with uid, name, and type",
				},
				"query": {
					Signature:   "prometheus.query(datasource_uid: str, promql: str, time: str | None = None) -> dict",
					Description: "Execute an instant PromQL query via Grafana proxy",
					Parameters: map[string]string{
						"datasource_uid": "The Grafana datasource UID for the Prometheus instance",
						"promql":         "The PromQL query string",
						"time":           "Optional timestamp (RFC3339, Unix timestamp, or 'now-1h' format). Default: now",
					},
					Returns: "Dictionary with 'resultType' and 'result' keys",
					Example: `from xatu import prometheus

# Query current value using datasource UID
result = prometheus.query("P4169E866C3094E38", "up")
print(result)

# Query with specific time
result = prometheus.query("P4169E866C3094E38", "up", time="now-1h")`,
				},
				"query_range": {
					Signature:   "prometheus.query_range(datasource_uid: str, promql: str, start: str, end: str, step: str) -> dict",
					Description: "Execute a range PromQL query via Grafana proxy",
					Parameters: map[string]string{
						"datasource_uid": "The Grafana datasource UID for the Prometheus instance",
						"promql":         "The PromQL query string",
						"start":          "Start time (RFC3339, Unix timestamp, or 'now-1h' format)",
						"end":            "End time (RFC3339, Unix timestamp, or 'now' format)",
						"step":           "Query resolution step (e.g., '1m', '5m', '1h')",
					},
					Returns: "Dictionary with time series data",
					Example: `from xatu import prometheus

result = prometheus.query_range(
    "P4169E866C3094E38",
    "rate(http_requests_total[5m])",
    start="now-1h",
    end="now",
    step="1m"
)`,
				},
				"get_labels": {
					Signature:   "prometheus.get_labels(datasource_uid: str) -> list[str]",
					Description: "Get all label names from a Prometheus datasource",
					Parameters: map[string]string{
						"datasource_uid": "The Grafana datasource UID",
					},
					Returns: "List of label names",
				},
				"get_label_values": {
					Signature:   "prometheus.get_label_values(datasource_uid: str, label: str) -> list[str]",
					Description: "Get all values for a specific label",
					Parameters: map[string]string{
						"datasource_uid": "The Grafana datasource UID",
						"label":          "Label name to get values for",
					},
					Returns: "List of label values",
				},
			},
		},
		"loki": {
			Description: "Query Loki for log data via Grafana proxy",
			Functions: map[string]FunctionDoc{
				"list_datasources": {
					Signature:   "loki.list_datasources() -> list[dict]",
					Description: "List available Loki datasources from Grafana",
					Returns:     "List of datasource info dictionaries with uid, name, and type",
				},
				"query": {
					Signature:   "loki.query(datasource_uid: str, logql: str, limit: int = 100, start: str | None = None, end: str | None = None, direction: str = 'backward') -> list[dict]",
					Description: "Execute a LogQL range query via Grafana proxy",
					Parameters: map[string]string{
						"datasource_uid": "The Grafana datasource UID for the Loki instance",
						"logql":          "The LogQL query string",
						"limit":          "Maximum number of log entries to return (default: 100)",
						"start":          "Start time (RFC3339, Unix timestamp, or 'now-1h' format). Default: now-1h",
						"end":            "End time (RFC3339, Unix timestamp, or 'now' format). Default: now",
						"direction":      "Sort direction: 'forward' (oldest first) or 'backward' (newest first)",
					},
					Returns: "List of log entries with 'timestamp', 'labels', and 'line' keys",
					Example: `from xatu import loki

# Query recent logs using datasource UID
logs = loki.query("P8E80F9AEF21F6940", '{app="beacon-node"} |= "error"', limit=100)
for log in logs:
    print(log['timestamp'], log['line'])`,
				},
				"query_instant": {
					Signature:   "loki.query_instant(datasource_uid: str, logql: str, time: str | None = None, limit: int = 100, direction: str = 'backward') -> list[dict]",
					Description: "Execute an instant LogQL query via Grafana proxy",
					Parameters: map[string]string{
						"datasource_uid": "The Grafana datasource UID for the Loki instance",
						"logql":          "The LogQL query string",
						"time":           "Evaluation timestamp. Default: now",
						"limit":          "Maximum number of log entries to return (default: 100)",
						"direction":      "Sort direction: 'forward' or 'backward'",
					},
					Returns: "List of log entries with 'timestamp', 'labels', and 'line' keys",
				},
				"get_labels": {
					Signature:   "loki.get_labels(datasource_uid: str, start: str | None = None, end: str | None = None) -> list[str]",
					Description: "Get all label names from a Loki datasource",
					Parameters: map[string]string{
						"datasource_uid": "The Grafana datasource UID",
						"start":          "Optional start time for label discovery",
						"end":            "Optional end time for label discovery",
					},
					Returns: "List of label names",
				},
				"get_label_values": {
					Signature:   "loki.get_label_values(datasource_uid: str, label: str, start: str | None = None, end: str | None = None) -> list[str]",
					Description: "Get all values for a specific label",
					Parameters: map[string]string{
						"datasource_uid": "The Grafana datasource UID",
						"label":          "Label name to get values for",
						"start":          "Optional start time",
						"end":            "Optional end time",
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

# Use the ClickHouse datasource UID (from datasources://list or config)
CLICKHOUSE_UID = "PDF61E9E97939C7ED"

# Query block timing data
df = clickhouse.query(CLICKHOUSE_UID, '''
    SELECT
        toStartOfHour(slot_start_date_time) as hour,
        avg(propagation_slot_start_diff) as avg_propagation_ms
    FROM beacon_api_eth_v1_events_block
    WHERE meta_network_name = 'mainnet'
      AND slot_start_date_time >= now() - INTERVAL 24 HOUR
    GROUP BY hour
    ORDER BY hour
''')

# Create visualization
plt.figure(figsize=(12, 6))
plt.plot(df['hour'], df['avg_propagation_ms'])
plt.xlabel('Time')
plt.ylabel('Average Propagation (ms)')
plt.title('Block Propagation Times - Last 24 Hours')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('/workspace/propagation.png', dpi=150)
plt.close()

url = storage.upload('/workspace/propagation.png')
print(f"Chart: {url}")`,
		},
		"data_export": {
			Description: "Exporting query results for further analysis",
			Example: `from xatu import clickhouse, storage

CLICKHOUSE_UID = "PDF61E9E97939C7ED"

# Query data
df = clickhouse.query(CLICKHOUSE_UID, '''
    SELECT *
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
		"multi_datasource_analysis": {
			Description: "Comparing data across different ClickHouse datasources",
			Example: `from xatu import clickhouse

# Datasource UIDs (from datasources://list)
XATU_UID = "PDF61E9E97939C7ED"      # Main Xatu cluster
XATU_CBT_UID = "PDDA0A20013A2233F"  # CBT cluster

# Query raw data from main Xatu cluster
raw_df = clickhouse.query(XATU_UID, '''
    SELECT slot, count() as raw_count
    FROM beacon_api_eth_v1_events_block
    WHERE meta_network_name = 'mainnet'
      AND slot >= 10000000
    GROUP BY slot
    ORDER BY slot DESC
    LIMIT 100
''')

# Query aggregated data from CBT cluster
cbt_df = clickhouse.query(XATU_CBT_UID, '''
    SELECT slot, block_seen_p50_ms
    FROM mainnet.cbt_block_timing
    WHERE slot >= 10000000
    ORDER BY slot DESC
    LIMIT 100
''')

# Merge and analyze
merged = raw_df.merge(cbt_df, on='slot')
print(merged.head())`,
		},
	},
	BestPractices: []string{
		"Use datasources://list or clickhouse.list_datasources() to discover available datasource UIDs",
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
		Resource: mcp.Resource{
			URI:         "api://xatu",
			Name:        "Xatu Library API",
			Description: "API documentation for the xatu Python library available in the sandbox",
			MIMEType:    "application/json",
		},
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
