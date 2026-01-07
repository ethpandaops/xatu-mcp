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
		Description: "The xatu library provides easy access to Ethereum network data through ClickHouse, Prometheus, and Loki. It is pre-installed in the sandbox environment.",
		Import:      "from xatu import clickhouse, prometheus, loki, storage",
	},
	Modules: map[string]ModuleDoc{
		"clickhouse": {
			Description: "Query ClickHouse databases for Ethereum blockchain data",
			Functions: map[string]FunctionDoc{
				"query": {
					Signature:   "clickhouse.query(cluster: str, sql: str) -> pandas.DataFrame",
					Description: "Execute a SQL query against a ClickHouse cluster and return results as a pandas DataFrame",
					Parameters: map[string]string{
						"cluster": "The cluster name: 'xatu', 'xatu-experimental', or 'xatu-cbt'",
						"sql":     "The SQL query to execute",
					},
					Returns: "pandas.DataFrame with query results",
					Example: `import pandas as pd
from xatu import clickhouse

# Query recent blocks
df = clickhouse.query("xatu", '''
    SELECT slot, block_root, proposer_index
    FROM beacon_api_eth_v1_events_block
    WHERE meta_network_name = 'mainnet'
    ORDER BY slot DESC
    LIMIT 100
''')

print(df.head())`,
				},
				"query_iter": {
					Signature:   "clickhouse.query_iter(cluster: str, sql: str, batch_size: int = 10000) -> Iterator[pandas.DataFrame]",
					Description: "Execute a query and return results in batches for memory-efficient processing of large datasets",
					Parameters: map[string]string{
						"cluster":    "The cluster name",
						"sql":        "The SQL query to execute",
						"batch_size": "Number of rows per batch (default: 10000)",
					},
					Returns: "Iterator of pandas DataFrames",
					Example: `from xatu import clickhouse

# Process large dataset in batches
for batch_df in clickhouse.query_iter("xatu", "SELECT * FROM large_table", batch_size=5000):
    process(batch_df)`,
				},
				"get_clusters": {
					Signature:   "clickhouse.get_clusters() -> dict[str, ClusterInfo]",
					Description: "Get information about available ClickHouse clusters",
					Returns:     "Dictionary of cluster names to their configurations",
				},
			},
		},
		"prometheus": {
			Description: "Query Prometheus metrics for monitoring data",
			Functions: map[string]FunctionDoc{
				"query": {
					Signature:   "prometheus.query(promql: str, time: datetime | None = None) -> dict",
					Description: "Execute an instant PromQL query",
					Parameters: map[string]string{
						"promql": "The PromQL query string",
						"time":   "Optional timestamp for the query (default: now)",
					},
					Returns: "Dictionary with query results",
					Example: `from xatu import prometheus

# Query current value
result = prometheus.query("up")
print(result)`,
				},
				"query_range": {
					Signature:   "prometheus.query_range(promql: str, start: datetime, end: datetime, step: str = '1m') -> dict",
					Description: "Execute a range PromQL query",
					Parameters: map[string]string{
						"promql": "The PromQL query string",
						"start":  "Start time for the range",
						"end":    "End time for the range",
						"step":   "Query resolution step (e.g., '1m', '5m', '1h')",
					},
					Returns: "Dictionary with time series data",
					Example: `from datetime import datetime, timedelta
from xatu import prometheus

end = datetime.now()
start = end - timedelta(hours=1)
result = prometheus.query_range("rate(http_requests_total[5m])", start, end, "1m")`,
				},
			},
		},
		"loki": {
			Description: "Query Loki for log data",
			Functions: map[string]FunctionDoc{
				"query": {
					Signature:   "loki.query(logql: str, limit: int = 1000, start: datetime | None = None, end: datetime | None = None) -> list[dict]",
					Description: "Execute a LogQL query",
					Parameters: map[string]string{
						"logql": "The LogQL query string",
						"limit": "Maximum number of log entries to return",
						"start": "Optional start time",
						"end":   "Optional end time",
					},
					Returns: "List of log entries",
					Example: `from xatu import loki

# Query recent logs
logs = loki.query('{app="xatu"} |= "error"', limit=100)
for log in logs:
    print(log['timestamp'], log['message'])`,
				},
			},
		},
		"storage": {
			Description: "Upload files to S3-compatible storage and get public URLs",
			Functions: map[string]FunctionDoc{
				"upload": {
					Signature:   "storage.upload(file_path: str, content_type: str | None = None) -> str",
					Description: "Upload a file and return its public URL",
					Parameters: map[string]string{
						"file_path":    "Path to the file to upload (should be in /output/)",
						"content_type": "Optional MIME type (auto-detected if not provided)",
					},
					Returns: "Public URL of the uploaded file",
					Example: `import matplotlib.pyplot as plt
from xatu import storage

# Create a chart
plt.figure(figsize=(10, 6))
plt.plot([1, 2, 3], [1, 4, 9])
plt.title("Example Chart")
plt.savefig('/output/chart.png')
plt.close()

# Upload and get URL
url = storage.upload('/output/chart.png')
print(f"Chart available at: {url}")`,
				},
				"upload_dataframe": {
					Signature:   "storage.upload_dataframe(df: pandas.DataFrame, filename: str, format: str = 'csv') -> str",
					Description: "Upload a pandas DataFrame as a file and return its public URL",
					Parameters: map[string]string{
						"df":       "The DataFrame to upload",
						"filename": "The filename to use (without path)",
						"format":   "Output format: 'csv', 'parquet', or 'json'",
					},
					Returns: "Public URL of the uploaded file",
					Example: `import pandas as pd
from xatu import clickhouse, storage

# Query data
df = clickhouse.query("xatu", "SELECT * FROM my_table LIMIT 1000")

# Upload as CSV
url = storage.upload_dataframe(df, "results.csv", format="csv")
print(f"Data available at: {url}")`,
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

# Query block timing data
df = clickhouse.query("xatu", '''
    SELECT
        toStartOfHour(slot_start_date_time) as hour,
        avg(propagation_slot_start_diff) / 1000 as avg_propagation_ms
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
plt.savefig('/output/propagation.png', dpi=150)
plt.close()

url = storage.upload('/output/propagation.png')
print(f"Chart: {url}")`,
		},
		"data_export": {
			Description: "Exporting query results for further analysis",
			Example: `from xatu import clickhouse, storage

# Query and export large dataset
df = clickhouse.query("xatu", '''
    SELECT *
    FROM beacon_api_eth_v1_events_block
    WHERE meta_network_name = 'mainnet'
      AND slot_start_date_time >= now() - INTERVAL 1 HOUR
''')

# Export as Parquet for efficient storage
url = storage.upload_dataframe(df, "blocks_export.parquet", format="parquet")
print(f"Data export: {url}")`,
		},
		"multi_cluster_analysis": {
			Description: "Comparing data across clusters",
			Example: `from xatu import clickhouse

# Query raw data from xatu
raw_df = clickhouse.query("xatu", '''
    SELECT slot, count() as raw_count
    FROM beacon_api_eth_v1_events_block
    WHERE meta_network_name = 'mainnet'
      AND slot >= 10000000
    GROUP BY slot
    ORDER BY slot DESC
    LIMIT 100
''')

# Query aggregated data from xatu-cbt
cbt_df = clickhouse.query("xatu-cbt", '''
    SELECT slot, block_seen_p50_ms
    FROM cbt_block_timing
    WHERE network = 'mainnet'
      AND slot >= 10000000
    ORDER BY slot DESC
    LIMIT 100
''')

# Merge and analyze
merged = raw_df.merge(cbt_df, on='slot')
print(merged.head())`,
		},
	},
	BestPractices: []string{
		"Always use LIMIT clauses to avoid fetching too much data",
		"Use time-based filters (slot_start_date_time) to limit query scope",
		"Prefer aggregations over fetching raw data when possible",
		"Use the appropriate cluster: xatu for raw data, xatu-cbt for aggregated timing data",
		"Write output files to /output/ directory before uploading",
		"Close matplotlib figures after saving to free memory",
		"Use query_iter for large datasets to avoid memory issues",
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
