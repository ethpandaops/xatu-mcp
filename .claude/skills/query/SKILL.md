---
name: query
description: Query Ethereum network data via ethpandaops MCP server. Use when analyzing blockchain data, block timing, attestations, validator performance, network health, or infrastructure metrics. Provides access to ClickHouse (blockchain data), Prometheus (metrics), Loki (logs), and Dora (explorer APIs).
argument-hint: <query or question>
user-invocable: false
---

# ethpandaops MCP Server Usage Guide

Query Ethereum network data through the ethpandaops MCP server. Execute Python code in sandboxed containers with access to ClickHouse blockchain data, Prometheus metrics, Loki logs, and Dora explorer APIs.

## Workflow

1. **Discover** - Read MCP resources to find available datasources and schemas
2. **Find patterns** - Use search tools to find query examples and runbooks
3. **Execute** - Run Python with `execute_python` using the `ethpandaops` library

## Quick Reference

### Discovering Data Sources

Read these resources to understand what data is available:

| Resource | Description |
|----------|-------------|
| `datasources://list` | All configured datasources |
| `datasources://clickhouse` | ClickHouse clusters (blockchain data) |
| `datasources://prometheus` | Prometheus instances (metrics) |
| `datasources://loki` | Loki instances (logs) |
| `networks://active` | Active Ethereum networks |
| `clickhouse://tables` | Available tables (if schema discovery enabled) |
| `clickhouse://tables/{table}` | Table schema details |
| `python://ethpandaops` | Python library API docs |

### Finding Query Patterns

**Search for example queries:**
```
search_examples(query="block arrival time")
search_examples(query="attestation participation", category="attestations")
```

**Search for investigation runbooks:**
```
search_runbooks(query="network not finalizing")
search_runbooks(query="slow queries", tag="performance")
```

## The ethpandaops Python Library

### ClickHouse - Blockchain Data

```python
from ethpandaops import clickhouse

# List available clusters
clusters = clickhouse.list_datasources()
# Returns: [{"name": "xatu", "database": "default"}, {"name": "xatu-cbt", ...}]

# Query data (returns pandas DataFrame)
df = clickhouse.query("xatu-cbt", """
    SELECT
        slot,
        avg(seen_slot_start_diff) as avg_arrival_ms
    FROM mainnet.fct_block_first_seen_by_node
    WHERE slot_start_date_time >= now() - INTERVAL 1 HOUR
    GROUP BY slot
    ORDER BY slot DESC
""")

# Parameterized queries
df = clickhouse.query("xatu", "SELECT * FROM blocks WHERE slot > {slot}", {"slot": 1000})
```

**Cluster selection:**
- `xatu-cbt` - Pre-aggregated tables (faster, use for metrics)
- `xatu` - Raw event data (use for detailed analysis)

**Required filters:**
- ALWAYS filter on partition key: `slot_start_date_time >= now() - INTERVAL X HOUR`
- Filter by network: `meta_network_name = 'mainnet'` or use schema like `mainnet.table_name`

### Prometheus - Infrastructure Metrics

```python
from ethpandaops import prometheus

# List instances
instances = prometheus.list_datasources()

# Instant query
result = prometheus.query("ethpandaops", "up")

# Range query
result = prometheus.query_range(
    "ethpandaops",
    "rate(http_requests_total[5m])",
    start="now-1h",
    end="now",
    step="1m"
)
```

**Time formats:** RFC3339 or relative (`now`, `now-1h`, `now-30m`)

### Loki - Log Data

```python
from ethpandaops import loki

# List instances
instances = loki.list_datasources()

# Query logs
logs = loki.query(
    "ethpandaops",
    '{app="beacon-node"} |= "error"',
    start="now-1h",
    limit=100
)
```

### Dora - Beacon Chain Explorer

```python
from ethpandaops import dora

# Get network health
overview = dora.get_network_overview("mainnet")
print(f"Current epoch: {overview['current_epoch']}")
print(f"Active validators: {overview['active_validator_count']}")

# Check finality
epochs_behind = overview['current_epoch'] - overview.get('finalized_epoch', 0)
if epochs_behind > 2:
    print(f"Warning: {epochs_behind} epochs behind finality")

# Generate explorer links
link = dora.link_validator("mainnet", "12345")
link = dora.link_slot("mainnet", "9000000")
link = dora.link_epoch("mainnet", 280000)
```

### Storage - Upload Outputs

```python
from ethpandaops import storage

# Save visualization
import matplotlib.pyplot as plt
plt.savefig("/workspace/chart.png")

# Upload for public URL
url = storage.upload("/workspace/chart.png")
print(f"Chart URL: {url}")

# List uploaded files
files = storage.list_files()
```

## Session Management

**Critical:** Each `execute_python` call runs in a **fresh Python process**. Variables do NOT persist.

**Files persist:** Save to `/workspace/` to share data between calls.

**Reuse sessions:** Pass `session_id` from tool responses for faster startup and workspace persistence.

### Multi-Step Analysis Pattern

```python
# Call 1: Query and save
from ethpandaops import clickhouse
df = clickhouse.query("xatu-cbt", "SELECT ...")
df.to_parquet("/workspace/data.parquet")
```

```python
# Call 2: Load and visualize (pass session_id from Call 1)
import pandas as pd
import matplotlib.pyplot as plt
from ethpandaops import storage

df = pd.read_parquet("/workspace/data.parquet")
plt.figure(figsize=(12, 6))
plt.plot(df["slot"], df["value"])
plt.savefig("/workspace/chart.png")
url = storage.upload("/workspace/chart.png")
print(f"Chart: {url}")
```

### Session Tools

```
manage_session(operation="list")     # View active sessions
manage_session(operation="create")   # Pre-create a session
manage_session(operation="destroy", session_id="...")  # Free a session
```

## Error Handling

ClickHouse errors include actionable suggestions:
- Missing date filter → "Add `slot_start_date_time >= now() - INTERVAL X HOUR`"
- Wrong cluster → "Use xatu-cbt for aggregated metrics"
- Query timeout → Break into smaller time windows

Default execution timeout is 60s, max 600s. For large analyses:
- Use `search_examples` to find optimized patterns
- Break work into smaller time windows
- Save intermediate results to `/workspace/`

## Notes

- Always filter ClickHouse queries on partition keys (`slot_start_date_time`)
- Use `xatu-cbt` for pre-aggregated metrics, `xatu` for raw event data
- Check `python://ethpandaops` resource for complete API documentation
- Use `search_examples` before writing complex queries from scratch
- Upload visualizations with `storage.upload()` for shareable URLs
- NEVER just copy/paste/recite base64 of images. You MUST save the image to the workspace and upload it to give it back to the user.
