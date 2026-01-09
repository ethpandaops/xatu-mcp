"""Xatu data access library for Ethereum network analytics.

This library provides access to Ethereum network data through Grafana proxy:
- ClickHouse: Raw and aggregated blockchain data
- Prometheus: Infrastructure metrics
- Loki: Log data
- Storage: S3-compatible file storage for outputs

All queries are routed through Grafana using datasource UIDs. Use
list_datasources() to discover available datasources or check the
datasources://list MCP resource.

Example usage:
    from xatu import clickhouse, prometheus, loki, storage

    # List available ClickHouse datasources
    datasources = clickhouse.list_datasources()
    uid = datasources[0]['uid']  # e.g., "PDF61E9E97939C7ED"

    # Query ClickHouse using datasource UID
    df = clickhouse.query(uid, "SELECT * FROM beacon_api_eth_v1_events_block LIMIT 10")

    # Query Prometheus using datasource UID
    result = prometheus.query("P4169E866C3094E38", "up")

    # Upload output file
    url = storage.upload("/workspace/chart.png")
"""

from . import clickhouse, prometheus, loki, storage
from .clickhouse import ClickHouseError

__all__ = ["clickhouse", "prometheus", "loki", "storage", "ClickHouseError"]
__version__ = "0.1.0"
