"""Xatu data access library for Ethereum network analytics.

This library provides direct access to Ethereum network data:
- ClickHouse: Raw and aggregated blockchain data
- Prometheus: Infrastructure metrics
- Loki: Log data
- Storage: S3-compatible file storage for outputs

Use list_datasources() to discover available datasources or check the
datasources://list MCP resource.

Example usage:
    from xatu import clickhouse, prometheus, loki, storage

    # List available ClickHouse clusters
    clusters = clickhouse.list_datasources()
    cluster_name = clusters[0]['name']  # e.g., "xatu"

    # Query ClickHouse using cluster name
    df = clickhouse.query(cluster_name, "SELECT * FROM beacon_api_eth_v1_events_block LIMIT 10")

    # Query Prometheus using instance name
    result = prometheus.query("ethpandaops", "up")

    # Upload output file
    url = storage.upload("/workspace/chart.png")
"""

from . import clickhouse, prometheus, loki, storage
from .clickhouse import ClickHouseError

__all__ = ["clickhouse", "prometheus", "loki", "storage", "ClickHouseError"]
__version__ = "0.1.0"
