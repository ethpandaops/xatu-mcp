"""ClickHouse data access via direct connections.

This module provides functions to query ClickHouse clusters directly
using the clickhouse-connect library.

Example:
    from xatu import clickhouse

    # List available ClickHouse clusters
    clusters = clickhouse.list_datasources()

    # Query using cluster name
    df = clickhouse.query("xatu", "SELECT * FROM beacon_api_eth_v1_events_block LIMIT 10")
"""

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import clickhouse_connect
import pandas as pd

logger = logging.getLogger(__name__)


class ClickHouseError(Exception):
    """Error from ClickHouse query execution with actionable suggestions."""

    def __init__(self, message: str, suggestion: str | None = None):
        self.message = message
        self.suggestion = suggestion
        super().__init__(self._format())

    def _format(self) -> str:
        parts = [f"ClickHouse Error: {self.message}"]
        if self.suggestion:
            parts.append(f"Suggestion: {self.suggestion}")
        return "\n".join(parts)


@dataclass
class _ClusterConfig:
    """Internal representation of a ClickHouse cluster configuration."""

    name: str
    host: str
    port: int
    database: str
    username: str
    password: str
    secure: bool
    skip_verify: bool
    timeout: int
    description: str
    protocol: str  # "native" or "http"


# Cache for cluster configurations.
_CLUSTERS: dict[str, _ClusterConfig] | None = None


def _load_clusters() -> None:
    """Load cluster configurations from environment variable."""
    global _CLUSTERS

    if _CLUSTERS is not None:
        return

    raw = os.environ.get("XATU_CLICKHOUSE_CONFIGS", "")
    if not raw:
        raise ValueError(
            "ClickHouse not configured. Set XATU_CLICKHOUSE_CONFIGS environment variable."
        )

    try:
        configs = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid XATU_CLICKHOUSE_CONFIGS JSON: {e}") from e

    _CLUSTERS = {}
    for cfg in configs:
        # Get protocol setting (default to "native")
        protocol = cfg.get("protocol", "native")

        # Parse host:port with IPv6 support using URL parsing
        raw_host = cfg.get("host", "")
        # Default port based on protocol
        port = 443 if protocol == "http" else 9440

        # Try to parse as a URL to handle IPv6 addresses like [::1]:9440
        if raw_host.startswith("[") or "://" in raw_host:
            # Handle bracketed IPv6 or full URL
            parsed = urlparse(f"tcp://{raw_host}" if "://" not in raw_host else raw_host)
            host = parsed.hostname or raw_host
            if parsed.port:
                port = parsed.port
        elif re.match(r"^[^:]+:\d+$", raw_host):
            # Simple host:port format (IPv4 or hostname)
            host, port_str = raw_host.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                host = raw_host
        else:
            host = raw_host

        # Get secure setting (default True)
        secure = cfg.get("secure")
        if secure is None:
            secure = True

        skip_verify = cfg.get("skip_verify", False)
        if skip_verify:
            logger.warning(
                "TLS certificate verification disabled (skip_verify=true) for %s - vulnerable to MITM attacks",
                cfg["name"],
            )

        cluster = _ClusterConfig(
            name=cfg["name"],
            host=host,
            port=port,
            database=cfg.get("database", "default"),
            username=cfg.get("username", ""),
            password=cfg.get("password", ""),
            secure=secure,
            skip_verify=skip_verify,
            timeout=cfg.get("timeout", 120),
            description=cfg.get("description", ""),
            protocol=protocol,
        )
        _CLUSTERS[cluster.name] = cluster


def _get_client(cluster_name: str) -> clickhouse_connect.driver.Client:
    """Get or create a ClickHouse client for a cluster.

    Args:
        cluster_name: The logical name of the ClickHouse cluster.

    Returns:
        A clickhouse-connect client.

    Raises:
        ValueError: If the cluster is not found.
    """
    _load_clusters()

    if _CLUSTERS is None or cluster_name not in _CLUSTERS:
        available = list(_CLUSTERS.keys()) if _CLUSTERS else []
        raise ValueError(
            f"Unknown cluster '{cluster_name}'. Available clusters: {available}"
        )

    cluster = _CLUSTERS[cluster_name]

    # Configure TLS verification
    verify = not cluster.skip_verify

    return clickhouse_connect.get_client(
        host=cluster.host,
        port=cluster.port,
        username=cluster.username,
        password=cluster.password,
        database=cluster.database,
        secure=cluster.secure,
        verify=verify,
        query_limit=0,  # No limit
        connect_timeout=30,
        send_receive_timeout=cluster.timeout,
    )


def list_datasources() -> list[dict[str, Any]]:
    """List available ClickHouse clusters.

    Returns:
        List of cluster info dictionaries with name, description, and database.

    Example:
        >>> clusters = list_datasources()
        >>> for c in clusters:
        ...     print(f"{c['name']}: {c['description']}")
    """
    _load_clusters()

    if _CLUSTERS is None:
        return []

    return [
        {
            "name": c.name,
            "description": c.description,
            "database": c.database,
        }
        for c in _CLUSTERS.values()
    ]


def query(
    cluster_name: str,
    sql: str,
    parameters: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Execute a SQL query against a ClickHouse cluster.

    Args:
        cluster_name: The logical name of the ClickHouse cluster.
        sql: SQL query to execute.
        parameters: Optional query parameters for parameterized queries.

    Returns:
        DataFrame with query results.

    Raises:
        ValueError: If cluster is not found.
        ClickHouseError: If query execution fails.

    Example:
        >>> df = query("xatu", "SELECT * FROM blocks LIMIT 10")
        >>> df = query("xatu", "SELECT * FROM blocks WHERE slot > {slot:UInt64}", {"slot": 1000})
    """
    client = _get_client(cluster_name)

    try:
        if parameters:
            result = client.query_df(sql, parameters=parameters)
        else:
            result = client.query_df(sql)

        return result
    except Exception as e:
        error_msg = str(e)

        # Provide helpful suggestions for common errors
        suggestion = None
        if "TIMEOUT" in error_msg.upper() or "timeout" in error_msg.lower():
            suggestion = (
                "Query timed out. Ensure you're filtering by the table's partition column "
                "(usually slot_start_date_time) to avoid full table scans. "
                "Use clickhouse://tables/{table} resource to find the partition key."
            )
        elif "MEMORY_LIMIT" in error_msg.upper():
            suggestion = (
                "Query exceeded memory limit. Add more restrictive filters or use LIMIT clause. "
                "Consider filtering by partition key first."
            )
        elif "Unknown identifier" in error_msg or "no column" in error_msg.lower():
            suggestion = (
                "Check column names against clickhouse://tables/{table} resource. "
                "Column names are case-sensitive."
            )

        raise ClickHouseError(error_msg, suggestion) from e
    finally:
        client.close()


def query_raw(
    cluster_name: str,
    sql: str,
    parameters: dict[str, Any] | None = None,
) -> tuple[list[tuple], list[str]]:
    """Execute a SQL query and return raw results.

    Args:
        cluster_name: The logical name of the ClickHouse cluster.
        sql: SQL query to execute.
        parameters: Optional query parameters.

    Returns:
        Tuple of (rows, column_names).

    Example:
        >>> rows, columns = query_raw("xatu", "SELECT slot, block_root FROM blocks LIMIT 5")
    """
    df = query(cluster_name, sql, parameters)

    if df.empty:
        return [], []

    rows = [tuple(row) for row in df.values]
    columns = list(df.columns)

    return rows, columns
