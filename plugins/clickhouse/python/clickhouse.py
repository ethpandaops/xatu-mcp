"""ClickHouse data access via credential proxy.

This module provides functions to query ClickHouse clusters. All requests
go through the credential proxy - credentials are never exposed to sandbox
containers.

Example:
    from ethpandaops import clickhouse

    # List available ClickHouse clusters
    clusters = clickhouse.list_datasources()

    # Query using cluster name
    df = clickhouse.query("xatu", "SELECT * FROM beacon_api_eth_v1_events_block LIMIT 10")
"""

import io
import json
import os
from typing import Any

import httpx
import pandas as pd

# Proxy configuration (required).
_PROXY_URL = os.environ.get("ETHPANDAOPS_PROXY_URL", "")
_PROXY_TOKEN = os.environ.get("ETHPANDAOPS_PROXY_TOKEN", "")

# Cache for datasource info.
_DATASOURCE_INFO: list[dict[str, str]] | None = None


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


def _check_proxy_config() -> None:
    """Verify proxy is configured."""
    if not _PROXY_URL or not _PROXY_TOKEN:
        raise ValueError(
            "Proxy not configured. ETHPANDAOPS_PROXY_URL and ETHPANDAOPS_PROXY_TOKEN are required."
        )


def _load_datasources() -> list[dict[str, str]]:
    """Load datasource info from environment variable."""
    global _DATASOURCE_INFO

    if _DATASOURCE_INFO is not None:
        return _DATASOURCE_INFO

    raw = os.environ.get("ETHPANDAOPS_CLICKHOUSE_DATASOURCES", "")
    if not raw:
        _DATASOURCE_INFO = []
        return _DATASOURCE_INFO

    try:
        _DATASOURCE_INFO = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid ETHPANDAOPS_CLICKHOUSE_DATASOURCES JSON: {e}") from e

    return _DATASOURCE_INFO


def _get_datasource_names() -> list[str]:
    """Get list of datasource names for validation."""
    return [ds["name"] for ds in _load_datasources()]


def _get_client() -> httpx.Client:
    """Get an HTTP client configured for the proxy."""
    _check_proxy_config()

    return httpx.Client(
        base_url=_PROXY_URL,
        headers={"Authorization": f"Bearer {_PROXY_TOKEN}"},
        timeout=httpx.Timeout(connect=5.0, read=300.0, write=60.0, pool=5.0),
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
    return _load_datasources()


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
    # Validate cluster exists.
    datasources = _get_datasource_names()
    if cluster_name not in datasources:
        raise ValueError(
            f"Unknown cluster '{cluster_name}'. Available clusters: {datasources}"
        )

    try:
        with _get_client() as client:
            params = {"default_format": "TabSeparatedWithNames"}
            if parameters:
                params.update(_build_query_params(parameters))

            # ClickHouse HTTP interface expects POST with query in body.
            response = client.post(
                f"/clickhouse/{cluster_name}/",
                content=sql,
                params=params,
            )
            response.raise_for_status()

            # Parse TSV response into DataFrame.
            if response.text.strip():
                return pd.read_csv(io.StringIO(response.text), sep="\t")

            return pd.DataFrame()

    except Exception as e:
        error_msg = str(e)
        suggestion = _get_error_suggestion(error_msg)
        raise ClickHouseError(error_msg, suggestion) from e


def _get_error_suggestion(error_msg: str) -> str | None:
    """Get a helpful suggestion based on the error message."""
    if "TIMEOUT" in error_msg.upper() or "timeout" in error_msg.lower():
        return (
            "Query timed out. Ensure you're filtering by the table's partition column "
            "(usually slot_start_date_time) to avoid full table scans. "
            "Use clickhouse://tables/{table} resource to find the partition key."
        )
    elif "MEMORY_LIMIT" in error_msg.upper():
        return (
            "Query exceeded memory limit. Add more restrictive filters or use LIMIT clause. "
            "Consider filtering by partition key first."
        )
    elif "Unknown identifier" in error_msg or "no column" in error_msg.lower():
        return (
            "Check column names against clickhouse://tables/{table} resource. "
            "Column names are case-sensitive."
        )

    return None


def _build_query_params(parameters: dict[str, Any]) -> dict[str, str]:
    """Build ClickHouse HTTP query parameters for named parameters."""
    params: dict[str, str] = {}
    for key, value in parameters.items():
        params[f"param_{key}"] = _format_param_value(value)

    return params


def _format_param_value(value: Any) -> str:
    """Format a parameter value for ClickHouse HTTP interface."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if value is None:
        return ""

    return str(value)


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
        return [], list(df.columns)

    rows = [tuple(row) for row in df.values]
    columns = list(df.columns)

    return rows, columns
