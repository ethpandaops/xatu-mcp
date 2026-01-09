"""ClickHouse data access via Grafana proxy.

This module provides functions to query ClickHouse datasources
through Grafana's unified query API.

Example:
    from xatu import clickhouse

    # List available ClickHouse datasources
    datasources = clickhouse.list_datasources()

    # Query using datasource UID
    df = clickhouse.query("datasource-uid", "SELECT * FROM beacon_api_eth_v1_events_block LIMIT 10")
"""

import os
from typing import Any

import httpx
import pandas as pd


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

# Grafana configuration from environment variables
_GRAFANA_URL = os.environ.get("XATU_GRAFANA_URL", "")
_GRAFANA_TOKEN = os.environ.get("XATU_GRAFANA_TOKEN", "")
_HTTP_TIMEOUT = int(os.environ.get("XATU_HTTP_TIMEOUT", "120"))

# Cache for datasources
_DATASOURCES: dict[str, dict] | None = None


def _get_client() -> httpx.Client:
    """Create an HTTP client for Grafana API calls.

    Returns:
        Configured httpx client.

    Raises:
        ValueError: If Grafana is not configured.
    """
    if not _GRAFANA_URL or not _GRAFANA_TOKEN:
        raise ValueError(
            "Grafana not configured. "
            "Set XATU_GRAFANA_URL and XATU_GRAFANA_TOKEN environment variables."
        )

    return httpx.Client(
        base_url=_GRAFANA_URL,
        headers={
            "Authorization": f"Bearer {_GRAFANA_TOKEN}",
            "Content-Type": "application/json",
        },
        timeout=_HTTP_TIMEOUT,
    )


def list_datasources() -> list[dict]:
    """List available ClickHouse datasources from Grafana.

    Returns:
        List of datasource info dictionaries with uid, name, and type.

    Example:
        >>> datasources = list_datasources()
        >>> for ds in datasources:
        ...     print(f"{ds['name']}: {ds['uid']}")
    """
    global _DATASOURCES

    with _get_client() as client:
        resp = client.get("/api/datasources")
        resp.raise_for_status()

        datasources = []
        _DATASOURCES = {}

        for ds in resp.json():
            ds_type = ds.get("type", "").lower()
            if "clickhouse" in ds_type:
                info = {
                    "uid": ds["uid"],
                    "name": ds["name"],
                    "type": ds["type"],
                }
                datasources.append(info)
                _DATASOURCES[ds["uid"]] = info

        return datasources


def _get_datasource(datasource_uid: str) -> dict:
    """Get datasource info, discovering if necessary.

    Args:
        datasource_uid: The Grafana datasource UID.

    Returns:
        Datasource info dictionary.

    Raises:
        ValueError: If datasource is not found.
    """
    global _DATASOURCES

    if _DATASOURCES is None:
        list_datasources()

    if _DATASOURCES and datasource_uid in _DATASOURCES:
        return _DATASOURCES[datasource_uid]

    # Datasource not found, try to fetch it directly
    with _get_client() as client:
        resp = client.get(f"/api/datasources/uid/{datasource_uid}")
        if resp.status_code == 404:
            available = list(_DATASOURCES.keys()) if _DATASOURCES else []
            raise ValueError(
                f"Datasource '{datasource_uid}' not found. "
                f"Available ClickHouse datasources: {available}"
            )
        resp.raise_for_status()

        ds = resp.json()
        info = {
            "uid": ds["uid"],
            "name": ds["name"],
            "type": ds["type"],
        }

        if _DATASOURCES is not None:
            _DATASOURCES[ds["uid"]] = info

        return info


def query(
    datasource_uid: str,
    sql: str,
    parameters: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Execute a SQL query via Grafana and return results as a DataFrame.

    Args:
        datasource_uid: The Grafana datasource UID for the ClickHouse instance.
        sql: SQL query to execute.
        parameters: Optional query parameters (currently not supported via Grafana).

    Returns:
        DataFrame with query results.

    Raises:
        ValueError: If datasource is not found or query fails.

    Example:
        >>> df = query("my-clickhouse-uid", "SELECT * FROM blocks LIMIT 10")
    """
    if parameters:
        raise NotImplementedError(
            "Parameterized queries are not yet supported via Grafana proxy. "
            "Please inline your parameters in the SQL query."
        )

    ds = _get_datasource(datasource_uid)

    # Build Grafana unified query request
    import time

    now_ms = int(time.time() * 1000)
    from_ms = now_ms - (60 * 60 * 1000)  # 1 hour ago

    body = {
        "from": str(from_ms),
        "to": str(now_ms),
        "queries": [
            {
                "refId": "A",
                "datasource": {"uid": datasource_uid, "type": ds["type"]},
                "queryType": "sql",
                "editorType": "sql",
                "format": 1,  # Table format
                "intervalMs": 1000,
                "maxDataPoints": 10000,
                "rawSql": sql,
            },
        ],
    }

    with _get_client() as client:
        try:
            resp = client.post("/api/ds/query", json=body)
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            _raise_query_error(e, datasource_uid)

        return _parse_grafana_response(resp.json())


def _raise_query_error(error: httpx.HTTPStatusError, datasource_uid: str) -> None:
    """Convert HTTP errors to actionable ClickHouseError exceptions."""
    status = error.response.status_code
    schema_hint = (
        f"Use clickhouse-schema://{{cluster}}/{{table}} resource to find the "
        f"partition key for your table."
    )

    if status == 504:
        raise ClickHouseError(
            "Query timed out (504 Gateway Timeout)",
            f"Ensure you're filtering by the table's partition column to avoid "
            f"full table scans. {schema_hint}",
        ) from error
    elif status == 502:
        raise ClickHouseError(
            "Database temporarily unavailable (502 Bad Gateway)",
            f"This is usually temporary. Wait 10 seconds and retry. "
            f"If persistent, check that your query filters on the partition column. {schema_hint}",
        ) from error
    elif status == 400:
        # Try to extract actual error from response
        try:
            detail = error.response.text
        except Exception:
            detail = "Bad request"
        raise ClickHouseError(
            f"Query error (400): {detail}",
            f"Check column names and types against clickhouse-schema://{{cluster}}/{{table}} resource.",
        ) from error
    else:
        raise ClickHouseError(
            f"HTTP error {status}: {error.response.text}",
        ) from error


def _parse_grafana_response(data: dict) -> pd.DataFrame:
    """Parse a Grafana unified query response into a DataFrame.

    Args:
        data: Grafana API response.

    Returns:
        DataFrame with query results.

    Raises:
        ValueError: If the response contains an error.
    """
    results = data.get("results", {})

    for ref_id, result in results.items():
        # Check for errors
        if error := result.get("error"):
            raise ValueError(f"Query failed: {error}")

        frames = result.get("frames", [])
        if not frames:
            return pd.DataFrame()

        # Parse the first frame
        frame = frames[0]
        schema = frame.get("schema", {})
        fields = schema.get("fields", [])
        values = frame.get("data", {}).get("values", [])

        if not fields or not values:
            return pd.DataFrame()

        # Build DataFrame
        columns = [f["name"] for f in fields]
        data_dict = dict(zip(columns, values))

        return pd.DataFrame(data_dict)

    return pd.DataFrame()


def query_raw(
    datasource_uid: str,
    sql: str,
    parameters: dict[str, Any] | None = None,
) -> tuple[list[tuple], list[str]]:
    """Execute a SQL query and return raw results.

    Args:
        datasource_uid: The Grafana datasource UID.
        sql: SQL query to execute.
        parameters: Optional query parameters (currently not supported).

    Returns:
        Tuple of (rows, column_names).
    """
    df = query(datasource_uid, sql, parameters)

    if df.empty:
        return [], []

    rows = [tuple(row) for row in df.values]
    columns = list(df.columns)

    return rows, columns
