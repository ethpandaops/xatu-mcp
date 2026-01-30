"""Loki log access via credential proxy.

This module provides functions to query Loki instances. All requests
go through the credential proxy - credentials are never exposed to sandbox
containers.

Example:
    from ethpandaops import loki

    # List available Loki instances
    instances = loki.list_datasources()

    # Query logs
    logs = loki.query("ethpandaops", '{app="beacon-node"}', limit=100)

    # Query with time range
    logs = loki.query(
        "ethpandaops",
        '{app="beacon-node"} |= "error"',
        start="now-1h",
        end="now",
        limit=50
    )
"""

import json
import os
import time as time_module
from typing import Any

import httpx

from ethpandaops._time import parse_duration

# Proxy configuration (required).
_PROXY_URL = os.environ.get("ETHPANDAOPS_PROXY_URL", "")
_PROXY_TOKEN = os.environ.get("ETHPANDAOPS_PROXY_TOKEN", "")

# Cache for datasource info.
_DATASOURCE_INFO: list[dict[str, str]] | None = None


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

    raw = os.environ.get("ETHPANDAOPS_LOKI_DATASOURCES", "")
    if not raw:
        _DATASOURCE_INFO = []
        return _DATASOURCE_INFO

    try:
        _DATASOURCE_INFO = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid ETHPANDAOPS_LOKI_DATASOURCES JSON: {e}") from e

    return _DATASOURCE_INFO


def _get_datasource_names() -> list[str]:
    """Get list of datasource names for validation."""
    return [ds["name"] for ds in _load_datasources()]


def _get_client(datasource: str) -> httpx.Client:
    """Get an HTTP client configured for the proxy with the specified datasource."""
    _check_proxy_config()

    return httpx.Client(
        base_url=_PROXY_URL,
        headers={
            "Authorization": f"Bearer {_PROXY_TOKEN}",
            "X-Datasource": datasource,
        },
        timeout=httpx.Timeout(connect=5.0, read=120.0, write=30.0, pool=5.0),
    )


def list_datasources() -> list[dict[str, Any]]:
    """List available Loki instances.

    Returns:
        List of instance info dictionaries with name, description, and url.

    Example:
        >>> instances = list_datasources()
        >>> for inst in instances:
        ...     print(f"{inst['name']}: {inst['description']}")
    """
    return _load_datasources()


def _parse_time(time_str: str) -> str:
    """Parse a time string to nanosecond Unix timestamp string.

    Args:
        time_str: Time string (e.g., "now", "now-1h", RFC3339, Unix timestamp).

    Returns:
        Unix timestamp in nanoseconds as string.
    """
    if time_str == "now":
        return str(int(time_module.time() * 1_000_000_000))

    if time_str.startswith("now-"):
        duration = time_str[4:]
        seconds = parse_duration(duration)
        return str(int((time_module.time() - seconds) * 1_000_000_000))

    # Try Unix timestamp (seconds).
    try:
        ts = int(time_str)
        # If it looks like seconds (< 1e12), convert to nanoseconds.
        if ts < 1_000_000_000_000:
            return str(ts * 1_000_000_000)
        return str(ts)
    except ValueError:
        pass

    # Try float (Unix timestamp with decimals).
    try:
        ts = float(time_str)
        return str(int(ts * 1_000_000_000))
    except ValueError:
        pass

    # Assume RFC3339.
    from datetime import datetime

    try:
        dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        return str(int(dt.timestamp() * 1_000_000_000))
    except ValueError as e:
        raise ValueError(f"Cannot parse time '{time_str}': {e}") from e


def _parse_log_results(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse Loki query results into a list of log entries."""
    results = []
    for stream in data.get("data", {}).get("result", []):
        labels = stream.get("stream", {})
        for value in stream.get("values", []):
            timestamp, line = value
            results.append(
                {
                    "timestamp": timestamp,
                    "labels": labels,
                    "line": line,
                }
            )

    return results


def _query_api(
    instance_name: str, path: str, params: dict[str, Any]
) -> list[dict[str, Any]]:
    """Execute a query against the Loki API via proxy."""
    datasources = _get_datasource_names()
    if instance_name not in datasources:
        raise ValueError(
            f"Unknown instance '{instance_name}'. Available instances: {datasources}"
        )

    with _get_client(instance_name) as client:
        response = client.get(f"/loki{path}", params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Loki query failed: {data.get('error', 'Unknown error')}"
            )

        return _parse_log_results(data)


def _query_labels_api(
    instance_name: str, path: str, params: dict[str, str]
) -> list[str]:
    """Execute a labels query against the Loki API via proxy."""
    datasources = _get_datasource_names()
    if instance_name not in datasources:
        raise ValueError(
            f"Unknown instance '{instance_name}'. Available instances: {datasources}"
        )

    with _get_client(instance_name) as client:
        response = client.get(f"/loki{path}", params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Failed to get labels: {data.get('error', 'Unknown error')}"
            )

        return data["data"]


def query(
    instance_name: str,
    logql: str,
    limit: int = 100,
    start: str | None = None,
    end: str | None = None,
    direction: str = "backward",
) -> list[dict[str, Any]]:
    """Execute a LogQL query.

    Args:
        instance_name: The logical name of the Loki instance.
        logql: LogQL query string.
        limit: Maximum number of log lines to return (default: 100).
        start: Start time (RFC3339, "now-1h" format, or Unix timestamp). Default: now-1h.
        end: End time (RFC3339, "now" format, or Unix timestamp). Default: now.
        direction: Sort direction: "forward" (oldest first) or "backward" (newest first).

    Returns:
        List of log entries, each with 'timestamp', 'labels', and 'line' keys.

    Example:
        >>> logs = query("ethpandaops", '{app="beacon-node"}', limit=10)
        >>> logs = query("ethpandaops", '{app="beacon-node"} |= "error"', start="now-1h", limit=50)
    """
    params: dict[str, Any] = {
        "query": logql,
        "limit": limit,
        "direction": direction,
    }

    # Set default time range if not provided.
    if start:
        params["start"] = _parse_time(start)
    else:
        params["start"] = _parse_time("now-1h")

    if end:
        params["end"] = _parse_time(end)
    else:
        params["end"] = _parse_time("now")

    return _query_api(instance_name, "/loki/api/v1/query_range", params)


def query_instant(
    instance_name: str,
    logql: str,
    time: str | None = None,
    limit: int = 100,
    direction: str = "backward",
) -> list[dict[str, Any]]:
    """Execute an instant LogQL query.

    Args:
        instance_name: The logical name of the Loki instance.
        logql: LogQL query string.
        time: Evaluation timestamp (RFC3339 or Unix timestamp). Default: now.
        limit: Maximum number of log lines to return (default: 100).
        direction: Sort direction: "forward" (oldest first) or "backward" (newest first).

    Returns:
        List of log entries, each with 'timestamp', 'labels', and 'line' keys.
    """
    params: dict[str, Any] = {
        "query": logql,
        "limit": limit,
        "direction": direction,
    }

    if time:
        params["time"] = _parse_time(time)
    else:
        params["time"] = _parse_time("now")

    return _query_api(instance_name, "/loki/api/v1/query", params)


def get_labels(
    instance_name: str,
    start: str | None = None,
    end: str | None = None,
) -> list[str]:
    """Get all label names.

    Args:
        instance_name: The logical name of the Loki instance.
        start: Start time for label discovery.
        end: End time for label discovery.

    Returns:
        List of label names.
    """
    params: dict[str, str] = {}
    if start:
        params["start"] = _parse_time(start)
    if end:
        params["end"] = _parse_time(end)

    return _query_labels_api(instance_name, "/loki/api/v1/labels", params)


def get_label_values(
    instance_name: str,
    label: str,
    start: str | None = None,
    end: str | None = None,
) -> list[str]:
    """Get all values for a label.

    Args:
        instance_name: The logical name of the Loki instance.
        label: Label name.
        start: Start time for value discovery.
        end: End time for value discovery.

    Returns:
        List of label values.
    """
    params: dict[str, str] = {}
    if start:
        params["start"] = _parse_time(start)
    if end:
        params["end"] = _parse_time(end)

    path = f"/loki/api/v1/label/{label}/values"
    return _query_labels_api(instance_name, path, params)
