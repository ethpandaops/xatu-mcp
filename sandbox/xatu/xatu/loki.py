"""Loki log access via Grafana proxy.

This module provides functions to query Loki datasources
through Grafana's datasource proxy.

Example:
    from xatu import loki

    # List available Loki datasources
    datasources = loki.list_datasources()

    # Query logs
    logs = loki.query("datasource-uid", '{app="beacon-node"}', limit=100)

    # Query with time range
    logs = loki.query(
        "datasource-uid",
        '{app="beacon-node"} |= "error"',
        start="now-1h",
        end="now",
        limit=50
    )
"""

import os
import time as time_module
from typing import Any

import httpx

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
    """List available Loki datasources from Grafana.

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
            if "loki" in ds_type:
                info = {
                    "uid": ds["uid"],
                    "name": ds["name"],
                    "type": ds["type"],
                }
                datasources.append(info)
                _DATASOURCES[ds["uid"]] = info

        return datasources


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
        seconds = _parse_duration(duration)
        return str(int((time_module.time() - seconds) * 1_000_000_000))

    # Try Unix timestamp (seconds)
    try:
        ts = int(time_str)
        # If it looks like seconds (< 1e12), convert to nanoseconds
        if ts < 1_000_000_000_000:
            return str(ts * 1_000_000_000)
        return str(ts)
    except ValueError:
        pass

    # Try float (Unix timestamp with decimals)
    try:
        ts = float(time_str)
        return str(int(ts * 1_000_000_000))
    except ValueError:
        pass

    # Assume RFC3339
    from datetime import datetime

    try:
        dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        return str(int(dt.timestamp() * 1_000_000_000))
    except ValueError as e:
        raise ValueError(f"Cannot parse time '{time_str}': {e}") from e


def _parse_duration(duration: str) -> int:
    """Parse a duration string to seconds.

    Args:
        duration: Duration string (e.g., "1h", "30m", "1d").

    Returns:
        Duration in seconds.
    """
    units = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 604800,
    }

    if not duration:
        return 0

    unit = duration[-1].lower()
    if unit not in units:
        raise ValueError(f"Unknown duration unit: {unit}")

    try:
        value = int(duration[:-1])
    except ValueError as e:
        raise ValueError(f"Invalid duration value: {duration}") from e

    return value * units[unit]


def query(
    datasource_uid: str,
    logql: str,
    limit: int = 100,
    start: str | None = None,
    end: str | None = None,
    direction: str = "backward",
) -> list[dict[str, Any]]:
    """Execute a LogQL query via Grafana proxy.

    Args:
        datasource_uid: The Grafana datasource UID for the Loki instance.
        logql: LogQL query string.
        limit: Maximum number of log lines to return (default: 100).
        start: Start time (RFC3339, "now-1h" format, or Unix timestamp). Default: now-1h.
        end: End time (RFC3339, "now" format, or Unix timestamp). Default: now.
        direction: Sort direction: "forward" (oldest first) or "backward" (newest first).

    Returns:
        List of log entries, each with 'timestamp', 'labels', and 'line' keys.

    Example:
        >>> logs = query("my-loki-uid", '{app="beacon-node"}', limit=10)
        >>> logs = query("my-loki-uid", '{app="beacon-node"} |= "error"', start="now-1h", limit=50)
    """
    params: dict[str, Any] = {
        "query": logql,
        "limit": limit,
        "direction": direction,
    }

    # Set default time range if not provided
    if start:
        params["start"] = _parse_time(start)
    else:
        params["start"] = _parse_time("now-1h")

    if end:
        params["end"] = _parse_time(end)
    else:
        params["end"] = _parse_time("now")

    with _get_client() as client:
        url = f"/api/datasources/proxy/uid/{datasource_uid}/loki/api/v1/query_range"
        response = client.get(url, params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(f"Loki query failed: {data.get('error', 'Unknown error')}")

        # Parse the results
        results = []
        for stream in data.get("data", {}).get("result", []):
            labels = stream.get("stream", {})
            for value in stream.get("values", []):
                timestamp, line = value
                results.append({
                    "timestamp": timestamp,
                    "labels": labels,
                    "line": line,
                })

        return results


def query_instant(
    datasource_uid: str,
    logql: str,
    time: str | None = None,
    limit: int = 100,
    direction: str = "backward",
) -> list[dict[str, Any]]:
    """Execute an instant LogQL query via Grafana proxy.

    Args:
        datasource_uid: The Grafana datasource UID for the Loki instance.
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

    with _get_client() as client:
        url = f"/api/datasources/proxy/uid/{datasource_uid}/loki/api/v1/query"
        response = client.get(url, params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(f"Loki query failed: {data.get('error', 'Unknown error')}")

        # Parse the results
        results = []
        for stream in data.get("data", {}).get("result", []):
            labels = stream.get("stream", {})
            for value in stream.get("values", []):
                timestamp, line = value
                results.append({
                    "timestamp": timestamp,
                    "labels": labels,
                    "line": line,
                })

        return results


def get_labels(
    datasource_uid: str,
    start: str | None = None,
    end: str | None = None,
) -> list[str]:
    """Get all label names via Grafana proxy.

    Args:
        datasource_uid: The Grafana datasource UID for the Loki instance.
        start: Start time for label discovery.
        end: End time for label discovery.

    Returns:
        List of label names.
    """
    with _get_client() as client:
        params: dict[str, str] = {}
        if start:
            params["start"] = _parse_time(start)
        if end:
            params["end"] = _parse_time(end)

        url = f"/api/datasources/proxy/uid/{datasource_uid}/loki/api/v1/labels"
        response = client.get(url, params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(f"Failed to get labels: {data.get('error', 'Unknown error')}")

        return data["data"]


def get_label_values(
    datasource_uid: str,
    label: str,
    start: str | None = None,
    end: str | None = None,
) -> list[str]:
    """Get all values for a label via Grafana proxy.

    Args:
        datasource_uid: The Grafana datasource UID for the Loki instance.
        label: Label name.
        start: Start time for value discovery.
        end: End time for value discovery.

    Returns:
        List of label values.
    """
    with _get_client() as client:
        params: dict[str, str] = {}
        if start:
            params["start"] = _parse_time(start)
        if end:
            params["end"] = _parse_time(end)

        url = f"/api/datasources/proxy/uid/{datasource_uid}/loki/api/v1/label/{label}/values"
        response = client.get(url, params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(f"Failed to get label values: {data.get('error', 'Unknown error')}")

        return data["data"]
