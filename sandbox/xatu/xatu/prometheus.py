"""Prometheus metrics access via Grafana proxy.

This module provides functions to query Prometheus datasources
through Grafana's datasource proxy.

Example:
    from xatu import prometheus

    # List available Prometheus datasources
    datasources = prometheus.list_datasources()

    # Instant query
    result = prometheus.query("datasource-uid", "up")

    # Range query
    result = prometheus.query_range(
        "datasource-uid",
        "rate(http_requests_total[5m])",
        start="now-1h",
        end="now",
        step="1m"
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
    """List available Prometheus datasources from Grafana.

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
            if "prometheus" in ds_type:
                info = {
                    "uid": ds["uid"],
                    "name": ds["name"],
                    "type": ds["type"],
                }
                datasources.append(info)
                _DATASOURCES[ds["uid"]] = info

        return datasources


def _parse_time(time_str: str) -> int:
    """Parse a time string to Unix timestamp.

    Args:
        time_str: Time string (e.g., "now", "now-1h", RFC3339, Unix timestamp).

    Returns:
        Unix timestamp in seconds.
    """
    if time_str == "now":
        return int(time_module.time())

    if time_str.startswith("now-"):
        duration = time_str[4:]
        seconds = _parse_duration(duration)
        return int(time_module.time()) - seconds

    # Try Unix timestamp
    try:
        return int(time_str)
    except ValueError:
        pass

    # Try float (Unix timestamp with decimals)
    try:
        return int(float(time_str))
    except ValueError:
        pass

    # Assume RFC3339
    from datetime import datetime

    try:
        dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        return int(dt.timestamp())
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


def query(datasource_uid: str, promql: str, time: str | None = None) -> dict[str, Any]:
    """Execute an instant PromQL query via Grafana proxy.

    Args:
        datasource_uid: The Grafana datasource UID for the Prometheus instance.
        promql: PromQL expression to evaluate.
        time: Evaluation timestamp (RFC3339 or Unix timestamp). Default: now.

    Returns:
        Query result as a dictionary with 'resultType' and 'result' keys.

    Example:
        >>> result = query("my-prometheus-uid", "up")
        >>> result = query("my-prometheus-uid", "rate(http_requests_total[5m])", time="2024-01-01T00:00:00Z")
    """
    params: dict[str, str] = {"query": promql}

    if time:
        params["time"] = str(_parse_time(time))
    else:
        params["time"] = str(int(time_module.time()))

    with _get_client() as client:
        url = f"/api/datasources/proxy/uid/{datasource_uid}/api/v1/query"
        response = client.get(url, params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(f"Prometheus query failed: {data.get('error', 'Unknown error')}")

        return data["data"]


def query_range(
    datasource_uid: str,
    promql: str,
    start: str,
    end: str,
    step: str,
) -> dict[str, Any]:
    """Execute a range PromQL query via Grafana proxy.

    Args:
        datasource_uid: The Grafana datasource UID for the Prometheus instance.
        promql: PromQL expression to evaluate.
        start: Start timestamp (e.g., "now-1h", RFC3339, or Unix timestamp).
        end: End timestamp (e.g., "now", RFC3339, or Unix timestamp).
        step: Query resolution step (e.g., "1m", "5m", "1h").

    Returns:
        Query result as a dictionary with 'resultType' and 'result' keys.

    Example:
        >>> result = query_range(
        ...     "my-prometheus-uid",
        ...     "rate(http_requests_total[5m])",
        ...     start="now-1h",
        ...     end="now",
        ...     step="1m"
        ... )
    """
    params = {
        "query": promql,
        "start": str(_parse_time(start)),
        "end": str(_parse_time(end)),
        "step": str(_parse_duration(step)),
    }

    with _get_client() as client:
        url = f"/api/datasources/proxy/uid/{datasource_uid}/api/v1/query_range"
        response = client.get(url, params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(f"Prometheus query failed: {data.get('error', 'Unknown error')}")

        return data["data"]


def get_labels(datasource_uid: str) -> list[str]:
    """Get all label names via Grafana proxy.

    Args:
        datasource_uid: The Grafana datasource UID for the Prometheus instance.

    Returns:
        List of label names.
    """
    with _get_client() as client:
        url = f"/api/datasources/proxy/uid/{datasource_uid}/api/v1/labels"
        response = client.get(url)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(f"Failed to get labels: {data.get('error', 'Unknown error')}")

        return data["data"]


def get_label_values(datasource_uid: str, label: str) -> list[str]:
    """Get all values for a label via Grafana proxy.

    Args:
        datasource_uid: The Grafana datasource UID for the Prometheus instance.
        label: Label name.

    Returns:
        List of label values.
    """
    with _get_client() as client:
        url = f"/api/datasources/proxy/uid/{datasource_uid}/api/v1/label/{label}/values"
        response = client.get(url)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(f"Failed to get label values: {data.get('error', 'Unknown error')}")

        return data["data"]
