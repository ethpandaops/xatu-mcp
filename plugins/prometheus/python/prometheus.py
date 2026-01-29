"""Prometheus metrics access via credential proxy.

This module provides functions to query Prometheus instances. All requests
go through the credential proxy - credentials are never exposed to sandbox
containers.

Example:
    from ethpandaops import prometheus

    # List available Prometheus instances
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

    raw = os.environ.get("ETHPANDAOPS_PROMETHEUS_DATASOURCES", "")
    if not raw:
        _DATASOURCE_INFO = []
        return _DATASOURCE_INFO

    try:
        _DATASOURCE_INFO = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid ETHPANDAOPS_PROMETHEUS_DATASOURCES JSON: {e}") from e

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
        timeout=httpx.Timeout(connect=5.0, read=120.0, write=30.0, pool=5.0),
    )


def list_datasources() -> list[dict[str, Any]]:
    """List available Prometheus instances.

    Returns:
        List of instance info dictionaries with name, description, and url.

    Example:
        >>> instances = list_datasources()
        >>> for inst in instances:
        ...     print(f"{inst['name']}: {inst['description']}")
    """
    return _load_datasources()


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
        seconds = parse_duration(duration)
        return int(time_module.time()) - seconds

    # Try Unix timestamp.
    try:
        return int(time_str)
    except ValueError:
        pass

    # Try float (Unix timestamp with decimals).
    try:
        return int(float(time_str))
    except ValueError:
        pass

    # Assume RFC3339.
    from datetime import datetime

    try:
        dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        return int(dt.timestamp())
    except ValueError as e:
        raise ValueError(f"Cannot parse time '{time_str}': {e}") from e


def _query_api(instance_name: str, path: str, params: dict[str, str]) -> dict[str, Any]:
    """Execute a query against the Prometheus API via proxy."""
    datasources = _get_datasource_names()
    if instance_name not in datasources:
        raise ValueError(
            f"Unknown instance '{instance_name}'. Available instances: {datasources}"
        )

    with _get_client() as client:
        response = client.get(f"/prometheus/{instance_name}{path}", params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Prometheus query failed: {data.get('error', 'Unknown error')}"
            )

        return data["data"]


def query(
    instance_name: str,
    promql: str,
    time: str | None = None,
) -> dict[str, Any]:
    """Execute an instant PromQL query.

    Args:
        instance_name: The logical name of the Prometheus instance.
        promql: PromQL expression to evaluate.
        time: Evaluation timestamp (RFC3339 or Unix timestamp). Default: now.

    Returns:
        Query result as a dictionary with 'resultType' and 'result' keys.

    Example:
        >>> result = query("ethpandaops", "up")
        >>> result = query("ethpandaops", "rate(http_requests_total[5m])", time="2024-01-01T00:00:00Z")
    """
    params: dict[str, str] = {"query": promql}

    if time:
        params["time"] = str(_parse_time(time))
    else:
        params["time"] = str(int(time_module.time()))

    return _query_api(instance_name, "/api/v1/query", params)


def query_range(
    instance_name: str,
    promql: str,
    start: str,
    end: str,
    step: str,
) -> dict[str, Any]:
    """Execute a range PromQL query.

    Args:
        instance_name: The logical name of the Prometheus instance.
        promql: PromQL expression to evaluate.
        start: Start timestamp (e.g., "now-1h", RFC3339, or Unix timestamp).
        end: End timestamp (e.g., "now", RFC3339, or Unix timestamp).
        step: Query resolution step (e.g., "1m", "5m", "1h").

    Returns:
        Query result as a dictionary with 'resultType' and 'result' keys.

    Example:
        >>> result = query_range(
        ...     "ethpandaops",
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
        "step": str(parse_duration(step)),
    }

    return _query_api(instance_name, "/api/v1/query_range", params)


def get_labels(instance_name: str) -> list[str]:
    """Get all label names.

    Args:
        instance_name: The logical name of the Prometheus instance.

    Returns:
        List of label names.
    """
    return _query_api(instance_name, "/api/v1/labels", {})


def get_label_values(instance_name: str, label: str) -> list[str]:
    """Get all values for a label.

    Args:
        instance_name: The logical name of the Prometheus instance.
        label: Label name.

    Returns:
        List of label values.
    """
    path = f"/api/v1/label/{label}/values"
    return _query_api(instance_name, path, {})
