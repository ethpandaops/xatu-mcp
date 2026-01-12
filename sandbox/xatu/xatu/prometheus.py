"""Prometheus metrics access via direct connections.

This module provides functions to query Prometheus instances directly
using the HTTP API.

Example:
    from xatu import prometheus

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
import logging
import os
import time as time_module
from dataclasses import dataclass
from typing import Any

import httpx

from ._time import parse_duration

logger = logging.getLogger(__name__)


@dataclass
class _InstanceConfig:
    """Internal representation of a Prometheus instance configuration."""

    name: str
    url: str
    username: str
    password: str
    skip_verify: bool
    timeout: int
    description: str


# Cache for instance configurations.
_INSTANCES: dict[str, _InstanceConfig] | None = None


def _load_instances() -> None:
    """Load instance configurations from environment variable."""
    global _INSTANCES

    if _INSTANCES is not None:
        return

    raw = os.environ.get("XATU_PROMETHEUS_CONFIGS", "")
    if not raw:
        raise ValueError(
            "Prometheus not configured. Set XATU_PROMETHEUS_CONFIGS environment variable."
        )

    try:
        configs = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid XATU_PROMETHEUS_CONFIGS JSON: {e}") from e

    _INSTANCES = {}
    for cfg in configs:
        skip_verify = cfg.get("skip_verify", False)
        if skip_verify:
            logger.warning(
                "TLS certificate verification disabled (skip_verify=true) for %s - vulnerable to MITM attacks",
                cfg["name"],
            )

        instance = _InstanceConfig(
            name=cfg["name"],
            url=cfg.get("url", "").rstrip("/"),
            username=cfg.get("username", ""),
            password=cfg.get("password", ""),
            skip_verify=skip_verify,
            timeout=cfg.get("timeout", 60),
            description=cfg.get("description", ""),
        )
        _INSTANCES[instance.name] = instance


def _get_client(instance_name: str) -> httpx.Client:
    """Get an HTTP client for a Prometheus instance.

    Args:
        instance_name: The logical name of the Prometheus instance.

    Returns:
        An httpx client configured for the instance.

    Raises:
        ValueError: If the instance is not found.
    """
    _load_instances()

    if _INSTANCES is None or instance_name not in _INSTANCES:
        available = list(_INSTANCES.keys()) if _INSTANCES else []
        raise ValueError(
            f"Unknown instance '{instance_name}'. Available instances: {available}"
        )

    instance = _INSTANCES[instance_name]

    # Configure authentication
    auth = None
    if instance.username:
        auth = (instance.username, instance.password)

    # Configure TLS verification
    verify = not instance.skip_verify

    # Configure granular timeout (connect, read, write, pool)
    timeout = httpx.Timeout(
        connect=5.0,
        read=float(instance.timeout),
        write=float(instance.timeout),
        pool=5.0,
    )

    return httpx.Client(
        base_url=instance.url,
        auth=auth,
        timeout=timeout,
        verify=verify,
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
    _load_instances()

    if _INSTANCES is None:
        return []

    return [
        {
            "name": inst.name,
            "description": inst.description,
            "url": inst.url,
        }
        for inst in _INSTANCES.values()
    ]


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

    with _get_client(instance_name) as client:
        response = client.get("/api/v1/query", params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Prometheus query failed: {data.get('error', 'Unknown error')}"
            )

        return data["data"]


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

    with _get_client(instance_name) as client:
        response = client.get("/api/v1/query_range", params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Prometheus query failed: {data.get('error', 'Unknown error')}"
            )

        return data["data"]


def get_labels(instance_name: str) -> list[str]:
    """Get all label names.

    Args:
        instance_name: The logical name of the Prometheus instance.

    Returns:
        List of label names.
    """
    with _get_client(instance_name) as client:
        response = client.get("/api/v1/labels")
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Failed to get labels: {data.get('error', 'Unknown error')}"
            )

        return data["data"]


def get_label_values(instance_name: str, label: str) -> list[str]:
    """Get all values for a label.

    Args:
        instance_name: The logical name of the Prometheus instance.
        label: Label name.

    Returns:
        List of label values.
    """
    with _get_client(instance_name) as client:
        response = client.get(f"/api/v1/label/{label}/values")
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Failed to get label values: {data.get('error', 'Unknown error')}"
            )

        return data["data"]
