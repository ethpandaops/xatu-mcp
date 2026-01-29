"""Loki log access via direct connections.

This module provides functions to query Loki instances directly
using the HTTP API.

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
import logging
import os
import time as time_module
from dataclasses import dataclass
from typing import Any

import httpx

from ethpandaops._time import parse_duration

logger = logging.getLogger(__name__)


@dataclass
class _InstanceConfig:
    """Internal representation of a Loki instance configuration."""

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

    raw = os.environ.get("ETHPANDAOPS_LOKI_CONFIGS", "")
    if not raw:
        raise ValueError(
            "Loki not configured. Set ETHPANDAOPS_LOKI_CONFIGS environment variable."
        )

    try:
        configs = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid ETHPANDAOPS_LOKI_CONFIGS JSON: {e}") from e

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
    """Get an HTTP client for a Loki instance.

    Args:
        instance_name: The logical name of the Loki instance.

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
    """List available Loki instances.

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

    # Set default time range if not provided
    if start:
        params["start"] = _parse_time(start)
    else:
        params["start"] = _parse_time("now-1h")

    if end:
        params["end"] = _parse_time(end)
    else:
        params["end"] = _parse_time("now")

    with _get_client(instance_name) as client:
        response = client.get("/loki/api/v1/query_range", params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Loki query failed: {data.get('error', 'Unknown error')}"
            )

        # Parse the results
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

    with _get_client(instance_name) as client:
        response = client.get("/loki/api/v1/query", params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Loki query failed: {data.get('error', 'Unknown error')}"
            )

        # Parse the results
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
    with _get_client(instance_name) as client:
        params: dict[str, str] = {}
        if start:
            params["start"] = _parse_time(start)
        if end:
            params["end"] = _parse_time(end)

        response = client.get("/loki/api/v1/labels", params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Failed to get labels: {data.get('error', 'Unknown error')}"
            )

        return data["data"]


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
    with _get_client(instance_name) as client:
        params: dict[str, str] = {}
        if start:
            params["start"] = _parse_time(start)
        if end:
            params["end"] = _parse_time(end)

        response = client.get(f"/loki/api/v1/label/{label}/values", params=params)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise ValueError(
                f"Failed to get label values: {data.get('error', 'Unknown error')}"
            )

        return data["data"]
