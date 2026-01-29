"""Shared time parsing utilities for Prometheus and Loki modules."""


def parse_duration(duration: str) -> int:
    """Parse a duration string to seconds.

    Args:
        duration: Duration string (e.g., "1h", "30m", "1d").

    Returns:
        Duration in seconds.

    Raises:
        ValueError: If the duration format is invalid.
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
