"""S3-compatible storage for output files via credential proxy.

This module provides functions to upload files to S3-compatible storage
and get public URLs for sharing. All requests go through the credential
proxy - credentials are never exposed to sandbox containers.

Example:
    from ethpandaops import storage

    # Upload a file
    url = storage.upload("/workspace/chart.png")
    print(f"Chart available at: {url}")

    # Upload with custom name
    url = storage.upload("/workspace/data.csv", remote_name="results.csv")
"""

import os
from pathlib import Path

import httpx

# Proxy configuration (required).
_PROXY_URL = os.environ.get("ETHPANDAOPS_PROXY_URL", "")
_PROXY_TOKEN = os.environ.get("ETHPANDAOPS_PROXY_TOKEN", "")

# S3 configuration.
_S3_BUCKET = os.environ.get("ETHPANDAOPS_S3_BUCKET", "mcp-outputs")
_S3_PUBLIC_URL_PREFIX = os.environ.get("ETHPANDAOPS_S3_PUBLIC_URL_PREFIX", "")


def _check_proxy_config() -> None:
    """Verify proxy is configured."""
    if not _PROXY_URL or not _PROXY_TOKEN:
        raise ValueError(
            "Proxy not configured. ETHPANDAOPS_PROXY_URL and ETHPANDAOPS_PROXY_TOKEN are required."
        )


def _get_client() -> httpx.Client:
    """Get an HTTP client configured for the proxy."""
    _check_proxy_config()

    return httpx.Client(
        base_url=_PROXY_URL,
        headers={"Authorization": f"Bearer {_PROXY_TOKEN}"},
        timeout=httpx.Timeout(connect=5.0, read=300.0, write=300.0, pool=5.0),
    )


def upload(local_path: str, remote_name: str | None = None) -> str:
    """Upload a file to S3 storage.

    Args:
        local_path: Path to the local file to upload.
        remote_name: Name for the file in S3. If None, uses the local filename.

    Returns:
        Public URL for the uploaded file.

    Raises:
        FileNotFoundError: If the local file doesn't exist.
        ValueError: If proxy is not configured.

    Example:
        >>> url = upload("/workspace/chart.png")
        >>> url = upload("/workspace/data.csv", remote_name="analysis_results.csv")
    """
    path = Path(local_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {local_path}")

    if remote_name is None:
        remote_name = path.name

    # Generate a unique key using execution context (set by sandbox).
    execution_id = os.environ.get("ETHPANDAOPS_EXECUTION_ID")
    if not execution_id:
        raise ValueError(
            "ETHPANDAOPS_EXECUTION_ID environment variable is required for uploads. "
            "This should be set automatically by the sandbox."
        )
    key = f"{execution_id}/{remote_name}"

    content_type = _get_content_type(path.suffix)

    with _get_client() as client:
        with open(path, "rb") as f:
            response = client.put(
                f"/s3/{_S3_BUCKET}/{key}",
                content=f.read(),
                headers={"Content-Type": content_type},
            )
            response.raise_for_status()

    # Build public URL.
    return _get_public_url(key)


def _get_public_url(key: str) -> str:
    """Build the public URL for an S3 object."""
    if _S3_PUBLIC_URL_PREFIX:
        return f"{_S3_PUBLIC_URL_PREFIX.rstrip('/')}/{key}"
    else:
        # Fallback to proxy URL (won't work for public access, but useful for debugging).
        return f"{_PROXY_URL.rstrip('/')}/s3/{_S3_BUCKET}/{key}"


def _get_content_type(suffix: str) -> str:
    """Get MIME type for a file suffix.

    Args:
        suffix: File suffix including the dot (e.g., ".png").

    Returns:
        MIME type string.
    """
    content_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".svg": "image/svg+xml",
        ".pdf": "application/pdf",
        ".csv": "text/csv",
        ".json": "application/json",
        ".html": "text/html",
        ".txt": "text/plain",
        ".parquet": "application/octet-stream",
    }

    return content_types.get(suffix.lower(), "application/octet-stream")


def list_files(prefix: str = "") -> list[dict]:
    """List files in the S3 bucket.

    Args:
        prefix: Optional prefix to filter files.

    Returns:
        List of file info dictionaries with 'key', 'size', 'last_modified'.
    """
    _check_proxy_config()

    params: dict[str, str] = {"list-type": "2"}
    if prefix:
        params["prefix"] = prefix

    results: list[dict] = []
    continuation_token: str | None = None

    with _get_client() as client:
        while True:
            if continuation_token:
                params["continuation-token"] = continuation_token

            response = client.get(f"/s3/{_S3_BUCKET}", params=params)
            response.raise_for_status()

            page_results, continuation_token = _parse_list_response(response.text)
            results.extend(page_results)
            if not continuation_token:
                break

    return results


def _parse_list_response(xml_text: str) -> tuple[list[dict], str | None]:
    """Parse S3 list response XML into file info dicts and continuation token."""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml_text)

    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag.split("}")[0].strip("{")

    def _tag(name: str) -> str:
        return f"{{{namespace}}}{name}" if namespace else name

    results: list[dict] = []
    for entry in root.findall(_tag("Contents")):
        key_elem = entry.find(_tag("Key"))
        size_elem = entry.find(_tag("Size"))
        last_modified_elem = entry.find(_tag("LastModified"))

        key = key_elem.text if key_elem is not None and key_elem.text else ""
        size_text = size_elem.text if size_elem is not None and size_elem.text else "0"
        last_modified = (
            last_modified_elem.text
            if last_modified_elem is not None and last_modified_elem.text
            else ""
        )

        try:
            size = int(size_text)
        except ValueError:
            size = 0

        if key:
            results.append(
                {"key": key, "size": size, "last_modified": last_modified}
            )

    is_truncated = root.findtext(_tag("IsTruncated"), default="false").lower()
    if is_truncated != "true":
        return results, None

    token = root.findtext(_tag("NextContinuationToken"), default="")
    return results, token or None


def get_url(key: str) -> str:
    """Get the public URL for a file.

    Args:
        key: S3 object key.

    Returns:
        Public URL for the file.
    """
    return _get_public_url(key)
