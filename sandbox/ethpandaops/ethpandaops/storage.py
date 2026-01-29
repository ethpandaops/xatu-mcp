"""S3-compatible storage for output files.

This module provides functions to upload files to S3-compatible storage
and get public URLs for sharing.

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

import boto3
from botocore.config import Config

_S3_ENDPOINT = os.environ.get("ETHPANDAOPS_S3_ENDPOINT", "")
_S3_ACCESS_KEY = os.environ.get("ETHPANDAOPS_S3_ACCESS_KEY", "")
_S3_SECRET_KEY = os.environ.get("ETHPANDAOPS_S3_SECRET_KEY", "")
_S3_BUCKET = os.environ.get("ETHPANDAOPS_S3_BUCKET", "mcp-outputs")
_S3_REGION = os.environ.get("ETHPANDAOPS_S3_REGION", "us-east-1")
_S3_PUBLIC_URL_PREFIX = os.environ.get("ETHPANDAOPS_S3_PUBLIC_URL_PREFIX", "")


def _get_client():
    """Get or create S3 client."""
    if not _S3_ENDPOINT:
        raise ValueError(
            "S3 storage not configured. Set ETHPANDAOPS_S3_ENDPOINT environment variable."
        )

    return boto3.client(
        "s3",
        endpoint_url=_S3_ENDPOINT,
        aws_access_key_id=_S3_ACCESS_KEY,
        aws_secret_access_key=_S3_SECRET_KEY,
        region_name=_S3_REGION,
        config=Config(signature_version="s3v4"),
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
        ValueError: If S3 is not configured.

    Example:
        >>> url = upload("/workspace/chart.png")
        >>> url = upload("/workspace/data.csv", remote_name="analysis_results.csv")
    """
    path = Path(local_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {local_path}")

    if remote_name is None:
        remote_name = path.name

    # Generate a unique key using execution context (set by sandbox)
    execution_id = os.environ.get("ETHPANDAOPS_EXECUTION_ID")
    if not execution_id:
        raise ValueError(
            "ETHPANDAOPS_EXECUTION_ID environment variable is required for uploads. "
            "This should be set automatically by the sandbox."
        )
    key = f"{execution_id}/{remote_name}"

    client = _get_client()

    # Determine content type
    content_type = _get_content_type(path.suffix)

    # Upload the file
    with open(path, "rb") as f:
        client.upload_fileobj(
            f,
            _S3_BUCKET,
            key,
            ExtraArgs={"ContentType": content_type},
        )

    # Build public URL
    if _S3_PUBLIC_URL_PREFIX:
        url = f"{_S3_PUBLIC_URL_PREFIX.rstrip('/')}/{key}"
    else:
        url = f"{_S3_ENDPOINT.rstrip('/')}/{_S3_BUCKET}/{key}"

    return url


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
    client = _get_client()

    response = client.list_objects_v2(Bucket=_S3_BUCKET, Prefix=prefix)

    files = []
    for obj in response.get("Contents", []):
        files.append({
            "key": obj["Key"],
            "size": obj["Size"],
            "last_modified": obj["LastModified"].isoformat(),
        })

    return files


def get_url(key: str) -> str:
    """Get the public URL for a file.

    Args:
        key: S3 object key.

    Returns:
        Public URL for the file.
    """
    if _S3_PUBLIC_URL_PREFIX:
        return f"{_S3_PUBLIC_URL_PREFIX.rstrip('/')}/{key}"
    else:
        return f"{_S3_ENDPOINT.rstrip('/')}/{_S3_BUCKET}/{key}"
