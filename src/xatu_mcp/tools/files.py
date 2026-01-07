"""File management tools for output files.

Note: S3 uploads are handled by user code inside the sandbox via xatu.storage.
These tools provide documentation on how to use file storage.
"""

import re
from typing import Any

import structlog
from mcp.types import TextContent, Tool

from xatu_mcp.config import Config

logger = structlog.get_logger()

# Valid filename pattern - alphanumeric, underscores, hyphens, dots, no path separators
_SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-][a-zA-Z0-9_\-\.]*$')


def _validate_filename(filename: str) -> str:
    """Validate a filename to prevent path traversal attacks.

    Args:
        filename: The filename to validate.

    Returns:
        The validated filename.

    Raises:
        ValueError: If the filename is invalid or potentially malicious.
    """
    if not filename:
        raise ValueError("filename cannot be empty")

    # Check for path traversal attempts
    if '/' in filename or '\\' in filename:
        raise ValueError("filename cannot contain path separators")
    if filename.startswith('.'):
        raise ValueError("filename cannot start with '.'")
    if '..' in filename:
        raise ValueError("filename cannot contain '..'")

    # Check against allowed pattern
    if not _SAFE_FILENAME_PATTERN.match(filename):
        raise ValueError(
            "filename must contain only alphanumeric characters, underscores, hyphens, and dots"
        )

    # Length check
    if len(filename) > 255:
        raise ValueError("filename too long (max 255 characters)")

    return filename


def build_file_tools() -> list[Tool]:
    """Build the file management tool definitions.

    Returns:
        List of Tool definitions for file management.
    """
    return [
        Tool(
            name="get_output_file",
            description="""Get information about how to retrieve output files.

Output files are uploaded from within sandbox code using xatu.storage:

```python
from xatu import storage

# Upload a file and get its URL
url = storage.upload("/output/chart.png")
print(f"Chart: {url}")
```

The URL is returned directly to stdout. This tool provides documentation
on how to use file storage in sandbox code.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Name of the file (for documentation purposes)",
                    },
                },
                "required": ["filename"],
            },
        ),
        Tool(
            name="list_output_files",
            description="""Get information about output file handling.

Output files should be uploaded from within sandbox code using xatu.storage.
This tool provides documentation on how files are handled.""",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


async def handle_get_output_file(
    arguments: dict[str, Any],
    _config: Config,
) -> list[TextContent]:
    """Handle the get_output_file tool call.

    Args:
        arguments: Tool arguments.
        _config: Server configuration (unused, kept for API consistency).

    Returns:
        Text content with usage information.
    """
    filename = arguments.get("filename")
    if filename:
        # Validate to prevent any path traversal in error messages
        try:
            _validate_filename(filename)
        except ValueError as e:
            raise ValueError(f"Invalid filename: {e}")

    return [
        TextContent(
            type="text",
            text="""Output files should be uploaded from within sandbox code.

Example:
```python
from xatu import storage

# Save your file to /output
plt.savefig('/output/chart.png')

# Upload and get URL
url = storage.upload('/output/chart.png')
print(f"Chart URL: {url}")
```

The URL will be printed to stdout and visible in the execution results.""",
        )
    ]


async def handle_list_output_files(
    arguments: dict[str, Any],
    _config: Config,
) -> list[TextContent]:
    """Handle the list_output_files tool call.

    Args:
        arguments: Tool arguments.
        _config: Server configuration (unused, kept for API consistency).

    Returns:
        Text content with usage information.
    """
    return [
        TextContent(
            type="text",
            text="""Output files are managed within sandbox code using xatu.storage.

Available functions:
- storage.upload(path) - Upload a file and get its public URL
- storage.upload(path, remote_name="custom.png") - Upload with custom name
- storage.list_files(prefix="") - List uploaded files
- storage.get_url(key) - Get URL for an existing file

Example workflow:
```python
from xatu import storage, clickhouse
import matplotlib.pyplot as plt

# Query data
df = clickhouse.query("mainnet", "SELECT * FROM beacon_api_eth_v1_events_block LIMIT 100")

# Create visualization
plt.figure(figsize=(10, 6))
plt.plot(df['slot'], df['block'])
plt.savefig('/output/blocks.png')

# Upload and get URL
url = storage.upload('/output/blocks.png')
print(f"Chart: {url}")
```""",
        )
    ]
