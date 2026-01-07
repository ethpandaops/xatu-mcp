# Xatu MCP Sandbox Container
# This container provides a secure execution environment for Python code
# with the xatu library pre-installed for Ethereum network data analysis.

FROM python:3.11-slim

# Install uv and system dependencies
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -s /bin/bash sandbox

# Create directories
RUN mkdir -p /shared /output && \
    chown sandbox:sandbox /shared /output

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN uv pip install --system --no-cache -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Install the xatu library
COPY xatu /opt/xatu
RUN uv pip install --system --no-cache /opt/xatu && rm -rf /opt/xatu

# Set working directory
WORKDIR /home/sandbox

# Switch to non-root user
USER sandbox

# Default command (overridden by the sandbox backend)
CMD ["python", "--version"]
