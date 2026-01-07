# Xatu MCP Server Dockerfile
#
# Build:
#   docker build -t xatu-mcp:latest .
#
# Run:
#   docker run -p 8080:8080 -v /var/run/docker.sock:/var/run/docker.sock xatu-mcp:latest

FROM python:3.11-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy project files (including README.md required by pyproject.toml)
COPY pyproject.toml README.md ./
COPY src/ src/

# Install the package using uv
RUN uv pip install --system --no-cache .

# Runtime image
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash xatu && \
    usermod -aG docker xatu

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/xatu-mcp /usr/local/bin/xatu-mcp

# Copy source for reference
COPY --from=builder /app/src /app/src

# Create directories
RUN mkdir -p /config /shared /output && \
    chown -R xatu:xatu /app /config /shared /output

# Switch to non-root user (commented out for docker socket access)
# USER xatu

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Default command - start with SSE transport
ENTRYPOINT ["xatu-mcp"]
CMD ["serve", "--transport", "sse"]
