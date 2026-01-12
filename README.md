# xatu-mcp

An MCP server that provides AI assistants with Ethereum network analytics capabilities via [Xatu](https://github.com/ethpandaops/xatu) data.

Agents execute Python code in sandboxed containers with access to ClickHouse blockchain data, Prometheus metrics, Loki logs, and S3-compatible storage for outputs. All data queries are proxied through Grafana using datasource UIDs.

Read more: https://www.anthropic.com/engineering/code-execution-with-mcp

## Quick Start

```bash
# Configure
cp config.example.yaml config.yaml
# Edit config.yaml with your Grafana URL and service token

# Run (builds sandbox image, starts MinIO + MCP server)
docker-compose up -d
```

The server runs on port 2480 (SSE transport, configurable via `MCP_SERVER_PORT`) with MinIO on ports 2400/2401 (configurable via `MINIO_API_PORT`/`MINIO_CONSOLE_PORT`).

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "xatu": {
      "url": "http://localhost:2480/sse"
    }
  }
}
```

## Tools & Resources

| Tool | Description |
|------|-------------|
| `execute_python` | Execute Python in a sandbox with the `xatu` library |
| `search_examples` | Search for query examples and patterns |

Resources are available for datasource discovery (`datasources://`), network info (`networks://`), table schemas (`clickhouse://`), and API docs (`api://xatu`).

## Development

```bash
make build           # Build binary
make test            # Run tests
make lint            # Run linters
make docker          # Build Docker image
make docker-sandbox  # Build sandbox image
```

## License

MIT
