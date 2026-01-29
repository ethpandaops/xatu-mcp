# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ethpandaops/mcp is an MCP (Model Context Protocol) server that provides AI assistants with Ethereum network analytics capabilities. It enables agents to execute Python code in sandboxed containers with access to ClickHouse blockchain data, Prometheus metrics, Loki logs, and S3-compatible storage for outputs.

Data queries connect directly to configured datasources (ClickHouse, Prometheus, Loki) without intermediate proxies.

The server uses a **plugin architecture** where each datasource (ClickHouse, Prometheus, Loki) is a self-contained plugin that owns its config schema, validation, environment variables, Python module, examples, and optional MCP resources.

## Commands

```bash
# Build
make build                    # Build binary
make docker                   # Build Docker image
make docker-sandbox           # Build sandbox container image

# Test
make test                     # Run tests with race detector
make test-coverage            # Run tests with coverage report

# Lint and format
make lint                     # Run golangci-lint
make lint-fix                 # Run golangci-lint with auto-fix
make fmt                      # Format code

# Run
make run                      # Run with stdio transport
make run-sse                  # Run with SSE transport on port 2480
./mcp serve                   # Start server (default: stdio)
./mcp serve -t sse -p 2480   # Start with SSE transport

# Evaluation tests (in tests/eval/)
cd tests/eval && uv sync      # Install Python dependencies
uv run python -m scripts.run_eval  # Run eval tests
uv run python -m scripts.repl      # Interactive REPL
```

## Architecture

```
pkg/
├── types/           # Shared types (DatasourceInfo, ExampleCategory, ModuleDoc)
├── plugin/          # Plugin interface and registry
│   ├── plugin.go    # Plugin interface contract
│   └── registry.go  # Plugin lifecycle management
├── server/          # MCP server implementation
│   ├── server.go    # Service interface, transport handlers (stdio/SSE/HTTP)
│   └── builder.go   # Dependency injection, plugin lifecycle, service wiring
├── tool/            # MCP tools (execute_python, search_examples)
│   ├── registry.go  # Tool registration interface
│   └── execute_python.go  # Main tool for Python sandbox execution
├── resource/        # MCP resources (datasources, networks, examples, API docs)
│   ├── registry.go  # Static and template resource handlers
│   └── *.go         # Individual resource providers
├── sandbox/         # Sandboxed code execution
│   ├── sandbox.go   # Service interface (Docker/gVisor backends)
│   ├── docker.go    # Docker container execution
│   ├── gvisor.go    # gVisor-based execution (production)
│   └── session.go   # Session management for persistent containers
├── auth/            # GitHub OAuth authentication
├── config/          # Configuration loading and validation
├── embedding/       # GGUF embedding model for semantic search
└── observability/   # Prometheus metrics

plugins/
├── clickhouse/      # ClickHouse datasource plugin
│   ├── plugin.go    # Plugin implementation
│   ├── config.go    # Cluster and schema discovery config
│   ├── schema.go    # ClickHouse schema discovery client
│   ├── resources.go # clickhouse://tables MCP resources
│   ├── examples.go  # Embedded query examples
│   ├── examples.yaml
│   └── python/
│       └── clickhouse.py  # Python module for sandbox
├── prometheus/      # Prometheus datasource plugin
│   ├── plugin.go
│   ├── config.go
│   ├── examples.go
│   ├── examples.yaml
│   └── python/
│       └── prometheus.py
└── loki/            # Loki datasource plugin
    ├── plugin.go
    ├── config.go
    ├── examples.go
    ├── examples.yaml
    └── python/
        └── loki.py

sandbox/             # Sandbox Docker image
├── Dockerfile       # Python 3.11 slim with data analysis libraries
├── requirements.txt # Shared pip dependencies
└── ethpandaops/     # Platform Python package
    ├── pyproject.toml
    └── ethpandaops/
        ├── __init__.py   # Lazy imports for plugin modules
        ├── _time.py      # Shared time utilities
        └── storage.py    # S3 storage module

tests/eval/          # LLM evaluation harness
├── agent/           # Claude Agent SDK wrapper
├── metrics/         # Custom DeepEval metrics
├── cases/           # Test cases in YAML format
└── scripts/         # CLI tools (run_eval, repl, langfuse)
```

## Key Patterns

### Plugin Architecture
Each datasource is a self-contained plugin implementing `plugin.Plugin`:
- **Config**: Own YAML schema, defaults, and validation
- **Env vars**: Builds environment variables for sandbox containers
- **Resources**: Registers custom MCP resources (e.g., `clickhouse://tables`)
- **Examples**: Embedded query examples for semantic search
- **API docs**: Python module documentation
- **Lifecycle**: `Start()` for async init (schema discovery), `Stop()` for cleanup

Plugins are registered in `pkg/server/builder.go` and initialized from the `plugins:` config section.

### Builder Pattern
`pkg/server/builder.go` wires all dependencies. Services are created and started in order:
1. Plugin registry (init, validate, start all plugins)
2. Sandbox service
3. Cartographoor client (network discovery)
4. Auth service
5. Example index (semantic search)
6. Tool and resource registries
7. MCP server

### Registry Pattern
Tools and resources use registries (`tool.Registry`, `resource.Registry`) that allow registration of handlers and definitions. The server iterates over registries to register with the MCP server.

### Sandbox Execution Flow
1. `execute_python` tool receives code
2. Builds environment variables from plugin registry (each plugin provides its own env vars) plus platform S3 vars
3. Calls `sandbox.Service.Execute()` which creates/reuses a Docker container
4. Container runs Python with the `ethpandaops` library pre-installed
5. Python code connects directly to ClickHouse/Prometheus/Loki using credentials from env
6. Output, files, and session info returned to caller

## Configuration

Configuration uses `plugins:` key for datasources:
```yaml
plugins:
  clickhouse:
    clusters: [...]
    schema_discovery: { ... }
  prometheus:
    instances: [...]
  loki:
    instances: [...]
```

Platform config stays at top level:
- `sandbox.backend` - `docker` (local) or `gvisor` (production)
- `storage` - S3-compatible storage for output files
- `auth` - GitHub OAuth configuration

Environment variables are substituted using `${VAR_NAME}` syntax in YAML.

## Testing

The eval harness in `tests/eval/` tests end-to-end task completion:
- Uses Claude Agent SDK with native MCP support
- DeepEval for metrics (tool correctness, task completion)
- Test cases defined in YAML (`cases/*.yaml`)
- Traces stored locally or in Langfuse

Run a specific test category:
```bash
uv run python -m scripts.run_eval --category basic_queries
```

## MCP Resources

Key resources exposed by the server:
- `datasources://list` - All configured datasources (ClickHouse, Prometheus, Loki)
- `datasources://clickhouse` - ClickHouse clusters only
- `datasources://prometheus` - Prometheus instances only
- `datasources://loki` - Loki instances only
- `networks://active` - Active Ethereum networks
- `networks://{name}` - Specific network details
- `clickhouse://tables` - List all tables (if schema discovery enabled)
- `clickhouse://tables/{table}` - Table schema details
- `python://ethpandaops` - Python library function signatures
- `examples://queries` - Common query patterns
- `ethpandaops://getting-started` - Getting started guide

## Local Development

### Testing Changes Locally

1. **Build the sandbox image** (required for Python execution):
   ```bash
   make docker-sandbox
   ```

2. **Set up configuration**:
   ```bash
   cp config.example.yaml config.yaml
   # Edit config.yaml with your datasource credentials
   ```

3. **Run the server locally**:
    - full stack with MinIO:
   ```bash
   docker-compose up -d
   ```

4. **Run the tests**:
   ```bash
   cd tests/eval
   uv run python -m scripts.run_eval --category basic_queries # Or whatever new tests you've added
   ```

### Docker Compose Stacks

#### Main Stack (`docker-compose.yaml`)

Runs the MCP server with S3-compatible storage for output files.

```bash
docker-compose up -d                            # Start all services
docker-compose logs -f ethpandaops-mcp-server   # View server logs
docker-compose down                             # Stop all services
```

**Services:**
- `ethpandaops-mcp-server` - The MCP server (ports 2480 for MCP, 31490 for metrics)
- `minio` - S3-compatible storage for chart/file uploads (port 31400 API, 31401 console)
- `minio-init` - Creates the output bucket on startup
- `sandbox-builder` - Builds the sandbox Docker image

**Requirements:**
- Docker socket mounted for sandbox container creation
- `config.yaml` in project root

**Networks:**
- `ethpandaops-mcp-external` - Exposed to host (MCP server, MinIO)
- `ethpandaops-mcp-internal` - Sandbox containers reach MinIO and external datasources (ClickHouse, Prometheus, Loki). Not marked `internal` so containers can resolve external DNS. In stdio mode (outside docker-compose), the server auto-creates this network on startup.

#### Langfuse Stack (`tests/eval/docker-compose.langfuse.yaml`)

Self-hosted Langfuse for viewing evaluation traces and metrics over time.

```bash
cd tests/eval
docker compose -f docker-compose.langfuse.yaml up -d   # Start Langfuse
docker compose -f docker-compose.langfuse.yaml down    # Stop Langfuse

# Or use the helper script:
uv run python -m scripts.langfuse up
uv run python -m scripts.langfuse down
```

**Services:**
- `langfuse-web` - Web UI (http://localhost:31700, login: admin@mcp.local / adminadmin)
- `langfuse-worker` - Background trace processing
- `postgres` - Main database
- `clickhouse` - Analytics database
- `redis` - Cache
- `minio` - Blob storage (separate from main stack, port 31909)

**Pre-configured API keys** (no manual setup needed):
- Public key: `pk-lf-mcp-eval-local`
- Secret key: `sk-lf-mcp-eval-local`
- Username: `admin@mcp.local`
- Password: `adminadmin`

To enable tracing to LANGFUSE, set in your environment:
```bash
export MCP_EVAL_LANGFUSE_ENABLED=true
```
