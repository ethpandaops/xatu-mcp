# Deployment modes

This document describes how ethpandaops/mcp is deployed in three modes and how the pieces fit together. The goal is a clear separation of concerns with minimal magic and predictable plugin behavior.

## Components

- MCP server: control plane. Owns transport, auth, tool/resource registration, and sandbox orchestration.
- Sandbox runners: data plane. Execute Python in isolated containers (Docker for dev, gVisor for prod).
- Credential proxy: trust boundary. Holds datasource + S3 credentials and proxies all datasource/S3 traffic.
- Plugins: per-datasource packages that define config, schema discovery, resources, examples, and Python API docs.

## Data flow (all modes)

1) Client connects to MCP server (stdio/SSE/HTTP).
2) MCP server builds a credential-free sandbox environment and injects:
   - proxy URL
   - proxy auth token (JWT or "none" for local dev)
   - datasource metadata (names/URLs) discovered from proxy
3) Sandbox runs Python; all data access flows through the proxy.
4) Proxy validates auth, rate-limits/audits, and forwards to ClickHouse/Prometheus/Loki/S3.

## Mode 1: Dev mode (proxy + MCP on this host)

Use when iterating locally.

- Proxy runs locally with auth.mode: none.
- MCP runs locally and points proxy.url to localhost.
- Sandboxes run via local Docker and reach proxy/S3 on the local Docker network.
- Typical entrypoint: docker-compose.yaml (builds sandbox, runs proxy, MCP, and MinIO).

## Mode 2: Local-agent mode (proxy in prod, MCP + sandboxes on this host)

Use when the MCP server runs locally but must reach production datasources.

- Proxy runs in production with auth.mode: jwt.
- MCP runs locally with proxy.url set to the production proxy and proxy.auth configured for OIDC.
- Local MCP uses mcp auth login to obtain a JWT; that JWT is injected into sandbox executions.
- Sandboxes must be able to reach the production proxy over the network.

## Mode 3: Remote-agent mode (proxy + MCP + sandboxes in prod)

Use for hosted deployments.

- Proxy and MCP run together in production, typically in Kubernetes or on VMs.
- MCP uses gVisor backend for stronger isolation.
- MCP HTTP auth is enabled (GitHub OAuth) for external clients.
- Sandboxes run in the same network and only reach datasources via the proxy.

## Configuration surface (per mode)

Required config knobs:

- proxy.url
  - dev: http://localhost:18081
  - local-agent: https://proxy.prod.example
  - remote-agent: http://proxy:18081 (service DNS)
- proxy.auth
  - dev: not set (proxy auth.mode: none)
  - local-agent/remote-agent: issuer_url + client_id for JWT
- sandbox.backend
  - dev/local-agent: docker
  - remote-agent: gvisor
- storage
  - endpoint must be reachable from sandboxes (no localhost)
  - public_url_prefix should be publicly reachable for user downloads

Examples to start from:

- config.example.yaml (MCP)
- proxy-config.example.yaml (proxy)
- docker-compose.yaml (dev)

## Separation of concerns

- Credential proxy is the sole holder of datasource + S3 credentials.
- MCP server never holds datasource creds and only uses the proxy for discovery and access.
- Sandboxes are credential-free; they only receive proxy URL + token and datasource metadata.
- Plugins remain purely declarative for schemas/resources/examples and use the proxy client for lookup.

## Plugin behavior across modes

- Plugin schema discovery and resources that require live data must use the proxy client.
- Datasource metadata is proxy-authoritative; plugin metadata is only used for docs/examples.
- Avoid embedding credentials or direct datasource URLs in plugin config for MCP.

## Related patterns (external)

- Anthropic MCP code execution architecture
- Cloudflare "Code Mode" (sandboxed code using MCP tools)
- JupyterHub hub/proxy separation and per-user servers
- gVisor runtime isolation model
