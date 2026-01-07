"""MCP server setup and transport runners."""

import asyncio
from contextlib import asynccontextmanager
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
import structlog

from xatu_mcp.config import Config
from xatu_mcp.sandbox import DockerBackend, GVisorBackend, SandboxBackend
from xatu_mcp.auth.context import AuthContext, set_auth_context, clear_auth_context

logger = structlog.get_logger()

# Interval for cleaning up expired auth data (5 minutes)
AUTH_CLEANUP_INTERVAL_SECONDS = 300


# Global authorization server instance (set when auth is enabled)
_auth_server: Any = None


def create_auth_server(config: Config) -> Any:
    """Create the authorization server if auth is enabled.

    Args:
        config: Server configuration.

    Returns:
        AuthorizationServer instance if auth is enabled, None otherwise.
    """
    global _auth_server

    if not config.auth.enabled:
        logger.info("Authentication disabled")
        return None

    if not config.auth.github:
        raise ValueError("GitHub OAuth configuration is required when auth is enabled")

    from xatu_mcp.auth import AuthorizationServer

    _auth_server = AuthorizationServer(
        config=config.auth,
        base_url=config.server.base_url,
    )

    logger.info(
        "Authorization server created",
        base_url=config.server.base_url,
        allowed_orgs=config.auth.allowed_orgs,
    )

    return _auth_server


def get_auth_server() -> Any:
    """Get the global authorization server instance.

    Returns:
        AuthorizationServer instance or None if not initialized.
    """
    return _auth_server


async def _auth_cleanup_loop(auth_server: Any, interval: int) -> None:
    """Background task that periodically cleans up expired auth data.

    Args:
        auth_server: The authorization server instance.
        interval: Cleanup interval in seconds.
    """
    while True:
        await asyncio.sleep(interval)
        try:
            auth_server.store.cleanup_expired()
            logger.debug("Cleaned up expired authorization codes and sessions")
        except Exception as e:
            logger.error("Error during auth cleanup", error=str(e))


@asynccontextmanager
async def _create_app_lifespan(auth_server: Any):
    """Create a lifespan context manager for the Starlette app.

    Starts background cleanup task when auth is enabled and stops it on shutdown.

    Args:
        auth_server: The authorization server instance (or None if auth disabled).

    Yields:
        None
    """
    cleanup_task = None

    if auth_server:
        cleanup_task = asyncio.create_task(
            _auth_cleanup_loop(auth_server, AUTH_CLEANUP_INTERVAL_SECONDS)
        )
        logger.info(
            "Started auth cleanup background task",
            interval_seconds=AUTH_CLEANUP_INTERVAL_SECONDS,
        )

    try:
        yield
    finally:
        if cleanup_task:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("Stopped auth cleanup background task")


def create_sandbox_backend(config: Config) -> SandboxBackend:
    """Create the appropriate sandbox backend based on config.

    Note: S3 uploads are handled by user code inside the sandbox via xatu.storage,
    not by the server. The storage config is passed as environment variables to
    the sandbox container.
    """
    backend_type = config.sandbox.backend.lower()

    if backend_type == "docker":
        return DockerBackend(
            image=config.sandbox.image,
            timeout=config.sandbox.timeout,
            memory_limit=config.sandbox.memory_limit,
            cpu_limit=config.sandbox.cpu_limit,
            network=config.sandbox.network,
            host_shared_path=config.sandbox.host_shared_path,
        )
    elif backend_type == "gvisor":
        return GVisorBackend(
            image=config.sandbox.image,
            timeout=config.sandbox.timeout,
            memory_limit=config.sandbox.memory_limit,
            cpu_limit=config.sandbox.cpu_limit,
            network=config.sandbox.network,
            host_shared_path=config.sandbox.host_shared_path,
        )
    else:
        raise ValueError(f"Unknown sandbox backend: {backend_type}")


def create_server(config: Config) -> Server:
    """Create and configure the MCP server.

    Args:
        config: Server configuration.

    Returns:
        Configured MCP server instance.
    """
    # Debug: log config values at server creation
    if config.clickhouse.xatu:
        logger.info(
            "Server config loaded",
            xatu_user=config.clickhouse.xatu.user,
            xatu_host=config.clickhouse.xatu.host,
        )

    server = Server("xatu-mcp")

    # Register ClickHouse clusters from config (must be done before resources)
    from xatu_mcp.resources.clickhouse_client import register_clusters_from_config

    register_clusters_from_config(config)

    # Create sandbox backend
    sandbox = create_sandbox_backend(config)

    # Register all tools in a unified handler (fixes handler overwriting issue)
    from xatu_mcp.tools import register_all_tools

    register_all_tools(server, sandbox, config)

    # Register resources
    from xatu_mcp.resources import register_resources

    register_resources(server)

    logger.info(
        "MCP server created",
        sandbox_backend=config.sandbox.backend,
        auth_enabled=config.auth.enabled,
    )

    return server


async def run_stdio(server: Server, config: Config) -> None:
    """Run the server using stdio transport.

    Args:
        server: The MCP server instance.
        config: Server configuration.
    """
    logger.info("Starting stdio transport")

    # Set auth context for stdio transport
    # Auth may be skipped based on config.auth.skip_for_stdio
    auth_context = AuthContext(
        user=None,
        is_stdio=True,
        auth_enabled=config.auth.enabled,
        skip_for_stdio=config.auth.skip_for_stdio,
    )
    set_auth_context(auth_context)

    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
    finally:
        clear_auth_context()


async def run_sse(server: Server, config: Config) -> None:
    """Run the server using SSE transport.

    Args:
        server: The MCP server instance.
        config: Server configuration.
    """
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Route, Mount
    from starlette.responses import JSONResponse
    import uvicorn

    logger.info("Starting SSE transport", host=config.server.host, port=config.server.port)

    sse = SseServerTransport("/messages/")

    async def handle_sse(request):
        # Set auth context from HTTP request state
        auth_user = getattr(request.state, "auth_user", None)
        auth_context = AuthContext(
            user=auth_user,
            is_stdio=False,
            auth_enabled=config.auth.enabled,
            skip_for_stdio=config.auth.skip_for_stdio,
        )
        set_auth_context(auth_context)

        try:
            async with sse.connect_sse(
                request.scope,
                request.receive,
                request._send,
            ) as streams:
                await server.run(
                    streams[0],
                    streams[1],
                    server.create_initialization_options(),
                )
        finally:
            clear_auth_context()

    async def handle_messages(request):
        """Handle POST messages to the SSE transport."""
        await sse.handle_post_message(request.scope, request.receive, request._send)

    async def health_check(request):
        return JSONResponse({"status": "healthy"})

    # Build routes
    routes = [
        Route("/sse", endpoint=handle_sse),
        Route("/messages/", endpoint=handle_messages, methods=["POST"]),
        Route("/health", endpoint=health_check),
    ]

    # Add auth routes if enabled
    auth_server = create_auth_server(config)
    if auth_server:
        routes.extend(auth_server.get_routes())

    # Create lifespan with cleanup task
    @asynccontextmanager
    async def lifespan(app):
        async with _create_app_lifespan(auth_server):
            yield

    app = Starlette(routes=routes, lifespan=lifespan)

    # Add auth middleware if enabled
    if auth_server:
        from xatu_mcp.auth import AuthenticationMiddleware

        app.add_middleware(
            AuthenticationMiddleware,
            config=config.auth,
            token_manager=auth_server.token_manager,
            store=auth_server.store,
            base_url=config.server.base_url,
        )

    uvicorn_config = uvicorn.Config(
        app,
        host=config.server.host,
        port=config.server.port,
        log_level="info",
    )
    server_instance = uvicorn.Server(uvicorn_config)
    await server_instance.serve()


async def run_streamable_http(server: Server, config: Config) -> None:
    """Run the server using Streamable HTTP transport.

    Args:
        server: The MCP server instance.
        config: Server configuration.
    """
    from mcp.server.streamable_http import StreamableHTTPServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.responses import JSONResponse
    import uvicorn

    logger.info(
        "Starting Streamable HTTP transport",
        host=config.server.host,
        port=config.server.port,
    )

    transport = StreamableHTTPServerTransport(
        "/mcp",
        server.create_initialization_options(),
    )

    async def handle_mcp(request):
        # Set auth context from HTTP request state
        auth_user = getattr(request.state, "auth_user", None)
        auth_context = AuthContext(
            user=auth_user,
            is_stdio=False,
            auth_enabled=config.auth.enabled,
            skip_for_stdio=config.auth.skip_for_stdio,
        )
        set_auth_context(auth_context)

        try:
            return await transport.handle_request(
                request.scope,
                request.receive,
                request._send,
                lambda: server,
            )
        finally:
            clear_auth_context()

    async def health_check(request):
        return JSONResponse({"status": "healthy"})

    async def ready_check(request):
        return JSONResponse({"status": "ready"})

    # Build routes
    routes = [
        Route("/mcp", endpoint=handle_mcp, methods=["GET", "POST"]),
        Route("/health", endpoint=health_check),
        Route("/ready", endpoint=ready_check),
    ]

    # Add auth routes if enabled
    auth_server = create_auth_server(config)
    if auth_server:
        routes.extend(auth_server.get_routes())

    # Create lifespan with cleanup task
    @asynccontextmanager
    async def lifespan(app):
        async with _create_app_lifespan(auth_server):
            yield

    app = Starlette(routes=routes, lifespan=lifespan)

    # Add auth middleware if enabled
    if auth_server:
        from xatu_mcp.auth import AuthenticationMiddleware

        app.add_middleware(
            AuthenticationMiddleware,
            config=config.auth,
            token_manager=auth_server.token_manager,
            store=auth_server.store,
            base_url=config.server.base_url,
        )

    uvicorn_config = uvicorn.Config(
        app,
        host=config.server.host,
        port=config.server.port,
        log_level="info",
    )
    server_instance = uvicorn.Server(uvicorn_config)
    await server_instance.serve()
