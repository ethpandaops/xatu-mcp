"""CLI entry point for the Xatu MCP server."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from xatu_mcp.config import Config

from xatu_mcp.config import load_config
from xatu_mcp.resources.clickhouse_client import (
    ClickHouseClient,
    get_cluster,
    list_clusters,
    register_clusters_from_config,
)
from xatu_mcp.server import create_server, run_stdio, run_sse, run_streamable_http

logger = structlog.get_logger()

# Default cache directory for schema data
DEFAULT_SCHEMA_CACHE_DIR = Path.home() / ".cache" / "xatu-mcp" / "schemas"


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="xatu-mcp",
        description="MCP server for Ethereum network analytics via Xatu data",
    )

    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        help="Path to config file (default: CONFIG_PATH env var or config.yaml)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Start the MCP server")
    serve_parser.add_argument(
        "--transport",
        "-t",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    serve_parser.add_argument(
        "--host",
        default=None,
        help="Host to bind to (overrides config)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind to (overrides config)",
    )

    # schema command
    schema_parser = subparsers.add_parser("schema", help="Manage ClickHouse schemas")
    schema_subparsers = schema_parser.add_subparsers(dest="schema_command")
    refresh_parser = schema_subparsers.add_parser("refresh", help="Refresh schemas from ClickHouse")
    refresh_parser.add_argument(
        "--cluster",
        choices=["xatu", "xatu-experimental", "xatu-cbt"],
        help="Specific cluster to refresh (default: all)",
    )
    refresh_parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_SCHEMA_CACHE_DIR,
        help=f"Directory to cache schema data (default: {DEFAULT_SCHEMA_CACHE_DIR})",
    )
    refresh_parser.add_argument(
        "--include-columns",
        action="store_true",
        help="Fetch detailed column schemas for all tables (slower but more complete)",
    )

    # version command
    subparsers.add_parser("version", help="Show version")

    args = parser.parse_args()

    # Configure structured logging
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer() if sys.stderr.isatty() else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    if args.command == "version":
        from xatu_mcp import __version__

        print(f"xatu-mcp {__version__}")
        return 0

    if args.command == "schema":
        return handle_schema_command(args)

    if args.command == "serve" or args.command is None:
        return handle_serve_command(args)

    parser.print_help()
    return 1


def handle_serve_command(args: argparse.Namespace) -> int:
    """Handle the serve command."""
    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        logger.error("Config file not found", error=str(e))
        return 1
    except ValueError as e:
        logger.error("Config error", error=str(e))
        return 1

    # Apply CLI overrides
    if hasattr(args, "host") and args.host:
        config.server.host = args.host
    if hasattr(args, "port") and args.port:
        config.server.port = args.port

    transport = getattr(args, "transport", "stdio")

    logger.info(
        "Starting Xatu MCP server",
        transport=transport,
        host=config.server.host,
        port=config.server.port,
    )

    server = create_server(config)

    try:
        if transport == "stdio":
            asyncio.run(run_stdio(server, config))
        elif transport == "sse":
            asyncio.run(run_sse(server, config))
        elif transport == "streamable-http":
            asyncio.run(run_streamable_http(server, config))
        else:
            logger.error("Unknown transport", transport=transport)
            return 1
    except KeyboardInterrupt:
        logger.info("Server stopped")
    except Exception as e:
        logger.exception("Server error", error=str(e))
        return 1

    return 0


def handle_schema_command(args: argparse.Namespace) -> int:
    """Handle the schema command."""
    if args.schema_command == "refresh":
        try:
            config = load_config(args.config)
        except FileNotFoundError as e:
            logger.error("Config file not found", error=str(e))
            return 1
        except ValueError as e:
            logger.error("Config error", error=str(e))
            return 1

        cluster_filter = getattr(args, "cluster", None)
        cache_dir: Path = getattr(args, "cache_dir", DEFAULT_SCHEMA_CACHE_DIR)
        include_columns = getattr(args, "include_columns", False)

        logger.info(
            "Refreshing schemas",
            cluster=cluster_filter or "all",
            cache_dir=str(cache_dir),
            include_columns=include_columns,
        )

        return asyncio.run(
            _refresh_schemas(config, cluster_filter, cache_dir, include_columns)
        )

    logger.error("Unknown schema command")
    return 1


async def _refresh_schemas(
    config: Config,
    cluster_filter: str | None,
    cache_dir: Path,
    include_columns: bool,
) -> int:
    """Refresh schemas from ClickHouse clusters.

    Args:
        config: The loaded configuration.
        cluster_filter: Optional cluster name to refresh only that cluster.
        cache_dir: Directory to cache schema data.
        include_columns: Whether to fetch detailed column schemas.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    # Register clusters from config
    register_clusters_from_config(config)

    # Determine which clusters to refresh
    try:
        all_clusters = list_clusters()
    except ValueError as e:
        logger.error("No clusters configured", error=str(e))
        return 1

    if cluster_filter:
        cluster = get_cluster(cluster_filter)
        if cluster is None:
            available = [c.name for c in all_clusters]
            logger.error(
                "Unknown cluster",
                cluster=cluster_filter,
                available=available,
            )
            return 1
        clusters_to_refresh = [cluster]
    else:
        clusters_to_refresh = all_clusters

    if not clusters_to_refresh:
        logger.warning("No clusters to refresh")
        return 0

    # Create cache directory if it doesn't exist
    cache_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Using cache directory", path=str(cache_dir))

    # Track overall statistics
    total_tables = 0
    total_columns = 0
    failed_clusters: list[str] = []

    for cluster in clusters_to_refresh:
        logger.info("Refreshing cluster", cluster=cluster.name, host=cluster.host)

        client = ClickHouseClient(cluster)
        try:
            # Fetch list of tables
            tables = await client.list_tables()
            table_count = len(tables)
            total_tables += table_count

            logger.info(
                "Fetched tables",
                cluster=cluster.name,
                table_count=table_count,
            )

            # Build cluster schema data
            cluster_schema: dict = {
                "cluster": cluster.name,
                "database": cluster.database,
                "host": cluster.host,
                "networks": cluster.networks,
                "description": cluster.description,
                "refreshed_at": datetime.now(timezone.utc).isoformat(),
                "table_count": table_count,
                "tables": {},
            }

            for table in tables:
                table_name = table["name"]
                table_data: dict = {
                    "name": table_name,
                    "engine": table.get("engine", ""),
                    "total_rows": table.get("total_rows", "0"),
                    "total_bytes": table.get("total_bytes", "0"),
                    "comment": table.get("comment", ""),
                }

                # Optionally fetch column details
                if include_columns:
                    try:
                        columns = await client.get_table_schema(table_name)
                        columns_data = []
                        for col in columns:
                            col_data = {
                                "name": col["name"],
                                "type": col["type"],
                                "comment": col.get("comment", ""),
                            }
                            if col.get("default_kind"):
                                col_data["default_kind"] = col["default_kind"]
                                col_data["default_expression"] = col.get(
                                    "default_expression", ""
                                )
                            if col.get("is_in_partition_key") == "1":
                                col_data["is_partition_key"] = True
                            if col.get("is_in_sorting_key") == "1":
                                col_data["is_sorting_key"] = True
                            if col.get("is_in_primary_key") == "1":
                                col_data["is_primary_key"] = True
                            columns_data.append(col_data)

                        table_data["columns"] = columns_data
                        total_columns += len(columns_data)
                        logger.debug(
                            "Fetched table schema",
                            cluster=cluster.name,
                            table=table_name,
                            column_count=len(columns_data),
                        )
                    except Exception as e:
                        logger.warning(
                            "Failed to fetch table schema",
                            cluster=cluster.name,
                            table=table_name,
                            error=str(e),
                        )
                        table_data["columns_error"] = str(e)

                cluster_schema["tables"][table_name] = table_data

            # Write cluster schema to cache file
            cache_file = cache_dir / f"{cluster.name}.json"
            with open(cache_file, "w") as f:
                json.dump(cluster_schema, f, indent=2)

            logger.info(
                "Cached cluster schema",
                cluster=cluster.name,
                file=str(cache_file),
                table_count=table_count,
            )

        except Exception as e:
            logger.error(
                "Failed to refresh cluster",
                cluster=cluster.name,
                error=str(e),
            )
            failed_clusters.append(cluster.name)
        finally:
            await client.close()

    # Write summary metadata file
    summary = {
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
        "clusters": [c.name for c in clusters_to_refresh],
        "total_tables": total_tables,
        "total_columns": total_columns if include_columns else None,
        "failed_clusters": failed_clusters,
    }
    summary_file = cache_dir / "summary.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    # Print final summary
    logger.info(
        "Schema refresh complete",
        clusters_refreshed=len(clusters_to_refresh) - len(failed_clusters),
        clusters_failed=len(failed_clusters),
        total_tables=total_tables,
        total_columns=total_columns if include_columns else "not fetched",
        cache_dir=str(cache_dir),
    )

    if failed_clusters:
        logger.warning("Some clusters failed to refresh", clusters=failed_clusters)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
