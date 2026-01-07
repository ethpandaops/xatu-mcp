"""ClickHouse client for querying schema information."""

import re
import httpx
import structlog
from dataclasses import dataclass

logger = structlog.get_logger()

# Valid identifier pattern for ClickHouse (alphanumeric, underscores, must start with letter)
_VALID_IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')


def _validate_identifier(name: str, identifier_type: str = "identifier") -> str:
    """Validate and return a safe identifier for use in SQL queries.

    Args:
        name: The identifier to validate.
        identifier_type: Type of identifier for error messages (e.g., "table", "column").

    Returns:
        The validated identifier.

    Raises:
        ValueError: If the identifier contains invalid characters.
    """
    if not name:
        raise ValueError(f"{identifier_type} name cannot be empty")
    if not _VALID_IDENTIFIER_PATTERN.match(name):
        raise ValueError(
            f"Invalid {identifier_type} name '{name}': must contain only alphanumeric "
            "characters and underscores, and must start with a letter or underscore"
        )
    if len(name) > 128:
        raise ValueError(f"{identifier_type} name too long (max 128 characters)")
    return name


@dataclass
class ClickHouseClusterInfo:
    """Information about a ClickHouse cluster."""

    name: str
    host: str
    port: int
    protocol: str
    user: str
    password: str
    database: str
    networks: list[str]
    description: str


# Cluster registry - populated at runtime from config
_clusters: dict[str, ClickHouseClusterInfo] = {}

# Public alias for read access (e.g., CLUSTERS.keys() for listing available cluster names)
# Note: Prefer using get_cluster() or list_clusters() functions for type-safe access
CLUSTERS = _clusters


def register_clusters_from_config(config: "Config") -> None:  # noqa: F821
    """Register clusters from configuration.

    This should be called during server startup to populate the cluster registry.

    Args:
        config: The server configuration containing ClickHouse cluster configs.
    """
    global _clusters
    _clusters.clear()

    if config.clickhouse.xatu:
        _clusters["xatu"] = ClickHouseClusterInfo(
            name="xatu",
            host=config.clickhouse.xatu.host,
            port=config.clickhouse.xatu.port,
            protocol=config.clickhouse.xatu.protocol,
            user=config.clickhouse.xatu.user,
            password=config.clickhouse.xatu.password,
            database=config.clickhouse.xatu.database,
            networks=config.clickhouse.xatu.networks,
            description="Production raw data cluster for mainnet and testnets",
        )

    if config.clickhouse.xatu_experimental:
        _clusters["xatu-experimental"] = ClickHouseClusterInfo(
            name="xatu-experimental",
            host=config.clickhouse.xatu_experimental.host,
            port=config.clickhouse.xatu_experimental.port,
            protocol=config.clickhouse.xatu_experimental.protocol,
            user=config.clickhouse.xatu_experimental.user,
            password=config.clickhouse.xatu_experimental.password,
            database=config.clickhouse.xatu_experimental.database,
            networks=config.clickhouse.xatu_experimental.networks,
            description="Experimental cluster for devnet data",
        )

    if config.clickhouse.xatu_cbt:
        _clusters["xatu-cbt"] = ClickHouseClusterInfo(
            name="xatu-cbt",
            host=config.clickhouse.xatu_cbt.host,
            port=config.clickhouse.xatu_cbt.port,
            protocol=config.clickhouse.xatu_cbt.protocol,
            user=config.clickhouse.xatu_cbt.user,
            password=config.clickhouse.xatu_cbt.password,
            database=config.clickhouse.xatu_cbt.database,
            networks=config.clickhouse.xatu_cbt.networks,
            description="Aggregated/CBT (Consensus Block Timing) tables",
        )

    logger.info("Registered ClickHouse clusters", count=len(_clusters), clusters=list(_clusters.keys()))


class ClickHouseClient:
    """Client for querying ClickHouse schema information."""

    def __init__(self, cluster: ClickHouseClusterInfo) -> None:
        """Initialize the client with cluster information.

        Args:
            cluster: The cluster configuration to connect to.
        """
        self.cluster = cluster
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                auth=(self.cluster.user, self.cluster.password),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _build_url(self) -> str:
        """Build the ClickHouse HTTP URL."""
        return f"{self.cluster.protocol}://{self.cluster.host}:{self.cluster.port}"

    async def query(self, sql: str) -> list[dict[str, str]]:
        """Execute a query and return results as list of dicts.

        Args:
            sql: The SQL query to execute.

        Returns:
            List of row dictionaries.

        Raises:
            httpx.HTTPError: If the query fails.
        """
        client = await self._get_client()
        url = self._build_url()

        # Use FORMAT JSONEachRow for easier parsing
        query_with_format = f"{sql.rstrip(';')} FORMAT JSONEachRow"

        logger.debug("Executing ClickHouse query", cluster=self.cluster.name, sql=sql[:100])

        response = await client.post(
            url,
            content=query_with_format,
            headers={"Content-Type": "text/plain"},
        )
        response.raise_for_status()

        # Parse JSONEachRow format (one JSON object per line)
        results: list[dict[str, str]] = []
        text = response.text.strip()
        if text:
            import json

            for line in text.split("\n"):
                if line.strip():
                    results.append(json.loads(line))

        return results

    async def list_tables(self) -> list[dict[str, str]]:
        """List all tables in the database.

        Returns:
            List of table information dicts with keys: name, engine, total_rows, total_bytes.
        """
        sql = """
        SELECT
            name,
            engine,
            toString(total_rows) as total_rows,
            toString(total_bytes) as total_bytes,
            comment
        FROM system.tables
        WHERE database = currentDatabase()
        AND name NOT LIKE '.%'
        ORDER BY name
        """
        return await self.query(sql)

    async def get_table_schema(self, table_name: str) -> list[dict[str, str]]:
        """Get the schema for a specific table.

        Args:
            table_name: The name of the table.

        Returns:
            List of column information dicts.

        Raises:
            ValueError: If table_name contains invalid characters.
        """
        # Validate table name to prevent SQL injection
        safe_table_name = _validate_identifier(table_name, "table")

        sql = f"""
        SELECT
            name,
            type,
            default_kind,
            default_expression,
            comment,
            is_in_partition_key,
            is_in_sorting_key,
            is_in_primary_key
        FROM system.columns
        WHERE database = currentDatabase()
        AND table = '{safe_table_name}'
        ORDER BY position
        """
        return await self.query(sql)

    async def get_table_info(self, table_name: str) -> dict[str, str] | None:
        """Get metadata about a specific table.

        Args:
            table_name: The name of the table.

        Returns:
            Table metadata dict or None if not found.

        Raises:
            ValueError: If table_name contains invalid characters.
        """
        # Validate table name to prevent SQL injection
        safe_table_name = _validate_identifier(table_name, "table")

        sql = f"""
        SELECT
            name,
            engine,
            toString(total_rows) as total_rows,
            toString(total_bytes) as total_bytes,
            comment,
            partition_key,
            sorting_key,
            primary_key,
            create_table_query
        FROM system.tables
        WHERE database = currentDatabase()
        AND name = '{safe_table_name}'
        LIMIT 1
        """
        results = await self.query(sql)
        return results[0] if results else None


def get_cluster(name: str) -> ClickHouseClusterInfo | None:
    """Get cluster information by name.

    Args:
        name: The cluster name.

    Returns:
        Cluster info or None if not found.

    Raises:
        ValueError: If no clusters have been registered (call register_clusters_from_config first).
    """
    if not _clusters:
        raise ValueError(
            "No ClickHouse clusters registered. Call register_clusters_from_config() during server startup."
        )
    return _clusters.get(name)


def list_clusters() -> list[ClickHouseClusterInfo]:
    """List all available clusters.

    Returns:
        List of all cluster configurations.

    Raises:
        ValueError: If no clusters have been registered (call register_clusters_from_config first).
    """
    if not _clusters:
        raise ValueError(
            "No ClickHouse clusters registered. Call register_clusters_from_config() during server startup."
        )
    return list(_clusters.values())
