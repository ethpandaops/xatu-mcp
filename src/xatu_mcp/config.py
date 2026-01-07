"""Configuration loading with environment variable substitution."""

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class ClickHouseClusterConfig(BaseModel):
    """Configuration for a ClickHouse cluster."""

    host: str
    port: int = 443
    protocol: str = "https"
    user: str
    password: str
    database: str = "default"
    networks: list[str] = Field(default_factory=list)


class ClickHouseConfig(BaseModel):
    """Configuration for all ClickHouse clusters."""

    xatu: ClickHouseClusterConfig | None = None
    xatu_experimental: ClickHouseClusterConfig | None = Field(
        default=None, alias="xatu-experimental"
    )
    xatu_cbt: ClickHouseClusterConfig | None = Field(default=None, alias="xatu-cbt")


class PrometheusConfig(BaseModel):
    """Prometheus configuration."""

    url: str


class LokiConfig(BaseModel):
    """Loki configuration."""

    url: str


class SandboxConfig(BaseModel):
    """Sandbox execution configuration."""

    backend: str = "docker"  # docker | gvisor
    image: str = "xatu-mcp-sandbox:latest"
    timeout: int = 60
    memory_limit: str = "2g"
    cpu_limit: float = 1.0
    network: str = "mcp-internal"
    # Host path for shared files when running Docker-in-Docker
    # This path must be accessible from the Docker host, not the container
    host_shared_path: str | None = None


class StorageConfig(BaseModel):
    """S3-compatible storage configuration."""

    endpoint: str
    access_key: str
    secret_key: str
    bucket: str = "xatu-mcp-outputs"
    public_url_prefix: str | None = None
    region: str = "us-east-1"


class ServerConfig(BaseModel):
    """Server configuration."""

    host: str = "0.0.0.0"
    port: int = 8080
    base_url: str = "http://localhost:8080"


class AuthGitHubConfig(BaseModel):
    """GitHub OAuth configuration."""

    client_id: str
    client_secret: str


class AuthTokensConfig(BaseModel):
    """Token configuration."""

    access_token_ttl: int = 3600  # 1 hour
    refresh_token_ttl: int = 2592000  # 30 days
    issuer: str = "https://mcp.example.com"
    secret_key: str = ""


class AuthRateLimitsConfig(BaseModel):
    """Rate limiting configuration."""

    requests_per_hour: int = 100


class AuthConfig(BaseModel):
    """Authentication configuration."""

    enabled: bool = False
    skip_for_stdio: bool = True
    github: AuthGitHubConfig | None = None
    allowed_orgs: list[str] = Field(default_factory=list)
    tokens: AuthTokensConfig = Field(default_factory=AuthTokensConfig)
    database_url: str | None = None
    rate_limits: AuthRateLimitsConfig = Field(default_factory=AuthRateLimitsConfig)


class ObservabilityConfig(BaseModel):
    """Observability configuration."""

    metrics_enabled: bool = True
    metrics_port: int = 9090
    tracing_enabled: bool = False
    otlp_endpoint: str | None = None


class Config(BaseSettings):
    """Main configuration for the Xatu MCP server."""

    server: ServerConfig = Field(default_factory=ServerConfig)
    clickhouse: ClickHouseConfig = Field(default_factory=ClickHouseConfig)
    prometheus: PrometheusConfig | None = None
    loki: LokiConfig | None = None
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    storage: StorageConfig | None = None
    auth: AuthConfig = Field(default_factory=AuthConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)


def substitute_env_vars(value: Any) -> Any:
    """Recursively substitute ${ENV_VAR} patterns with environment variable values."""
    if isinstance(value, str):
        pattern = re.compile(r"\$\{([^}]+)\}")
        matches = pattern.findall(value)
        result = value
        for match in matches:
            env_value = os.environ.get(match)
            if env_value is None:
                raise ValueError(f"Environment variable '{match}' is not set")
            if result == f"${{{match}}}":
                return env_value
            result = result.replace(f"${{{match}}}", env_value)
        return result
    elif isinstance(value, dict):
        return {k: substitute_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [substitute_env_vars(item) for item in value]
    return value


def load_config(config_path: str | Path | None = None) -> Config:
    """Load configuration from a YAML file with environment variable substitution.

    Args:
        config_path: Path to the YAML config file. If None, uses CONFIG_PATH env var
                     or defaults to config.yaml in the current directory.

    Returns:
        Validated Config object.

    Raises:
        FileNotFoundError: If the config file doesn't exist.
        ValueError: If an environment variable referenced in the config is not set.
        pydantic.ValidationError: If the config doesn't match the expected schema.
    """
    if config_path is None:
        config_path = os.environ.get("CONFIG_PATH", "config.yaml")

    config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path) as f:
        raw_config = yaml.safe_load(f)

    if raw_config is None:
        raw_config = {}

    substituted_config = substitute_env_vars(raw_config)

    return Config.model_validate(substituted_config)
