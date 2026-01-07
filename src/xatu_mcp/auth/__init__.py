"""OAuth 2.1 authentication module for Xatu MCP.

This module implements OAuth 2.1 authentication with:
- GitHub as identity provider
- PKCE (mandatory per OAuth 2.1)
- Resource Indicators (RFC 8707)
- Protected Resource Metadata (RFC 9728)
- Organization-based access control

Usage:
    from xatu_mcp.auth import AuthorizationServer, AuthenticationMiddleware

    # Create authorization server
    auth_server = AuthorizationServer(config.auth, base_url)

    # Add routes to your Starlette app
    routes = auth_server.get_routes()

    # Add authentication middleware
    app.add_middleware(
        AuthenticationMiddleware,
        config=config.auth,
        token_manager=auth_server.token_manager,
        store=auth_server.store,
        base_url=base_url,
    )
"""

from xatu_mcp.auth.models import (
    AuthorizationCode,
    AuthorizationRequest,
    GitHubUser,
    InMemoryStore,
    PKCEChallenge,
    Session,
    TokenPair,
    TokenRequest,
    TokenType,
    User,
)
from xatu_mcp.auth.tokens import (
    TokenClaims,
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    TokenAudienceError,
    TokenManager,
)
from xatu_mcp.auth.github import (
    GitHubOAuthClient,
    GitHubOAuthError,
    GitHubTokenResponse,
    generate_state,
    validate_redirect_uri,
)
from xatu_mcp.auth.discovery import (
    AuthorizationServerMetadata,
    ProtectedResourceMetadata,
    create_authorization_server_metadata,
    create_protected_resource_metadata,
    format_www_authenticate,
)
from xatu_mcp.auth.server import AuthorizationServer
from xatu_mcp.auth.middleware import (
    AuthenticatedUser,
    AuthenticationMiddleware,
    get_current_user,
    require_authenticated,
    require_scope,
)
from xatu_mcp.auth.context import (
    AuthContext,
    AuthenticationRequiredError,
    InsufficientScopeError,
    clear_auth_context,
    get_auth_context,
    require_scope_for_tool,
    set_auth_context,
)

__all__ = [
    # Models
    "AuthorizationCode",
    "AuthorizationRequest",
    "GitHubUser",
    "InMemoryStore",
    "PKCEChallenge",
    "Session",
    "TokenPair",
    "TokenRequest",
    "TokenType",
    "User",
    # Tokens
    "TokenClaims",
    "TokenError",
    "TokenExpiredError",
    "TokenInvalidError",
    "TokenAudienceError",
    "TokenManager",
    # GitHub
    "GitHubOAuthClient",
    "GitHubOAuthError",
    "GitHubTokenResponse",
    "generate_state",
    "validate_redirect_uri",
    # Discovery
    "AuthorizationServerMetadata",
    "ProtectedResourceMetadata",
    "create_authorization_server_metadata",
    "create_protected_resource_metadata",
    "format_www_authenticate",
    # Server
    "AuthorizationServer",
    # Middleware
    "AuthenticatedUser",
    "AuthenticationMiddleware",
    "get_current_user",
    "require_authenticated",
    "require_scope",
    # Context
    "AuthContext",
    "AuthenticationRequiredError",
    "InsufficientScopeError",
    "clear_auth_context",
    "get_auth_context",
    "require_scope_for_tool",
    "set_auth_context",
]
