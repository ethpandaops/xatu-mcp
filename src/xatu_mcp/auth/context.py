"""Auth context for MCP tool handlers using contextvars.

This module provides a way to pass authentication context to MCP tool handlers,
which don't have direct access to HTTP request state.
"""

from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from xatu_mcp.auth.middleware import AuthenticatedUser

import structlog

logger = structlog.get_logger()


@dataclass
class AuthContext:
    """Authentication context for MCP tool handlers.

    Attributes:
        user: The authenticated user, or None if not authenticated.
        is_stdio: Whether the request is via stdio transport (auth may be skipped).
        auth_enabled: Whether authentication is enabled in config.
        skip_for_stdio: Whether to skip auth checks for stdio transport.
    """

    user: "AuthenticatedUser | None"
    is_stdio: bool
    auth_enabled: bool
    skip_for_stdio: bool

    def should_enforce_auth(self) -> bool:
        """Check if authentication should be enforced for this context.

        Returns:
            True if auth should be enforced, False otherwise.
        """
        if not self.auth_enabled:
            return False
        if self.is_stdio and self.skip_for_stdio:
            return False
        return True

    def has_scope(self, scope: str) -> bool:
        """Check if the current user has the specified scope.

        Args:
            scope: The scope to check for.

        Returns:
            True if the user has the scope, False otherwise.
        """
        if not self.should_enforce_auth():
            # Auth not enforced, allow all scopes
            return True
        if self.user is None:
            return False
        return self.user.has_scope(scope)


# Context variable for storing auth context during request handling
_auth_context: ContextVar[AuthContext | None] = ContextVar("auth_context", default=None)


def set_auth_context(context: AuthContext) -> None:
    """Set the authentication context for the current execution.

    Args:
        context: The auth context to set.
    """
    _auth_context.set(context)
    logger.debug(
        "Auth context set",
        auth_enabled=context.auth_enabled,
        is_stdio=context.is_stdio,
        skip_for_stdio=context.skip_for_stdio,
        has_user=context.user is not None,
        user_scopes=context.user.scopes if context.user else [],
    )


def get_auth_context() -> AuthContext | None:
    """Get the current authentication context.

    Returns:
        The current auth context, or None if not set.
    """
    return _auth_context.get()


def clear_auth_context() -> None:
    """Clear the authentication context."""
    _auth_context.set(None)


class InsufficientScopeError(Exception):
    """Raised when a user lacks the required scope for an operation."""

    def __init__(self, required_scope: str, user_scopes: list[str] | None = None) -> None:
        """Initialize the error.

        Args:
            required_scope: The scope that was required.
            user_scopes: The scopes the user has (for debugging).
        """
        self.required_scope = required_scope
        self.user_scopes = user_scopes or []
        message = f"Insufficient scope: required '{required_scope}'"
        if user_scopes:
            message += f", user has {user_scopes}"
        super().__init__(message)


class AuthenticationRequiredError(Exception):
    """Raised when authentication is required but not provided."""

    def __init__(self, message: str = "Authentication required") -> None:
        """Initialize the error.

        Args:
            message: Error message.
        """
        super().__init__(message)


def require_scope_for_tool(scope: str) -> None:
    """Check if the current context has the required scope.

    Call this at the start of a tool handler to enforce scope requirements.

    Args:
        scope: The required scope.

    Raises:
        InsufficientScopeError: If the user lacks the required scope.
        AuthenticationRequiredError: If auth is required but user is not authenticated.
    """
    context = get_auth_context()

    if context is None:
        # No context set - this shouldn't happen in normal operation
        # but we fail closed for safety
        logger.warning("No auth context found when checking scope", scope=scope)
        raise AuthenticationRequiredError("Auth context not initialized")

    if not context.should_enforce_auth():
        # Auth not enforced (disabled or stdio with skip_for_stdio)
        logger.debug(
            "Auth not enforced, allowing tool",
            scope=scope,
            is_stdio=context.is_stdio,
            auth_enabled=context.auth_enabled,
        )
        return

    if context.user is None:
        logger.warning("Tool called without authentication", scope=scope)
        raise AuthenticationRequiredError()

    if not context.has_scope(scope):
        logger.warning(
            "Insufficient scope for tool",
            required_scope=scope,
            user_scopes=context.user.scopes,
            user_id=context.user.user.id,
        )
        raise InsufficientScopeError(scope, context.user.scopes)

    logger.debug(
        "Scope check passed",
        scope=scope,
        user_id=context.user.user.id,
    )
