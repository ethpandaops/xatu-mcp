// Package middleware provides authentication middleware for HTTP handlers.
package middleware

import (
	"context"
	"strings"

	"github.com/ethpandaops/xatu-mcp/pkg/auth/session"
	"github.com/ethpandaops/xatu-mcp/pkg/auth/token"
)

// contextKey is a type for context keys to avoid collisions.
type contextKey string

const (
	// authUserKey is the context key for the authenticated user.
	authUserKey contextKey = "auth_user"
)

// AuthUser represents an authenticated user attached to a request context.
type AuthUser struct {
	// User is the authenticated user.
	User *session.User

	// Session is the user's session.
	Session *session.Session

	// Claims are the JWT claims from the access token.
	Claims *token.Claims

	// Scopes are the parsed scopes from the token.
	Scopes []string
}

// HasScope checks if the user has the specified scope.
func (a *AuthUser) HasScope(scope string) bool {
	for _, s := range a.Scopes {
		if s == scope {
			return true
		}
	}

	return false
}

// WithAuthUser attaches an AuthUser to the context.
func WithAuthUser(ctx context.Context, user *AuthUser) context.Context {
	return context.WithValue(ctx, authUserKey, user)
}

// GetAuthUser retrieves the AuthUser from the context.
// Returns nil if no user is present.
func GetAuthUser(ctx context.Context) *AuthUser {
	user, _ := ctx.Value(authUserKey).(*AuthUser)

	return user
}

// AuthContext provides authentication context for tool handlers.
// This wraps the AuthUser with additional context about whether
// authentication is being enforced.
type AuthContext struct {
	// User is the authenticated user, or nil if not authenticated.
	User *AuthUser

	// IsStdio indicates if the request is via stdio transport.
	IsStdio bool

	// AuthEnabled indicates if authentication is enabled in config.
	AuthEnabled bool

	// SkipForStdio indicates if auth should be skipped for stdio transport.
	SkipForStdio bool
}

// ShouldEnforceAuth returns true if authentication should be enforced.
func (a *AuthContext) ShouldEnforceAuth() bool {
	if !a.AuthEnabled {
		return false
	}

	if a.IsStdio && a.SkipForStdio {
		return false
	}

	return true
}

// HasScope checks if the current user has the specified scope.
// Returns true if auth is not being enforced, or if the user has the scope.
func (a *AuthContext) HasScope(scope string) bool {
	if !a.ShouldEnforceAuth() {
		return true
	}

	if a.User == nil {
		return false
	}

	return a.User.HasScope(scope)
}

// RequireScope checks if the current context allows the specified scope.
// Returns nil if allowed, or an error if not.
func RequireScope(ctx context.Context, scope string) error {
	user := GetAuthUser(ctx)
	if user == nil {
		return &ScopeError{
			Scope:   scope,
			Message: "authentication required",
		}
	}

	if !user.HasScope(scope) {
		return &ScopeError{
			Scope:      scope,
			UserScopes: user.Scopes,
			Message:    "insufficient scope",
		}
	}

	return nil
}

// ScopeError is returned when a required scope is not present.
type ScopeError struct {
	Scope      string
	UserScopes []string
	Message    string
}

func (e *ScopeError) Error() string {
	if len(e.UserScopes) > 0 {
		return e.Message + ": required " + e.Scope + ", user has " + strings.Join(e.UserScopes, " ")
	}

	return e.Message + ": required " + e.Scope
}
