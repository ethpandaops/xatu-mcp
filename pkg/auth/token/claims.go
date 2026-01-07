// Package token provides JWT token creation and validation.
package token

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenType represents the type of token (access or refresh).
type TokenType string

const (
	// TokenTypeAccess represents an access token.
	TokenTypeAccess TokenType = "access"

	// TokenTypeRefresh represents a refresh token.
	TokenTypeRefresh TokenType = "refresh"
)

// String returns the string representation of the token type.
func (t TokenType) String() string {
	return string(t)
}

// Claims represents the JWT claims structure for authentication tokens.
type Claims struct {
	jwt.RegisteredClaims

	// Scope contains space-separated OAuth scopes.
	Scope string `json:"scope,omitempty"`

	// ClientID is the OAuth client that requested this token.
	ClientID string `json:"client_id,omitempty"`

	// TokenType identifies this as an access or refresh token.
	TokenType TokenType `json:"token_type,omitempty"`
}

// HasScope checks if the claims include the specified scope.
func (c *Claims) HasScope(scope string) bool {
	if c.Scope == "" {
		return false
	}

	scopes := strings.Split(c.Scope, " ")
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}

	return false
}

// Scopes returns the list of scopes as a slice.
func (c *Claims) Scopes() []string {
	if c.Scope == "" {
		return nil
	}

	return strings.Split(c.Scope, " ")
}

// IsExpired checks if the token has expired.
func (c *Claims) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}

	return c.ExpiresAt.Before(time.Now())
}

// CreateTokenParams contains parameters for creating a new token.
type CreateTokenParams struct {
	// UserID is the subject of the token.
	UserID string

	// ClientID is the OAuth client that requested this token.
	ClientID string

	// Scope contains space-separated OAuth scopes.
	Scope string

	// Resource is the audience/resource this token is bound to (RFC 8707).
	Resource string
}
