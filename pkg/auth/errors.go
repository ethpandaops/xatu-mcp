// Package auth provides OAuth 2.1 authentication for xatu-mcp.
package auth

import "errors"

// Token-related errors.
var (
	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired = errors.New("token has expired")

	// ErrTokenInvalid indicates the token is malformed or has an invalid signature.
	ErrTokenInvalid = errors.New("token is invalid")

	// ErrTokenAudience indicates the token audience does not match the expected resource.
	ErrTokenAudience = errors.New("token audience mismatch")

	// ErrTokenType indicates the token type does not match the expected type.
	ErrTokenType = errors.New("token type mismatch")
)

// Session-related errors.
var (
	// ErrSessionNotFound indicates no session exists for the given identifier.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionRevoked indicates the session has been revoked.
	ErrSessionRevoked = errors.New("session has been revoked")

	// ErrSessionExpired indicates the session has expired.
	ErrSessionExpired = errors.New("session has expired")
)

// User-related errors.
var (
	// ErrUserNotFound indicates no user exists for the given identifier.
	ErrUserNotFound = errors.New("user not found")
)

// Authorization errors.
var (
	// ErrUnauthorized indicates the request lacks valid authentication credentials.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrInsufficientScope indicates the token lacks the required scope.
	ErrInsufficientScope = errors.New("insufficient scope")

	// ErrOrgMembershipRequired indicates the user is not a member of any allowed organization.
	ErrOrgMembershipRequired = errors.New("organization membership required")
)

// OAuth flow errors.
var (
	// ErrInvalidRequest indicates the OAuth request is malformed.
	ErrInvalidRequest = errors.New("invalid request")

	// ErrInvalidGrant indicates the authorization code or refresh token is invalid.
	ErrInvalidGrant = errors.New("invalid grant")

	// ErrInvalidClient indicates the client ID is invalid.
	ErrInvalidClient = errors.New("invalid client")

	// ErrInvalidRedirectURI indicates the redirect URI is invalid or doesn't match.
	ErrInvalidRedirectURI = errors.New("invalid redirect URI")

	// ErrInvalidPKCE indicates the PKCE code verifier is invalid.
	ErrInvalidPKCE = errors.New("invalid PKCE code verifier")

	// ErrAuthCodeExpired indicates the authorization code has expired.
	ErrAuthCodeExpired = errors.New("authorization code has expired")

	// ErrAuthCodeUsed indicates the authorization code has already been used.
	ErrAuthCodeUsed = errors.New("authorization code has already been used")

	// ErrInvalidState indicates the OAuth state parameter is invalid or missing.
	ErrInvalidState = errors.New("invalid state parameter")

	// ErrResourceMismatch indicates the resource parameter doesn't match.
	ErrResourceMismatch = errors.New("resource mismatch")
)

// GitHub OAuth errors.
var (
	// ErrGitHubOAuth indicates a failure in the GitHub OAuth flow.
	ErrGitHubOAuth = errors.New("GitHub OAuth error")

	// ErrGitHubAPI indicates a failure calling the GitHub API.
	ErrGitHubAPI = errors.New("GitHub API error")
)
