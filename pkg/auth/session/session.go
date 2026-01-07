// Package session provides session and user management.
package session

import "context"

// Store defines the interface for session and user storage.
type Store interface {
	// User methods.

	// GetUser retrieves a user by ID.
	GetUser(ctx context.Context, userID string) (*User, error)

	// GetUserByGitHubID retrieves a user by their GitHub ID.
	GetUserByGitHubID(ctx context.Context, githubID int64) (*User, error)

	// SaveUser creates or updates a user.
	SaveUser(ctx context.Context, user *User) error

	// UpdateUserOrganizations updates a user's organization memberships.
	UpdateUserOrganizations(ctx context.Context, userID string, organizations []string) error

	// Session methods.

	// GetSession retrieves a session by ID.
	GetSession(ctx context.Context, sessionID string) (*Session, error)

	// GetSessionByAccessJTI retrieves a session by access token JTI.
	GetSessionByAccessJTI(ctx context.Context, jti string) (*Session, error)

	// GetSessionByRefreshJTI retrieves a session by refresh token JTI.
	GetSessionByRefreshJTI(ctx context.Context, jti string) (*Session, error)

	// SaveSession creates or updates a session.
	SaveSession(ctx context.Context, session *Session) error

	// RevokeSession marks a session as revoked.
	RevokeSession(ctx context.Context, sessionID string) error

	// UpdateSessionTokens updates a session with new token JTIs (for token refresh).
	UpdateSessionTokens(ctx context.Context, sessionID string, accessJTI string, refreshJTI string) error

	// Authorization code methods.

	// GetAuthorizationCode retrieves an authorization code.
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)

	// SaveAuthorizationCode stores an authorization code.
	SaveAuthorizationCode(ctx context.Context, authCode *AuthorizationCode) error

	// MarkAuthorizationCodeUsed marks an authorization code as used.
	MarkAuthorizationCodeUsed(ctx context.Context, code string) error

	// DeleteAuthorizationCode removes an authorization code.
	DeleteAuthorizationCode(ctx context.Context, code string) error

	// Pending authorization methods.

	// GetPendingAuthorization retrieves a pending authorization by state.
	GetPendingAuthorization(ctx context.Context, state string) (*PendingAuthorization, error)

	// SavePendingAuthorization stores a pending authorization.
	SavePendingAuthorization(ctx context.Context, state string, pending *PendingAuthorization) error

	// DeletePendingAuthorization removes a pending authorization.
	DeletePendingAuthorization(ctx context.Context, state string) error

	// Cleanup.

	// CleanupExpired removes expired codes and sessions.
	CleanupExpired(ctx context.Context) error
}
