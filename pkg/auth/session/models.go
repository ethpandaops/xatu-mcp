// Package session provides session and user management.
package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
)

// User represents an authenticated user.
type User struct {
	// ID is the unique identifier for the user.
	ID string `json:"id"`

	// GitHubID is the user's GitHub ID.
	GitHubID int64 `json:"github_id"`

	// GitHubLogin is the user's GitHub username.
	GitHubLogin string `json:"github_login"`

	// Name is the user's display name.
	Name string `json:"name,omitempty"`

	// Email is the user's email address.
	Email string `json:"email,omitempty"`

	// AvatarURL is the URL to the user's avatar.
	AvatarURL string `json:"avatar_url,omitempty"`

	// Organizations is a list of GitHub organizations the user belongs to.
	Organizations []string `json:"organizations"`

	// CreatedAt is when the user was first created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the user was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// IsMemberOf checks if the user is a member of any of the allowed organizations.
// If allowedOrgs is empty, returns true (no restriction).
func (u *User) IsMemberOf(allowedOrgs []string) bool {
	if len(allowedOrgs) == 0 {
		return true
	}

	for _, userOrg := range u.Organizations {
		for _, allowedOrg := range allowedOrgs {
			if userOrg == allowedOrg {
				return true
			}
		}
	}

	return false
}

// Session represents an authenticated user session.
type Session struct {
	// ID is the unique identifier for the session.
	ID string `json:"id"`

	// UserID is the ID of the user who owns this session.
	UserID string `json:"user_id"`

	// AccessTokenJTI is the JWT ID of the current access token.
	AccessTokenJTI string `json:"access_token_jti"`

	// RefreshTokenJTI is the JWT ID of the current refresh token.
	RefreshTokenJTI string `json:"refresh_token_jti"`

	// ClientID is the OAuth client that created this session.
	ClientID string `json:"client_id"`

	// Scope contains the granted OAuth scopes.
	Scope string `json:"scope"`

	// Resource is the resource this session is bound to (RFC 8707).
	Resource string `json:"resource"`

	// CreatedAt is when the session was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the session expires.
	ExpiresAt time.Time `json:"expires_at"`

	// LastUsedAt is when the session was last used.
	LastUsedAt time.Time `json:"last_used_at"`

	// Revoked indicates if the session has been revoked.
	Revoked bool `json:"revoked"`
}

// IsValid checks if the session is valid (not revoked and not expired).
func (s *Session) IsValid() bool {
	if s.Revoked {
		return false
	}

	return time.Now().Before(s.ExpiresAt)
}

// NewSession creates a new session with the given parameters.
func NewSession(
	userID string,
	accessTokenJTI string,
	refreshTokenJTI string,
	clientID string,
	scope string,
	resource string,
	ttl time.Duration,
) *Session {
	now := time.Now()

	return &Session{
		ID:              uuid.New().String(),
		UserID:          userID,
		AccessTokenJTI:  accessTokenJTI,
		RefreshTokenJTI: refreshTokenJTI,
		ClientID:        clientID,
		Scope:           scope,
		Resource:        resource,
		CreatedAt:       now,
		ExpiresAt:       now.Add(ttl),
		LastUsedAt:      now,
		Revoked:         false,
	}
}

// PKCEChallenge represents a PKCE challenge for authorization flow.
type PKCEChallenge struct {
	// CodeChallenge is the S256 hash of the code verifier.
	CodeChallenge string `json:"code_challenge"`

	// CodeChallengeMethod is the method used to create the challenge (always S256).
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// Verify verifies the code verifier against the challenge using S256.
func (p *PKCEChallenge) Verify(codeVerifier string) bool {
	if p.CodeChallengeMethod != "S256" {
		return false
	}

	// Generate expected challenge from verifier.
	hash := sha256.Sum256([]byte(codeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])

	// Constant-time comparison to prevent timing attacks.
	return subtle.ConstantTimeCompare([]byte(expected), []byte(p.CodeChallenge)) == 1
}

// AuthorizationCode represents an OAuth 2.1 authorization code.
type AuthorizationCode struct {
	// Code is the authorization code value.
	Code string `json:"code"`

	// ClientID is the OAuth client that requested this code.
	ClientID string `json:"client_id"`

	// RedirectURI is the redirect URI for this code.
	RedirectURI string `json:"redirect_uri"`

	// Scope contains the requested OAuth scopes.
	Scope string `json:"scope"`

	// Resource is the resource indicator (RFC 8707).
	Resource string `json:"resource"`

	// UserID is the ID of the user who authorized this code.
	UserID string `json:"user_id"`

	// PKCE contains the PKCE challenge data.
	PKCE PKCEChallenge `json:"pkce"`

	// State is the OAuth state parameter.
	State string `json:"state,omitempty"`

	// CreatedAt is when the code was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the code expires.
	ExpiresAt time.Time `json:"expires_at"`

	// Used indicates if the code has already been used.
	Used bool `json:"used"`
}

// IsExpired checks if the authorization code has expired.
func (a *AuthorizationCode) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// IsValid checks if the authorization code is valid (not used and not expired).
func (a *AuthorizationCode) IsValid() bool {
	return !a.Used && !a.IsExpired()
}

// NewAuthorizationCode creates a new authorization code.
func NewAuthorizationCode(
	code string,
	clientID string,
	redirectURI string,
	scope string,
	resource string,
	userID string,
	pkce PKCEChallenge,
	state string,
	ttl time.Duration,
) *AuthorizationCode {
	now := time.Now()

	return &AuthorizationCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		Resource:    resource,
		UserID:      userID,
		PKCE:        pkce,
		State:       state,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		Used:        false,
	}
}

// PendingAuthorization stores state during the OAuth flow.
type PendingAuthorization struct {
	// ClientID is the OAuth client that initiated the flow.
	ClientID string `json:"client_id"`

	// RedirectURI is the callback URL.
	RedirectURI string `json:"redirect_uri"`

	// Scope contains the requested OAuth scopes.
	Scope string `json:"scope"`

	// State is the client's state parameter.
	State string `json:"state"`

	// CodeChallenge is the PKCE code challenge.
	CodeChallenge string `json:"code_challenge"`

	// CodeChallengeMethod is the PKCE method (always S256).
	CodeChallengeMethod string `json:"code_challenge_method"`

	// Resource is the resource indicator (RFC 8707).
	Resource string `json:"resource"`

	// CreatedAt is when the authorization was initiated.
	CreatedAt time.Time `json:"created_at"`
}
