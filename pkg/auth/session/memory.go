// Package session provides session and user management.
package session

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Error sentinels for session operations.
var (
	// ErrUserNotFound indicates no user exists for the given identifier.
	ErrUserNotFound = errors.New("user not found")

	// ErrSessionNotFound indicates no session exists for the given identifier.
	ErrSessionNotFound = errors.New("session not found")

	// ErrInvalidGrant indicates the authorization code or refresh token is invalid.
	ErrInvalidGrant = errors.New("invalid grant")

	// ErrInvalidState indicates the OAuth state parameter is invalid or missing.
	ErrInvalidState = errors.New("invalid state parameter")
)

// Ensure MemoryStore implements Store.
var _ Store = (*MemoryStore)(nil)

// MemoryStore implements Store with in-memory storage.
type MemoryStore struct {
	log logrus.FieldLogger

	mu                    sync.RWMutex
	users                 map[string]*User    // userID -> User
	usersByGitHubID       map[int64]string    // githubID -> userID
	sessions              map[string]*Session // sessionID -> Session
	sessionsByAccessJTI   map[string]string   // accessJTI -> sessionID
	sessionsByRefreshJTI  map[string]string   // refreshJTI -> sessionID
	authorizationCodes    map[string]*AuthorizationCode
	pendingAuthorizations map[string]*PendingAuthorization

	// Cleanup goroutine control.
	stopCleanup chan struct{}
	cleanupDone chan struct{}
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore(log logrus.FieldLogger) *MemoryStore {
	return &MemoryStore{
		log:                   log.WithField("component", "memory_store"),
		users:                 make(map[string]*User, 100),
		usersByGitHubID:       make(map[int64]string, 100),
		sessions:              make(map[string]*Session, 1000),
		sessionsByAccessJTI:   make(map[string]string, 1000),
		sessionsByRefreshJTI:  make(map[string]string, 1000),
		authorizationCodes:    make(map[string]*AuthorizationCode, 100),
		pendingAuthorizations: make(map[string]*PendingAuthorization, 100),
		stopCleanup:           make(chan struct{}),
		cleanupDone:           make(chan struct{}),
	}
}

// Start begins the cleanup goroutine.
func (m *MemoryStore) Start(ctx context.Context) error {
	go m.cleanupLoop(ctx)

	m.log.Info("Memory store started")

	return nil
}

// Stop stops the cleanup goroutine.
func (m *MemoryStore) Stop() error {
	close(m.stopCleanup)
	<-m.cleanupDone

	m.log.Info("Memory store stopped")

	return nil
}

// cleanupLoop runs periodic cleanup of expired data.
func (m *MemoryStore) cleanupLoop(ctx context.Context) {
	defer close(m.cleanupDone)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			if err := m.CleanupExpired(ctx); err != nil {
				m.log.WithError(err).Warn("Cleanup failed")
			}
		}
	}
}

// GetUser retrieves a user by ID.
func (m *MemoryStore) GetUser(_ context.Context, userID string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, ok := m.users[userID]
	if !ok {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// GetUserByGitHubID retrieves a user by their GitHub ID.
func (m *MemoryStore) GetUserByGitHubID(_ context.Context, githubID int64) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	userID, ok := m.usersByGitHubID[githubID]
	if !ok {
		return nil, ErrUserNotFound
	}

	user, ok := m.users[userID]
	if !ok {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// SaveUser creates or updates a user.
func (m *MemoryStore) SaveUser(_ context.Context, user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.users[user.ID] = user
	m.usersByGitHubID[user.GitHubID] = user.ID

	return nil
}

// UpdateUserOrganizations updates a user's organization memberships.
func (m *MemoryStore) UpdateUserOrganizations(_ context.Context, userID string, organizations []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[userID]
	if !ok {
		return ErrUserNotFound
	}

	user.Organizations = organizations
	user.UpdatedAt = time.Now()

	return nil
}

// GetSession retrieves a session by ID.
func (m *MemoryStore) GetSession(_ context.Context, sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

// GetSessionByAccessJTI retrieves a session by access token JTI.
func (m *MemoryStore) GetSessionByAccessJTI(_ context.Context, jti string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessionID, ok := m.sessionsByAccessJTI[jti]
	if !ok {
		return nil, ErrSessionNotFound
	}

	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

// GetSessionByRefreshJTI retrieves a session by refresh token JTI.
func (m *MemoryStore) GetSessionByRefreshJTI(_ context.Context, jti string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessionID, ok := m.sessionsByRefreshJTI[jti]
	if !ok {
		return nil, ErrSessionNotFound
	}

	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

// SaveSession creates or updates a session.
func (m *MemoryStore) SaveSession(_ context.Context, session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[session.ID] = session
	m.sessionsByAccessJTI[session.AccessTokenJTI] = session.ID
	m.sessionsByRefreshJTI[session.RefreshTokenJTI] = session.ID

	return nil
}

// RevokeSession marks a session as revoked.
func (m *MemoryStore) RevokeSession(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	session.Revoked = true

	return nil
}

// UpdateSessionTokens updates a session with new token JTIs.
func (m *MemoryStore) UpdateSessionTokens(
	_ context.Context,
	sessionID string,
	accessJTI string,
	refreshJTI string,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	// Remove old JTI mappings.
	delete(m.sessionsByAccessJTI, session.AccessTokenJTI)
	delete(m.sessionsByRefreshJTI, session.RefreshTokenJTI)

	// Update session.
	session.AccessTokenJTI = accessJTI
	session.RefreshTokenJTI = refreshJTI
	session.LastUsedAt = time.Now()

	// Add new JTI mappings.
	m.sessionsByAccessJTI[accessJTI] = session.ID
	m.sessionsByRefreshJTI[refreshJTI] = session.ID

	return nil
}

// GetAuthorizationCode retrieves an authorization code.
func (m *MemoryStore) GetAuthorizationCode(_ context.Context, code string) (*AuthorizationCode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	authCode, ok := m.authorizationCodes[code]
	if !ok {
		return nil, ErrInvalidGrant
	}

	return authCode, nil
}

// SaveAuthorizationCode stores an authorization code.
func (m *MemoryStore) SaveAuthorizationCode(_ context.Context, authCode *AuthorizationCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.authorizationCodes[authCode.Code] = authCode

	return nil
}

// MarkAuthorizationCodeUsed marks an authorization code as used.
func (m *MemoryStore) MarkAuthorizationCodeUsed(_ context.Context, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	authCode, ok := m.authorizationCodes[code]
	if !ok {
		return ErrInvalidGrant
	}

	authCode.Used = true

	return nil
}

// DeleteAuthorizationCode removes an authorization code.
func (m *MemoryStore) DeleteAuthorizationCode(_ context.Context, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.authorizationCodes, code)

	return nil
}

// GetPendingAuthorization retrieves a pending authorization by state.
func (m *MemoryStore) GetPendingAuthorization(_ context.Context, state string) (*PendingAuthorization, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pending, ok := m.pendingAuthorizations[state]
	if !ok {
		return nil, ErrInvalidState
	}

	return pending, nil
}

// SavePendingAuthorization stores a pending authorization.
func (m *MemoryStore) SavePendingAuthorization(
	_ context.Context,
	state string,
	pending *PendingAuthorization,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pendingAuthorizations[state] = pending

	return nil
}

// DeletePendingAuthorization removes a pending authorization.
func (m *MemoryStore) DeletePendingAuthorization(_ context.Context, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.pendingAuthorizations, state)

	return nil
}

// CleanupExpired removes expired codes and sessions.
func (m *MemoryStore) CleanupExpired(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Clean expired authorization codes.
	expiredCodes := make([]string, 0, 10)

	for code, authCode := range m.authorizationCodes {
		if authCode.IsExpired() {
			expiredCodes = append(expiredCodes, code)
		}
	}

	for _, code := range expiredCodes {
		delete(m.authorizationCodes, code)
	}

	// Clean expired sessions.
	expiredSessions := make([]string, 0, 10)

	for sessionID, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	for _, sessionID := range expiredSessions {
		session := m.sessions[sessionID]
		delete(m.sessionsByAccessJTI, session.AccessTokenJTI)
		delete(m.sessionsByRefreshJTI, session.RefreshTokenJTI)
		delete(m.sessions, sessionID)
	}

	// Clean expired pending authorizations (older than 10 minutes).
	expiredPending := make([]string, 0, 10)
	pendingTTL := 10 * time.Minute

	for state, pending := range m.pendingAuthorizations {
		if now.Sub(pending.CreatedAt) > pendingTTL {
			expiredPending = append(expiredPending, state)
		}
	}

	for _, state := range expiredPending {
		delete(m.pendingAuthorizations, state)
	}

	if len(expiredCodes) > 0 || len(expiredSessions) > 0 || len(expiredPending) > 0 {
		m.log.WithFields(logrus.Fields{
			"expired_codes":    len(expiredCodes),
			"expired_sessions": len(expiredSessions),
			"expired_pending":  len(expiredPending),
		}).Debug("Cleaned up expired data")
	}

	return nil
}
