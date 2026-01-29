package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// TokenStore manages per-execution tokens with TTL-based expiry.
type TokenStore struct {
	mu      sync.RWMutex
	tokens  map[string]tokenEntry
	ttl     time.Duration
	stopCh  chan struct{}
	stopped bool
}

type tokenEntry struct {
	executionID string
	expiresAt   time.Time
}

// NewTokenStore creates a new token store with the given TTL.
func NewTokenStore(ttl time.Duration) *TokenStore {
	ts := &TokenStore{
		tokens: make(map[string]tokenEntry, 64),
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}

	// Start background cleanup goroutine.
	go ts.cleanupLoop()

	return ts
}

// Register creates a new token for the given execution ID.
// Returns the generated token.
func (ts *TokenStore) Register(executionID string) string {
	token := generateToken()

	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.tokens[token] = tokenEntry{
		executionID: executionID,
		expiresAt:   time.Now().Add(ts.ttl),
	}

	return token
}

// Validate checks if a token is valid and returns the associated execution ID.
// Returns empty string if the token is invalid or expired.
func (ts *TokenStore) Validate(token string) string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	entry, ok := ts.tokens[token]
	if !ok {
		return ""
	}

	if time.Now().After(entry.expiresAt) {
		return ""
	}

	return entry.executionID
}

// Revoke removes a token by execution ID.
func (ts *TokenStore) Revoke(executionID string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for token, entry := range ts.tokens {
		if entry.executionID == executionID {
			delete(ts.tokens, token)

			return
		}
	}
}

// Stop stops the background cleanup goroutine.
func (ts *TokenStore) Stop() {
	ts.mu.Lock()
	if ts.stopped {
		ts.mu.Unlock()
		return
	}

	ts.stopped = true
	ts.mu.Unlock()

	close(ts.stopCh)
}

// cleanupLoop periodically removes expired tokens.
func (ts *TokenStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ts.stopCh:
			return
		case <-ticker.C:
			ts.cleanup()
		}
	}
}

// cleanup removes expired tokens.
func (ts *TokenStore) cleanup() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()

	for token, entry := range ts.tokens {
		if now.After(entry.expiresAt) {
			delete(ts.tokens, token)
		}
	}
}

// generateToken creates a cryptographically secure random token.
func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// This should never happen with crypto/rand.
		panic("failed to generate random token: " + err.Error())
	}

	return base64.URLEncoding.EncodeToString(b)
}
