package sandbox

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ethpandaops/xatu-mcp/pkg/config"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Session represents a persistent sandbox execution environment.
type Session struct {
	ID          string
	OwnerID     string // GitHub user ID that owns this session
	ContainerID string
	CreatedAt   time.Time
	LastUsed    time.Time
	Env         map[string]string
}

// SessionManager manages the lifecycle of persistent sandbox sessions.
type SessionManager struct {
	cfg      config.SessionConfig
	log      logrus.FieldLogger
	sessions map[string]*Session
	mu       sync.RWMutex
	done     chan struct{}
	wg       sync.WaitGroup

	// cleanupCallback is called when a session is destroyed.
	cleanupCallback func(ctx context.Context, containerID string) error
}

// NewSessionManager creates a new session manager.
func NewSessionManager(
	cfg config.SessionConfig,
	log logrus.FieldLogger,
	cleanupCallback func(ctx context.Context, containerID string) error,
) *SessionManager {
	return &SessionManager{
		cfg:             cfg,
		log:             log.WithField("component", "session-manager"),
		sessions:        make(map[string]*Session, cfg.MaxSessions),
		done:            make(chan struct{}),
		cleanupCallback: cleanupCallback,
	}
}

// Start begins the background cleanup goroutine.
func (m *SessionManager) Start(ctx context.Context) error {
	if !m.cfg.IsEnabled() {
		m.log.Info("Session support is disabled")
		return nil
	}

	m.log.WithFields(logrus.Fields{
		"ttl":          m.cfg.TTL,
		"max_duration": m.cfg.MaxDuration,
		"max_sessions": m.cfg.MaxSessions,
	}).Info("Starting session manager")

	m.wg.Add(1)

	go m.cleanupLoop(ctx)

	return nil
}

// Stop terminates the cleanup goroutine and destroys all active sessions.
func (m *SessionManager) Stop(ctx context.Context) error {
	if !m.cfg.IsEnabled() {
		return nil
	}

	m.log.Info("Stopping session manager")

	close(m.done)
	m.wg.Wait()

	// Destroy all remaining sessions.
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))

	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}

	m.sessions = make(map[string]*Session, m.cfg.MaxSessions)
	m.mu.Unlock()

	for _, s := range sessions {
		if err := m.cleanupCallback(ctx, s.ContainerID); err != nil {
			m.log.WithFields(logrus.Fields{
				"session_id":   s.ID,
				"container_id": s.ContainerID,
				"error":        err,
			}).Warn("Failed to cleanup session during shutdown")
		}
	}

	m.log.Info("Session manager stopped")

	return nil
}

// Create creates a new session and returns its ID.
// ownerID should be the GitHub user ID of the authenticated user.
func (m *SessionManager) Create(containerID string, env map[string]string, ownerID string) (*Session, error) {
	if !m.cfg.IsEnabled() {
		return nil, fmt.Errorf("sessions are disabled")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.sessions) >= m.cfg.MaxSessions {
		return nil, fmt.Errorf("maximum number of sessions (%d) reached", m.cfg.MaxSessions)
	}

	now := time.Now()
	session := &Session{
		ID:          uuid.New().String(),
		OwnerID:     ownerID,
		ContainerID: containerID,
		CreatedAt:   now,
		LastUsed:    now,
		Env:         env,
	}

	m.sessions[session.ID] = session

	m.log.WithFields(logrus.Fields{
		"session_id":   session.ID,
		"container_id": containerID,
	}).Info("Created new session")

	return session, nil
}

// Get retrieves a session by ID and updates its last used timestamp.
// ownerID should be the GitHub user ID of the authenticated user requesting the session.
func (m *SessionManager) Get(sessionID string, ownerID string) (*Session, error) {
	if !m.cfg.IsEnabled() {
		return nil, fmt.Errorf("sessions are disabled")
	}

	m.mu.Lock()

	session, ok := m.sessions[sessionID]
	if !ok {
		m.mu.Unlock()

		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	// Verify ownership.
	if session.OwnerID != ownerID {
		m.mu.Unlock()

		return nil, fmt.Errorf("session %s not owned by caller", sessionID)
	}

	// Check if session has exceeded max duration.
	if time.Since(session.CreatedAt) > m.cfg.MaxDuration {
		delete(m.sessions, sessionID)
		containerID := session.ContainerID
		m.mu.Unlock()

		// Cleanup container asynchronously to avoid blocking.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := m.cleanupCallback(ctx, containerID); err != nil {
				m.log.WithFields(logrus.Fields{
					"session_id":   sessionID,
					"container_id": containerID,
					"error":        err,
				}).Warn("Failed to cleanup expired session container")
			}
		}()

		return nil, fmt.Errorf("session %s has expired (max duration exceeded)", sessionID)
	}

	// Check if session has exceeded TTL (idle timeout).
	if time.Since(session.LastUsed) > m.cfg.TTL {
		delete(m.sessions, sessionID)
		containerID := session.ContainerID
		m.mu.Unlock()

		// Cleanup container asynchronously.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := m.cleanupCallback(ctx, containerID); err != nil {
				m.log.WithFields(logrus.Fields{
					"session_id":   sessionID,
					"container_id": containerID,
					"error":        err,
				}).Warn("Failed to cleanup expired session container")
			}
		}()

		return nil, fmt.Errorf("session %s has expired (idle timeout exceeded)", sessionID)
	}

	// Update last used timestamp.
	session.LastUsed = time.Now()

	m.mu.Unlock()

	return session, nil
}

// Touch updates the last used timestamp for a session.
func (m *SessionManager) Touch(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, ok := m.sessions[sessionID]; ok {
		session.LastUsed = time.Now()
	}
}

// TTLRemaining returns the time remaining until the session expires from inactivity.
func (m *SessionManager) TTLRemaining(sessionID string) time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return 0
	}

	elapsed := time.Since(session.LastUsed)
	remaining := m.cfg.TTL - elapsed

	if remaining < 0 {
		return 0
	}

	return remaining
}

// Destroy removes a session and triggers cleanup callback.
func (m *SessionManager) Destroy(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	session, ok := m.sessions[sessionID]

	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("session %s not found", sessionID)
	}

	delete(m.sessions, sessionID)
	m.mu.Unlock()

	m.log.WithFields(logrus.Fields{
		"session_id":   sessionID,
		"container_id": session.ContainerID,
	}).Info("Destroying session")

	return m.cleanupCallback(ctx, session.ContainerID)
}

// Enabled returns whether sessions are enabled.
func (m *SessionManager) Enabled() bool {
	return m.cfg.IsEnabled()
}

// cleanupLoop runs periodically to destroy expired sessions.
func (m *SessionManager) cleanupLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-ticker.C:
			m.cleanupExpired(ctx)
		}
	}
}

// cleanupExpired destroys sessions that have exceeded TTL or max duration.
func (m *SessionManager) cleanupExpired(ctx context.Context) {
	m.mu.Lock()
	now := time.Now()
	expiredSessions := make([]*Session, 0)

	for id, session := range m.sessions {
		// Check TTL (time since last use).
		if now.Sub(session.LastUsed) > m.cfg.TTL {
			m.log.WithFields(logrus.Fields{
				"session_id": id,
				"idle_time":  now.Sub(session.LastUsed),
			}).Info("Session expired (TTL)")

			expiredSessions = append(expiredSessions, session)
			delete(m.sessions, id)

			continue
		}

		// Check max duration.
		if now.Sub(session.CreatedAt) > m.cfg.MaxDuration {
			m.log.WithFields(logrus.Fields{
				"session_id": id,
				"age":        now.Sub(session.CreatedAt),
			}).Info("Session expired (max duration)")

			expiredSessions = append(expiredSessions, session)
			delete(m.sessions, id)
		}
	}

	m.mu.Unlock()

	// Cleanup containers outside the lock.
	for _, session := range expiredSessions {
		if err := m.cleanupCallback(ctx, session.ContainerID); err != nil {
			m.log.WithFields(logrus.Fields{
				"session_id":   session.ID,
				"container_id": session.ContainerID,
				"error":        err,
			}).Warn("Failed to cleanup expired session")
		}
	}
}
