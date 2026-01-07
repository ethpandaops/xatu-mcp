// Package auth provides OAuth 2.1 authentication for xatu-mcp.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/pkg/auth/middleware"
	"github.com/ethpandaops/xatu-mcp/pkg/auth/oauth"
	"github.com/ethpandaops/xatu-mcp/pkg/auth/session"
	"github.com/ethpandaops/xatu-mcp/pkg/auth/token"
	"github.com/ethpandaops/xatu-mcp/pkg/config"
)

// Service is the main auth service interface.
type Service interface {
	// Start initializes the auth service.
	Start(ctx context.Context) error

	// Stop shuts down the auth service.
	Stop() error

	// Enabled returns whether authentication is enabled.
	Enabled() bool

	// Middleware returns the authentication middleware handler.
	Middleware() func(http.Handler) http.Handler

	// MountRoutes mounts OAuth routes on a chi router.
	MountRoutes(r chi.Router)

	// RequireScope checks if the given context has the required scope.
	RequireScope(ctx context.Context, scope string) error

	// GetStore returns the session store.
	GetStore() session.Store

	// GetTokenService returns the token service.
	GetTokenService() token.Service
}

// Ensure service implements Service.
var _ Service = (*service)(nil)

// service is the main auth service implementation.
type service struct {
	log          logrus.FieldLogger
	cfg          config.AuthConfig
	baseURL      string
	store        *session.MemoryStore
	tokenService token.Service
	oauthServer  *oauth.Server
	authMW       *middleware.Middleware
	rateLimiter  *middleware.RateLimiter

	// Lifecycle control.
	stopCh    chan struct{}
	stoppedCh chan struct{}
}

// NewService creates a new auth service.
func NewService(log logrus.FieldLogger, cfg config.AuthConfig, baseURL string) (Service, error) {
	log = log.WithField("component", "auth_service")

	if !cfg.Enabled {
		log.Info("Authentication is disabled")

		return &service{
			log:     log,
			cfg:     cfg,
			baseURL: baseURL,
		}, nil
	}

	// Create session store.
	store := session.NewMemoryStore(log)

	// Create token service.
	tokenSvc, err := token.NewService(log, cfg.Tokens)
	if err != nil {
		return nil, fmt.Errorf("creating token service: %w", err)
	}

	// Create OAuth server.
	oauthSrv, err := oauth.NewServer(log, cfg, baseURL, store, tokenSvc)
	if err != nil {
		return nil, fmt.Errorf("creating OAuth server: %w", err)
	}

	// Create middleware.
	authMW := middleware.NewMiddleware(log, cfg, store, tokenSvc, baseURL)

	// Create rate limiter.
	rateLimiter := middleware.NewRateLimiter(log, cfg.RateLimits.RequestsPerHour)

	s := &service{
		log:          log,
		cfg:          cfg,
		baseURL:      baseURL,
		store:        store,
		tokenService: tokenSvc,
		oauthServer:  oauthSrv,
		authMW:       authMW,
		rateLimiter:  rateLimiter,
		stopCh:       make(chan struct{}),
		stoppedCh:    make(chan struct{}),
	}

	log.WithFields(logrus.Fields{
		"base_url":     baseURL,
		"allowed_orgs": cfg.AllowedOrgs,
	}).Info("Auth service created")

	return s, nil
}

// Start initializes the auth service.
func (s *service) Start(ctx context.Context) error {
	if !s.cfg.Enabled {
		return nil
	}

	// Start the session store cleanup.
	if err := s.store.Start(ctx); err != nil {
		return fmt.Errorf("starting session store: %w", err)
	}

	// Start rate limiter cleanup.
	s.rateLimiter.StartCleanup(time.Hour, s.stopCh)

	s.log.Info("Auth service started")

	return nil
}

// Stop shuts down the auth service.
func (s *service) Stop() error {
	if !s.cfg.Enabled {
		return nil
	}

	// Signal stop.
	close(s.stopCh)

	// Stop session store.
	if err := s.store.Stop(); err != nil {
		s.log.WithError(err).Warn("Failed to stop session store")
	}

	s.log.Info("Auth service stopped")

	return nil
}

// Enabled returns whether authentication is enabled.
func (s *service) Enabled() bool {
	return s.cfg.Enabled
}

// Middleware returns the authentication middleware handler.
func (s *service) Middleware() func(http.Handler) http.Handler {
	if !s.cfg.Enabled {
		// Return a no-op middleware when auth is disabled.
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	// Chain auth middleware and rate limiting.
	return func(next http.Handler) http.Handler {
		return s.authMW.Handler(s.rateLimiter.Handler(next))
	}
}

// MountRoutes mounts OAuth routes on a chi router.
func (s *service) MountRoutes(r chi.Router) {
	if !s.cfg.Enabled {
		return
	}

	s.oauthServer.MountRoutes(r)
}

// RequireScope checks if the given context has the required scope.
func (s *service) RequireScope(ctx context.Context, scope string) error {
	if !s.cfg.Enabled {
		return nil
	}

	return middleware.RequireScope(ctx, scope)
}

// GetStore returns the session store.
func (s *service) GetStore() session.Store {
	return s.store
}

// GetTokenService returns the token service.
func (s *service) GetTokenService() token.Service {
	return s.tokenService
}
