package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/mcp/pkg/proxy/handlers"
)

// Service is the credential proxy service interface.
type Service interface {
	// Start starts the proxy server.
	Start(ctx context.Context) error

	// Stop stops the proxy server.
	Stop(ctx context.Context) error

	// URL returns the proxy URL for sandbox environment variables.
	URL() string

	// RegisterToken creates a new token for an execution and returns it.
	RegisterToken(executionID string) string

	// RevokeToken revokes a token for an execution.
	RevokeToken(executionID string)

	// ClickHouseDatasources returns the list of ClickHouse datasource names.
	ClickHouseDatasources() []string

	// PrometheusDatasources returns the list of Prometheus datasource names.
	PrometheusDatasources() []string

	// LokiDatasources returns the list of Loki datasource names.
	LokiDatasources() []string

	// S3Bucket returns the configured S3 bucket name.
	S3Bucket() string
}

// service implements the Service interface.
type service struct {
	log    logrus.FieldLogger
	cfg    Config
	server *http.Server
	mux    *http.ServeMux

	tokens     *TokenStore
	listenAddr string

	clickhouseHandler *handlers.ClickHouseHandler
	prometheusHandler *handlers.PrometheusHandler
	lokiHandler       *handlers.LokiHandler
	s3Handler         *handlers.S3Handler

	mu      sync.RWMutex
	started bool
}

// Compile-time interface check.
var _ Service = (*service)(nil)

// Options holds the configuration for creating a new proxy service.
type Options struct {
	Config     Config
	ClickHouse []handlers.ClickHouseConfig
	Prometheus []handlers.PrometheusConfig
	Loki       []handlers.LokiConfig
	S3         *handlers.S3Config
}

// New creates a new proxy service.
func New(log logrus.FieldLogger, opts Options) Service {
	opts.Config.ApplyDefaults()

	s := &service{
		log:        log.WithField("component", "proxy"),
		cfg:        opts.Config,
		tokens:     NewTokenStore(opts.Config.TokenTTL),
		listenAddr: opts.Config.ListenAddr,
		mux:        http.NewServeMux(),
	}

	// Create handlers for each datasource type.
	if len(opts.ClickHouse) > 0 {
		s.clickhouseHandler = handlers.NewClickHouseHandler(log, opts.ClickHouse)
	}

	if len(opts.Prometheus) > 0 {
		s.prometheusHandler = handlers.NewPrometheusHandler(log, opts.Prometheus)
	}

	if len(opts.Loki) > 0 {
		s.lokiHandler = handlers.NewLokiHandler(log, opts.Loki)
	}

	if opts.S3 != nil && opts.S3.Endpoint != "" {
		s.s3Handler = handlers.NewS3Handler(log, opts.S3)
	}

	// Register routes.
	s.registerRoutes()

	return s
}

// registerRoutes sets up the HTTP routes.
func (s *service) registerRoutes() {
	// Health check endpoint (no auth required).
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Datasources info endpoint (for Python modules to discover available datasources).
	s.mux.HandleFunc("/datasources", s.handleDatasources)

	// Authenticated routes.
	if s.clickhouseHandler != nil {
		s.mux.Handle("/clickhouse/", s.withTokenAuth(s.clickhouseHandler))
	}

	if s.prometheusHandler != nil {
		s.mux.Handle("/prometheus/", s.withTokenAuth(s.prometheusHandler))
	}

	if s.lokiHandler != nil {
		s.mux.Handle("/loki/", s.withTokenAuth(s.lokiHandler))
	}

	if s.s3Handler != nil {
		s.mux.Handle("/s3/", s.withTokenAuth(s.s3Handler))
	}
}

// withTokenAuth wraps a handler with token authentication.
func (s *service) withTokenAuth(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header.
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Expect "Bearer <token>" format.
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")

		// Validate token.
		executionID := s.tokens.Validate(token)
		if executionID == "" {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Add execution ID to request context for logging.
		ctx := context.WithValue(r.Context(), executionIDKey, executionID)

		s.log.WithFields(logrus.Fields{
			"execution_id": executionID,
			"path":         r.URL.Path,
			"method":       r.Method,
		}).Debug("Authenticated request")

		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

type contextKey string

const executionIDKey contextKey = "execution_id"

// handleDatasources returns the list of available datasources.
func (s *service) handleDatasources(w http.ResponseWriter, _ *http.Request) {
	info := struct {
		ClickHouse []string `json:"clickhouse"`
		Prometheus []string `json:"prometheus"`
		Loki       []string `json:"loki"`
		S3Bucket   string   `json:"s3_bucket,omitempty"`
	}{
		ClickHouse: s.ClickHouseDatasources(),
		Prometheus: s.PrometheusDatasources(),
		Loki:       s.LokiDatasources(),
		S3Bucket:   s.S3Bucket(),
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(info); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// Start starts the proxy server.
func (s *service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return fmt.Errorf("proxy already started")
	}

	s.server = &http.Server{
		Addr:              s.listenAddr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute, // Long timeout for S3 uploads
		IdleTimeout:       60 * time.Second,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
	}

	// Start server in background.
	go func() {
		s.log.WithField("addr", s.listenAddr).Info("Starting proxy server")

		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.WithError(err).Error("Proxy server error")
		}
	}()

	s.started = true

	return nil
}

// Stop stops the proxy server.
func (s *service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return nil
	}

	s.tokens.Stop()

	if s.server != nil {
		if err := s.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutting down proxy server: %w", err)
		}
	}

	s.started = false
	s.log.Info("Proxy server stopped")

	return nil
}

// URL returns the proxy URL for sandbox environment variables.
func (s *service) URL() string {
	// Return a URL that containers on mcp-internal network can reach.
	// The proxy listens on all interfaces, so we use the configured sandbox host.
	host := s.cfg.SandboxHost
	if host == "" {
		host = "host.docker.internal"
	}

	// Extract port from listen address.
	port := "8081"
	if _, p, err := net.SplitHostPort(s.listenAddr); err == nil && p != "" {
		port = p
	}

	return fmt.Sprintf("http://%s:%s", host, port)
}

// RegisterToken creates a new token for an execution and returns it.
func (s *service) RegisterToken(executionID string) string {
	return s.tokens.Register(executionID)
}

// RevokeToken revokes a token for an execution.
func (s *service) RevokeToken(executionID string) {
	s.tokens.Revoke(executionID)
}

// ClickHouseDatasources returns the list of ClickHouse datasource names.
func (s *service) ClickHouseDatasources() []string {
	if s.clickhouseHandler == nil {
		return nil
	}

	return s.clickhouseHandler.Clusters()
}

// PrometheusDatasources returns the list of Prometheus datasource names.
func (s *service) PrometheusDatasources() []string {
	if s.prometheusHandler == nil {
		return nil
	}

	return s.prometheusHandler.Instances()
}

// LokiDatasources returns the list of Loki datasource names.
func (s *service) LokiDatasources() []string {
	if s.lokiHandler == nil {
		return nil
	}

	return s.lokiHandler.Instances()
}

// S3Bucket returns the configured S3 bucket name.
func (s *service) S3Bucket() string {
	if s.s3Handler == nil {
		return ""
	}

	return s.s3Handler.Bucket()
}
