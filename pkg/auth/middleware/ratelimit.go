// Package middleware provides authentication middleware for HTTP handlers.
package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// RateLimiter provides per-user rate limiting.
type RateLimiter struct {
	log      logrus.FieldLogger
	limiters sync.Map // map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

// NewRateLimiter creates a new rate limiter.
// requestsPerHour is the maximum requests per hour per user.
func NewRateLimiter(log logrus.FieldLogger, requestsPerHour int) *RateLimiter {
	if requestsPerHour <= 0 {
		requestsPerHour = 100 // default
	}

	// Convert requests per hour to rate per second.
	r := rate.Limit(float64(requestsPerHour) / 3600.0)

	// Burst allows some requests to go through immediately.
	// Set to 1/10th of hourly limit or at least 10.
	burst := requestsPerHour / 10
	if burst < 10 {
		burst = 10
	}

	return &RateLimiter{
		log:   log.WithField("component", "rate_limiter"),
		rate:  r,
		burst: burst,
	}
}

// getLimiter gets or creates a rate limiter for the given key.
func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	if limiter, ok := rl.limiters.Load(key); ok {
		return limiter.(*rate.Limiter)
	}

	limiter := rate.NewLimiter(rl.rate, rl.burst)
	rl.limiters.Store(key, limiter)

	return limiter
}

// Allow checks if a request is allowed for the given key.
func (rl *RateLimiter) Allow(key string) bool {
	limiter := rl.getLimiter(key)

	return limiter.Allow()
}

// Handler returns the rate limiting middleware handler.
func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get rate limit key from authenticated user or IP.
		key := rl.getKey(r)

		if !rl.Allow(key) {
			rl.log.WithFields(logrus.Fields{
				"key":  key,
				"path": r.URL.Path,
			}).Warn("Rate limit exceeded")

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)

			_, _ = w.Write([]byte(`{"error":"rate_limit_exceeded","error_description":"Too many requests. Please try again later."}`))

			return
		}

		next.ServeHTTP(w, r)
	})
}

// getKey returns the rate limit key for a request.
// Uses user ID if authenticated, otherwise uses IP address.
func (rl *RateLimiter) getKey(r *http.Request) string {
	// Check for authenticated user.
	if authUser := GetAuthUser(r.Context()); authUser != nil && authUser.User != nil {
		return "user:" + authUser.User.ID
	}

	// Fall back to IP address.
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}

	if ip == "" {
		ip = r.RemoteAddr
	}

	return "ip:" + ip
}

// CleanupExpired removes expired rate limiters to prevent memory leaks.
// This should be called periodically.
func (rl *RateLimiter) CleanupExpired() {
	// Rate limiters don't have explicit expiry, but we can remove ones
	// that haven't been used recently. For simplicity, we'll just
	// periodically clear all limiters. They'll be recreated on next request.
	rl.limiters = sync.Map{}

	rl.log.Debug("Cleared rate limiters")
}

// StartCleanup starts a background goroutine to clean up expired limiters.
func (rl *RateLimiter) StartCleanup(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				rl.CleanupExpired()
			case <-stopCh:
				return
			}
		}
	}()
}
