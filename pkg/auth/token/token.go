// Package token provides JWT token creation and validation.
package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/pkg/config"
)

// Error sentinels for token operations.
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

// Service defines the interface for token operations.
type Service interface {
	// CreateAccessToken creates a new access token.
	CreateAccessToken(ctx context.Context, params CreateTokenParams) (token string, jti string, err error)

	// CreateRefreshToken creates a new refresh token.
	CreateRefreshToken(ctx context.Context, params CreateTokenParams) (token string, jti string, err error)

	// ValidateToken validates a token and returns its claims.
	ValidateToken(ctx context.Context, token string, expectedAudience string, tokenType TokenType) (*Claims, error)

	// GetAccessTokenTTL returns the access token TTL.
	GetAccessTokenTTL() time.Duration

	// GetRefreshTokenTTL returns the refresh token TTL.
	GetRefreshTokenTTL() time.Duration
}

// Ensure service implements Service.
var _ Service = (*service)(nil)

// service implements the Service interface.
type service struct {
	log             logrus.FieldLogger
	secretKey       []byte
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	algorithm       jwt.SigningMethod
}

// NewService creates a new token service.
func NewService(log logrus.FieldLogger, cfg config.TokensConfig) (Service, error) {
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("tokens.secret_key is required")
	}

	s := &service{
		log:             log.WithField("component", "token_service"),
		secretKey:       []byte(cfg.SecretKey),
		issuer:          cfg.Issuer,
		accessTokenTTL:  cfg.AccessTokenTTL,
		refreshTokenTTL: cfg.RefreshTokenTTL,
		algorithm:       jwt.SigningMethodHS256,
	}

	// Apply defaults.
	if s.accessTokenTTL == 0 {
		s.accessTokenTTL = time.Hour
	}

	if s.refreshTokenTTL == 0 {
		s.refreshTokenTTL = 30 * 24 * time.Hour
	}

	s.log.WithFields(logrus.Fields{
		"issuer":            s.issuer,
		"access_token_ttl":  s.accessTokenTTL,
		"refresh_token_ttl": s.refreshTokenTTL,
	}).Info("Token service initialized")

	return s, nil
}

// CreateAccessToken creates a new access token.
func (s *service) CreateAccessToken(
	ctx context.Context,
	params CreateTokenParams,
) (string, string, error) {
	return s.createToken(ctx, params, TokenTypeAccess, s.accessTokenTTL)
}

// CreateRefreshToken creates a new refresh token.
func (s *service) CreateRefreshToken(
	ctx context.Context,
	params CreateTokenParams,
) (string, string, error) {
	return s.createToken(ctx, params, TokenTypeRefresh, s.refreshTokenTTL)
}

// createToken creates a new token with the specified type and TTL.
func (s *service) createToken(
	_ context.Context,
	params CreateTokenParams,
	tokenType TokenType,
	ttl time.Duration,
) (string, string, error) {
	jti := uuid.New().String()
	now := time.Now()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   params.UserID,
			Audience:  jwt.ClaimStrings{params.Resource},
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Scope:     params.Scope,
		ClientID:  params.ClientID,
		TokenType: tokenType,
	}

	token := jwt.NewWithClaims(s.algorithm, claims)

	signed, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", "", fmt.Errorf("signing token: %w", err)
	}

	s.log.WithFields(logrus.Fields{
		"jti":        jti,
		"user_id":    params.UserID,
		"client_id":  params.ClientID,
		"token_type": tokenType,
		"scope":      params.Scope,
		"resource":   params.Resource,
		"expires_in": ttl.String(),
	}).Debug("Token created")

	return signed, jti, nil
}

// ValidateToken validates a token and returns its claims.
func (s *service) ValidateToken(
	_ context.Context,
	tokenStr string,
	expectedAudience string,
	expectedType TokenType,
) (*Claims, error) {
	if expectedAudience == "" {
		return nil, fmt.Errorf("expected_audience is required for token validation (RFC 8707)")
	}

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
		// Verify signing method.
		if token.Method.Alg() != s.algorithm.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return s.secretKey, nil
	}, jwt.WithIssuer(s.issuer), jwt.WithExpirationRequired())

	if err != nil {
		// Check for specific error types.
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}

		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	if !token.Valid {
		return nil, ErrTokenInvalid
	}

	// Verify token type.
	if claims.TokenType != expectedType {
		s.log.WithFields(logrus.Fields{
			"expected_type": expectedType,
			"actual_type":   claims.TokenType,
		}).Warn("Token type mismatch")

		return nil, fmt.Errorf("%w: expected %s, got %s", ErrTokenType, expectedType, claims.TokenType)
	}

	// Verify audience (RFC 8707 - critical for security).
	audienceValid := false

	for _, aud := range claims.Audience {
		if aud == expectedAudience {
			audienceValid = true

			break
		}
	}

	if !audienceValid {
		s.log.WithFields(logrus.Fields{
			"expected_audience": expectedAudience,
			"actual_audience":   claims.Audience,
		}).Warn("Token audience mismatch")

		return nil, fmt.Errorf("%w: token audience %v does not match expected %s",
			ErrTokenAudience, claims.Audience, expectedAudience)
	}

	return claims, nil
}

// GetAccessTokenTTL returns the access token TTL.
func (s *service) GetAccessTokenTTL() time.Duration {
	return s.accessTokenTTL
}

// GetRefreshTokenTTL returns the refresh token TTL.
func (s *service) GetRefreshTokenTTL() time.Duration {
	return s.refreshTokenTTL
}
