// Package oauth provides OAuth 2.1 authorization server functionality.
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/pkg/auth/github"
	"github.com/ethpandaops/xatu-mcp/pkg/auth/session"
	"github.com/ethpandaops/xatu-mcp/pkg/auth/token"
	"github.com/ethpandaops/xatu-mcp/pkg/config"
)

const (
	// Authorization code TTL.
	authCodeTTL = 10 * time.Minute

	// Session TTL.
	sessionTTL = 30 * 24 * time.Hour
)

// Server implements OAuth 2.1 authorization server endpoints.
type Server struct {
	log          logrus.FieldLogger
	baseURL      string
	allowedOrgs  []string
	store        session.Store
	tokenService token.Service
	github       *github.Client

	// Pre-computed metadata.
	resourceMetadata *ProtectedResourceMetadata
	serverMetadata   *AuthorizationServerMetadata
}

// NewServer creates a new OAuth server.
func NewServer(
	log logrus.FieldLogger,
	cfg config.AuthConfig,
	baseURL string,
	store session.Store,
	tokenService token.Service,
) (*Server, error) {
	s := &Server{
		log:              log.WithField("component", "oauth_server"),
		baseURL:          strings.TrimSuffix(baseURL, "/"),
		allowedOrgs:      cfg.AllowedOrgs,
		store:            store,
		tokenService:     tokenService,
		resourceMetadata: NewProtectedResourceMetadata(baseURL),
		serverMetadata:   NewAuthorizationServerMetadata(baseURL),
	}

	if cfg.GitHub != nil {
		s.github = github.NewClient(log, cfg.GitHub)
	}

	s.log.WithFields(logrus.Fields{
		"base_url":       baseURL,
		"github_enabled": s.github != nil,
		"allowed_orgs":   s.allowedOrgs,
	}).Info("OAuth server initialized")

	return s, nil
}

// MountRoutes mounts the OAuth routes on a chi router.
func (s *Server) MountRoutes(r chi.Router) {
	// Well-known endpoints.
	r.Get("/.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	r.Get("/.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	r.Get("/.well-known/openid-configuration", s.handleAuthorizationServerMetadata)

	// OAuth endpoints.
	r.Get("/auth/authorize", s.handleAuthorize)
	r.Get("/auth/github/callback", s.handleGitHubCallback)
	r.Post("/auth/token", s.handleToken)
	r.Post("/auth/revoke", s.handleRevoke)
	r.Get("/auth/userinfo", s.handleUserinfo)
}

// GetResourceMetadataURL returns the URL to the protected resource metadata.
func (s *Server) GetResourceMetadataURL() string {
	return fmt.Sprintf("%s/.well-known/oauth-protected-resource", s.baseURL)
}

// handleProtectedResourceMetadata handles /.well-known/oauth-protected-resource (RFC 9728).
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=3600")

	if err := json.NewEncoder(w).Encode(s.resourceMetadata); err != nil {
		s.log.WithError(err).Error("Failed to encode resource metadata")
	}
}

// handleAuthorizationServerMetadata handles /.well-known/oauth-authorization-server (RFC 8414).
func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=3600")

	if err := json.NewEncoder(w).Encode(s.serverMetadata); err != nil {
		s.log.WithError(err).Error("Failed to encode server metadata")
	}
}

// handleAuthorize handles the authorization endpoint.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.github == nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "GitHub OAuth not configured")

		return
	}

	// Parse authorization request.
	authReq := parseAuthorizationRequest(r)

	// Validate request.
	if errs := s.validateAuthorizationRequest(authReq); len(errs) > 0 {
		s.writeError(w, http.StatusBadRequest, "invalid_request", strings.Join(errs, "; "))

		return
	}

	// Validate redirect URI.
	if !github.ValidateRedirectURI(authReq.RedirectURI) {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")

		return
	}

	// Generate state for GitHub OAuth.
	githubState, err := s.generateState()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "Failed to generate state")

		return
	}

	// Store pending authorization.
	pending := &session.PendingAuthorization{
		ClientID:            authReq.ClientID,
		RedirectURI:         authReq.RedirectURI,
		Scope:               authReq.Scope,
		State:               authReq.State,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
		Resource:            authReq.Resource,
		CreatedAt:           time.Now(),
	}

	if err := s.store.SavePendingAuthorization(r.Context(), githubState, pending); err != nil {
		s.log.WithError(err).Error("Failed to save pending authorization")
		s.writeError(w, http.StatusInternalServerError, "server_error", "Failed to save authorization state")

		return
	}

	// Redirect to GitHub.
	githubCallbackURI := fmt.Sprintf("%s/auth/github/callback", s.baseURL)
	githubURL := s.github.GetAuthorizationURL(githubCallbackURI, githubState, "read:user read:org")

	s.log.WithFields(logrus.Fields{
		"client_id": authReq.ClientID,
		"scope":     authReq.Scope,
	}).Info("Starting authorization flow")

	http.Redirect(w, r, githubURL, http.StatusFound)
}

// handleGitHubCallback handles the GitHub OAuth callback.
func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if s.github == nil {
		s.writeHTMLError(w, http.StatusInternalServerError, "Error", "GitHub OAuth not configured")

		return
	}

	// Get callback parameters.
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	oauthError := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	if oauthError != "" {
		s.log.WithFields(logrus.Fields{
			"error":       oauthError,
			"description": errorDescription,
		}).Warn("GitHub OAuth error")
		s.writeHTMLError(w, http.StatusBadRequest, "Authentication Failed", fmt.Sprintf("%s: %s", oauthError, errorDescription))

		return
	}

	if code == "" || state == "" {
		s.writeHTMLError(w, http.StatusBadRequest, "Error", "Missing code or state parameter")

		return
	}

	// Retrieve pending authorization.
	pending, err := s.store.GetPendingAuthorization(ctx, state)
	if err != nil {
		s.log.WithError(err).Warn("Invalid state in callback")
		s.writeHTMLError(w, http.StatusBadRequest, "Error", "Invalid or expired state")

		return
	}

	// Clean up pending authorization.
	if delErr := s.store.DeletePendingAuthorization(ctx, state); delErr != nil {
		s.log.WithError(delErr).Warn("Failed to delete pending authorization")
	}

	// Exchange code for GitHub token.
	githubCallbackURI := fmt.Sprintf("%s/auth/github/callback", s.baseURL)

	githubToken, err := s.github.ExchangeCode(ctx, code, githubCallbackURI)
	if err != nil {
		s.log.WithError(err).Error("GitHub OAuth failed")
		s.writeHTMLError(w, http.StatusBadRequest, "Authentication Failed", err.Error())

		return
	}

	// Get GitHub user profile.
	githubUser, err := s.github.GetUser(ctx, githubToken.AccessToken)
	if err != nil {
		s.log.WithError(err).Error("Failed to get GitHub user")
		s.writeHTMLError(w, http.StatusInternalServerError, "Error", "Failed to get user profile")

		return
	}

	// Validate org membership.
	if len(s.allowedOrgs) > 0 {
		if !githubUser.IsMemberOf(s.allowedOrgs) {
			s.log.WithFields(logrus.Fields{
				"github_login": githubUser.Login,
				"user_orgs":    githubUser.Organizations,
				"allowed_orgs": s.allowedOrgs,
			}).Warn("User not in allowed organizations")
			s.writeHTMLError(w, http.StatusForbidden, "Access Denied",
				"You are not authorized to access this resource. "+
					"Please contact your administrator if you believe this is an error.")

			return
		}
	}

	// Get or create user.
	user, err := s.getOrCreateUser(ctx, githubUser)
	if err != nil {
		s.log.WithError(err).Error("Failed to get/create user")
		s.writeHTMLError(w, http.StatusInternalServerError, "Error", "Failed to process user")

		return
	}

	// Create authorization code.
	authCode, err := s.createAuthorizationCode(ctx, pending, user.ID)
	if err != nil {
		s.log.WithError(err).Error("Failed to create authorization code")
		s.writeHTMLError(w, http.StatusInternalServerError, "Error", "Failed to create authorization code")

		return
	}

	s.log.WithFields(logrus.Fields{
		"github_login": githubUser.Login,
		"user_id":      user.ID,
		"client_id":    pending.ClientID,
	}).Info("Authorization successful")

	// Redirect back to client with authorization code.
	redirectParams := url.Values{
		"code": {authCode.Code},
	}

	if pending.State != "" {
		redirectParams.Set("state", pending.State)
	}

	redirectURL := fmt.Sprintf("%s?%s", pending.RedirectURI, redirectParams.Encode())
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleToken handles the token endpoint.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid form data")

		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r)
	default:
		s.writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			fmt.Sprintf("Grant type '%s' is not supported", grantType))
	}
}

// handleAuthorizationCodeGrant handles the authorization_code grant type.
func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse token request.
	tokenReq := tokenRequest{
		GrantType:    "authorization_code",
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     r.FormValue("client_id"),
		CodeVerifier: r.FormValue("code_verifier"),
		Resource:     r.FormValue("resource"),
	}

	// Validate request.
	if errs := s.validateAuthCodeTokenRequest(tokenReq); len(errs) > 0 {
		s.writeError(w, http.StatusBadRequest, "invalid_request", strings.Join(errs, "; "))

		return
	}

	// Get authorization code.
	authCode, err := s.store.GetAuthorizationCode(ctx, tokenReq.Code)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "Invalid authorization code")

		return
	}

	// Validate authorization code.
	if !authCode.IsValid() {
		_ = s.store.DeleteAuthorizationCode(ctx, tokenReq.Code)
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "Authorization code expired or already used")

		return
	}

	// Validate client_id.
	if authCode.ClientID != tokenReq.ClientID {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "Client ID mismatch")

		return
	}

	// Validate redirect_uri.
	if authCode.RedirectURI != tokenReq.RedirectURI {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "Redirect URI mismatch")

		return
	}

	// Validate resource (RFC 8707).
	if authCode.Resource != tokenReq.Resource {
		s.writeError(w, http.StatusBadRequest, "invalid_target", "Resource mismatch")

		return
	}

	// Verify PKCE.
	if !authCode.PKCE.Verify(tokenReq.CodeVerifier) {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "Invalid code_verifier (PKCE)")

		return
	}

	// Mark code as used.
	if err := s.store.MarkAuthorizationCodeUsed(ctx, tokenReq.Code); err != nil {
		s.log.WithError(err).Error("Failed to mark authorization code as used")
	}

	// Create tokens.
	tokenParams := token.CreateTokenParams{
		UserID:   authCode.UserID,
		ClientID: authCode.ClientID,
		Scope:    authCode.Scope,
		Resource: authCode.Resource,
	}

	accessToken, accessJTI, err := s.tokenService.CreateAccessToken(ctx, tokenParams)
	if err != nil {
		s.log.WithError(err).Error("Failed to create access token")
		s.writeError(w, http.StatusInternalServerError, "server_error", "Failed to create tokens")

		return
	}

	refreshToken, refreshJTI, err := s.tokenService.CreateRefreshToken(ctx, tokenParams)
	if err != nil {
		s.log.WithError(err).Error("Failed to create refresh token")
		s.writeError(w, http.StatusInternalServerError, "server_error", "Failed to create tokens")

		return
	}

	// Create session.
	sess := session.NewSession(
		authCode.UserID,
		accessJTI,
		refreshJTI,
		authCode.ClientID,
		authCode.Scope,
		authCode.Resource,
		sessionTTL,
	)

	if err := s.store.SaveSession(ctx, sess); err != nil {
		s.log.WithError(err).Error("Failed to save session")
		s.writeError(w, http.StatusInternalServerError, "server_error", "Failed to create session")

		return
	}

	s.log.WithFields(logrus.Fields{
		"user_id":   authCode.UserID,
		"client_id": authCode.ClientID,
		"scope":     authCode.Scope,
	}).Info("Tokens issued")

	s.writeTokenResponse(w, accessToken, refreshToken, authCode.Scope)
}

// handleRefreshTokenGrant handles the refresh_token grant type.
func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	refreshTokenStr := r.FormValue("refresh_token")
	if refreshTokenStr == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")

		return
	}

	// Validate refresh token.
	claims, err := s.tokenService.ValidateToken(ctx, refreshTokenStr, s.baseURL, token.TokenTypeRefresh)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "expired") {
			s.writeError(w, http.StatusBadRequest, "invalid_grant", "Refresh token has expired")

			return
		}

		s.writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())

		return
	}

	// Get session.
	sess, err := s.store.GetSessionByRefreshJTI(ctx, claims.ID)
	if err != nil || !sess.IsValid() {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "Invalid or revoked refresh token")

		return
	}

	// Get user.
	user, err := s.store.GetUser(ctx, sess.UserID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "User not found")

		return
	}

	// Re-validate org membership if configured.
	if len(s.allowedOrgs) > 0 {
		if !user.IsMemberOf(s.allowedOrgs) {
			// Revoke session.
			_ = s.store.RevokeSession(ctx, sess.ID)
			s.writeError(w, http.StatusBadRequest, "invalid_grant",
				"User is no longer a member of allowed organizations")

			return
		}
	}

	// Create new tokens (rotate refresh token).
	tokenParams := token.CreateTokenParams{
		UserID:   user.ID,
		ClientID: sess.ClientID,
		Scope:    sess.Scope,
		Resource: sess.Resource,
	}

	accessToken, accessJTI, err := s.tokenService.CreateAccessToken(ctx, tokenParams)
	if err != nil {
		s.log.WithError(err).Error("Failed to create access token")
		s.writeError(w, http.StatusInternalServerError, "server_error", "Failed to create tokens")

		return
	}

	refreshToken, refreshJTI, err := s.tokenService.CreateRefreshToken(ctx, tokenParams)
	if err != nil {
		s.log.WithError(err).Error("Failed to create refresh token")
		s.writeError(w, http.StatusInternalServerError, "server_error", "Failed to create tokens")

		return
	}

	// Update session with new token JTIs.
	if err := s.store.UpdateSessionTokens(ctx, sess.ID, accessJTI, refreshJTI); err != nil {
		s.log.WithError(err).Error("Failed to update session tokens")
	}

	s.log.WithFields(logrus.Fields{
		"user_id":   user.ID,
		"client_id": sess.ClientID,
	}).Info("Tokens refreshed")

	s.writeTokenResponse(w, accessToken, refreshToken, sess.Scope)
}

// handleRevoke handles the token revocation endpoint.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid form data")

		return
	}

	tokenStr := r.FormValue("token")
	if tokenStr == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "Token is required")

		return
	}

	// Try to decode the token to get its JTI.
	// We validate against both access and refresh token types.
	var sess *session.Session

	// Try as access token first.
	if claims, err := s.tokenService.ValidateToken(ctx, tokenStr, s.baseURL, token.TokenTypeAccess); err == nil {
		sess, _ = s.store.GetSessionByAccessJTI(ctx, claims.ID)
	} else if claims, err := s.tokenService.ValidateToken(ctx, tokenStr, s.baseURL, token.TokenTypeRefresh); err == nil {
		// Try as refresh token.
		sess, _ = s.store.GetSessionByRefreshJTI(ctx, claims.ID)
	}

	if sess != nil {
		if err := s.store.RevokeSession(ctx, sess.ID); err != nil {
			s.log.WithError(err).Warn("Failed to revoke session")
		} else {
			s.log.WithField("session_id", sess.ID).Info("Session revoked")
		}
	}

	// Per RFC 7009, always return 200 for revocation.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write([]byte("{}"))
}

// handleUserinfo handles the userinfo endpoint.
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get token from Authorization header.
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		s.writeUnauthorized(w, "Missing or invalid Authorization header")

		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate token.
	claims, err := s.tokenService.ValidateToken(ctx, tokenStr, s.baseURL, token.TokenTypeAccess)
	if err != nil {
		s.writeUnauthorized(w, err.Error())

		return
	}

	// Get user.
	user, err := s.store.GetUser(ctx, claims.Subject)
	if err != nil {
		s.writeUnauthorized(w, "User not found")

		return
	}

	// Return user info.
	userInfo := map[string]any{
		"sub":                user.ID,
		"name":               user.Name,
		"preferred_username": user.GitHubLogin,
		"email":              user.Email,
		"picture":            user.AvatarURL,
		"organizations":      user.Organizations,
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		s.log.WithError(err).Error("Failed to encode user info")
	}
}

// Helper functions.

type authorizationRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

func parseAuthorizationRequest(r *http.Request) authorizationRequest {
	return authorizationRequest{
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		ResponseType:        r.URL.Query().Get("response_type"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		Resource:            r.URL.Query().Get("resource"),
	}
}

func (s *Server) validateAuthorizationRequest(req authorizationRequest) []string {
	var errs []string

	if req.ResponseType != "code" {
		errs = append(errs, fmt.Sprintf("unsupported_response_type: %s", req.ResponseType))
	}

	if req.CodeChallengeMethod != "S256" {
		errs = append(errs, "invalid_request: code_challenge_method must be S256")
	}

	if req.CodeChallenge == "" {
		errs = append(errs, "invalid_request: code_challenge is required")
	}

	if req.Resource == "" {
		errs = append(errs, "invalid_request: resource parameter is required (RFC 8707)")
	}

	if req.RedirectURI == "" {
		errs = append(errs, "invalid_request: redirect_uri is required")
	}

	return errs
}

type tokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	Resource     string
}

func (s *Server) validateAuthCodeTokenRequest(req tokenRequest) []string {
	var errs []string

	if req.Code == "" {
		errs = append(errs, "code is required")
	}

	if req.RedirectURI == "" {
		errs = append(errs, "redirect_uri is required")
	}

	if req.ClientID == "" {
		errs = append(errs, "client_id is required")
	}

	if req.CodeVerifier == "" {
		errs = append(errs, "code_verifier is required (PKCE)")
	}

	if req.Resource == "" {
		errs = append(errs, "resource is required (RFC 8707)")
	}

	return errs
}

func (s *Server) generateState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (s *Server) getOrCreateUser(ctx context.Context, githubUser *github.GitHubUser) (*session.User, error) {
	user, err := s.store.GetUserByGitHubID(ctx, githubUser.ID)
	if err == nil {
		// Update user info.
		user.Name = githubUser.Name
		user.Email = githubUser.Email
		user.AvatarURL = githubUser.AvatarURL
		user.Organizations = githubUser.Organizations
		user.UpdatedAt = time.Now()

		if saveErr := s.store.SaveUser(ctx, user); saveErr != nil {
			return nil, fmt.Errorf("updating user: %w", saveErr)
		}

		return user, nil
	}

	// Create new user.
	now := time.Now()
	user = &session.User{
		ID:            uuid.New().String(),
		GitHubID:      githubUser.ID,
		GitHubLogin:   githubUser.Login,
		Name:          githubUser.Name,
		Email:         githubUser.Email,
		AvatarURL:     githubUser.AvatarURL,
		Organizations: githubUser.Organizations,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.store.SaveUser(ctx, user); err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	return user, nil
}

func (s *Server) createAuthorizationCode(
	ctx context.Context,
	pending *session.PendingAuthorization,
	userID string,
) (*session.AuthorizationCode, error) {
	// Generate secure code.
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return nil, fmt.Errorf("generating code: %w", err)
	}

	code := base64.RawURLEncoding.EncodeToString(codeBytes)

	authCode := session.NewAuthorizationCode(
		code,
		pending.ClientID,
		pending.RedirectURI,
		pending.Scope,
		pending.Resource,
		userID,
		session.PKCEChallenge{
			CodeChallenge:       pending.CodeChallenge,
			CodeChallengeMethod: pending.CodeChallengeMethod,
		},
		pending.State,
		authCodeTTL,
	)

	if err := s.store.SaveAuthorizationCode(ctx, authCode); err != nil {
		return nil, fmt.Errorf("saving authorization code: %w", err)
	}

	return authCode, nil
}

func (s *Server) writeError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := map[string]string{
		"error":             errCode,
		"error_description": description,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.WithError(err).Error("Failed to write error response")
	}
}

func (s *Server) writeHTMLError(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%s</title></head>
<body>
<h1>%s</h1>
<p>%s</p>
</body>
</html>`, title, title, message)

	_, _ = w.Write([]byte(html))
}

func (s *Server) writeUnauthorized(w http.ResponseWriter, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", FormatWWWAuthenticate(
		s.GetResourceMetadataURL(),
		"",
		"invalid_token",
		description,
	))
	w.WriteHeader(http.StatusUnauthorized)

	resp := map[string]string{
		"error":             "invalid_token",
		"error_description": description,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.WithError(err).Error("Failed to write error response")
	}
}

func (s *Server) writeTokenResponse(w http.ResponseWriter, accessToken, refreshToken, scope string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	resp := map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(s.tokenService.GetAccessTokenTTL().Seconds()),
		"refresh_token": refreshToken,
		"scope":         scope,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.WithError(err).Error("Failed to write token response")
	}
}
