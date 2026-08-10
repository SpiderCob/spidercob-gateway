package authserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

type testEnv struct {
	as    *AuthServer
	store store.Store
	svc   *identity.Service
}

func newTestEnv(t *testing.T, ttlOverrides Config) *testEnv {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.NewService(s)

	cfg := ttlOverrides
	cfg.Issuer = "https://gw.test"
	cfg.Nodes = []string{"jira"}
	cfg.Identity = svc
	cfg.Store = s

	as, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &testEnv{as: as, store: s, svc: svc}
}

func tokenRequest(t *testing.T, as *AuthServer, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	as.Routes().ServeHTTP(rec, req)
	return rec
}

func TestJWKS_PublishesActiveKey(t *testing.T) {
	env := newTestEnv(t, Config{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	env.as.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var doc jwksDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(doc.Keys))
	}
	if doc.Keys[0].Kty != "OKP" || doc.Keys[0].Crv != "Ed25519" || doc.Keys[0].Alg != "EdDSA" {
		t.Fatalf("unexpected key shape: %+v", doc.Keys[0])
	}
}

func TestJWKS_MultipleKeysAfterRotate(t *testing.T) {
	env := newTestEnv(t, Config{})
	if _, err := env.as.keys.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	env.as.Routes().ServeHTTP(rec, req)

	var doc jwksDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Keys) != 2 {
		t.Fatalf("expected 2 keys after rotation (old key still published), got %d", len(doc.Keys))
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	env := newTestEnv(t, Config{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/jira", nil)
	rec := httptest.NewRecorder()
	env.as.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var meta map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if meta["resource"] != "https://gw.test/mcp/jira" {
		t.Fatalf("resource = %v, want https://gw.test/mcp/jira", meta["resource"])
	}
	servers, _ := meta["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != "https://gw.test" {
		t.Fatalf("authorization_servers = %v", meta["authorization_servers"])
	}
	if _, ok := meta["authorization_grant_profiles_supported"]; !ok {
		t.Fatalf("expected authorization_grant_profiles_supported field to exist")
	}
}

func TestProtectedResourceMetadata_UnknownNode404s(t *testing.T) {
	env := newTestEnv(t, Config{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/nope", nil)
	rec := httptest.NewRecorder()
	env.as.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestToken_ClientCredentials_MintsScopedToken(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	form := url.Values{
		"grant_type":    {grantClientCredentials},
		"client_id":     {agent.ClientID},
		"client_secret": {secret},
		"resource":      {"jira"},
	}
	rec := tokenRequest(t, env.as, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TokenType != "Bearer" || resp.AccessToken == "" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.ExpiresIn <= 0 || resp.ExpiresIn > int(DefaultNHITokenTTL.Seconds()) {
		t.Fatalf("expires_in = %d, want within (0, %d]", resp.ExpiresIn, int(DefaultNHITokenTTL.Seconds()))
	}

	claims, err := env.as.ValidateAccessToken("jira", resp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.Subject != "agent:"+agent.ClientID {
		t.Fatalf("sub = %q, want agent:%s", claims.Subject, agent.ClientID)
	}
}

func TestToken_ClientCredentials_WrongSecretRejected(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, _, err := env.svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	form := url.Values{
		"grant_type":    {grantClientCredentials},
		"client_id":     {agent.ClientID},
		"client_secret": {"wrong"},
		"resource":      {"jira"},
	}
	rec := tokenRequest(t, env.as, form)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestToken_ClientCredentials_ReExchangeWithSameSecretJustWorks(t *testing.T) {
	// Story 16: no refresh grant -- an NHI just re-calls /token with the
	// same client_credentials.
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	form := url.Values{
		"grant_type":    {grantClientCredentials},
		"client_id":     {agent.ClientID},
		"client_secret": {secret},
		"resource":      {"jira"},
	}
	rec1 := tokenRequest(t, env.as, form)
	rec2 := tokenRequest(t, env.as, form)
	if rec1.Code != http.StatusOK || rec2.Code != http.StatusOK {
		t.Fatalf("both re-exchanges should succeed: %d, %d", rec1.Code, rec2.Code)
	}
}

func TestToken_LoginThenSessionReExchange(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	if _, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	loginForm := url.Values{
		"grant_type": {grantLogin},
		"username":   {"alice"},
		"password":   {"s3cret-pw"},
		"resource":   {"jira"},
	}
	loginRec := tokenRequest(t, env.as, loginForm)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp struct {
		AccessToken  string `json:"access_token"`
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if loginResp.SessionToken == "" {
		t.Fatalf("expected a session_token in the login response")
	}
	// Mirrored cookie, same pattern as the proxy's Mcp-Session-Id (story:
	// browser clients shouldn't need to hand-manage the session token).
	var cookieFound bool
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value == loginResp.SessionToken {
			cookieFound = true
		}
	}
	if !cookieFound {
		t.Fatalf("expected a mirrored %s cookie", sessionCookieName)
	}

	// The mirrored cookie's own lifetime should match the session token's
	// real validity (a.sessionTTL) -- without an explicit MaxAge, this
	// was a session-only cookie the browser drops on close, unexpectedly
	// shortening how long a human can silently re-mint tokens versus what
	// the actual signed session_token allows for (flagged by Copilot's
	// review on PR #4).
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == sessionCookieName {
			if c.MaxAge <= 0 {
				t.Fatalf("session cookie MaxAge = %d, want a positive value matching the session TTL", c.MaxAge)
			}
		}
	}

	claims, err := env.as.ValidateAccessToken("jira", loginResp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken (login): %v", err)
	}
	if claims.Subject != "user:alice" {
		t.Fatalf("sub = %q, want user:alice", claims.Subject)
	}

	// Story 17: re-presenting the still-valid session mints a fresh access
	// token silently -- no password required this time.
	sessionForm := url.Values{
		"grant_type":    {grantSession},
		"session_token": {loginResp.SessionToken},
		"resource":      {"jira"},
	}
	sessionRec := tokenRequest(t, env.as, sessionForm)
	if sessionRec.Code != http.StatusOK {
		t.Fatalf("session re-exchange status = %d, body = %s", sessionRec.Code, sessionRec.Body.String())
	}
	var sessionResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(sessionRec.Body.Bytes(), &sessionResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, err := env.as.ValidateAccessToken("jira", sessionResp.AccessToken); err != nil {
		t.Fatalf("ValidateAccessToken (re-exchanged): %v", err)
	}
}

// TestToken_LoginSessionCookieSecureOverTLS guards both directions of
// the Secure attribute (flagged by Copilot's review on PR #4): set when
// the request actually arrived over TLS, so the cookie can never leak
// over a subsequent cleartext connection, but NOT unconditionally set,
// since that would silently break local/dev deployments that don't
// terminate TLS themselves.
func TestToken_LoginSessionCookieSecureOverTLS(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	if _, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	form := url.Values{
		"grant_type": {grantLogin},
		"username":   {"alice"},
		"password":   {"s3cret-pw"},
		"resource":   {"jira"},
	}

	plainReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	plainReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	plainRec := httptest.NewRecorder()
	env.as.Routes().ServeHTTP(plainRec, plainReq)
	for _, c := range plainRec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Secure {
			t.Fatal("session cookie is Secure over a plain HTTP request -- would break local/dev deployments with no TLS termination")
		}
	}

	tlsReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tlsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tlsReq.TLS = &tls.ConnectionState{}
	tlsRec := httptest.NewRecorder()
	env.as.Routes().ServeHTTP(tlsRec, tlsReq)
	var sawSecure bool
	for _, c := range tlsRec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Secure {
			sawSecure = true
		}
	}
	if !sawSecure {
		t.Fatal("expected the session cookie to be Secure when the request arrived over TLS")
	}
}

func TestToken_LoginWrongPasswordRejected(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	if _, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	form := url.Values{
		"grant_type": {grantLogin},
		"username":   {"alice"},
		"password":   {"wrong"},
		"resource":   {"jira"},
	}
	rec := tokenRequest(t, env.as, form)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestToken_SessionTokenCannotBeUsedAsAccessToken(t *testing.T) {
	// A session token is a different typ -- it must not validate as a
	// bearer access token even though both are signed by the same key.
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	if _, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	loginRec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantLogin}, "username": {"alice"}, "password": {"s3cret-pw"}, "resource": {"jira"},
	})
	var loginResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)

	if _, err := env.as.ValidateAccessToken("jira", loginResp.SessionToken); err == nil {
		t.Fatalf("expected session token to be rejected as an access token")
	}
}

func TestToken_UnknownResourceRejected(t *testing.T) {
	env := newTestEnv(t, Config{})
	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantClientCredentials}, "resource": {"not-a-node"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestToken_UnsupportedGrantTypeRejected(t *testing.T) {
	env := newTestEnv(t, Config{})
	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {"password"}, "resource": {"jira"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestValidateAccessToken_WrongAudienceRejected(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {"jira"},
	})
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	// The token was minted for "jira"; validating it against some other
	// node must fail even though the signature and everything else is
	// genuinely valid -- this is the confused-deputy protection
	// (MASTER_PLAN.md §0: never a multi-audience token).
	if _, err := env.as.ValidateAccessToken("other-node", resp.AccessToken); err == nil {
		t.Fatalf("expected wrong-audience validation to fail")
	}
}

func TestValidateAccessToken_ExpiredRejected(t *testing.T) {
	// Secondary seam (issue #3 Testing Decisions): construct a
	// deliberately-expired token directly (bypassing /token's TTL
	// defaulting, which treats a non-positive Config TTL as "unset") so
	// this doesn't need to wait out a real TTL.
	env := newTestEnv(t, Config{})
	signed, _, err := env.as.mintAccessToken("agent:ci-bot", "", "jira", -time.Second)
	if err != nil {
		t.Fatalf("mintAccessToken: %v", err)
	}
	if _, err := env.as.ValidateAccessToken("jira", signed); err == nil {
		t.Fatalf("expected expired token to be rejected")
	}
}

func TestValidateAccessToken_TamperedSignatureRejected(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {"jira"},
	})
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	tampered := resp.AccessToken[:len(resp.AccessToken)-2] + "xx"
	if _, err := env.as.ValidateAccessToken("jira", tampered); err == nil {
		t.Fatalf("expected tampered signature to be rejected")
	}
}

func TestValidateAccessToken_WrongIssuerRejected(t *testing.T) {
	env := newTestEnv(t, Config{})
	other := newTestEnv(t, Config{})

	ctx := context.Background()
	agent, secret, err := other.svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec := tokenRequest(t, other.as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {"jira"},
	})
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	// Two different AuthServer instances have different signing keys, so
	// this is really exercising "unknown kid" -- but if it were ever the
	// exact same key by coincidence, the issuer check must still catch a
	// cross-issuer token.
	if _, err := env.as.ValidateAccessToken("jira", resp.AccessToken); err == nil {
		t.Fatalf("expected cross-issuer token to be rejected")
	}
}

func TestRevokeJTI_RejectsOnEverySubsequentRequest(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {"jira"},
	})
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	claims, err := env.as.ValidateAccessToken("jira", resp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken before revoke: %v", err)
	}

	if err := env.as.RevokeJTI(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	if _, err := env.as.ValidateAccessToken("jira", resp.AccessToken); err == nil {
		t.Fatalf("expected revoked token to be rejected")
	}
	// And again -- must stay rejected, not just once.
	if _, err := env.as.ValidateAccessToken("jira", resp.AccessToken); err == nil {
		t.Fatalf("expected revoked token to stay rejected on a second request")
	}
}

func TestRevocationSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	svc := identity.NewService(s)
	ctx := context.Background()
	agent, secret, err := svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	as1, err := New(ctx, Config{Issuer: "https://gw.test", Nodes: []string{"jira"}, Identity: svc, Store: s})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := tokenRequest(t, as1, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {"jira"},
	})
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	claims, err := as1.ValidateAccessToken("jira", resp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if err := as1.RevokeJTI(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	revoked, err := s.IsRevoked(ctx, claims.ID)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatalf("expected revocation to be persisted to the store")
	}
}

func TestValidateAccessToken_MissingTokenRejected(t *testing.T) {
	env := newTestEnv(t, Config{})
	if _, err := env.as.ValidateAccessToken("jira", ""); err == nil {
		t.Fatalf("expected empty token to be rejected")
	}
}
