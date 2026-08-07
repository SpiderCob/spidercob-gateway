package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sumeetgp/spidercob-gateway/internal/authserver"
	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/policy"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// realAuthAdapter is the same shape as cmd/spidercob's authValidator --
// duplicated here rather than exported from main, since main.go is not
// importable and this is the one place proxy needs a real authserver.
type realAuthAdapter struct{ as *authserver.AuthServer }

func (a realAuthAdapter) ValidateAccessToken(node, token string) (AuthClaims, error) {
	c, err := a.as.ValidateAccessToken(node, token)
	if err != nil {
		return AuthClaims{}, err
	}
	return AuthClaims{Subject: c.Subject, Act: c.Act}, nil
}

// authTestEnv wires a real store + identity + authserver + Gateway
// together -- this is the "Primary seam, extended" from issue #3's Testing
// Decisions: Gateway.ServeHTTP with real bearer-token validation, tested
// end-to-end by minting a real token via the authserver seam and
// presenting it to the gateway.
type authTestEnv struct {
	gw    *Gateway
	as    *authserver.AuthServer
	svc   *identity.Service
	store store.Store
}

func newAuthTestEnv(t *testing.T, upstreamURL, nodeName string) *authTestEnv {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.NewService(s)

	cfg := &config.Config{
		Listen: ":0",
		Issuer: "https://gw.test",
		Nodes: []config.Node{
			{Name: nodeName, Transport: config.TransportStreamableHTTP, UpstreamURL: upstreamURL},
		},
	}

	as, err := authserver.New(context.Background(), authserver.Config{
		Issuer:   cfg.Issuer,
		Nodes:    []string{nodeName},
		Identity: svc,
		Store:    s,
	})
	if err != nil {
		t.Fatalf("authserver.New: %v", err)
	}

	gw, err := New(cfg, realAuthAdapter{as: as})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() {
		if err := gw.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	return &authTestEnv{gw: gw, as: as, svc: svc, store: s}
}

// mintToken drives the real HTTP /token endpoint (client_credentials, a
// freshly created NHI) to produce a node-scoped access token -- exercising
// the full real mint-then-present flow, not a shortcut through authserver
// internals.
func (e *authTestEnv) mintToken(t *testing.T, node string) string {
	t.Helper()
	agent, secret, err := e.svc.CreateAgent(context.Background(), "test-agent")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {agent.ClientID},
		"client_secret": {secret},
		"resource":      {node},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.as.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint token: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	return resp.AccessToken
}

func TestGateway_MissingBearerTokenRejectedWithWWWAuthenticate(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	env := newAuthTestEnv(t, upstream.URL, "jira")

	req := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	rec := httptest.NewRecorder()
	env.gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
	wa := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wa, "/.well-known/oauth-protected-resource/jira") {
		t.Fatalf("WWW-Authenticate = %q, want it to point at jira's RFC 9728 metadata URL", wa)
	}
}

func TestGateway_InvalidBearerTokenRejected(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	env := newAuthTestEnv(t, upstream.URL, "jira")

	req := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()
	env.gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_WrongAudienceTokenRejected(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	env := newAuthTestEnv(t, upstream.URL, "jira")

	// Mint a token scoped to a *different* AuthServer/node entirely, so
	// even its signature won't match -- the strongest version of "this
	// token was never meant for this node."
	other := newAuthTestEnv(t, upstream.URL, "other-node")
	token := other.mintToken(t, "other-node")

	req := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	env.gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (wrong audience/unknown key), body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_RevokedTokenRejected(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	env := newAuthTestEnv(t, upstream.URL, "jira")

	token := env.mintToken(t, "jira")
	claims, err := env.as.ValidateAccessToken("jira", token)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if err := env.as.RevokeJTI(context.Background(), claims.ID, claims.ExpiresAt.Time); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	env.gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (revoked), body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_ValidTokenRoutesThroughSessionMachinery(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	env := newAuthTestEnv(t, upstream.URL, "jira")
	env.gw.policy = policy.AllowAll{} // isolate this test to auth+routing, not Phase 3's not-yet-built policy evaluator

	token := env.mintToken(t, "jira")

	req := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	env.gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Mcp-Session-Id") == "" {
		t.Fatalf("expected a minted Mcp-Session-Id, same as an unauthenticated Phase-1 initialize would get")
	}
}

func TestGateway_DefaultPolicyIsDenyAll(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	env := newAuthTestEnv(t, upstream.URL, "jira")
	// No policy override here -- proving New's real, unmodified default.

	token := env.mintToken(t, "jira")

	req := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	env.gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (DenyAll is the phase-2 default), body = %s", rec.Code, rec.Body.String())
	}
}
