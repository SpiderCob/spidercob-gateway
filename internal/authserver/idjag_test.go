package authserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"

	"github.com/sumeetgp/spidercob-gateway/internal/idptrust"
)

// fakeIdP is a real, minimal RS256-signing external IdP for these tests --
// real IdPs (Keycloak, Okta) sign with RS256, unlike this gateway's own
// Ed25519 self-issued tokens.
type fakeIdP struct {
	issuer     string
	privateKey *rsa.PrivateKey
	kid        string
	server     *httptest.Server
}

func newFakeIdP(t *testing.T, issuer string) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "test-key-1"
	jwk, err := jwkset.NewJWKFromKey(priv.Public(), jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: kid, ALG: jwkset.AlgRS256, USE: jwkset.UseSig},
	})
	if err != nil {
		t.Fatalf("NewJWKFromKey: %v", err)
	}
	body, err := json.Marshal(jwkset.JWKSMarshal{Keys: []jwkset.JWKMarshal{jwk.Marshal()}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return &fakeIdP{issuer: issuer, privateKey: priv, kid: kid, server: server}
}

func (f *fakeIdP) jwksURL() string { return f.server.URL }

func (f *fakeIdP) mintIDJAG(t *testing.T, sub, act, aud, jti string, exp, iat time.Time) string {
	t.Helper()
	claims := &idptrust.Claims{
		Act: act,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(iat),
			ID:        jti,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = f.kid
	signed, err := token.SignedString(f.privateKey)
	if err != nil {
		t.Fatalf("sign ID-JAG: %v", err)
	}
	return signed
}

// newTestEnvWithTrustedIdP builds a testEnv whose AuthServer has one
// trusted external IdP configured (Mode B enabled), plus the fake IdP
// itself for minting assertions against.
func newTestEnvWithTrustedIdP(t *testing.T) (*testEnv, *fakeIdP) {
	t.Helper()
	idp := newFakeIdP(t, "https://idp.example.com")
	ts, err := idptrust.New(context.Background(), []idptrust.TrustedIssuer{
		{Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: "https://gw.test"},
	})
	if err != nil {
		t.Fatalf("idptrust.New: %v", err)
	}
	env := newTestEnv(t, Config{IdPTrust: ts})
	return env, idp
}

func TestToken_JWTBearer_MintsScopedTokenForNewUser(t *testing.T) {
	env, idp := newTestEnvWithTrustedIdP(t)
	assertion := idp.mintIDJAG(t, "alice-sub", "agent-app", "https://gw.test", "idjag-1", time.Now().Add(time.Minute), time.Now())

	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantJWTBearer}, "assertion": {assertion}, "resource": {"jira"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	claims, err := env.as.ValidateAccessToken("jira", resp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if !strings.HasPrefix(claims.Subject, "user:") {
		t.Fatalf("sub = %q, want user: prefix", claims.Subject)
	}
	if claims.Act != "agent-app" {
		t.Fatalf("act = %q, want agent-app (preserved from the ID-JAG's actor chain)", claims.Act)
	}
}

func TestToken_JWTBearer_SecondLoginResolvesSameUser(t *testing.T) {
	env, idp := newTestEnvWithTrustedIdP(t)

	a1 := idp.mintIDJAG(t, "alice-sub", "agent-app", "https://gw.test", "idjag-1", time.Now().Add(time.Minute), time.Now())
	rec1 := tokenRequest(t, env.as, url.Values{"grant_type": {grantJWTBearer}, "assertion": {a1}, "resource": {"jira"}})
	var resp1 struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec1.Body.Bytes(), &resp1)
	claims1, err := env.as.ValidateAccessToken("jira", resp1.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken (1): %v", err)
	}

	a2 := idp.mintIDJAG(t, "alice-sub", "agent-app", "https://gw.test", "idjag-2", time.Now().Add(time.Minute), time.Now())
	rec2 := tokenRequest(t, env.as, url.Values{"grant_type": {grantJWTBearer}, "assertion": {a2}, "resource": {"jira"}})
	var resp2 struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
	claims2, err := env.as.ValidateAccessToken("jira", resp2.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken (2): %v", err)
	}

	if claims1.Subject != claims2.Subject {
		t.Fatalf("two logins for the same external identity resolved different users: %q vs %q", claims1.Subject, claims2.Subject)
	}
}

func TestToken_JWTBearer_ReplayedAssertionRejected(t *testing.T) {
	env, idp := newTestEnvWithTrustedIdP(t)
	assertion := idp.mintIDJAG(t, "alice-sub", "agent-app", "https://gw.test", "idjag-replay", time.Now().Add(time.Minute), time.Now())

	form := url.Values{"grant_type": {grantJWTBearer}, "assertion": {assertion}, "resource": {"jira"}}
	first := tokenRequest(t, env.as, form)
	if first.Code != http.StatusOK {
		t.Fatalf("first redemption: status = %d, body = %s", first.Code, first.Body.String())
	}
	second := tokenRequest(t, env.as, form)
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("replayed assertion: status = %d, want 401, body = %s", second.Code, second.Body.String())
	}
}

func TestToken_JWTBearer_UntrustedIssuerRejected(t *testing.T) {
	env, _ := newTestEnvWithTrustedIdP(t)
	stranger := newFakeIdP(t, "https://not-trusted.example.com")
	assertion := stranger.mintIDJAG(t, "alice-sub", "agent-app", "https://gw.test", "idjag-1", time.Now().Add(time.Minute), time.Now())

	rec := tokenRequest(t, env.as, url.Values{"grant_type": {grantJWTBearer}, "assertion": {assertion}, "resource": {"jira"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestToken_JWTBearer_WrongAudienceRejected(t *testing.T) {
	env, idp := newTestEnvWithTrustedIdP(t)
	// aud must be this gateway's own AS identity, not a node.
	assertion := idp.mintIDJAG(t, "alice-sub", "agent-app", "https://some-other-gateway.example.com", "idjag-1", time.Now().Add(time.Minute), time.Now())

	rec := tokenRequest(t, env.as, url.Values{"grant_type": {grantJWTBearer}, "assertion": {assertion}, "resource": {"jira"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestToken_JWTBearer_NoTrustedIdPConfiguredRejected(t *testing.T) {
	// Default testEnv (no IdPTrust) -- Mode B entirely absent.
	env := newTestEnv(t, Config{})
	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantJWTBearer}, "assertion": {"whatever"}, "resource": {"jira"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestToken_JWTBearer_MissingAssertionRejected(t *testing.T) {
	env, _ := newTestEnvWithTrustedIdP(t)
	rec := tokenRequest(t, env.as, url.Values{"grant_type": {grantJWTBearer}, "resource": {"jira"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestProtectedResourceMetadata_AdvertisesIDJAGProfileOnlyWhenTrustConfigured(t *testing.T) {
	withoutTrust := newTestEnv(t, Config{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/jira", nil)
	rec := httptest.NewRecorder()
	withoutTrust.as.Routes().ServeHTTP(rec, req)
	var meta struct {
		AuthorizationGrantProfilesSupported []string `json:"authorization_grant_profiles_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(meta.AuthorizationGrantProfilesSupported) != 0 {
		t.Fatalf("expected no grant profiles advertised without a trusted IdP, got %v", meta.AuthorizationGrantProfilesSupported)
	}

	withTrust, _ := newTestEnvWithTrustedIdP(t)
	req2 := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/jira", nil)
	rec2 := httptest.NewRecorder()
	withTrust.as.Routes().ServeHTTP(rec2, req2)
	var meta2 struct {
		AuthorizationGrantProfilesSupported []string `json:"authorization_grant_profiles_supported"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &meta2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, p := range meta2.AuthorizationGrantProfilesSupported {
		if p == idJAGGrantProfile {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %q in authorization_grant_profiles_supported, got %v", idJAGGrantProfile, meta2.AuthorizationGrantProfilesSupported)
	}
}
