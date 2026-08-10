package idptrust

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

// fakeIdP is a real, minimal RS256-signing IdP for tests -- real external
// IdPs (Keycloak, Okta) default to RS256, unlike this gateway's own
// Ed25519 self-signed tokens, so this package's tests need real RSA keys
// and a real JWKS HTTP endpoint, not just golang-jwt in-process.
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
	doc := jwkset.JWKSMarshal{Keys: []jwkset.JWKMarshal{jwk.Marshal()}}
	body, err := json.Marshal(doc)
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

// mintIDJAG signs an ID-JAG-shaped assertion with this fake IdP's key.
// Every claim is a parameter (not hardcoded) so tests can construct
// deliberately-wrong ones without waiting on a real clock or a real IdP.
func (f *fakeIdP) mintIDJAG(t *testing.T, sub, aud string, exp, iat time.Time) string {
	t.Helper()
	return f.mintClaims(t, &Claims{
		Act: "agent-app",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(iat),
			ID:        "idjag-jti-1",
		},
	})
}

// mintClaims signs an arbitrary, caller-constructed Claims value --
// the lower-level primitive mintIDJAG builds on, exposed directly so
// tests can construct deliberately-incomplete assertions (e.g. a
// missing exp/jti/sub) that mintIDJAG's fixed shape can't express.
func (f *fakeIdP) mintClaims(t *testing.T, claims *Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = f.kid
	signed, err := token.SignedString(f.privateKey)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return signed
}

const gatewayAudience = "https://gw.test"

func newTestTrustStore(t *testing.T, issuers ...TrustedIssuer) *TrustStore {
	t.Helper()
	ts, err := New(context.Background(), issuers)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ts
}

func TestValidate_AcceptsGenuineAssertionFromTrustedIssuer(t *testing.T) {
	idp := newFakeIdP(t, "https://idp.example.com")
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})

	assertion := idp.mintIDJAG(t, "alice", gatewayAudience, time.Now().Add(time.Minute), time.Now())
	claims, err := ts.Validate(assertion)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "alice" {
		t.Fatalf("sub = %q, want alice", claims.Subject)
	}
	if claims.Act != "agent-app" {
		t.Fatalf("act = %q, want agent-app", claims.Act)
	}
}

func TestValidate_UntrustedIssuerRejected(t *testing.T) {
	idp := newFakeIdP(t, "https://idp.example.com")
	other := newFakeIdP(t, "https://not-trusted.example.com")
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})

	assertion := other.mintIDJAG(t, "alice", gatewayAudience, time.Now().Add(time.Minute), time.Now())
	if _, err := ts.Validate(assertion); err == nil {
		t.Fatalf("expected untrusted-issuer assertion to be rejected")
	}
}

func TestValidate_WrongAudienceRejected(t *testing.T) {
	idp := newFakeIdP(t, "https://idp.example.com")
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})

	assertion := idp.mintIDJAG(t, "alice", "https://some-other-resource.example.com", time.Now().Add(time.Minute), time.Now())
	if _, err := ts.Validate(assertion); err == nil {
		t.Fatalf("expected wrong-audience assertion to be rejected")
	}
}

func TestValidate_ExpiredAssertionRejected(t *testing.T) {
	idp := newFakeIdP(t, "https://idp.example.com")
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})

	// Beyond the clock-skew leeway, not just barely past exp.
	past := time.Now().Add(-5 * time.Minute)
	assertion := idp.mintIDJAG(t, "alice", gatewayAudience, past, past.Add(-time.Minute))
	if _, err := ts.Validate(assertion); err == nil {
		t.Fatalf("expected expired assertion to be rejected")
	}
}

func TestValidate_WithinClockSkewLeewayAccepted(t *testing.T) {
	idp := newFakeIdP(t, "https://idp.example.com")
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})

	// Expired 10s ago -- within the 60s leeway, so a clock a few seconds
	// out of sync between two independent parties doesn't cause spurious
	// rejections.
	justExpired := time.Now().Add(-10 * time.Second)
	assertion := idp.mintIDJAG(t, "alice", gatewayAudience, justExpired, justExpired.Add(-time.Minute))
	if _, err := ts.Validate(assertion); err != nil {
		t.Fatalf("expected assertion within clock-skew leeway to be accepted, got: %v", err)
	}
}

func TestValidate_TamperedSignatureRejected(t *testing.T) {
	idp := newFakeIdP(t, "https://idp.example.com")
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})

	assertion := idp.mintIDJAG(t, "alice", gatewayAudience, time.Now().Add(time.Minute), time.Now())
	tampered := assertion[:len(assertion)-2] + "xx"
	if _, err := ts.Validate(tampered); err == nil {
		t.Fatalf("expected tampered signature to be rejected")
	}
}

func TestValidate_WrongKeyRejected(t *testing.T) {
	// An assertion claiming to be from idp.issuer but actually signed by a
	// different keypair -- proves signature verification is real, not
	// just an issuer-string comparison.
	idp := newFakeIdP(t, "https://idp.example.com")
	impostor := newFakeIdP(t, "https://idp.example.com") // same claimed issuer, different key
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})

	assertion := impostor.mintIDJAG(t, "alice", gatewayAudience, time.Now().Add(time.Minute), time.Now())
	if _, err := ts.Validate(assertion); err == nil {
		t.Fatalf("expected assertion signed by an untrusted key to be rejected even with a matching iss string")
	}
}

func TestValidate_MalformedAssertionRejected(t *testing.T) {
	idp := newFakeIdP(t, "https://idp.example.com")
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})
	if _, err := ts.Validate("not-a-jwt-at-all"); err == nil {
		t.Fatalf("expected malformed assertion to be rejected")
	}
}

// TestValidate_MissingExpRejected guards against a real panic risk in
// internal/authserver.handleJWTBearer, which dereferences
// claims.ExpiresAt.Time unconditionally -- jwt.RegisteredClaims treats
// exp as optional, so a malicious or misconfigured IdP omitting it
// would otherwise reach that dereference as a nil pointer.
func TestValidate_MissingExpRejected(t *testing.T) {
	idp := newFakeIdP(t, "https://idp.example.com")
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})

	assertion := idp.mintClaims(t, &Claims{
		Act: "agent-app",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   idp.issuer,
			Subject:  "alice",
			Audience: jwt.ClaimStrings{gatewayAudience},
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ID:       "idjag-jti-missing-exp",
			// ExpiresAt deliberately omitted.
		},
	})
	if _, err := ts.Validate(assertion); err == nil {
		t.Fatal("expected an assertion with no exp claim to be rejected")
	}
}

func TestValidate_MissingJTIRejected(t *testing.T) {
	idp := newFakeIdP(t, "https://idp.example.com")
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})

	assertion := idp.mintClaims(t, &Claims{
		Act: "agent-app",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    idp.issuer,
			Subject:   "alice",
			Audience:  jwt.ClaimStrings{gatewayAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			// ID (jti) deliberately omitted.
		},
	})
	if _, err := ts.Validate(assertion); err == nil {
		t.Fatal("expected an assertion with no jti claim to be rejected")
	}
}

func TestValidate_MissingSubjectRejected(t *testing.T) {
	idp := newFakeIdP(t, "https://idp.example.com")
	ts := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})

	assertion := idp.mintClaims(t, &Claims{
		Act: "agent-app",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    idp.issuer,
			Audience:  jwt.ClaimStrings{gatewayAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "idjag-jti-missing-sub",
			// Subject deliberately omitted.
		},
	})
	if _, err := ts.Validate(assertion); err == nil {
		t.Fatal("expected an assertion with no sub claim to be rejected")
	}
}

func TestHasAny(t *testing.T) {
	empty := newTestTrustStore(t)
	if empty.HasAny() {
		t.Fatalf("HasAny() on an empty TrustStore should be false")
	}

	idp := newFakeIdP(t, "https://idp.example.com")
	nonEmpty := newTestTrustStore(t, TrustedIssuer{
		Issuer: idp.issuer, JWKSURL: idp.jwksURL(), ExpectedAudience: gatewayAudience,
	})
	if !nonEmpty.HasAny() {
		t.Fatalf("HasAny() with a configured issuer should be true")
	}
}

func TestValidate_MultipleTrustedIssuers(t *testing.T) {
	idpA := newFakeIdP(t, "https://idp-a.example.com")
	idpB := newFakeIdP(t, "https://idp-b.example.com")
	ts := newTestTrustStore(t,
		TrustedIssuer{Issuer: idpA.issuer, JWKSURL: idpA.jwksURL(), ExpectedAudience: gatewayAudience},
		TrustedIssuer{Issuer: idpB.issuer, JWKSURL: idpB.jwksURL(), ExpectedAudience: gatewayAudience},
	)

	for _, idp := range []*fakeIdP{idpA, idpB} {
		assertion := idp.mintIDJAG(t, "alice", gatewayAudience, time.Now().Add(time.Minute), time.Now())
		claims, err := ts.Validate(assertion)
		if err != nil {
			t.Fatalf("Validate for issuer %s: %v", idp.issuer, err)
		}
		if claims.Issuer != idp.issuer {
			t.Fatalf("iss = %q, want %q", claims.Issuer, idp.issuer)
		}
	}
}
