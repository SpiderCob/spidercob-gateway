// Package idptrust validates external ID-JAGs (RFC 7523 JWT-bearer
// assertions, RFC 8693 token-exchange output) against a configured list of
// trusted external IdPs. It knows nothing about this gateway's own
// tokens, revocation, or user provisioning -- internal/authserver calls in
// here for "is this assertion genuinely from an IdP I trust," then does
// everything gateway-specific (one-time-use jti, JIT provisioning, minting
// the actual access token) itself.
//
// JWKS fetching/caching/rotation and RSA/EC key reconstruction from a
// remote, third-party-controlled endpoint is exactly the kind of
// security-sensitive plumbing this repo leans on a vetted library for
// rather than hand-rolling (same principle as using golang-jwt/jwt/v5 for
// token mechanics in internal/authserver, MASTER_PLAN.md §6, 2026-08-07) --
// github.com/MicahParks/keyfunc/v3 does the actual JWKS work here; this
// package is only the gateway-specific trust-list/audience logic wrapped
// around it.
package idptrust

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// clockSkewLeeway tolerates ordinary clock drift between the customer's
// IdP and this gateway when checking exp/iat/nbf. Deliberately looser than
// internal/authserver's own access-token validation (zero leeway there):
// this gateway controls its own clock and its own short TTLs, but an
// external IdP's clock is a different party's, entirely outside this
// gateway's control.
const clockSkewLeeway = 60 * time.Second

var (
	ErrUntrustedIssuer  = errors.New("idptrust: untrusted issuer")
	ErrWrongAudience    = errors.New("idptrust: assertion audience does not match this gateway")
	ErrInvalidAssertion = errors.New("idptrust: invalid assertion")
)

// TrustedIssuer is one externally-trusted IdP: where its JWKS lives, and
// what audience an ID-JAG it issues must be bound to (this gateway's own
// AS identity -- RFC 7523's resource-server-is-the-audience requirement,
// distinct from the per-node aud the resulting access token gets).
type TrustedIssuer struct {
	Issuer           string
	JWKSURL          string
	ExpectedAudience string
}

// Claims is an ID-JAG's payload shape: standard registered claims plus the
// RFC 8693 actor claim identifying which app/agent the human is acting
// through.
type Claims struct {
	Act string `json:"act,omitempty"`
	jwt.RegisteredClaims
}

// TrustStore holds every configured trusted issuer and the live,
// auto-refreshing JWKS keyfunc for each. Built once at startup from
// config (issue #5's bootstrap mechanism, same pattern as issue #3's
// SeedAgents) -- there's no admin API yet to change trust at runtime.
type TrustStore struct {
	mu       sync.RWMutex
	issuers  map[string]TrustedIssuer
	keyfuncs map[string]keyfunc.Keyfunc
}

// New builds a TrustStore, starting a background JWKS-refresh goroutine
// per configured issuer (via keyfunc.NewDefaultCtx) that runs until ctx is
// canceled.
func New(ctx context.Context, issuers []TrustedIssuer) (*TrustStore, error) {
	ts := &TrustStore{
		issuers:  make(map[string]TrustedIssuer, len(issuers)),
		keyfuncs: make(map[string]keyfunc.Keyfunc, len(issuers)),
	}
	for _, iss := range issuers {
		kf, err := keyfunc.NewDefaultCtx(ctx, []string{iss.JWKSURL})
		if err != nil {
			return nil, fmt.Errorf("idptrust: build JWKS keyfunc for issuer %q: %w", iss.Issuer, err)
		}
		ts.issuers[iss.Issuer] = iss
		ts.keyfuncs[iss.Issuer] = kf
	}
	return ts, nil
}

// HasAny reports whether at least one trusted issuer is configured --
// internal/authserver uses this to decide whether RFC 9728 metadata should
// advertise the id-jag grant profile at all.
func (ts *TrustStore) HasAny() bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.issuers) > 0
}

// Validate verifies assertion's signature against the actual JWKS of the
// issuer it claims to be from, that the claimed issuer is one this gateway
// trusts, and that its audience matches that issuer's configured expected
// audience. It deliberately does NOT check jti one-time-use -- that
// depends on the caller's own revocation/denylist state, which this
// package has no access to and shouldn't need to.
func (ts *TrustStore) Validate(assertion string) (*Claims, error) {
	// Peek at the unverified iss to know which issuer's JWKS to verify
	// against -- there's no single shared key space across every trusted
	// IdP the way there is for this gateway's own self-issued tokens, so
	// the signing key can't be selected before knowing who claims to have
	// signed it. The real, signature-verified parse happens below; nothing
	// from this first pass is trusted.
	var unverified Claims
	if _, _, err := jwt.NewParser().ParseUnverified(assertion, &unverified); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAssertion, err)
	}

	ts.mu.RLock()
	trusted, ok := ts.issuers[unverified.Issuer]
	kf, kfOK := ts.keyfuncs[unverified.Issuer]
	ts.mu.RUnlock()
	if !ok || !kfOK {
		return nil, fmt.Errorf("%w: %q", ErrUntrustedIssuer, unverified.Issuer)
	}

	claims := &Claims{}
	_, err := jwt.ParseWithClaims(assertion, claims, kf.Keyfunc, jwt.WithLeeway(clockSkewLeeway))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAssertion, err)
	}

	// Belt-and-suspenders: the verified claims should already agree with
	// the unverified peek (same token, same bytes) -- but re-check rather
	// than assume, since trust selection above was made on the unverified
	// value.
	if claims.Issuer != trusted.Issuer {
		return nil, fmt.Errorf("%w: %q", ErrUntrustedIssuer, claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != trusted.ExpectedAudience {
		return nil, fmt.Errorf("%w: got %v, want [%q]", ErrWrongAudience, claims.Audience, trusted.ExpectedAudience)
	}

	return claims, nil
}
