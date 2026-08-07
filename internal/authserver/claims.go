package authserver

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// JWT header "typ" values. Access tokens and local-session tokens are both
// signed by the same KeySet, so the header typ is what stops one from
// being accepted where the other is expected -- a session token replayed
// as a bearer access token, or vice versa, fails typ verification before
// claims are even inspected.
const (
	typAccess  = "at+jwt"      // node-scoped access token (RFC 9068-style typ)
	typSession = "session+jwt" // Mode A human's re-exchangeable local session
)

// Claims is this gateway's access-token payload. act is shaped to match
// RFC 8693's actor claim now (issue #3's Implementation Decisions) even
// though nothing populates it yet -- no flow built in this phase has a
// human delegating to an agent; that's Phase 2b's external-IdP delegation
// story. aud is always exactly one entry (never a multi-audience token,
// MASTER_PLAN.md §0) -- enforced at mint time here and re-checked at
// verify time in ValidateAccessToken, not assumed from either side alone.
type Claims struct {
	Act   string `json:"act,omitempty"`
	Scope string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

var (
	ErrTokenExpired          = errors.New("authserver: token expired")
	ErrTokenInvalidSignature = errors.New("authserver: invalid token signature")
	ErrTokenMalformed        = errors.New("authserver: malformed token")
	ErrTokenWrongType        = errors.New("authserver: wrong token type for this endpoint")
	ErrTokenWrongIssuer      = errors.New("authserver: wrong issuer")
	ErrTokenWrongAudience    = errors.New("authserver: wrong audience")
	ErrTokenRevoked          = errors.New("authserver: token revoked")
)

// parseAndVerify parses tokenString, checks its signature against ks, and
// requires its header "typ" to equal wantTyp. It deliberately does not
// check aud/revocation -- those depend on which node is being called and
// on the caller's denylist, both request-specific, so they're checked by
// callers (ValidateAccessToken, the session-grant handler) after this
// returns.
func parseAndVerify(ks *KeySet, tokenString, wantTyp string) (*Claims, error) {
	var gotTyp string
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		kp, ok := ks.keyByKID(kid)
		if !ok {
			return nil, fmt.Errorf("unknown signing key %q", kid)
		}
		gotTyp, _ = t.Header["typ"].(string)
		return kp.pub, nil
	})

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, ErrTokenInvalidSignature
		default:
			return nil, fmt.Errorf("%w: %v", ErrTokenMalformed, err)
		}
	}
	if !tok.Valid {
		return nil, ErrTokenMalformed
	}
	if gotTyp != wantTyp {
		return nil, ErrTokenWrongType
	}
	return claims, nil
}
