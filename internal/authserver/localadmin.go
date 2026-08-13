package authserver

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrLocalAdminDisabled is returned by LoginLocalAdmin/
// ValidateLocalAdminSession when this admin-auth mode isn't configured at
// all (Config.LocalAdminGroup is empty) -- distinct from
// ErrInvalidLocalAdminCredentials so a caller can tell "this deployment
// doesn't support local admin login" apart from "these particular
// credentials/session don't grant it."
var ErrLocalAdminDisabled = errors.New("authserver: local admin login is not configured")

// ErrInvalidLocalAdminCredentials covers an unknown username, a wrong
// password, and a real user who simply isn't in the configured admin
// group, all alike -- deliberately not distinguished, the same
// non-enumeration posture identity.Service.Authenticate already
// establishes for every other credential check in this codebase.
var ErrInvalidLocalAdminCredentials = errors.New("authserver: invalid local admin credentials")

// LoginLocalAdmin is the standalone (no spider-snoop) counterpart to the
// browser admin UI's spider-snoop-token-based login (issue #43): verifies
// a local (Mode A) human's username/password via the same
// identity.Service.Authenticate every other local login already uses,
// then checks their live group membership against Config.LocalAdminGroup
// -- not a role baked into any prior credential, a real store query
// every time. Returns a signed, distinctly-typed local admin session
// token on success.
func (a *AuthServer) LoginLocalAdmin(ctx context.Context, username, password string) (string, error) {
	if a.localAdminGroup == "" {
		return "", ErrLocalAdminDisabled
	}
	user, err := a.identity.Authenticate(ctx, username, password)
	if err != nil {
		return "", ErrInvalidLocalAdminCredentials
	}
	groups, err := a.identity.UserGroupNames(ctx, user.Username)
	if err != nil {
		return "", err
	}
	if !slices.Contains(groups, a.localAdminGroup) {
		return "", ErrInvalidLocalAdminCredentials
	}
	return a.mintLocalAdminSessionToken(user.Username)
}

// ValidateLocalAdminSession verifies token's signature, expiry, and type,
// then re-resolves the user and re-checks their live group membership
// fresh from the store -- group membership isn't even encoded in the
// token, so there's nothing to "trust" from a prior check. A user
// deleted, or removed from the admin group, after the token was minted
// loses access on their very next request, not just their next login.
func (a *AuthServer) ValidateLocalAdminSession(ctx context.Context, token string) (username string, err error) {
	if a.localAdminGroup == "" {
		return "", ErrLocalAdminDisabled
	}
	claims, err := parseAndVerify(a.keys, token, typLocalAdminSession)
	if err != nil {
		return "", err
	}
	if claims.Issuer != a.issuer {
		return "", ErrTokenWrongIssuer
	}
	user, err := a.identity.GetUser(ctx, claims.Subject)
	if err != nil {
		return "", ErrInvalidLocalAdminCredentials
	}
	groups, err := a.identity.UserGroupNames(ctx, user.Username)
	if err != nil {
		return "", err
	}
	if !slices.Contains(groups, a.localAdminGroup) {
		return "", ErrInvalidLocalAdminCredentials
	}
	return user.Username, nil
}

func (a *AuthServer) mintLocalAdminSessionToken(username string) (string, error) {
	jti, err := randomID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.issuer,
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(now.Add(a.sessionTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	return a.keys.sign(claims, typLocalAdminSession)
}
