package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// ErrInvalidCredentials covers both "no such user/agent" and "wrong
// password/secret" -- deliberately not distinguished in the returned error,
// so a caller can't use error type alone to enumerate valid usernames or
// client IDs.
var ErrInvalidCredentials = errors.New("identity: invalid credentials")

// Service is the identity seam authserver calls into: "create this
// principal," "verify these credentials." It owns hashing; store.Store
// only ever sees opaque hash strings.
type Service struct {
	store store.Store
}

func NewService(s store.Store) *Service {
	return &Service{store: s}
}

// CreateUser registers a local (Mode A) human account with an argon2id
// password hash.
func (svc *Service) CreateUser(ctx context.Context, username, password string) (store.User, error) {
	hash, err := hashSecret(password)
	if err != nil {
		return store.User{}, err
	}
	return svc.store.CreateUser(ctx, username, hash)
}

// Authenticate verifies a human's local login. Returns ErrInvalidCredentials
// for both an unknown username and a wrong password.
func (svc *Service) Authenticate(ctx context.Context, username, password string) (store.User, error) {
	u, err := svc.store.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, ErrInvalidCredentials
	}
	if err != nil {
		return store.User{}, err
	}
	ok, err := verifySecret(password, u.PasswordHash)
	if err != nil {
		// A malformed hash (notably unusablePasswordHash, story 23 --
		// JIT-provisioned Mode B accounts can never have a real one) means
		// "can't authenticate," same as a wrong password -- never leak the
		// distinction between "bad password" and "this account has no
		// usable password at all."
		return store.User{}, ErrInvalidCredentials
	}
	if !ok {
		return store.User{}, ErrInvalidCredentials
	}
	return u, nil
}

// unusablePasswordHash is stored for JIT-provisioned (Mode B) users
// instead of a real argon2id hash (issue #5, story 23). It deliberately
// isn't in PHC format, so verifySecret always fails to parse it and
// Authenticate always returns ErrInvalidCredentials -- an externally-
// governed identity can never gain a second, gateway-local password
// nobody assigned it.
const unusablePasswordHash = "!external-identity-no-local-password"

// ResolveOrCreateExternalUser is the JIT-provisioning seam for Mode B
// (issue #5): given a validated external IdP's (issuer, subject), it
// resolves the existing local user from a prior login, or creates a new
// one -- zero group memberships by default, same default-deny guarantee
// as any other new account (story 11). The username assigned to a newly
// created account is internal bookkeeping only, never used for lookup --
// every subsequent resolution goes through (issuer, subject), never
// through it. The resolve-or-create itself is delegated to the store as
// one atomic operation (not composed from separate lookup/insert calls
// here) so two concurrent first-logins for the same (issuer, subject)
// can't race into two different user rows.
func (svc *Service) ResolveOrCreateExternalUser(ctx context.Context, issuer, subject string) (store.User, error) {
	username, err := randomToken("ext_", 16)
	if err != nil {
		return store.User{}, err
	}
	u, _, err := svc.store.ResolveOrCreateExternalUser(ctx, issuer, subject, username, unusablePasswordHash)
	return u, err
}

// CreateAgent registers an NHI with a freshly generated client_id and
// client secret. The plaintext secret is returned exactly once -- only its
// argon2id hash is ever persisted, so it cannot be recovered later, only
// rotated (create a new agent).
func (svc *Service) CreateAgent(ctx context.Context, name string) (agent store.Agent, plaintextSecret string, err error) {
	clientID, err := randomToken("agt_", 16)
	if err != nil {
		return store.Agent{}, "", err
	}
	secret, err := randomToken("", 32)
	if err != nil {
		return store.Agent{}, "", err
	}
	hash, err := hashSecret(secret)
	if err != nil {
		return store.Agent{}, "", err
	}
	agent, err = svc.store.CreateAgent(ctx, clientID, hash, name)
	if err != nil {
		return store.Agent{}, "", err
	}
	return agent, secret, nil
}

// GetUser looks up a user by username with no credential check -- used by
// the authserver's local-session re-exchange grant (issue #3, story 17),
// where the caller has already proven identity via a still-valid signed
// session token and just needs to confirm the account still exists before
// minting a fresh access token.
func (svc *Service) GetUser(ctx context.Context, username string) (store.User, error) {
	return svc.store.GetUserByUsername(ctx, username)
}

// CreateAgentWithCredentials registers an NHI with a caller-supplied
// client_id and secret, instead of generating them. Only for bootstrapping
// known credentials before an admin API exists (Phase 4) -- e.g. config-
// seeded agents (config.Config.SeedAgents) so automation/run-e2e-auth.sh
// can mint real tokens against the compiled binary via curl. Prefer
// CreateAgent for anything reachable by a real operator once the admin API
// lands; a caller-chosen secret is inherently weaker than a generated one.
func (svc *Service) CreateAgentWithCredentials(ctx context.Context, clientID, secret, name string) (store.Agent, error) {
	hash, err := hashSecret(secret)
	if err != nil {
		return store.Agent{}, err
	}
	return svc.store.CreateAgent(ctx, clientID, hash, name)
}

// AuthenticateAgent verifies an NHI's client_credentials. Returns
// ErrInvalidCredentials for an unknown client_id, a wrong secret, AND a
// revoked agent (issue #13) alike -- the same non-enumeration property as
// Authenticate, and the same constant-time comparison inside
// verifySecret (MASTER_PLAN.md's five security-review seams explicitly
// call out timing-safe secret comparison as distinct from the human
// login path). A revoked agent must never be distinguishable from a
// wrong secret to the caller -- otherwise "invalid_client" vs. "this
// agent exists but is revoked" itself leaks agent existence.
func (svc *Service) AuthenticateAgent(ctx context.Context, clientID, secret string) (store.Agent, error) {
	a, err := svc.store.GetAgentByClientID(ctx, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Agent{}, ErrInvalidCredentials
	}
	if err != nil {
		return store.Agent{}, err
	}
	ok, err := verifySecret(secret, a.SecretHash)
	if err != nil {
		return store.Agent{}, err
	}
	if !ok {
		return store.Agent{}, ErrInvalidCredentials
	}
	if a.RevokedAt != nil {
		return store.Agent{}, ErrInvalidCredentials
	}
	return a, nil
}

func randomToken(prefix string, nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}
