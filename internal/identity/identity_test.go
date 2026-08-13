package identity

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return NewService(s)
}

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := hashSecret("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashSecret: %v", err)
	}
	if hash == "correct horse battery staple" {
		t.Fatalf("hash must not equal the plaintext")
	}
	ok, err := verifySecret("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("verifySecret: %v", err)
	}
	if !ok {
		t.Fatalf("verifySecret should accept the correct password")
	}
	ok, err = verifySecret("wrong password", hash)
	if err != nil {
		t.Fatalf("verifySecret: %v", err)
	}
	if ok {
		t.Fatalf("verifySecret should reject a wrong password")
	}
}

func TestVerifySecretRejectsUnsupportedArgon2Version(t *testing.T) {
	hash, err := hashSecret("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashSecret: %v", err)
	}
	// Claim an unsupported version (argon2.Version is 0x13 == 19) --
	// verifySecret parses the version field but must not silently ignore
	// it; a self-describing format that doesn't check its own version tag
	// isn't actually self-describing.
	tampered := strings.Replace(hash, "$v=19$", "$v=16$", 1)
	if tampered == hash {
		t.Fatalf("test setup: expected to find $v=19$ in %q", hash)
	}
	ok, err := verifySecret("correct horse battery staple", tampered)
	if err == nil && ok {
		t.Fatalf("verifySecret must reject a hash claiming an unsupported argon2 version")
	}
}

func TestPasswordHashesAreSalted(t *testing.T) {
	h1, err := hashSecret("same-input")
	if err != nil {
		t.Fatalf("hashSecret: %v", err)
	}
	h2, err := hashSecret("same-input")
	if err != nil {
		t.Fatalf("hashSecret: %v", err)
	}
	if h1 == h2 {
		t.Fatalf("two hashes of the same password must differ (random salt)")
	}
}

func TestUserGroupNames_ReflectsRealGroupMembership(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := NewService(s)
	ctx := context.Background()

	u, err := svc.CreateUser(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	names, err := svc.UserGroupNames(ctx, "alice")
	if err != nil {
		t.Fatalf("UserGroupNames (no groups yet): %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("UserGroupNames = %v, want none before any group assignment", names)
	}

	g, err := s.CreateGroup(ctx, "admin")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.AssignUserGroup(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}

	names, err = svc.UserGroupNames(ctx, "alice")
	if err != nil {
		t.Fatalf("UserGroupNames: %v", err)
	}
	if len(names) != 1 || names[0] != "admin" {
		t.Fatalf("UserGroupNames = %v, want [admin]", names)
	}
}

func TestUserGroupNames_UnknownUsernameErrors(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.UserGroupNames(ctx, "nobody"); err == nil {
		t.Fatal("expected an error for an unknown username")
	}
}

func TestUserCreateAndAuthenticate(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	u, err := svc.CreateUser(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.PasswordHash == "s3cret-pw" {
		t.Fatalf("password must not be stored in plaintext")
	}

	got, err := svc.Authenticate(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("Authenticate returned wrong user: %+v", got)
	}

	if _, err := svc.Authenticate(ctx, "alice", "wrong-pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.Authenticate(ctx, "nobody", "whatever"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user = %v, want ErrInvalidCredentials (same error, no enumeration)", err)
	}
}

func TestAgentCreateAndAuthenticate(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	agent, secret, err := svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if agent.ClientID == "" {
		t.Fatalf("expected a generated client_id")
	}
	if secret == "" {
		t.Fatalf("expected a generated plaintext secret")
	}
	if agent.SecretHash == secret {
		t.Fatalf("secret must not be stored in plaintext")
	}

	got, err := svc.AuthenticateAgent(ctx, agent.ClientID, secret)
	if err != nil {
		t.Fatalf("AuthenticateAgent: %v", err)
	}
	if got.ID != agent.ID {
		t.Fatalf("AuthenticateAgent returned wrong agent: %+v", got)
	}

	if _, err := svc.AuthenticateAgent(ctx, agent.ClientID, "wrong-secret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong secret = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.AuthenticateAgent(ctx, "unknown-client", secret); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown client_id = %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthenticateAgent_RevokedAgentRejected(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := NewService(s)
	ctx := context.Background()

	agent, secret, err := svc.CreateAgent(ctx, "revoke-me")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if _, err := svc.AuthenticateAgent(ctx, agent.ClientID, secret); err != nil {
		t.Fatalf("AuthenticateAgent (before revocation): %v", err)
	}

	if err := s.RevokeAgent(ctx, agent.ClientID); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}

	// A revoked agent's otherwise-correct secret must be rejected exactly
	// like a wrong one -- not distinguishably, so revocation can never be
	// probed for via the error shape (issue #13).
	if _, err := svc.AuthenticateAgent(ctx, agent.ClientID, secret); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("AuthenticateAgent (after revocation) = %v, want ErrInvalidCredentials", err)
	}
}

func TestResolveOrCreateExternalUser_FirstLoginProvisionsZeroGroupAccount(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	u, err := svc.ResolveOrCreateExternalUser(ctx, "https://idp.example.com", "alice-sub")
	if err != nil {
		t.Fatalf("ResolveOrCreateExternalUser: %v", err)
	}
	if u.ID == 0 {
		t.Fatalf("expected a real user id")
	}

	got, err := svc.store.UserGroups(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserGroups: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("JIT-provisioned user should start with zero groups, got %v", got)
	}
}

func TestResolveOrCreateExternalUser_SecondLoginResolvesSameAccount(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	first, err := svc.ResolveOrCreateExternalUser(ctx, "https://idp.example.com", "alice-sub")
	if err != nil {
		t.Fatalf("ResolveOrCreateExternalUser (first): %v", err)
	}
	second, err := svc.ResolveOrCreateExternalUser(ctx, "https://idp.example.com", "alice-sub")
	if err != nil {
		t.Fatalf("ResolveOrCreateExternalUser (second): %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("second login resolved a different account: %+v vs %+v", second, first)
	}
}

func TestResolveOrCreateExternalUser_DifferentIssuersAreDistinctAccounts(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	a, err := svc.ResolveOrCreateExternalUser(ctx, "https://idp-a.example.com", "alice-sub")
	if err != nil {
		t.Fatalf("ResolveOrCreateExternalUser (idp-a): %v", err)
	}
	b, err := svc.ResolveOrCreateExternalUser(ctx, "https://idp-b.example.com", "alice-sub")
	if err != nil {
		t.Fatalf("ResolveOrCreateExternalUser (idp-b): %v", err)
	}
	if a.ID == b.ID {
		t.Fatalf("same subject at two different issuers must not collapse into one account")
	}
}

func TestResolveOrCreateExternalUser_CannotAuthenticateViaLocalLogin(t *testing.T) {
	// Story 23: a JIT-provisioned account can never gain a second,
	// gateway-local password nobody assigned it.
	svc := newTestService(t)
	ctx := context.Background()

	u, err := svc.ResolveOrCreateExternalUser(ctx, "https://idp.example.com", "alice-sub")
	if err != nil {
		t.Fatalf("ResolveOrCreateExternalUser: %v", err)
	}

	for _, password := range []string{"", "password", u.PasswordHash, "!external-identity-no-local-password"} {
		if _, err := svc.Authenticate(ctx, u.Username, password); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Authenticate(%q, %q) = %v, want ErrInvalidCredentials", u.Username, password, err)
		}
	}
}

func TestCreateAgentWithCredentials_UsesCallerSuppliedValues(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	agent, err := svc.CreateAgentWithCredentials(ctx, "seed-client", "seed-secret", "e2e-seed")
	if err != nil {
		t.Fatalf("CreateAgentWithCredentials: %v", err)
	}
	if agent.ClientID != "seed-client" {
		t.Fatalf("ClientID = %q, want seed-client", agent.ClientID)
	}
	if agent.SecretHash == "seed-secret" {
		t.Fatalf("secret must not be stored in plaintext")
	}

	got, err := svc.AuthenticateAgent(ctx, "seed-client", "seed-secret")
	if err != nil {
		t.Fatalf("AuthenticateAgent: %v", err)
	}
	if got.ID != agent.ID {
		t.Fatalf("AuthenticateAgent returned wrong agent: %+v", got)
	}
}

func TestTwoAgentsGetDifferentCredentials(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	a1, s1, err := svc.CreateAgent(ctx, "bot-1")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	a2, s2, err := svc.CreateAgent(ctx, "bot-2")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if a1.ClientID == a2.ClientID {
		t.Fatalf("client_ids must be unique: both %q", a1.ClientID)
	}
	if s1 == s2 {
		t.Fatalf("secrets must be unique")
	}
}
