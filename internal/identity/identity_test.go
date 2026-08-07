package identity

import (
	"context"
	"errors"
	"path/filepath"
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
