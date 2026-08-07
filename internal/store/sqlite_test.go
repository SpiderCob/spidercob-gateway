package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenAppliesMigrationsAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := s1.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopening the same file must not error re-applying migrations.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer s2.Close()
	if err := s2.Ping(); err != nil {
		t.Fatalf("Ping after reopen: %v", err)
	}
}

func TestUserCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "alice", "hash-1")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == 0 || u.Username != "alice" || u.PasswordHash != "hash-1" {
		t.Fatalf("unexpected user: %+v", u)
	}
	if u.CreatedAt.IsZero() {
		t.Fatalf("expected CreatedAt to be set")
	}

	byName, err := s.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if byName != u {
		t.Fatalf("GetUserByUsername returned %+v, want %+v", byName, u)
	}

	byID, err := s.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if byID != u {
		t.Fatalf("GetUserByID returned %+v, want %+v", byID, u)
	}

	if _, err := s.GetUserByUsername(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUserByUsername(nobody) = %v, want ErrNotFound", err)
	}

	if _, err := s.CreateUser(ctx, "alice", "hash-2"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate CreateUser = %v, want ErrConflict", err)
	}
}

func TestAgentCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	a, err := s.CreateAgent(ctx, "client-123", "sechash-1", "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if a.ID == 0 || a.ClientID != "client-123" || a.Name != "ci-bot" {
		t.Fatalf("unexpected agent: %+v", a)
	}

	byClient, err := s.GetAgentByClientID(ctx, "client-123")
	if err != nil {
		t.Fatalf("GetAgentByClientID: %v", err)
	}
	if byClient != a {
		t.Fatalf("GetAgentByClientID returned %+v, want %+v", byClient, a)
	}

	byID, err := s.GetAgentByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	if byID != a {
		t.Fatalf("GetAgentByID returned %+v, want %+v", byID, a)
	}

	if _, err := s.GetAgentByClientID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAgentByClientID(nope) = %v, want ErrNotFound", err)
	}

	if _, err := s.CreateAgent(ctx, "client-123", "sechash-2", "dup"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate CreateAgent = %v, want ErrConflict", err)
	}
}

func TestGroupMembership(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "bob", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	a, err := s.CreateAgent(ctx, "client-9", "sechash", "job")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	g, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if g.ID == 0 || g.Name != "engineering" {
		t.Fatalf("unexpected group: %+v", g)
	}

	if err := s.AssignUserGroup(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}
	// Assigning twice must be idempotent, not an error.
	if err := s.AssignUserGroup(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("AssignUserGroup (repeat): %v", err)
	}
	if err := s.AssignAgentGroup(ctx, a.ID, g.ID); err != nil {
		t.Fatalf("AssignAgentGroup: %v", err)
	}

	userGroups, err := s.UserGroups(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserGroups: %v", err)
	}
	if len(userGroups) != 1 || userGroups[0].Name != "engineering" {
		t.Fatalf("UserGroups = %+v, want [engineering]", userGroups)
	}

	agentGroups, err := s.AgentGroups(ctx, a.ID)
	if err != nil {
		t.Fatalf("AgentGroups: %v", err)
	}
	if len(agentGroups) != 1 || agentGroups[0].Name != "engineering" {
		t.Fatalf("AgentGroups = %+v, want [engineering]", agentGroups)
	}

	if _, err := s.CreateGroup(ctx, "engineering"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate CreateGroup = %v, want ErrConflict", err)
	}
}

func TestRevocationLifecycle(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	revoked, err := s.IsRevoked(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatalf("jti-1 should not be revoked before RevokeJTI")
	}

	future := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := s.RevokeJTI(ctx, "jti-1", future); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	revoked, err = s.IsRevoked(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked after revoke: %v", err)
	}
	if !revoked {
		t.Fatalf("jti-1 should be revoked")
	}

	// A revocation already expired in the past must not show up when
	// hydrating the in-memory denylist on startup.
	past := time.Now().Add(-time.Hour)
	if err := s.RevokeJTI(ctx, "jti-expired", past); err != nil {
		t.Fatalf("RevokeJTI (expired): %v", err)
	}

	revs, err := s.LoadRevocations(ctx)
	if err != nil {
		t.Fatalf("LoadRevocations: %v", err)
	}
	if len(revs) != 1 || revs[0].JTI != "jti-1" {
		t.Fatalf("LoadRevocations = %+v, want only jti-1", revs)
	}
}

func TestConcurrentWrites(t *testing.T) {
	// Exercises the write-concurrency fix directly: many goroutines
	// hitting the same SQLite file at once must not surface "database is
	// locked" errors.
	s := openTestStore(t)
	ctx := context.Background()

	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			_, err := s.CreateUser(ctx, "user-"+time.Now().Format("150405.000000000")+"-"+string(rune('a'+i%26)), "hash")
			errs <- err
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent CreateUser failed: %v", err)
		}
	}
}
