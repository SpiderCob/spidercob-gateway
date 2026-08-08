package store

import (
	"context"
	"errors"
	"fmt"
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

func TestListAgents(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateAgent(ctx, "client-a", "hash-a", "agent-a"); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if _, err := s.CreateAgent(ctx, "client-b", "hash-b", "agent-b"); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	agents, err := s.ListAgents(ctx)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("ListAgents = %+v, want 2 agents", agents)
	}
}

func TestRevokeAgent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	a, err := s.CreateAgent(ctx, "client-r", "hash", "revoke-me")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if a.RevokedAt != nil {
		t.Fatalf("newly created agent has RevokedAt = %v, want nil", a.RevokedAt)
	}

	if err := s.RevokeAgent(ctx, "client-r"); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	revoked, err := s.GetAgentByClientID(ctx, "client-r")
	if err != nil {
		t.Fatalf("GetAgentByClientID: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatalf("expected RevokedAt to be set after RevokeAgent")
	}

	// Idempotent: revoking again is not an error.
	if err := s.RevokeAgent(ctx, "client-r"); err != nil {
		t.Fatalf("RevokeAgent (again): %v", err)
	}

	if err := s.RevokeAgent(ctx, "never-existed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RevokeAgent (unknown client_id) = %v, want ErrNotFound", err)
	}
}

func TestExternalIdentityResolveOrCreate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.GetUserByExternalIdentity(ctx, "https://idp.example.com", "alice-sub"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUserByExternalIdentity (unprovisioned) = %v, want ErrNotFound", err)
	}

	u, created, err := s.ResolveOrCreateExternalUser(ctx, "https://idp.example.com", "alice-sub", "ext_alice", "!unusable")
	if err != nil {
		t.Fatalf("ResolveOrCreateExternalUser (first login): %v", err)
	}
	if !created {
		t.Fatalf("expected created=true on first login")
	}

	got, err := s.GetUserByExternalIdentity(ctx, "https://idp.example.com", "alice-sub")
	if err != nil {
		t.Fatalf("GetUserByExternalIdentity: %v", err)
	}
	if got != u {
		t.Fatalf("GetUserByExternalIdentity = %+v, want %+v", got, u)
	}

	// Second login for the same (issuer, subject) resolves the same user,
	// doesn't create a duplicate.
	u2, created2, err := s.ResolveOrCreateExternalUser(ctx, "https://idp.example.com", "alice-sub", "ext_alice_2", "!unusable")
	if err != nil {
		t.Fatalf("ResolveOrCreateExternalUser (second login): %v", err)
	}
	if created2 {
		t.Fatalf("expected created=false on second login")
	}
	if u2 != u {
		t.Fatalf("second login resolved a different user: %+v, want %+v", u2, u)
	}

	// A different subject at the same issuer must not resolve to the same user.
	if _, err := s.GetUserByExternalIdentity(ctx, "https://idp.example.com", "bob-sub"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUserByExternalIdentity (different subject) = %v, want ErrNotFound", err)
	}

	// The same (issuer, subject) pair can't be linked to two different users.
	u3, err := s.CreateUser(ctx, "ext_manual", "!unusable")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.LinkExternalIdentity(ctx, u3.ID, "https://idp.example.com", "alice-sub"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate LinkExternalIdentity = %v, want ErrConflict", err)
	}
}

func TestExternalIdentityResolveOrCreate_ConcurrentFirstLoginNoDuplicate(t *testing.T) {
	// The race this guards against: two concurrent first-logins for the
	// same (issuer, subject) must resolve to exactly one user, not two.
	s := openTestStore(t)
	ctx := context.Background()

	const n = 10
	type result struct {
		u   User
		err error
	}
	results := make(chan result, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			u, _, err := s.ResolveOrCreateExternalUser(ctx, "https://idp.example.com", "concurrent-sub",
				fmt.Sprintf("ext_concurrent_%d", i), "!unusable")
			results <- result{u, err}
		}(i)
	}

	seen := map[int64]bool{}
	for i := 0; i < n; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("ResolveOrCreateExternalUser: %v", r.err)
		}
		seen[r.u.ID] = true
	}
	if len(seen) != 1 {
		t.Fatalf("expected exactly one distinct user across %d concurrent first-logins, got %d", n, len(seen))
	}
}

func intPtr(i int) *int       { return &i }
func strPtr(s string) *string { return &s }

func TestToolPin_CreateGetQuarantine(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.GetToolPin(ctx, "jira", "search_issues"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetToolPin (unpinned) = %v, want ErrNotFound", err)
	}

	pin, err := s.CreateToolPin(ctx, "jira", "search_issues", "hash-v1", "")
	if err != nil {
		t.Fatalf("CreateToolPin: %v", err)
	}
	if pin.Node != "jira" || pin.ToolName != "search_issues" || pin.Hash != "hash-v1" {
		t.Fatalf("unexpected pin: %+v", pin)
	}
	if pin.QuarantinedAt != nil {
		t.Fatalf("expected a freshly-established pin to not be quarantined, got %+v", pin.QuarantinedAt)
	}
	if pin.InputSchema != nil {
		t.Fatalf("expected InputSchema to be nil for an empty-string input, got %v", *pin.InputSchema)
	}
	if pin.PinnedAt.IsZero() {
		t.Fatalf("expected PinnedAt to be set")
	}

	got, err := s.GetToolPin(ctx, "jira", "search_issues")
	if err != nil {
		t.Fatalf("GetToolPin: %v", err)
	}
	if got != pin {
		t.Fatalf("GetToolPin = %+v, want %+v", got, pin)
	}

	if _, err := s.CreateToolPin(ctx, "jira", "search_issues", "hash-v2", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate CreateToolPin = %v, want ErrConflict", err)
	}

	if err := s.QuarantineToolPin(ctx, "jira", "search_issues", "hash changed from hash-v1 to hash-v2"); err != nil {
		t.Fatalf("QuarantineToolPin: %v", err)
	}
	quarantined, err := s.GetToolPin(ctx, "jira", "search_issues")
	if err != nil {
		t.Fatalf("GetToolPin (after quarantine): %v", err)
	}
	if quarantined.QuarantinedAt == nil {
		t.Fatalf("expected QuarantinedAt to be set")
	}
	if quarantined.DriftDetail == nil || *quarantined.DriftDetail != "hash changed from hash-v1 to hash-v2" {
		t.Fatalf("DriftDetail = %v, want the drift detail string", quarantined.DriftDetail)
	}

	// Idempotent: quarantining an already-quarantined pin again just
	// updates the detail, it doesn't error.
	if err := s.QuarantineToolPin(ctx, "jira", "search_issues", "second drift"); err != nil {
		t.Fatalf("QuarantineToolPin (again): %v", err)
	}

	if err := s.QuarantineToolPin(ctx, "jira", "never-pinned-tool", "n/a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("QuarantineToolPin (never pinned) = %v, want ErrNotFound", err)
	}
}

func TestToolPin_InputSchemaPersists(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	schema := `{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`
	pin, err := s.CreateToolPin(ctx, "jira", "get_ticket", "hash-v1", schema)
	if err != nil {
		t.Fatalf("CreateToolPin: %v", err)
	}
	if pin.InputSchema == nil || *pin.InputSchema != schema {
		t.Fatalf("pin.InputSchema = %v, want %q", pin.InputSchema, schema)
	}

	got, err := s.GetToolPin(ctx, "jira", "get_ticket")
	if err != nil {
		t.Fatalf("GetToolPin: %v", err)
	}
	if got.InputSchema == nil || *got.InputSchema != schema {
		t.Fatalf("GetToolPin's InputSchema = %v, want %q", got.InputSchema, schema)
	}
}

func TestToolPinsForNode(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateToolPin(ctx, "jira", "search_issues", "h1", ""); err != nil {
		t.Fatalf("CreateToolPin: %v", err)
	}
	if _, err := s.CreateToolPin(ctx, "jira", "create_issue", "h2", ""); err != nil {
		t.Fatalf("CreateToolPin: %v", err)
	}
	if _, err := s.CreateToolPin(ctx, "postgres-ro", "query", "h3", ""); err != nil {
		t.Fatalf("CreateToolPin: %v", err)
	}

	pins, err := s.ToolPinsForNode(ctx, "jira")
	if err != nil {
		t.Fatalf("ToolPinsForNode: %v", err)
	}
	if len(pins) != 2 {
		t.Fatalf("ToolPinsForNode(jira) = %+v, want 2 pins", pins)
	}

	empty, err := s.ToolPinsForNode(ctx, "unknown-node")
	if err != nil {
		t.Fatalf("ToolPinsForNode (unknown node): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ToolPinsForNode(unknown-node) = %+v, want none", empty)
	}
}

func TestReplacePoliciesAndPoliciesForGroups(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	eng, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	sre, err := s.CreateGroup(ctx, "sre")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	got, err := s.PoliciesForGroups(ctx, []int64{eng.ID}, "jira")
	if err != nil {
		t.Fatalf("PoliciesForGroups (empty): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no policies before ReplacePolicies, got %+v", got)
	}

	err = s.ReplacePolicies(ctx, []NewPolicy{
		{GroupID: eng.ID, Node: "jira", RuleType: PolicyAllow, Methods: []string{"tools/call"}, Tools: []string{"search_issues"}},
		{GroupID: eng.ID, Node: "jira", RuleType: PolicyDeny, Methods: []string{"tools/call"}, Tools: []string{"delete_issue"}},
		{GroupID: sre.ID, Node: "jira", RuleType: PolicyAllow, RateLimitMaxCalls: intPtr(10), RateLimitWindowSeconds: intPtr(60), BlockOnScanFlag: true},
		{GroupID: sre.ID, Node: "postgres-ro", RuleType: PolicyAllow},
	})
	if err != nil {
		t.Fatalf("ReplacePolicies: %v", err)
	}

	engPolicies, err := s.PoliciesForGroups(ctx, []int64{eng.ID}, "jira")
	if err != nil {
		t.Fatalf("PoliciesForGroups (eng): %v", err)
	}
	if len(engPolicies) != 2 {
		t.Fatalf("expected 2 policies for eng/jira, got %+v", engPolicies)
	}

	srePolicies, err := s.PoliciesForGroups(ctx, []int64{sre.ID}, "jira")
	if err != nil {
		t.Fatalf("PoliciesForGroups (sre): %v", err)
	}
	if len(srePolicies) != 1 {
		t.Fatalf("expected 1 policy for sre/jira, got %+v", srePolicies)
	}
	p := srePolicies[0]
	if p.RuleType != PolicyAllow || !p.BlockOnScanFlag {
		t.Fatalf("unexpected policy: %+v", p)
	}
	if p.RateLimitMaxCalls == nil || *p.RateLimitMaxCalls != 10 {
		t.Fatalf("RateLimitMaxCalls = %v, want 10", p.RateLimitMaxCalls)
	}
	if p.RateLimitWindowSeconds == nil || *p.RateLimitWindowSeconds != 60 {
		t.Fatalf("RateLimitWindowSeconds = %v, want 60", p.RateLimitWindowSeconds)
	}
	if len(p.Methods) != 0 {
		t.Fatalf("expected empty Methods (all methods), got %v", p.Methods)
	}

	// Wrong node must not leak in.
	noPostgres, err := s.PoliciesForGroups(ctx, []int64{eng.ID}, "postgres-ro")
	if err != nil {
		t.Fatalf("PoliciesForGroups (wrong node): %v", err)
	}
	if len(noPostgres) != 0 {
		t.Fatalf("expected no eng policies for postgres-ro, got %+v", noPostgres)
	}

	// A second ReplacePolicies call fully replaces, not accumulates.
	if err := s.ReplacePolicies(ctx, []NewPolicy{
		{GroupID: eng.ID, Node: "jira", RuleType: PolicyAllow},
	}); err != nil {
		t.Fatalf("ReplacePolicies (second call): %v", err)
	}
	afterReplace, err := s.PoliciesForGroups(ctx, []int64{eng.ID}, "jira")
	if err != nil {
		t.Fatalf("PoliciesForGroups (after replace): %v", err)
	}
	if len(afterReplace) != 1 {
		t.Fatalf("expected exactly 1 policy after replacement, got %+v (replace should not accumulate)", afterReplace)
	}
	sreAfterReplace, err := s.PoliciesForGroups(ctx, []int64{sre.ID}, "jira")
	if err != nil {
		t.Fatalf("PoliciesForGroups (sre after replace): %v", err)
	}
	if len(sreAfterReplace) != 0 {
		t.Fatalf("expected sre's policies gone after full replace, got %+v", sreAfterReplace)
	}
}

func TestAllPolicies(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	empty, err := s.AllPolicies(ctx)
	if err != nil {
		t.Fatalf("AllPolicies (empty): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected no policies yet, got %+v", empty)
	}

	eng, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	sre, err := s.CreateGroup(ctx, "sre")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.ReplacePolicies(ctx, []NewPolicy{
		{GroupID: eng.ID, Node: "jira", RuleType: PolicyAllow},
		{GroupID: sre.ID, Node: "postgres-ro", RuleType: PolicyDeny},
	}); err != nil {
		t.Fatalf("ReplacePolicies: %v", err)
	}

	all, err := s.AllPolicies(ctx)
	if err != nil {
		t.Fatalf("AllPolicies: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("AllPolicies = %+v, want 2 policies (unfiltered, across every group)", all)
	}
}

func TestGetGroupByName(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.GetGroupByName(ctx, "engineering"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGroupByName (unprovisioned) = %v, want ErrNotFound", err)
	}

	created, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	got, err := s.GetGroupByName(ctx, "engineering")
	if err != nil {
		t.Fatalf("GetGroupByName: %v", err)
	}
	if got != created {
		t.Fatalf("GetGroupByName = %+v, want %+v", got, created)
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

func TestListGroups(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateGroup(ctx, "engineering"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := s.CreateGroup(ctx, "support"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	groups, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("ListGroups = %+v, want 2 groups", groups)
	}
}

func TestDeleteGroup(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateGroup(ctx, "throwaway"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.DeleteGroup(ctx, "throwaway"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if _, err := s.GetGroupByName(ctx, "throwaway"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGroupByName after delete = %v, want ErrNotFound", err)
	}

	if err := s.DeleteGroup(ctx, "never-existed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteGroup (unknown name) = %v, want ErrNotFound", err)
	}

	// A group still referenced by a policy must not be silently
	// deletable, even though the schema's own FK is ON DELETE CASCADE --
	// deleting the group would otherwise silently wipe that policy row
	// too (story 27).
	g2, err := s.CreateGroup(ctx, "policy-holder")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.ReplacePolicies(ctx, []NewPolicy{
		{GroupID: g2.ID, Node: "jira", RuleType: PolicyAllow},
	}); err != nil {
		t.Fatalf("ReplacePolicies: %v", err)
	}
	if err := s.DeleteGroup(ctx, "policy-holder"); !errors.Is(err, ErrConflict) {
		t.Fatalf("DeleteGroup (still referenced by a policy) = %v, want ErrConflict", err)
	}
	if _, err := s.GetGroupByName(ctx, "policy-holder"); err != nil {
		t.Fatalf("group must still exist after a refused delete: %v", err)
	}
}

func TestRemoveGroupMembership(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "carol", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	a, err := s.CreateAgent(ctx, "client-rm", "hash", "job")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	g, err := s.CreateGroup(ctx, "temp-access")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	if err := s.AssignUserGroup(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}
	if err := s.AssignAgentGroup(ctx, a.ID, g.ID); err != nil {
		t.Fatalf("AssignAgentGroup: %v", err)
	}

	if err := s.RemoveUserGroup(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("RemoveUserGroup: %v", err)
	}
	if err := s.RemoveAgentGroup(ctx, a.ID, g.ID); err != nil {
		t.Fatalf("RemoveAgentGroup: %v", err)
	}

	userGroups, err := s.UserGroups(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserGroups: %v", err)
	}
	if len(userGroups) != 0 {
		t.Fatalf("UserGroups after removal = %+v, want none", userGroups)
	}
	agentGroups, err := s.AgentGroups(ctx, a.ID)
	if err != nil {
		t.Fatalf("AgentGroups: %v", err)
	}
	if len(agentGroups) != 0 {
		t.Fatalf("AgentGroups after removal = %+v, want none", agentGroups)
	}

	// Idempotent: removing a membership that doesn't exist is not an error.
	if err := s.RemoveUserGroup(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("RemoveUserGroup (already removed): %v", err)
	}
	if err := s.RemoveAgentGroup(ctx, a.ID, g.ID); err != nil {
		t.Fatalf("RemoveAgentGroup (already removed): %v", err)
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
