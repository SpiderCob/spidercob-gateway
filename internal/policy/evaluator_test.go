package policy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

func newTestEvaluator(t *testing.T) (*Evaluator, store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return NewEvaluator(s), s
}

func TestEvaluator_UnknownPrincipalDefaultsDeny(t *testing.T) {
	ev, _ := newTestEvaluator(t)
	ctx := context.Background()

	d := ev.Decide(ctx, "user:nobody", "jira", "tools/call", "search_issues")
	if d.Allowed {
		t.Fatal("expected default-deny for a principal with no store record")
	}
}

func TestEvaluator_UserWithNoGroupsDefaultsDeny(t *testing.T) {
	ev, s := newTestEvaluator(t)
	ctx := context.Background()

	if _, err := s.CreateUser(ctx, "alice", "hash"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	d := ev.Decide(ctx, "user:alice", "jira", "tools/call", "search_issues")
	if d.Allowed {
		t.Fatal("expected default-deny for a user with zero group memberships")
	}
}

func TestEvaluator_UserGrantedViaGroupPolicy(t *testing.T) {
	ev, s := newTestEvaluator(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "alice", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	g, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.AssignUserGroup(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}
	if err := s.ReplacePolicies(ctx, []store.NewPolicy{
		{GroupID: g.ID, Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}, Tools: []string{"search_issues"}},
	}); err != nil {
		t.Fatalf("ReplacePolicies: %v", err)
	}

	if !ev.Decide(ctx, "user:alice", "jira", "tools/call", "search_issues").Allowed {
		t.Fatal("expected allowed via group policy")
	}
	if ev.Decide(ctx, "user:alice", "jira", "tools/call", "delete_issue").Allowed {
		t.Fatal("expected a different tool to stay denied")
	}
	if ev.Decide(ctx, "user:alice", "other-node", "tools/call", "search_issues").Allowed {
		t.Fatal("expected access scoped to the granted node only")
	}
}

func TestEvaluator_AgentGrantedViaAgentGroupPolicy(t *testing.T) {
	ev, s := newTestEvaluator(t)
	ctx := context.Background()

	a, err := s.CreateAgent(ctx, "agt_ci", "sechash", "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	g, err := s.CreateGroup(ctx, "ci")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.AssignAgentGroup(ctx, a.ID, g.ID); err != nil {
		t.Fatalf("AssignAgentGroup: %v", err)
	}
	if err := s.ReplacePolicies(ctx, []store.NewPolicy{
		{GroupID: g.ID, Node: "jira", RuleType: store.PolicyAllow},
	}); err != nil {
		t.Fatalf("ReplacePolicies: %v", err)
	}

	if !ev.Decide(ctx, "agent:agt_ci", "jira", "tools/call", "anything").Allowed {
		t.Fatal("expected NHI access via agent_groups, same as a human via user_groups")
	}
}

func TestEvaluator_RevokedRateLimitReturns429Shape(t *testing.T) {
	ev, s := newTestEvaluator(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "alice", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	g, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.AssignUserGroup(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}
	maxCalls, window := 1, 3600
	if err := s.ReplacePolicies(ctx, []store.NewPolicy{
		{GroupID: g.ID, Node: "jira", RuleType: store.PolicyAllow, RateLimitMaxCalls: &maxCalls, RateLimitWindowSeconds: &window},
	}); err != nil {
		t.Fatalf("ReplacePolicies: %v", err)
	}

	first := ev.Decide(ctx, "user:alice", "jira", "tools/call", "search_issues")
	if !first.Allowed {
		t.Fatalf("expected first call allowed, got %+v", first)
	}
	second := ev.Decide(ctx, "user:alice", "jira", "tools/call", "search_issues")
	if second.Allowed || !second.RateLimited {
		t.Fatalf("expected second call denied+rate-limited, got %+v", second)
	}
}

func TestEvaluator_FilterTools(t *testing.T) {
	ev, s := newTestEvaluator(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "alice", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	g, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.AssignUserGroup(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}
	if err := s.ReplacePolicies(ctx, []store.NewPolicy{
		{GroupID: g.ID, Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}, Tools: []string{"search_issues", "create_issue"}},
	}); err != nil {
		t.Fatalf("ReplacePolicies: %v", err)
	}

	got := ev.FilterTools(ctx, "user:alice", "jira", []string{"search_issues", "delete_issue", "create_issue"})
	want := []string{"search_issues", "create_issue"}
	if len(got) != len(want) {
		t.Fatalf("FilterTools = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("FilterTools = %v, want %v (order preserved)", got, want)
		}
	}
}

func TestEvaluator_FilterToolsDoesNotConsumeRateLimit(t *testing.T) {
	ev, s := newTestEvaluator(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "alice", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	g, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.AssignUserGroup(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}
	maxCalls, window := 1, 3600
	if err := s.ReplacePolicies(ctx, []store.NewPolicy{
		{GroupID: g.ID, Node: "jira", RuleType: store.PolicyAllow, RateLimitMaxCalls: &maxCalls, RateLimitWindowSeconds: &window},
	}); err != nil {
		t.Fatalf("ReplacePolicies: %v", err)
	}

	// Listing tools repeatedly must not burn the same budget as invoking one.
	for i := 0; i < 5; i++ {
		got := ev.FilterTools(ctx, "user:alice", "jira", []string{"search_issues"})
		if len(got) != 1 {
			t.Fatalf("FilterTools call %d = %v, want [search_issues] every time", i, got)
		}
	}
	if !ev.Decide(ctx, "user:alice", "jira", "tools/call", "search_issues").Allowed {
		t.Fatal("expected the actual invocation's rate-limit budget to still be untouched by FilterTools calls")
	}
}
