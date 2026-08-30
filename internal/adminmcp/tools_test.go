package adminmcp

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sumeetgp/spidercob-gateway/internal/audit"
	"github.com/sumeetgp/spidercob-gateway/internal/pin"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// fakeSessionKiller records every EndSession call it receives -- the
// shape every kill_session test below needs.
type fakeSessionKiller struct {
	ended []string
	err   error
}

func (f *fakeSessionKiller) EndSession(ctx context.Context, id string) error {
	f.ended = append(f.ended, id)
	return f.err
}

func newTestServer(t *testing.T, fetch pin.Fetcher, killer SessionKiller) (*Server, store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if fetch == nil {
		fetch = func(context.Context, string) ([]pin.ToolDef, error) { return nil, nil }
	}
	if killer == nil {
		killer = &fakeSessionKiller{}
	}
	srv, err := New(Config{Store: s, Pins: pin.NewRegistry(s), Fetch: fetch, Sessions: killer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, s
}

// contentText extracts the plain text of a CallToolResult's first
// content block -- every tool in this package returns exactly one.
func contentText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil || len(result.Content) == 0 {
		t.Fatal("expected a non-empty CallToolResult.Content")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected the first content block to be text, got %T", result.Content[0])
	}
	return tc.Text
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func strPtr(s string) *string { return &s }

func testAuditRecord(action, resource string) audit.Record {
	return audit.Record{Timestamp: time.Now(), ActorHumanUsername: "test-admin", Action: action, Resource: resource}
}

func TestListNodes(t *testing.T) {
	srv, s := newTestServer(t, nil, nil)
	ctx := context.Background()
	if _, err := s.CreateNode(ctx, store.Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtr("http://x"), Source: store.NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	result, _, err := srv.listNodes(ctx, nil, listNodesInput{})
	if err != nil {
		t.Fatalf("listNodes: %v", err)
	}
	text := contentText(t, result)
	if !contains(text, "jira") {
		t.Fatalf("expected the listing to mention jira, got %s", text)
	}
}

func TestQueryAudit(t *testing.T) {
	srv, s := newTestServer(t, nil, nil)
	ctx := context.Background()
	if _, err := s.AppendAuditRecord(ctx, testAuditRecord("create_agent", "ci-bot")); err != nil {
		t.Fatalf("AppendAuditRecord: %v", err)
	}

	result, _, err := srv.queryAudit(ctx, nil, queryAuditInput{})
	if err != nil {
		t.Fatalf("queryAudit: %v", err)
	}
	text := contentText(t, result)
	if !contains(text, "create_agent") {
		t.Fatalf("expected the audit read to mention create_agent, got %s", text)
	}
}

func TestListQuarantinedTools(t *testing.T) {
	srv, s := newTestServer(t, nil, nil)
	ctx := context.Background()
	if _, err := s.CreateToolPin(ctx, "jira", "search_issues", "h1", ""); err != nil {
		t.Fatalf("CreateToolPin: %v", err)
	}
	if err := s.QuarantineToolPin(ctx, "jira", "search_issues", "drift"); err != nil {
		t.Fatalf("QuarantineToolPin: %v", err)
	}

	result, _, err := srv.listQuarantinedTools(ctx, nil, listQuarantinedToolsInput{})
	if err != nil {
		t.Fatalf("listQuarantinedTools: %v", err)
	}
	text := contentText(t, result)
	if !contains(text, "search_issues") {
		t.Fatalf("expected the listing to mention search_issues, got %s", text)
	}
}

func TestGrantAccess_WithoutConfirm_DoesNotMutate(t *testing.T) {
	srv, s := newTestServer(t, nil, nil)
	ctx := context.Background()
	if _, err := s.CreateGroup(ctx, "engineering"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	result, _, err := srv.grantAccess(ctx, nil, grantAccessInput{Group: "engineering", Node: "jira"})
	if err != nil {
		t.Fatalf("grantAccess: %v", err)
	}
	if !contains(contentText(t, result), "jira") {
		t.Fatalf("expected the preview to describe the pending grant")
	}
	policies, err := s.AllPolicies(ctx)
	if err != nil {
		t.Fatalf("AllPolicies: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("expected zero policy rows after a preview-only call, got %+v", policies)
	}
}

func TestGrantAccess_WithConfirm_CreatesRuleAndLeavesOthersUntouched(t *testing.T) {
	srv, s := newTestServer(t, nil, nil)
	ctx := context.Background()
	eng, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	marketing, err := s.CreateGroup(ctx, "marketing")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	// Pre-existing, unrelated rules that must survive byte-for-byte.
	preexisting := []store.NewPolicy{
		{GroupID: eng.ID, Node: "postgres-ro", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}, Tools: []string{"query"}},
		{GroupID: marketing.ID, Node: "confluence", RuleType: store.PolicyAllow},
	}
	if err := s.ReplacePolicies(ctx, preexisting); err != nil {
		t.Fatalf("ReplacePolicies (seed): %v", err)
	}

	_, _, err = srv.grantAccess(ctx, nil, grantAccessInput{
		Group: "marketing", Node: "jira", Tools: []string{"search_issues", "create_issue"}, Confirm: true,
	})
	if err != nil {
		t.Fatalf("grantAccess (confirmed): %v", err)
	}

	after, err := s.AllPolicies(ctx)
	if err != nil {
		t.Fatalf("AllPolicies: %v", err)
	}
	if len(after) != 3 {
		t.Fatalf("expected 3 policy rows (2 pre-existing + 1 new), got %d: %+v", len(after), after)
	}

	var newRule *store.Policy
	for i := range after {
		if after[i].GroupID == marketing.ID && after[i].Node == "jira" {
			newRule = &after[i]
		}
	}
	if newRule == nil {
		t.Fatalf("expected a new marketing/jira rule, got %+v", after)
	}
	if !reflect.DeepEqual(newRule.Tools, []string{"search_issues", "create_issue"}) {
		t.Fatalf("new rule's Tools = %v, want the requested tools", newRule.Tools)
	}

	// The two pre-existing rules are untouched.
	var sawEngPostgres, sawMarketingConfluence bool
	for _, p := range after {
		if p.GroupID == eng.ID && p.Node == "postgres-ro" {
			sawEngPostgres = true
			if !reflect.DeepEqual(p.Tools, []string{"query"}) {
				t.Fatalf("pre-existing eng/postgres-ro rule's Tools changed: %v", p.Tools)
			}
		}
		if p.GroupID == marketing.ID && p.Node == "confluence" {
			sawMarketingConfluence = true
		}
	}
	if !sawEngPostgres || !sawMarketingConfluence {
		t.Fatalf("a pre-existing rule went missing: %+v", after)
	}
}

func TestGrantAccess_UnknownGroupRejected(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	_, _, err := srv.grantAccess(context.Background(), nil, grantAccessInput{Group: "does-not-exist", Node: "jira", Confirm: true})
	if err == nil {
		t.Fatal("expected an error for an unresolvable group name")
	}
}

func TestRevokeAccess_WithConfirm_RemovesOnlyTheTargetedRule(t *testing.T) {
	srv, s := newTestServer(t, nil, nil)
	ctx := context.Background()
	eng, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.ReplacePolicies(ctx, []store.NewPolicy{
		{GroupID: eng.ID, Node: "jira", RuleType: store.PolicyAllow},
		{GroupID: eng.ID, Node: "postgres-ro", RuleType: store.PolicyAllow},
	}); err != nil {
		t.Fatalf("ReplacePolicies (seed): %v", err)
	}

	_, _, err = srv.revokeAccess(ctx, nil, revokeAccessInput{Group: "engineering", Node: "jira", Confirm: true})
	if err != nil {
		t.Fatalf("revokeAccess: %v", err)
	}

	after, err := s.AllPolicies(ctx)
	if err != nil {
		t.Fatalf("AllPolicies: %v", err)
	}
	if len(after) != 1 || after[0].Node != "postgres-ro" {
		t.Fatalf("expected only the postgres-ro rule to remain, got %+v", after)
	}
}

func TestRevokeAccess_NothingToRevoke(t *testing.T) {
	srv, s := newTestServer(t, nil, nil)
	ctx := context.Background()
	if _, err := s.CreateGroup(ctx, "engineering"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	result, _, err := srv.revokeAccess(ctx, nil, revokeAccessInput{Group: "engineering", Node: "jira", Confirm: true})
	if err != nil {
		t.Fatalf("revokeAccess: %v", err)
	}
	if !contains(contentText(t, result), "nothing to revoke") {
		t.Fatalf("expected an honest 'nothing to revoke' response, got %s", contentText(t, result))
	}
}

func TestKillSession_ConfirmRequired(t *testing.T) {
	killer := &fakeSessionKiller{}
	srv, _ := newTestServer(t, nil, killer)
	ctx := context.Background()

	if _, _, err := srv.killSession(ctx, nil, killSessionInput{SessionID: "sess-1"}); err != nil {
		t.Fatalf("killSession (preview): %v", err)
	}
	if len(killer.ended) != 0 {
		t.Fatalf("expected zero EndSession calls before confirm, got %v", killer.ended)
	}

	if _, _, err := srv.killSession(ctx, nil, killSessionInput{SessionID: "sess-1", Confirm: true}); err != nil {
		t.Fatalf("killSession (confirmed): %v", err)
	}
	if len(killer.ended) != 1 || killer.ended[0] != "sess-1" {
		t.Fatalf("expected exactly one EndSession(sess-1) call, got %v", killer.ended)
	}
}

func TestApproveTool_ConfirmedRefetchesAndClearsQuarantine(t *testing.T) {
	fresh := pin.ToolDef{Name: "search_issues", Description: "now with pagination", InputSchema: []byte(`{"type":"object"}`)}
	fetch := func(ctx context.Context, node string) ([]pin.ToolDef, error) {
		return []pin.ToolDef{fresh}, nil
	}
	srv, s := newTestServer(t, fetch, nil)
	ctx := context.Background()
	if _, err := s.CreateToolPin(ctx, "jira", "search_issues", "old-hash", ""); err != nil {
		t.Fatalf("CreateToolPin: %v", err)
	}
	if err := s.QuarantineToolPin(ctx, "jira", "search_issues", "drift"); err != nil {
		t.Fatalf("QuarantineToolPin: %v", err)
	}

	if _, _, err := srv.approveTool(ctx, nil, approveToolInput{Node: "jira", Tool: "search_issues", Confirm: true}); err != nil {
		t.Fatalf("approveTool: %v", err)
	}

	got, err := s.GetToolPin(ctx, "jira", "search_issues")
	if err != nil {
		t.Fatalf("GetToolPin: %v", err)
	}
	if got.QuarantinedAt != nil {
		t.Fatalf("expected quarantine cleared after approval")
	}
	wantHash, err := pin.Hash(fresh)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if got.Hash != wantHash {
		t.Fatalf("pin.Hash = %q, want the freshly-fetched definition's hash %q", got.Hash, wantHash)
	}
}

func TestApproveTool_FetchFailureLeavesQuarantineUntouched(t *testing.T) {
	fetch := func(ctx context.Context, node string) ([]pin.ToolDef, error) {
		return nil, errors.New("upstream unreachable")
	}
	srv, s := newTestServer(t, fetch, nil)
	ctx := context.Background()
	if _, err := s.CreateToolPin(ctx, "jira", "search_issues", "old-hash", ""); err != nil {
		t.Fatalf("CreateToolPin: %v", err)
	}
	if err := s.QuarantineToolPin(ctx, "jira", "search_issues", "drift"); err != nil {
		t.Fatalf("QuarantineToolPin: %v", err)
	}

	if _, _, err := srv.approveTool(ctx, nil, approveToolInput{Node: "jira", Tool: "search_issues", Confirm: true}); err == nil {
		t.Fatal("expected an error when the live refetch fails")
	}

	got, err := s.GetToolPin(ctx, "jira", "search_issues")
	if err != nil {
		t.Fatalf("GetToolPin: %v", err)
	}
	if got.QuarantinedAt == nil {
		t.Fatal("expected the pin to remain quarantined after a failed approval attempt")
	}
	if got.Hash != "old-hash" {
		t.Fatalf("expected the hash unchanged after a failed approval, got %q", got.Hash)
	}
}
