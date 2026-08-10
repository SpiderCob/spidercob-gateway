package policy

import (
	"testing"

	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

func TestEvaluate_DefaultDenyWithNoMatchingRule(t *testing.T) {
	got := evaluate(nil, "tools/call", "search_issues")
	if got.Allowed {
		t.Fatal("expected default-deny with no policies at all")
	}

	got = evaluate([]store.Policy{
		{Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"resources/read"}},
	}, "tools/call", "search_issues")
	if got.Allowed {
		t.Fatal("expected default-deny when no rule matches the requested method")
	}
}

func TestEvaluate_ServerLevelAllowMatchesEveryMethodAndTool(t *testing.T) {
	policies := []store.Policy{
		{Node: "jira", RuleType: store.PolicyAllow}, // no Methods/Tools = everything
	}
	if !evaluate(policies, "tools/call", "delete_issue").Allowed {
		t.Fatal("server-level allow should cover any tool")
	}
	if !evaluate(policies, "resources/read", "").Allowed {
		t.Fatal("server-level allow should cover any method")
	}
}

func TestEvaluate_MethodLevelDoesNotGrantOtherMethods(t *testing.T) {
	policies := []store.Policy{
		{Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}},
	}
	if !evaluate(policies, "tools/call", "anything").Allowed {
		t.Fatal("expected tools/call allowed")
	}
	if evaluate(policies, "resources/read", "").Allowed {
		t.Fatal("method-level allow for tools/call must not also grant resources/read")
	}
}

func TestEvaluate_ToolLevelRestrictsWithinToolsCall(t *testing.T) {
	policies := []store.Policy{
		{Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}, Tools: []string{"search_issues"}},
	}
	if !evaluate(policies, "tools/call", "search_issues").Allowed {
		t.Fatal("expected the specifically-allowed tool to be allowed")
	}
	if evaluate(policies, "tools/call", "delete_issue").Allowed {
		t.Fatal("expected a different tool to be denied")
	}
}

func TestEvaluate_ExplicitDenyOverridesAllow(t *testing.T) {
	policies := []store.Policy{
		{Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}}, // all tools
		{Node: "jira", RuleType: store.PolicyDeny, Methods: []string{"tools/call"}, Tools: []string{"delete_issue"}},
	}
	if !evaluate(policies, "tools/call", "search_issues").Allowed {
		t.Fatal("expected search_issues allowed (only delete_issue is denied)")
	}
	if evaluate(policies, "tools/call", "delete_issue").Allowed {
		t.Fatal("expected explicit deny to override the broader allow")
	}
}

func TestEvaluate_AdditiveAllowAcrossGroups(t *testing.T) {
	// Simulates two different groups' rules both being passed in (the
	// caller is responsible for gathering rules across every group a
	// principal belongs to before calling evaluate).
	policies := []store.Policy{
		{GroupID: 1, Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}, Tools: []string{"search_issues"}},
		{GroupID: 2, Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}, Tools: []string{"create_issue"}},
	}
	if !evaluate(policies, "tools/call", "search_issues").Allowed {
		t.Fatal("expected search_issues allowed via group 1")
	}
	if !evaluate(policies, "tools/call", "create_issue").Allowed {
		t.Fatal("expected create_issue allowed via group 2")
	}
	if evaluate(policies, "tools/call", "delete_issue").Allowed {
		t.Fatal("expected delete_issue still denied -- neither group granted it")
	}
}

func TestEvaluate_BlockOnScanFlagAppliesIfAnyMatchingAllowRequestsIt(t *testing.T) {
	policies := []store.Policy{
		{Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}, BlockOnScanFlag: false},
		{Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}, BlockOnScanFlag: true},
	}
	got := evaluate(policies, "tools/call", "search_issues")
	if !got.Allowed || !got.BlockOnScanFlag {
		t.Fatalf("expected allowed+block-on-scan-flag, got %+v", got)
	}
}

func TestEvaluate_RateLimitTakesTheMostRestrictiveMatchingAllow(t *testing.T) {
	ten, sixty := 10, 60
	five, thirty := 5, 30
	policies := []store.Policy{
		{Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}, RateLimitMaxCalls: &ten, RateLimitWindowSeconds: &sixty},
		{Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}, RateLimitMaxCalls: &five, RateLimitWindowSeconds: &thirty},
	}
	got := evaluate(policies, "tools/call", "search_issues")
	if got.RateLimitMaxCalls == nil || *got.RateLimitMaxCalls != 5 {
		t.Fatalf("RateLimitMaxCalls = %v, want the more restrictive 5", got.RateLimitMaxCalls)
	}
	if got.RateLimitWindowSeconds == nil || *got.RateLimitWindowSeconds != 30 {
		t.Fatalf("RateLimitWindowSeconds = %v, want 30", got.RateLimitWindowSeconds)
	}
}

func TestEvaluate_RateLimitComparesEffectiveRateNotJustMaxCalls(t *testing.T) {
	// Regression test: picking the smallest max_calls alone is wrong when
	// windows differ. 10/hour is far stricter overall than 2/sec, even
	// though 10 > 2 -- "most restrictive" has to mean the lower effective
	// rate (calls/window), not the smaller raw number.
	tenPerHour, hour := 10, 3600
	twoPerSec, sec := 2, 1
	policies := []store.Policy{
		{Node: "jira", RuleType: store.PolicyAllow, RateLimitMaxCalls: &tenPerHour, RateLimitWindowSeconds: &hour},
		{Node: "jira", RuleType: store.PolicyAllow, RateLimitMaxCalls: &twoPerSec, RateLimitWindowSeconds: &sec},
	}
	got := evaluate(policies, "tools/call", "search_issues")
	if got.RateLimitMaxCalls == nil || *got.RateLimitMaxCalls != 10 {
		t.Fatalf("RateLimitMaxCalls = %v, want the truly more restrictive 10 (10/hour beats 2/sec)", got.RateLimitMaxCalls)
	}
	if got.RateLimitWindowSeconds == nil || *got.RateLimitWindowSeconds != 3600 {
		t.Fatalf("RateLimitWindowSeconds = %v, want 3600", got.RateLimitWindowSeconds)
	}
}

func TestEvaluate_RateLimitTieBreaksOnMaxCallsWhenEffectiveRateEqual(t *testing.T) {
	// 1/60s and 10/600s have identical average rate but very different
	// burst allowances -- 1/60s permits far less burst, so it must win
	// the tie-break even though 10 > 1.
	onePerMinute, minute := 1, 60
	tenPerTenMinutes, tenMinutes := 10, 600
	policies := []store.Policy{
		{Node: "jira", RuleType: store.PolicyAllow, RateLimitMaxCalls: &tenPerTenMinutes, RateLimitWindowSeconds: &tenMinutes},
		{Node: "jira", RuleType: store.PolicyAllow, RateLimitMaxCalls: &onePerMinute, RateLimitWindowSeconds: &minute},
	}
	got := evaluate(policies, "tools/call", "search_issues")
	if got.RateLimitMaxCalls == nil || *got.RateLimitMaxCalls != 1 {
		t.Fatalf("RateLimitMaxCalls = %v, want the smaller-burst 1 to win the tie-break on equal effective rate", got.RateLimitMaxCalls)
	}
}

func TestEvaluate_NodeScopingIsCallerResponsibility(t *testing.T) {
	// evaluate itself doesn't filter by node -- PoliciesForGroups already
	// scopes the query by node before evaluate ever sees the rules. This
	// test documents that assumption: a rule for a different node, if it
	// somehow ended up in the slice, would still match here.
	policies := []store.Policy{
		{Node: "postgres-ro", RuleType: store.PolicyAllow},
	}
	if !evaluate(policies, "tools/call", "anything").Allowed {
		t.Fatal("evaluate does not itself check Node -- node-scoping happens at the store query layer (story 24)")
	}
}
