package policy

import (
	"context"
	"testing"
)

func TestAllowAll_AlwaysAllows(t *testing.T) {
	ctx := context.Background()
	d := (AllowAll{}).Decide(ctx, "user:alice", "jira", "tools/call", "delete_issue")
	if !d.Allowed {
		t.Fatal("AllowAll should always allow")
	}
	tools := (AllowAll{}).FilterTools(ctx, "user:alice", "jira", []string{"a", "b"})
	if len(tools) != 2 {
		t.Fatalf("AllowAll.FilterTools should pass every tool through, got %v", tools)
	}
}

func TestDenyAll_AlwaysDenies(t *testing.T) {
	ctx := context.Background()
	d := (DenyAll{}).Decide(ctx, "user:alice", "jira", "tools/call", "search_issues")
	if d.Allowed {
		t.Fatal("DenyAll should always deny")
	}
	tools := (DenyAll{}).FilterTools(ctx, "user:alice", "jira", []string{"a", "b"})
	if len(tools) != 0 {
		t.Fatalf("DenyAll.FilterTools should return nothing, got %v", tools)
	}
}
