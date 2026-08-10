package proxy

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/sumeetgp/spidercob-gateway/internal/pin"
)

func TestGateway_SchemaValidCallSucceeds(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw, _, reg := newPinTestEnv(t, upstream.URL, "jira")
	ctx := context.Background()

	def := pin.ToolDef{
		Name:        "search_issues",
		Description: "search",
		InputSchema: []byte(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`),
	}
	if err := reg.Observe(ctx, "jira", []pin.ToolDef{def}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	sessionID, _ := initialize(t, gw, "jira")
	rec := doWithSession(gw, "jira", sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_issues","arguments":{"query":"open tickets"}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (schema-valid call), body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_SchemaInvalidCallRejected(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw, _, reg := newPinTestEnv(t, upstream.URL, "jira")
	ctx := context.Background()

	def := pin.ToolDef{
		Name:        "search_issues",
		Description: "search",
		InputSchema: []byte(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`),
	}
	if err := reg.Observe(ctx, "jira", []pin.ToolDef{def}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	sessionID, _ := initialize(t, gw, "jira")
	// Missing the required "query" argument entirely.
	rec := doWithSession(gw, "jira", sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_issues","arguments":{}}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (schema-invalid call), body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "pinned schema") {
		t.Fatalf("rejection reason should be distinguishable as a schema violation, got: %s", rec.Body.String())
	}
	// Regression test: the gateway's own wrapper text used to prepend
	// "...pinned schema" on top of ValidateArguments' error, which
	// already carries its own "...pinned schema" wording -- producing a
	// duplicated, awkward message.
	if n := strings.Count(rec.Body.String(), "pinned schema"); n != 1 {
		t.Fatalf("expected \"pinned schema\" to appear exactly once (not duplicated), got %d times: %s", n, rec.Body.String())
	}
}

func TestGateway_SchemaEnforcement_WrongArgumentTypeRejected(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw, _, reg := newPinTestEnv(t, upstream.URL, "jira")
	ctx := context.Background()

	def := pin.ToolDef{
		Name:        "search_issues",
		Description: "search",
		InputSchema: []byte(`{"type":"object","properties":{"limit":{"type":"integer"}}}`),
	}
	if err := reg.Observe(ctx, "jira", []pin.ToolDef{def}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	sessionID, _ := initialize(t, gw, "jira")
	rec := doWithSession(gw, "jira", sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_issues","arguments":{"limit":"not a number"}}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (wrong argument type), body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_SchemaEnforcement_NoPinYetNeverBlocks(t *testing.T) {
	// A tool the background refresher hasn't observed yet (no pin at all)
	// must never be blocked by schema enforcement -- there's nothing to
	// validate against yet (story 23).
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw, _, _ := newPinTestEnv(t, upstream.URL, "jira")

	sessionID, _ := initialize(t, gw, "jira")
	rec := doWithSession(gw, "jira", sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_issues","arguments":{"anything":"goes"}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no pin yet, nothing to validate against), body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_SchemaEnforcement_PinnedWithNoInputSchemaNeverBlocks(t *testing.T) {
	// A tool that was pinned but genuinely takes no structured arguments
	// (no InputSchema at observation time) must never be blocked either
	// (story 23) -- distinct from "no pin exists," but the same
	// treatment.
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw, _, reg := newPinTestEnv(t, upstream.URL, "jira")
	ctx := context.Background()

	def := pin.ToolDef{Name: "search_issues", Description: "search"} // no InputSchema
	if err := reg.Observe(ctx, "jira", []pin.ToolDef{def}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	sessionID, _ := initialize(t, gw, "jira")
	rec := doWithSession(gw, "jira", sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_issues","arguments":{"anything":"goes"}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (pinned tool with no inputSchema), body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_SchemaEnforcement_NoRegistryConfiguredNeverBlocks(t *testing.T) {
	// Pinning disabled entirely (no SetPinRegistry call) must behave
	// exactly as it did before issue #11 -- same nil-safety posture
	// already established for quarantine checks in issue #9.
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL) // no SetPinRegistry call

	sessionID, _ := initialize(t, gw, "jira")
	rec := doWithSession(gw, "jira", sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_issues","arguments":{"anything":"goes"}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (pinning disabled by default), body = %s", rec.Code, rec.Body.String())
	}
}
