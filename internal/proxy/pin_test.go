package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/pin"
	"github.com/sumeetgp/spidercob-gateway/internal/policy"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// newPinTestEnv is newHTTPTestGateway plus a real, store-backed
// pin.Registry wired into the Gateway -- issue #9's primary seam:
// Gateway.ServeHTTP end-to-end, real registry, real store data, not a
// fake. policy is left at AllowAll so these tests isolate pinning
// behavior specifically, the same posture policy_test.go's
// newPolicyTestEnv takes for policy.
func newPinTestEnv(t *testing.T, upstreamURL, nodeName string) (*Gateway, store.Store, *pin.Registry) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	cfg := &config.Config{
		Listen: ":0",
		Nodes: []config.Node{
			{Name: nodeName, Transport: config.TransportStreamableHTTP, UpstreamURL: upstreamURL},
		},
	}
	gw, err := New(cfg, fakeValidator{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.policy = policy.AllowAll{}
	reg := pin.NewRegistry(s)
	gw.SetPinRegistry(reg)
	t.Cleanup(func() {
		if err := gw.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return gw, s, reg
}

func TestGateway_QuarantinedToolCallRejectedWith403(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw, _, reg := newPinTestEnv(t, upstream.URL, "jira")
	ctx := context.Background()

	// Establish a pin, then observe a drifted definition -- exactly the
	// TOFU-then-drift sequence the real background scheduler would
	// produce, just driven directly here instead of through a fake
	// Fetcher and real time.
	original := pin.ToolDef{Name: "delete_issue", Description: "delete", InputSchema: []byte(`{}`)}
	if err := reg.Observe(ctx, "jira", []pin.ToolDef{original}); err != nil {
		t.Fatalf("Observe (establish): %v", err)
	}
	drifted := original
	drifted.Description = "delete an issue AND wipe the whole project"
	if err := reg.Observe(ctx, "jira", []pin.ToolDef{drifted}); err != nil {
		t.Fatalf("Observe (drift): %v", err)
	}

	sessionID, _ := initialize(t, gw, "jira")
	rec := doWithSession(gw, "jira", sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_issue","arguments":{}}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (quarantined tool), body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_PinnedNonDriftedToolCallSucceeds(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw, _, reg := newPinTestEnv(t, upstream.URL, "jira")
	ctx := context.Background()

	def := pin.ToolDef{Name: "search_issues", Description: "search", InputSchema: []byte(`{}`)}
	if err := reg.Observe(ctx, "jira", []pin.ToolDef{def}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	sessionID, _ := initialize(t, gw, "jira")
	rec := doWithSession(gw, "jira", sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_issues","arguments":{}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (pinned, no drift), body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_NeverObservedToolCallStillSucceeds(t *testing.T) {
	// A tool with no pin at all (the background refresher hasn't observed
	// it yet) must not be blocked by that absence -- TOFU establishes
	// trust, it doesn't gate access pending its own first observation.
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw, _, _ := newPinTestEnv(t, upstream.URL, "jira")

	sessionID, _ := initialize(t, gw, "jira")
	rec := doWithSession(gw, "jira", sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_issues","arguments":{}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no pin yet is not quarantine), body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_ToolsListFiltersQuarantinedTools(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw, _, reg := newPinTestEnv(t, upstream.URL, "jira")
	ctx := context.Background()

	// newFakeUpstreamServer's tools/list always returns search_issues,
	// delete_issue, create_issue -- pin and then drift just delete_issue.
	original := pin.ToolDef{Name: "delete_issue", Description: "delete", InputSchema: []byte(`{}`)}
	if err := reg.Observe(ctx, "jira", []pin.ToolDef{original}); err != nil {
		t.Fatalf("Observe (establish): %v", err)
	}
	drifted := original
	drifted.Description = "delete an issue AND wipe the whole project"
	if err := reg.Observe(ctx, "jira", []pin.ToolDef{drifted}); err != nil {
		t.Fatalf("Observe (drift): %v", err)
	}

	sessionID, _ := initialize(t, gw, "jira")
	rec := doWithSession(gw, "jira", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v, body: %s", err, rec.Body.String())
	}
	var names []string
	for _, tool := range resp.Result.Tools {
		names = append(names, tool.Name)
	}
	if len(names) != 2 || !contains(names, "search_issues") || !contains(names, "create_issue") {
		t.Fatalf("tools = %v, want exactly [search_issues, create_issue]", names)
	}
	if contains(names, "delete_issue") {
		t.Fatalf("delete_issue must be invisible (quarantined), got tools = %v", names)
	}
}

func TestGateway_NoRegistryConfiguredNeverQuarantinesAnything(t *testing.T) {
	// A Gateway that never got SetPinRegistry called on it (pinning
	// disabled) must behave exactly as it did before issue #9 -- no nil
	// pointer panics, no unexpected blocks.
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL) // no SetPinRegistry call

	sessionID, _ := initialize(t, gw, "jira")
	rec := doWithSession(gw, "jira", sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_issue","arguments":{}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (pinning disabled by default), body = %s", rec.Code, rec.Body.String())
	}
}
