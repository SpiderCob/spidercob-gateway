package proxy

import (
	"context"
	"errors"
	"testing"
)

// TestGateway_ListSessionsReflectsLiveMCPSessions is the Gateway-level
// counterpart to TestSessionManager_ListReturnsLiveSessionsWithPrincipalAndNode
// -- proving the admin-facing surface (issue #35, kill-session) actually
// reflects a real session established through the real ServeHTTP routing
// path, not just sessionManager in isolation.
func TestGateway_ListSessionsReflectsLiveMCPSessions(t *testing.T) {
	gw := newStdioTestGateway(t)

	if got := gw.ListSessions(); len(got) != 0 {
		t.Fatalf("ListSessions before any session exists = %+v, want empty", got)
	}

	sessionID, _ := initialize(t, gw, "echo")

	got := gw.ListSessions()
	if len(got) != 1 {
		t.Fatalf("ListSessions = %+v, want exactly 1", got)
	}
	if got[0].ID != sessionID {
		t.Fatalf("ID = %q, want %q", got[0].ID, sessionID)
	}
	if got[0].Node != "echo" {
		t.Fatalf("Node = %q, want echo", got[0].Node)
	}
	if got[0].Principal != "user:test" {
		t.Fatalf("Principal = %q, want user:test (see fakeValidator)", got[0].Principal)
	}
}

// TestGateway_EndSessionTearsDownRealStdioProcess is the DoD analogue for
// kill-session that MASTER_PLAN.md already set for session mapping itself
// ("killing a session server-side actually terminates the upstream
// connection or child process -- verified against both an HTTP node and a
// stdio node"): EndSession must actually reach the same teardown path a
// session's own owner already gets via DELETE /mcp/{node}, not just stop
// listing it.
func TestGateway_EndSessionTearsDownRealStdioProcess(t *testing.T) {
	gw := newStdioTestGateway(t)
	sessionID, _ := initialize(t, gw, "echo")

	if err := gw.EndSession(context.Background(), sessionID); err != nil {
		t.Fatalf("EndSession: %v", err)
	}

	if got := gw.ListSessions(); len(got) != 0 {
		t.Fatalf("ListSessions after EndSession = %+v, want empty", got)
	}

	// A request bearing the now-dead session ID must be rejected exactly
	// like it already is after a self-initiated DELETE -- never mistaken
	// for a fresh one.
	rec := doWithSession(gw, "echo", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	if rec.Code != 404 {
		t.Fatalf("status after EndSession = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

// TestGateway_EndSessionTearsDownRealUpstreamHTTPSession is
// TestGateway_EndSessionTearsDownRealStdioProcess's streamable_http
// counterpart -- MASTER_PLAN.md's own DoD bar for session teardown
// ("verified against both an HTTP node and a stdio node") applies just as
// much to this admin-initiated door onto it.
func TestGateway_EndSessionTearsDownRealUpstreamHTTPSession(t *testing.T) {
	upstream, fake := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL)

	sessionID, _ := initialize(t, gw, "jira")

	if err := gw.EndSession(context.Background(), sessionID); err != nil {
		t.Fatalf("EndSession: %v", err)
	}

	// Assert the *real upstream session* was torn down via a real DELETE,
	// not just the gateway's own bookkeeping.
	if got := fake.deleteCount("upstream-session-1"); got != 1 {
		t.Fatalf("expected exactly one DELETE against the real upstream session, got %d", got)
	}
	if got := gw.ListSessions(); len(got) != 0 {
		t.Fatalf("ListSessions after EndSession = %+v, want empty", got)
	}

	rec := doWithSession(gw, "jira", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}`)
	if rec.Code != 404 {
		t.Fatalf("status after EndSession = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_EndSessionUnknownIDReturnsErrSessionNotFound(t *testing.T) {
	gw := newStdioTestGateway(t)

	err := gw.EndSession(context.Background(), "never-existed")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("EndSession on unknown id: err = %v, want ErrSessionNotFound", err)
	}
}
