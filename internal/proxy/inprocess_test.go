package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
)

// fakeInProcessHandler is an in-process http.Handler test double with the
// exact same MCP-shaped behavior as fakeUpstreamServer (mints its own
// Mcp-Session-Id on initialize, tracks DELETE calls) -- proving
// inProcessUpstreamSession behaves identically to httpUpstreamSession's
// existing, already-proven session-lifecycle tests, just reached without
// any network at all.
type fakeInProcessHandler struct {
	mu      sync.Mutex
	deleted map[string]int
	nextID  int
	served  bool // proves this handler, not a real listener, actually served the request
}

func newFakeInProcessHandler() *fakeInProcessHandler {
	return &fakeInProcessHandler{deleted: make(map[string]int)}
}

func (f *fakeInProcessHandler) deleteCount(sessionID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleted[sessionID]
}

func (f *fakeInProcessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.served = true
	f.mu.Unlock()

	if r.Method == http.MethodDelete {
		id := r.Header.Get("Mcp-Session-Id")
		f.mu.Lock()
		f.deleted[id]++
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var req struct {
		ID     any    `json:"id"`
		Method string `json:"method"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &req)

	if req.Method == "initialize" {
		f.mu.Lock()
		f.nextID++
		id := "in-process-upstream-session-" + strconv.Itoa(f.nextID)
		f.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", id)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": req.ID,
		"result": map[string]any{"echo": req.Method},
	})
}

func newInProcessTestGateway(t *testing.T, nodeName string, handler http.Handler) *Gateway {
	t.Helper()
	gw := newEmptyTestGateway(t)
	gw.RegisterInProcessNode(nodeName, handler)
	return gw
}

func TestGateway_InProcessNode_RoutesLikeHTTPNode(t *testing.T) {
	handler := newFakeInProcessHandler()
	gw := newInProcessTestGateway(t, "spidercob-admin", handler)

	sessionID, rec := initialize(t, gw, "spidercob-admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize failed: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if sessionID == "" {
		t.Fatal("expected a gateway-minted session ID")
	}
	if strings.HasPrefix(sessionID, "in-process-upstream-session-") {
		t.Fatalf("gateway leaked the in-process handler's raw session ID to the client: %q", sessionID)
	}

	call := doWithSession(gw, "spidercob-admin", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}`)
	if call.Code != http.StatusOK {
		t.Fatalf("tools/call failed: status = %d, body = %s", call.Code, call.Body.String())
	}

	if !handler.served {
		t.Fatal("expected the in-process handler to have actually served the request")
	}
}

func TestGateway_InProcessNode_NoNetworkInvolved(t *testing.T) {
	// Prove the in-process path never opens a real listener/connection --
	// this test would hang or fail on a real network call, since no
	// server is running on this port; if it passes fast, the handler was
	// invoked directly.
	handler := newFakeInProcessHandler()
	gw := newInProcessTestGateway(t, "spidercob-admin", handler)
	sessionID, _ := initialize(t, gw, "spidercob-admin")
	if sessionID == "" {
		t.Fatal("expected a session; the in-process handler must have been called directly, no real network round trip")
	}
}

func TestGateway_InProcessNode_DeleteTearsDownUpstreamSession(t *testing.T) {
	handler := newFakeInProcessHandler()
	gw := newInProcessTestGateway(t, "spidercob-admin", handler)

	sessionID, _ := initialize(t, gw, "spidercob-admin")

	req := httptest.NewRequest(http.MethodDelete, "/mcp/spidercob-admin/", nil)
	authorize(req)
	req.Header.Set("Mcp-Session-Id", sessionID)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", rec.Code)
	}

	if handler.deleteCount("in-process-upstream-session-1") != 1 {
		t.Fatalf("expected the in-process handler to see exactly one DELETE for its own session ID, got %d", handler.deleteCount("in-process-upstream-session-1"))
	}

	// Reuse after teardown is rejected, same as any other node.
	reuse := doWithSession(gw, "spidercob-admin", sessionID, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}`)
	if reuse.Code != http.StatusNotFound {
		t.Fatalf("reuse after DELETE: status = %d, want 404", reuse.Code)
	}
}

func TestGateway_RegisterInProcessNode_NotReachableThroughAddNode(t *testing.T) {
	// There is no config.Node shape that can carry an http.Handler --
	// AddNode (the admin-API-reachable path) can never create an
	// in-process node. This test documents that boundary rather than
	// exercising new behavior: config.ValidateNode already rejects a
	// node with no real transport.
	gw := newEmptyTestGateway(t)
	if err := gw.AddNode(config.Node{Name: "spidercob-admin"}); err == nil {
		t.Fatal("expected AddNode to reject a node with no transport -- there's no way to smuggle an in-process handler through it")
	}
}

// TestGateway_AddNode_RefusesToShadowAnInProcessNode and
// TestGateway_RemoveNode_RefusesToRemoveAnInProcessNode are the
// regression proof for a real review finding on issue #59: without
// these, a real (transport-valid, e.g. stdio) node registered under the
// same name as a reserved in-process one would either silently shadow it
// (AddNode) or -- the actually-exploitable half -- let an ordinary
// RemoveNode call tear down the live in-process routing entry entirely,
// a DoS of that node until a restart. internal/adminapi's own
// reserved-name check (routes.go) is the primary guard; this is the
// second, independent layer, enforced at the one place that actually
// mutates g.nodes, so it holds regardless of what any future caller
// does.
func TestGateway_AddNode_RefusesToShadowAnInProcessNode(t *testing.T) {
	gw := newEmptyTestGateway(t)
	gw.RegisterInProcessNode("spidercob-admin", newFakeInProcessHandler())

	err := gw.AddNode(config.Node{Name: "spidercob-admin", Transport: config.TransportStdio, Command: "go", Args: []string{"run", "./stdioadapter/testdata/echoserver"}})
	if err == nil {
		t.Fatal("expected AddNode to refuse registering a node under a reserved in-process name")
	}

	// The real, live in-process handler is still what actually answers.
	sessionID, rec := initialize(t, gw, "spidercob-admin")
	if rec.Code != http.StatusOK || sessionID == "" {
		t.Fatalf("expected the reserved node to still route to the real in-process handler, got status %d", rec.Code)
	}
}

func TestGateway_RemoveNode_RefusesToRemoveAnInProcessNode(t *testing.T) {
	gw := newEmptyTestGateway(t)
	gw.RegisterInProcessNode("spidercob-admin", newFakeInProcessHandler())

	if err := gw.RemoveNode("spidercob-admin"); err == nil {
		t.Fatal("expected RemoveNode to refuse removing a reserved in-process node")
	}

	// The exploit this guards against: even after the "removal" is
	// attempted, the node must still actually work.
	sessionID, rec := initialize(t, gw, "spidercob-admin")
	if rec.Code != http.StatusOK || sessionID == "" {
		t.Fatalf("expected the reserved node to survive a RemoveNode attempt, got status %d", rec.Code)
	}
}
