package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/policy"
)

// testBearerToken and fakeValidator stand in for a real authserver in
// every test below that isn't itself about authentication (session
// mapping, stdio routing, crash handling, ...) -- those get their own
// dedicated tests against a real *authserver.AuthServer further down.
// Likewise gw.policy is overridden back to AllowAll after construction:
// New's real default is policy.DenyAll{} (issue #3), correct for
// production, but these tests are isolating session/routing/stdio
// behavior, not policy enforcement.
const testBearerToken = "test-token"

type fakeValidator struct{}

func (fakeValidator) ValidateAccessToken(node, token string) (AuthClaims, error) {
	if token != testBearerToken {
		return AuthClaims{}, errors.New("fakeValidator: invalid token")
	}
	return AuthClaims{Subject: "user:test"}, nil
}

func authorize(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+testBearerToken)
}

// multiPrincipalValidator maps distinct bearer tokens to distinct
// principals, for tests that need two differently-authenticated callers
// (e.g. session hijack across principals) -- fakeValidator above
// collapses every valid token to the same "user:test" principal, which
// can't exercise that.
type multiPrincipalValidator map[string]string

func (v multiPrincipalValidator) ValidateAccessToken(node, token string) (AuthClaims, error) {
	subject, ok := v[token]
	if !ok {
		return AuthClaims{}, errors.New("multiPrincipalValidator: invalid token")
	}
	return AuthClaims{Subject: subject}, nil
}

func authorizeAs(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
}

func newStdioTestGateway(t *testing.T) *Gateway {
	t.Helper()
	cfg := &config.Config{
		Listen: ":0",
		Nodes: []config.Node{
			{
				Name:      "echo",
				Transport: config.TransportStdio,
				Command:   "go",
				Args:      []string{"run", "./stdioadapter/testdata/echoserver"},
			},
		},
	}
	gw, err := New(cfg, fakeValidator{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.policy = policy.AllowAll{}
	t.Cleanup(func() {
		if err := gw.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return gw
}

// fakeUpstreamServer is a real, minimal streamable_http MCP-shaped test
// upstream: it mints its own Mcp-Session-Id on initialize (as a real
// upstream MCP server would) and records whether/how many times DELETE
// was called for a given session, so tests can assert the gateway
// actually tears the upstream session down, not just its own mapping.
type fakeUpstreamServer struct {
	mu      sync.Mutex
	deleted map[string]int
	nextID  int
}

func newFakeUpstreamServer() (*httptest.Server, *fakeUpstreamServer) {
	f := &fakeUpstreamServer{deleted: make(map[string]int)}
	return httptest.NewServer(http.HandlerFunc(f.handle)), f
}

func (f *fakeUpstreamServer) deleteCount(sessionID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleted[sessionID]
}

func (f *fakeUpstreamServer) handle(w http.ResponseWriter, r *http.Request) {
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
		id := "upstream-session-" + strconv.Itoa(f.nextID)
		f.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", id)
	}

	w.Header().Set("Content-Type", "application/json")
	if req.Method == "tools/list" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]any{
				"tools": []map[string]any{
					{"name": "search_issues", "description": "search"},
					{"name": "delete_issue", "description": "delete"},
					{"name": "create_issue", "description": "create"},
				},
				"nextCursor": "page-2",
			},
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": req.ID,
		"result": map[string]any{"echo": req.Method},
	})
}

func newHTTPTestGateway(t *testing.T, upstreamURL string) *Gateway {
	return newHTTPTestGatewayWithValidator(t, upstreamURL, fakeValidator{})
}

func newHTTPTestGatewayWithValidator(t *testing.T, upstreamURL string, validator TokenValidator) *Gateway {
	t.Helper()
	cfg := &config.Config{
		Listen: ":0",
		Nodes: []config.Node{
			{Name: "jira", Transport: config.TransportStreamableHTTP, UpstreamURL: upstreamURL},
		},
	}
	gw, err := New(cfg, validator)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.policy = policy.AllowAll{}
	t.Cleanup(func() {
		if err := gw.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return gw
}

func initialize(t *testing.T, gw *Gateway, node string) (sessionID string, resp *httptest.ResponseRecorder) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/"+node+"/", strings.NewReader(body))
	authorize(req)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize failed: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	id := rec.Header().Get("Mcp-Session-Id")
	if id == "" {
		t.Fatal("expected a Mcp-Session-Id header on the initialize response")
	}
	return id, rec
}

func doWithSession(gw *Gateway, node, sessionID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp/"+node+"/", strings.NewReader(body))
	authorize(req)
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec
}

// TestGateway_StdioNodeRoutesLikeHTTPNode is the Phase 1 DoD for the stdio
// adapter: a real stdio MCP server (the echoserver fixture, spawned as a
// real child process) must be reachable through the exact same session
// lifecycle and request path -- /mcp/<node>/... -- as an HTTP-backed node.
func TestGateway_StdioNodeRoutesLikeHTTPNode(t *testing.T) {
	gw := newStdioTestGateway(t)
	sessionID, _ := initialize(t, gw, "echo")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`
	rec := doWithSession(gw, "echo", sessionID, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v, body: %s", err, rec.Body.String())
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in response: %v", resp)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("expected one content item, got: %v", result["content"])
	}
	item, _ := content[0].(map[string]any)
	if item["text"] != "hi" {
		t.Fatalf("echo mismatch, got %v", item["text"])
	}
}

// TestGateway_StdioNodeResponseIsScanned proves stdio nodes don't bypass
// the outbound DLP chain -- a real gap if left unscanned, since content
// inspection is a core part of what the gateway is for, not an HTTP-only
// nicety.
func TestGateway_StdioNodeResponseIsScanned(t *testing.T) {
	gw := newStdioTestGateway(t)
	sessionID, _ := initialize(t, gw, "echo")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"key AKIAABCDEFGHIJKLMNOP leaked"}}}`
	rec := doWithSession(gw, "echo", sessionID, body)

	if strings.Contains(rec.Body.String(), "AKIA") {
		t.Fatalf("secret leaked through an unscanned stdio response: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "[REDACTED:aws-access-key]") {
		t.Fatalf("expected a structural redaction marker, got: %s", rec.Body.String())
	}
}

func TestGateway_InitializeMintsOwnSessionID_NeverUpstreams(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL)

	sessionID, rec := initialize(t, gw, "jira")

	if strings.HasPrefix(sessionID, "upstream-session-") {
		t.Fatalf("gateway leaked the upstream's raw session ID to the client: %q", sessionID)
	}

	cookies := rec.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == sessionCookieName && c.Value == sessionID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a mirrored %s cookie matching the session header, got cookies: %v", sessionCookieName, cookies)
	}
}

func TestGateway_ContinuingRequestReachesSameUpstreamSession(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL)

	sessionID, _ := initialize(t, gw, "jira")

	rec := doWithSession(gw, "jira", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_UnknownSessionIDRejected(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL)

	rec := doWithSession(gw, "jira", "not-a-real-session", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGateway_MissingSessionOnNonInitializeRejected(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL)

	rec := doWithSession(gw, "jira", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestGateway_DeleteTearsDownUpstreamSessionAndRejectsReuse(t *testing.T) {
	upstream, fake := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL)

	sessionID, _ := initialize(t, gw, "jira")

	req := httptest.NewRequest(http.MethodDelete, "/mcp/jira/", nil)
	authorize(req)
	req.Header.Set("Mcp-Session-Id", sessionID)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Assert the *real upstream session* was torn down, not just the
	// gateway's own bookkeeping. The fake server mints deterministic IDs
	// starting at "upstream-session-1" for the first session it sees.
	if got := fake.deleteCount("upstream-session-1"); got != 1 {
		t.Fatalf("expected exactly one DELETE against the real upstream session, got %d", got)
	}

	// Reusing the now-dead gateway session ID must be rejected, not
	// silently treated as a fresh one.
	rec2 := doWithSession(gw, "jira", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}`)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("status after DELETE = %d, want %d", rec2.Code, http.StatusNotFound)
	}
}

// TestGateway_SessionRejectsRequestFromDifferentPrincipal is the session
// hijack regression: a session ID is only ever handed to the principal
// that minted it (over the response header/body on initialize), but
// nothing before this test stopped a *different*, independently
// authenticated principal from reusing it if they obtained it some other
// way (logs, a shared proxy, guessing) -- the only checks were "does this
// session exist" and "is it for this node," never "is it this caller's."
// A session must be rejected exactly like an unknown one (same 404, no
// distinguishing signal) for any principal other than the one that
// created it.
func TestGateway_SessionRejectsRequestFromDifferentPrincipal(t *testing.T) {
	const tokenOwner = "token-owner"
	const tokenAttacker = "token-attacker"
	validator := multiPrincipalValidator{
		tokenOwner:    "agent:owner",
		tokenAttacker: "agent:attacker",
	}
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGatewayWithValidator(t, upstream.URL, validator)

	initReq := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	authorizeAs(initReq, tokenOwner)
	initRec := httptest.NewRecorder()
	gw.ServeHTTP(initRec, initReq)
	if initRec.Code != http.StatusOK {
		t.Fatalf("initialize failed: status = %d, body = %s", initRec.Code, initRec.Body.String())
	}
	sessionID := initRec.Header().Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatal("expected a Mcp-Session-Id header on the initialize response")
	}

	hijackReq := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}`))
	authorizeAs(hijackReq, tokenAttacker)
	hijackReq.Header.Set("Mcp-Session-Id", sessionID)
	hijackRec := httptest.NewRecorder()
	gw.ServeHTTP(hijackRec, hijackReq)
	if hijackRec.Code != http.StatusNotFound {
		t.Fatalf("hijack attempt status = %d, want %d (same as unknown session, body = %s)", hijackRec.Code, http.StatusNotFound, hijackRec.Body.String())
	}

	// The legitimate owner's session must still be usable afterward --
	// rejecting the attacker must not have torn down or otherwise
	// disturbed the real owner's session.
	ownReq := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}`))
	authorizeAs(ownReq, tokenOwner)
	ownReq.Header.Set("Mcp-Session-Id", sessionID)
	ownRec := httptest.NewRecorder()
	gw.ServeHTTP(ownRec, ownReq)
	if ownRec.Code != http.StatusOK {
		t.Fatalf("owner's own follow-up request status = %d, want %d, body = %s", ownRec.Code, http.StatusOK, ownRec.Body.String())
	}
}

// TestGateway_DeleteRejectsSessionFromDifferentPrincipal is the DELETE
// counterpart: handleDelete's own comment already says "a caller who
// authenticated against this node may always end their own session" --
// the code didn't actually enforce "their own," so any principal valid
// for the node could end anyone else's session on it (a denial-of-service
// variant of the same hijack class). The attacker's DELETE must be
// rejected without tearing down the real owner's upstream session.
func TestGateway_DeleteRejectsSessionFromDifferentPrincipal(t *testing.T) {
	const tokenOwner = "token-owner"
	const tokenAttacker = "token-attacker"
	validator := multiPrincipalValidator{
		tokenOwner:    "agent:owner",
		tokenAttacker: "agent:attacker",
	}
	upstream, fake := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGatewayWithValidator(t, upstream.URL, validator)

	initReq := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	authorizeAs(initReq, tokenOwner)
	initRec := httptest.NewRecorder()
	gw.ServeHTTP(initRec, initReq)
	if initRec.Code != http.StatusOK {
		t.Fatalf("initialize failed: status = %d, body = %s", initRec.Code, initRec.Body.String())
	}
	sessionID := initRec.Header().Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatal("expected a Mcp-Session-Id header on the initialize response")
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/mcp/jira/", nil)
	authorizeAs(delReq, tokenAttacker)
	delReq.Header.Set("Mcp-Session-Id", sessionID)
	delRec := httptest.NewRecorder()
	gw.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusNotFound {
		t.Fatalf("attacker DELETE status = %d, want %d, body = %s", delRec.Code, http.StatusNotFound, delRec.Body.String())
	}
	if got := fake.deleteCount("upstream-session-1"); got != 0 {
		t.Fatalf("attacker's rejected DELETE must not reach the real upstream session, got %d calls", got)
	}

	ownReq := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}`))
	authorizeAs(ownReq, tokenOwner)
	ownReq.Header.Set("Mcp-Session-Id", sessionID)
	ownRec := httptest.NewRecorder()
	gw.ServeHTTP(ownRec, ownReq)
	if ownRec.Code != http.StatusOK {
		t.Fatalf("owner's session must survive the attacker's rejected DELETE: status = %d, body = %s", ownRec.Code, ownRec.Body.String())
	}
}

func TestGateway_StdioSessionDeleteKillsChildProcess(t *testing.T) {
	gw := newStdioTestGateway(t)
	sessionID, _ := initialize(t, gw, "echo")

	req := httptest.NewRequest(http.MethodDelete, "/mcp/echo/", nil)
	authorize(req)
	req.Header.Set("Mcp-Session-Id", sessionID)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// The session is gone; using it again must fail cleanly, not hang or
	// silently spawn a new process under the old ID.
	rec2 := doWithSession(gw, "echo", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("status after DELETE = %d, want %d, body = %s", rec2.Code, http.StatusNotFound, rec2.Body.String())
	}
}

// TestGateway_StdioCrashMidSessionFailsCleanlyThenSelfHeals uses the real
// crashserver fixture (initializes normally, then exits on its own) to
// prove an in-flight session whose process crashed fails the next request
// cleanly -- a JSON-RPC error, not a hang -- and that the gateway
// proactively cleans up the dead mapping so re-initializing works
// immediately, without requiring an explicit DELETE for an
// already-dead process.
func TestGateway_StdioCrashMidSessionFailsCleanlyThenSelfHeals(t *testing.T) {
	cfg := &config.Config{
		Listen: ":0",
		Nodes: []config.Node{
			{Name: "crash", Transport: config.TransportStdio, Command: "go", Args: []string{"run", "./stdioadapter/testdata/crashserver"}},
		},
	}
	gw, err := New(cfg, fakeValidator{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.policy = policy.AllowAll{}
	t.Cleanup(func() {
		if err := gw.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	sessionID, _ := initialize(t, gw, "crash")

	// Wait for the fixture to actually exit on its own (it does, ~150ms
	// after starting -- see testdata/crashserver) and for the gateway to
	// notice and self-heal. There's an inherent small race between the
	// process actually dying and the background watcher (stdioadapter's
	// Node.Alive) flipping -- a request landing in that window fails via
	// the SDK's own error path instead (session stays mapped a moment
	// longer); poll until the session is *definitively* gone (404) rather
	// than trying to catch the exact request that triggers self-heal.
	deadline := time.Now().Add(5 * time.Second)
	var lastCode int
	var lastBody string
	for time.Now().Before(deadline) {
		rec := doWithSession(gw, "crash", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
		lastCode, lastBody = rec.Code, rec.Body.String()
		if lastCode == http.StatusNotFound {
			break // self-heal completed: the dead session is gone
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lastCode != http.StatusNotFound {
		t.Fatalf("expected the crashed session to eventually be cleaned up (404), last status = %d, body = %s", lastCode, lastBody)
	}

	// A fresh initialize must work immediately -- the node itself isn't
	// quarantined just because one session's process died.
	newSessionID, _ := initialize(t, gw, "crash")
	if newSessionID == sessionID {
		t.Fatal("expected a brand new session id, not a reused one")
	}
}

// TestGateway_StdioSpawnFailureTriggersBackoffOnNextAttempt uses the real
// failserver fixture (a command that always fails to even start speaking
// MCP) to prove a spawn failure is actually recorded against the node's
// health and changes the *next* attempt's outcome -- from a generic spawn
// failure (502) to an explicit backoff response (503) -- rather than
// retrying identically forever. This is the wiring proof; the quarantine
// threshold and backoff-delay math themselves are exhaustively covered,
// without real waiting, by TestNodeHealth_Decide.
func TestGateway_StdioSpawnFailureTriggersBackoffOnNextAttempt(t *testing.T) {
	cfg := &config.Config{
		Listen: ":0",
		Nodes: []config.Node{
			{Name: "broken", Transport: config.TransportStdio, Command: "go", Args: []string{"run", "./stdioadapter/testdata/failserver"}},
		},
	}
	gw, err := New(cfg, fakeValidator{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.policy = policy.AllowAll{}
	t.Cleanup(func() {
		if err := gw.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	req1 := httptest.NewRequest(http.MethodPost, "/mcp/broken/", strings.NewReader(initBody))
	authorize(req1)
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusBadGateway {
		t.Fatalf("first attempt: status = %d, want %d (generic spawn failure), body = %s", rec1.Code, http.StatusBadGateway, rec1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/mcp/broken/", strings.NewReader(initBody))
	authorize(req2)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("second immediate attempt: status = %d, want %d (backoff), body = %s", rec2.Code, http.StatusServiceUnavailable, rec2.Body.String())
	}
}

// TestGateway_StdioNodeQuarantinedAfterRepeatedFailures drives nodeHealth
// directly to actually cross the quarantine threshold (proven exhaustively,
// timing-free, in TestNodeHealth_Decide), then verifies the Gateway
// actually consults that state and refuses a new session with 503 --
// completing the same wiring proof for the quarantine path that the
// backoff test above covers for backoff.
func TestGateway_StdioNodeQuarantinedAfterRepeatedFailures(t *testing.T) {
	cfg := &config.Config{
		Listen: ":0",
		Nodes: []config.Node{
			{Name: "broken", Transport: config.TransportStdio, Command: "go", Args: []string{"run", "./stdioadapter/testdata/failserver"}},
		},
	}
	gw, err := New(cfg, fakeValidator{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.policy = policy.AllowAll{}
	t.Cleanup(func() {
		if err := gw.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	h := gw.healthFor("broken")
	now := time.Now()
	for i := 0; i < crashQuarantineAfter; i++ {
		h.recordFailure(now)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp/broken/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	authorize(req)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d (quarantined), body = %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}
