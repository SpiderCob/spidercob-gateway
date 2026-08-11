package adminapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
	"github.com/sumeetgp/spidercob-gateway/internal/uisession"
)

// fakeMCPSessionManager is a hand-rolled MCPSessionManager for testing
// (issue #35, kill-session) -- mirrors fakeIntrospector/
// fakeAdminTokenValidator's existing "hand-rolled fake for this package's
// own interface" pattern, so these tests never need a real
// *proxy.Gateway.
type fakeMCPSessionManager struct {
	mu       sync.Mutex
	sessions []SessionInfo
	ended    []string
	endErr   error
}

func (f *fakeMCPSessionManager) ListSessions() []SessionInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]SessionInfo, len(f.sessions))
	copy(out, f.sessions)
	return out
}

func (f *fakeMCPSessionManager) EndSession(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.endErr != nil {
		return f.endErr
	}
	for _, s := range f.sessions {
		if s.ID == id {
			f.ended = append(f.ended, id)
			return nil
		}
	}
	return ErrSessionNotFound
}

func (f *fakeMCPSessionManager) endedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.ended))
	copy(out, f.ended)
	return out
}

func newFakeMCPSessionManager() *fakeMCPSessionManager {
	return &fakeMCPSessionManager{}
}

// newTestAdminAPIWithMCPSessions mirrors newTestAdminAPIWithSessions
// (uisession_test.go), just customizing MCPSessions instead of
// UISessions -- the two "session" concepts this codebase deliberately
// keeps distinct (browser admin-UI login vs. live MCP traffic sessions).
func newTestAdminAPIWithMCPSessions(t *testing.T, authn AdminTokenValidator, introspector SpiderSnoopIntrospector, mcpSessions MCPSessionManager) (*AdminAPI, store.Store) {
	t.Helper()
	uiSessions := uisession.NewRegistry(uisession.RegistryConfig{MaxAge: time.Hour})
	return newTestAdminAPIFull(t, authn, introspector, uiSessions, mcpSessions)
}

// newTestAdminAPIFull lets a test customize both session concepts at
// once -- needed for the cookie-auth tests below, which need a real
// uisession.Registry to actually log in through and a fake
// MCPSessionManager to assert against.
func newTestAdminAPIFull(t *testing.T, authn AdminTokenValidator, introspector SpiderSnoopIntrospector, uiSessions *uisession.Registry, mcpSessions MCPSessionManager) (*AdminAPI, store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.NewService(s)
	api, err := New(Config{Store: s, Identity: svc, Authn: authn, Introspector: introspector, UISessions: uiSessions, MCPSessions: mcpSessions})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return api, s
}

func TestListSessions_EmptyReturnsEmptyList(t *testing.T) {
	api, _ := newTestAdminAPIWithMCPSessions(t, validAdminAuthn(), adminIntrospector(), newFakeMCPSessionManager())
	rec := fullyAuthedRequest(api, "GET", "/admin/sessions", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "[]\n" {
		t.Fatalf("body = %q, want an empty JSON array", rec.Body.String())
	}
}

func TestListSessions_ReturnsWhatTheSessionManagerReports(t *testing.T) {
	idle := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := &fakeMCPSessionManager{sessions: []SessionInfo{
		{ID: "sess-1", Node: "jira", Principal: "agent:ci-bot", IdleSince: idle},
	}}
	api, _ := newTestAdminAPIWithMCPSessions(t, validAdminAuthn(), adminIntrospector(), mgr)

	rec := fullyAuthedRequest(api, "GET", "/admin/sessions", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"id":"sess-1"`, `"node":"jira"`, `"principal":"agent:ci-bot"`, `"idle_since":"2026-01-01T00:00:00Z"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body = %s, want it to contain %s", body, want)
		}
	}
}

func TestKillSession_Succeeds(t *testing.T) {
	mgr := &fakeMCPSessionManager{sessions: []SessionInfo{{ID: "sess-1", Node: "jira", Principal: "agent:ci-bot"}}}
	api, _ := newTestAdminAPIWithMCPSessions(t, validAdminAuthn(), adminIntrospector(), mgr)

	rec := fullyAuthedRequest(api, "DELETE", "/admin/sessions/sess-1", nil)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	if ids := mgr.endedIDs(); len(ids) != 1 || ids[0] != "sess-1" {
		t.Fatalf("endedIDs = %v, want [sess-1]", ids)
	}
}

func TestKillSession_UnknownIDReturns404(t *testing.T) {
	api, _ := newTestAdminAPIWithMCPSessions(t, validAdminAuthn(), adminIntrospector(), newFakeMCPSessionManager())

	rec := fullyAuthedRequest(api, "DELETE", "/admin/sessions/never-existed", nil)
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestKillSession_LogsAdminAction(t *testing.T) {
	mgr := &fakeMCPSessionManager{sessions: []SessionInfo{{ID: "sess-1", Node: "jira"}}}
	api, s := newTestAdminAPIWithMCPSessions(t, validAdminAuthn(), adminIntrospector(), mgr)

	rec := fullyAuthedRequest(api, "DELETE", "/admin/sessions/sess-1", nil)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}

	records, err := s.ListAuditRecords(context.Background())
	if err != nil {
		t.Fatalf("ListAuditRecords: %v", err)
	}
	if len(records) != 1 || records[0].Action != "kill_session" || records[0].Resource != "sess-1" {
		t.Fatalf("audit records = %+v, want one kill_session record for sess-1", records)
	}
}

func TestListSessions_MissingCredentialsRejected(t *testing.T) {
	api, _ := newTestAdminAPIWithMCPSessions(t, validAdminAuthn(), adminIntrospector(), newFakeMCPSessionManager())
	rec := doAdminRequest(api, "GET", "/admin/sessions", reqOpts{})
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestKillSession_MissingCredentialsRejected(t *testing.T) {
	api, _ := newTestAdminAPIWithMCPSessions(t, validAdminAuthn(), adminIntrospector(), newFakeMCPSessionManager())
	rec := doAdminRequest(api, "DELETE", "/admin/sessions/sess-1", reqOpts{})
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestListSessions_NonAdminRoleRejected(t *testing.T) {
	introspector := &fakeIntrospector{result: IntrospectionResult{Username: "bob", Role: "analyst"}}
	api, _ := newTestAdminAPIWithMCPSessions(t, validAdminAuthn(), introspector, newFakeMCPSessionManager())
	rec := fullyAuthedRequest(api, "GET", "/admin/sessions", nil)
	if rec.Code != 403 {
		t.Fatalf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestListSessions_CookieAloneSucceeds(t *testing.T) {
	mgr := &fakeMCPSessionManager{sessions: []SessionInfo{{ID: "sess-1", Node: "jira"}}}
	uiSessions := uisession.NewRegistry(uisession.RegistryConfig{MaxAge: time.Hour})
	api, _ := newTestAdminAPIFull(t, validAdminAuthn(), adminIntrospector(), uiSessions, mgr)

	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := fullyAuthedRequest(api, "POST", "/admin/ui/session", loginBody)
	cookie := sessionCookieFrom(loginRec)
	if cookie == nil {
		t.Fatal("expected a session cookie from login")
	}

	rec := doRawRequest(api, "GET", "/admin/sessions", nil, cookie)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
}

func TestKillSession_CookieAloneSucceeds(t *testing.T) {
	mgr := &fakeMCPSessionManager{sessions: []SessionInfo{{ID: "sess-1", Node: "jira"}}}
	uiSessions := uisession.NewRegistry(uisession.RegistryConfig{MaxAge: time.Hour})
	api, _ := newTestAdminAPIFull(t, validAdminAuthn(), adminIntrospector(), uiSessions, mgr)

	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := fullyAuthedRequest(api, "POST", "/admin/ui/session", loginBody)
	cookie := sessionCookieFrom(loginRec)
	if cookie == nil {
		t.Fatal("expected a session cookie from login")
	}

	rec := doRawRequest(api, "DELETE", "/admin/sessions/sess-1", nil, cookie)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
}
