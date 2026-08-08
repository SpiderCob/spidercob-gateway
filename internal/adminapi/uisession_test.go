package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
	"github.com/sumeetgp/spidercob-gateway/internal/uisession"
)

// newTestAdminAPIWithSessions is newTestAdminAPI plus an explicit
// *uisession.Registry, so tests that need to control session-expiry
// timing can inject a fake-clock registry the same way pin's
// scheduler tests inject a fake clock.
func newTestAdminAPIWithSessions(t *testing.T, authn AdminTokenValidator, introspector SpiderSnoopIntrospector, sessions *uisession.Registry) (*AdminAPI, store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.NewService(s)
	api, err := New(Config{Store: s, Identity: svc, Authn: authn, Introspector: introspector, UISessions: sessions})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return api, s
}

func doRawRequest(api *AdminAPI, method, path string, body []byte, cookie *http.Cookie) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	api.Routes().ServeHTTP(rec, req)
	return rec
}

func sessionCookieFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == UISessionCookieName {
			return c
		}
	}
	return nil
}

// --- POST /admin/ui/session (login) ---

func TestCreateUISession_ValidTokenSucceedsAndSetsCookie(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	body, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	rec := doRawRequest(api, "POST", "/admin/ui/session", body, nil)

	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookieFrom(rec)
	if cookie == nil {
		t.Fatal("no session cookie set on successful login")
	}
	if !cookie.HttpOnly {
		t.Fatal("session cookie is not HttpOnly")
	}
	if cookie.Value == "" {
		t.Fatal("session cookie has an empty value")
	}

	var resp uiSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Username != "alice" || resp.Role != "admin" {
		t.Fatalf("response = %+v, want username alice, role admin", resp)
	}
}

func TestCreateUISession_MissingTokenRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	body, _ := json.Marshal(createUISessionRequest{})
	rec := doRawRequest(api, "POST", "/admin/ui/session", body, nil)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCreateUISession_IntrospectionErrorFailsClosed(t *testing.T) {
	introspector := &fakeIntrospector{err: errors.New("spider-snoop unreachable")}
	api, _ := newTestAdminAPI(t, validAdminAuthn(), introspector)
	body, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	rec := doRawRequest(api, "POST", "/admin/ui/session", body, nil)
	if rec.Code != 503 {
		t.Fatalf("status = %d, want 503 (fail closed), body = %s", rec.Code, rec.Body.String())
	}
	if sessionCookieFrom(rec) != nil {
		t.Fatal("a cookie was set despite a failed introspection")
	}
}

func TestCreateUISession_NonAdminRoleRejected(t *testing.T) {
	introspector := &fakeIntrospector{result: IntrospectionResult{Username: "bob", Role: "analyst"}}
	api, _ := newTestAdminAPI(t, validAdminAuthn(), introspector)
	body, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	rec := doRawRequest(api, "POST", "/admin/ui/session", body, nil)
	if rec.Code != 403 {
		t.Fatalf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
	if sessionCookieFrom(rec) != nil {
		t.Fatal("a cookie was set despite a non-admin role")
	}
}

// --- GET /admin/ui/session (whoami) ---

func TestGetUISession_NoCookieRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := doRawRequest(api, "GET", "/admin/ui/session", nil, nil)
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGetUISession_ValidCookieSucceeds(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", loginBody, nil)
	cookie := sessionCookieFrom(loginRec)
	if cookie == nil {
		t.Fatal("login did not set a cookie")
	}

	rec := doRawRequest(api, "GET", "/admin/ui/session", nil, cookie)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp uiSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Username != "alice" || resp.Role != "admin" {
		t.Fatalf("response = %+v, want username alice, role admin", resp)
	}
}

func TestGetUISession_UnknownCookieRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := doRawRequest(api, "GET", "/admin/ui/session", nil, &http.Cookie{Name: UISessionCookieName, Value: "never-issued"})
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

// --- DELETE /admin/ui/session (logout) ---

func TestDeleteUISession_InvalidatesCookie(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", loginBody, nil)
	cookie := sessionCookieFrom(loginRec)

	logoutRec := doRawRequest(api, "DELETE", "/admin/ui/session", nil, cookie)
	if logoutRec.Code != 204 {
		t.Fatalf("logout status = %d, want 204, body = %s", logoutRec.Code, logoutRec.Body.String())
	}

	rec := doRawRequest(api, "GET", "/admin/ui/session", nil, cookie)
	if rec.Code != 401 {
		t.Fatalf("status after logout = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

// --- Cookie path is additive on agents/groups/policies/nodes (issue #19: nodes joined the rest in this issue) ---

func TestCookieAuth_ValidCookieAloneSucceedsOnAgents(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", loginBody, nil)
	cookie := sessionCookieFrom(loginRec)

	rec := doRawRequest(api, "GET", "/admin/agents", nil, cookie)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (cookie alone, no NHI token), body = %s", rec.Code, rec.Body.String())
	}
}

// --- Cookie path on nodes (issue #19) ---

func TestCookieAuth_ValidCookieAloneSucceedsOnListNodes(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", loginBody, nil)
	cookie := sessionCookieFrom(loginRec)

	rec := doRawRequest(api, "GET", "/admin/nodes", nil, cookie)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (cookie alone now succeeds on nodes, issue #19), body = %s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuth_ValidCookieAloneCanCreateNode(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", loginBody, nil)
	cookie := sessionCookieFrom(loginRec)

	body, _ := json.Marshal(createNodeRequest{Name: "cookie-created", Transport: "streamable_http", UpstreamURL: "http://a"})
	rec := doRawRequest(api, "POST", "/admin/nodes", body, cookie)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuth_ValidCookieAloneCanDeleteAdminSourcedNode(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	if _, err := s.CreateNode(context.Background(), store.Node{Name: "throwaway", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://a"), Source: store.NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", loginBody, nil)
	cookie := sessionCookieFrom(loginRec)

	rec := doRawRequest(api, "DELETE", "/admin/nodes/throwaway", nil, cookie)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuth_ValidCookieAloneRefusedDeletingConfigSourcedNode(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	if _, err := s.UpsertConfigNode(context.Background(), store.Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://a")}); err != nil {
		t.Fatalf("UpsertConfigNode: %v", err)
	}
	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", loginBody, nil)
	cookie := sessionCookieFrom(loginRec)

	rec := doRawRequest(api, "DELETE", "/admin/nodes/jira", nil, cookie)
	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := s.GetNodeByName(context.Background(), "jira"); err != nil {
		t.Fatalf("config-sourced node must still exist after a refused delete: %v", err)
	}
}

func TestCookieAuth_NoCredentialAtAllRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := doRawRequest(api, "GET", "/admin/agents", nil, nil)
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuth_InvalidCookieAndNoNHITokenRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := doRawRequest(api, "GET", "/admin/agents", nil, &http.Cookie{Name: UISessionCookieName, Value: "garbage"})
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuth_ExistingNHIPathStillWorksWithoutACookie(t *testing.T) {
	// The pre-issue-#17 dual-trust path must be completely unaffected --
	// this mirrors TestGate_ValidBothChecksSucceeds exactly but through
	// the new gateBrowserOrService wrapper agents/groups/policies now
	// use, proving the cookie addition didn't change existing behavior.
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := fullyAuthedRequest(api, "GET", "/admin/agents", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuth_ExpiredSessionRejectedWithoutExplicitLogout(t *testing.T) {
	clockTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return clockTime }
	sessions := uisession.NewRegistry(uisession.RegistryConfig{MaxAge: time.Hour, Clock: clock})

	api, _ := newTestAdminAPIWithSessions(t, validAdminAuthn(), adminIntrospector(), sessions)
	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", loginBody, nil)
	cookie := sessionCookieFrom(loginRec)
	if cookie == nil {
		t.Fatal("login did not set a cookie")
	}

	// Still valid well within the hour.
	rec := doRawRequest(api, "GET", "/admin/agents", nil, cookie)
	if rec.Code != 200 {
		t.Fatalf("status before expiry = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	clockTime = clockTime.Add(2 * time.Hour)
	rec = doRawRequest(api, "GET", "/admin/agents", nil, cookie)
	if rec.Code != 401 {
		t.Fatalf("status after expiry = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}
