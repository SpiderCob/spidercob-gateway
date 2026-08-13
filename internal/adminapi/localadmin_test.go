package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
	"github.com/sumeetgp/spidercob-gateway/internal/uisession"
)

// fakeLocalAdminAuthenticator and fakeLocalIntrospector are a matched
// pair of hand-rolled fakes for LocalAdminAuthenticator/
// SpiderSnoopIntrospector (issue #43) -- the same "hand-rolled fake for
// this package's own interface" pattern fakeIntrospector/
// fakeAdminTokenValidator already established, so these tests never need
// real signing/store machinery (already covered by internal/authserver's
// own tests). Login returns a deterministic "token" the paired
// introspector can parse straight back into a username, modeling the
// real system's shape without duplicating its cryptography.
type fakeLocalAdminAuthenticator struct {
	validPasswords map[string]string // username -> password
}

func (f *fakeLocalAdminAuthenticator) Login(_ context.Context, username, password string) (string, error) {
	want, ok := f.validPasswords[username]
	if !ok || want != password {
		return "", errors.New("invalid local admin credentials")
	}
	return "local-session-for-" + username, nil
}

type fakeLocalIntrospector struct{}

func (fakeLocalIntrospector) Introspect(_ context.Context, token string) (IntrospectionResult, error) {
	username, ok := strings.CutPrefix(token, "local-session-for-")
	if !ok {
		return IntrospectionResult{}, errors.New("invalid local session token")
	}
	return IntrospectionResult{Username: username, Role: "admin"}, nil
}

func newTestAdminAPILocalMode(t *testing.T, localAdmin LocalAdminAuthenticator) (*AdminAPI, store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.NewService(s)
	sessions := uisession.NewRegistry(uisession.RegistryConfig{MaxAge: time.Hour})
	api, err := New(Config{
		Store: s, Identity: svc,
		Authn:        validAdminAuthn(),
		Introspector: fakeLocalIntrospector{},
		UISessions:   sessions,
		MCPSessions:  newFakeMCPSessionManager(),
		LocalAdmin:   localAdmin,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return api, s
}

func TestCreateUISession_LocalAdminValidCredentialsSucceeds(t *testing.T) {
	api, _ := newTestAdminAPILocalMode(t, &fakeLocalAdminAuthenticator{validPasswords: map[string]string{"alice": "s3cret"}})

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "s3cret"})
	rec := doRawRequest(api, "POST", "/admin/ui/session", body, nil)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookieFrom(rec)
	if cookie == nil {
		t.Fatal("expected a session cookie to be set")
	}

	whoamiRec := doRawRequest(api, "GET", "/admin/ui/session", nil, cookie)
	if whoamiRec.Code != 200 {
		t.Fatalf("whoami status = %d, want 200, body = %s", whoamiRec.Code, whoamiRec.Body.String())
	}
	if !strings.Contains(whoamiRec.Body.String(), `"username":"alice"`) {
		t.Fatalf("whoami body = %s, want it to name alice", whoamiRec.Body.String())
	}
}

func TestCreateUISession_LocalAdminWrongPasswordRejected(t *testing.T) {
	api, _ := newTestAdminAPILocalMode(t, &fakeLocalAdminAuthenticator{validPasswords: map[string]string{"alice": "s3cret"}})

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "wrong"})
	rec := doRawRequest(api, "POST", "/admin/ui/session", body, nil)
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCreateUISession_LocalAdminUnsupportedWhenNotConfigured(t *testing.T) {
	// A spider-snoop-integrated (or fully disabled) AdminAPI has no
	// LocalAdmin wired in at all -- posting username/password to it must
	// be rejected outright, not silently fall through to being
	// misinterpreted as a spider-snoop token.
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "whatever"})
	rec := doRawRequest(api, "POST", "/admin/ui/session", body, nil)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCreateUISession_LocalAdminCookieWorksOnGatedEndpoints(t *testing.T) {
	api, _ := newTestAdminAPILocalMode(t, &fakeLocalAdminAuthenticator{validPasswords: map[string]string{"alice": "s3cret"}})

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "s3cret"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", body, nil)
	cookie := sessionCookieFrom(loginRec)
	if cookie == nil {
		t.Fatal("expected a session cookie")
	}

	rec := doRawRequest(api, "GET", "/admin/agents", nil, cookie)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (cookie alone succeeds on a gateBrowserOrService endpoint), body = %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteUISession_LocalAdminLogoutInvalidatesCookie(t *testing.T) {
	api, _ := newTestAdminAPILocalMode(t, &fakeLocalAdminAuthenticator{validPasswords: map[string]string{"alice": "s3cret"}})

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "s3cret"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", body, nil)
	cookie := sessionCookieFrom(loginRec)

	logoutRec := doRawRequest(api, "DELETE", "/admin/ui/session", nil, cookie)
	if logoutRec.Code != 204 {
		t.Fatalf("logout status = %d, want 204", logoutRec.Code)
	}

	rec := doRawRequest(api, "GET", "/admin/agents", nil, cookie)
	if rec.Code != 401 {
		t.Fatalf("status after logout = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGetAuthMode_ReportsLocalWhenLocalAdminConfigured(t *testing.T) {
	api, _ := newTestAdminAPILocalMode(t, &fakeLocalAdminAuthenticator{validPasswords: map[string]string{"alice": "s3cret"}})

	rec := doRawRequest(api, "GET", "/admin/ui/auth-mode", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"mode":"local"`) {
		t.Fatalf("body = %s, want mode local", rec.Body.String())
	}
}

func TestGetAuthMode_ReportsSpiderSnoopWhenLocalAdminNotConfigured(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())

	rec := doRawRequest(api, "GET", "/admin/ui/auth-mode", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"mode":"spider_snoop"`) {
		t.Fatalf("body = %s, want mode spider_snoop", rec.Body.String())
	}
}
