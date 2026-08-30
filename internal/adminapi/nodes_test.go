package adminapi

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
	"github.com/sumeetgp/spidercob-gateway/internal/uisession"
)

// fakeNodeRegistrar records every AddNode/RemoveNode call it receives --
// the shape every issue #57 wiring test below needs to prove createNode/
// deleteNode actually call into it, with the right arguments, only after
// the store write already succeeded.
type fakeNodeRegistrar struct {
	mu        sync.Mutex
	added     []config.Node
	removed   []string
	addErr    error
	removeErr error
}

func (f *fakeNodeRegistrar) AddNode(n config.Node) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, n)
	return f.addErr
}

func (f *fakeNodeRegistrar) RemoveNode(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, name)
	return f.removeErr
}

func newTestAdminAPIWithNodeRegistrar(t *testing.T, registrar NodeRegistrar) (*AdminAPI, store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.NewService(s)
	sessions := uisession.NewRegistry(uisession.RegistryConfig{MaxAge: time.Hour})
	api, err := New(Config{
		Store: s, Identity: svc, Authn: validAdminAuthn(), Introspector: adminIntrospector(),
		UISessions: sessions, MCPSessions: newFakeMCPSessionManager(), NodeRegistrar: registrar,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return api, s
}

func TestCreateNode_WithRegistrar_AppliesLiveAfterStoreWrite(t *testing.T) {
	reg := &fakeNodeRegistrar{}
	api, s := newTestAdminAPIWithNodeRegistrar(t, reg)

	body, _ := json.Marshal(createNodeRequest{Name: "jira", Transport: "streamable_http", UpstreamURL: "http://localhost:3001"})
	rec := fullyAuthedRequest(api, "POST", "/admin/nodes", body)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	// Store write happened (same assertion TestCreateNode_StreamableHTTP_Succeeds
	// already makes for the no-registrar case).
	if _, err := s.GetNodeByName(t.Context(), "jira"); err != nil {
		t.Fatalf("node not persisted: %v", err)
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()
	if len(reg.added) != 1 {
		t.Fatalf("expected exactly one AddNode call, got %d", len(reg.added))
	}
	if reg.added[0].Name != "jira" || reg.added[0].Transport != "streamable_http" || reg.added[0].UpstreamURL != "http://localhost:3001" {
		t.Fatalf("unexpected AddNode argument: %+v", reg.added[0])
	}
}

func TestCreateNode_RegistrarFailure_StillReturnsSuccess(t *testing.T) {
	// The store write is authoritative; a live-apply failure logs but
	// never turns an already-succeeded store write into a failed
	// request (issue #57 spec).
	reg := &fakeNodeRegistrar{addErr: errors.New("live registration boom")}
	api, s := newTestAdminAPIWithNodeRegistrar(t, reg)

	body, _ := json.Marshal(createNodeRequest{Name: "jira", Transport: "streamable_http", UpstreamURL: "http://localhost:3001"})
	rec := fullyAuthedRequest(api, "POST", "/admin/nodes", body)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201 even though live-apply failed, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := s.GetNodeByName(t.Context(), "jira"); err != nil {
		t.Fatalf("the store write must still have succeeded: %v", err)
	}
}

func TestDeleteNode_WithRegistrar_AppliesLiveAfterStoreDelete(t *testing.T) {
	reg := &fakeNodeRegistrar{}
	api, s := newTestAdminAPIWithNodeRegistrar(t, reg)
	if _, err := s.CreateNode(t.Context(), store.Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://a"), Source: store.NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	rec := fullyAuthedRequest(api, "DELETE", "/admin/nodes/jira", nil)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()
	if len(reg.removed) != 1 || reg.removed[0] != "jira" {
		t.Fatalf("expected exactly one RemoveNode(\"jira\") call, got %+v", reg.removed)
	}
}

func TestDeleteNode_RegistrarFailure_StillReturnsSuccess(t *testing.T) {
	reg := &fakeNodeRegistrar{removeErr: errors.New("live removal boom")}
	api, s := newTestAdminAPIWithNodeRegistrar(t, reg)
	if _, err := s.CreateNode(t.Context(), store.Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://a"), Source: store.NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	rec := fullyAuthedRequest(api, "DELETE", "/admin/nodes/jira", nil)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204 even though live-apply failed, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteNode_ConfigSourced_NeverReachesRegistrar(t *testing.T) {
	// The existing config-sourced-node refusal (409) happens before any
	// registrar call -- a config node's live state is never touched by
	// this admin path at all.
	reg := &fakeNodeRegistrar{}
	api, s := newTestAdminAPIWithNodeRegistrar(t, reg)
	if _, err := s.CreateNode(t.Context(), store.Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://a"), Source: store.NodeSourceConfig}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	rec := fullyAuthedRequest(api, "DELETE", "/admin/nodes/jira", nil)
	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()
	if len(reg.removed) != 0 {
		t.Fatalf("expected zero RemoveNode calls for a refused config-sourced delete, got %+v", reg.removed)
	}
}

func TestCreateNode_NoRegistrar_UnaffectedByIssue57(t *testing.T) {
	// A nil NodeRegistrar (the plain newTestAdminAPI helper every
	// pre-existing node test already uses) must behave exactly as
	// before this issue -- a regression check on top of those existing
	// tests, not a replacement for them.
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	body, _ := json.Marshal(createNodeRequest{Name: "jira", Transport: "streamable_http", UpstreamURL: "http://localhost:3001"})
	rec := fullyAuthedRequest(api, "POST", "/admin/nodes", body)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := s.GetNodeByName(t.Context(), "jira"); err != nil {
		t.Fatalf("node not persisted: %v", err)
	}
}
