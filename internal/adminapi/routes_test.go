package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
	"github.com/sumeetgp/spidercob-gateway/internal/uisession"
)

type fakeAdminTokenValidator struct {
	claims AdminClaims
	err    error
}

func (f *fakeAdminTokenValidator) ValidateAdminAccessToken(token string) (AdminClaims, error) {
	return f.claims, f.err
}

func validAdminAuthn() AdminTokenValidator {
	return &fakeAdminTokenValidator{claims: AdminClaims{Subject: "agent:spider-snoop-backend"}}
}

func adminIntrospector() SpiderSnoopIntrospector {
	return &fakeIntrospector{result: IntrospectionResult{Username: "alice", Role: "admin"}}
}

func newTestAdminAPI(t *testing.T, authn AdminTokenValidator, introspector SpiderSnoopIntrospector) (*AdminAPI, store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.NewService(s)
	sessions := uisession.NewRegistry(uisession.RegistryConfig{MaxAge: time.Hour})
	api, err := New(Config{Store: s, Identity: svc, Authn: authn, Introspector: introspector, UISessions: sessions})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return api, s
}

type reqOpts struct {
	includeNHI   bool
	includeHuman bool
	body         []byte
}

func doAdminRequest(api *AdminAPI, method, path string, opts reqOpts) *httptest.ResponseRecorder {
	var r io.Reader
	if opts.body != nil {
		r = bytes.NewReader(opts.body)
	}
	req := httptest.NewRequest(method, path, r)
	if opts.includeNHI {
		req.Header.Set("Authorization", "Bearer nhi-token")
	}
	if opts.includeHuman {
		req.Header.Set(HumanSessionHeader, "human-token")
	}
	rec := httptest.NewRecorder()
	api.Routes().ServeHTTP(rec, req)
	return rec
}

func fullyAuthedRequest(api *AdminAPI, method, path string, body []byte) *httptest.ResponseRecorder {
	return doAdminRequest(api, method, path, reqOpts{includeNHI: true, includeHuman: true, body: body})
}

// --- Gate ---

func TestGate_MissingNHITokenRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := doAdminRequest(api, "GET", "/admin/agents", reqOpts{includeHuman: true})
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGate_InvalidNHITokenRejected(t *testing.T) {
	authn := &fakeAdminTokenValidator{err: errors.New("bad token")}
	api, _ := newTestAdminAPI(t, authn, adminIntrospector())
	rec := fullyAuthedRequest(api, "GET", "/admin/agents", nil)
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGate_MissingHumanSessionHeaderRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := doAdminRequest(api, "GET", "/admin/agents", reqOpts{includeNHI: true})
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGate_IntrospectionErrorFailsClosed(t *testing.T) {
	introspector := &fakeIntrospector{err: errors.New("spider-snoop unreachable")}
	api, _ := newTestAdminAPI(t, validAdminAuthn(), introspector)
	rec := fullyAuthedRequest(api, "GET", "/admin/agents", nil)
	if rec.Code != 503 {
		t.Fatalf("status = %d, want 503 (fail closed on introspection error), body = %s", rec.Code, rec.Body.String())
	}
}

func TestGate_InvalidSessionRejectedAsUnauthorizedNotServiceUnavailable(t *testing.T) {
	// A definite "spider-snoop rejected this human token" (ErrInvalidSession)
	// is a client error, not a service outage -- must map to 401, not the
	// generic fail-closed 503 an unreachable/erroring spider-snoop gets.
	introspector := &fakeIntrospector{err: fmt.Errorf("wrapped: %w", ErrInvalidSession)}
	api, _ := newTestAdminAPI(t, validAdminAuthn(), introspector)
	rec := fullyAuthedRequest(api, "GET", "/admin/agents", nil)
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401 for an invalid/expired human session, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGate_NonAdminRoleRejected(t *testing.T) {
	introspector := &fakeIntrospector{result: IntrospectionResult{Username: "bob", Role: "analyst"}}
	api, _ := newTestAdminAPI(t, validAdminAuthn(), introspector)
	rec := fullyAuthedRequest(api, "GET", "/admin/agents", nil)
	if rec.Code != 403 {
		t.Fatalf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGate_ValidBothChecksSucceeds(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := fullyAuthedRequest(api, "GET", "/admin/agents", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
}

// --- Agents ---

func TestCreateAgent_Succeeds(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	body, _ := json.Marshal(createAgentRequest{Name: "ci-bot"})
	rec := fullyAuthedRequest(api, "POST", "/admin/agents", body)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	var resp createAgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ClientID == "" || resp.Secret == "" || resp.Name != "ci-bot" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if _, err := s.GetAgentByClientID(context.Background(), resp.ClientID); err != nil {
		t.Fatalf("agent not actually persisted: %v", err)
	}
}

func TestCreateAgent_MissingNameRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := fullyAuthedRequest(api, "POST", "/admin/agents", []byte(`{}`))
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestListAgents_ReturnsCreatedAgents(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	if _, _, err := identity.NewService(s).CreateAgent(ctx, "a"); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if _, _, err := identity.NewService(s).CreateAgent(ctx, "b"); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec := fullyAuthedRequest(api, "GET", "/admin/agents", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var agents []agentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &agents); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("agents = %+v, want 2", agents)
	}
}

func TestRevokeAgent_Succeeds(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	agent, _, err := identity.NewService(s).CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec := fullyAuthedRequest(api, "DELETE", "/admin/agents/"+agent.ClientID, nil)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	got, err := s.GetAgentByClientID(ctx, agent.ClientID)
	if err != nil {
		t.Fatalf("GetAgentByClientID: %v", err)
	}
	if got.RevokedAt == nil {
		t.Fatal("expected agent to be revoked")
	}
}

func TestRevokeAgent_UnknownRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := fullyAuthedRequest(api, "DELETE", "/admin/agents/never-existed", nil)
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

// --- Groups ---

func TestCreateGroup_Succeeds(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	body, _ := json.Marshal(createGroupRequest{Name: "engineering"})
	rec := fullyAuthedRequest(api, "POST", "/admin/groups", body)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := s.GetGroupByName(context.Background(), "engineering"); err != nil {
		t.Fatalf("group not actually persisted: %v", err)
	}
}

func TestCreateGroup_DuplicateRejected(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	if _, err := s.CreateGroup(context.Background(), "engineering"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	body, _ := json.Marshal(createGroupRequest{Name: "engineering"})
	rec := fullyAuthedRequest(api, "POST", "/admin/groups", body)
	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
}

func TestListGroups_ReturnsCreatedGroups(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	if _, err := s.CreateGroup(ctx, "engineering"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := s.CreateGroup(ctx, "support"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	rec := fullyAuthedRequest(api, "GET", "/admin/groups", nil)
	var groups []groupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &groups); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %+v, want 2", groups)
	}
}

func TestDeleteGroup_Succeeds(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	if _, err := s.CreateGroup(ctx, "throwaway"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	rec := fullyAuthedRequest(api, "DELETE", "/admin/groups/throwaway", nil)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteGroup_UnknownRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := fullyAuthedRequest(api, "DELETE", "/admin/groups/never-existed", nil)
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteGroup_StillReferencedByPolicyRejected(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	g, err := s.CreateGroup(ctx, "policy-holder")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.ReplacePolicies(ctx, []store.NewPolicy{
		{GroupID: g.ID, Node: "jira", RuleType: store.PolicyAllow},
	}); err != nil {
		t.Fatalf("ReplacePolicies: %v", err)
	}
	rec := fullyAuthedRequest(api, "DELETE", "/admin/groups/policy-holder", nil)
	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAddAndRemoveGroupMember_User(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	if _, err := s.CreateGroup(ctx, "engineering"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	u, err := s.CreateUser(ctx, "carol", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	body, _ := json.Marshal(groupMemberRequest{Type: "user", Identifier: "carol"})
	rec := fullyAuthedRequest(api, "POST", "/admin/groups/engineering/members", body)
	if rec.Code != 204 {
		t.Fatalf("add member status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	groups, err := s.UserGroups(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserGroups: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "engineering" {
		t.Fatalf("UserGroups = %+v, want [engineering]", groups)
	}

	rec = fullyAuthedRequest(api, "DELETE", "/admin/groups/engineering/members/user/carol", nil)
	if rec.Code != 204 {
		t.Fatalf("remove member status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	groups, err = s.UserGroups(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserGroups: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("UserGroups after removal = %+v, want none", groups)
	}
}

func TestAddGroupMember_Agent(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	if _, err := s.CreateGroup(ctx, "engineering"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	agent, _, err := identity.NewService(s).CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	body, _ := json.Marshal(groupMemberRequest{Type: "agent", Identifier: agent.ClientID})
	rec := fullyAuthedRequest(api, "POST", "/admin/groups/engineering/members", body)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	groups, err := s.AgentGroups(ctx, agent.ID)
	if err != nil {
		t.Fatalf("AgentGroups: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "engineering" {
		t.Fatalf("AgentGroups = %+v, want [engineering]", groups)
	}
}

func TestAddGroupMember_UnknownGroupRejected(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	if _, err := s.CreateUser(context.Background(), "carol", "hash"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	body, _ := json.Marshal(groupMemberRequest{Type: "user", Identifier: "carol"})
	rec := fullyAuthedRequest(api, "POST", "/admin/groups/never-existed/members", body)
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAddGroupMember_UnknownIdentifierRejected(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	if _, err := s.CreateGroup(context.Background(), "engineering"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	body, _ := json.Marshal(groupMemberRequest{Type: "user", Identifier: "never-existed"})
	rec := fullyAuthedRequest(api, "POST", "/admin/groups/engineering/members", body)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

// --- Policies ---

func TestListPolicies_ResolvesGroupNames(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	g, err := s.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.ReplacePolicies(ctx, []store.NewPolicy{
		{GroupID: g.ID, Node: "jira", RuleType: store.PolicyAllow, Methods: []string{"tools/call"}},
	}); err != nil {
		t.Fatalf("ReplacePolicies: %v", err)
	}

	rec := fullyAuthedRequest(api, "GET", "/admin/policies", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var policies []policyRuleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &policies); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(policies) != 1 || policies[0].Group != "engineering" || policies[0].Node != "jira" {
		t.Fatalf("policies = %+v, want [{engineering jira allow ...}]", policies)
	}
}

func TestReplacePolicies_Succeeds(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	if _, err := s.CreateGroup(ctx, "engineering"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	body, _ := json.Marshal([]policyRuleRequest{
		{Group: "engineering", Node: "jira", RuleType: "allow", Tools: []string{"search_issues"}},
	})
	rec := fullyAuthedRequest(api, "PUT", "/admin/policies", body)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	all, err := s.AllPolicies(ctx)
	if err != nil {
		t.Fatalf("AllPolicies: %v", err)
	}
	if len(all) != 1 || all[0].Node != "jira" {
		t.Fatalf("AllPolicies = %+v, want 1 rule for jira", all)
	}
}

func TestReplacePolicies_UnknownGroupRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	body, _ := json.Marshal([]policyRuleRequest{
		{Group: "never-existed", Node: "jira", RuleType: "allow"},
	})
	rec := fullyAuthedRequest(api, "PUT", "/admin/policies", body)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestReplacePolicies_InvalidRuleTypeRejected(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	if _, err := s.CreateGroup(context.Background(), "engineering"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	body, _ := json.Marshal([]policyRuleRequest{
		{Group: "engineering", Node: "jira", RuleType: "maybe"},
	})
	rec := fullyAuthedRequest(api, "PUT", "/admin/policies", body)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

// --- Nodes (issue #15) ---

func TestCreateNode_StreamableHTTP_Succeeds(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	body, _ := json.Marshal(createNodeRequest{Name: "jira", Transport: "streamable_http", UpstreamURL: "http://localhost:3001"})
	rec := fullyAuthedRequest(api, "POST", "/admin/nodes", body)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	var resp nodeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Name != "jira" || resp.Source != store.NodeSourceAdmin {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.UpstreamURL == nil || *resp.UpstreamURL != "http://localhost:3001" {
		t.Fatalf("UpstreamURL = %v, want http://localhost:3001", resp.UpstreamURL)
	}

	got, err := s.GetNodeByName(context.Background(), "jira")
	if err != nil {
		t.Fatalf("node not actually persisted: %v", err)
	}
	if got.Source != store.NodeSourceAdmin {
		t.Fatalf("Source = %q, want %q", got.Source, store.NodeSourceAdmin)
	}
}

func TestCreateNode_Stdio_Succeeds(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	body, _ := json.Marshal(createNodeRequest{Name: "local", Transport: "stdio", Command: "go", Args: []string{"run", "./x"}})
	rec := fullyAuthedRequest(api, "POST", "/admin/nodes", body)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCreateNode_MissingUpstreamURLRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	body, _ := json.Marshal(createNodeRequest{Name: "jira", Transport: "streamable_http"})
	rec := fullyAuthedRequest(api, "POST", "/admin/nodes", body)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCreateNode_UnknownTransportRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	body, _ := json.Marshal(createNodeRequest{Name: "jira", Transport: "carrier-pigeon"})
	rec := fullyAuthedRequest(api, "POST", "/admin/nodes", body)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCreateNode_NameCollisionRejected(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	if _, err := s.CreateNode(context.Background(), store.Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://a"), Source: store.NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	body, _ := json.Marshal(createNodeRequest{Name: "jira", Transport: "streamable_http", UpstreamURL: "http://b"})
	rec := fullyAuthedRequest(api, "POST", "/admin/nodes", body)
	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
}

func TestListNodes_ReturnsCreatedNodes(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	if _, err := s.CreateNode(ctx, store.Node{Name: "a", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://a"), Source: store.NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := s.UpsertConfigNode(ctx, store.Node{Name: "b", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://b")}); err != nil {
		t.Fatalf("UpsertConfigNode: %v", err)
	}

	rec := fullyAuthedRequest(api, "GET", "/admin/nodes", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var nodes []nodeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %+v, want 2 (config- and admin-sourced alike)", nodes)
	}
}

func TestDeleteNode_AdminSourced_Succeeds(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	if _, err := s.CreateNode(context.Background(), store.Node{Name: "throwaway", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://a"), Source: store.NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	rec := fullyAuthedRequest(api, "DELETE", "/admin/nodes/throwaway", nil)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteNode_ConfigSourced_Rejected(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	if _, err := s.UpsertConfigNode(context.Background(), store.Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://a")}); err != nil {
		t.Fatalf("UpsertConfigNode: %v", err)
	}
	rec := fullyAuthedRequest(api, "DELETE", "/admin/nodes/jira", nil)
	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := s.GetNodeByName(context.Background(), "jira"); err != nil {
		t.Fatalf("config-sourced node must still exist after a refused delete: %v", err)
	}
}

// raceDeleteNodeStore wraps a real store.Store and forces DeleteNode to
// return a caller-chosen error, simulating a node that was deleted by a
// concurrent request in the window between deleteNode's own GetNodeByName
// existence check and its DeleteNode call.
type raceDeleteNodeStore struct {
	store.Store
	deleteNodeErr error
}

func (s *raceDeleteNodeStore) DeleteNode(ctx context.Context, name string) error {
	if s.deleteNodeErr != nil {
		return s.deleteNodeErr
	}
	return s.Store.DeleteNode(ctx, name)
}

func TestDeleteNode_ConcurrentlyDeletedNodeReturns404NotInternalError(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateNode(context.Background(), store.Node{Name: "throwaway", Transport: "streamable_http", UpstreamURL: strPtrForTest("http://a"), Source: store.NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	raced := &raceDeleteNodeStore{Store: s, deleteNodeErr: store.ErrNotFound}

	svc := identity.NewService(s)
	sessions := uisession.NewRegistry(uisession.RegistryConfig{MaxAge: time.Hour})
	api, err := New(Config{Store: raced, Identity: svc, Authn: validAdminAuthn(), Introspector: adminIntrospector(), UISessions: sessions})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := fullyAuthedRequest(api, "DELETE", "/admin/nodes/throwaway", nil)
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404 (consistent with other delete endpoints on a concurrent delete), body = %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteNode_UnknownRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := fullyAuthedRequest(api, "DELETE", "/admin/nodes/never-existed", nil)
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func strPtrForTest(s string) *string { return &s }
