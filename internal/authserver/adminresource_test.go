package authserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestToken_AdminClientCredentials_AllowlistedAgentMintsAdminScopedToken(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "spider-snoop-backend")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	// Rebuild the AuthServer with this agent allowlisted -- newTestEnv's
	// helper doesn't know the agent's client_id until after CreateAgent.
	as, err := New(ctx, Config{
		Issuer: "https://gw.test", Nodes: []string{"jira"},
		Identity: env.svc, Store: env.store,
		AdminIntegrationClientIDs: []string{agent.ClientID},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := tokenRequest(t, as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {AdminResource},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	claims, err := as.ValidateAdminAccessToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAdminAccessToken: %v", err)
	}
	if claims.Subject != "agent:"+agent.ClientID {
		t.Fatalf("sub = %q, want agent:%s", claims.Subject, agent.ClientID)
	}
}

func TestToken_AdminClientCredentials_NonAllowlistedAgentRejected(t *testing.T) {
	// A perfectly valid agent, just not on the admin allowlist -- must be
	// rejected exactly like a wrong secret (401 invalid_client), not
	// distinguishably.
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "some-other-service")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {AdminResource},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
	var errResp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
	if errResp.Error != "invalid_client" {
		t.Fatalf("error = %q, want invalid_client (same shape as a wrong-secret rejection)", errResp.Error)
	}
}

func TestToken_AdminResource_NonClientCredentialsGrantRejected(t *testing.T) {
	env := newTestEnv(t, Config{})
	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantLogin}, "username": {"whoever"}, "password": {"whatever"},
		"resource": {AdminResource},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestToken_AdminResource_AcceptsBareAndFullURIForm(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "spider-snoop-backend")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	as, err := New(ctx, Config{
		Issuer: "https://gw.test", Nodes: []string{"jira"},
		Identity: env.svc, Store: env.store,
		AdminIntegrationClientIDs: []string{agent.ClientID},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := tokenRequest(t, as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {"https://gw.test/_admin"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the full-URI resource form, body = %s", rec.Code, rec.Body.String())
	}
}

func TestValidateAdminAccessToken_OrdinaryNodeTokenRejected(t *testing.T) {
	// An ordinary, validly-minted node-scoped token must never validate
	// as an admin token -- the two audiences are structurally distinct.
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {"jira"},
	})
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	if _, err := env.as.ValidateAdminAccessToken(resp.AccessToken); err == nil {
		t.Fatal("ValidateAdminAccessToken accepted an ordinary node-scoped token, want rejection")
	}
}

func TestValidateAccessToken_AdminScopedTokenRejectedForANode(t *testing.T) {
	// The reverse direction: an admin-scoped token must never validate
	// against any real node.
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "spider-snoop-backend")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	as, err := New(ctx, Config{
		Issuer: "https://gw.test", Nodes: []string{"jira"},
		Identity: env.svc, Store: env.store,
		AdminIntegrationClientIDs: []string{agent.ClientID},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := tokenRequest(t, as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {AdminResource},
	})
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	if _, err := as.ValidateAccessToken("jira", resp.AccessToken); err == nil {
		t.Fatal("ValidateAccessToken accepted an admin-scoped token for node jira, want rejection")
	}
}

func TestValidateAdminAccessToken_RevokedRejected(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "spider-snoop-backend")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	as, err := New(ctx, Config{
		Issuer: "https://gw.test", Nodes: []string{"jira"},
		Identity: env.svc, Store: env.store,
		AdminIntegrationClientIDs: []string{agent.ClientID},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := tokenRequest(t, as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {agent.ClientID},
		"client_secret": {secret}, "resource": {AdminResource},
	})
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	claims, err := as.ValidateAdminAccessToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAdminAccessToken: %v", err)
	}
	if err := as.RevokeJTI(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}
	if _, err := as.ValidateAdminAccessToken(resp.AccessToken); err == nil {
		t.Fatal("ValidateAdminAccessToken accepted a revoked token, want rejection")
	}
}
