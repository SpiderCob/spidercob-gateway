package authserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

// Security review finding #4: revoking an agent (store.RevokeAgent, what
// the admin API's DELETE /admin/agents/{client_id} calls) must make its
// already-issued tokens stop validating on the very next request, not
// only once they expire -- "revocation is effective on every subsequent
// request".

func mintAgentToken(t *testing.T, as *AuthServer, clientID, secret, resource string) string {
	t.Helper()
	rec := tokenRequest(t, as, url.Values{
		"grant_type": {grantClientCredentials}, "client_id": {clientID},
		"client_secret": {secret}, "resource": {resource},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("mint status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.AccessToken == "" {
		t.Fatalf("unmarshal token: %v", err)
	}
	return resp.AccessToken
}

func TestRevokeAgent_InvalidatesAlreadyIssuedNodeToken(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	tok := mintAgentToken(t, env.as, agent.ClientID, secret, "jira")
	if _, err := env.as.ValidateAccessToken("jira", tok); err != nil {
		t.Fatalf("ValidateAccessToken before revoke: %v", err)
	}

	if err := env.store.RevokeAgent(ctx, agent.ClientID); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := env.as.ValidateAccessToken("jira", tok); !errors.Is(err, ErrTokenRevoked) {
			t.Fatalf("request %d after revoke: err = %v, want ErrTokenRevoked", i+1, err)
		}
	}
}

func TestRevokeAgent_InvalidatesAlreadyIssuedAdminToken(t *testing.T) {
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
	tok := mintAgentToken(t, as, agent.ClientID, secret, AdminResource)
	if _, err := as.ValidateAdminAccessToken(tok); err != nil {
		t.Fatalf("ValidateAdminAccessToken before revoke: %v", err)
	}

	if err := env.store.RevokeAgent(ctx, agent.ClientID); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}

	if _, err := as.ValidateAdminAccessToken(tok); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("after revoke: err = %v, want ErrTokenRevoked", err)
	}
}

func TestRevokeAgent_OtherAgentsTokensKeepWorking(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	revoked, rSecret, err := env.svc.CreateAgent(ctx, "revoked-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	kept, kSecret, err := env.svc.CreateAgent(ctx, "kept-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	_ = mintAgentToken(t, env.as, revoked.ClientID, rSecret, "jira")
	keptTok := mintAgentToken(t, env.as, kept.ClientID, kSecret, "jira")

	if err := env.store.RevokeAgent(ctx, revoked.ClientID); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if _, err := env.as.ValidateAccessToken("jira", keptTok); err != nil {
		t.Fatalf("unrevoked agent's token rejected: %v", err)
	}
}

func TestRevokeAgent_StillRejectedAfterRestart(t *testing.T) {
	env := newTestEnv(t, Config{})
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "ci-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	tok := mintAgentToken(t, env.as, agent.ClientID, secret, "jira")
	if err := env.store.RevokeAgent(ctx, agent.ClientID); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}

	// A fresh AuthServer over the same store, sharing the signing keys,
	// models a restart that kept its keys: revocation must still hold.
	as2, err := New(ctx, Config{Issuer: "https://gw.test", Nodes: []string{"jira"}, Identity: env.svc, Store: env.store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	as2.keys = env.as.keys
	if _, err := as2.ValidateAccessToken("jira", tok); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("after restart: err = %v, want ErrTokenRevoked", err)
	}
}
