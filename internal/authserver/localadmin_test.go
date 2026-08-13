package authserver

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
)

func newLocalAdminTestEnv(t *testing.T) (*testEnv, int64) {
	t.Helper()
	env := newTestEnv(t, Config{LocalAdminGroup: "admin"})
	g, err := env.store.CreateGroup(context.Background(), "admin")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	return env, g.ID
}

func TestLoginLocalAdmin_ValidCredentialsInAdminGroupSucceeds(t *testing.T) {
	env, groupID := newLocalAdminTestEnv(t)
	ctx := context.Background()

	u, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := env.store.AssignUserGroup(ctx, u.ID, groupID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}

	token, err := env.as.LoginLocalAdmin(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("LoginLocalAdmin: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty local admin session token")
	}

	username, err := env.as.ValidateLocalAdminSession(ctx, token)
	if err != nil {
		t.Fatalf("ValidateLocalAdminSession: %v", err)
	}
	if username != "alice" {
		t.Fatalf("username = %q, want alice", username)
	}
}

func TestLoginLocalAdmin_WrongPasswordRejected(t *testing.T) {
	env, groupID := newLocalAdminTestEnv(t)
	ctx := context.Background()

	u, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := env.store.AssignUserGroup(ctx, u.ID, groupID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}

	if _, err := env.as.LoginLocalAdmin(ctx, "alice", "wrong-password"); err == nil {
		t.Fatal("expected an error for a wrong password")
	}
}

func TestLoginLocalAdmin_UnknownUsernameRejected(t *testing.T) {
	env, _ := newLocalAdminTestEnv(t)
	if _, err := env.as.LoginLocalAdmin(context.Background(), "nobody", "whatever"); err == nil {
		t.Fatal("expected an error for an unknown username")
	}
}

func TestLoginLocalAdmin_CorrectCredentialsButNotInAdminGroupRejected(t *testing.T) {
	env, _ := newLocalAdminTestEnv(t)
	ctx := context.Background()

	// A real, correctly-authenticated local user who simply isn't in the
	// admin group -- must be rejected, not silently granted admin access
	// just for having a valid password.
	if _, err := env.svc.CreateUser(ctx, "bob", "s3cret-pw"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := env.as.LoginLocalAdmin(ctx, "bob", "s3cret-pw"); err == nil {
		t.Fatal("expected an error for a user not in the admin group")
	}
}

func TestLoginLocalAdmin_WrongPasswordAndNotInGroupProduceTheSameError(t *testing.T) {
	// Non-enumerable, same posture as every other credential check in
	// this codebase: a wrong password and "real user, wrong group" must
	// not be distinguishable from the error alone.
	env, groupID := newLocalAdminTestEnv(t)
	ctx := context.Background()

	u, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := env.store.AssignUserGroup(ctx, u.ID, groupID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}
	if _, err := env.svc.CreateUser(ctx, "bob", "s3cret-pw"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, wrongPasswordErr := env.as.LoginLocalAdmin(ctx, "alice", "wrong-password")
	_, notInGroupErr := env.as.LoginLocalAdmin(ctx, "bob", "s3cret-pw")
	if wrongPasswordErr == nil || notInGroupErr == nil {
		t.Fatalf("expected both attempts to fail, got wrongPasswordErr=%v notInGroupErr=%v", wrongPasswordErr, notInGroupErr)
	}
	if wrongPasswordErr.Error() != notInGroupErr.Error() {
		t.Fatalf("expected identical error messages, got %q vs %q", wrongPasswordErr, notInGroupErr)
	}
}

func TestLoginLocalAdmin_DisabledWhenLocalAdminGroupUnset(t *testing.T) {
	env := newTestEnv(t, Config{}) // no LocalAdminGroup -- spider-snoop-integrated or fully-disabled mode
	ctx := context.Background()
	if _, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := env.as.LoginLocalAdmin(ctx, "alice", "s3cret-pw"); err == nil {
		t.Fatal("expected an error when local-admin mode isn't configured at all")
	}
}

func TestValidateLocalAdminSession_RemovedFromGroupRejectedImmediately(t *testing.T) {
	// The real point of a live re-check, not a cached/trusted claim: a
	// session minted while the user was an admin must stop working the
	// moment they're removed from the group -- not at next login, on
	// their very next request (issue #43).
	env, groupID := newLocalAdminTestEnv(t)
	ctx := context.Background()

	u, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := env.store.AssignUserGroup(ctx, u.ID, groupID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}

	token, err := env.as.LoginLocalAdmin(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("LoginLocalAdmin: %v", err)
	}
	if _, err := env.as.ValidateLocalAdminSession(ctx, token); err != nil {
		t.Fatalf("ValidateLocalAdminSession before removal: %v", err)
	}

	if err := env.store.RemoveUserGroup(ctx, u.ID, groupID); err != nil {
		t.Fatalf("RemoveUserGroup: %v", err)
	}

	if _, err := env.as.ValidateLocalAdminSession(ctx, token); err == nil {
		t.Fatal("expected the same still-unexpired token to be rejected immediately after group removal")
	}
}

func TestValidateLocalAdminSession_OrdinarySessionTokenRejected(t *testing.T) {
	// Cross-contamination check: a token minted for a completely
	// different purpose (the ordinary Mode A MCP-session re-exchange
	// token) must never validate as a local admin session, even though
	// both are signed by the same keys.
	env, groupID := newLocalAdminTestEnv(t)
	ctx := context.Background()

	u, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := env.store.AssignUserGroup(ctx, u.ID, groupID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}

	loginRec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantLogin}, "username": {"alice"}, "password": {"s3cret-pw"}, "resource": {"jira"},
	})
	if loginRec.Code != 200 {
		t.Fatalf("login: status = %d, body = %s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if loginResp.SessionToken == "" {
		t.Fatal("expected a session_token in the login response")
	}

	if _, err := env.as.ValidateLocalAdminSession(ctx, loginResp.SessionToken); err == nil {
		t.Fatal("expected an ordinary MCP-session re-exchange token to be rejected as a local admin session")
	}
}

func TestLoginLocalAdmin_MintedTokenRejectedByOrdinarySessionValidation(t *testing.T) {
	// The reverse cross-contamination check: a local admin session token
	// must never be usable to re-mint an ordinary per-node MCP access
	// token via the "session" grant.
	env, groupID := newLocalAdminTestEnv(t)
	ctx := context.Background()

	u, err := env.svc.CreateUser(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := env.store.AssignUserGroup(ctx, u.ID, groupID); err != nil {
		t.Fatalf("AssignUserGroup: %v", err)
	}
	token, err := env.as.LoginLocalAdmin(ctx, "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("LoginLocalAdmin: %v", err)
	}

	rec := tokenRequest(t, env.as, url.Values{
		"grant_type": {grantSession}, "session_token": {token}, "resource": {"jira"},
	})
	if rec.Code == 200 {
		t.Fatalf("expected the local admin session token to be rejected by the ordinary session grant, got 200: %s", rec.Body.String())
	}
}
