package adminapi

import (
	"context"
	"encoding/json"
	"testing"
)

// TestLogAdminAction_SuccessfulActionsProduceRealAuditRecords exercises
// logAdminAction's one seam via a representative handful of its nine
// callers (issue #23) -- the point being tested ("logAdminAction writes
// a real record") is identical logic regardless of which caller
// invoked it, so this isn't exhaustive over all nine.
func TestLogAdminAction_SuccessfulActionsProduceRealAuditRecords(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()

	body, _ := json.Marshal(createAgentRequest{Name: "ci-bot"})
	rec := fullyAuthedRequest(api, "POST", "/admin/agents", body)
	if rec.Code != 201 {
		t.Fatalf("create agent status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	groupBody, _ := json.Marshal(createGroupRequest{Name: "engineering"})
	groupRec := fullyAuthedRequest(api, "POST", "/admin/groups", groupBody)
	if groupRec.Code != 201 {
		t.Fatalf("create group status = %d, want 201, body = %s", groupRec.Code, groupRec.Body.String())
	}

	entries, err := s.ListAuditRecords(ctx)
	if err != nil {
		t.Fatalf("ListAuditRecords: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d audit records, want 2", len(entries))
	}

	first := entries[0]
	if first.Action != "create_agent" {
		t.Fatalf("entries[0].Action = %q, want create_agent", first.Action)
	}
	if first.ActorNHISubject != "agent:spider-snoop-backend" {
		t.Fatalf("entries[0].ActorNHISubject = %q, want agent:spider-snoop-backend", first.ActorNHISubject)
	}
	if first.ActorHumanUsername != "alice" || first.ActorHumanRole != "admin" {
		t.Fatalf("entries[0] actor = %q/%q, want alice/admin", first.ActorHumanUsername, first.ActorHumanRole)
	}
	if first.Resource == "" {
		t.Fatal("entries[0].Resource is empty, want the created agent's client_id")
	}

	second := entries[1]
	if second.Action != "create_group" || second.Resource != "engineering" {
		t.Fatalf("entries[1] = %+v, want action=create_group resource=engineering", second)
	}
}

// TestLogAdminAction_RejectedRequestProducesNoAuditRecord confirms the
// gate rejecting a request (before the handler, and therefore
// logAdminAction, ever runs) leaves the audit trail untouched -- only
// successful mutations are recorded (issue #23 spec, story 6).
func TestLogAdminAction_RejectedRequestProducesNoAuditRecord(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())

	rec := doAdminRequest(api, "POST", "/admin/agents", reqOpts{}) // no credential at all
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	entries, err := s.ListAuditRecords(context.Background())
	if err != nil {
		t.Fatalf("ListAuditRecords: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("got %d audit records for a rejected request, want 0", len(entries))
	}
}

// TestLogAdminAction_UISessionOriginatedActionHasEmptyNHISubject
// confirms a cookie-authenticated action (issue #17) records an empty
// ActorNHISubject, matching adminIdentity's existing shape for a
// UI-session-originated request rather than fabricating one.
func TestLogAdminAction_UISessionOriginatedActionHasEmptyNHISubject(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())

	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", loginBody, nil)
	cookie := sessionCookieFrom(loginRec)

	body, _ := json.Marshal(createGroupRequest{Name: "ui-created"})
	rec := doRawRequest(api, "POST", "/admin/groups", body, cookie)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	entries, err := s.ListAuditRecords(context.Background())
	if err != nil {
		t.Fatalf("ListAuditRecords: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit records, want 1", len(entries))
	}
	if entries[0].ActorNHISubject != "" {
		t.Fatalf("ActorNHISubject = %q, want empty for a UI-session-originated action", entries[0].ActorNHISubject)
	}
}
