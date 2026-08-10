package adminapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/audit"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

func seedAuditRecords(t *testing.T, s store.Store, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		_, err := s.AppendAuditRecord(ctx, audit.Record{
			Timestamp:          time.Now(),
			ActorNHISubject:    "agent:spider-snoop-backend",
			ActorHumanUsername: "alice",
			ActorHumanRole:     "admin",
			Action:             "seeded_action",
			Resource:           "res",
		})
		if err != nil {
			t.Fatalf("AppendAuditRecord: %v", err)
		}
	}
}

func decodeAuditPage(t *testing.T, rec *httptest.ResponseRecorder) []auditRecordResponse {
	t.Helper()
	var out []auditRecordResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v (body: %s)", err, rec.Body.String())
	}
	return out
}

func TestListAudit_NHITokenPlusHeaderSucceeds(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	seedAuditRecords(t, s, 2)

	rec := fullyAuthedRequest(api, "GET", "/admin/audit", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeAuditPage(t, rec)
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
}

func TestListAudit_CookieAloneSucceeds(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	seedAuditRecords(t, s, 1)

	loginBody, _ := json.Marshal(createUISessionRequest{SpiderSnoopSessionToken: "human-token"})
	loginRec := doRawRequest(api, "POST", "/admin/ui/session", loginBody, nil)
	cookie := sessionCookieFrom(loginRec)

	rec := doRawRequest(api, "GET", "/admin/audit", nil, cookie)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (cookie alone, no NHI token, from day one -- issue #25), body = %s", rec.Code, rec.Body.String())
	}
}

func TestListAudit_NoCredentialRejected(t *testing.T) {
	api, _ := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	rec := doAdminRequest(api, "GET", "/admin/audit", reqOpts{})
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestListAudit_MostRecentFirst(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	ctx := context.Background()
	first, err := s.AppendAuditRecord(ctx, audit.Record{Timestamp: time.Now(), ActorHumanUsername: "alice", ActorHumanRole: "admin", Action: "a1", Resource: "r1"})
	if err != nil {
		t.Fatalf("AppendAuditRecord: %v", err)
	}
	second, err := s.AppendAuditRecord(ctx, audit.Record{Timestamp: time.Now(), ActorHumanUsername: "alice", ActorHumanRole: "admin", Action: "a2", Resource: "r2"})
	if err != nil {
		t.Fatalf("AppendAuditRecord: %v", err)
	}

	rec := fullyAuthedRequest(api, "GET", "/admin/audit", nil)
	got := decodeAuditPage(t, rec)
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[0].ID != second.ID || got[1].ID != first.ID {
		t.Fatalf("got ids [%d, %d], want most-recent-first [%d, %d]", got[0].ID, got[1].ID, second.ID, first.ID)
	}
}

func TestListAudit_PaginationParamsForwarded(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	seedAuditRecords(t, s, 5)

	firstPage := decodeAuditPage(t, fullyAuthedRequest(api, "GET", "/admin/audit?limit=2", nil))
	if len(firstPage) != 2 {
		t.Fatalf("first page: got %d records, want 2", len(firstPage))
	}

	secondPage := decodeAuditPage(t, fullyAuthedRequest(api, "GET",
		"/admin/audit?limit=2&before_id="+strconv.FormatInt(firstPage[len(firstPage)-1].ID, 10), nil))
	if len(secondPage) != 2 {
		t.Fatalf("second page: got %d records, want 2", len(secondPage))
	}
	for _, older := range secondPage {
		for _, newer := range firstPage {
			if older.ID == newer.ID {
				t.Fatalf("record %d appeared on both pages", older.ID)
			}
		}
		if older.ID >= firstPage[len(firstPage)-1].ID {
			t.Fatalf("second page record id %d should be older than %d", older.ID, firstPage[len(firstPage)-1].ID)
		}
	}
}

func TestListAudit_MalformedPaginationParamsFallBackToDefaults(t *testing.T) {
	api, s := newTestAdminAPI(t, validAdminAuthn(), adminIntrospector())
	seedAuditRecords(t, s, 2)

	rec := fullyAuthedRequest(api, "GET", "/admin/audit?limit=not-a-number&before_id=also-not-a-number", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (malformed params should fall back to defaults, not 400), body = %s", rec.Code, rec.Body.String())
	}
	got := decodeAuditPage(t, rec)
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
}
