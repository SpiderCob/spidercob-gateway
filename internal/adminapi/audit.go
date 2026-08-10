package adminapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// auditRecordResponse mirrors store.AuditLogEntry's fields. hash/
// prev_hash are included even though this issue builds no
// verification UI on top of them -- a later "chain-intact indicator"
// feature (issue #25 spec, story 11) shouldn't need a second endpoint
// change to get the data it needs.
type auditRecordResponse struct {
	ID                 int64  `json:"id"`
	Timestamp          string `json:"ts"`
	ActorNHISubject    string `json:"actor_nhi_subject,omitempty"`
	ActorHumanUsername string `json:"actor_human_username"`
	ActorHumanRole     string `json:"actor_human_role"`
	Action             string `json:"action"`
	Resource           string `json:"resource"`
	PrevHash           string `json:"prev_hash"`
	Hash               string `json:"hash"`
}

func toAuditRecordResponse(e store.AuditLogEntry) auditRecordResponse {
	return auditRecordResponse{
		ID:                 e.ID,
		Timestamp:          e.Timestamp.Format(time.RFC3339),
		ActorNHISubject:    e.ActorNHISubject,
		ActorHumanUsername: e.ActorHumanUsername,
		ActorHumanRole:     e.ActorHumanRole,
		Action:             e.Action,
		Resource:           e.Resource,
		PrevHash:           e.PrevHash,
		Hash:               e.Hash,
	}
}

// listAudit serves GET /admin/audit (issue #25): a paginated,
// most-recent-first read over the audit trail issue #23 built.
// Malformed limit/before_id query params fall back to their defaults
// rather than 400ing -- a typo in a pagination parameter shouldn't
// break an otherwise-valid request to view recent activity. Never
// exposes audit.Verify or any chain-integrity computation -- that
// stays verifychain's job, not a normal listing request's cost.
func (a *AdminAPI) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit")) // 0 on parse failure -> store default
	beforeID, _ := strconv.ParseInt(r.URL.Query().Get("before_id"), 10, 64)

	entries, err := a.store.ListAuditRecordsPage(r.Context(), limit, beforeID)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to list audit records")
		return
	}
	out := make([]auditRecordResponse, 0, len(entries))
	for _, e := range entries {
		out = append(out, toAuditRecordResponse(e))
	}
	writeJSON(w, http.StatusOK, out)
}
