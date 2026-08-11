package adminapi

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ErrSessionNotFound is returned by MCPSessionManager.EndSession when id
// doesn't correspond to a currently live session -- deliberately this
// package's own sentinel, not internal/proxy's, so this package never
// needs to import internal/proxy directly (issue #35, kill-session).
// main.go's wiring adapter is responsible for translating
// proxy.ErrSessionNotFound into this one.
var ErrSessionNotFound = errors.New("adminapi: session not found")

// SessionInfo is a point-in-time snapshot of one live MCP session, this
// package's own copy of internal/proxy's SessionInfo shape -- mirrors
// AdminClaims/AuthClaims' existing "parallel shape, no shared import"
// pattern (issue #13).
type SessionInfo struct {
	ID        string
	Node      string
	Principal string
	IdleSince time.Time
}

// MCPSessionManager is what the admin API needs from the gateway's live
// MCP session state (issue #35, kill-session): list every currently live
// session, and end one by id. Deliberately distinct from UISessions
// (internal/uisession.Registry, the browser admin-UI login concept) --
// this is about the traffic-facing MCP sessions clients actually use the
// gateway for. Defined here, not in internal/proxy, so this package's
// dependency surface stays minimal -- main.go is the only place that
// needs to know *proxy.Gateway actually satisfies it (via a thin adapter,
// since proxy.SessionInfo and this package's SessionInfo are distinct
// types by design, same reasoning as AdminTokenValidator/
// adminAuthValidator).
type MCPSessionManager interface {
	ListSessions() []SessionInfo
	EndSession(ctx context.Context, id string) error
}

type sessionResponse struct {
	ID        string `json:"id"`
	Node      string `json:"node"`
	Principal string `json:"principal"`
	IdleSince string `json:"idle_since"`
}

func toSessionResponse(s SessionInfo) sessionResponse {
	return sessionResponse{ID: s.ID, Node: s.Node, Principal: s.Principal, IdleSince: s.IdleSince.Format(time.RFC3339)}
}

// listSessions serves GET /admin/sessions (issue #35): every currently
// live MCP session across every node, for an admin to review before
// deciding whether to kill one.
func (a *AdminAPI) listSessions(w http.ResponseWriter, r *http.Request) {
	sessions := a.mcpSessions.ListSessions()
	out := make([]sessionResponse, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, toSessionResponse(s))
	}
	writeJSON(w, http.StatusOK, out)
}

// killSession serves DELETE /admin/sessions/{id} (issue #35): ends one
// specific session, reusing the exact teardown path a session's own
// owner already gets via DELETE /mcp/{node} -- this is simply a second,
// admin-authenticated door onto that existing mechanism.
func (a *AdminAPI) killSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.mcpSessions.EndSession(r.Context(), id); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			writeAdminError(w, http.StatusNotFound, "session not found")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "failed to end session")
		return
	}
	a.logAdminAction(r, "kill_session", id)
	w.WriteHeader(http.StatusNoContent)
}
