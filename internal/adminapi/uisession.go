package adminapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// UISessionCookieName is the HttpOnly cookie the browser-facing admin
// UI (issue #17) uses to carry its session token. Deliberately a
// distinct name/mechanism from HumanSessionHeader: that header carries
// the raw spider-snoop session token on every service-to-service
// request; this cookie carries an opaque, gateway-minted token that
// only ever maps back to a spider-snoop token server-side, via
// a.uiSessions -- the browser never needs to hold or resend the
// spider-snoop token itself after the initial login call.
const UISessionCookieName = "spidercob_admin_session"

type createUISessionRequest struct {
	// SpiderSnoopSessionToken is the human's own, already-established
	// spider-snoop session token. v0's login UX is a manual paste (no
	// redirect-based SSO yet -- a real spider-snoop-side change,
	// deliberately deferred, see the issue #17 spec).
	SpiderSnoopSessionToken string `json:"spider_snoop_session_token,omitempty"`
	// Username/Password are the standalone (no spider-snoop) local admin
	// login alternative (issue #43) -- mutually exclusive with
	// SpiderSnoopSessionToken; a request naming Username routes to
	// createLocalAdminUISession instead of the spider-snoop path below.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type uiSessionResponse struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// createUISession is the login endpoint: verify the submitted spider-
// snoop session token via the exact same SpiderSnoopIntrospector the
// service-to-service path already uses, and on success mint a new
// gateway-local UI session and set it as an HttpOnly cookie. This is
// the one place a raw spider-snoop token is ever handled by the UI
// session mechanism -- every subsequent request only ever presents the
// cookie.
func (a *AdminAPI) createUISession(w http.ResponseWriter, r *http.Request) {
	var req createUISessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username != "" || req.Password != "" {
		a.createLocalAdminUISession(w, r, req.Username, req.Password)
		return
	}

	if req.SpiderSnoopSessionToken == "" {
		writeAdminError(w, http.StatusBadRequest, "spider_snoop_session_token is required")
		return
	}

	result, err := a.introspector.Introspect(r.Context(), req.SpiderSnoopSessionToken)
	if err != nil {
		// Fail closed, same posture as gate: an introspection error
		// (spider-snoop unreachable, timed out, ...) is never treated
		// as "log them in anyway."
		writeAdminError(w, http.StatusServiceUnavailable, "failed to verify spider-snoop session")
		return
	}
	if !isAdminRole(result.Role) {
		writeAdminError(w, http.StatusForbidden, "session does not have admin access")
		return
	}

	sess, err := a.uiSessions.Create(req.SpiderSnoopSessionToken)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     UISessionCookieName,
		Value:    sess.Token,
		Path:     "/admin/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	slog.Info("admin ui session created", "admin_username", result.Username, "admin_role", result.Role)
	writeJSON(w, http.StatusCreated, uiSessionResponse{Username: result.Username, Role: result.Role})
}

// getUISession is the whoami endpoint the SPA calls on load to decide
// whether to show the login screen or the app.
func (a *AdminAPI) getUISession(w http.ResponseWriter, r *http.Request) {
	ident, ok := a.checkUISessionCookie(r)
	if !ok {
		writeAdminError(w, http.StatusUnauthorized, "no active session")
		return
	}
	writeJSON(w, http.StatusOK, uiSessionResponse{Username: ident.humanUsername, Role: ident.humanRole})
}

// deleteUISession is logout: idempotent, clearing both the server-side
// registry entry (if any) and the cookie itself. A request with no
// cookie, or a cookie for a session that's already gone, still
// succeeds -- logging out twice is not an error.
func (a *AdminAPI) deleteUISession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(UISessionCookieName); err == nil {
		a.uiSessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     UISessionCookieName,
		Value:    "",
		Path:     "/admin/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// checkUISessionCookie is the one place the cookie -> trusted identity
// decision is made, shared by getUISession and gateBrowserOrService so
// there is exactly one implementation of "is this cookie currently
// good," not two that could drift. A session's registry lookup
// (uisession.Registry.Get) only bounds this UI session's own absolute
// age; checkUISessionCookie additionally re-introspects the session's
// underlying spider-snoop token live, on every call -- a spider-snoop-
// side logout or role downgrade must be caught here too, the same
// fail-static posture gate already takes for the service-to-service
// path, not just "the cookie still resolves to something."
func (a *AdminAPI) checkUISessionCookie(r *http.Request) (adminIdentity, bool) {
	c, err := r.Cookie(UISessionCookieName)
	if err != nil || c.Value == "" {
		return adminIdentity{}, false
	}
	sess, ok := a.uiSessions.Get(c.Value)
	if !ok {
		return adminIdentity{}, false
	}
	result, err := a.introspector.Introspect(r.Context(), sess.HumanToken)
	if err != nil || !isAdminRole(result.Role) {
		return adminIdentity{}, false
	}
	return adminIdentity{humanUsername: result.Username, humanRole: result.Role}, true
}
