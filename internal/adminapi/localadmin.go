package adminapi

import (
	"context"
	"log/slog"
	"net/http"
)

// LocalAdminAuthenticator is what adminapi needs for the standalone (no
// spider-snoop) admin login path (issue #43): verify a local human's
// credentials and their live admin-group membership, and mint a signed
// session token on success. Defined here, not in internal/authserver, so
// this package's dependency surface stays minimal -- main.go is the only
// place that needs to know *authserver.AuthServer actually implements
// it (via a thin adapter, mirroring AdminTokenValidator/
// adminAuthValidator's existing pattern). Nil (Config.LocalAdmin unset)
// means this deployment doesn't support local admin login.
type LocalAdminAuthenticator interface {
	Login(ctx context.Context, username, password string) (sessionToken string, err error)
}

type authModeResponse struct {
	// Mode is "local" or "spider_snoop" -- tells the admin UI's Login
	// screen which credential shape this deployment actually accepts,
	// before it renders anything.
	Mode string `json:"mode"`
}

// getAuthMode serves GET /admin/ui/auth-mode (issue #43), unauthenticated
// like the session endpoints it sits alongside.
func (a *AdminAPI) getAuthMode(w http.ResponseWriter, r *http.Request) {
	mode := "spider_snoop"
	if a.localAdmin != nil {
		mode = "local"
	}
	writeJSON(w, http.StatusOK, authModeResponse{Mode: mode})
}

// createLocalAdminUISession is createUISession's standalone counterpart
// (issue #43): verifies username/password via LocalAdmin.Login instead
// of introspecting an already-established spider-snoop token, then hands
// the resulting session token to the *exact same* uisession.Registry/
// cookie-issuing code createUISession already uses -- everything
// downstream (whoami, gateBrowserOrService, logout) is unchanged,
// unbranched code, because that session token is just another opaque
// string to it.
func (a *AdminAPI) createLocalAdminUISession(w http.ResponseWriter, r *http.Request, username, password string) {
	if a.localAdmin == nil {
		writeAdminError(w, http.StatusBadRequest, "this deployment does not support local admin login")
		return
	}
	if username == "" || password == "" {
		writeAdminError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	token, err := a.localAdmin.Login(r.Context(), username, password)
	if err != nil {
		// Fail closed with a generic message regardless of the
		// underlying reason (unknown username, wrong password, not in
		// the admin group, or a real store error) -- same non-
		// enumerable, fail-closed posture as the spider-snoop
		// introspection path just below.
		writeAdminError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	sess, err := a.uiSessions.Create(token)
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
	slog.Info("admin ui session created (local admin)", "admin_username", username)
	writeJSON(w, http.StatusCreated, uiSessionResponse{Username: username, Role: "admin"})
}
