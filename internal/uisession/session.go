// Package uisession is the gateway admin UI's browser-facing session
// mechanism (issue #17, Phase 4c-1). It is deliberately narrower than
// the dual-trust NHI-token-plus-header check internal/adminapi's
// service-to-service callers use (issues #13, #15): a browser can
// never safely hold the NHI client_secret needed to mint an
// admin-audience token, so a UI session is instead minted from a
// one-time verification of the human's own spider-snoop session token,
// via the exact same SpiderSnoopIntrospector already used for the
// service-to-service path -- no new spider-snoop-side surface, no new
// trust primitive, just a different entry point onto the same live
// check.
package uisession

import "time"

// Session is a single browser-facing admin session -- the value an
// HttpOnly cookie's opaque token maps to. Deliberately in-memory only
// (see Registry): a gateway restart logs every UI session out, the
// same posture MCP's own Mcp-Session-Id mapping already takes.
type Session struct {
	// Token is the opaque, cryptographically-random cookie value.
	Token string
	// HumanToken is the underlying spider-snoop session token supplied
	// at login. It is re-submitted to SpiderSnoopIntrospector on every
	// subsequent request that presents this session's cookie -- Valid
	// alone only bounds this session's own absolute age, it is never a
	// substitute for that live check (a spider-snoop-side logout or
	// role downgrade must still be caught, not just "cookie exists").
	HumanToken string
	CreatedAt  time.Time
}

// Valid is the registry's pure decision function -- mirrors
// internal/pin's dueForRefresh injectable-clock pattern: a session is
// valid only while its absolute age is under maxAge. A zero-value
// Session (never created) and a non-positive maxAge are both always
// invalid -- there is no "always valid" sentinel here the way
// dueForRefresh has one for "always due", since an admin UI session
// with no upper bound at all would be a real security regression, not
// a convenience.
func Valid(s Session, now time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 || s.CreatedAt.IsZero() {
		return false
	}
	return now.Sub(s.CreatedAt) < maxAge
}
