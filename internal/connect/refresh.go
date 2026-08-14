// Package connect implements the "spidercob connect" subcommand (issue
// #52): a local reverse proxy that holds one long-lived NHI credential,
// mints and silently refreshes short-lived, node-scoped access tokens in
// the background, and forwards MCP traffic to the real gateway with a
// currently-valid Authorization header attached. The calling MCP client
// presents no credential of its own at all.
//
// Zero changes to internal/authserver/internal/proxy -- this package is
// purely a client of the existing, unchanged /token endpoint and
// node-scoped aud claims.
package connect

import "time"

// DefaultRefreshFraction is the fraction of a token's total lifetime
// (expiresAt - issuedAt) that must elapse before the background loop
// proactively refreshes it -- confirmed in the issue #52 spec. 0.75
// leaves real headroom (a token minted with the default 120s NHI TTL
// gets refreshed at the 90s mark, 30s before it would actually expire)
// without refreshing so eagerly that a short-lived token barely gets
// used before being replaced.
const DefaultRefreshFraction = 0.75

// dueForRefresh reports whether a token issued at issuedAt and expiring
// at expiresAt should be refreshed now, at refreshFraction of its total
// lifetime elapsed. A token that's already at or past its expiry (or
// was never issued at all -- the zero time.Time value naturally falls
// into this branch too, since "now" is never before the zero time) is
// unconditionally due, regardless of the fraction math.
func dueForRefresh(now, issuedAt, expiresAt time.Time, refreshFraction float64) bool {
	if !now.Before(expiresAt) {
		return true
	}
	lifetime := expiresAt.Sub(issuedAt)
	threshold := issuedAt.Add(time.Duration(float64(lifetime) * refreshFraction))
	return !now.Before(threshold)
}
