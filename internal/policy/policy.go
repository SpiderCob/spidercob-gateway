// Package policy decides whether a request may reach an MCP node.
// Phase 3a (issue #7) replaces the DenyAll stub with the real
// group/method/tool evaluator backed by the store (design doc §5):
// server-level -> method-level -> tool-level, default-deny,
// deny-overrides-allow-overrides-default-deny, additive-allow across every
// group a principal belongs to (MASTER_PLAN.md §6, 2026-08-04). Also
// covers tools/list response filtering, per-group/per-NHI rate limiting,
// and block-on-scan-flag. Parameter-level constraints remain a v1.1 item
// (design doc §5), not built here.
package policy

import "context"

// Decision is the result of a request-time policy check.
type Decision struct {
	Allowed bool
	// RateLimited is only meaningful when Allowed is false -- it
	// distinguishes "denied by policy" (403) from "allowed by policy but
	// over the rate limit right now" (429), so a client can tell the two
	// apart.
	RateLimited bool
	// BlockOnScanFlag is only meaningful when Allowed is true -- the
	// caller (internal/proxy) should escalate any non-Allow scan verdict
	// on this specific call from "log only" to "block," per whichever
	// matched ALLOW rule requested it.
	BlockOnScanFlag bool
}

// Engine is what internal/proxy consults for every request (the
// server/method/tool decision) and for every tools/list response (which
// tools a principal is allowed to see at all, given they can already call
// tools/list). principal is the validated access token's sub claim (e.g.
// "user:alice", "agent:agt_x") -- see proxy.AuthClaimsFromContext.
type Engine interface {
	// Decide evaluates one request: principal calling method (and, when
	// method is "tools/call", tool) against node.
	Decide(ctx context.Context, principal, node, method, tool string) Decision
	// FilterTools returns the subset of toolNames principal is authorized
	// to invoke via tools/call on node, preserving order. Does not consume
	// rate limit -- listing what's available shouldn't cost the same
	// budget as actually invoking it.
	FilterTools(ctx context.Context, principal, node string, toolNames []string) []string
}

// AllowAll is the phase-1 placeholder, kept for tests that isolate
// session/routing/stdio behavior from policy (same purpose as issue #3's
// DevAllowAllPolicy escape hatch). Do NOT ship a release with this as the
// default.
type AllowAll struct{}

func (AllowAll) Decide(context.Context, string, string, string, string) Decision {
	return Decision{Allowed: true}
}

func (AllowAll) FilterTools(_ context.Context, _, _ string, toolNames []string) []string {
	return toolNames
}

// DenyAll is the phase-2/3a-until-configured default: a validly
// authenticated caller with no assigned group, or no matching policy
// rule, still gets nothing, not everything. Fail static, never fail open
// (design doc §0) -- an unauthored policy state must resolve to "nothing
// works," not "anything goes."
type DenyAll struct{}

func (DenyAll) Decide(context.Context, string, string, string, string) Decision {
	return Decision{Allowed: false}
}

func (DenyAll) FilterTools(context.Context, string, string, []string) []string {
	return nil
}
