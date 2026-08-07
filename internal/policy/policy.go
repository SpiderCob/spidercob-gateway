// Package policy decides whether a request may reach an MCP node.
// Phase 3 replaces AllowAll with the group/method/tool evaluator backed by the
// store (design doc §5): server-level -> method-level -> tool-level ->
// parameter-level, default-deny, tools/list filtering.
package policy

import "net/http"

type Engine interface {
	Allow(node string, r *http.Request) bool
}

// AllowAll is the phase-1 placeholder. It exists so the call site in the proxy
// is already shaped correctly; do NOT ship a release with this as the default.
type AllowAll struct{}

func (AllowAll) Allow(string, *http.Request) bool { return true }

// DenyAll is the phase-2 default, replacing AllowAll the moment real
// tokens exist (MASTER_PLAN.md §6, 2026-08-04 decision): a validly
// authenticated caller with no assigned group still gets nothing, not
// everything, until Phase 3's real group/method/tool evaluator lands.
// Fail static, never fail open (design doc §0) applies here too -- an
// unauthored policy state must resolve to "nothing works," not "anything
// goes."
type DenyAll struct{}

func (DenyAll) Allow(string, *http.Request) bool { return false }
