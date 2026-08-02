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
