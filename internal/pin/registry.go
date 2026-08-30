package pin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// Registry is the store-backed TOFU pin tracker for one gateway process.
// See the package doc comment for why establishing a pin on first
// observation -- rather than requiring admin pre-approval, which has no
// UI/API yet -- is the trust mechanism, and why persistence across
// restarts is load-bearing rather than incidental.
type Registry struct {
	store store.Store
}

// NewRegistry builds a Registry backed by s.
func NewRegistry(s store.Store) *Registry {
	return &Registry{store: s}
}

// Observe reconciles node's currently-observed tool definitions against
// their pins: a tool seen for the first time is pinned (TOFU); a
// previously-pinned, not-yet-quarantined tool whose hash no longer
// matches is quarantined, with driftDetail recording what changed for
// later investigation (story 12). An already-quarantined tool is left
// alone -- there is no re-approval mechanism in this phase (Phase 4), so
// re-observing the same drifted definition on every subsequent refresh
// must not reset, duplicate, or otherwise disturb the existing
// quarantine.
func (r *Registry) Observe(ctx context.Context, node string, tools []ToolDef) error {
	for _, t := range tools {
		newHash, err := Hash(t)
		if err != nil {
			return fmt.Errorf("pin: hash %s/%s: %w", node, t.Name, err)
		}

		existing, err := r.store.GetToolPin(ctx, node, t.Name)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if _, err := r.store.CreateToolPin(ctx, node, t.Name, newHash, string(t.InputSchema)); err != nil {
				return fmt.Errorf("pin: establish %s/%s: %w", node, t.Name, err)
			}
		case err != nil:
			return fmt.Errorf("pin: lookup %s/%s: %w", node, t.Name, err)
		case existing.QuarantinedAt != nil:
			// Already quarantined -- no re-approval mechanism this phase.
		case Drifted(existing.Hash, newHash):
			detail := fmt.Sprintf("hash changed from %s to %s", existing.Hash, newHash)
			if err := r.store.QuarantineToolPin(ctx, node, t.Name, detail); err != nil {
				return fmt.Errorf("pin: quarantine %s/%s: %w", node, t.Name, err)
			}
			// Story 12: a quarantine event needs enough detail to actually
			// investigate, not just "something changed."
			slog.Warn("pin: tool quarantined, definition drifted since it was pinned",
				"node", node, "tool", t.Name, "old_hash", existing.Hash, "new_hash", newHash)
		}
	}
	return nil
}

// Approve re-pins node's tool current to its freshly-observed definition
// and clears its quarantine (issue #59: spidercob-admin's approve_tool)
// -- a deliberate, one-time TOFU reset for that one tool, the only way a
// quarantine ever clears (Observe itself never re-approves anything, see
// its own doc comment). current must be the tool's *live*, just-fetched
// definition, not the stale one that triggered the quarantine -- the
// caller (internal/adminmcp) is responsible for fetching it fresh via
// the same Fetcher the background scheduler already uses, before calling
// this. Returns whatever error the underlying store call does, including
// store.ErrNotFound if no pin exists for this tool at all -- there's
// nothing to approve for a tool that was never observed in the first
// place.
func (r *Registry) Approve(ctx context.Context, node string, current ToolDef) error {
	newHash, err := Hash(current)
	if err != nil {
		return fmt.Errorf("pin: hash %s/%s: %w", node, current.Name, err)
	}
	return r.store.ApproveToolPin(ctx, node, current.Name, newHash, string(current.InputSchema))
}

// NonQuarantined filters toolNames down to those with no quarantined pin
// for node. Deliberately mirrors policy.Evaluator.FilterTools' shape so
// the two compose directly at the tools/list filtering seam (story 9).
// Fail static: a store error drops every tool rather than risk showing a
// quarantined one, the same "never fail open" posture policy.Evaluator
// already takes.
func (r *Registry) NonQuarantined(ctx context.Context, node string, toolNames []string) []string {
	pins, err := r.store.ToolPinsForNode(ctx, node)
	if err != nil {
		return nil
	}
	quarantined := make(map[string]bool, len(pins))
	for _, p := range pins {
		if p.QuarantinedAt != nil {
			quarantined[p.ToolName] = true
		}
	}
	out := make([]string, 0, len(toolNames))
	for _, name := range toolNames {
		if !quarantined[name] {
			out = append(out, name)
		}
	}
	return out
}

// IsQuarantined reports whether node's tool toolName currently has a
// quarantined pin -- the tools/call pre-dispatch gate's seam (story 10).
// Fail static: a store error is treated as quarantined. A tool that's
// never been observed (no pin exists yet) is treated as not quarantined
// -- TOFU establishes its pin on the next background refresh, a request
// racing ahead of that first observation isn't itself evidence of drift.
func (r *Registry) IsQuarantined(ctx context.Context, node, toolName string) bool {
	p, err := r.store.GetToolPin(ctx, node, toolName)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		return true
	}
	return p.QuarantinedAt != nil
}

// PinnedSchema returns node's tool toolName's currently-pinned
// inputSchema, if any -- the schema-enforcement seam's read side (issue
// #11). exists is false when no pin has been established yet for this
// (node, toolName), distinguishable from "a pin exists but the tool has
// no inputSchema" (schema == nil, exists == true): both call for the
// same treatment at the call site -- nothing to validate against, so
// skip validation and allow through (stories 2 and 23) -- but for
// different reasons worth keeping distinguishable in the return shape
// even though today's caller treats them identically.
func (r *Registry) PinnedSchema(ctx context.Context, node, toolName string) (schema json.RawMessage, exists bool, err error) {
	p, err := r.store.GetToolPin(ctx, node, toolName)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if p.InputSchema == nil {
		return nil, true, nil
	}
	return json.RawMessage(*p.InputSchema), true, nil
}
