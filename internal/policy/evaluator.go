package policy

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// Evaluator is the real, store-backed Engine (issue #7) -- replaces
// DenyAll the moment policy is actually configured. Resolves a
// principal's groups fresh from the store on every call (no caching):
// group membership and policy are already re-resolved on every token
// reissuance and re-checked per request (design doc §5's "request-time
// check wins," MASTER_PLAN.md §6 2026-08-04), so a live lookup here is
// what that decision actually requires, not an optimization to add later.
type Evaluator struct {
	store   store.Store
	limiter *rateLimiter
}

// NewEvaluator builds an Evaluator backed by s, with a real wall-clock
// rate limiter.
func NewEvaluator(s store.Store) *Evaluator {
	return &Evaluator{store: s, limiter: newRateLimiter(time.Now)}
}

// principalGroupIDs resolves "user:<username>" or "agent:<client_id>"
// (the sub claim shape internal/authserver already mints, issue #3/§5) to
// that principal's group IDs. An unrecognized prefix or a lookup miss
// both resolve to "no groups" -- which evaluate() already turns into
// default-deny, so this doesn't need its own separate error path to stay
// fail-static.
func (e *Evaluator) principalGroupIDs(ctx context.Context, principal string) ([]int64, error) {
	switch {
	case strings.HasPrefix(principal, "user:"):
		username := strings.TrimPrefix(principal, "user:")
		u, err := e.store.GetUserByUsername(ctx, username)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		groups, err := e.store.UserGroups(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		return groupIDs(groups), nil
	case strings.HasPrefix(principal, "agent:"):
		clientID := strings.TrimPrefix(principal, "agent:")
		a, err := e.store.GetAgentByClientID(ctx, clientID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		groups, err := e.store.AgentGroups(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		return groupIDs(groups), nil
	default:
		// Matches the lookup-miss case above: no separate error path,
		// just "no groups" -- evaluate() already turns that into
		// default-deny, so an unrecognized shape stays fail-static
		// without generating its own noisy error handling.
		return nil, nil
	}
}

func groupIDs(groups []store.Group) []int64 {
	ids := make([]int64, len(groups))
	for i, g := range groups {
		ids[i] = g.ID
	}
	return ids
}

// policiesFor resolves principal's groups and fetches every policy rule
// attached to any of them, scoped to node -- the one store round trip
// both Decide and FilterTools build on.
func (e *Evaluator) policiesFor(ctx context.Context, principal, node string) ([]store.Policy, error) {
	ids, err := e.principalGroupIDs(ctx, principal)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return e.store.PoliciesForGroups(ctx, ids, node)
}

func (e *Evaluator) Decide(ctx context.Context, principal, node, method, tool string) Decision {
	policies, err := e.policiesFor(ctx, principal, node)
	if err != nil {
		return Decision{Allowed: false} // fail static, never fail open
	}
	res := evaluate(policies, method, tool)
	if !res.Allowed {
		return Decision{Allowed: false}
	}
	if res.RateLimitMaxCalls != nil && res.RateLimitWindowSeconds != nil {
		key := principal + "|" + node
		window := time.Duration(*res.RateLimitWindowSeconds) * time.Second
		if !e.limiter.allow(key, *res.RateLimitMaxCalls, window) {
			return Decision{Allowed: false, RateLimited: true}
		}
	}
	return Decision{Allowed: true, BlockOnScanFlag: res.BlockOnScanFlag}
}

func (e *Evaluator) FilterTools(ctx context.Context, principal, node string, toolNames []string) []string {
	policies, err := e.policiesFor(ctx, principal, node)
	if err != nil {
		return nil
	}
	var out []string
	for _, name := range toolNames {
		if evaluate(policies, "tools/call", name).Allowed {
			out = append(out, name)
		}
	}
	return out
}
