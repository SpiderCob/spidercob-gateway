package policy

import "github.com/sumeetgp/spidercob-gateway/internal/store"

// evalResult is what the pure matching/evaluation logic produces --
// deliberately separate from Decision, which additionally reflects
// rate-limiting (stateful, not pure) applied on top by Evaluator.Decide.
type evalResult struct {
	Allowed                bool
	BlockOnScanFlag        bool
	RateLimitMaxCalls      *int
	RateLimitWindowSeconds *int
}

// matches reports whether p applies to a request for method (and, when
// method is "tools/call", tool). An empty Methods list matches every
// method; an empty Tools list matches every tool, and Tools is only
// consulted at all when method is "tools/call" -- a Tools entry on a rule
// that doesn't also gate tools/call would be meaningless, so it's ignored
// rather than silently mismatching everything.
func matches(p store.Policy, method, tool string) bool {
	if len(p.Methods) > 0 && !contains(p.Methods, method) {
		return false
	}
	if method == "tools/call" && len(p.Tools) > 0 && !contains(p.Tools, tool) {
		return false
	}
	return true
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// evaluate implements the decided evaluation order (MASTER_PLAN.md §6,
// 2026-08-04): collect every rule (across all of a principal's groups,
// already narrowed to the right node by the caller) matching this
// method/tool -> any DENY among them wins outright -> else any ALLOW wins
// -> else default-deny. Multiple simultaneously-matching ALLOW rules are
// additive for the allow/deny outcome itself; for BlockOnScanFlag, any
// matching ALLOW rule requesting it is enough to apply it (escalating too
// eagerly is the safe direction); for rate limiting, the most restrictive
// (smallest max-calls) among matching ALLOW rules that set one applies.
func evaluate(policies []store.Policy, method, tool string) evalResult {
	var sawAllow, sawDeny bool
	var blockOnScanFlag bool
	var maxCalls, windowSeconds *int

	for _, p := range policies {
		if !matches(p, method, tool) {
			continue
		}
		switch p.RuleType {
		case store.PolicyDeny:
			sawDeny = true
		case store.PolicyAllow:
			sawAllow = true
			if p.BlockOnScanFlag {
				blockOnScanFlag = true
			}
			if p.RateLimitMaxCalls != nil && (maxCalls == nil || *p.RateLimitMaxCalls < *maxCalls) {
				maxCalls = p.RateLimitMaxCalls
				windowSeconds = p.RateLimitWindowSeconds
			}
		}
	}

	if sawDeny {
		return evalResult{Allowed: false}
	}
	if !sawAllow {
		return evalResult{Allowed: false}
	}
	return evalResult{
		Allowed:                true,
		BlockOnScanFlag:        blockOnScanFlag,
		RateLimitMaxCalls:      maxCalls,
		RateLimitWindowSeconds: windowSeconds,
	}
}
