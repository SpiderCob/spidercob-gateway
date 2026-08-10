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

// moreRestrictive reports whether (calls1 over window1) is a stricter
// rate limit than (calls2 over window2). "Most restrictive" means the
// lower effective rate (calls/window), not the smaller raw max_calls --
// 1/sec is far stricter than 2/hour even though 1 < 2. Compared via
// cross-multiplication (calls1*window2 vs calls2*window1) to avoid
// floating point. When the effective rate is exactly equal, the smaller
// max_calls wins as a tie-break: 1/60s and 10/600s average the same rate,
// but 1/60s permits far less burst.
func moreRestrictive(calls1, window1, calls2, window2 int) bool {
	lhs := int64(calls1) * int64(window2)
	rhs := int64(calls2) * int64(window1)
	if lhs != rhs {
		return lhs < rhs
	}
	return calls1 < calls2
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
// (lowest effective rate, calls/window -- see moreRestrictive) among
// matching ALLOW rules that set one applies.
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
			if p.RateLimitMaxCalls != nil && p.RateLimitWindowSeconds != nil &&
				(maxCalls == nil || moreRestrictive(*p.RateLimitMaxCalls, *p.RateLimitWindowSeconds, *maxCalls, *windowSeconds)) {
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
