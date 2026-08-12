// Policy matrix cell classification (issue #41) -- a deliberate,
// simplified client-side re-derivation of internal/policy/evaluate.go's
// real evaluation semantics, NOT a re-implementation shared with the Go
// code (there's no realistic way for a browser-side TS function to share
// a Go package's logic directly -- the discipline here is keeping the two
// *semantically* in sync by design, not by shared implementation). If
// evaluate.go's real semantics ever change, this needs a deliberate,
// matching update.
//
// This summarizes *configuration* for a (group, node) pair, independent
// of any specific method/tool/request -- it does not answer "would this
// exact call succeed," which is a narrower question the real gateway
// already answers correctly at actual request time.
import type { PolicyRule } from './api'

export type CellState = 'no-rule' | 'allowed' | 'denied' | 'restricted'

// isUnscoped mirrors matches()'s notion of "matches every request": a
// rule with no methods restriction and no tools restriction matches
// unconditionally. A rule with only `tools` set (no `methods`) still
// technically matches every non-tools/call method in the real evaluator
// (see evaluate.go's own doc comment on this), but is treated as scoped
// here regardless -- from a policy-review perspective, a tools-restricted
// row is never a full grant of everything, and this classifier
// deliberately errs toward flagging that ambiguity as "restricted" rather
// than ever showing a narrower-than-actual grant as "allowed".
function isUnscoped(rule: PolicyRule): boolean {
  return (rule.methods ?? []).length === 0 && (rule.tools ?? []).length === 0
}

// rulesForCell returns every rule that applies to this exact (group,
// node) pair -- the full set classifyCell and the cell-detail view both
// work from.
export function rulesForCell(policies: PolicyRule[], group: string, node: string): PolicyRule[] {
  return policies.filter((p) => p.group === group && p.node === node)
}

// classifyCell mirrors evaluate()'s real decision order (any matching
// DENY wins outright over any ALLOW; otherwise any matching ALLOW wins;
// otherwise default-deny) generalized across every possible method/tool,
// rather than one specific request:
//
//   - no rule at all for this pair                                -> "no-rule"
//   - no ALLOW rule at all (sawAllow can never become true, so the
//     real evaluator returns Allowed:false for every possible
//     method/tool regardless of any DENY's own scoping)            -> "denied"
//   - an unscoped DENY exists (matches, and wins over, every
//     possible request)                                            -> "denied"
//   - an unscoped ALLOW exists and no DENY exists at all            -> "allowed"
//   - anything else that still has at least one matching ALLOW      -> "restricted"
//     (the ALLOW itself is scoped, or a scoped DENY carves out part
//     of an otherwise-unscoped ALLOW)
//
// Verified by hand against a direct port of evaluate.go's real logic,
// including a brute-force cross-check across a spread of representative
// method/tool combinations -- see the PR this shipped in for the
// verification script (issue #41 has no application-level test harness
// to commit this as; web/ has no JS/browser test infra in this repo).
export function classifyCell(rulesForPair: PolicyRule[]): CellState {
  if (rulesForPair.length === 0) return 'no-rule'

  const allows = rulesForPair.filter((r) => r.rule_type === 'allow')
  const denies = rulesForPair.filter((r) => r.rule_type === 'deny')

  if (allows.length === 0) return 'denied'
  if (denies.some(isUnscoped)) return 'denied'
  if (allows.some(isUnscoped) && denies.length === 0) return 'allowed'
  return 'restricted'
}
