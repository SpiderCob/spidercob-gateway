# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source, self-hosted MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container, for teams without a dedicated IAM department. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-07)

- **Phase 3a is done and merged.** [PR #8](https://github.com/SpiderCob/spidercob-gateway/pull/8) merged to `main`, closing [issue #7](https://github.com/SpiderCob/spidercob-gateway/issues/7) — the real policy engine. **This is the actual "the gateway does something" milestone**: `policy.DenyAll{}` is gone as the working default; a real, store-backed `policy.Evaluator` grants access via group/method/tool rules (deny-overrides-allow-overrides-default-deny, additive-allow across groups), filters `tools/list` responses to hide unauthorized tools, rate-limits per group/NHI (429, distinct from 403), and can escalate scan-flagged calls to an actual block per policy rule (`block_on_scan_flag`). `automation/run-e2e-policy.sh` (`make ci`, no Docker) is the first e2e script in this repo's history to get a real `200` on a real tool call — every prior one deliberately stopped at a 403/401 to prove auth without overclaiming access worked.
- **Policy is authored via `config.Policies`** — config-file bootstrap, same posture as `config.SeedAgents`/`config.TrustedIdPs` (no admin API exists yet, Phase 4). Unlike identity data, policy config **fully replaces** the store's `policies` table on every restart — it has no independent state of its own beyond config in this phase.
- **Architectural note if you touch `internal/proxy` or `internal/policy`:** the policy check now runs *after* the JSON-RPC request body is parsed (it needs the method, and for `tools/call` the tool name — Phase 2's coarse node-only check ran before any body reading happened). `internal/policy.Engine`'s interface changed shape entirely (`Decide`/`FilterTools`, not the old `Allow(node, r) bool`) — this was a deliberate redesign, not just a new implementation, confirmed with the user before the spec was written.
- `README.md`'s quickstart now shows real policy configuration (grant a seeded NHI a group + a policy rule) instead of the `dev_allow_all_policy` escape hatch — verified to actually work end-to-end before it was published, not just written from memory.
- `make ci` runs **four** Docker-free layers now: `run-tests.sh`, `run-e2e.sh`, `run-e2e-auth.sh`, `run-e2e-policy.sh`. `make ci-interop` (real Keycloak, Docker-required) is unaffected and still green — re-verified after this issue's `main.go` changes.

## Next up

**Two follow-on Phase 3 issues, neither spec'd yet, deliberately split from 3a for reviewability** (`MASTER_PLAN.md` §3):

- **Phase 3b — tool pinning / rug-pull defense.** `internal/pin`: snapshot `tools/list` on node registration, hash name+description+inputSchema, quarantine on drift. Periodic background refresh, not per-request diffing (latency budget).
- **Phase 3c — scan upgrades.** `internal/scan`: schema enforcement against pinned `inputSchema` (do this first, cheapest/broadest win — and depends on 3b's pinning existing), Gitleaks-derived secret rule expansion, entropy scorer, PII with Luhn, homoglyph/zero-width normalization. Issue #7's `block_on_scan_flag` already lets a policy rule escalate the *existing* two-scanner pipeline's verdicts per tool/group — 3c is about the scanners themselves getting richer, not the policy-escalation mechanism (already built).

Neither is gated on the other — pick whichever makes more sense next, or ask the user. Run `/to-spec` for whichever is picked (same process used for issues #3, #5, #7).

**Secondary, not urgent:** `make ci-interop` still doesn't run in GitHub Actions CI (needs Docker + network egress, unconfirmed on the self-hosted Hetzner runner) — `MASTER_PLAN.md` §7 open decision, unresolved across three issues now.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed — as of this writing, nothing has that label; Phase 3b or 3c needs `/to-spec` first.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
