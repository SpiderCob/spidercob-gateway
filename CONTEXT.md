# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source, self-hosted MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container, for teams without a dedicated IAM department. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-07)

- **Phase 3b is done and merged.** [PR #10](https://github.com/SpiderCob/spidercob-gateway/pull/10) merged to `main`, closing [issue #9](https://github.com/SpiderCob/spidercob-gateway/issues/9) — tool pinning (rug-pull defense). New `internal/pin` package: `Hash`/`Drifted` pure functions (canonicalized JSON hashing over name+description+`inputSchema`, so key-reordering never false-positives as drift), a store-backed `Registry` (TOFU establishment on first observation, per-tool quarantine on a hash mismatch, fail-static reads), and a `Scheduler` (per-node background refresher — ticker + stop/done channels, mirrors the idle-session reaper; pure `dueForRefresh` decision function, injectable-clock tested, mirrors `nodeHealth`'s pattern from Phase 1).
- **Pins are persisted and never reset on restart** — the opposite posture from `policies` (which fully replaces on every startup). A pin surviving a restart unchanged is load-bearing, not incidental: re-establishing TOFU on every boot would let an attacker trivially bypass the whole defense by waiting for (or triggering) one.
- **Composes with policy at the same two seams issue #7 built, doesn't replace them.** `Gateway.SetPinRegistry` (mirrors `SetPolicy`'s post-construction-setter pattern) wires quarantine checks into the `tools/call` gate (must be both policy-authorized *and* not quarantined — rejection body says "quarantined", distinguishable in logs/response from a plain policy "forbidden") and into `tools/list` filtering (`pin.NonQuarantined` further narrows `policy.FilterTools`'s output). A `nil` registry (before `SetPinRegistry` is called) disables pinning entirely — same "start permissive, composition root opts in" posture as policy's `DenyAll{}`-until-`SetPolicy` default.
- **The background refresher owns its own internal, gateway-initiated session** (`Gateway.FetchToolsForPin`, new `internal/proxy/pinfetch.go`) — opens a short-lived upstream connection via the existing `newUpstream` machinery, drives `initialize`+`tools/list`, tears it down immediately. Never registered in the client-facing session table, so it can't interfere with (or be confused with) a real client session. Applies identically to stdio and streamable_http nodes.
- **Refresh interval is admin-configurable per node**, via config: `config.Node.PinRefreshIntervalSeconds` (falls back to `config.PinRefreshIntervalSeconds`, default 5 minutes) and a separate, normally-much-shorter `config.PinCheckIntervalSeconds` (default 10s) controlling how often the scheduler wakes up to check whether *any* node is due.
- **`automation/run-e2e-pin.sh`** (new, wired into `make ci`) proves the whole sequence against the real compiled binary: a new stdio fixture (`internal/proxy/stdioadapter/testdata/pinserver`) whose one tool's description is read from a file the script rewrites mid-run — TOFU-pins on first background refresh, stays fully normal right after establishment (no false-positive drift), then a simulated rug pull (rewriting the description file) gets caught within one more refresh cycle: `tools/call` rejected (403) and the tool gone from `tools/list`.
- `make ci` now runs **five** Docker-free layers: `run-tests.sh`, `run-e2e.sh`, `run-e2e-auth.sh`, `run-e2e-policy.sh`, `run-e2e-pin.sh`. `make ci-interop` (real Keycloak, Docker-required) is unaffected and still green.
- **No re-approval mechanism exists** — once a tool is quarantined it stays quarantined until a human edits the store directly; clearing it via API/UI is explicitly Phase 4, same "no admin API yet" gap every prior phase has scoped around rather than worked around.

## Next up

**Phase 3c — not yet spec'd.** `internal/scan` upgrades: schema enforcement against the now-pinned `inputSchema` (do this first — cheapest, broadest win, and was explicitly blocked on 3b's pins existing until now), Gitleaks-derived secret rule expansion, entropy scorer, PII with Luhn, homoglyph/zero-width normalization *before* pattern matching. Ship with honest defaults: block secrets outbound, flag-don't-block injection heuristics (issue #7's `block_on_scan_flag` already lets a specific policy rule override that default per tool/group, ahead of the richer scanners this item adds). Run `/to-spec` for this next — no GitHub issue exists yet.

Once 3c lands, **Phase 3 is fully complete** — Phase 4 (admin UI & packaging → OSS launch) is next after that; see `MASTER_PLAN.md` §3 for its full step list and the launch-gate checklist.

**Secondary, not urgent:** `make ci-interop` still doesn't run in GitHub Actions CI (needs Docker + network egress, unconfirmed on the self-hosted Hetzner runner) — `MASTER_PLAN.md` §7 open decision, unresolved across four issues now.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed — as of this writing, nothing has that label; Phase 3c needs `/to-spec` first.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
