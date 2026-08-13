# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container. Launches together with **spider-snoop** (the parent Spidercob product) as one integrated product, not two separate logins. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-13)

- **Phase 3 is fully complete, and Phase 4's first eleven slices are done** — plus deploy packaging's Dockerfile/docker-compose half (§11) and the standalone-admin-login gap (§7). All spec'd Phase 1–4 issues through **#45** are closed. **No open issues, no open PRs**, as of this writing — verified via `gh issue list`/`gh pr list`, not assumed.
- **`MASTER_PLAN.md` §3 step 10c's entire original admin-UI screen list is closed out**, and so are both big named gaps that used to sit in §7's decision log and §11 (standalone admin login; Dockerfile/docker-compose). What's left on the roadmap now genuinely needs product judgment, not a pre-made checklist — see "Next up" below.
- **The admin UI covers six screens.** `make ci` runs **fifteen** Docker-free layers now (`run-tests.sh` + 14 e2e scripts); `make ci-interop` and `make ci-docker` are both separate, Docker-required, testing different concerns from each other and from `make ci`.
- **The Copilot-review triage/fix arc (Tier 1 + Tier 2) is fully done** — see `docs/tier2-findings.md` on `main`. Only Tier 3 (3 findings, deliberately low-priority) remains, unchanged.
- **Issue #45 (per-MCP-request audit trail) — spec'd and built in the same session, right after issue #43.** This closes the exact gap `internal/audit/audit.go`'s own doc comment had named as deliberately deferred since issue #23 ("wired to one consumer"). Worth knowing if this area comes up again:
  - **No schema change.** MCP-request records reuse `audit.Record`'s existing shape exactly as that package's doc comment always anticipated: `Action` encodes `"<rpc_method>:<outcome>"` (`allowed`, `denied_policy`, `rate_limited`, `quarantined`, `schema_rejected`, `blocked_scan`), `Resource` encodes `"<node>[/<tool>]"`. This was a deliberate, discussed-with-the-user tradeoff over adding structured `node`/`tool`/`decision` columns closer to `docs/design.md` §6's original sketch — revisit only if real usage shows the string encoding is a genuine limitation.
  - **New seam, same pattern as `SetPolicy`/`SetPinRegistry`**: `internal/proxy` defines a minimal `AuditRecorder` interface and a `Gateway.SetAuditRecorder` setter; `cmd/spidercob`'s new `auditRecorderAdapter` wires `*store.SQLiteStore` into it at the composition root. A nil recorder (before `SetAuditRecorder` is called) means auditing is a no-op — same "start permissive" posture those two already established.
  - **The one real design difference from admin-action auditing** (also discussed with the user before building): this fires on *every* MCP request, not occasional admin mutations, so writes go through an **async, bounded queue drained by a single background worker**, not a synchronous store write on the request's own goroutine. A full queue drops the record and counts it (`metrics.AuditRecordsDropped`) rather than ever blocking or failing the request — proven directly by a dedicated Go test, not just asserted. The single background worker is also what keeps the hash-chain's required serialization correct regardless of how many requests are enqueuing concurrently.
  - **Scope, deliberately**: every policy-gated JSON-RPC method (`initialize`, `tools/list`, `tools/call`, ...) gets a record for both its allowed and denied outcomes. Session teardown (`DELETE`) and pre-authentication failures are excluded on purpose — teardown was never policy-gated to begin with, and there's no validated principal yet to attribute a pre-auth record to.
  - **Verification**: 13 new `internal/proxy` tests (one per outcome branch, actor-field derivation for both human and agent subjects, all three excluded paths, and the queue-overflow property), a new `internal/store` test proving admin-action-shaped and MCP-request-shaped records interleave into one continuous `audit.Verify`-clean chain (not two parallel ones), and a new `automation/run-e2e-mcp-audit.sh` — a real policy-allowed `tools/call` and a real policy-denied request both land in the real `GET /admin/audit` endpoint through the real compiled binary, tool name included in the resource field.
  - Landed as **[PR #46](https://github.com/SpiderCob/spidercob-gateway/pull/46)**, merged.
- **Issue #43 (standalone admin login)** and earlier issues (#35, #37, #39, #41) — all done in prior sessions of this same arc; full detail in `MASTER_PLAN.md` if it matters for what you're doing, not repeated here.

## Next up

**No open issues or PRs right now, and no more pre-named items waiting anywhere in `MASTER_PLAN.md`.** One real remaining candidate needs `/to-spec` and real product judgment about priority:
- **goreleaser signed releases + `brew install`** — the deliberately-deferred remaining half of deploy packaging (§11) — release engineering, a different kind of work than everything else in this arc, no application-level test seam.

**Optional, low-priority leftover:** Tier 3's three Copilot-review findings (`docs/tier2-findings.md`). Not spec'd, not blocking anything.

**Secondary, not urgent:** `make ci-interop` and `make ci-docker` both still don't run in GitHub Actions CI (needs Docker + network egress, unconfirmed on the self-hosted Hetzner runner) — `MASTER_PLAN.md` §7, unresolved for a while now. The GitHub Actions workflow still runs plain `gofmt`/`go vet`/`go build`/`go test` (no `make web`/npm step, no Docker layer). **Local-dev gotcha, hit repeatedly across nearly every issue in this repo's history:** a real `npm run build` (Vite's `emptyOutDir: true`) wipes the tracked `internal/webui/dist/.gitkeep` placeholder — `touch`/`git checkout` it back before committing.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context. `docs/tier2-findings.md` has the full Copilot-review findings detail if that history matters for what you're doing.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed — as of this writing, nothing has that label; the next slice needs `/to-spec` first — see "Next up" above for the one real candidate.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
