# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container. Launches together with **spider-snoop** (the parent Spidercob product) as one integrated product, not two separate logins. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-13)

- **Phase 3 is fully complete, and Phase 4's first ten slices are done — plus deploy packaging's Dockerfile/docker-compose half (§11) and the standalone-admin-login gap (§7).** All 13 spec'd Phase 1–4 issues (#1–#25) plus issues #35, #37, #39, #41, and #43 are closed. **No open issues, no open PRs**, as of this writing — verified via `gh issue list`/`gh pr list`, not assumed.
- **`MASTER_PLAN.md` §3 step 10c's entire original admin-UI screen list is closed out**, and now the two big named gaps in §7's decision log (standalone admin login) and §11 (Dockerfile/docker-compose) are too. What's left on the roadmap now genuinely needs product judgment, not a pre-made checklist — see "Next up" below.
- **The admin UI covers six screens.** `make ci` runs **fourteen** Docker-free layers; `make ci-interop` and `make ci-docker` are both separate, Docker-required, testing different concerns from each other and from `make ci`.
- **The Copilot-review triage/fix arc (Tier 1 + Tier 2) is fully done** — see `docs/tier2-findings.md` on `main`. Only Tier 3 (3 findings, deliberately low-priority) remains, unchanged.
- **Issue #43 (standalone admin login) — spec'd and built in the same session.** This was the biggest slice of this whole arc — it touches the auth trust model directly, not just presentation over existing data like the last few features did. Worth knowing if this area comes up again:
  - **The design fell into place cleanly once traced through**: local admin-ness is membership in a config-designated group (`Config.LocalAdminGroup`) — no schema change, and bootstrapping the first admin costs *nothing new*, since issue #21's existing `SeedUsers` + `groups` mechanism already assigns a seeded user to groups. A seeded user in that group is a real admin from first startup.
  - **`internal/adminapi`'s `SpiderSnoopIntrospector` interface is completely unchanged** — a second implementation (wrapping `*authserver.AuthServer`'s new `ValidateLocalAdminSession`) satisfies it, exactly the config/adapter swap `MASTER_PLAN.md`'s 2026-08-08 decision log said this interface was deliberately built for. `createUISession` grows a username/password alternative to the spider-snoop-token flow that feeds the *same* `uisession.Registry`/cookie code — everything downstream (whoami, gate, logout, audit logging) is unbranched.
  - **Real security discipline carried through**: the local admin session is a distinctly-typed signed token (verified in both directions that it can never be replayed as the ordinary MCP-session token, or vice versa), and group membership is re-checked live from the store on *every* request, not just at login — removal from the admin group takes effect on the very next request, proven directly with the same still-unexpired token.
  - **Verification**: real Go-level tests for every piece (including the cross-contamination and live-revocation properties), a real manual browser session against a gateway with zero spider-snoop config (login form auto-detected correctly, a real admin operation succeeded, a non-admin-group user was correctly rejected with a non-enumerable error), and then a new `automation/run-e2e-standalone-admin.sh` scripting that exact story — 16 checks, all passed on the first real run.
  - Landed as **[PR #44](https://github.com/SpiderCob/spidercob-gateway/pull/44)**, merged.
- **Issues #35, #37, #39, #41** — kill-session, config-snippet generator, deploy packaging, policy matrix — all done in prior sessions of this same arc; full detail in `MASTER_PLAN.md` if it matters for what you're doing, not repeated here.

## Next up

**No open issues or PRs right now, and no more pre-named items waiting anywhere in `MASTER_PLAN.md`.** The two real remaining candidates both need `/to-spec` and real product judgment about priority:
- **Per-MCP-request audit trail** (`docs/design.md` §6's fuller original vision) — today's audit trail only covers admin-API mutations, not actual MCP traffic (every `tools/call`, etc.). Real latency-budget considerations wiring `internal/audit` into `internal/proxy`'s hot path — deserves its own seam-check.
- **goreleaser signed releases + `brew install`** — the deliberately-deferred remaining half of deploy packaging (§11) — release engineering, a different kind of work than everything else in this arc, no application-level test seam.

**Optional, low-priority leftover:** Tier 3's three Copilot-review findings (`docs/tier2-findings.md`). Not spec'd, not blocking anything.

**Secondary, not urgent:** `make ci-interop` and `make ci-docker` both still don't run in GitHub Actions CI (needs Docker + network egress, unconfirmed on the self-hosted Hetzner runner) — `MASTER_PLAN.md` §7, unresolved for a while now. The GitHub Actions workflow still runs plain `gofmt`/`go vet`/`go build`/`go test` (no `make web`/npm step, no Docker layer). **Local-dev gotcha, hit repeatedly across nearly every issue in this repo's history:** a real `npm run build` (Vite's `emptyOutDir: true`) wipes the tracked `internal/webui/dist/.gitkeep` placeholder — `touch` it back before committing.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context. `docs/tier2-findings.md` has the full Copilot-review findings detail if that history matters for what you're doing.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed — as of this writing, nothing has that label; the next slice needs `/to-spec` first, and there's no more pre-named item to reach for — see "Next up" above for the two real candidates.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
