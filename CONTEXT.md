# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container. Launches together with **spider-snoop** (the parent Spidercob product) as one integrated product, not two separate logins. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-12)

- **Phase 3 is fully complete, and Phase 4's first nine slices are done and merged.** All 13 spec'd Phase 1–4 issues (#1–#25) plus issues #35 (kill-session) and #37 (config-snippet generator) are closed. **No open issues, no open PRs**, as of this writing — verified directly via `gh issue list`/`gh pr list`, not assumed.
- **The admin UI covers six screens** (config-snippet generator lives inside the existing Agents screen, not a seventh). `make ci` runs **thirteen** Docker-free layers; `make ci-interop` (real Keycloak, Docker-required) is unaffected and still green.
- **The Copilot-review triage/fix arc (Tier 1 + Tier 2) is fully done** — see `docs/tier2-findings.md` on `main` for the complete list. Nothing new to add; only Tier 3 (3 findings, deliberately low-priority/no-urgency) remains, unchanged from before.
- **Issue #35 (kill-session, Phase 4c-6)** — `GET/DELETE /admin/sessions`, sixth admin UI screen. Full detail in the previous version of this file / `MASTER_PLAN.md` step 10c-6 if it matters for what you're doing; not repeated here to keep this file from growing unbounded.
- **Issue #37 (config-snippet generator, Phase 4c-7) — spec'd and built in the same session.** `/to-spec` surfaced a real product-shape fork worth knowing about if this area comes up again: a **live, freshly-minted token** in the snippet (chosen) vs. a **placeholder template usable from anywhere** (not chosen). The reason: NHI tokens default to a 120s TTL with no refresh-token grant, so a snippet with a live token only "just works" for a little while — that tension is handled honestly (visible `expires_in`, explicit regenerate-when-it-lapses guidance) rather than oversold or newly "solved."
  - **Turned out to need no new backend at all.** Tracing the actual data flow: an agent's plaintext secret is only ever in memory once — right after `createAgent` returns, in the Agents screen's existing one-time-secret reveal — and `POST /token`'s `client_credentials` grant is *already public and unauthenticated* (the secret itself is the credential). So the whole feature is a frontend addition to that existing reveal: a node picker, calling `/token` directly from the browser with the secret already in hand, rendering a ready-to-copy `mcpServers`-shaped JSON snippet (the shared config shape Claude Desktop/Claude Code/Cursor's remote-server config all converge on). `window.location.origin` gives the correct URL in every deployment since the admin UI/`/token`/`/mcp/*` all share one origin.
  - **Verification**: no backend changed, so no new backend tests; this repo has no JS/browser test harness (`web/` has zero test files anywhere — true for every frontend change in this repo's history so far). Verified via `tsc -b`/`oxlint`/`vite build` (clean) **plus a direct manual smoke test against the real compiled binary**, confirming the exact request/response shapes the new `mintNodeToken` function assumes (success `{access_token, expires_in}`; failure `401 {error, error_description}`) — worth remembering as the pattern for "pure frontend, real backend contract" features generally: don't stop at "it compiles," hit the real binary once by hand even without a scripted e2e test.
  - Landed as **[PR #38](https://github.com/SpiderCob/spidercob-gateway/pull/38)**, merged.

## Next up

**No open issues or PRs right now.** Candidates from `MASTER_PLAN.md` §3 step 10c (all need `/to-spec` first, nothing pre-spec'd):
- **Policy matrix visualization** — the one remaining named-but-unspec'd admin UI item (10c-1's list/replace form already covers Policies' functional need; this would be a visualization layer on top).
- **`deploy/` packaging** — distroless Dockerfile, docker-compose, signed releases via goreleaser, `brew install` (`MASTER_PLAN.md` §3 step 11).
- The **standalone-admin-login gap** (`MASTER_PLAN.md` §7 — a no-spider-snoop deployment still can't reach any `/admin/*` surface at all) and the **per-MCP-request audit trail** (`docs/design.md` §6's original fuller vision, wiring `internal/audit` into `internal/proxy`'s hot path) are both bigger, still open, still unspec'd.

**Optional, low-priority leftover:** Tier 3's three Copilot-review findings (`docs/tier2-findings.md`). Not spec'd, not blocking anything, pick up only if/when they become relevant.

**Secondary, not urgent:** `make ci-interop` still doesn't run in GitHub Actions CI (needs Docker + network egress, unconfirmed on the self-hosted Hetzner runner) — `MASTER_PLAN.md` §7, unresolved across several issues now. The GitHub Actions workflow still runs plain `gofmt`/`go vet`/`go build`/`go test` (no `make web`/npm step) — fine today since `internal/webui/dist`'s tracked `.gitkeep` keeps the Go build green without Node.js, but CI isn't currently proving the frontend actually builds. **Local-dev gotcha, hit repeatedly across nearly every issue in this repo's history:** a real `npm run build` (Vite's `emptyOutDir: true`) wipes the tracked `internal/webui/dist/.gitkeep` placeholder — `touch` it back before committing.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context. `docs/tier2-findings.md` has the full Copilot-review findings detail if that history matters for what you're doing.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed — as of this writing, nothing has that label; the next slice needs `/to-spec` first.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
