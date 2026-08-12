# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container. Launches together with **spider-snoop** (the parent Spidercob product) as one integrated product, not two separate logins. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-12)

- **Phase 3 is fully complete, and Phase 4's first ten slices are done.** All 13 spec'd Phase 1–4 issues (#1–#25) plus issues #35 (kill-session), #37 (config-snippet generator), #39 (deploy packaging's Dockerfile/docker-compose half), and #41 (policy matrix visualization) are closed. **No open issues, no open PRs**, as of this writing — verified via `gh issue list`/`gh pr list`, not assumed.
- **`MASTER_PLAN.md` §3 step 10c's entire original admin-UI screen list is now closed out** — every item (setup wizard, CSV upload, node registration, policy matrix, audit viewer, kill-session, config-snippet generator) is either shipped or deliberately, explicitly out of scope. Worth knowing: there's no more "obvious next admin-UI item" waiting on that list — whatever comes next needs real product judgment, not just picking the next unchecked box.
- **The admin UI covers six screens** (config-snippet generator lives inside Agents; policy matrix lives inside Policies — neither added a new screen). `make ci` runs **thirteen** Docker-free layers; `make ci-interop` and `make ci-docker` are both separate, Docker-required, and test different concerns from each other.
- **The Copilot-review triage/fix arc (Tier 1 + Tier 2) is fully done** — see `docs/tier2-findings.md` on `main`. Only Tier 3 (3 findings, deliberately low-priority) remains, unchanged.
- **Issue #41 (policy matrix visualization) — spec'd and built in the same session.** Worth knowing if this area comes up again:
  - **Real design fork resolved before writing any code**: a (group, node) pair can have multiple, partially-overlapping rules under `internal/policy/evaluate.go`'s real semantics (any matching DENY wins outright; otherwise any matching ALLOW wins). A naive binary allow/deny cell would misrepresent a scoped grant. Landed on a **4-state model** (no-rule / allowed / denied / restricted), with "restricted" as the deliberate catch-all whenever a cell is ambiguous — never render a narrower-than-actual grant as a full allow.
  - **No new backend at all** — same pattern as config-snippet generator: a read-only List/Matrix toggle on the existing Policies screen, computed client-side from the three endpoints (`/admin/policies`, `/admin/groups`, `/admin/nodes`) already fetched elsewhere.
  - **The one piece of real logic (the cell classifier) was verified before any UI was built around it**: ported `evaluate.go`'s actual Go logic to a standalone script, brute-force cross-checked the classifier's claims across 7 concrete cases (an "allowed" classification must hold true for every sampled method/tool combination; "denied" must hold false for every one). All 7 passed. This is the pattern worth reusing for any future "client-side logic that has to stay semantically faithful to a Go package it can't literally share code with" situation.
  - **Manual QA was a real, driven browser session** (not just eyeballing a screenshot of one state): logged in, built a deliberately varied real policy set covering all four states via the real admin API, and confirmed the rendered grid, colors, click-through rule detail, and the "Edit in list view" round-trip all matched — plus a regression spot-check on Agents/Nodes since shared CSS tokens changed.
  - Landed as **[PR #42](https://github.com/SpiderCob/spidercob-gateway/pull/42)**, merged.
- **Issue #39 (deploy packaging)**, **#37 (config-snippet generator)**, and **#35 (kill-session)** — all done in this same overall arc across prior sessions; full detail in `MASTER_PLAN.md` if it matters for what you're doing, not repeated here.

## Next up

**No open issues or PRs right now, and no more pre-named items waiting on `MASTER_PLAN.md`'s admin-UI list.** Real candidates, all needing `/to-spec` first:
- **goreleaser signed releases + `brew install`** — the deliberately-deferred remaining half of deploy packaging (§11) — release engineering, a different kind of work than everything else in this arc.
- The **standalone-admin-login gap** (`MASTER_PLAN.md` §7 — a no-spider-snoop deployment still can't reach any `/admin/*` surface at all) and the **per-MCP-request audit trail** (`docs/design.md` §6's fuller vision, wiring `internal/audit` into `internal/proxy`'s hot path) are both bigger, still open, still unspec'd — the two most substantial remaining items in the whole roadmap at this point.

**Optional, low-priority leftover:** Tier 3's three Copilot-review findings (`docs/tier2-findings.md`). Not spec'd, not blocking anything.

**Secondary, not urgent:** `make ci-interop` and `make ci-docker` both still don't run in GitHub Actions CI (needs Docker + network egress, unconfirmed on the self-hosted Hetzner runner) — `MASTER_PLAN.md` §7, unresolved for a while now. The GitHub Actions workflow still runs plain `gofmt`/`go vet`/`go build`/`go test` (no `make web`/npm step, no Docker layer). **Local-dev gotcha, hit repeatedly across nearly every issue in this repo's history:** a real `npm run build` (Vite's `emptyOutDir: true`) wipes the tracked `internal/webui/dist/.gitkeep` placeholder — `touch` it back before committing.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context. `docs/tier2-findings.md` has the full Copilot-review findings detail if that history matters for what you're doing.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed — as of this writing, nothing has that label; the next slice needs `/to-spec` first, and (see above) there's no more pre-named admin-UI item to reach for — the next spec needs real judgment about what matters most.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
