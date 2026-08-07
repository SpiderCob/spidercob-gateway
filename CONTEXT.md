# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source, self-hosted MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container, for teams without a dedicated IAM department. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-07)

- **Issue #1 is fully implemented, all 5 items, and validated end-to-end — but not yet merged.** [PR #2](https://github.com/SpiderCob/spidercob-gateway/pull/2) is open against `main` on branch `issue-1-session-mapping`, closes [issue #1](https://github.com/SpiderCob/spidercob-gateway/issues/1). Full suite green under `-race`, reconfirmed across repeated runs. **`main` itself still has the pre-Phase-1 skeleton** (`AllowAll` policy stub, no identity/auth, no admin UI, no session concept) until this PR merges — don't assume Phase 1 behavior is live on `main` yet.
- What's in the PR: streaming-scan interface groundwork; the go-sdk adopted for gateway→upstream connections; stdio nodes routable through the same path as HTTP nodes (with a DLP-scanning gap I found and closed along the way); gateway-minted session IDs with a translation table + mirrored cookie, working across both transports; idle session timeout; full stdio crash detection, backoff, and quarantine. `docs/session-lifecycle.md` (also in the PR) has Mermaid sequence diagrams for all of this — read that before touching `internal/proxy/` again, it's the fastest way back up to speed on the session-lifecycle mechanics.
- Development workflow (branch per issue, TDD, real end-to-end validation against an actual MCP server before any PR, merge only after that passes) is documented in `CLAUDE.md` on `main` under "Development workflow." Every issue must follow it — including updating *this file* after merging.

## Next up

1. **Get PR #2 reviewed and merged.** Nothing else should start until this lands — `main` is stale relative to it.
2. After merge: flip the Phase 1 checkboxes in `MASTER_PLAN.md` §3, update this file's "where things stand" section to reflect `main`, then move to Phase 2 (identity & tokens) per `MASTER_PLAN.md`.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
