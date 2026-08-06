# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source, self-hosted MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container, for teams without a dedicated IAM department. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-06)

- Phase 1 spec published: [GitHub issue #1](https://github.com/SpiderCob/spidercob-gateway/issues/1) — session mapping + stdio adapter, with a resequenced build order (see the issue's comments, and `MASTER_PLAN.md` §3/§6 2026-08-06 entry).
- **No implementation has started yet.** The codebase is still the pre-existing skeleton: a routing proxy with seed DLP/injection scanners, `policy` is a stub (`AllowAll` — should become `DenyAll` once real tokens exist in Phase 2, per the decisions log), no identity/auth, no admin UI. See `MASTER_PLAN.md` §2 for the full accurate inventory — don't trust the README, it understates and overstates progress in different places.
- Development workflow (branch per issue, TDD, real end-to-end validation against an actual MCP server before any PR, merge only after that passes) is documented in `CLAUDE.md` on `main` under "Development workflow." Every issue must follow it — including updating *this file* after merging.

## Next up

Issue #1, in the resequenced order documented in its GitHub comments:
1. Streaming-scan interface groundwork (independent, do first)
2. Minimal stdio proxying (no crash supervision yet)
3. Session mapping (tested against both HTTP and stdio nodes together)
4. Idle session timeout (same dual-transport testing)
5. Full stdio process supervision (crash restart/backoff, quarantine)

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
