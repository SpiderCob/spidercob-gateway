## Agent skills

### Issue tracker

Issues live in GitHub Issues (SpiderCob/spidercob-gateway), using the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context — `CONTEXT.md` and `docs/adr/` at the repo root, created lazily as needed. See `docs/agents/domain.md`.

## Development workflow

Every issue goes through this sequence — TDD and real end-to-end validation before anything merges, no exceptions:

1. **Branch per issue**: `issue-<n>-<short-slug>` off `main` (e.g. `issue-1-session-mapping`).
2. **TDD**: write the tests first, per the seams agreed in the issue's spec. Tests fail (red) before any implementation exists.
3. **Implement** until those tests pass (green).
4. **Real end-to-end validation, not just unit tests.** If the issue touches MCP traffic, spin up a real MCP server (not a mock) — the reference `@modelcontextprotocol/server-everything` server, or whatever's appropriate for the issue — and drive the actual flow through the gateway end-to-end. If the flow needs isolation (to avoid clobbering other test state), stand up a throwaway sandbox (docker-compose stack, temp dir, whatever fits) rather than running it against shared state.
5. **Only after the e2e flow is demonstrated working** does a PR go up — don't open the PR before this step passes.
6. **Merge only after the PR's checks and the e2e validation are both green.**
7. **After merge**, update `CONTEXT.md` on the `context_main` branch (below) with what just landed and what's next, and push it, before starting the next issue.

## Session continuity: the `context_main` branch

`context_main` is an orphan branch holding a single rolling `CONTEXT.md` — a short, current-state snapshot for starting a fresh session with no memory of prior conversations. It's deliberately separate from `main`'s code history (nothing to check out, just a doc to read), and separate in *purpose* from any future domain-glossary `CONTEXT.md` that `/domain-modeling` might eventually create on `main` per `docs/agents/domain.md` — don't conflate the two; this one is a session/status handoff doc, not a vocabulary glossary.

**To read it at the start of a session**: `git fetch origin && git show origin/context_main:CONTEXT.md`.

**To update it** (after every issue merges): checkout `context_main`, overwrite `CONTEXT.md`, commit, push. Keep it short — current state and what's next, not a duplicate of `MASTER_PLAN.md`/`docs/design.md`. Point to those for full detail rather than copying them.
