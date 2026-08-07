---
name: handoff
description: Close out a work session cleanly (verify nothing uncommitted, update the context_main handoff doc, push) and produce a clear summary with the exact read path -- or, run at the start of a session, read that handoff to get oriented. Use when context is filling up, an issue/PR has just merged, or a natural stopping point is reached.
---

# Session Handoff

This repo uses an orphan branch, `context_main`, holding a single rolling
`CONTEXT.md` as the session-continuity mechanism (see `CLAUDE.md` →
"Session continuity: the `context_main` branch"). This skill is the
concrete, repeatable procedure for using it well in both directions --
closing out a session, and picking one up.

## Ending a session (handoff out)

Run this when: context is filling up, an issue/PR just merged, or you've
reached a natural stopping point and want a clean handoff rather than
losing state to compaction.

1. **Verify nothing is uncommitted or unpushed.** `git status --short` on
   every branch touched this session; compare `git log <branch> --oneline
   -1` against `git log origin/<branch> --oneline -1` to confirm local and
   remote agree. Don't hand off a session with local-only work sitting
   uncommitted -- a fresh session has no way to know it exists.
2. **Check actual current state, don't trust memory of what was done.**
   Re-verify via `gh issue list --repo SpiderCob/spidercob-gateway --state
   all` and `gh pr list --repo SpiderCob/spidercob-gateway --state all`
   rather than assuming -- issue and PR numbers share one sequence on
   GitHub, and it's easy to misremember which number is which (a PR can
   consume a number an issue never used).
3. **Update `context_main`'s `CONTEXT.md`:**
   - `git checkout context_main`
   - Rewrite "Where things stand" to reflect reality as of right now --
     what merged, what's still true and unchanged, what's explicitly
     *not* done yet. Don't let it read more finished than it is.
   - Rewrite "Next up" to name the specific next issue/spec/task, with
     its GitHub link if one exists -- not a vague phase name.
   - Commit and push: `git push origin context_main`.
   - `git checkout main` (or wherever the session started) to leave a
     clean working tree.
4. **State the handoff clearly to the user**, including:
   - The **exact path to read it back**, as a literal command, not a
     vague pointer: `git show origin/context_main:CONTEXT.md`.
   - A one-line reminder of the workflow this repo uses: **branch per
     issue, tests written and failing (red) before implementation, real
     end-to-end validation via `make ci` before any PR, merge only after
     that's green** -- documented in full in `CLAUDE.md`, but a fresh
     session (or a human) shouldn't have to go find that just to know
     *how* work happens here.
   - Confirmation that everything is committed and pushed -- nothing is
     sitting only in this conversation's history.

## Starting a session (handoff in)

Run this when a session has no memory of prior conversations in this
repo.

1. `git fetch origin && git show origin/context_main:CONTEXT.md` -- read
   this first, before exploring the codebase.
2. Check out `main`, read `docs/MASTER_PLAN.md` (status + decisions log --
   the source of truth for what's actually done) and `docs/design.md`
   (strategy/spec rationale) for full context.
3. `gh issue list --repo SpiderCob/spidercob-gateway --state open --json
   number,title,labels` -- confirm what's actually queued (`ready-for-
   agent` label) rather than trusting `CONTEXT.md`'s "Next up" alone,
   since it can drift if a prior session skipped step 3 of "Ending a
   session" above.
4. Proceed per the workflow in `CLAUDE.md` -- branch per issue, TDD,
   `make ci` before a PR.
