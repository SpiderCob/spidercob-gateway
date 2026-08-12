# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container. Launches together with **spider-snoop** (the parent Spidercob product) as one integrated product, not two separate logins. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-12)

- **Phase 3 is fully complete, Phase 4's first nine slices are done, and `deploy/` packaging's Dockerfile+docker-compose half (§11) is also done.** All 13 spec'd Phase 1–4 issues (#1–#25) plus issues #35 (kill-session), #37 (config-snippet generator), and #39 (Dockerfile/docker-compose fix) are closed. **No open issues, no open PRs**, as of this writing — verified via `gh issue list`/`gh pr list`, not assumed.
- **The admin UI covers six screens.** `make ci` runs **thirteen** Docker-free layers; `make ci-interop` (real Keycloak) and the new `make ci-docker` (real production image build+run) are both Docker-required and unaffected by each other — verified separate concerns, not merged into one target.
- **The Copilot-review triage/fix arc (Tier 1 + Tier 2) is fully done** — see `docs/tier2-findings.md` on `main`. Only Tier 3 (3 findings, deliberately low-priority) remains, unchanged.
- **Issue #39 (deploy packaging, §11's Dockerfile+docker-compose half) — spec'd and built in the same session.** Worth knowing if this area comes up again:
  - **Two real, verified bugs were found in the *existing* Dockerfile before writing the spec**, not assumed from the one-line `MASTER_PLAN.md` roadmap bullet: it never ran the frontend build (so `docker build` shipped a binary whose `/ui/` 404d for every request — confirmed by hand, not just reasoned about), and its Go base image (`golang:1.22-alpine`) didn't match `go.mod`'s `go 1.25.0`. Both fixed: a real three-stage build (Node stage, version-matched Go stage, the same distroless final stage as before), `-ldflags="-s -w"` keeping the image at **24.7MB** (target was ~30MB).
  - **New root `docker-compose.yml`**, distinct from `deploy/docker-compose.yml` (that one stays exactly what it already was — the Keycloak interop harness, untouched) — makes README's own "docker compose up" pitch literally true for the first time. README's Quickstart updated to lead with it (`go run` demoted to the documented no-Docker alternative).
  - **A genuinely new testing seam** — no existing e2e script in this repo built/ran the actual Docker image before (Keycloak interop uses Docker only for Keycloak; the gateway itself always ran as a directly-compiled host binary). New `automation/run-e2e-docker.sh` + `make ci-docker`: builds the real image, cross-compiles the existing `echoserver` fixture for the Docker daemon's own arch and mounts it in as a real stdio node (distroless has no shell/toolchain to `go run` one inside the container), and proves healthy/`/ui/`-serves-real-HTML/token-mint/`tools/call` against a real running container.
  - **Everything was verified by hand first** (`docker build`, `docker run`, `docker compose up`, curling a real container) before being automated into the e2e script — including deliberately reproducing the `/ui/` 404 regression against the old Dockerfile to confirm the bug was real, not assumed.
  - **Deferred, separate future spec**: goreleaser signed releases and `brew install` — different kind of work (release engineering), no application-level test seam this repo's TDD/e2e conventions apply to.
  - Landed as **[PR #40](https://github.com/SpiderCob/spidercob-gateway/pull/40)**, merged.
- **Issue #37 (config-snippet generator)** and **issue #35 (kill-session)** — both done in prior sessions this arc; full detail in `MASTER_PLAN.md` §3 step 10c-6/10c-7 if it matters for what you're doing, not repeated here.

## Next up

**No open issues or PRs right now.** Candidates from `MASTER_PLAN.md` (all need `/to-spec` first, nothing pre-spec'd):
- **goreleaser signed releases + `brew install`** — the remaining, deliberately-deferred half of §11 (release engineering, not application code — a different kind of spec than everything else in this arc).
- **Policy matrix visualization** — the one remaining named-but-unspec'd admin UI item.
- The **standalone-admin-login gap** (`MASTER_PLAN.md` §7) and the **per-MCP-request audit trail** (`docs/design.md` §6's fuller vision) are both bigger, still open, still unspec'd.

**Optional, low-priority leftover:** Tier 3's three Copilot-review findings (`docs/tier2-findings.md`). Not spec'd, not blocking anything.

**Secondary, not urgent:** `make ci-interop` and the new `make ci-docker` both still don't run in GitHub Actions CI (needs Docker + network egress, unconfirmed on the self-hosted Hetzner runner) — same open, unresolved gap `MASTER_PLAN.md` §7 has named for a while now, one more layer added to it. The GitHub Actions workflow still runs plain `gofmt`/`go vet`/`go build`/`go test` (no `make web`/npm step, no Docker layer) — fine today since `internal/webui/dist`'s tracked `.gitkeep` keeps the Go build green without Node.js, but CI isn't currently proving the frontend actually builds, or that the packaged image actually works. **Local-dev gotcha, hit repeatedly across nearly every issue in this repo's history:** a real `npm run build` (Vite's `emptyOutDir: true`) wipes the tracked `internal/webui/dist/.gitkeep` placeholder — `touch` it back before committing.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context. `docs/tier2-findings.md` has the full Copilot-review findings detail if that history matters for what you're doing.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed — as of this writing, nothing has that label; the next slice needs `/to-spec` first.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
