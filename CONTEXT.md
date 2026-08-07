# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source, self-hosted MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container, for teams without a dedicated IAM department. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-07)

- **Phase 1 is done and merged.** [PR #2](https://github.com/SpiderCob/spidercob-gateway/pull/2) merged to `main`, closing [issue #1](https://github.com/SpiderCob/spidercob-gateway/issues/1) — all 5 items: streaming-scan interface groundwork, stdio nodes routable through the same path as HTTP nodes, gateway-minted session IDs (translation table + mirrored cookie, both transports), idle session timeout, full stdio crash detection/backoff/quarantine. `main` now has real session-aware behavior, not the old stateless passthrough.
- `docs/session-lifecycle.md` on `main` has Mermaid sequence diagrams for all of this (HTTP init/continue/DELETE, stdio init/continue/DELETE, plus the stdio-only crash-and-self-heal path) — read that before touching `internal/proxy/`, it's the fastest way back up to speed.
- `automation/` on `main` is the real end-to-end validation layer — `make ci` builds the actual gateway binary, spawns a real stdio MCP server through it, and drives a full session lifecycle via `curl`, not just `go test`'s in-process harness. Extend it per issue (`automation/README.md`) rather than validating by hand.
- **Still true, unchanged by Phase 1:** `policy` is `AllowAll{}` — no access control exists yet. No identity/auth, no admin UI, no persistence. Per the decisions log, `AllowAll` needs to become `DenyAll{}` as part of Phase 2, the moment real tokens exist — don't ship or demo this repo as if it authenticates anyone.
- Development workflow (branch per issue, TDD, real end-to-end validation via `make ci` before any PR, merge only after that passes) is documented in `CLAUDE.md` on `main` under "Development workflow." Every issue must follow it — including updating *this file* after merging.

## Next up

**Phase 2 is split into two issues (2026-08-07), not bundled like Phase 1 was** — Keycloak/Okta interop needs real external services (Docker, a live IdP), a different test-infrastructure shape than the self-contained identity/authserver core. See `MASTER_PLAN.md` §3 Phase 2 for the full reasoning.

- **[Issue #3](https://github.com/SpiderCob/spidercob-gateway/issues/3) — Phase 2a: identity & authserver core (Mode A + NHI, no external IdP) — spec published, ready to implement.** Covers a real `internal/store` SQLite implementation (currently just a `Ping()` stub — a previously-unstated prerequisite this issue makes explicit), `internal/identity`, `internal/authserver` (`/token`, JWKS with multi-key support, RFC 9728 metadata, `jti` revocation), and flipping `policy.AllowAll{}` → `policy.DenyAll{}`. Same TDD/branch/`make ci`/PR workflow as issue #1. **This is the next thing to actually build.**
- **Phase 2b — not yet spec'd, gated on issue #3 merging.** Keycloak RFC 7523 interop, the free Okta Developer account setup, JIT provisioning for externally-authenticated users. Run `/to-spec` for this once 2a is done, same process used for #3.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
