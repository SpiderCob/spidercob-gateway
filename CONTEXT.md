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

**Phase 2: identity & tokens.** Per `MASTER_PLAN.md` §3 — `internal/identity` (local users, argon2id, NHI `client_credentials`), `internal/authserver` (Ed25519/JWKS with multi-key support, `/token` for the internal exchange and NHI, RFC 9728 metadata, `jti` revocation), wiring the Keycloak interop harness for real ID-JAGs via RFC 7523, and setting up the free Okta Developer account during this phase (not deferred to launch). No spec has been written for this yet — that's the first step, same `/to-spec` process used for issue #1.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
