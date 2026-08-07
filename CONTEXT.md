# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source, self-hosted MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container, for teams without a dedicated IAM department. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-07)

- **Phase 2a is done and merged.** [PR #4](https://github.com/SpiderCob/spidercob-gateway/pull/4) merged to `main`, closing [issue #3](https://github.com/SpiderCob/spidercob-gateway/issues/3) — identity & authserver core (Mode A humans + NHI, no external IdP): real SQLite store (`users`/`agents`/`groups`/`user_groups`/`agent_groups`/`revocations`, hand-rolled migrations), `internal/identity` (argon2id password + NHI-secret hashing), `internal/authserver` (hand-rolled AS — not `ory/fosite`/`zitadel/oidc`, `golang-jwt/jwt/v5` for tokens; Ed25519 multi-key JWKS; `/token` with `client_credentials` + an internal login/session-re-exchange pair; RFC 9728 metadata; `jti` revocation). `internal/proxy` now does real bearer-token validation on every request (401 + `WWW-Authenticate` on missing/invalid).
- **`policy.AllowAll{}` → `policy.DenyAll{}` is now the real default** — this is the single most important thing to know before touching this repo: **the gateway authenticates every request but authorizes none of them.** No MCP call succeeds end-to-end until Phase 3's policy engine exists to author real rules with. This is the correct, spec-mandated interim state (`MASTER_PLAN.md` §6, 2026-08-04 decision), not a bug — don't "fix" it by loosening the default.
- A `dev_allow_all_policy` config field + `SeedAgents` config-seeded NHI credentials exist as narrow, loudly-logged dev/CI-only escape hatches (used by `automation/run-e2e.sh`) — there's still no admin API to register users/agents over HTTP (that's Phase 4). Don't build on top of these as if they were a real bootstrap mechanism.
- `docs/spec/conformance.md`'s NHI/`client_credentials` rows and the Phase-2a-applicable MCP-auth-spec rows are checked, each backed by a passing test. Everything requiring an external IdP (ID-JAG exchange, IdP trust, JIT provisioning) is still unchecked — that's Phase 2b.
- `automation/` (`make ci`) is now three layers: `run-tests.sh` (unit/integration), `run-e2e.sh` (session/DLP pipeline against the real binary, via `dev_allow_all_policy`), `run-e2e-auth.sh` (new — full auth lifecycle: 401/JWKS/RFC 9728/mint/wrong-secret/`DenyAll`-not-401/wrong-aud/expiry/re-mint — against the real binary's actual `DenyAll` default). Extend per issue (`automation/README.md`) rather than validating by hand.
- **Still true, unchanged by Phase 2a:** no admin UI, no persistence beyond identity (no `mcp_nodes`/`tool_pins`/`policies`/`audit_log` tables yet — those are Phase 3+). SSE/streaming responses still pass through unscanned (Phase 3).

## Next up

**Two parallel tracks are now open, not gated on each other:**

- **Phase 2b — not yet spec'd.** External IdP interop: Keycloak RFC 7523 exchange (harness already stubbed in `deploy/docker-compose.yml`), free Okta Developer account setup, JIT provisioning for externally-authenticated users. Extends the `/token`/JWKS infrastructure Phase 2a built rather than replacing it. Run `/to-spec` for this, same process used for issue #3.
- **Phase 3 — not yet spec'd, and arguably more urgent.** `internal/policy` v0 (replace `DenyAll` with the real group/method/tool evaluator, ALLOW+DENY rule types, deny-overrides-allow-overrides-default-deny), `tools/list` filtering, tool pinning (`internal/pin`), scan upgrades. **This is what makes the gateway actually usable** — right now Phase 2a's own `automation/run-e2e-auth.sh` can only prove auth works up to a 403, not that any real MCP call succeeds, because there's no policy to grant access with. Per `MASTER_PLAN.md` §3: "Do not start Phase 3 until an unauthenticated request is actually rejected and a real ID-JAG round-trips through Keycloak" — that Keycloak clause is Phase 2b's job, so there's a real open question about whether Phase 3 should now start in parallel with 2b rather than strictly after it. Worth revisiting explicitly in `MASTER_PLAN.md` §3's ordering language before picking the next issue.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed — as of this writing, nothing has that label yet; the next issue (2b or 3) needs to be spec'd first via `/to-spec`.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
