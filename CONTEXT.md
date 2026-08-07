# Spidercob Gateway — Current State

**Read this first in a new session with no memory of prior conversations.** For the full plan and rationale, see `MASTER_PLAN.md` and `docs/design.md` on `main` — this file is a rolling snapshot, not a replacement for those. It lives on this orphan branch (`context_main`) deliberately, separate from `main`'s code history — nothing to check out here, just a doc to read. See `CLAUDE.md` on `main` for the update procedure and why this is a different thing from any future domain-glossary `CONTEXT.md`.

## What this is

Open-source, self-hosted MCP gateway: spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) plus policy and DLP, in one container, for teams without a dedicated IAM department. Full north star: `MASTER_PLAN.md` §0 on `main`.

## Where things stand (as of 2026-08-07)

- **Phase 2b is done and merged.** [PR #6](https://github.com/SpiderCob/spidercob-gateway/pull/6) merged to `main`, closing [issue #5](https://github.com/SpiderCob/spidercob-gateway/issues/5) — external IdP interop (Mode B): `internal/idptrust` (validates external ID-JAGs against a configured trusted-issuer list, JWKS via `github.com/MicahParks/keyfunc/v3`), a new `urn:ietf:params:oauth:grant-type:jwt-bearer` grant at `/token` (RFC 7523), JIT user provisioning (`internal/identity.ResolveOrCreateExternalUser`, atomic in the store layer — closes a real concurrent-first-login race), RFC 9728 metadata now genuinely advertising the `id-jag` grant profile. **Verified against a real Keycloak container**, not just unit tests — `automation/run-e2e-idjag.sh` (`make ci-interop`) scripts the full 3-legged RFC 7523/8693 flow via Keycloak's own Admin REST API and drives it against the real compiled binary. Okta interop is a manual runbook (`interop/okta-runbook.md`), not automated — no disposable-per-CI-run Okta org option exists.
- **All three identity modes now work: Mode A (local login), NHI (`client_credentials`), Mode B (external IdP).** Every one of them still hits `policy.DenyAll{}` after authenticating — **this is still true and still the most important thing to know:** the gateway authenticates everyone, authorizes no one, until Phase 3's policy engine exists.
- **Real interop findings from building the Keycloak harness** (recorded in `interop/README.md` and `MASTER_PLAN.md`'s decisions log — read before touching `internal/idptrust` or the interop scripts): Keycloak's `audience` parameter names a registered client_id, not a URI (unlike this gateway's own token `aud`); making a client appear in another's token `aud` needs a client-level Audience protocol mapper, not the documented shared-client-scope-with-role-mappings approach; new Keycloak users need a populated profile or the dynamic `VERIFY_PROFILE` action silently blocks login; `requested_token_type=id-jag` isn't honored by current Keycloak (harmless — `internal/idptrust` never inspects an assertion's own type label).
- `docs/spec/conformance.md`'s full ID-JAG table is now checked, each row backed by a test. Only PKCE/dynamic-client-registration/RFC 9207 rows stay unchecked — architecturally inapplicable to this gateway's grant set (no `authorization_code` flow anywhere), not gaps.
- `make ci` (three Docker-free layers: `run-tests.sh`, `run-e2e.sh`, `run-e2e-auth.sh`) and `make ci-interop` (a fourth layer, Docker-required, real Keycloak) are both green. **`make ci-interop` does not run in GitHub Actions CI yet** — needs Docker + network egress, unconfirmed on the self-hosted Hetzner runner. A real gap, not yet closed.

## Next up

**Phase 3 — not yet spec'd, and the clear next step.** The original `MASTER_PLAN.md` gate ("don't start Phase 3 before an ID-JAG round-trips through Keycloak") is now satisfied — Phase 2b just did that. Phase 3 replaces `policy.DenyAll{}` with the real group/method/tool evaluator (ALLOW+DENY rule types, deny-overrides-allow-overrides-default-deny — decisions already recorded in `MASTER_PLAN.md` §6), adds `tools/list` filtering and tool pinning (`internal/pin`). **This is what makes the gateway do anything useful end-to-end for the first time** — right now not even Mode B's own real Keycloak test can get past a 403, since there's no policy to grant access with.

Run `/to-spec` for Phase 3 (same process used for issues #3 and #5) to produce the spec, then publish it with the `ready-for-agent` label.

**Secondary, not urgent:** the `make ci-interop`-doesn't-run-in-CI gap noted above. Worth fixing before more Docker-requiring interop targets accumulate, but doesn't block Phase 3.

## How to use this file

1. Read this for orientation.
2. Check out `main`, read `MASTER_PLAN.md` (current plan + decisions log — status source of truth) and `docs/design.md` (strategy/spec rationale) for full context.
3. Check the GitHub issue tracker (`ready-for-agent` label, `SpiderCob/spidercob-gateway`) for what's actually queued and unclaimed — as of this writing, nothing has that label; Phase 3 needs `/to-spec` first.
4. After finishing an issue — merged, per the workflow in `CLAUDE.md` — update this file with what changed and what's next, commit, and push `context_main` before starting the next issue.
