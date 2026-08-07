# Spec Conformance Checklist

The test plan. Every row eventually maps to automated tests against the
interop harness. Track spec revisions here — each draft change is also a
blog post (see design doc GTM section).

## MCP Authorization (2025-11-25 spec + EMA extension, stable 2026-06)

| Requirement | Ref | Status |
|---|---|---|
| Resource-server role only; AS separate | MCP auth spec | ☐ phase 2b |
| OAuth 2.1 + PKCE (S256) | MCP auth spec | ☐ phase 2b (no authorization_code flow built yet; issue #3's grants are client_credentials + an internal exchange, neither uses PKCE) |
| Protected resource metadata per node | RFC 9728 | ☑ phase 2a — issue #3, `authserver.ServeProtectedResourceMetadata`, `TestProtectedResourceMetadata` |
| Token audience binding per node | RFC 8707 | ☑ phase 2a — issue #3, `AuthServer.mintAccessToken`/`ValidateAccessToken`, `TestToken_ClientCredentials_MintsScopedToken`, `TestValidateAccessToken_WrongAudienceRejected` |
| Issuer identifier validation | RFC 9207 | ☐ phase 2b (this issue validates a token's own `iss` claim against the AS, which is a different check than RFC 9207's authorization-response mix-up-attack mitigation — no authorization_code flow exists yet for that to apply to) |
| Dynamic client registration | RFC 7591 | ☐ phase 3 |
| WWW-Authenticate on 401 with metadata URL | RFC 9728 | ☑ phase 2a — issue #3, `Gateway.authenticate`, `TestGateway_MissingBearerTokenRejectedWithWWWAuthenticate` |
| AS metadata advertises `authorization_grant_profiles_supported` incl. `urn:ietf:params:oauth:grant-profile:id-jag` (client discovery signal, confirmed how Claude Code checks EMA support) | MCP EMA extension | ☐ phase 2b — field exists and is served (empty) as of issue #3; won't meaningfully advertise ID-JAG support until external IdP trust is wired |

## NHI / client_credentials (RFC 6749 §4.4)

Decoupled from human Mode A/B — always available regardless of which identity mode a tenant's humans use (`MASTER_PLAN.md` §1, §6).

| Requirement | Ref | Status |
|---|---|---|
| `/token` accepts `grant_type=client_credentials` with agent's hashed secret | RFC 6749 §4.4 | ☑ phase 2a — issue #3, `AuthServer.handleClientCredentials`, `TestToken_ClientCredentials_MintsScopedToken` |
| Timing-safe secret comparison (no early-exit compare) | — | ☑ phase 2a — issue #3, `identity.verifySecret` (`subtle.ConstantTimeCompare`), exercised by `TestAgentCreateAndAuthenticate` |
| Issued token: `sub` = agent's own identity, `aud` = single node, short TTL (120s default) | design doc §4, MASTER_PLAN §6 | ☑ phase 2a — issue #3, `TestToken_ClientCredentials_MintsScopedToken` |
| Agent's group membership resolved from `agent_groups`, never inherited from `owner_user_id` | MASTER_PLAN §1, §6 | ☐ phase 3 (needs policy engine; `agent_groups` exists and is assignable as of issue #3 — `store.AssignAgentGroup`, `TestGroupMembership` — but nothing reads it for access decisions yet) |
| No refresh-token grant issued — expiry means re-calling `/token` with the same credential | MASTER_PLAN §6, 2026-08-04 | ☑ phase 2a — issue #3, `TestToken_ClientCredentials_ReExchangeWithSameSecretJustWorks`; also exercised against the real binary by `automation/run-e2e-auth.sh` |
| Last-used timestamp recorded per agent credential | MASTER_PLAN §1 | ☐ phase 4 (admin UI surface) |

## ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant-04)

| Requirement | Ref | Status |
|---|---|---|
| Accept ID-JAG via JWT bearer grant at /token | RFC 7523 | ☐ phase 2b (external IdP required) |
| Validate iss against configured IdP trust | draft §sec | ☐ phase 2b (`idp_trust` table, external IdP required) |
| Validate aud == this gateway's AS | draft §sec | ☐ phase 2b |
| Enforce one-time-use jti | draft §sec | ☐ phase 2b |
| Preserve sub (human) + act (agent) chain into issued tokens | RFC 8693 | ☐ phase 2b — `Claims.Act` exists and is shaped to RFC 8693 as of issue #3, but nothing populates it yet: no flow built in phase 2a has a human delegating to an agent |
| Issued access token: single node aud, short TTL | RFC 8707 | ☑ phase 2a — same mechanism as the NHI table above; applies equally to Mode A human tokens (`TestToken_LoginThenSessionReExchange`) |
| Internal exchange path (embedded IdP, Mode A) | design doc §2.3 | ☑ phase 2a — issue #3, login + session-re-exchange grants (`AuthServer.handleLogin`/`handleSession`), `TestToken_LoginThenSessionReExchange` |
