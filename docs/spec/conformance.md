# Spec Conformance Checklist

The test plan. Every row eventually maps to automated tests against the
interop harness. Track spec revisions here — each draft change is also a
blog post (see design doc GTM section).

## MCP Authorization (2025-11-25 spec + EMA extension, stable 2026-06)

| Requirement | Ref | Status |
|---|---|---|
| Resource-server role only; AS separate | MCP auth spec | ☐ phase 2 |
| OAuth 2.1 + PKCE (S256) | MCP auth spec | ☐ phase 2 |
| Protected resource metadata per node | RFC 9728 | ☐ phase 2 |
| Token audience binding per node | RFC 8707 | ☐ phase 2 |
| Issuer identifier validation | RFC 9207 | ☐ phase 2 |
| Dynamic client registration | RFC 7591 | ☐ phase 3 |
| WWW-Authenticate on 401 with metadata URL | RFC 9728 | ☐ phase 2 |
| AS metadata advertises `authorization_grant_profiles_supported` incl. `urn:ietf:params:oauth:grant-profile:id-jag` (client discovery signal, confirmed how Claude Code checks EMA support) | MCP EMA extension | ☐ phase 2 |

## NHI / client_credentials (RFC 6749 §4.4)

Decoupled from human Mode A/B — always available regardless of which identity mode a tenant's humans use (`MASTER_PLAN.md` §1, §6).

| Requirement | Ref | Status |
|---|---|---|
| `/token` accepts `grant_type=client_credentials` with agent's hashed secret | RFC 6749 §4.4 | ☐ phase 2 |
| Timing-safe secret comparison (no early-exit compare) | — | ☐ phase 2 |
| Issued token: `sub` = agent's own identity, `aud` = single node, short TTL (120s default) | design doc §4, MASTER_PLAN §6 | ☐ phase 2 |
| Agent's group membership resolved from `agent_groups`, never inherited from `owner_user_id` | MASTER_PLAN §1, §6 | ☐ phase 3 (needs policy engine) |
| No refresh-token grant issued — expiry means re-calling `/token` with the same credential | MASTER_PLAN §6, 2026-08-04 | ☐ phase 2 |
| Last-used timestamp recorded per agent credential | MASTER_PLAN §1 | ☐ phase 4 (admin UI surface) |

## ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant-04)

| Requirement | Ref | Status |
|---|---|---|
| Accept ID-JAG via JWT bearer grant at /token | RFC 7523 | ☐ phase 2 |
| Validate iss against configured IdP trust | draft §sec | ☐ phase 2 |
| Validate aud == this gateway's AS | draft §sec | ☐ phase 2 |
| Enforce one-time-use jti | draft §sec | ☐ phase 2 |
| Preserve sub (human) + act (agent) chain into issued tokens | RFC 8693 | ☐ phase 2 |
| Issued access token: single node aud, short TTL | RFC 8707 | ☐ phase 2 |
| Internal exchange path (embedded IdP, Mode A) | design doc §2.3 | ☐ phase 2 |
