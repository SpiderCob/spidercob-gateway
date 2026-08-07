# ID-JAG Interop Harness (Phase 0)

Build this **before** the product's auth code. Every interop bug found against a real IdP now is a design fix; found later, it's a rewrite. Reference walkthrough: [Christian Posta's Okta SAML + Keycloak ID-JAG setup](https://blog.christianposta.com/okta-saml-and-keycloak-for-id-jag-cross-app-access/) · Spec: [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant).

**This flow is fully automated** in `../automation/run-e2e-idjag.sh` (`make ci-interop`, issue #5) — realm/client/user setup via Keycloak's own Admin REST API, all three legs driven against the real compiled gateway binary. What follows is the manual walkthrough the script encodes; read it to understand what the script does, or to reproduce a step by hand while debugging an interop failure.

## 1. Start Keycloak

```bash
docker compose -f ../deploy/docker-compose.yml up keycloak
# Admin console: http://localhost:8081 (admin/admin)
```

## 2. Configure the realm (checklist)

- [ ] Create realm `spidercob-interop`
- [ ] Create client `spidercob-gateway` (confidential, `bearerOnly`) — **required**, contrary to an earlier draft of this doc: standard token exchange's `audience` parameter must name a real, registered client in the realm, not an arbitrary URI the way this gateway's own access-token `aud` works. This client exists purely as that audience target; it never itself authenticates anyone.
- [ ] Create client `agent-app` (confidential, direct access grants enabled) — represents the AI agent/app the user signed into.
- [ ] Enable **standard token exchange** on `agent-app` (current Keycloak: a per-client toggle, `standard.token.exchange.enabled` client attribute — enabled by default server-wide, no realm-level feature flag needed. Older/other versions may need `--features=token-exchange` at startup and a different, admin-fine-grained-permissions-based configuration path instead.)
- [ ] Add a client-level **Audience** protocol mapper (`oidc-audience-mapper`) on `agent-app`, with `included.client.audience` = `spidercob-gateway`. This is what actually makes `spidercob-gateway` appear in `agent-app`'s tokens' `aud` — Keycloak's documented alternative (a shared client scope carrying a role-scope-mapping to the target client's roles) did **not** reliably apply under the direct-grant flow in practice; a mapper attached directly to the client did. If a future Keycloak version behaves differently, that's a real interop finding — update this doc and `run-e2e-idjag.sh` together, don't just patch around it silently.
- [ ] Create user `alice` (password auth for the harness) — must have `emailVerified: true` plus a populated `email`/`firstName`/`lastName`, even with `requiredActions` explicitly empty. An under-populated profile trips Keycloak's dynamic `VERIFY_PROFILE` required action ("Account is not fully set up") on the direct-grant flow regardless of `requiredActions`'s literal contents.

## 3. The three-legged flow to reproduce

**Leg 1 — user identity:** `alice` signs into `agent-app`, getting a real access token (not just an ID token — RFC 8693 token exchange's `subject_token_type` for the standard flow is `urn:ietf:params:oauth:token-type:access_token`).

```bash
curl -s http://localhost:8081/realms/spidercob-interop/protocol/openid-connect/token \
  -d grant_type=password -d client_id=agent-app -d client_secret=$SECRET \
  -d username=alice -d password=... -d scope=openid | jq -r .access_token
```

**Leg 2 — RFC 8693 token exchange at the IdP:** trade that access token for an assertion audience-bound to the gateway.

```bash
curl -s http://localhost:8081/realms/spidercob-interop/protocol/openid-connect/token \
  -u agent-app:$SECRET \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=$ACCESS_TOKEN \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag \
  -d audience=spidercob-gateway
```

If `requested_token_type=id-jag` isn't honored by your Keycloak version (it emits a plain access-token-typed response instead — record this, it's real interop knowledge, not a bug in this doc), the resulting token is still a real, externally-signed, gateway-audience-bound assertion and functionally serves the same role for leg 3 below: this gateway's validator (`internal/idptrust`) never inspects the assertion's own type label, only its signature/`iss`/`aud`/`exp`/`jti`.

**Leg 3 — RFC 7523 JWT bearer grant at the gateway (issue #5 builds this):** present the assertion at the gateway's `/token`; receive a short-lived access token with `aud` = one specific MCP node.

```bash
curl -s http://localhost:8080/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion=$ASSERTION \
  -d resource=jira
```

## 4. Capture test vectors

For every successful leg, save the decoded JWTs into `vectors/` (claims only, strip signatures of anything secret). These become permanent regression tests for the gateway's validator: `sub` preserved, `act` chain present, `aud` correct, one-time-use `jti` enforced. `run-e2e-idjag.sh` does this automatically on every run.

## Notes

- Keycloak's exact support for the `id-jag` requested token type varies by version — record what your version emits; mapping quirks are exactly the interop knowledge worth blogging about.
- Second interop target: `okta-runbook.md` in this directory — a manual (not automated, per `MASTER_PLAN.md` §7's open "no Okta CI story" decision) walkthrough of the same flow against a free Okta developer org, which exercises real client-side EMA behavior Keycloak alone doesn't.
