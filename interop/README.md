# ID-JAG Interop Harness (Phase 0)

Build this **before** the product's auth code. Every interop bug found against a real IdP now is a design fix; found later, it's a rewrite. Reference walkthrough: [Christian Posta's Okta SAML + Keycloak ID-JAG setup](https://blog.christianposta.com/okta-saml-and-keycloak-for-id-jag-cross-app-access/) · Spec: [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant).

## 1. Start Keycloak

```bash
docker compose -f ../deploy/docker-compose.yml up keycloak
# Admin console: http://localhost:8081 (admin/admin)
```

## 2. Configure the realm (checklist)

- [ ] Create realm `spidercob-interop`
- [ ] Create user `alice` (password auth for the harness)
- [ ] Create client `agent-app` (confidential) — represents the AI agent/app the user signed into
- [ ] Create client `spidercob-gateway` — represents this gateway's authorization server
- [ ] Enable **token exchange** (standard token exchange in current Keycloak; older versions need the feature flag `--features=token-exchange`)
- [ ] Permit `agent-app` to request exchanges targeting audience `spidercob-gateway`

## 3. The three-legged flow to reproduce

**Leg 1 — user identity:** `alice` signs into `agent-app`, which holds an OIDC ID token.

```bash
curl -s http://localhost:8081/realms/spidercob-interop/protocol/openid-connect/token \
  -d grant_type=password -d client_id=agent-app -d client_secret=$SECRET \
  -d username=alice -d password=... -d scope=openid | jq -r .id_token
```

**Leg 2 — RFC 8693 token exchange at the IdP:** trade the ID token for an ID-JAG audience-bound to the gateway.

```bash
curl -s http://localhost:8081/realms/spidercob-interop/protocol/openid-connect/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=agent-app -d client_secret=$SECRET \
  -d subject_token=$ID_TOKEN \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag \
  -d audience=spidercob-gateway
```

**Leg 3 — RFC 7523 JWT bearer grant at the gateway (phase 2 builds this):** present the ID-JAG at the gateway's `/token`; receive a short-lived access token with `aud` = one specific MCP node.

```bash
curl -s http://localhost:8080/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion=$ID_JAG \
  -d resource=http://localhost:8080/mcp/jira
```

## 4. Capture test vectors

For every successful leg, save the decoded JWTs into `vectors/` (claims only, strip signatures of anything secret). These become permanent regression tests for the gateway's validator: `sub` preserved, `act` chain present, `aud` correct, one-time-use `jti` enforced.

## Notes

- Keycloak's exact support for the `id-jag` requested token type varies by version — record what your version emits; mapping quirks are exactly the interop knowledge worth blogging about.
- Add an Okta developer org as the second harness before launch (their [AI agent token exchange guide](https://developer.okta.com/docs/guides/ai-agent-token-exchange/-/main/) is the reference).
