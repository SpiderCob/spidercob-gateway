# Okta Interop Runbook (Manual Verification)

Second interop target for the RFC 7523/8693 ID-JAG exchange, alongside the automated Keycloak harness (`README.md`, `../automation/run-e2e-idjag.sh`). **Not automated** — `MASTER_PLAN.md` §7 records that Okta has no obvious CI story (a hosted SaaS dev org, unlike Keycloak's per-run disposable container), so this stays a documented, repeatable manual procedure rather than a `make ci-interop` step. Run it before any launch claiming "works with Okta," and re-run it whenever this gateway's `/token` jwt-bearer handling changes.

Reference: [Okta's AI agent token exchange guide](https://developer.okta.com/docs/guides/ai-agent-token-exchange/-/main/) — the canonical source for exact console steps, which drift faster than this doc; if a step below doesn't match what you see in Okta's admin console, trust Okta's own current docs over this file and update this file to match.

Why Okta specifically, not just Keycloak: per `MASTER_PLAN.md`'s 2026-08-04 decision, Keycloak alone doesn't exercise Claude Code's actual client-side EMA behavior — that's proven against Okta specifically.

## 1. Create the free developer org

1. Sign up at [developer.okta.com](https://developer.okta.com/signup/) — Integrator Free Plan, no cost, no credit card. Confirmed sufficient for Cross App Access (XAA) setup per `MASTER_PLAN.md`'s 2026-08-04 note.
2. Note your org's base URL, e.g. `https://dev-12345678.okta.com`.

Optional first step before touching a real org: prototype the flow shape against the no-signup [XAA playground at xaa.dev](https://xaa.dev) (referenced in `README.md`) to get oriented on the moving pieces before doing it for real.

## 2. Configure Cross App Access (checklist)

- [ ] In the Okta admin console, enable **Cross App Access** for the org (Security → Cross App Access, or wherever Okta's current console places it — this has moved before).
- [ ] Create an app integration representing the agent/app the user signs into — equivalent to `interop/README.md`'s `agent-app` Keycloak client. OIDC, confidential client.
- [ ] Create (or reuse) an app integration representing this gateway's authorization server — equivalent to `spidercob-gateway` in the Keycloak harness. This is the ID-JAG's intended audience.
- [ ] Grant the agent-app integration permission to request an ID-JAG audience-bound to the gateway integration (Okta's Cross App Access authorization policy step — this is the org-level equivalent of Keycloak's "permit agent-app to request exchanges targeting audience spidercob-gateway").
- [ ] Create a test user in the org (equivalent to Keycloak's `alice`).

## 3. The three-legged flow to reproduce

Same shape as `README.md`'s Keycloak walkthrough — only the endpoints and Okta-specific parameter names differ.

**Leg 1 — user identity:** the test user signs into the agent-app integration via Okta's standard OIDC flow, which holds an ID token. Okta's guide walks through obtaining this via its authorization code flow; for a scripted check, Okta also supports the resource-owner password flow on some org configurations (may need to be explicitly enabled — check the current guide).

**Leg 2 — RFC 8693 token exchange at Okta:** trade the ID token for an ID-JAG audience-bound to the gateway, at Okta's org-specific token endpoint:

```bash
curl -s https://$OKTA_DOMAIN/oauth2/v1/token \
  -u "$AGENT_APP_CLIENT_ID:$AGENT_APP_CLIENT_SECRET" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=$ID_TOKEN \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag \
  -d audience=$GATEWAY_ISSUER
```

**Leg 3 — RFC 7523 JWT bearer grant at the gateway (issue #5 builds this):** present the ID-JAG at the gateway's `/token`, scoped to a specific registered node — identical request shape to the Keycloak leg, since this gateway's `/token` doesn't distinguish which external IdP issued the assertion, only whether it's in `config.TrustedIdPs`:

```bash
curl -s http://localhost:8080/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion=$ID_JAG \
  -d resource=http://localhost:8080/mcp/jira
```

## 4. Gateway config for this run

Add Okta as a trusted issuer alongside (or instead of) the Keycloak entry `run-e2e-idjag.sh` configures automatically:

```json
{
  "trusted_idps": [
    {
      "issuer": "https://dev-12345678.okta.com/oauth2/default",
      "jwks_url": "https://dev-12345678.okta.com/oauth2/default/v1/keys",
      "expected_audience": "http://localhost:8080"
    }
  ]
}
```

`issuer` and `jwks_url` must match exactly what Okta stamps on ID-JAGs and publishes at its own `/.well-known/openid-configuration` for the authorization server in use (the `default` custom authorization server above, or a differently-named one if configured) — confirm both against that discovery document for your org rather than assuming this exact path.

## 5. What "passing" means

- [ ] Leg 1 + 2 succeed against real Okta endpoints, producing a real ID-JAG (capture its decoded claims — see below).
- [ ] Leg 3 succeeds against this gateway's real `/token`, returning a node-scoped access token whose `sub` resolves to a JIT-provisioned local user and whose `act` claim reflects the agent-app's client ID (RFC 8693 actor chain preserved, story 13 of issue #5).
- [ ] A second full run (steps 1–3 again) for the same Okta user resolves the same local user, not a duplicate (story 12).
- [ ] Replaying a captured ID-JAG's `assertion` value against `/token` a second time is rejected (one-time-use `jti`, story 7) — same guarantee the Keycloak harness proves automatically.

## 6. Capture test vectors

Same as `README.md` §4: save decoded claims (never signatures or secrets) from every successful leg into `vectors/`, named distinctly from the Keycloak vectors (e.g. `okta-leg2-idjag-claims.json`) so a future spec-draft change or an Okta-side config change that breaks the flow is caught by re-running this runbook, not discovered later.

## Notes

- Okta's exact support surface for `requested_token_type=urn:ietf:params:oauth:token-type:id-jag` is newer and less battle-tested than Keycloak's more general token-exchange support — record what your org's response actually looks like; deviations from the spec text are exactly the interop knowledge worth writing up (per `MASTER_PLAN.md`'s "every interop bug found early is a design fix" principle, and `design.md`'s GTM plan to blog spec-draft changes).
- If Okta ever gains a documented way to spin up a disposable, API-provisioned dev org per CI run, revisit the `MASTER_PLAN.md` §7 "no CI story" open decision — this runbook would become the seed for a real `automation/run-e2e-idjag-okta.sh`, not a permanent manual-only fixture.
