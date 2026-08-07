# Spidercob Gateway

**The open-source MCP gateway for teams without an IAM department** — enterprise-grade agent identity (ID-JAG / MCP Enterprise-Managed Authorization) and traffic inspection, in one container.

> Part of the [Spidercob](https://github.com/sumeetgp/spider-snoop) family. Status: **pre-alpha, phase 2b** — routing/sanitization skeleton plus real identity and token issuance across all three modes (local, NHI, external IdP); every request is now authenticated, but nothing is authorized yet (`policy.DenyAll{}` — Phase 3 hasn't landed). Not production-ready.

## Why

Non-human identities (agents, service accounts) outnumber humans ~100:1 in most orgs, and most MCP deployments today run on anonymous static API keys. Spidercob Gateway sits in front of your internal MCP servers and gives every request a real identity chain (human `sub` + agent `act`), group-based policy, and bidirectional content inspection (secret/DLP redaction outbound, injection heuristics both ways).

- **Spec-correct:** implements the resource side of [ID-JAG](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant) / MCP Enterprise-Managed Authorization — works with Okta, Entra, Keycloak. No IdP? The embedded identity mode has you covered.
- **Small-team-shaped:** `docker compose up`, upload a CSV of users, check boxes. Target: protected MCPs in 15 minutes.
- **Security data path:** outbound secret redaction, response-embedded injection detection, tool pinning (planned), hash-chained audit (planned).

## Quickstart (current skeleton)

Every request now needs a real bearer token (Phase 2a) — and even with one, `policy.DenyAll{}` is the real default (Phase 3's policy engine doesn't exist yet), so nothing is authorized out of the box. To actually see a call go through today, use the same `dev_allow_all_policy` + `seed_agents` combination `automation/run-e2e.sh` uses — **dev/demo only, never in production**:

```bash
cp config.example.json config.json   # point nodes at your MCP servers
```

Add to `config.json`:

```json
{
  "dev_allow_all_policy": true,
  "seed_agents": [
    { "client_id": "demo-agent", "client_secret": "change-me", "name": "local demo" }
  ]
}
```

```bash
go run ./cmd/spidercob -config config.json

# mint a token, then call through the gateway with it
curl -s http://localhost:8080/token \
  -d grant_type=client_credentials -d client_id=demo-agent -d client_secret=change-me -d resource=<node-name>
```

Point any MCP client (Claude Desktop, Claude Code) at `http://localhost:8080/mcp/<node-name>` with `Authorization: Bearer <access_token>` instead of the upstream directly.

Metrics at `http://localhost:8080/metrics` (Prometheus format), JSON logs on stdout, `/healthz` + `/readyz` probes — free-tier Grafana Cloud setup in [docs/observability.md](docs/observability.md), prebuilt dashboard in [deploy/grafana-dashboard.json](deploy/grafana-dashboard.json).

Try the DLP demo — put a fake AWS key (`AKIA` + 16 chars) in any MCP tool response and watch the gateway return `[REDACTED:aws-access-key]`.

## Architecture

```
agent ── bearer token ──▶ [ authN → policy → sanitize → route → DLP → audit ] ──▶ internal MCP servers
                                        Spidercob Gateway
```

Full design: [docs/design.md](docs/design.md). Spec conformance tracking: [docs/spec/conformance.md](docs/spec/conformance.md). ID-JAG interop harness: [interop/](interop/).

## Roadmap (abridged)

- [x] Phase 1: JSON-RPC-aware routing, buffered scan pipeline, stdio adapter
- [x] Phase 2a: embedded IdP + AS core — local users/NHI credentials, `/token`, JWKS, per-node tokens (RFC 8707), RFC 9728 metadata, real bearer-token enforcement
- [x] Phase 2b: external IdP interop — ID-JAG grant (RFC 7523/8693), verified against a real Keycloak realm; Okta via a manual runbook
- [ ] Phase 3: group/method/tool policy, `tools/list` filtering, tool pinning
- [ ] Phase 4: admin UI, CSV users, docker packaging → **OSS launch**
- [ ] v1.0: Okta/Keycloak certified interop, `spidercob-admin` MCP server (manage the gateway by talking to Claude)

## Contributing

Not open for contributions quite yet — watch the repo; `good-first-issue`s (scanner rules!) arrive at launch. Security reports: see [SECURITY.md](SECURITY.md).

## License

Apache-2.0
