# Spidercob Gateway

**The open-source MCP gateway for teams without an IAM department** — enterprise-grade agent identity (ID-JAG / MCP Enterprise-Managed Authorization) and traffic inspection, in one container.

> Part of the [Spidercob](https://github.com/sumeetgp/spider-snoop) family. Status: **pre-alpha, phase 1** — routing + sanitization skeleton. Not production-ready.

## Why

Non-human identities (agents, service accounts) outnumber humans ~100:1 in most orgs, and most MCP deployments today run on anonymous static API keys. Spidercob Gateway sits in front of your internal MCP servers and gives every request a real identity chain (human `sub` + agent `act`), group-based policy, and bidirectional content inspection (secret/DLP redaction outbound, injection heuristics both ways).

- **Spec-correct:** implements the resource side of [ID-JAG](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant) / MCP Enterprise-Managed Authorization — works with Okta, Entra, Keycloak. No IdP? The embedded identity mode has you covered.
- **Small-team-shaped:** `docker compose up`, upload a CSV of users, check boxes. Target: protected MCPs in 15 minutes.
- **Security data path:** outbound secret redaction, response-embedded injection detection, tool pinning (planned), hash-chained audit (planned).

## Quickstart (current skeleton)

```bash
cp config.example.json config.json   # point nodes at your MCP servers
go run ./cmd/spidercob -config config.json
```

Point any MCP client (Claude Desktop, Claude Code) at `http://localhost:8080/mcp/<node-name>` instead of the upstream directly.

Metrics at `http://localhost:8080/metrics` (Prometheus format), JSON logs on stdout, `/healthz` + `/readyz` probes — free-tier Grafana Cloud setup in [docs/observability.md](docs/observability.md), prebuilt dashboard in [deploy/grafana-dashboard.json](deploy/grafana-dashboard.json).

Try the DLP demo — put a fake AWS key (`AKIA` + 16 chars) in any MCP tool response and watch the gateway return `[REDACTED:aws-access-key]`.

## Architecture

```
agent ── bearer token ──▶ [ authN → policy → sanitize → route → DLP → audit ] ──▶ internal MCP servers
                                        Spidercob Gateway
```

Full design: [docs/design.md](docs/design.md). Spec conformance tracking: [docs/spec/conformance.md](docs/spec/conformance.md). ID-JAG interop harness: [interop/](interop/).

## Roadmap (abridged)

- [x] Phase 1: JSON-RPC-aware routing, buffered scan pipeline, stdio adapter (in progress)
- [ ] Phase 2: embedded IdP + OAuth 2.1 AS, ID-JAG grant (RFC 7523/8693), per-node tokens (RFC 8707), RFC 9728 metadata
- [ ] Phase 3: group/method/tool policy, `tools/list` filtering, tool pinning
- [ ] Phase 4: admin UI, CSV users, docker packaging → **OSS launch**
- [ ] v1.0: Okta/Keycloak certified interop, `spidercob-admin` MCP server (manage the gateway by talking to Claude)

## Contributing

Not open for contributions quite yet — watch the repo; `good-first-issue`s (scanner rules!) arrive at launch. Security reports: see [SECURITY.md](SECURITY.md).

## License

Apache-2.0
