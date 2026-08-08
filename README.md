# Spidercob Gateway

**The open-source MCP gateway for teams without an IAM department** — enterprise-grade agent identity (ID-JAG / MCP Enterprise-Managed Authorization) and traffic inspection, in one container.

> Part of the [Spidercob](https://github.com/sumeetgp/spider-snoop) family. Status: **pre-alpha, Phase 3 complete, Phase 4 underway** — real identity/token issuance across all three modes (local, NHI, external IdP), a real group/method/tool policy engine (authorized calls actually succeed, unauthorized ones are rejected and hidden from `tools/list`), tool pinning (every node's tools are trusted on first observation and re-checked in the background, so a tool mutated after approval — a "rug pull" — gets quarantined, blocked and hidden, automatically), schema-enforced tool calls plus a rounder DLP pipeline (Luhn-checked cards, plausibility-filtered SSNs, an entropy scorer, homoglyph/zero-width-evasion-resistant injection detection), a real HTTP admin API for agents/groups/policies/nodes — trusted via a service-to-service NHI token plus a live spider-snoop session check, no separate gateway login — and a real admin **UI**, four screens in: sign in with your existing spider-snoop session, then manage agents, groups, policies, and now nodes from a browser instead of `curl` (`internal/webui`, `go:embed`, a browser-facing cookie session additive to the existing API, never a replacement for it). Registering a node still means a restart before it actually routes traffic — no hot-reload yet, and the UI says so plainly. CSV users, an audit viewer, and packaging are the still-missing pieces. Not production-ready.

## Why

Non-human identities (agents, service accounts) outnumber humans ~100:1 in most orgs, and most MCP deployments today run on anonymous static API keys. Spidercob Gateway sits in front of your internal MCP servers and gives every request a real identity chain (human `sub` + agent `act`), group-based policy, and bidirectional content inspection (secret/DLP redaction outbound, injection heuristics both ways).

- **Spec-correct:** implements the resource side of [ID-JAG](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant) / MCP Enterprise-Managed Authorization — works with Okta, Entra, Keycloak. No IdP? The embedded identity mode has you covered.
- **Small-team-shaped:** `docker compose up`, upload a CSV of users, check boxes. Target: protected MCPs in 15 minutes.
- **Security data path:** outbound secret/PII redaction (Luhn-checked cards, plausibility-filtered SSNs, entropy-based unknown-secret detection), response-embedded injection detection (homoglyph/zero-width evasion resistant), inbound schema enforcement against each tool's pinned `inputSchema`, tool pinning (TOFU + background drift detection), hash-chained audit (planned).

## Quickstart (current skeleton)

Every request needs a real bearer token, and by default `policy` denies everything until you actually grant access. `config.json` is still the quickest path for a first run; agents/groups/policies/nodes can now also be managed from `/ui/` once the admin API is enabled, not just `config.json` — though a node registered from the UI still needs a gateway restart before it actually routes traffic (no hot-reload yet; the UI tells you this explicitly right after you register one). This mints an NHI credential, grants it access to one node, and calls through the gateway with it:

```bash
cp config.example.json config.json   # point nodes at your MCP servers
```

Add to `config.json`:

```json
{
  "seed_agents": [
    { "client_id": "demo-agent", "client_secret": "change-me", "name": "local demo", "groups": ["demo"] }
  ],
  "policies": [
    { "group": "demo", "node": "<node-name>", "rule_type": "allow" }
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

(For exercising the session/DLP pipeline without setting up real policy, `dev_allow_all_policy: true` is still available — **dev/demo only, never in production**; see `automation/run-e2e.sh`.)

Metrics at `http://localhost:8080/metrics` (Prometheus format), JSON logs on stdout, `/healthz` + `/readyz` probes — free-tier Grafana Cloud setup in [docs/observability.md](docs/observability.md), prebuilt dashboard in [deploy/grafana-dashboard.json](deploy/grafana-dashboard.json).

Try the DLP demo — put a fake AWS key (`AKIA` + 16 chars) in any MCP tool response and watch the gateway return `[REDACTED:aws-access-key]`.

`go run ./cmd/spidercob` above builds fine without Node.js installed, but `/ui/` will 404 until the admin UI's frontend is actually built — run `make web` once (or just `make build`/`make run`, which both do it for you) to get a real, UI-serving binary.

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
- [x] Phase 3a: group/method/tool policy engine, `tools/list` filtering, rate limiting
- [x] Phase 3b: tool pinning (TOFU + background drift detection, rug-pull defense)
- [x] Phase 3c: scan upgrades (schema enforcement, entropy, PII, homoglyph) — **Phase 3 complete**
- [x] Phase 4a: `internal/adminapi` v0 — HTTP admin API (agents/groups/policies), spider-snoop-integrated auth
- [x] Phase 4b: node registration — `POST/GET/DELETE /admin/nodes`, persisted, config-sourced nodes win on conflict, restart-required (no hot-reload), proven via a real process-restart e2e
- [x] Phase 4c-1: admin UI v0 — agents/groups/policies from a browser (React+Vite, `go:embed`), a new cookie-based session additive to the existing NHI-token API, sign-in via your existing spider-snoop session
- [x] Phase 4c-2: admin UI node-registration screen — cookie session widened to `/admin/nodes`, transport-conditional create form, explicit restart-required notice
- [ ] Phase 4c-3+: CSV users, audit viewer, kill-session, config-snippet generator, docker packaging → **OSS launch**
- [ ] v1.0: Okta/Keycloak certified interop, `spidercob-admin` MCP server (manage the gateway by talking to Claude)

## Contributing

Not open for contributions quite yet — watch the repo; `good-first-issue`s (scanner rules!) arrive at launch. Security reports: see [SECURITY.md](SECURITY.md).

## License

Apache-2.0
