# Spidercob Gateway

**The open-source MCP gateway for teams without an IAM department** — enterprise-grade agent identity (ID-JAG / MCP Enterprise-Managed Authorization) and traffic inspection, in one container.

> Part of the [Spidercob](https://github.com/sumeetgp/spider-snoop) family. Status: **pre-alpha, Phase 3 complete, Phase 4 underway** — real identity/token issuance across all three modes (local, NHI, external IdP), a real group/method/tool policy engine (authorized calls actually succeed, unauthorized ones are rejected and hidden from `tools/list`), tool pinning (every node's tools are trusted on first observation and re-checked in the background, so a tool mutated after approval — a "rug pull" — gets quarantined, blocked and hidden, automatically), schema-enforced tool calls plus a rounder DLP pipeline (Luhn-checked cards, plausibility-filtered SSNs, an entropy scorer, homoglyph/zero-width-evasion-resistant injection detection), a real HTTP admin API for agents/groups/policies/nodes/sessions — trusted either via a service-to-service NHI token plus a live spider-snoop session check (no separate gateway login), or, for standalone deployments with no spider-snoop integration at all, a local username/password checked against a config-designated admin group — and a real admin **UI**, six screens in, whose login screen auto-detects which of those two your deployment actually uses before showing you a form (`internal/webui`, `go:embed`, a browser-facing cookie session additive to the existing API, never a replacement for it). Registering or deleting a node via the admin API now applies live, on the already-running gateway — no restart, immediately routable/mintable (or, on delete, immediately not — though a session already open on it keeps working until it ends on its own). Bulk-provisioning local users (`config.json`'s `seed_users_csv_path`) is how a standalone deployment gets both its regular users and its first admin — put a seeded user in the admin group and they're a real admin from first startup, no separate bootstrap step. Every admin action, and now every proxied MCP request too — allowed or denied, `tools/call`/`tools/list`/`initialize` — leaves a real, tamper-evident **hash-chained audit record** (`internal/audit`), readable via a real `GET /admin/audit` endpoint plus a fifth UI screen — paginated, most-recent-first — not just a log line or a fixture-program-only trail. Per-request writes go through an async, bounded queue (a single background worker, drop-and-count on overflow) so audit logging can never add latency to — or fail — the request it's recording. The gateway now also ships as a real, `docker compose up`-able container — a real Docker image with the admin UI actually built in, not just the Go binary. An upstream's `text/event-stream` (SSE) response is now relayed to the client incrementally and DLP-scanned through a windowed, boundary-safe scanner as it flows, rather than fully buffered first — a bounded response-side size cap terminates a runaway stream instead of growing memory without bound. The gateway can now also be managed by talking to it — `spidercob-admin`, a reserved MCP node exposing `list_nodes`/`grant_access`/`revoke_access`/`query_audit`/`kill_session`/`list_quarantined_tools`/`approve_tool` through the exact same policy-gated pipeline every other node uses, mutating tools requiring an explicit `confirm: true` re-call before anything actually happens. Not production-ready.

## Why

Non-human identities (agents, service accounts) outnumber humans ~100:1 in most orgs, and most MCP deployments today run on anonymous static API keys. Spidercob Gateway sits in front of your internal MCP servers and gives every request a real identity chain (human `sub` + agent `act`), group-based policy, and bidirectional content inspection (secret/DLP redaction outbound, injection heuristics both ways).

- **Spec-correct:** implements the resource side of [ID-JAG](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant) / MCP Enterprise-Managed Authorization — works with Okta, Entra, Keycloak. No IdP? The embedded identity mode has you covered.
- **Small-team-shaped:** `docker compose up`, point `config.json` at a CSV of users and your policy rules. Target: protected MCPs in 15 minutes.
- **Security data path:** outbound secret/PII redaction (Luhn-checked cards, plausibility-filtered SSNs, entropy-based unknown-secret detection), response-embedded injection detection (homoglyph/zero-width evasion resistant), inbound schema enforcement against each tool's pinned `inputSchema`, tool pinning (TOFU + background drift detection), hash-chained audit covering both admin actions and every proxied MCP request.

## Installing a release

Every `v*` tag publishes signed, cross-platform binaries (`linux`/`darwin`
× `amd64`/`arm64`) to the [Releases page](https://github.com/SpiderCob/spidercob-gateway/releases)
and a signed, multi-arch container image to
`ghcr.io/spidercob/spidercob-gateway`, both signed keylessly via
Sigstore/cosign — see [docs/verify-release.md](docs/verify-release.md)
for how to verify a download actually came from this project's own CI.
[`v0.1.0`](https://github.com/SpiderCob/spidercob-gateway/releases/tag/v0.1.0)
is the first real release — a pre-launch tag proving the binary pipeline
for real (repo is still private, not the official launch), verified end
to end: real signed archives, a real `cosign verify-blob` pass against
the published bundle, a real extracted binary run. It predates the
container-image pipeline, though, so it has no image — the *next* tag
will be the first with one (that pipeline is built and proven for real
too: a disposable push/pull/sign/verify round trip against the actual
registry passes on every PR that touches it). `brew install
SpiderCob/tap/spidercob-gateway` isn't available yet — that needs a
separate tap repository that doesn't exist yet — so the sections below
are still how to run the gateway for now.

## Quickstart (current skeleton)

Every request needs a real bearer token, and by default `policy` denies everything until you actually grant access. `config.json` is still the quickest path for a first run; agents/groups/policies/nodes can now also be managed from `/ui/` once the admin API is enabled, not just `config.json` — a node registered from the UI is routable and mintable immediately, no restart required. This mints an NHI credential, grants it access to one node, and calls through the gateway with it:

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
docker compose up --build

# mint a token, then call through the gateway with it
curl -s http://localhost:8080/token \
  -d grant_type=client_credentials -d client_id=demo-agent -d client_secret=change-me -d resource=<node-name>
```

(No Docker handy, or iterating on the gateway itself? `go run ./cmd/spidercob -config config.json` works exactly the same way, straight against your local Go toolchain — no Docker required.)

Point any MCP client (Claude Desktop, Claude Code) at `http://localhost:8080/mcp/<node-name>` with `Authorization: Bearer <access_token>` instead of the upstream directly.

(For exercising the session/DLP pipeline without setting up real policy, `dev_allow_all_policy: true` is still available — **dev/demo only, never in production**; see `automation/run-e2e.sh`.)

To bulk-provision local (Mode A) human accounts — the "no IAM department" story, for a standalone deployment with no spider-snoop integration — point `config.json`'s `seed_users_csv_path` at a CSV file (`username,password,groups` columns, `groups` semicolon-separated). Provisioning is idempotent and one-way: a new username gets created and group-assigned on every startup, but an existing user's password is never reset by a later run, even if the CSV changes. See `automation/run-e2e-seed-users.sh` for a working example end to end.

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
- [x] Phase 4b: node registration — `POST/GET/DELETE /admin/nodes`, persisted, a name collision between a config-sourced and admin-sourced node is rejected (not silently overwritten either way), restart-required (no hot-reload), proven via a real process-restart e2e
- [x] Phase 4c-1: admin UI v0 — agents/groups/policies from a browser (React+Vite, `go:embed`), a new cookie-based session additive to the existing NHI-token API, sign-in via your existing spider-snoop session
- [x] Phase 4c-2: admin UI node-registration screen — cookie session widened to `/admin/nodes`, transport-conditional create form, explicit restart-required notice
- [x] Phase 4c-3: CSV bulk user import — `config.json`'s `seed_users_csv_path`, idempotent (create-if-missing, never resets an existing password), for standalone (no spider-snoop) deployments
- [x] Phase 4c-4: `internal/audit` core — hash-chained, append-only, wired into admin-API actions
- [x] Phase 4c-5: audit viewer — `GET /admin/audit` (paginated, both credential shapes from day one) + the admin UI's fifth screen; chain verification itself stays off the HTTP surface
- [x] Phase 4c-6: kill-session — `GET/DELETE /admin/sessions`, sixth admin UI screen
- [x] Phase 4c-7: config-snippet generator — real, ready-to-paste MCP client config at agent-creation time
- [x] Phase 4c-8: docker packaging — real `docker build`/`docker compose up`, admin UI actually built into the image
- [x] Phase 4c-9: policy matrix visualization — read-only groups-×-nodes access-at-a-glance view on the Policies screen
- [x] Standalone admin login — local group-based admin access for no-spider-snoop deployments; the Login screen auto-detects which credential shape a deployment accepts
- [x] Per-MCP-request audit trail — every proxied `tools/call`/`tools/list`/`initialize`, allowed or denied, now leaves a hash-chained `audit_log` row (async, bounded write queue so this never adds latency to the request path)
- [x] goreleaser signed releases + `brew install` — pipeline built and proven end to end; `v0.1.0` tagged and verified live (real signed archives, real `cosign verify-blob` pass). `brew install` itself still isn't live — needs a separate tap repo that doesn't exist yet → **OSS launch**
- [x] Signed, multi-arch container image on GHCR — same existing Dockerfile, published on every `v*` tag from here on (`v0.1.0` predates it, so the *next* tag is the first with an image); a real disposable push/pull/sign/verify/cleanup round trip against the actual registry passes on every PR touching this pipeline
- [x] `spidercob connect` — a local sidecar (new subcommand of the same binary) that holds one long-lived credential and silently mints/refreshes short-lived tokens in the background, so an interactive MCP client (Claude Desktop/Code, Cursor) never has to babysit an expiring pasted token; run `spidercob connect -gateway <url> -client-id <id> -client-secret <secret> -node <name>` and point your client at the printed local URL instead
- [x] Windowed streaming (SSE) response scanning — an upstream's `text/event-stream` response is now relayed to the client incrementally, in real time, through a windowed DLP scanner (secret/PII redaction, boundary-safe against a match split across a chunk) instead of being fully buffered first; a new response-side size cap terminates a runaway stream rather than growing memory without bound. Non-streaming responses (the large majority of traffic) are unaffected.
- [x] Hot-reload for admin-registered nodes — registering or deleting a node via the admin API applies live, on the already-running gateway; no restart, immediately routable and mintable (or, on delete, immediately not — a session already open on it keeps working until it ends on its own). Config-declared (`config.json`) nodes are unchanged and still restart-only.
- [x] `spidercob-admin` — the gateway as its own MCP server (design doc §9.1): a reserved, always-registered node reached in-process (no network hop, no subprocess) through the exact same policy/pin/scan/audit pipeline every other node already goes through. Default-deny until an operator grants a group access to it, same as any other node. Seven tools — `list_nodes`, `grant_access`, `revoke_access`, `query_audit`, `kill_session`, `list_quarantined_tools`, `approve_tool` — the last two backed by a genuinely new capability (there was previously no way to list every currently-quarantined tool across all nodes, or to re-approve one at all). The four mutating tools require a `confirm: true` re-call before anything actually happens; the first call only describes what would happen.
- [ ] v1.0: Okta/Keycloak certified interop, windowed entropy/injection scanning (currently secret/PII-only on the streaming path)

## Contributing

Not open for contributions quite yet — watch the repo; `good-first-issue`s (scanner rules!) arrive at launch. Security reports: see [SECURITY.md](SECURITY.md).

## License

Apache-2.0
