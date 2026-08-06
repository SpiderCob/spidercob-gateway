# Spidercob ID-JAG Gateway — Technical Design Document

**Status:** Draft v0.3 · July 2026
**Product:** Open-source, self-hosted MCP gateway with spec-correct ID-JAG identity, group-based access control, input sanitization, and DLP — plus a managed tier via the Spidercob control plane.
**Team:** Solo founder, Claude-assisted development. Strategy: OSS-first → community traction → raise → enterprise tier.

---

## 1. Executive Summary

Enterprises and startups are deploying internal MCP servers (Jira, Postgres, internal APIs) and have no good way to control which humans and agents can reach which server, with what identity, and with what data leaving the boundary. The Spidercob Gateway is a single Docker-deployable reverse proxy + policy engine + token service that sits in front of all internal MCP servers.

The wedge: **be the first credible open-source implementation of ID-JAG (IETF Identity Assertion Authorization Grant) applied to MCP.** Okta/Microsoft are pushing this spec ("Cross App Access") from the IdP side; nobody owns the open-source *resource side* — the gateway that consumes ID-JAG grants and enforces policy in front of MCP servers. Sanitization/DLP on the MCP data path is the second moat.

Target initial customer: startups with 50–100 users, no dedicated IAM team, who want to deploy in an afternoon.

---

## 2. Getting the Spec Right (Critical Correction)

The v0.1 sketch treated "ID JAG" as a custom gateway-minted JWT with an `allowed_mcps` claim. **That is not what ID-JAG is, and shipping that would forfeit the differentiation.** Two specs define the real architecture:

### 2.1 ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant, currently draft-04)

ID-JAG lets an app/agent that already holds an SSO identity assertion obtain access to a *different* app's API by coordinating through the **enterprise IdP** — not by minting its own tokens. The flow composes two existing RFCs:

1. **RFC 8693 Token Exchange (at the IdP):** The requesting app/agent presents its OIDC ID token (or SAML assertion) to the enterprise IdP and requests a JWT Authorization Grant for a specific target resource. The IdP evaluates enterprise policy and returns a short-lived, one-time-use **ID-JAG** (`urn:ietf:params:oauth:token-type:id-jag`), audience-restricted to the target's authorization server and downscoped to the task.
2. **RFC 7523 JWT Bearer Grant (at the resource's AS):** The app presents the ID-JAG to the *target resource's* authorization server, which validates it (issuer = trusted IdP, audience = itself) and issues its own scoped access token for the resource.

Key properties the gateway must preserve:

- **The IdP is the policy chokepoint.** The enterprise admin governs agent→resource access centrally, in the IdP, not via per-app secrets.
- **Identity chaining:** the human is the `sub`, the acting agent appears via the `act`/actor claim (RFC 8693 delegation semantics). Every hop is attributable to a real person *and* the software acting for them. Audit logs must record both.
- **One token, one audience.** An ID-JAG is bound to a single target authorization server; the access token it yields is bound to a single resource. No multi-resource tokens.

### 2.2 MCP Authorization Spec (Nov 2025 revision + July 2026 draft)

- An MCP server is an **OAuth 2.1 resource server only**. Token issuance belongs to a separate authorization server. Remote MCP servers must implement OAuth 2.1 with PKCE (S256).
- Discovery via **RFC 9728 Protected Resource Metadata** (`/.well-known/oauth-protected-resource`) pointing at the AS; AS metadata via RFC 8414.
- **RFC 8707 Resource Indicators** so tokens are bound to a specific MCP server (confused-deputy protection); clients validate issuer per **RFC 9207**.
- Dynamic client registration (RFC 7591) for zero-touch client onboarding.

### 2.3 What this means for Spidercob's architecture

The gateway plays **two spec roles simultaneously**:

1. **Authorization Server** for every MCP server behind it — the endpoint that *consumes* ID-JAGs (RFC 7523 grant type) and issues short-lived, per-MCP-server access tokens.
2. **Resource-server front** — the proxy that validates those access tokens on every JSON-RPC request and serves RFC 9728 metadata on behalf of each proxied MCP server.

Identity comes in three deployment modes:

| Mode | Who issues identity | Target buyer |
|---|---|---|
| **A. Standalone** | Gateway's *embedded IdP* (local users, CSV upload, optional built-in OIDC). Gateway is IdP + AS + proxy in one binary. | Startups, 50–100 users, no Okta |
| **B. Federated (true ID-JAG)** | Customer's IdP (Okta, Entra, Keycloak) issues ID-JAGs; gateway AS validates them and exchanges for MCP access tokens. | Mid-market/enterprise with existing SSO |
| **C. Managed** | Mode A or B, with policy pushed from Spidercob SaaS control plane. | Paid tier |

Mode A is deliberately a *superset shim*: the embedded IdP speaks the same RFC 8693 exchange internally, so upgrading A→B is a config change (swap issuer trust), not a migration. This is the adoption ramp: start standalone, grow into Okta federation, graduate to managed.

---

## 3. System Architecture

Three logical planes, one Go binary, one container:

```
                        ┌─────────────────────────────────────────────┐
                        │            SPIDERCOB GATEWAY                │
  Agents / MCP clients  │                                             │   Internal network
                        │  ┌──────────────┐   ┌───────────────────┐  │
  ──(1) SSO/login──────▶│  │ Identity     │   │ Control Plane     │  │
  ──(2) token exchange─▶│  │ Engine       │   │ (Admin UI + API)  │  │
       (ID-JAG in,      │  │ embedded IdP │   │ users/groups/     │  │
        access tok out) │  │ + OAuth AS   │   │ policies/audit    │  │
                        │  └──────┬───────┘   └─────────┬─────────┘  │
                        │         │ introspect          │ policy      │
                        │  ┌──────▼─────────────────────▼─────────┐  │
  ──(3) JSON-RPC───────▶│  │ Data Plane (Interceptor)             │  │──▶ MCP: Jira
       Bearer token     │  │ authN → policy → sanitize → route    │  │──▶ MCP: Postgres-RO
                        │  │ → DLP scan response → audit          │  │──▶ MCP: internal API
                        │  └──────────────────────────────────────┘  │
                        └─────────────────────────────────────────────┘
                                          │
                          (Managed mode: outbound gRPC/WebSocket
                           tunnel to Spidercob SaaS control plane)
```

- **Control Plane:** Admin UI (static React served by the binary) + REST API. Users, groups, MCP node registry, policies, audit log viewer, token/session revocation.
- **Identity Engine:** Embedded IdP (Mode A), OAuth 2.1 AS with token-exchange and JWT-bearer grant support, JWKS endpoint, RFC 9728 metadata per proxied MCP server, external-IdP trust config (Mode B).
- **Data Plane:** JSON-RPC-aware L7 proxy. This is the hot path; everything else exists to configure it.

---

## 4. Token & Session Design

- **Access tokens:** JWTs signed EdDSA (Ed25519), **one token per MCP server** (`aud` = that server's canonical URI via RFC 8707). Never a single token valid at multiple MCPs — the v0.1 `allowed_mcps` map recreates the confused-deputy problem the MCP spec was revised to kill.
- **Default TTL: 120 seconds for NHI/agent tokens, 10 minutes for human tokens, both admin-configurable.** *(Updated 2026-08-06 — see `MASTER_PLAN.md` §6, 2026-08-04. Originally scoped as a 15–60 min range; short, mode-differentiated defaults are the actual design — NHI tokens get a much tighter window given higher automation/blast-radius risk.)*
- **Claims:** `iss` (gateway AS), `sub` (human user or, for pure NHI calls, the agent's own identity), `act` (agent client_id — preserved from the ID-JAG's actor chain), `aud` (target MCP), `scope` (see §5), `jti`, `exp`, `iat`.
- **Revocation:** in-memory `jti` denylist (per-process map; a shared store is a v1.1 HA item), fed by admin UI "kill session" and by Spidercob threat signals in managed mode. Deny-list beats short TTL for incident response; both together are the design.
- **No separate refresh-token grant.** *(Updated 2026-08-06 — supersedes the `offline_access` refresh-token line originally here; see `MASTER_PLAN.md` §6, 2026-08-04.)* On expiry, each mode re-runs its own original exchange instead: NHI re-calls `/token` with the same `client_credentials` (standard practice — client_credentials grants don't typically issue refresh tokens anyway); Mode A humans silently re-mint via their still-valid local UI session; Mode B humans silently redo the RFC 8693+7523 exchange again — invisible to the user under EMA's zero-touch model, and this naturally keeps the IdP in the loop on every reissuance, which bounds deprovisioning staleness better than a long-lived refresh token would.
- **Sender constraint (v1.1):** optional DPoP so a stolen bearer token is useless off-host.
- **NHI (agent) credentialing is decoupled from Mode A/B, not Mode-A-only.** *(Updated 2026-08-06 — see `MASTER_PLAN.md` §1, §6, 2026-08-04.)* Every NHI is a first-class principal with its own group membership (`agent_groups`), independent of Mode A/B, since an org fully on enterprise SSO for humans still needs a local, IdP-agnostic way to onboard a CI job or standing automation. Two credentialing tiers: (1) a static, hashed client secret + `client_credentials` grant for ephemeral/stateless NHIs that can't hold a key between runs (v1); (2) a locally-generated keypair enrolled the same way the gateway container itself enrolls, for long-running NHIs that can (v1.1, "secretless" — no long-lived shared secret ever transmitted). Tier-1 secrets never reach an MCP server and are hashed at rest (argon2id).

---

## 5. Policy Engine

Group-based, default-deny, evaluated at token issuance *and* re-checked per request (tokens can outlive a policy change; the request-time check wins).

**Granularity levels (ship in this order):**

1. **Server-level:** group G may access MCP node N.
2. **Method-level:** allowed JSON-RPC methods (`tools/call`, `resources/read`, `prompts/list`…).
3. **Tool-level:** allowlist of specific tool names within `tools/call`. The gateway also *filters `tools/list` responses* so unauthorized tools are invisible, not just blocked — agents can't be prompt-injected into calling tools they can't see.
4. **Parameter-level (v1.1):** constraints on tool arguments (e.g., `ticket_id` must match `^[A-Z]+-\d+$`; `query` must not contain DDL). Expressed as JSON-schema overlays on the tool's declared `inputSchema`.

**Implementation:** start with a simple deterministic evaluator over normalized policy rows (SQLite). Design the interface so **Cedar (cedar-go)** can be swapped in for v1.1 — Cedar gives you auditable, analyzable policies without shipping a Rego runtime. Scopes encode coarse policy into the token (`mcp:jira:tools:get_jira_ticket`), fine policy stays server-side.

**Tool pinning (rug-pull defense):** on MCP node registration, snapshot `tools/list` and hash each tool's name+description+inputSchema. If an upstream server later changes a tool definition, the gateway quarantines the tool (blocked + admin alert) until re-approved. Malicious tool-description mutation is a top real-world MCP attack; checkbox-cheap to defend at registration time.

---

## 6. Data Plane (Proxy Interception)

**Transports:** Streamable HTTP (primary, current spec), SSE (legacy compat), and a **stdio adapter** — a tiny supervisor that spawns local stdio MCP servers as child processes and exposes them as HTTP nodes. Startups run lots of stdio servers; wrapping them is a major adoption unlock the v0.1 sketch missed.

**Request lifecycle:**

1. TLS terminate → parse JSON-RPC (reject malformed/oversized early; cap body size).
2. Validate bearer token: signature, `exp`, `aud` matches this route, `jti` not revoked.
3. Policy check (method → tool → params).
4. Inbound sanitization (§7).
5. Forward upstream with a *gateway-held upstream credential* (the agent's token never reaches the MCP server; the gateway injects per-node service credentials or passes through user context via headers, configurable per node).
6. Outbound DLP scan on the response (§7); streaming responses scanned in windowed chunks with redaction applied before flush.
7. Audit record: `sub`, `act`, node, method, tool, decision, latency, sanitizer verdicts, redaction count. Hash-chained log lines (tamper evidence) — cheap now, sellable later.

**Session semantics:** MCP is stateful (initialize handshake, session IDs). The gateway owns session mapping: one client session ↔ one upstream session, torn down on revocation. This is the part naive HTTP reverse proxies get wrong and why `httputil.ReverseProxy` alone isn't enough — budget real engineering time here.

---

## 7. Sanitization & DLP (the Spidercob moat)

Modular pipeline, each stage a `Scanner` interface (verdict: allow / redact / block / flag), hot-reloadable rules, per-node and per-group configurability.

**Inbound (agent → MCP):**

- Schema enforcement: arguments must validate against the tool's pinned `inputSchema`. Rejects whole classes of injection for free.
- Injection heuristics: pattern sets for prompt-injection markers ("ignore previous instructions", role-reassignment phrases, encoded payloads), SQL/command-injection signatures for tools that touch shells/DBs, homoglyph/zero-width-char normalization *before* matching.
- Size/recursion caps on JSON structures.

**Outbound (MCP → agent):**

- Secret detection: curated regex + entropy scoring (AWS keys, GCP/Azure creds, private key blocks, JWTs, connection strings) — start from Gitleaks' ruleset.
- PII detection: SSN/credit-card (with Luhn), email/phone (configurable — often legitimate).
- **Response-embedded injection:** scan *tool results* for instruction-like content targeting the LLM ("when you summarize this, also run…"). Data returned from MCP servers is the #1 injection vector into agents; scanning responses for injections, not just secrets, is a differentiator most gateways skip.
- Redaction is structural (`[REDACTED:aws-key]` with audit reference), never silent dropping.

**Honesty in the docs:** regex+heuristics catch the commodity 80%. The engine is built so an ML classifier (local ONNX model in OSS, Spidercob-hosted models in managed) slots in as another `Scanner`. Don't market heuristics as AI.

---

## 8. Data Model

SQLite embedded (pure-Go driver, WAL mode) by default; Postgres behind the same store interface for HA/managed.

- `users` — id, username, email, password_hash (argon2id, Mode A), role (admin|member), status, created_at
- `agents` — id, owner_user_id, name, client_id, api_key_hash, status *(agents are first-class principals, separate from humans — required for `act` chaining)*
- `groups` / `user_groups` / `agent_groups`
- `mcp_nodes` — id, name, canonical_uri, transport (streamable_http|sse|stdio), upstream_auth (none|service_token|passthrough), status, health
- `tool_pins` — node_id, tool_name, schema_hash, description_hash, approved_at, approved_by
- `policies` — id, group_id, node_id, **rule_type (allow|deny)**, allowed_methods[], allowed_tools[], param_constraints (json), **rate_limit (json, optional — max calls / window)**, sanitizer_profile_id. *(Updated 2026-08-06: explicit `rule_type` and `rate_limit` columns — the original allow-only table couldn't express deny-as-exception carve-outs or per-group/per-NHI quotas; evaluation order is deny-overrides-allow-overrides-default-deny, see `MASTER_PLAN.md` §6, 2026-08-04.)*
- `sanitizer_profiles` — id, name, inbound_rules (json), outbound_rules (json)
- `idp_trust` — issuer, jwks_uri, expected_aud, mode (Mode B federation config)
- `revocations` — jti, reason, revoked_at (persisted; mirrored to memory)
- `audit_log` — ts, sub, act, node_id, method, tool, decision, scanner_flags (json), latency_ms, prev_hash, hash

CSV user upload = insert into `users` + `user_groups`; SCIM 2.0 endpoint is the enterprise-tier replacement (same tables).

---

## 9. Admin Experience (Mode A happy path)

`docker compose up` → open `:8080` → create admin → upload `users.csv` (name, email, groups) → "Add MCP Server" (URL or stdio command) → gateway probes it, lists discovered tools with checkboxes → assign groups → done. Target: **under 15 minutes from download to first proxied, policy-enforced MCP call.** Every screen has a "copy agent config" snippet (Claude Desktop / Claude Code / cursor-style JSON) pointing at the gateway. That snippet is the growth loop: every agent config a customer shares contains your product.

### 9.1 `spidercob-admin`: the gateway as its own MCP server (v1.0)

Expose the admin API itself as a built-in MCP server behind the gateway, so an admin can manage it conversationally from Claude: *"give the marketing group access to the Jira MCP but only read tools"*, *"who called `delete_record` this week?"*, *"kill all of agent X's sessions."* Tools: `list_nodes`, `grant_access`, `revoke_access`, `query_audit`, `kill_session`, `list_quarantined_tools`, `approve_tool`.

Design rules: it is just another `mcp_nodes` entry, subject to the same policy engine (admin-group only, default-deny), the same audit log, and the same scanners — the gateway dogfooding itself is the point. Mutating tools (`grant_access`, `kill_session`) return a confirmation payload and require an explicit `confirm: true` re-call, so a prompt-injected agent can't silently escalate privileges through the admin surface. This is simultaneously a feature, the best launch demo ("I manage my MCP security by talking to Claude"), and proof the policy engine works.

---

## 10. Deployment Topologies

**OSS / self-hosted:** one `docker-compose.yml`, one gateway container (UI, AS, proxy in one Go binary) + a volume for SQLite. No Redis, no Postgres, no separate frontend container at this scale — every extra container halves the number of startups that finish setup.

**Managed ("Headless Edge Mode"):** identical container in the customer VPC; MCP traffic and data never leave their network. Gateway dials *out* (mTLS gRPC stream) to the Spidercob control plane for: policy sync (signed policy bundles, verified at the edge — SaaS compromise can't silently rewrite customer policy), threat-intel rule pushes, fleet health, aggregated *metadata-only* audit (counts/verdicts, no payloads, configurable). Edge keeps enforcing last-known policy if the tunnel drops — fail static, never fail open.

**Licensing seam:** OSS core under Apache-2.0 (permissive maximizes the standard-adoption bet); managed-tier value = hosted control plane, SSO/SCIM at scale, ML scanners, threat intel feed, fleet management, compliance reporting. The seam is *operational scale*, not withheld security features — crippled-OSS security tools get forked.

---

## 11. Tech Stack

- **Language:** Go. Single static binary, native concurrency for streaming proxies, mature OAuth libs (`fosite` or hand-rolled AS on `golang-jwt` + `jose`), `crypto/ed25519` in stdlib. Custom JSON-RPC-aware proxy layer (not bare `httputil.ReverseProxy` — see §6 session semantics).
- **DB:** `modernc.org/sqlite` (no cgo) → Postgres via store interface.
- **UI:** React + Vite, embedded via `go:embed`.
- **Policy:** internal evaluator → `cedar-go` at v1.1.
- **Scanners:** Go regexp (RE2, no ReDoS) + entropy; ONNX runtime slot for ML.
- **Distribution:** Docker image, Homebrew tap, single-binary release, Helm chart at v1.1.

### 11.1 Reusable building blocks (don't build these from scratch)

| Need | Use | Why |
|---|---|---|
| MCP protocol (client + server + stdio + streamable HTTP) | **`modelcontextprotocol/go-sdk`** (official, Google-maintained, v1.4.x, spec-complete for 2025-11-25) | Eliminates the entire protocol layer: use client side for upstream connections, server side for terminating agent connections and for `spidercob-admin`. The single biggest schedule accelerator — weeks of transport/session work gone. |
| OAuth 2.1 authorization server | **`ory/fosite`** (extensible OAuth2/OIDC SDK) or **`zitadel/oidc` v3** (OpenID-certified) | Both let you add custom grant handlers — implement RFC 7523/8693 (ID-JAG consumption) as a fosite handler instead of hand-rolling token endpoint security. Prototype with both in week 3; pick whichever fights you less. |
| Secret detection rules | **Gitleaks ruleset** (MIT) | Battle-tested regex + entropy rules for AWS/GCP/Azure/keys/JWTs; import as seed `rules/` content. |
| Injection/PII scanner patterns | **LLM Guard** (35 scanners, Python) as *pattern source*, not runtime dependency | Port its input/output scanner heuristics to Go; credit upstream. Don't embed Python in the hot path. |
| Policy language (v1.1) | **`cedar-go`** | Auditable, analyzable policies; AWS-backed. |
| ID-JAG interop reference | **agentgateway** (AAIF) + **Christian Posta's Keycloak ID-JAG setup** | Working EMA implementations to test against and learn edge cases from — reference, not dependency. |
| Admin UX patterns | **Obot**, **MCPX** | Study their node-registration and tool-listing flows; borrow what works, simplify harder. |

Net effect on the §13.2 schedule: the go-sdk removes most of Phase 1's protocol risk, and fosite/zitadel-oidc de-risks Phase 2's token endpoint. Solo effort concentrates where differentiation lives: policy, scanners, pinning, UI, and the ID-JAG grant handler.

---

## 12. Competitive Landscape & Positioning (updated July 2026)

The window moved. ID-JAG for MCP was formalized as MCP's **Enterprise-Managed Authorization (EMA)** extension, which reached **stable status in June 2026**. Spec compliance is no longer a wedge — it is table stakes. Current field:

**ID-JAG/EMA implementers (direct):**

- **agentgateway (AAIF, open source)** — already ships ID-JAG + EMA support. The closest direct threat to a "first OSS ID-JAG gateway" claim; that claim is gone. But it is a *data-plane component* aimed at platform engineers: no admin UI, no user/group management, no embedded IdP, no DLP. It assumes you bring Kubernetes, an IdP, and expertise.
- **TrueFoundry MCP Gateway** — XAA/IdP-governed agent access, enterprise-shaped and part of a larger ML platform.
- **Kong** — enterprise MCP access control on Agent Gateway; incumbent land-grab, priced and shaped for large orgs.
- **Atlassian (Rovo MCP)** — built the resource side for their own product; validates the pattern, not a competitor.
- **IdP/auth-vendor ecosystem** — Okta, WorkOS, Stytch, Scalekit, Keycard, MintMCP, Zuplo, and ~20 others have announced ID-JAG support. These are *issuer-side* or auth-as-a-service; they need resource-side gateways to exist. Potential partners, not competitors.

**NHI security platforms (adjacent):**

- **Aembit** — closest analog: secretless workload attestation, token exchange, sidecar proxy, an MCP Identity Gateway, blended human-agent identity. Enterprise sales motion, not OSS, not content inspection.
- **Astrix → acquired by Cisco** (standalone sales ended June 30, 2026). Market validation and a consolidation signal: the acquirers are already shopping.
- **Oasis, Entro, Token Security, Clutch** — NHI discovery/posture/governance, not inline enforcement. Adjacent; possible integration partners.

**MCP gateways without deep identity:** Obot, Lunar.dev MCPX, Bifrost — routing/governance focus, none combine EMA-native identity with a security data path.

### The repositioned wedge

Three gaps remain open, and Spidercob should claim all three at once:

1. **Batteries-included for small teams.** agentgateway is a component; Aembit/Kong/TrueFoundry are enterprise-priced. Nobody ships "docker compose up → UI → CSV users → protected MCPs in 15 minutes." The under-500-employee segment is unserved.
2. **Embedded IdP (Mode A).** EMA assumes the customer already has Okta/Entra. Startups without an IdP are locked out of the entire ecosystem — Spidercob's embedded IdP is their on-ramp, and the A→B federation upgrade path is the land-and-expand motion.
3. **Identity + content inspection in one box.** No identity player inspects the traffic (injection scanning, DLP, tool pinning); no inspection player does spec-correct identity. The combination is unclaimed.

**Market tailwind (the NHI thesis):** NHIs outnumber human identities ~100:1 in enterprises; Microsoft's 2026 Secure Access Report found 97% of orgs had an identity-related incident in the past year, 70% originating from AI activity. The `sub`+`act` human-agent chain this gateway enforces is precisely the fix for anonymous-service-account sprawl. Consolidation (Cisco/Astrix) means speed to a usable OSS release matters more than feature completeness.

**Build-vs-fork decision:** do *not* fork or wrap agentgateway. Its architecture (Rust, platform-team-shaped) is the opposite of the single-binary product thesis, and differentiation lives in the product layer (UI, embedded IdP, scanners) that would have to be built anyway. Do steal its interop learnings and cite it respectfully — the community notices graciousness.

---

## 13. Solo Implementation Plan (Claude-assisted)

Scoped for one founder shipping with Claude Code. The rule that makes this survivable: **every phase ends with something demoable, and nothing enters scope that doesn't serve the OSS launch.**

### 13.1 Repository layout

```
spidercob/
├── cmd/spidercob/main.go          # single entrypoint, cobra CLI (serve, admin, migrate)
├── internal/
│   ├── store/                     # store interface + sqlite impl (postgres later)
│   ├── identity/                  # embedded IdP: users, sessions, password auth
│   ├── authserver/                # OAuth 2.1 AS: /token (RFC 7523 + 8693), JWKS,
│   │                              #   RFC 9728 metadata per node, revocation
│   ├── policy/                    # evaluator interface + v0 rule engine
│   ├── proxy/                     # JSON-RPC parse, session map, streamable HTTP,
│   │   └── stdioadapter/          #   child-process supervisor for stdio MCPs
│   ├── scan/                      # Scanner interface + regex/entropy/schema scanners
│   ├── pin/                       # tools/list snapshot + hash + quarantine
│   ├── audit/                     # hash-chained log writer + query API
│   └── adminapi/                  # REST for the UI
├── ui/                            # React+Vite, embedded via go:embed
├── deploy/                        # docker-compose.yml, Dockerfile, helm (later)
├── interop/                       # ID-JAG test vectors, Keycloak + Okta harnesses
└── docs/                          # mkdocs — treat docs as a launch feature
```

### 13.2 Build order (dependency-sorted, originally ~12 weeks to launch)

*(Note, 2026-08-06: real scope added since this estimate — full stdio process supervision with backoff/quarantine, dual Phase 2 interop targets (Keycloak **and** Okta, not just Keycloak), explicit ALLOW/DENY policy rules, rate limiting, scan-verdict-conditional policy actions, two-tier NHI credentialing — means 12 weeks should be treated as stale, not a target still holding. See `MASTER_PLAN.md` §7 open decisions.)*

**Phase 0 — Validation & setup (weeks 0–2, part-time, before writing product code)**

- Read draft-04 and the EMA spec line-by-line; write a 1-page "spec conformance checklist" that becomes the test plan.
- Stand up a Keycloak instance issuing ID-JAGs (Christian Posta's writeup is the template) — this is the interop harness everything gets tested against, *built before the product*.
- Landing page + waitlist (one evening). Post the concept in the MCP community Discord/GitHub discussions and r/mcp: "would you use this?" 10 conversations minimum. If nobody bites on the *concept*, cheaper to learn now.
- Pick the final OSS name and check trademark/domain/GitHub org availability.

**Phase 1 — Skeleton that proxies (weeks 1–3)**

1. `store` + migrations + `users/groups/mcp_nodes` tables.
2. `proxy`: streamable-HTTP passthrough with JSON-RPC parsing and session mapping. No auth yet. Milestone: Claude Desktop → gateway → a real MCP server works.
3. `stdioadapter`. Milestone: any stdio server from the registry runs behind the gateway.

**Phase 2 — Identity & tokens (weeks 3–6)**

4. `identity`: local users, argon2id, session cookies for the UI; agent API keys.
5. `authserver`: Ed25519 keys, JWKS, `/token` with internal exchange (Mode A), per-node `aud`, RFC 9728 metadata endpoints, `jti` revocation. Milestone: unauthenticated JSON-RPC gets 401 + correct `WWW-Authenticate` resource-metadata pointer; token-bearing requests route.
6. Wire the Keycloak harness: accept external ID-JAGs (Mode B core). This early — interop bugs found now are design fixes, found later are rewrites.

**Phase 3 — Policy & scanning (weeks 6–9)**

7. `policy` v0: server/method/tool levels + `tools/list` filtering.
8. `pin`: snapshot, hash, quarantine flow.
9. `scan`: schema enforcement, Gitleaks-derived secret rules, entropy scorer, injection pattern set, homoglyph normalization. Ship with honest defaults (block secrets outbound, flag-don't-block injection heuristics).

**Phase 4 — Admin UI & packaging (weeks 9–12)**

10. UI: setup wizard, users+CSV upload, node registration with tool-checkbox screen, policy matrix, audit viewer, kill-session button, per-client "copy config" snippets.
11. `deploy/`: Dockerfile (distroless, <30 MB), docker-compose, signed releases via goreleaser, `brew install`.
12. Docs: quickstart (the 15-minute path), spec-conformance page, threat-model page, comparison page vs agentgateway/Kong/Aembit (fair, factual — comparison pages are top-of-funnel gold).

**Launch gate checklist:** fresh-machine quickstart ≤15 min · Keycloak *and* Okta dev-org interop demos recorded · README with 60-second demo GIF · security.md + a completed self-audit pass · Apache-2.0 LICENSE + CLA decision · seed content written (see §14).

### 13.3 Post-launch roadmap

- **v1.0 (launch + 8 weeks):** hardening from community issues, Okta-certified interop, **`spidercob-admin` MCP server (§9.1)**, SSE compat, response-injection scanning v2, revocation webhooks, audit export.
- **v1.1 (quarter 2):** Cedar policies, parameter constraints, DPoP, SCIM, Postgres/HA, Helm, ONNX scanner slot.
- **Managed tier (only after funding):** control-plane tunnel, signed policy bundles, fleet dashboard, threat-intel feed, SOC 2 evidence packs. Do not build any of this pre-raise — it has zero OSS-traction value.

### 13.4 Working solo with Claude — practical rules

- **Spec-first prompting:** keep the conformance checklist and draft-04/EMA text in the repo (`docs/spec/`); point Claude at them in every auth-related session. LLMs confidently invent OAuth details — the checklist is the guardrail.
- **Test harness as ratchet:** every interop bug becomes a permanent test against the Keycloak harness before it's fixed. Solo devs can't afford regressions.
- Use Claude Code for the mechanical 70% (CRUD, UI screens, migrations, table-driven tests, docs) and reserve your own review depth for the **five** security-critical seams: token validation, **NHI credential issuance (`client_credentials`)**, policy evaluation, session mapping, redaction ordering. *(Updated 2026-08-06 — added the NHI seam; see `MASTER_PLAN.md` §6, 2026-08-04. The underlying token-signing code is shared with ID-JAG handling, but `client_credentials` authentication logic is distinct and shouldn't be assumed covered by testing the ID-JAG path alone.)* **Get one external security review of those seams before launch** — a paid freelance audit (~$3–5k) or a respected community reviewer; an auth product with a launch-week token bypass is dead.
- Ruthless scope cuts already made: no HA, no Postgres, no SSO for the *admin UI*, no Mode C, no ML scanners at launch. Resist re-adding them.

---

## 14. Go-to-Market: OSS Launch, Marketing & Impact

Solo + OSS means marketing *is* documentation, content, and community presence. Plan it like a feature.

### 14.1 Positioning

One sentence, everywhere: **"The open-source MCP gateway for teams without an IAM department — enterprise-grade agent identity (ID-JAG/EMA) and traffic inspection in one container."** Named enemy: the anonymous service account with a static API key. Named tailwind: every Okta/Microsoft XAA press release is your top-of-funnel — write the "how to actually use this with your MCP servers, free" companion to each one.

### 14.2 Launch sequence (2-week campaign, prepared during Phase 4)

1. **Soft launch:** 10–20 waitlist/Discord people get it a week early; fix the quickstart friction they hit; collect 2–3 quotable reactions.
2. **Show HN** ("Show HN: Open-source MCP gateway with ID-JAG identity and DLP — one container"). The post that works is the honest builder story: NHI problem → spec explanation → what it does/doesn't do. Founder answers every comment for 24h.
3. Same week: r/mcp + r/selfhosted + r/netsec (tailored per community — r/selfhosted cares about the container, r/netsec about the threat model), MCP community Discord, LinkedIn/X thread aimed at the identity crowd (tag the IdP-ecosystem folks — WorkOS/Stytch/Scalekit devrels amplify anything that grows the XAA ecosystem).
4. **Submit to the MCP registry and awesome-mcp lists** — durable discovery, disproportionate long-tail traffic.
5. Post the interop demo to the IETF OAuth WG mailing list as implementation feedback on draft-04. This is both spec citizenship and the highest-credibility marketing channel that exists for this product.

### 14.3 Content engine (post-launch, 2 posts/month, sustainable solo)

- **Spec-tracker posts** — every MCP-auth or ID-JAG draft change, explained within days. Becomes *the* subscription for people tracking this space; compounding SEO.
- **Attack-demo posts** — "watch an agent exfiltrate an AWS key through an MCP server, then watch the gateway redact it," with recorded demos. Security content with demos outperforms everything.
- **Comparison pages** — vs agentgateway, Kong, Aembit, MintMCP; fair and factual, updated quarterly.
- Conference CFPs (Identiverse, KubeCon, BSides, IdentityNext): "Non-human identity for MCP: implementing ID-JAG in the open." Recorded talks are permanent credibility assets.

### 14.4 Community mechanics

- Discord from day one; founder visibly present. GitHub Discussions for support (public SEO), issues for bugs only.
- 10–15 curated `good-first-issue`s at launch (scanner rules are perfect: small, self-contained, security-flavored).
- **Scanner rules as community surface:** a `rules/` directory with a contribution guide turns users into contributors — the Gitleaks/Sigma playbook.
- Monthly release cadence, every release with a changelog post. Rhythm signals aliveness; aliveness drives adoption.
- Opt-in, anonymous telemetry (gateway count, version, node count — never payloads), stated loudly in the README. You cannot raise on star counts alone; **weekly active gateways** is the metric that matters.

### 14.5 Impact measures (what "it's working" looks like)

- 90 days: 1.5–3k stars, 300+ Discord members, 50+ weekly-active gateways, 3 external contributors, 1 IdP-vendor co-marketing touch (a WorkOS/Stytch/Okta blog mention counts).
- 180 days: 100–150 weekly-active gateways, 5+ design partners (teams using it in production who will take a call), first "we'd pay for the managed version" inbound — *log every one of these; they are the fundraise deck.*

---

## 15. Funding Path: OSS Traction → Raise → Enterprise

### 15.1 The narrative you are building evidence for

"NHI is the fastest-growing identity problem (100:1 ratio, 70% of incidents AI-linked). The spec layer just standardized (EMA stable June 2026). Incumbents are consolidating (Cisco bought Astrix). We are the open-source default for the resource side — X hundred production gateways in Y months, solo-built — and the managed control plane is the business." Open-core with an operational-scale seam (§10) is a well-understood model (GitLab, Grafana, Teleport — Teleport is the closest structural comp: OSS access gateway → enterprise identity company).

### 15.2 What to show, by stage

- **Pre-seed ($500k–1.5M, angels + OSS-friendly pre-seed funds):** raisable at the 90-day marks above plus the narrative. Target funds with OSS/security theses and identity-adjacent angels (IdP-vendor alumni are ideal — they have both conviction and networks here).
- **Seed ($2–4M):** 150+ weekly-active gateways, 5–10 design partners, 2–3 paid pilots of an early managed tier ($500–2k/mo — price for signal, not revenue), a named design partner logo.
- **Alternative paths if VC is slow:** GitHub Sponsors + a hosted-gateway waitlist to test willingness-to-pay; accelerators with OSS tracks (YC takes solo technical founders with traction); or profitable-by-default via paid support contracts. Consolidation cuts both ways — a strong OSS position with real deployments is also an acquisition asset; don't optimize for it, but don't ignore inbound.

### 15.3 Solo-founder risk management

- The bus-factor question will come up in every pitch: answer it with the hash-chained audit of your own dev process — clean repo, tests, docs, signed releases. Operational maturity reads as de-risking.
- Do not incorporate the managed tier's IP ambiguously: OSS under a company you own from day one (Apache-2.0, CLA or DCO decided at launch), so the raise has a clean asset.
- Time-box the OSS-traction experiment: if 180-day metrics are badly missed, the honest moves are (a) narrow to the best-performing niche (e.g., "the identity gateway for Claude Code fleets"), or (b) join the winner — the skills and reputation compound either way.

---

## 16. Threat Model Highlights & Open Risks

- **Gateway compromise = keys to everything.** Mitigations: minimal attack surface (one binary, no shell-outs), signed releases, key material in OS keychain/KMS where available, mandatory TLS, admin UI bindable to localhost/tailnet only.
- **Upstream MCP server is malicious/compromised:** tool pinning, response scanning, per-node egress allowlists (v1.1).
- **Spec churn risk:** both the MCP auth spec (July 2026 draft in flight) and ID-JAG (draft-04) are moving. Isolate spec-facing code behind versioned adapters; track drafts as a first-class engineering activity, and treat it as marketing (blog every draft change).
- **Sanitization overclaim risk:** prompt injection is not a solved problem; position scanners as defense-in-depth reducing commodity risk, never as a guarantee. This honesty is itself differentiating in a market full of "AI firewall" vapor.
- **Latency budget:** target < 5 ms added p50 (token validation + policy + regex scan); entropy/ML scans async-flag rather than block where profile allows.

---

## 17. Sources

- [IETF draft-ietf-oauth-identity-assertion-authz-grant (ID-JAG, draft-04)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant)
- [Okta: AI agent token exchange guide](https://developer.okta.com/docs/guides/ai-agent-token-exchange/-/main/) · [Okta: Cross App Access with OIDC](https://developer.okta.com/blog/2025/09/03/cross-app-access) · [Okta: XAA resource application](https://developer.okta.com/blog/2026/02/17/xaa-resource-app)
- [WorkOS: XAA / ID-JAG explainer](https://workos.com/blog/id-jag-cross-app-access) · [Descope: ID-JAG Cross App Access](https://www.descope.com/learn/post/id-jag-cross-app-access)
- [Christian Posta: Okta SAML + Keycloak for ID-JAG](https://blog.christianposta.com/okta-saml-and-keycloak-for-id-jag-cross-app-access/)
- [Descope: MCP authorization spec](https://www.descope.com/blog/post/mcp-auth-spec) · [Evolution of MCP auth 2024→July 2026](https://medium.com/@ayshsandu/the-evolution-of-mcp-auth-every-spec-every-lesson-2024-11-05-2026-07-28-draft-e3f165a12fdb) · [MCP authorization spec 2026 changes](https://dasroot.net/posts/2026/04/mcp-authorization-specification-oauth-2-1-resource-indicators/)
- Competitive: [Obot: 13 MCP gateways compared](https://obot.ai/blog/the-13-best-mcp-gateways-for-enterprise-teams/) · [Lunar.dev: best OSS MCP gateways](https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026) · [Maxim: enterprise MCP gateways](https://www.getmaxim.ai/articles/top-5-enterprise-mcp-gateway-solutions-in-2026/)
- EMA/ID-JAG implementers: [agentgateway ID-JAG + EMA support (AAIF)](https://aaif.io/blog/agentgateway-now-supports-id-jag-and-mcp-enterprise-managed-auth) · [MCP Enterprise Authorization stable, June 2026](https://www.techtimes.com/articles/318708/20260619/mcp-enterprise-authorization-goes-stable-zero-touch-sso-okta-anthropic-vs-code.htm) · [TrueFoundry XAA gateway](https://www.truefoundry.com/blog/mcp-gateway-cross-app-access-identity-governed-agent-access) · [Kong enterprise MCP access control](https://konghq.com/blog/product-releases/enterprise-grade-mcp-access-control) · [Atlassian Rovo MCP + XAA/ID-JAG](https://www.atlassian.com/blog/development/enterprise-managed-authorization-rovo-mcp-xaa-id-jag)
- NHI market: [Aembit: identity vendors for AI agents](https://aembit.io/blog/10-identity-security-vendors-for-ai-agents-strengths-tradeoffs-and-how-they-fit/) · [NHI platform comparison incl. Cisco/Astrix](https://www.cremit.io/reports/rsac-2026-nhi) · [NHI for AI agents guide (100:1 ratio, Microsoft 2026 report)](https://aibuzz.blog/non-human-identity-for-ai-agents-explained/)
- Building blocks: [modelcontextprotocol/go-sdk (official Go SDK)](https://github.com/modelcontextprotocol/go-sdk) · [ory/fosite](https://github.com/ory/fosite) · [zitadel/oidc](https://github.com/zitadel/oidc) · [LLM Guard scanner reference](https://appsecsanta.com/llm-guard)
