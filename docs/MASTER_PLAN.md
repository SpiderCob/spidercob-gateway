# Spidercob Gateway — Master Plan

**Purpose of this doc:** the single place that says *what we're building, why, and what to do next*. `design.md` is the strategy/spec rationale (why ID-JAG, why this architecture, GTM, funding) — read that for the "why." This doc is the living execution tracker — read it first in every session, update it as ground truth changes. When the two disagree, this doc wins on *status*, `design.md` wins on *rationale*.

---

## 0. North Star

**One sentence:** The open-source MCP gateway for teams without an IAM department — spec-correct agent identity (ID-JAG / MCP Enterprise-Managed Authorization) and traffic inspection (DLP, injection defense), in one container, running in 15 minutes.

**The problem we're killing:** every internal MCP server today is either wide open or protected by a static API key nobody rotates. Non-human identities (agents, service accounts) outnumber humans ~100:1, and there's no open-source resource-side gateway that gives every MCP request a real, attributable identity (human `sub` + acting agent `act`) and inspects what flows through it.

**What winning looks like, by horizon:**

| Horizon | Looks like |
|---|---|
| **OSS launch** (end of Phase 4) | Anyone can `docker compose up`, protect a real MCP server, and see a secret get redacted — in under 15 minutes, no IdP required. |
| **90 days post-launch** | 1.5–3k stars, 50+ weekly-active gateways, 3 external contributors, one IdP-vendor co-marketing touch. |
| **180 days** | 100–150 weekly-active gateways, 5+ design partners running it in production, first inbound "we'd pay for managed." |
| **Funded** | Managed control plane exists; OSS core stays fully-featured (the seam is operational scale, never withheld security). |

**Non-negotiables that protect the north star** (violating these forfeits the whole bet — see `design.md` §2, §12):
- The gateway must be **spec-correct** ID-JAG/EMA — not a custom JWT with an `allowed_mcps` claim. That was the v0.1 mistake; redoing it kills the differentiation.
- **Never a multi-audience token.** One access token = one MCP server, always (RFC 8707). This is the confused-deputy protection the whole design hinges on.
- **Fail static, never fail open** — if policy sync or the tunnel drops, keep enforcing last-known policy.
- **Identity + content inspection in one box** is the unclaimed wedge (§12). Don't let either half atrophy relative to the other.
- **The data plane never leaves customer infrastructure — in every tier, no exception.** The container that actually enforces policy and touches live MCP traffic always runs on customer-owned infrastructure. Spidercob never operates or routes a customer's production MCP traffic itself — no one will trust a third party with that, and it's not a cost/liability worth carrying either. Anything Spidercob operates (a future SaaS control plane) is limited to policy authoring and config sync; it is never inline on the request path. See §6 decision log, 2026-08-03.

---

## 1. What We're Building, End to End

One Go binary, one container, three logical planes:

```
Agent / MCP client
     │ (1) gets identity: local login (Mode A) or enterprise IdP token exchange (Mode B)
     ▼
┌─────────────────────────── SPIDERCOB GATEWAY ───────────────────────────┐
│  Identity Engine          Control Plane            Data Plane           │
│  embedded IdP OR          Admin UI + REST API       (the hot path)      │
│  ID-JAG consumer,         users/groups/nodes/        authN → policy →   │
│  OAuth 2.1 AS,            policies/audit             sanitize → route → │
│  JWKS, per-node                                       DLP-scan → audit  │
│  access tokens                                                          │
└───────────────────────────────────────────────────────────────────────┘
     │ (2) exchanges identity for a short-lived, single-audience token
     ▼
(3) JSON-RPC over the token  ──▶  gateway validates + enforces policy  ──▶  internal MCP servers
                                                                              (Jira, Postgres-RO, ...)
```

**The three identity modes** (design doc §2.3 — build Mode A first, it's a strict subset of B):

- **Mode A — Standalone.** Gateway is its own IdP: local users, CSV upload, argon2id passwords. No customer IdP required. This is the on-ramp for the target buyer (50–100-person startup, no IAM team).
- **Mode B — Federated (the actual ID-JAG spec flow).** Customer's IdP (Okta/Entra/Keycloak) issues ID-JAGs via RFC 8693 token exchange; the gateway's AS validates and exchanges them for per-node access tokens via RFC 7523. This is what makes the "spec-correct" claim real.
- **Mode C — Managed.** A or B, plus policy pushed from a Spidercob SaaS control plane. **Do not build before funding** — zero OSS-traction value, explicit scope cut (§13.3). **Data-plane note:** even in Mode C, the enforcing gateway container runs on the customer's own infrastructure. The SaaS control plane authors policy and pushes signed bundles down an outbound tunnel — it never sits inline on live traffic. There is no tier where Spidercob operates the actual proxy on a customer's behalf.

**Mode C enrollment and registration mechanism (post-funding, but recorded now before it's lost — 2026-08-06):** the SaaS control plane can never reach a customer's MCP servers directly (data-plane-customer-only, §0), so registration is a two-step, control-plane-mediated flow, not a direct probe:
1. Admin generates a short-TTL, **single-use enrollment token** in the control plane UI (hashed at rest, tenant-scoped). The container is **one generic image for every tenant** — never a custom-baked-per-tenant image — deployed with that token as an env var. Baking policy into a unique per-customer image was the original instinct, but it can't work anyway: tool discovery (below) requires a *live, already-connected* gateway to do the probing, so there's nothing to bake in before first boot.
2. On first boot, the container generates its own Ed25519 keypair **locally — the private key never leaves the customer's machine** — and calls the control plane's `/enroll` endpoint with the token and its public key. The control plane validates and burns the token (single-use, can't be replayed), records the public key against a new `gateway_instances` row, and returns a control-plane-signed instance identity plus the tenant's current policy bundle as the first sync. Every connection after that authenticates with the gateway's own keypair, never the original token again. (Same pattern as Kubernetes `kubeadm join` tokens or Tailscale auth keys — bootstrap credential vs. long-lived identity, kept separate.)
3. **Tool discovery is gated on step 2 having already happened.** Admin can register MCP node *metadata* (name, URL — no probe needed) as a pending record before any container is deployed, but the actual `tools/list` probe can only run *after* a gateway is enrolled and connected: control plane sends a `ProbeNodeRequest` down the tunnel, the connected gateway does the live probe locally (it can reach the customer's own network), and reports back **metadata only** (tool names, descriptions, schema hashes — never payloads) for the admin to assign per-group access to in the SaaS UI.

**Non-human identities (NHI) are first-class principals, not an afterthought.** Every group can contain both human users and agents (`user_groups` and `agent_groups`, §8) — an NHI (a scheduled job, a standing automation) gets its *own* minimal group assignment, never inherited from whichever human registered it, so least-privilege actually holds for automated access. NHI authentication is decoupled from whichever mode a tenant's humans use — an org fully on Okta SSO still needs a local, IdP-agnostic way to onboard a CI job. Two credentialing tiers by NHI shape (see §6, 2026-08-04): a static, hashed client secret for ephemeral/stateless NHIs that can't hold a key between runs (v1); a locally-generated keypair enrolled the same way the gateway container itself enrolls, for long-running NHIs that can (v1.1, "secretless"). This is the other half of the NHI market thesis (design doc §12) — the sprawl problem is as much "who remembers this credential exists six months later" as it is "can this agent get in," so last-used tracking and stale-credential flagging in the admin UI matter as much as the access-control mechanics.

**The request lifecycle every JSON-RPC call goes through** (design doc §6):
1. TLS terminate, parse JSON-RPC, reject malformed/oversized early.
2. Validate bearer token — signature, `exp`, `aud` matches this node, `jti` not revoked.
3. Policy check — server → method → tool → (v1.1) parameter level.
4. Inbound sanitization — schema enforcement against the pinned `inputSchema`, injection heuristics, size/recursion caps.
5. Forward upstream with a gateway-held credential (the agent's token never reaches the MCP server).
6. Outbound DLP scan on the response — secrets, PII, response-embedded injection; redact structurally, never drop silently.
7. Hash-chained audit record: `sub`, `act`, node, method, tool, decision, scanner verdicts, latency.

**The two "moats" we're claiming** (§12.3): nobody doing spec-correct identity also inspects content, and nobody inspecting content also does spec-correct identity. Both halves have to ship, or the positioning collapses into "yet another gateway."

---

## 2. Current Reality Check (as of this session)

Read this before assuming anything is done. The README's "Phase 1 in progress" undersells what exists and oversells what doesn't — this table is the accurate version.

| Component | State | Detail |
|---|---|---|
| `internal/proxy` | **Partially built** | Node routing, buffered request/response scanning, JSON-RPC method extraction, Prometheus metrics, `/healthz` `/readyz` stubs. Streaming (SSE) responses pass through **unscanned**. No session-mapping (one client session ↔ one upstream session) yet — proxy is stateless passthrough today. |
| `internal/scan` | **Seed only** | 2 scanners: secret regex (AWS/GCP/private-key/JWT/Slack patterns) and injection heuristics (4 hardcoded phrase patterns). No schema enforcement, no entropy scoring, no PII/Luhn, no homoglyph/zero-width normalization. 3 unit tests. |
| `internal/policy` | **Stub** | `AllowAll{}` — literally no enforcement. Explicitly commented "do NOT ship a release with this as the default." |
| `internal/store` | **Empty interface** | `Ping() error` only. No SQLite impl, no migrations, no tables. |
| `internal/identity`, `internal/authserver`, `internal/pin`, `internal/audit`, `internal/adminapi` | **Do not exist yet** | No directories. This is all of Phase 2–4. |
| `internal/proxy/stdioadapter` | **Does not exist** | README claims "in progress" — it isn't started. |
| `ui/` | **Does not exist** | No admin UI at all. |
| `docs/spec/conformance.md` | **Checklist written, 0 items checked** | Good — this is the guardrail the design doc asks for (§13.4). Use it literally: nothing in Phase 2 is done until its row flips. |
| Tests | **3 tests, `scan` package only** | No integration tests, no interop harness wired (Keycloak container exists in `docker-compose.yml` but nothing talks to it yet). |
| CI | **Wired, minimal** | `gofmt`/`vet`/`build`/`test` on push/PR. No security scanning, no release automation yet. |

**Bottom line:** we have a routing + DLP-demo skeleton (~700 lines). Identity, policy enforcement, persistence, and the admin UI — i.e. everything that makes this a *product* rather than a proxy demo — is unbuilt. That's expected for where we are (end of Phase 1, start of Phase 2 per the 12-week plan in `design.md` §13.2), but it means **no security claims should be made about this repo publicly yet** — it doesn't authenticate anyone.

---

## 3. Step-by-Step Plan From Here

Each step has a **Definition of Done (DoD)** — don't mark it done, or let Claude mark it done, without meeting it. Steps are dependency-ordered; don't skip ahead to policy before tokens exist, or scanning improvements before schema enforcement (schema enforcement kills a whole injection class for free — do it before hand-rolling more regex).

### Phase 1 — finish the skeleton (close out what's open)
- [ ] **Session mapping.** The gateway mints its own client-facing session ID at `initialize` — never passes through the upstream's raw session ID — and maintains a local mapping `gateway_session_id → (node, upstream_session_id_or_process_handle)`. The `initialize` response sets both the `Mcp-Session-Id` header (spec-required) and a mirrored session cookie with the same value, so native cookie-based cloud-LB stickiness works out of the box for v1.1 HA without customers hand-configuring header hashing (§6, 2026-08-04). On revocation/`DELETE`, the gateway tears down the corresponding upstream session/process and removes the mapping; further requests bearing that session ID are rejected immediately, not silently re-created. *DoD: killing a session server-side actually terminates the upstream connection or child process.*
- [ ] **Idle session timeout.** Sessions with no activity for a configurable duration are automatically torn down the same way as explicit revocation — mapping removed, upstream session/process reaped. Prevents orphaned upstream sessions and orphaned stdio child processes from accumulating indefinitely. *DoD: an idle session past its timeout is fully gone (mapping + upstream resource) without any client action.*
- [ ] **stdio adapter**, with defensive process supervision as a first-class part of the spec, not an afterthought: restart on crash with exponential backoff (the standard pattern — systemd `Restart=on-failure`+`RestartSec`, Kubernetes `CrashLoopBackOff`, supervisord `autorestart`+`startretries`); after N rapid crashes within a window, stop auto-restarting and quarantine the node (mark unhealthy, alert admin) instead of looping forever; any in-flight session tied to a crashed process fails cleanly back to the client (forcing re-`initialize`) rather than hanging. Per the MCP spec, stdio servers must write only protocol JSON-RPC to stdout and everything else to stderr — treat a non-parseable stdout line as a logged protocol-violation warning (not fatal for one bad line), but count repeated violations toward the same quarantine threshold as crashes. *DoD: at least one real stdio server runs behind the gateway end-to-end; a simulated crash auto-restarts with backoff; a simulated crash-loop gets quarantined rather than looping forever.*
- [ ] **Streaming-safe scanning groundwork.** Even if full windowed redaction waits for Phase 3, decide now how SSE chunks will be buffered/scanned so the interface doesn't need to change later.

**stdio nodes are explicitly out of scope for multi-replica HA (§6, 2026-08-04).** A stdio node is pinned to whichever single gateway instance spawned it — v1.1 HA (policy replicated to N independent replicas) is scoped to HTTP-transport (streamable_http/SSE) nodes only. Don't build inter-replica stdio ownership/failover — that would require exactly the risky node-to-node coordination the control-plane-only distribution model is designed to avoid. A customer wanting HA for a stdio-backed server should front it with its own networked HTTP wrapper instead.

### Phase 2 — Identity & tokens (the spec-correctness core)
1. `internal/identity`: local users, argon2id password hashing, session cookies for the (future) UI, agent (NHI) API keys — hashed at rest, `client_credentials` grant, own group membership via `agent_groups` rather than inherited from an owner (§6, 2026-08-04). JIT provisioning for Mode B: first successful token exchange auto-creates a local user record keyed on `(iss, sub)`, default-deny (no group) until an admin assigns one.
2. `internal/authserver`: Ed25519 keypair(s) + JWKS endpoint supporting **multiple concurrent signing keys** (old key stays published until every token it signed has expired — build this in from day one; retrofitting later is painful). `/token` endpoint supporting the **internal exchange** (Mode A bootstrap) and NHI `client_credentials`; per-node `aud` (RFC 8707); RFC 9728 protected-resource metadata per node, including `authorization_grant_profiles_supported` advertising ID-JAG support (confirmed live in Claude Code as of June 2026); `jti` revocation (in-memory denylist, single-process only — a shared/Redis-backed version is a v1.1 HA item, §7). Default access-token TTL: **120 seconds for NHI tokens, 10 minutes for human tokens**, both admin-configurable (§6, 2026-08-04). **No separate refresh-token grant type** — on expiry, each mode simply re-runs its own original exchange: NHI re-calls `/token` with the same `client_credentials`; Mode A humans silently re-mint via their still-valid local UI session; Mode B humans silently redo the RFC 8693+7523 exchange again (invisible to the user under EMA's zero-touch model, and this naturally keeps the IdP in the loop on every reissuance — directly addresses deprovisioning staleness, §7). Client implementations must handle 401-triggers-reauth-and-retry for any operation spanning more than one TTL window — document this for NHI integrators given the 120s default.
   - *DoD (milestone from design doc §13.2):* unauthenticated JSON-RPC gets `401` with a correct `WWW-Authenticate` pointing at the RFC 9728 metadata URL; token-bearing requests route correctly; wrong-`aud` tokens are rejected.
3. Wire the **Keycloak interop harness** (already stubbed in `deploy/docker-compose.yml`) to accept *external* ID-JAGs via RFC 7523 — this is Mode B's core and the actual spec claim. Do this inside Phase 2, not after — per design doc §13.4, interop bugs found early are design fixes; found late they're rewrites. **Set up a free Okta Developer account (Integrator Free Plan) as a second interop target during Phase 2, not deferred to the launch gate** — confirmed free and sufficient for Cross App Access setup; the no-signup XAA playground at xaa.dev is worth prototyping against first. Keycloak alone doesn't exercise Claude Code's actual client-side EMA behavior, which is proven against Okta specifically — catching integration bugs here rather than at the Phase 4 launch gate is what "interop bugs found early are design fixes" actually requires.
4. Flip every row in `docs/spec/conformance.md` that Phase 2 covers, backed by a passing interop test — not by eyeballing the spec. Includes the NHI/`client_credentials` rows added alongside the existing ID-JAG/MCP-auth rows (see `docs/spec/conformance.md`).

**The policy stub during Phase 2 is `DenyAll{}`, never `AllowAll{}` (§6, 2026-08-04).** The moment real tokens exist, the safe default is nothing works until policy is authored — not everything works until someone locks it down. Phase 3 replaces `DenyAll` with the real group/method/tool evaluator; it never replaces a permissive default. This also reaffirms the existing "request-time check wins" rule (§5/design doc §5): policy takes effect the instant it's configured and deployed, with no waiting for token expiry.

**Do not start Phase 3 until an unauthenticated request is actually rejected and a real ID-JAG round-trips through Keycloak.** That's the whole wedge; everything after this is polish on top of it.

### Phase 3 — Policy & scanning
7. `internal/policy` v0 — replace `DenyAll`: server-level → method-level → tool-level, backed by the store, with explicit **ALLOW and DENY rule types** (not allow-only), evaluated as deny-overrides-allow-overrides-default-deny (§6, 2026-08-04). **`tools/list` response filtering** (unauthorized tools become invisible, not just blocked — this is a specific prompt-injection defense, don't treat it as a nice-to-have). **Rate limiting/quota per group or per NHI** (precedented by spider-snoop's own credit-based throttling) — defense-in-depth against an authorized-but-compromised agent, enforced **per-replica** under multi-replica HA (a direct, accepted consequence of the no-shared-store-by-default HA design, §6/§7 — approximate enforcement is fine for v1 since it's defense-in-depth, not the primary access-control mechanism; exact global enforcement rides the same optional shared-store upgrade path as `jti`/session consistency if a customer needs it later). **Scan-verdict-conditional actions**: let a policy rule reference a scanner verdict (e.g., block rather than just log an injection-flagged call, for specific tools/groups) — closes the current gap where `scan` and `policy` are disconnected pipeline stages.
8. `internal/pin` — snapshot `tools/list` on node registration, hash name+description+inputSchema, quarantine on drift (rug-pull defense). **Drift detection is a periodic background refresh, not continuous per-request diffing** — keeps the hot path fast (latency budget, design doc §16); refresh interval is admin-configurable per node.
9. `internal/scan` upgrades: schema enforcement against pinned `inputSchema` (do this first — cheapest, broadest win), Gitleaks-derived secret rule expansion, entropy scorer, PII with Luhn, homoglyph/zero-width normalization *before* pattern matching. Ship with honest defaults: block secrets outbound, flag-don't-block injection heuristics.

**`tools/list` filtering and pagination:** treat the upstream's pagination cursor as fully opaque and pass it through unchanged — never recompute pagination ourselves. Filter the `tools` array in place per page; a filtered page coming back thinner than the upstream's original, or even empty, is spec-legal (MCP clients aren't supposed to assume fixed page sizes) and fine for v1. Auto-advancing through fully-empty filtered pages on the client's behalf is a later UX polish, not a v1 correctness requirement.

**Phase 3 DoD:** a request for a tool outside the caller's group policy is rejected (403) and that tool does not appear in that caller's `tools/list` response. A request for an authorized tool succeeds end-to-end. A simulated upstream schema change on an already-approved tool gets quarantined within one refresh interval and blocked until re-approved. A secret embedded in a tool response is redacted before reaching the client, with a corresponding audit record. An injection-flagged request is flagged, not blocked, per the honest default — and logged with a scanner verdict. All of the above are automated tests against the interop harness, not manual verification.

### Phase 4 — Admin UI & packaging → OSS launch
10. UI (React+Vite, `go:embed`): setup wizard, CSV user upload, node registration with tool-checkbox screen, policy matrix, audit viewer, kill-session button, per-client "copy config" snippet generator.
11. `deploy/`: distroless Dockerfile (<30MB), docker-compose, signed releases via goreleaser, `brew install`.
12. Docs as a launch feature: quickstart (must hit ≤15 min on a clean machine), spec-conformance page (public version of §2 above), threat-model page, fair comparison page vs agentgateway/Kong/Aembit.

**Launch gate — do not flip the repo to public until all of these are true** (design doc §13.2):
- [ ] Fresh-machine quickstart ≤ 15 minutes, timed for real
- [ ] Keycloak *and* Okta dev-org interop demos recorded
- [ ] README with a 60-second demo GIF
- [ ] `SECURITY.md` complete + a self-audit pass done
- [ ] **External security review of the five critical seams** (token validation, NHI credential issuance/`client_credentials`, policy evaluation, session mapping, redaction ordering) — paid audit or trusted community reviewer. An auth product with a launch-week token bypass is dead on arrival.
- [ ] LICENSE (Apache-2.0, already in place) + CLA/DCO decision made
- [ ] Seed content written (§14 of design doc)

### Post-launch (do not pull forward)
- **v1.0:** `spidercob-admin` MCP server (§9.1 — manage the gateway by talking to Claude, dogfoods the policy engine), SSE compat, response-injection scanning v2, revocation webhooks, audit export with continuous streaming to customer SIEM / control-plane metadata aggregation — this is the actual durability story for audit history under HA, not local SQLite (§6, 2026-08-04).
- **v1.1:** Cedar policies (`cedar-go`), parameter-level constraints, DPoP sender-constraint, SCIM, Postgres/HA + sticky LB routing as the default session/revocation-consistency mechanism (a mirrored session cookie alongside `Mcp-Session-Id` so native cloud-LB cookie stickiness works out of the box, plus per-provider HA deploy docs — AWS ALB app-cookie config, GCP LB cookie affinity, nginx/HAProxy header-hash alternative; shared Redis/Postgres remains a later upgrade path, §6), Helm chart, ONNX scanner slot, NHI keypair/"secretless" enrollment (tier 2, §6), new policy conditions (time-of-day windows, a `REQUIRE_APPROVAL` action for high-risk tools, device-trust — parallels spider-snoop's own policy engine).
- **Managed tier:** only after funding. Zero OSS-traction value pre-raise — resist the temptation to build control-plane plumbing early.

---

## 4. Explicit Scope Cuts (resist re-adding these)

Straight from design doc §13.4 — repeated here because scope creep is the actual risk for a solo build, not lack of ideas:

- No HA, no Postgres before v1.1 — SQLite + store interface is enough.
- No SSO for the *admin UI* itself at launch.
- No Mode C (managed) before funding.
- No ML scanners at launch — regex + entropy is the honest v1, ONNX is a slot, not a promise.
- **No forward-proxy / general egress-DLP mode.** The gateway is a reverse proxy in front of *registered* MCP nodes only — never a general "route all your traffic through us" egress proxy (that's a different, much bigger, more infrastructure-heavy product with different competitors — CASB/SWG vendors, not MCP gateways). Technically feasible later (TLS interception + protocol sniffing to classify MCP vs. non-MCP traffic), deliberately deferred — don't let it creep into Phase 3/4 scope. Decision, 2026-08-03.

---

## 5. How We Work This Plan

- **This doc is the status source of truth.** Update the checkboxes in §3 and the table in §2 as work lands — don't let them drift the way the README already has.
- **Spec-first for anything auth-related.** Point at `docs/spec/conformance.md` and the draft-04/EMA text before touching `authserver` or `identity`. LLMs confidently invent OAuth details; the checklist is the guardrail, not a formality.
- **Every interop bug becomes a permanent regression test** against the Keycloak harness before it's considered fixed.
- **Reserve deep human review for five seams:** token validation, NHI credential issuance (`client_credentials`), policy evaluation, session mapping, redaction ordering. Everything else (CRUD, migrations, UI screens, table-driven tests, docs) is fair game for heavier Claude delegation.
- **The repo stays private until the launch gate in §3 is fully checked.** No security claims, no "try this in prod" language, until then.

---

## 6. Decisions Log (resolved — don't relitigate without a real reason)

- **2026-08-03 — Reverse proxy only, no forward-proxy/egress-DLP mode.** The gateway enforces policy in front of *registered* MCP nodes; it does not become a general "route all your traffic through us" proxy. See §4.
- **2026-08-03 — Default-deny confirmed as the policy model** (already `design.md` §5; explicitly re-confirmed here with rationale). Reasons: (1) you can't enumerate the danger space in advance — default-allow means every newly-added tool is reachable by everyone until someone remembers to block it; (2) it's the only model consistent with tool pinning, which is already default-deny in spirit (quarantine on schema drift until re-approved); (3) it's what makes `tools/list` filtering meaningful — hiding unauthorized tools only matters if "unauthorized" is the default, not the exception; (4) it's what enterprise security review expects as table stakes. **Bootstrap exception:** the first admin account gets implicit access to the *management* API (nodes/policy/users) at setup — default-deny governs MCP *resource* access for every group thereafter, not the admin's own provisioning step.
- **2026-08-03 — Data plane is customer-infrastructure-only, in every tier, no exception.** See the 5th non-negotiable in §0. Reasons stated directly by the founder: trust (no customer will let a third party route their live internal MCP traffic) and cost (Spidercob shouldn't carry the liability/uptime burden of being inline on every customer's production path). This resolves how Mode C registration works: the SaaS control plane (post-funding) only authors policy and pushes signed bundles down a tunnel to a customer-owned container — it is never itself in the request path.
- **2026-08-04 — Policy conflict resolution: deny-overrides-allow, additive-allow across group memberships, default-deny as the base case.** Same evaluation order as AWS IAM: collect every matching rule across all of a principal's groups for a given node/method/tool → any explicit DENY wins → else any explicit ALLOW wins → else (nothing matches) → default-deny. Requires the policy schema to support explicit DENY rules, not allow-only — needed to express carve-outs ("all Jira tools except `delete_ticket`") without enumerating every other tool individually.
- **2026-08-04 — NHI credentialing: two tiers, decoupled from human Mode A/B.** See §1. Tier 1 (v1): static hashed client secret + `client_credentials` grant, for ephemeral/stateless NHIs (CI jobs, serverless — nowhere durable to hold a private key between runs). Tier 2 (v1.1): locally-generated keypair enrolled via the same burnable-token mechanism as gateway container enrollment, for long-running NHIs — no long-lived shared secret ever transmitted. `agent_groups` (already in the §8 data model) gives NHIs their own group membership, independent of the human who registered them — inheriting the owner's access would violate least-privilege for exactly the identities that need it most.
- **2026-08-04 — Continuous auth = short-TTL + fresh re-evaluation on reissuance, no separate polling loop.** Group membership and policy are already re-resolved from the local store on every token reissuance and re-checked per request (§5's "request-time check wins" already implied this) — short access-token TTLs are sufficient; no need for a live "is this token still good" side-channel.
- **2026-08-04 — Force-sync from the control plane is the break-glass mechanism, for Mode C only.** If a customer's local policy store is corrupted, wiping and re-pulling the last-known-good signed bundle from the control plane recovers it — but only for tenants actually connected to one. A disconnected, pure self-hosted deployment (Mode A/B, no control plane) has no such recovery path yet — see §7.
- **2026-08-04 — HA/multi-replica mechanism: independent local SQLite per replica, kept in sync by replaying the same signed policy bundle to each — not a shared database.** SQLite is single-writer; replicas can't safely share one file. Since policy config is small, admin-authored, and already control-plane-durable in Mode C, replicating it to N independently-functional replicas (the same mechanism as container enrollment/first-sync) sidesteps needing Postgres for redundancy in that topology. Consequence: losing a replica doesn't lose *policy* (it's just a mirror, trivially regenerated) — but it does lose that replica's local *audit log* unless audit records are already being streamed continuously to the customer's SIEM or the control plane's metadata aggregation. For HA deployments, local SQLite audit storage should be treated as a short-term buffer, not the system of record.
- **2026-08-04 — Round robin is safe for token *validation*, not safe (alone) for `jti` revocation consistency or MCP session continuity.** Access-token validation is stateless (signed JWT + replicated signing keys) — any replica can verify any token, no affinity needed. But `jti` revocation is currently an in-memory-per-process denylist (design doc §4) — a token revoked on replica A is still valid on replica B unless the denylist is shared. Separately, MCP's own stateful session (the `initialize` handshake + ongoing session mapping, §6) lives in whichever replica's memory established it — a fresh token doesn't fix a request landing on a replica that's never heard of that session. See §7 for the fix options.
- **2026-08-04 — HA/routing infrastructure is entirely the customer's responsibility**, consistent with the data-plane-customer-only non-negotiable. Spidercob provides the mechanism (health endpoints, enrollment, policy replication) — the customer provisions and operates the load balancer, replica count, and routing.
- **2026-08-04 — No separate refresh-token grant; short TTL + re-exchange on expiry is the whole mechanism.** NHI (120s default TTL) re-calls `/token` with the same `client_credentials`; Mode A humans silently re-mint via their local UI session; Mode B humans silently redo the RFC 8693+7523 exchange (invisible under EMA's zero-touch model). This is simpler than a dedicated `offline_access` refresh token *and* naturally keeps the IdP in the loop on every reissuance, directly bounding deprovisioning staleness. Default TTLs: 120s NHI, 10min human, both admin-configurable. `design.md` §4's `offline_access` refresh-token line is superseded by this.
- **2026-08-04 — Policy stub is `DenyAll`, never `AllowAll`, from the moment real tokens exist.** Closes the Phase 2→3 interim-state hazard where a JIT-provisioned, zero-group user would otherwise get full access via a permissive stub. Phase 3 replaces `DenyAll` with the real evaluator; it never replaces a permissive default.
- **2026-08-04 — Okta interop moves into Phase 2, not the Phase 4 launch gate.** A free Okta Developer account (Integrator Free Plan) supports Cross App Access setup — confirmed, no cost blocker. Keycloak alone doesn't exercise Claude Code's actual client-side EMA behavior, which is proven against Okta specifically; catching integration bugs during Phase 2 matches the stated "interop bugs found early are design fixes" principle better than deferring to launch.
- **2026-08-04 — stdio nodes are out of scope for multi-replica HA.** Pinned to whichever single instance spawned them; v1.1 HA covers HTTP-transport nodes only. Building inter-replica stdio ownership/failover would require the same risky node-to-node coordination the control-plane-only distribution model exists to avoid — not worth it. A customer wanting HA for a stdio-backed server should wrap it as a networked HTTP server instead.
- **2026-08-04 — stdio process supervision: restart with exponential backoff, quarantine after repeated crash-looping, fail in-flight sessions cleanly.** Standard pattern (systemd/Kubernetes/supervisord), not invented here. Non-JSON-RPC stdout output is a spec violation by the upstream (MCP requires protocol-only stdout, everything else to stderr) — log as a warning, don't crash the gateway over one bad line, but count repeated violations toward the same quarantine threshold as crashes.
- **2026-08-04 — Rate-limit/quota enforcement is per-replica under HA, accepted as a v1 limitation.** Falls directly out of the no-shared-store-by-default HA decision, not a separate choice. Fine because it's defense-in-depth, not the primary access-control mechanism (policy allow/deny stays exact regardless of replica); exact global enforcement is available later via the same optional shared-store upgrade path as `jti`/session consistency.
- **2026-08-04 — Tool-pin drift detection is a periodic background refresh (admin-configurable interval), not per-request diffing.** Keeps the hot path fast; bounded, known-window drift detection is an acceptable and simpler tradeoff than continuous checking.
- **2026-08-04 — `tools/list` pagination: cursor stays fully opaque, filtered pages (even empty ones) are spec-legal.** No pagination math to reimplement — just filter the `tools` array per page and pass the upstream's cursor through unchanged. Auto-advancing through empty filtered pages is optional future UX polish, not a v1 requirement.
- **2026-08-04 — External security review scope is five seams, not four: added NHI credential issuance (`client_credentials`) alongside token validation, policy evaluation, session mapping, redaction ordering.** The underlying token-signing code is shared with ID-JAG handling, but `client_credentials` authentication logic (e.g., timing-safe secret comparison) is distinct and shouldn't be assumed covered by testing the ID-JAG path alone.
- **2026-08-04 — Sticky LB routing is the default v1.1 HA mechanism, not shared Redis.** Every major cloud LB (AWS ALB, GCP HTTP(S) LB, Azure Application Gateway) and common self-hosted options (nginx, HAProxy, k8s ingress) support session affinity, so this doesn't require customers to adopt new infrastructure. One nuance: MCP's session ID travels as the `Mcp-Session-Id` HTTP header, but most cloud-native LBs' built-in stickiness keys on cookies, not arbitrary headers — so the gateway will also set a mirrored session cookie (same value as the header) on `initialize` responses, purely so native cookie-based LB stickiness works out of the box without customers hand-configuring header hashing. A shared store (Redis, or Postgres if a customer's already running it for HA) remains an available upgrade path later for true any-replica-handles-any-request semantics — not required for the v1.1 default.

- **2026-08-06 — design.md synced to current decisions; treat mismatches as bugs, not alternate truth.** A review pass found design.md's original text still stated the pre-decision TTL range, the `offline_access` refresh design, "four" seams, and an allow-only `policies` schema with no rate-limit column — all superseded since. design.md now carries inline "Updated 2026-08-06" notes at each spot rather than being silently rewritten, so the history of *why* it changed stays visible. The Mode C enrollment/registration mechanism (burnable token → locally-generated keypair → tool-discovery-gated-on-connection) was designed in conversation earlier but had never been written into either doc until this pass — see §1.
- **2026-08-06 — Three engineering risks surfaced by the same review, moved to §7 rather than left implicit:** SQLite write-concurrency configuration, the unverified <5ms latency budget, and Okta's lack of an obvious CI story. None are blockers, all need a conscious decision before the phase that depends on them, not an optimistic default.

## 7. Open Decisions (need a call before Phase 2 starts)

- **OAuth AS library:** `ory/fosite` vs `zitadel/oidc` v3 — design doc says prototype both in week 3 and pick whichever fights less. Not yet decided.
- **Final OSS name/trademark/domain check** — still using `spidercob-gateway`; design doc's Phase 0 called for a dedicated check before this locks in publicly.
- **CLA vs DCO** for external contributions — needs deciding before Phase 4 launch gate, not urgent now.
- **Disconnected self-hosted HA/backup story (no control plane at all):** Mode C's replica-recovery-via-policy-replication doesn't apply here — a pure Mode A/B deployment with no control-plane connection needs its own answer (documented SQLite backup, or an export/import CLI) before v1.1 HA claims apply to that topology too. Not designed yet.
- **NHI credentialing build order:** tier 1 (static secret) is proposed to land in Phase 2 alongside human identity; tier 2 (keypair enrollment) is proposed for v1.1. Reasonable default, not yet stress-tested against real NHI use cases.
- **Container lifecycle management vs. policy sync, as separate control-channel concerns.** "Which image version is running / health / restarts" (fleet lifecycle) is a different message type than "here's the current signed policy bundle" (config sync) — keep them as distinct channels/messages on the future control-plane tunnel so a bad policy push and a bad version rollout don't share a rollback path. Not designed yet, relevant to the post-funding Managed tier.
- **SQLite write-concurrency configuration under Go isn't decided.** `modernc.org/sqlite` + WAL mode allows concurrent readers with one writer, but Go's `database/sql` pooling needs deliberate configuration (serializing writes through one connection, setting `busy_timeout`) or `database is locked` errors show up under real concurrent load — a common footgun, not automatic. Needs to be a conscious `internal/store` design decision in Phase 2, not left to whatever the driver defaults to.
- **The <5ms p50 added-latency budget (design doc §16) is plausible but unverified.** Ed25519 verification and in-memory map lookups are fast enough in isolation, but nothing's been load-tested against realistic payloads — a large `tools/list` response being filtered, or a big tool-call argument being schema-validated and scanned, could plausibly exceed it. Load-test this early in Phase 3 rather than carrying it to launch as an unverified assumption.
- **Okta interop has no CI story yet.** Keycloak runs in a container and is naturally CI-able (already stubbed in `docker-compose.yml`). Okta is a hosted SaaS dev org with no equivalent "spin up fresh per CI run" option — meaning either a persistent dev-org's credentials live as CI secrets (a real secret-hygiene question for this repo's own CI) or Okta interop checks stay manual/pre-release rather than continuous. Undecided; needs settling now that Okta interop moved into Phase 2 (§6, 2026-08-04).
- **The original ~12-week timeline (design doc §13.2) is stale, not confirmed.** Real scope has been added since the original estimate (see the 2026-08-06 note in design.md §13.2) without the timeline being explicitly revisited. Not urgent to fix today, but shouldn't be quoted anywhere (docs, GTM planning) as still holding without a deliberate re-estimate.
