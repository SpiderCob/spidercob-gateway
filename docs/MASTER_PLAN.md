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
- **Mode C — Managed.** A or B, plus policy pushed from a Spidercob SaaS control plane. **Do not build before funding** — zero OSS-traction value, explicit scope cut (§13.3).

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
- [ ] **Session mapping.** One client MCP session ↔ one upstream session, torn down cleanly. *DoD: killing a session server-side actually terminates the upstream connection; documented in design doc §6 as the thing naive proxies get wrong — don't skip it.*
- [ ] **stdio adapter.** Child-process supervisor exposing a local stdio MCP server as an HTTP node. *DoD: at least one real stdio server from the MCP servers registry runs behind the gateway end-to-end.*
- [ ] **Streaming-safe scanning groundwork.** Even if full windowed redaction waits for Phase 3, decide now how SSE chunks will be buffered/scanned so the interface doesn't need to change later.

### Phase 2 — Identity & tokens (the spec-correctness core)
1. `internal/identity`: local users, argon2id password hashing, session cookies for the (future) UI, agent API keys (hashed at rest).
2. `internal/authserver`: Ed25519 keypair + JWKS endpoint; `/token` endpoint supporting the **internal exchange** (Mode A bootstrap); per-node `aud` (RFC 8707); RFC 9728 protected-resource metadata per node; `jti` revocation (in-memory denylist).
   - *DoD (milestone from design doc §13.2):* unauthenticated JSON-RPC gets `401` with a correct `WWW-Authenticate` pointing at the RFC 9728 metadata URL; token-bearing requests route correctly; wrong-`aud` tokens are rejected.
3. Wire the **Keycloak interop harness** (already stubbed in `deploy/docker-compose.yml`) to accept *external* ID-JAGs via RFC 7523 — this is Mode B's core and the actual spec claim. Do this inside Phase 2, not after — per design doc §13.4, interop bugs found early are design fixes; found late they're rewrites.
4. Flip every row in `docs/spec/conformance.md` that Phase 2 covers, backed by a passing interop test — not by eyeballing the spec.

**Do not start Phase 3 until an unauthenticated request is actually rejected and a real ID-JAG round-trips through Keycloak.** That's the whole wedge; everything after this is polish on top of it.

### Phase 3 — Policy & scanning
7. `internal/policy` v0 — replace `AllowAll`: server-level → method-level → tool-level, backed by the store. **`tools/list` response filtering** (unauthorized tools become invisible, not just blocked — this is a specific prompt-injection defense, don't treat it as a nice-to-have).
8. `internal/pin` — snapshot `tools/list` on node registration, hash name+description+inputSchema, quarantine on drift (rug-pull defense).
9. `internal/scan` upgrades: schema enforcement against pinned `inputSchema` (do this first — cheapest, broadest win), Gitleaks-derived secret rule expansion, entropy scorer, PII with Luhn, homoglyph/zero-width normalization *before* pattern matching. Ship with honest defaults: block secrets outbound, flag-don't-block injection heuristics.

### Phase 4 — Admin UI & packaging → OSS launch
10. UI (React+Vite, `go:embed`): setup wizard, CSV user upload, node registration with tool-checkbox screen, policy matrix, audit viewer, kill-session button, per-client "copy config" snippet generator.
11. `deploy/`: distroless Dockerfile (<30MB), docker-compose, signed releases via goreleaser, `brew install`.
12. Docs as a launch feature: quickstart (must hit ≤15 min on a clean machine), spec-conformance page (public version of §2 above), threat-model page, fair comparison page vs agentgateway/Kong/Aembit.

**Launch gate — do not flip the repo to public until all of these are true** (design doc §13.2):
- [ ] Fresh-machine quickstart ≤ 15 minutes, timed for real
- [ ] Keycloak *and* Okta dev-org interop demos recorded
- [ ] README with a 60-second demo GIF
- [ ] `SECURITY.md` complete + a self-audit pass done
- [ ] **External security review of the four critical seams** (token validation, policy evaluation, session mapping, redaction ordering) — paid audit or trusted community reviewer. An auth product with a launch-week token bypass is dead on arrival.
- [ ] LICENSE (Apache-2.0, already in place) + CLA/DCO decision made
- [ ] Seed content written (§14 of design doc)

### Post-launch (do not pull forward)
- **v1.0:** `spidercob-admin` MCP server (§9.1 — manage the gateway by talking to Claude, dogfoods the policy engine), SSE compat, response-injection scanning v2, revocation webhooks, audit export.
- **v1.1:** Cedar policies (`cedar-go`), parameter-level constraints, DPoP sender-constraint, SCIM, Postgres/HA, Helm chart, ONNX scanner slot.
- **Managed tier:** only after funding. Zero OSS-traction value pre-raise — resist the temptation to build control-plane plumbing early.

---

## 4. Explicit Scope Cuts (resist re-adding these)

Straight from design doc §13.4 — repeated here because scope creep is the actual risk for a solo build, not lack of ideas:

- No HA, no Postgres before v1.1 — SQLite + store interface is enough.
- No SSO for the *admin UI* itself at launch.
- No Mode C (managed) before funding.
- No ML scanners at launch — regex + entropy is the honest v1, ONNX is a slot, not a promise.

---

## 5. How We Work This Plan

- **This doc is the status source of truth.** Update the checkboxes in §3 and the table in §2 as work lands — don't let them drift the way the README already has.
- **Spec-first for anything auth-related.** Point at `docs/spec/conformance.md` and the draft-04/EMA text before touching `authserver` or `identity`. LLMs confidently invent OAuth details; the checklist is the guardrail, not a formality.
- **Every interop bug becomes a permanent regression test** against the Keycloak harness before it's considered fixed.
- **Reserve deep human review for four seams:** token validation, policy evaluation, session mapping, redaction ordering. Everything else (CRUD, migrations, UI screens, table-driven tests, docs) is fair game for heavier Claude delegation.
- **The repo stays private until the launch gate in §3 is fully checked.** No security claims, no "try this in prod" language, until then.

---

## 6. Open Decisions (need a call before Phase 2 starts)

- **OAuth AS library:** `ory/fosite` vs `zitadel/oidc` v3 — design doc says prototype both in week 3 and pick whichever fights less. Not yet decided.
- **Final OSS name/trademark/domain check** — still using `spidercob-gateway`; design doc's Phase 0 called for a dedicated check before this locks in publicly.
- **CLA vs DCO** for external contributions — needs deciding before Phase 4 launch gate, not urgent now.
