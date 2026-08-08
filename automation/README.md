# Automation

Scripts that make the CLAUDE.md development workflow ("TDD, tests green,
then real end-to-end validation, then a PR") a real, runnable thing
instead of something re-typed by hand each time.

**Node.js prerequisite (issue #17):** the admin UI's frontend
(`web/`, React+Vite+TS) is embedded into the gateway binary via
`go:embed` (`internal/webui`). `go build`/`go vet`/`go test ./...` all
still succeed without Node.js installed at all — `internal/webui/dist`
carries a tracked `.gitkeep` placeholder specifically so a fresh clone
never hard-fails just to run the Go test suite — but a binary built
that way serves 404s under `/ui/`. `make build` and `make ci` both
depend on a new `make web` target (`cd web && npm ci && npm run
build`) so the default path always produces a real, UI-serving binary;
run `make web` by hand first if you're invoking `go build` directly
instead of going through `make`.

- **`run-tests.sh`** — the fast local/CI check: `gofmt -l`, `go vet`,
  `go build`, `go test ./... -race -count=1`. This already includes
  in-process integration tests that spawn real fixture MCP servers (e.g.
  `internal/proxy/stdioadapter`'s tests use `go run` against
  `testdata/echoserver`, `crashserver`, `failserver`) — not mocks, just
  scoped to a single Go test binary via `httptest`.

- **`run-e2e.sh`** — a genuinely different layer: builds the *actual*
  compiled gateway binary, registers a real stdio MCP node, runs the
  gateway as a real OS process, and drives a full session lifecycle
  against it with `curl` (`initialize` → `tools/call` incl. a real
  secret-redaction check → `DELETE` → reuse-rejected). Catches bugs the
  in-process suite structurally can't: does the binary actually start,
  parse its config, bind its port, serve real HTTP.

- **`run-e2e-auth.sh`** — issue #3's auth lifecycle, against the real
  compiled binary with its real, unmodified `DenyAll` default (not
  `run-e2e.sh`'s `dev_allow_all_policy` escape hatch): unauthenticated
  request → 401 + `WWW-Authenticate`; JWKS and RFC 9728 metadata actually
  served; `client_credentials` mint; wrong secret rejected; valid token →
  403 (`DenyAll`, not 401 — proves auth succeeded, not that access is
  granted); wrong-audience token rejected; a deliberately-short-TTL token
  expires and gets rejected; re-minting afterward just works. Mints via a
  config-seeded NHI credential (`config.SeedAgents`) since there's no admin
  API yet (Phase 4) to register one over HTTP.

- **`run-e2e-policy.sh`** — issue #7's policy engine, against the real
  compiled binary with a real `config.Policies` bootstrap: a principal
  with no group at all gets 403 even on `initialize` (no special-casing);
  a server-level grant lets a real tool call actually succeed end-to-end
  (the first time any e2e script in this repo reaches a real 200 on a
  policy-gated call, not just a 403 proving auth alone); a method-scoped
  grant allows `tools/list` but denies `tools/call`; a rate-limited group's
  second call gets 429, distinct from 403. Not part of `make ci-interop`
  — no Docker needed, runs in `make ci`.

- **`run-e2e-pin.sh`** — issue #9's tool pinning, against the real
  compiled binary with a real stdio node whose one tool's description is
  controlled by a file the script rewrites mid-run (`dev_allow_all_policy`
  so only pinning, not policy, is under test): before any refresh, a tool
  with no pin is neither invisible nor blocked; after the background
  scheduler's first refresh, the same unchanged tool is still fully
  normal (TOFU establishment isn't drift); the script then rewrites the
  description file to simulate a rug pull, and confirms within one more
  refresh cycle that the tool's `tools/call` is rejected with a
  pinning-specific (not policy-specific) reason and it's gone from
  `tools/list`. Not part of `make ci-interop` — no Docker needed, runs in
  `make ci`.

- **`run-e2e-schema.sh`** — issue #11's schema-enforcement seam, against
  the real compiled binary and the same `pinserver` fixture
  `run-e2e-pin.sh` uses: its one tool's `inputSchema` is the MCP go-sdk's
  own real, inferred schema (a required `text` string, no additional
  properties allowed) — not hand-crafted for this test. After a real
  TOFU-established pin captures that schema, a valid call succeeds; a
  call missing the required argument, one with a wrong-typed argument,
  and one with an unexpected extra property are each rejected (403,
  reason names "pinned schema" so it's distinguishable from a
  policy/quarantine denial), all before ever reaching the upstream. Not
  part of `make ci-interop` — no Docker needed, runs in `make ci`.

- **`run-e2e-adminapi.sh`** — issue #13's admin API (Phase 4), against
  the real compiled binary: a real `_admin`-audience NHI token minted via
  the compiled binary's own `/token` endpoint (only the config-designated
  integration agent can mint it — a non-allowlisted agent is proven
  rejected first), plus a real (fixture, not spider-snoop itself) HTTP
  server standing in for spider-snoop's `GET /api/users/me`. Drives real
  `/admin/*` operations (create agent, create group, assign membership,
  replace policy) through the full dual-trust gate and confirms the
  store-visible effects via the same API afterward. Not part of
  `make ci-interop` — no Docker needed, runs in `make ci`.

- **`run-e2e-nodes.sh`** — issue #15's node registration (Phase 4b), against the real compiled binary, including a real process restart: a node is registered via `POST /admin/nodes` against a gateway running with zero configured MCP nodes, confirmed listed immediately, confirmed **not yet reachable** on the still-running process (`/mcp/echo/` 404s, and minting a per-node token for it fails) — then the same binary is actually killed and relaunched against the same `store_db_path`, and the node is confirmed reachable afterward: a real session, a real `tools/call`. Proves the "restart required, no hot-reload" behavior against the real process lifecycle, not just a doc comment. Not part of `make ci-interop` — no Docker needed, runs in `make ci`.

- **`run-e2e-adminui-session.sh`** — issue #17's admin UI session/cookie
  path (Phase 4c-1), against the real compiled binary and the same
  `fakespidersnoop` fixture issue #13's e2e uses: a browser-shaped caller
  (a real curl cookie jar, never an NHI bearer token) logs in via
  `POST /admin/ui/session`, gets a real `HttpOnly` cookie, and that
  cookie alone drives real `/admin/agents`, `/admin/groups`, and
  `/admin/policies` operations — but is confirmed rejected on
  `/admin/nodes`, which stays service-to-service only. Also confirms the
  pre-existing NHI-token-plus-header path is completely unaffected by
  this addition, that logout actually invalidates the cookie, and that a
  session expires on its own (a deliberately short 2s
  `admin_ui_session_max_age_seconds`) without an explicit logout. Not
  part of `make ci-interop` — no Docker needed, runs in `make ci`.
  Requires `internal/webui/dist` to exist (`make web`, or `make ci`/
  `make build`, which both depend on it) — see the note below.

- **`run-e2e-adminui-nodes.sh`** — issue #19's extension of the cookie
  path onto `/admin/nodes`, against the real compiled binary. Narrowly
  scoped on purpose: logs in via the browser cookie (no NHI token
  anywhere in this script), confirms the cookie alone now succeeds on
  `GET/POST/DELETE /admin/nodes` (previously service-to-service only),
  registers a real node and confirms it's persisted, confirms deleting
  a `config`-sourced node via the cookie is refused with the same 409
  message the NHI path already produces, confirms deleting the
  cookie-registered node succeeds. Does **not** re-prove restart-
  required behavior — that stays `run-e2e-nodes.sh`'s job, unmodified.
  Not part of `make ci-interop` — no Docker needed, runs in `make ci`.

- **`run-e2e-seed-users.sh`** — issue #21's CSV bulk user import
  (Phase 4c-3), against the real compiled binary: a real CSV file
  (not inline `config.json`) bootstraps a local Mode A human via
  `seed_users_csv_path`, and that user's real password actually works
  — a real `POST /token` login grant, then a real authorized
  `tools/call` through a real stdio node, the same "first real 200"
  DoD pattern `run-e2e-policy.sh` established, here for a CSV-seeded
  human instead of a config-seeded NHI. Then, like `run-e2e-nodes.sh`,
  actually kills and relaunches the compiled binary — this time
  against an *edited* CSV whose password for that same username has
  changed — and confirms the **original** password still works and
  the edited one doesn't: this bootstrap must never silently reset an
  existing user's password on a later run. Not part of
  `make ci-interop` — no Docker needed, runs in `make ci`.

- **`run-e2e-idjag.sh`** (`make ci-interop`, separate from `make ci` —
  needs Docker) — issue #5's Keycloak interop: the real 3-legged RFC
  7523/8693 flow against a real Keycloak container, realm/client/user
  setup scripted via Keycloak's own Admin REST API. See `interop/README.md`
  for what this proves and the real interop quirks it found.

- **`run-all.sh`** — every Docker-free script above, in order. This is the
  one command to run before opening a PR. `make ci-interop` is a separate,
  required-but-Docker-gated layer — see `interop/README.md`.

## Extending this as new issues land

This folder is meant to grow with the codebase, not stay frozen at
Phase 1. When a new issue adds a real end-to-end flow worth smoke-testing
against the actual binary (auth in Phase 2, policy enforcement in
Phase 3, etc.), add a new `run-e2e-<flow>.sh` alongside `run-e2e.sh`
rather than growing one script indefinitely, and wire it into
`run-all.sh`. Keep each script narrowly about *one* lifecycle, the same
way the existing one is scoped to "a stdio session, start to finish" —
that's what keeps failures easy to localize.

The in-process Go test suite (`internal/*/*_test.go`) is still where most
test coverage should live; these scripts exist specifically for the
"does the real, compiled thing actually work" layer on top of that, not
as a replacement for it.
