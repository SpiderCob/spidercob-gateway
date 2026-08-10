# Tier 2/3 Copilot-review findings (reconstructed 2026-08-10)

Reconstructed from `gh api repos/SpiderCob/spidercob-gateway/pulls/<n>/comments`
for PRs #2–#26 (the automated `copilot-pull-request-reviewer` comments
discovered on PR #26 — see `context_main`'s `CONTEXT.md` for the discovery
story). Tier 1 (8 findings) was already fixed via PR #27/#28/#29. This file
is the durable list Tier 1's write-up said was still missing.

Status legend: `[ ]` open, `[x]` fixed (with the PR that fixed it).

## Tier 3 — performance-only, deliberately left open (no current urgency)

- `internal/pin/validate.go:37` — `ValidateArguments` recompiles the JSON
  Schema on every `tools/call` instead of caching the compiled form.
- `internal/adminapi/introspect.go:142` — `CachingIntrospector`'s cache map
  has no eviction/size bound.
- `internal/proxy/proxy.go` (quarantine check) — a store error and a real
  tool-definition-drift quarantine both surface as the same 403 message,
  conflating "the DB is down" with "the tool changed under you."

## Tier 2 — real but lower-stakes, being fixed now

### Group A — concurrency / store correctness
- [x] `internal/proxy/session.go` `reapIdle` — a session can be `touch()`ed
  after being selected as expired (lock released) but before `end()` runs;
  it gets torn down anyway. (orig. PR #2) — fixed: select-and-remove now
  happens atomically under one lock, teardown runs afterward.
- [x] `internal/proxy/session.go` `end()` — deletes the session mapping
  before calling `teardown()`; if teardown fails, cleanup is non-retryable
  and can leak the upstream (e.g. a stdio child process). (orig. PR #2) —
  fixed: mapping only removed once the upstream is confirmed gone
  (`teardown()` succeeds, or `alive()` reports false); a genuine failure
  (still alive) leaves it in place, retryable via another `end()` call or
  the next `reapIdle` pass.
- [x] `internal/store/sqlite.go` — SQLite DSN built by string-interpolating
  `path` directly into a `file:` URI; a path containing `?`/`#` breaks
  opening the file or injects pragmas/query params. (orig. PR #4) — fixed
  via `sqliteURIPath`.
- [x] `internal/store/sqlite.go` `IsRevoked` — returns `true` for a matching
  `jti` even after `expires_at` has passed, unlike `LoadRevocations` which
  filters expired rows. (orig. PR #4) — fixed.
- [x] `internal/identity/password.go` `verifySecret` — parses the Argon2
  version from the PHC string but never validates it against the expected
  version. (orig. PR #4) — fixed.
- [x] `internal/authserver/denylist.go` `tryConsume` — marks a `jti`
  consumed in-memory before persisting; if the store write fails, the
  in-memory mark isn't rolled back, so a client retry gets a false replay
  (401) instead of another `server_error`. (orig. PR #6) — fixed.

### Group B — HTTP status code correctness
- [ ] `internal/adminapi/introspect.go` `HTTPIntrospector` — returns a
  generic error for any non-200 response, so an invalid/expired human
  session (401/403) looks identical to spider-snoop being unreachable.
  (orig. PR #14)
- [ ] `internal/adminapi/routes.go` `Gate` — maps all introspection errors
  to 503, including the 401/403 case above; should be a client 401.
  (orig. PR #14)
- [ ] `internal/adminapi/routes.go` `deleteNode` — maps all `DeleteNode`
  errors to 500; a concurrent delete (`ErrNotFound`) should be 404 like
  other delete endpoints. (orig. PR #16)
- [ ] `internal/adminapi/routes.go` — an invalid/expired UI-session cookie
  falls through to the service-to-service gate, producing a misleading
  "missing or malformed Authorization header" error for browser callers
  instead of a UI-session-specific 401. (orig. PR #18)

### Group C — data hygiene / UX correctness
- [ ] `internal/store/sqlite.go` `ListAgents` — selects/scans `secret_hash`
  even though no caller uses it; unnecessary blast-radius for credential
  material. (orig. PR #14)
- [ ] `internal/uisession/registry.go` `Get` — treats an expired session as
  a miss but leaves the entry in the map; should delete on lookup.
  (orig. PR #18)
- [ ] `web/src/screens/Policies.tsx` — comma-splitting methods/tools can
  produce empty strings (trailing/double comma), which the backend then
  treats as a restrictive allowlist that can never match. (orig. PR #18)
- [ ] `web/src/screens/Nodes.tsx` `handleCreate` — validates trimmed
  fields but POSTs the raw (untrimmed) draft, and doesn't strip
  transport-irrelevant stale fields when switching transports. (orig. PR #20)
- [ ] `web/src/screens/Nodes.tsx` — `justRegistered` only drives the summary
  banner, not a per-row indicator on the actual new node. (orig. PR #20)
- [ ] `internal/policy/evaluator.go` — an unrecognized principal prefix
  returns an error instead of the documented `(nil, nil)` "no groups"
  default-deny. (orig. PR #8)
- [ ] `internal/policy/evaluate.go` — "most restrictive" ALLOW resolution
  picks the smallest `max_calls` alone, which is wrong when windows differ
  (1/sec is more restrictive than 2/hour). (orig. PR #8)
- [ ] `internal/proxy/proxy.go` — schema-enforcement error message
  prepends its own "pinned schema" text on top of `ValidateArguments`'s
  error, which already has one; produces duplicated wording. (orig. PR #12)

### Group D — docs / comments / test naming
- [x] `go.mod` — `go 1.25.0` should be `go 1.25` (major.minor; patch
  pinning via `toolchain` directive if needed). (orig. PR #2) — **checked,
  doesn't hold**: with the actual installed toolchain (go1.25.0), `go mod
  tidy` rewrites `go 1.25` straight back to `go 1.25.0` unprompted --
  modern Go (1.21+) writes the full patch version in the `go` directive by
  default; the finding's premise (major.minor is the norm, patch gets
  normalized away) matches an older Go tooling convention, not this one.
  No change made.
- [ ] `deploy/docker-compose.yml` — Keycloak image floats on `:latest`;
  pin a known-good version. (orig. PR #6)
- [ ] `docs/spec/conformance.md` — claims the actor chain (`act` claim) is
  preserved, but captured vectors show no `act` present. (orig. PR #6)
- [ ] `internal/config/config.go` — doc comment calls the rate limiter a
  "rolling window"; the implementation is a fixed-window counter.
  (orig. PR #8)
- [ ] `internal/policy/evaluator_test.go` — test named around "Revoked"
  actually exercises rate limiting (429), not revocation. (orig. PR #8)
- [ ] `README.md` (x2: intro + roadmap) — says a config-declared node
  "wins on conflict"; actual behavior rejects the collision instead.
  (orig. PR #16)
- [ ] `README.md` — "Small-team-shaped" bullet implies the admin UI is
  usable in the standalone (no spider-snoop) + CSV-seeded-users story,
  which it isn't (admin UI is gated on spider-snoop integration).
  (orig. PR #22)
- [ ] `internal/adminapi/routes.go` — `logAdminAction`'s doc comment is
  duplicated (a pre-issue-#23 block plus the updated one). (orig. PR #24)

### Group E — e2e script hardening
- [ ] `automation/run-e2e-adminui-nodes.sh` — logs in but never asserts a
  cookie was actually set; a login break would masquerade as an
  `/admin/nodes` regression. (orig. PR #20)
- [ ] `automation/run-e2e-adminui-nodes.sh` — claims the cookie-authed
  delete of a config-sourced node returns a specific 409 message but only
  checks the status code. (orig. PR #20)
- [ ] `automation/run-e2e-audit.sh` — the fake spider-snoop readiness loop
  never asserts success after retries. (orig. PR #24)

### Group F — config validation
- [ ] `internal/config/config.go` — validation only checks that
  `rate_limit_max_calls`/`rate_limit_window_seconds` are paired, not that
  they're positive; `window_seconds=0` silently disables the window.
  (orig. PR #8)

## Already fixed (Tier 1, for cross-reference — do not re-do)
`internal/authserver/proxy.go` Bearer parsing, `internal/config/config.go`
Issuer construction, `internal/authserver/authserver.go` cookie
MaxAge/Secure, `internal/config/config.go` `ValidateNode` charset,
`internal/idptrust/idptrust.go` + `internal/authserver/authserver.go`
missing-claim panic risk (PR #28) · `internal/store/sqlite.go` `DeleteGroup`
TOCTOU, `internal/pin/scheduler.go` fetch timeout, `internal/webui/webui.go`
directory-listing fallback, `internal/scan/pii.go` byte-safe redaction,
`internal/audit/audit.go` `GenesisPrevHash` const (PR #29).
