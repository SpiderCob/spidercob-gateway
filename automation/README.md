# Automation

Scripts that make the CLAUDE.md development workflow ("TDD, tests green,
then real end-to-end validation, then a PR") a real, runnable thing
instead of something re-typed by hand each time.

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

- **`run-all.sh`** — both, in order. This is the one command to run
  before opening a PR.

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
