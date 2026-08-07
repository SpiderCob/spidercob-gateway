#!/usr/bin/env bash
# Fast local/CI check: format, vet, build, then the full unit + in-process
# integration suite (including the stdio-adapter tests, which spawn real
# fixture MCP servers via `go run` -- not mocks). Run this before every
# commit; it's what "TDD, tests green" means in the CLAUDE.md workflow.
#
# Does NOT include automation/run-e2e.sh, which drives the actual compiled
# binary as a real process -- see run-all.sh to run both.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "==> gofmt"
unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
	echo "gofmt found unformatted files:" >&2
	echo "$unformatted" >&2
	exit 1
fi

echo "==> go vet"
go vet ./...

echo "==> go build"
go build ./...

echo "==> go test (race, no cache)"
go test ./... -race -count=1

echo "==> all green"
