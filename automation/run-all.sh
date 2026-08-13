#!/usr/bin/env bash
# The one command: fast unit/integration suite, then the real end-to-end
# smoke test against the compiled binary. Run this before opening a PR --
# it's the concrete realization of the CLAUDE.md workflow's "tests green,
# then validated end-to-end, then a PR goes up" rule.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$script_dir/run-tests.sh"
echo
"$script_dir/run-e2e.sh"
echo
"$script_dir/run-e2e-auth.sh"
echo
"$script_dir/run-e2e-policy.sh"
echo
"$script_dir/run-e2e-pin.sh"
echo
"$script_dir/run-e2e-schema.sh"
echo
"$script_dir/run-e2e-adminapi.sh"
echo
"$script_dir/run-e2e-nodes.sh"
echo
"$script_dir/run-e2e-adminui-session.sh"
echo
"$script_dir/run-e2e-adminui-nodes.sh"
echo
"$script_dir/run-e2e-seed-users.sh"
echo
"$script_dir/run-e2e-audit.sh"
echo
"$script_dir/run-e2e-adminui-sessions.sh"
echo
"$script_dir/run-e2e-standalone-admin.sh"
echo
"$script_dir/run-e2e-mcp-audit.sh"
echo
"$script_dir/run-e2e-release.sh"
