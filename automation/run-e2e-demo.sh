#!/usr/bin/env bash
# Keeps the one-command demo honest: builds the gateway and demo/leakyserver,
# runs them with demo/config.json (paths rewritten for a local run, no
# Docker), and runs demo/try.sh against it -- the fake AWS key and test card
# must come back redacted, exactly as demo/README.md promises.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_PORT:-18087}"
base="http://127.0.0.1:${port}"
work_dir="$(mktemp -d)"
gw_pid=""
cleanup() {
	if [[ -n "$gw_pid" ]] && kill -0 "$gw_pid" 2>/dev/null; then
		kill "$gw_pid" 2>/dev/null || true
		wait "$gw_pid" 2>/dev/null || true
	fi
	rm -rf "$work_dir"
}
trap cleanup EXIT

pass=0
fail=0
check_contains() {
	if [[ "$2" == *"$3"* ]]; then echo "  ok   - $1"; pass=$((pass + 1)); else echo "  FAIL - $1 (expected: $3)"; fail=$((fail + 1)); fi
}
check_not_contains() {
	if [[ "$2" != *"$3"* ]]; then echo "  ok   - $1"; pass=$((pass + 1)); else echo "  FAIL - $1 (must not contain: $3)"; fail=$((fail + 1)); fi
}

echo "==> building gateway + demo/leakyserver"
(cd "$repo_root" && go build -o "$work_dir/spidercob" ./cmd/spidercob && go build -o "$work_dir/leakyserver" ./demo/leakyserver)
cp "$repo_root/demo/users.csv" "$work_dir/users.csv"
sed -e "s#\"/leakyserver\"#\"$work_dir/leakyserver\"#" -e "s#\"/users.csv\"#\"$work_dir/users.csv\"#" \
	-e "s#/tmp/spidercob-demo.db#$work_dir/demo.db#" -e "s#:8080#:${port}#g" \
	"$repo_root/demo/config.json" >"$work_dir/config.json"

echo "==> starting gateway with the demo config"
"$work_dir/spidercob" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!

echo "==> demo/try.sh"
out=$(GATEWAY_URL="$base" "$repo_root/demo/try.sh" 2>&1) || { echo "$out"; cat "$work_dir/gateway.log"; exit 1; }
check_contains "AWS key redacted" "$out" "AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key]"
check_contains "test card redacted" "$out" "BILLING_TEST_CARD=[REDACTED:credit-card]"
check_not_contains "raw AWS key never shown" "$out" "AKIA""IOSFODNN7EXAMPLE"
check_not_contains "raw card never shown" "$out" "4111 1111"
check_contains "harmless line passes through" "$out" "LOG_LEVEL=info"

echo
echo "==> ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
