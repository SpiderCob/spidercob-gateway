#!/usr/bin/env bash
# Real end-to-end smoke test for issue #21's CSV bulk user import
# (Phase 4c-3), against the real compiled binary: a real CSV file
# bootstraps a local (Mode A) human via config.json's
# seed_users_csv_path, and that user's password actually works -- a
# real POST /token login grant, then a real authorized tool call
# through a real stdio node (the same "first real 200" DoD moment
# run-e2e-policy.sh established for a config-seeded NHI, here for a
# CSV-seeded human instead). Then proves idempotency for real: the
# gateway is killed and relaunched (same store_db_path) against an
# *edited* CSV whose password for that same username has changed, and
# the ORIGINAL password is confirmed to still be the one that works --
# this bootstrap must never silently reset an existing user's password.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_SEEDUSERS_PORT:-18090}"
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

check() {
	local desc="$1" got="$2" want="$3"
	if [[ "$got" == "$want" ]]; then
		echo "  ok   - $desc"
		pass=$((pass + 1))
	else
		echo "  FAIL - $desc (got: $got, want: $want)"
		fail=$((fail + 1))
	fi
}

check_contains() {
	local desc="$1" haystack="$2" needle="$3"
	if [[ "$haystack" == *"$needle"* ]]; then
		echo "  ok   - $desc"
		pass=$((pass + 1))
	else
		echo "  FAIL - $desc (expected to find: $needle)"
		fail=$((fail + 1))
	fi
}

json_field() {
	{ echo "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | sed -E 's/.*:"([^"]*)"/\1/'; } || true
}

wait_healthy() {
	for _ in $(seq 1 50); do
		if curl -sf "${base}/healthz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	echo "gateway never became healthy; log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
}

echo "==> building gateway binary and echoserver fixture"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)
(cd "$repo_root" && go build -o "$work_dir/echoserver" ./internal/proxy/stdioadapter/testdata/echoserver)

echo "==> writing the seed users CSV (real bulk-import file, not inline config.json)"
cat >"$work_dir/users.csv" <<'EOF'
username,password,groups
alice,original-password,engineering
EOF

echo "==> writing e2e config (real stdio node, real policy, seed_users_csv_path)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "seed_users_csv_path": "${work_dir}/users.csv",
  "policies": [
    { "group": "engineering", "node": "echo", "rule_type": "allow" }
  ],
  "nodes": [
    { "name": "echo", "transport": "stdio", "command": "${work_dir}/echoserver" }
  ]
}
EOF

echo "==> starting gateway (first launch)"
"$work_dir/spidercob-gateway" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!
wait_healthy

echo "==> THE DoD MOMENT: the CSV-seeded user's password actually works -- a real login, a real authorized call"
login_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=urn:spidercob:params:oauth:grant-type:login" \
	--data-urlencode "username=alice" \
	--data-urlencode "password=original-password" \
	--data-urlencode "resource=echo")
access_token=$(json_field "$login_body" "access_token")
check "CSV-seeded user can log in with their real password" "$([[ -n "$access_token" ]] && echo yes || echo no)" "yes"

init_headers="$work_dir/init_headers.txt"
init_status=$(curl -sS -D "$init_headers" -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${access_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "the seeded user's group membership actually grants real node access" "$init_status" "200"
session_id=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')

call_body=$(curl -sS -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${access_token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"csv seeded user works"}}}')
check_contains "a real tool call by the CSV-seeded user actually works" "$call_body" "csv seeded user works"

echo "==> restarting the gateway against an EDITED CSV (same username, different password)"
kill "$gw_pid" 2>/dev/null || true
wait "$gw_pid" 2>/dev/null || true
gw_pid=""

cat >"$work_dir/users.csv" <<'EOF'
username,password,groups
alice,a-different-password,engineering
EOF

"$work_dir/spidercob-gateway" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!
wait_healthy

echo "==> THE OTHER DoD MOMENT: the ORIGINAL password still works -- this bootstrap never silently resets an existing user's password"
still_original_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/token" \
	--data-urlencode "grant_type=urn:spidercob:params:oauth:grant-type:login" \
	--data-urlencode "username=alice" \
	--data-urlencode "password=original-password" \
	--data-urlencode "resource=echo")
check "original password still works after a restart against an edited CSV" "$still_original_status" "200"

new_password_rejected_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/token" \
	--data-urlencode "grant_type=urn:spidercob:params:oauth:grant-type:login" \
	--data-urlencode "username=alice" \
	--data-urlencode "password=a-different-password" \
	--data-urlencode "resource=echo")
check "the edited CSV's new password was never applied" "$new_password_rejected_status" "401"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
fi
