#!/usr/bin/env bash
# Real end-to-end smoke test for issue #7 (Phase 3a policy engine v0):
# drives the actual compiled binary through the real config.Policies
# bootstrap -- config-seeded agents in different groups, each hitting the
# real store-backed policy.Evaluator (internal/proxy.SetPolicy), not a
# fake. This is the DoD moment: every prior phase's real e2e coverage
# (run-e2e-auth.sh, run-e2e-idjag.sh) deliberately stopped at a 403 to
# prove authentication without overclaiming that access works. Here, for
# the first time, an authorized real tool call actually succeeds.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_POLICY_PORT:-18083}"
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

mint_token() {
	local client_id="$1" secret="$2"
	local body
	body=$(curl -sS -X POST "${base}/token" \
		--data-urlencode "grant_type=client_credentials" \
		--data-urlencode "client_id=${client_id}" \
		--data-urlencode "client_secret=${secret}" \
		--data-urlencode "resource=echo")
	json_field "$body" "access_token"
}

echo "==> building gateway binary"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)

echo "==> writing e2e config (real stdio node, real policy bootstrap)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "seed_agents": [
    { "client_id": "agent-no-access",   "client_secret": "no-access-secret",   "name": "no-access" },
    { "client_id": "agent-full-access", "client_secret": "full-access-secret", "name": "full-access", "groups": ["full-access"] },
    { "client_id": "agent-read-only",   "client_secret": "read-only-secret",   "name": "read-only",   "groups": ["read-only"] },
    { "client_id": "agent-throttled",   "client_secret": "throttled-secret",   "name": "throttled",   "groups": ["throttled"] }
  ],
  "policies": [
    { "group": "full-access", "node": "echo", "rule_type": "allow" },
    { "group": "read-only",   "node": "echo", "rule_type": "allow", "methods": ["initialize", "tools/list"] },
    { "group": "throttled",   "node": "echo", "rule_type": "allow", "rate_limit_max_calls": 1, "rate_limit_window_seconds": 3600 }
  ],
  "nodes": [
    {
      "name": "echo",
      "transport": "stdio",
      "command": "go",
      "args": ["run", "${repo_root}/internal/proxy/stdioadapter/testdata/echoserver"]
    }
  ]
}
EOF

echo "==> starting gateway"
"$work_dir/spidercob-gateway" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!

for _ in $(seq 1 50); do
	if curl -sf "${base}/healthz" >/dev/null 2>&1; then
		break
	fi
	sleep 0.2
done
if ! curl -sf "${base}/healthz" >/dev/null 2>&1; then
	echo "gateway never became healthy; log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
fi

echo "==> agent with no group at all: even initialize is denied"
no_access_token=$(mint_token "agent-no-access" "no-access-secret")
status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${no_access_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "no policy at all -> 403, no special-casing for initialize" "$status" "403"

echo "==> full-access agent: initialize, tools/list, and a real tool call all succeed"
full_token=$(mint_token "agent-full-access" "full-access-secret")
init_headers="$work_dir/init_headers.txt"
init_body=$(curl -sS -D "$init_headers" -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${full_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
session_id=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "server-level grant allows initialize" "$([[ -n "$session_id" ]] && echo yes || echo no)" "yes"

tools_list_body=$(curl -sS -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${full_token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
check_contains "tools/list shows the echo tool" "$tools_list_body" '"name":"echo"'

echo "==> THE DoD MOMENT: a real, policy-authorized tool call succeeds end-to-end"
call_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${full_token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"policy engine works"}}}')
call_body=$(curl -sS -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${full_token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"policy engine works"}}}')
check "authorized tool call returns 200 (first time in this repo's history)" "$call_status" "200"
check_contains "the real upstream's echoed output actually reaches the client" "$call_body" "policy engine works"

echo "==> read-only agent: tools/list works, but tools/call is denied (method-level restriction)"
ro_token=$(mint_token "agent-read-only" "read-only-secret")
ro_headers="$work_dir/ro_headers.txt"
curl -sS -D "$ro_headers" -o /dev/null -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${ro_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
ro_session=$(grep -i '^Mcp-Session-Id:' "$ro_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "read-only agent can initialize" "$([[ -n "$ro_session" ]] && echo yes || echo no)" "yes"

ro_list_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${ro_token}" -H "Mcp-Session-Id: ${ro_session}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
check "read-only agent's tools/list is allowed" "$ro_list_status" "200"

ro_call_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${ro_token}" -H "Mcp-Session-Id: ${ro_session}" \
	-d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"nope"}}}')
check "read-only agent's tools/call is denied (method-level restriction)" "$ro_call_status" "403"

echo "==> throttled agent: first call succeeds, second is rate-limited"
throttled_token=$(mint_token "agent-throttled" "throttled-secret")
throttled_first=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${throttled_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "throttled agent's first call (initialize) succeeds" "$throttled_first" "200"

throttled_second=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${throttled_token}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}')
check "throttled agent's second call is rate-limited (429, distinct from 403)" "$throttled_second" "429"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
fi
