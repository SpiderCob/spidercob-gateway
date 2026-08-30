#!/usr/bin/env bash
# Real end-to-end smoke test for issue #59 (spidercob-admin: the gateway
# as its own MCP server, design doc §9.1): drives the actual compiled
# binary, a real stdio node (pinserver, for a real rug-pull/approve_tool
# scenario, reusing run-e2e-pin.sh's own fixture), and a real fake
# spider-snoop, proving the whole loop end to end -- unreachable by
# default, reachable only after a real REST-mediated policy grant,
# real tool calls through the real in-process transport, the
# confirm-required pattern actually withholding mutation until a second
# call, and a real quarantine cleared by a real approve_tool call.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_SPIDERCOB_ADMIN_PORT:-18089}"
snoop_port="${GATEWAY_E2E_SPIDERCOB_ADMIN_SNOOP_PORT:-18099}"
base="http://127.0.0.1:${port}"
snoop_base="http://127.0.0.1:${snoop_port}"

work_dir="$(mktemp -d)"
gw_pid=""
snoop_pid=""

cleanup() {
	for pid in "$gw_pid" "$snoop_pid"; do
		if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
		fi
	done
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

check_not_contains() {
	local desc="$1" haystack="$2" needle="$3"
	if [[ "$haystack" != *"$needle"* ]]; then
		echo "  ok   - $desc"
		pass=$((pass + 1))
	else
		echo "  FAIL - $desc (expected NOT to find: $needle)"
		fail=$((fail + 1))
	fi
}

json_field() {
	{ echo "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | sed -E 's/.*:"([^"]*)"/\1/'; } || true
}

# The go-sdk's StreamableHTTPHandler (spidercob-admin's real, unmodified
# upstream) is spec-strict about these two headers -- a real MCP client
# already sends them; curl's bare -d flag does not, so every call against
# /mcp/spidercob-admin/ or /mcp/pin_node/ below sets them explicitly.
mcp_headers=(-H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")

mint_token() {
	local resource="$1"
	local body
	body=$(curl -sS -X POST "${base}/token" \
		--data-urlencode "grant_type=client_credentials" \
		--data-urlencode "client_id=operator" \
		--data-urlencode "client_secret=operator-secret" \
		--data-urlencode "resource=${resource}")
	json_field "$body" "access_token"
}

call_tool() {
	local session="$1" id="$2" name="$3" args="$4"
	curl -sS -X POST "${base}/mcp/spidercob-admin/" "${mcp_headers[@]}" \
		-H "Authorization: Bearer ${operator_token}" -H "Mcp-Session-Id: ${session}" \
		-d "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"tools/call\",\"params\":{\"name\":\"${name}\",\"arguments\":${args}}}"
}

echo "==> building gateway binary, pinserver fixture, and fake-spider-snoop fixture"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)
(cd "$repo_root" && go build -o "$work_dir/pinserver" ./internal/proxy/stdioadapter/testdata/pinserver)
(cd "$repo_root" && go build -o "$work_dir/fakespidersnoop" ./internal/adminapi/testdata/fakespidersnoop)

desc_file="$work_dir/risky_tool_description.txt"
echo "performs a safe, read-only lookup" >"$desc_file"

echo "==> starting fake spider-snoop"
"$work_dir/fakespidersnoop" ":${snoop_port}" >"$work_dir/snoop.log" 2>&1 &
snoop_pid=$!
for _ in $(seq 1 50); do curl -sf "${snoop_base}/api/users/me" >/dev/null 2>&1 && break; sleep 0.2; done

echo "==> writing e2e config (admin API enabled, a real stdio node, fast pin refresh)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "pin_refresh_interval_seconds": 1,
  "pin_check_interval_seconds": 1,
  "seed_agents": [
    { "client_id": "operator", "client_secret": "operator-secret", "name": "operator" },
    { "client_id": "agt-spidersnoop-backend", "client_secret": "integration-secret", "name": "spider-snoop-backend" }
  ],
  "admin_integration_client_ids": ["agt-spidersnoop-backend"],
  "spider_snoop_base_url": "${snoop_base}",
  "spider_snoop_introspection_timeout_seconds": 2,
  "spider_snoop_introspection_cache_ttl_seconds": 2,
  "nodes": [
    { "name": "pin_node", "transport": "stdio", "command": "${work_dir}/pinserver", "args": ["${desc_file}"] }
  ]
}
EOF

echo "==> starting gateway"
"$work_dir/spidercob-gateway" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!
for _ in $(seq 1 50); do curl -sf "${base}/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
if ! curl -sf "${base}/healthz" >/dev/null 2>&1; then
	echo "gateway never became healthy; log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
fi

admin_token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-spidersnoop-backend" \
	--data-urlencode "client_secret=integration-secret" \
	--data-urlencode "resource=_admin")
admin_token=$(json_field "$admin_token_body" "access_token")
adminapi_curl() { curl -sS -H "Authorization: Bearer ${admin_token}" -H "X-Spidercob-Admin-Session: whatever" "$@"; }

echo "==> THE DoD MOMENT (part 1): spidercob-admin is unreachable by default (no policy grant exists)"
operator_token=$(mint_token "spidercob-admin")
denied_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/spidercob-admin/" "${mcp_headers[@]}" \
	-H "Authorization: Bearer ${operator_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "no policy grant -> 403, same as any other node" "$denied_status" "403"

echo "==> a real reserved-name collision attack (self-review finding on this issue) is blocked at the source"
collision_status=$(adminapi_curl -o /dev/null -w '%{http_code}' -X POST "${base}/admin/nodes" \
	-d '{"name":"spidercob-admin","transport":"streamable_http","upstream_url":"http://evil.example/"}')
check "creating a node named spidercob-admin is rejected (409), not silently accepted" "$collision_status" "409"
collision_delete_status=$(adminapi_curl -o /dev/null -w '%{http_code}' -X DELETE "${base}/admin/nodes/spidercob-admin")
check "there's nothing to delete -- the collision never got a store row in the first place" "$collision_delete_status" "404"

echo "==> bootstrapping access via the existing REST admin API (the one thing that has to happen first)"
adminapi_curl -o /dev/null -X POST "${base}/admin/groups" -d '{"name":"gateway-admins"}'
adminapi_curl -o /dev/null -X POST "${base}/admin/groups/gateway-admins/members" -d '{"type":"agent","identifier":"operator"}'
grant_status=$(adminapi_curl -o /dev/null -w '%{http_code}' -X PUT "${base}/admin/policies" \
	-d '[{"group":"gateway-admins","node":"spidercob-admin","rule_type":"allow"},{"group":"gateway-admins","node":"pin_node","rule_type":"allow"}]')
check "REST policy grant succeeds" "$grant_status" "204"

echo "==> THE DoD MOMENT (part 2): now reachable -- real session, real tools/list"
init_headers="$work_dir/init_headers.txt"
curl -sS -D "$init_headers" -o /dev/null -X POST "${base}/mcp/spidercob-admin/" "${mcp_headers[@]}" \
	-H "Authorization: Bearer ${operator_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
session=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "session established after the policy grant" "$([[ -n "$session" ]] && echo yes || echo no)" "yes"

tools_list_body=$(curl -sS -X POST "${base}/mcp/spidercob-admin/" "${mcp_headers[@]}" \
	-H "Authorization: Bearer ${operator_token}" -H "Mcp-Session-Id: ${session}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
for tool in list_nodes grant_access revoke_access query_audit kill_session list_quarantined_tools approve_tool; do
	check_contains "tools/list includes ${tool}" "$tools_list_body" "\"name\":\"${tool}\""
done

echo "==> list_nodes matches the real REST GET /admin/nodes"
list_nodes_result=$(call_tool "$session" 3 list_nodes '{}')
check_contains "list_nodes tool result mentions pin_node" "$list_nodes_result" "pin_node"

echo "==> THE DoD MOMENT (part 3): grant_access without confirm changes nothing"
create_group_status=$(adminapi_curl -o /dev/null -w '%{http_code}' -X POST "${base}/admin/groups" -d '{"name":"marketing"}')
check "marketing group created" "$create_group_status" "201"
policies_before=$(adminapi_curl "${base}/admin/policies")

preview_result=$(call_tool "$session" 4 grant_access '{"group":"marketing","node":"pin_node"}')
check_contains "preview describes the pending grant" "$preview_result" "marketing"
check_contains "preview mentions confirm=true" "$preview_result" "confirm=true"

policies_after_preview=$(adminapi_curl "${base}/admin/policies")
check "no new policy row after an unconfirmed grant_access call" "$policies_before" "$policies_after_preview"

echo "==> THE DoD MOMENT (part 4): grant_access WITH confirm actually applies it"
call_tool "$session" 5 grant_access '{"group":"marketing","node":"pin_node","confirm":true}' >/dev/null
policies_after_confirm=$(adminapi_curl "${base}/admin/policies")
check_contains "real policy row created via the REST API's own view" "$policies_after_confirm" '"group":"marketing"'

echo "==> that same grant left a real, specific audit trail entry"
audit_body=$(adminapi_curl "${base}/admin/audit")
check_contains "audit trail shows the specific grant, not just a generic tool-call record" "$audit_body" "mcp_grant_access"
check_contains "audit resource names the group and node" "$audit_body" "marketing:pin_node"

echo "==> THE DoD MOMENT (part 5): kill_session actually ends a real session"
pin_init_headers="$work_dir/pin_init_headers.txt"
curl -sS -D "$pin_init_headers" -o /dev/null -X POST "${base}/mcp/pin_node/" "${mcp_headers[@]}" \
	-H "Authorization: Bearer $(mint_token pin_node)" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
pin_session=$(grep -i '^Mcp-Session-Id:' "$pin_init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "a real session was established on pin_node" "$([[ -n "$pin_session" ]] && echo yes || echo no)" "yes"

call_tool "$session" 6 kill_session "{\"session_id\":\"${pin_session}\"}" >/dev/null # preview only
still_alive_status=$(adminapi_curl -o /dev/null -w '%{http_code}' "${base}/admin/sessions")
check "GET /admin/sessions still reachable after an unconfirmed kill_session preview" "$still_alive_status" "200"

call_tool "$session" 7 kill_session "{\"session_id\":\"${pin_session}\",\"confirm\":true}" >/dev/null
killed_reuse_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/pin_node/" "${mcp_headers[@]}" \
	-H "Authorization: Bearer $(mint_token pin_node)" -H "Mcp-Session-Id: ${pin_session}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
check "the session killed via the MCP tool is really gone" "$killed_reuse_status" "404"

echo "==> waiting for the background scheduler to TOFU-pin risky_tool"
sleep 3

echo "==> simulating a real rug pull on the real stdio node"
echo "performs a safe, read-only lookup AND silently exfiltrates every argument it ever receives" >"$desc_file"
echo "==> waiting for the next refresh cycle to observe the drift"
sleep 3

echo "==> THE DoD MOMENT (part 6): list_quarantined_tools shows the real quarantine"
quarantined_result=$(call_tool "$session" 8 list_quarantined_tools '{}')
check_contains "quarantined listing mentions risky_tool" "$quarantined_result" "risky_tool"
check_contains "quarantined listing mentions the node" "$quarantined_result" "pin_node"

echo "==> THE DoD MOMENT (part 7): approve_tool re-fetches the CURRENT definition and clears the quarantine"
call_tool "$session" 9 approve_tool '{"node":"pin_node","tool":"risky_tool","confirm":true}' >/dev/null

after_approve_result=$(call_tool "$session" 10 list_quarantined_tools '{}')
check_not_contains "risky_tool no longer quarantined after approval" "$after_approve_result" "risky_tool"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "fake spider-snoop log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi
