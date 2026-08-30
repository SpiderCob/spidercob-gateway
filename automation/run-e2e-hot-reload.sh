#!/usr/bin/env bash
# Real end-to-end smoke test for issue #57 (hot-reload for admin-
# registered nodes): drives the actual compiled binary through real
# POST/DELETE /admin/nodes calls against the *same still-running*
# process -- no restart anywhere in this script. run-e2e-nodes.sh
# (issue #15) needed updating alongside this issue too -- its original
# "not yet reachable before a restart" assertion was exactly the
# behavior this issue makes false, so that script's own DoD moment is
# now the restart-*persistence* half specifically (the node survives a
# real restart, not "requires one"), and this script is the thorough,
# dedicated no-restart-needed proof (creation, deletion, an in-flight
# session surviving deletion).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_HOTRELOAD_PORT:-18088}"
snoop_port="${GATEWAY_E2E_HOTRELOAD_SNOOP_PORT:-18098}"
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

echo "==> building gateway binary, echoserver fixture, and fake-spider-snoop fixture"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)
(cd "$repo_root" && go build -o "$work_dir/echoserver" ./internal/proxy/stdioadapter/testdata/echoserver)
(cd "$repo_root" && go build -o "$work_dir/fakespidersnoop" ./internal/adminapi/testdata/fakespidersnoop)

echo "==> starting fake spider-snoop (stands in for GET /api/users/me)"
"$work_dir/fakespidersnoop" ":${snoop_port}" >"$work_dir/snoop.log" 2>&1 &
snoop_pid=$!
for _ in $(seq 1 50); do
	if curl -sf "${snoop_base}/api/users/me" >/dev/null 2>&1; then
		break
	fi
	sleep 0.2
done

echo "==> writing e2e config (admin API enabled, zero MCP nodes to start)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "dev_allow_all_policy": true,
  "nodes": [],
  "seed_agents": [
    { "client_id": "agt-spidersnoop-backend", "client_secret": "integration-secret", "name": "spider-snoop-backend" }
  ],
  "admin_integration_client_ids": ["agt-spidersnoop-backend"],
  "spider_snoop_base_url": "${snoop_base}",
  "spider_snoop_introspection_timeout_seconds": 2,
  "spider_snoop_introspection_cache_ttl_seconds": 2
}
EOF

echo "==> starting gateway (ONE launch -- no restart anywhere in this script)"
"$work_dir/spidercob-gateway" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!
wait_healthy

admin_token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-spidersnoop-backend" \
	--data-urlencode "client_secret=integration-secret" \
	--data-urlencode "resource=_admin")
admin_token=$(json_field "$admin_token_body" "access_token")
check "admin token minted" "$([[ -n "$admin_token" ]] && echo yes || echo no)" "yes"

echo "==> before registration: the node genuinely doesn't exist yet"
before_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${admin_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "unknown node -> 404 before registration" "$before_status" "404"

echo "==> registering a new stdio node via the admin API"
create_node_body=$(curl -sS -X POST "${base}/admin/nodes" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token" \
	-d "{\"name\":\"echo\",\"transport\":\"stdio\",\"command\":\"${work_dir}/echoserver\"}")
check_contains "node created via the admin API" "$create_node_body" '"name":"echo"'

echo "==> THE DoD MOMENT (part 1): a real token mints for it, with ZERO restart"
echo_token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-spidersnoop-backend" \
	--data-urlencode "client_secret=integration-secret" \
	--data-urlencode "resource=echo")
echo_token=$(json_field "$echo_token_body" "access_token")
check "a real per-node token mints immediately, no restart" "$([[ -n "$echo_token" ]] && echo yes || echo no)" "yes"

echo "==> THE DoD MOMENT (part 2): RFC 9728 metadata serves for it immediately"
meta_status=$(curl -sS -o /dev/null -w '%{http_code}' "${base}/.well-known/oauth-protected-resource/echo")
check "RFC 9728 metadata is real (200), not a 404, no restart" "$meta_status" "200"

echo "==> THE DoD MOMENT (part 3): a real session establishes and a real tool call works, no restart"
init_headers="$work_dir/init_headers.txt"
init_status=$(curl -sS -D "$init_headers" -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${echo_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "the still-running gateway routes to the hot-added node" "$init_status" "200"
session_id=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "a real session was established" "$([[ -n "$session_id" ]] && echo yes || echo no)" "yes"

call_body=$(curl -sS -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${echo_token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hot-reload works"}}}')
check_contains "a real tool call against the hot-added node actually works" "$call_body" "hot-reload works"

echo "==> deleting the node via the admin API, still no restart"
delete_status=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "${base}/admin/nodes/echo" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check "delete succeeds" "$delete_status" "204"

echo "==> THE DoD MOMENT (part 4): a NEW session against the deleted node is rejected immediately"
new_session_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${echo_token}" \
	-d '{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}')
check "a brand new session against the removed node is rejected, no restart needed" "$new_session_status" "404"

echo "==> THE DoD MOMENT (part 5): the session already open BEFORE the delete keeps working (story 5)"
survivor_body=$(curl -sS -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${echo_token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"still alive"}}}')
check_contains "an already-established session survives the node's removal" "$survivor_body" "still alive"

echo "==> minting a NEW token for the deleted node now fails"
remint_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-spidersnoop-backend" \
	--data-urlencode "client_secret=integration-secret" \
	--data-urlencode "resource=echo")
check "minting for a removed node fails after deletion" "$(json_field "$remint_body" "access_token")" ""

echo "==> RFC 9728 metadata 404s for the deleted node"
meta_after_status=$(curl -sS -o /dev/null -w '%{http_code}' "${base}/.well-known/oauth-protected-resource/echo")
check "metadata gone for the deleted node" "$meta_after_status" "404"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "fake spider-snoop log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi
