#!/usr/bin/env bash
# Real end-to-end smoke test for issue #15 (Phase 4b: node registration),
# updated by issue #57 (hot-reload): drives the actual compiled binary
# through a real POST /admin/nodes call, proves the node is immediately
# usable on the same still-running process (hot-reload, issue #57 --
# this used to assert the *opposite*, "not yet reachable until restart";
# that assertion is what issue #57 existed to make false, and now is),
# then restarts the same binary against the same store_db_path to prove
# the node's registration genuinely persisted and survives a restart too
# -- a real, separate property from "works without a restart," not a
# redundant re-check of it. run-e2e-hot-reload.sh (issue #57) is the
# thorough, dedicated hot-reload proof (creation, deletion, an
# in-flight session surviving deletion); this script's own remaining job
# is the restart-persistence half specifically.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_NODES_PORT:-18087}"
snoop_port="${GATEWAY_E2E_NODES_SNOOP_PORT:-18097}"
base="http://127.0.0.1:${port}"
snoop_base="http://127.0.0.1:${snoop_port}"

work_dir="$(mktemp -d)"
gw_pid=""
snoop_pid=""

cleanup() {
	if [[ -n "$gw_pid" ]] && kill -0 "$gw_pid" 2>/dev/null; then
		kill "$gw_pid" 2>/dev/null || true
		wait "$gw_pid" 2>/dev/null || true
	fi
	if [[ -n "$snoop_pid" ]] && kill -0 "$snoop_pid" 2>/dev/null; then
		kill "$snoop_pid" 2>/dev/null || true
		wait "$snoop_pid" 2>/dev/null || true
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

echo "==> starting gateway (first launch, zero nodes)"
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

echo "==> registering a new stdio node via the admin API"
create_node_body=$(curl -sS -X POST "${base}/admin/nodes" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token" \
	-d "{\"name\":\"echo\",\"transport\":\"stdio\",\"command\":\"${work_dir}/echoserver\"}")
check_contains "node created via the admin API" "$create_node_body" '"name":"echo"'
check_contains "node is admin-sourced" "$create_node_body" '"source":"admin"'

list_nodes_body=$(curl -sS "${base}/admin/nodes" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check_contains "registered node appears in GET /admin/nodes" "$list_nodes_body" '"name":"echo"'

echo "==> the node is reachable on this SAME still-running process, no restart (issue #57 hot-reload)"
echo_token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-spidersnoop-backend" \
	--data-urlencode "client_secret=integration-secret" \
	--data-urlencode "resource=echo")
echo_token=$(json_field "$echo_token_body" "access_token")
check "a real per-node token mints with zero restart" "$([[ -n "$echo_token" ]] && echo yes || echo no)" "yes"

init_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${echo_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "the unrestarted gateway routes to the just-registered node" "$init_status" "200"

echo "==> restarting the gateway (same binary, same config, same store_db_path)"
kill "$gw_pid" 2>/dev/null || true
wait "$gw_pid" 2>/dev/null || true
gw_pid=""

"$work_dir/spidercob-gateway" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!
wait_healthy

echo "==> THE DoD MOMENT: the node's registration genuinely persisted across a real restart"
post_restart_token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-spidersnoop-backend" \
	--data-urlencode "client_secret=integration-secret" \
	--data-urlencode "resource=echo")
post_restart_token=$(json_field "$post_restart_token_body" "access_token")
check "a real per-node token can still be minted after a real restart" "$([[ -n "$post_restart_token" ]] && echo yes || echo no)" "yes"

init_headers="$work_dir/init_headers.txt"
init_status2=$(curl -sS -D "$init_headers" -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${post_restart_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "restarted gateway still routes to the persisted node" "$init_status2" "200"
session_id=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "a real session was established post-restart" "$([[ -n "$session_id" ]] && echo yes || echo no)" "yes"

call_body=$(curl -sS -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${post_restart_token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"node registration persists across a restart"}}}')
check_contains "a real tool call against the persisted node actually works" "$call_body" "node registration persists across a restart"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "fake spider-snoop log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi
