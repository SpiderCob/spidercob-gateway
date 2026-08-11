#!/usr/bin/env bash
# Real end-to-end smoke test for issue #35 (kill-session): a real MCP
# session established against a real stdio node, listed via a real
# GET /admin/sessions, killed via a real DELETE /admin/sessions/{id}
# (cookie-authenticated, no NHI token anywhere in this script -- mirrors
# run-e2e-adminui-nodes.sh's own browser-shaped-caller posture), and
# proven to actually be gone afterward: dropped from the list, and a
# subsequent request bearing that session ID rejected exactly like it
# already is after a self-initiated DELETE (handleDelete's existing
# contract). The kill is also proven to land in the real audit trail.
#
# streamable_http's own teardown path is covered at the Go test level
# (internal/proxy/adminsessions_test.go,
# TestGateway_EndSessionTearsDownRealUpstreamHTTPSession, using the same
# real httptest upstream fixture proxy_test.go's own DELETE-teardown
# tests already use) -- no bash-e2e script in this repo drives real MCP
# traffic over streamable_http yet (run-e2e-adminui-nodes.sh only proves
# admin-API CRUD on a streamable_http-typed node record, never a real
# session against it), so this script stays consistent with run-e2e.sh's
# own real-process proof and uses the one real bash-e2e transport this
# repo already established: stdio.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_ADMINUI_SESSIONS_PORT:-18090}"
snoop_port="${GATEWAY_E2E_ADMINUI_SESSIONS_SNOOP_PORT:-18100}"
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

check_not_contains() {
	local desc="$1" haystack="$2" needle="$3"
	if [[ "$haystack" != *"$needle"* ]]; then
		echo "  ok   - $desc"
		pass=$((pass + 1))
	else
		echo "  FAIL - $desc (must not contain: $needle)"
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
if ! curl -sf "${snoop_base}/api/users/me" >/dev/null 2>&1; then
	echo "fake spider-snoop never became ready; log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi

echo "==> writing e2e config (admin API enabled, one real stdio node, allow-all policy)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "dev_allow_all_policy": true,
  "nodes": [
    { "name": "echo", "transport": "stdio", "command": "${work_dir}/echoserver" }
  ],
  "seed_agents": [
    { "client_id": "agt-spidersnoop-backend", "client_secret": "integration-secret", "name": "spider-snoop-backend" },
    { "client_id": "agt-caller", "client_secret": "caller-secret", "name": "session-caller" }
  ],
  "admin_integration_client_ids": ["agt-spidersnoop-backend"],
  "spider_snoop_base_url": "${snoop_base}",
  "spider_snoop_introspection_timeout_seconds": 2,
  "spider_snoop_introspection_cache_ttl_seconds": 2
}
EOF

echo "==> starting gateway"
"$work_dir/spidercob-gateway" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!
wait_healthy

echo "==> logging in via the browser session (cookie), no NHI token anywhere in this script"
cookie_jar="$work_dir/cookies.txt"
curl -sS -c "$cookie_jar" -X POST "${base}/admin/ui/session" \
	-d '{"spider_snoop_session_token":"a-real-spider-snoop-session-token"}' >/dev/null
check "a cookie was actually set" "$([[ -s "$cookie_jar" ]] && grep -q spidercob_admin_session "$cookie_jar" && echo yes || echo no)" "yes"

echo "==> before any session exists, the list is empty"
empty_list_body=$(curl -sS -b "$cookie_jar" "${base}/admin/sessions")
check "empty session list is [] not an error" "$empty_list_body" "[]"

echo "==> minting a real per-node token and establishing a real MCP session against echo"
caller_token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-caller" \
	--data-urlencode "client_secret=caller-secret" \
	--data-urlencode "resource=echo")
caller_token=$(json_field "$caller_token_body" "access_token")
check "per-node token minted" "$([[ -n "$caller_token" ]] && echo yes || echo no)" "yes"

init_headers="$work_dir/init_headers.txt"
curl -sS -D "$init_headers" -o /dev/null -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${caller_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
session_id=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "a real session was established" "$([[ -n "$session_id" ]] && echo yes || echo no)" "yes"

echo "==> THE DoD MOMENT (part 1): the real session is actually listed, with the right node and principal"
list_body=$(curl -sS -b "$cookie_jar" "${base}/admin/sessions")
check_contains "the live session appears in GET /admin/sessions" "$list_body" "\"id\":\"${session_id}\""
check_contains "its node is reported correctly" "$list_body" '"node":"echo"'
check_contains "its owning principal is reported correctly" "$list_body" '"principal":"agent:agt-caller"'

echo "==> killing an unknown session id is refused with 404"
unknown_kill_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" -X DELETE "${base}/admin/sessions/never-existed")
check "unknown session id -> 404" "$unknown_kill_status" "404"

echo "==> THE DoD MOMENT (part 2): the cookie alone kills the real session"
kill_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" -X DELETE "${base}/admin/sessions/${session_id}")
check "cookie alone kills the session" "$kill_status" "204"

after_kill_list_body=$(curl -sS -b "$cookie_jar" "${base}/admin/sessions")
check_not_contains "the killed session no longer appears in the list" "$after_kill_list_body" "\"id\":\"${session_id}\""

echo "==> THE DoD MOMENT (part 3): the real session is really gone, not just delisted"
reuse_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${caller_token}" \
	-H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"should not work"}}}')
check "killed session rejected exactly like a self-deleted one" "$reuse_status" "404"

echo "==> the kill shows up in the real audit trail"
audit_body=$(curl -sS -b "$cookie_jar" "${base}/admin/audit")
check_contains "kill_session action recorded" "$audit_body" '"action":"kill_session"'
check_contains "the killed session's id recorded as the resource" "$audit_body" "\"resource\":\"${session_id}\""

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "fake spider-snoop log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi
