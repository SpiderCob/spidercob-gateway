#!/usr/bin/env bash
# Real end-to-end smoke test for issue #45's per-MCP-request audit trail:
# extends the hash-chained audit_log (issue #23, previously wired only
# into internal/adminapi's admin mutations) to actual proxied MCP
# traffic. Drives a real allowed tools/call and a real policy-denied
# request through the actual compiled binary against a real stdio
# upstream (the echoserver fixture, same as run-e2e-policy.sh), then
# reads them back via the real GET /admin/audit endpoint (issue #25) --
# proving the whole path end-to-end, not just internal/proxy's in-process
# test seam. Also proves the excluded-from-auditing paths issue #45's
# spec named (session teardown, auth failure) really do leave no record.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_MCP_AUDIT_PORT:-18101}"
snoop_port="${GATEWAY_E2E_MCP_AUDIT_SNOOP_PORT:-18102}"
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

mint_token() {
	local client_id="$1" secret="$2" resource="$3"
	local body
	body=$(curl -sS -X POST "${base}/token" \
		--data-urlencode "grant_type=client_credentials" \
		--data-urlencode "client_id=${client_id}" \
		--data-urlencode "client_secret=${secret}" \
		--data-urlencode "resource=${resource}")
	json_field "$body" "access_token"
}

# fetch_audit polls GET /admin/audit until it sees at least $1 records
# (the audit worker is deliberately async -- issue #45's spec -- so the
# record may not be persisted the instant the MCP response returns) and
# echoes the final response body.
fetch_audit() {
	local want_count="$1" body count
	for _ in $(seq 1 50); do
		body=$(curl -sS "${base}/admin/audit?limit=50" \
			-H "Authorization: Bearer ${admin_token}" \
			-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
		count=$(echo "$body" | grep -o '"id":[0-9]*' | wc -l | tr -d ' ')
		if [[ "$count" -ge "$want_count" ]]; then
			echo "$body"
			return 0
		fi
		sleep 0.1
	done
	echo "$body"
}

echo "==> building gateway binary and fake-spider-snoop fixture"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)
(cd "$repo_root" && go build -o "$work_dir/fakespidersnoop" ./internal/adminapi/testdata/fakespidersnoop)

echo "==> starting fake spider-snoop (stands in for GET /api/users/me, needed to read GET /admin/audit)"
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

echo "==> writing e2e config (real stdio node, real policy bootstrap, admin API enabled)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "seed_agents": [
    { "client_id": "agt-spidersnoop-backend", "client_secret": "integration-secret", "name": "spider-snoop-backend" },
    { "client_id": "agent-full-access", "client_secret": "full-access-secret", "name": "full-access", "groups": ["full-access"] },
    { "client_id": "agent-no-access",   "client_secret": "no-access-secret",   "name": "no-access" }
  ],
  "policies": [
    { "group": "full-access", "node": "echo", "rule_type": "allow" }
  ],
  "nodes": [
    {
      "name": "echo",
      "transport": "stdio",
      "command": "go",
      "args": ["run", "${repo_root}/internal/proxy/stdioadapter/testdata/echoserver"]
    }
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

admin_token=$(mint_token "agt-spidersnoop-backend" "integration-secret" "_admin")
check "admin token minted" "$([[ -n "$admin_token" ]] && echo yes || echo no)" "yes"

echo "==> a real, policy-authorized tools/call succeeds -- and must leave an audit trail"
full_token=$(mint_token "agent-full-access" "full-access-secret" "echo")
init_headers="$work_dir/init_headers.txt"
curl -sS -D "$init_headers" -o /dev/null -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${full_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
session_id=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "full-access agent can initialize" "$([[ -n "$session_id" ]] && echo yes || echo no)" "yes"

call_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${full_token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"audited"}}}')
check "authorized tool call succeeds" "$call_status" "200"

echo "==> a real, policy-denied request must also leave an audit trail -- enforcement is exactly what's being audited"
no_access_token=$(mint_token "agent-no-access" "no-access-secret" "echo")
denied_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${no_access_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "no-group agent denied" "$denied_status" "403"

echo "==> an unauthenticated request must leave NO audit trail (issue #45 spec story 17 -- no validated principal to attribute it to)"
curl -sS -o /dev/null -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer not-a-real-token" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

echo "==> THE DoD MOMENT: both real MCP-request outcomes above are retrievable via the real GET /admin/audit endpoint"
# 2 records from the full-access agent (initialize:allowed, tools/call:allowed) + 1 from the denied agent (initialize:denied_policy).
audit_body=$(fetch_audit 3)
check_contains "full-access agent's initialize is audited" "$audit_body" '"action":"initialize:allowed"'
check_contains "the real tools/call is audited, tool name included in the resource" "$audit_body" '"resource":"echo/echo"'
check_contains "the denied agent's rejection is audited, not just the successes" "$audit_body" '"action":"initialize:denied_policy"'
record_count=$(echo "$audit_body" | grep -o '"id":[0-9]*' | wc -l | tr -d ' ')
check "exactly 3 audit records -- the unauthenticated attempt left none" "$record_count" "3"

echo "==> session teardown must leave no additional audit record (lifecycle management, not a policy-gated access -- issue #45 spec story 16)"
curl -sS -o /dev/null -X DELETE "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${full_token}" -H "Mcp-Session-Id: ${session_id}"
sleep 0.5 # give any (incorrect) async enqueue a moment to land before asserting it didn't
audit_after_delete=$(curl -sS "${base}/admin/audit?limit=50" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
after_delete_count=$(echo "$audit_after_delete" | grep -o '"id":[0-9]*' | wc -l | tr -d ' ')
check "still exactly 3 records after DELETE" "$after_delete_count" "3"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "fake spider-snoop log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi
