#!/usr/bin/env bash
# Real end-to-end smoke test for issue #19: the admin UI's cookie-based
# session (issue #17) extended to /admin/nodes, against the real compiled
# binary. Narrowly scoped on purpose -- this proves "the cookie is now
# accepted here too," not "node registration works end to end" (that's
# already run-e2e-nodes.sh's job, including the real restart-required
# proof, and is deliberately not re-tested here).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_ADMINUI_NODES_PORT:-18089}"
snoop_port="${GATEWAY_E2E_ADMINUI_NODES_SNOOP_PORT:-18099}"
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

echo "==> building gateway binary and fake-spider-snoop fixture"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)
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

echo "==> writing e2e config (admin API enabled, one pre-registered config-sourced node)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "nodes": [
    { "name": "jira", "transport": "streamable_http", "upstream_url": "http://example.invalid" }
  ],
  "seed_agents": [
    { "client_id": "agt-spidersnoop-backend", "client_secret": "integration-secret", "name": "spider-snoop-backend" }
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

echo "==> logging in via the browser session (cookie), no NHI token anywhere in this script"
cookie_jar="$work_dir/cookies.txt"
curl -sS -c "$cookie_jar" -X POST "${base}/admin/ui/session" \
	-d '{"spider_snoop_session_token":"a-real-spider-snoop-session-token"}' >/dev/null
# If login itself is broken, every check below would fail too -- but with
# a misleading "/admin/nodes regression" flavor instead of pointing at
# login/setup. Assert the cookie actually landed first (mirrors
# run-e2e-adminui-session.sh) so a login break is diagnosed as exactly
# that.
check "a cookie was actually set" "$([[ -s "$cookie_jar" ]] && grep -q spidercob_admin_session "$cookie_jar" && echo yes || echo no)" "yes"

echo "==> THE DoD MOMENT: the cookie alone now succeeds on /admin/nodes (issue #19 -- it did not before)"
list_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" "${base}/admin/nodes")
check "cookie alone succeeds on GET /admin/nodes" "$list_status" "200"

list_body=$(curl -sS -b "$cookie_jar" "${base}/admin/nodes")
check_contains "the config-sourced node is visible" "$list_body" '"name":"jira"'

create_body=$(curl -sS -b "$cookie_jar" -X POST "${base}/admin/nodes" \
	-d '{"name":"cookie-created","transport":"streamable_http","upstream_url":"http://example.invalid"}')
check_contains "cookie alone can register a new node" "$create_body" '"name":"cookie-created"'
check_contains "the newly-registered node is admin-sourced" "$create_body" '"source":"admin"'

list_body_after_create=$(curl -sS -b "$cookie_jar" "${base}/admin/nodes")
check_contains "the cookie-registered node is really persisted" "$list_body_after_create" "cookie-created"

echo "==> deleting the config-sourced node via the cookie is refused, same 409 message as the NHI path"
delete_config_resp=$(curl -sS -b "$cookie_jar" -X DELETE "${base}/admin/nodes/jira" -w '\n%{http_code}')
delete_config_status=$(tail -n1 <<<"$delete_config_resp")
delete_config_body=$(sed '$d' <<<"$delete_config_resp")
check "cookie alone refused deleting a config-sourced node" "$delete_config_status" "409"
check_contains "the 409 actually explains it's config-defined" "$delete_config_body" "this node is defined in config.json"

still_listed_body=$(curl -sS -b "$cookie_jar" "${base}/admin/nodes")
check_contains "the config-sourced node still exists after the refused delete" "$still_listed_body" '"name":"jira"'

echo "==> deleting the admin-sourced (cookie-created) node via the cookie succeeds"
delete_admin_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" -X DELETE "${base}/admin/nodes/cookie-created")
check "cookie alone can delete an admin-sourced node" "$delete_admin_status" "204"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "fake spider-snoop log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi
