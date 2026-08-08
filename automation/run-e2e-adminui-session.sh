#!/usr/bin/env bash
# Real end-to-end smoke test for issue #17's admin UI session/cookie
# path (Phase 4c-1), against the real compiled binary: a browser-shaped
# caller (curl with a real cookie jar, no NHI bearer token at all) logs
# in via POST /admin/ui/session using the exact same fake spider-snoop
# fixture issue #13's e2e already uses, gets a real HttpOnly cookie, and
# that cookie alone authenticates real /admin/agents, /admin/groups, and
# /admin/policies calls. Also proves the existing NHI-token-plus-header
# path (issue #13/#15) is completely unaffected by this addition, and
# that a UI session actually expires on its own, not just on explicit
# logout. /admin/nodes joined the cookie path in issue #19 -- proving
# that specific extension is run-e2e-adminui-nodes.sh's job, not this
# script's; this script only needs to not regress on the resources it
# already covers.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_ADMINUI_PORT:-18088}"
snoop_port="${GATEWAY_E2E_ADMINUI_SNOOP_PORT:-18098}"
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

echo "==> writing e2e config (admin API enabled, a deliberately short UI-session max age)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "nodes": [],
  "seed_agents": [
    { "client_id": "agt-spidersnoop-backend", "client_secret": "integration-secret", "name": "spider-snoop-backend" }
  ],
  "admin_integration_client_ids": ["agt-spidersnoop-backend"],
  "spider_snoop_base_url": "${snoop_base}",
  "spider_snoop_introspection_timeout_seconds": 2,
  "spider_snoop_introspection_cache_ttl_seconds": 2,
  "admin_ui_session_max_age_seconds": 2
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

echo "==> baseline unchanged: no credential at all is still rejected"
no_cred_status=$(curl -sS -o /dev/null -w '%{http_code}' "${base}/admin/agents")
check "no cookie, no NHI token -> 401, exactly as issue #13/#15 already behave" "$no_cred_status" "401"

echo "==> the existing service-to-service NHI-token-plus-header path is untouched"
admin_token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-spidersnoop-backend" \
	--data-urlencode "client_secret=integration-secret" \
	--data-urlencode "resource=_admin")
admin_token=$(json_field "$admin_token_body" "access_token")
nhi_status=$(curl -sS -o /dev/null -w '%{http_code}' "${base}/admin/agents" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check "NHI token + human header alone (no cookie) still succeeds" "$nhi_status" "200"

echo "==> login: missing token field is rejected"
missing_token_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/admin/ui/session" -d '{}')
check "missing spider_snoop_session_token rejected" "$missing_token_status" "400"

echo "==> login: a real spider-snoop session token mints a real cookie"
cookie_jar="$work_dir/cookies.txt"
login_body=$(curl -sS -c "$cookie_jar" -X POST "${base}/admin/ui/session" \
	-d '{"spider_snoop_session_token":"a-real-spider-snoop-session-token"}')
check_contains "login response reports the introspected identity" "$login_body" '"username":"alice"'
check "a cookie was actually set" "$([[ -s "$cookie_jar" ]] && grep -q spidercob_admin_session "$cookie_jar" && echo yes || echo no)" "yes"

echo "==> whoami with the cookie succeeds"
whoami_body=$(curl -sS -b "$cookie_jar" "${base}/admin/ui/session")
check_contains "whoami reflects the logged-in admin" "$whoami_body" '"role":"admin"'

echo "==> THE DoD MOMENT: the cookie alone (no NHI bearer token at all) drives real admin operations"
cookie_agents_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" "${base}/admin/agents")
check "cookie alone succeeds on /admin/agents" "$cookie_agents_status" "200"

create_group_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" -X POST "${base}/admin/groups" \
	-d '{"name":"ui-created-group"}')
check "cookie alone can create a real group" "$create_group_status" "201"

list_groups_body=$(curl -sS -b "$cookie_jar" "${base}/admin/groups")
check_contains "the cookie-created group is really persisted" "$list_groups_body" "ui-created-group"

policies_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" "${base}/admin/policies")
check "cookie alone succeeds on /admin/policies" "$policies_status" "200"

echo "==> logout invalidates the cookie"
logout_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" -X DELETE "${base}/admin/ui/session")
check "logout succeeds" "$logout_status" "204"
after_logout_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" "${base}/admin/agents")
check "the same cookie is rejected after logout" "$after_logout_status" "401"

echo "==> a fresh session expires on its own after its configured max age, without an explicit logout"
fresh_cookie_jar="$work_dir/fresh_cookies.txt"
curl -sS -c "$fresh_cookie_jar" -X POST "${base}/admin/ui/session" \
	-d '{"spider_snoop_session_token":"another-real-token"}' >/dev/null
before_expiry_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$fresh_cookie_jar" "${base}/admin/agents")
check "session valid immediately after login" "$before_expiry_status" "200"
sleep 3
after_expiry_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$fresh_cookie_jar" "${base}/admin/agents")
check "session rejected once its 2s max age elapses, no logout called" "$after_expiry_status" "401"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "fake spider-snoop log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi
