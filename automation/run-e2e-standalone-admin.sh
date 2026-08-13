#!/usr/bin/env bash
# Real end-to-end smoke test for issue #43 (standalone admin login): the
# one thing no e2e script in this repo has ever actually proven --
# a real compiled binary started with ZERO spider-snoop configuration
# anywhere in it (no spider_snoop_base_url, no
# admin_integration_client_ids, no seed_agents at all) still has a
# reachable, real admin surface. A config-seeded local admin (the
# existing issue #21 SeedUsers + groups mechanism, unchanged) logs in
# for real, drives real admin operations through the real compiled
# binary, and the result lands in the real audit trail exactly like a
# spider-snoop-backed session's would.
#
# Also proves the two negative cases that make this a real access
# control, not a rubber stamp: a real user with a wrong password, and a
# real user with the *correct* password who simply isn't in the
# designated admin group, are both rejected with the identical
# non-enumerable message -- and that the service-to-service NHI-token-
# plus-header path has no way to reach admin at all in this deployment
# shape (no admin-scoped NHI credential exists to mint one with).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_STANDALONE_ADMIN_PORT:-18700}"
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

echo "==> writing a real seed_users CSV -- alice in the admin group, bob is not"
cat >"$work_dir/seed_users.csv" <<EOF
username,password,groups
alice,s3cret-pw,admin
bob,s3cret-pw,engineering
EOF

echo "==> writing e2e config -- NO spider-snoop configuration anywhere (the whole point)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "local_admin_group": "admin",
  "seed_users_csv_path": "${work_dir}/seed_users.csv",
  "nodes": [
    { "name": "echo", "transport": "stdio", "command": "${work_dir}/echoserver" }
  ]
}
EOF

echo "==> starting gateway"
"$work_dir/spidercob-gateway" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!
wait_healthy

echo "==> the login screen's auth-mode check reports local, not spider_snoop"
auth_mode_body=$(curl -sS "${base}/admin/ui/auth-mode")
check_contains "auth-mode reports local" "$auth_mode_body" '"mode":"local"'

echo "==> a real user with the CORRECT password but NOT in the admin group is rejected"
not_admin_resp=$(curl -sS -w '\n%{http_code}' -X POST "${base}/admin/ui/session" \
	-d '{"username":"bob","password":"s3cret-pw"}')
not_admin_status=$(tail -n1 <<<"$not_admin_resp")
not_admin_body=$(sed '$d' <<<"$not_admin_resp")
check "correct password, wrong group -> 401" "$not_admin_status" "401"

echo "==> a real user with a WRONG password is rejected with the identical message"
wrong_password_resp=$(curl -sS -w '\n%{http_code}' -X POST "${base}/admin/ui/session" \
	-d '{"username":"alice","password":"not-the-real-password"}')
wrong_password_status=$(tail -n1 <<<"$wrong_password_resp")
wrong_password_body=$(sed '$d' <<<"$wrong_password_resp")
check "wrong password -> 401" "$wrong_password_status" "401"
check "wrong-password and wrong-group errors are non-enumerable (identical body)" "$wrong_password_body" "$not_admin_body"

echo "==> THE DoD MOMENT: a real local admin login succeeds with zero spider-snoop anywhere"
cookie_jar="$work_dir/cookies.txt"
login_status=$(curl -sS -o /dev/null -w '%{http_code}' -c "$cookie_jar" -X POST "${base}/admin/ui/session" \
	-d '{"username":"alice","password":"s3cret-pw"}')
check "correct password, in admin group -> 201" "$login_status" "201"
check "a cookie was actually set" "$([[ -s "$cookie_jar" ]] && grep -q spidercob_admin_session "$cookie_jar" && echo yes || echo no)" "yes"

whoami_body=$(curl -sS -b "$cookie_jar" "${base}/admin/ui/session")
check_contains "whoami reflects alice" "$whoami_body" '"username":"alice"'
check_contains "whoami reflects admin role" "$whoami_body" '"role":"admin"'

echo "==> a real admin operation succeeds through the real compiled binary via this cookie alone"
create_body=$(curl -sS -b "$cookie_jar" -X POST "${base}/admin/agents" -d '{"name":"standalone-test-agent"}')
check_contains "agent created via the local-admin cookie" "$create_body" '"name":"standalone-test-agent"'

list_body=$(curl -sS -b "$cookie_jar" "${base}/admin/agents")
check_contains "the created agent appears in GET /admin/agents" "$list_body" "standalone-test-agent"

echo "==> that real operation lands in the real audit trail, same as any other admin action"
audit_body=$(curl -sS -b "$cookie_jar" "${base}/admin/audit")
check_contains "create_agent recorded" "$audit_body" '"action":"create_agent"'
check_contains "actor is alice" "$audit_body" '"actor_human_username":"alice"'

echo "==> the service-to-service NHI-token-plus-header path has no way to reach admin here"
# No seed_agents at all in this config -- there is no NHI credential in
# existence to even attempt minting an admin-scoped token with.
admin_token_resp=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=nonexistent-agent" \
	--data-urlencode "client_secret=whatever" \
	--data-urlencode "resource=_admin")
check_contains "minting an admin NHI token fails (no such credential exists)" "$admin_token_resp" "invalid_client"

no_cred_status=$(curl -sS -o /dev/null -w '%{http_code}' "${base}/admin/agents")
check "no credentials at all -> 401" "$no_cred_status" "401"

echo "==> logout invalidates the session"
logout_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" -X DELETE "${base}/admin/ui/session")
check "logout -> 204" "$logout_status" "204"
post_logout_status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" "${base}/admin/agents")
check "the same cookie is rejected after logout" "$post_logout_status" "401"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
fi
