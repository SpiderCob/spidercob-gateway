#!/usr/bin/env bash
# Real end-to-end smoke test for issue #63 (design.md §10, self-hosted
# fleet control plane, Phase 1): drives the real compiled binary's
# /admin/proxies surface -- a proxy is a new principal kind alongside
# agents/humans, paired the same client_credentials-issuance way, with
# the same dual-trust admin gate. This proves the admin-facing identity
# piece for real; it does NOT touch anything tunnel/bundle-related
# (later phases) -- there is no proxy-side binary behavior to test yet,
# only "the control plane can create, list, and revoke a proxy identity."
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_PROXIES_PORT:-18106}"
snoop_port="${GATEWAY_E2E_PROXIES_SNOOP_PORT:-18116}"
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
		echo "  FAIL - $desc (expected NOT to find: $needle)"
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

echo "==> writing e2e config (admin API enabled, one integration agent)"
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

echo "==> minting a real admin-scoped NHI token"
admin_token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-spidersnoop-backend" \
	--data-urlencode "client_secret=integration-secret" \
	--data-urlencode "resource=_admin")
admin_token=$(json_field "$admin_token_body" "access_token")
check "admin token minted" "$([[ -n "$admin_token" ]] && echo yes || echo no)" "yes"

echo "==> before creation: GET /admin/proxies is empty"
initial_list=$(curl -sS "${base}/admin/proxies" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check "empty proxy list starts as []" "$initial_list" "[]"

echo "==> THE DoD MOMENT: a real proxy is created via the admin API"
create_proxy_body=$(curl -sS -X POST "${base}/admin/proxies" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token" \
	-d '{"name":"us-east-proxy"}')
proxy_client_id=$(json_field "$create_proxy_body" "client_id")
proxy_secret=$(json_field "$create_proxy_body" "secret")
check "new proxy created" "$([[ -n "$proxy_client_id" && -n "$proxy_secret" ]] && echo yes || echo no)" "yes"

echo "==> missing name is rejected"
missing_name_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/admin/proxies" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token" \
	-d '{}')
check "missing name rejected" "$missing_name_status" "400"

echo "==> created proxy appears in GET /admin/proxies, without its secret"
list_proxies_body=$(curl -sS "${base}/admin/proxies" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check_contains "created proxy appears in the list" "$list_proxies_body" "us-east-proxy"
check_contains "created proxy's client_id appears" "$list_proxies_body" "$proxy_client_id"
check_not_contains "the list response never carries the secret" "$list_proxies_body" "$proxy_secret"

echo "==> request missing the human-session header is rejected (same dual-trust gate as agents)"
missing_human_status=$(curl -sS -o /dev/null -w '%{http_code}' "${base}/admin/proxies" \
	-H "Authorization: Bearer ${admin_token}")
check "missing human-session header rejected" "$missing_human_status" "401"

echo "==> revoking an unknown proxy is rejected"
unknown_revoke_status=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "${base}/admin/proxies/never-existed" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check "revoking an unknown proxy is 404" "$unknown_revoke_status" "404"

echo "==> revoking the real proxy succeeds and is reflected in the list"
revoke_status=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "${base}/admin/proxies/${proxy_client_id}" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check "proxy revoked" "$revoke_status" "204"

after_revoke_body=$(curl -sS "${base}/admin/proxies" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check_contains "revoked proxy shows a revoked_at timestamp" "$after_revoke_body" '"revoked_at"'

echo "==> revoking the same proxy again is idempotent (still 204, not an error)"
idempotent_revoke_status=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "${base}/admin/proxies/${proxy_client_id}" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check "idempotent re-revoke still 204" "$idempotent_revoke_status" "204"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "fake spider-snoop log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi
