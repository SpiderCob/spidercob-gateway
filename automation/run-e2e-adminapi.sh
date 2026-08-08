#!/usr/bin/env bash
# Real end-to-end smoke test for issue #13's admin API (Phase 4): drives
# the actual compiled binary through the real /admin/* surface -- a real
# NHI token minted via the compiled binary's own /token endpoint
# (resource=_admin), plus a real (fixture, not spider-snoop itself) HTTP
# server standing in for spider-snoop's GET /api/users/me -- not
# simulated with in-process mocks only. Proves the full dual-trust flow:
# service-to-service NHI token + live human-session introspection, both
# required, and real admin operations (create agent, create group, assign
# membership, replace policy) with store-visible effects afterward.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_ADMINAPI_PORT:-18086}"
snoop_port="${GATEWAY_E2E_ADMINAPI_SNOOP_PORT:-18096}"
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

echo "==> writing e2e config (admin API enabled, one integration agent, one non-integration agent)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "nodes": [],
  "seed_agents": [
    { "client_id": "agt-spidersnoop-backend", "client_secret": "integration-secret", "name": "spider-snoop-backend" },
    { "client_id": "agt-not-allowlisted", "client_secret": "other-secret", "name": "some-other-service" }
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

echo "==> non-allowlisted agent cannot mint an admin-scoped token"
denied_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-not-allowlisted" \
	--data-urlencode "client_secret=other-secret" \
	--data-urlencode "resource=_admin")
check "non-allowlisted agent rejected for the admin resource" "$denied_status" "401"

echo "==> minting a real admin-scoped NHI token for the integration agent"
admin_token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-spidersnoop-backend" \
	--data-urlencode "client_secret=integration-secret" \
	--data-urlencode "resource=_admin")
admin_token=$(json_field "$admin_token_body" "access_token")
check "admin token minted" "$([[ -n "$admin_token" ]] && echo yes || echo no)" "yes"

echo "==> request missing the human-session header is rejected"
missing_human_status=$(curl -sS -o /dev/null -w '%{http_code}' "${base}/admin/agents" \
	-H "Authorization: Bearer ${admin_token}")
check "missing human-session header rejected" "$missing_human_status" "401"

echo "==> THE DoD MOMENT: a real admin operation succeeds through the full dual-trust gate"
create_agent_body=$(curl -sS -X POST "${base}/admin/agents" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token" \
	-d '{"name":"ci-bot"}')
new_client_id=$(json_field "$create_agent_body" "client_id")
new_secret=$(json_field "$create_agent_body" "secret")
check "new agent created via the admin API" "$([[ -n "$new_client_id" && -n "$new_secret" ]] && echo yes || echo no)" "yes"

list_agents_body=$(curl -sS "${base}/admin/agents" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check_contains "created agent appears in GET /admin/agents" "$list_agents_body" "ci-bot"

echo "==> create a group and assign the new agent to it"
create_group_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/admin/groups" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token" \
	-d '{"name":"engineering"}')
check "group created" "$create_group_status" "201"

add_member_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/admin/groups/engineering/members" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token" \
	-d "{\"type\":\"agent\",\"identifier\":\"${new_client_id}\"}")
check "agent assigned to group" "$add_member_status" "204"

echo "==> replace policy and confirm it round-trips through GET /admin/policies"
replace_policy_status=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "${base}/admin/policies" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token" \
	-d '[{"group":"engineering","node":"jira","rule_type":"allow"}]')
check "policies replaced" "$replace_policy_status" "204"

list_policies_body=$(curl -sS "${base}/admin/policies" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check_contains "replaced policy visible via GET /admin/policies" "$list_policies_body" '"node":"jira"'
check_contains "replaced policy names the right group" "$list_policies_body" '"group":"engineering"'

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "fake spider-snoop log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi
