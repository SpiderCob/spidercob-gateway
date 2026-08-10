#!/usr/bin/env bash
# Real end-to-end smoke test for issue #23's hash-chained audit trail
# (Phase 4c-4), against the real compiled binary: real admin operations
# through the full dual-trust gate leave real, persisted audit_log rows
# -- proven by opening the actual store_db_path file directly (via the
# real verifychain fixture, not a mock) since no HTTP endpoint exposes
# audit records yet (out of scope for this issue). Also proves a
# rejected/unauthenticated request leaves no record, and -- the real
# tamper-evidence proof, not just "Verify runs" -- directly corrupts one
# row in the SQLite file (via the real corruptrow fixture) and confirms
# verification now fails and names that record.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_AUDIT_PORT:-18091}"
snoop_port="${GATEWAY_E2E_AUDIT_SNOOP_PORT:-18100}"
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

echo "==> building gateway binary, fake-spider-snoop, verifychain, and corruptrow fixtures"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)
(cd "$repo_root" && go build -o "$work_dir/fakespidersnoop" ./internal/adminapi/testdata/fakespidersnoop)
(cd "$repo_root" && go build -o "$work_dir/verifychain" ./internal/audit/testdata/verifychain)
(cd "$repo_root" && go build -o "$work_dir/corruptrow" ./internal/audit/testdata/corruptrow)

echo "==> starting fake spider-snoop (stands in for GET /api/users/me)"
"$work_dir/fakespidersnoop" ":${snoop_port}" >"$work_dir/snoop.log" 2>&1 &
snoop_pid=$!
for _ in $(seq 1 50); do
	if curl -sf "${snoop_base}/api/users/me" >/dev/null 2>&1; then
		break
	fi
	sleep 0.2
done

echo "==> writing e2e config (admin API enabled)"
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

echo "==> a rejected, unauthenticated request first -- must leave no audit record"
rejected_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/admin/agents" -d '{"name":"should-not-exist"}')
check "unauthenticated create attempt rejected" "$rejected_status" "401"

echo "==> minting a real admin-scoped NHI token and performing real admin operations"
admin_token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-spidersnoop-backend" \
	--data-urlencode "client_secret=integration-secret" \
	--data-urlencode "resource=_admin")
admin_token=$(echo "$admin_token_body" | grep -o '"access_token":"[^"]*"' | head -1 | sed -E 's/.*:"([^"]*)"/\1/')
check "admin token minted" "$([[ -n "$admin_token" ]] && echo yes || echo no)" "yes"

create_agent_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/admin/agents" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token" \
	-d '{"name":"ci-bot"}')
check "create_agent succeeded" "$create_agent_status" "201"

create_group_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/admin/groups" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token" \
	-d '{"name":"engineering"}')
check "create_group succeeded" "$create_group_status" "201"

delete_group_status=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "${base}/admin/groups/engineering" \
	-H "Authorization: Bearer ${admin_token}" \
	-H "X-Spidercob-Admin-Session: whatever-spider-snoop-session-token")
check "delete_group succeeded" "$delete_group_status" "204"

echo "==> stopping the gateway so the store file is quiescent for direct inspection"
kill "$gw_pid" 2>/dev/null || true
wait "$gw_pid" 2>/dev/null || true
gw_pid=""

echo "==> THE DoD MOMENT (part 1): three real admin operations left three real, chained audit records"
verify_output=$("$work_dir/verifychain" "$work_dir/spidercob.db")
echo "$verify_output" | sed 's/^/    /'
check_contains "exactly 3 audit records (not 4 -- the rejected attempt left none)" "$verify_output" "record_count=3"
check_contains "the real chain verifies cleanly" "$verify_output" "verify=pass"

echo "==> THE DoD MOMENT (part 2): a direct, on-disk row alteration is actually caught"
"$work_dir/corruptrow" "$work_dir/spidercob.db" 2 >/dev/null
tampered_output=$("$work_dir/verifychain" "$work_dir/spidercob.db" || true)
echo "$tampered_output" | sed 's/^/    /'
check_contains "tampered chain fails verification" "$tampered_output" "verify=fail"
check_contains "the failure identifies the tampered record (index 1, the second of three)" "$tampered_output" "record 1"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "fake spider-snoop log:" >&2
	cat "$work_dir/snoop.log" >&2
	exit 1
fi
