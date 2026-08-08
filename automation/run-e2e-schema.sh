#!/usr/bin/env bash
# Real end-to-end smoke test for issue #11's schema-enforcement seam
# (Phase 3c): drives the actual compiled binary through a real stdio node
# (the same pinserver fixture run-e2e-pin.sh uses) whose one tool's
# inputSchema is the MCP go-sdk's own real, inferred schema -- not
# hand-crafted for this test -- requiring a "text" string argument and
# forbidding additional properties. Proves a tools/call with valid
# arguments succeeds, and one with missing/wrong-typed/unexpected
# arguments is rejected, once the tool has a TOFU-established pin.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_SCHEMA_PORT:-18085}"
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

json_field() {
	{ echo "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | sed -E 's/.*:"([^"]*)"/\1/'; } || true
}

mint_token() {
	local client_id="$1" secret="$2"
	local body
	body=$(curl -sS -X POST "${base}/token" \
		--data-urlencode "grant_type=client_credentials" \
		--data-urlencode "client_id=${client_id}" \
		--data-urlencode "client_secret=${secret}" \
		--data-urlencode "resource=pin_node")
	json_field "$body" "access_token"
}

echo "==> building gateway binary and pinserver fixture"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)
(cd "$repo_root" && go build -o "$work_dir/pinserver" ./internal/proxy/stdioadapter/testdata/pinserver)

desc_file="$work_dir/risky_tool_description.txt"
echo "performs a safe, read-only lookup" >"$desc_file"

echo "==> writing e2e config (real stdio node, fast pin refresh cadence)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "dev_allow_all_policy": true,
  "pin_refresh_interval_seconds": 1,
  "pin_check_interval_seconds": 1,
  "seed_agents": [
    { "client_id": "agent-full-access", "client_secret": "full-access-secret", "name": "full-access" }
  ],
  "nodes": [
    {
      "name": "pin_node",
      "transport": "stdio",
      "command": "${work_dir}/pinserver",
      "args": ["${desc_file}"]
    }
  ]
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

token=$(mint_token "agent-full-access" "full-access-secret")

init_headers="$work_dir/init_headers.txt"
curl -sS -D "$init_headers" -o /dev/null -X POST "${base}/mcp/pin_node/" \
	-H "Authorization: Bearer ${token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
session_id=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "initialize succeeds" "$([[ -n "$session_id" ]] && echo yes || echo no)" "yes"

echo "==> waiting for the background scheduler's first refresh (TOFU establishment, real inputSchema)"
sleep 3

echo "==> valid arguments (required 'text' string present): call succeeds"
valid_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/pin_node/" \
	-H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"risky_tool","arguments":{"text":"hello"}}}')
check "schema-valid call succeeds" "$valid_status" "200"

echo "==> THE DoD MOMENT: missing required argument is rejected before ever reaching the upstream"
missing_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/pin_node/" \
	-H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"risky_tool","arguments":{}}}')
missing_body=$(curl -sS -X POST "${base}/mcp/pin_node/" \
	-H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"risky_tool","arguments":{}}}')
check "missing required argument rejected (403, distinct from a policy/quarantine denial)" "$missing_status" "403"
check_contains "rejection reason names the pinned schema (story 3)" "$missing_body" "pinned schema"

echo "==> wrong-typed argument is rejected"
wrongtype_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/pin_node/" \
	-H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"risky_tool","arguments":{"text":123}}}')
check "wrong-typed argument rejected" "$wrongtype_status" "403"

echo "==> unexpected additional property is rejected (schema declares additionalProperties:false)"
extra_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/pin_node/" \
	-H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"risky_tool","arguments":{"text":"hello","unexpected":"field"}}}')
check "unexpected additional property rejected" "$extra_status" "403"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
fi
