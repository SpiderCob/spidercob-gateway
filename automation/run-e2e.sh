#!/usr/bin/env bash
# Real end-to-end smoke test, per the CLAUDE.md workflow: build the actual
# gateway binary, register a real stdio MCP server (the echoserver
# fixture), run the gateway as a real process, and drive a full session
# lifecycle against it with curl -- not go test's in-process harness. This
# catches a different class of bug than the unit/integration suite: does
# the compiled binary actually start, parse its config, bind its port, and
# serve real HTTP the way the harness assumes.
#
# Exercises: initialize (session header + cookie minted), tools/call
# (echo works, and a real secret gets redacted -- the full DLP pipeline
# through the real binary), DELETE (real teardown), and reuse-after-delete
# (rejected, not silently re-created).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_PORT:-18080}"
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

echo "==> building gateway binary"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)

echo "==> writing e2e config (real stdio MCP node: echoserver)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "nodes": [
    {
      "name": "echo",
      "transport": "stdio",
      "command": "go",
      "args": ["run", "${repo_root}/internal/proxy/stdioadapter/testdata/echoserver"]
    }
  ]
}
EOF

echo "==> starting gateway"
"$work_dir/spidercob-gateway" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!

echo "==> waiting for /healthz"
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

echo "==> initialize (new session)"
init_headers="$work_dir/init_headers.txt"
init_body=$(curl -sS -D "$init_headers" -X POST "${base}/mcp/echo/" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
session_id=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "session id minted" "$([[ -n "$session_id" ]] && echo yes || echo no)" "yes"
check "mirrored cookie set" "$(grep -qi '^Set-Cookie: spidercob_session=' "$init_headers" && echo yes || echo no)" "yes"

echo "==> tools/call: echo"
echo_body=$(curl -sS -X POST "${base}/mcp/echo/" \
	-H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"automation smoke test"}}}')
check_contains "echo tool returns what it was given" "$echo_body" "automation smoke test"

echo "==> tools/call: secret gets redacted (full DLP pipeline, real binary)"
secret_body=$(curl -sS -X POST "${base}/mcp/echo/" \
	-H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"key AKIAABCDEFGHIJKLMNOP leaked"}}}')
check_not_contains "raw AWS key not present in response" "$secret_body" "AKIAABCDEFGHIJKLMNOP"
check_contains "structural redaction marker present" "$secret_body" "[REDACTED:aws-access-key]"

echo "==> DELETE (real teardown)"
delete_status=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "${base}/mcp/echo/" \
	-H "Mcp-Session-Id: ${session_id}")
check "DELETE returns 204" "$delete_status" "204"

echo "==> reuse after DELETE is rejected"
reuse_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/echo/" \
	-H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"should not work"}}}')
check "dead session rejected with 404" "$reuse_status" "404"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
fi
