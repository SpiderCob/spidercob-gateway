#!/usr/bin/env bash
# Real end-to-end smoke test for issue #52's "spidercob connect" local
# sidecar: builds the real binary, starts a real gateway (seeded NHI
# agent, two real stdio nodes, real policy grants, and a deliberately
# short nhi_token_ttl_seconds), starts the *same binary's* `connect`
# subcommand pointed at it, and drives real MCP traffic through the
# local sidecar with NO Authorization header from the caller at all --
# proving the sidecar itself is what's attaching a valid, node-scoped
# credential. Also proves the one property unique to this feature: a
# request made *after* the original token would have expired still
# succeeds unattended, through the same still-running process -- the
# real, timed proof that the background refresh loop genuinely works,
# not just that the initial mint did.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gw_port="${GATEWAY_E2E_CONNECT_GW_PORT:-18810}"
connect_port="${GATEWAY_E2E_CONNECT_PORT:-18811}"
gw_base="http://127.0.0.1:${gw_port}"
connect_base="http://127.0.0.1:${connect_port}"
short_ttl_seconds=3

work_dir="$(mktemp -d)"
gw_pid=""
connect_pid=""

cleanup() {
	if [[ -n "$connect_pid" ]] && kill -0 "$connect_pid" 2>/dev/null; then
		kill "$connect_pid" 2>/dev/null || true
		wait "$connect_pid" 2>/dev/null || true
	fi
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

session_id_from_headers() {
	grep -i '^Mcp-Session-Id:' "$1" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n'
}

echo "==> building the real gateway binary (spidercob connect is a subcommand of this same binary)"
(cd "$repo_root" && go build -o "$work_dir/spidercob" ./cmd/spidercob)

echo "==> writing e2e config -- two real stdio nodes, a real agent granted both, a deliberately short token TTL"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${gw_port}",
  "issuer": "http://127.0.0.1:${gw_port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "nhi_token_ttl_seconds": ${short_ttl_seconds},
  "seed_agents": [
    { "client_id": "connect-agent", "client_secret": "connect-agent-secret", "name": "connect-agent", "groups": ["full-access"] }
  ],
  "policies": [
    { "group": "full-access", "node": "echo-a", "rule_type": "allow" },
    { "group": "full-access", "node": "echo-b", "rule_type": "allow" }
  ],
  "nodes": [
    { "name": "echo-a", "transport": "stdio", "command": "go", "args": ["run", "${repo_root}/internal/proxy/stdioadapter/testdata/echoserver"] },
    { "name": "echo-b", "transport": "stdio", "command": "go", "args": ["run", "${repo_root}/internal/proxy/stdioadapter/testdata/echoserver"] }
  ]
}
EOF

echo "==> starting the real gateway"
"$work_dir/spidercob" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gw_pid=$!
for _ in $(seq 1 50); do
	if curl -sf "${gw_base}/healthz" >/dev/null 2>&1; then
		break
	fi
	sleep 0.2
done
if ! curl -sf "${gw_base}/healthz" >/dev/null 2>&1; then
	echo "gateway never became healthy; log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
fi

echo "==> starting the real connect sidecar, proxying both nodes"
"$work_dir/spidercob" connect \
	-gateway "$gw_base" \
	-client-id connect-agent \
	-client-secret connect-agent-secret \
	-node echo-a -node echo-b \
	-listen "127.0.0.1:${connect_port}" \
	>"$work_dir/connect.log" 2>&1 &
connect_pid=$!
for _ in $(seq 1 50); do
	if curl -sf -o /dev/null -X POST "${connect_base}/mcp/echo-a/" -d '{}' 2>/dev/null; then
		break
	fi
	if ! kill -0 "$connect_pid" 2>/dev/null; then
		echo "connect sidecar exited early; log:" >&2
		cat "$work_dir/connect.log" >&2
		exit 1
	fi
	sleep 0.2
done

echo "==> a real MCP session through the sidecar for node echo-a -- caller presents NO Authorization header at all"
init_headers="$work_dir/init_headers_a.txt"
init_body=$(curl -sS -D "$init_headers" -X POST "${connect_base}/mcp/echo-a/" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
session_a=$(session_id_from_headers "$init_headers")
check "echo-a: real session established with no caller credential" "$([[ -n "$session_a" ]] && echo yes || echo no)" "yes"

call_body=$(curl -sS -X POST "${connect_base}/mcp/echo-a/" -H "Mcp-Session-Id: ${session_a}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"via connect, node echo-a"}}}')
check_contains "echo-a: real tools/call succeeds through the sidecar" "$call_body" "via connect, node echo-a"

echo "==> node echo-b through the SAME running sidecar -- proves multi-node, independently-scoped tokens"
init_headers_b="$work_dir/init_headers_b.txt"
curl -sS -D "$init_headers_b" -o /dev/null -X POST "${connect_base}/mcp/echo-b/" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
session_b=$(session_id_from_headers "$init_headers_b")
check "echo-b: real session established through the same sidecar instance" "$([[ -n "$session_b" ]] && echo yes || echo no)" "yes"

call_body_b=$(curl -sS -X POST "${connect_base}/mcp/echo-b/" -H "Mcp-Session-Id: ${session_b}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"via connect, node echo-b"}}}')
check_contains "echo-b: real tools/call succeeds through the same sidecar" "$call_body_b" "via connect, node echo-b"

echo "==> an unconfigured node returns a clear 404 from the sidecar itself, never a confusing pass-through"
unknown_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${connect_base}/mcp/not-configured/" -d '{}')
check "unconfigured node -> 404" "$unknown_status" "404"

echo "==> THE DoD MOMENT: waiting past the real (short) token TTL, then making another request through the SAME still-running sidecar, unattended"
sleep $((short_ttl_seconds + 2))
init_headers_late="$work_dir/init_headers_late.txt"
curl -sS -D "$init_headers_late" -o /dev/null -X POST "${connect_base}/mcp/echo-a/" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
session_late=$(session_id_from_headers "$init_headers_late")
check "a request after the original token's real expiry still succeeds -- proves the background refresh loop genuinely re-minted it unattended" \
	"$([[ -n "$session_late" ]] && echo yes || echo no)" "yes"

call_body_late=$(curl -sS -X POST "${connect_base}/mcp/echo-a/" -H "Mcp-Session-Id: ${session_late}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"after real token expiry, still works"}}}')
check_contains "post-expiry tools/call succeeds" "$call_body_late" "after real token expiry, still works"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "connect sidecar log:" >&2
	cat "$work_dir/connect.log" >&2
	exit 1
fi
