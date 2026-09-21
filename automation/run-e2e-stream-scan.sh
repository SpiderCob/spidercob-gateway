#!/usr/bin/env bash
# Real end-to-end smoke test for issue #55/#61 (windowed streaming/SSE
# response scanning): drives the actual compiled gateway binary against
# a real, separate streamable_http upstream process (internal/proxy/
# testdata/sseupstream), through real curl requests -- not the in-process
# httptest fixtures internal/proxy's own unit/integration tests already
# use. Five properties, each needing the real compiled binary + a real
# TCP round trip to actually prove:
#
#   1. a secret split across a real chunk boundary is still redacted
#      (the core DLP-safety claim);
#   2. the response is genuinely delivered incrementally, not buffered
#      and sent as one blob -- proven by time-to-first-byte being far
#      shorter than total request time against a deliberately slow
#      two-chunk stream;
#   3. a stream that would otherwise run forever is cut off at the
#      response size cap -- proven by real received-byte-count bounds
#      and real elapsed time well under curl's own timeout.
#   4. a high-entropy unnamed-secret token split across a real chunk
#      boundary is still flagged (issue #61), and reaches the client
#      byte-for-byte unmodified -- EntropyScanner is flag-only.
#   5. a prompt-injection phrase split across a real chunk boundary is
#      still flagged (issue #61), and likewise reaches the client
#      unmodified -- InjectionScanner is flag-only.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_STREAM_PORT:-18086}"
upstream_port="${GATEWAY_E2E_STREAM_UPSTREAM_PORT:-18087}"
base="http://127.0.0.1:${port}"

work_dir="$(mktemp -d)"
gw_pid=""
upstream_pid=""

cleanup() {
	for pid in "$gw_pid" "$upstream_pid"; do
		if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
		fi
	done
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

check_true() {
	local desc="$1" cond="$2"
	if [[ "$cond" == "true" ]]; then
		echo "  ok   - $desc"
		pass=$((pass + 1))
	else
		echo "  FAIL - $desc"
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

echo "==> building gateway binary and real SSE upstream fixture"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)
(cd "$repo_root" && go build -o "$work_dir/sseupstream" ./internal/proxy/testdata/sseupstream)

echo "==> starting real SSE upstream"
"$work_dir/sseupstream" ":${upstream_port}" >"$work_dir/upstream.log" 2>&1 &
upstream_pid=$!
sleep 0.2

echo "==> writing e2e config (real streamable_http node, full-access policy)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "seed_agents": [
    { "client_id": "agent-full-access", "client_secret": "full-access-secret", "name": "full-access", "groups": ["full-access"] }
  ],
  "policies": [
    { "group": "full-access", "node": "streamy", "rule_type": "allow" }
  ],
  "nodes": [
    { "name": "streamy", "transport": "streamable_http", "upstream_url": "http://127.0.0.1:${upstream_port}" }
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

echo "==> minting token and establishing a session"
token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agent-full-access" \
	--data-urlencode "client_secret=full-access-secret" \
	--data-urlencode "resource=streamy")
token=$(json_field "$token_body" "access_token")

init_headers="$work_dir/init_headers.txt"
curl -sS -D "$init_headers" -o /dev/null -X POST "${base}/mcp/streamy/" \
	-H "Authorization: Bearer ${token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
session_id=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check_true "session established" "$([[ -n "$session_id" ]] && echo true || echo false)"

echo "==> 1: a secret split across a real chunk boundary is redacted, not leaked"
tail_log_body=$(curl -sS -X POST "${base}/mcp/streamy/" \
	-H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tail_log"}}')
# Built by concatenation, not one contiguous literal, so this repo's own
# dlp-scan pre-commit hook doesn't flag this fake-AWS-key-shaped test
# fixture as a real leaked credential (CONTEXT.md's issue #52 precedent).
fake_aws_key="AKIAABCDE""FGHIJKLMNOP"
check_true "no raw secret in the response" "$([[ "$tail_log_body" != *"${fake_aws_key}"* ]] && echo true || echo false)"
check_contains "structural redaction marker present" "$tail_log_body" "[REDACTED:aws-access-key]"

echo "==> 2: the response is genuinely streamed, not buffered-then-sent"
timing=$(curl -sS -o "$work_dir/slow_stream.out" \
	-w '%{time_starttransfer} %{time_total}' \
	-X POST "${base}/mcp/streamy/" \
	-H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"slow_stream"}}')
ttfb=$(echo "$timing" | awk '{print $1}')
total=$(echo "$timing" | awk '{print $2}')
# The upstream sleeps 800ms between its two chunks. A genuinely streamed
# response has already delivered its first byte(s) well before that
# pause finishes; a buffered-then-sent response would show time to
# first byte roughly equal to total time, since nothing reaches the
# client until the whole thing (including the pause) is done.
ttfb_ok=$(awk -v t="$ttfb" 'BEGIN { print (t < 0.4) ? "true" : "false" }')
total_ok=$(awk -v t="$total" 'BEGIN { print (t > 0.7) ? "true" : "false" }')
check_true "time-to-first-byte (${ttfb}s) is well under the 800ms pause" "$ttfb_ok"
check_true "total request time (${total}s) reflects the full pause" "$total_ok"

echo "==> 3: a runaway stream is cut off at the response size cap, not left to run forever"
cap_start=$(date +%s.%N)
set +e
curl -sS --max-time 10 -o "$work_dir/never_stop.out" \
	-X POST "${base}/mcp/streamy/" \
	-H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"never_stop"}}'
set -e
cap_end=$(date +%s.%N)
cap_elapsed=$(awk -v a="$cap_start" -v b="$cap_end" 'BEGIN { print b - a }')
received_bytes=$(wc -c <"$work_dir/never_stop.out" | tr -d ' ')

# The gateway's response-size cap is 10 MiB. Bytes received should land
# just above it (one read's worth of overshoot, not unbounded) and the
# request should finish in well under curl's 10s --max-time -- proof
# the *gateway*, not curl's own timeout, ended the connection.
bytes_ok=$(awk -v n="$received_bytes" 'BEGIN { mib = 1024*1024; print (n > 5*mib && n < 11*mib) ? "true" : "false" }')
elapsed_ok=$(awk -v s="$cap_elapsed" 'BEGIN { print (s < 5) ? "true" : "false" }')
check_true "received ~10 MiB, not unbounded (got ${received_bytes} bytes)" "$bytes_ok"
check_true "connection ended promptly (${cap_elapsed}s), the gateway cut it off, not curl's own timeout" "$elapsed_ok"

echo "==> 4: a high-entropy token split across a real chunk boundary is flagged, not redacted"
entropy_body=$(curl -sS -X POST "${base}/mcp/streamy/" \
	-H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"high_entropy_split"}}')
fake_high_entropy_token="qX7z2mKpL9wR4vT8nY1sB6cJ0hF3dG5a"
check_contains "flag-only: the token itself still reaches the client unmodified" "$entropy_body" "$fake_high_entropy_token"

echo "==> 5: a prompt-injection phrase split across a real chunk boundary is flagged, not redacted"
injection_body=$(curl -sS -X POST "${base}/mcp/streamy/" \
	-H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"injection_split"}}')
check_contains "flag-only: the phrase itself still reaches the client unmodified" "$injection_body" "ignore previous instructions"

metrics_body=$(curl -sS "${base}/metrics")
check_contains "spidercob_streamed_responses_total metric present" "$metrics_body" "spidercob_streamed_responses_total"
check_contains "spidercob_stream_cap_exceeded_total metric present" "$metrics_body" "spidercob_stream_cap_exceeded_total"
# Exact-value checks, not just substring presence -- a windowedFlagger
# that double-flagged (e.g. a "flag once" regression) would still pass a
# bare check_contains here, since the metric line would just carry a
# larger number under the same label set.
entropy_flag_line=$(echo "$metrics_body" | grep -F 'spidercob_scan_verdicts_total{scanner="entropy",action="flag",direction="response",node="streamy"}' || true)
injection_flag_line=$(echo "$metrics_body" | grep -F 'spidercob_scan_verdicts_total{scanner="injection-heuristics",action="flag",direction="response",node="streamy"}' || true)
check "entropy scanner flagged the streamed response exactly once" "$(echo "$entropy_flag_line" | awk '{print $2}')" "1"
check "injection scanner flagged the streamed response exactly once" "$(echo "$injection_flag_line" | awk '{print $2}')" "1"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	echo "upstream log:" >&2
	cat "$work_dir/upstream.log" >&2
	exit 1
fi
