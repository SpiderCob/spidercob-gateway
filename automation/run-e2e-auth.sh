#!/usr/bin/env bash
# Real end-to-end smoke test for issue #3 (Phase 2a identity & authserver
# core): build the actual gateway binary, run it as a real process with its
# real, unmodified defaults (no dev_allow_all_policy escape hatch -- that's
# run-e2e.sh's job, and it's explicitly not what this script is proving),
# and drive the full mint -> use -> expire lifecycle against it with curl.
#
# There's no admin API yet (Phase 4) to register an NHI over HTTP, so this
# mints via a config-seeded agent credential (config.SeedAgents) -- see its
# doc comment in internal/config/config.go.
#
# Exercises: unauthenticated request -> 401 + WWW-Authenticate pointing at
# RFC 9728 metadata; JWKS and protected-resource metadata are actually
# served; client_credentials mint; a valid token reaches the policy layer
# (403 DenyAll, not 401 -- proving auth succeeded, not that access is
# granted, which Phase 3 still owns); a token minted for one node is
# rejected against another (confused-deputy protection); and a
# deliberately-short-TTL token, valid at first use, is rejected once it
# actually expires -- the "expire" half of "mint -> use -> expire-or-revoke"
# (issue #3's Testing Decisions). jti revocation has no HTTP surface yet
# either (Phase 4), so it's covered by internal/authserver's Go test suite
# instead, not here.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_AUTH_PORT:-18081}"
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

extract_json_field() {
	# Minimal, dependency-free extraction: works for this script's flat,
	# single-line JSON responses -- not a general JSON parser.
	echo "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | sed -E 's/.*:"([^"]*)"/\1/'
}

echo "==> building gateway binary"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)

echo "==> writing e2e config (real defaults: DenyAll, no dev escape hatch)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${port}",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "${work_dir}/spidercob.db",
  "nhi_token_ttl_seconds": 2,
  "seed_agents": [
    { "client_id": "e2e-auth-agent", "client_secret": "e2e-auth-secret-not-for-production", "name": "run-e2e-auth.sh" }
  ],
  "nodes": [
    { "name": "jira", "upstream_url": "http://127.0.0.1:${port}/does-not-need-to-resolve" },
    { "name": "other-node", "upstream_url": "http://127.0.0.1:${port}/does-not-need-to-resolve" }
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

echo "==> unauthenticated request rejected with 401 + WWW-Authenticate"
unauth_headers="$work_dir/unauth_headers.txt"
unauth_status=$(curl -sS -o /dev/null -D "$unauth_headers" -w '%{http_code}' -X POST "${base}/mcp/jira/" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "missing bearer token rejected with 401" "$unauth_status" "401"
check_contains "WWW-Authenticate points at RFC 9728 metadata" \
	"$(cat "$unauth_headers")" "/.well-known/oauth-protected-resource/jira"

echo "==> JWKS is served"
jwks_body=$(curl -sS "${base}/.well-known/jwks.json")
check_contains "JWKS advertises an Ed25519 (OKP) key" "$jwks_body" '"crv":"Ed25519"'

echo "==> RFC 9728 protected-resource metadata is served per node"
prm_body=$(curl -sS "${base}/.well-known/oauth-protected-resource/jira")
check_contains "metadata names this node's canonical resource URI" "$prm_body" "\"resource\":\"http://127.0.0.1:${port}/mcp/jira\""

echo "==> mint a node-scoped access token (client_credentials, seeded agent)"
token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=e2e-auth-agent" \
	--data-urlencode "client_secret=e2e-auth-secret-not-for-production" \
	--data-urlencode "resource=jira")
access_token=$(extract_json_field "$token_body" "access_token")
check "access token minted" "$([[ -n "$access_token" ]] && echo yes || echo no)" "yes"

echo "==> wrong client secret rejected"
bad_token_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=e2e-auth-agent" \
	--data-urlencode "client_secret=totally-wrong" \
	--data-urlencode "resource=jira")
check "wrong client_secret rejected with 401" "$bad_token_status" "401"

echo "==> valid token reaches the policy layer (403 DenyAll, not 401 -- proves auth succeeded)"
authed_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/jira/" \
	-H "Authorization: Bearer ${access_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "valid token + real DenyAll default = 403, not 401" "$authed_status" "403"

echo "==> a token minted for jira is rejected against other-node (confused-deputy protection)"
wrong_aud_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/other-node/" \
	-H "Authorization: Bearer ${access_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "wrong-audience token rejected with 401" "$wrong_aud_status" "401"

echo "==> token expires: valid now, rejected once its 2s TTL elapses"
sleep 3
expired_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${base}/mcp/jira/" \
	-H "Authorization: Bearer ${access_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "expired token rejected with 401" "$expired_status" "401"

echo "==> re-minting after expiry just works (no refresh grant needed, story 16)"
token_body2=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=e2e-auth-agent" \
	--data-urlencode "client_secret=e2e-auth-secret-not-for-production" \
	--data-urlencode "resource=jira")
access_token2=$(extract_json_field "$token_body2" "access_token")
check "re-exchange with the same client_credentials mints a fresh token" "$([[ -n "$access_token2" ]] && echo yes || echo no)" "yes"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
fi
