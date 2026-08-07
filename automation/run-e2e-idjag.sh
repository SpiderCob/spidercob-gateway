#!/usr/bin/env bash
# Real end-to-end interop test for issue #5 (Phase 2b): the actual
# three-legged RFC 7523/8693 flow interop/README.md documents, driven
# against a real Keycloak container and the real compiled gateway binary --
# not simulated, not mocked. This is Phase 0's interop harness
# (deploy/docker-compose.yml's keycloak service) finally exercised for
# real, per the "build this before the product's auth code, every interop
# bug found now is a design fix, found later a rewrite" principle in
# interop/README.md.
#
# Leg 1 (Keycloak, password grant): alice signs into the agent-app client,
#   getting a real access token.
# Leg 2 (Keycloak, RFC 8693 token exchange): agent-app exchanges that
#   access token for an ID-JAG, audience-bound to this gateway.
# Leg 3 (this gateway, RFC 7523 JWT-bearer grant): the ID-JAG is presented
#   to the real compiled gateway's /token; the gateway validates it against
#   its own JWKS fetch from Keycloak (internal/idptrust) and mints a real
#   node-scoped access token.
#
# Realm/client/user setup is scripted here via Keycloak's own Admin REST
# API (not a static realm-export.json) -- imperative curl calls are far
# easier to debug against a real, possibly-version-drifted server than a
# realm import that fails silently. If any step here stops matching
# Keycloak's actual current behavior, that mismatch IS the interop bug
# this harness exists to catch -- fix this script, not the assumption.
#
# Needs Docker (deploy/docker-compose.yml's keycloak service) -- this is
# `make ci-interop`, a separate, required-but-not-unconditional layer from
# `make ci` (which doesn't need Docker). See automation/README.md.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gw_port="${GATEWAY_E2E_IDJAG_PORT:-18082}"
gw_base="http://127.0.0.1:${gw_port}"
kc_port="${KEYCLOAK_E2E_PORT:-8081}"
kc_base="http://127.0.0.1:${kc_port}"
kc_realm="spidercob-interop"

work_dir="$(mktemp -d)"
gw_pid=""
compose_started=0

cleanup() {
	if [[ -n "$gw_pid" ]] && kill -0 "$gw_pid" 2>/dev/null; then
		kill "$gw_pid" 2>/dev/null || true
		wait "$gw_pid" 2>/dev/null || true
	fi
	if [[ "$compose_started" -eq 1 ]]; then
		(cd "$repo_root/deploy" && docker compose down >/dev/null 2>&1 || true)
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

check_nonempty() {
	local desc="$1" got="$2"
	if [[ -n "$got" ]]; then
		echo "  ok   - $desc"
		pass=$((pass + 1))
	else
		echo "  FAIL - $desc (got empty value)"
		fail=$((fail + 1))
	fi
}

json_field() {
	# Minimal, dependency-free extraction for this script's flat JSON
	# responses -- not a general JSON parser. "No match" (e.g. an error
	# response with no access_token field) is an expected, checkable
	# outcome here, not a script-ending error -- `|| true` stops that case
	# from tripping `set -o pipefail` and aborting the whole script before
	# the caller ever gets to look at what came back.
	{ echo "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | sed -E 's/.*:"([^"]*)"/\1/'; } || true
}

decode_jwt_claims() {
	# Prints a JWT's claims (2nd segment) as JSON, padding base64url as
	# needed -- for capturing vectors and asserting on claim values with
	# json_field, same spirit as interop/README.md §4's "decode and save."
	local jwt="$1" payload
	payload=$(echo "$jwt" | cut -d. -f2 | tr '_-' '/+')
	case $((${#payload} % 4)) in
	2) payload="${payload}==" ;;
	3) payload="${payload}=" ;;
	esac
	echo "$payload" | base64 -d 2>/dev/null
}

echo "==> starting Keycloak (deploy/docker-compose.yml)"
(cd "$repo_root/deploy" && docker compose up -d keycloak)
compose_started=1

echo "==> waiting for Keycloak"
for _ in $(seq 1 60); do
	if curl -sf "${kc_base}/realms/master" >/dev/null 2>&1; then
		break
	fi
	sleep 2
done
if ! curl -sf "${kc_base}/realms/master" >/dev/null 2>&1; then
	echo "Keycloak never became ready" >&2
	docker compose -f "$repo_root/deploy/docker-compose.yml" logs keycloak >&2
	exit 1
fi

echo "==> getting Keycloak admin token"
admin_token_body=$(curl -sS "${kc_base}/realms/master/protocol/openid-connect/token" \
	-d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin)
admin_token=$(json_field "$admin_token_body" "access_token")
if [[ -z "$admin_token" ]]; then
	echo "failed to get Keycloak admin token; response: $admin_token_body" >&2
	exit 1
fi
kc_auth=(-H "Authorization: Bearer ${admin_token}" -H "Content-Type: application/json")

echo "==> creating realm ${kc_realm}"
curl -sS -o /dev/null -w '' -X POST "${kc_base}/admin/realms" "${kc_auth[@]}" \
	-d "{\"realm\":\"${kc_realm}\",\"enabled\":true}" || true # tolerate "already exists" on a re-run

# gw-client-id is the audience-target client this ID-JAG will be bound to.
# Standard token exchange's `audience` parameter must name a real,
# registered client (not an arbitrary URI, unlike this gateway's own
# access-token aud, which IS a URI) -- interop knowledge worth recording,
# not this doc's original guess. bearerOnly=true: this client only ever
# needs to be an audience target, never itself authenticate anyone.
gw_client_id="spidercob-gateway"
echo "==> creating client ${gw_client_id} (the ID-JAG's audience target)"
curl -sS -X POST "${kc_base}/admin/realms/${kc_realm}/clients" "${kc_auth[@]}" -d "{
  \"clientId\": \"${gw_client_id}\",
  \"enabled\": true,
  \"publicClient\": false,
  \"standardFlowEnabled\": false,
  \"serviceAccountsEnabled\": false,
  \"bearerOnly\": true
}" >/dev/null || true

echo "==> creating client agent-app (standard token exchange enabled)"
agent_secret="agent-app-secret-not-for-production"
curl -sS -X POST "${kc_base}/admin/realms/${kc_realm}/clients" "${kc_auth[@]}" -d "{
  \"clientId\": \"agent-app\",
  \"secret\": \"${agent_secret}\",
  \"enabled\": true,
  \"publicClient\": false,
  \"directAccessGrantsEnabled\": true,
  \"standardFlowEnabled\": false,
  \"serviceAccountsEnabled\": false,
  \"attributes\": { \"standard.token.exchange.enabled\": \"true\" }
}" >/dev/null || true

# A client-level "Audience" protocol mapper is what actually makes
# gw_client_id show up in agent-app's own tokens' aud -- a shared
# client-scope with a role-mapping (Keycloak's documented mechanism) did
# NOT reliably apply under the direct-grant flow in practice; a mapper
# attached directly to the client did. Record any future discrepancy here,
# not silently work around it.
agent_clients_body=$(curl -sS "${kc_base}/admin/realms/${kc_realm}/clients?clientId=agent-app" "${kc_auth[@]}")
agent_uuid=$(json_field "$agent_clients_body" "id")
curl -sS -X POST "${kc_base}/admin/realms/${kc_realm}/clients/${agent_uuid}/protocol-mappers/models" "${kc_auth[@]}" -d "{
  \"name\": \"gateway-audience\",
  \"protocol\": \"openid-connect\",
  \"protocolMapper\": \"oidc-audience-mapper\",
  \"config\": { \"included.client.audience\": \"${gw_client_id}\", \"id.token.claim\": \"false\", \"access.token.claim\": \"true\" }
}" >/dev/null || true

echo "==> creating user alice"
# emailVerified + a populated profile (email/first/last name) are required
# for the direct-grant (password) flow to succeed at all -- an
# under-populated profile trips Keycloak's dynamic VERIFY_PROFILE required
# action ("Account is not fully set up"), even with requiredActions
# explicitly empty. Another real interop finding, not an assumption.
curl -sS -X POST "${kc_base}/admin/realms/${kc_realm}/users" "${kc_auth[@]}" -d '{
  "username": "alice",
  "enabled": true,
  "emailVerified": true,
  "email": "alice@spidercob-interop.test",
  "firstName": "Alice",
  "lastName": "Interop",
  "requiredActions": [],
  "credentials": [{"type": "password", "value": "alice-password", "temporary": false}]
}' >/dev/null || true

kc_issuer="${kc_base}/realms/${kc_realm}"
kc_jwks_url="${kc_issuer}/protocol/openid-connect/certs"
gw_issuer="${gw_base}"

echo "==> building gateway binary"
(cd "$repo_root" && go build -o "$work_dir/spidercob-gateway" ./cmd/spidercob)

echo "==> writing gateway config (trusting Keycloak realm ${kc_realm})"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":${gw_port}",
  "issuer": "${gw_issuer}",
  "store_db_path": "${work_dir}/spidercob.db",
  "trusted_idps": [
    { "issuer": "${kc_issuer}", "jwks_url": "${kc_jwks_url}", "expected_audience": "${gw_client_id}" }
  ],
  "nodes": [
    { "name": "jira", "upstream_url": "http://127.0.0.1:${gw_port}/does-not-need-to-resolve" }
  ]
}
EOF

echo "==> starting gateway"
"$work_dir/spidercob-gateway" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
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

echo "==> RFC 9728 metadata advertises the id-jag grant profile (trusted IdP configured)"
metadata_body=$(curl -sS "${gw_base}/.well-known/oauth-protected-resource/jira")
check "authorization_grant_profiles_supported includes id-jag" \
	"$(echo "$metadata_body" | { grep -c 'urn:ietf:params:oauth:grant-profile:id-jag' || true; })" "1"

echo "==> leg 1: alice signs into agent-app (Keycloak password grant)"
leg1_body=$(curl -sS "${kc_base}/realms/${kc_realm}/protocol/openid-connect/token" \
	-d grant_type=password -d client_id=agent-app -d client_secret="${agent_secret}" \
	-d username=alice -d password=alice-password -d scope=openid)
leg1_access_token=$(json_field "$leg1_body" "access_token")
check_nonempty "leg 1 produced a real access token" "$leg1_access_token"
decode_jwt_claims "$leg1_access_token" >"$repo_root/interop/vectors/keycloak-leg1-access-token-claims.json" 2>/dev/null || true

echo "==> leg 2: RFC 8693 token exchange for an ID-JAG audience-bound to this gateway"
leg2_body=$(curl -sS "${kc_base}/realms/${kc_realm}/protocol/openid-connect/token" \
	-u "agent-app:${agent_secret}" \
	-d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
	-d subject_token="${leg1_access_token}" \
	-d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
	-d requested_token_type=urn:ietf:params:oauth:token-type:id-jag \
	-d audience="${gw_client_id}")
idjag=$(json_field "$leg2_body" "access_token")
if [[ -z "$idjag" ]]; then
	echo "  note: requested_token_type=id-jag not honored by this Keycloak version/config (response: $leg2_body)"
	echo "  falling back to a plain audience-scoped token-exchange (still a real, externally-signed, audience-bound assertion -- see interop/README.md notes)"
	leg2_body=$(curl -sS "${kc_base}/realms/${kc_realm}/protocol/openid-connect/token" \
		-u "agent-app:${agent_secret}" \
		-d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
		-d subject_token="${leg1_access_token}" \
		-d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
		-d audience="${gw_client_id}")
	idjag=$(json_field "$leg2_body" "access_token")
fi
check_nonempty "leg 2 produced a real, gateway-audience-bound assertion" "$idjag"
decode_jwt_claims "$idjag" >"$repo_root/interop/vectors/keycloak-leg2-idjag-claims.json" 2>/dev/null || true

echo "==> leg 3: RFC 7523 jwt-bearer grant at this gateway's real /token"
leg3_body=$(curl -sS "${gw_base}/token" \
	-d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
	-d assertion="${idjag}" -d resource=jira)
gw_access_token=$(json_field "$leg3_body" "access_token")
check_nonempty "leg 3 minted a real gateway access token" "$gw_access_token"
decode_jwt_claims "$gw_access_token" >"$repo_root/interop/vectors/gateway-access-token-claims.json" 2>/dev/null || true

echo "==> minted token's sub is a JIT-provisioned local user"
check "sub has the user: prefix" \
	"$(decode_jwt_claims "$gw_access_token" 2>/dev/null | { grep -c '"sub":"user:' || true; })" "1"

echo "==> minted token reaches the policy layer (403 DenyAll, not 401 -- proves the whole chain validated)"
authed_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${gw_base}/mcp/jira/" \
	-H "Authorization: Bearer ${gw_access_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "valid Mode B token + real DenyAll default = 403, not 401" "$authed_status" "403"

echo "==> replaying the same ID-JAG a second time is rejected (one-time-use jti)"
leg3_replay_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${gw_base}/token" \
	-d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
	-d assertion="${idjag}" -d resource=jira)
check "replayed ID-JAG rejected with 401" "$leg3_replay_status" "401"

echo
echo "==> ${pass} passed, ${fail} failed"
echo "==> vectors captured in interop/vectors/"
if [[ "$fail" -gt 0 ]]; then
	echo "gateway log:" >&2
	cat "$work_dir/gateway.log" >&2
	exit 1
fi
