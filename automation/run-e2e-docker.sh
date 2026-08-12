#!/usr/bin/env bash
# Real end-to-end smoke test for issue #39 (deploy packaging): builds the
# *actual* production Docker image from the real Dockerfile -- not just
# `go build`'s output, which every other e2e script in this repo already
# proves works -- and drives a real running container through curl.
#
# This is the one check in this repo that would have caught the exact bug
# this issue fixes: the Dockerfile used to `go build` without ever running
# the frontend build first, so a `docker build` shipped a binary whose
# /ui/ 404s for every request (internal/webui/dist is gitignored except a
# tracked .gitkeep placeholder, and go:embed only captures what's on disk
# at build time). Proving /ui/ actually serves real HTML through a real
# container is this script's whole reason to exist -- everything else
# (healthz, a real token mint, a real tools/call) is here to prove the
# packaged artifact isn't a *different*, worse gateway than the one the
# rest of this repo's test suite already validates.
#
# Needs Docker -- this is `make ci-docker`, a separate, required-but-not-
# unconditional layer from `make ci` (which doesn't need Docker), kept
# apart from `make ci-interop` (a different Docker-dependent concern:
# Keycloak protocol interop, not this repo's own packaged artifact).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${GATEWAY_E2E_DOCKER_PORT:-18400}"
base="http://127.0.0.1:${port}"
image_tag="spidercob-gateway-e2e:$$"
container_name="spidercob-gateway-e2e-$$"

work_dir="$(mktemp -d)"

cleanup() {
	docker rm -f "$container_name" >/dev/null 2>&1 || true
	docker rmi "$image_tag" >/dev/null 2>&1 || true
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

echo "==> building the real production image from the real Dockerfile"
(cd "$repo_root" && docker build -t "$image_tag" .)

echo "==> checking the built image's size against the ~30MB target (MASTER_PLAN.md §11)"
# `docker images`' human-readable SIZE column, not `docker inspect
# .Size` -- the latter reports inconsistently (layer/content-store
# accounting differences) across Docker's image-store backends and
# doesn't match what `docker images` itself, or a human operator, would
# actually see.
size_str=$(docker images "$image_tag" --format "{{.Size}}")
if [[ "$size_str" == *MB ]] && awk -v n="${size_str%MB}" 'BEGIN{exit !(n < 40)}'; then
	echo "  ok   - image size ${size_str} (comfortably under the ~30MB target, generous margin for a check)"
	pass=$((pass + 1))
else
	echo "  FAIL - image size ${size_str}, expected well under 40MB"
	fail=$((fail + 1))
fi

echo "==> cross-compiling the echoserver fixture for the Docker daemon's own OS/arch"
daemon_arch="$(docker info --format '{{.Architecture}}')"
case "$daemon_arch" in
x86_64) goarch=amd64 ;;
aarch64 | arm64) goarch=arm64 ;;
*)
	echo "unrecognized Docker daemon architecture: $daemon_arch" >&2
	exit 1
	;;
esac
(cd "$repo_root" && GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 go build -o "$work_dir/echoserver" ./internal/proxy/stdioadapter/testdata/echoserver)
chmod +x "$work_dir/echoserver"

echo "==> writing e2e config (a real stdio node, the fixture mounted into the container)"
cat >"$work_dir/config.json" <<EOF
{
  "listen": ":8080",
  "issuer": "http://127.0.0.1:${port}",
  "store_db_path": "/tmp/spidercob.db",
  "dev_allow_all_policy": true,
  "nodes": [
    { "name": "echo", "transport": "stdio", "command": "/fixtures/echoserver" }
  ],
  "seed_agents": [
    { "client_id": "agt-dockere2e", "client_secret": "docker-e2e-secret", "name": "docker-e2e-agent" }
  ]
}
EOF

echo "==> running a real container from the real image"
docker run -d --name "$container_name" -p "${port}:8080" \
	-v "$work_dir/config.json:/config.json:ro" \
	-v "$work_dir/echoserver:/fixtures/echoserver:ro" \
	"$image_tag" >/dev/null

for _ in $(seq 1 50); do
	if curl -sf "${base}/healthz" >/dev/null 2>&1; then
		break
	fi
	sleep 0.2
done
if ! curl -sf "${base}/healthz" >/dev/null 2>&1; then
	echo "container never became healthy; log:" >&2
	docker logs "$container_name" >&2 2>&1 || true
	exit 1
fi
check "container is healthy" "$(curl -sS -o /dev/null -w '%{http_code}' "${base}/healthz")" "200"

echo "==> THE DoD MOMENT: /ui/ actually serves the real built admin UI, not a 404"
ui_status=$(curl -sS -o /dev/null -w '%{http_code}' "${base}/ui/")
check "GET /ui/ returns 200, not 404" "$ui_status" "200"
ui_body=$(curl -sS "${base}/ui/")
check_contains "the real built index.html is served (not an empty/placeholder page)" "$ui_body" "<div id=\"root\">"

echo "==> a real token mints through the real container"
token_body=$(curl -sS -X POST "${base}/token" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=agt-dockere2e" \
	--data-urlencode "client_secret=docker-e2e-secret" \
	--data-urlencode "resource=echo")
access_token=$(json_field "$token_body" "access_token")
check "access token minted" "$([[ -n "$access_token" ]] && echo yes || echo no)" "yes"

echo "==> a real MCP session against the real, containerized stdio node"
init_headers="$work_dir/init_headers.txt"
curl -sS -D "$init_headers" -o /dev/null -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${access_token}" \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
session_id=$(grep -i '^Mcp-Session-Id:' "$init_headers" | sed -E 's/^[Mm]cp-[Ss]ession-[Ii]d: *//' | tr -d '\r\n')
check "a real session was established inside the container" "$([[ -n "$session_id" ]] && echo yes || echo no)" "yes"

echo "==> a real tools/call succeeds through the real container"
call_body=$(curl -sS -X POST "${base}/mcp/echo/" \
	-H "Authorization: Bearer ${access_token}" -H "Mcp-Session-Id: ${session_id}" \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"docker packaging works"}}}')
check_contains "echo tool returns what it was given, through the real image" "$call_body" "docker packaging works"

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "container log:" >&2
	docker logs "$container_name" >&2 2>&1 || true
	exit 1
fi
