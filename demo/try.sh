#!/usr/bin/env bash
# Calls the demo's leaky MCP tool through the gateway, the way an AI agent
# would, and shows what the agent actually receives. Start the demo first:
#   docker compose -f demo/docker-compose.yml up -d --build
set -euo pipefail
base="${GATEWAY_URL:-http://localhost:8080}"

for _ in $(seq 1 60); do curl -sf "$base/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "$base/healthz" >/dev/null || { echo "Gateway isn't up at $base yet. Start it with: docker compose -f demo/docker-compose.yml up -d --build" >&2; exit 1; }

echo "1. The agent gets its own short-lived token (no shared API key)"
token=$(curl -sS "$base/token" \
  -d grant_type=client_credentials -d client_id=demo-agent \
  -d client_secret=demo-secret-not-for-production -d resource=leaky |
  sed -E 's/.*"access_token":"([^"]*)".*/\1/')

hdrs=$(mktemp); trap 'rm -f "$hdrs"' EXIT
curl -sS -D "$hdrs" -o /dev/null "$base/mcp/leaky/" -H "Authorization: Bearer $token" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
session=$(grep -i '^Mcp-Session-Id:' "$hdrs" | sed -E 's/^[^:]*: *//' | tr -d '\r\n')

echo "2. The agent asks the MCP server to read a config file."
echo "   The server returns a (fake) AWS key and a test card number."
echo
echo "3. What the agent actually receives through Spidercob:"
echo
curl -sS "$base/mcp/leaky/" -H "Authorization: Bearer $token" -H "Mcp-Session-Id: $session" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_config","arguments":{"path":".env"}}}' |
  sed -E 's/.*"text":"([^"]*)".*/\1/' | sed 's/\\n/\n/g' | sed 's/^/   /'
echo
echo "4. Every call is in the tamper-evident audit log. Admin UI: $base/ui/"
echo "   (demo login: admin / demo-admin-not-for-production)"
