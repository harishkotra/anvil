#!/usr/bin/env bash
# Run server + client together. Ports come from the environment, then .env, then the spec
# defaults (3001 API / 5173 client) so a clean machine matches the spec without editing.
set -euo pipefail
cd "$(dirname "$0")/.."

read_env() {
  [ -f .env ] && sed -n "s/^[[:space:]]*$1=//p" .env | head -1 || true
}

API_PORT="${PORT:-$(read_env PORT)}"; API_PORT="${API_PORT:-3001}"
CLIENT_PORT="${CLIENT_PORT:-$(read_env CLIENT_PORT)}"; CLIENT_PORT="${CLIENT_PORT:-5173}"

export PORT="$API_PORT" ANVIL_API_PORT="$API_PORT"
echo "[dev] API :$API_PORT -> client :$CLIENT_PORT (proxy /api)"
exec ./node_modules/.bin/concurrently -k -n server,client -c cyan,magenta \
  "bash scripts/server.sh" \
  "cd client && npx vite --host 127.0.0.1 --port $CLIENT_PORT"
