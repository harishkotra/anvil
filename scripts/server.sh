#!/usr/bin/env bash
# FastAPI on $PORT (spec default 3001, .env may override). agent.main reads .env itself.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON=".venv/bin/python"
[ -x "$PYTHON" ] || PYTHON="$(command -v python3)"
exec "$PYTHON" -m agent.main
