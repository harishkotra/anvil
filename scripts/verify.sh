#!/usr/bin/env bash
# `npm run verify` -> `python -m agent.verify`, using the project virtualenv when present.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON=".venv/bin/python"
[ -x "$PYTHON" ] || PYTHON="$(command -v python3)"
exec "$PYTHON" -m agent.verify "$@"
