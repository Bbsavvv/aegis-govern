#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -q -e ".[dev]"
HOST="${HOST:-${AEGIS_HOST:-0.0.0.0}}"
PORT="${PORT:-${AEGIS_PORT:-8080}}"
echo "Aegis dashboard → http://${HOST}:${PORT}"
exec python -m uvicorn api.app:app --host "$HOST" --port "$PORT"
