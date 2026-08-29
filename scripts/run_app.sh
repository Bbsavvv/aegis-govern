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
echo "Aegis dashboard → http://127.0.0.1:8080"
exec python -m uvicorn api.app:app --host 127.0.0.1 --port 8080
