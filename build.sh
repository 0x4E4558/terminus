#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  echo "Error: this script must be executed inside an activated virtual environment." >&2
  echo "Example:" >&2
  echo "  python3 -m venv .venv && source .venv/bin/activate && ./build.sh" >&2
  exit 1
fi

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

PYTHONPATH=src python -m unittest discover -s tests -q
python -m build

echo "Build and tests completed successfully."
