#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"

"$PYTHON_BIN" -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

PYTHONPATH=src python -m unittest discover -s tests -q
python -m build

echo "Build and tests completed successfully."
