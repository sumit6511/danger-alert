#!/usr/bin/env bash
# Builds dist/danger-alert : a single self-contained Linux executable.
# Uses a portable Python build so the result runs on Ubuntu 20.04+ (not just the build machine).
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.local/bin:$PATH"
command -v uv >/dev/null || pip install --user uv
uv venv --python 3.12 --managed-python --clear .build-venv
uv pip install --python .build-venv pyinstaller pynput
PYHOME="$(.build-venv/bin/python -c 'import sys; print(sys.base_prefix)')"
LD_LIBRARY_PATH="$PYHOME/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" .build-venv/bin/pyinstaller --onefile --clean --noconfirm --name danger-alert \
  --hidden-import pynput.keyboard._xorg --hidden-import pynput.mouse._xorg \
  --hidden-import tkinter danger_alert.py
echo "Built: $(pwd)/dist/danger-alert"
