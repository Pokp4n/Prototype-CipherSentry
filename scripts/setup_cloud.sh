#!/usr/bin/env bash
set -euo pipefail
cd /workspace/Prototype-CipherSentry
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
PIP_CACHE_DIR=/workspace/.cache/pip .venv/bin/python -m pip install --disable-pip-version-check -r requirements-dev.txt
.venv/bin/python -m pip check
