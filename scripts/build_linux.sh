#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m PyInstaller \
  --noconfirm \
  --clean \
  --windowed \
  --name THZCodeSpair-File-Inspector \
  --add-data "rules:rules" \
  --hidden-import magic \
  --hidden-import yara \
  --hidden-import pefile \
  main.py

echo "Build ready: $ROOT/dist/THZCodeSpair-File-Inspector/"
