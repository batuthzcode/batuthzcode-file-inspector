from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_cli_quiet_json(tmp_path: Path):
    sample = tmp_path / "sample.txt"
    sample.write_text("hello", encoding="utf-8")
    process = subprocess.run([sys.executable, str(ROOT / "cli.py"), str(sample), "--quiet"], capture_output=True, text=True)
    assert process.returncode == 0
    assert json.loads(process.stdout)["name"] == "sample.txt"


def test_cli_fail_threshold():
    fixture = ROOT / "tests" / "yara-fixture.txt"
    process = subprocess.run([sys.executable, str(ROOT / "cli.py"), str(fixture), "--quiet", "--fail-on", "high"], capture_output=True, text=True)
    assert process.returncode == 2
