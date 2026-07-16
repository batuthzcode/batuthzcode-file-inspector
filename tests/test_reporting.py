from __future__ import annotations

import json
from pathlib import Path

from analyzer import analyze_file
from reporting import write_html, write_json


def test_json_and_html_reports(tmp_path: Path):
    sample = tmp_path / "a<script>.txt"
    sample.write_text("plain content", encoding="utf-8")
    result = analyze_file(str(sample))
    json_path = write_json(result, tmp_path / "report.json")
    html_path = write_html(result, tmp_path / "report.html")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["hashes"]["SHA256"] == result.hashes["SHA256"]
    document = html_path.read_text(encoding="utf-8")
    assert "THZCodeSpair" in document
    assert "a&lt;script&gt;.txt" in document
    assert "a<script>.txt" not in document
