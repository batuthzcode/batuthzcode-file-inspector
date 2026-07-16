from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from analyzer import analyze_file


def titles(result):
    return {finding.title for finding in result.findings}


def test_hashes_and_basic_metadata(tmp_path: Path):
    sample = tmp_path / "hello.txt"
    sample.write_bytes(b"hello world\n")
    result = analyze_file(str(sample))
    assert result.hashes["SHA256"] == hashlib.sha256(sample.read_bytes()).hexdigest()
    assert result.size == 12
    assert 0 <= result.entropy <= 8
    assert result.path == str(sample.resolve())


def test_yara_detects_obfuscated_downloader():
    result = analyze_file(str(Path(__file__).with_name("yara-fixture.txt")))
    assert "Suspicious_PowerShell_Downloader" in result.yara_matches
    assert "Suspicious_Script_Obfuscation" in result.yara_matches
    assert result.score >= 70


def test_pdf_active_content(tmp_path: Path):
    sample = tmp_path / "document.pdf"
    sample.write_bytes(b"%PDF-1.7\n1 0 obj <</OpenAction 2 0 R /JavaScript (test)>> endobj")
    result = analyze_file(str(sample))
    assert "PDF JavaScript içeriyor" in titles(result)
    assert "PDF açılış eylemi içeriyor" in titles(result)


def test_zip_path_traversal_and_executable(tmp_path: Path):
    sample = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("../../outside.exe", b"MZ placeholder")
    result = analyze_file(str(sample))
    assert "Arşiv dizin kaçışı" in titles(result)
    assert "Arşivde çalıştırılabilir dosya" in titles(result)
    assert result.score >= 40


def test_rejects_directory(tmp_path: Path):
    try:
        analyze_file(str(tmp_path))
    except ValueError as exc:
        assert "dosyalar" in str(exc)
    else:
        raise AssertionError("directory should have been rejected")
