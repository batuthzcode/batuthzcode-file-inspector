from pathlib import Path

from analyzer import analyze_file
from history_store import HistoryStore


def test_history_roundtrip(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    result = analyze_file(str(sample))
    store = HistoryStore(tmp_path / "history.db")
    store.add(result)
    rows = store.list()
    assert len(rows) == 1
    assert rows[0][1] == "sample.bin"
    assert rows[0][5] == result.hashes["SHA256"]
    store.clear()
    assert store.list() == []
