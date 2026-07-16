# Architecture

```text
Desktop UI (main.py) ───────┐
                            ├── Static engine (analyzer.py) ── libmagic
CLI (cli.py) ───────────────┤                              ├── YARA
                            │                              ├── pefile
                            │                              ├── readelf / ExifTool
                            │                              └── optional ClamAV
                            ├── Reporting (reporting.py) ──── JSON / HTML
                            └── History (history_store.py) ── SQLite
```

## Static engine

`analyze_file` is deterministic for file content except filesystem timestamps and optional system-engine results. It streams the complete file for cryptographic hashes and entropy while retaining a bounded sample for indicator extraction. Format-specific parsers operate read-only.

The engine returns an `AnalysisResult` dataclass. Both the Qt interface and CLI consume this model, keeping presentation independent from detection logic.

## Scoring

Each finding has a severity, explanation and point weight. Weights accumulate and are capped at 100. High-risk verdicts should require either a strong signature match or several correlated indicators. A human-readable reason is retained for every awarded point.

## Privacy

There is no network client in the application. Optional engines are local executables. SQLite history stores report metadata, never a copy of the inspected file.

## Extension points

- Additional YARA files in `rules/`
- Format-specific pure functions called by `analyze_file`
- Additional exporters consuming `AnalysisResult`
- Sandbox adapters kept outside the static engine process
