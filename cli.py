from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from analyzer import analyze_file
from reporting import to_dict, write_html, write_json


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        prog="thz-inspect",
        description="Inspect an untrusted file locally without executing or uploading it.",
    )
    command.add_argument("file", help="file to inspect")
    command.add_argument("--json", dest="json_path", metavar="PATH", help="write a structured JSON report")
    command.add_argument("--html", dest="html_path", metavar="PATH", help="write a standalone HTML report")
    command.add_argument("--quiet", action="store_true", help="only print the final JSON object")
    command.add_argument("--fail-on", choices=("caution", "suspicious", "high"), default=None, help="return exit code 2 at or above this risk level")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = analyze_file(args.file, None if args.quiet else lambda n, s: print(f"[{n:3d}%] {s}", file=sys.stderr))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json_path: write_json(result, args.json_path)
    if args.html_path: write_html(result, args.html_path)
    if args.quiet:
        print(json.dumps(to_dict(result), ensure_ascii=False))
    else:
        print(f"\n{result.name}\n  verdict : {result.verdict}\n  score   : {result.score}/100\n  sha256  : {result.hashes['SHA256']}\n  findings: {len(result.findings)}")
        for finding in result.findings: print(f"  - [{finding.severity.upper()}] {finding.title}")
    thresholds = {"caution": 15, "suspicious": 40, "high": 70}
    return 2 if args.fail_on and result.score >= thresholds[args.fail_on] else 0


if __name__ == "__main__":
    raise SystemExit(main())
