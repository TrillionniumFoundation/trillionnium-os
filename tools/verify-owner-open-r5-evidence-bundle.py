#!/usr/bin/env python3
"""Validate one Owner-Open R5 evidence bundle without promoting any gap."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from owner_open_r5_evidence_bundle import validate_bundle  # noqa: E402


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--require-promotable", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = validate_bundle(
        args.manifest.resolve(), require_promotable=args.require_promotable
    )
    value = {
        "ok": report.ok,
        "errors": report.errors,
        "warnings": report.warnings,
        "facts": report.facts,
    }
    if args.json:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARNING: {warning}")
        if report.ok:
            print("owner-open R5 evidence bundle verified")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
