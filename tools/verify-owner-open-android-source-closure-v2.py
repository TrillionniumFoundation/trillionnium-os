#!/usr/bin/env python3
"""Correct package-block parsing for the owner-open Android source closure."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "verify-owner-open-android-source-closure.py"
SPEC = importlib.util.spec_from_file_location(
    "owner_open_android_source_closure_v1_base", BASE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v1 Android source-closure verifier")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

PROFILE = BASE.PROFILE
GENERATED_FRAGMENT = BASE.GENERATED_FRAGMENT
ANDROID_ROOT = BASE.ANDROID_ROOT
COMMON_OWNER_OPEN = BASE.COMMON_OWNER_OPEN
SUPERVISOR_CONFIG = BASE.SUPERVISOR_CONFIG


def added_product_packages(product_text: str) -> set[str]:
    marker = "PRODUCT_PACKAGES +="
    start = product_text.find(marker)
    if start < 0:
        return set()
    result: set[str] = set()
    started = False
    for raw_line in product_text[start + len(marker) :].splitlines():
        line = raw_line.strip()
        if not line:
            if started:
                break
            continue
        if line.startswith("#"):
            if started:
                break
            continue
        started = True
        for token in line.replace("\\", " ").split():
            if re.fullmatch(r"[A-Za-z0-9_.+-]+", token):
                result.add(token)
    return result


_base_verify = BASE.verify
BASE.added_product_packages = added_product_packages


def verify(root: Path):
    return _base_verify(root)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = verify(args.root)
    if args.json:
        print(json.dumps(report.value(), ensure_ascii=False, sort_keys=True, indent=2))
    elif report.ok:
        for warning in report.warnings:
            print(f"WARNING: {warning}")
        print("PASS_OWNER_OPEN_ANDROID_SOURCE_CLOSURE_V2 compiled=false")
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
