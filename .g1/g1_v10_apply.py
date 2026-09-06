#!/usr/bin/env python3
"""Idempotently construct the reviewed G1 clock-domain repair."""
from __future__ import annotations

import argparse
from pathlib import Path

ALIAS = (
    "from time import monotonic as _retirement_monotonic\n"
    "from time import sleep as _retirement_sleep\n"
)
TARGETS = (
    (
        "tools/owner-open/build_owner_open_rootfs_image_release_v2.py",
        "def _quiet_group(",
        "\n\ndef bounded_command(",
    ),
    (
        "tools/owner-open/jsonl_provider_runtime.py",
        "def _group_quiet(",
        "\n\ndef _status(",
    ),
)


def isolate(path: Path, start_marker: str, end_marker: str) -> None:
    text = path.read_text(encoding="utf-8")
    if ALIAS not in text:
        marker = "import time\n"
        if text.count(marker) != 1:
            raise SystemExit(f"unexpected time import shape: {path}")
        text = text.replace(marker, marker + ALIAS, 1)
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    region = text[start:end]
    region = region.replace("time.monotonic()", "_retirement_monotonic()")
    region = region.replace("time.sleep(", "_retirement_sleep(")
    if "time.monotonic()" in region or "time.sleep(" in region:
        raise SystemExit(f"retirement clock remained coupled: {path}")
    if "_retirement_monotonic()" not in region or "_retirement_sleep(" not in region:
        raise SystemExit(f"retirement clock aliases are not exercised: {path}")
    path.write_text(text[:start] + region + text[end:], encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worktree", type=Path, required=True)
    args = parser.parse_args()
    root = args.worktree.resolve()
    probe = root / "__schema_probe__"
    if probe.exists() or probe.is_symlink():
        probe.unlink()
    for relative, start, end in TARGETS:
        isolate(root / relative, start, end)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
