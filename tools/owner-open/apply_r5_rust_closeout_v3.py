#!/usr/bin/env python3
"""Apply the exact Rust fixes exposed by the fail-closed R5 source closeout.

This development-only applicator is intentionally narrow. It accepts only the
reviewed post-v2 source cut, performs exact replacements, and refuses to write
when a preimage is absent or ambiguous. It has no runtime, provider, Android,
or release effects. The validating workflow commits and pushes its result only
after the complete Python/Rust/Cargo closure passes with truthful exit codes.
"""

from __future__ import annotations

import argparse
from pathlib import Path


class RepairError(RuntimeError):
    """Raised when the audited source preimage is not exact."""


def replace_exact(
    path: str,
    old: str,
    new: str,
    *,
    expected: int = 1,
) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise RepairError(
            f"{path}: expected {expected} replacements, observed {count}: {old!r}"
        )
    target.write_text(text.replace(old, new), encoding="utf-8")


def apply_repairs() -> None:
    replace_exact(
        "crates/trillionnium-owner-open-event-store/src/lib.rs",
        "    let mut limited = (&mut *reader).take(maximum as u64 + 2);\n",
        "    let mut limited = std::io::Read::take(reader, maximum as u64 + 2);\n",
    )
    replace_exact(
        "crates/trillionnium-owner-open-tool-bridge/src/lib.rs",
        "                drop(observe);\n",
        "",
    )
    replace_exact(
        "crates/trillionnium-owner-open-tool-bridge/src/lib.rs",
        "        drop(observe);\n",
        "",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v3 Rust closeout replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    apply_repairs()
    print("PASS_R5_RUST_CLOSEOUT_V3_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
