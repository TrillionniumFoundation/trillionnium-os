#!/usr/bin/env python3
"""Read-only verifier for source-only operation replay-sync helper candidates."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import build_operation_replay_sync_static as contract


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--recipe",
        type=Path,
        default=Path(__file__).with_name("operation-replay-sync-static-recipe-v1.json"),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    artifact = commands.add_parser("artifact")
    artifact.add_argument("path", type=Path)
    build = commands.add_parser("build")
    build.add_argument("receipt", type=Path)
    reconcile = commands.add_parser("reconcile")
    reconcile.add_argument("--amd64-receipt", type=Path, required=True)
    reconcile.add_argument("--arm64-receipt", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        recipe, recipe_sha = contract.load_recipe(args.recipe)
        if args.command == "artifact":
            result = contract.inspect_elf_path(args.path)
        elif args.command == "build":
            result = contract._verify_build_receipt(args.receipt, recipe, recipe_sha)
        elif args.command == "reconcile":
            result = contract.reconcile_receipts(
                args.recipe, args.amd64_receipt, args.arm64_receipt
            )
        else:  # pragma: no cover
            raise contract.ContractError("unsupported verifier command")
    except contract.ContractError as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 78
    sys.stdout.buffer.write(contract.canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
