#!/usr/bin/env python3
"""Release-candidate installed-Codex qualification supervisor entry."""
from __future__ import annotations

import sys

import supervise_codex_mcp_qualification as base


def main(argv: list[str]) -> int:
    try:
        args = base.parse_args(argv)
        base.private_directory(args.evidence_dir.parent, "evidence parent")
        report = base.execute(args)
    except (OSError, base.SupervisorError, base.subprocess.SubprocessError) as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 1
    if (
        report.get("status") != "passed"
        or not report.get("cleanup", {}).get("config_restored")
    ):
        print(
            "HOLD: release supervisor did not finish with a restored passed state",
            file=sys.stderr,
        )
        return 1
    print("PASS_RELEASE_SUPERVISED_INSTALLED_CODEX_MCP_QUALIFICATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
