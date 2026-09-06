#!/usr/bin/env python3
"""Apply the deterministic G1 CodeQL data-exposure and URL-boundary repair."""
from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one exact source occurrence, found {count}: {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worktree", type=Path, required=True)
    args = parser.parse_args()
    root = args.worktree.resolve()

    verifier = root / "tools/verify-owner-open-r5-workflow-boundaries.py"
    replace_once(
        verifier,
        '''        if (\n            API_WRITE.search(text)\n            and "repos/" in text\n            and ("api.github.com" in text or "GITHUB_API_URL" in text)\n        ):\n''',
        '''        if API_WRITE.search(text) and "/repos/" in text:\n''',
        "reject repository API writes without hostname substring trust",
    )

    verifier_tests = root / "tools/tests/test_verify_owner_open_r5_workflow_boundaries.py"
    replace_once(
        verifier_tests,
        '''        self.assertTrue(any("mutate GitHub repository" in item for item in self.errors()))\n\n    def test_target_route_cannot_allocate_self_hosted_runner(self) -> None:\n''',
        '''        self.assertTrue(any("mutate GitHub repository" in item for item in self.errors()))\n\n    def test_repository_control_mutation_rejects_hostname_smuggling(self) -> None:\n        value = self.clean_pr_workflow() + (\n            '      - run: curl --request PUT '\n            '"https://attacker.invalid/api.github.com/repos/x/y/branches/main/protection"\\n'\n        )\n        self.write("owner-open-r5-tool-loop.yml", value)\n        self.assertTrue(any("mutate GitHub repository" in item for item in self.errors()))\n\n    def test_target_route_cannot_allocate_self_hosted_runner(self) -> None:\n''',
        "add hostname-smuggling regression",
    )

    android = root / "apps/trillionniumd/src/android_agent_api.rs"
    replacements = (
        (
            '                "uid={uid}"\n',
            '                "unexpected Android user-zero custody classification"\n',
            "remove UID from assertion diagnostics",
        ),
        (
            '            other => panic!("legacy provider state escaped quarantine: {other:?}"),\n',
            '            _ => panic!("legacy provider state escaped quarantine"),\n',
            "redact legacy provider recovery state",
        ),
        (
            '            other => panic!("legacy terminal result disappeared after reopen: {other:?}"),\n',
            '            _ => panic!("legacy terminal result disappeared after reopen"),\n',
            "redact legacy terminal recovery state",
        ),
        (
            '            other => panic!("poisoned direct state escaped quarantine: {other:?}"),\n',
            '            _ => panic!("poisoned direct state escaped quarantine"),\n',
            "redact poisoned direct state",
        ),
        (
            '                other => panic!("malformed direct state escaped quarantine: {other:?}"),\n',
            '                _ => panic!("malformed direct state escaped quarantine"),\n',
            "redact malformed direct state",
        ),
        (
            '            other => panic!("same manifest reprovision did not recover: {other:?}"),\n',
            '            _ => panic!("same manifest reprovision did not recover"),\n',
            "redact reprovision recovery state",
        ),
        (
            '            other => panic!("legacy v1 saga was not quarantined: {other:?}"),\n',
            '            _ => panic!("legacy v1 saga was not quarantined"),\n',
            "redact legacy v1 recovery state",
        ),
        (
            '            other => panic!("v2 saga was blocked by legacy v1 record: {other:?}"),\n',
            '            _ => panic!("v2 saga was blocked by legacy v1 record"),\n',
            "redact v2 recovery state",
        ),
        (
            '            other => panic!("provider pending was not fixed indeterminate: {other:?}"),\n',
            '            _ => panic!("provider pending was not fixed indeterminate"),\n',
            "redact provider-pending recovery state",
        ),
    )
    for old, new, label in replacements:
        replace_once(android, old, new, label)

    trusted = root / "crates/trillionnium-agent-direct-tools/src/trusted_context.rs"
    replace_once(
        trusted,
        '            other => panic!("expected ackable replay disposition, got {other:?}"),\n',
        '            _ => panic!("expected ackable replay disposition"),\n',
        "redact trusted replay disposition",
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
