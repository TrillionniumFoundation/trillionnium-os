#!/usr/bin/env python3
"""Apply the deterministic G1 CodeQL and hosted-test portability repair."""
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
            '            assert_eq!(error, super::ANDROID_USER_ZERO_CUSTODY_ERROR, "uid={uid}");\n',
            '            assert_eq!(\n                error,\n                super::ANDROID_USER_ZERO_CUSTODY_ERROR,\n                "unexpected Android user-zero custody classification"\n            );\n',
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

    inbox = root / "apps/trillionniumd/src/direct_operation_binding_inbox.rs"
    replace_once(
        inbox,
        '''    struct Fixture {\n        _root: TempDir,\n        system_api: PathBuf,\n        accessibility: PathBuf,\n    }\n''',
        '''    struct Fixture {\n        _root: TempDir,\n        _trusted_parent: TempDir,\n        system_api: PathBuf,\n        accessibility: PathBuf,\n    }\n''',
        "retain the portable trusted test parent",
    )
    replace_once(
        inbox,
        '''            // Keep the fixture below a non-writable, trusted ancestor and\n            // make its own directory explicitly private.  The production\n            // path rejects group/world-writable ancestors; relying on the\n            // host's umask or the collaboration workspace mode would make\n            // these tests fail before exercising the publication contract.\n            // `/tmp` is intentionally sticky/world-writable, while `/run` is\n            // root-owned but not writable by the unprivileged test user.  The\n            // canonical development root is owner-owned and mode 0755, so the\n            // test-only publisher accepts it as its trusted non-root parent.\n            let root = tempfile::Builder::new()\n                .prefix(".direct-binding-publisher-test-")\n                .tempdir_in("/data/toshiba-dev")\n                .unwrap();\n            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();\n''',
        '''            // Keep the fixture below a non-writable, trusted ancestor and\n            // make both test-created directories explicitly private. The\n            // production path rejects group/world-writable ancestors, so `/tmp`\n            // cannot be used. A per-run directory under the current account's\n            // home preserves the same ancestor contract without depending on a\n            // developer-machine-specific `/data/toshiba-dev` mount.\n            let home = std::env::var_os("HOME")\n                .map(PathBuf::from)\n                .expect("HOME must identify the trusted test parent");\n            let trusted_parent = tempfile::Builder::new()\n                .prefix(".direct-binding-publisher-parent-")\n                .tempdir_in(home)\n                .unwrap();\n            fs::set_permissions(trusted_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();\n            let root = tempfile::Builder::new()\n                .prefix(".direct-binding-publisher-test-")\n                .tempdir_in(trusted_parent.path())\n                .unwrap();\n            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();\n''',
        "replace machine-specific fixture root",
    )
    replace_once(
        inbox,
        '''            Self {\n                _root: root,\n                system_api,\n                accessibility,\n            }\n''',
        '''            Self {\n                _root: root,\n                _trusted_parent: trusted_parent,\n                system_api,\n                accessibility,\n            }\n''',
        "retain both fixture lifetimes",
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
