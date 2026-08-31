from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"R15 {label} anchor is not exact")
    return text.replace(old, new, 1)


# A transient try_wait error must not discard the only wait(2) owner. Transfer
# the still-owned Child to the bounded abort-reaper path instead.
process_path = Path("crates/trillionnium-owner-open-job-runtime/src/process.rs")
process_text = process_path.read_text()
drop_start = process_text.index("impl Drop for SpawnGuard")
drop_end = process_text.index("impl ProcessControl", drop_start)
drop_block = process_text[drop_start:drop_end]
drop_block = replace_once(
    drop_block,
    "                Err(_) => return,\n",
    "                Err(_) => break,\n",
    "spawn-guard try_wait ownership",
)
process_path.write_text(process_text[:drop_start] + drop_block + process_text[drop_end:])

source_test_path = Path("tools/tests/test_owner_open_r15_runtime_hardening.py")
source_test = source_test_path.read_text()
source_test = replace_once(
    source_test,
    '        self.assertIn("owner-open-job-abort-reaper", drop)\n',
    '        self.assertIn("owner-open-job-abort-reaper", drop)\n'
    '        self.assertIn("Err(_) => break", drop)\n'
    '        self.assertNotIn("Err(_) => return", drop)\n',
    "spawn-guard source regression",
)
source_test_path.write_text(source_test)

# Scan both workflow extensions and reject the common YAML/API forms that could
# otherwise restore repository-write authority outside the reviewed protocol.
verifier_path = Path("tools/verify-owner-open-r5-workflow-boundaries.py")
verifier = verifier_path.read_text()
old_regexes = r'''WRITE_PERMISSION = re.compile(
    r"(?m)^\s*(?:contents|actions|pull-requests|issues|checks|deployments):\s*write\s*$"
)
API_WRITE = re.compile(
    r"(?:--method\s+(?:POST|PUT|PATCH|DELETE)\b|"
    r"method\s*=\s*['\"](?:POST|PUT|PATCH|DELETE)['\"])",
    re.IGNORECASE,
)
'''
new_regexes = r'''WRITE_PERMISSION = re.compile(
    r"(?im)^\s*(?:(?:contents|actions|pull-requests|issues|checks|deployments)"
    r"\s*:\s*['\"]?write['\"]?|permissions\s*:\s*['\"]?write-all['\"]?|"
    r"permissions\s*:\s*\{[^}\n]*\b(?:contents|actions|pull-requests|issues|"
    r"checks|deployments)\s*:\s*['\"]?write['\"]?[^}\n]*\})\s*(?:#.*)?$"
)
API_WRITE = re.compile(
    r"(?:--method(?:=|\s+)[\s'\"]*(?:POST|PUT|PATCH|DELETE)\b|"
    r"(?:-X|--request)(?:=|\s+)[\s'\"]*(?:POST|PUT|PATCH|DELETE)\b|"
    r"method\s*=\s*['\"](?:POST|PUT|PATCH|DELETE)['\"])",
    re.IGNORECASE,
)
'''
verifier = replace_once(
    verifier,
    old_regexes,
    new_regexes,
    "workflow write-authority regexes",
)
verifier = replace_once(
    verifier,
    "\ndef verify(root: Path) -> dict[str, Any]:\n",
    "\ndef _workflow_paths(workflow_dir: Path) -> list[Path]:\n"
    "    return sorted(\n"
    "        set(workflow_dir.glob(\"*.yml\"))\n"
    "        | set(workflow_dir.glob(\"*.yaml\"))\n"
    "    )\n\n\n"
    "def verify(root: Path) -> dict[str, Any]:\n",
    "workflow extension enumeration",
)
verifier = replace_once(
    verifier,
    '    observed = {path.name for path in workflow_dir.glob("owner-open*.yml")}\n'
    '    for name in sorted(required - observed):\n'
    '        errors.append(f"required permanent workflow is absent: {name}")\n\n'
    '    for path in sorted(workflow_dir.glob("owner-open*.yml")):\n',
    '    workflow_paths = _workflow_paths(workflow_dir)\n'
    '    observed = {path.name for path in workflow_paths}\n'
    '    for name in sorted(required - observed):\n'
    '        errors.append(f"required permanent workflow is absent: {name}")\n\n'
    '    for path in workflow_paths:\n',
    "complete workflow enumeration",
)
verifier = replace_once(
    verifier,
    '        if API_WRITE.search(text) and "api.github.com/repos/" in text:\n',
    '        if (\n'
    '            API_WRITE.search(text)\n'
    '            and "repos/" in text\n'
    '            and ("api.github.com" in text or "GITHUB_API_URL" in text)\n'
    '        ):\n',
    "GitHub API write detection",
)
verifier_path.write_text(verifier)

boundary_test_anchor = '''\n\nif __name__ == "__main__":\n    unittest.main()\n'''
boundary_test_addition = r'''

    def test_yaml_write_all_and_api_request_forms_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            required = (
                "owner-open-r5-tool-loop.yml",
                "owner-open-r5-target-evidence-capture.yml",
                "owner-open-r5-governance-readiness.yml",
            )
            for name in required:
                (workflows / name).write_text(self.workflow(False), encoding="utf-8")
            (workflows / "owner-open-r16-write-evasion.yaml").write_text(
                self.workflow(False)
                .replace("permissions:\n  contents: read", "permissions: write-all")
                + "      - run: curl --request PATCH \"$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/branches/main/protection\"\n",
                encoding="utf-8",
            )
            (workflows / "owner-open-r16-inline-write.yaml").write_text(
                self.workflow(False).replace(
                    "permissions:\n  contents: read",
                    "permissions: {contents: write}",
                ),
                encoding="utf-8",
            )
            errors = self.module.verify(root)["errors"]
            self.assertTrue(
                any(
                    "owner-open-r16-write-evasion.yaml" in item
                    and "write permission" in item
                    for item in errors
                )
            )
            self.assertTrue(
                any(
                    "owner-open-r16-write-evasion.yaml" in item
                    and "mutate GitHub repository controls" in item
                    for item in errors
                )
            )
            self.assertTrue(
                any(
                    "owner-open-r16-inline-write.yaml" in item
                    and "write permission" in item
                    for item in errors
                )
            )
'''
source_test = source_test_path.read_text()
source_test = replace_once(
    source_test,
    boundary_test_anchor,
    boundary_test_addition + boundary_test_anchor,
    "workflow bypass regression insertion",
)
source_test_path.write_text(source_test)

# Make the permanent R15 gate self-contained and strict over every host-valid
# optional feature partition, not only the default workspace feature set.
workflow_path = Path(".github/workflows/owner-open-r15-runtime-hardening.yml")
workflow = workflow_path.read_text()
workflow = replace_once(
    workflow,
    '  TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT: userdebug\n',
    '  TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT: userdebug\n'
    '  LANG: C.UTF-8\n'
    '  LC_ALL: C.UTF-8\n',
    "R15 workflow deterministic locale",
)
workflow = replace_once(
    workflow,
    "          python3 -m compileall -q tools\n"
    "          python3 -m unittest discover -s tools/tests -p 'test_*.py' -v\n"
    "          python3 tools/verify-owner-open-r5-workflow-boundaries.py --json\n",
    "          python3 tools/generate-owner-open-types.py --check\n"
    "          python3 tools/verify-owner-open-r5.py --json\n"
    "          python3 tools/verify-owner-open-r5-gap-evidence.py --json\n"
    "          python3 -m compileall -q tools\n"
    "          PYTHONWARNINGS=error::ResourceWarning \\\n"
    "            python3 -m unittest discover -s tools/tests -p 'test_*.py' -v\n"
    "          python3 tools/verify-owner-open-r5-workflow-boundaries.py --json\n",
    "R15 workflow complete Python gates",
)
workflow = replace_once(
    workflow,
    "          cargo fmt --all -- --check\n"
    "          cargo test --workspace --all-targets --locked\n",
    "          cargo metadata --locked --format-version 1 > /tmp/r15-cargo-metadata.json\n"
    "          cargo fmt --all -- --check\n"
    "          cargo test --workspace --all-targets --locked\n",
    "R15 workflow locked metadata gate",
)
workflow = replace_once(
    workflow,
    "          cargo doc --workspace --no-deps --locked\n",
    "          RUSTDOCFLAGS=\"-D warnings\" cargo doc --workspace --no-deps --locked\n",
    "R15 workflow rustdoc warnings",
)
feature_test_tail = (
    "          cargo test -p trillionniumd --all-targets --no-default-features "
    "--features dev-conformance-fault-hook,legacy-plan-conformance --locked\n"
)
feature_clippy_tail = feature_test_tail + (
    "          cargo clippy -p trillionnium-agent-direct-tools --all-targets --no-default-features --features dev-overrides --locked -- -D warnings\n"
    "          cargo clippy -p trillionnium-agent-direct-tools --all-targets --no-default-features --features development-compatibility-lane --locked -- -D warnings\n"
    "          cargo clippy -p trillionnium-agent-direct-tools --all-targets --no-default-features --features production-durable-hotpath --locked -- -D warnings\n"
    "          cargo clippy -p trillionnium-agent-direct-tools --all-targets --no-default-features --features device-launch-package-conformance --locked -- -D warnings\n"
    "          cargo clippy -p trillionnium-tool-runtime --all-targets --all-features --locked -- -D warnings\n"
    "          cargo clippy -p trillionnium-shell-exec --all-targets --all-features --locked -- -D warnings\n"
    "          cargo clippy -p trillionnium-agent-privilege-broker --all-targets --features p0-launch-package-device-conformance --locked -- -D warnings\n"
    "          cargo clippy -p trillionnium-os-types --all-targets --all-features --locked -- -D warnings\n"
    "          cargo clippy -p trillionnium-privilege-broker-protocol --all-targets --all-features --locked -- -D warnings\n"
    "          cargo clippy -p trillionniumd --all-targets --no-default-features --features dev-conformance-fault-hook,legacy-plan-conformance --locked -- -D warnings\n"
)
workflow = replace_once(
    workflow,
    feature_test_tail,
    feature_clippy_tail,
    "R15 workflow optional-feature Clippy gates",
)
workflow_path.write_text(workflow)
