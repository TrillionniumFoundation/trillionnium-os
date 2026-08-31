from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
import importlib.util

ROOT = Path(__file__).resolve().parents[2]


class RuntimeHardeningSourceTests(unittest.TestCase):
    def test_job_runtime_is_fail_closed_by_default(self) -> None:
        text = (ROOT / "crates/trillionnium-owner-open-job-runtime/src/types.rs").read_text()
        default = text[text.index("impl Default for JobRuntimeConfig"):text.index("impl JobRuntimeConfig")]
        self.assertIn("allow_unjournaled_effects: false", default)
        self.assertIn("pub fn development_unsafe() -> Self", text)

    def test_product_requires_explicit_development_escape_hatch(self) -> None:
        for version in ("v6", "v7"):
            text = (ROOT / f"apps/trillionnium-owner-open-host/src/bin/r5_control_host_{version}/entry.rs").read_text()
            self.assertIn("let mut allow_unjournaled_effects = false", text)
            self.assertIn("--allow-unjournaled-effects-for-development", text)
            self.assertIn("conflicts with --allow-unjournaled-effects-for-development", text)
            self.assertNotIn("allow_unjournaled_effects: !parsed.require_job_journal", text)

    def test_all_process_paths_clear_ambient_environment(self) -> None:
        paths = (
            "crates/trillionnium-owner-open-provider-jsonl/src/lib.rs",
            "crates/trillionnium-owner-open-job-runtime/src/process.rs",
            "crates/trillionnium-owner-open-runtime/src/process.rs",
        )
        for path in paths:
            text = (ROOT / path).read_text()
            self.assertIn("env_clear()", text, path)
            self.assertIn("INHERITED_ENV_ALLOWLIST", text, path)

    def test_parent_death_uses_parent_pid_captured_before_fork(self) -> None:
        provider = (ROOT / "crates/trillionnium-owner-open-provider-jsonl/src/lib.rs").read_text()
        jobs = (ROOT / "crates/trillionnium-owner-open-job-runtime/src/process.rs").read_text()
        self.assertIn("let parent_pid = unsafe { libc::getpid() };", provider)
        self.assertGreaterEqual(jobs.count("let parent_pid = unsafe { libc::getpid() };"), 2)
        self.assertNotIn("let parent_pid = libc::getppid();", jobs)

    def test_spawn_guard_and_pty_close_are_truthful(self) -> None:
        process = (ROOT / "crates/trillionnium-owner-open-job-runtime/src/process.rs").read_text()
        manager = (ROOT / "crates/trillionnium-owner-open-job-runtime/src/manager.rs").read_text()
        drop = process[process.index("impl Drop for SpawnGuard"):process.index("impl ProcessControl")]
        self.assertIn("try_wait", drop)
        self.assertIn("SPAWN_GUARD_REAP_GRACE", drop)
        self.assertIn("owner-open-job-abort-reaper", drop)
        self.assertIn("PtyEofCharacterSent", process)
        self.assertIn('"pty_eof_character_sent"', manager)
        self.assertIn('"stdin_closed": stdin_closed', manager)


class WorkflowBoundaryGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        path = ROOT / "tools/verify-owner-open-r5-workflow-boundaries.py"
        spec = importlib.util.spec_from_file_location("r15_boundaries", path)
        assert spec is not None and spec.loader is not None
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    @staticmethod
    def workflow(named: bool) -> str:
        checkout = """      - name: Check out exact source\n        uses: actions/checkout@deadbeef\n""" if named else """      - uses: actions/checkout@deadbeef\n"""
        return """name: permanent\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  check:\n    steps:\n""" + checkout + """        with:\n          fetch-depth: 0\n          persist-credentials: false\n          ref: ${{ github.event.pull_request.head.sha || github.sha }}\n      - run: test \"$(git --no-replace-objects rev-parse HEAD)\" = \"${{ github.event.pull_request.head.sha || github.sha }}\"\n"""

    def test_named_checkout_is_checked_and_later_revision_is_scanned(self) -> None:
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
            (workflows / "owner-open-r15-permanent.yml").write_text(
                self.workflow(True).replace("persist-credentials: false", "persist-credentials: true"),
                encoding="utf-8",
            )
            errors = self.module.verify(root)["errors"]
            self.assertTrue(any("owner-open-r15-permanent.yml" in item and "persists credentials" in item for item in errors))


if __name__ == "__main__":
    unittest.main()
