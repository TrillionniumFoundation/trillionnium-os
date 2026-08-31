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

    def test_all_process_paths_preserve_owner_environment_semantics(self) -> None:
        paths = (
            "crates/trillionnium-owner-open-provider-jsonl/src/lib.rs",
            "crates/trillionnium-owner-open-job-runtime/src/process.rs",
            "crates/trillionnium-owner-open-runtime/src/process.rs",
        )
        for path in paths:
            text = (ROOT / path).read_text()
            # The R15 process boundary is deliberately deterministic: only
            # the small mechanical inherited allowlist crosses the Host
            # boundary, and request-specific values are applied afterward.
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

    def test_process_identity_publication_precedes_live_control(self) -> None:
        types = (ROOT / "crates/trillionnium-owner-open-job-runtime/src/types.rs").read_text()
        manager = (ROOT / "crates/trillionnium-owner-open-job-runtime/src/manager.rs").read_text()
        v7_wire = (ROOT / "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v7/wire.rs").read_text()
        docs = (ROOT / "docs/protocols/owner-open-jobs-v1.md").read_text()

        for field in ("pid", "process_group_id", "session_id", "boot_id", "start_time_ticks"):
            self.assertIn(field, types)
            self.assertIn(field, manager)
        self.assertIn("ProcessIdentityBound", types)
        self.assertIn("process_identity_for_event", manager)
        self.assertIn("FRAME_JOB_IDENTITY_BOUND", v7_wire)
        self.assertIn("process_identity_bound", v7_wire)
        self.assertIn("job.process_identity_bound", docs)

        publication_start = manager.index("let running = Arc::new(RunningJob")
        publication_end = manager.index("Ok(JobStartResult {", publication_start)
        publication = manager[publication_start:publication_end]
        self.assertLess(publication.index("ProcessIdentityBound"), publication.index("running_jobs.insert"))
        self.assertLess(publication.index("RuntimeJobEventKind::Started"), publication.index("running_jobs.insert"))
        self.assertLess(publication.index("complete_operation"), publication.index("running_jobs.insert"))
        self.assertLess(publication.index("spawn_dispatcher"), publication.rindex("drop(running_jobs)"))
        self.assertIn("running_jobs.remove(&request.key)", publication)
        # Every post-spawn event/journal failure must release the admission
        # guard before abort_started_job reacquires it for removal.
        self.assertGreaterEqual(publication.count("drop(running_jobs)"), 4)


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
