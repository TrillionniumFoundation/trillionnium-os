from __future__ import annotations

from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW_ROOT = Path(__file__).resolve().parents[2] / ".github" / "workflows"
ACTIVE_WORKFLOW_NAMES = (
    "g1-exact-head-source.yml",
    "g1-synthetic-merge.yml",
)


def workflow_paths() -> list[Path]:
    return [WORKFLOW_ROOT / name for name in ACTIVE_WORKFLOW_NAMES]


class OwnerOpenWorkflowExactHeadTest(unittest.TestCase):
    def test_direct_verifier_invocations_bind_checkout_pair(self) -> None:
        paths = workflow_paths()
        self.assertTrue(paths, f"no G1 workflows found under {WORKFLOW_ROOT}")
        for path in paths:
            with self.subTest(workflow=path.name):
                workflow = path.read_text(encoding="utf-8")
                self.assertIn(
                    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
                    workflow,
                )
                self.assertIn("fetch-depth: 0", workflow)
                self.assertIn("persist-credentials: false", workflow)
                self.assertIn("git --no-replace-objects", workflow)
                self.assertIn("python3 tools/docs/verify_global_docs.py", workflow)
                if path.name == "g1-exact-head-source.yml":
                    self.assertIn('ref: ${{ env.SOURCE_HEAD_SHA }}', workflow)
                    self.assertIn('SOURCE_HEAD_SHA', workflow)
                    self.assertIn(
                        'rev-parse HEAD^{tree}', workflow
                    )
                else:
                    self.assertIn('EVENT_BASE_SHA', workflow)
                    self.assertIn('EVENT_HEAD_SHA', workflow)
                    self.assertIn('rev-parse HEAD^1', workflow)
                    self.assertIn('rev-parse HEAD^2', workflow)

    def test_head_status_and_diff_checks_disable_replacement_objects(self) -> None:
        paths = workflow_paths()
        self.assertTrue(paths, f"no G1 workflows found under {WORKFLOW_ROOT}")
        checked = 0
        for path in paths:
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "git " not in line:
                    continue
                if re.search(r"\b(?:rev-parse|status|diff)\b", line) is None:
                    continue
                checked += 1
                with self.subTest(workflow=path.name, line=line_number):
                    self.assertIn(
                        "--no-replace-objects",
                        line,
                        "exact-head/status/diff git checks must ignore replace refs",
                    )
        self.assertGreaterEqual(checked, 1, "no git exact-head/status/diff check found")

    def test_synthetic_merge_binds_fork_and_manual_source_identity(self) -> None:
        workflow = (WORKFLOW_ROOT / "g1-synthetic-merge.yml").read_text(
            encoding="utf-8"
        )
        # The checkout must target the event's source repository explicitly;
        # otherwise a fork PR can accidentally run the base repository's head.
        self.assertIn("repository: ${{ env.EVENT_HEAD_REPOSITORY }}", workflow)
        self.assertIn("head_repository:", workflow)
        # A PR's hidden ref is served by the base repository and remains
        # verifiable for private forks without trusting an anonymous fork URL.
        self.assertIn('refs/pull/$EVENT_PR_NUMBER/head', workflow)
        self.assertIn('base_remote_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}.git"', workflow)
        self.assertNotIn(
            'git ls-remote "$EVENT_HEAD_REPOSITORY"',
            workflow,
            "parent movement must use the canonical base-repository PR ref",
        )
        # Missing manual inputs must not fall back to github.sha (the
        # workflow commit), which would silently qualify the wrong source.
        self.assertIn("INVALID_BASE_SHA", workflow)
        self.assertIn("INVALID_HEAD_SHA", workflow)
        self.assertIn("invalid/empty-head-repository", workflow)
        # The read-only token must not be inherited by source-controlled test
        # commands.  It is scoped to the provenance fetch/check steps and is
        # explicitly unset before checkout/merge processing.
        self.assertNotIn("GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertIn("G1_GIT_TOKEN: ${{ github.token }}", workflow)
        self.assertIn("unset G1_GIT_TOKEN", workflow)
        self.assertIn('[[ -e "$MERGE_DIR" || -L "$MERGE_DIR" ]]', workflow)
        self.assertNotIn('rm -rf -- "$MERGE_DIR"', workflow)
        self.assertIn("python3 -m unittest discover -s tools/tests -p 'test*.py' -v", workflow)
        for field in (
            '"head_repository"',
            '"event_name"',
            '"pull_request_number"',
            '"base_ref"',
            '"head_ref"',
        ):
            self.assertIn(field, workflow)


class WorktreeGuardExecutionTests(unittest.TestCase):
    """Execute the guards in the checked-in workflows, not an imitation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.bash = shutil.which("bash")
        cls.git = shutil.which("git")
        if cls.bash is None or cls.git is None:
            raise RuntimeError("workflow guard regression requires bash and git")
        cls.guards: list[tuple[str, str]] = []
        pattern = re.compile(
            r'(?m)^(?P<indent> +)if ! worktree_status=.*?'
            r'^\s*test -z "\$worktree_status"$',
            re.DOTALL,
        )
        for path in sorted(WORKFLOW_ROOT.glob("*.yml")):
            workflow = path.read_text(encoding="utf-8")
            for index, match in enumerate(pattern.finditer(workflow)):
                cls.guards.append((f"{path.name}:{index}", textwrap.dedent(match.group(0))))

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="g1-worktree-guard-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "checkout with spaces"
        self.repo.mkdir()
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.outside = self.root / "not a checkout"
        self.outside.mkdir()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update({
            "HOME": str(self.root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GITHUB_WORKSPACE": str(self.repo),
            "RUNNER_TEMP": str(self.runner),
            "MERGE_DIR": str(self.repo),
            "merge_dir": str(self.repo),
        })
        self.git_run("init", "-q")
        self.git_run("config", "user.email", "guard-test@example.invalid")
        self.git_run("config", "user.name", "Worktree Guard Test")
        (self.repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        self.git_run("add", "tracked.txt")
        self.git_run("commit", "-qm", "test fixture")
        for name in ("g1-synthetic-merge", "g1-evidence-merge", "g1-android-privilege-merge"):
            (self.runner / name).symlink_to(self.repo, target_is_directory=True)

    def git_run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.git, "--no-replace-objects", "-C", str(self.repo), *args],
            env=self.env, capture_output=True, text=True, check=True, timeout=10,
        )

    def assert_guards(self, *, success: bool, env: dict[str, str] | None = None) -> None:
        self.assertGreaterEqual(len(self.guards), 31, "a workflow worktree guard disappeared")
        for label, guard in self.guards:
            with self.subTest(guard=label):
                result = subprocess.run(
                    [self.bash, "-c", "set -euo pipefail\n" + guard],
                    cwd=self.outside, env=env if env is not None else self.env,
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode == 0, success, result.stderr)

    def test_every_status_query_uses_a_guard_and_explicit_checkout(self) -> None:
        status_queries = 0
        for path in sorted(WORKFLOW_ROOT.glob("*.yml")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\bgit\b.*\bstatus\b.*--porcelain", line) is None:
                    continue
                status_queries += 1
                with self.subTest(workflow=path.name, line=number):
                    self.assertTrue(line.strip().startswith('if ! worktree_status="$(git '))
                    self.assertIn('--no-replace-objects', line)
                    self.assertIn('-C "${', line)
                    self.assertIn(':?}', line)
                    self.assertIn('--untracked-files=all', line)
                    self.assertIn('--ignore-submodules=none', line)
        self.assertEqual(status_queries, len(self.guards))
        self.assertGreaterEqual(status_queries, 31)

    def test_clean_checkout_passes_from_unrelated_working_directory(self) -> None:
        self.assert_guards(success=True)

    def test_modified_tracked_file_fails(self) -> None:
        (self.repo / "tracked.txt").write_text("changed\n", encoding="utf-8")
        self.assert_guards(success=False)

    def test_staged_change_fails(self) -> None:
        (self.repo / "tracked.txt").write_text("staged\n", encoding="utf-8")
        self.git_run("add", "tracked.txt")
        self.assert_guards(success=False)

    def test_deleted_tracked_file_fails(self) -> None:
        (self.repo / "tracked.txt").unlink()
        self.assert_guards(success=False)

    def test_untracked_file_fails_even_when_git_config_hides_untracked(self) -> None:
        self.git_run("config", "status.showUntrackedFiles", "no")
        (self.repo / "new file.txt").write_text("untracked\n", encoding="utf-8")
        self.assert_guards(success=False)

    def test_non_repository_fails_instead_of_passing_with_empty_stdout(self) -> None:
        shutil.rmtree(self.repo / ".git")
        self.assert_guards(success=False)

    def test_missing_repository_directory_fails(self) -> None:
        shutil.rmtree(self.repo)
        self.assert_guards(success=False)

    def test_git_failure_with_empty_output_fails(self) -> None:
        fakebin = self.root / "bin"
        fakebin.mkdir()
        fakegit = fakebin / "git"
        fakegit.write_text("#!/bin/sh\nexit 73\n", encoding="utf-8")
        fakegit.chmod(0o755)
        env = dict(self.env, PATH=str(fakebin))
        self.assert_guards(success=False, env=env)

    def test_missing_git_executable_fails(self) -> None:
        env = dict(self.env, PATH=str(self.root / "missing-bin"))
        self.assert_guards(success=False, env=env)

    def test_empty_required_paths_fail(self) -> None:
        env = dict(self.env, GITHUB_WORKSPACE="", RUNNER_TEMP="", MERGE_DIR="", merge_dir="")
        self.assert_guards(success=False, env=env)

    def test_merge_guards_do_not_check_the_clean_source_checkout(self) -> None:
        # Source and merge are separate subjects: a clean source cannot hide
        # dirty merge output even when the invoking step happens to be there.
        clean = self.root / "clean-source"
        subprocess.run([self.git, "clone", "-q", str(self.repo), str(clean)],
                       env=self.env, check=True, capture_output=True, timeout=10)
        (self.repo / "tracked.txt").write_text("dirty merge\n", encoding="utf-8")
        env = dict(self.env, GITHUB_WORKSPACE=str(clean))
        for label, guard in self.guards:
            expected = '${GITHUB_WORKSPACE:?' in guard
            with self.subTest(guard=label):
                result = subprocess.run([self.bash, "-c", "set -euo pipefail\n" + guard],
                                        cwd=clean, env=env, capture_output=True, timeout=10)
                self.assertEqual(result.returncode == 0, expected, result.stderr)

    def test_original_nested_test_reproduces_false_success(self) -> None:
        # A control proving that this matrix catches the original defect.
        result = subprocess.run(
            [self.bash, "-c", 'set -euo pipefail\ntest -z "$(git --no-replace-objects status --porcelain=v1 --untracked-files=all)"'],
            cwd=self.outside, env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("not a git repository", result.stderr)



class SourcePrerequisiteWorkflowTests(unittest.TestCase):
    """Exercise the checked-in Bash guards with explicit test-only tools.

    Command doubles here test admission/error propagation, never qualify real
    Rust or ACL availability for the complete source-discovery suite.
    """
    @staticmethod
    def job_text(workflow: str, job: str) -> str:
        match = re.search(r"(?ms)^  " + re.escape(job) + r":\n.*?(?=^  [a-z][a-z0-9-]*:\n|\Z)", workflow)
        if match is None:
            raise AssertionError(f"missing job {job}")
        return match.group(0)

    @staticmethod
    def step_text(job: str, name: str) -> str:
        match = re.search(r"(?ms)^      - name: " + re.escape(name) + r"\n.*?(?=^      - name: |\Z)", job)
        if match is None:
            raise AssertionError(f"missing step {name}")
        return match.group(0)

    @classmethod
    def script(cls, job: str, name: str) -> str:
        step = cls.step_text(job, name)
        marker = "        run: |\n"
        if marker not in step:
            raise AssertionError(f"missing script in {name}")
        return textwrap.dedent(step.split(marker, 1)[1]).strip() + "\n"

    def setUp(self) -> None:
        self.jobs = [self.job_text((WORKFLOW_ROOT / name).read_text(), job)
                     for name, job in (("g1-exact-head-source.yml", "docs-graph"),
                                       ("g1-synthetic-merge.yml", "synthetic-merge"))]
        self.guards = [self.script(job, "Verify source-test prerequisites") for job in self.jobs]
        self.temp = tempfile.TemporaryDirectory(prefix="g1-prerequisite-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "test-only-bin"
        self.bin.mkdir()
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin), RUNNER_TEMP=str(self.runner))
        # The actual shell/core utilities run; only selected dependency commands
        # are doubles. Nothing is installed into the system or source checkout.
        for command in ("tee", "mktemp", "chmod", "grep", "rm"):
            executable = shutil.which(command)
            if executable is None:
                raise RuntimeError(f"guard tests require real {command}")
            (self.bin / command).symlink_to(executable)
        self.bash = shutil.which("bash")
        if self.bash is None:
            raise RuntimeError("guard tests require bash")
        self.tool("id", 'printf "%s\\n" "${TEST_UID-65534}"\nexit "${TEST_ID_STATUS:-0}"\n')
        self.tool("python3", 'exit "${TEST_PYTHON_STATUS:-0}"\n')
        self.tool("rustc", 'printf "%s\\n" "${TEST_RUST_VERSION:-rustc 1.93.0 (fixture)}"\nexit "${TEST_RUST_STATUS:-0}"\n')
        self.tool("cargo", 'printf "%s\\n" "${TEST_CARGO_VERSION:-cargo 1.93.0 (fixture)}"\nexit "${TEST_CARGO_STATUS:-0}"\n')
        self.tool("setfacl", 'exit "${TEST_ACL_STATUS:-0}"\n')
        self.tool("getfacl", 'printf "%s\\n" "${TEST_ACL_RECORD:-user:0:r--}"\nexit "${TEST_ACL_READ_STATUS:-0}"\n')

    def tool(self, name: str, body: str) -> None:
        target = self.bin / name
        target.write_text("#!/bin/sh\n" + body)
        target.chmod(0o700)

    def run_guards(self, *, success: bool, **environment: str) -> None:
        for index, guard in enumerate(self.guards):
            with self.subTest(lane=index):
                result = subprocess.run([self.bash, "-c", guard], cwd=self.runner,
                                        env=dict(self.env, **environment),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                if not success:
                    self.assertNotIn("SOURCE_TEST_PREREQUISITES_OK_NOT_QUALIFICATION", result.stdout)
                self.assertEqual(list(self.runner.glob("g1-acl-*")), [])

    def test_acl_installation_precedes_any_candidate_checkout(self) -> None:
        for job in self.jobs:
            install = self.step_text(job, "Install declared source-test system tools")
            self.assertLess(job.index(install), job.index("uses: actions/checkout@"))
            self.assertIn("working-directory: ${{ runner.temp }}", install)
            self.assertIn("/usr/bin/sudo /usr/bin/apt-get", install)
            self.assertIn("install --yes --no-install-recommends acl", install)
            self.assertNotIn("continue-on-error", install)
            self.assertNotIn("|| true", install)
            self.assertNotIn("python3", install)

    def test_both_lanes_pin_rust_and_python_before_preflight(self) -> None:
        for job in self.jobs:
            self.assertIn('python-version: "3.13"', job)
            self.assertIn('toolchain: "1.93.0"', job)
            self.assertLess(job.index('toolchain: "1.93.0"'), job.index("- name: Verify source-test prerequisites"))
            step = self.step_text(job, "Verify source-test prerequisites")
            self.assertIn("working-directory: ${{ runner.temp }}", step)
            self.assertNotIn("sudo", step)

    def test_complete_discovery_not_only_focused_suites(self) -> None:
        for job in self.jobs:
            self.assertIn("python3 -m unittest discover -s tools/tests -p 'test*.py' -v 2>&1 | tee", job)
            self.assertLess(job.index("- name: Verify source-test prerequisites"),
                            job.index("python3 -m unittest discover -s tools/tests -p 'test*.py'"))
            self.assertNotIn("continue-on-error:", job)

    def test_failure_diagnostics_have_no_qualification_authority(self) -> None:
        for job in self.jobs:
            step = self.step_text(job, "Retain source-test diagnostics without qualification authority")
            self.assertIn("if: ${{ always() }}", step)
            self.assertIn("g1-source-prerequisites.log", step)
            self.assertIn("g1-source-tools.log", step)
            self.assertIn("python.log", step)
            self.assertNotIn("evidence.json", step)

    def test_prerequisite_guards_are_identical(self) -> None:
        self.assertEqual(self.guards[0], self.guards[1])

    def test_all_changed_shell_blocks_parse(self) -> None:
        for job in self.jobs:
            for name in ("Install declared source-test system tools", "Verify source-test prerequisites"):
                script = self.script(job, name)
                result = subprocess.run([self.bash, "-n"], input=script, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_test_only_valid_dependencies_pass_the_guard(self) -> None:
        self.run_guards(success=True)

    def test_root_execution_is_rejected(self) -> None:
        self.run_guards(success=False, TEST_UID="0")

    def test_failed_uid_command_is_rejected(self) -> None:
        self.run_guards(success=False, TEST_ID_STATUS="25")

    def test_missing_or_malformed_uid_is_rejected(self) -> None:
        for value in ("", "unknown", "00", "-1"):
            with self.subTest(uid=value):
                self.run_guards(success=False, TEST_UID=value)

    def test_wrong_python_is_rejected(self) -> None:
        self.run_guards(success=False, TEST_PYTHON_STATUS="1")

    def test_wrong_or_prerelease_rust_is_rejected(self) -> None:
        for value in ("rustc 1.92.0 (fixture)", "rustc 1.93.0-nightly (fixture)", "rustc 1.93.00 (fixture)"):
            with self.subTest(version=value):
                self.run_guards(success=False, TEST_RUST_VERSION=value)

    def test_wrong_cargo_is_rejected(self) -> None:
        self.run_guards(success=False, TEST_CARGO_VERSION="cargo 1.94.0 (fixture)")

    def test_failing_compiler_is_not_hidden_by_tee(self) -> None:
        self.run_guards(success=False, TEST_RUST_STATUS="23")

    def test_failing_cargo_is_not_hidden_by_tee(self) -> None:
        self.run_guards(success=False, TEST_CARGO_STATUS="24")

    def test_missing_required_tool_is_rejected(self) -> None:
        for command in ("python3", "rustc", "cargo", "setfacl", "getfacl"):
            target = self.bin / command
            saved = target.read_text()
            target.unlink()
            try:
                with self.subTest(command=command):
                    self.run_guards(success=False)
            finally:
                target.write_text(saved)
                target.chmod(0o700)

    def test_acl_write_failure_is_rejected_and_probe_removed(self) -> None:
        self.run_guards(success=False, TEST_ACL_STATUS="1")

    def test_acl_read_failure_is_rejected_and_probe_removed(self) -> None:
        self.run_guards(success=False, TEST_ACL_READ_STATUS="1")

    def test_wrong_acl_readback_is_rejected(self) -> None:
        self.run_guards(success=False, TEST_ACL_RECORD="user:0:---")

    def test_empty_temp_directory_is_rejected(self) -> None:
        self.run_guards(success=False, RUNNER_TEMP="")

    def test_complete_source_failure_cannot_be_masked_by_tee(self) -> None:
        self.tool("python3", 'printf "%s\\n" "test-only unittest failure"\nexit 23\n')
        script = self.script(self.jobs[0], "Run the complete Python source matrix")
        result = subprocess.run([self.bash, "-c", script], cwd=self.runner, env=self.env,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 23)
        self.assertIn("test-only unittest failure", (self.runner / "g1-source-python.log").read_text())


if __name__ == "__main__":
    unittest.main()
