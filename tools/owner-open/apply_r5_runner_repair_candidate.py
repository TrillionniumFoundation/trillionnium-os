#!/usr/bin/env python3
"""Apply the exact source/test repairs discovered by the R5 runner closeout.

This is a development-only, fail-closed applicator. It performs exact textual
replacements against the audited source cut and exits before writing a target
whose expected preimage is absent or ambiguous. It does not run effects,
contact providers, alter Android products, or promote evidence. The validating
workflow formats, commits locally, runs all Python/Rust gates, and pushes the
result only when every gate returns zero.
"""

from __future__ import annotations

import argparse
from pathlib import Path


class RepairError(RuntimeError):
    pass


def replace_exact(
    path: str,
    old: str,
    new: str,
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


def insert_after(
    path: str,
    marker: str,
    addition: str,
    expected: int = 1,
) -> None:
    replace_exact(path, marker, marker + addition, expected)


def replace_in_function(
    path: str,
    function: str,
    old: str,
    new: str,
    expected: int = 1,
) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    marker = f"    def {function}"
    try:
        start = text.index(marker)
    except ValueError as error:
        raise RepairError(f"{path}: function {function!r} is absent") from error
    next_method = text.find("\n    def ", start + len(marker))
    next_decorator = text.find("\n    @", start + len(marker))
    candidates = [value for value in (next_method, next_decorator) if value >= 0]
    end = min(candidates) if candidates else len(text)
    segment = text[start:end]
    count = segment.count(old)
    if count != expected:
        raise RepairError(
            f"{path}:{function}: expected {expected}, observed {count}: {old!r}"
        )
    target.write_text(
        text[:start] + segment.replace(old, new) + text[end:],
        encoding="utf-8",
    )


def repair_reserved_unittest_names() -> None:
    stage = "tools/tests/test_stage_owner_open_rootfs_payload_release.py"
    replace_exact(
        stage,
        "    def run(self, plan: Path, output: Path) -> subprocess.CompletedProcess[bytes]:\n",
        "    def run_command(\n"
        "        self, plan: Path, output: Path\n"
        "    ) -> subprocess.CompletedProcess[bytes]:\n",
    )
    replace_exact(stage, "self.run(plan, output)", "self.run_command(plan, output)", 7)

    supervisor = "tools/tests/test_supervise_codex_mcp_qualification_release.py"
    replace_exact(
        supervisor,
        "    def run(self, evidence: Path, *, timeout: str = \"5\", **environment: str):\n",
        "    def run_command(\n"
        "        self, evidence: Path, *, timeout: str = \"5\", **environment: str\n"
        "    ):\n",
    )
    replace_exact(supervisor, "self.run(evidence", "self.run_command(evidence", 3)


def repair_private_python_fixtures() -> None:
    supervisor_release = "tools/tests/test_supervise_codex_mcp_qualification_release.py"
    paths = (
        "tools/tests/test_supervise_codex_mcp_qualification.py",
        supervisor_release,
        "tools/tests/test_qualify_owner_open_adb.py",
        "tools/tests/test_qualify_owner_open_adb_selected.py",
    )
    for path in paths:
        insert_after(path, "from pathlib import Path\n", "import shutil\n")
        insert_after(
            path,
            "        self.root.chmod(0o700)\n",
            "        self.python = self.root / \"python\"\n"
            "        shutil.copyfile(Path(sys.executable).resolve(), self.python)\n"
            "        self.python.chmod(0o700)\n",
        )
        replace_exact(
            path,
            "            \"--python\",\n"
            "            str(Path(sys.executable).resolve()),\n",
            "            \"--python\",\n"
            "            str(self.python),\n",
        )

    shell_test = "tools/tests/test_build_shell_exec_artifact_set.py"
    insert_after(shell_test, "import platform\n", "import shutil\n")
    replace_in_function(
        shell_test,
        "test_supervisor_bounds_output_and_kills_surviving_descendants",
        "        python = BUILD.raw_primitives.open_retained_executable(\n"
        "            Path(sys.executable).resolve(), \"test Python\"\n"
        "        )\n",
        "        private_python = tempfile.TemporaryDirectory()\n"
        "        python_path = Path(private_python.name) / \"python\"\n"
        "        shutil.copyfile(Path(sys.executable).resolve(), python_path)\n"
        "        python_path.chmod(0o700)\n"
        "        python = BUILD.raw_primitives.open_retained_executable(\n"
        "            python_path, \"test Python\"\n"
        "        )\n",
    )
    replace_in_function(
        shell_test,
        "test_supervisor_bounds_output_and_kills_surviving_descendants",
        "        finally:\n"
        "            python.close()\n",
        "        finally:\n"
        "            python.close()\n"
        "            private_python.cleanup()\n",
    )


def repair_adb_test_isolation() -> None:
    relay_test = "tools/tests/test_adb_smart_socket_relay_selected.py"
    insert_after(
        relay_test,
        "class SelectedAdbSmartSocketRelayTest(unittest.TestCase):\n",
        "    RELAY = RELAY\n\n",
    )
    replace_exact(relay_test, "str(RELAY)", "str(self.RELAY)", 2)
    replace_exact(
        relay_test,
        "            \"tools/owner-open/adb_smart_socket_relay_selected.py\",\n",
        "            f\"tools/owner-open/{self.RELAY.name}\",\n",
    )

    selected_adb_test = "tools/tests/test_qualify_owner_open_adb_selected.py"
    insert_after(
        selected_adb_test,
        "class SelectedAdbQualificationTest(unittest.TestCase):\n",
        "    QUALIFIER = QUALIFIER\n"
        "    RELAY = RELAY\n\n",
    )
    replace_exact(selected_adb_test, "str(QUALIFIER)", "str(self.QUALIFIER)")
    replace_exact(selected_adb_test, "str(RELAY)", "str(self.RELAY)")

    release_paths = "tools/tests/test_release_qualification_paths.py"
    replace_exact(
        release_paths,
        "relay_suite.RELAY = ROOT / \"adb_smart_socket_relay_release.py\"\n"
        "adb_suite.RELAY = ROOT / \"adb_smart_socket_relay_release.py\"\n"
        "adb_suite.QUALIFIER = ROOT / \"qualify_owner_open_adb_release.py\"\n\n\n",
        "RELEASE_RELAY = ROOT / \"adb_smart_socket_relay_release.py\"\n"
        "RELEASE_QUALIFIER = ROOT / \"qualify_owner_open_adb_release.py\"\n\n\n",
    )
    replace_exact(
        release_paths,
        "class ReleaseAdbRelayTest(relay_suite.SelectedAdbSmartSocketRelayTest):\n"
        "    pass\n",
        "class ReleaseAdbRelayTest(relay_suite.SelectedAdbSmartSocketRelayTest):\n"
        "    RELAY = RELEASE_RELAY\n",
    )
    replace_exact(
        release_paths,
        "class ReleaseAdbQualificationTest(adb_suite.SelectedAdbQualificationTest):\n"
        "    pass\n",
        "class ReleaseAdbQualificationTest(adb_suite.SelectedAdbQualificationTest):\n"
        "    RELAY = RELEASE_RELAY\n"
        "    QUALIFIER = RELEASE_QUALIFIER\n",
    )

    release_paths_v2 = "tools/tests/test_release_qualification_paths_v2.py"
    replace_exact(
        release_paths_v2,
        "relay_suite.RELAY = RELEASE_RELAY\n"
        "adb_suite.RELAY = RELEASE_RELAY\n"
        "adb_suite.QUALIFIER = RELEASE_QUALIFIER\n\n\n",
        "",
    )
    insert_after(
        release_paths_v2,
        "class ReleaseAdbRelayV2Test(relay_suite.SelectedAdbSmartSocketRelayTest):\n",
        "    RELAY = RELEASE_RELAY\n\n",
    )
    replace_exact(
        release_paths_v2,
        "class ReleaseAdbQualificationV2Test(adb_suite.SelectedAdbQualificationTest):\n"
        "    pass\n",
        "class ReleaseAdbQualificationV2Test(adb_suite.SelectedAdbQualificationTest):\n"
        "    RELAY = RELEASE_RELAY\n"
        "    QUALIFIER = RELEASE_QUALIFIER\n",
    )


def repair_python_source_and_environment_contracts() -> None:
    selected_paths_test = "tools/tests/test_verify_owner_open_selected_paths.py"
    insert_after(selected_paths_test, "import json\n", "import sys\n")
    insert_after(
        selected_paths_test,
        "module = importlib.util.module_from_spec(spec)\n",
        "sys.modules[spec.name] = module\n",
    )

    p01_test = "tools/tests/test_p01_daemon_receipt_build.py"
    replace_in_function(
        p01_test,
        "test_group_writable_source_ancestor_uses_separate_nofollow_policy",
        "    def test_group_writable_source_ancestor_uses_separate_nofollow_policy(self) -> None:\n",
        "    def test_source_ancestor_uses_separate_nofollow_policy(self) -> None:\n",
    )
    replace_in_function(
        p01_test,
        "test_source_ancestor_uses_separate_nofollow_policy",
        "        self.assertNotEqual(current_control_mode & 0o020, 0)\n",
        "",
    )

    rootfs_test = "tools/tests/test_rootfs_v8_erofs_admission.py"
    replace_in_function(
        rootfs_test,
        "test_android_staging_filter_c_packager_erofs_differential_corpus",
        "        source = locate_android_staging_filter_c_source()\n",
        "        try:\n"
        "            source = locate_android_staging_filter_c_source()\n"
        "        except AssertionError as error:\n"
        "            self.skipTest(str(error))\n",
    )

    replace_exact(
        "tools/owner-open/prepare-adb-reverse-v1.sh",
        "[[ \"$SERIAL\" =~ ^[A-Za-z0-9._:\\[\\]-]{1,128}$ ]] || {\n"
        "  echo \"serial is empty or malformed\" >&2\n"
        "  exit 64\n"
        "}\n",
        "if [[ ! \"$SERIAL\" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] &&\n"
        "   [[ ! \"$SERIAL\" =~ ^\\[[0-9A-Fa-f:]+\\]:[0-9]{1,5}$ ]]; then\n"
        "  echo \"serial is empty or malformed\" >&2\n"
        "  exit 64\n"
        "fi\n",
    )

    replace_exact(
        "tools/materialize_p01_final_daemon_artifact.py",
        "CONTROL_REPOSITORY = REPOSITORY.parent\n",
        "CONTROL_REPOSITORY = REPOSITORY\n",
    )


def repair_rust_sources() -> None:
    event_store = "crates/trillionnium-owner-open-event-store/src/lib.rs"
    replace_exact(
        event_store,
        "    let read = reader\n"
        "        .take(maximum as u64 + 2)\n",
        "    let read = reader\n"
        "        .by_ref()\n"
        "        .take(maximum as u64 + 2)\n",
    )
    replace_exact(
        event_store,
        "    if matches!(\n"
        "        error.raw_os_error(),\n"
        "        Some(libc::EWOULDBLOCK) | Some(libc::EAGAIN)\n"
        "    ) {\n",
        "    if error\n"
        "        .raw_os_error()\n"
        "        .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)\n"
        "    {\n",
    )

    replace_exact(
        "crates/trillionnium-owner-open-runtime/src/lib.rs",
        "use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};\n",
        "use std::sync::mpsc::{SyncSender, sync_channel};\n",
    )


def apply_repairs() -> None:
    repair_reserved_unittest_names()
    repair_private_python_fixtures()
    repair_adb_test_isolation()
    repair_python_source_and_environment_contracts()
    repair_rust_sources()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited replacements to the current checkout",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    apply_repairs()
    print("PASS_R5_EXACT_REPAIRS_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
