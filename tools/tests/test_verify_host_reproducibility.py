"""Contract and process-lifecycle tests for Host reproducibility builds."""
from __future__ import annotations

import copy
import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from tools.tests.authenticated_python_bootstrap_fixture import (
    BOOTSTRAP_LOGICAL_PATH,
    load_authenticated_module,
    run_authenticated,
)

PATH = Path(__file__).resolve().parents[1] / "build/verify_host_reproducibility.py"
LOGICAL_PATH = "tools/build/verify_host_reproducibility.py"
VERIFY = load_authenticated_module("host_reproducibility", PATH, LOGICAL_PATH)


def builds() -> list[dict]:
    item = {"exit_code": 0, "source_before": {"commit": "a", "lock": "locked"},
            "source_after": {"commit": "a", "lock": "locked"},
            "tools_before": {"rustc": "1.99.0"}, "tools_after": {"rustc": "1.99.0"},
            "artifacts": {name: {"size": 16, "sha256": "a" * 64} for name in VERIFY.BINARIES}}
    return [copy.deepcopy(item), copy.deepcopy(item)]


def live_task(pid: int) -> bool:
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return False
    fields = raw.rsplit(b")", 1)[1].split()
    return bool(fields) and fields[0] not in (b"Z", b"X")


def wait_not_live(pid: int) -> None:
    deadline = time.monotonic() + 3.0
    while live_task(pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    if live_task(pid):
        raise AssertionError(f"build descendant {pid} survived cleanup")


def split_group_script(*, flood: bool) -> str:
    child_body = (
        "chunk = b'x' * 4096\n"
        "while True:\n"
        "    os.write(1, chunk)\n"
        if flood
        else
        "while True:\n"
        "    time.sleep(1)\n"
    )
    return f'''\
import os
from pathlib import Path
import signal
import sys
import time

path = Path(sys.argv[1])
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    path.write_text(str(os.getpid()), encoding="ascii")
    {child_body.replace(chr(10), chr(10) + "    ").rstrip()}
while not path.exists():
    time.sleep(0.001)
os._exit(0)
'''


class HostReproducibilityTests(unittest.TestCase):
    def test_sealed_gcc_discovers_original_helper_prefix_and_compiles_without_ambient_flags(self) -> None:
        compiler = shutil.which("gcc")
        self.assertIsNotNone(compiler, "the sealed build recipe requires GNU GCC")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            custody = root / "custody"
            custody.mkdir(mode=0o700)
            pin = VERIFY.PinnedTool(Path(compiler).resolve(), custody, "cc")
            runtime = SimpleNamespace(descriptors=(), environment=lambda: {})
            try:
                helpers = VERIFY.gcc_helper_configuration(pin, root, runtime)
                self.assertFalse(helpers["helpers_recursively_attested"])
                self.assertEqual(helpers["discovery_execution"], "sealed-cc-with-selected-source-argv0")
                source = root / "hello.c"
                source.write_text('int main(void) { return 0; }\n')
                executable = root / "hello"
                tools = {name: {"path": "/unused/" + name} for name in ("cargo", "rustc", "cc", "ar")}
                tools["cc"]["gcc_helpers"] = helpers
                with mock.patch.dict(os.environ, {"GCC_EXEC_PREFIX": "/hostile/", "COMPILER_PATH": "/hostile/", "LIBRARY_PATH": "/hostile/"}):
                    _, env = VERIFY.recipe(root, root / "target", root / "home", root / "cache", tools, {"source_date_epoch": "123"})
                self.assertEqual(env["GCC_EXEC_PREFIX"], helpers["gcc_exec_prefix"])
                self.assertNotIn("COMPILER_PATH", env)
                self.assertNotIn("LIBRARY_PATH", env)
                env["PATH"] = "/usr/bin:/bin"
                result = subprocess.run([str(pin.execution_path), str(source), "-o", str(executable)],
                    env=env, pass_fds=(pin.descriptor,), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(subprocess.run([str(executable)]).returncode, 0)
                pin.assert_descriptor()
                pin.assert_source_selection()
            finally:
                pin.close()

    def query_split_group(self, stream: int | None, *, close_pipes: bool = False) -> str:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "child"
            body = (f"while True: os.write({stream}, b'x' * 4096)"
                    if stream is not None else "while True: time.sleep(1)")
            close = "os.close(1); os.close(2)" if close_pipes else ""
            script = f'''import os,signal,time
from pathlib import Path
child=os.fork()
if child==0:
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    Path({str(marker)!r}).write_text(str(os.getpid()))
    {close}
    {body}
while not Path({str(marker)!r}).exists(): time.sleep(0.001)
os.write(1,b'identity\\n')
os._exit(0)
'''
            started = time.monotonic()
            try:
                return VERIFY.query([sys.executable, "-c", script], root)
            finally:
                self.assertTrue(marker.exists(), "query did not start its native fork fixture")
                wait_not_live(int(marker.read_text()))
                self.assertLess(time.monotonic() - started, 6.0)

    def test_identity_query_bounds_stdout_before_capture_and_cleans_exited_leader_child(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "combined output bound"):
            self.query_split_group(1)

    def test_identity_query_bounds_stderr_before_capture_and_cleans_exited_leader_child(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "combined output bound"):
            self.query_split_group(2)

    def test_identity_query_uses_one_shared_stdout_stderr_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            script = "import os;os.write(1,b'x'*600);os.write(2,b'y'*600)"
            with mock.patch.object(VERIFY.CORE, "MAX_QUERY_OUTPUT_BYTES", 1024):
                with self.assertRaisesRegex(VERIFY.VerificationError, "combined output bound"):
                    VERIFY.query([sys.executable, "-c", script], Path(directory))

    def test_identity_query_timeout_cleans_child_after_leader_exit(self) -> None:
        with mock.patch.object(VERIFY.CORE, "QUERY_TIMEOUT_SECONDS", 1.0):
            with self.assertRaisesRegex(VERIFY.VerificationError, "timeout"):
                self.query_split_group(None)

    def test_successful_identity_query_cleans_child_that_closed_both_pipes(self) -> None:
        self.assertEqual(self.query_split_group(None, close_pipes=True), "identity")

    def test_identity_query_has_devnull_stdin_finite_env_and_explicit_fd_inheritance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, b"identity\n")
                script = ("import os;assert os.read(0,1)==b'';"
                          "assert set(os.environ)=={'PATH','LC_ALL'};"
                          f"os.write(1,os.read({read_fd},64))")
                self.assertEqual(VERIFY.query([sys.executable, "-c", script], Path(directory),
                                              pass_fds=(read_fd,)), "identity")
            finally:
                os.close(read_fd)
                os.close(write_fd)

    def test_identity_query_nonzero_status_does_not_expose_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            script = "import os;os.write(2,b'private-fixture-token');os._exit(7)"
            with self.assertRaisesRegex(VERIFY.VerificationError, "status 7") as failure:
                VERIFY.query([sys.executable, "-c", script], Path(directory))
            self.assertNotIn("private-fixture-token", str(failure.exception))

    def test_identity_query_requires_strict_utf8_on_both_streams_without_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for stream in (1, 2):
                with self.subTest(stream=stream):
                    script = f"import os;os.write({stream},b'private-fixture-token'+bytes([255]))"
                    with self.assertRaisesRegex(VERIFY.VerificationError, "strict UTF-8") as failure:
                        VERIFY.query([sys.executable, "-c", script], Path(directory))
                    self.assertNotIn("private-fixture-token", str(failure.exception))

    def test_identity_query_selector_setup_failure_reaps_actual_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original = VERIFY.CLEANUP.OwnedSessionPopen.__init__
            processes = []

            def observe(process, *args, **kwargs):
                original(process, *args, **kwargs)
                processes.append(process)

            with mock.patch.object(VERIFY.CLEANUP.OwnedSessionPopen, "__init__", observe), \
                    mock.patch.object(VERIFY.selectors, "DefaultSelector", side_effect=OSError("fixture setup")):
                with self.assertRaisesRegex(OSError, "fixture setup"):
                    VERIFY.query([sys.executable, "-c", "import time;time.sleep(20)"], Path(directory))
            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(processes[0].returncode)
            self.assertTrue(processes[0].stdout.closed)
            self.assertTrue(processes[0].stderr.closed)
            wait_not_live(processes[0].pid)

    def make_runtime_sdk(self, root: Path) -> tuple[Path, Path]:
        compiler = shutil.which("cc")
        if compiler is None:
            self.fail("the Linux reproducibility test requires the documented C compiler")
        sdk, custody = root / "sdk", root / "custody"
        (sdk / "bin").mkdir(parents=True)
        (sdk / "lib").mkdir()
        custody.mkdir(mode=0o700)
        llvm = sdk / "lib/libLLVM.so.test"
        driver = sdk / "lib/librustc_driver-deadbeef.so"
        for text, output, arguments in (
            ("int llvm_value(void) { return 17; }", llvm,
             ["-shared", "-fPIC", "-Wl,-soname,libLLVM.so.test"]),
            ("extern int llvm_value(void); int driver_value(void) { return llvm_value(); }",
             driver, ["-shared", "-fPIC", "-L" + str(sdk / "lib"),
                      "-Wl,--no-as-needed", "-l:libLLVM.so.test",
                      "-Wl,-soname,librustc_driver-deadbeef.so",
                      "-Wl,-rpath,$ORIGIN/../lib"]),
            ('#include <stdio.h>\nextern int driver_value(void);\n'
             'int main(void) { printf("%d\\n", driver_value()); return 0; }',
             sdk / "bin/rustc", ["-L" + str(sdk / "lib"),
                                 "-l:librustc_driver-deadbeef.so",
                                 "-Wl,-rpath,$ORIGIN/../lib"]),
        ):
            subprocess.run([compiler, "-x", "c", "-", *arguments, "-o", str(output)],
                           input=text, text=True, capture_output=True, check=True)
        return sdk, custody

    def test_sealed_runtime_executes_original_shared_elf_after_both_library_swaps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk, custody = self.make_runtime_sdk(root)
            pin = VERIFY.PinnedTool(sdk / "bin/rustc", custody, "rustc")
            runtime = VERIFY.PinnedRustRuntime(sdk / "bin/rustc", custody)
            try:
                for library in runtime.pins.values():
                    library.requested_path.write_bytes(b"hostile replacement")
                    with self.assertRaises(OSError):
                        os.pwrite(library.descriptor, b"X", 0)
                    self.assertEqual(fcntl.fcntl(library.descriptor, fcntl.F_GET_SEALS), 15)
                actual = VERIFY.query([str(pin.execution_path)], root,
                                      pass_fds=(pin.descriptor, *runtime.descriptors),
                                      runtime=runtime)
                self.assertEqual(actual, "17")
                marker = root / "mutable-executed"
                pin.requested_path.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
                pin.requested_path.chmod(0o700)
                self.assertEqual(VERIFY.query([str(pin.requested_path)], root,
                    executable=pin.execution_path,
                    pass_fds=(pin.descriptor, *runtime.descriptors), runtime=runtime), "17")
                self.assertFalse(marker.exists())
                runtime.assert_descriptor()
                with self.assertRaisesRegex(VERIFY.VerificationError, "selected tool"):
                    runtime.assert_source_selection()
            finally:
                runtime.close()
                pin.close()

    def test_runtime_query_and_recipe_discard_ambient_loader_variables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk, custody = self.make_runtime_sdk(root)
            pin = VERIFY.PinnedTool(sdk / "bin/rustc", custody, "rustc")
            runtime = VERIFY.PinnedRustRuntime(sdk / "bin/rustc", custody)
            marker = root / "ambient-executed"
            preload = root / "preload.so"
            payload = ('#include <stdio.h>\n__attribute__((constructor)) '
                       f'void hostile(void) {{ FILE *f=fopen("{marker}", "w"); '
                       'if(f) { fputs("executed",f); fclose(f); } }')
            subprocess.run([shutil.which("cc"), "-x", "c", "-", "-shared", "-fPIC",
                            "-o", str(preload)], input=payload, text=True,
                           capture_output=True, check=True)
            try:
                with mock.patch.dict(os.environ, {"LD_PRELOAD": str(preload),
                                                   "LD_LIBRARY_PATH": str(root)}):
                    self.assertEqual(VERIFY.query([str(pin.execution_path)], root,
                        pass_fds=(pin.descriptor, *runtime.descriptors), runtime=runtime), "17")
                    tools = {name: {"path": "/tools/" + name}
                             for name in ("cargo", "rustc", "cc", "ar")}
                    tools["rust_runtime"] = runtime.identity()
                    _, env = VERIFY.recipe(root, root / "target", root / "home", root / "cache",
                                           tools, {"source_date_epoch": "123"})
                self.assertFalse(marker.exists())
                self.assertNotIn("LD_PRELOAD", env)
                self.assertEqual(env["LD_LIBRARY_PATH"], str(runtime.execution_directory))
                flags = env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
                self.assertEqual(flags[flags.index("--sysroot") + 1], str(sdk))
            finally:
                runtime.close()
                pin.close()

    def test_runtime_nonelf_symlink_ambiguity_and_aggregate_bound_fail_without_fd_leaks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk, _ = self.make_runtime_sdk(root)
            originals = {path.name: path.read_bytes() for path in (sdk / "lib").iterdir()}
            baseline = len(os.listdir("/proc/self/fd"))
            for index, failure in enumerate(("nonelf", "symlink", "ambiguous", "budget")):
                with self.subTest(failure=failure):
                    for path in (sdk / "lib").iterdir():
                        path.unlink()
                    for name, data in originals.items():
                        (sdk / "lib" / name).write_bytes(data)
                    custody = root / f"failure-{index}"
                    custody.mkdir(mode=0o700)
                    driver = sdk / "lib/librustc_driver-deadbeef.so"
                    if failure == "nonelf":
                        driver.write_bytes(b"not an ELF")
                    elif failure == "symlink":
                        driver.unlink()
                        driver.symlink_to(sdk / "lib/libLLVM.so.test")
                    elif failure == "ambiguous":
                        (sdk / "lib/librustc_driver-cafe.so").write_bytes(originals[driver.name])
                    bound = 1 if failure == "budget" else VERIFY.MAX_PINNED_RUST_RUNTIME_BYTES
                    with mock.patch.object(VERIFY.CORE, "MAX_PINNED_RUST_RUNTIME_BYTES", bound):
                        with self.assertRaises((RuntimeError, OSError, VERIFY.VerificationError)):
                            VERIFY.PinnedRustRuntime(sdk / "bin/rustc", custody)
                    self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_only_two_successful_identical_builds_pass(self) -> None:
        self.assertTrue(VERIFY.compare_artifacts(builds())["passed"])
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.compare_artifacts(builds()[:1])

    def test_artifact_difference_has_failure_gate(self) -> None:
        value = builds()
        value[1]["artifacts"][VERIFY.BINARIES[0]]["sha256"] = "b" * 64
        result = VERIFY.compare_artifacts(value)
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "FAIL_ARTIFACT_DIFFERENCE")

    def test_build_failure_source_or_tool_drift_missing_artifact_cannot_pass(self) -> None:
        changes = [lambda b: b[1].update(exit_code=101),
                   lambda b: b[0]["source_after"].update(lock="changed"),
                   lambda b: b[1]["source_before"].update(commit="moved"),
                   lambda b: b[1]["tools_after"].update(rustc="other"),
                   lambda b: b[0]["artifacts"].pop(VERIFY.BINARIES[0]),
                   lambda b: [item["artifacts"][VERIFY.BINARIES[0]].pop("sha256") for item in b]]
        for change in changes:
            with self.subTest(change=change):
                value = builds()
                change(value)
                with self.assertRaises(VERIFY.VerificationError):
                    VERIFY.compare_artifacts(value)

    def test_implementation_manifest_binds_facade_core_and_cleanup_sources(self) -> None:
        manifest = VERIFY.implementation_manifest()
        self.assertEqual([item["path"] for item in manifest["files"]],
                         list(VERIFY.IMPLEMENTATION_PATHS))
        VERIFY.validate_implementation_manifest(manifest)
        with tempfile.TemporaryDirectory() as directory:
            copied_root = Path(directory)
            for relative in VERIFY.IMPLEMENTATION_PATHS:
                source = VERIFY.CORE.ROOT / relative
                destination = copied_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            with mock.patch.object(VERIFY.CORE, "ROOT", copied_root), \
                 mock.patch.object(VERIFY.CORE, "PINNED_IMPLEMENTATION_FILES", None):
                before = VERIFY.live_implementation_manifest()
                target = copied_root / VERIFY.IMPLEMENTATION_PATHS[-1]
                target.write_bytes(target.read_bytes() + b"\n# identity mutation\n")
                after = VERIFY.live_implementation_manifest()
        self.assertNotEqual(before["manifest_sha256"], after["manifest_sha256"])
        core_source = Path(VERIFY.CORE_PATH).read_text(encoding="utf-8")
        self.assertIn('"implementation_manifest": implementation', core_source)

    def test_snapshot_loader_executes_the_admitted_bytes_after_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module_path = root / "module.py"
            safe = b"VALUE = 'safe'\n"
            module_path.write_bytes(safe)

            def swap(path: Path) -> None:
                path.write_text("raise RuntimeError('hostile path bytes executed')\n")

            with mock.patch.object(VERIFY, "REPOSITORY_ROOT", root):
                module, loaded, identity = VERIFY._load_snapshot(
                    "host_reproducibility_snapshot_test",
                    module_path,
                    "module.py",
                    before_exec=swap,
                )
            self.assertEqual(loaded, safe)
            self.assertEqual(module.VALUE, "safe")
            self.assertEqual(identity["sha256"], VERIFY.sha256(safe))
            sys.modules.pop("host_reproducibility_snapshot_test", None)

    def test_descriptor_pinned_tool_survives_source_swap_but_reports_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "python-source"
            custody = root / "custody"
            custody.mkdir(mode=0o700)
            shutil.copyfile(sys.executable, source)
            source.chmod(0o700)
            pin = VERIFY.PinnedTool(source, custody, "python")
            try:
                source.write_bytes(b"#!/bin/sh\nexit 98\n")
                source.chmod(0o700)
                result = subprocess.run(
                    [str(pin.execution_path), "-I", "-c", "print('descriptor-safe')"],
                    pass_fds=(pin.descriptor,),
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.stdout.strip(), "descriptor-safe")
                pin.assert_descriptor()
                with self.assertRaisesRegex(VERIFY.VerificationError, "selected tool"):
                    pin.assert_source_selection()
            finally:
                pin.close()

    def test_recipe_is_fixed_offline_and_remaps_both_build_paths(self) -> None:
        tools = {
            name: {"path": f"/tools/original/{name}",
                   "execution_path": f"/custody/{name}"}
            for name in ("cargo", "rustc", "cc", "ar")
        }
        for label in ("a", "b"):
            command, env = VERIFY.recipe(Path("/source"), Path(f"/tmp/target-{label}"),
                Path(f"/tmp/home-{label}"), Path("/cache"), tools, {"source_date_epoch": "123"})
            for flag in ("--locked", "--offline", "--frozen", "--release"):
                self.assertIn(flag, command)
            self.assertEqual(command[0], "/custody/cargo")
            self.assertEqual(env["RUSTC"], "/custody/rustc")
            self.assertEqual(env["CC"], "/custody/cc")
            self.assertEqual(env["AR"], "/custody/ar")
            self.assertEqual(env["SOURCE_DATE_EPOCH"], "123")
            self.assertEqual(env["CARGO_INCREMENTAL"], "0")
            self.assertIn(f"--remap-path-prefix=/tmp/target-{label}=/build/target", env["CARGO_ENCODED_RUSTFLAGS"])
            self.assertIn(f"--remap-path-prefix=/tmp/home-{label}=/build/cargo-home", env["CARGO_ENCODED_RUSTFLAGS"])
            self.assertNotIn("RUSTUP_TOOLCHAIN", env)

    def test_ambient_cargo_config_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, cache = root / "repo", root / "cache"
            repo.mkdir()
            cache.mkdir()
            (cache / "config.toml").write_text("[build]\nrustflags=['unexpected']\n")
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.reject_ambient_config(repo, cache)

    def test_fixed_toolchain_version_rejected_before_build(self) -> None:
        paths = [Path("/cargo"), Path("/rustc"), Path("/cc"), Path("/ar")]
        with mock.patch.object(VERIFY.CORE, "file_identity", return_value={"path": "/tool", "sha256": "x"}), \
             mock.patch.object(VERIFY.CORE, "query", side_effect=["cargo 1.95.0 (x)", "rustc 1.99.0 (x)\nrelease: 1.99.0"]):
            with self.assertRaisesRegex(VERIFY.VerificationError, "Cargo must"):
                VERIFY.toolchain_identity(*paths, Path("/repo"))

    def test_dirty_or_moved_source_is_rejected(self) -> None:
        with mock.patch.object(VERIFY.CORE, "query", side_effect=["/repo", "head", " M Cargo.toml"]):
            with self.assertRaisesRegex(VERIFY.VerificationError, "source must be clean"):
                VERIFY.source_identity(Path("/repo"))
        with mock.patch.object(VERIFY.CORE, "query", side_effect=["/repo", "moved"]):
            with self.assertRaisesRegex(VERIFY.VerificationError, "expected commit"):
                VERIFY.source_identity(Path("/repo"), "reviewed")

    def run_split_group(self, *, flood: bool, timeout: float) -> tuple[Path, Path, float]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        child_path = root / "child"
        log = root / "cargo.log"
        started = time.monotonic()
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.run_build(
                [sys.executable, "-c", split_group_script(flood=flood), str(child_path)],
                dict(os.environ),
                root,
                log,
                timeout,
            )
        elapsed = time.monotonic() - started
        child = int(child_path.read_text(encoding="ascii"))
        wait_not_live(child)
        return root, log, elapsed

    def test_timeout_cleans_child_after_leader_exit_and_next_build_is_clean(self) -> None:
        root, _, elapsed = self.run_split_group(flood=False, timeout=1.0)
        self.assertLess(elapsed, 5.0)
        result = VERIFY.run_build(
            [sys.executable, "-c", "pass"],
            dict(os.environ),
            root,
            root / "next.log",
            2,
        )
        self.assertEqual(result["exit_code"], 0)

    def test_log_bound_cleans_child_after_leader_exit(self) -> None:
        with mock.patch.object(VERIFY.CORE, "MAX_LOG_BYTES", 1024):
            _, log, elapsed = self.run_split_group(flood=True, timeout=2)
        self.assertLess(elapsed, 5.0)
        self.assertLessEqual(log.stat().st_size, 1024)


    def test_direct_build_launcher_is_non_authorizing(self) -> None:
        result = subprocess.run(
            [sys.executable, str(PATH), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("direct pathname execution is non-authorizing", result.stderr)

    def test_authenticated_build_bootstrap_runs_help(self) -> None:
        result = run_authenticated(PATH, LOGICAL_PATH, ["--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout.lower())
        manifest = VERIFY.implementation_manifest()
        bootstrap = manifest["files"][0]
        self.assertEqual(bootstrap["path"], BOOTSTRAP_LOGICAL_PATH)
        self.assertEqual(bootstrap, VERIFY.PINNED_IMPLEMENTATION_FILES[BOOTSTRAP_LOGICAL_PATH])

    def test_preinterpreter_build_swap_restore_cannot_emit_admitted_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "verify_host_reproducibility.py"
            backup = root / "verify_host_reproducibility.reviewed"
            marker = root / "hostile-ran"
            shutil.copyfile(PATH, backup)
            launcher.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('ran')\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            result = run_authenticated(
                launcher,
                LOGICAL_PATH,
                ["--help"],
                restore_backup=backup,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unadmitted launcher bytes", result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(launcher.read_bytes(), PATH.read_bytes())

    def test_build_launcher_rejects_swap_restore_before_facade_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            facade = root / "facade.py"
            backup = root / "facade.reviewed"
            marker = root / "hostile-ran"
            reviewed = b"VALUE = 'reviewed'\n"
            facade.write_bytes(reviewed)
            hostile = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('ran')\n"
            ).encode()
            swapped = False

            def before(_absolute: Path, _component: str, final: bool) -> None:
                nonlocal swapped
                if final and not swapped:
                    facade.rename(backup)
                    facade.write_bytes(hostile)
                    swapped = True

            def restore(_absolute: Path, _descriptor: int) -> None:
                facade.unlink()
                backup.rename(facade)

            with self.assertRaisesRegex(RuntimeError, "unadmitted facade bytes"):
                getattr(VERIFY, "__launcher_authenticate_facade")(
                    facade,
                    expected_sha256=VERIFY.sha256(reviewed),
                    before_component=before,
                    after_final=restore,
                )
            self.assertFalse(marker.exists())
            self.assertEqual(facade.read_bytes(), reviewed)

    def test_build_snapshot_walk_rejects_parent_symlink_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "selected"
            backup = root / "selected-reviewed"
            attacker = root / "attacker"
            parent.mkdir()
            attacker.mkdir()
            (parent / "module.py").write_text("VALUE = 'reviewed'\n")
            (attacker / "module.py").write_text("raise RuntimeError('hostile')\n")
            swapped = False

            def swap(_absolute: Path, component: str, final: bool) -> None:
                nonlocal swapped
                if component == parent.name and not final and not swapped:
                    parent.rename(backup)
                    parent.symlink_to(attacker, target_is_directory=True)
                    swapped = True

            try:
                with mock.patch.object(VERIFY, "REPOSITORY_ROOT", root):
                    with self.assertRaises(OSError):
                        VERIFY._snapshot_source(
                            parent / "module.py",
                            "selected/module.py",
                            before_component=swap,
                        )
            finally:
                if parent.is_symlink():
                    parent.unlink()
                if backup.exists():
                    backup.rename(parent)

    def test_build_python_final_component_swap_restore_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "module.py"
            backup = root / "module.reviewed"
            source.write_text("VALUE = 'reviewed'\n")
            swapped = False

            def before(_absolute: Path, _component: str, final: bool) -> None:
                nonlocal swapped
                if final and not swapped:
                    source.rename(backup)
                    source.write_text("raise RuntimeError('hostile')\n")
                    swapped = True

            def restore(_absolute: Path, _descriptor: int) -> None:
                source.unlink()
                backup.rename(source)

            with mock.patch.object(VERIFY, "REPOSITORY_ROOT", root):
                with self.assertRaisesRegex(RuntimeError, "selection changed"):
                    VERIFY._snapshot_source(
                        source,
                        "module.py",
                        before_component=before,
                        after_final=restore,
                    )

    def test_all_toolchain_roles_reject_parent_substitution(self) -> None:
        for role in ("cargo", "rustc", "cc", "ar"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent = root / "selected"
                backup = root / "selected-reviewed"
                attacker = root / "attacker"
                custody = root / "custody"
                parent.mkdir()
                attacker.mkdir()
                custody.mkdir(mode=0o700)
                source = parent / role
                shutil.copyfile(sys.executable, source)
                source.chmod(0o700)
                hostile = attacker / role
                hostile.write_text("#!/bin/sh\nexit 99\n")
                hostile.chmod(0o700)
                swapped = False

                def before(_absolute: Path, component: str, final: bool) -> None:
                    nonlocal swapped
                    if component == parent.name and not final and not swapped:
                        parent.rename(backup)
                        parent.symlink_to(attacker, target_is_directory=True)
                        swapped = True

                try:
                    with self.assertRaises(OSError):
                        VERIFY.PinnedTool(
                            source,
                            custody,
                            role,
                            before_component=before,
                        )
                finally:
                    if parent.is_symlink():
                        parent.unlink()
                    if backup.exists():
                        backup.rename(parent)

    def test_all_toolchain_roles_reject_final_swap_restore(self) -> None:
        for role in ("cargo", "rustc", "cc", "ar"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / f"{role}-source"
                backup = root / f"{role}-reviewed"
                custody = root / "custody"
                custody.mkdir(mode=0o700)
                shutil.copyfile(sys.executable, source)
                source.chmod(0o700)
                swapped = False

                def before(_absolute: Path, _component: str, final: bool) -> None:
                    nonlocal swapped
                    if final and not swapped:
                        source.rename(backup)
                        source.write_text("#!/bin/sh\nexit 98\n")
                        source.chmod(0o700)
                        swapped = True

                def restore(_absolute: Path, _descriptor: int) -> None:
                    source.unlink()
                    backup.rename(source)

                with self.assertRaisesRegex(
                    VERIFY.VerificationError, "changed before custody completed"
                ):
                    VERIFY.PinnedTool(
                        source,
                        custody,
                        role,
                        before_component=before,
                        after_final=restore,
                    )



if __name__ == "__main__":
    unittest.main()
