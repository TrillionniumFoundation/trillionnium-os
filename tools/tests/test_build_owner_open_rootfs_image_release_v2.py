from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1] / "owner-open"
STAGER = TOOLS / "stage_owner_open_rootfs_payload_release.py"
BUILDER = TOOLS / "build_owner_open_rootfs_image_release_v2.py"
HELP = "-noappend -all-root -no-xattrs -no-exports -no-progress -comp -b -mkfs-time -all-time -sort"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def aarch64_elf() -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<H", header, 16, 2)
    struct.pack_into("<H", header, 18, 183)
    return bytes(header) + b"host-fixture"


def deterministic_tool(help_text: str = HELP) -> str:
    return f'''#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import stat
import sys
if sys.argv[1:] == ["-help"]:
    print({help_text!r})
    raise SystemExit(0)
source = Path(sys.argv[1])
output = Path(sys.argv[2])
digest = hashlib.sha256()
for path in sorted(source.rglob("*")):
    relative = path.relative_to(source).as_posix().encode()
    metadata = path.lstat()
    if path.is_dir():
        continue
    digest.update(len(relative).to_bytes(4, "little"))
    digest.update(relative)
    digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "little"))
    raw = path.read_bytes()
    digest.update(len(raw).to_bytes(8, "little"))
    digest.update(raw)
output.write_bytes(b"FAKE-SQUASHFS\\0" + digest.digest())
output.chmod(0o644)
raise SystemExit(0)
'''


def nondeterministic_tool(counter: Path) -> str:
    return f'''#!/usr/bin/env python3
from pathlib import Path
import sys
if sys.argv[1:] == ["-help"]:
    print({HELP!r})
    raise SystemExit(0)
counter = Path({str(counter)!r})
value = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(value))
output = Path(sys.argv[2])
output.write_bytes(b"NONDETERMINISTIC" + value.to_bytes(8, "little"))
output.chmod(0o644)
raise SystemExit(0)
'''


class BuildOwnerOpenRootfsImageReleaseV2Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.inputs = self.root / "inputs"
        self.staging_parent = self.root / "staging"
        self.output_parent = self.root / "images"
        for path in (self.inputs, self.staging_parent, self.output_parent):
            path.mkdir(mode=0o700)
        self.host = self.inputs / "host"
        self.config = self.inputs / "config.json"
        self.host.write_bytes(aarch64_elf())
        self.config.write_text('{"fixture":true}\n', encoding="utf-8")
        self.host.chmod(0o700)
        self.config.chmod(0o600)
        self.staging = self.staging_parent / "payload"
        self.stage_payload()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def stage_payload(self) -> None:
        plan = self.root / "plan.json"
        plan.write_text(
            json.dumps(
                {
                    "schema": "org.trillionnium.owner-open.rootfs-payload-plan.v1",
                    "payload_id": "image-fixture",
                    "architecture": "aarch64",
                    "libc": "glibc",
                    "entries": [
                        {
                            "role": "host",
                            "source": str(self.host),
                            "destination": "/usr/libexec/trillionnium/host",
                            "mode": "0555",
                            "uid": 0,
                            "gid": 0,
                            "expected_sha256": digest(self.host),
                            "require_aarch64_elf": True,
                        },
                        {
                            "role": "config",
                            "source": str(self.config),
                            "destination": "/etc/trillionnium/owner-open/config.json",
                            "mode": "0444",
                            "uid": 0,
                            "gid": 0,
                            "expected_sha256": digest(self.config),
                        },
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        plan.chmod(0o600)
        completed = subprocess.run(
            [
                str(Path(sys.executable).resolve()),
                str(STAGER),
                "--execute",
                "--plan",
                str(plan),
                "--output",
                str(self.staging),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )

    def tool(self, source: str, name: str = "mksquashfs") -> Path:
        path = self.root / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o700)
        return path

    def command(
        self,
        tool: Path,
        output: Path,
        *,
        expected: str | None = None,
        timeout: str = "10",
    ) -> list[str]:
        return [
            str(Path(sys.executable).resolve()),
            str(BUILDER),
            "--execute",
            "--staging",
            str(self.staging),
            "--mksquashfs",
            str(tool),
            "--expected-mksquashfs-sha256",
            expected or digest(tool),
            "--output",
            str(output),
            "--runs",
            "2",
            "--probe-timeout",
            "3",
            "--build-timeout",
            timeout,
            "--json",
        ]

    def run_command(
        self, command: list[str], timeout: float = 30
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )

    def test_two_independent_builds_are_byte_identical(self) -> None:
        tool = self.tool(deterministic_tool())
        output = self.output_parent / "pass"
        completed = self.run_command(self.command(tool, output))
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        result = json.loads(completed.stdout)
        self.assertTrue(result["reproducible"])
        self.assertEqual(result["reproducibility_runs"], 2)
        self.assertEqual(len({item["image_sha256"] for item in result["build_runs"]}), 1)
        self.assertFalse(result["claims"]["image_included"])
        image = output / "owner-open-rootfs.squashfs"
        manifest = output / "owner-open-rootfs.image-manifest.json"
        self.assertTrue(image.exists())
        self.assertTrue(manifest.exists())
        self.assertEqual(stat.S_IMODE(image.lstat().st_mode), 0o444)
        image_value = json.loads(manifest.read_text())
        self.assertEqual(image_value["image_sha256"], digest(image))
        self.assertEqual(
            image_value["runtime_state_directory"],
            "/var/lib/trillionnium/owner-open",
        )
        self.assertFalse(any(path.name.startswith("run-") for path in output.iterdir()))

    def test_missing_runtime_state_mountpoint_is_rejected(self) -> None:
        (self.staging / "root/var/lib/trillionnium/owner-open").rmdir()
        tool = self.tool(deterministic_tool())
        output = self.output_parent / "missing-state-mountpoint"
        completed = self.run_command(self.command(tool, output))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"canonical writable state mountpoint", completed.stderr)
        self.assertFalse(output.exists())

    def test_staging_tamper_is_rejected_before_output_creation(self) -> None:
        target = self.staging / "root/etc/trillionnium/owner-open/config.json"
        target.chmod(0o644)
        target.write_text("tampered\n", encoding="utf-8")
        target.chmod(0o444)
        tool = self.tool(deterministic_tool())
        output = self.output_parent / "tampered"
        completed = self.run_command(self.command(tool, output))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"digest or byte count drifted", completed.stderr)
        self.assertFalse(output.exists())

    def test_tool_digest_and_help_options_are_bound(self) -> None:
        tool = self.tool(deterministic_tool())
        output = self.output_parent / "wrong-tool"
        completed = self.run_command(self.command(tool, output, expected="0" * 64))
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(output.exists())

        missing = self.tool(deterministic_tool("-noappend -all-root"), "mksquashfs-missing")
        output = self.output_parent / "missing-options"
        completed = self.run_command(self.command(missing, output))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"lacks required deterministic options", completed.stderr)
        self.assertFalse(output.exists())

    def test_nondeterministic_image_tool_is_rejected_and_cleaned(self) -> None:
        tool = self.tool(
            nondeterministic_tool(self.root / "counter"),
            "mksquashfs-nondeterministic",
        )
        output = self.output_parent / "nondeterministic"
        completed = self.run_command(self.command(tool, output))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"not byte-identical", completed.stderr)
        self.assertFalse(output.exists())

    def test_timed_out_image_tool_is_reaped_and_output_is_removed(self) -> None:
        tool = self.tool(
            f'''#!/usr/bin/env python3
import sys
import time
if sys.argv[1:] == ["-help"]:
    print({HELP!r})
    raise SystemExit(0)
time.sleep(60)
''',
            "mksquashfs-hang",
        )
        output = self.output_parent / "timeout"
        started = time.monotonic()
        completed = self.run_command(self.command(tool, output, timeout="1"), timeout=10)
        self.assertLess(time.monotonic() - started, 8)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"timed out and was reaped", completed.stderr)
        self.assertFalse(output.exists())

    def test_execute_flag_is_required(self) -> None:
        tool = self.tool(deterministic_tool())
        output = self.output_parent / "not-executed"
        command = self.command(tool, output)
        command.remove("--execute")
        completed = self.run_command(command, timeout=5)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"--execute is required", completed.stderr)
        self.assertFalse(output.exists())

    def test_help_mutation_of_payload_is_rejected_against_original_manifest(self) -> None:
        target = self.staging / "root/etc/trillionnium/owner-open/config.json"
        code = deterministic_tool().replace(
            'if sys.argv[1:] == ["-help"]:',
            f'if sys.argv[1:] == ["-help"]:\n    target=Path({str(target)!r})\n    target.chmod(0o644)\n    target.write_bytes(b"modified after validation\\n")\n    target.chmod(0o444)',
        )
        tool = self.tool(code)
        output = self.output_parent / "help-mutated"
        result = self.run_command(self.command(tool, output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"digest or byte count drifted", result.stderr)
        self.assertFalse(output.exists())

    def test_mutated_external_and_embedded_manifests_do_not_replace_snapshot(self) -> None:
        root = self.staging / "root"
        external = self.staging / "owner-open-rootfs.manifest.json"
        code = deterministic_tool().replace(
            'if sys.argv[1:] == ["-help"]:',
            f'''if sys.argv[1:] == ["-help"]:
    import json
    root=Path({str(root)!r})
    external=Path({str(external)!r})
    embedded=root/'etc/trillionnium/owner-open/rootfs.manifest.json'
    target=root/'etc/trillionnium/owner-open/config.json'
    target.chmod(0o644);target.write_bytes(b'changed');target.chmod(0o444)
    value=json.loads(external.read_bytes())
    for item in value['entries']:
        if item['destination'].endswith('/config.json'):
            item['sha256']=hashlib.sha256(b'changed').hexdigest();item['bytes']=7
    raw=json.dumps(value,sort_keys=True,indent=2).encode()+b'\\n'
    external.chmod(0o600);external.write_bytes(raw)
    embedded.chmod(0o600);embedded.write_bytes(raw);embedded.chmod(0o444)''',
        )
        output = self.output_parent / "manifest-mutated"
        result = self.run_command(self.command(self.tool(code), output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"embedded and external staging manifests differ", result.stderr)
        self.assertFalse(output.exists())

    def test_tool_mutation_of_normalized_input_is_rejected_before_receipt(self) -> None:
        code = deterministic_tool().replace(
            'digest = hashlib.sha256()',
            "target=source/'etc/trillionnium/owner-open/config.json'\n"
            "target.chmod(0o644);target.write_bytes(b'changed during build');target.chmod(0o444)\n"
            'digest = hashlib.sha256()',
        )
        output = self.output_parent / "build-mutated"
        result = self.run_command(self.command(self.tool(code), output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"digest or byte count drifted", result.stderr)
        self.assertFalse(output.exists())

    def test_tool_changed_by_help_is_rejected_before_build(self) -> None:
        code = deterministic_tool().replace(
            'if sys.argv[1:] == ["-help"]:',
            'if sys.argv[1:] == ["-help"]:\n    with open(sys.argv[0],"a") as f: f.write("\\n# changed\\n")',
        )
        output = self.output_parent / "tool-mutated"
        result = self.run_command(self.command(self.tool(code), output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"expected SHA-256", result.stderr)
        self.assertFalse(output.exists())

    def test_tool_changed_on_final_run_cannot_publish_old_identity(self) -> None:
        code = deterministic_tool().replace(
            'output.chmod(0o644)',
            'output.chmod(0o644)\nif output.name == "run-2.squashfs":\n'
            '    with open(sys.argv[0],"a") as f: f.write("\\n# changed\\n")',
        )
        output = self.output_parent / "last-tool-mutated"
        result = self.run_command(self.command(self.tool(code), output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"expected SHA-256", result.stderr)
        self.assertFalse(output.exists())

    def test_tool_mode_mutation_of_normalized_input_is_rejected(self) -> None:
        code = deterministic_tool().replace(
            'digest = hashlib.sha256()',
            "(source/'etc/trillionnium/owner-open/config.json').chmod(0o644)\ndigest = hashlib.sha256()",
        )
        output = self.output_parent / "build-mode-mutated"
        result = self.run_command(self.command(self.tool(code), output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"file mode drifted", result.stderr)
        self.assertFalse(output.exists())

    def test_help_added_undeclared_file_is_rejected(self) -> None:
        target = self.staging / "root/etc/trillionnium/owner-open/unlisted"
        code = deterministic_tool().replace(
            'if sys.argv[1:] == ["-help"]:',
            f'if sys.argv[1:] == ["-help"]:\n    Path({str(target)!r}).write_bytes(b"unlisted")',
        )
        output = self.output_parent / "added-file"
        result = self.run_command(self.command(self.tool(code), output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"undeclared file", result.stderr)
        self.assertFalse(output.exists())


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "WNOWAIT"), "Linux process retirement")
class RootfsCommandBoundaryTest(unittest.TestCase):
    """Host fixtures only; never an Android image or installed-target receipt."""
    @classmethod
    def setUpClass(cls):
        import importlib.util
        cls.spawn_class = subprocess.Popen
        sys.path.insert(0, str(TOOLS))
        try:
            spec = importlib.util.spec_from_file_location("rootfs_builder_boundary", BUILDER)
            cls.runtime = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.runtime)
        finally:
            sys.path.remove(str(TOOLS))

    def setUp(self):
        import ctypes
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pidfile = self.root / "descendant.pid"
        self.script = self.root / "fixture.py"
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.old_subreaper = ctypes.c_int()
        self.assertEqual(self.libc.prctl(37, ctypes.byref(self.old_subreaper), 0, 0, 0), 0)
        self.assertEqual(self.libc.prctl(36, 1, 0, 0, 0), 0)
        self.children = []
        self.addCleanup(self.clean_processes)
        spawn = subprocess.Popen
        def tracked(*args, **kwargs):
            child = spawn(*args, **kwargs)
            self.children.append(child)
            return child
        patcher = mock.patch.object(self.runtime.subprocess, "Popen", side_effect=tracked)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, value in (("TERM_GRACE", 0.03), ("KILL_GRACE", 0.5), ("DRAIN_SECONDS", 0.05)):
            patcher = mock.patch.object(self.runtime, name, value, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)

    def clean_processes(self):
        try:
            for child in self.children:
                if child.returncode is None:
                    try:
                        os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    except ChildProcessError:
                        continue
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=2)
                for pipe in (child.stdout, child.stderr):
                    if pipe is not None:
                        pipe.close()
            if self.pidfile.exists():
                pid = int(self.pidfile.read_text())
                try:
                    os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    pass
                else:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    deadline = time.monotonic() + 2
                    while os.waitpid(pid, os.WNOHANG)[0] == 0:
                        if time.monotonic() >= deadline:
                            self.fail("fixture descendant did not exit")
                        time.sleep(0.005)
        finally:
            self.libc.prctl(36, self.old_subreaper.value, 0, 0, 0)

    def command(self, source, timeout=3):
        self.script.write_text(source)
        return self.runtime.bounded_command([sys.executable, str(self.script)], timeout)

    def fork_source(self, *, escape=False, hold_pipes=False, leader_exits=True):
        return (
            "import os,time,signal\nr,w=os.pipe()\npid=os.fork()\nif pid==0:\n os.close(r)\n"
            + (" os.setsid()\n" if escape else "")
            + " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            + (" os.close(0);os.close(1);os.close(2)\n" if not hold_pipes else "")
            + f" with open({str(self.pidfile)!r},'w') as f: f.write(str(os.getpid()))\n"
            + " os.write(w,b'R');os.close(w)\n while True: time.sleep(1)\n"
            + "os.close(w);assert os.read(r,1)==b'R';os.close(r)\n"
            + ("os._exit(0)\n" if leader_exits else "print('READY',flush=True)\nwhile True: time.sleep(1)\n")
        )

    def test_normal_exit_retires_surviving_child(self):
        result = self.command(self.fork_source())
        self.assertEqual(result["returncode"], 0)
        self.assertTrue(self.pidfile.exists())
        state = Path(f"/proc/{int(self.pidfile.read_text())}/stat").read_bytes().rsplit(b")", 1)[1].split()[0]
        self.assertIn(state, (b"Z", b"X"))

    def test_original_group_pipe_holder_is_retired_before_drain(self):
        result = self.command(self.fork_source(hold_pipes=True))
        self.assertEqual(result["returncode"], 0)
        self.assertIsNotNone(self.children[0].returncode)

    def test_escaped_pipe_holder_has_finite_drain_error(self):
        with self.assertRaisesRegex(self.runtime.base.ImageError, "drain deadline"):
            self.command(self.fork_source(escape=True, hold_pipes=True))
        self.assertTrue(self.pidfile.exists())
        state = Path(f"/proc/{int(self.pidfile.read_text())}/stat").read_bytes().rsplit(b")", 1)[1].split()[0]
        self.assertNotIn(state, (b"Z", b"X"))  # no escaped-descendant cleanup claim
        self.assertTrue(self.children[0].stdout.closed)

    def test_communicate_is_not_used_to_buffer_unbounded_output(self):
        # The module's Popen is a tracking mock; patch the real class separately.
        with mock.patch.object(self.spawn_class, "communicate", side_effect=AssertionError("unbounded capture")):
            result = self.command("import os\nos.write(1,b'exact bytes')\n")
        self.assertEqual(result["stdout"], b"exact bytes")

    def test_exact_combined_output_boundary_and_raw_bytes(self):
        with mock.patch.object(self.runtime.base, "MAX_OUTPUT_BYTES", 8):
            result = self.command("import os\nos.write(1,b'\\x00\\xffab');os.write(2,b'cdef')\n")
        self.assertEqual(result["stdout"], b"\x00\xffab")
        self.assertEqual(result["stderr"], b"cdef")
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(result["stdout"]).hexdigest())
        self.assertEqual(result["stderr_sha256"], hashlib.sha256(result["stderr"]).hexdigest())

    def test_excess_output_uses_only_one_sentinel_byte(self):
        original, reads = os.read, []
        def read(fd, amount):
            if self.children and fd in (self.children[0].stdout.fileno(), self.children[0].stderr.fileno()):
                data = original(fd, amount)
                reads.append((amount, len(data)))
                return data
            return original(fd, amount)
        with mock.patch.object(self.runtime.base, "MAX_OUTPUT_BYTES", 32), \
                mock.patch.object(self.runtime.os, "read", side_effect=read):
            with self.assertRaisesRegex(self.runtime.base.ImageError, "output exceeds byte bound"):
                self.command("import os,time\nos.write(1,b'x'*4096)\ntime.sleep(30)\n", 3)
        self.assertTrue(reads)
        self.assertLessEqual(sum(size for _request, size in reads), 33)
        self.assertTrue(all(request <= 33 for request, _size in reads))
        self.assertIsNotNone(self.children[0].returncode)

    def test_stderr_also_consumes_shared_capture_budget(self):
        with mock.patch.object(self.runtime.base, "MAX_OUTPUT_BYTES", 4):
            with self.assertRaisesRegex(self.runtime.base.ImageError, "output exceeds byte bound"):
                self.command("import os\nos.write(2,b'excess')\n")
        self.assertTrue(self.children[0].stderr.closed)

    def test_nonfinite_timeout_rejected_before_spawn(self):
        for value in (float("nan"), float("inf"), -float("inf"), True, 0, -1, 1801, "3"):
            with self.subTest(value=value), self.assertRaises(self.runtime.base.ImageError):
                self.runtime.bounded_command([sys.executable, "-c", "pass"], value)
        self.assertEqual(self.children, [])

    def test_invalid_output_budgets_rejected_before_spawn(self):
        for value in (True, 0, -1, 1.5, 16 * 1024 * 1024 + 1):
            with self.subTest(value=value), mock.patch.object(self.runtime.base, "MAX_OUTPUT_BYTES", value):
                with self.assertRaises(self.runtime.base.ImageError):
                    self.runtime.bounded_command([sys.executable, "-c", "pass"], 1)
        self.assertEqual(self.children, [])

    def test_missing_waitid_rejected_before_spawn(self):
        with mock.patch.object(self.runtime.os, "waitid", None), self.assertRaises(self.runtime.base.ImageError):
            self.runtime.bounded_command([sys.executable, "-c", "pass"], 1)
        self.assertEqual(self.children, [])

    def test_ignored_sigchld_rejected_before_spawn(self):
        with mock.patch.object(self.runtime.signal, "getsignal", return_value=signal.SIG_IGN), self.assertRaises(self.runtime.base.ImageError):
            self.runtime.bounded_command([sys.executable, "-c", "pass"], 1)
        self.assertEqual(self.children, [])

    def test_setup_failure_retires_child_and_closes_pipes(self):
        with mock.patch.object(self.runtime.os, "set_blocking", side_effect=OSError("setup failure")):
            with self.assertRaisesRegex(self.runtime.base.ImageError, "setup failure"):
                self.command("import time\ntime.sleep(30)\n")
        self.assertIsNotNone(self.children[0].returncode)
        self.assertTrue(self.children[0].stdout.closed and self.children[0].stderr.closed)

    def test_selector_creation_failure_retires_child(self):
        with mock.patch.object(self.runtime.selectors, "DefaultSelector", side_effect=OSError("selector failure")):
            with self.assertRaises(self.runtime.base.ImageError):
                self.command("import time\ntime.sleep(30)\n")
        self.assertIsNotNone(self.children[0].returncode)

    def test_selector_registration_failure_retires_child(self):
        selector = self.runtime.selectors.DefaultSelector()
        with mock.patch.object(self.runtime.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(selector, "register", side_effect=OSError("registration failure")):
            with self.assertRaisesRegex(self.runtime.base.ImageError, "registration failure"):
                self.command("import time\ntime.sleep(30)\n")
        self.assertIsNotNone(self.children[0].returncode)

    def test_selector_wait_failure_retires_child(self):
        selector = self.runtime.selectors.DefaultSelector()
        with mock.patch.object(self.runtime.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(selector, "select", side_effect=OSError("select failure")):
            with self.assertRaisesRegex(self.runtime.base.ImageError, "select failure"):
                self.command("import time\ntime.sleep(30)\n")
        self.assertIsNotNone(self.children[0].returncode)

    def test_no_procfs_confirmation_is_never_success(self):
        with mock.patch.object(self.runtime, "_quiet_group", side_effect=OSError("procfs denied")):
            with self.assertRaisesRegex(self.runtime.base.ImageError, "cleanup unconfirmed"):
                self.command("pass\n")
        self.assertIsNotNone(self.children[0].returncode)

    def test_reaped_anchor_never_receives_signal(self):
        child = mock.Mock(pid=999999, returncode=0)
        with mock.patch.object(self.runtime.os, "killpg") as kill:
            with self.assertRaisesRegex(self.runtime.base.ImageError, "anchor"):
                self.runtime.terminate_group(child)
        kill.assert_not_called()

    def test_term_failure_still_attempts_kill_and_is_not_success(self):
        original, seen = os.killpg, []
        def kill(pid, sig):
            seen.append(sig)
            if sig == signal.SIGTERM:
                raise PermissionError("TERM refused")
            return original(pid, sig)
        with mock.patch.object(self.runtime.os, "killpg", side_effect=kill):
            with self.assertRaisesRegex(self.runtime.base.ImageError, "cleanup unconfirmed"):
                self.command("pass\n")
        self.assertEqual(seen, [signal.SIGTERM, signal.SIGKILL])
        self.assertIsNotNone(self.children[0].returncode)

    def test_timeout_after_descendant_readiness_retires_group(self):
        original_read, original_clock, ready = os.read, time.monotonic, [False]
        def read(fd, size):
            data = original_read(fd, size)
            if data == b"READY\n":
                ready[0] = True
            return data
        with mock.patch.object(self.runtime.os, "read", side_effect=read), \
                mock.patch.object(self.runtime.time, "monotonic", side_effect=lambda: original_clock() + (10 if ready[0] else 0)):
            with self.assertRaisesRegex(self.runtime.base.ImageError, "timed out and was reaped"):
                self.command(self.fork_source(leader_exits=False))
        self.assertTrue(ready[0])
        state = Path(f"/proc/{int(self.pidfile.read_text())}/stat").read_bytes().rsplit(b")", 1)[1].split()[0]
        self.assertIn(state, (b"Z", b"X"))

    def test_closed_output_does_not_end_live_tool_early(self):
        with self.assertRaisesRegex(self.runtime.base.ImageError, "timed out"):
            self.command("import os,time\nos.close(1);os.close(2);time.sleep(30)\n", 0.1)
        self.assertIsNotNone(self.children[0].returncode)

    def test_nonzero_exit_is_preserved(self):
        result = self.command("import os\nos.write(2,b'raw error');raise SystemExit(9)\n")
        self.assertEqual(result["returncode"], 9)
        self.assertEqual(result["stderr"], b"raw error")

    def test_parenthesized_process_name_keeps_anchor_parseable(self):
        result = self.command("import ctypes\nctypes.CDLL(None).prctl(15,b'name ) ( test',0,0,0)\n")
        self.assertEqual(result["returncode"], 0)

    def test_procfs_entry_budget_rejects_unbounded_scan(self):
        with mock.patch.object(self.runtime, "MAX_PROC_ENTRIES", 0):
            with self.assertRaisesRegex(self.runtime.base.ImageError, "observation budget"):
                self.command("pass\n")
        self.assertIsNotNone(self.children[0].returncode)

    def test_keyboard_interrupt_still_retires_and_closes(self):
        selector = self.runtime.selectors.DefaultSelector()
        with mock.patch.object(self.runtime.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(selector, "select", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.command("import time\ntime.sleep(30)\n")
        self.assertIsNotNone(self.children[0].returncode)
        self.assertTrue(self.children[0].stdout.closed)

    def test_descriptors_do_not_leak_across_success_and_failure(self):
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(3):
            self.command("pass\n")
            with mock.patch.object(self.runtime.os, "set_blocking", side_effect=OSError("setup")):
                with self.assertRaises(self.runtime.base.ImageError): self.command("pass\n")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)


    def test_anchor_loss_stops_further_group_signals(self):
        child = mock.Mock(pid=12345, returncode=None)
        with mock.patch.object(self.runtime, "_observe_exit", side_effect=[None, None, ChildProcessError("lost"), ChildProcessError("lost")]), \
                mock.patch.object(self.runtime.os, "killpg") as kill:
            with self.assertRaisesRegex(self.runtime.base.ImageError, "anchor lost"):
                self.runtime.terminate_group(child)
        kill.assert_called_once_with(12345, signal.SIGTERM)
        child.wait.assert_not_called()

    def test_cleanup_failure_never_uses_successful_timeout_wording(self):
        with mock.patch.object(self.runtime, "_quiet_group", side_effect=OSError("no proof")):
            with self.assertRaises(self.runtime.base.ImageError) as caught:
                self.command("import time\ntime.sleep(30)\n", 0.1)
        self.assertIn("cleanup", str(caught.exception))
        self.assertNotIn("timed out and was reaped", str(caught.exception))

    def test_output_read_failure_still_retires_and_closes(self):
        original = os.read
        def read(fd, amount):
            if self.children and fd in (self.children[0].stdout.fileno(), self.children[0].stderr.fileno()):
                raise OSError("pipe read failure")
            return original(fd, amount)
        with mock.patch.object(self.runtime.os, "read", side_effect=read):
            with self.assertRaisesRegex(self.runtime.base.ImageError, "pipe read failure"):
                self.command("print('ready',flush=True)\n")
        self.assertIsNotNone(self.children[0].returncode)
        self.assertTrue(self.children[0].stdout.closed)

    def test_signal_exit_status_is_preserved(self):
        result = self.command("import os,signal\nos.kill(os.getpid(),signal.SIGUSR1)\n")
        self.assertEqual(result["returncode"], -signal.SIGUSR1)

    def test_exact_arguments_are_not_interpreted_as_shell(self):
        self.script.write_text("import json,sys\nprint(json.dumps(sys.argv[1:]),flush=True)\n")
        result = self.runtime.bounded_command([sys.executable, str(self.script), "x y", "$HOME;literal"], 3)
        self.assertEqual(json.loads(result["stdout"]), ["x y", "$HOME;literal"])


if __name__ == "__main__":
    unittest.main()
