#!/usr/bin/env python3
"""Synthetic inventory tests. No ADB server, phone, or device command is contacted."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name("phone_inventory.py")
spec = importlib.util.spec_from_file_location("hepta_inventory", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def projection(values, size=512, uid=10042, before="a" * 64, after=None):
    lines = ['  ' + json.dumps(k) + ': ' + json.dumps(v) + ',' for k, v in values.items()]
    return ("SOURCE_SHA256_BEFORE " + before + "  files/known.json\n"
            + "SOURCE_METADATA %d %d 600 1\n" % (size, uid)
            + "\n".join(lines) + "\nSOURCE_SHA256_AFTER " + (after or before) + "  files/known.json\n").encode()


SESSION = {"schema": "hepta.local-session.v1", "status": "model_reported_done", "task_id": "b" * 32,
           "running": False, "pending": False, "blocked": False, "cleanup_known": True, "app_uid": 10042,
           "external_model": False, "automatic_resume": False, "goal_independently_verified": False}
CONFIG = {"schema": "hepta.local-runtime.v1", "compute": "npu", "context_tokens": 4096, "threads": 4}
PACKAGE_DUMP = ("""Packages:
  Package [TARGET] (abcd):
    userId=10042
    versionCode=2 minSdk=30 targetSdk=35
    versionName=0.3.1-lfm3-local
    primaryCpuAbi=arm64-v8a
    legacyNativeLibraryDir=/data/app/example/lib/arm64
    requested permissions:
    usesOptionalNativeLibraries:
      libadsprpc.so
      libcdsprpc.so
      libOpenCL.so
    User 0: ceDataInode=42 installed=true hidden=false suspended=false stopped=false enabled=0
      runtime permissions:
""").replace("TARGET", m.PACKAGE).encode()
MEMINFO = b"MemTotal:       16000000 kB\nMemFree:         1000000 kB\nMemAvailable:    5000000 kB\nCached:          3000000 kB\nSwapTotal:       8000000 kB\nSwapFree:        4000000 kB\n"


class SyntheticRunner:
    def __init__(self):
        self.calls, self.host_calls, self.socket_queries = [], [], []
        self.overrides = {}
        self.server_version = b"0029"
        self.devices = b"FAKE\tdevice product:fixture model:razr_fixture device:fixture transport_id:1\n"
        self.after_devices = None
        self.props = {
            "ro.product.manufacturer": "motorola", "ro.product.model": "razr fixture",
            "ro.product.device": "fixture", "ro.soc.manufacturer": "Qualcomm", "ro.soc.model": "SM8750",
            "ro.board.platform": "sun", "ro.product.cpu.abilist": "arm64-v8a", "ro.build.version.release": "15",
            "ro.build.version.sdk": "35", "ro.build.version.security_patch": "2026-10-01",
            "ro.build.fingerprint": "motorola/fixture/fake:15/TEST/1:user/release-keys", "ro.serialno": "FAKE",
        }

    def host(self, argv, timeout, limit):
        self.host_calls.append(argv)
        if argv != [sys.executable, "version"]:
            raise AssertionError("unexpected host executable invocation")
        return {"argv": argv, "exit_code": 0, "client_timed_out": False, "output_truncated": False,
                "stdout": b"Android Debug Bridge version 1.0.41\nVersion fixture\n", "stderr": b""}

    def smart(self, host, port, request, timeout):
        self.socket_queries.append((host, port, request))
        if (host, port) != ("127.0.0.1", 17389):
            raise AssertionError("explicit connection identity changed")
        if request == "host:version":
            return self.server_version
        if request == "host:devices-l":
            count = sum(q[2] == request for q in self.socket_queries)
            return self.after_devices if count > 1 and self.after_devices is not None else self.devices
        raise AssertionError("non-read-only smart request")

    def shell(self, host, port, serial, command, timeout, limit):
        command = tuple(command)
        if (host, port, serial) != ("127.0.0.1", 17389, "FAKE"):
            raise AssertionError("selected device/port changed")
        if command not in (m.base_commands() | m.user_commands(0)):
            raise AssertionError("command not in independently checked read-only allowlist")
        self.calls.append(command)
        if not 0 < timeout <= 1 or limit > 524288:
            raise AssertionError("unbounded command")
        code, stdout = 0, b""
        if command in self.overrides:
            value = self.overrides[command]
            if isinstance(value, Exception):
                raise value
            if isinstance(value, dict):
                return value
            code, stdout = value if isinstance(value, tuple) else (0, value)
        elif command[0] == "getprop":
            stdout = (self.props[command[1]] + "\n").encode()
        elif command == ("getconf", "PAGESIZE"):
            stdout = b"16384\n"
        elif command == ("cmd", "activity", "get-current-user"):
            stdout = b"0\n"
        elif command == ("cat", "/proc/meminfo"):
            stdout = MEMINFO
        elif command == ("cat", "/proc/pressure/memory"):
            stdout = b"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
        elif command == ("dumpsys", "battery"):
            stdout = b"Current Battery Service state:\n  level: 80\n  scale: 100\n  temperature: 354\n  voltage: 4100\n  status: 2\n  health: 2\n"
        elif command == ("dumpsys", "thermalservice"):
            stdout = b"Thermal Status: 0\n"
        elif command == ("dumpsys", "package", m.PACKAGE):
            stdout = PACKAGE_DUMP
        elif command == ("dumpsys", "meminfo", m.PACKAGE):
            stdout = ("** MEMINFO in pid 123 [" + m.PACKAGE + "] **\n  TOTAL PSS: 1024  TOTAL RSS: 2048  TOTAL SWAP PSS: 64\n").encode()
        elif command[:4] == ("cmd", "package", "list", "packages"):
            stdout = ("package:" + m.PACKAGE + " versionCode:2 uid:10042\n").encode()
            if command[-1] != m.PACKAGE:
                stdout += b"package:com.android.settings uid:1000 versionCode:35\n"
        elif command[:3] == ("cmd", "package", "query-activities"):
            stdout = (m.PACKAGE + "/.MainActivity\ncom.android.settings/.Settings\n").encode()
        elif command[:3] == ("cmd", "package", "path"):
            stdout = b"package:/data/app/example/base.apk\n"
        elif command[:4] == ("run-as", m.PACKAGE, "--user", "0"):
            if command[4:] == ("id", "-u"):
                stdout = b"10042\n"
            elif command[-1] == m.SESSION_SCRIPT:
                stdout = projection(SESSION)
            elif command[-1] == m.CONFIG_SCRIPT:
                stdout = projection(CONFIG)
            elif command[-1] == m.INTERRUPTION_LATCH_SCRIPT:
                stdout = b"absent\n"
            else:
                raise AssertionError("unexpected app-private read")
        else:
            raise AssertionError("fixture does not cover read-only command")
        return {"remote_command": list(command), "exit_code": code, "client_timed_out": False,
                "output_truncated": False, "stdout": stdout, "stderr": b"", "stdin_bytes": 0}


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = SyntheticRunner()
        # Any accidental network path fails the test instead of contacting a phone.
        denied = patch.object(m.socket, "create_connection", side_effect=AssertionError("network is forbidden in synthetic tests"))
        denied.start()
        self.addCleanup(denied.stop)

    def args(self, **changes):
        value = dict(adb=sys.executable, adb_host="127.0.0.1", adb_port=17389, serial="FAKE",
                     output=self.root / "snapshot", command_timeout=1.0, overall_timeout=30.0)
        value.update(changes)
        return types.SimpleNamespace(**value)

    def run_fake(self, **changes):
        args = self.args(**changes)
        with patch.object(m, "_run_bounded", self.runner.host), patch.object(m, "_smart_request", self.runner.smart), \
             patch.object(m, "_shell_v2_read", self.runner.shell), contextlib.redirect_stdout(io.StringIO()):
            code = m.run_inventory(args)
        return code, json.loads((args.output / "inventory.json").read_text())

    def test_complete_synthetic_inventory_does_not_qualify_product(self):
        code, report = self.run_fake()
        self.assertEqual(code, 0)
        self.assertEqual(report["observation_status"], "OBSERVED")
        self.assertEqual(report["test_verdict"], "NOT_RUN")
        self.assertEqual(report["production_ready"], "UNKNOWN")
        self.assertFalse(report["model_inference_executed"])
        self.assertFalse(report["actual_model_or_runtime_artifact_bytes_verified"])
        self.assertFalse(report["planned_candidate_identity"]["observed_on_phone"])
        self.assertEqual(report["installed_app_identity"]["actual_uid"], 10042)
        self.assertLessEqual(len(self.runner.calls), m.MAX_COMMANDS)
        self.assertEqual(self.runner.host_calls, [[sys.executable, "version"]])
        self.assertEqual({(h, p) for h, p, _ in self.runner.socket_queries}, {("127.0.0.1", 17389)})

    def test_actual_installed_identity_is_not_replaced_by_planned_version(self):
        self.runner.overrides[("dumpsys", "package", m.PACKAGE)] = PACKAGE_DUMP.replace(b"versionName=0.3.1-lfm3-local", b"versionName=old-installed-build")
        code, report = self.run_fake()
        self.assertEqual(code, 0)
        self.assertFalse(report["installed_matches_planned_version"])
        self.assertEqual(report["installed_app_identity"]["package_details"]["version_name"], "old-installed-build")

    def test_new_private_files_include_hashed_raw_stdout_and_stderr(self):
        _, report = self.run_fake()
        out = Path(report["evidence_directory"])
        manifest = json.loads((out / "file-manifest.json").read_text())
        self.assertTrue(any(x["path"].endswith(".stdout.bin") for x in manifest["files"]))
        self.assertTrue(any(x["path"].endswith(".stderr.bin") for x in manifest["files"]))
        for row in manifest["files"]:
            data = (out / row["path"]).read_bytes()
            self.assertEqual(row["sha256"], m.digest(data))
            self.assertEqual(row["bytes"], len(data))
        for item in [out] + list(out.rglob("*")):
            self.assertEqual(item.stat().st_mode & 0o777, 0o700 if item.is_dir() else 0o600)

    def test_existing_directory_refuses_before_any_client_or_server_call(self):
        target = self.root / "snapshot"
        target.mkdir()
        with self.assertRaises(FileExistsError):
            self.run_fake()
        self.assertFalse(self.runner.calls or self.runner.host_calls or self.runner.socket_queries)

    def test_existing_dangling_symlink_refuses_before_calls(self):
        (self.root / "snapshot").symlink_to(self.root / "does-not-exist", target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.run_fake()
        self.assertFalse(self.runner.calls or self.runner.host_calls or self.runner.socket_queries)

    def test_invalid_connection_never_succeeds_or_calls_device(self):
        for change in ({"serial": ""}, {"serial": "FAKE; id"}, {"serial": "--any"}, {"adb_port": 0},
                       {"adb_port": 65536}, {"adb": "adb"}, {"adb_host": "localhost"},
                       {"command_timeout": float("nan")}, {"overall_timeout": 10000}):
            with self.subTest(change=change), self.assertRaises(m.DriverError):
                self.run_fake(**change)
        self.assertFalse(self.runner.calls or self.runner.host_calls or self.runner.socket_queries)

    def test_cli_requires_adb_port_serial_and_output(self):
        for omitted in ("--adb", "--adb-port", "--serial", "--output"):
            values = {"--adb": sys.executable, "--adb-port": "17389", "--serial": "FAKE", "--output": str(self.root / "snapshot")}
            argv = [x for key, value in values.items() if key != omitted for x in (key, value)]
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                m.parser().parse_args(argv)
        self.assertFalse(self.runner.calls)

    def test_absent_offline_unauthorized_duplicate_device_refuses_phone_commands(self):
        for i, value in enumerate((b"", b"OTHER\tdevice\n", b"FAKE\toffline\n", b"FAKE\tunauthorized\n", b"FAKE\tdevice\nFAKE\tdevice\n")):
            self.runner.devices = value
            code, report = self.run_fake(output=self.root / ("case-" + str(i)))
            self.assertNotEqual(code, 0)
            self.assertEqual(report["identity_status"], "UNKNOWN")
            self.assertEqual(report["remote_command_count"], 0)
        self.assertFalse(self.runner.calls)

    def test_server_version_mismatch_does_not_start_or_reset(self):
        self.runner.server_version = b"0028"
        code, report = self.run_fake()
        self.assertNotEqual(code, 0)
        self.assertFalse(self.runner.calls)
        self.assertFalse(report["adb_server_start_or_reset_requested"])
        self.assertEqual([q[2] for q in self.runner.socket_queries], ["host:version"])

    def test_reusable_preflight_has_no_phone_command_or_overall_timeout_dependency(self):
        args = self.args()
        del args.overall_timeout
        args.output.mkdir(mode=0o700)
        with patch.object(m, "_run_bounded", self.runner.host), patch.object(m, "_smart_request", self.runner.smart):
            observed = m.require_existing_adb_server(args, args.output)
        self.assertEqual(observed["server_protocol_hex"], "0029")
        self.assertEqual(observed["connected"]["selected"]["serial"], "FAKE")
        self.assertFalse(self.runner.calls)

    def test_missing_required_observed_identity_never_returns_success(self):
        for i, key in enumerate(("ro.product.model", "ro.soc.model", "ro.build.version.sdk", "ro.product.cpu.abilist")):
            old = self.runner.props[key]
            self.runner.props[key] = ""
            code, report = self.run_fake(output=self.root / ("missing-" + str(i)))
            self.assertNotEqual(code, 0)
            self.assertEqual(report["identity_status"], "UNKNOWN")
            self.runner.props[key] = old

    def test_invalid_page_size_never_returns_success(self):
        self.runner.overrides[("getconf", "PAGESIZE")] = b"12345\n"
        code, report = self.run_fake()
        self.assertNotEqual(code, 0)
        self.assertEqual(report["identity_status"], "UNKNOWN")

    def test_unknown_sentinels_and_unknown_abi_are_not_valid_identity(self):
        for i, (key, value) in enumerate((("ro.soc.model", "unknown"), ("ro.product.model", "null"),
                                        ("ro.product.cpu.abilist", "not-an-android-abi"))):
            old = self.runner.props[key]
            self.runner.props[key] = value
            code, report = self.run_fake(output=self.root / ("invalid-identity-" + str(i)))
            self.assertNotEqual(code, 0)
            self.assertEqual(report["identity_status"], "UNKNOWN")
            self.runner.props[key] = old

    def test_missing_package_or_disagreeing_uid_is_not_success(self):
        key = ("cmd", "package", "list", "packages", "--user", "0", "-U", "--show-versioncode", m.PACKAGE)
        for i, response in enumerate((b"", ("package:" + m.PACKAGE + " versionCode:2 uid:10043\n").encode())):
            self.runner.overrides[key] = response
            before = len(self.runner.calls)
            code, report = self.run_fake(output=self.root / ("identity-" + str(i)))
            self.assertNotEqual(code, 0)
            self.assertEqual(report["identity_status"], "UNKNOWN")
            self.assertFalse(any(c[0] == "run-as" for c in self.runner.calls[before:]))

    def test_device_transport_change_invalidates_snapshot(self):
        self.runner.after_devices = self.runner.devices.replace(b"transport_id:1", b"transport_id:2")
        code, report = self.run_fake()
        self.assertNotEqual(code, 0)
        self.assertFalse(report["transport_user_build_stable_between_observations"])

    def test_memory_metrics_remain_distinct_and_swap_is_not_ram(self):
        _, report = self.run_fake()
        value = report["observations"]["kernel-memory"]["value"]
        self.assertEqual(value["kernel_memavailable_bytes"], 5000000 * 1024)
        self.assertEqual(value["kernel_memfree_bytes"], 1000000 * 1024)
        self.assertEqual(value["kernel_metrics_bytes"]["MemTotal"], 16000000 * 1024)
        self.assertEqual(value["kernel_metrics_bytes"]["SwapTotal"], 8000000 * 1024)
        self.assertIsNone(value["activity_manager_avail_mem_bytes"])
        self.assertIsNone(value["model_memory_budget_bytes"])
        self.assertFalse(value["swap_counted_as_ram"])
        process = report["observations"]["app-process-memory"]["value"]["processes"][0]
        self.assertEqual(process["pss_bytes"], 1024 * 1024)
        self.assertEqual(process["rss_bytes"], 2048 * 1024)
        self.assertEqual(process["swap_pss_bytes"], 64 * 1024)

    def test_missing_memavailable_is_not_reconstructed_from_memfree(self):
        self.runner.overrides[("cat", "/proc/meminfo")] = MEMINFO.replace(b"MemAvailable:    5000000 kB\n", b"")
        code, report = self.run_fake()
        self.assertNotEqual(code, 0)
        value = report["observations"]["kernel-memory"]["value"]
        self.assertIsNone(value["kernel_memavailable_bytes"])
        self.assertFalse(value["memavailable_estimated_from_free_or_cache"])

    def test_battery_temperature_is_tenths_celsius_and_frozen_state_retained(self):
        data = b"UPDATES STOPPED\nlevel: 39\nscale: 100\ntemperature: 372\n"
        value = m.parse_battery(data)
        self.assertEqual(value["temperature_celsius"], 37.2)
        self.assertTrue(value["service_updates_stopped"])

    def test_optional_missing_state_does_not_infer_idle_or_config_defaults(self):
        for script in (m.SESSION_SCRIPT, m.CONFIG_SCRIPT):
            self.runner.overrides[("run-as", m.PACKAGE, "--user", "0", "sh", "-c", script)] = (40, b"")
        code, report = self.run_fake()
        self.assertEqual(code, 0)
        for name in ("app-session-state", "app-runtime-config"):
            value = report["observations"][name]["value"]
            self.assertEqual(value["status"], "ABSENT")
            self.assertEqual(value["effective_setting"], "UNKNOWN")
        self.assertEqual(report["effective_session_state"]["state"], "UNKNOWN")

    def test_present_interruption_latch_overrides_an_old_clean_session(self):
        key = ("run-as", m.PACKAGE, "--user", "0", "sh", "-c", m.INTERRUPTION_LATCH_SCRIPT)
        self.runner.overrides[key] = b"present\n"
        code, report = self.run_fake()
        self.assertEqual(code, 0)  # Observation succeeded; product/task acceptance still NOT_RUN.
        base = report["observations"]["app-session-state"]["value"]["values"]
        self.assertTrue(base["cleanup_known"])
        self.assertFalse(base["running"] or base["pending"])
        effective = report["effective_session_state"]
        self.assertEqual(effective["state"], "INTERRUPTED")
        self.assertFalse(effective["cleanup_known"])
        self.assertFalse(effective["new_task_admission_granted"])
        self.assertFalse(report["observations"]["app-interruption-latch"]["value"]["contents_read"])
        self.assertIn(key, self.runner.calls)

    def test_latch_run_as_error_is_unknown_and_cannot_establish_quiescence(self):
        key = ("run-as", m.PACKAGE, "--user", "0", "sh", "-c", m.INTERRUPTION_LATCH_SCRIPT)
        self.runner.overrides[key] = (1, b"")
        code, report = self.run_fake()
        self.assertEqual(code, 3)
        effective = report["effective_session_state"]
        self.assertEqual(effective["latch_presence"], "UNKNOWN")
        self.assertEqual(effective["state"], "UNKNOWN")
        self.assertIsNone(effective["cleanup_known"])
        self.assertFalse(effective["new_task_admission_granted"])

    def test_absent_latch_keeps_clean_base_as_unverified_app_report(self):
        _, report = self.run_fake()
        effective = report["effective_session_state"]
        self.assertEqual(effective["latch_presence"], "ABSENT")
        self.assertEqual(effective["state"], "APP_REPORTED_QUIESCENT")
        self.assertFalse(effective["independently_verified"])
        self.assertFalse(effective["new_task_admission_granted"])

    def test_latch_presence_read_uses_only_the_observed_android_user(self):
        adb = m.ReadOnlyAdb(self.args())
        adb.allow_observed_user(10)
        commands = [c for c in adb.allowed_commands if c[-1] == m.INTERRUPTION_LATCH_SCRIPT]
        self.assertEqual(commands, [("run-as", m.PACKAGE, "--user", "10", "sh", "-c", m.INTERRUPTION_LATCH_SCRIPT)])
        with patch.object(m, "_shell_v2_read", side_effect=AssertionError("wrong user must be rejected")):
            with self.assertRaises(m.DriverError):
                adb.command(["run-as", m.PACKAGE, "--user", "0", "sh", "-c", m.INTERRUPTION_LATCH_SCRIPT])

    def test_latch_script_checks_presence_only_including_empty_and_broken_symlink(self):
        for kind in ("missing", "empty", "content", "directory", "broken_symlink", "fifo"):
            with self.subTest(kind=kind):
                local = self.root / ("latch-" + kind)
                (local / "files").mkdir(parents=True)
                path = local / m.INTERRUPTION_LATCH_PATH
                if kind == "empty":
                    path.touch()
                elif kind == "content":
                    path.write_text("SECRET_LATCH_CONTENT_MUST_NOT_BE_READ")
                elif kind == "directory":
                    path.mkdir()
                elif kind == "broken_symlink":
                    path.symlink_to(local / "missing-target")
                elif kind == "fifo":
                    os.mkfifo(path)
                # This executes only a host fixture script; no run-as/ADB/phone.
                result = subprocess.run(["sh", "-c", m.INTERRUPTION_LATCH_SCRIPT], cwd=local,
                                        capture_output=True, timeout=2, check=False)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"absent\n" if kind == "missing" else b"present\n")
                self.assertEqual(result.stderr, b"")

    def test_private_projection_changed_or_duplicate_is_unknown(self):
        key = ("run-as", m.PACKAGE, "--user", "0", "sh", "-c", m.SESSION_SCRIPT)
        samples = [projection(SESSION, after="c" * 64), projection(SESSION).replace(b'  "pending": false,', b'  "pending": false,\n  "pending": true,')]
        for i, sample in enumerate(samples):
            self.runner.overrides[key] = sample
            code, report = self.run_fake(output=self.root / ("projection-" + str(i)))
            self.assertNotEqual(code, 0)
            self.assertEqual(report["observations"]["app-session-state"]["status"], "UNKNOWN")

    def test_no_target_process_is_observed_without_starting_it(self):
        self.runner.overrides[("dumpsys", "meminfo", m.PACKAGE)] = ("No process found for: " + m.PACKAGE + "\n").encode()
        _, report = self.run_fake()
        self.assertEqual(report["observations"]["app-process-memory"]["value"]["process_state"], "NO_PROCESS_REPORTED")
        self.assertFalse(report["app_launched_or_stopped"])

    def test_native_library_declarations_are_actual_metadata_or_unknown(self):
        value = m.parse_package_dump(PACKAGE_DUMP, 0)
        self.assertIn("libOpenCL.so", value["native_library_declarations"]["usesOptionalNativeLibraries"])
        self.assertIsNone(value["native_library_declarations"]["usesNativeLibraries"])
        self.assertFalse(value["binary_or_manifest_bytes_verified"])
        omitted = PACKAGE_DUMP.replace(b"    usesOptionalNativeLibraries:\n      libadsprpc.so\n      libcdsprpc.so\n      libOpenCL.so\n", b"")
        self.assertEqual(m.parse_package_dump(omitted, 0)["native_library_declaration_status"], "UNKNOWN")

    def test_missing_native_declarations_retains_partial_instead_of_host_manifest(self):
        self.runner.overrides[("dumpsys", "package", m.PACKAGE)] = PACKAGE_DUMP.replace(
            b"    usesOptionalNativeLibraries:\n      libadsprpc.so\n      libcdsprpc.so\n      libOpenCL.so\n", b"")
        code, report = self.run_fake()
        self.assertEqual(code, 3)
        self.assertEqual(report["observation_status"], "PARTIAL")
        self.assertIsNone(report["installed_app_identity"]["package_details"]["native_library_declarations"]["usesOptionalNativeLibraries"])

    def test_empty_launcher_or_apk_query_is_unknown(self):
        with self.assertRaises(m.DriverError):
            m.parse_launchers(b"")
        with self.assertRaises(m.DriverError):
            m.parse_apk_paths(b"")
        self.assertEqual(m.parse_launchers(b"No activities found\n"), [])

    def test_allowlist_rejects_launch_reset_settings_ui_dump_and_generic_private_read(self):
        adb = m.ReadOnlyAdb(self.args())
        adb.allow_observed_user(0)
        bad = (["am", "start", "-n", m.PACKAGE + "/.MainActivity"], ["am", "force-stop", m.PACKAGE],
               ["settings", "list", "secure"], ["settings", "put", "secure", "x", "1"], ["uiautomator", "dump"],
               ["input", "keyevent", "3"], ["kill", "123"], ["kill-server"], ["start-server"], ["pm", "clear", m.PACKAGE],
               ["getprop"], ["run-as", m.PACKAGE, "cat", "files/control-tasks/owner.json"])
        with patch.object(m, "_shell_v2_read", side_effect=AssertionError("must reject before transport")):
            for command in bad:
                with self.subTest(command=command), self.assertRaises(m.DriverError):
                    adb.command(command)
            with self.assertRaises(m.DriverError):
                adb.command(["getprop", "ro.soc.model"], input_data=b"unsafe")
            with self.assertRaises(m.DriverError):
                adb.app_bytes("files/control-session.json")
        self.assertEqual(adb.sequence, 0)

    def test_projection_script_exports_only_whitelisted_scalars_in_a_host_fixture(self):
        local = self.root / "local-fixture"
        (local / "files").mkdir(parents=True)
        data = dict(SESSION, state="SECRET_INSTRUCTION should never be exported", instruction="SECRET_OWNER", token="SECRET_TOKEN")
        path = local / "files" / "control-session.json"
        path.write_text(json.dumps(data, indent=2))
        path.chmod(0o600)
        # Pure host fixture: not run-as, not ADB, no network or phone.
        result = subprocess.run(["sh", "-c", m.SESSION_SCRIPT], cwd=local, capture_output=True, timeout=3, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(b"SECRET", result.stdout)
        self.assertNotIn(b'"state"', result.stdout)
        self.assertIn(b'"running": false', result.stdout)
        self.assertIn(b"SOURCE_SHA256_AFTER", result.stdout)

    def test_private_symlink_is_refused_without_reading_target(self):
        local = self.root / "local-symlink"
        (local / "files").mkdir(parents=True)
        secret = local / "secret.txt"
        secret.write_text("SECRET")
        (local / "files" / "control-session.json").symlink_to(secret)
        result = subprocess.run(["sh", "-c", m.SESSION_SCRIPT], cwd=local, capture_output=True, timeout=3, check=False)
        self.assertEqual(result.returncode, 41)
        self.assertEqual(result.stdout, b"")


def frame(stream, data):
    return bytes([stream]) + len(data).to_bytes(4, "little") + data


class MemorySocket:
    def __init__(self, data):
        self.data = bytearray(data)
        self.sent = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *ignored):
        self.closed = True

    def settimeout(self, value):
        if value <= 0:
            raise AssertionError("unbounded or invalid timeout")

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, limit):
        size = min(3, limit, len(self.data))
        value = bytes(self.data[:size])
        del self.data[:size]
        return value


class ProtocolTests(unittest.TestCase):
    def shell(self, frames, limit=100):
        channel = MemorySocket(b"OKAYOKAY" + frames)
        with patch.object(m.socket, "create_connection", return_value=channel) as connect, \
             patch.object(m.subprocess, "Popen", side_effect=AssertionError("phone reads must not spawn an adb client")):
            result = m._shell_v2_read("127.0.0.1", 17389, "FAKE", ("getprop", "ro.soc.model"), 1, limit)
        self.assertEqual(connect.call_args.args[0], ("127.0.0.1", 17389))
        return channel, result

    def test_shell_v2_keeps_stderr_and_remote_nonzero_exit(self):
        channel, result = self.shell(frame(1, b"value\n") + frame(2, b"warning\n") + frame(3, b"\x28"))
        self.assertEqual(result["stdout"], b"value\n")
        self.assertEqual(result["stderr"], b"warning\n")
        self.assertEqual(result["exit_code"], 40)
        self.assertEqual(channel.sent[0][4:], b"host:transport:FAKE")
        self.assertEqual(channel.sent[1][4:], b"shell,v2,raw:getprop ro.soc.model")
        self.assertEqual(channel.sent[2], b"\x04\x00\x00\x00\x00")
        self.assertTrue(channel.closed)
        self.assertNotIn(b"kill-server", b"".join(channel.sent))
        self.assertNotIn(b"host:kill", b"".join(channel.sent))

    def test_combined_stream_byte_cap_never_reports_success(self):
        channel, result = self.shell(frame(1, b"abc") + frame(2, b"DEFG") + frame(3, b"\x00"), limit=5)
        self.assertEqual(result["stdout"], b"abc")
        self.assertEqual(result["stderr"], b"DE")
        self.assertTrue(result["output_truncated"])
        self.assertIsNone(result["exit_code"])
        self.assertTrue(channel.closed)

    def test_no_exit_packet_and_invalid_exit_length_are_unknown(self):
        for packet in (frame(1, b"partial"), frame(3, b"\x00\x00\x00\x00")):
            _, result = self.shell(packet)
            self.assertIsNone(result["exit_code"])
            self.assertTrue(result["transport_error"])

    def test_failed_socket_never_starts_a_server(self):
        with patch.object(m.socket, "create_connection", side_effect=ConnectionRefusedError("fixture")), \
             patch.object(m.subprocess, "Popen", side_effect=AssertionError("implicit daemon start")):
            result = m._shell_v2_read("127.0.0.1", 17389, "FAKE", ("getprop", "ro.soc.model"), 1, 100)
        self.assertIsNone(result["exit_code"])
        self.assertTrue(result["transport_error"])

    def test_smart_socket_rejects_non_readonly_requests_before_connect(self):
        with patch.object(m.socket, "create_connection", side_effect=AssertionError("must reject before connection")):
            for service in ("host:kill", "host:start-server", "host:reconnect", "host:transport-any"):
                with self.assertRaises(m.DriverError):
                    m._smart_request("127.0.0.1", 17389, service, 1)

    def test_lowlevel_shell_cannot_bypass_command_allowlist_or_bounds(self):
        with patch.object(m.socket, "create_connection", side_effect=AssertionError("must reject before connection")):
            for command, serial, timeout, limit in ((["am", "start", "x"], "FAKE", 1, 100),
                                                   (["getprop", "ro.soc.model"], "FAKE;id", 1, 100),
                                                   (["getprop", "ro.soc.model"], "FAKE", 0, 100),
                                                   (["getprop", "ro.soc.model"], "FAKE", 1, 9999999)):
                with self.assertRaises(m.DriverError):
                    m._shell_v2_read("127.0.0.1", 17389, serial, command, timeout, limit)

    def test_local_version_capture_also_has_a_byte_bound(self):
        # This is a synthetic host Python child, never an ADB invocation.
        result = m._run_bounded([sys.executable, "-c", "import os; os.write(1, b'x' * 100000)"], 2, 128)
        self.assertLessEqual(len(result["stdout"]) + len(result["stderr"]), 128)
        self.assertTrue(result["output_truncated"])
        self.assertIsNone(result["exit_code"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
