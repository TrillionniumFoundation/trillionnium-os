import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

import lifecycle_guards as guards
import phone_lifecycle as lifecycle


def session():
    return {"schema": "hepta.local-session.v1", "status": "cancelled", "state": "已停止",
            "task_id": "a" * 32, "origin": "private_debug_nonce", "instruction_sha256": "b" * 64,
            "debug_nonce_sha256": "c" * 64, "pending": False, "running": False, "blocked": False,
            "cleanup_known": True, "app_uid": 10481, "updated_wall_ms": 1794162000000,
            "external_model": False, "automatic_resume": False}


def make_png(width, height, pixels):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff)
    raw = b"".join(b"\0" + pixels[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return guards.PNG_MAGIC + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


class LifecycleEvidenceTests(unittest.TestCase):
    def test_full_clean_record_rejects_active_unknown_and_missing_nonce(self):
        value = session()
        self.assertEqual(guards.clean_session(value, 10481)["task_id"], "a" * 32)
        for key, changed in (("running", True), ("pending", True), ("blocked", True), ("cleanup_known", False),
                             ("automatic_resume", True), ("app_uid", 10482), ("debug_nonce_sha256", None)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                guards.clean_session({**value, key: changed}, 10481)

    def test_identity_is_not_replaced_by_terminal_flag(self):
        with self.assertRaises(ValueError):
            guards.clean_session(session(), 10481, task_id="d" * 32)
        value = session()
        del value["instruction_sha256"]
        with self.assertRaises(ValueError):
            guards.clean_session(value, 10481)

    def test_real_host_proc_start_ticks_and_argv_are_read_without_env(self):
        root = Path("/proc/self")
        value = guards.parse_proc((root / "stat").read_bytes(), (root / "status").read_bytes(),
                                  (root / "cmdline").read_bytes(), (root / "stat").read_bytes())
        self.assertEqual(value["pid"], int(root.resolve().name))
        self.assertEqual(value["uid"], os.getuid())
        self.assertGreater(value["start_ticks"], 0)
        self.assertTrue(value["argv"])
        self.assertNotIn("environ", value)

    def test_actual_pid_reuse_or_reparenting_invalidates_double_observation(self):
        root = Path("/proc/self")
        before = (root / "stat").read_bytes()
        text = before.decode()
        marker = text.rfind(") ") + 2
        fields = text[marker:].split()
        fields[19] = str(int(fields[19]) + 1)
        after = (text[:marker] + " ".join(fields)).encode()
        with self.assertRaises(ValueError):
            guards.parse_proc(before, (root / "status").read_bytes(), (root / "cmdline").read_bytes(), after)

    def test_stop_roi_ignores_unrelated_clock_pixels_but_detects_control_change(self):
        pixels = bytes(range(60))
        first = guards.png_extract(make_png(5, 4, pixels))
        clock = bytearray(pixels)
        clock[0] ^= 255
        other = guards.png_extract(make_png(5, 4, bytes(clock)))
        self.assertEqual(guards.png_roi(first, [1, 1, 4, 3]), guards.png_roi(other, [1, 1, 4, 3]))
        control = bytearray(pixels)
        control[(1 * 5 + 1) * 3] ^= 255
        changed = guards.png_extract(make_png(5, 4, bytes(control)))
        self.assertNotEqual(guards.png_roi(first, [1, 1, 4, 3]), guards.png_roi(changed, [1, 1, 4, 3]))

    def test_android_warning_prefix_is_separate_and_crc_failures_are_not_images(self):
        png = make_png(1, 1, b"\x01\x02\x03")
        image = guards.png_extract(b"Warning: multiple displays\n" + png)
        self.assertEqual(image["png"], png)
        self.assertTrue(image["warning"])
        broken = bytearray(png)
        broken[25] ^= 1
        for bad in (bytes(broken), b"unexpected output\n" + png, png[:-1], png + b"extra"):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                guards.png_extract(bad)

    def test_cancel_request_rejects_permissions_links_and_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "request.json"
            lifecycle.write(path, {"challenge": "a" * 64}, exclusive=True)
            self.assertEqual(lifecycle.control_file(path)["challenge"], "a" * 64)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                lifecycle.control_file(path)
            path.chmod(0o600)
            os.link(path, root / "other.json")
            with self.assertRaises(ValueError):
                lifecycle.control_file(path)
            (root / "other.json").unlink()
            path.write_text('{"challenge":"a","challenge":"b"}')
            with self.assertRaises(ValueError):
                lifecycle.control_file(path)

    def test_cancel_natural_completion_race_never_passes(self):
        candidate = {"model_profile": "minicpm5-2b-q4_k_m", "model_sha256": "e" * 64, "compute": "npu", "context_tokens": 8192}
        binding = {"task_id": "a" * 32, "nonce_sha256": "c" * 64, "run_id": "d" * 32,
                   "parent": {"pid": 1234}, "worker": {"argv": ["/data/app/example/lib/arm64/libhepta_local_runner.so"]}}
        receipt = {"schema": "hepta.local-model.receipt.v2", "package_name": guards.PACKAGE,
                   "run_id": "d" * 32, "app_uid": 10481, "app_pid": 1234, "expected_parent_pid": 1234,
                   "runtime": "llama_cpp", "mode": "llm", "model_profile": candidate["model_profile"],
                   "model_sha256_verified": "e" * 64, "compute_requested": "npu", "context_tokens": 8192,
                   "process_started": True, "process_exit_observed": True, "cancel_requested": True,
                   "timeout_observed": False, "inference_completed": False, "status": "cancelled",
                   "fallback_allowed": False, "automatic_retry": False, "image_sent_to_model": False,
                   "exit_code": 143, "runner_path": binding["worker"]["argv"][0], "native_receipt": {}}
        result = {"task_id": "a" * 32, "status": "cancelled", "cleanup_known": True, "external_model": False}
        self.assertTrue(guards.cancellation_receipt(receipt, result, session(), binding, candidate, 10481))
        for change in ({"exit_code": 0}, {"timeout_observed": True}, {"native_receipt": {"generation_complete": True}},
                       {"native_receipt": {"worker_outcome": "completed"}}, {"expected_parent_pid": 1235}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                guards.cancellation_receipt({**receipt, **change}, result, session(), binding, candidate, 10481)


class RuntimePathTests(unittest.TestCase):
    def setUp(self):
        self.code="/data/app/~~Fixture==/org.trillionnium.hepta.local-Fixture=="
        self.dump=("  codePath="+self.code+"\n  legacyNativeLibraryDir="+self.code+"/lib\n  primaryCpuAbi=arm64-v8a\n").encode()
        self.inventory=guards.installed_library_inventory(self.dump)
        self.runner=self.code+"/lib/arm64/libhepta_local_runner.so"
        self.user="/data/user/0/"+guards.PACKAGE;self.alias="/data/data/"+guards.PACKAGE
        self.roots={self.user:self.user,self.alias:self.user}
        self.paths=guards.runtime_path_binding(self.inventory,(self.runner+"\n").encode(),self.runner.encode(),self.user,self.roots,10481)
        self.run="d"*32;self.parent={"uid":10481,"pid":5582,"argv":[guards.PACKAGE]}
        self.candidate={"model_profile":"spark-x2.6-4b-q4_k_m","compute":"npu","context_tokens":4096,"threads":4}
        self.file="Spark-X2.6-4B-Q4_K_M.gguf"
        opts={"--expected-parent-pid":"5582","--request-id":self.run,"--model-profile":self.candidate["model_profile"],
              "--mode":"llm","--runtime":"llama_cpp","--compute":"npu","--ctx-size":"4096","--threads":"4",
              "--model":self.alias+"/files/model/"+self.file}
        for flag,name in (("--prompt-file","prompt.txt"),("--result-file","native-result.json"),("--text-file","raw-text.txt"),
                          ("--system-file","system.txt"),("--grammar-file","grammar.gbnf")):
            opts[flag]=self.alias+"/files/runs/"+self.run+"/"+name
        self.worker={"uid":10481,"ppid":5582,"argv":[self.runner]+[item for pair in opts.items() for item in pair]}

    def check(self,worker=None,paths=None):
        return guards.native_identity(worker or self.worker,self.parent,self.run,self.candidate,self.user,self.runner,self.file,
                                      self.paths if paths is None else paths)

    def test_legacy_library_root_is_not_the_actual_executable_directory(self):
        self.assertEqual(self.inventory["search_directory"],self.code+"/lib")
        self.assertEqual(self.paths["runner"],self.runner)
        self.assertTrue(self.check())
        wrong=copy.deepcopy(self.worker);wrong["argv"][0]=self.code+"/lib/libhepta_local_runner.so"
        with self.assertRaises(ValueError):self.check(wrong)

    def test_native_and_legacy_declarations_must_share_one_installation(self):
        both=self.dump+("  nativeLibraryDir="+self.code+"/lib/arm64\n").encode()
        self.assertEqual(guards.installed_library_inventory(both)["expected_runner"],self.runner)
        for bad in (self.dump.replace(b"arm64-v8a",b"x86_64"),self.dump+b" nativeLibraryDir=/data/local/tmp/lib\n",
                    self.dump.replace(b"legacyNativeLibraryDir=",b"missingLibraryDir=")):
            with self.subTest(bad=bad),self.assertRaises(ValueError):guards.installed_library_inventory(bad)

    def test_runner_must_be_unique_regular_discovery_and_same_canonical_path(self):
        for discovered,canonical in ((self.runner+"\n"+self.runner+"\n",self.runner),(self.runner+"\n","/data/local/tmp/libhepta_local_runner.so"),
                                     (self.code+"/lib/libhepta_local_runner.so\n",self.runner)):
            with self.subTest(discovered=discovered),self.assertRaises(ValueError):
                guards.runtime_path_binding(self.inventory,discovered.encode(),canonical.encode(),self.user,self.roots,10481)

    def test_data_data_alias_needs_matching_on_device_canonical_observation(self):
        self.assertTrue(self.check())
        with self.assertRaises(ValueError):
            guards.native_identity(self.worker,self.parent,self.run,self.candidate,self.user,self.runner,self.file)
        for roots in ({self.user:self.user}, {self.user:self.user,self.alias:"/data/user/10/"+guards.PACKAGE},
                      {self.user:self.user,self.alias:self.user,"/data/local/tmp":self.user}):
            with self.subTest(roots=roots),self.assertRaises(ValueError):
                guards.runtime_path_binding(self.inventory,self.runner.encode(),self.runner.encode(),self.user,roots,10481)

    def test_common_suffix_other_user_or_other_run_never_matches(self):
        for flag,value in (("--prompt-file","/data/user/10/"+guards.PACKAGE+"/files/runs/"+self.run+"/prompt.txt"),
                           ("--result-file",self.alias+"/files/runs/"+"e"*32+"/native-result.json"),
                           ("--model",self.alias+"/files/model/other.gguf")):
            changed=copy.deepcopy(self.worker);changed["argv"][changed["argv"].index(flag)+1]=value
            with self.subTest(flag=flag),self.assertRaises(ValueError):self.check(changed)

    def test_forged_private_alias_or_changed_parent_remains_rejected(self):
        changed=copy.deepcopy(self.paths);changed["private_roots"].append("/data/local/tmp")
        changed["readlink_observations"]["/data/local/tmp"]=self.user
        with self.assertRaises(ValueError):self.check(paths=changed)
        worker={**self.worker,"ppid":5583}
        with self.assertRaises(ValueError):self.check(worker)


class DisplayAndFrameTests(unittest.TestCase):
    @staticmethod
    def displays(other="null", primary=None):
        if primary is None:
            primary = "Window{a1b2 u0 org.trillionnium.hepta.local/org.trillionnium.hepta.local.MainActivity}"
        return ("WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)\n"
                "  Display: mDisplayId=1 (organized)\n"
                "    init=1080x1272 360dpi\n"
                "  mCurrentFocus=" + other + "\n"
                "  Display: mDisplayId=0 (organized)\n"
                "    init=1224x2992 480dpi\n"
                "  mCurrentFocus=" + primary + "\n").encode()

    def test_secondary_display_null_does_not_hide_primary_component(self):
        result = guards.focus_observation(b" mTopFocusedDisplayId=0\n", self.displays(),
                                          b" mTopFocusedDisplayId=0\n", 0)
        self.assertEqual(result["focus_package"], guards.PACKAGE)
        self.assertEqual(result["logical_display_id"], 0)
        self.assertEqual(result["focus_user"], 0)
        self.assertEqual(result["observed_display_ids"], [1, 0])
        self.assertFalse(result["atomic_snapshot_claimed"])

    def test_other_display_package_is_never_the_requested_display_focus(self):
        other = "Window{1234 u0 com.example.secondary/.Other}"
        result = guards.display_focus(self.displays(other), 0)
        self.assertEqual(result["focus_package"], guards.PACKAGE)
        self.assertEqual(guards.display_focus(self.displays(other), 1)["focus_package"], "com.example.secondary")
        self.assertIsNone(guards.display_focus(self.displays(other, "null"), 0)["focus_package"])

    def test_missing_duplicate_and_malformed_display_labels_fail_closed(self):
        original = self.displays()
        changes = [original.replace(b"mDisplayId=0", b"mDisplayId=1"),
                   original.replace(b"mDisplayId=0", b"mDisplayId=unknown"),
                   original.replace(b"mCurrentFocus=Window", b"mCurrentFocus =Window"),
                   original + b"  mCurrentFocus=null\n",
                   original.replace(b"(dumpsys window displays)", b"(unknown)"),
                   original.replace(b"org.trillionnium.hepta.local.MainActivity}", b"org.trillionnium.hepta.local.MainActivity} extra")]
        for value in changes:
            with self.subTest(value=value), self.assertRaises(ValueError):
                guards.display_focus(value, 0)

    def test_top_display_missing_duplicate_or_changed_is_not_focus_proof(self):
        bad = [b"", b"mTopFocusedDisplayId=0\nmTopFocusedDisplayId=0\n",
               b"mTopFocusedDisplayId=0\nmTopFocusedDisplayId=unknown\n",
               b"mTopFocusedDisplayId=unknown\n", b"mTopFocusedDisplayId=65536\n"]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                guards.top_focused_display(value)
        with self.assertRaises(ValueError):
            guards.focus_observation(b"mTopFocusedDisplayId=0\n", self.displays(), b"mTopFocusedDisplayId=1\n", 0)

    def test_probe_retains_ordered_scope_dumps_and_checks_current_android_user(self):
        class Adb:
            def __init__(self, displays):
                self.displays, self.calls = displays, []
            def command(self, args, **kwargs):
                self.calls.append(args)
                return 0, self.displays if args[-1] == "displays" else b"mTopFocusedDisplayId=0\n"
        with tempfile.TemporaryDirectory() as temp:
            probe = lifecycle.Probe.__new__(lifecycle.Probe)
            probe.args = type("Args", (), {"logical_display_id": 0})()
            probe.out, probe.uid = Path(temp), 10481
            probe.adb = Adb(self.displays())
            self.assertEqual(probe.window("fixture")["focus_package"], guards.PACKAGE)
            self.assertEqual(probe.adb.calls, [["dumpsys", "window", "windows"], ["dumpsys", "window", "displays"], ["dumpsys", "window", "windows"]])
            self.assertTrue((probe.out / "fixture-binding.json").is_file())
            probe.adb = Adb(self.displays().replace(b" u0 ", b" u10 "))
            with self.assertRaises(ValueError):
                probe.window("different-user")

    def test_transition_changed_stop_roi_rejects_but_clock_outside_it_does_not(self):
        pixels = bytes(range(60))
        first = guards.png_extract(make_png(5, 4, pixels))
        clock = bytearray(pixels); clock[0] ^= 255
        second = guards.png_extract(make_png(5, 4, bytes(clock)))
        self.assertEqual(guards.stable_stop_roi(first, second, [1, 1, 4, 3]), guards.png_roi(first, [1, 1, 4, 3]))
        blank = guards.png_extract(make_png(5, 4, bytes(60)))
        with self.assertRaises(ValueError):
            guards.stable_stop_roi(blank, second, [1, 1, 4, 3])

    def test_host_crop_preview_preserves_pixels_and_never_authorizes_tap(self):
        image = guards.png_extract(make_png(5, 4, bytes(range(60))))
        with tempfile.TemporaryDirectory() as temp:
            probe = lifecycle.Probe.__new__(lifecycle.Probe)
            probe.out = Path(temp)
            metadata = probe.stop_preview(image)
            self.assertFalse(metadata["authorizes_tap"])
            self.assertFalse(metadata["scaled"])
            self.assertEqual(metadata["source_png_sha256"], guards.sha(image["png"]))
            if metadata["available"]:
                preview = guards.png_extract((probe.out / metadata["path"]).read_bytes())
                self.assertEqual(guards.png_roi(image, [0, 0, 5, 4]), guards.png_roi(preview, [0, 0, 5, 4]))
                self.assertEqual(metadata["coordinate_origin"], [0, 0])


if __name__ == "__main__":
    unittest.main()
