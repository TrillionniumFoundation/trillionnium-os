"""Host-only exact-reference cancellation authorization contracts; no ADB."""
import copy
import json
import struct
import tempfile
import unittest
import zlib
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import lifecycle_guards as guard
import phone_lifecycle as lifecycle


def image(change=False):
    width, height = 40, 32
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            row.extend((x * 5 % 256, y * 7 % 256, (x + y) * 3 % 256))
        if change and y == 15:
            row[15 * 3] ^= 1
        rows.append(b"\0" + bytes(row))
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    data = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))
    return guard.png_extract(data)


class ObservedTemplateTests(unittest.TestCase):
    def setUp(self):
        self.candidate = {"package": guard.PACKAGE, "apk_sha256": "a" * 64, "version_code": 10}
        self.display = {"serial": "HOST_ONLY_FIXTURE", "physical_display_id": "123", "logical_display_id": 0,
                        "input_width": 40, "input_height": 32}
        self.reference = image()
        rectangle = [5, 5, 30, 25]
        self.value = {"schema": "hepta.lifecycle-observed-stop-template.v1", "observed_control": "停止",
                      "operator_observed_enabled_control": True, "reference_png": "observed-stop.png",
                      "reference_png_sha256": guard.sha(self.reference["png"]),
                      "reference_roi_sha256": guard.png_roi(self.reference, rectangle),
                      "candidate": dict(self.candidate), "display": dict(self.display),
                      "observed_component": guard.PACKAGE + "/.MainActivity", "point": [15, 15], "rectangle": rectangle,
                      "scaled": False, "coordinate_origin": [0, 0], "single_tap_only": True,
                      "extends_native_lifetime": False, "created_host_wall_ms": 1000, "expires_host_wall_ms": 601000}

    def validate(self, value=None, reference=None, now=2000):
        return lifecycle.validate_stop_template(value or self.value, reference or self.reference,
                                                self.candidate, self.display, now)

    def test_complete_reference_has_exact_pixel_identity(self):
        self.assertEqual(self.validate(), self.value["reference_roi_sha256"])

    def test_other_apk_version_device_or_display_cannot_authorize(self):
        changes = [("candidate", "apk_sha256", "b" * 64), ("candidate", "version_code", 11),
                   ("display", "serial", "OTHER"), ("display", "physical_display_id", "124"),
                   ("display", "logical_display_id", 1), ("display", "input_width", 41)]
        for section, key, value in changes:
            altered = copy.deepcopy(self.value)
            altered[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                self.validate(altered)

    def test_boolean_in_numeric_identity_is_rejected(self):
        altered = copy.deepcopy(self.value)
        altered["display"]["logical_display_id"] = False
        with self.assertRaises(ValueError):
            self.validate(altered)
        altered = copy.deepcopy(self.value)
        altered["candidate"]["version_code"] = True
        with self.assertRaises(ValueError):
            self.validate(altered)

    def test_expiry_future_and_excessive_validity_are_rejected(self):
        for now in (999, 601001):
            with self.subTest(now=now), self.assertRaises(ValueError):
                self.validate(now=now)
        altered = copy.deepcopy(self.value)
        altered["expires_host_wall_ms"] += 1
        with self.assertRaises(ValueError):
            self.validate(altered)

    def test_reference_image_and_roi_tampering_are_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(reference=image(True))
        altered = copy.deepcopy(self.value)
        altered["reference_roi_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.validate(altered)

    def test_old_task_or_inferred_control_fields_are_not_accepted(self):
        for key, value in (("task_id", "a" * 32), ("automatic_detection", True), ("observed_control", "Continue"),
                           ("operator_observed_enabled_control", False), ("scaled", True),
                           ("extends_native_lifetime", True), ("observed_component", guard.PACKAGE + "/OtherActivity")):
            altered = copy.deepcopy(self.value)
            altered[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(altered)

    def test_point_must_remain_strictly_inside_operator_rectangle(self):
        for point in ([5, 15], [30, 15], [15, 25], [True, 15], [-1, 15]):
            altered = copy.deepcopy(self.value)
            altered["point"] = point
            with self.subTest(point=point), self.assertRaises(ValueError):
                self.validate(altered)

    def fresh_request(self, first=None, current=None):
        state = {"host_run_id": "b" * 32, "challenge": "c" * 64}
        binding = {"task_id": "d" * 32, "nonce_sha256": "e" * 64, "run_id": "f" * 32,
                   "worker": {"pid": 1234, "start_ticks": 56789}}
        result = lifecycle.template_cancel_request(self.value, self.reference, first or self.reference,
                    current or self.reference, self.candidate, self.display, state, binding, 2000)
        return result, state, binding

    def test_automatic_request_uses_only_current_task_nonce_worker(self):
        result, state, binding = self.fresh_request()
        for key in ("host_run_id", "challenge"):
            self.assertEqual(result[key], state[key])
        for key in ("task_id", "nonce_sha256", "run_id"):
            self.assertEqual(result[key], binding[key])
        self.assertEqual(result["worker_pid"], binding["worker"]["pid"])
        self.assertEqual(result["worker_start_ticks"], binding["worker"]["start_ticks"])
        self.assertEqual(result["screenshot_sha256"], guard.sha(self.reference["png"]))
        self.assertEqual(result["point"], self.value["point"])
        self.assertIsNot(result["point"], self.value["point"])

    def test_transition_or_changed_second_frame_cannot_create_auto_request(self):
        with self.assertRaises(ValueError):
            self.fresh_request(first=image(True))
        with self.assertRaises(ValueError):
            self.fresh_request(current=image(True))

    def test_manual_mode_remains_default(self):
        args = lifecycle.parser().parse_args(["monitor", "--plan", "p", "--output", "o", "--adb", "/existing/adb",
                    "--adb-port", "5061", "--serial", "SERIAL", "--physical-display-id", "123",
                    "--logical-display-id", "0", "--input-width", "40", "--input-height", "32"])
        self.assertIsNone(args.stop_template)

    def test_final_pre_tap_gate_rejects_expiry_during_fresh_device_reads(self):
        lifecycle.require_current_tap_time(1000, 90, 100, 2000, 99)
        for now, monotonic in ((91001, 99), (999, 99), (2000, 100), (2000, 101)):
            with self.subTest(now=now, monotonic=monotonic), self.assertRaises(ValueError):
                lifecycle.require_current_tap_time(1000, 90, 100, now, monotonic)

    def test_offline_preparation_retains_original_png_and_requires_new_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.png"
            original.write_bytes(self.reference["png"])
            candidate = root / "candidate.json"
            candidate.write_text(json.dumps(self.candidate))
            args = Namespace(candidate=candidate, image=original, output=root / "prepared", point=[15, 15],
                             rectangle=[5, 5, 30, 25], observed_component=guard.PACKAGE + "/.MainActivity",
                             operator_observed_enabled_stop=True, valid_ms=600000, **self.display)
            with patch("subprocess.run", side_effect=AssertionError("template preparation must not contact any process/device")):
                lifecycle.stop_template(args)
            self.assertEqual((args.output / "observed-stop.png").read_bytes(), original.read_bytes())
            template = lifecycle.control_file(args.output / "template.json")
            self.assertIs(template["operator_observed_enabled_control"], True)
            with self.assertRaises(FileExistsError):
                lifecycle.stop_template(args)


if __name__ == "__main__":
    unittest.main()
