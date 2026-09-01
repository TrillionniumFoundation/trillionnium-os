from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-adbroot-evaluated-graph.py"
SPEC = importlib.util.spec_from_file_location("adbroot_evaluated_graph", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class EvaluatedAdbrootGraphTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._write_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, relative: Path | str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _write_fixture(self) -> None:
        common_block = "\n".join(MODULE.COMMON_SECURITY_ACTIVE_LINES) + "\n"
        product_block = "\n".join(MODULE.PRODUCT_PRIVILEGE_ACTIVE_LINES) + "\n"
        self._write(MODULE.COMMON_PATH, "# fixture\n" + common_block + "# after\n")
        self._write(
            MODULE.COMMON_OWNER_OPEN_PATH,
            "# fixture\n" + "\n".join(MODULE.COMMON_OWNER_OPEN_ACTIVE_LINES) + "\n",
        )
        self._write(MODULE.PRODUCT_PATH, "# fixture\n" + product_block + "# after\n")
        for name, statements in MODULE.EXPECTED_POLICY_STATEMENTS.items():
            self._write(MODULE.ADBROOT_POLICY_DIR / name, "\n".join(statements) + "\n")
        projects = "\n".join(
            f'  <project name="{name}" path="{path}" revision="{index + 1:040x}" />'
            for index, (path, name) in enumerate(MODULE.MANIFEST_PROJECTS.items())
        )
        self._write(MODULE.MANIFEST_PATH, f"<manifest>\n{projects}\n</manifest>\n")

    def evaluate(self):
        return MODULE.evaluate_repository(
            self.root,
            source_commit="a" * 40,
            evaluated_commit="a" * 40,
            evaluated_tree="b" * 40,
            evaluation_kind="source_head",
        )

    def test_full_requested_matrix_is_evaluated(self) -> None:
        receipt = self.evaluate()
        self.assertEqual(receipt["matrix_case_count"], 12)
        self.assertEqual(receipt["negative_case_count"], 10)
        cases = {
            (case["variant"], case["opt_in_state"]): case
            for case in receipt["matrix"]
        }
        self.assertEqual(set(cases), {
            (variant, state)
            for variant in MODULE.SUPPORTED_VARIANTS
            for state, _value in MODULE.OPT_IN_CASES
        })
        self.assertTrue(cases[("userdebug", "true")]["service_authority_selected"])
        self.assertTrue(cases[("eng", "true")]["policy_authority_selected"])
        self.assertFalse(cases[("user", "true")]["service_authority_selected"])
        self.assertFalse(cases[("userdebug", "malformed")]["property_control_authority_selected"])

    def test_release_and_non_opt_in_cases_have_no_adbroot_authority(self) -> None:
        receipt = self.evaluate()
        for case in receipt["matrix"]:
            if case["variant"] == "user" or case["opt_in_state"] != "true":
                self.assertFalse(case["service_authority_selected"], case)
                self.assertFalse(case["policy_authority_selected"], case)
                self.assertFalse(case["property_control_authority_selected"], case)

    def test_user_and_userdebug_keep_adb_authentication_secure(self) -> None:
        receipt = self.evaluate()
        for case in receipt["matrix"]:
            expected = "0" if case["variant"] == "eng" else "1"
            self.assertEqual(case["ro_adb_secure"], expected)

    def test_receipt_is_source_bound_and_self_digesting(self) -> None:
        receipt = self.evaluate()
        self.assertEqual(receipt["source_commit"], "a" * 40)
        self.assertEqual(receipt["evaluated_tree"], "b" * 40)
        self.assertEqual(receipt["receipt_sha256"], MODULE._receipt_digest(receipt))
        self.assertFalse(receipt["soong_compiled"])
        self.assertFalse(receipt["selinux_compiled"])
        self.assertFalse(receipt["installed"])
        self.assertFalse(receipt["public_release"])

    def test_manifest_projects_are_immutable_and_complete(self) -> None:
        receipt = self.evaluate()
        self.assertEqual(set(receipt["manifest_projects"]), set(MODULE.MANIFEST_PROJECTS))
        for value in receipt["manifest_projects"].values():
            self.assertRegex(value["revision"], r"^[0-9a-f]{40}$")

    def test_missing_manifest_project_fails_closed(self) -> None:
        path = self.root / MODULE.MANIFEST_PATH
        text = path.read_text(encoding="utf-8")
        text = text.replace(' path="packages/modules/adb"', ' path="packages/modules/missing"')
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.VerificationError, "packages/modules/adb"):
            self.evaluate()

    def test_nonimmutable_manifest_revision_fails_closed(self) -> None:
        path = self.root / MODULE.MANIFEST_PATH
        text = path.read_text(encoding="utf-8").replace(f'{1:040x}', "lineage-23.2", 1)
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.VerificationError, "immutable SHA"):
            self.evaluate()

    def test_missing_product_input_fails_closed(self) -> None:
        (self.root / MODULE.PRODUCT_PATH).unlink()
        with self.assertRaisesRegex(MODULE.VerificationError, "required input"):
            self.evaluate()

    def test_common_product_inheritance_order_is_exact(self) -> None:
        path = self.root / MODULE.COMMON_OWNER_OPEN_PATH
        lines = list(MODULE.COMMON_OWNER_OPEN_ACTIVE_LINES)
        path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.VerificationError, "unconditionally inherit"):
            self.evaluate()

    def test_package_policy_gate_divergence_fails_closed(self) -> None:
        path = self.root / MODULE.PRODUCT_PATH
        text = path.read_text(encoding="utf-8").replace(
            MODULE.ADBROOT_POLICY_INSTALL_PATH,
            "vendor/trillionnium/owner-open/sepolicy/private",
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.VerificationError, "gate drifted"):
            self.evaluate()

    def test_extra_privilege_reference_outside_gate_fails_closed(self) -> None:
        path = self.root / MODULE.PRODUCT_PATH
        path.write_text(path.read_text(encoding="utf-8") + "PRODUCT_PACKAGES += adb_root\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.VerificationError, "outside the single reviewed"):
            self.evaluate()

    def test_policy_input_set_is_exact(self) -> None:
        self._write(MODULE.ADBROOT_POLICY_DIR / "unexpected.te", "allow x y:z q;\n")
        with self.assertRaisesRegex(MODULE.VerificationError, "input set drifted"):
            self.evaluate()

    def test_policy_symlink_fails_closed(self) -> None:
        path = self.root / MODULE.ADBROOT_POLICY_DIR / "service.te"
        path.unlink()
        path.symlink_to("adbroot.te")
        with self.assertRaisesRegex(MODULE.VerificationError, "symlink"):
            self.evaluate()

    def test_policy_widening_fails_closed(self) -> None:
        path = self.root / MODULE.ADBROOT_POLICY_DIR / "adbroot.te"
        path.write_text(path.read_text(encoding="utf-8") + "allow adbroot self:capability sys_admin;\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.VerificationError, "statements drifted"):
            self.evaluate()

    def test_synthetic_merge_parent_order_is_enforced(self) -> None:
        with self.assertRaisesRegex(MODULE.VerificationError, "ordered base then source"):
            MODULE.evaluate_repository(
                self.root,
                source_commit="a" * 40,
                base_commit="c" * 40,
                evaluated_commit="d" * 40,
                evaluated_tree="b" * 40,
                evaluation_kind="synthetic_merge",
                parent_commits=("a" * 40, "c" * 40),
            )


if __name__ == "__main__":
    unittest.main()
