from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/docs/verify_component_documentation.py"
SPEC = importlib.util.spec_from_file_location(
    "verify_component_documentation", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ComponentDocumentationTests(unittest.TestCase):
    def write_fixture(self, root: Path) -> None:
        (root / "Cargo.toml").write_text(
            """[workspace]
members = ["active", "sealed"]
default-members = ["active"]
resolver = "3"
""",
            encoding="utf-8",
        )
        for path, package in (("active", "active-package"), ("sealed", "sealed-package")):
            directory = root / path
            directory.mkdir(parents=True)
            (directory / "Cargo.toml").write_text(
                f"""[package]
name = "{package}"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (directory / "README.md").write_text(
                f"# {package}\n\n{package}\n\n"
                + "Source-only component documentation. " * 20,
                encoding="utf-8",
            )

        machine = root / "docs/machine"
        machine.mkdir(parents=True)
        (machine / "module-catalog.v1.json").write_text(
            json.dumps(
                {"default_source_closure": ["active"]},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        governance = root / "governance"
        governance.mkdir()
        (governance / "component-lifecycle.v1.json").write_text(
            json.dumps(
                {
                    "schema": "org.trillionnium.component-lifecycle.v1",
                    "program_revision": "fixture",
                    "authority": "docs/machine/module-catalog.v1.json",
                    "rule": "Every non-default fixture member is sealed.",
                    "non_product_members": [
                        {
                            "path": "sealed",
                            "classification": "sealed_fixture",
                            "replacement": ["active"],
                            "reason": (
                                "The fixture keeps this component outside the "
                                "default product graph."
                            ),
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_checked_in_workspace_has_complete_component_documentation(self) -> None:
        VERIFY.verify(ROOT)

    def test_complete_minimal_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            VERIFY.verify(root)

    def test_missing_non_default_readme_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            (root / "sealed/README.md").unlink()
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "workspace member README missing: sealed",
            ):
                VERIFY.verify(root)

    def test_lifecycle_omission_cannot_hide_a_workspace_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "governance/component-lifecycle.v1.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["non_product_members"] = []
            path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "component lifecycle must exactly follow",
            ):
                VERIFY.verify(root)

    def test_default_member_cannot_be_classified_non_product(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "governance/component-lifecycle.v1.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["non_product_members"][0]["path"] = "active"
            path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "default member is classified non-product",
            ):
                VERIFY.verify(root)

    def test_duplicate_package_names_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            (root / "sealed/Cargo.toml").write_text(
                """[package]
name = "active-package"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (root / "sealed/README.md").write_text(
                "# active-package\n\nactive-package\n\n" + "bounded docs " * 40,
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "duplicate workspace package names",
            ):
                VERIFY.verify(root)


if __name__ == "__main__":
    unittest.main()
