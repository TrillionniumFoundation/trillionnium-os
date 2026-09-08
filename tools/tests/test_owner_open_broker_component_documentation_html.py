from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/docs/verify_component_documentation.py"
SPEC = importlib.util.spec_from_file_location(
    "verify_component_documentation_html", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ComponentDocumentationHtmlBlockTests(unittest.TestCase):
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
            contract = (
                "\n\n[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)"
                if path == "active"
                else ""
            )
            (directory / "README.md").write_text(
                f"# {package}\n\nCargo package: `{package}`.{contract}\n\n"
                "```sh\n"
                f"cargo test --locked -p {package} --all-targets\n"
                "```\n\n"
                + "Source-only bounded component documentation. " * 20,
                encoding="utf-8",
            )

        machine = root / "docs/machine"
        machine.mkdir(parents=True)
        modules = root / "docs/modules"
        modules.mkdir()
        (modules / "MOD-FIXTURE.md").write_text(
            "# Fixture module\n\nBounded fixture contract.\n",
            encoding="utf-8",
        )
        (machine / "module-catalog.v1.json").write_text(
            json.dumps(
                {
                    "modules": [
                        {
                            "id": "MOD-FIXTURE",
                            "paths": ["active/src/lib.rs"],
                        }
                    ],
                    "default_source_closure": ["active"],
                },
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

    def replace_real_surfaces_with_html(self, root: Path, opener: str, closer: str) -> None:
        path = root / "active/README.md"
        prose = path.read_text(encoding="utf-8")
        prose = prose.replace(
            "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)",
            "MOD-FIXTURE",
        )
        prose = prose.replace(
            "```sh\ncargo test --locked -p active-package --all-targets\n```",
            "cargo test",
        )
        prose += (
            f"\n{opener}\n"
            "```sh\n"
            "cargo test --locked -p active-package --all-targets\n"
            "```\n"
            "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)\n"
            f"{closer}\n"
        )
        path.write_text(prose, encoding="utf-8")

    def test_div_block_cannot_supply_command_or_contract_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            self.replace_real_surfaces_with_html(root, "<div>", "</div>")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "raw HTML block opener is forbidden",
            ):
                VERIFY.verify(root)

    def test_custom_element_block_cannot_supply_documentation_credit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            self.replace_real_surfaces_with_html(
                root,
                '<component-contract mode="hidden">',
                "</component-contract>",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "raw HTML block opener is forbidden",
            ):
                VERIFY.verify(root)

    def test_pre_block_is_rejected_instead_of_partially_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            self.replace_real_surfaces_with_html(root, "<pre>", "</pre>")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "raw HTML block opener is forbidden",
            ):
                VERIFY.verify(root)

    def test_declaration_processing_instruction_and_cdata_fail_closed(self) -> None:
        for raw in (
            "<!DOCTYPE html>",
            '<?component-contract mode="hidden"?>',
            "<![CDATA[ hidden documentation ]]>",
        ):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_fixture(root)
                path = root / "active/README.md"
                path.write_text(
                    path.read_text(encoding="utf-8") + f"\n{raw}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    VERIFY.VerificationError,
                    "raw HTML block opener is forbidden",
                ):
                    VERIFY.verify(root)

    def test_inline_html_after_prose_remains_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\nOrdinary prose may contain <span>bounded inline HTML</span>.\n",
                encoding="utf-8",
            )
            VERIFY.verify(root)

    def test_html_example_inside_text_fence_remains_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\n```text\n<div>example only</div>\n```\n",
                encoding="utf-8",
            )
            VERIFY.verify(root)


if __name__ == "__main__":
    unittest.main()
