from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
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

    def test_missing_exact_test_command_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "cargo test --locked -p active-package --all-targets",
                    "cargo test --locked --all-targets",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing exact local test command",
            ):
                VERIFY.verify(root)

    def test_active_member_missing_module_contract_link_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)",
                    "MOD-FIXTURE",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing module contract link docs/modules/MOD-FIXTURE.md",
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

    def test_duplicate_json_member_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            (root / "docs/machine/module-catalog.v1.json").write_text(
                '{"modules": [], "default_source_closure": ["active"], '
                '"default_source_closure": ["active"]}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "duplicate JSON member 'default_source_closure'",
            ):
                VERIFY.verify(root)

    def test_absolute_lifecycle_path_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "governance/component-lifecycle.v1.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["non_product_members"][0]["path"] = "/sealed"
            path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "must be relative",
            ):
                VERIFY.verify(root)

    def test_parent_traversal_lifecycle_path_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "governance/component-lifecycle.v1.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["non_product_members"][0]["path"] = "../sealed"
            path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "traverses",
            ):
                VERIFY.verify(root)

    def test_workspace_member_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            source = root / "sealed"
            target = root / "sealed-target"
            source.rename(target)
            try:
                source.symlink_to(target.name, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "traverses symlink",
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
                "# active-package\n\nCargo package: `active-package`.\n\n"
                "```sh\n"
                "cargo test --locked -p active-package --all-targets\n"
                "```\n\n"
                + "bounded source documentation " * 20,
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "duplicate workspace package names",
            ):
                VERIFY.verify(root)

    def test_html_comment_cannot_supply_exact_test_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            command = "cargo test --locked -p active-package --all-targets"
            prose = path.read_text(encoding="utf-8").replace(command, "cargo test")
            prose += f"\n<!-- {command} -->\n"
            path.write_text(prose, encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing exact local test command",
            ):
                VERIFY.verify(root)

    def test_plain_or_inline_code_cannot_supply_exact_test_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            command = "cargo test --locked -p active-package --all-targets"
            prose = path.read_text(encoding="utf-8").replace(command, "cargo test")
            prose += f"\nRun `{command}` from another document.\n"
            path.write_text(prose, encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing exact local test command",
            ):
                VERIFY.verify(root)

    def test_non_shell_code_block_cannot_supply_exact_test_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            command = "cargo test --locked -p active-package --all-targets"
            prose = path.read_text(encoding="utf-8").replace("```sh", "```text", 1)
            self.assertIn(command, prose)
            path.write_text(prose, encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing exact local test command",
            ):
                VERIFY.verify(root)

    def test_html_comment_cannot_supply_module_contract_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            link = "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)"
            prose = path.read_text(encoding="utf-8").replace(link, "MOD-FIXTURE")
            prose += f"\n<!-- {link} -->\n"
            path.write_text(prose, encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing module contract link docs/modules/MOD-FIXTURE.md",
            ):
                VERIFY.verify(root)

    def test_code_example_cannot_supply_module_contract_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            link = "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)"
            prose = path.read_text(encoding="utf-8").replace(link, "MOD-FIXTURE")
            prose += f"\n```text\n{link}\n```\n"
            path.write_text(prose, encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing module contract link docs/modules/MOD-FIXTURE.md",
            ):
                VERIFY.verify(root)

    def test_wrong_relative_module_target_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            wrong = root / "active/docs/modules"
            wrong.mkdir(parents=True)
            (wrong / "MOD-FIXTURE.md").write_text("wrong copy\n", encoding="utf-8")
            path = root / "active/README.md"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "../docs/modules/MOD-FIXTURE.md",
                    "docs/modules/MOD-FIXTURE.md",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                r"does not resolve to a canonical docs/modules/MOD-\*\.md file",
            ):
                VERIFY.verify(root)

    def test_module_link_suffix_cannot_satisfy_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "../docs/modules/MOD-FIXTURE.md)",
                    "../docs/modules/MOD-FIXTURE.md.bak)",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                r"does not resolve to a canonical docs/modules/MOD-\*\.md file",
            ):
                VERIFY.verify(root)

    def test_module_link_fragment_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "../docs/modules/MOD-FIXTURE.md)",
                    "../docs/modules/MOD-FIXTURE.md#scope)",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "has query or fragment",
            ):
                VERIFY.verify(root)

    def test_unterminated_html_comment_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            path.write_text(
                path.read_text(encoding="utf-8") + "\n<!-- hidden boundary\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "unterminated HTML comment",
            ):
                VERIFY.verify(root)

    def test_reports_all_missing_component_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            for directory, package in (
                ("active", "active-package"),
                ("sealed", "sealed-package"),
            ):
                path = root / directory / "README.md"
                path.write_text(
                    path.read_text(encoding="utf-8").replace(
                        f"cargo test --locked -p {package} --all-targets",
                        "cargo test",
                    ),
                    encoding="utf-8",
                )
            with self.assertRaises(VERIFY.VerificationError) as raised:
                VERIFY.verify(root)
            message = str(raised.exception)
            self.assertIn("active-package", message)
            self.assertIn("sealed-package", message)

    def test_indented_code_cannot_supply_module_contract_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            link = "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)"
            prose = path.read_text(encoding="utf-8").replace(link, "MOD-FIXTURE")
            prose += f"\n    {link}\n"
            path.write_text(prose, encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing module contract link docs/modules/MOD-FIXTURE.md",
            ):
                VERIFY.verify(root)

    def test_escaped_markdown_link_cannot_supply_module_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            link = "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)"
            prose = path.read_text(encoding="utf-8").replace(link, "MOD-FIXTURE")
            prose += "\n\\[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)\n"
            path.write_text(prose, encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing module contract link docs/modules/MOD-FIXTURE.md",
            ):
                VERIFY.verify(root)

    def test_module_link_symlink_traversal_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            alias = root / "alias"
            try:
                alias.symlink_to(root / "docs/modules", target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            path = root / "active/README.md"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "../docs/modules/MOD-FIXTURE.md",
                    "../alias/MOD-FIXTURE.md",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "traverses symlink",
            ):
                VERIFY.verify(root)


if __name__ == "__main__":
    unittest.main()
