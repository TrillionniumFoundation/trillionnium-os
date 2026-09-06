"""Hostile regressions for the machine-verifiable module documentation graph."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.docs import verify_module_documentation as verifier


ROOT = Path(__file__).resolve().parents[2]


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _copy_minimal_fixture(destination: Path) -> None:
    for relative in (
        "Cargo.toml",
        "docs/machine/module-catalog.v1.json",
        "docs/machine/doc-set.v1.json",
        "docs/machine/module-document-index.v1.json",
        "docs/machine/resource-budget-provenance.v1.json",
        "docs/MODULE_DOCUMENTATION_POLICY.md",
    ):
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    shutil.copytree(ROOT / "docs/modules", destination / "docs/modules")

    catalog = json.loads(
        (destination / "docs/machine/module-catalog.v1.json").read_text(encoding="utf-8")
    )
    for module in catalog["modules"]:
        for relative in module["paths"]:
            path = destination / relative
            if Path(relative).suffix:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            else:
                path.mkdir(parents=True, exist_ok=True)
    for member in catalog["default_source_closure"]:
        directory = destination / member
        directory.mkdir(parents=True, exist_ok=True)
        for filename in ("README.md", "Cargo.toml"):
            shutil.copy2(ROOT / member / filename, directory / filename)
    # A fixture must satisfy the same source-navigation checks as the real
    # checkout; otherwise negative tests can pass for the wrong missing file.
    for document in (destination / "docs/modules").glob("*.md"):
        text = document.read_text(encoding="utf-8")
        paths = re.findall(r"^- (?:Implementation|Verification) source: `([^`]+)`", text, re.M)
        for relative in paths:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)



class ModuleDocumentationContractTests(unittest.TestCase):
    def test_checked_in_repository_has_complete_module_documentation(self) -> None:
        verifier.verify_index_and_documents(ROOT)

    def _fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        _copy_minimal_fixture(root)
        return temporary, root

    def test_complete_minimal_fixture_passes_before_mutation(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        verifier.verify_index_and_documents(root)

    def test_every_visible_resource_and_slo_value_is_bound(self) -> None:
        catalog = verifier.load_json(ROOT / "docs/machine/module-catalog.v1.json")
        module = catalog["modules"][0]
        original = (ROOT / "docs/modules/MOD-PROTOCOL.md").read_text(encoding="utf-8")
        rows = re.findall(r"^\| ([^|]+) \| ([0-9][^|]*) \|$", original, re.M)
        self.assertEqual(len(rows), 16)
        for label, value in rows:
            with self.subTest(label=label):
                old = f"| {label} | {value} |"
                changed = original.replace(old, f"| {label} | 999999999 |", 1)
                with self.assertRaisesRegex(verifier.VerificationError, "section 9 contract drift"):
                    verifier.verify_contract_prose(changed, module)

    def test_identity_api_state_and_concurrency_values_are_bound(self) -> None:
        catalog = verifier.load_json(ROOT / "docs/machine/module-catalog.v1.json")
        module = next(item for item in catalog["modules"] if item["id"] == "MOD-BROKER")
        original = (ROOT / "docs/modules/MOD-BROKER.md").read_text(encoding="utf-8")
        prefixes = (
            "- Module version:", "- Plane:", "- Catalog input labels:",
            "- Catalog output labels:", "- Catalog error labels:",
            "- State authority:", "- Partition key:", "- Durability class:",
            "- Retention ceiling:", "- Terminal vocabulary:",
            "- Maximum declared concurrency:", "- Admission resource:",
            "- Lease source:", "- Lock scope:", "- Backpressure:",
            "- Timeout ceiling:", "- Lease expiry:", "- Duplicate/conflict rule:",
            "Direct dependencies:", "Open machine gaps:",
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                old = next(line for line in original.splitlines() if line.startswith(prefix))
                changed = original.replace(old, prefix + " `unbound_value`", 1)
                with self.assertRaisesRegex(verifier.VerificationError, "contract drift"):
                    verifier.verify_contract_prose(changed, module)

    def test_comment_or_code_example_cannot_replace_contract_field(self) -> None:
        module = verifier.load_json(ROOT / "docs/machine/module-catalog.v1.json")["modules"][0]
        original = (ROOT / "docs/modules/MOD-PROTOCOL.md").read_text(encoding="utf-8")
        line = "- Maximum declared concurrency: `16`"
        for replacement in (f"<!-- {line} -->", f"```text\n{line}\n```", line + "\n" + line):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(verifier.VerificationError, "contract drift"):
                    verifier.verify_contract_prose(original.replace(line, replacement, 1), module)

    def test_required_headings_cannot_be_hidden_in_examples(self) -> None:
        text = (ROOT / "docs/modules/MOD-PROTOCOL.md").read_text(encoding="utf-8")
        heading = "## 12. Failure matrix and degraded behavior"
        with self.assertRaisesRegex(verifier.VerificationError, "sections"):
            verifier.verify_headings(text.replace(heading, f"<!-- {heading} -->"),
                                     list(verifier.REQUIRED_SECTIONS), "MOD-PROTOCOL")

    def test_document_index_cannot_weaken_required_section_set(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "docs/machine/module-document-index.v1.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["required_sections"] = value["required_sections"][:15]
        _write_json(path, value)
        with self.assertRaisesRegex(verifier.VerificationError, "section set drifted"):
            verifier.verify_index_and_documents(root)

    def test_nonexistent_implementation_symbol_fails_closed(self) -> None:
        text = (ROOT / "docs/modules/MOD-PROTOCOL.md").read_text(encoding="utf-8")
        changed = text.replace("— `RunTurnFrame`", "— `InventedRunTurnFrame`")
        with self.assertRaisesRegex(verifier.VerificationError, "declaration missing"):
            verifier.verify_implementation_links(ROOT, changed, "MOD-PROTOCOL")

    def test_missing_or_external_verification_path_fails_closed(self) -> None:
        text = (ROOT / "docs/modules/MOD-PROTOCOL.md").read_text(encoding="utf-8")
        for path in ("missing/test.rs", "../external.rs"):
            changed = re.sub(r"^- Verification source: `[^`]+`$",
                             f"- Verification source: `{path}`", text, flags=re.M)
            with self.subTest(path=path), self.assertRaises(verifier.VerificationError):
                verifier.verify_implementation_links(ROOT, changed, "MOD-PROTOCOL")

    def test_readme_with_only_filler_no_test_or_module_link_fails(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        catalog = verifier.load_json(root / "docs/machine/module-catalog.v1.json")
        path = root / catalog["default_source_closure"][0] / "README.md"
        path.write_text("Filler without a usable test or contract link. " * 30, encoding="utf-8")
        with self.assertRaisesRegex(verifier.VerificationError, "local test command"):
            verifier.verify_index_and_documents(root)

    def test_program_revision_mismatch_fails_closed(self) -> None:
        for name in ("module-document-index.v1.json", "resource-budget-provenance.v1.json"):
            temporary, root = self._fixture()
            self.addCleanup(temporary.cleanup)
            path = root / "docs/machine" / name
            value = json.loads(path.read_text(encoding="utf-8"))
            value["program_revision"] = "different-program"
            _write_json(path, value)
            with self.subTest(name=name), self.assertRaisesRegex(verifier.VerificationError, "program revision drifted"):
                verifier.verify_index_and_documents(root)

    def test_missing_module_document_fails_closed(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        (root / "docs/modules/MOD-PROTOCOL.md").unlink()
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_index_and_documents(root)

    def test_duplicate_module_identity_fails_closed(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "docs/machine/module-document-index.v1.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["modules"][1]["id"] = value["modules"][0]["id"]
        _write_json(path, value)
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_index_and_documents(root)

    def test_document_path_traversal_fails_closed(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "docs/machine/module-document-index.v1.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["modules"][0]["doc_path"] = "../outside.md"
        _write_json(path, value)
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_index_and_documents(root)

    def test_missing_required_section_fails_closed(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "docs/modules/MOD-PROTOCOL.md"
        text = path.read_text(encoding="utf-8")
        text = text.replace("## 12. Failure matrix and degraded behavior", "## Failure behavior", 1)
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_index_and_documents(root)

    def test_unregistered_module_document_fails_closed(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        (root / "docs/modules/UNREGISTERED.md").write_text("# unregistered\n", encoding="utf-8")
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_index_and_documents(root)

    def test_editorial_marker_fails_closed(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "docs/modules/MOD-PROTOCOL.md"
        path.write_text(path.read_text(encoding="utf-8") + "\nTBD\n", encoding="utf-8")
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_index_and_documents(root)

    def test_unqualified_measured_budget_fails_closed(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "docs/machine/resource-budget-provenance.v1.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["measured"] = True
        value["modules"][0]["measured"] = True
        value["modules"][0]["sample_count"] = 1
        _write_json(path, value)
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_index_and_documents(root)

    def test_api_schema_drift_fails_closed(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "docs/machine/module-document-index.v1.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["modules"][0]["api_schema"] = "org.example.forged.api.v9"
        _write_json(path, value)
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_index_and_documents(root)

    def test_default_component_without_readme_fails_closed(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        catalog = json.loads(
            (root / "docs/machine/module-catalog.v1.json").read_text(encoding="utf-8")
        )
        (root / catalog["default_source_closure"][0] / "README.md").unlink()
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_index_and_documents(root)

    def test_docset_registration_drift_fails_closed(self) -> None:
        temporary, root = self._fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "docs/machine/doc-set.v1.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["required_files"].remove("docs/modules/MOD-PROTOCOL.md")
        _write_json(path, value)
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_index_and_documents(root)


if __name__ == "__main__":
    unittest.main()
