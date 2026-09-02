"""Hostile regressions for the machine-verifiable module documentation graph."""

from __future__ import annotations

import json
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
        readme = directory / "README.md"
        readme.write_text(
            "# Fixture component\n\nThis module fixture documents the local runtime boundary. "
            "Automatic redispatch is forbidden. " * 5,
            encoding="utf-8",
        )


class ModuleDocumentationContractTests(unittest.TestCase):
    def test_checked_in_repository_has_complete_module_documentation(self) -> None:
        verifier.verify_index_and_documents(ROOT)

    def _fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        _copy_minimal_fixture(root)
        return temporary, root

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
