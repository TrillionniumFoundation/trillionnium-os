from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/docs/verify_repository_authority.py"
SPEC = importlib.util.spec_from_file_location("verify_repository_authority", MODULE_PATH)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class RepositoryAuthorityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        shutil.copytree(
            ROOT,
            self.root,
            ignore=shutil.ignore_patterns(".git", "target", "__pycache__", "*.pyc"),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def profile(self) -> tuple[Path, dict]:
        path = self.root / VERIFY.PROFILE_PATH
        return path, json.loads(path.read_text())

    def add_forbidden_document(self) -> str:
        relative = "docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md"
        (self.root / relative).write_text("# stale\n")
        return relative

    def test_checked_in_repository_passes(self) -> None:
        report = VERIFY.verify(ROOT)
        self.assertEqual(report["profiles"], 2)
        self.assertGreaterEqual(report["markdown_files"], 84)
        self.assertGreater(report["local_links"], 50)

    def test_root_markdown_is_in_closed_inventory(self) -> None:
        path = self.root / "README.md"
        path.write_text(path.read_text() + "\n[missing](docs/DOES_NOT_EXIST.md)\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "target does not exist"):
            VERIFY.verify(self.root)

    def test_governance_markdown_is_in_closed_inventory(self) -> None:
        path = self.root / "governance/README.md"
        path.write_text(path.read_text() + "\n[missing](DOES_NOT_EXIST.md)\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "target does not exist"):
            VERIFY.verify(self.root)

    def test_new_unregistered_markdown_cannot_declare_external_authority(self) -> None:
        path = self.root / "UNREGISTERED.md"
        path.write_text("Canonical source for this program: <https://example.invalid/plan>\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "external target"):
            VERIFY.verify(self.root)

    def test_broken_repository_local_link_fails(self) -> None:
        path = self.root / "apps/trillionnium-owner-open-host/README.md"
        path.write_text(path.read_text() + "\n[missing](../../docs/DOES_NOT_EXIST.md)\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "target does not exist"):
            VERIFY.verify(self.root)

    def test_forbidden_historical_inline_link_fails(self) -> None:
        self.add_forbidden_document()
        readme = self.root / "crates/trillionnium-agent-direct-tools/README.md"
        readme.write_text(
            readme.read_text()
            + "\nCanonical plan: [legacy](../../docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):
            VERIFY.verify(self.root)

    def test_reference_style_authority_link_fails(self) -> None:
        self.add_forbidden_document()
        path = self.root / "README.md"
        path.write_text(
            path.read_text()
            + "\nCanonical plan: [legacy plan][legacy].\n\n"
              "[legacy]: docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):
            VERIFY.verify(self.root)

    def test_collapsed_reference_authority_link_fails(self) -> None:
        self.add_forbidden_document()
        path = self.root / "README.md"
        path.write_text(
            path.read_text()
            + "\nCanonical plan: [legacy][].\n\n"
              "[legacy]: docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):
            VERIFY.verify(self.root)

    def test_shortcut_reference_authority_link_fails(self) -> None:
        self.add_forbidden_document()
        path = self.root / "README.md"
        path.write_text(
            path.read_text()
            + "\nCanonical plan: [legacy].\n\n"
              "[legacy]: docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):
            VERIFY.verify(self.root)

    def test_html_authority_link_fails(self) -> None:
        self.add_forbidden_document()
        path = self.root / "README.md"
        path.write_text(
            path.read_text()
            + '\nCanonical plan: <a href="docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md">legacy</a>\n'
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):
            VERIFY.verify(self.root)

    def test_wrapped_inline_authority_link_fails(self) -> None:
        self.add_forbidden_document()
        path = self.root / "README.md"
        path.write_text(
            path.read_text()
            + "\nCanonical plan: [legacy](\n"
              "docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):
            VERIFY.verify(self.root)

    def test_bare_authority_path_fails(self) -> None:
        self.add_forbidden_document()
        path = self.root / "README.md"
        path.write_text(
            path.read_text()
            + "\nCanonical plan is docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md.\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):
            VERIFY.verify(self.root)

    def test_indented_list_continuation_is_visible(self) -> None:
        self.add_forbidden_document()
        path = self.root / "README.md"
        path.write_text(
            path.read_text()
            + "\n- retained note\n"
              "    Canonical plan: [legacy](docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):
            VERIFY.verify(self.root)

    def test_external_canonical_link_fails(self) -> None:
        path = self.root / "README.md"
        path.write_text(
            path.read_text()
            + "\nCanonical plan: [external](https://example.invalid/plan).\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "external target"):
            VERIFY.verify(self.root)

    def test_duplicate_reference_definition_fails(self) -> None:
        path = self.root / "README.md"
        path.write_text(
            path.read_text()
            + "\n[one]: docs/START_HERE.md\n[ONE]: docs/GLOBAL_ARCHITECTURE.md\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "duplicate"):
            VERIFY.verify(self.root)

    def test_authority_phrase_cannot_point_to_unregistered_readme(self) -> None:
        path = self.root / "apps/trillionnium-owner-open-host/README.md"
        path.write_text(path.read_text() + "\nCanonical plan: [README](../../README.md)\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "unregistered target"):
            VERIFY.verify(self.root)

    def test_active_profile_cannot_select_sealed_component(self) -> None:
        path, value = self.profile()
        active = value["profiles"][0]
        active["selected_implementation_paths"].append(
            "crates/trillionnium-agent-direct-tools"
        )
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(VERIFY.VerificationError, "overlaps sealed"):
            VERIFY.verify(self.root)

    def test_active_profile_cannot_use_broad_ancestor(self) -> None:
        path, value = self.profile()
        active = value["profiles"][0]
        active["selected_implementation_paths"] = [
            "tools" if item == "tools/owner-open" else item
            for item in active["selected_implementation_paths"]
        ]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(VERIFY.VerificationError, "not an exact component or module root"):
            VERIFY.verify(self.root)

    def test_active_profile_cannot_use_child_only_underselection(self) -> None:
        child = self.root / "tools/owner-open/narrow"
        child.mkdir()
        path, value = self.profile()
        active = value["profiles"][0]
        active["selected_implementation_paths"] = [
            "tools/owner-open/narrow" if item == "tools/owner-open" else item
            for item in active["selected_implementation_paths"]
        ]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(VERIFY.VerificationError, "not an exact component or module root"):
            VERIFY.verify(self.root)

    def test_capability_owner_must_own_every_implementation_path(self) -> None:
        path, value = self.profile()
        capability = value["profiles"][0]["offered_capabilities"][0]
        capability["owner_module"] = "MOD-EVENT-STORE"
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(VERIFY.VerificationError, "ownership differs"):
            VERIFY.verify(self.root)

    def test_cross_module_implementation_substitution_fails(self) -> None:
        path, value = self.profile()
        capability = value["profiles"][0]["offered_capabilities"][0]
        capability["implementation_paths"] = [
            "crates/trillionnium-owner-open-event-store"
        ]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(VERIFY.VerificationError, "ownership differs"):
            VERIFY.verify(self.root)

    def test_semantic_capability_requires_profile_owner(self) -> None:
        path = self.root / "docs/PRODUCT_SEMANTICS.md"
        source = path.read_text()
        source = source.replace(
            VERIFY.CAPABILITY_END,
            "- `system-api.open-uri`\n" + VERIFY.CAPABILITY_END,
        )
        path.write_text(source)
        with self.assertRaisesRegex(VERIFY.VerificationError, "current capabilities differ"):
            VERIFY.verify(self.root)

    def test_sealed_profile_cannot_offer_behavior(self) -> None:
        path, value = self.profile()
        sealed = value["profiles"][1]
        sealed["selected_modules"] = ["MOD-PROTOCOL"]
        sealed["selected_implementation_paths"] = ["crates/trillionnium-owner-open-types"]
        sealed["offered_capabilities"] = [
            {
                "id": "system-api.open-uri",
                "owner_module": "MOD-PROTOCOL",
                "implementation_paths": ["crates/trillionnium-owner-open-types"],
            }
        ]
        sealed["blocked_capabilities"] = [
            item for item in sealed["blocked_capabilities"]
            if item["id"] != "system-api.open-uri"
        ]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(VERIFY.VerificationError, "cannot select or offer"):
            VERIFY.verify(self.root)

    def test_symlink_target_is_rejected(self) -> None:
        outside = Path(self.temp.name) / "outside.md"
        outside.write_text("outside")
        link = self.root / "docs/unsafe-link.md"
        link.symlink_to(outside)
        readme = self.root / "apps/trillionnium-owner-open-host/README.md"
        readme.write_text(readme.read_text() + "\n[unsafe](../../docs/unsafe-link.md)\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "symlink"):
            VERIFY.verify(self.root)


if __name__ == "__main__":
    unittest.main()
