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

    def test_checked_in_repository_passes(self) -> None:
        report = VERIFY.verify(ROOT)
        self.assertEqual(report["profiles"], 2)
        self.assertGreater(report["markdown_files"], 20)
        self.assertGreater(report["local_links"], 20)

    def test_broken_repository_local_link_fails(self) -> None:
        path = self.root / "apps/trillionnium-owner-open-host/README.md"
        path.write_text(path.read_text() + "\n[missing](../../docs/DOES_NOT_EXIST.md)\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "target does not exist"):
            VERIFY.verify(self.root)

    def test_forbidden_historical_link_fails(self) -> None:
        path = self.root / "docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md"
        path.write_text("# stale\n")
        readme = self.root / "crates/trillionnium-agent-direct-tools/README.md"
        readme.write_text(
            readme.read_text()
            + "\n[canonical plan](../../docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):
            VERIFY.verify(self.root)

    def test_authority_phrase_cannot_point_to_unregistered_readme(self) -> None:
        path = self.root / "apps/trillionnium-owner-open-host/README.md"
        path.write_text(path.read_text() + "\nCanonical plan: [README](../../README.md)\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "unregistered target"):
            VERIFY.verify(self.root)

    def test_active_profile_cannot_select_sealed_component(self) -> None:
        path = self.root / VERIFY.PROFILE_PATH
        value = json.loads(path.read_text())
        active = value["profiles"][0]
        active["selected_cargo_components"].append("crates/trillionnium-agent-direct-tools")
        active["selected_implementation_paths"].append("crates/trillionnium-agent-direct-tools")
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(VERIFY.VerificationError, "default_source_closure"):
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
        path = self.root / VERIFY.PROFILE_PATH
        value = json.loads(path.read_text())
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
