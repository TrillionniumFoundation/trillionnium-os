#!/usr/bin/env python3
"""Static schema and side-effect boundary checks for W3.1."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "packaging/owner-open-adb/verify_arm64_adb.py"
SCHEMA = ROOT / "packaging/owner-open-adb/owner-open-adb-arm64-artifact.schema.json"


class OwnerOpenAdbArtifactSchemaTest(unittest.TestCase):
    def test_schema_and_verifier_use_the_same_closed_claim_ceiling(self) -> None:
        document = json.loads(SCHEMA.read_text(encoding="utf-8"))
        source = VERIFIER.read_text(encoding="utf-8")
        self.assertEqual(document["additionalProperties"], False)
        self.assertEqual(
            document["properties"]["schema"]["const"],
            "org.trillionnium.owner-open.adb-arm64-artifact.v1",
        )
        claims = document["properties"]["claims"]["properties"]
        self.assertIs(claims["ordinary_adb_client"]["const"], True)
        for field in (
            "typed_trillionnium_adapter",
            "image_inclusion",
            "integrated_codex_turn",
            "physical_device_effect",
            "release_qualified",
        ):
            self.assertIs(claims[field]["const"], False, field)
        self.assertIn("QUALIFIED_SOURCE_ARTIFACT_ONLY", source)

    def test_verifier_is_read_only_and_has_no_device_or_key_action(self) -> None:
        source = VERIFIER.read_text(encoding="utf-8")
        for forbidden in (
            "subprocess",
            "os.system",
            "Popen",
            "adb start-server",
            "adb devices",
            "fastboot",
            "private_key",
            "sign_target_files",
            "urllib",
            "requests.",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("path.open(\"rb\")", source)
        self.assertNotIn("path.write_", source)

    def test_runtime_constants_match_schema_bounds(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_owner_open_adb_schema_contract", VERIFIER
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        document = json.loads(SCHEMA.read_text(encoding="utf-8"))
        maximum = document["properties"]["artifact"]["properties"]["bytes"][
            "maximum"
        ]
        self.assertEqual(maximum, module.MAX_ARTIFACT_BYTES)
        self.assertEqual(module.EM_AARCH64, 183)
        self.assertEqual(module.SCHEMA, document["properties"]["schema"]["const"])


if __name__ == "__main__":
    unittest.main()
