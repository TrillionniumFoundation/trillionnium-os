#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = (
    ROOT
    / "crates/trillionnium-agent-direct-tools/tools/generate-canonical-operation-binding.py"
)
GENERATED = (
    ROOT / "crates/trillionnium-agent-direct-tools/src/canonical_operation_contract.rs"
)
DESCRIPTOR_CONTRACT = (
    ROOT / "crates/trillionnium-os-types/contracts/agent-descriptor-registry-v1.json"
)


def load_generator():
    spec = importlib.util.spec_from_file_location("canonical_operation_generator", GENERATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("canonical operation generator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CanonicalOperationStablePrincipalTest(unittest.TestCase):
    def test_checked_in_generated_source_is_fresh(self) -> None:
        subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            check=True,
        )

    def test_executable_identity_rotation_cannot_change_stable_binding(self) -> None:
        module = load_generator()
        rendered = module.render()
        descriptor_contract = json.loads(DESCRIPTOR_CONTRACT.read_bytes())
        measured_identity = descriptor_contract["descriptors"][0]["identity_key_sha256"]
        rotated_identity = "a" * 64
        self.assertNotEqual(measured_identity, rotated_identity)
        self.assertNotIn(measured_identity, rendered)
        self.assertNotIn(rotated_identity, rendered)
        self.assertNotIn("identity_key_sha256", rendered)
        self.assertNotIn("agent_descriptor_registry", rendered)
        self.assertIn(
            "agent_principal_registry::CODEX_STABLE_PRINCIPAL.replay_namespace",
            rendered,
        )
        self.assertEqual(rendered, GENERATED.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
