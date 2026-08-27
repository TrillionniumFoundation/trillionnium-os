#!/usr/bin/env python3
"""Direct tests for the independent stable Agent principal generator."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT
    / "crates/trillionnium-os-types/tools/generate-agent-principal-registry.py"
)
STABLE_CONTRACT = (
    ROOT
    / "crates/trillionnium-os-types/contracts/agent-principal-registry-v2.json"
)
DESCRIPTOR_CONTRACT = (
    ROOT
    / "crates/trillionnium-os-types/contracts/agent-descriptor-registry-v1.json"
)
OPERATION_CONTRACT = (
    ROOT
    / "crates/trillionnium-agent-direct-tools/contracts/canonical-operation-binding-v1.json"
)


def load_module():
    spec = importlib.util.spec_from_file_location("agent_principal_generator", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR = load_module()


def stable_fields_from_descriptor(descriptor: dict) -> dict:
    return {
        field: descriptor[field]
        for field in (
            "provider_id",
            "agent_id",
            "replay_namespace",
            "uid",
            "gid",
            "agent_selinux_domain",
            "runtime_adapter",
        )
    }


class AgentPrincipalRegistryGeneratorTests(unittest.TestCase):
    def load_json(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def write_contract(self, root: Path, value: dict) -> Path:
        path = root / "agent-principal-registry-v2.json"
        path.write_text(
            json.dumps(value, ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def write_descriptor_contract(self, root: Path, value: dict) -> Path:
        path = root / "agent-descriptor-registry-v1.json"
        path.write_text(
            json.dumps(value, ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def test_identity_rotation_is_not_a_stable_generator_input(self) -> None:
        stable_contract = self.load_json(STABLE_CONTRACT)
        descriptor_contract = self.load_json(DESCRIPTOR_CONTRACT)
        stable_principal = stable_contract["principals"][0]
        descriptor = descriptor_contract["descriptors"][0]
        descriptor_fields_before = stable_fields_from_descriptor(descriptor)
        self.assertEqual(
            descriptor_fields_before,
            {key: stable_principal[key] for key in descriptor_fields_before},
        )

        _, _, canonical_before, digest_before = GENERATOR.load_and_validate(STABLE_CONTRACT)
        descriptor_contract["descriptors"][0]["identity_key_sha256"] = "a" * 64
        rotated_descriptor = descriptor_contract["descriptors"][0]
        self.assertEqual(
            descriptor_fields_before,
            stable_fields_from_descriptor(rotated_descriptor),
        )
        with tempfile.TemporaryDirectory(
            prefix="trillionnium-stable-principal-rotation."
        ) as temporary:
            temporary_root = Path(temporary)
            rotated_path = self.write_descriptor_contract(
                temporary_root,
                descriptor_contract,
            )
            generated_before = GENERATOR.render(
                STABLE_CONTRACT,
                DESCRIPTOR_CONTRACT,
                OPERATION_CONTRACT,
                temporary_root,
                temporary_root / "before.rs",
                temporary_root / "descriptor-before.rs",
            )
            generated_after = GENERATOR.render(
                STABLE_CONTRACT,
                rotated_path,
                OPERATION_CONTRACT,
                temporary_root,
                temporary_root / "after.rs",
                temporary_root / "descriptor-after.rs",
            )
        _, _, canonical_after, digest_after = GENERATOR.load_and_validate(STABLE_CONTRACT)
        self.assertEqual(canonical_after, canonical_before)
        self.assertEqual(digest_after, digest_before)
        self.assertEqual(
            GENERATOR.semantic_rust(generated_after),
            GENERATOR.semantic_rust(generated_before),
        )

    def test_stable_field_change_rotates_canonical_digest(self) -> None:
        original = self.load_json(STABLE_CONTRACT)
        _, _, canonical_before, digest_before = GENERATOR.load_and_validate(
            STABLE_CONTRACT
        )
        changed = copy.deepcopy(original)
        changed["principals"][0]["runtime_adapter"] = "supervised-codex-cli-v2"
        with tempfile.TemporaryDirectory(
            prefix="trillionnium-stable-principal-test."
        ) as temporary:
            changed_path = self.write_contract(Path(temporary), changed)
            _, _, canonical_after, digest_after = GENERATOR.load_and_validate(
                changed_path
            )
        self.assertNotEqual(canonical_after, canonical_before)
        self.assertNotEqual(digest_after, digest_before)

    def test_identity_digest_is_rejected_from_v2_closed_schema(self) -> None:
        changed = self.load_json(STABLE_CONTRACT)
        changed["principals"][0]["identity_key_sha256"] = "a" * 64
        with tempfile.TemporaryDirectory(
            prefix="trillionnium-stable-principal-test."
        ) as temporary:
            changed_path = self.write_contract(Path(temporary), changed)
            with self.assertRaisesRegex(SystemExit, "closed field schema"):
                GENERATOR.load_and_validate(changed_path)

    def test_v1_stable_field_drift_fails_compatibility_gate(self) -> None:
        stable_contract = self.load_json(STABLE_CONTRACT)
        descriptor_contract = self.load_json(DESCRIPTOR_CONTRACT)
        descriptor_contract["descriptors"][0]["runtime_adapter"] = (
            "supervised-codex-cli-drift"
        )
        with tempfile.TemporaryDirectory(
            prefix="trillionnium-stable-principal-drift."
        ) as temporary:
            drifted_path = self.write_descriptor_contract(
                Path(temporary),
                descriptor_contract,
            )
            with self.assertRaisesRegex(SystemExit, "stable fields drifted"):
                GENERATOR.validate_descriptor_contract_compatibility(
                    drifted_path,
                    stable_contract,
                )

    def test_v1_endpoint_drift_fails_compatibility_gate(self) -> None:
        stable_contract = self.load_json(STABLE_CONTRACT)
        descriptor_contract = self.load_json(DESCRIPTOR_CONTRACT)
        descriptor_contract["endpoints"][0]["tool_selinux_domain"] = (
            "u:r:trillionnium_agent_system_api_tool_drift:s0"
        )
        with tempfile.TemporaryDirectory(
            prefix="trillionnium-stable-endpoint-drift."
        ) as temporary:
            drifted_path = self.write_descriptor_contract(
                Path(temporary),
                descriptor_contract,
            )
            with self.assertRaisesRegex(SystemExit, "endpoints drifted"):
                GENERATOR.validate_descriptor_contract_compatibility(
                    drifted_path,
                    stable_contract,
                )

    def test_generated_module_is_semantically_current(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="trillionnium-stable-principal-source."
        ) as temporary:
            empty_source_root = Path(temporary)
            expected = GENERATOR.render(
                STABLE_CONTRACT,
                DESCRIPTOR_CONTRACT,
                OPERATION_CONTRACT,
                empty_source_root,
                empty_source_root / "agent_principal_registry.rs",
                empty_source_root / "agent_descriptor_registry.rs",
            )
        generated = (
            ROOT
            / "crates/trillionnium-os-types/src/agent_principal_registry.rs"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            GENERATOR.semantic_rust(generated),
            GENERATOR.semantic_rust(expected),
        )


if __name__ == "__main__":
    unittest.main()
