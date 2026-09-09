from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools/contracts/generate_module_contracts.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("_module_contracts", GENERATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load module-contract generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ModuleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contracts = load_generator()

    def test_generated_output_is_deterministic_and_complete(self) -> None:
        first = self.contracts.generated(ROOT)
        second = self.contracts.generated(ROOT)
        self.assertEqual(first, second)
        catalog = json.loads(first[self.contracts.CONTRACT_CATALOG_PATH])
        self.assertEqual(catalog["module_count"], 16)
        self.assertEqual(len(catalog["modules"]), 16)
        self.assertFalse(catalog["automatic_redispatch"])
        self.assertFalse(catalog["public_release"])
        for module in catalog["modules"]:
            artifacts = module["artifacts"]
            for key in ("api", "state", "errors", "compatibility"):
                self.assertIn(artifacts[key], first)
            self.assertTrue(module["implementation_sources"])

    def test_strict_parser_rejects_duplicate_and_nonfinite_members(self) -> None:
        with self.assertRaises(self.contracts.ContractError):
            self.contracts.strict_load(b'{"a":1,"a":2}', "duplicate")
        with self.assertRaises(self.contracts.ContractError):
            self.contracts.strict_load(b'{"a":NaN}', "nonfinite")

    def test_validator_rejects_unknown_missing_and_identity_drift(self) -> None:
        outputs = self.contracts.generated(ROOT)
        catalog = json.loads(outputs[self.contracts.CONTRACT_CATALOG_PATH])
        module = catalog["modules"][0]
        schema = json.loads(outputs[module["artifacts"]["api"]])
        valid_path = f"schemas/modules/{module['slug']}/golden/valid/api.json"
        valid = json.loads(outputs[valid_path])
        self.contracts.validate_schema(valid, schema)
        for mutation in (
            {**valid, "unexpected": True},
            {key: value for key, value in valid.items() if key != "request_digest"},
            {**valid, "request_digest": "F" * 64},
            {**valid, "module_id": "MOD-NOT-THE-BOUND-MODULE"},
        ):
            with self.assertRaises(self.contracts.ContractError):
                self.contracts.validate_schema(mutation, schema)

    def test_lock_binds_every_generated_artifact_except_itself(self) -> None:
        outputs = self.contracts.generated(ROOT)
        lock = json.loads(outputs[self.contracts.LOCK_PATH])
        expected = set(outputs) - {self.contracts.LOCK_PATH}
        self.assertEqual(set(lock["artifacts"]), expected)
        for path in expected:
            self.assertEqual(lock["artifacts"][path]["sha256"], self.contracts.sha(outputs[path]))
            self.assertEqual(lock["artifacts"][path]["bytes"], len(outputs[path]))
        self.assertFalse(lock["public_release"])

    def test_every_logical_label_resolves_once(self) -> None:
        outputs = self.contracts.generated(ROOT)
        catalog = json.loads(outputs[self.contracts.CONTRACT_CATALOG_PATH])
        labels = []
        for module in catalog["modules"]:
            labels.extend(module["logical_labels"].values())
        self.assertEqual(len(labels), len(set(labels)))
        self.assertEqual(len(labels), 48)


if __name__ == "__main__":
    unittest.main()
