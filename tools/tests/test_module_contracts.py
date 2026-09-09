from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools/contracts/generate_module_contracts.py"
SCHEMARS = ROOT / "schemas/modules/_shared/envelopes-v1.schemars.json"


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
        cls.schemars = SCHEMARS.read_bytes()

    def outputs(self):
        return self.contracts.generated(ROOT, self.schemars)

    def test_generated_output_is_deterministic_complete_and_source_only(self) -> None:
        first = self.outputs()
        second = self.outputs()
        self.assertEqual(first, second)
        catalog = json.loads(first[self.contracts.CONTRACT_CATALOG_PATH])
        self.assertEqual(catalog["module_count"], 16)
        self.assertEqual(len(catalog["modules"]), 16)
        self.assertEqual(
            catalog["producer_consumer_pair_count"],
            len(catalog["producer_consumer_pairs"]),
        )
        self.assertFalse(catalog["automatic_redispatch"])
        self.assertFalse(catalog["promotion_authorized"])
        self.assertFalse(catalog["public_release"])
        for module in catalog["modules"]:
            artifacts = module["artifacts"]
            for key in ("api", "state", "errors", "compatibility"):
                self.assertIn(artifacts[key], first)
            self.assertTrue(module["implementation_sources"])
            self.assertTrue(module["test_sources"])

    def test_strict_parser_rejects_duplicate_nonfinite_depth_and_oversize(self) -> None:
        with self.assertRaises(self.contracts.ContractError):
            self.contracts.strict_load(b'{"a":1,"a":2}', "duplicate")
        with self.assertRaises(self.contracts.ContractError):
            self.contracts.strict_load(b'{"a":NaN}', "nonfinite")
        nested = {}
        for _ in range(40):
            nested = {"n": nested}
        with self.assertRaises(self.contracts.ContractError):
            self.contracts.strict_load(json.dumps(nested).encode(), "deep")
        with self.assertRaises(self.contracts.ContractError):
            self.contracts.strict_load(b" " * (4 * 1024 * 1024 + 1), "large")

    def test_schemars_projection_is_semantically_bound(self) -> None:
        bundle, normalized = self.contracts.validate_schemars_bundle(self.schemars)
        self.assertEqual(normalized, self.contracts.canonical_json(bundle))
        mutated = copy.deepcopy(bundle)
        mutated["state"]["definitions"]["ModuleLifecycleStateV1"]["enum"].remove("FENCED")
        with self.assertRaises(self.contracts.ContractError):
            self.contracts.validate_schemars_bundle(self.contracts.canonical_json(mutated))
        mutated = copy.deepcopy(bundle)
        mutated["api"]["properties"]["host_epoch"]["type"] = "boolean"
        with self.assertRaises(self.contracts.ContractError):
            self.contracts.validate_schemars_bundle(self.contracts.canonical_json(mutated))

    def test_all_shared_vectors_are_exhaustive_and_fail_closed(self) -> None:
        outputs = self.outputs()
        catalog = json.loads(outputs[self.contracts.CONTRACT_CATALOG_PATH])
        for module in catalog["modules"]:
            for kind in ("api", "state", "errors"):
                schema = json.loads(outputs[module["artifacts"][kind]])
                path = f"schemas/modules/{module['slug']}/golden/valid/{kind}.json"
                value = self.contracts.strict_load(outputs[path], path)
                self.contracts.validate_schema(value, schema, path)
                self.contracts.validate_semantics(
                    value, kind, module["module_id"], module["logical_labels"][kind]
                )
            prefix = f"schemas/modules/{module['slug']}/golden/invalid/"
            invalid = [path for path in outputs if path.startswith(prefix)]
            self.assertEqual(len(invalid), 14)
            for path in invalid:
                kind = Path(path).name.split("-", 1)[0]
                schema = json.loads(outputs[module["artifacts"][kind]])
                with self.assertRaises(self.contracts.ContractError, msg=path):
                    value = self.contracts.strict_load(outputs[path], path)
                    self.contracts.validate_schema(value, schema, path)
                    self.contracts.validate_semantics(
                        value, kind, module["module_id"], module["logical_labels"][kind]
                    )

    def test_lock_binds_every_generated_artifact_except_itself(self) -> None:
        outputs = self.outputs()
        lock = json.loads(outputs[self.contracts.LOCK_PATH])
        expected = set(outputs) - {self.contracts.LOCK_PATH}
        self.assertEqual(set(lock["artifacts"]), expected)
        for path in expected:
            self.assertEqual(lock["artifacts"][path]["sha256"], self.contracts.sha(outputs[path]))
            self.assertEqual(lock["artifacts"][path]["bytes"], len(outputs[path]))
        self.assertFalse(lock["automatic_redispatch"])
        self.assertFalse(lock["public_release"])

    def test_every_logical_label_resolves_once_and_versions_are_independent(self) -> None:
        outputs = self.outputs()
        catalog = json.loads(outputs[self.contracts.CONTRACT_CATALOG_PATH])
        labels = []
        for module in catalog["modules"]:
            labels.extend(module["logical_labels"].values())
            compatibility = json.loads(outputs[module["artifacts"]["compatibility"]])
            self.assertEqual(compatibility["state_schema_version"], "1")
            self.assertEqual(compatibility["api_semver"], "1.0.0")
            self.assertFalse(compatibility["effect_identity_defaults_allowed"])
            self.assertFalse(compatibility["field_aliases_allowed"])
            self.assertFalse(compatibility["automatic_redispatch_after_uncertainty"])
        self.assertEqual(len(labels), len(set(labels)))
        self.assertEqual(len(labels), 48)

    def test_dependency_matrix_is_exact_and_version_intersections_are_nonempty(self) -> None:
        outputs = self.outputs()
        catalog = json.loads(outputs[self.contracts.CONTRACT_CATALOG_PATH])
        source = json.loads((ROOT / self.contracts.CATALOG_PATH).read_text())
        expected = sorted(
            (dependency, module["id"])
            for module in source["modules"]
            for dependency in module["dependencies"]
        )
        observed = sorted(
            (item["producer"], item["consumer"])
            for item in catalog["producer_consumer_pairs"]
        )
        self.assertEqual(observed, expected)
        self.assertTrue(all(item["compatible_api_versions"] for item in catalog["producer_consumer_pairs"]))

    def test_static_sources_forbid_defaults_aliases_and_auto_redispatch(self) -> None:
        rust = self.contracts.rust_source().decode()
        self.assertNotIn("serde(default", rust)
        self.assertNotIn("serde(alias", rust)
        self.assertNotIn("AUTOMATIC_REDISPATCH", rust)
        android = self.contracts.android_verifier_source().decode()
        self.assertIn("RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH", android)
        self.assertNotIn("shell=True", android)


if __name__ == "__main__":
    unittest.main()
