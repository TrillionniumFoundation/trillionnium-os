from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools/contracts/generate_module_contracts.py"
CHECKER = ROOT / "tools/contracts/check_module_contract_compatibility.py"
SCHEMARS = ROOT / "schemas/modules/_shared/envelopes-v1.schemars.json"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ModuleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contracts = load_module(GENERATOR, "_module_contracts")
        cls.checker = load_module(CHECKER, "_module_contract_compatibility")
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
        for raw in (
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'{"a":1e400}',
            b'{"a":{"nested":[-1e400]}}',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(self.contracts.ContractError):
                    self.contracts.strict_load(raw, "nonfinite")
        nested = {}
        for _ in range(40):
            nested = {"n": nested}
        with self.assertRaises(self.contracts.ContractError):
            self.contracts.strict_load(json.dumps(nested).encode(), "deep")
        with self.assertRaises(self.contracts.ContractError):
            self.contracts.strict_load(b" " * (4 * 1024 * 1024 + 1), "large")

    def test_canonical_text_domain_is_utf8_byte_bounded_and_control_free(self) -> None:
        self.assertTrue(self.contracts.valid_text("a" * 256, 256))
        self.assertFalse(self.contracts.valid_text("a" * 257, 256))
        self.assertTrue(self.contracts.valid_text("é" * 128, 256))
        self.assertFalse(self.contracts.valid_text("é" * 129, 256))
        self.assertFalse(self.contracts.valid_text("prefix\u0085suffix", 256))
        self.assertFalse(self.contracts.valid_text("\ud800", 256))

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
            self.assertEqual(len(invalid), 24)
            for path in invalid:
                kind = Path(path).name.split("-", 1)[0]
                schema = json.loads(outputs[module["artifacts"][kind]])
                with self.assertRaises(self.contracts.ContractError, msg=path):
                    value = self.contracts.strict_load(outputs[path], path)
                    self.contracts.validate_schema(value, schema, path)
                    self.contracts.validate_semantics(
                        value, kind, module["module_id"], module["logical_labels"][kind]
                    )

    def test_valid_vectors_hit_exact_ascii_byte_boundaries(self) -> None:
        outputs = self.outputs()
        catalog = json.loads(outputs[self.contracts.CONTRACT_CATALOG_PATH])
        for module in catalog["modules"]:
            base = f"schemas/modules/{module['slug']}/golden/valid"
            api = json.loads(outputs[f"{base}/api.json"])
            state = json.loads(outputs[f"{base}/state.json"])
            errors = json.loads(outputs[f"{base}/errors.json"])
            self.assertEqual(len(api["operation_id"].encode()), 256)
            self.assertEqual(len(api["ordering_key"].encode()), 512)
            self.assertEqual(len(api["fencing_token"].encode()), 512)
            self.assertEqual(len(state["operation_id"].encode()), 256)
            self.assertEqual(len(state["fencing_token"].encode()), 512)
            self.assertEqual(len(errors["operation_id"].encode()), 256)
            self.assertEqual(len(errors["code"].encode()), 128)
            self.assertEqual(len(errors["original_cause"].encode()), 4096)

    def test_compatibility_fingerprint_preserves_annotation_named_properties(self) -> None:
        for property_name in sorted(self.checker.NON_SEMANTIC):
            base = {
                "type": "object",
                "properties": {
                    property_name: {
                        "type": "string",
                        "title": "annotation one",
                    }
                },
                "required": [property_name],
            }
            annotation_only = copy.deepcopy(base)
            annotation_only["properties"][property_name]["description"] = "annotation two"
            self.assertEqual(
                self.checker.fingerprint(base),
                self.checker.fingerprint(annotation_only),
                property_name,
            )
            breaking = copy.deepcopy(base)
            breaking["properties"][property_name]["type"] = "integer"
            self.assertNotEqual(
                self.checker.fingerprint(base),
                self.checker.fingerprint(breaking),
                property_name,
            )

    def test_compatibility_base_resolution_distinguishes_absence_from_git_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "fixture"], cwd=root, check=True)
            (root / "present.json").write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "add", "present.json"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            (root / "later.json").write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "add", "later.json"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "head"], cwd=root, check=True)

            self.assertEqual(self.checker.resolve_commit(base, root=root), base)
            self.assertEqual(self.checker.show(base, "present.json", root=root), b"{}\n")
            self.assertIsNone(
                self.checker.show(base, "later.json", allow_absent=True, root=root)
            )
            with self.assertRaises(ValueError):
                self.checker.show(base, "later.json", root=root)
            with self.assertRaises(ValueError):
                self.checker.resolve_commit("does-not-exist-review-fixture", root=root)

        failed = subprocess.CompletedProcess(
            args=["git"],
            returncode=128,
            stdout=b"",
            stderr=b"permission denied fixture",
        )
        with mock.patch.object(self.checker.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(ValueError, "permission denied fixture"):
                self.checker.git(["ls-tree"], "permission simulation")


    def test_change_review_state_machine_is_closed_and_one_shot(self) -> None:
        migration = {
            "from_versions": [],
            "to_version": "v1",
            "strategy": "none",
            "dual_read": False,
            "dual_write": False,
        }
        rollback = {
            "supported": False,
            "procedure": "fail_closed_fixture",
            "fail_closed": True,
        }

        def no_change_review():
            return {
                "class": "NO_CHANGE",
                "contracts": [],
                "families": [],
                "review_id": None,
                "migration_plan": None,
                "rollback_plan": None,
                "migration_review_sha256": self.checker.sha256_bytes(
                    self.checker.canonical(migration)
                ),
                "rollback_review_sha256": self.checker.sha256_bytes(
                    self.checker.canonical(rollback)
                ),
                "base_catalog_sha256": None,
                "base_contract_sha256": {},
                "target_contract_sha256": {},
            }

        def compatibility(review):
            return {
                "introduction_review_class": "INITIAL_V1",
                "change_review": review,
                "migration_review": migration,
                "rollback_review": rollback,
            }

        def write_json(path: Path, value) -> bytes:
            raw = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8") + b"\n"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            return raw

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "fixture"], cwd=root, check=True
            )

            paths = {
                "api": "schemas/api.json",
                "state": "schemas/state.json",
                "errors": "schemas/errors.json",
                "compatibility": "schemas/compatibility.json",
            }
            catalog = {
                "module_count": 1,
                "modules": [
                    {
                        "module_id": "MOD-FIXTURE",
                        "artifacts": paths,
                    }
                ],
            }
            schemas = {
                "api": {
                    "type": "object",
                    "properties": {
                        "operation_id": {"type": "string", "maxLength": 256},
                        "ordering_key": {"type": "string", "maxLength": 512},
                        "payload": {"type": "object"},
                    },
                    "required": ["operation_id", "ordering_key", "payload"],
                },
                "state": {
                    "type": "object",
                    "properties": {
                        "state": {"type": "string", "enum": ["RECEIVED", "CLOSED"]},
                        "durable_sequence": {"type": "integer"},
                    },
                    "required": ["state", "durable_sequence"],
                },
                "errors": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "maxLength": 128},
                        "class": {"type": "string", "enum": ["TERMINAL_FAILURE"]},
                    },
                    "required": ["code", "class"],
                },
            }
            write_json(root / self.checker.CATALOG, catalog)
            for kind in ("api", "state", "errors"):
                write_json(root / paths[kind], schemas[kind])
            write_json(root / paths["compatibility"], compatibility(no_change_review()))
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            base = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()
            base_catalog_raw = subprocess.check_output(
                ["git", "show", f"{base}:{self.checker.CATALOG}"], cwd=root
            )
            base_schema_raw = {
                kind: subprocess.check_output(
                    ["git", "show", f"{base}:{paths[kind]}"], cwd=root
                )
                for kind in ("api", "state", "errors")
            }

            self.assertEqual(
                self.checker.evaluate(root, base)["semantic_changes"], []
            )

            bad = no_change_review()
            bad["class"] = "INITIAL_V1"
            write_json(root / paths["compatibility"], compatibility(bad))
            with self.assertRaisesRegex(ValueError, "class is unknown"):
                self.checker.evaluate(root, base)
            bad["class"] = "ARBITRARY_APPROVAL"
            write_json(root / paths["compatibility"], compatibility(bad))
            with self.assertRaisesRegex(ValueError, "class is unknown"):
                self.checker.evaluate(root, base)

            cases = {
                "required": (
                    "api",
                    lambda value: value["required"].append("new_required"),
                ),
                "type": (
                    "api",
                    lambda value: value["properties"]["payload"].update(
                        {"type": "array"}
                    ),
                ),
                "enum": (
                    "api",
                    lambda value: value["properties"]["operation_id"].update(
                        {"enum": ["one", "two"]}
                    ),
                ),
                "default": (
                    "api",
                    lambda value: value["properties"]["payload"].update(
                        {"default": {}}
                    ),
                ),
                "identity": (
                    "api",
                    lambda value: value["properties"]["operation_id"].update(
                        {"maxLength": 255}
                    ),
                ),
                "ordering": (
                    "api",
                    lambda value: value["properties"]["ordering_key"].update(
                        {"maxLength": 511}
                    ),
                ),
                "state": (
                    "state",
                    lambda value: value["properties"]["state"].update(
                        {"enum": ["CLOSED"]}
                    ),
                ),
                "error": (
                    "errors",
                    lambda value: value["properties"]["code"].update(
                        {"maxLength": 127}
                    ),
                ),
            }
            for expected_family, (kind, mutate) in cases.items():
                with self.subTest(family=expected_family):
                    for restore_kind in ("api", "state", "errors"):
                        write_json(root / paths[restore_kind], schemas[restore_kind])
                    target = copy.deepcopy(schemas[kind])
                    mutate(target)
                    target_raw = write_json(root / paths[kind], target)
                    write_json(
                        root / paths["compatibility"],
                        compatibility(no_change_review()),
                    )
                    with self.assertRaisesRegex(
                        ValueError, "lacks BREAKING_MIGRATION review"
                    ):
                        self.checker.evaluate(root, base)

                    families = self.checker.semantic_change_families(
                        schemas[kind], target, kind
                    )
                    self.assertIn(expected_family, families)
                    reviewed = no_change_review()
                    reviewed.update(
                        {
                            "class": "BREAKING_MIGRATION",
                            "contracts": [kind],
                            "families": families,
                            "review_id": f"review-{expected_family}-fixture",
                            "migration_plan": "migrate exact bound fixture bytes",
                            "rollback_plan": "fail closed and restore exact base bytes",
                            "base_catalog_sha256": self.checker.sha256_bytes(
                                base_catalog_raw
                            ),
                            "base_contract_sha256": {
                                kind: self.checker.sha256_bytes(base_schema_raw[kind])
                            },
                            "target_contract_sha256": {
                                kind: self.checker.sha256_bytes(target_raw)
                            },
                        }
                    )
                    write_json(
                        root / paths["compatibility"], compatibility(reviewed)
                    )
                    result = self.checker.evaluate(root, base)
                    self.assertEqual(
                        result["semantic_changes"], [f"MOD-FIXTURE:{kind}"]
                    )

            for kind in ("api", "state", "errors"):
                write_json(root / paths[kind], schemas[kind])
            stale = no_change_review()
            stale.update(
                {
                    "class": "BREAKING_MIGRATION",
                    "contracts": ["api"],
                    "families": ["type"],
                    "review_id": "stale-review-fixture",
                    "migration_plan": "stale migration",
                    "rollback_plan": "stale rollback",
                    "base_catalog_sha256": self.checker.sha256_bytes(
                        base_catalog_raw
                    ),
                    "base_contract_sha256": {
                        "api": self.checker.sha256_bytes(base_schema_raw["api"])
                    },
                    "target_contract_sha256": {
                        "api": self.checker.sha256_bytes(base_schema_raw["api"])
                    },
                }
            )
            write_json(root / paths["compatibility"], compatibility(stale))
            with self.assertRaisesRegex(ValueError, "stale breaking review"):
                self.checker.evaluate(root, base)

    def test_initial_introduction_uses_provenance_not_reusable_change_class(self) -> None:
        outputs = self.outputs()
        catalog = json.loads(outputs[self.contracts.CONTRACT_CATALOG_PATH])
        for module in catalog["modules"]:
            compatibility = json.loads(outputs[module["artifacts"]["compatibility"]])
            self.assertEqual(
                compatibility["introduction_review_class"], "INITIAL_V1"
            )
            self.assertEqual(compatibility["change_review"]["class"], "NO_CHANGE")
            self.assertEqual(compatibility["change_review"]["contracts"], [])
            self.assertEqual(compatibility["change_review"]["families"], [])

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
        self.assertTrue(
            all(
                item["compatible_api_versions"]
                for item in catalog["producer_consumer_pairs"]
            )
        )

    def test_static_sources_forbid_defaults_aliases_and_auto_redispatch(self) -> None:
        rust = self.contracts.rust_source().decode()
        self.assertNotIn("serde(default", rust)
        self.assertNotIn("serde(alias", rust)
        self.assertNotIn("AUTOMATIC_REDISPATCH", rust)
        android = self.contracts.android_verifier_source().decode()
        self.assertIn("RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH", android)
        self.assertIn("parse_float=finite_float", android)
        self.assertNotIn("shell=True", android)


if __name__ == "__main__":
    unittest.main()
