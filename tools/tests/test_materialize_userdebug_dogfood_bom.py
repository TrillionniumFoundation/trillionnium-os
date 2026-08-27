#!/usr/bin/env python3
"""Fixture tests for the explicit userdebug dirty-source BOM lane."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1]
SCRIPT = TOOLS / "materialize_userdebug_dogfood_bom.py"


def load_module():
    spec = importlib.util.spec_from_file_location("userdebug_dogfood_bom", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BOM = load_module()


def write_json(path: Path, value: object) -> None:
    path.write_bytes(BOM.canonical_json_bytes(value))


class UserdebugDogfoodBomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manifest = self.root / "resolved.xml"
        self.manifest.write_bytes(
            (
                b'<manifest><project name="platform/foo" revision="'
                + b"a" * 40
                + b'" /></manifest>\n'
            )
        )
        self.bom_path = self.root / "source-bom.json"
        self.output = self.root / "dogfood-bom.json"
        self.write_bom()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_project(self, failures: list[str] | None = None) -> dict[str, object]:
        failures = [] if failures is None else list(failures)
        return {
            "id": "control_plane",
            "checkout": {"root": "control", "path": "."},
            "requirements": {
                "manifest_required": False,
                "clean": True,
                "no_ignored_paths": True,
            },
            "manifest": None,
            "git": {
                "head": "a" * 40,
                "clean_nonignored": "nonignored_worktree_dirty" not in failures,
                "ignored": {
                    "count": 1 if "ignored_paths_present" in failures else 0,
                    "paths": ["generated.bin"]
                    if "ignored_paths_present" in failures
                    else [],
                },
            },
            "failures": failures,
        }

    def write_bom(self, *, projects: list[dict[str, object]] | None = None) -> None:
        projects = projects or [
            self.make_project(["nonignored_worktree_dirty"]),
            {
                **self.make_project(["ignored_paths_present"]),
                "id": "ai_shell",
            },
        ]
        blockers = sorted(
            f"project_{failure}:{project['id']}"
            for project in projects
            for failure in project["failures"]
        )
        source_set = {
            "schema": "org.trillionnium.p0-cross-repo-source-set.v2",
            "bytes": 123,
            "sha256": "1" * 64,
        }
        manifest_raw = self.manifest.read_bytes()
        value: dict[str, object] = {
            "schema": BOM.SOURCE_BOM_SCHEMA,
            "decision": BOM.SOURCE_BOM_HOLD,
            "posture": {
                "local_only": True,
                "network_access_performed": False,
                "signed": False,
                "release_pin_published": False,
                "build_authorized": False,
                "ota_authorized": False,
                "device_write_authorized": False,
                "observed_artifact_hashes_are_release_pins": False,
                "observed_tree_hashes_are_release_pins": False,
                "public_release_allowed": False,
                "release_allowed": False,
                "effect_authority": False,
            },
            "source_set": source_set,
            "resolved_manifest": {
                "producer": "local_repo_manifest_r",
                "bytes": len(manifest_raw),
                "sha256": BOM.hashlib.sha256(manifest_raw).hexdigest(),
                "project_count": 1,
                "all_revisions_exact": True,
                "declared_checkout_revision_drift_count": 0,
                "declared_checkout_revision_drifts": [],
            },
            "projects": projects,
            "artifacts": [],
            "trees": [],
            "blockers": blockers,
            "receipt_id_scope": BOM.RECEIPT_ID_SCOPE,
        }
        value["receipt_id"] = BOM.SHA256_PREFIX + BOM.hashlib.sha256(
            BOM.canonical_json_bytes(value)
        ).hexdigest()
        write_json(self.bom_path, value)

    def run_tool(self, *, allow: bool = True) -> int:
        argv = [
            "--bom",
            str(self.bom_path),
            "--resolved-manifest",
            str(self.manifest),
            "--output",
            str(self.output),
        ]
        if allow:
            argv.append("--allow-dirty-userdebug-dogfood")
        return BOM.main(argv)

    def test_valid_snapshot_is_non_authorizing_and_exact(self) -> None:
        self.assertEqual(self.run_tool(), 0)
        receipt = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(receipt["schema"], BOM.DOGFOOD_SCHEMA)
        self.assertEqual(receipt["decision"], BOM.DOGFOOD_DECISION)
        self.assertEqual(
            receipt["project_inventory"]["dirty_project_ids"], ["control_plane"]
        )
        self.assertEqual(receipt["project_inventory"]["ignored_project_ids"], ["ai_shell"])
        self.assertFalse(receipt["posture"]["device_write_authorized"])
        self.assertFalse(receipt["posture"]["effect_authority"])
        unsigned = copy.deepcopy(receipt)
        receipt_id = unsigned.pop("receipt_id")
        self.assertEqual(
            receipt_id,
            BOM.SHA256_PREFIX + BOM.hashlib.sha256(BOM.canonical_json_bytes(unsigned)).hexdigest(),
        )
        self.assertEqual(
            BOM.materialize_raw(
                self.bom_path.read_bytes(),
                self.manifest.read_bytes(),
                allow_dirty_userdebug_dogfood=True,
            ),
            receipt,
        )

    def test_explicit_switch_is_required(self) -> None:
        self.assertNotEqual(self.run_tool(allow=False), 0)
        self.assertFalse(self.output.exists())

    def test_output_is_o_excl(self) -> None:
        self.assertEqual(self.run_tool(), 0)
        original = self.output.read_bytes()
        self.assertNotEqual(self.run_tool(), 0)
        self.assertEqual(self.output.read_bytes(), original)

    def test_input_self_hash_is_checked(self) -> None:
        value = json.loads(self.bom_path.read_text(encoding="utf-8"))
        value["decision"] = BOM.SOURCE_BOM_HOLD
        value["receipt_id"] = BOM.SHA256_PREFIX + "0" * 64
        write_json(self.bom_path, value)
        self.assertNotEqual(self.run_tool(), 0)

    def test_manifest_bytes_are_bound(self) -> None:
        self.manifest.write_bytes(self.manifest.read_bytes() + b"tamper\n")
        self.assertNotEqual(self.run_tool(), 0)

    def test_manifest_drift_is_rejected(self) -> None:
        value = json.loads(self.bom_path.read_text(encoding="utf-8"))
        value["resolved_manifest"]["all_revisions_exact"] = False
        value["receipt_id"] = BOM.SHA256_PREFIX + BOM.hashlib.sha256(
            BOM.canonical_json_bytes({k: v for k, v in value.items() if k != "receipt_id"})
        ).hexdigest()
        write_json(self.bom_path, value)
        self.assertNotEqual(self.run_tool(), 0)

    def test_non_project_blocker_is_rejected(self) -> None:
        value = json.loads(self.bom_path.read_text(encoding="utf-8"))
        value["blockers"].append("artifact_missing:agentd")
        value["blockers"].sort()
        value["receipt_id"] = BOM.SHA256_PREFIX + BOM.hashlib.sha256(
            BOM.canonical_json_bytes({k: v for k, v in value.items() if k != "receipt_id"})
        ).hexdigest()
        write_json(self.bom_path, value)
        self.assertNotEqual(self.run_tool(), 0)

    def test_unsupported_project_failure_is_rejected(self) -> None:
        projects = [self.make_project(["required_manifest_project_missing"])]
        self.write_bom(projects=projects)
        self.assertNotEqual(self.run_tool(), 0)

    def test_authorizing_input_posture_is_rejected(self) -> None:
        value = json.loads(self.bom_path.read_text(encoding="utf-8"))
        value["posture"]["effect_authority"] = True
        value["receipt_id"] = BOM.SHA256_PREFIX + BOM.hashlib.sha256(
            BOM.canonical_json_bytes({k: v for k, v in value.items() if k != "receipt_id"})
        ).hexdigest()
        write_json(self.bom_path, value)
        self.assertNotEqual(self.run_tool(), 0)

    def test_symlink_input_is_rejected(self) -> None:
        link = self.root / "bom-link.json"
        link.symlink_to(self.bom_path)
        argv = [
            "--bom",
            str(link),
            "--resolved-manifest",
            str(self.manifest),
            "--output",
            str(self.output),
            "--allow-dirty-userdebug-dogfood",
        ]
        self.assertNotEqual(BOM.main(argv), 0)


if __name__ == "__main__":
    unittest.main()
