#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
PACKAGE_ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(PACKAGE_ROOT))

import build_operation_replay_sync_static as contract  # noqa: E402
from test_operation_replay_sync_static import (  # noqa: E402
    make_static_aarch64_elf,
    write_mock_bundle,
)


RECIPE = PACKAGE_ROOT / "operation-replay-sync-static-recipe-v1.json"


class PublicHoldGuardTests(unittest.TestCase):
    def test_public_build_hold_blocks_every_effect_seam(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="operation-helper-public-hold."
        ) as temporary:
            parent = Path(temporary) / "output-parent"
            parent.mkdir()
            before = tuple(parent.iterdir())
            args = argparse.Namespace(
                acknowledge_non_authorizing_source_only=True,
                recipe=Path("/does/not/exist/recipe.json"),
                profile="amd64-cross",
                source_root=Path("/does/not/exist/source"),
                vendor_dir=Path("/does/not/exist/vendor"),
                toolchain_receipt=Path("/does/not/exist/toolchain.json"),
                image_receipt=Path("/does/not/exist/image.json"),
                output=parent / "candidate",
            )
            seam_names = (
                "load_recipe",
                "read_regular",
                "_load_image_receipt",
                "_load_toolchain_receipt",
                "_tree_manifest",
                "_retain_absent_absolute_leaf",
                "_write_new",
                "_bounded_build",
                "_publish_retained_bundle",
            )
            patches = [
                mock.patch.object(
                    contract,
                    name,
                    side_effect=AssertionError(f"public HOLD crossed {name}"),
                )
                for name in seam_names
            ]
            patches.append(
                mock.patch.object(
                    contract.subprocess,
                    "Popen",
                    side_effect=AssertionError("public HOLD started a process"),
                )
            )
            mocks = []
            try:
                for patcher in patches:
                    mocks.append(patcher.start())
                with self.assertRaisesRegex(
                    contract.ContractError,
                    "cgroup-v2.*publication journal.*permanent-HOLD",
                ):
                    contract.build_candidate(args)
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
            self.assertEqual(tuple(parent.iterdir()), before)
            self.assertTrue(all(item.call_count == 0 for item in mocks))

    def test_recipe_rejects_every_activation_flip(self) -> None:
        recipe, _ = contract.load_recipe(RECIPE)
        mutations = (
            ("candidate execution", ("build_contract", "candidate_execution_enabled"), True),
            (
                "outer cgroup requirement",
                ("build_contract", "outer_cgroup_v2_zero_survivor_required"),
                False,
            ),
            (
                "durable journal requirement",
                ("build_contract", "durable_publication_journal_required"),
                False,
            ),
            (
                "durable reconciliation",
                ("reconcile_contract", "durable_publication_enabled"),
                True,
            ),
            (
                "reconcile custody requirement",
                ("reconcile_contract", "fixed_custody_journal_required"),
                False,
            ),
        )
        for label, path, replacement in mutations:
            with self.subTest(label=label):
                changed = copy.deepcopy(recipe)
                changed[path[0]][path[1]] = replacement
                with self.assertRaises(contract.ContractError):
                    contract.verify_recipe(changed)
        for section in ("source_checkpoint", "authority"):
            for key in recipe[section]:
                with self.subTest(section=section, key=key):
                    changed = copy.deepcopy(recipe)
                    changed[section][key] = True
                    with self.assertRaises(contract.ContractError):
                        contract.verify_recipe(changed)

    def test_v1_receipt_cannot_claim_cgroup_or_journal_proof(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="operation-helper-v1-proof-claim."
        ) as temporary:
            root = Path(temporary)
            system = make_static_aarch64_elf(0xD503201F)
            accessibility = make_static_aarch64_elf(0xD65F03C0)
            receipt_path = write_mock_bundle(
                root / "bundle",
                "amd64-cross",
                system,
                accessibility,
            )
            recipe, recipe_sha = contract.load_recipe(RECIPE)
            original = json.loads(receipt_path.read_text(encoding="ascii"))
            for key in (
                "outer_cgroup_v2_zero_survivor_verified",
                "durable_publication_journal_verified",
            ):
                with self.subTest(key=key):
                    changed = copy.deepcopy(original)
                    changed["invocation"][key] = True
                    changed["receipt_id"] = contract._receipt_id(
                        changed,
                        b"trillionnium.operation-replay-sync-static-build-receipt.v1",
                    )
                    os.chmod(receipt_path, 0o600)
                    receipt_path.write_bytes(contract.canonical_json_bytes(changed))
                    os.chmod(receipt_path, 0o444)
                    with self.assertRaisesRegex(
                        contract.ContractError,
                        "build invocation posture drifted",
                    ):
                        contract._verify_build_receipt(
                            receipt_path,
                            recipe,
                            recipe_sha,
                        )


if __name__ == "__main__":
    unittest.main()
