#!/usr/bin/env python3

"""EROFS admission v4 and rootfs v9 custody propagation tests."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1]
REPOSITORY = TOOLS.parent


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EROFS = load_module("rootfs_v9_erofs", "build_immutable_rootfs_erofs.py")
PACKAGE_FIXTURES = load_module(
    "rootfs_v9_package_fixtures", "tests/test_package_current_rootfs.py"
)
SOURCE_SET_SHA256 = "b" * 64
RESOLVED_MANIFEST_SHA256 = "c" * 64


def locate_android_staging_filter_c_source() -> Path:
    candidates: list[Path] = []
    android_build_top = os.environ.get("ANDROID_BUILD_TOP")
    if android_build_top:
        candidates.append(Path(android_build_top))
    trillionnium_android_root = os.environ.get("TRILLIONNIUM_ANDROID_ROOT")
    if trillionnium_android_root:
        candidates.append(Path(trillionnium_android_root))
    # The external disk is the only canonical Android estate.  Keep the
    # fallback explicit so a deleted internal-SSD checkout cannot silently
    # become a source authority during differential testing.
    candidates.append(
        Path(
            "/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/android/"
            "lineage-fogos"
        )
    )
    candidates.append(Path.home() / "android/lineage-fogos")
    relative = Path(
        "vendor/trillionnium/prebuilt/common/src/"
        "trillionnium_rootfs_tar_staging_filter.c"
    )
    for root in candidates:
        source = root / relative
        if source.is_file() and not source.is_symlink():
            return source
    raise AssertionError(
        "pinned Android staging-filter C source is required for differential tests"
    )


def build_tool(role: str) -> dict[str, object]:
    identity = EROFS.EXPECTED_LAUNCHER_BUILD_TOOL_IDENTITIES[role]
    return {
        "schema": EROFS.LAUNCHER_BUILD_TOOL_SCHEMA,
        "role": role,
        "path": f"/custody/{role}",
        "bytes": identity["bytes"],
        "sha256": identity["sha256"],
        "mode": identity["mode"],
        "uid": 0,
        "gid": 0,
        "link_count": 1,
        "version": identity["version"],
        "target": identity["target"],
        "execution": {
            "mechanism": "retained_open_file_description_via_proc_self_fd",
            "measured_before_first_execution": True,
            "all_invocations_used_same_open_file_description": True,
            "descriptor_and_path_stable_after_last_execution": True,
            "ambient_environment_inherited": False,
            "environment_allowlist": list(
                EROFS.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST
            ),
        },
        "complete_recursive_toolchain_closure": False,
    }


def identity_gate() -> dict[str, object]:
    return {
        "counterfactual_same_source_rebuild": {
            "evidence_receipt": None,
            "required": True,
            "verified": False,
        },
        "digests": dict(EROFS.EXPECTED_LEGACY_DESCRIPTOR_DIGESTS),
        "literal_digest_absence_verified": True,
        "stable_principal_admission_split": {
            "evidence_receipt": None,
            "required": True,
            "verified": False,
        },
        "status": EROFS.CODEX_PACKAGE_STATUS,
    }


def launcher_ab_summary() -> dict[str, object]:
    return {
        "bytes": 8192,
        "compiler_and_elf_inspector_build_time_bytes_bound": True,
        "decision": EROFS.COMMON_LAUNCHER_AB_DECISION,
        "deterministic_artifact_set_ab_verified": True,
        "lane": "common",
        "physical_source_bom_or_live_graph_remeasured_by_this_stage": False,
        "raw_elf_ab_receipt_id": "sha256:" + "7" * 64,
        "receipt_id": "sha256:" + "8" * 64,
        "release_status": EROFS.COMMON_LAUNCHER_AB_HOLD,
        "same_upstream_source_bom_receipt_claim": True,
        "schema": EROFS.COMMON_LAUNCHER_AB_SCHEMA,
        "sha256": "9" * 64,
        "status": EROFS.COMMON_LAUNCHER_AB_HOLD,
    }


def common_build_evidence() -> dict[str, object]:
    return {
        "compiler": build_tool("compiler_driver"),
        "elf_inspector": build_tool("elf_inspector"),
        "launcher_ab": launcher_ab_summary(),
        "source_bom_claim_authority": copy.deepcopy(
            EROFS.SOURCE_BOM_CLAIM_AUTHORITY
        ),
        "upstream_source_bom_receipt_claim": {
            "authority": "local_exact_clean_graph_not_build_or_release_authority",
            "bytes": 4096,
            "control_head": "3" * 40,
            "file_sha256": "4" * 64,
            "receipt_id": "sha256:" + "5" * 64,
            "resolved_manifest_sha256": RESOLVED_MANIFEST_SHA256,
            "source_set_sha256": SOURCE_SET_SHA256,
        },
        "stable_principal_launcher_measurement": {
            "executable_identity_is_stable_registry_input": False,
            "launcher_executable_sha256": "a" * 64,
            "launcher_identity_source": "measured_after_closed_launcher_inputs",
            "stable_principal_canonical_sha256": (
                EROFS.STABLE_PRINCIPAL_CANONICAL_SHA256
            ),
            "stable_principal_contract_sha256": (
                EROFS.STABLE_PRINCIPAL_CONTRACT_SHA256
            ),
            "status": "host_measurement_only_avb_slot_admission_absent",
        },
        "toolchain_claim_authority": copy.deepcopy(
            EROFS.TOOLCHAIN_CLAIM_AUTHORITY
        ),
        "upstream_receipt_target_compiler_closure_claim": {
            "schema": "org.trillionnium.target-compiler-effective-closure.v1",
            "target": "aarch64-linux-gnu",
            "normalized_search_arguments": [
                "--sysroot=$TARGET_SYSROOT",
                "-B$TARGET_COMPILER_BIN",
                "-B$TARGET_GCC_LIBDIR",
                "-B$TARGET_BINUTILS_DIR",
            ],
            "reported_sysroot": "$TARGET_SYSROOT",
            "components": copy.deepcopy(
                EROFS.EXPECTED_TARGET_COMPILER_COMPONENTS
            ),
            "snapshot_tree_fully_remeasured_before_and_after_build": True,
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
            "complete_host_execution_runtime_closure": False,
        },
        "upstream_receipt_toolchain_snapshot_claim": copy.deepcopy(
            EROFS.EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING
        ),
    }


def launcher_ab_projection() -> dict[str, object]:
    return {
        "filename": EROFS.COMMON_LAUNCHER_AB_FILE,
        "mode": "0444",
        **launcher_ab_summary(),
    }


class RootfsV9ErofsAdmissionTests(unittest.TestCase):
    def test_active_schemas_are_v9_v5_v4_and_launcher_ab_v4(self) -> None:
        self.assertEqual(
            EROFS.CODEX_PACKAGE_CONTRACT_SCHEMA,
            "org.trillionnium.rootfs-package.contract.v9",
        )
        self.assertEqual(
            EROFS.CODEX_PACKAGE_RECEIPT_SCHEMA,
            "org.trillionnium.rootfs-package.receipt.v9",
        )
        self.assertEqual(
            EROFS.COMMON_ARTIFACT_SET_SCHEMA,
            "org.trillionnium.common-codex-rootfs-artifact-set.v5",
        )
        self.assertEqual(
            EROFS.CODEX_PREFLIGHT_SCHEMA,
            "org.trillionnium.root-linux.codex-erofs-preflight-receipt.v4",
        )
        self.assertEqual(
            EROFS.COMMON_LAUNCHER_AB_SCHEMA,
            "org.trillionnium.codex-launcher-artifact-set-ab.v4",
        )
        self.assertEqual(
            EROFS.ANDROID_STAGING_FILTER_SCHEMA,
            "org.trillionnium.rootfs-tar-staging-filter.v1",
        )
        self.assertEqual(
            EROFS.ANDROID_STAGING_FILTER_SOURCE_SHA256,
            "dc48c9ce97f1e64a62e45d00350b44801adb7cc0f60f8666b1d5e87696ce6092",
        )

    def test_android_staging_filter_closure_is_independently_reproduced(
        self,
    ) -> None:
        raw = PACKAGE_FIXTURES.android_filter_fixture_tar()
        with tempfile.TemporaryDirectory() as temporary:
            tar_path = Path(temporary) / "rootfs.tar"
            tar_path.write_bytes(raw)
            expected = {
                "schema": EROFS.ANDROID_STAGING_FILTER_SCHEMA,
                "source_sha256": EROFS.ANDROID_STAGING_FILTER_SOURCE_SHA256,
                "bytes": PACKAGE_FIXTURES.ANDROID_FILTER_FIXTURE_RAW_BYTES,
                "sha256": (
                    PACKAGE_FIXTURES.ANDROID_FILTER_FIXTURE_FILTERED_SHA256
                ),
            }
            self.assertEqual(
                EROFS.reproduce_android_staging_filter(tar_path), expected
            )
            self.assertEqual(
                EROFS.validate_android_staging_filter_receipt(
                    expected, tar_path, len(raw)
                ),
                expected,
            )

            variants: list[tuple[str, object, str]] = []
            unknown = dict(expected)
            unknown["unexpected"] = True
            variants.append(("unknown-key", unknown, "keys differ"))
            wrong_source = dict(expected)
            wrong_source["source_sha256"] = "0" * 64
            variants.append(("source", wrong_source, "identity drifted"))
            wrong_bytes = dict(expected)
            wrong_bytes["bytes"] = int(expected["bytes"]) - 1
            variants.append(("bytes", wrong_bytes, "identity drifted"))
            wrong_digest = dict(expected)
            wrong_digest["sha256"] = "0" * 64
            variants.append(("digest", wrong_digest, "does not reproduce"))
            for label, value, message in variants:
                with self.subTest(label=label):
                    with self.assertRaisesRegex(EROFS.ImageError, message):
                        EROFS.validate_android_staging_filter_receipt(
                            value, tar_path, len(raw)
                        )

    def test_android_staging_filter_octal_matches_c_uint64_boundary(self) -> None:
        with self.assertRaisesRegex(EROFS.ImageError, "C octal bound"):
            EROFS._android_staging_filter_octal(
                b"2000000000000000000000", "oversized fixture field"
            )

    def test_android_staging_filter_c_packager_erofs_differential_corpus(
        self,
    ) -> None:
        source = locate_android_staging_filter_c_source()
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            EROFS.ANDROID_STAGING_FILTER_SOURCE_SHA256,
        )
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "a host C compiler is required")
        assert compiler is not None

        corpus = PACKAGE_FIXTURES.android_filter_differential_corpus()
        labels = {label for label, _, _ in corpus}
        self.assertTrue(
            {
                "regular-linkname",
                "directory-linkname",
                "mode-above-07777",
                "uid-base256",
                "uid-blank",
                "gid-non-octal",
                "size-base256",
                "mtime-digit-after-terminator",
                "devmajor-nonzero",
                "devminor-nonzero",
                "name-nul-tail",
                "uname-nul-tail",
                "gname-nul-tail",
                "prefix-nul-tail",
                "header-trailer-padding",
                "noncanonical-name",
                "noncanonical-prefix",
                "escaping-short-symlink",
                "short-symlink-linkname-nul-tail",
            }.issubset(labels)
        )

        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            binary = temporary_root / "trillionnium-rootfs-tar-staging-filter"
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(source),
                    "-o",
                    str(binary),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            tar_path = temporary_root / "rootfs.tar"
            for label, content, accepted in corpus:
                with self.subTest(label=label):
                    tar_path.write_bytes(content)
                    c_result = subprocess.run(
                        [str(binary)],
                        input=content,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    if accepted:
                        self.assertEqual(
                            c_result.returncode,
                            0,
                            c_result.stderr.decode("utf-8", "replace"),
                        )
                        packager_closure = (
                            PACKAGE_FIXTURES.packager.android_staging_filter_closure(
                                tar_path
                            )
                        )
                        erofs_closure = EROFS.reproduce_android_staging_filter(
                            tar_path
                        )
                        self.assertEqual(packager_closure, erofs_closure)
                        self.assertEqual(
                            packager_closure["bytes"], len(c_result.stdout)
                        )
                        self.assertEqual(
                            packager_closure["sha256"],
                            hashlib.sha256(c_result.stdout).hexdigest(),
                        )
                        if label == "baseline":
                            self.assertEqual(
                                packager_closure["sha256"],
                                PACKAGE_FIXTURES.ANDROID_FILTER_FIXTURE_FILTERED_SHA256,
                            )
                    else:
                        self.assertNotEqual(c_result.returncode, 0)
                        with self.assertRaises(
                            PACKAGE_FIXTURES.packager.PackagerError
                        ):
                            PACKAGE_FIXTURES.packager.android_staging_filter_closure(
                                tar_path
                            )
                        with self.assertRaises(EROFS.ImageError):
                            EROFS.reproduce_android_staging_filter(tar_path)

    def test_active_admission_v4_is_bound_to_rootfs_v9(self) -> None:
        path = EROFS.CODEX_ADMISSION_MANIFEST_PATH
        manifest = EROFS.validate_codex_admission_manifest(
            path, hashlib.sha256(path.read_bytes()).hexdigest()
        )
        self.assertEqual(
            manifest["schema"],
            "org.trillionnium.root-linux.codex-erofs-admission.v4",
        )
        self.assertEqual(
            manifest["archive_contract"]["contract_schema"],
            "org.trillionnium.rootfs-package.contract.v9",
        )
        self.assertEqual(
            manifest["archive_contract"]["receipt_schema"],
            "org.trillionnium.rootfs-package.receipt.v9",
        )
        self.assertIn(
            "complete recursive compiler and ELF-inspector toolchain byte closure",
            manifest["admission"]["missing_gates"],
        )

    def test_historical_v1_through_v3_are_not_accepted_as_active(self) -> None:
        for version in (1, 2, 3):
            path = (
                REPOSITORY
                / f"packaging/root-linux/rootfs-codex-erofs-admission.v{version}.json"
            )
            historical = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                historical["schema"],
                f"org.trillionnium.root-linux.codex-erofs-admission.v{version}",
            )
            with self.assertRaisesRegex(EROFS.ImageError, "schema drifted"):
                EROFS.validate_codex_admission_manifest(
                    path, hashlib.sha256(path.read_bytes()).hexdigest()
                )

    def test_admission_cannot_drop_recursive_toolchain_blocker(self) -> None:
        source = EROFS.CODEX_ADMISSION_MANIFEST_PATH
        manifest = json.loads(source.read_text(encoding="utf-8"))
        manifest["admission"]["missing_gates"].remove(
            "complete recursive compiler and ELF-inspector toolchain byte closure"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "admission.json"
            path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(EROFS.ImageError, "blocker set drifted"):
                EROFS.validate_codex_admission_manifest(
                    path, hashlib.sha256(path.read_bytes()).hexdigest()
                )

    def test_full_compiler_inspector_and_launcher_ab_custody_is_required(self) -> None:
        evidence = common_build_evidence()
        self.assertEqual(
            EROFS.validate_common_build_evidence(evidence, "evidence"), evidence
        )
        for field in ("source_bom_claim_authority", "toolchain_claim_authority"):
            self.assertEqual(
                evidence[field]["source"],
                "content_hash_bound_common_and_self_hashed_launcher_receipt",
            )

        missing_inspector = copy.deepcopy(evidence)
        missing_inspector.pop("elf_inspector")
        with self.assertRaisesRegex(EROFS.ImageError, "missing=.*elf_inspector"):
            EROFS.validate_common_build_evidence(missing_inspector, "evidence")

        weak_launcher_ab = copy.deepcopy(evidence)
        weak_launcher_ab["launcher_ab"][
            "compiler_and_elf_inspector_build_time_bytes_bound"
        ] = False
        with self.assertRaisesRegex(EROFS.ImageError, "launcher_ab custody"):
            EROFS.validate_common_build_evidence(weak_launcher_ab, "evidence")

        overclaimed_source = copy.deepcopy(evidence)
        overclaimed_source["source_bom_claim_authority"][
            "physical_source_bom_input_to_this_stage"
        ] = True
        with self.assertRaisesRegex(EROFS.ImageError, "overclaims downstream authority"):
            EROFS.validate_common_build_evidence(overclaimed_source, "evidence")

        overclaimed_toolchain = copy.deepcopy(evidence)
        overclaimed_toolchain["toolchain_claim_authority"][
            "effective_components_requeried_by_this_stage"
        ] = True
        with self.assertRaisesRegex(EROFS.ImageError, "overclaims downstream authority"):
            EROFS.validate_common_build_evidence(overclaimed_toolchain, "evidence")

        for field in ("source_set_sha256", "resolved_manifest_sha256"):
            with self.subTest(zero_source_bom_digest=field):
                zero_digest = common_build_evidence()
                zero_digest["upstream_source_bom_receipt_claim"][field] = "0" * 64
                with self.assertRaisesRegex(
                    EROFS.ImageError,
                    "upstream_source_bom_receipt_claim drifted",
                ):
                    EROFS.validate_common_build_evidence(zero_digest, "evidence")

        drift_cases = (
            (
                ("compiler", "sha256"),
                "a" * 64,
                "frozen Mobian snapshot leaf",
            ),
            (
                ("upstream_receipt_toolchain_snapshot_claim", "manifest_sha256"),
                "a" * 64,
                "frozen Mobian snapshot",
            ),
            (
                (
                    "upstream_receipt_target_compiler_closure_claim",
                    "components",
                    "ld",
                    "sha256",
                ),
                "a" * 64,
                "components.ld differs from the frozen Mobian snapshot",
            ),
            (
                (
                    "upstream_receipt_target_compiler_closure_claim",
                    "complete_host_execution_runtime_closure",
                ),
                True,
                "posture differs",
            ),
        )
        for path, replacement, message in drift_cases:
            with self.subTest(path=path):
                drifted = common_build_evidence()
                target = drifted
                for field in path[:-1]:
                    target = target[field]
                target[path[-1]] = replacement
                with self.assertRaisesRegex(EROFS.ImageError, message):
                    EROFS.validate_common_build_evidence(drifted, "evidence")

    def test_tool_bytes_and_execution_custody_fail_closed(self) -> None:
        evidence = common_build_evidence()
        evidence["compiler"]["sha256"] = "not-a-digest"
        with self.assertRaises(EROFS.ImageError):
            EROFS.validate_common_build_evidence(evidence, "evidence")

        evidence = common_build_evidence()
        evidence["elf_inspector"]["execution"][
            "all_invocations_used_same_open_file_description"
        ] = False
        with self.assertRaisesRegex(EROFS.ImageError, "custody is malformed"):
            EROFS.validate_common_build_evidence(evidence, "evidence")

    def test_launcher_ab_physical_projection_is_exact(self) -> None:
        projection = launcher_ab_projection()
        summary = launcher_ab_summary()
        self.assertEqual(
            EROFS.validate_common_launcher_ab_projection(
                projection, summary, "launcher A/B"
            ),
            projection,
        )

        weak_mode = copy.deepcopy(projection)
        weak_mode["mode"] = "0644"
        with self.assertRaisesRegex(EROFS.ImageError, "projection drifted"):
            EROFS.validate_common_launcher_ab_projection(
                weak_mode, summary, "launcher A/B"
            )

        cross_spliced = copy.deepcopy(projection)
        cross_spliced["sha256"] = "b" * 64
        with self.assertRaisesRegex(EROFS.ImageError, "projection drifted"):
            EROFS.validate_common_launcher_ab_projection(
                cross_spliced, summary, "launcher A/B"
            )

    def test_preflight_receipt_propagates_full_v9_build_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rootfs = root / "rootfs.tar.zst"
            rootfs.write_bytes(b"rootfs")
            tar_path = root / "rootfs.tar"
            tar_path.write_bytes(b"tar")
            admission = root / "admission.json"
            admission.write_bytes(b"{}\n")
            contexts = root / "file_contexts.bin"
            contexts.write_bytes(b"contexts")
            evidence = common_build_evidence()
            package_facts = {
                "admission": {
                    "decision": EROFS.CODEX_PACKAGE_DECISION,
                    "identity_independence_gate": identity_gate(),
                    "release_allowed": False,
                    "status": EROFS.CODEX_PACKAGE_STATUS,
                },
                "common_build_evidence": evidence,
                "critical_selinux_objects": [],
            }
            receipt = EROFS.codex_preflight_receipt(
                args=argparse.Namespace(
                    admission_manifest=admission,
                    admission_manifest_sha256="1" * 64,
                    compiled_file_contexts=contexts,
                    compiled_file_contexts_sha256="2" * 64,
                    mount_point=EROFS.FINAL_MOUNT_POINT,
                    rootfs=rootfs,
                    source_date_epoch=1_785_110_400,
                ),
                rootfs_info=rootfs.stat(),
                rootfs_sha256=hashlib.sha256(rootfs.read_bytes()).hexdigest(),
                tar_path=tar_path,
                archive={"member_count": 1, "regular_bytes": 3},
                admission_manifest={
                    "schema": EROFS.CODEX_ADMISSION_MANIFEST_SCHEMA,
                    "admission": {"missing_gates": ["identity proof"]},
                },
                admission_manifest_info=admission.stat(),
                compiled_contexts_info=contexts.stat(),
                compiled_contexts_header={"magic": 0xF97CFF8A, "version": 5},
                package_facts=package_facts,
            )
            self.assertEqual(receipt["schema"], EROFS.CODEX_PREFLIGHT_SCHEMA)
            self.assertEqual(receipt["common_build_evidence"], evidence)
            self.assertEqual(receipt["limitations"], EROFS.PREFLIGHT_LIMITATIONS)
            self.assertFalse(receipt["release_allowed"])
            self.assertTrue(receipt["decision"].startswith("HOLD_"))


if __name__ == "__main__":
    unittest.main()
