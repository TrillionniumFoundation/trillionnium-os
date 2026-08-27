from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/verify_codex_only_raw_elf_ab.py"
SPEC = importlib.util.spec_from_file_location("codex_only_raw_elf_ab", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def fake_elf(seed: bytes) -> bytes:
    value = bytearray(512)
    value[:4] = b"\x7fELF"
    value[4] = 2
    value[5] = 1
    value[16:18] = (3).to_bytes(2, "little")
    value[18:20] = (183).to_bytes(2, "little")
    value[64 : 64 + len(seed)] = seed
    return bytes(value)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


TARGET_TOOL_BYTES = {
    "linker": fake_elf(b"fixed-aarch64-gcc"),
    "ar": fake_elf(b"fixed-aarch64-ar"),
    "readelf": fake_elf(b"fixed-aarch64-readelf"),
}


class Fixture:
    def __init__(self, root: Path, lane: str = "common") -> None:
        self.root = root
        self.lane = lane
        self.a = root / "a"
        self.b = root / "b"
        self.output = root / "output"
        self.prefix_a = root / "lane-a"
        self.prefix_b = root / "lane-b"
        for path in (self.a, self.b, self.output):
            path.mkdir(mode=0o700)
        self.write_target_toolchain(self.prefix_a)
        self.write_target_toolchain(self.prefix_b)
        self.artifacts = {
            role: fake_elf(role.encode("ascii"))
            for role in VERIFIER.LANES[lane]["artifacts"]
        }
        self.write_lane(self.a, self.prefix_a)
        self.write_lane(self.b, self.prefix_b)

    def write_target_toolchain(self, prefix: Path) -> None:
        compiler_bin = prefix / "toolchain/sysroot/usr/bin"
        compiler_bin.mkdir(parents=True, mode=0o700)
        for role, filename in {
            "linker": "aarch64-linux-gnu-gcc-12",
            "ar": "aarch64-linux-gnu-ar",
            "readelf": "aarch64-linux-gnu-readelf",
        }.items():
            path = compiler_bin / filename
            path.write_bytes(TARGET_TOOL_BYTES[role])
            path.chmod(0o555)

    def hardening(self, role: str) -> dict[str, object]:
        needed = ["libgcc_s.so.1", "libc.so.6"]
        if role == "daemon":
            needed.insert(1, "libm.so.6")
            needed.append("ld-linux-aarch64.so.1")
            stack_guard = {
                "loader_dt_needed": True,
                "undefined_dynamic_symbol": "__stack_chk_guard@GLIBC_2.17",
                "version": "GLIBC_2.17",
                "version_provider": "ld-linux-aarch64.so.1",
                "loader_bound_undefined_symbols": [
                    "__stack_chk_guard@GLIBC_2.17"
                ],
            }
        else:
            stack_guard = {
                "loader_dt_needed": False,
                "undefined_dynamic_symbol": None,
                "version": None,
                "version_provider": None,
                "loader_bound_undefined_symbols": [],
            }
        return {
            "elf_class": "ELF64",
            "endianness": "little",
            "machine": "AArch64",
            "type": "DYN_PIE",
            "interpreter": "/lib/ld-linux-aarch64.so.1",
            "gnu_relro": True,
            "bind_now": True,
            "gnu_stack_executable": False,
            "writable_executable_load_segment": False,
            "rpath_or_runpath": False,
            "text_relocations": False,
            "debug_sections": False,
            "needed": needed,
            "aarch64_stack_protector_guard": stack_guard,
            "required_glibc_versions": ["GLIBC_2.17", "GLIBC_2.34"],
            "maximum_glibc": "GLIBC_2.34",
            "gnu_build_id_sha1": sha256(self.artifacts[role])[:40],
        }

    def receipt(self, prefix: Path | str) -> dict[str, object]:
        prefix = os.fspath(prefix)
        lane = VERIFIER.LANES[self.lane]
        tools = {}
        for index, role in enumerate(VERIFIER.TOOL_ROLES):
            if role in {"cargo", "rustc"}:
                path = f"{prefix}/rust/bin/{role}"
            elif role == "host_linker":
                path = f"{prefix}/host/bin/{role}"
            else:
                leaf = {
                    "linker": "aarch64-linux-gnu-gcc-12",
                    "ar": "aarch64-linux-gnu-ar",
                    "readelf": "aarch64-linux-gnu-readelf",
                }[role]
                path = f"{prefix}/toolchain/sysroot/usr/bin/{leaf}"
            identity = (
                dict(VERIFIER.EXPECTED_TARGET_TOOL_IDENTITIES[role])
                if role in VERIFIER.EXPECTED_TARGET_TOOL_IDENTITIES
                else {
                    "bytes": 1000 + index,
                    "sha256": sha256(role.encode("ascii")),
                    "mode": "0755",
                    "version": f"{role} fixed-version",
                }
            )
            tools[role] = {
                "path": path,
                **identity,
            }
        receipt: dict[str, object] = {
            "schema": VERIFIER.RAW_SCHEMA,
            "decision": VERIFIER.RAW_PASS,
            "release_status": VERIFIER.RELEASE_HOLD,
            "lane": self.lane,
            "variant": lane["variant"],
            "target": VERIFIER.TARGET,
            "profile": "release",
            "source_date_epoch": 1785110400,
            "source_bom": {
                "schema": VERIFIER.SOURCE_BOM_SCHEMA,
                "decision": VERIFIER.SOURCE_BOM_PASS,
                "bytes": 4096,
                "sha256": "1" * 64,
                "receipt_id": "sha256:" + "2" * 64,
                "source_set_sha256": "3" * 64,
                "resolved_manifest_sha256": "4" * 64,
                "live_full_remeasurement_before_and_after_build": True,
                "byte_equal_to_each_live_remeasurement": True,
                "authority": "local_source_measurement_not_release_authority",
            },
            "build": VERIFIER.expected_build(self.lane),
            "toolchain": {
                "boundary": VERIFIER.TOOLCHAIN_BOUNDARY,
                "cargo_home": f"{prefix}/cargo-home",
                "rust_toolchain_root": f"{prefix}/rust",
                "rust_target_libdir": f"{prefix}/rust/lib/rustlib/aarch64/lib",
                "target_toolchain_root": f"{prefix}/toolchain",
                "host_toolchain_root": f"{prefix}/host",
                "target_sysroot": f"{prefix}/toolchain/sysroot",
                "target_search_prefixes": {
                    "compiler_bin": f"{prefix}/toolchain/sysroot/usr/bin",
                    "gcc_libdir": (
                        f"{prefix}/toolchain/sysroot/usr/lib/gcc-cross/"
                        "aarch64-linux-gnu/12"
                    ),
                    "binutils_dir": (
                        f"{prefix}/toolchain/sysroot/usr/aarch64-linux-gnu/bin"
                    ),
                    "host_runtime_libdir": (
                        f"{prefix}/toolchain/sysroot/usr/lib/x86_64-linux-gnu"
                    ),
                },
                "snapshot_manifest": dict(VERIFIER.EXPECTED_SNAPSHOT_MANIFEST),
                "resolved_components": {
                    name: dict(record)
                    for name, record in VERIFIER.EXPECTED_RESOLVED_COMPONENTS.items()
                },
                "executables": tools,
                "input_remeasurement_after_build_required": True,
                "snapshot_tree_fully_remeasured_before_and_after_build": True,
                "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
                "complete_release_toolchain_closure": False,
            },
            "artifacts": {
                role: {
                    "file": filename,
                    "bytes": len(self.artifacts[role]),
                    "sha256": sha256(self.artifacts[role]),
                    "mode": "0555",
                    "link_count": 1,
                    "hardening": self.hardening(role),
                    "lane_markers_verified": True,
                    "unremapped_host_paths_absent": True,
                    "retired_agent_identity_absent": True,
                }
                for role, filename in lane["artifacts"].items()
            },
            "posture": dict(VERIFIER.POSTURE),
            "limitations": list(VERIFIER.LIMITATIONS),
            "receipt_id_scope": VERIFIER.RECEIPT_ID_SCOPE,
        }
        receipt["receipt_id"] = "sha256:" + sha256(
            VERIFIER.canonical_json_bytes(receipt)
        )
        return receipt

    def write_lane(
        self,
        directory: Path,
        prefix: Path | str,
        receipt: dict[str, object] | None = None,
    ) -> None:
        lane = VERIFIER.LANES[self.lane]
        for role, filename in lane["artifacts"].items():
            path = directory / filename
            path.write_bytes(self.artifacts[role])
            path.chmod(0o555)
        receipt_path = directory / lane["receipt"]
        receipt_path.write_bytes(
            VERIFIER.canonical_json_bytes(receipt or self.receipt(prefix))
        )
        receipt_path.chmod(0o444)

    def rewrite_receipt(self, directory: Path, receipt: dict[str, object]) -> None:
        path = directory / VERIFIER.LANES[self.lane]["receipt"]
        path.chmod(0o600)
        path.write_bytes(VERIFIER.canonical_json_bytes(receipt))
        path.chmod(0o444)

    def args(self) -> argparse.Namespace:
        receipt = str(VERIFIER.LANES[self.lane]["receipt"])
        return argparse.Namespace(
            a_artifact_dir=self.a,
            a_receipt=self.a / receipt,
            b_artifact_dir=self.b,
            b_receipt=self.b / receipt,
            output_dir=self.output,
        )


class CodexOnlyRawElfAbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._expected_target_tool_identities = copy.deepcopy(
            VERIFIER.EXPECTED_TARGET_TOOL_IDENTITIES
        )
        VERIFIER.EXPECTED_TARGET_TOOL_IDENTITIES = {
            "linker": {
                "bytes": len(TARGET_TOOL_BYTES["linker"]),
                "sha256": sha256(TARGET_TOOL_BYTES["linker"]),
                "mode": "0555",
                "version": "aarch64-linux-gnu-gcc fixed",
            },
            "ar": {
                "bytes": len(TARGET_TOOL_BYTES["ar"]),
                "sha256": sha256(TARGET_TOOL_BYTES["ar"]),
                "mode": "0555",
                "version": "GNU ar fixed",
            },
            "readelf": {
                "bytes": len(TARGET_TOOL_BYTES["readelf"]),
                "sha256": sha256(TARGET_TOOL_BYTES["readelf"]),
                "mode": "0555",
                "version": "GNU readelf fixed",
            },
        }

    @classmethod
    def tearDownClass(cls) -> None:
        VERIFIER.EXPECTED_TARGET_TOOL_IDENTITIES = (
            cls._expected_target_tool_identities
        )

    def test_device_inode_uses_stat_device_not_sequence_mode_slot(self) -> None:
        metadata = os.stat(__file__)
        expected = (metadata.st_dev, metadata.st_ino)
        self.assertEqual(VERIFIER.device_inode(metadata), expected)
        self.assertEqual(
            VERIFIER.device_inode(VERIFIER.stable_identity(metadata)), expected
        )

    def test_valid_path_distinct_ab_publishes_canonical_host_only_pass(self) -> None:
        self.assertEqual(
            VERIFIER.RECEIPT_ID_SCOPE,
            "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)",
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            input_before = {
                path: (path.stat().st_mode, path.stat().st_size, path.stat().st_mtime_ns)
                for directory in (fixture.a, fixture.b)
                for path in directory.iterdir()
            }
            result = VERIFIER.verify(fixture.args())
            self.assertEqual(result["decision"], VERIFIER.AGGREGATE_PASS)
            self.assertEqual(result["release_status"], VERIFIER.RELEASE_HOLD)
            output = fixture.output / VERIFIER.OUTPUT_NAME
            raw = output.read_bytes()
            self.assertEqual(raw, VERIFIER.canonical_json_bytes(json.loads(raw)))
            self.assertEqual(stat_mode(output), 0o444)
            self.assertEqual(output.stat().st_nlink, 1)
            self.assertTrue(result["tool_paths_may_differ_and_are_excluded_from_identity"])
            for field in (
                "physical_input_directories_distinct",
                "physical_input_artifact_inodes_distinct",
                "physical_target_toolchain_roots_distinct",
                "physical_target_sysroots_distinct",
                "physical_selected_target_tool_inodes_distinct",
            ):
                self.assertTrue(result["comparisons"][field])
            self.assertTrue(
                result["comparisons"]["same_upstream_source_bom_receipt_claim"]
            )
            self.assertFalse(
                result["comparisons"][
                    "physical_source_bom_or_live_graph_remeasured_by_this_stage"
                ]
            )
            self.assertTrue(
                result["comparisons"]["receipt_ids_are_content_identifiers_only"]
            )
            self.assertFalse(
                result["comparisons"][
                    "receipt_ids_are_signatures_or_attestations"
                ]
            )
            self.assertEqual(
                result["toolchain_snapshot"],
                VERIFIER.EXPECTED_SNAPSHOT_MANIFEST,
            )
            self.assertEqual(
                result["target_compiler_closure"]["components"],
                VERIFIER.EXPECTED_RESOLVED_COMPONENTS,
            )
            self.assertFalse(
                result["target_compiler_closure"][
                    "complete_host_execution_runtime_closure"
                ]
            )
            for role, expected in VERIFIER.EXPECTED_TARGET_TOOL_IDENTITIES.items():
                self.assertEqual(result["selected_tool_identities"][role], expected)
            input_after = {
                path: (path.stat().st_mode, path.stat().st_size, path.stat().st_mtime_ns)
                for directory in (fixture.a, fixture.b)
                for path in directory.iterdir()
            }
            self.assertEqual(input_before, input_after)

    def test_p01_lane_is_supported_without_final_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary), "p01_userdebug_pre_daemon")
            result = VERIFIER.verify(fixture.args())
            self.assertEqual(result["lane"], "p01_userdebug_pre_daemon")
            self.assertNotIn("daemon", result["artifacts"])

    def test_loader_stack_guard_evidence_is_daemon_only_and_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            receipt = fixture.receipt(fixture.prefix_a)
            receipt["artifacts"]["daemon"]["hardening"][
                "aarch64_stack_protector_guard"
            ]["version_provider"] = "libc.so.6"
            receipt.pop("receipt_id")
            receipt["receipt_id"] = "sha256:" + sha256(
                VERIFIER.canonical_json_bytes(receipt)
            )
            fixture.rewrite_receipt(fixture.a, receipt)
            with self.assertRaisesRegex(
                VERIFIER.AggregateError, "stack-protector guard evidence differs"
            ):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            receipt = fixture.receipt(fixture.prefix_a)
            hardening = receipt["artifacts"]["system_api_tool"]["hardening"]
            hardening["needed"].append("ld-linux-aarch64.so.1")
            hardening["aarch64_stack_protector_guard"] = {
                "loader_dt_needed": True,
                "undefined_dynamic_symbol": "__stack_chk_guard@GLIBC_2.17",
                "version": "GLIBC_2.17",
                "version_provider": "ld-linux-aarch64.so.1",
                "loader_bound_undefined_symbols": [
                    "__stack_chk_guard@GLIBC_2.17"
                ],
            }
            receipt.pop("receipt_id")
            receipt["receipt_id"] = "sha256:" + sha256(
                VERIFIER.canonical_json_bytes(receipt)
            )
            fixture.rewrite_receipt(fixture.a, receipt)
            with self.assertRaisesRegex(VERIFIER.AggregateError, "dependency closure"):
                VERIFIER.verify(fixture.args())

    def test_superseded_raw_v2_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            receipt = fixture.receipt(fixture.prefix_a)
            receipt["schema"] = "org.trillionnium.codex-only-raw-elf-set.v2"
            receipt.pop("receipt_id")
            receipt["receipt_id"] = "sha256:" + sha256(
                VERIFIER.canonical_json_bytes(receipt)
            )
            fixture.rewrite_receipt(fixture.a, receipt)
            with self.assertRaisesRegex(VERIFIER.AggregateError, "header differs"):
                VERIFIER.verify(fixture.args())

    def test_target_tool_identity_drift_is_rejected(self) -> None:
        cases = (
            ("linker", "bytes", 1),
            ("ar", "sha256", "f" * 64),
            ("readelf", "mode", "0755"),
            ("linker", "version", "aarch64-linux-gnu-gcc-12 forged"),
        )
        for role, field, value in cases:
            with self.subTest(role=role, field=field):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = Fixture(Path(temporary))
                    receipt = fixture.receipt(fixture.prefix_b)
                    receipt["toolchain"]["executables"][role][field] = value
                    receipt.pop("receipt_id")
                    receipt["receipt_id"] = "sha256:" + sha256(
                        VERIFIER.canonical_json_bytes(receipt)
                    )
                    fixture.rewrite_receipt(fixture.b, receipt)
                    with self.assertRaisesRegex(
                        VERIFIER.AggregateError,
                        f"selected target tool identity {role} differs",
                    ):
                        VERIFIER.verify(fixture.args())

    def test_target_tool_wrapper_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            receipt = fixture.receipt(fixture.prefix_b)
            receipt["toolchain"]["executables"]["linker"]["path"] = (
                str(
                    fixture.prefix_b
                    / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc"
                )
            )
            receipt.pop("receipt_id")
            receipt["receipt_id"] = "sha256:" + sha256(
                VERIFIER.canonical_json_bytes(receipt)
            )
            fixture.rewrite_receipt(fixture.b, receipt)
            with self.assertRaisesRegex(
                VERIFIER.AggregateError, "target tool leaf differs"
            ):
                VERIFIER.verify(fixture.args())

    def test_snapshot_manifest_and_effective_component_drift_are_rejected(self) -> None:
        cases = (
            ("snapshot", "toolchain snapshot manifest binding differs"),
            ("component", "resolved target compiler components differ"),
        )
        for case, message in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = Fixture(Path(temporary))
                    receipt = fixture.receipt(fixture.prefix_b)
                    if case == "snapshot":
                        receipt["toolchain"]["snapshot_manifest"]["tree_digest"] = (
                            "f" * 64
                        )
                    else:
                        receipt["toolchain"]["resolved_components"]["libc.so"][
                            "sha256"
                        ] = "f" * 64
                    receipt.pop("receipt_id")
                    receipt["receipt_id"] = "sha256:" + sha256(
                        VERIFIER.canonical_json_bytes(receipt)
                    )
                    fixture.rewrite_receipt(fixture.b, receipt)
                    with self.assertRaisesRegex(VERIFIER.AggregateError, message):
                        VERIFIER.verify(fixture.args())

    def test_host_runtime_or_complete_toolchain_overclaim_is_rejected(self) -> None:
        fields = (
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed",
            "complete_release_toolchain_closure",
        )
        for field in fields:
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = Fixture(Path(temporary))
                    receipt = fixture.receipt(fixture.prefix_b)
                    receipt["toolchain"][field] = True
                    receipt.pop("receipt_id")
                    receipt["receipt_id"] = "sha256:" + sha256(
                        VERIFIER.canonical_json_bytes(receipt)
                    )
                    fixture.rewrite_receipt(fixture.b, receipt)
                    with self.assertRaisesRegex(
                        VERIFIER.AggregateError,
                        "toolchain posture is malformed",
                    ):
                        VERIFIER.verify(fixture.args())

    def test_actual_artifact_must_match_own_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            path = fixture.a / "trillionnium-agent-system-api"
            path.chmod(0o600)
            path.write_bytes(fake_elf(b"tampered"))
            path.chmod(0o555)
            with self.assertRaisesRegex(VERIFIER.AggregateError, "differs from its receipt"):
                VERIFIER.verify(fixture.args())

    def test_ab_artifacts_must_be_byte_identical_even_when_both_receipts_bind(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            role = "system_api_tool"
            different = fake_elf(b"independent-different")
            path = fixture.b / "trillionnium-agent-system-api"
            path.chmod(0o600)
            path.write_bytes(different)
            path.chmod(0o555)
            receipt = fixture.receipt(fixture.prefix_b)
            receipt["artifacts"][role]["bytes"] = len(different)
            receipt["artifacts"][role]["sha256"] = sha256(different)
            receipt["artifacts"][role]["hardening"]["gnu_build_id_sha1"] = sha256(different)[:40]
            receipt.pop("receipt_id")
            receipt["receipt_id"] = "sha256:" + sha256(
                VERIFIER.canonical_json_bytes(receipt)
            )
            fixture.rewrite_receipt(fixture.b, receipt)
            with self.assertRaisesRegex(VERIFIER.AggregateError, "semantics differ"):
                VERIFIER.verify(fixture.args())

    def test_selected_tool_byte_or_version_drift_is_rejected(self) -> None:
        for field, value in (("sha256", "f" * 64), ("version", "different")):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = Fixture(Path(temporary))
                    receipt = fixture.receipt(fixture.prefix_b)
                    receipt["toolchain"]["executables"]["rustc"][field] = value
                    receipt.pop("receipt_id")
                    receipt["receipt_id"] = "sha256:" + sha256(
                        VERIFIER.canonical_json_bytes(receipt)
                    )
                    fixture.rewrite_receipt(fixture.b, receipt)
                    with self.assertRaisesRegex(VERIFIER.AggregateError, "semantics differ"):
                        VERIFIER.verify(fixture.args())

    def test_source_bom_or_build_semantic_drift_is_rejected(self) -> None:
        for mutate in (
            lambda receipt: receipt["source_bom"].__setitem__("sha256", "f" * 64),
            lambda receipt: receipt["build"].__setitem__("jobs", 2),
        ):
            with self.subTest(mutate=mutate):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = Fixture(Path(temporary))
                    receipt = fixture.receipt(fixture.prefix_b)
                    mutate(receipt)
                    receipt.pop("receipt_id")
                    receipt["receipt_id"] = "sha256:" + sha256(
                        VERIFIER.canonical_json_bytes(receipt)
                    )
                    fixture.rewrite_receipt(fixture.b, receipt)
                    with self.assertRaises(VERIFIER.AggregateError):
                        VERIFIER.verify(fixture.args())

    def test_directory_inventory_is_bidirectional_and_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            extra = fixture.a / "extra"
            extra.write_bytes(b"not admitted")
            extra.chmod(0o555)
            with self.assertRaisesRegex(VERIFIER.AggregateError, "artifact sets differ"):
                VERIFIER.verify(fixture.args())

    def test_symlink_and_hardlink_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            target = fixture.a / "trillionnium-agent-system-api"
            alias = fixture.a / "alias"
            os.link(target, alias)
            with self.assertRaises(VERIFIER.AggregateError):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            target = fixture.a / "trillionnium-agent-system-api"
            target.unlink()
            target.symlink_to(fixture.b / "trillionnium-agent-system-api")
            with self.assertRaisesRegex(VERIFIER.AggregateError, "symlink"):
                VERIFIER.verify(fixture.args())

    def test_physical_a_b_aliases_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            args = fixture.args()
            args.b_artifact_dir = fixture.a / ".." / "a"
            args.b_receipt = fixture.a / VERIFIER.LANES[fixture.lane]["receipt"]
            with self.assertRaisesRegex(
                VERIFIER.AggregateError,
                "same physical directory",
            ):
                VERIFIER.verify(args)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            fixture.rewrite_receipt(
                fixture.b,
                fixture.receipt(fixture.prefix_a),
            )
            with self.assertRaisesRegex(
                VERIFIER.AggregateError,
                "toolchain roots are the same physical directory",
            ):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            b_sysroot = fixture.prefix_b / "toolchain/sysroot"
            shutil.rmtree(b_sysroot)
            b_sysroot.symlink_to(fixture.prefix_a / "toolchain/sysroot")
            with self.assertRaisesRegex(
                VERIFIER.AggregateError,
                "target sysroot contains a symbolic link|"
                "target sysroots are the same physical directory",
            ):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            b_bin = fixture.prefix_b / "toolchain/sysroot/usr/bin"
            shutil.rmtree(b_bin)
            b_bin.symlink_to(fixture.prefix_a / "toolchain/sysroot/usr/bin")
            with self.assertRaisesRegex(
                VERIFIER.AggregateError,
                "target tool .* parent contains a symbolic link|"
                "selected target tools reuse",
            ):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            filename = VERIFIER.LANES[fixture.lane]["artifacts"]["system_api_tool"]
            b_artifact = fixture.b / filename
            b_artifact.unlink()
            os.link(fixture.a / filename, b_artifact)
            with self.assertRaisesRegex(
                VERIFIER.AggregateError,
                "one link|reuse one or more physical inodes",
            ):
                VERIFIER.verify(fixture.args())

    def test_intermediate_toolchain_symlink_is_rejected_component_by_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            real_b = fixture.root / "lane-b-real"
            fixture.prefix_b.rename(real_b)
            fixture.prefix_b.symlink_to(real_b, target_is_directory=True)
            with self.assertRaisesRegex(
                VERIFIER.AggregateError,
                "target toolchain root contains a symbolic link",
            ):
                VERIFIER.verify(fixture.args())

    def test_retained_tool_path_drift_before_publication_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            target = (
                fixture.prefix_b
                / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12"
            )
            original_finalize = VERIFIER.finalize_receipt

            def finalize_and_replace(value: dict[str, object]) -> bytes:
                result = original_finalize(value)
                replacement = target.with_name(target.name + ".replacement")
                replacement.write_bytes(target.read_bytes())
                replacement.chmod(0o555)
                os.replace(replacement, target)
                return result

            VERIFIER.finalize_receipt = finalize_and_replace
            try:
                with self.assertRaisesRegex(
                    VERIFIER.AggregateError,
                    "retained (?:pathname|directory) changed|"
                    "inputs changed before aggregate publication",
                ):
                    VERIFIER.verify(fixture.args())
            finally:
                VERIFIER.finalize_receipt = original_finalize
            self.assertFalse((fixture.output / VERIFIER.OUTPUT_NAME).exists())

    def test_input_directory_rename_replace_before_publication_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            original_finalize = VERIFIER.finalize_receipt

            def finalize_and_replace(value: dict[str, object]) -> bytes:
                result = original_finalize(value)
                held = fixture.root / "a-held"
                fixture.a.rename(held)
                fixture.a.mkdir(mode=0o700)
                for source in held.iterdir():
                    shutil.copy2(source, fixture.a / source.name)
                return result

            VERIFIER.finalize_receipt = finalize_and_replace
            try:
                with self.assertRaisesRegex(
                    VERIFIER.AggregateError,
                    "A input directory (?:retained pathname changed|changed while read)",
                ):
                    VERIFIER.verify(fixture.args())
            finally:
                VERIFIER.finalize_receipt = original_finalize
            self.assertFalse((fixture.output / VERIFIER.OUTPUT_NAME).exists())

    def test_output_directory_rename_replace_during_publication_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            original_write = VERIFIER.write_exclusive_at

            def write_after_replacing_output(
                directory: int, name: str, value: bytes
            ) -> VERIFIER.RetainedPublishedFile:
                held = fixture.root / "output-held"
                fixture.output.rename(held)
                fixture.output.mkdir(mode=0o700)
                return original_write(directory, name, value)

            VERIFIER.write_exclusive_at = write_after_replacing_output
            try:
                with self.assertRaisesRegex(
                    VERIFIER.AggregateError,
                    "output directory retained pathname changed",
                ):
                    VERIFIER.verify(fixture.args())
            finally:
                VERIFIER.write_exclusive_at = original_write
            self.assertFalse((fixture.output / VERIFIER.OUTPUT_NAME).exists())

    def test_published_aggregate_path_and_bytes_are_revalidated(self) -> None:
        for mutation in ("replace", "in_place"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                original_write = VERIFIER.write_exclusive_at

                def mutate_after_write(
                    directory: int, name: str, value: bytes
                ) -> VERIFIER.RetainedPublishedFile:
                    retained = original_write(directory, name, value)
                    target = fixture.output / name
                    if mutation == "replace":
                        replacement = target.with_name(target.name + ".replacement")
                        replacement.write_bytes(value)
                        replacement.chmod(0o444)
                        os.replace(replacement, target)
                    else:
                        target.chmod(0o600)
                        target.write_bytes(b"corrupt-but-pass\n")
                        target.chmod(0o444)
                    return retained

                VERIFIER.write_exclusive_at = mutate_after_write
                try:
                    with self.assertRaisesRegex(
                        VERIFIER.AggregateError,
                        "descriptor, pathname, or bytes changed",
                    ):
                        VERIFIER.verify(fixture.args())
                finally:
                    VERIFIER.write_exclusive_at = original_write

    def test_input_artifact_in_place_mutation_during_publication_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            filename = str(
                VERIFIER.LANES[fixture.lane]["artifacts"]["system_api_tool"]
            )
            target = fixture.a / filename
            original_write = VERIFIER.write_exclusive_at

            def mutate_then_write(
                directory: int, name: str, value: bytes
            ) -> VERIFIER.RetainedPublishedFile:
                target.chmod(0o755)
                target.write_bytes(fake_elf(b"post-reread-in-place-tamper"))
                target.chmod(0o555)
                return original_write(directory, name, value)

            VERIFIER.write_exclusive_at = mutate_then_write
            try:
                with self.assertRaisesRegex(
                    VERIFIER.AggregateError, "retained pathname or bytes changed"
                ):
                    VERIFIER.verify(fixture.args())
            finally:
                VERIFIER.write_exclusive_at = original_write
            self.assertFalse((fixture.output / VERIFIER.OUTPUT_NAME).exists())

    def test_physical_target_tool_must_match_its_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            archiver = (
                fixture.prefix_b
                / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-ar"
            )
            archiver.chmod(0o600)
            archiver.write_bytes(fake_elf(b"tampered-archiver"))
            archiver.chmod(0o555)
            with self.assertRaisesRegex(
                VERIFIER.AggregateError,
                "target tool ar differs from its receipt identity",
            ):
                VERIFIER.verify(fixture.args())

    def test_output_must_be_empty_private_and_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            (fixture.output / "occupied").write_bytes(b"x")
            with self.assertRaisesRegex(VERIFIER.AggregateError, "must be empty"):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            fixture.output.chmod(0o750)
            with self.assertRaisesRegex(VERIFIER.AggregateError, "0700"):
                VERIFIER.verify(fixture.args())


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o7777


if __name__ == "__main__":
    unittest.main()
