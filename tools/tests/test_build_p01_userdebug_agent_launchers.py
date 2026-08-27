from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/build_p01_userdebug_agent_launchers.py"
SPEC = importlib.util.spec_from_file_location("p01_launcher_builder", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class P01UserdebugLauncherBuilderTests(unittest.TestCase):
    @staticmethod
    def trusted_tool_directory() -> tempfile.TemporaryDirectory[str]:
        runtime_root = Path(
            os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.geteuid()}")
        )
        try:
            metadata = runtime_root.stat()
        except OSError as error:
            raise unittest.SkipTest("no private runtime directory for tool fixtures") from error
        if (
            not runtime_root.is_absolute()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise unittest.SkipTest("runtime directory is not invoking-user private")
        return tempfile.TemporaryDirectory(
            prefix="launcher-build-tool-test.", dir=runtime_root
        )

    @staticmethod
    def write_tool(root: Path, name: str, value: bytes = b"fixture-tool\n") -> Path:
        path = root / name
        path.write_bytes(value)
        path.chmod(0o555)
        return path

    @staticmethod
    def source_bom_bytes(control_head: str = "c" * 40) -> bytes:
        contract_raw = BUILDER.SOURCE_SET_CONTRACT.read_bytes()
        contract = json.loads(contract_raw)
        projects = []
        for index, expected in enumerate(contract["projects"]):
            head = control_head if expected["id"] == "control_plane" else f"{index + 1:040x}"
            manifest = None
            if expected["manifest_required"]:
                manifest = {
                    "path": expected["manifest_path"],
                    "name": expected["expected_manifest_name"],
                    "revision": head,
                    "checkout_differs_from_declared_revision": False,
                }
            projects.append(
                {
                    "id": expected["id"],
                    "checkout": {
                        "path": expected["checkout_path"],
                        "root": expected["checkout_root"],
                    },
                    "failures": [],
                    "requirements": {
                        "clean": expected["require_clean"],
                        "manifest_required": expected["manifest_required"],
                        "no_ignored_paths": expected["require_no_ignored"],
                    },
                    "manifest": manifest,
                    "git": {
                        "head": head,
                        "head_tree": f"{index + 101:040x}",
                        "object_format": "sha1",
                        "clean_nonignored": True,
                        "exact_nonignored_state_captured": True,
                        "stable_revalidation_passed": True,
                        "status": {"bytes": 0, "entries": []},
                        "tracked_diff": {"bytes": 0},
                        "untracked": {"count": 0, "entries": []},
                        "ignored": {"count": 0, "paths": []},
                    },
                }
            )
        trees = []
        for expected in contract["trees"]:
            inventory_preimage = {
                "schema": "org.trillionnium.stable-source-tree-inventory.v1",
                "entries": [{"mode": "0755", "path": ".", "type": "directory"}],
            }
            trees.append(
                {
                    "authority": "observed_local_non_git_source_tree_input",
                    "failures": [],
                    "id": expected["id"],
                    "source": {
                        "checkout_root": expected["checkout_root"],
                        "path": expected["path"],
                    },
                    "requirements": {
                        "byte_limit": expected["byte_limit"],
                        "entry_limit": expected["entry_limit"],
                        "mode_policy": expected["mode_policy"],
                        "no_follow": True,
                        "required": expected["required"],
                        "stable_remeasurement": True,
                    },
                    "inventory": {
                        **inventory_preimage,
                        "digest_scope": (
                            "sha256(canonical-json-utf8-of-schema-and-entries-with-lf)"
                        ),
                        "sha256": BUILDER.sha256_bytes(
                            BUILDER.canonical_source_bom_bytes(inventory_preimage)
                        ),
                        "entry_count": 1,
                        "no_follow_path_walk_passed": True,
                        "safe_modes_and_types_passed": True,
                        "confined_link_addresses_passed": True,
                        "stable_remeasurement_passed": True,
                    },
                }
            )
        receipt = {
            "schema": BUILDER.SOURCE_BOM_SCHEMA,
            "decision": BUILDER.SOURCE_BOM_PASS,
            "posture": {
                "local_only": True,
                "signed": False,
                "build_authorized": False,
                "release_pin_published": False,
                "device_write_authorized": False,
                "ota_authorized": False,
            },
            "source_set": {
                "bytes": len(contract_raw),
                "schema": contract["schema"],
                "sha256": BUILDER.sha256_bytes(contract_raw),
            },
            "resolved_manifest": {
                "all_revisions_exact": True,
                "bytes": 195_467,
                "declared_checkout_revision_drift_count": 0,
                "declared_checkout_revision_drifts": [],
                "producer": "supplied_regular_file",
                "project_count": 1_172,
                "sha256": "6" * 64,
            },
            "projects": projects,
            "trees": trees,
            "artifacts": [],
            "blockers": [],
            "receipt_id_scope": BUILDER.SOURCE_BOM_RECEIPT_ID_SCOPE,
        }
        receipt["receipt_id"] = "sha256:" + BUILDER.sha256_bytes(
            BUILDER.canonical_source_bom_bytes(receipt)
        )
        return BUILDER.canonical_source_bom_bytes(receipt)

    def test_launcher_to_daemon_dependency_graph_is_codex_only_and_acyclic(
        self,
    ) -> None:
        graph = BUILDER.DEPENDENCY_GRAPH
        self.assertEqual(
            graph["edge_semantics"],
            "left artifact is a build input of the right artifact",
        )
        edges = [tuple(edge.split("->", 1)) for edge in graph["edges"]]
        forbidden = set(graph["forbidden_edges"])
        self.assertTrue(graph["acyclic"])
        self.assertEqual(len(edges), len(set(edges)))
        self.assertFalse({"->".join(edge) for edge in edges} & forbidden)
        self.assertEqual(
            set(edges),
            {
                ("selected_system_api", "codex_userdebug_launcher"),
                ("codex_runtime", "codex_userdebug_launcher"),
                ("daemon_build_binding", "p01_daemon_final_build"),
                ("selected_system_api", "p01_daemon_final_build"),
                ("replay_sync_helper", "p01_daemon_final_build"),
                ("high_water_authority", "p01_daemon_final_build"),
                ("codex_userdebug_launcher", "p01_daemon_final_build"),
            },
        )

        adjacency: dict[str, set[str]] = {}
        for source, target in edges:
            adjacency.setdefault(source, set()).add(target)
            adjacency.setdefault(target, set())
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> None:
            self.assertNotIn(node, visiting, f"dependency cycle reaches {node}")
            if node in visited:
                return
            visiting.add(node)
            for target in adjacency[node]:
                visit(target)
            visiting.remove(node)
            visited.add(node)

        for node in adjacency:
            visit(node)

    def test_output_contract_is_codex_only_v8(self) -> None:
        self.assertEqual(
            BUILDER.OUTPUT_NAMES,
            {
                "system_api_tool": "trillionnium-agent-system-api-device-conformance",
                "replay_sync_helper": (
                    "trillionnium-system-api-device-conformance-replay-sync"
                ),
                "high_water_authority": (
                    "trillionnium-direct-operation-custody-high-water"
                ),
                "codex_launcher": (
                    "trillionnium-codex-agent-0.144.1-p01-userdebug"
                ),
                "receipt": "p01-userdebug-pre-daemon-artifact-set.v8.json",
            },
        )
        self.assertEqual(
            BUILDER.P01_PRE_DAEMON_RECEIPT_SCHEMA,
            "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v8",
        )
        source = MODULE_PATH.read_text(encoding="utf-8").casefold()
        self.assertNotIn("open" + "claw", source)

    def test_identity_independence_gate_is_closed_and_unverified(self) -> None:
        legacy_digests = BUILDER.load_legacy_descriptor_registry_digests()
        gate = BUILDER.legacy_descriptor_contamination_hold_gate(legacy_digests)
        self.assertEqual(
            gate,
            {
                "counterfactual_same_source_rebuild": {
                    "evidence_receipt": None,
                    "required": True,
                    "verified": False,
                },
                "digests": legacy_digests,
                "literal_digest_absence_verified": True,
                "stable_principal_admission_split": {
                    "evidence_receipt": None,
                    "required": True,
                    "verified": False,
                },
                "status": BUILDER.IDENTITY_INDEPENDENCE_HOLD_STATUS,
            },
        )
        self.assertEqual(
            legacy_digests,
            {
                "canonical digest": (
                    "bc6c64abbb893e6e75ed708f87cf864e6c8f7503381371dc394409bddc4009c2"
                ),
                "contract digest": (
                    "5ecd89d3c9fedbbeb0ac1de32fba2b5e5e5d248048ddc9a9e0359a0a01903119"
                ),
                "launcher identity": (
                    "edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c"
                ),
            },
        )
        with self.assertRaisesRegex(RuntimeError, "digest set is not closed"):
            BUILDER.legacy_descriptor_contamination_hold_gate(
                {"launcher identity": legacy_digests["launcher identity"]}
            )

    def test_daemon_build_binding_closes_target_and_bookworm_abi(self) -> None:
        artifacts = {
            "system_api_tool": b"system",
            "replay_sync_helper": b"replay",
            "high_water_authority": b"high-water",
            "codex_launcher": b"launcher",
        }
        gate = BUILDER.legacy_descriptor_contamination_hold_gate(
            BUILDER.load_legacy_descriptor_registry_digests()
        )
        toolchain_snapshot = {"schema": BUILDER.TOOLCHAIN_SNAPSHOT_BINDING_SCHEMA}
        target_compiler_closure = {"schema": BUILDER.TARGET_COMPILER_CLOSURE_SCHEMA}
        binding = BUILDER.daemon_build_binding(
            artifacts,
            gate,
            toolchain_snapshot,
            target_compiler_closure,
        )
        self.assertEqual(
            binding["target_profile"],
            {
                "architecture": "aarch64",
                "dynamic_interpreter": "/lib/ld-linux-aarch64.so.1",
                "libc_family": "glibc",
                "maximum_glibc": "GLIBC_2.36",
                "operating_system": "linux",
                "runtime_base_contract": "debian-bookworm-arm64",
                "rust_target_triple": "aarch64-unknown-linux-gnu",
            },
        )
        self.assertEqual(
            binding["cargo_profile"],
            {
                "debug": 0,
                "debug_assertions": False,
                "incremental": False,
                "name": "release",
                "opt_level": "3",
                "strip": "symbols",
            },
        )
        self.assertEqual(binding["build_policy"], BUILDER.DAEMON_BUILD_POLICY)
        self.assertEqual(binding["toolchain_snapshot"], toolchain_snapshot)
        self.assertEqual(
            binding["target_compiler_closure"], target_compiler_closure
        )

    def test_stable_digest_is_allowed_but_legacy_digest_is_rejected(self) -> None:
        legacy_digests = BUILDER.load_legacy_descriptor_registry_digests()
        stable_metadata = b"\n".join(
            (
                BUILDER.FROZEN_STABLE_PRINCIPAL_CANONICAL_SHA256.encode(),
                BUILDER.FROZEN_STABLE_PRINCIPAL_CONTRACT_SHA256.encode(),
                b"d" * 64,
            )
        )
        BUILDER.validate_identity_digest_literal_absence(
            {"system_api_tool": stable_metadata}, legacy_digests
        )
        with self.assertRaisesRegex(RuntimeError, "legacy registry launcher identity"):
            BUILDER.validate_identity_digest_literal_absence(
                {
                    "system_api_tool": (
                        stable_metadata
                        + legacy_digests["launcher identity"].encode("ascii")
                    )
                },
                legacy_digests,
            )

    def test_daemon_consumer_requires_closed_v8_binding_and_hold_gate(self) -> None:
        source = (ROOT / "apps/trillionniumd/build.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("p01-userdebug-pre-daemon-artifact-set.v8.json", source)
        self.assertIn(
            "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v8", source
        )
        self.assertNotIn("p01-userdebug-pre-daemon-artifact-set.v5.json", source)
        self.assertNotIn(
            "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v5", source
        )
        self.assertNotIn("p01-userdebug-pre-daemon-artifact-set.v4.json", source)
        self.assertNotIn(
            "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v4", source
        )
        for required in (
            "legacy_descriptor_contamination_hold_gate",
            "hold_identity_independence_evidence_unverified",
            "counterfactual_same_source_rebuild",
            "stable_principal_admission_split",
            'exact_bool(evidence_value, "verified", false)',
            'field(evidence_value, "evidence_receipt").is_null()',
            ".trillionnium_p01_identity_hold_v2",
            "org.trillionnium.p01-userdebug-identity-independence-hold.v2",
            "daemon_build_binding_sha256=",
            'env::var("TARGET").as_deref()',
            'env::var("CARGO_CFG_TARGET_ENV").as_deref()',
            'env::var("PROFILE").as_deref()',
            'env::var("OPT_LEVEL").as_deref()',
            'env::var("CARGO_INCREMENTAL").as_deref()',
            'env::var("SOURCE_DATE_EPOCH").as_deref()',
            "normalized_daemon_rustflags()",
            "DAEMON_NORMALIZED_RUSTFLAGS",
            '"maximum_glibc", "GLIBC_2.36"',
            "literal_digest_absence_verified=true",
            "legacy_descriptor_canonical_sha256=",
            "legacy_descriptor_contract_sha256=",
            "legacy_descriptor_launcher_identity_sha256=",
            "org.trillionnium.launcher-build-tool-custody.v1",
            'validate_launcher_build_tool(&receipt, "elf_inspector", "elf_inspector")',
        ):
            self.assertIn(required, source)
        hold_record = source.split("let hold_record = format!(", 1)[1].split(
            ");", 1
        )[0]
        self.assertNotIn("stable_principal_canonical_sha256=", hold_record)
        self.assertNotIn("stable_principal_contract_sha256=", hold_record)
        self.assertNotIn("launcher_executable_sha256=", hold_record)
        self.assertNotIn("receipt_sha256=", hold_record)
        self.assertIn('field(receipt, "source_bom")', source)
        self.assertNotIn("source_bom", hold_record)

    def test_source_bom_binding_accepts_only_canonical_local_pass(self) -> None:
        raw = self.source_bom_bytes()
        binding = BUILDER.validate_source_bom_bytes(raw)
        self.assertEqual(binding["receipt_id"], json.loads(raw)["receipt_id"])
        self.assertEqual(binding["control_head"], "c" * 40)
        self.assertEqual(
            binding["authority"],
            "local_exact_clean_graph_not_build_or_release_authority",
        )

        tampered = json.loads(raw)
        tampered["decision"] = "HOLD_LOCAL_SOURCE_GRAPH"
        with self.assertRaisesRegex(RuntimeError, "PASS posture"):
            BUILDER.validate_source_bom_bytes(
                BUILDER.canonical_source_bom_bytes(tampered)
            )

        tampered = json.loads(raw)
        tampered["receipt_id"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(RuntimeError, "receipt_id"):
            BUILDER.validate_source_bom_bytes(
                BUILDER.canonical_source_bom_bytes(tampered)
            )

        tampered = json.loads(raw)
        tampered["artifacts"] = [{"id": "stale-prebuilt"}]
        tampered.pop("receipt_id")
        tampered["receipt_id"] = "sha256:" + BUILDER.sha256_bytes(
            BUILDER.canonical_source_bom_bytes(tampered)
        )
        with self.assertRaisesRegex(RuntimeError, "previously built ELF"):
            BUILDER.validate_source_bom_bytes(
                BUILDER.canonical_source_bom_bytes(tampered)
            )

        tampered = json.loads(raw)
        tampered["source_set"]["sha256"] = "0" * 64
        tampered.pop("receipt_id")
        tampered["receipt_id"] = "sha256:" + BUILDER.sha256_bytes(
            BUILDER.canonical_source_bom_bytes(tampered)
        )
        with self.assertRaisesRegex(RuntimeError, "source-set descriptor is not exact"):
            BUILDER.validate_source_bom_bytes(
                BUILDER.canonical_source_bom_bytes(tampered)
            )

        tampered = json.loads(raw)
        tampered["resolved_manifest"]["sha256"] = "0" * 64
        tampered.pop("receipt_id")
        tampered["receipt_id"] = "sha256:" + BUILDER.sha256_bytes(
            BUILDER.canonical_source_bom_bytes(tampered)
        )
        with self.assertRaisesRegex(RuntimeError, "resolved manifest descriptor"):
            BUILDER.validate_source_bom_bytes(
                BUILDER.canonical_source_bom_bytes(tampered)
            )

        tampered = json.loads(raw)
        tampered["projects"].pop()
        tampered.pop("receipt_id")
        tampered["receipt_id"] = "sha256:" + BUILDER.sha256_bytes(
            BUILDER.canonical_source_bom_bytes(tampered)
        )
        with self.assertRaisesRegex(RuntimeError, "project graph is truncated"):
            BUILDER.validate_source_bom_bytes(
                BUILDER.canonical_source_bom_bytes(tampered)
            )

        tampered = json.loads(raw)
        tampered["trees"][1] = tampered["trees"][0]
        tampered.pop("receipt_id")
        tampered["receipt_id"] = "sha256:" + BUILDER.sha256_bytes(
            BUILDER.canonical_source_bom_bytes(tampered)
        )
        with self.assertRaisesRegex(RuntimeError, "reordered or duplicated"):
            BUILDER.validate_source_bom_bytes(
                BUILDER.canonical_source_bom_bytes(tampered)
            )

    def test_source_bom_binding_accepts_supplied_manifest_digest(self) -> None:
        value = json.loads(self.source_bom_bytes())
        value["resolved_manifest"]["sha256"] = "e" * 64
        value.pop("receipt_id")
        value["receipt_id"] = "sha256:" + BUILDER.sha256_bytes(
            BUILDER.canonical_source_bom_bytes(value)
        )

        binding = BUILDER.validate_source_bom_bytes(
            BUILDER.canonical_source_bom_bytes(value)
        )

        self.assertEqual(binding["resolved_manifest_sha256"], "e" * 64)

    def test_source_bom_binding_measures_checked_in_contract_raw_bytes(self) -> None:
        contract = json.loads(BUILDER.SOURCE_SET_CONTRACT.read_bytes())
        alternate_raw = (json.dumps(contract, sort_keys=True) + "\n").encode("utf-8")
        value = json.loads(self.source_bom_bytes())
        value["source_set"] = {
            "bytes": len(alternate_raw),
            "schema": contract["schema"],
            "sha256": BUILDER.sha256_bytes(alternate_raw),
        }
        value.pop("receipt_id")
        value["receipt_id"] = "sha256:" + BUILDER.sha256_bytes(
            BUILDER.canonical_source_bom_bytes(value)
        )

        with tempfile.TemporaryDirectory() as temporary:
            alternate_contract = Path(temporary) / "source-set.json"
            alternate_contract.write_bytes(alternate_raw)
            with mock.patch.object(
                BUILDER, "SOURCE_SET_CONTRACT", alternate_contract
            ):
                binding = BUILDER.validate_source_bom_bytes(
                    BUILDER.canonical_source_bom_bytes(value)
                )

        self.assertEqual(
            binding["source_set_sha256"], BUILDER.sha256_bytes(alternate_raw)
        )

    def test_source_bom_binding_remeasures_clean_control_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as checkout_temporary:
            checkout = Path(checkout_temporary)
            subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
            tracked = checkout / "tracked.txt"
            tracked.write_text("frozen\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=checkout, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Trillionnium Test",
                    "-c",
                    "user.email=test@trillionnium.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "fixture",
                ],
                cwd=checkout,
                check=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=checkout,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            with tempfile.TemporaryDirectory() as evidence_temporary:
                bom = Path(evidence_temporary) / "source-bom.json"
                bom.write_bytes(self.source_bom_bytes(head))
                binding = BUILDER.load_source_bom_binding(bom, checkout)
                self.assertEqual(binding["control_head"], head)

                tracked.write_text("dirty\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "differs from the source BOM"):
                    BUILDER.load_source_bom_binding(bom, checkout)

    def test_source_bom_binding_rejects_ignored_control_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as checkout_temporary:
            checkout = Path(checkout_temporary)
            subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
            (checkout / ".gitignore").write_text("ignored.bin\n", encoding="utf-8")
            subprocess.run(["git", "add", ".gitignore"], cwd=checkout, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Trillionnium Test",
                    "-c",
                    "user.email=test@trillionnium.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "fixture",
                ],
                cwd=checkout,
                check=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=checkout,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            (checkout / "ignored.bin").write_bytes(b"contamination")
            with tempfile.TemporaryDirectory() as evidence_temporary:
                bom = Path(evidence_temporary) / "source-bom.json"
                bom.write_bytes(self.source_bom_bytes(head))
                with self.assertRaisesRegex(RuntimeError, "ignored inputs"):
                    BUILDER.load_source_bom_binding(bom, checkout)

    def test_live_source_bom_remeasurement_requires_exact_canonical_bytes(self) -> None:
        raw = self.source_bom_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bom = root / "source-bom.json"
            bom.write_bytes(raw)
            android = root / "android"
            artifacts = root / "artifacts"
            android.mkdir()
            artifacts.mkdir()
            manifest = root / "resolved-manifest.xml"
            manifest.write_text("<manifest/>\n", encoding="utf-8")

            def materialize(
                argv: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                output = Path(argv[argv.index("--output") + 1])
                output.write_bytes(raw)
                self.assertIn(str(BUILDER.SOURCE_SET_CONTRACT), argv)
                self.assertIn(str(android), argv)
                self.assertIn(str(artifacts), argv)
                self.assertIn(str(manifest), argv)
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            with (
                mock.patch.object(
                    BUILDER, "current_control_checkout_root", return_value=root
                ),
                mock.patch.object(BUILDER, "verify_current_control_checkout"),
                mock.patch.object(BUILDER.subprocess, "run", side_effect=materialize),
            ):
                binding = BUILDER.remeasure_live_source_bom_binding(
                    bom, android, artifacts, manifest, root
                )
            self.assertEqual(binding["file_sha256"], BUILDER.sha256_bytes(raw))

            def materialize_drifted(
                argv: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                output = Path(argv[argv.index("--output") + 1])
                output.write_bytes(raw + b" ")
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            with (
                mock.patch.object(
                    BUILDER, "current_control_checkout_root", return_value=root
                ),
                mock.patch.object(BUILDER, "verify_current_control_checkout"),
                mock.patch.object(
                    BUILDER.subprocess, "run", side_effect=materialize_drifted
                ),
                self.assertRaisesRegex(RuntimeError, "live source graph differs"),
            ):
                BUILDER.remeasure_live_source_bom_binding(
                    bom, android, artifacts, manifest, root
                )

    def test_launcher_build_remeasures_full_source_graph_before_and_after(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        build_body = source.split("def build_into(", 1)[1].split(
            "def parse_args()", 1
        )[0]
        self.assertEqual(build_body.count("remeasure_live_source_bom_binding("), 2)
        for option in (
            "--android-root",
            "--artifact-root",
            "--resolved-manifest",
            "--cc",
            "--readelf",
        ):
            self.assertIn(option, source)
        self.assertNotIn("shutil.which", source)

    def test_frozen_inputs_match_the_reviewed_identity_rotation(self) -> None:
        self.assertEqual(
            {
                "system_api": BUILDER.FROZEN_SYSTEM_API_SHA256,
                "replay_sync": BUILDER.FROZEN_REPLAY_SYNC_HELPER_SHA256,
                "high_water": BUILDER.FROZEN_HIGH_WATER_AUTHORITY_SHA256,
            },
            {
                "system_api": "5d5b92f9f190c40a3d84c82212fb1c81ef9bf3228ea7eb4ca42949af0b48cf55",
                "replay_sync": "49e899b166472e3a663528c3a70f0db21644e5848a162aaab2f68ab1aa6dd927",
                "high_water": "e2339d5bd99747148f13b313d422450b9e20b6f4ade786cda829af6b883a4b5b",
            },
        )
        self.assertEqual(
            BUILDER.sha256_bytes(BUILDER.STABLE_PRINCIPAL_CONTRACT.read_bytes()),
            BUILDER.FROZEN_STABLE_PRINCIPAL_CONTRACT_SHA256,
        )
        self.assertEqual(
            BUILDER.FROZEN_STABLE_PRINCIPAL_CANONICAL_SHA256,
            "a9c224116123deb49908beda3ab047fc98d6917cfeb62d60364033858cc57153",
        )

    def test_bounded_input_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"measured\n")
            alias = root / "alias"
            alias.symlink_to(source)
            with self.assertRaises(OSError):
                BUILDER.read_bounded_regular(alias, "fixture", 1024)

    def test_output_directory_must_be_owner_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            output.chmod(0o770)
            with self.assertRaisesRegex(RuntimeError, "owner-controlled"):
                BUILDER.open_empty_output_dir(output)

    def test_output_directory_requires_absolute_componentwise_nofollow_path(
        self,
    ) -> None:
        with self.assertRaisesRegex(RuntimeError, "canonical absolute"):
            BUILDER.open_empty_output_dir(Path("relative-output"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_parent = root / "real-parent"
            real_parent.mkdir(mode=0o700)
            (real_parent / "output").mkdir(mode=0o700)
            alias = root / "alias-parent"
            alias.symlink_to(real_parent.name)
            with self.assertRaisesRegex(RuntimeError, "link or non-directory"):
                BUILDER.open_empty_output_dir(alias / "output")

    def test_output_publication_rejects_directory_rename_and_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir(mode=0o700)
            custody = BUILDER.open_empty_output_dir(output)
            try:
                BUILDER.write_exclusive_at(custody, "artifact", b"artifact\n", 0o555)
                output.rename(root / "moved-output")
                output.mkdir(mode=0o700)
                with self.assertRaisesRegex(
                    RuntimeError, "output directory retained pathname changed"
                ):
                    BUILDER.finalize_output_publication(
                        custody, {"artifact": (b"artifact\n", 0o555)}
                    )
            finally:
                custody.close()

    def test_output_publication_rejects_prior_artifact_pathname_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir(mode=0o700)
            custody = BUILDER.open_empty_output_dir(output)
            try:
                BUILDER.write_exclusive_at(custody, "artifact", b"artifact\n", 0o555)
                (output / "artifact").rename(root / "original-artifact")
                (output / "artifact").write_bytes(b"artifact\n")
                (output / "artifact").chmod(0o555)
                BUILDER.write_exclusive_at(custody, "receipt", b"receipt\n", 0o444)
                with self.assertRaisesRegex(
                    RuntimeError, "descriptor, pathname, or bytes changed"
                ):
                    BUILDER.finalize_output_publication(
                        custody,
                        {
                            "artifact": (b"artifact\n", 0o555),
                            "receipt": (b"receipt\n", 0o444),
                        },
                    )
            finally:
                custody.close()

    def test_output_publication_rejects_retained_inode_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            custody = BUILDER.open_empty_output_dir(output)
            try:
                artifact = BUILDER.write_exclusive_at(
                    custody, "artifact", b"artifact\n", 0o555
                )
                BUILDER.write_exclusive_at(custody, "receipt", b"receipt\n", 0o444)
                os.pwrite(artifact.descriptor, b"X", 0)
                os.fsync(artifact.descriptor)
                with self.assertRaisesRegex(
                    RuntimeError, "descriptor, pathname, or bytes changed"
                ):
                    BUILDER.finalize_output_publication(
                        custody,
                        {
                            "artifact": (b"artifact\n", 0o555),
                            "receipt": (b"receipt\n", 0o444),
                        },
                    )
            finally:
                custody.close()

    def test_output_publication_rejects_extra_inventory_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            custody = BUILDER.open_empty_output_dir(output)
            try:
                BUILDER.write_exclusive_at(custody, "artifact", b"artifact\n", 0o555)
                (output / "unexpected").write_bytes(b"contamination\n")
                with self.assertRaisesRegex(RuntimeError, "exact published set"):
                    BUILDER.finalize_output_publication(
                        custody, {"artifact": (b"artifact\n", 0o555)}
                    )
            finally:
                custody.close()

    def test_output_custody_close_drains_every_descriptor_after_one_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            custody = BUILDER.open_empty_output_dir(output)
            artifact = BUILDER.write_exclusive_at(
                custody, "artifact", b"artifact\n", 0o555
            )
            descriptors = {artifact.descriptor, *custody.descriptors}
            real_close = os.close
            calls: list[int] = []

            def close_then_report_once(descriptor: int) -> None:
                calls.append(descriptor)
                real_close(descriptor)
                if len(calls) == 1:
                    raise RuntimeError("forced publication close failure")

            with mock.patch.object(
                BUILDER.os, "close", side_effect=close_then_report_once
            ), self.assertRaisesRegex(RuntimeError, "descriptor cleanup failed"):
                custody.close()

            self.assertCountEqual(calls, descriptors)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            custody.close()

    def test_launcher_build_tool_rejects_non_absolute_and_symlink_paths(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "canonical absolute syntax"):
            BUILDER.open_launcher_build_tool(Path("relative-gcc"), "compiler_driver")

        with self.trusted_tool_directory() as temporary:
            root = Path(temporary)
            target = self.write_tool(root, "gcc-real")
            alias = root / "gcc-alias"
            alias.symlink_to(target.name)
            with self.assertRaises(OSError):
                BUILDER.open_launcher_build_tool(alias, "compiler_driver")

    def test_launcher_build_tool_rejects_group_writable_and_multi_link_files(
        self,
    ) -> None:
        with self.trusted_tool_directory() as temporary:
            root = Path(temporary)
            writable = self.write_tool(root, "group-writable")
            writable.chmod(0o575)
            with self.assertRaisesRegex(RuntimeError, "bounded immutable executable"):
                BUILDER.open_launcher_build_tool(writable, "compiler_driver")

            original = self.write_tool(root, "hardlink-source")
            alias = root / "hardlink-alias"
            os.link(original, alias)
            with self.assertRaisesRegex(RuntimeError, "bounded immutable executable"):
                BUILDER.open_launcher_build_tool(original, "compiler_driver")

    def test_launcher_build_tool_revalidation_rejects_pathname_replacement(self) -> None:
        with self.trusted_tool_directory() as temporary:
            root = Path(temporary)
            path = self.write_tool(root, "gcc")
            tool = BUILDER.open_launcher_build_tool(path, "compiler_driver")
            try:
                path.rename(root / "gcc-original")
                self.write_tool(root, "gcc", b"replacement-tool\n")
                with self.assertRaisesRegex(RuntimeError, "changed while retained"):
                    BUILDER.revalidate_launcher_build_tool(tool)
            finally:
                tool.close()

    def test_launcher_build_tool_close_drains_both_descriptors_after_one_error(
        self,
    ) -> None:
        with self.trusted_tool_directory() as temporary:
            root = Path(temporary)
            tool = BUILDER.open_launcher_build_tool(
                self.write_tool(root, "gcc"), "compiler_driver"
            )
            descriptors = {tool.descriptor, tool.parent_descriptor}
            real_close = os.close
            calls: list[int] = []

            def close_then_report_once(descriptor: int) -> None:
                calls.append(descriptor)
                real_close(descriptor)
                if len(calls) == 1:
                    raise RuntimeError("forced executable close failure")

            with mock.patch.object(
                BUILDER.os, "close", side_effect=close_then_report_once
            ), self.assertRaisesRegex(RuntimeError, "descriptor cleanup failed"):
                tool.close()

            self.assertCountEqual(calls, descriptors)
            self.assertEqual(tool.descriptor, -1)
            self.assertEqual(tool.parent_descriptor, -1)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            tool.close()

    def test_launcher_build_environment_is_closed_and_rejects_ambient_fields(self) -> None:
        with self.trusted_tool_directory() as temporary:
            root = Path(temporary)
            compiler = BUILDER.open_launcher_build_tool(
                self.write_tool(root, "gcc"), "compiler_driver"
            )
            inspector = BUILDER.open_launcher_build_tool(
                self.write_tool(root, "readelf"), "elf_inspector"
            )
            try:
                environment = BUILDER.launcher_build_environment(
                    compiler, inspector, root, root / "snapshot-usr-lib"
                )
                self.assertEqual(
                    set(environment), set(BUILDER.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST)
                )
                self.assertEqual(environment["TMPDIR"], str(root))
                self.assertEqual(
                    environment["LD_LIBRARY_PATH"], str(root / "snapshot-usr-lib")
                )
                for forbidden in (
                    "CC",
                    "COMPILER_PATH",
                    "GCC_EXEC_PREFIX",
                    "LD_PRELOAD",
                    "LIBRARY_PATH",
                ):
                    self.assertNotIn(forbidden, environment)
                contaminated = {**environment, "LD_PRELOAD": "/tmp/inject.so"}
                with self.assertRaisesRegex(RuntimeError, "allowlist differs"):
                    BUILDER.run_retained_tool(
                        compiler,
                        ["--version"],
                        environment=contaminated,
                        cwd=root,
                        timeout=1,
                    )
            finally:
                inspector.close()
                compiler.close()

    def test_launcher_build_tool_executes_retained_fd_with_original_argv0(self) -> None:
        with self.trusted_tool_directory() as temporary:
            root = Path(temporary)
            tool = BUILDER.open_launcher_build_tool(
                self.write_tool(root, "gcc"), "compiler_driver"
            )
            try:
                environment = BUILDER.launcher_build_environment(
                    tool, tool, root, root / "snapshot-usr-lib"
                )
                completed = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=b"fixture gcc\n", stderr=b""
                )
                with mock.patch.object(
                    BUILDER.subprocess, "run", return_value=completed
                ) as run:
                    self.assertEqual(
                        BUILDER.run_retained_tool(
                            tool,
                            ["--version"],
                            environment=environment,
                            cwd=root,
                            timeout=30,
                        ),
                        b"fixture gcc\n",
                    )
                positional, keywords = run.call_args
                self.assertEqual(positional[0], [str(tool.path), "--version"])
                self.assertEqual(
                    keywords["executable"], f"/proc/self/fd/{tool.descriptor}"
                )
                self.assertEqual(keywords["pass_fds"], (tool.descriptor,))
                self.assertEqual(keywords["env"], environment)
                self.assertIs(keywords["stdin"], subprocess.DEVNULL)
            finally:
                tool.close()

    def test_launcher_build_tool_identity_declares_exact_custody_boundary(self) -> None:
        with self.trusted_tool_directory() as temporary:
            root = Path(temporary)
            tool = BUILDER.open_launcher_build_tool(
                self.write_tool(root, "gcc", b"measured-compiler\n"),
                "compiler_driver",
            )
            try:
                environment = BUILDER.launcher_build_environment(
                    tool, tool, root, root / "snapshot-usr-lib"
                )
                with mock.patch.object(
                    BUILDER,
                    "run_retained_tool",
                    side_effect=[b"fixture gcc 1\n", b"aarch64-linux-gnu\n"],
                ):
                    identity = BUILDER.launcher_build_tool_identity(
                        tool,
                        environment=environment,
                        build_root=root,
                        require_target=True,
                    )
                self.assertEqual(identity["schema"], BUILDER.LAUNCHER_BUILD_TOOL_SCHEMA)
                self.assertEqual(identity["role"], "compiler_driver")
                self.assertEqual(identity["bytes"], len(b"measured-compiler\n"))
                self.assertEqual(
                    identity["sha256"], BUILDER.sha256_bytes(b"measured-compiler\n")
                )
                self.assertEqual(identity["link_count"], 1)
                self.assertEqual(identity["target"], "aarch64-linux-gnu")
                self.assertFalse(identity["complete_recursive_toolchain_closure"])
                self.assertEqual(
                    identity["execution"],
                    {
                        "mechanism": (
                            "retained_open_file_description_via_proc_self_fd"
                        ),
                        "measured_before_first_execution": True,
                        "all_invocations_used_same_open_file_description": True,
                        "descriptor_and_path_stable_after_last_execution": True,
                        "ambient_environment_inherited": False,
                        "environment_allowlist": list(
                            BUILDER.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST
                        ),
                    },
                )
            finally:
                tool.close()

    def test_launcher_pin_exists_only_in_final_daemon_build_closure(self) -> None:
        pin = "TRILLIONNIUM_P01_CODEX_LAUNCHER_SHA256"
        forbidden_roots = (
            ROOT / "crates/trillionnium-os-types",
            ROOT / "crates/trillionnium-agent-direct-tools",
            ROOT / "crates/trillionnium-tool-runtime",
        )
        for source_root in forbidden_roots:
            for path in source_root.rglob("*"):
                if path.is_file() and path.suffix in {".rs", ".toml", ".json"}:
                    self.assertNotIn(pin, path.read_text(encoding="utf-8"), str(path))

        daemon_build = (ROOT / "apps/trillionniumd/build.rs").read_text()
        daemon_identity = (
            ROOT / "apps/trillionniumd/src/builtin_provider_identity.rs"
        ).read_text()
        self.assertIn(pin, daemon_build)
        self.assertIn(pin, daemon_identity)

    def test_codex_launcher_hardening_is_fixed(self) -> None:
        codex = BUILDER.CODEX_SOURCE.read_text()
        for required in (
            "O_NOFOLLOW",
            "O_NONBLOCK",
            "same_stat",
            "PR_SET_NO_NEW_PRIVS",
            "PR_SET_DUMPABLE",
            "RLIMIT_CORE",
            "SYS_execveat",
            "AT_EMPTY_PATH",
            "SYS_close_range",
            "TRILLIONNIUM_CODEX_REQUIRE_EMPTY_GROUPS",
            "TRILLIONNIUM_CODEX_REQUIRE_ACCESSIBILITY_TOOL",
        ):
            self.assertIn(required, codex)

    def test_checked_in_p01_tools_do_not_read_registry_identity_key(self) -> None:
        BUILDER.validate_p01_identity_authority_source()

    def test_identity_authority_source_gate_rejects_registry_key_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary)
            (source_root / "p01.rs").write_text(
                "fn invalid() { let _ = CODEX.identity_key_sha256; }\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "legacy descriptor identity key"):
                BUILDER.validate_p01_identity_authority_source(source_root)

    def test_activated_payload_gate_rejects_inert_system_api(self) -> None:
        system = b"\n".join(
            (
                b"trillionnium.p0-device-conformance-activation-snapshot.v1",
                b"com.android.settings",
                b"trillionnium-agent-system-api-p0-1-device-conformance",
                b"org.trillionnium.p01.conformance.compiled-variant.v1=userdebug",
                b"System API effect lane is not compiled",
            )
        )
        replay = b"\n".join(
            (
                b"trillionnium.p0-replay-sync-ack-confirmation.v1",
                b"non_product_userdebug_daemon_custody",
                b"P0-2 sealed replay authority changed before ACTIVATE",
                b"org.trillionnium.p01.conformance.compiled-variant.v1=userdebug",
            )
        )
        with self.assertRaisesRegex(RuntimeError, "inert System API"):
            BUILDER.validate_p01_activated_payloads(
                {
                    "system_api_tool": system,
                    "replay_sync_helper": replay,
                }
            )

    def test_activated_payload_gate_accepts_exact_marker_set(self) -> None:
        BUILDER.validate_p01_activated_payloads(
            {
                "system_api_tool": b"\n".join(
                    (
                        b"trillionnium.p0-device-conformance-activation-snapshot.v1",
                        b"com.android.settings",
                        b"trillionnium-agent-system-api-p0-1-device-conformance",
                        b"org.trillionnium.p01.conformance.compiled-variant.v1=userdebug",
                    )
                ),
                "replay_sync_helper": b"\n".join(
                    (
                        b"trillionnium.p0-replay-sync-ack-confirmation.v1",
                        b"non_product_userdebug_daemon_custody",
                        b"P0-2 sealed replay authority changed before ACTIVATE",
                        b"org.trillionnium.p01.conformance.compiled-variant.v1=userdebug",
                    )
                ),
            }
        )

    def test_retired_identity_gate_rejects_every_legacy_token(self) -> None:
        for token in BUILDER.retired_identity_tokens():
            with self.subTest(token=token):
                with self.assertRaisesRegex(RuntimeError, "retired Agent identity"):
                    BUILDER.validate_no_retired_identity(
                        b"prefix-" + token.upper() + b"-suffix", "fixture"
                    )

    def test_retired_identity_gate_accepts_codex_only_payload(self) -> None:
        BUILDER.validate_no_retired_identity(
            b"openai-codex\nagent-codex-direct-v1\n5901\n", "fixture"
        )


if __name__ == "__main__":
    unittest.main()
