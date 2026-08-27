from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/build_common_codex_integrity_launcher.py"
SPEC = importlib.util.spec_from_file_location("common_codex_launcher_builder", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class CommonCodexIntegrityLauncherBuilderTests(unittest.TestCase):
    def test_import_disables_bytecode_before_loading_shared_primitives(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        assignment = source.index("sys.dont_write_bytecode = True")
        shared_import = source.index(
            "import build_p01_userdebug_agent_launchers as primitives"
        )
        self.assertLess(assignment, shared_import)

    def test_dependency_graph_is_closed_codex_only_and_acyclic(self) -> None:
        self.assertEqual(
            BUILDER.DEPENDENCY_GRAPH,
            {
                "edge_semantics": "left artifact is a build input of the right artifact",
                "edges": [
                    "codex_runtime->codex_launcher",
                    "system_api_tool->codex_launcher",
                    "accessibility_tool->codex_launcher",
                    "daemon->rootfs_package",
                    "replay_sync_helper->rootfs_package",
                    "codex_launcher->rootfs_package",
                ],
                "forbidden_edges": [
                    "codex_launcher->system_api_tool",
                    "codex_launcher->accessibility_tool",
                    "rootfs_package->daemon",
                    "rootfs_package->replay_sync_helper",
                ],
                "acyclic": True,
            },
        )

    def test_output_contract_is_common_codex_only(self) -> None:
        self.assertEqual(
            BUILDER.OUTPUT_NAMES,
            {
                "system_api_tool": "trillionnium-agent-system-api",
                "accessibility_tool": "trillionnium-agent-accessibility",
                "replay_sync_helper": "trillionnium-system-api-replay-sync",
                "daemon": "trillionniumd",
                "codex_launcher": "trillionnium-codex-agent-0.144.1",
                "receipt": "common-codex-rootfs-artifact-set.v5.json",
            },
        )
        source = MODULE_PATH.read_text(encoding="utf-8").casefold()
        self.assertNotIn("open" + "claw", source)

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

    def test_frozen_inputs_are_nonzero_lowercase_sha256(self) -> None:
        for digest in (
            BUILDER.FROZEN_CODEX_RUNTIME_SHA256,
            BUILDER.FROZEN_SYSTEM_API_SHA256,
            BUILDER.FROZEN_ACCESSIBILITY_SHA256,
            BUILDER.FROZEN_REPLAY_SYNC_SHA256,
            BUILDER.FROZEN_DAEMON_SHA256,
        ):
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotEqual(digest, "0" * 64)

    def test_frozen_inputs_match_the_reviewed_identity_rotation(self) -> None:
        self.assertEqual(
            {
                "system_api": BUILDER.FROZEN_SYSTEM_API_SHA256,
                "accessibility": BUILDER.FROZEN_ACCESSIBILITY_SHA256,
                "replay_sync": BUILDER.FROZEN_REPLAY_SYNC_SHA256,
                "daemon": BUILDER.FROZEN_DAEMON_SHA256,
            },
            {
                "system_api": "3802e114fe6f479052015dddb0ee7e02a2c70f51dea847a98e60aaddfc1f0e1a",
                "accessibility": "f79515414740b0d6c4a46f44c5b9dca0173db01cfef2dc4d9cb582ca05755064",
                "replay_sync": "6d25eedb5264be27da78f12393b0e1747706347aa11e3673cb881836e4d47268",
                "daemon": "f3345817137c227926c943d0248e05cf97379014c857a78c2e9c23d46b1ff341",
            },
        )

    def test_common_builder_uses_shared_retained_tool_custody(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        for required in (
            'open_launcher_build_tool(args.cc, "compiler_driver")',
            'open_launcher_build_tool(args.readelf, "elf_inspector")',
            "launcher_build_tool_identity(",
            "revalidate_launcher_build_tool(compiler)",
            "revalidate_launcher_build_tool(inspector)",
            '"compiler": compiler_identity',
            '"elf_inspector": inspector_identity',
            "org.trillionnium.common-codex-rootfs-artifact-set.v5",
            "finalize_output_publication(",
        ):
            self.assertIn(required, source)

    def test_common_output_publication_rejects_directory_rename_and_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir(mode=0o700)
            custody = BUILDER.primitives.open_empty_output_dir(output)
            try:
                BUILDER.primitives.write_exclusive_at(
                    custody, "artifact", b"common-artifact\n", 0o555
                )
                output.rename(root / "moved-output")
                output.mkdir(mode=0o700)
                with self.assertRaisesRegex(
                    RuntimeError, "output directory retained pathname changed"
                ):
                    BUILDER.primitives.finalize_output_publication(
                        custody, {"artifact": (b"common-artifact\n", 0o555)}
                    )
            finally:
                custody.close()

    def test_common_output_publication_rejects_final_receipt_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir(mode=0o700)
            custody = BUILDER.primitives.open_empty_output_dir(output)
            try:
                BUILDER.primitives.write_exclusive_at(
                    custody, "artifact", b"common-artifact\n", 0o555
                )
                BUILDER.primitives.write_exclusive_at(
                    custody, "receipt", b"common-receipt\n", 0o444
                )
                (output / "receipt").rename(root / "original-receipt")
                (output / "receipt").write_bytes(b"common-receipt\n")
                (output / "receipt").chmod(0o444)
                with self.assertRaisesRegex(
                    RuntimeError, "descriptor, pathname, or bytes changed"
                ):
                    BUILDER.primitives.finalize_output_publication(
                        custody,
                        {
                            "artifact": (b"common-artifact\n", 0o555),
                            "receipt": (b"common-receipt\n", 0o444),
                        },
                    )
            finally:
                custody.close()

    def test_legacy_registry_digest_loader_matches_generated_values(self) -> None:
        identity, contract_sha256, canonical_sha256 = (
            BUILDER.load_legacy_descriptor_registry_digests()
        )
        self.assertRegex(identity, r"^[0-9a-f]{64}$")
        self.assertEqual(
            contract_sha256,
            hashlib.sha256(BUILDER.LEGACY_DESCRIPTOR_CONTRACT.read_bytes()).hexdigest(),
        )
        generated = (
            ROOT / "crates/trillionnium-os-types/src/agent_descriptor_registry.rs"
        ).read_text(encoding="utf-8")
        self.assertRegex(
            generated,
            rf'pub const CANONICAL_REGISTRY_SHA256: &str =\s*"{canonical_sha256}";',
        )

    def test_stable_principal_digest_loader_matches_generated_values(self) -> None:
        contract_sha256, canonical_sha256 = (
            BUILDER.load_stable_principal_registry_digests()
        )
        self.assertEqual(
            contract_sha256,
            hashlib.sha256(BUILDER.STABLE_PRINCIPAL_CONTRACT.read_bytes()).hexdigest(),
        )
        generated = (
            ROOT / "crates/trillionnium-os-types/src/agent_principal_registry.rs"
        ).read_text(encoding="utf-8")
        self.assertRegex(
            generated,
            rf'pub const STABLE_PRINCIPAL_CANONICAL_SHA256: &str =\s*"{canonical_sha256}";',
        )

    def test_prelauncher_tools_cannot_embed_registry_derived_digests(self) -> None:
        digests = {
            "launcher identity": "a" * 64,
            "contract digest": "b" * 64,
            "canonical digest": "c" * 64,
        }
        for label, digest in digests.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(RuntimeError, f"registry {label}"):
                    BUILDER.validate_prelauncher_legacy_registry_digest_absence(
                        {
                            "system_api_tool": b"prefix" + digest.encode("ascii"),
                            "accessibility_tool": b"held-accessibility",
                        },
                        digests,
                    )
        BUILDER.validate_prelauncher_legacy_registry_digest_absence(
            {
                "system_api_tool": b"held-system-api",
                "accessibility_tool": b"held-accessibility",
            },
            digests,
        )

        build_body = MODULE_PATH.read_text(encoding="utf-8").split(
            "def build_into(", 1
        )[1].split("def parse_args()", 1)[0]
        for required_artifact in (
            '"codex_runtime": runtime',
            '"system_api_tool": system_api',
            '"accessibility_tool": accessibility',
            '"replay_sync_helper": replay_sync',
            '"daemon": daemon',
            '"launcher_source": source_bytes',
        ):
            self.assertIn(required_artifact, build_body)

    def test_launcher_identity_is_a_measured_build_output(self) -> None:
        launcher = b"deterministic-launcher"
        identity = hashlib.sha256(launcher).hexdigest()
        self.assertEqual(BUILDER.measure_launcher_identity(launcher), identity)


if __name__ == "__main__":
    unittest.main()
