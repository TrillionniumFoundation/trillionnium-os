#!/usr/bin/env python3
"""Fixture tests for the local cross-repository source BOM."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1]
SCRIPT = TOOLS / "materialize_cross_repo_source_bom.py"


def load_module():
    spec = importlib.util.spec_from_file_location("cross_repo_source_bom", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BOM = load_module()
CANONICAL_PROMPT_CONTRACT = BOM.CANONICAL_PROMPT_CONTRACT


def rust_prompt_source(
    contract: str = CANONICAL_PROMPT_CONTRACT,
    version: int = BOM.CANONICAL_PROMPT_CONTRACT_VERSION,
    extra: str = "",
) -> str:
    return (
        "pub const DIRECT_EXECUTION_PROMPT_CONTRACT: &str =\n"
        f'    "{contract}";\n'
        f"pub const DIRECT_EXECUTION_PROMPT_CONTRACT_VERSION: u64 = {version};\n"
        + extra
    )


def java_prompt_source(
    contract: str = CANONICAL_PROMPT_CONTRACT,
    version: int = BOM.CANONICAL_PROMPT_CONTRACT_VERSION,
    extra: str = "",
) -> str:
    return (
        "final class PromptFixture {\n"
        "    private static final String CODEX_PROMPT_CONTRACT =\n"
        f'            "{contract}";\n'
        f"    private static final long PROMPT_CONTRACT_VERSION = {version}L;\n"
        "}\n"
        + extra
    )


def run_git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout.decode("utf-8").strip()


def initialize_repo(root: Path) -> str:
    root.mkdir(parents=True)
    run_git(root, "init", "-q")
    (root / "source.txt").write_text("source\n", encoding="utf-8")
    run_git(root, "add", "source.txt")
    run_git(
        root,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture",
    )
    return run_git(root, "rev-parse", "HEAD")


def commit_file(root: Path, relative: str, content: str | bytes, message: str) -> str:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        destination.write_bytes(content)
    else:
        destination.write_text(content, encoding="utf-8")
    run_git(root, "add", "--", relative)
    run_git(
        root,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        message,
    )
    return run_git(root, "rev-parse", "HEAD")


def write_variant_elf(path: Path, variant: str) -> None:
    marker = (
        "org.trillionnium.p01.conformance.compiled-variant.v1=" + variant
    ).encode("ascii")
    assert len(marker) < 96
    payload = marker + b"\x00" * (96 - len(marker))
    names = b"\x00.shstrtab\x00.trillionnium.p01.variant\x00"
    program_offset = 64
    names_offset = program_offset + 56
    payload_offset = (names_offset + len(names) + 7) & ~7
    sections_offset = (payload_offset + len(payload) + 7) & ~7
    total = sections_offset + 3 * 64
    raw = bytearray(total)
    raw[:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        raw,
        16,
        2,
        183,
        1,
        0x10000,
        program_offset,
        sections_offset,
        0,
        64,
        56,
        1,
        64,
        3,
        1,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        raw,
        program_offset,
        1,
        5,
        0,
        0x10000,
        0x10000,
        total,
        total,
        0x1000,
    )
    raw[names_offset : names_offset + len(names)] = names
    raw[payload_offset : payload_offset + len(payload)] = payload
    struct.pack_into(
        "<IIQQQQIIQQ",
        raw,
        sections_offset + 64,
        1,
        3,
        0,
        0,
        names_offset,
        len(names),
        0,
        0,
        1,
        0,
    )
    struct.pack_into(
        "<IIQQQQIIQQ",
        raw,
        sections_offset + 128,
        len(b"\x00.shstrtab\x00"),
        1,
        2,
        0x10000 + payload_offset,
        payload_offset,
        len(payload),
        0,
        0,
        1,
        0,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o755)


def write_tree_file(path: Path, content: bytes) -> None:
    path.touch(mode=0o644, exist_ok=False)
    path.write_bytes(content)


class CrossRepoSourceBomTests(unittest.TestCase):
    def test_bounded_command_timeout_does_not_wait_for_child_cleanup(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(BOM.BomError, "slow command failed"):
            BOM.bounded_command(
                [
                    "/usr/bin/python3",
                    "-c",
                    "import time; time.sleep(30)",
                ],
                Path("/tmp"),
                "slow command",
                1024,
                timeout=1,
            )
        self.assertLess(time.monotonic() - started, 5.0)

    def test_bounded_command_enforces_stdout_bound(self) -> None:
        with self.assertRaisesRegex(BOM.BomError, "large command exceeds output bound"):
            BOM.bounded_command(
                [
                    "/usr/bin/python3",
                    "-c",
                    "print('x' * 4096)",
                ],
                Path("/tmp"),
                "large command",
                128,
                timeout=5,
            )

    def test_bounded_command_disables_repo_trace_mutation(self) -> None:
        output = BOM.bounded_command(
            [
                "/usr/bin/python3",
                "-c",
                "import os; print(os.environ['REPO_TRACE'])",
            ],
            Path("/tmp"),
            "repo trace environment",
            128,
            timeout=5,
        )
        self.assertEqual(output, b"0\n")

    def test_bounded_command_accepts_explicit_nonzero_status(self) -> None:
        output = BOM.bounded_command(
            [
                "/usr/bin/python3",
                "-c",
                "import sys; print('detached'); sys.exit(1)",
            ],
            Path("/tmp"),
            "detached-head probe",
            128,
            timeout=5,
            allowed_returncodes=(0, 1),
        )
        self.assertEqual(output, b"detached\n")

    def test_strict_regular_bytes_rejects_symlinked_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="strict-source-parent.") as temporary:
            root = Path(temporary)
            real_parent = root / "real"
            real_parent.mkdir()
            source = real_parent / "source.json"
            source.write_bytes(b"source\n")
            alias = root / "alias"
            alias.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(BOM.BomError, "symlink"):
                BOM.strict_regular_bytes(alias / "source.json", "source", 1024)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="trillionnium-cross-repo-bom-test."
        )
        self.root = Path(self.temporary.name)
        self.android = self.root / "android"
        self.android.mkdir()
        self.control = self.root / "control"
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.vendor = self.android / "vendor/trillionnium"
        self.control_head = initialize_repo(self.control)
        self.control_prompt_path = (
            "trillionnium-os/crates/trillionnium-tool-runtime/src/"
            "supervised_codex.rs"
        )
        self.control_head = commit_file(
            self.control,
            self.control_prompt_path,
            rust_prompt_source(),
            "prompt tuple",
        )
        self.ai_shell = self.android / "packages/apps/TrillionniumAiShell"
        initialize_repo(self.ai_shell)
        self.ai_shell_prompt_path = (
            "src/org/trillionnium/aishell/AiShellActivity.java"
        )
        self.ai_shell_head = commit_file(
            self.ai_shell,
            self.ai_shell_prompt_path,
            java_prompt_source(),
            "prompt tuple",
        )
        self.ai_authority = self.android / "packages/apps/TrillionniumAiAuthority"
        initialize_repo(self.ai_authority)
        self.ai_authority_prompt_path = (
            "src/org/trillionnium/aiauthority/EgressConsentActivity.java"
        )
        self.ai_authority_head = commit_file(
            self.ai_authority,
            self.ai_authority_prompt_path,
            java_prompt_source(),
            "prompt tuple",
        )
        self.vendor_head = initialize_repo(self.vendor)
        motorola = self.android / "vendor/motorola"
        motorola.mkdir(parents=True, mode=0o755)
        self.fogos_blobs = motorola / "fogos"
        self.fogos_blobs.mkdir(mode=0o755)
        write_tree_file(self.fogos_blobs / "blob.bin", b"fogos-blob\n")
        os.link(self.fogos_blobs / "blob.bin", self.fogos_blobs / "blob-hardlink.bin")
        (self.fogos_blobs / "links").mkdir(mode=0o755)
        os.symlink("../blob.bin", self.fogos_blobs / "links/blob.bin")
        self.common_blobs = motorola / "sm6375-common"
        self.common_blobs.mkdir(mode=0o755)
        write_tree_file(self.common_blobs / "common.bin", b"common-blob\n")
        self.artifact_relative = "device-conformance"
        write_variant_elf(self.artifacts / self.artifact_relative, "userdebug")
        self.contract_value = {
            "schema": BOM.CONTRACT_SCHEMA,
            "projects": [
                {
                    "id": "control_plane",
                    "checkout_root": "control",
                    "checkout_path": ".",
                    "manifest_required": False,
                    "manifest_path": None,
                    "expected_manifest_name": None,
                    "require_clean": True,
                    "require_no_ignored": True,
                },
                {
                    "id": "vendor_trillionnium",
                    "checkout_root": "android",
                    "checkout_path": "vendor/trillionnium",
                    "manifest_required": True,
                    "manifest_path": "vendor/trillionnium",
                    "expected_manifest_name": (
                        "TrillionniumFoundation/android-vendor-trillionnium"
                    ),
                    "require_clean": True,
                    "require_no_ignored": True,
                },
                {
                    "id": "ai_shell",
                    "checkout_root": "android",
                    "checkout_path": "packages/apps/TrillionniumAiShell",
                    "manifest_required": True,
                    "manifest_path": "packages/apps/TrillionniumAiShell",
                    "expected_manifest_name": "Fixture/android-ai-shell",
                    "require_clean": True,
                    "require_no_ignored": True,
                },
                {
                    "id": "ai_authority",
                    "checkout_root": "android",
                    "checkout_path": "packages/apps/TrillionniumAiAuthority",
                    "manifest_required": True,
                    "manifest_path": "packages/apps/TrillionniumAiAuthority",
                    "expected_manifest_name": "Fixture/android-ai-authority",
                    "require_clean": True,
                    "require_no_ignored": True,
                },
            ],
            "trees": [
                {
                    "id": "vendor_motorola_fogos_blobs",
                    "checkout_root": "android",
                    "path": "vendor/motorola/fogos",
                    "required": True,
                    "entry_limit": 100,
                    "byte_limit": 1024 * 1024,
                    "mode_policy": BOM.TREE_MODE_POLICY,
                },
                {
                    "id": "vendor_motorola_sm6375_common_blobs",
                    "checkout_root": "android",
                    "path": "vendor/motorola/sm6375-common",
                    "required": True,
                    "entry_limit": 100,
                    "byte_limit": 1024 * 1024,
                    "mode_policy": BOM.TREE_MODE_POLICY,
                },
            ],
            "artifacts": [
                {
                    "id": "device_conformance",
                    "checkout_root": "artifacts",
                    "path": self.artifact_relative,
                    "required": True,
                    "lane": "non_product_userdebug_only",
                    "embedded_variant": "userdebug",
                    "variant_section": ".trillionnium.p01.variant",
                    "release_pin": False,
                }
            ],
        }
        self.contract = self.root / "contract.json"
        self.write_contract(self.contract_value)
        self.manifest = self.root / "manifest.xml"
        self.write_manifest(include_vendor=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_contract(self, value: dict[str, object]) -> None:
        self.contract.write_bytes(BOM.canonical_json_bytes(value))

    def write_manifest(self, *, include_vendor: bool) -> None:
        projects = ""
        if include_vendor:
            projects = (
                '<project name="TrillionniumFoundation/android-vendor-trillionnium" '
                'path="vendor/trillionnium" revision="'
                + self.vendor_head
                + '" remote="canonical"/>\n'
            )
        else:
            projects = (
                '<project name="AOSP/platform-build" path="build/make" revision="'
                + self.vendor_head
                + '" remote="canonical"/>\n'
            )
        projects += (
            '<project name="Fixture/android-ai-shell" '
            'path="packages/apps/TrillionniumAiShell" revision="'
            + self.ai_shell_head
            + '" remote="canonical"/>\n'
            '<project name="Fixture/android-ai-authority" '
            'path="packages/apps/TrillionniumAiAuthority" revision="'
            + self.ai_authority_head
            + '" remote="canonical"/>\n'
        )
        self.manifest.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<manifest>\n'
            '  <remote name="canonical" fetch="https://github.com"/>\n'
            + projects
            + '</manifest>\n',
            encoding="utf-8",
        )

    def commit_prompt(self, role: str, content: str | bytes) -> None:
        roots = {
            "control_plane": (self.control, self.control_prompt_path, "control_head"),
            "ai_shell": (self.ai_shell, self.ai_shell_prompt_path, "ai_shell_head"),
            "ai_authority": (
                self.ai_authority,
                self.ai_authority_prompt_path,
                "ai_authority_head",
            ),
        }
        root, relative, head_attribute = roots[role]
        head = commit_file(root, relative, content, "prompt tuple mutation")
        setattr(self, head_attribute, head)
        self.write_manifest(include_vendor=True)

    def measure(self) -> dict[str, object]:
        return BOM.measure(
            self.contract,
            self.android,
            self.control,
            self.artifacts,
            self.manifest,
        )

    def write_manifest_receipt(self, *, producer: str = "local_repo_manifest_direct_pinned") -> Path:
        raw = self.manifest.read_bytes()
        resolved_manifest = self.android / ".repo/manifests/fixture.xml"
        resolved_manifest.parent.mkdir(parents=True, exist_ok=True)
        resolved_manifest.write_bytes(raw)
        root = BOM.ET.fromstring(raw)
        projects = []
        for project in root.findall("project"):
            path = project.get("path", project.get("name", ""))
            revision = project.get("revision", "")
            projects.append(
                {
                    "path": path,
                    "name": project.get("name", ""),
                    "declared_revision": revision,
                    "resolved_revision": revision,
                    "head_kind": "detached",
                }
            )
        receipt: dict[str, object] = {
            "schema": BOM.MANIFEST_RESOLUTION_RECEIPT_SCHEMA,
            "decision": BOM.MANIFEST_RESOLUTION_PASS,
            "authority": "local_source_provenance_not_release_authority",
            "release_allowed": False,
            "producer": producer,
            "resolution_mode": "static_manifest_all_project_heads_exact",
            "android_root": str(self.android.resolve()),
            "manifest_path": str(resolved_manifest.resolve()),
            "manifest_bytes": len(raw),
            "manifest_sha256": BOM.sha256_bytes(raw),
            "project_count": len(projects),
            "projects": projects,
        }
        receipt["receipt_id"] = "sha256:" + BOM.sha256_bytes(
            BOM.canonical_json_bytes(receipt)
        )
        path = self.root / "manifest-receipt.json"
        path.write_bytes(BOM.canonical_json_bytes(receipt))
        self.provenance_manifest = resolved_manifest
        return path

    def test_clean_exact_graph_and_variant_section_pass_deterministically(self) -> None:
        first = self.measure()
        second = self.measure()
        self.assertEqual(first, second)
        self.assertEqual(first["decision"], BOM.PASS)
        self.assertEqual(first["schema"], BOM.RECEIPT_SCHEMA_V2)
        self.assertEqual(first["blockers"], [])
        self.assertEqual(
            set(first),
            {
                "schema",
                "decision",
                "posture",
                "source_set",
                "resolved_manifest",
                "projects",
                "trees",
                "artifacts",
                "blockers",
                "receipt_id_scope",
                "receipt_id",
            },
        )
        self.assertTrue(all(project["git"]["clean_nonignored"] for project in first["projects"]))
        self.assertEqual(len(first["trees"]), 2)
        fogos = first["trees"][0]["inventory"]
        self.assertTrue(fogos["stable_remeasurement_passed"])
        self.assertEqual(
            fogos["addressed_bytes"],
            fogos["regular_file_logical_bytes"] + fogos["symlink_target_bytes"],
        )
        self.assertEqual(fogos["type_counts"]["hardlink"], 1)
        self.assertEqual(fogos["type_counts"]["symlink"], 1)
        artifact = first["artifacts"][0]
        self.assertFalse(artifact["release_pin"])
        self.assertEqual(
            artifact["elf"]["compiled_variant_section"]["marker"],
            "org.trillionnium.p01.conformance.compiled-variant.v1=userdebug",
        )
        unsigned = dict(first)
        receipt_id = unsigned.pop("receipt_id")
        self.assertEqual(
            receipt_id,
            "sha256:" + BOM.sha256_bytes(BOM.canonical_json_bytes(unsigned)),
        )

    def test_v1_contract_and_receipt_remain_legacy_compatible(self) -> None:
        value = copy.deepcopy(self.contract_value)
        value["schema"] = BOM.CONTRACT_SCHEMA_V1
        del value["trees"]
        self.write_contract(value)
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.PASS)
        self.assertEqual(receipt["schema"], BOM.RECEIPT_SCHEMA_V1)
        self.assertEqual(receipt["source_set"]["schema"], BOM.CONTRACT_SCHEMA_V1)
        self.assertNotIn("trees", receipt)
        self.assertNotIn("observed_tree_hashes_are_release_pins", receipt["posture"])
        self.assertEqual(
            set(receipt),
            {
                "schema",
                "decision",
                "posture",
                "source_set",
                "resolved_manifest",
                "projects",
                "artifacts",
                "blockers",
                "receipt_id_scope",
                "receipt_id",
            },
        )

    def test_prompt_tuple_uses_captured_head_not_dirty_worktree(self) -> None:
        (self.control / self.control_prompt_path).write_text(
            rust_prompt_source("trillionnium.codex-dirty-worktree-prompt.v9", 9),
            encoding="utf-8",
        )
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertIn(
            "project_nonignored_worktree_dirty:control_plane", receipt["blockers"]
        )
        self.assertNotIn(BOM.PROMPT_TUPLE_BLOCKER, receipt["blockers"])

    def test_prompt_tuple_mismatch_is_single_stable_hold_blocker(self) -> None:
        self.commit_prompt(
            "control_plane",
            rust_prompt_source("trillionnium.codex-mismatched-prompt.v3", 3),
        )
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertEqual(receipt["blockers"], [BOM.PROMPT_TUPLE_BLOCKER])

    def test_equal_noncanonical_prompt_tuple_is_hold(self) -> None:
        contract = "trillionnium.codex-equal-but-noncanonical-prompt.v3"
        self.commit_prompt("control_plane", rust_prompt_source(contract, 3))
        self.commit_prompt("ai_shell", java_prompt_source(contract, 3))
        self.commit_prompt("ai_authority", java_prompt_source(contract, 3))
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertEqual(receipt["blockers"], [BOM.PROMPT_TUPLE_BLOCKER])

    def test_prompt_contract_suffix_must_agree_with_numeric_version(self) -> None:
        contract = "trillionnium.codex-p0-system-api-shell-exec-prompt.v4"
        self.commit_prompt("control_plane", rust_prompt_source(contract, 3))
        self.commit_prompt("ai_shell", java_prompt_source(contract, 3))
        self.commit_prompt("ai_authority", java_prompt_source(contract, 3))
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertEqual(receipt["blockers"], [BOM.PROMPT_TUPLE_BLOCKER])

    def test_duplicate_live_prompt_declaration_is_hold(self) -> None:
        duplicate = (
            "pub const DIRECT_EXECUTION_PROMPT_CONTRACT: &str = "
            f'"{CANONICAL_PROMPT_CONTRACT}";\n'
            "pub const DIRECT_EXECUTION_PROMPT_CONTRACT_VERSION: u64 = 3;\n"
        )
        self.commit_prompt("control_plane", rust_prompt_source(extra=duplicate))
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertEqual(receipt["blockers"], [BOM.PROMPT_TUPLE_BLOCKER])

    def test_invalid_utf8_prompt_blob_is_hold(self) -> None:
        self.commit_prompt(
            "control_plane", rust_prompt_source().encode("utf-8") + b"\xff\n"
        )
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertEqual(receipt["blockers"], [BOM.PROMPT_TUPLE_BLOCKER])

    def test_nul_in_prompt_blob_is_hold(self) -> None:
        self.commit_prompt(
            "control_plane", rust_prompt_source().encode("utf-8") + b"\x00\n"
        )
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertEqual(receipt["blockers"], [BOM.PROMPT_TUPLE_BLOCKER])

    def test_oversized_prompt_blob_is_rejected_before_blob_retrieval(self) -> None:
        content = rust_prompt_source().encode("utf-8")
        content += b" " * (BOM.MAX_PROMPT_SOURCE_BYTES + 1 - len(content))
        self.commit_prompt("control_plane", content)
        with mock.patch.object(BOM, "git", wraps=BOM.git) as observed_git:
            receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertEqual(receipt["blockers"], [BOM.PROMPT_TUPLE_BLOCKER])
        prompt_blob_reads = [
            call
            for call in observed_git.call_args_list
            if len(call.args) > 1
            and list(call.args[1][:2]) == ["cat-file", "blob"]
            and self.control_prompt_path in str(call.args[1][2])
        ]
        self.assertEqual(prompt_blob_reads, [])

    def test_missing_prompt_blob_is_hold(self) -> None:
        run_git(self.control, "rm", "--", self.control_prompt_path)
        run_git(
            self.control,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            "remove prompt source",
        )
        self.control_head = run_git(self.control, "rev-parse", "HEAD")
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertEqual(receipt["blockers"], [BOM.PROMPT_TUPLE_BLOCKER])

    def test_prompt_declarations_inside_comments_are_not_live_duplicates(self) -> None:
        commented_fakes = (
            "// pub const DIRECT_EXECUTION_PROMPT_CONTRACT: &str = "
            '"trillionnium.codex-comment-fake.v8";\n'
            "// pub const DIRECT_EXECUTION_PROMPT_CONTRACT_VERSION: u64 = 8;\n"
            "/* pub const DIRECT_EXECUTION_PROMPT_CONTRACT: &str = "
            '"trillionnium.codex-block-comment-fake.v7";\n'
            "pub const DIRECT_EXECUTION_PROMPT_CONTRACT_VERSION: u64 = 7; */\n"
        )
        self.commit_prompt(
            "control_plane", rust_prompt_source(extra=commented_fakes)
        )
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.PASS)
        self.assertEqual(receipt["blockers"], [])

    def test_stable_tree_tamper_changes_digest_and_receipt_identity(self) -> None:
        before = self.measure()
        (self.fogos_blobs / "blob.bin").write_bytes(b"fogos-blob-tampered\n")
        after = self.measure()
        self.assertEqual(after["decision"], BOM.PASS)
        self.assertNotEqual(
            before["trees"][0]["inventory"]["sha256"],
            after["trees"][0]["inventory"]["sha256"],
        )
        self.assertNotEqual(before["receipt_id"], after["receipt_id"])

    def test_tree_tamper_between_remeasurements_is_hold(self) -> None:
        original = BOM._measure_source_tree_once
        changed = False

        def measure_and_tamper(root: Path, item: dict[str, object]) -> dict[str, object]:
            nonlocal changed
            result = original(root, item)
            if item["id"] == "vendor_motorola_fogos_blobs" and not changed:
                changed = True
                (self.fogos_blobs / "blob.bin").write_bytes(b"changed-between-runs\n")
            return result

        with mock.patch.object(BOM, "_measure_source_tree_once", side_effect=measure_and_tamper):
            receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertIn(
            "tree_unavailable_unsafe_or_unstable:vendor_motorola_fogos_blobs",
            receipt["blockers"],
        )
        self.assertIsNone(receipt["trees"][0]["inventory"])

    def test_tree_symlink_escape_is_hold(self) -> None:
        os.symlink("../../../../outside", self.fogos_blobs / "escape")
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertIn(
            "tree_unavailable_unsafe_or_unstable:vendor_motorola_fogos_blobs",
            receipt["blockers"],
        )

    def test_tree_special_file_is_hold(self) -> None:
        os.mkfifo(self.common_blobs / "forbidden-fifo")
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertIn(
            "tree_unavailable_unsafe_or_unstable:vendor_motorola_sm6375_common_blobs",
            receipt["blockers"],
        )

    def test_dirty_untracked_and_ignored_state_is_exactly_held(self) -> None:
        (self.control / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        run_git(self.control, "add", ".gitignore")
        run_git(
            self.control,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            "ignore contract",
        )
        (self.control / "source.txt").write_text("changed\n", encoding="utf-8")
        (self.control / "untracked.txt").write_bytes(b"untracked\n")
        (self.control / "ignored").mkdir()
        (self.control / "ignored/generated.bin").write_bytes(b"ignored\n")
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertIn(
            "project_nonignored_worktree_dirty:control_plane", receipt["blockers"]
        )
        self.assertIn("project_ignored_paths_present:control_plane", receipt["blockers"])
        control = receipt["projects"][0]["git"]
        self.assertEqual(control["untracked"]["count"], 1)
        self.assertEqual(
            control["untracked"]["entries"][0]["sha256"],
            BOM.sha256_bytes(b"untracked\n"),
        )
        self.assertEqual(control["ignored"]["paths"], ["ignored/"])
        self.assertGreater(control["tracked_diff"]["bytes"], 0)

    def test_missing_manifest_project_is_hold(self) -> None:
        self.write_manifest(include_vendor=False)
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertIn(
            "project_required_manifest_project_missing:vendor_trillionnium",
            receipt["blockers"],
        )

    def test_strict_supplied_manifest_lane_requires_provenance_receipt(self) -> None:
        with self.assertRaisesRegex(
            BOM.BomError, "provenance receipt is required"
        ):
            BOM.measure(
                self.contract,
                self.android,
                self.control,
                self.artifacts,
                self.manifest,
                None,
                True,
            )

    def test_manifest_provenance_receipt_binds_supplied_bytes(self) -> None:
        receipt_path = self.write_manifest_receipt()
        measured = BOM.measure(
            self.contract,
            self.android,
            self.control,
            self.artifacts,
            self.provenance_manifest,
            receipt_path,
            True,
        )
        self.assertEqual(measured["decision"], BOM.PASS)
        self.assertEqual(
            measured["resolved_manifest"]["producer"],
            "local_repo_manifest_direct_pinned",
        )

    def test_manifest_provenance_digest_tamper_is_rejected(self) -> None:
        receipt_path = self.write_manifest_receipt()
        value = json.loads(receipt_path.read_text(encoding="utf-8"))
        value["manifest_sha256"] = "0" * 64
        receipt_path.write_bytes(BOM.canonical_json_bytes(value))
        with self.assertRaisesRegex(BOM.BomError, "digest differs"):
            BOM.measure(
                self.contract,
                self.android,
                self.control,
                self.artifacts,
                self.provenance_manifest,
                receipt_path,
                True,
            )

    def test_cli_strict_manifest_provenance_accepts_resolver_receipt(self) -> None:
        receipt_path = self.write_manifest_receipt()
        output = self.root / "cli-source-bom.json"
        status = BOM.main(
            [
                "--android-root",
                str(self.android),
                "--control-root",
                str(self.control),
                "--artifact-root",
                str(self.artifacts),
                "--contract",
                str(self.contract),
                "--resolved-manifest",
                str(self.provenance_manifest),
                "--resolved-manifest-receipt",
                str(receipt_path),
                "--require-resolved-manifest-provenance",
                "--output",
                str(output),
            ]
        )
        self.assertEqual(status, 0)
        value = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            value["resolved_manifest"]["producer"],
            "local_repo_manifest_direct_pinned",
        )

    def test_cli_strict_manifest_provenance_rejects_regular_file_without_receipt(
        self,
    ) -> None:
        output = self.root / "cli-source-bom.json"
        status = BOM.main(
            [
                "--android-root",
                str(self.android),
                "--control-root",
                str(self.control),
                "--artifact-root",
                str(self.artifacts),
                "--contract",
                str(self.contract),
                "--resolved-manifest",
                str(self.manifest),
                "--require-resolved-manifest-provenance",
                "--output",
                str(output),
            ]
        )
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())

    def test_cli_strict_manifest_provenance_rejects_tampered_receipt(self) -> None:
        receipt_path = self.write_manifest_receipt()
        value = json.loads(receipt_path.read_text(encoding="utf-8"))
        value["receipt_id"] = "sha256:" + "0" * 64
        receipt_path.write_bytes(BOM.canonical_json_bytes(value))
        output = self.root / "cli-source-bom.json"
        status = BOM.main(
            [
                "--android-root",
                str(self.android),
                "--control-root",
                str(self.control),
                "--artifact-root",
                str(self.artifacts),
                "--contract",
                str(self.contract),
                "--resolved-manifest",
                str(self.provenance_manifest),
                "--resolved-manifest-receipt",
                str(receipt_path),
                "--require-resolved-manifest-provenance",
                "--output",
                str(output),
            ]
        )
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())

    def test_repo_resolved_checkout_drift_from_declared_pin_is_hold(self) -> None:
        raw = self.manifest.read_text(encoding="utf-8")
        raw = raw.replace(
            ' remote="canonical"/>',
            ' remote="canonical" upstream="' + "a" * 40 + '" '
            'dest-branch="' + "a" * 40 + '"/>',
            1,
        )
        self.manifest.write_text(raw, encoding="utf-8")
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertIn(
            "resolved_manifest_checkout_differs_from_declared_revisions",
            receipt["blockers"],
        )
        self.assertIn(
            "project_manifest_checkout_revision_drift:vendor_trillionnium",
            receipt["blockers"],
        )
        self.assertEqual(
            receipt["resolved_manifest"]["declared_checkout_revision_drifts"],
            [
                {
                    "path": "vendor/trillionnium",
                    "declared_revision": "a" * 40,
                    "checkout_revision": self.vendor_head,
                }
            ],
        )

    def test_wrong_compiled_variant_section_is_hold(self) -> None:
        write_variant_elf(self.artifacts / self.artifact_relative, "eng")
        receipt = self.measure()
        self.assertEqual(receipt["decision"], BOM.HOLD)
        self.assertIn("artifact_invalid:device_conformance", receipt["blockers"])
        self.assertIsNone(receipt["artifacts"][0]["elf"])

    def test_unknown_contract_key_is_rejected(self) -> None:
        value = copy.deepcopy(self.contract_value)
        value["unknown"] = True
        self.write_contract(value)
        with self.assertRaisesRegex(BOM.BomError, "keys differ"):
            self.measure()

    def test_artifact_may_not_be_measured_from_a_source_checkout(self) -> None:
        value = copy.deepcopy(self.contract_value)
        value["artifacts"][0]["checkout_root"] = "control"
        self.write_contract(value)
        with self.assertRaisesRegex(BOM.BomError, "out-of-tree artifact root"):
            self.measure()

    def test_output_inside_measured_checkout_is_rejected_before_measurement(self) -> None:
        output = self.control / "receipt.json"
        status = BOM.main(
            [
                "--android-root",
                str(self.android),
                "--control-root",
                str(self.control),
                "--artifact-root",
                str(self.artifacts),
                "--contract",
                str(self.contract),
                "--resolved-manifest",
                str(self.manifest),
                "--output",
                str(output),
            ]
        )
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())

    def test_output_inside_artifact_root_is_rejected_before_measurement(self) -> None:
        output = self.artifacts / "receipt.json"
        status = BOM.main(
            [
                "--android-root",
                str(self.android),
                "--control-root",
                str(self.control),
                "--artifact-root",
                str(self.artifacts),
                "--contract",
                str(self.contract),
                "--resolved-manifest",
                str(self.manifest),
                "--output",
                str(output),
            ]
        )
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
