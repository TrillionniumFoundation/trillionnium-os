#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import selectors
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
PACKAGE_ROOT = HERE.parent
sys.path.insert(0, str(PACKAGE_ROOT))

import build_operation_replay_sync_static as contract  # noqa: E402


RECIPE = PACKAGE_ROOT / "operation-replay-sync-static-recipe-v1.json"


def make_static_aarch64_elf(text_word: int = 0xD503201F) -> bytes:
    """Create a bounded static AArch64 ET_EXEC fixture with 64K separation."""

    program_offset = 64
    program_count = 4
    text_offset = 0x10000
    data_offset = 0x20000
    names_offset = 0x20100
    section_offset = 0x20200
    section_count = 4
    total = section_offset + section_count * 64
    blob = bytearray(total)
    blob[:16] = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        blob,
        16,
        2,
        183,
        1,
        0x410000,
        program_offset,
        section_offset,
        0,
        64,
        56,
        program_count,
        64,
        section_count,
        3,
    )
    programs = [
        (contract.PT_LOAD, contract.PF_R, 0, 0x400000, 0x400000, 0x1000, 0x1000, 0x10000),
        (
            contract.PT_LOAD,
            contract.PF_R | contract.PF_X,
            text_offset,
            0x410000,
            0x410000,
            0x100,
            0x100,
            0x10000,
        ),
        (
            contract.PT_LOAD,
            contract.PF_R | contract.PF_W,
            data_offset,
            0x420000,
            0x420000,
            0x100,
            0x200,
            0x10000,
        ),
        (contract.PT_GNU_STACK, contract.PF_R | contract.PF_W, 0, 0, 0, 0, 0, 16),
    ]
    for index, program in enumerate(programs):
        struct.pack_into("<IIQQQQQQ", blob, program_offset + index * 56, *program)
    struct.pack_into("<I", blob, text_offset, text_word)
    blob[data_offset] = 0x5A
    names = b"\0.text\0.data\0.shstrtab\0"
    blob[names_offset : names_offset + len(names)] = names
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 0x6, 0x410000, text_offset, 4, 0, 0, 4, 0),
        (7, 1, 0x3, 0x420000, data_offset, 1, 0, 0, 1, 0),
        (13, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
    ]
    for index, section in enumerate(sections):
        struct.pack_into("<IIQQQQIIQQ", blob, section_offset + index * 64, *section)
    return bytes(blob)


def mutate_u16(blob: bytes, offset: int, value: int) -> bytes:
    result = bytearray(blob)
    struct.pack_into("<H", result, offset, value)
    return bytes(result)


def mutate_u32(blob: bytes, offset: int, value: int) -> bytes:
    result = bytearray(blob)
    struct.pack_into("<I", result, offset, value)
    return bytes(result)


def mutate_u64(blob: bytes, offset: int, value: int) -> bytes:
    result = bytearray(blob)
    struct.pack_into("<Q", result, offset, value)
    return bytes(result)


class FaultSelector:
    def __init__(self, fault: str):
        self.fault = fault
        self.inner = selectors.DefaultSelector()

    def register(self, fileobj: object, events: int) -> object:
        if self.fault == "register":
            raise RuntimeError("selector register fault")
        return self.inner.register(fileobj, events)

    def unregister(self, fileobj: object) -> object:
        return self.inner.unregister(fileobj)

    def select(self, timeout: float | None = None) -> object:
        if self.fault == "select":
            raise RuntimeError("selector select fault")
        return self.inner.select(timeout)

    def close(self) -> None:
        self.inner.close()
        if self.fault == "close":
            raise RuntimeError("selector close fault")


class RecipeTests(unittest.TestCase):
    def test_checked_in_recipe_is_exact_source_hold(self) -> None:
        recipe, digest = contract.load_recipe(RECIPE)
        self.assertEqual(recipe["source_checkpoint"], contract.CHECKPOINT_FALSE)
        self.assertEqual(recipe["authority"], contract.AUTHORITY_FALSE)
        self.assertEqual(recipe["reconcile_contract"]["profiles"], list(contract.PROFILES))
        self.assertEqual(len(digest), 64)

    def test_recipe_rejects_any_authority_flip(self) -> None:
        recipe, _ = contract.load_recipe(RECIPE)
        changed = copy.deepcopy(recipe)
        changed["authority"]["installable"] = True
        with self.assertRaisesRegex(contract.ContractError, "authority"):
            contract.verify_recipe(changed)

    def test_build_requires_explicit_source_only_ack_before_any_input(self) -> None:
        args = argparse.Namespace(
            acknowledge_non_authorizing_source_only=False,
            recipe=Path("/does/not/exist/recipe.json"),
            profile="amd64-cross",
            source_root=Path("/does/not/exist"),
            vendor_dir=Path("/does/not/exist"),
            image_receipt=Path("/does/not/exist"),
            toolchain_receipt=Path("/does/not/exist"),
            output=Path("/does/not/exist"),
        )
        with self.assertRaisesRegex(contract.ContractError, "explicit non-authorizing"):
            contract.build_candidate(args)

    def test_acknowledged_build_is_fixed_cgroup_and_journal_hold_before_inputs(self) -> None:
        args = argparse.Namespace(
            acknowledge_non_authorizing_source_only=True,
            recipe=Path("/does/not/exist/recipe.json"),
            profile="amd64-cross",
            source_root=Path("/does/not/exist"),
            vendor_dir=Path("/does/not/exist"),
            image_receipt=Path("/does/not/exist"),
            toolchain_receipt=Path("/does/not/exist"),
            output=Path("/does/not/exist"),
        )
        observed: list[subprocess.Popen[bytes]] = []
        original_observer = contract._PROCESS_OBSERVER
        original_recipe_loader = contract.load_recipe
        recipe_loads: list[Path] = []

        def forbidden_recipe_load(path: Path) -> tuple[dict[str, object], str]:
            recipe_loads.append(path)
            raise AssertionError("fixed HOLD tried to open its recipe")

        contract._PROCESS_OBSERVER = observed.append
        contract.load_recipe = forbidden_recipe_load
        try:
            with self.assertRaisesRegex(
                contract.ContractError, "cgroup-v2.*publication journal"
            ):
                contract.build_candidate(args)
        finally:
            contract._PROCESS_OBSERVER = original_observer
            contract.load_recipe = original_recipe_loader
        self.assertEqual(observed, [])
        self.assertEqual(recipe_loads, [])

    def test_cli_has_no_implicit_build_command(self) -> None:
        script = PACKAGE_ROOT / "build_operation_replay_sync_static.py"
        result = subprocess.run(
            [sys.executable, str(script)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"cargo build", result.stdout + result.stderr)

    def test_bounded_empty_environment_runner_records_and_limits_log(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-runner.") as temporary:
            root = Path(temporary)
            result = contract._bounded_build(
                [sys.executable, "-c", "print('fixed-log')"], root, {}, root / "ok.log"
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["size"], len(b"fixed-log\n"))
            original_limit = contract.MAX_BUILD_LOG_BYTES
            contract.MAX_BUILD_LOG_BYTES = 32
            try:
                with self.assertRaisesRegex(contract.ContractError, "byte limit"):
                    contract._bounded_build(
                        [sys.executable, "-c", "print('x' * 1024)"],
                        root,
                        {},
                        root / "overflow.log",
                    )
            finally:
                contract.MAX_BUILD_LOG_BYTES = original_limit

    def _assert_runner_fault_reaps(
        self,
        root: Path,
        log_name: str,
        configure: object,
        *,
        short_child: bool = False,
    ) -> None:
        original_factory = contract._SELECTOR_FACTORY
        original_read = contract._READ_FD
        original_close = contract._CLOSE_FD
        original_observer = contract._PROCESS_OBSERVER
        observed: list[subprocess.Popen[bytes]] = []
        contract._PROCESS_OBSERVER = observed.append
        try:
            configure()
            source = "print('ready', flush=True)"
            if not short_child:
                source += "; import time; time.sleep(60)"
            with self.assertRaises(contract.ContractError):
                contract._bounded_build(
                    [sys.executable, "-c", source],
                    root,
                    {},
                    root / log_name,
                )
        finally:
            contract._SELECTOR_FACTORY = original_factory
            contract._READ_FD = original_read
            contract._CLOSE_FD = original_close
            contract._PROCESS_OBSERVER = original_observer
        self.assertEqual(len(observed), 1)
        pid = observed[0].pid
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        with self.assertRaises(ProcessLookupError):
            os.killpg(pid, 0)

    def test_runner_reaps_on_selector_constructor_register_select_and_read_faults(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-runner-faults.") as temporary:
            root = Path(temporary)

            def constructor_fault() -> None:
                def fail() -> object:
                    raise RuntimeError("selector constructor fault")

                contract._SELECTOR_FACTORY = fail

            def register_fault() -> None:
                contract._SELECTOR_FACTORY = lambda: FaultSelector("register")

            def select_fault() -> None:
                contract._SELECTOR_FACTORY = lambda: FaultSelector("select")

            def read_fault() -> None:
                def fail(_fd: int, _size: int) -> bytes:
                    raise RuntimeError("selector read fault")

                contract._READ_FD = fail

            for name, configure in (
                ("constructor", constructor_fault),
                ("register", register_fault),
                ("select", select_fault),
                ("read", read_fault),
            ):
                with self.subTest(name=name):
                    self._assert_runner_fault_reaps(
                        root, f"{name}.log", configure
                    )

    def test_runner_surfaces_selector_and_log_close_faults_after_reap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-runner-close.") as temporary:
            root = Path(temporary)

            def selector_close_fault() -> None:
                contract._SELECTOR_FACTORY = lambda: FaultSelector("close")

            self._assert_runner_fault_reaps(
                root,
                "selector-close.log",
                selector_close_fault,
                short_child=True,
            )

            def log_close_fault() -> None:
                def close_then_fail(descriptor: int) -> None:
                    os.close(descriptor)
                    raise RuntimeError("log close fault")

                contract._CLOSE_FD = close_then_fail

            self._assert_runner_fault_reaps(
                root, "log-close.log", log_close_fault, short_child=True
            )

    def test_runner_reaps_descendant_in_same_isolated_process_group(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-runner-descendant.") as temporary:
            root = Path(temporary)
            descendant_pid_file = root / "descendant.pid"
            original_read = contract._READ_FD
            original_observer = contract._PROCESS_OBSERVER
            observed: list[subprocess.Popen[bytes]] = []
            contract._PROCESS_OBSERVER = observed.append

            def fail_read(_fd: int, _size: int) -> bytes:
                raise RuntimeError("injected read failure")

            contract._READ_FD = fail_read
            source = (
                "import pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                f"pathlib.Path({str(descendant_pid_file)!r}).write_text(str(child.pid));"
                "print('ready',flush=True);time.sleep(60)"
            )
            try:
                with self.assertRaises(contract.ContractError):
                    contract._bounded_build(
                        [sys.executable, "-c", source],
                        root,
                        {},
                        root / "descendant.log",
                    )
            finally:
                contract._READ_FD = original_read
                contract._PROCESS_OBSERVER = original_observer
            self.assertEqual(len(observed), 1)
            descendant_pid = int(descendant_pid_file.read_text(encoding="ascii"))
            with self.assertRaises(ProcessLookupError):
                os.kill(descendant_pid, 0)
            with self.assertRaises(ProcessLookupError):
                os.killpg(observed[0].pid, 0)

    def test_rejects_cargo_config_from_every_source_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-cargo-config.") as temporary:
            root = Path(temporary)
            source = root / "snapshot" / "nested"
            source.mkdir(parents=True)
            ambient = root / ".cargo"
            ambient.mkdir()
            (ambient / "config").write_text("[build]\n", encoding="utf-8")
            with self.assertRaisesRegex(contract.ContractError, "ambient Cargo"):
                contract._reject_ancestor_cargo_configuration(source)

    def test_component_open_and_absent_leaf_reject_intermediate_or_leaf_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-path-custody.") as temporary:
            root = Path(temporary)
            real = root / "real"
            nested = real / "nested"
            nested.mkdir(parents=True)
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(contract.ContractError, "component-open"):
                contract._open_directory_path_retained(link / "nested", "symlinked path")

            parent = root / "parent"
            parent.mkdir()
            dangling = parent / "candidate"
            dangling.symlink_to(root / "missing-target")
            with self.assertRaisesRegex(contract.ContractError, "must not preexist"):
                contract._retain_absent_absolute_leaf(dangling, "output bundle")


class InputReceiptTests(unittest.TestCase):
    def _write_image_receipt(self, path: Path, network: str = "none") -> None:
        document = {
            "schema": contract.IMAGE_SCHEMA,
            "profile": "amd64-cross",
            "host_arch": "x86_64",
            "claimed_image_id": "sha256:" + "1" * 64,
            "invocation_id": "fixture-invocation",
            "network_mode": network,
            "rootfs_read_only": True,
            "authority": contract.AUTHORITY_FALSE,
        }
        path.write_bytes(contract.canonical_json_bytes(document))

    def _write_toolchain_receipt(self, root: Path) -> tuple[Path, dict[str, Path]]:
        tools: dict[str, Path] = {}
        tool_records: dict[str, dict[str, str]] = {}
        for index, name in enumerate(("cargo", "rustc", "linker", "archiver"), start=1):
            path = root / name
            payload = f"#!/bin/sh\n# fixture {index}\n".encode("ascii")
            path.write_bytes(payload)
            os.chmod(path, 0o555)
            tools[name] = path
            tool_records[name] = {
                "path": str(path),
                "sha256": contract.sha256_bytes(payload),
            }
        crt_root = root / "crt"
        crt_root.mkdir()
        files = []
        manifest = hashlib.sha256()
        manifest.update(b"trillionnium.operation-replay-sync-static-crt.v1\0")
        names = tuple(sorted((
            "crt1.o",
            "crti.o",
            "crtbegin.o",
            "crtend.o",
            "crtn.o",
            "libc.a",
            "libunwind.a",
        )))
        for index, name in enumerate(names):
            payload = f"crt-fixture-{index}".encode("ascii")
            (crt_root / name).write_bytes(payload)
            os.chmod(crt_root / name, 0o444)
            digest = contract.sha256_bytes(payload)
            files.append({"path": name, "sha256": digest, "size": len(payload)})
            manifest.update(name.encode("utf-8") + b"\0")
            manifest.update(str(len(payload)).encode("ascii") + b"\0")
            manifest.update(bytes.fromhex(digest))
        os.chmod(crt_root, 0o555)
        document = {
            "schema": contract.TOOLCHAIN_SCHEMA,
            "profile": "amd64-cross",
            "target": contract.TARGET,
            "claimed_target_spec_sha256": "2" * 64,
            "tools": tool_records,
            "crt": {
                "root": str(crt_root),
                "files": files,
                "manifest_sha256": manifest.hexdigest(),
            },
            "authority": contract.AUTHORITY_FALSE,
        }
        receipt = root / "toolchain-receipt.json"
        receipt.write_bytes(contract.canonical_json_bytes(document))
        return receipt, tools

    def test_image_and_toolchain_crt_receipts_are_remeasured(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-inputs.") as temporary:
            root = Path(temporary)
            image = root / "image.json"
            self._write_image_receipt(image)
            image_value, image_sha = contract._load_image_receipt(
                image, "amd64-cross", "x86_64"
            )
            self.assertEqual(image_value["network_mode"], "none")
            self.assertEqual(len(image_sha), 64)
            toolchain, tools = self._write_toolchain_receipt(root)
            value, receipt_sha, measured = contract._load_toolchain_receipt(
                toolchain, "amd64-cross"
            )
            self.assertEqual(value["target"], contract.TARGET)
            self.assertEqual(len(receipt_sha), 64)
            self.assertEqual(set(measured), set(tools))

    def test_receipts_reject_network_or_tool_byte_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-input-drift.") as temporary:
            root = Path(temporary)
            image = root / "image.json"
            self._write_image_receipt(image, network="bridge")
            with self.assertRaisesRegex(contract.ContractError, "image receipt"):
                contract._load_image_receipt(image, "amd64-cross", "x86_64")
            toolchain, tools = self._write_toolchain_receipt(root)
            os.chmod(tools["cargo"], 0o600)
            tools["cargo"].write_bytes(b"drift")
            os.chmod(tools["cargo"], 0o555)
            with self.assertRaisesRegex(contract.ContractError, "digest"):
                contract._load_toolchain_receipt(toolchain, "amd64-cross")

    @staticmethod
    def _rewrite_crt_manifest(receipt: Path, document: dict[str, object]) -> None:
        crt = document["crt"]
        assert isinstance(crt, dict)
        files = crt["files"]
        assert isinstance(files, list)
        manifest = hashlib.sha256()
        manifest.update(b"trillionnium.operation-replay-sync-static-crt.v1\0")
        for entry in files:
            assert isinstance(entry, dict)
            manifest.update(str(entry["path"]).encode("ascii") + b"\0")
            manifest.update(str(entry["size"]).encode("ascii") + b"\0")
            manifest.update(bytes.fromhex(str(entry["sha256"])))
        crt["manifest_sha256"] = manifest.hexdigest()
        receipt.write_bytes(contract.canonical_json_bytes(document))

    def test_crt_rejects_unsorted_duplicate_and_resource_amplification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-crt-shape.") as temporary:
            root = Path(temporary)
            receipt, _ = self._write_toolchain_receipt(root)
            original = json.loads(receipt.read_text(encoding="ascii"))

            unsorted = copy.deepcopy(original)
            unsorted["crt"]["files"][0], unsorted["crt"]["files"][1] = (
                unsorted["crt"]["files"][1],
                unsorted["crt"]["files"][0],
            )
            self._rewrite_crt_manifest(receipt, unsorted)
            with self.assertRaisesRegex(contract.ContractError, "sorted and unique"):
                contract._load_toolchain_receipt(receipt, "amd64-cross")

            duplicate = copy.deepcopy(original)
            duplicate["crt"]["files"].insert(
                1, copy.deepcopy(duplicate["crt"]["files"][0])
            )
            self._rewrite_crt_manifest(receipt, duplicate)
            with self.assertRaisesRegex(
                contract.ContractError, "duplicate basename|sorted and unique"
            ):
                contract._load_toolchain_receipt(receipt, "amd64-cross")

            declared_small = copy.deepcopy(original)
            declared_small["crt"]["files"][0]["size"] = 1
            self._rewrite_crt_manifest(receipt, declared_small)
            with self.assertRaisesRegex(contract.ContractError, "byte limit"):
                contract._load_toolchain_receipt(receipt, "amd64-cross")

            self._rewrite_crt_manifest(receipt, original)
            old_count = contract.MAX_CRT_FILES
            old_total = contract.MAX_CRT_TOTAL_BYTES
            old_file = contract.MAX_CRT_FILE_BYTES
            try:
                contract.MAX_CRT_FILES = 6
                with self.assertRaisesRegex(contract.ContractError, "count"):
                    contract._load_toolchain_receipt(receipt, "amd64-cross")
                contract.MAX_CRT_FILES = old_count
                contract.MAX_CRT_TOTAL_BYTES = 1
                with self.assertRaisesRegex(contract.ContractError, "aggregate"):
                    contract._load_toolchain_receipt(receipt, "amd64-cross")
                contract.MAX_CRT_TOTAL_BYTES = old_total
                contract.MAX_CRT_FILE_BYTES = 1
                with self.assertRaisesRegex(contract.ContractError, "record"):
                    contract._load_toolchain_receipt(receipt, "amd64-cross")
            finally:
                contract.MAX_CRT_FILES = old_count
                contract.MAX_CRT_TOTAL_BYTES = old_total
                contract.MAX_CRT_FILE_BYTES = old_file

    def test_crt_rejects_writable_root_file_and_intermediate_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-crt-custody.") as temporary:
            root = Path(temporary)
            receipt, _ = self._write_toolchain_receipt(root)
            document = json.loads(receipt.read_text(encoding="ascii"))
            crt_root = Path(document["crt"]["root"])

            os.chmod(crt_root, 0o755)
            with self.assertRaisesRegex(contract.ContractError, "root must be read-only"):
                contract._load_toolchain_receipt(receipt, "amd64-cross")
            os.chmod(crt_root, 0o555)

            first = crt_root / document["crt"]["files"][0]["path"]
            os.chmod(first, 0o644)
            with self.assertRaisesRegex(contract.ContractError, "writable"):
                contract._load_toolchain_receipt(receipt, "amd64-cross")
            os.chmod(first, 0o444)

            outside = root / "outside"
            outside.mkdir()
            escaped = outside / first.name
            escaped.write_bytes(first.read_bytes())
            os.chmod(escaped, 0o444)
            os.chmod(outside, 0o555)
            os.chmod(crt_root, 0o755)
            (crt_root / "escape").symlink_to(outside, target_is_directory=True)
            os.chmod(crt_root, 0o555)
            changed = copy.deepcopy(document)
            changed["crt"]["files"][0]["path"] = f"escape/{first.name}"
            changed["crt"]["files"] = sorted(
                changed["crt"]["files"], key=lambda entry: entry["path"]
            )
            self._rewrite_crt_manifest(receipt, changed)
            with self.assertRaisesRegex(contract.ContractError, "component-open"):
                contract._load_toolchain_receipt(receipt, "amd64-cross")


class RawElfContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.valid = make_static_aarch64_elf()

    def assert_hold(self, blob: bytes, pattern: str) -> None:
        with self.assertRaisesRegex(contract.ContractError, pattern):
            contract.inspect_elf_bytes(blob)

    def test_exact_static_contract_passes(self) -> None:
        receipt = contract.inspect_elf_bytes(self.valid)
        self.assertEqual(receipt["type"], "ET_EXEC")
        self.assertEqual(receipt["machine"], "AArch64")
        self.assertEqual(receipt["combined_wx_safe_page_sizes"], [4096, 16384, 65536])
        self.assertFalse(receipt["pt_interp_present"])
        self.assertFalse(receipt["pt_dynamic_present"])

    def test_rejects_et_dyn_wrong_machine_and_entry_outside_rx(self) -> None:
        self.assert_hold(mutate_u16(self.valid, 16, 3), "ET_EXEC")
        self.assert_hold(mutate_u16(self.valid, 18, 62), "AArch64")
        self.assert_hold(mutate_u64(self.valid, 24, 0x420000), "entry point")

    def test_rejects_interp_dynamic_and_dynamic_section(self) -> None:
        # Change the first read-only LOAD into a forbidden program header.
        self.assert_hold(mutate_u32(self.valid, 64, contract.PT_INTERP), "forbidden")
        self.assert_hold(mutate_u32(self.valid, 64, contract.PT_DYNAMIC), "forbidden")
        # SHT_DYNAMIC on the .data section.
        section_offset = 0x20200 + 2 * 64 + 4
        self.assert_hold(mutate_u32(self.valid, section_offset, contract.SHT_DYNAMIC), "dynamic")

    def test_rejects_missing_duplicate_or_executable_stack(self) -> None:
        stack_offset = 64 + 3 * 56
        self.assert_hold(mutate_u32(self.valid, stack_offset, 4), "exactly one")
        duplicate = mutate_u32(self.valid, 64, contract.PT_GNU_STACK)
        self.assert_hold(duplicate, "exactly one")
        executable = mutate_u32(
            self.valid, stack_offset + 4, contract.PF_R | contract.PF_W | contract.PF_X
        )
        self.assert_hold(executable, "GNU_STACK is executable")

    def test_rejects_alignment_and_program_file_bounds(self) -> None:
        rx_offset = 64 + 56
        self.assert_hold(mutate_u64(self.valid, rx_offset + 48, 3), "power of two")
        self.assert_hold(
            mutate_u64(self.valid, rx_offset + 48, 4096), "largest supported page"
        )
        self.assert_hold(mutate_u64(self.valid, rx_offset + 16, 0x410001), "congruence")
        self.assert_hold(
            mutate_u64(self.valid, rx_offset + 32, len(self.valid)), "outside the ELF"
        )

    def test_rejects_section_bounds_alignment_and_table_overflow(self) -> None:
        text_section = 0x20200 + 64
        self.assert_hold(mutate_u64(self.valid, text_section + 24, len(self.valid)), "outside")
        self.assert_hold(mutate_u64(self.valid, text_section + 48, 3), "power of two")
        self.assert_hold(mutate_u64(self.valid, text_section + 16, 0x410001), "address alignment")
        self.assert_hold(mutate_u64(self.valid, text_section + 24, 0x10001), "file-offset alignment")
        self.assert_hold(mutate_u64(self.valid, 40, len(self.valid) - 8), "section headers")
        self.assert_hold(mutate_u32(self.valid, 0x20200, 1), "null section")

    def test_nobits_offset_is_conceptual_but_address_stays_aligned(self) -> None:
        data_section = 0x20200 + 2 * 64
        changed = mutate_u32(self.valid, data_section + 4, contract.SHT_NOBITS)
        changed = mutate_u64(changed, data_section + 24, 0xFFFFFFFFFFFFFFF0)
        changed = mutate_u64(changed, data_section + 48, 0x100)
        contract.inspect_elf_bytes(changed)
        changed = mutate_u64(changed, data_section + 16, 0x420001)
        self.assert_hold(changed, "address alignment")

    def test_rejects_wx_overlap_that_exists_only_at_64k_pages(self) -> None:
        rw_offset = 64 + 2 * 56
        changed = mutate_u64(self.valid, rw_offset + 8, 0x1F000)
        changed = mutate_u64(changed, rw_offset + 16, 0x41F000)
        changed = mutate_u64(changed, rw_offset + 24, 0x41F000)
        self.assert_hold(changed, "65536-byte pages")

    @unittest.skipUnless(shutil.which("zig"), "current host has no Zig toolchain")
    def test_real_current_zig_static_aarch64_fixture(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-zig.") as temporary:
            root = Path(temporary)
            source = root / "entry.S"
            output = root / "entry"
            source.write_text(
                ".text\n.global _start\n.type _start,%function\n_start:\n"
                "mov x0, #0\nmov x8, #93\nsvc #0\n"
                ".section .note.GNU-stack,\"\",%progbits\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    shutil.which("zig") or "zig",
                    "cc",
                    "-target",
                    "aarch64-linux-musl",
                    "-nostdlib",
                    "-static",
                    "-no-pie",
                    "-Wl,-z,max-page-size=65536",
                    "-Wl,-z,noexecstack",
                    "-Wl,-e,_start",
                    "-o",
                    str(output),
                    str(source),
                ],
                env={"HOME": str(root), "PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest(f"current Zig fixture unavailable: {result.stderr[:200]!r}")
            receipt = contract.inspect_elf_path(output)
            self.assertEqual(receipt["machine"], "AArch64")
            self.assertEqual(receipt["type"], "ET_EXEC")


class RetainedPublicationTests(unittest.TestCase):
    def _open_parent(self, parent: Path) -> tuple[int, os.stat_result]:
        parent.mkdir()
        os.chmod(parent, 0o700)
        return contract._open_directory_path_retained(parent, "test output parent")

    def test_bundle_publication_ignores_umask_and_fixes_exact_modes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-publication.") as temporary:
            parent = Path(temporary) / "parent"
            parent_fd, parent_identity = self._open_parent(parent)
            old_umask = os.umask(0o777)
            try:
                contract._publish_retained_bundle(
                    parent / "candidate",
                    parent_fd,
                    parent_identity,
                    [("helper", b"helper-bytes", 0o555), ("receipt", b"{}\n", 0o444)],
                )
            finally:
                os.umask(old_umask)
                os.close(parent_fd)
            self.assertEqual(stat_mode(parent / "candidate"), 0o700)
            self.assertEqual(stat_mode(parent / "candidate" / "helper"), 0o555)
            self.assertEqual(stat_mode(parent / "candidate" / "receipt"), 0o444)
            self.assertEqual((parent / "candidate" / "helper").read_bytes(), b"helper-bytes")

    def test_bundle_name_rebind_cannot_publish_into_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-name-rebind.") as temporary:
            parent = Path(temporary) / "parent"
            parent_fd, parent_identity = self._open_parent(parent)
            output = parent / "candidate"
            detached = parent / "detached-candidate"
            original_hook = contract._PUBLICATION_PRE_LINK_BARRIER

            def rebind(_output: Path, _parent_fd: int, _bundle_fd: int) -> None:
                output.rename(detached)
                output.mkdir()
                os.chmod(output, 0o700)

            contract._PUBLICATION_PRE_LINK_BARRIER = rebind
            try:
                with self.assertRaisesRegex(contract.ContractError, "rebound"):
                    contract._publish_retained_bundle(
                        output,
                        parent_fd,
                        parent_identity,
                        [("helper", b"expected", 0o555)],
                    )
            finally:
                contract._PUBLICATION_PRE_LINK_BARRIER = original_hook
                os.close(parent_fd)
            self.assertEqual(list(output.iterdir()), [])
            self.assertEqual((detached / "helper").read_bytes(), b"expected")

    def test_parent_rebind_is_commit_unknown_hold(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-parent-rebind.") as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent_fd, parent_identity = self._open_parent(parent)
            output = parent / "candidate"
            detached_parent = root / "detached-parent"
            original_hook = contract._PUBLICATION_PRE_LINK_BARRIER

            def rebind(_output: Path, _parent_fd: int, _bundle_fd: int) -> None:
                parent.rename(detached_parent)
                parent.mkdir()
                os.chmod(parent, 0o700)

            contract._PUBLICATION_PRE_LINK_BARRIER = rebind
            try:
                with self.assertRaisesRegex(contract.ContractError, "rebound"):
                    contract._publish_retained_bundle(
                        output,
                        parent_fd,
                        parent_identity,
                        [("helper", b"expected", 0o555)],
                    )
            finally:
                contract._PUBLICATION_PRE_LINK_BARRIER = original_hook
                os.close(parent_fd)
            self.assertFalse(output.exists())
            self.assertEqual(
                (detached_parent / "candidate" / "helper").read_bytes(), b"expected"
            )

    def test_partial_publication_is_never_rolled_back_or_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-commit-unknown.") as temporary:
            parent = Path(temporary) / "parent"
            parent_fd, parent_identity = self._open_parent(parent)
            output = parent / "candidate"
            original_link = contract._linkat_empty_noreplace
            calls = 0

            def fail_second(source_fd: int, destination_fd: int, name: str) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise contract.ContractError("injected second-link failure")
                original_link(source_fd, destination_fd, name)

            contract._linkat_empty_noreplace = fail_second
            try:
                with self.assertRaisesRegex(contract.ContractError, "second-link"):
                    contract._publish_retained_bundle(
                        output,
                        parent_fd,
                        parent_identity,
                        [("first", b"one", 0o555), ("second", b"two", 0o444)],
                    )
            finally:
                contract._linkat_empty_noreplace = original_link
            self.assertEqual((output / "first").read_bytes(), b"one")
            self.assertFalse((output / "second").exists())
            with self.assertRaises((contract.ContractError, FileExistsError)):
                contract._publish_retained_bundle(
                    output,
                    parent_fd,
                    parent_identity,
                    [("first", b"replacement", 0o555)],
                )
            self.assertEqual((output / "first").read_bytes(), b"one")
            os.close(parent_fd)

    def test_persistent_reconcile_output_is_fixed_hold_without_custody_journal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-output.") as temporary:
            parent = Path(temporary) / "parent"
            parent.mkdir()
            os.chmod(parent, 0o700)
            output = parent / "reconcile.json"
            document = {"schema": "fixture", "authority": contract.AUTHORITY_FALSE}
            with self.assertRaisesRegex(contract.ContractError, "fixed HOLD"):
                contract._write_optional_output(output, document)
            self.assertFalse(output.exists())

    def test_reconcile_cli_output_holds_before_opening_input_receipts(self) -> None:
        script = PACKAGE_ROOT / "build_operation_replay_sync_static.py"
        with tempfile.TemporaryDirectory(prefix="operation-helper-output-cli.") as temporary:
            output = Path(temporary) / "reconcile.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--recipe",
                    "/does/not/exist/recipe.json",
                    "reconcile",
                    "--amd64-receipt",
                    "/does/not/exist/amd64/build-receipt.json",
                    "--arm64-receipt",
                    "/does/not/exist/arm64/build-receipt.json",
                    "--output",
                    str(output),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 78)
            self.assertIn(b"fixed custody journal", result.stderr)
            self.assertFalse(output.exists())


def stat_mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode & 0o7777


def write_mock_bundle(
    root: Path,
    profile: str,
    system_blob: bytes,
    accessibility_blob: bytes,
) -> Path:
    recipe, recipe_sha = contract.load_recipe(RECIPE)
    root.mkdir()
    os.chmod(root, 0o700)
    blobs = {"system-api": system_blob, "accessibility": accessibility_blob}
    artifacts = []
    for role in contract.ROLE_ORDER:
        role_config = recipe["roles"][role]
        blob = blobs[role]
        elf = contract.inspect_elf_bytes(blob)
        (root / role_config["filename"]).write_bytes(blob)
        os.chmod(root / role_config["filename"], 0o555)
        source_sha = recipe["source_contract"]["fixed_files"][role_config["entry_source"]]
        artifacts.append(
            {
                "role": role,
                "cargo_bin": role_config["cargo_bin"],
                "filename": role_config["filename"],
                "entry_source": role_config["entry_source"],
                "entry_source_sha256": source_sha,
                "sha256": elf["sha256"],
                "size": elf["size"],
                "mode": "0555",
                "role_binding_sha256": contract._role_binding(
                    role, role_config, elf["sha256"], source_sha
                ),
                "elf": elf,
            }
        )
    tree_fact = lambda digest: {
        "schema": "trillionnium.operation-replay-sync-static-tree.v1",
        "file_count": 1,
        "directory_count": 1,
        "regular_bytes": 1,
        "manifest_sha256": digest,
        "readonly_mode_bits_verified": True,
        "symlinks_allowed": False,
        "compiler_read_set_bound": False,
        "hostile_same_uid_custody_proven": False,
    }
    inputs = {
        "recipe_sha256": recipe_sha,
        "source_tree": tree_fact("1" * 64),
        "cargo_lock_sha256": recipe["source_contract"]["cargo_lock_sha256"],
        "vendor_tree": tree_fact("2" * 64),
        "toolchain_receipt_sha256": "3" * 64 if profile == "amd64-cross" else "4" * 64,
        "claimed_target_spec_sha256": "5" * 64,
        "crt_manifest_sha256": "6" * 64,
        "image_receipt_sha256": "7" * 64 if profile == "amd64-cross" else "8" * 64,
        "claimed_image_id": "sha256:"
        + ("9" * 64 if profile == "amd64-cross" else "a" * 64),
    }
    receipt = {
        "schema": contract.BUILD_SCHEMA,
        "status": "SOURCE_ONLY_UNWIRED_CANDIDATE",
        "profile": profile,
        "target": contract.TARGET,
        "inputs": inputs,
        "invocation": {
            "base_environment": "empty",
            "environment_keys": sorted(
                {
                    "HOME",
                    "PATH",
                    "LC_ALL",
                    "LANG",
                    "TZ",
                    "SOURCE_DATE_EPOCH",
                    "CARGO_NET_OFFLINE",
                    "CARGO_HOME",
                    "CARGO_TARGET_DIR",
                    "RUSTC",
                    "CARGO_ENCODED_RUSTFLAGS",
                    "CARGO_PROFILE_RELEASE_OPT_LEVEL",
                    "CARGO_PROFILE_RELEASE_DEBUG",
                    "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS",
                    "CARGO_PROFILE_RELEASE_INCREMENTAL",
                    "CARGO_PROFILE_RELEASE_STRIP",
                    "CARGO_PROFILE_RELEASE_PANIC",
                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER",
                    "CC_aarch64_unknown_linux_musl",
                    "AR_aarch64_unknown_linux_musl",
                }
            ),
            "cargo_argv": [
                "/toolchain/cargo",
                "build",
                "--release",
                "--locked",
                "--offline",
                "--no-default-features",
                "--features",
                recipe["cargo"]["feature"],
                "--target",
                contract.TARGET,
                "--package",
                recipe["cargo"]["package"],
                "--bin",
                recipe["cargo"]["bins"][0],
                "--bin",
                recipe["cargo"]["bins"][1],
            ],
            "source_date_epoch": recipe["source_date_epoch"],
            "path_remap_root": recipe["build_contract"]["path_remap_root"],
            "cargo_locked": True,
            "cargo_offline": True,
            "cargo_release": True,
            "network_namespace_verified_by_builder": False,
            "compiler_read_set_bound": False,
            "hostile_same_uid_source_custody_proven": False,
            "toolchain_runtime_read_set_bound": False,
            "crt_link_read_set_bound": False,
            "builder_image_execution_bound": False,
            "outer_cgroup_v2_zero_survivor_verified": False,
            "durable_publication_journal_verified": False,
            "automatic_work_cleanup_performed": False,
            "work_retained_for_ephemeral_lane_cleanup": True,
            "log": {"sha256": "b" * 64, "size": 0, "exit_code": 0},
        },
        "artifacts": artifacts,
        "source_checkpoint": contract.CHECKPOINT_FALSE,
        "authority": contract.AUTHORITY_FALSE,
        "receipt_id": "",
    }
    receipt["receipt_id"] = contract._receipt_id(
        receipt, b"trillionnium.operation-replay-sync-static-build-receipt.v1"
    )
    receipt_path = root / "build-receipt.json"
    receipt_path.write_bytes(contract.canonical_json_bytes(receipt))
    os.chmod(receipt_path, 0o444)
    return receipt_path


class ReconcileTests(unittest.TestCase):
    def test_same_role_byte_identity_passes_and_authority_stays_false(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-reconcile.") as temporary:
            root = Path(temporary)
            system = make_static_aarch64_elf(0xD503201F)
            accessibility = make_static_aarch64_elf(0xD65F03C0)
            amd64 = write_mock_bundle(root / "amd64", "amd64-cross", system, accessibility)
            arm64 = write_mock_bundle(root / "arm64", "arm64-native", system, accessibility)
            result = contract.reconcile_receipts(RECIPE, amd64, arm64)
            self.assertEqual(
                result["status"],
                "PREVIEW_SOURCE_ONLY_UNWIRED_BYTE_RECONCILIATION",
            )
            self.assertTrue(result["same_role_byte_identical"])
            self.assertTrue(result["cross_role_byte_distinct"])
            self.assertFalse(result["durable_publication"])
            self.assertFalse(result["fixed_custody_journal_verified"])
            self.assertEqual(result["authority"], contract.AUTHORITY_FALSE)
            self.assertEqual(result["source_checkpoint"], contract.CHECKPOINT_FALSE)

    def test_role_exchange_is_rejected_even_when_each_build_is_well_formed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-role-swap.") as temporary:
            root = Path(temporary)
            system = make_static_aarch64_elf(0xD503201F)
            accessibility = make_static_aarch64_elf(0xD65F03C0)
            amd64 = write_mock_bundle(root / "amd64", "amd64-cross", system, accessibility)
            arm64 = write_mock_bundle(root / "arm64", "arm64-native", accessibility, system)
            with self.assertRaisesRegex(contract.ContractError, "not byte-identical|role exchange"):
                contract.reconcile_receipts(RECIPE, amd64, arm64)

    def test_same_role_profile_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-profile-drift.") as temporary:
            root = Path(temporary)
            system = make_static_aarch64_elf(0xD503201F)
            accessibility = make_static_aarch64_elf(0xD65F03C0)
            amd64 = write_mock_bundle(root / "amd64", "amd64-cross", system, accessibility)
            changed_system = make_static_aarch64_elf(0xD503205F)
            arm64 = write_mock_bundle(root / "arm64", "arm64-native", changed_system, accessibility)
            with self.assertRaisesRegex(contract.ContractError, "not byte-identical"):
                contract.reconcile_receipts(RECIPE, amd64, arm64)

    def test_reconcile_revalidates_artifact_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-artifact-drift.") as temporary:
            root = Path(temporary)
            system = make_static_aarch64_elf(0xD503201F)
            accessibility = make_static_aarch64_elf(0xD65F03C0)
            amd64 = write_mock_bundle(root / "amd64", "amd64-cross", system, accessibility)
            arm64 = write_mock_bundle(root / "arm64", "arm64-native", system, accessibility)
            artifact = amd64.parent / "trillionnium-system-api-operation-replay-sync"
            os.chmod(artifact, 0o600)
            artifact.write_bytes(make_static_aarch64_elf(0xD503205F))
            os.chmod(artifact, 0o555)
            with self.assertRaisesRegex(contract.ContractError, "bytes or ELF receipt drifted"):
                contract.reconcile_receipts(RECIPE, amd64, arm64)

    def test_reconcile_rejects_any_extra_bundle_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-extra-entry.") as temporary:
            root = Path(temporary)
            system = make_static_aarch64_elf(0xD503201F)
            accessibility = make_static_aarch64_elf(0xD65F03C0)
            amd64 = write_mock_bundle(root / "amd64", "amd64-cross", system, accessibility)
            arm64 = write_mock_bundle(root / "arm64", "arm64-native", system, accessibility)
            extra = amd64.parent / "unexpected"
            extra.write_bytes(b"not-authority")
            os.chmod(extra, 0o444)
            with self.assertRaisesRegex(contract.ContractError, "entries drifted"):
                contract.reconcile_receipts(RECIPE, amd64, arm64)

    def test_left_receipt_swap_after_semantic_verify_fails_final_barrier(self) -> None:
        with tempfile.TemporaryDirectory(prefix="operation-helper-late-swap.") as temporary:
            root = Path(temporary)
            system = make_static_aarch64_elf(0xD503201F)
            accessibility = make_static_aarch64_elf(0xD65F03C0)
            amd64 = write_mock_bundle(root / "amd64", "amd64-cross", system, accessibility)
            arm64 = write_mock_bundle(root / "arm64", "arm64-native", system, accessibility)
            original_hook = contract._RECONCILE_PRE_FINAL_BARRIER

            def swap_receipt(
                left: contract._RetainedBuildBundle,
                _right: contract._RetainedBuildBundle,
            ) -> None:
                retained_bytes = left.receipt_path.read_bytes()
                hidden = left.root_path.parent / "retained-original-receipt"
                left.receipt_path.rename(hidden)
                left.receipt_path.write_bytes(retained_bytes)
                os.chmod(left.receipt_path, 0o444)

            contract._RECONCILE_PRE_FINAL_BARRIER = swap_receipt
            try:
                with self.assertRaisesRegex(
                    contract.ContractError,
                    "entries drifted|retained build receipt|named inode",
                ):
                    contract.reconcile_receipts(RECIPE, amd64, arm64)
            finally:
                contract._RECONCILE_PRE_FINAL_BARRIER = original_hook


if __name__ == "__main__":
    unittest.main()
