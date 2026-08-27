from __future__ import annotations

import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/build_codex_only_raw_elf_set.py"
SPEC = importlib.util.spec_from_file_location("codex_only_raw_elf_builder", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUILDER
SPEC.loader.exec_module(BUILDER)


class CodexOnlyRawElfBuilderTests(unittest.TestCase):
    def test_builder_disables_import_bytecode_before_loading_bom_materializer(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        assignment = source.index("sys.dont_write_bytecode = True")
        materializer_load = source.index("SOURCE_BOM = _load_source_bom_materializer()")
        self.assertLess(assignment, materializer_load)

    def test_lane_graph_and_cargo_commands_are_closed(self) -> None:
        common = BUILDER.LANES["common"]
        self.assertEqual(
            [item.arguments() for item in common.invocations],
            [
                (
                    "build",
                    "--locked",
                    "--offline",
                    "--quiet",
                    "--release",
                    "--target",
                    "aarch64-unknown-linux-gnu",
                    "--no-default-features",
                    "--package",
                    "trillionnium-agent-direct-tools",
                    "--bin",
                    "trillionnium-agent-system-api",
                    "--bin",
                    "trillionnium-agent-accessibility",
                    "--bin",
                    "trillionnium-system-api-replay-sync",
                ),
                (
                    "build",
                    "--locked",
                    "--offline",
                    "--quiet",
                    "--release",
                    "--target",
                    "aarch64-unknown-linux-gnu",
                    "--no-default-features",
                    "--package",
                    "trillionniumd",
                    "--bin",
                    "trillionniumd",
                ),
            ],
        )
        self.assertEqual(
            [(item.role, item.binary) for item in common.artifacts],
            [
                ("system_api_tool", "trillionnium-agent-system-api"),
                ("accessibility_tool", "trillionnium-agent-accessibility"),
                ("replay_sync_helper", "trillionnium-system-api-replay-sync"),
                ("daemon", "trillionniumd"),
            ],
        )

        p01 = BUILDER.LANES["p01_userdebug_pre_daemon"]
        commands = [item.arguments() for item in p01.invocations]
        self.assertIn("device-launch-package-conformance", commands[0])
        self.assertIn("p0-launch-package-device-conformance", commands[1])
        self.assertNotIn("trillionniumd", [item.binary for item in p01.artifacts])
        self.assertEqual(
            p01.receipt_name,
            "codex-only-raw-elf-set.p01-userdebug-pre-daemon.v3.json",
        )
        self.assertEqual(
            common.receipt_name,
            "codex-only-raw-elf-set.common.v3.json",
        )

    def test_cli_requires_every_external_build_boundary(self) -> None:
        # Exercise the real parser by proving an otherwise empty invocation is
        # rejected, then inspect source-level option declarations without
        # running or mutating a build tree.
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                BUILDER.parse_args([])
        source = MODULE_PATH.read_text(encoding="utf-8")
        for option in (
            "--source-bom",
            "--android-root",
            "--artifact-root",
            "--resolved-manifest",
            "--cargo",
            "--rustc",
            "--host-linker",
            "--linker",
            "--ar",
            "--readelf",
            "--cargo-home",
            "--rust-toolchain-root",
            "--target-toolchain-root",
            "--target-sysroot",
        ):
            self.assertIn(f'parser.add_argument("{option}"', source)
        self.assertIn('"--dyn-syms"', source)

    def test_private_output_and_target_directories_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "valid"
            valid.mkdir(mode=0o700)
            path, descriptor, _, custody = BUILDER.open_private_empty_directory(
                valid, "fixture"
            )
            self.assertEqual(descriptor, custody.descriptor)
            custody.close()
            self.assertEqual(path, valid.resolve())

            nonempty = root / "nonempty"
            nonempty.mkdir(mode=0o700)
            (nonempty / "input").write_bytes(b"x")
            with self.assertRaisesRegex(BUILDER.RawElfBuildError, "must be empty"):
                BUILDER.open_private_empty_directory(nonempty, "fixture")

            broad = root / "broad"
            broad.mkdir(mode=0o700)
            broad.chmod(0o750)
            with self.assertRaisesRegex(BUILDER.RawElfBuildError, "0700"):
                BUILDER.open_private_empty_directory(broad, "fixture")

            alias = root / "alias"
            alias.symlink_to(valid, target_is_directory=True)
            with self.assertRaisesRegex(
                BUILDER.RawElfBuildError, "symbolic link|symlink"
            ):
                BUILDER.open_private_empty_directory(alias, "fixture")

    def test_output_directory_rename_replace_is_rejected_by_final_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir(mode=0o700)
            _, descriptor, _, custody = BUILDER.open_private_empty_directory(
                output, "output directory"
            )
            published: list[BUILDER.RetainedPublishedFile] = []
            try:
                held = root / "output-held"
                output.rename(held)
                output.mkdir(mode=0o700)
                published.append(
                    BUILDER.write_exclusive_at(
                        descriptor, "receipt.json", b"{}\n", 0o444
                    )
                )
                with self.assertRaisesRegex(
                    BUILDER.RawElfBuildError, "retained pathname changed"
                ):
                    BUILDER.assert_closed_publication(
                        descriptor,
                        custody,
                        {"receipt.json"},
                        published,
                    )
                self.assertFalse((output / "receipt.json").exists())
                self.assertTrue((held / "receipt.json").exists())
            finally:
                BUILDER.close_published_files(published)
                custody.close()

    def test_published_file_and_prior_artifact_replace_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            _, descriptor, _, custody = BUILDER.open_private_empty_directory(
                output, "output directory"
            )
            published: list[BUILDER.RetainedPublishedFile] = []
            try:
                published.append(
                    BUILDER.write_exclusive_at(
                        descriptor, "artifact-a", b"first", 0o555
                    )
                )
                replacement = output / "replacement"
                replacement.write_bytes(b"first")
                replacement.chmod(0o555)
                os.replace(replacement, output / "artifact-a")
                published.append(
                    BUILDER.write_exclusive_at(
                        descriptor, "receipt.json", b"{}\n", 0o444
                    )
                )
                with self.assertRaisesRegex(
                    BUILDER.RawElfBuildError,
                    "descriptor, pathname, or bytes changed",
                ):
                    BUILDER.assert_closed_publication(
                        descriptor,
                        custody,
                        {"artifact-a", "receipt.json"},
                        published,
                    )
            finally:
                BUILDER.close_published_files(published)
                custody.close()

    def test_published_file_in_place_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            _, descriptor, _, custody = BUILDER.open_private_empty_directory(
                output, "output directory"
            )
            published: list[BUILDER.RetainedPublishedFile] = []
            try:
                published.append(
                    BUILDER.write_exclusive_at(
                        descriptor, "receipt.json", b"original\n", 0o444
                    )
                )
                path = output / "receipt.json"
                path.chmod(0o600)
                path.write_bytes(b"tampered\n")
                path.chmod(0o444)
                with self.assertRaisesRegex(
                    BUILDER.RawElfBuildError,
                    "descriptor, pathname, or bytes changed",
                ):
                    BUILDER.assert_closed_publication(
                        descriptor,
                        custody,
                        {"receipt.json"},
                        published,
                    )
            finally:
                BUILDER.close_published_files(published)
                custody.close()

    def test_strict_regular_input_rejects_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"measured")
            alias = root / "alias"
            alias.symlink_to(source)
            with self.assertRaises(BUILDER.RawElfBuildError):
                BUILDER.strict_regular_bytes(alias, "alias", 1024)
            hardlink = root / "hardlink"
            os.link(source, hardlink)
            with self.assertRaisesRegex(BUILDER.RawElfBuildError, "bounded regular"):
                BUILDER.strict_regular_bytes(source, "source", 1024)
            value, metadata = BUILDER.strict_regular_bytes(
                source,
                "Cargo-private hardlink",
                1024,
                require_single_link=False,
            )
            self.assertEqual(value, b"measured")
            self.assertEqual(metadata.st_nlink, 2)

    def test_tool_boundary_rejects_unclosed_shell_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper = Path(temporary) / "linker"
            wrapper.write_text("#!/usr/bin/env bash\nexec /usr/bin/false \"$@\"\n")
            wrapper.chmod(0o555)
            with self.assertRaisesRegex(BUILDER.RawElfBuildError, "direct measured ELF"):
                BUILDER.validate_executable(wrapper, "linker")

    def test_retained_tool_execution_preserves_argv0_and_revalidates_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = []
            for name in ("cargo", "rustc"):
                path = root / name
                path.write_bytes(Path("/usr/bin/true").read_bytes())
                path.chmod(0o555)
                tools.append(BUILDER.open_retained_executable(path, name))
            cargo, rustc = tools
            cargo_descriptor = cargo.descriptor
            rustc_descriptor = rustc.descriptor
            try:
                self.assertEqual(
                    BUILDER.run_retained_bounded(
                        cargo,
                        (),
                        env={"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"},
                        cwd=None,
                        maximum=1024,
                        timeout=30,
                        label="retained executable smoke",
                        inherited_tools=(rustc,),
                    ),
                    b"",
                )
                completed = mock.Mock(returncode=0, stdout=b"identity\n")
                with mock.patch.object(
                    BUILDER.subprocess, "run", return_value=completed
                ) as run:
                    output = BUILDER.run_retained_bounded(
                        cargo,
                        ("--version", "--verbose"),
                        env={"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"},
                        cwd=None,
                        maximum=1024,
                        timeout=30,
                        label="cargo identity query",
                        inherited_tools=(rustc,),
                    )
                self.assertEqual(output, b"identity\n")
                positional, keywords = run.call_args
                self.assertEqual(
                    positional[0],
                    [str(cargo.path), "--version", "--verbose"],
                )
                self.assertEqual(keywords["executable"], cargo.fd_path)
                self.assertEqual(
                    keywords["pass_fds"],
                    (cargo_descriptor, rustc_descriptor),
                )
                BUILDER.revalidate_retained_executable(cargo)

                replacement = root / "replacement"
                replacement.write_bytes(cargo.initial_bytes)
                replacement.chmod(0o555)
                os.replace(replacement, cargo.path)
                with self.assertRaisesRegex(
                    BUILDER.RawElfBuildError, "original pathname changed"
                ):
                    BUILDER._require_original_executable_path(cargo)
                with self.assertRaisesRegex(BUILDER.RawElfBuildError, "changed"):
                    BUILDER.revalidate_retained_executable(cargo)
                self.assertEqual(
                    os.pread(cargo.descriptor, len(cargo.initial_bytes), 0),
                    cargo.initial_bytes,
                )
            finally:
                BUILDER.close_retained_executables(tools)
            for descriptor in (cargo_descriptor, rustc_descriptor):
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_toolchain_rejects_sysroot_as_root_before_opening_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rust_root = root / "rust"
            target_sysroot = root / "toolchain/sysroot"
            host_root = root / "host"
            cargo_home = root / "cargo-home"
            for directory in (rust_root, target_sysroot, cargo_home):
                directory.mkdir(mode=0o700, parents=True)
            args = BUILDER.argparse.Namespace(
                cargo=rust_root / "cargo",
                rustc=rust_root / "rustc",
                host_linker=host_root / "host-linker",
                linker=target_sysroot / "usr/bin/aarch64-linux-gnu-gcc-12",
                ar=target_sysroot / "usr/bin/aarch64-linux-gnu-ar",
                readelf=target_sysroot / "usr/bin/aarch64-linux-gnu-readelf",
                rust_toolchain_root=rust_root,
                target_toolchain_root=target_sysroot,
                host_toolchain_root=host_root,
                target_sysroot=target_sysroot,
                target_compiler_bin=target_sysroot / "usr/bin",
                target_gcc_libdir=(
                    target_sysroot / "usr/lib/gcc-cross/aarch64-linux-gnu/12"
                ),
                target_binutils_dir=target_sysroot / "usr/aarch64-linux-gnu/bin",
                target_host_runtime_libdir=(
                    target_sysroot / "usr/lib/x86_64-linux-gnu"
                ),
                cargo_home=cargo_home,
                toolchain_manifest=root / "toolchain-manifest.json",
            )

            with mock.patch.object(
                BUILDER, "open_retained_executable"
            ) as open_tool, mock.patch.object(
                BUILDER, "run_retained_bounded"
            ) as run_tool:
                with self.assertRaisesRegex(
                    BUILDER.RawElfBuildError,
                    "target sysroot is outside the exact lane snapshot layout",
                ):
                    BUILDER.inspect_toolchain(args, {})

            open_tool.assert_not_called()
            run_tool.assert_not_called()

    def test_toolchain_query_failure_closes_every_retained_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rust_root = root / "rust"
            target_root = root / "toolchain"
            host_root = root / "host"
            cargo_home = root / "cargo-home"
            target_sysroot = target_root / "sysroot"
            target_compiler_bin = target_sysroot / "usr/bin"
            target_gcc_libdir = (
                target_sysroot / "usr/lib/gcc-cross/aarch64-linux-gnu/12"
            )
            target_binutils_dir = target_sysroot / "usr/aarch64-linux-gnu/bin"
            target_host_runtime_libdir = (
                target_sysroot / "usr/lib/x86_64-linux-gnu"
            )
            for directory in (
                rust_root,
                host_root,
                cargo_home,
                target_compiler_bin,
                target_gcc_libdir,
                target_binutils_dir,
                target_host_runtime_libdir,
            ):
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            paths = {
                "cargo": rust_root / "cargo",
                "rustc": rust_root / "rustc",
                "host_linker": host_root / "host-linker",
                "linker": target_compiler_bin / "aarch64-linux-gnu-gcc-12",
                "ar": target_compiler_bin / "aarch64-linux-gnu-ar",
                "readelf": target_compiler_bin / "aarch64-linux-gnu-readelf",
            }
            executable = Path("/usr/bin/true").read_bytes()
            for path in paths.values():
                path.write_bytes(executable)
                path.chmod(0o555)
            opened = []
            real_open = BUILDER.open_retained_executable

            def capture(path: Path, role: str):
                tool = real_open(path, role)
                opened.append((tool, tool.descriptor))
                return tool

            args = BUILDER.argparse.Namespace(
                **paths,
                rust_toolchain_root=rust_root,
                target_toolchain_root=target_root,
                host_toolchain_root=host_root,
                cargo_home=cargo_home,
                target_sysroot=target_sysroot,
                target_compiler_bin=target_compiler_bin,
                target_gcc_libdir=target_gcc_libdir,
                target_binutils_dir=target_binutils_dir,
                target_host_runtime_libdir=target_host_runtime_libdir,
                toolchain_manifest=root / "manifest.json",
            )
            with mock.patch.object(
                BUILDER, "open_retained_executable", side_effect=capture
            ), mock.patch.object(
                BUILDER,
                "run_retained_bounded",
                side_effect=BUILDER.RawElfBuildError("query stopped"),
            ):
                with self.assertRaisesRegex(BUILDER.RawElfBuildError, "query stopped"):
                    BUILDER.inspect_toolchain(args, {})
            self.assertEqual(len(opened), 6)
            for tool, descriptor in opened:
                self.assertEqual(tool.descriptor, -1)
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_control_root_is_the_outer_git_worktree(self) -> None:
        self.assertEqual(BUILDER.derive_control_root(), ROOT.parent.resolve())

    def test_live_source_bom_must_be_byte_equal(self) -> None:
        measured = {
            "schema": BUILDER.SOURCE_BOM_SCHEMA,
            "decision": BUILDER.SOURCE_BOM_PASS,
            "artifacts": [],
            "blockers": [],
        }
        raw = BUILDER.SOURCE_BOM.canonical_json_bytes(measured)

        def same(*_args: object) -> dict[str, object]:
            return measured

        BUILDER.remeasure_source_bom(
            raw,
            android_root=Path("/android"),
            control_root=Path("/control"),
            artifact_root=Path("/artifacts"),
            resolved_manifest=Path("/manifest.xml"),
            measure=same,
        )

        def changed(*_args: object) -> dict[str, object]:
            return {**measured, "blockers": ["dirty"]}

        with self.assertRaisesRegex(BUILDER.RawElfBuildError, "byte-for-byte"):
            BUILDER.remeasure_source_bom(
                raw,
                android_root=Path("/android"),
                control_root=Path("/control"),
                artifact_root=Path("/artifacts"),
                resolved_manifest=Path("/manifest.xml"),
                measure=changed,
            )

    def test_lane_markers_are_positive_and_negative_gates(self) -> None:
        p01 = BUILDER.LANES["p01_userdebug_pre_daemon"].artifacts[0]
        valid = b"\x00".join(p01.required_markers)
        BUILDER.validate_artifact_markers(valid, p01)
        with self.assertRaisesRegex(BUILDER.RawElfBuildError, "omits required"):
            BUILDER.validate_artifact_markers(valid.replace(p01.required_markers[0], b""), p01)
        with self.assertRaisesRegex(BUILDER.RawElfBuildError, "forbidden lane"):
            BUILDER.validate_artifact_markers(
                valid + b"\x00" + p01.forbidden_markers[0], p01
            )
        with self.assertRaisesRegex(BUILDER.RawElfBuildError, "retired Agent"):
            BUILDER.validate_artifact_markers(valid + b"\x00OpenClaw", p01)

    def test_path_leak_gate_catches_exact_host_paths(self) -> None:
        BUILDER.validate_no_path_leaks(b"relative/source.rs", (Path("/secret/build"),), "elf")
        with self.assertRaisesRegex(BUILDER.RawElfBuildError, "unremapped"):
            BUILDER.validate_no_path_leaks(
                b"prefix /secret/build/crate/src.rs suffix",
                (Path("/secret/build"),),
                "elf",
            )

    def test_artifact_inspection_uses_supplied_closed_environment(self) -> None:
        specification = BUILDER.LANES["common"].artifacts[0]
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[16:18] = (3).to_bytes(2, "little")
        header[18:20] = (183).to_bytes(2, "little")
        artifact = bytes(header) + b"\x00".join(specification.required_markers)
        environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "LD_LIBRARY_PATH": "/snapshot/toolchain/sysroot/usr/lib/x86_64-linux-gnu",
            "PATH": "",
            "TZ": "UTC",
        }

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / specification.binary
            path.write_bytes(artifact)
            with mock.patch.dict(
                os.environ,
                {"AMBIENT_MUST_NOT_REACH_READELF": "host-value"},
            ), mock.patch.object(
                BUILDER,
                "run_retained_bounded",
                return_value=self.hardened_readelf().encode("utf-8"),
            ) as run:
                BUILDER.inspect_artifact(
                    path,
                    specification,
                    readelf=mock.sentinel.readelf,
                    environment=environment,
                    leaked_paths=(),
                )

        self.assertEqual(run.call_args.kwargs["env"], environment)
        self.assertNotIn(
            "AMBIENT_MUST_NOT_REACH_READELF",
            run.call_args.kwargs["env"],
        )

    @staticmethod
    def hardened_readelf() -> str:
        return """\
ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           AArch64
Program Headers:
  LOAD 0x0 0x0 0x0 0x10 0x10 R E 0x1000
  LOAD 0x10 0x10 0x10 0x10 0x10 RW 0x1000
  GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x10
  GNU_RELRO 0x10 0x10 0x10 0x10 0x10 R 0x1
      [Requesting program interpreter: /lib/ld-linux-aarch64.so.1]
Dynamic section:
 0x1 (NEEDED) Shared library: [libgcc_s.so.1]
 0x1 (NEEDED) Shared library: [libc.so.6]
 0x1e (FLAGS) BIND_NOW
Version needs section:
  Name: GLIBC_2.17  Flags: none  Version: 2
Displaying notes found in: .note.gnu.build-id
 Build ID: 0123456789abcdef0123456789abcdef01234567
"""

    def test_readelf_hardening_gate_is_closed(self) -> None:
        evidence = BUILDER.parse_and_validate_readelf(self.hardened_readelf(), "fixture")
        self.assertTrue(evidence["gnu_relro"])
        self.assertFalse(evidence["gnu_stack_executable"])
        self.assertEqual(evidence["needed"], ["libgcc_s.so.1", "libc.so.6"])
        self.assertEqual(evidence["maximum_glibc"], "GLIBC_2.17")
        self.assertEqual(
            evidence["aarch64_stack_protector_guard"],
            {
                "loader_dt_needed": False,
                "undefined_dynamic_symbol": None,
                "version": None,
                "version_provider": None,
                "loader_bound_undefined_symbols": [],
            },
        )

        daemon = self.hardened_readelf().replace(
            " 0x1 (NEEDED) Shared library: [libc.so.6]",
            " 0x1 (NEEDED) Shared library: [libm.so.6]\n"
            " 0x1 (NEEDED) Shared library: [libc.so.6]",
        )
        BUILDER.parse_and_validate_readelf(
            daemon,
            "daemon",
            allowed_needed=BUILDER.ROLE_NEEDED["daemon"],
        )
        with self.assertRaisesRegex(BUILDER.RawElfBuildError, "dependency closure"):
            BUILDER.parse_and_validate_readelf(daemon, "tool")

        loader_needed = self.hardened_readelf().replace(
            " 0x1 (NEEDED) Shared library: [libc.so.6]",
            " 0x1 (NEEDED) Shared library: [ld-linux-aarch64.so.1]\n"
            " 0x1 (NEEDED) Shared library: [libc.so.6]",
        ).replace(
            "Version needs section:\n"
            "  Name: GLIBC_2.17  Flags: none  Version: 2",
            "Symbol table '.dynsym' contains 2 entries:\n"
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
            "     1: 0000000000000000     0 OBJECT  GLOBAL DEFAULT  UND "
            "__stack_chk_guard@GLIBC_2.17 (5)\n"
            "Version needs section:\n"
            "  0x0020: Version: 1  File: ld-linux-aarch64.so.1  Cnt: 1\n"
            "  0x0030:   Name: GLIBC_2.17  Flags: none  Version: 5\n"
            "  0x0040: Version: 1  File: libc.so.6  Cnt: 1\n"
            "  0x0050:   Name: GLIBC_2.17  Flags: none  Version: 2",
        )
        with self.assertRaisesRegex(BUILDER.RawElfBuildError, "PT_INTERP"):
            BUILDER.parse_and_validate_readelf(
                loader_needed,
                "tool",
                allowed_needed=BUILDER.ROLE_NEEDED["daemon"],
            )
        loader_evidence = BUILDER.parse_and_validate_readelf(
            loader_needed,
            "daemon",
            allowed_needed=BUILDER.ROLE_NEEDED["daemon"],
            allow_loader_for_stack_guard=True,
        )
        self.assertEqual(
            loader_evidence["aarch64_stack_protector_guard"],
            {
                "loader_dt_needed": True,
                "undefined_dynamic_symbol": "__stack_chk_guard@GLIBC_2.17",
                "version": "GLIBC_2.17",
                "version_provider": "ld-linux-aarch64.so.1",
                "loader_bound_undefined_symbols": [
                    "__stack_chk_guard@GLIBC_2.17"
                ],
            },
        )
        for malformed in (
            loader_needed.replace(
                "     1: 0000000000000000     0 OBJECT  GLOBAL DEFAULT  UND "
                "__stack_chk_guard@GLIBC_2.17 (5)\n",
                "",
            ),
            loader_needed.replace(
                "__stack_chk_guard@GLIBC_2.17 (5)",
                "__stack_chk_guard@GLIBC_2.18 (5)",
            ),
            loader_needed.replace(
                "__stack_chk_guard@GLIBC_2.17 (5)\n",
                "__stack_chk_guard@GLIBC_2.17 (5)\n"
                "     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND "
                "unexpected@GLIBC_2.17 (5)\n",
            ),
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(BUILDER.RawElfBuildError, "exclusively"):
                    BUILDER.parse_and_validate_readelf(
                        malformed,
                        "daemon",
                        allowed_needed=BUILDER.ROLE_NEEDED["daemon"],
                        allow_loader_for_stack_guard=True,
                    )

        with self.assertRaisesRegex(BUILDER.RawElfBuildError, "GLIBC_2.36"):
            BUILDER.parse_and_validate_readelf(
                self.hardened_readelf().replace("GLIBC_2.17", "GLIBC_2.37"),
                "tool",
            )

        for replacement, error in (
            (("GNU_RELRO", "NO_RELRO"), "GNU_RELRO"),
            (("BIND_NOW", "LAZY"), "immediate"),
            (("GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW ", "GNU_STACK 0x0 0x0 0x0 0x0 0x0 RWE "), "non-executable"),
            (("Shared library: [libc.so.6]", "Shared library: [libevil.so]"), "unexpected shared-library"),
        ):
            with self.subTest(error=error):
                with self.assertRaisesRegex(BUILDER.RawElfBuildError, error):
                    BUILDER.parse_and_validate_readelf(
                        self.hardened_readelf().replace(*replacement), "fixture"
                    )

    def test_environment_is_controlled_remapped_and_variant_typed(self) -> None:
        retained = {
            role: mock.Mock(fd_path=f"/proc/self/fd/{descriptor}")
            for descriptor, role in enumerate(
                ("cargo", "rustc", "host_linker", "linker", "ar", "readelf"),
                start=101,
            )
        }
        common = BUILDER.build_environment(
            lane=BUILDER.LANES["common"],
            target_dir=Path("/build/target"),
            cargo_home=Path("/build/cargo-home"),
            rust_toolchain_root=Path("/tool/rust"),
            cargo=retained["cargo"],
            rustc=retained["rustc"],
            host_linker=retained["host_linker"],
            linker=retained["linker"],
            ar=retained["ar"],
            readelf=retained["readelf"],
            android_root=Path("/src/android"),
            artifact_root=Path("/build/empty-artifacts"),
            resolved_manifest=Path("/evidence/manifest.xml"),
            output_dir=Path("/build/output"),
            target_sysroot=Path("/snapshot/toolchain/sysroot"),
            target_compiler_bin=Path("/snapshot/toolchain/sysroot/usr/bin"),
            target_gcc_libdir=Path(
                "/snapshot/toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12"
            ),
            target_binutils_dir=Path(
                "/snapshot/toolchain/sysroot/usr/aarch64-linux-gnu/bin"
            ),
            target_host_runtime_libdir=Path(
                "/snapshot/toolchain/sysroot/usr/lib/x86_64-linux-gnu"
            ),
        )
        self.assertNotIn("HOME", common)
        self.assertNotIn("TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT", common)
        self.assertEqual(common["CARGO_NET_OFFLINE"], "true")
        self.assertIn("/usr/src/trillionnium-os", common["CARGO_ENCODED_RUSTFLAGS"])
        self.assertEqual(common["PATH"], "")
        self.assertEqual(common["RUSTC"], "/proc/self/fd/102")
        self.assertEqual(
            common["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"],
            "/proc/self/fd/103",
        )
        self.assertNotIn("CC", common)
        self.assertEqual(
            common["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER"],
            "/proc/self/fd/104",
        )
        self.assertEqual(
            common["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR"],
            "/proc/self/fd/105",
        )
        self.assertIn(
            "linker=/proc/self/fd/104", common["CARGO_ENCODED_RUSTFLAGS"]
        )
        self.assertEqual(
            common["LD_LIBRARY_PATH"],
            "/snapshot/toolchain/sysroot/usr/lib/x86_64-linux-gnu",
        )
        self.assertEqual(
            common["CFLAGS_aarch64_unknown_linux_gnu"],
            "--sysroot=/snapshot/toolchain/sysroot "
            "-B/snapshot/toolchain/sysroot/usr/bin "
            "-B/snapshot/toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12 "
            "-B/snapshot/toolchain/sysroot/usr/aarch64-linux-gnu/bin",
        )

        p01 = BUILDER.build_environment(
            lane=BUILDER.LANES["p01_userdebug_pre_daemon"],
            target_dir=Path("/build/target"),
            cargo_home=Path("/build/cargo-home"),
            rust_toolchain_root=Path("/tool/rust"),
            cargo=retained["cargo"],
            rustc=retained["rustc"],
            host_linker=retained["host_linker"],
            linker=retained["linker"],
            ar=retained["ar"],
            readelf=retained["readelf"],
            android_root=Path("/src/android"),
            artifact_root=Path("/build/empty-artifacts"),
            resolved_manifest=Path("/evidence/manifest.xml"),
            output_dir=Path("/build/output"),
            target_sysroot=Path("/snapshot/toolchain/sysroot"),
            target_compiler_bin=Path("/snapshot/toolchain/sysroot/usr/bin"),
            target_gcc_libdir=Path(
                "/snapshot/toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12"
            ),
            target_binutils_dir=Path(
                "/snapshot/toolchain/sysroot/usr/aarch64-linux-gnu/bin"
            ),
            target_host_runtime_libdir=Path(
                "/snapshot/toolchain/sysroot/usr/lib/x86_64-linux-gnu"
            ),
        )
        self.assertEqual(
            p01["TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT"], "userdebug"
        )

    def test_ambient_cargo_configuration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            control = root / "control"
            cargo_home = root / "cargo-home"
            control.mkdir()
            cargo_home.mkdir()
            BUILDER.reject_ambient_cargo_configuration(control, cargo_home)
            (cargo_home / "config.toml").write_text("[net]\noffline = false\n")
            with self.assertRaisesRegex(BUILDER.RawElfBuildError, "Cargo home"):
                BUILDER.reject_ambient_cargo_configuration(control, cargo_home)

    def test_receipt_is_canonical_deterministic_and_host_only(self) -> None:
        self.assertEqual(
            BUILDER.RECEIPT_ID_SCOPE,
            "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)",
        )
        first = {
            "schema": BUILDER.RECEIPT_SCHEMA,
            "decision": BUILDER.PASS,
            "release_status": BUILDER.PRODUCT_HOLD,
            "posture": {"host_only": True, "release_allowed": False},
        }
        second = json.loads(json.dumps(first))
        first_raw = BUILDER.finalize_receipt(first)
        second_raw = BUILDER.finalize_receipt(second)
        self.assertEqual(first_raw, second_raw)
        parsed = json.loads(first_raw)
        preimage = dict(parsed)
        receipt_id = preimage.pop("receipt_id")
        self.assertEqual(
            receipt_id,
            "sha256:" + BUILDER.sha256_bytes(BUILDER.canonical_json_bytes(preimage)),
        )
        self.assertFalse(parsed["posture"]["release_allowed"])


if __name__ == "__main__":
    unittest.main()
