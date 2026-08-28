from __future__ import annotations

import errno
import hashlib
import importlib.util
import inspect
import json
import os
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "build_shell_exec_artifact_set.py"
SPEC = importlib.util.spec_from_file_location("build_shell_exec_artifact_set", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def elf(
    *,
    machine: int = 183,
    elf_type: int = 2,
    dynamic_tags: tuple[int, ...] = (0,),
) -> bytes:
    """Return a small structurally valid static AArch64 ELF test image."""

    raw = bytearray(512)
    raw[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        raw,
        16,
        elf_type,
        machine,
        1,
        0x400100,
        64,
        0,
        0,
        64,
        56,
        3,
        0,
        0,
        0,
    )
    # One read/execute load mapping the complete file.
    struct.pack_into(
        "<IIQQQQQQ",
        raw,
        64,
        BUILD.PT_LOAD,
        5,
        0,
        0x400000,
        0x400000,
        len(raw),
        len(raw),
        0x1000,
    )
    dynamic_offset = 0x180
    dynamic_bytes = 16 * len(dynamic_tags)
    struct.pack_into(
        "<IIQQQQQQ",
        raw,
        64 + 56,
        BUILD.PT_DYNAMIC,
        4,
        dynamic_offset,
        0x400000 + dynamic_offset,
        0x400000 + dynamic_offset,
        dynamic_bytes,
        dynamic_bytes,
        8,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        raw,
        64 + 112,
        BUILD.PT_GNU_STACK,
        6,
        0,
        0,
        0,
        0,
        0,
        16,
    )
    for index, tag in enumerate(dynamic_tags):
        struct.pack_into("<qQ", raw, dynamic_offset + index * 16, tag, 0)
    return bytes(raw)


def mutate_program_header(raw: bytes, index: int, field: int, value: int) -> bytes:
    result = bytearray(raw)
    fields = list(struct.unpack_from("<IIQQQQQQ", result, 64 + index * 56))
    fields[field] = value
    struct.pack_into("<IIQQQQQQ", result, 64 + index * 56, *fields)
    return bytes(result)


def retained_test_executable(path: Path, raw: bytes):
    path.write_bytes(raw)
    path.chmod(0o555)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    return BUILD.raw_primitives.RetainedExecutable(
        role="test retained executable",
        path=path,
        descriptor=descriptor,
        initial_metadata=os.fstat(descriptor),
        initial_bytes=raw,
    )


class ShellExecArtifactSetTests(unittest.TestCase):
    def test_exact_product_build_closure_is_locked(self) -> None:
        self.assertEqual(BUILD.TARGET, "aarch64-unknown-linux-musl")
        self.assertEqual(BUILD.HOST_TARGET, "x86_64-unknown-linux-gnu")
        self.assertEqual(BUILD.FEATURES, ("android-product",))
        self.assertEqual(BUILD.RUST_VERSION, "1.95.0")
        self.assertEqual(BUILD.ZIG_VERSION, "0.14.1")
        self.assertEqual(BUILD.AARCH64_PRODUCT_USER_VA_LIMIT, 1 << 48)
        # Rust 1.95 accepts the legacy stable direct-LLD spelling.  The
        # expanded `gnu-lld` spelling would require nightly
        # `-Z unstable-options` and make the real stable build fail before
        # compiling any source.
        self.assertEqual(BUILD.RUSTC_LINKER_FLAVOR, "ld.lld")
        self.assertEqual(
            [item[1] for item in BUILD.ARTIFACTS],
            [
                "trillionnium-agent-shell",
                "trillionnium-shell-exec-broker-userdebug",
                "trillionnium-shell-exec-worker-userdebug",
            ],
        )
        self.assertEqual(
            BUILD.PUBLISHED_NAMES,
            {
                *(item[1] for item in BUILD.ARTIFACTS),
                BUILD.RECEIPT_NAME,
            },
        )

    def test_all_build_custody_inputs_are_explicit_and_required(self) -> None:
        required = {
            action.dest
            for action in BUILD.parser()._actions
            if getattr(action, "required", False)
        }
        self.assertEqual(
            required,
            {
                "workspace",
                "source_bom",
                "android_root",
                "artifact_root",
                "resolved_manifest",
                "output",
                "cargo",
                "rustc",
                "linker",
                "host_linker_wrapper",
                "zig",
                "qemu_aarch64_static",
                "host_dynamic_loader",
                "host_libc",
                "host_libgcc_s",
                "host_libm",
                "host_libdl",
                "host_libpthread",
                "host_librt",
                "host_libz",
                "host_dev_null",
                "rust_toolchain_root",
                "zig_toolchain_root",
                "cargo_home",
            },
        )

    def test_host_linker_environment_is_literal_fd_only_and_cache_scoped(self) -> None:
        environment = BUILD.build_environment(
            workspace=Path("/control/trillionnium-os"),
            android_root=Path("/android"),
            artifact_root=Path("/empty-artifacts"),
            resolved_manifest=Path("/evidence/resolved.xml"),
            output_parent=Path("/output"),
            role_descriptors={
                role: 100 + index
                for index, role in enumerate(BUILD.BUILD_INPUT_ROLES)
            },
            rust_toolchain_root=Path("/rust-1.95"),
            zig_toolchain_root=Path("/zig-0.14.1"),
        )
        self.assertEqual(
            set(environment),
            {
                "CARGO_BUILD_JOBS",
                "CARGO_CACHE_RUSTC_INFO",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_HOME",
                "CARGO_INCREMENTAL",
                "CARGO_NET_OFFLINE",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
                "CARGO_TARGET_DIR",
                "HOME",
                "LANG",
                "LC_ALL",
                "PATH",
                "RUSTC",
                "RUST_BACKTRACE",
                "SOURCE_DATE_EPOCH",
                "TMPDIR",
                "TRILLIONNIUM_ZIG_REAL",
                "TZ",
                "ZIG_GLOBAL_CACHE_DIR",
                "ZIG_LIB_DIR",
                "ZIG_LOCAL_CACHE_DIR",
            },
        )
        self.assertEqual(environment["PATH"], "")
        self.assertEqual(environment["CARGO_HOME"], "/proc/self/fd/106/cargo-home")
        self.assertEqual(
            environment["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"],
            "/proc/self/fd/102",
        )
        self.assertEqual(environment["RUSTC"], "/proc/self/fd/100")
        self.assertEqual(environment["TRILLIONNIUM_ZIG_REAL"], "/proc/self/fd/103")
        self.assertEqual(environment["ZIG_LIB_DIR"], "/proc/self/fd/104/lib")
        self.assertEqual(
            environment["ZIG_GLOBAL_CACHE_DIR"],
            "/proc/self/fd/106/zig-global-cache",
        )
        self.assertEqual(
            environment["ZIG_LOCAL_CACHE_DIR"],
            "/proc/self/fd/106/zig-local-cache",
        )
        self.assertNotIn("CC", environment)
        self.assertNotIn("RUSTC_LINKER", environment)
        self.assertNotIn("cc", environment.values())

    def test_operational_cargo_home_uses_retained_payload_roots_only(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as temporary:
            root = Path(temporary)
            target = root / "target"
            source = root / "input"
            target.mkdir(mode=0o700)
            source.mkdir(mode=0o700)
            (source / "registry").mkdir(mode=0o555)
            (source / "git").mkdir(mode=0o555)
            (source / ".global-cache").write_bytes(b"mutable metadata is input-only")
            target_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                BUILD.prepare_operational_cargo_home(
                    target_fd,
                    source_fd,
                    105,
                )
                cargo_home = target / "cargo-home"
                self.assertEqual(
                    set(os.listdir(cargo_home)), {"registry", "git"}
                )
                self.assertEqual(
                    os.readlink(cargo_home / "registry"),
                    "/proc/self/fd/105/registry",
                )
                self.assertEqual(
                    os.readlink(cargo_home / "git"),
                    "/proc/self/fd/105/git",
                )
                self.assertFalse((cargo_home / ".global-cache").exists())
            finally:
                os.close(source_fd)
                os.close(target_fd)

    def test_receipt_environment_canonicalizes_every_runtime_descriptor(self) -> None:
        environment = {
            "RUSTC": "/proc/self/fd/100",
            "CARGO_HOME": "/proc/self/fd/106/cargo-home",
            "CARGO_ENCODED_RUSTFLAGS": (
                "-C\x1flinker=/proc/self/fd/101\x1f--remap-path-prefix\x1f"
                "/proc/self/fd/104=/usr/src/zig"
            ),
        }
        projected = BUILD.receipt_environment(
            environment,
            role_descriptors={
                role: 100 + index
                for index, role in enumerate(BUILD.BUILD_INPUT_ROLES)
            },
        )
        self.assertEqual(projected["RUSTC"], "@RUSTC@")
        self.assertEqual(projected["CARGO_HOME"], "@TARGET_SCRATCH@/cargo-home")
        self.assertIn("linker=@TARGET_LINKER@", projected["CARGO_ENCODED_RUSTFLAGS"])
        self.assertIn("@ZIG_ROOT@=/usr/src/zig", projected["CARGO_ENCODED_RUSTFLAGS"])
        self.assertNotIn("/proc/self/fd/", repr(projected))
        with self.assertRaisesRegex(BUILD.BuildError, "unbound inherited descriptor"):
            BUILD.receipt_environment(
                {"RUSTC": "/proc/self/fd/1000"},
                role_descriptors={
                    role: 100 + index
                    for index, role in enumerate(BUILD.BUILD_INPUT_ROLES)
                },
            )

    @unittest.skipUnless(sys.platform == "linux", "Landlock is Linux-specific")
    def test_landlock_allows_only_explicit_reads_and_target_writes(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as temporary:
            root = Path(temporary)
            allowed = root / "receipt-bound-source"
            target = root / "private-target"
            allowed.mkdir(mode=0o700)
            target.mkdir(mode=0o700)
            (allowed / "member").write_bytes(b"receipt-bound")
            ambient = root / "out-of-bom-sentinel"
            ambient.write_bytes(b"ambient-secret")
            outside_write = root / "outside-write"
            allowed_fd = os.open(allowed, os.O_PATH | os.O_DIRECTORY)
            target_fd = os.open(target, os.O_PATH | os.O_DIRECTORY)
            ruleset = None
            try:
                try:
                    ruleset = BUILD.RetainedLandlockRuleset.create(
                        [
                            (
                                "receipt_bound_source",
                                allowed_fd,
                                BUILD.LANDLOCK_READ_ONLY,
                                "directory",
                            ),
                            (
                                "private_target",
                                target_fd,
                                BUILD.LANDLOCK_TARGET,
                                "directory",
                            ),
                        ]
                    )
                except BUILD.BuildError as error:
                    self.skipTest(str(error))
                record = ruleset.receipt_record()
                self.assertEqual(
                    [rule["role"] for rule in record["rules"]],
                    ["receipt_bound_source", "private_target"],
                )
                self.assertNotIn("/proc", repr(record))

                read_pipe, write_pipe = os.pipe2(os.O_CLOEXEC)
                pid = os.fork()
                if pid == 0:  # pragma: no cover - asserted through parent result
                    os.close(read_pipe)
                    status = 0
                    result = b"PASS"
                    try:
                        BUILD.restrict_current_process_with_landlock(
                            ruleset.descriptor
                        )
                        if (allowed / "member").read_bytes() != b"receipt-bound":
                            raise RuntimeError("allowed input bytes changed")
                        if (
                            Path(f"/proc/self/fd/{allowed_fd}/member").read_bytes()
                            != b"receipt-bound"
                        ):
                            raise RuntimeError("allowed procfd input bytes changed")
                        for forbidden in (
                            ambient,
                            Path("/etc/passwd"),
                            Path("/proc/self/status"),
                        ):
                            try:
                                forbidden.read_bytes()
                            except PermissionError as error:
                                if error.errno != errno.EACCES:
                                    raise
                            else:
                                raise RuntimeError(
                                    f"ambient read escaped Landlock: {forbidden}"
                                )
                        try:
                            (allowed / "forbidden-write").write_bytes(b"escape")
                        except PermissionError as error:
                            if error.errno != errno.EACCES:
                                raise
                        else:
                            raise RuntimeError("read-only input accepted a write")
                        try:
                            outside_write.write_bytes(b"escape")
                        except PermissionError as error:
                            if error.errno != errno.EACCES:
                                raise
                        else:
                            raise RuntimeError("ambient directory accepted a write")
                        (target / "written").write_bytes(b"target-only")
                    except BaseException as error:
                        status = 1
                        result = repr(error).encode("utf-8", errors="replace")
                    try:
                        os.write(write_pipe, result[:4096])
                    finally:
                        os.close(write_pipe)
                    os._exit(status)
                os.close(write_pipe)
                observed = os.read(read_pipe, 4097)
                os.close(read_pipe)
                _pid, wait_status = os.waitpid(pid, 0)
                self.assertTrue(os.WIFEXITED(wait_status), observed.decode(errors="replace"))
                self.assertEqual(
                    os.WEXITSTATUS(wait_status),
                    0,
                    observed.decode(errors="replace"),
                )
                self.assertEqual(observed, b"PASS")
                self.assertEqual((target / "written").read_bytes(), b"target-only")
                self.assertFalse((allowed / "forbidden-write").exists())
                self.assertFalse(outside_write.exists())
                self.assertEqual(ambient.read_bytes(), b"ambient-secret")
            finally:
                if ruleset is not None:
                    ruleset.close()
                os.close(target_fd)
                os.close(allowed_fd)

    @unittest.skipUnless(
        sys.platform == "linux" and platform.machine() == "x86_64",
        "the exact Cargo boundary fixture is Linux x86-64 specific",
    )
    def test_exact_cargo_build_rs_cannot_read_out_of_bom_sentinel(self) -> None:
        input_names = {
            "rust": "TRILLIONNIUM_SHELL_EXEC_TEST_RUST_TOOLCHAIN_ROOT",
            "zig": "TRILLIONNIUM_SHELL_EXEC_TEST_ZIG_TOOLCHAIN_ROOT",
            "cargo_home": "TRILLIONNIUM_SHELL_EXEC_TEST_CARGO_HOME",
        }
        configured = {
            role: os.environ.get(variable)
            for role, variable in input_names.items()
        }
        if not all(configured.values()):
            self.skipTest(
                "set " + ", ".join(input_names.values()) + " for the exact toolchain test"
            )
        rust_root = Path(str(configured["rust"])).resolve(strict=True)
        zig_root = Path(str(configured["zig"])).resolve(strict=True)
        cargo_home_path = Path(str(configured["cargo_home"])).resolve(strict=True)
        runtime_paths = {
            "host_dynamic_loader": Path(
                "/lib64/ld-linux-x86-64.so.2"
            ).resolve(strict=True),
            "host_libc": Path("/lib/x86_64-linux-gnu/libc.so.6").resolve(
                strict=True
            ),
            "host_libgcc_s": Path(
                "/lib/x86_64-linux-gnu/libgcc_s.so.1"
            ).resolve(strict=True),
            "host_libm": Path("/lib/x86_64-linux-gnu/libm.so.6").resolve(
                strict=True
            ),
            "host_libdl": Path("/lib/x86_64-linux-gnu/libdl.so.2").resolve(
                strict=True
            ),
            "host_libpthread": Path(
                "/lib/x86_64-linux-gnu/libpthread.so.0"
            ).resolve(strict=True),
            "host_librt": Path("/lib/x86_64-linux-gnu/librt.so.1").resolve(
                strict=True
            ),
            "host_libz": Path("/lib/x86_64-linux-gnu/libz.so.1").resolve(
                strict=True
            ),
        }

        # RetainedDirectoryChain deliberately rejects sticky ancestors such as
        # /tmp, so place this ephemeral fixture below the controlled tools tree.
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            source = workspace / "src"
            target = root / "private-target"
            android = root / "unrelated-android"
            artifacts = root / "unrelated-artifacts"
            output_parent = root / "publication-parent"
            for directory in (
                workspace,
                source,
                target,
                android,
                artifacts,
                output_parent,
            ):
                directory.mkdir(mode=0o700)
            for name in ("home", "tmp", "zig-global-cache", "zig-local-cache"):
                (target / name).mkdir(mode=0o700)
            manifest = root / "unrelated-resolved-manifest.xml"
            manifest.write_bytes(b"<manifest/>\n")
            allowed = workspace / "receipt-bound-member"
            allowed.write_bytes(b"allowed-source-bytes")
            ambient = root / "out-of-bom-sentinel"
            ambient.write_bytes(b"ambient-secret")
            publication = output_parent / "must-not-publish"
            (workspace / "Cargo.toml").write_text(
                """[package]
name = "landlock-build-rs-fixture"
version = "0.0.0"
edition = "2024"
build = "build.rs"

[lib]
path = "src/lib.rs"

[[bin]]
name = "landlock-build-rs-fixture"
path = "src/main.rs"

[workspace]
""",
                encoding="utf-8",
            )
            (workspace / "Cargo.lock").write_text(
                """# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "landlock-build-rs-fixture"
version = "0.0.0"
""",
                encoding="utf-8",
            )
            (source / "lib.rs").write_text(
                "pub fn fixture() -> u8 { 1 }\n", encoding="utf-8"
            )
            (source / "main.rs").write_text(
                "fn main() { assert_eq!(landlock_build_rs_fixture::fixture(), 1); }\n",
                encoding="utf-8",
            )
            (workspace / "build.rs").write_text(
                "fn main() {\n"
                f"    let _ = std::fs::read({json.dumps(str(ambient))})"
                '.expect("out-of-BOM read unexpectedly denied the malicious build");\n'
                "}\n",
                encoding="utf-8",
            )

            retained_tools = []
            retained_runtime = []
            retained_directories = []
            dev_null = None
            ruleset = None
            build_roles = None
            target_fd = -1
            try:
                cargo = BUILD.raw_primitives.open_retained_executable(
                    rust_root / "bin/cargo", "exact fixture cargo"
                )
                retained_tools.append(cargo)
                rustc = BUILD.raw_primitives.open_retained_executable(
                    rust_root / "bin/rustc", "exact fixture rustc"
                )
                retained_tools.append(rustc)
                linker = BUILD.raw_primitives.open_retained_executable(
                    rust_root
                    / "lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld",
                    "exact fixture target linker",
                )
                retained_tools.append(linker)
                wrapper = BUILD.raw_primitives.open_retained_executable(
                    zig_root / "host-tools/zig-cc-wrapper",
                    "exact fixture host-linker wrapper",
                )
                retained_tools.append(wrapper)
                zig = BUILD.raw_primitives.open_retained_executable(
                    zig_root / "zig", "exact fixture Zig"
                )
                retained_tools.append(zig)
                for role, label, _names in BUILD.HOST_RUNTIME_INPUTS:
                    retained = BUILD.RetainedRegular.open(
                        runtime_paths[role], label, BUILD.MAX_HOST_RUNTIME_BYTES
                    )
                    BUILD.validate_host_runtime_elf(retained.raw, label)
                    retained_runtime.append((role, retained))
                dev_null = BUILD.RetainedDevNull.open(Path("/dev/null"))

                workspace_input = (
                    BUILD.filesystem_primitives.RetainedDirectoryChain.open(
                        workspace, "exact fixture workspace"
                    )
                )
                retained_directories.append(workspace_input)
                rust_input = BUILD.filesystem_primitives.RetainedDirectoryChain.open(
                    rust_root, "exact fixture Rust root"
                )
                retained_directories.append(rust_input)
                zig_input = BUILD.filesystem_primitives.RetainedDirectoryChain.open(
                    zig_root, "exact fixture Zig root"
                )
                retained_directories.append(zig_input)
                cargo_input = (
                    BUILD.filesystem_primitives.RetainedDirectoryChain.open(
                        cargo_home_path, "exact fixture Cargo home"
                    )
                )
                retained_directories.append(cargo_input)
                target_fd = os.open(
                    target, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
                )
                build_roles = BUILD.RetainedBuildRoleDescriptors.open(
                    {
                        "rustc": rustc.descriptor,
                        "target_linker": linker.descriptor,
                        "host_linker_wrapper": wrapper.descriptor,
                        "zig": zig.descriptor,
                        "zig_root": zig_input.directory_fd,
                        "cargo_home_input": cargo_input.directory_fd,
                        "target": target_fd,
                        "cargo": cargo.descriptor,
                    }
                )
                role_descriptors = build_roles.descriptors
                BUILD.prepare_operational_cargo_home(
                    target_fd,
                    cargo_input.directory_fd,
                    role_descriptors["cargo_home_input"],
                )
                environment = BUILD.build_environment(
                    workspace=workspace,
                    android_root=android,
                    artifact_root=artifacts,
                    resolved_manifest=manifest,
                    output_parent=output_parent,
                    role_descriptors=role_descriptors,
                    rust_toolchain_root=rust_root,
                    zig_toolchain_root=zig_root,
                )
                ruleset = BUILD.create_build_landlock_ruleset(
                    workspace_fd=workspace_input.directory_fd,
                    rust_root_fd=rust_input.directory_fd,
                    zig_root_fd=zig_input.directory_fd,
                    cargo_home_fd=cargo_input.directory_fd,
                    target_fd=target_fd,
                    build_tools=(
                        ("cargo_executable", cargo),
                        ("rustc_executable", rustc),
                        ("target_linker_executable", linker),
                        ("host_linker_wrapper_executable", wrapper),
                        ("zig_executable", zig),
                    ),
                    runtime_inputs=retained_runtime,
                    dev_null=dev_null,
                )
                policy_roles = {
                    rule["role"] for rule in ruleset.receipt_record()["rules"]
                }
                self.assertNotIn("android_source", policy_roles)
                self.assertNotIn("source_bom_artifact_root", policy_roles)
                self.assertNotIn("resolved_manifest", policy_roles)
                self.assertNotIn("custodian_role_fd_directory", policy_roles)
                command = (
                    "build",
                    "--locked",
                    "--frozen",
                    "--offline",
                    "--quiet",
                    "--release",
                    "--target",
                    BUILD.TARGET,
                    "--bin",
                    "landlock-build-rs-fixture",
                )

                def cargo_build_then_publish() -> None:
                    BUILD.run_retained(
                        cargo,
                        command,
                        environment=environment,
                        expected_environment=set(environment),
                        cwd=workspace,
                        timeout=300,
                        maximum_output=2 * 1024 * 1024,
                        label="malicious out-of-BOM build.rs fixture",
                        pass_fds=tuple(role_descriptors.values()),
                        execution_descriptor=role_descriptors["cargo"],
                        landlock_ruleset=ruleset,
                    )
                    publication.write_bytes(b"incorrectly published")

                with self.assertRaisesRegex(BUILD.BuildError, "status 101"):
                    cargo_build_then_publish()
                self.assertFalse(publication.exists())
                self.assertEqual(ambient.read_bytes(), b"ambient-secret")

                (workspace / "build.rs").write_text(
                    "use std::{fs, io::ErrorKind, path::PathBuf};\n"
                    "fn denied(path: &str) {\n"
                    "    match fs::read(path) {\n"
                    "        Err(error) if error.kind() == ErrorKind::PermissionDenied => (),\n"
                    '        other => panic!("ambient read was not denied: {other:?}"),\n'
                    "    }\n"
                    "}\n"
                    "fn main() {\n"
                    f"    assert_eq!(fs::read({json.dumps(str(allowed))}).unwrap(), "
                    'b"allowed-source-bytes");\n'
                    f"    denied({json.dumps(str(ambient))});\n"
                    '    denied("/etc/passwd");\n'
                    '    denied("/proc/self/status");\n'
                    '    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());\n'
                    '    fs::write(out.join("landlock-positive"), b"target-only").unwrap();\n'
                    "}\n",
                    encoding="utf-8",
                )
                positive_output = BUILD.run_retained(
                    cargo,
                    command,
                    environment=environment,
                    expected_environment=set(environment),
                    cwd=workspace,
                    timeout=300,
                    maximum_output=2 * 1024 * 1024,
                    label="positive closed build.rs fixture",
                    pass_fds=tuple(role_descriptors.values()),
                    execution_descriptor=role_descriptors["cargo"],
                    landlock_ruleset=ruleset,
                )
                self.assertEqual(positive_output, b"")
                positive_markers = list(
                    target.glob(
                        f"{BUILD.TARGET}/release/build/*/out/landlock-positive"
                    )
                )
                self.assertEqual(len(positive_markers), 1)
                self.assertEqual(positive_markers[0].read_bytes(), b"target-only")
                self.assertEqual(ambient.read_bytes(), b"ambient-secret")
                self.assertFalse(publication.exists())
                build_roles.assert_stable()
            finally:
                if ruleset is not None:
                    ruleset.close()
                if build_roles is not None:
                    build_roles.close()
                if target_fd >= 0:
                    os.close(target_fd)
                for retained in reversed(retained_directories):
                    retained.close()
                if dev_null is not None:
                    dev_null.close()
                for _role, retained in reversed(retained_runtime):
                    retained.close()
                for retained in reversed(retained_tools):
                    retained.close()

    def test_static_host_closure_elf_is_enforced(self) -> None:
        self.assertEqual(
            BUILD.inspect_static_host_tool(elf(machine=62), "host fixture"),
            {
                "elf_machine": "x86-64",
                "elf_type": "ET_EXEC",
                "pt_interp": None,
                "dt_needed": [],
            },
        )
        with self.assertRaisesRegex(BUILD.BuildError, "x86-64"):
            BUILD.inspect_static_host_tool(elf(), "host fixture")
        with self.assertRaisesRegex(BUILD.BuildError, "DT_NEEDED"):
            BUILD.inspect_static_host_tool(
                elf(machine=62, dynamic_tags=(BUILD.DT_NEEDED, BUILD.DT_NULL)),
                "host fixture",
            )
        interpreter = mutate_program_header(elf(machine=62), 1, 0, BUILD.PT_INTERP)
        with self.assertRaisesRegex(BUILD.BuildError, "PT_INTERP"):
            BUILD.inspect_static_host_tool(interpreter, "host fixture")

    def test_zig_wrapper_is_an_exact_fd_exec_adapter(self) -> None:
        source = (SCRIPT.parent / "zig_cc_exec_wrapper.c").read_text(encoding="utf-8")
        self.assertIn('getenv("TRILLIONNIUM_ZIG_REAL")', source)
        self.assertIn('getenv("ZIG_LIB_DIR")', source)
        self.assertIn('forwarded[1] = (char *)"cc"', source)
        self.assertIn('forwarded[2] = (char *)"-target"', source)
        self.assertIn('forwarded[3] = (char *)"x86_64-linux-gnu"', source)
        self.assertIn('forwarded[4] = (char *)"-mcpu=baseline"', source)
        self.assertIn('self_separator[] = "self/fd/"', source)
        self.assertIn("execve(driver, forwarded, envp)", source)
        for forbidden in ("execvp(", "execlp(", "system(", "popen(", 'getenv("PATH")'):
            self.assertNotIn(forbidden, source)

    def test_closed_tree_mutation_is_rejected_pre_to_post(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as temporary:
            root = Path(temporary)
            member = root / "member"
            member.write_bytes(b"before")
            member.chmod(0o444)
            before = BUILD.measure_closed_tree(
                root,
                "Zig host toolchain closure fixture",
                entry_limit=16,
                byte_limit=1024,
            )
            member.chmod(0o644)
            member.write_bytes(b"after")
            member.chmod(0o444)
            after = BUILD.measure_closed_tree(
                root,
                "Zig host toolchain closure fixture",
                entry_limit=16,
                byte_limit=1024,
            )
            with self.assertRaisesRegex(BUILD.BuildError, "changed during the build"):
                BUILD.require_same_tree(
                    before,
                    after,
                    "Zig host toolchain closure fixture",
                )

    def test_zig_and_cargo_input_inventories_must_be_owner_readonly(self) -> None:
        BUILD.require_immutable_tree(
            {"entries": [{"path": ".", "type": "directory", "mode": "0555"}]},
            "fixture",
        )
        with self.assertRaisesRegex(BUILD.BuildError, "owner-writable"):
            BUILD.require_immutable_tree(
                {
                    "entries": [
                        {"path": "member", "type": "file", "mode": "0644"}
                    ]
                },
                "fixture",
            )

    def test_zig_tree_is_retained_and_remeasured_around_cargo(self) -> None:
        source = inspect.getsource(BUILD.build)
        pre_measure = source.index("zig_inventory = measure_closed_tree(")
        cargo_run = source.index("run_retained(\n            cargo,")
        post_measure = source.index("require_same_tree(\n            zig_inventory,")
        self.assertLess(pre_measure, cargo_run)
        self.assertLess(cargo_run, post_measure)
        self.assertIn("build_roles = RetainedBuildRoleDescriptors.open(", source)
        self.assertIn("role_descriptors = build_roles.descriptors", source)
        self.assertIn("pass_fds=tuple(role_descriptors.values())", source)
        self.assertNotIn("MinimalBuildCustodian.start(", source)
        self.assertIn("zig_root.directory_fd", source)

    def test_cargo_hardlinks_must_be_closed_inside_target_scratch(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as temporary:
            root = Path(temporary)
            target = root / "target"
            output = target / "release" / "fixture"
            peer = target / "release" / "deps" / "fixture-hash"
            peer.parent.mkdir(parents=True)
            output.write_bytes(b"cargo artifact")
            os.link(output, peer)
            target_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(
                    BUILD.read_built_artifact(
                        target_fd, "release/fixture", "Cargo fixture", 1024
                    ),
                    b"cargo artifact",
                )
                os.link(output, root / "external-link")
                with self.assertRaisesRegex(BUILD.BuildError, "outside private"):
                    BUILD.read_built_artifact(
                        target_fd, "release/fixture", "Cargo fixture", 1024
                    )
            finally:
                os.close(target_fd)

    def test_static_aarch64_exec_is_accepted(self) -> None:
        self.assertEqual(
            BUILD.inspect_static_aarch64_elf(elf(), "fixture"),
            {
                "elf_machine": "AArch64",
                "elf_type": "ET_EXEC",
                "pt_interp": None,
                "dt_needed": [],
            },
        )

    def test_empty_or_malformed_program_header_table_is_rejected(self) -> None:
        no_headers = bytearray(elf())
        struct.pack_into("<H", no_headers, 56, 0)
        with self.assertRaisesRegex(BUILD.BuildError, "empty program-header"):
            BUILD.inspect_static_aarch64_elf(bytes(no_headers), "fixture")

        out_of_bounds = bytearray(elf())
        struct.pack_into("<Q", out_of_bounds, 32, len(out_of_bounds) - 1)
        with self.assertRaisesRegex(BUILD.BuildError, "out-of-bounds"):
            BUILD.inspect_static_aarch64_elf(bytes(out_of_bounds), "fixture")

    def test_load_segment_and_entry_point_invariants_are_enforced(self) -> None:
        no_load = mutate_program_header(elf(), 0, 0, 4)
        with self.assertRaisesRegex(BUILD.BuildError, "executable PT_LOAD"):
            BUILD.inspect_static_aarch64_elf(no_load, "fixture")

        non_executable = mutate_program_header(elf(), 0, 1, 4)
        with self.assertRaisesRegex(BUILD.BuildError, "executable PT_LOAD"):
            BUILD.inspect_static_aarch64_elf(non_executable, "fixture")

        entry_outside = bytearray(elf())
        struct.pack_into("<Q", entry_outside, 24, 0x500000)
        with self.assertRaisesRegex(BUILD.BuildError, "entry point"):
            BUILD.inspect_static_aarch64_elf(bytes(entry_outside), "fixture")

        writable_executable = mutate_program_header(elf(), 0, 1, 7)
        with self.assertRaisesRegex(BUILD.BuildError, "writable-executable"):
            BUILD.inspect_static_aarch64_elf(writable_executable, "fixture")

        filesz_larger = mutate_program_header(elf(), 0, 6, 128)
        with self.assertRaisesRegex(BUILD.BuildError, "p_filesz"):
            BUILD.inspect_static_aarch64_elf(filesz_larger, "fixture")

        no_load_alignment = mutate_program_header(elf(), 0, 7, 1)
        with self.assertRaisesRegex(BUILD.BuildError, "smaller than one base page"):
            BUILD.inspect_static_aarch64_elf(no_load_alignment, "fixture")

        exact_uint64_wrap = mutate_program_header(
            elf(), 0, 3, (1 << 64) - len(elf())
        )
        with self.assertRaisesRegex(BUILD.BuildError, "wraps uint64"):
            BUILD.inspect_static_aarch64_elf(exact_uint64_wrap, "fixture")

        at_user_limit = mutate_program_header(
            elf(), 0, 3, BUILD.AARCH64_PRODUCT_USER_VA_LIMIT
        )
        with self.assertRaisesRegex(BUILD.BuildError, "user-address limit"):
            BUILD.inspect_static_aarch64_elf(at_user_limit, "fixture")

        crossing_user_limit = mutate_program_header(
            mutate_program_header(
                elf(), 0, 3, BUILD.AARCH64_PRODUCT_USER_VA_LIMIT - 0x1000
            ),
            0,
            6,
            0x2000,
        )
        with self.assertRaisesRegex(BUILD.BuildError, "user-address limit"):
            BUILD.inspect_static_aarch64_elf(crossing_user_limit, "fixture")

    def test_interp_dynamic_and_stack_invariants_are_enforced(self) -> None:
        interpreter = mutate_program_header(elf(), 1, 0, BUILD.PT_INTERP)
        with self.assertRaisesRegex(BUILD.BuildError, "PT_INTERP"):
            BUILD.inspect_static_aarch64_elf(interpreter, "fixture")

        with self.assertRaisesRegex(BUILD.BuildError, "DT_NEEDED"):
            BUILD.inspect_static_aarch64_elf(elf(dynamic_tags=(1, 0)), "fixture")

        with self.assertRaisesRegex(BUILD.BuildError, "DT_NULL"):
            BUILD.inspect_static_aarch64_elf(elf(dynamic_tags=(2, 2)), "fixture")

        executable_stack = mutate_program_header(elf(), 2, 1, 7)
        with self.assertRaisesRegex(BUILD.BuildError, "executable.*PT_GNU_STACK"):
            BUILD.inspect_static_aarch64_elf(executable_stack, "fixture")

        # A nonzero p_memsz is the valid ELF mechanism for requesting a
        # non-default stack size; both the fixed Zig driver and wrapper use it.
        sized_stack = mutate_program_header(elf(), 2, 6, 0x1000000)
        BUILD.inspect_static_aarch64_elf(sized_stack, "fixture")

        stack_file_bytes = mutate_program_header(
            mutate_program_header(elf(), 2, 6, 1), 2, 5, 1
        )
        with self.assertRaisesRegex(BUILD.BuildError, "malformed PT_GNU_STACK"):
            BUILD.inspect_static_aarch64_elf(stack_file_bytes, "fixture")

        missing_stack = mutate_program_header(elf(), 2, 0, 4)
        with self.assertRaisesRegex(BUILD.BuildError, "exactly one"):
            BUILD.inspect_static_aarch64_elf(missing_stack, "fixture")

    def test_wrong_architecture_and_retired_markers_are_rejected(self) -> None:
        wrong = bytearray(elf())
        struct.pack_into("<H", wrong, 18, 62)
        with self.assertRaisesRegex(BUILD.BuildError, "AArch64"):
            BUILD.inspect_static_aarch64_elf(bytes(wrong), "fixture")
        for marker in BUILD.FORBIDDEN_MARKERS:
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(BUILD.BuildError, "retired"):
                    BUILD.inspect_static_aarch64_elf(elf() + marker, "fixture")

    def test_source_bom_uses_mature_closed_v2_validator(self) -> None:
        with self.assertRaisesRegex(BUILD.BuildError, "closed exact v2 graph"):
            BUILD.validate_source_bom(b"{}")
        raw = b'{"fixture":true}'
        binding = {"file_sha256": hashlib.sha256(raw).hexdigest()}
        with mock.patch.object(
            BUILD.bom_primitives,
            "validate_source_bom_bytes",
            return_value=binding,
        ) as validator:
            self.assertIs(BUILD.validate_source_bom(raw), binding)
        validator.assert_called_once_with(raw)

    def test_explicit_userdebug_dogfood_wrapper_binds_hold_inputs(self) -> None:
        manifest_raw = b'<manifest><project name="fixture" revision="' + b"a" * 40 + b'" /></manifest>\n'
        source = {
            "schema": BUILD.DOGFOOD_SOURCE_SCHEMA,
            "decision": BUILD.DOGFOOD_SOURCE_DECISION,
            "posture": {
                "local_only": True,
                "network_access_performed": False,
                "signed": False,
                "release_pin_published": False,
                "build_authorized": False,
                "ota_authorized": False,
                "device_write_authorized": False,
                "public_release_allowed": False,
                "release_allowed": False,
                "effect_authority": False,
            },
            "source_set": {
                "bytes": 1,
                "schema": "org.trillionnium.p0-cross-repo-source-set.v2",
                "sha256": "1" * 64,
            },
            "resolved_manifest": {
                "producer": "local_repo_manifest_r",
                "bytes": len(manifest_raw),
                "sha256": hashlib.sha256(manifest_raw).hexdigest(),
                "project_count": 1,
                "all_revisions_exact": True,
                "declared_checkout_revision_drift_count": 0,
                "declared_checkout_revision_drifts": [],
            },
            "projects": [
                {
                    "id": "fixture",
                    "checkout": {"root": "fixture", "path": "."},
                    "requirements": {
                        "manifest_required": False,
                        "clean": True,
                        "no_ignored_paths": True,
                    },
                    "manifest": None,
                    "git": {
                        "head": "a" * 40,
                        "clean_nonignored": False,
                        "ignored": {"count": 0, "paths": []},
                    },
                    "failures": ["nonignored_worktree_dirty"],
                }
            ],
            "trees": [],
            "artifacts": [],
            "blockers": ["project_nonignored_worktree_dirty:fixture"],
            "receipt_id_scope": BUILD.DOGFOOD_RECEIPT_ID_SCOPE,
        }
        source["receipt_id"] = "sha256:" + hashlib.sha256(
            BUILD.pretty_json(source)
        ).hexdigest()
        source_raw = BUILD.pretty_json(source)
        wrapper = BUILD.dogfood_primitives.materialize_raw(
            source_raw,
            manifest_raw,
            allow_dirty_userdebug_dogfood=True,
        )
        wrapper_raw = BUILD.dogfood_primitives.canonical_json_bytes(wrapper)
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as temporary:
            wrapper_path = Path(temporary) / BUILD.DOGFOOD_WRAPPER_NAME
            with mock.patch.object(BUILD, "DOGFOOD_WRAPPER_PATH", wrapper_path):
                binding = BUILD.validate_userdebug_dogfood_source(
                    source_raw,
                    wrapper_raw,
                    manifest_raw,
                    wrapper_path=wrapper_path,
                )
            self.assertEqual(binding["file_sha256"], hashlib.sha256(source_raw).hexdigest())
            self.assertEqual(binding["wrapper_sha256"], hashlib.sha256(wrapper_raw).hexdigest())

    def test_userdebug_dogfood_wrapper_rejects_invalid_or_noncanonical_input(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as temporary:
            wrapper_path = Path(temporary) / BUILD.DOGFOOD_WRAPPER_NAME
            with mock.patch.object(BUILD, "DOGFOOD_WRAPPER_PATH", wrapper_path):
                with self.assertRaisesRegex(BUILD.BuildError, "source inputs are invalid"):
                    BUILD.validate_userdebug_dogfood_source(
                        b"{}", b"{}", b"<manifest />", wrapper_path=wrapper_path
                    )

                manifest_raw = b'<manifest><project name="fixture" revision="' + b"a" * 40 + b'" /></manifest>\n'
                source = {
                    "schema": BUILD.DOGFOOD_SOURCE_SCHEMA,
                    "decision": BUILD.DOGFOOD_SOURCE_DECISION,
                    "posture": {
                        "local_only": True,
                        "network_access_performed": False,
                        "signed": False,
                        "release_pin_published": False,
                        "build_authorized": False,
                        "ota_authorized": False,
                        "device_write_authorized": False,
                    },
                    "source_set": {
                        "bytes": 1,
                        "schema": "org.trillionnium.p0-cross-repo-source-set.v2",
                        "sha256": "1" * 64,
                    },
                    "resolved_manifest": {
                        "producer": "local_repo_manifest_r",
                        "bytes": len(manifest_raw),
                        "sha256": hashlib.sha256(manifest_raw).hexdigest(),
                        "project_count": 1,
                        "all_revisions_exact": True,
                        "declared_checkout_revision_drift_count": 0,
                        "declared_checkout_revision_drifts": [],
                    },
                    "projects": [],
                    "trees": [],
                    "artifacts": [],
                    "blockers": [],
                    "receipt_id_scope": BUILD.DOGFOOD_RECEIPT_ID_SCOPE,
                }
                source["receipt_id"] = "sha256:" + hashlib.sha256(
                    BUILD.pretty_json(source)
                ).hexdigest()
                source_raw = BUILD.pretty_json(source)
                with self.assertRaisesRegex(BUILD.BuildError, "source inputs are invalid"):
                    BUILD.validate_userdebug_dogfood_source(
                        source_raw,
                        b"not-canonical",
                        manifest_raw,
                        wrapper_path=wrapper_path,
                    )

    def test_userdebug_dogfood_live_check_is_bounded_to_retained_hashes(self) -> None:
        class RetainedFixture:
            def __init__(self, raw: bytes) -> None:
                self.raw = raw
                self.assertions = 0

            def assert_stable(self) -> None:
                self.assertions += 1

        source = RetainedFixture(b"source")
        wrapper = RetainedFixture(b"wrapper")
        manifest = RetainedFixture(b"manifest")
        binding = {
            "file_sha256": hashlib.sha256(source.raw).hexdigest(),
            "bytes": len(source.raw),
            "wrapper_sha256": hashlib.sha256(wrapper.raw).hexdigest(),
            "resolved_manifest_sha256": hashlib.sha256(manifest.raw).hexdigest(),
            "receipt_id": "source-receipt",
            "control_head": "dogfood-wrapper-bound",
        }
        observed = BUILD.validate_userdebug_dogfood_live(
            source, wrapper, manifest, binding
        )
        self.assertEqual(observed, binding)
        self.assertEqual(source.assertions, 1)
        self.assertEqual(wrapper.assertions, 1)
        self.assertEqual(manifest.assertions, 1)
        tampered = dict(binding)
        tampered["bytes"] += 1
        with self.assertRaisesRegex(BUILD.BuildError, "live bytes binding changed"):
            BUILD.validate_userdebug_dogfood_live(
                source, wrapper, manifest, tampered
            )


    def test_artifact_set_self_hash_uses_android_canonical_preimage(self) -> None:
        receipt = BUILD.build_receipt(
            source_bom_sha256="1" * 64,
            cargo_identity="cargo 1|bin=" + "2" * 64 + "|home=" + "3" * 64,
            rustc_identity="rustc 1|bin=" + "4" * 64 + "|tree=" + "5" * 64,
            artifacts=[],
        )
        preimage = dict(receipt)
        digest = preimage.pop("artifact_set_sha256")
        self.assertEqual(digest, hashlib.sha256(BUILD.compact_json(preimage)).hexdigest())
        preimage["revision"] = 2
        self.assertNotEqual(
            digest,
            hashlib.sha256(BUILD.compact_json(preimage)).hexdigest(),
        )
        self.assertEqual(json.loads(BUILD.pretty_json(receipt)), receipt)

    def test_qemu_input_is_explicitly_receipt_bound_before_publication(self) -> None:
        cargo = mock.Mock(initial_bytes=b"measured cargo", role="cargo")
        identity = BUILD.tool_identity_string(
            "cargo 1.95.0 (0123456789 2026-01-01)",
            cargo,
            "closure",
            "1" * 64,
            "qemu",
            "2" * 64,
        )
        self.assertIn("|qemu=" + "2" * 64, identity)
        self.assertLessEqual(len(identity.encode()), 256)
        source = inspect.getsource(BUILD.build)
        probe = source.index("probe_aarch64_artifact(")
        cleanup = source.index("cleanup_scratch(target_scratch)")
        publication = source.index("publish_scratch = create_scratch_directory(")
        self.assertLess(probe, cleanup)
        self.assertLess(cleanup, publication)
        self.assertIn('"qemu_aarch64_static_sha256"', source)
        self.assertIn('"qemu_load_start_probes"', source)

    def test_publication_is_exact_atomic_and_no_replace(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as temporary:
            root = Path(temporary)
            parent = BUILD.filesystem_primitives.RetainedDirectoryChain.open(
                root, "test publication parent"
            )
            try:
                expected = {
                    name: (name.encode("utf-8"), 0o444 if name == BUILD.RECEIPT_NAME else 0o555)
                    for name in BUILD.PUBLISHED_NAMES
                }
                first = BUILD.create_scratch_directory(parent, ".first.")
                for name, (raw, mode) in expected.items():
                    BUILD.write_file_at(first.descriptor, name, raw, mode)
                BUILD.publish_directory(first, "published", expected)
                first.close()
                self.assertEqual(set((root / "published").iterdir()), {
                    root / "published" / name for name in BUILD.PUBLISHED_NAMES
                })
                for name, (_raw, mode) in expected.items():
                    self.assertEqual(
                        stat.S_IMODE((root / "published" / name).stat().st_mode), mode
                    )

                (root / "occupied").mkdir(mode=0o700)
                (root / "occupied" / "sentinel").write_bytes(b"preserve")
                second = BUILD.create_scratch_directory(parent, ".second.")
                for name, (raw, mode) in expected.items():
                    BUILD.write_file_at(second.descriptor, name, raw, mode)
                with self.assertRaisesRegex(BUILD.BuildError, "appeared.*publication"):
                    BUILD.publish_directory(second, "occupied", expected)
                self.assertEqual((root / "occupied" / "sentinel").read_bytes(), b"preserve")
                BUILD.cleanup_scratch(second)
            finally:
                parent.close()

    def test_cleanup_refuses_a_lexically_replaced_sibling(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as temporary:
            root = Path(temporary)
            parent = BUILD.filesystem_primitives.RetainedDirectoryChain.open(
                root, "test cleanup parent"
            )
            scratch = BUILD.create_scratch_directory(parent, ".scratch.")
            moved = ".retained-moved"
            try:
                os.rename(
                    scratch.name,
                    moved,
                    src_dir_fd=parent.directory_fd,
                    dst_dir_fd=parent.directory_fd,
                )
                os.mkdir(scratch.name, 0o700, dir_fd=parent.directory_fd)
                impostor = os.open(
                    scratch.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent.directory_fd,
                )
                try:
                    sentinel = os.open(
                        "sentinel",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=impostor,
                    )
                    os.close(sentinel)
                finally:
                    os.close(impostor)
                with self.assertRaisesRegex(BUILD.BuildError, "scratch directory changed"):
                    BUILD.cleanup_scratch(scratch)
                self.assertTrue((root / scratch.name / "sentinel").is_file())
                (root / scratch.name / "sentinel").unlink()
                (root / scratch.name).rmdir()
                os.rename(
                    moved,
                    scratch.name,
                    src_dir_fd=parent.directory_fd,
                    dst_dir_fd=parent.directory_fd,
                )
                BUILD.cleanup_scratch(scratch)
            finally:
                if scratch.descriptor >= 0:
                    scratch.close()
                parent.close()

    @unittest.skipUnless(
        platform.machine() in BUILD.DENIED_SYSCALLS and sys.platform == "linux",
        "seccomp syscall table is Linux-host specific",
    )
    def test_child_sandbox_denies_socket_creation(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import socket,sys; "
                    "\ntry: socket.socket()"
                    "\nexcept PermissionError: sys.exit(42)"
                    "\nelse: sys.exit(0)"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            preexec_fn=BUILD.install_child_sandbox,
        )
        self.assertEqual(completed.returncode, 42, completed.stderr.decode(errors="replace"))

        local_pair = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import socket; left,right=socket.socketpair(); "
                    "left.send(b'x'); assert right.recv(1) == b'x'; "
                    "left.close(); right.close()"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            preexec_fn=BUILD.install_child_sandbox,
        )
        self.assertEqual(
            local_pair.returncode,
            0,
            local_pair.stderr.decode(errors="replace"),
        )
        nonlocal_pair = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import socket,sys; "
                    "\ntry: socket.socketpair(socket.AF_INET)"
                    "\nexcept PermissionError: sys.exit(42)"
                    "\nexcept OSError: sys.exit(1)"
                    "\nelse: sys.exit(0)"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            preexec_fn=BUILD.install_child_sandbox,
        )
        self.assertEqual(
            nonlocal_pair.returncode,
            42,
            nonlocal_pair.stderr.decode(errors="replace"),
        )
        denied_numbers = {
            # connect, bind, listen, ptrace/process-VM/kcmp, io_uring,
            # and pidfd_getfd must all fail at the filter boundary.
            "x86_64": (42, 49, 50, 101, 310, 311, 312, 425, 438),
            "aarch64": (203, 200, 201, 117, 270, 271, 272, 425, 438),
        }[platform.machine()]
        denied_calls = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import ctypes,errno,sys; libc=ctypes.CDLL(None,use_errno=True); "
                    f"calls={denied_numbers!r}; "
                    "results=[]; "
                    "\nfor number in calls:"
                    "\n ctypes.set_errno(0); result=libc.syscall(number,-1,0,0,0,0,0); "
                    "results.append((result,ctypes.get_errno()))"
                    "\nsys.exit(0 if all(item == (-1,errno.EPERM) for item in results) else 1)"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            preexec_fn=BUILD.install_child_sandbox,
        )
        self.assertEqual(
            denied_calls.returncode,
            0,
            denied_calls.stderr.decode(errors="replace"),
        )

        # Cargo 1.95 uses a child process group for rustc invocations. The
        # session supervisor permits that operation but still denies escape
        # into a fresh session.
        grouped = subprocess.run(
            [sys.executable, "-c", "import os; os.setpgid(0, 0)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            preexec_fn=BUILD.install_child_sandbox,
        )
        self.assertEqual(grouped.returncode, 0, grouped.stderr.decode(errors="replace"))
        escaped = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import os,sys; "
                    "\ntry: os.setsid()"
                    "\nexcept PermissionError: sys.exit(42)"
                    "\nelse: sys.exit(0)"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            preexec_fn=BUILD.install_child_sandbox,
        )
        self.assertEqual(escaped.returncode, 42, escaped.stderr.decode(errors="replace"))

    @unittest.skipUnless(
        platform.machine() in BUILD.DENIED_SYSCALLS and sys.platform == "linux",
        "supervised execution is Linux-host specific",
    )
    def test_qemu_load_start_probe_requires_exact_role_statuses_and_bounds(self) -> None:
        fake_qemu_raw = b"""#!/bin/sh
IFS= read -r role < "$1" || exit 90
case "$role" in
  tool)
    [ "$#" -eq 1 ] || exit 91
    printf '%s\n' 'invalid request: usage: trillionnium-agent-shell mcp' >&2
    exit 2
    ;;
  broker)
    [ "$#" -eq 2 ] || exit 92
    [ "$2" = "--trillionnium-invalid-artifact-load-probe" ] || exit 93
    printf '%s\n' 'shell exec broker rejected invalid arguments; only --cleanup-stale-only is accepted' >&2
    exit 2
    ;;
  worker)
    [ "$#" -eq 1 ] || exit 94
    printf '%s\n' 'shell exec worker failed closed: worker I/O failed: Bad file descriptor (os error 9)' >&2
    exit 1
    ;;
  *) exit 95 ;;
esac
"""
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as temporary:
            qemu = retained_test_executable(
                Path(temporary) / "fake-qemu-aarch64-static", fake_qemu_raw
            )
            try:
                for role, (
                    arguments,
                    expected_status,
                    expected_output,
                ) in BUILD.PROBE_SPECS.items():
                    with self.subTest(role=role):
                        result = BUILD.probe_aarch64_artifact(
                            qemu, f"{role}\n".encode(), role, SCRIPT.parent
                        )
                        self.assertEqual(result["role"], role)
                        self.assertEqual(
                            result["expected_exit_status"], expected_status
                        )
                        self.assertEqual(result["arguments"], list(arguments))
                        self.assertEqual(
                            result["timeout_seconds"], BUILD.PROBE_TIMEOUT_SECONDS
                        )
                        self.assertEqual(
                            result["maximum_output_bytes"],
                            BUILD.MAX_PROBE_OUTPUT_BYTES,
                        )
                        self.assertEqual(
                            result["captured_output_bytes"], len(expected_output)
                        )
                        self.assertEqual(
                            result["captured_output_sha256"],
                            hashlib.sha256(expected_output).hexdigest(),
                        )
                        self.assertEqual(
                            result["expected_output_sha256"],
                            hashlib.sha256(expected_output).hexdigest(),
                        )
                with self.assertRaisesRegex(
                    BUILD.BuildError, "expected_status=2"
                ):
                    BUILD.probe_aarch64_artifact(
                        qemu, b"unexpected-role\n", "tool", SCRIPT.parent
                    )
            finally:
                qemu.close()

    @unittest.skipUnless(
        platform.machine() in BUILD.DENIED_SYSCALLS and sys.platform == "linux",
        "supervised execution is Linux-host specific",
    )
    def test_supervisor_bounds_output_and_kills_surviving_descendants(self) -> None:
        private_python = tempfile.TemporaryDirectory()
        python_path = Path(private_python.name) / "python"
        shutil.copyfile(Path(sys.executable).resolve(), python_path)
        python_path.chmod(0o700)
        python = BUILD.raw_primitives.open_retained_executable(
            python_path, "test Python"
        )
        environment = {"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"}
        try:
            with self.assertRaisesRegex(BUILD.BuildError, "output exceeds"):
                BUILD.run_retained(
                    python,
                    ("-c", "import os; os.write(1, b'x' * 65536)"),
                    environment=environment,
                    expected_environment=set(environment),
                    cwd=SCRIPT.parent,
                    timeout=10,
                    maximum_output=16,
                    label="bounded-output fixture",
                )
            with self.assertRaisesRegex(BUILD.BuildError, "surviving descendant"):
                BUILD.run_retained(
                    python,
                    (
                        "-c",
                        "import os,time; child=os.fork(); "
                        "(os.setpgid(0, 0), time.sleep(30)) if child == 0 else None",
                    ),
                    environment=environment,
                    expected_environment=set(environment),
                    cwd=SCRIPT.parent,
                    timeout=10,
                    maximum_output=16,
                    label="surviving-descendant fixture",
                )
        finally:
            python.close()
            private_python.cleanup()


if __name__ == "__main__":
    unittest.main()
