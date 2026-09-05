from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
RECEIPT_NAME = "p01-userdebug-pre-daemon-artifact-set.v8.json"
LEGACY_RECEIPT_NAME = "p01-userdebug-pre-daemon-artifact-set.v6.json"


class P01DaemonBuildScriptSourceTests(unittest.TestCase):
    def test_daemon_build_binding_keys_follow_canonical_serde_order(self) -> None:
        source = (ROOT / "apps/trillionniumd/build.rs").read_text()
        binding_keys = source.split(
            "fn validate_daemon_build_binding", 1
        )[1].split(
            '"P0 userdebug daemon build binding schema is not closed"', 1
        )[0]
        self.assertIn(
            '"stable_principal",\n'
            '            "target_compiler_closure",\n'
            '            "target_profile",\n'
            '            "toolchain_snapshot",',
            binding_keys,
        )
        self.assertNotIn(
            '"stable_principal",\n'
            '            "target_profile",\n'
            '            "target_compiler_closure",',
            binding_keys,
        )

    def test_v8_receipt_and_new_artifact_hashes_are_frozen(self) -> None:
        source = (ROOT / "apps/trillionniumd/build.rs").read_text()
        for marker in (
            '"p01-userdebug-pre-daemon-artifact-set.v8.json"',
            '"org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v8"',
            '"5d5b92f9f190c40a3d84c82212fb1c81ef9bf3228ea7eb4ca42949af0b48cf55"',
            '"49e899b166472e3a663528c3a70f0db21644e5848a162aaab2f68ab1aa6dd927"',
            '"e2339d5bd99747148f13b313d422450b9e20b6f4ade786cda829af6b883a4b5b"',
        ):
            self.assertIn(marker, source)
        self.assertNotIn(
            '"org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v6"', source
        )

    def test_compiler_and_elf_inspector_use_closed_physical_custody(self) -> None:
        source = (ROOT / "apps/trillionniumd/build.rs").read_text()
        for marker in (
            '"org.trillionnium.launcher-build-tool-custody.v1"',
            'validate_launcher_build_tool(&receipt, "compiler", "compiler_driver")',
            'validate_launcher_build_tool(&receipt, "elf_inspector", "elf_inspector")',
            "O_NOFOLLOW",
            "retained_open_file_description_via_proc_self_fd",
            '"complete_recursive_toolchain_closure"',
        ):
            self.assertIn(marker, source)

    def test_rust_linker_must_equal_the_retained_target_compiler_descriptor(self) -> None:
        source = (ROOT / "apps/trillionniumd/build.rs").read_text()
        self.assertIn(
            'env::var(TARGET_CC_ENV).expect("P0 userdebug daemon build omits retained target compiler")',
            source,
        )
        self.assertIn('token.strip_prefix("linker=")', source)
        self.assertIn(
            'value, retained_target_compiler,\n'
            '                "P0 userdebug daemon Rust linker differs from the retained target compiler"',
            source,
        )
        self.assertNotIn(
            'token.strip_prefix("linker=/proc/self/fd/")', source
        )

    def test_cc_rs_alternate_environment_is_closed_and_rebuilt_on_change(self) -> None:
        source = (ROOT / "apps/trillionniumd/build.rs").read_text()
        forbidden = (
            "CC_aarch64-unknown-linux-gnu",
            "TARGET_CC",
            "CC",
            "CXX_aarch64-unknown-linux-gnu",
            "CXX_aarch64_unknown_linux_gnu",
            "TARGET_CXX",
            "CXX",
            "AR_aarch64-unknown-linux-gnu",
            "TARGET_AR",
            "AR",
            "RANLIB_aarch64-unknown-linux-gnu",
            "RANLIB_aarch64_unknown_linux_gnu",
            "TARGET_RANLIB",
            "RANLIB",
            "CFLAGS_aarch64-unknown-linux-gnu",
            "TARGET_CFLAGS",
            "CFLAGS",
            "CXXFLAGS_aarch64-unknown-linux-gnu",
            "TARGET_CXXFLAGS",
            "CXXFLAGS",
            "ARFLAGS_aarch64-unknown-linux-gnu",
            "ARFLAGS_aarch64_unknown_linux_gnu",
            "TARGET_ARFLAGS",
            "ARFLAGS",
            "RANLIBFLAGS_aarch64-unknown-linux-gnu",
            "RANLIBFLAGS_aarch64_unknown_linux_gnu",
            "TARGET_RANLIBFLAGS",
            "RANLIBFLAGS",
            "CRATE_CC_NO_DEFAULTS",
            "CC_SHELL_ESCAPED_FLAGS",
            "CC_FORCE_DISABLE",
            "CC_ENABLE_DEBUG_OUTPUT",
            "CC_KNOWN_WRAPPER_CUSTOM",
            "CROSS_COMPILE",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
        )
        for name in forbidden:
            self.assertIn(f'"{name}"', source)
        self.assertIn("env::var_os(name).is_none()", source)
        self.assertIn(
            "for name in FORBIDDEN_NATIVE_BUILD_ENVIRONMENTS {\n"
            '        println!("cargo:rerun-if-env-changed={name}");',
            source,
        )

    def test_cargo_target_and_runtime_directories_are_physically_confined(self) -> None:
        source = (ROOT / "apps/trillionniumd/build.rs").read_text()
        for marker in (
            "open_custodied_absolute_directory",
            "open_private_cargo_descendant",
            "components.len() >= 2",
            "Some(0o700)",
            "metadata.uid() == effective_uid",
            "mode & 0o022 == 0",
            "metadata.dev() == target_metadata.dev()",
            "path.strip_prefix(target_path)",
            "paths_overlap(&target_dir, &manifest_directory)",
            "paths_overlap(&target_dir, lane_root)",
            "receipt_path",
            "libc::O_NOFOLLOW | libc::O_DIRECTORY",
            "snapshot_count, 1",
        ):
            self.assertIn(marker, source)
        self.assertNotIn(
            "component.starts_with(&target_dir) && component != target_dir",
            source,
        )

    def test_real_integration_uses_target_local_rust_custody(self) -> None:
        source = Path(__file__).read_text()
        cargo_check_source = source.split("def " + "cargo_check", 1)[1].split(
            "def " + "rewrite_receipt", 1
        )[0]
        setup_source = source.split("def " + "setUpClass", 1)[1].split(
            "def " + "_cleanup_private_cargo", 1
        )[0]
        self.assertIn(
            'private_rust_root = cls.cargo_target / "rust-toolchain"', setup_source
        )
        self.assertIn('"--reflink=auto"', setup_source)
        for marker in (
            '"RUSTC": str(self.private_rust_root / "bin/rustc")',
            'str(self.private_rust_root / "bin/cargo")',
            'umask=0o077',
            'os.chmod(self.cargo_target, 0o700)',
        ):
            self.assertIn(marker, cargo_check_source)
        self.assertNotIn('"RUSTUP_HOME"', cargo_check_source)
        self.assertNotIn('"RUSTUP_TOOLCHAIN"', cargo_check_source)

    def test_private_cargo_cleanup_rejects_replaced_root_without_following_it(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="p01-daemon-cleanup-outside.", dir=Path.home()
        ) as outside_name:
            outside = Path(outside_name)
            os.chmod(outside, 0o711)
            temporary = tempfile.TemporaryDirectory(
                prefix="p01-daemon-private-cargo.", dir=Path.home()
            )
            root = Path(temporary.name)
            metadata = root.lstat()

            class CleanupHarness:
                cargo_temporary = temporary
                cargo_temporary_root = root
                cargo_temporary_parent = Path.home().resolve(strict=True)
                cargo_temporary_identity = (metadata.st_dev, metadata.st_ino)

            root.rmdir()
            root.symlink_to(outside, target_is_directory=True)
            try:
                with self.assertRaisesRegex(
                    RuntimeError, "refusing unsafe private Cargo recursive cleanup"
                ):
                    P01DaemonReceiptBuildIntegrationTests._cleanup_private_cargo.__func__(
                        CleanupHarness
                    )
                self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o711)
            finally:
                if root.is_symlink():
                    root.unlink()
                if not root.exists():
                    root.mkdir(mode=0o700)
                temporary.cleanup()

    def test_private_cargo_target_mode_is_restored_when_tool_open_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="p01-daemon-open-failure.", dir=Path.home()
        ) as temporary:
            target = Path(temporary) / "target"
            target.mkdir(mode=0o700)
            harness = P01DaemonReceiptBuildIntegrationTests(
                "test_valid_receipt_drives_the_real_daemon_build_script"
            )
            harness.lane_root = Path(temporary) / "lane"
            harness.cargo_target = target
            receipt = Path(temporary) / RECEIPT_NAME
            with (
                mock.patch.object(
                    harness, "stage_artifact_fixture", return_value=receipt
                ),
                mock.patch.object(harness, "clean_daemon_package_outputs"),
                mock.patch("os.open", side_effect=OSError("injected open failure")),
            ):
                with self.assertRaisesRegex(OSError, "injected open failure"):
                    harness.cargo_check(receipt, target_mode=0o720)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)

    def test_real_integration_uses_fixed_input_stage_and_package_only_clean(
        self,
    ) -> None:
        source = Path(__file__).read_text()
        staging = source.split("def " + "stage_artifact_fixture", 1)[1].split(
            "def " + "clean_daemon_package_outputs", 1
        )[0]
        cleaning = source.split("def " + "clean_daemon_package_outputs", 1)[1].split(
            "def " + "cargo_check", 1
        )[0]
        for marker in (
            "artifact_stage_identity",
            "fixed integration artifact stage escaped custody",
            "entry.is_dir(follow_symlinks=False)",
            "stage / receipt.name",
        ):
            self.assertIn(marker, staging)
        for marker in (
            '"clean"',
            '"--package"',
            '"trillionniumd"',
            '"--release"',
            '"--target"',
            '"--locked"',
            '"--offline"',
        ):
            self.assertIn(marker, cleaning)
        self.assertNotIn('"--workspace"', cleaning)

    def test_source_ancestor_uses_separate_nofollow_policy(self) -> None:
        source = (ROOT / "apps/trillionniumd/build.rs").read_text()
        current_control_mode = stat.S_IMODE(ROOT.parent.stat().st_mode)
        self.assertEqual(current_control_mode & 0o002, 0)
        helper = source.split(
            "fn open_nofollow_source_directory", 1
        )[1].split("fn open_private_cargo_descendant", 1)[0]
        self.assertIn("metadata.permissions().mode() & 0o002 == 0", helper)
        self.assertNotIn("metadata.permissions().mode() & 0o022 == 0", helper)
        strict_helper = source.split(
            "fn open_custodied_absolute_directory", 1
        )[1].split("fn open_nofollow_source_directory", 1)[0]
        self.assertIn("mode & 0o022 == 0", strict_helper)
        self.assertIn("Some(0o700)", source)

        descriptor = os.open(
            "/", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
        )
        try:
            for component in (ROOT / "apps/trillionniumd").parts[1:]:
                child = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW
                    | os.O_DIRECTORY,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
                metadata = os.fstat(descriptor)
                self.assertIn(metadata.st_uid, {0, os.geteuid()})
                self.assertEqual(stat.S_IMODE(metadata.st_mode) & 0o002, 0)
        finally:
            os.close(descriptor)

    def test_sqlite_and_pkg_config_ambient_overrides_are_forbidden(self) -> None:
        source = (ROOT / "apps/trillionniumd/build.rs").read_text()
        forbidden = source.split(
            "const FORBIDDEN_NATIVE_BUILD_ENVIRONMENTS", 1
        )[1].split("];", 1)[0]
        for name in (
            "LIBSQLITE3_SYS_USE_PKG_CONFIG",
            "LIBSQLITE3_SYS_BUNDLING",
            "LIBSQLITE3_FLAGS",
            "SQLITE_MAX_VARIABLE_NUMBER",
            "SQLITE_MAX_EXPR_DEPTH",
            "SQLITE_MAX_COLUMN",
            "SQLITE3_INCLUDE_DIR",
            "SQLITE3_LIB_DIR",
            "SQLITE3_STATIC",
            "PKG_CONFIG_PATH",
            "PKG_CONFIG_LIBDIR",
            "PKG_CONFIG_SYSROOT_DIR",
            "PKG_CONFIG_PATH_aarch64_unknown_linux_gnu",
            "PKG_CONFIG_PATH_aarch64-unknown-linux-gnu",
        ):
            self.assertIn(f'"{name}"', forbidden)

    def test_final_receipt_discloses_transient_source_mutation_boundary(self) -> None:
        source = (
            ROOT / "tools/materialize_p01_final_daemon_artifact.py"
        ).read_text()
        self.assertIn(
            "final_daemon_build_same_uid_transient_source_mutation_and_restore_"
            "between_source_checks_cannot_be_excluded",
            source,
        )

    def test_embedded_daemon_measurement_contract_is_cycle_free_v4(self) -> None:
        source = (ROOT / "apps/trillionniumd/build.rs").read_text()
        self.assertIn(
            'const P01_MEASUREMENT_SCHEMA: &str = '
            '"org.trillionnium.p01-userdebug-daemon-measurement.v4";',
            source,
        )
        self.assertIn('.trillionnium_p01_measurement_v4', source)
        self.assertIn('join("p01_daemon_measurement_v4.rs")', source)
        self.assertNotIn("TRILLIONNIUM_P01_PRE_DAEMON_RECEIPT_SHA256", source)


class P01DaemonReceiptBuildIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configured = os.environ.get("TRILLIONNIUM_P01_TEST_ARTIFACT_SET")
        if not configured:
            raise unittest.SkipTest(
                "set TRILLIONNIUM_P01_TEST_ARTIFACT_SET to a built v8 artifact set"
            )
        cls.source = Path(configured)
        if not (cls.source / RECEIPT_NAME).is_file():
            raise unittest.SkipTest("configured v8 artifact set is incomplete")
        configured_manifest = os.environ.get(
            "TRILLIONNIUM_P01_TEST_TOOLCHAIN_MANIFEST"
        )
        if not configured_manifest:
            raise unittest.SkipTest(
                "set TRILLIONNIUM_P01_TEST_TOOLCHAIN_MANIFEST to the exact lane "
                "manifest paired with the v8 artifact set"
            )
        cls.toolchain_manifest = Path(configured_manifest)
        if not cls.toolchain_manifest.is_file():
            raise unittest.SkipTest("configured P01 toolchain manifest is missing")
        cls.lane_root = cls.toolchain_manifest.parent
        cls.toolchain_root = cls.lane_root / "toolchain"
        cls.cargo_home = cls.toolchain_root / "cargo"
        cls.snapshot_rust_root = (
            cls.toolchain_root
            / "rustup/toolchains/stable-x86_64-unknown-linux-gnu"
        )
        for path, label in (
            (cls.cargo_home, "snapshot Cargo home"),
            (cls.snapshot_rust_root, "snapshot Rust toolchain"),
            (cls.snapshot_rust_root / "bin/cargo", "snapshot Cargo executable"),
            (cls.snapshot_rust_root / "bin/rustc", "snapshot rustc executable"),
        ):
            if not path.exists():
                raise unittest.SkipTest(f"configured {label} is missing")

        cls.cargo_temporary = tempfile.TemporaryDirectory(
            prefix="p01-daemon-private-cargo.", dir=Path.home()
        )
        cls.addClassCleanup(cls._cleanup_private_cargo)
        custody_root = Path(cls.cargo_temporary.name)
        cls.cargo_temporary_parent = Path.home().resolve(strict=True)
        resolved_custody_root = custody_root.resolve(strict=True)
        custody_metadata = custody_root.lstat()
        if (
            custody_root.parent != Path.home()
            or resolved_custody_root.parent != cls.cargo_temporary_parent
            or not custody_root.name.startswith("p01-daemon-private-cargo.")
            or not stat.S_ISDIR(custody_metadata.st_mode)
            or custody_metadata.st_uid != os.geteuid()
        ):
            raise RuntimeError("private Cargo temporary root escaped its parent")
        cls.cargo_temporary_root = custody_root
        cls.cargo_temporary_identity = (
            custody_metadata.st_dev,
            custody_metadata.st_ino,
        )
        os.chmod(custody_root, 0o700)
        cls.cargo_target = custody_root / "target"
        cls.cargo_target.mkdir(mode=0o700)
        os.chmod(cls.cargo_target, 0o700)
        cls.artifact_stage = custody_root / "artifact-stage"
        cls.artifact_stage.mkdir(mode=0o700)
        artifact_stage_metadata = cls.artifact_stage.lstat()
        cls.artifact_stage_identity = (
            artifact_stage_metadata.st_dev,
            artifact_stage_metadata.st_ino,
        )
        cls.private_rust_root = cls.cargo_target / "rust-toolchain"
        subprocess.run(
            [
                "/usr/bin/cp",
                "--archive",
                "--reflink=auto",
                "--",
                str(cls.snapshot_rust_root),
                str(cls.private_rust_root),
            ],
            check=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": ""},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            umask=0o077,
        )
        cls._verify_private_rust_tree()
        cls.addClassCleanup(cls._verify_private_rust_tree)

    @classmethod
    def _cleanup_private_cargo(cls) -> None:
        temporary = getattr(cls, "cargo_temporary", None)
        if temporary is None:
            return
        root = getattr(cls, "cargo_temporary_root", None)
        expected_parent = getattr(cls, "cargo_temporary_parent", None)
        expected_identity = getattr(cls, "cargo_temporary_identity", None)
        if root is None or expected_parent is None or expected_identity is None:
            raise RuntimeError("private Cargo cleanup root was not initialized")
        try:
            metadata = root.lstat()
        except FileNotFoundError:
            temporary.cleanup()
            return
        resolved_root = root.resolve(strict=True)
        if (
            root.parent != Path.home()
            or resolved_root.parent != expected_parent
            or not root.name.startswith("p01-daemon-private-cargo.")
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or (metadata.st_dev, metadata.st_ino) != expected_identity
        ):
            raise RuntimeError("refusing unsafe private Cargo recursive cleanup")
        for current, directories, _files in os.walk(
            resolved_root, topdown=True, followlinks=False
        ):
            current_path = Path(current)
            current_metadata = current_path.lstat()
            if (
                not stat.S_ISDIR(current_metadata.st_mode)
                or current_metadata.st_uid != os.geteuid()
                or current_metadata.st_dev != metadata.st_dev
                or not current_path.resolve(strict=True).is_relative_to(resolved_root)
            ):
                raise RuntimeError("private Cargo cleanup traversal escaped custody")
            os.chmod(current_path, 0o700, follow_symlinks=False)
            for name in list(directories):
                path = current_path / name
                child = path.lstat()
                if stat.S_ISLNK(child.st_mode):
                    directories.remove(name)
                    continue
                if (
                    not stat.S_ISDIR(child.st_mode)
                    or child.st_uid != os.geteuid()
                    or child.st_dev != metadata.st_dev
                    or not path.resolve(strict=True).is_relative_to(resolved_root)
                ):
                    raise RuntimeError("private Cargo cleanup child escaped custody")
                os.chmod(path, 0o700, follow_symlinks=False)
        temporary.cleanup()

    @classmethod
    def _verify_private_rust_tree(cls) -> None:
        target_metadata = cls.cargo_target.lstat()
        if (
            cls.private_rust_root.parent != cls.cargo_target
            or not stat.S_ISDIR(target_metadata.st_mode)
            or target_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(target_metadata.st_mode) != 0o700
        ):
            raise RuntimeError("private Rust tree is outside its 0700 Cargo custody")
        manifest = json.loads(cls.toolchain_manifest.read_bytes())
        prefix = "rustup/toolchains/stable-x86_64-unknown-linux-gnu"
        entries = {
            entry["path"]: entry
            for entry in manifest.get("entries", [])
            if entry.get("path") == prefix
            or entry.get("path", "").startswith(f"{prefix}/")
        }
        if prefix not in entries:
            raise RuntimeError("toolchain manifest omits the private Rust root")
        expected_paths: set[str] = set()
        target_device = target_metadata.st_dev
        for manifest_path, entry in entries.items():
            relative = manifest_path.removeprefix(prefix).lstrip("/")
            path = cls.private_rust_root / relative if relative else cls.private_rust_root
            metadata = path.lstat()
            expected_paths.add(relative)
            entry_type = entry.get("type")
            if entry_type == "directory":
                if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
                    raise RuntimeError(f"private Rust directory differs: {relative}")
                if (
                    metadata.st_uid != os.geteuid()
                    or metadata.st_dev != target_device
                    or stat.S_IMODE(metadata.st_mode) != int(entry["mode"], 8)
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                ):
                    raise RuntimeError(f"private Rust directory custody differs: {relative}")
            elif entry_type == "regular":
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_dev != target_device
                    or metadata.st_nlink != 1
                    or metadata.st_size != entry.get("bytes")
                    or stat.S_IMODE(metadata.st_mode) != int(entry["mode"], 8)
                ):
                    raise RuntimeError(f"private Rust file custody differs: {relative}")
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() != entry.get("sha256"):
                    raise RuntimeError(f"private Rust file bytes differ: {relative}")
            elif entry_type == "symlink":
                if not stat.S_ISLNK(metadata.st_mode) or os.readlink(path) != entry.get(
                    "target"
                ):
                    raise RuntimeError(f"private Rust symlink differs: {relative}")
            else:
                raise RuntimeError(f"unsupported private Rust entry: {relative}")

        observed_paths = {""}
        for current, directories, files in os.walk(
            cls.private_rust_root, followlinks=False
        ):
            current_path = Path(current)
            for name in (*directories, *files):
                observed_paths.add(
                    (current_path / name).relative_to(cls.private_rust_root).as_posix()
                )
        if observed_paths != expected_paths:
            raise RuntimeError("private Rust tree differs from its manifest subtree")

    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory(prefix="p01-daemon-receipt-test.")
        target = Path(temporary.name) / "artifact-set"
        shutil.copytree(self.source, target, copy_function=shutil.copy2)
        os.chmod(target, 0o700)
        return temporary, target

    def stage_artifact_fixture(self, receipt: Path) -> Path:
        stage = self.artifact_stage
        metadata = stage.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or (metadata.st_dev, metadata.st_ino) != self.artifact_stage_identity
            or stage.parent != self.cargo_target.parent
        ):
            raise RuntimeError("fixed integration artifact stage escaped custody")
        for entry in os.scandir(stage):
            path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                raise RuntimeError("fixed integration artifact stage contains a directory")
            path.unlink()
        for source in receipt.parent.iterdir():
            source_metadata = source.lstat()
            destination = stage / source.name
            if stat.S_ISREG(source_metadata.st_mode):
                shutil.copy2(source, destination, follow_symlinks=False)
            elif stat.S_ISLNK(source_metadata.st_mode):
                destination.symlink_to(os.readlink(source))
            else:
                raise RuntimeError("integration artifact fixture is not file-only")
        final = stage.lstat()
        if (
            not stat.S_ISDIR(final.st_mode)
            or (final.st_dev, final.st_ino) != self.artifact_stage_identity
        ):
            raise RuntimeError("fixed integration artifact stage changed while copied")
        return stage / receipt.name

    def clean_daemon_package_outputs(self) -> None:
        lane_root = self.lane_root
        host_runtime = lane_root / "toolchain/sysroot/usr/lib/x86_64-linux-gnu"
        environment = {
            "HOME": str(Path.home()),
            "PATH": f"{self.private_rust_root / 'bin'}:/usr/bin:/bin",
            "CARGO_HOME": str(self.cargo_home),
            "RUSTC": str(self.private_rust_root / "bin/rustc"),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(self.cargo_target),
            "LANG": "C",
            "LC_ALL": "C",
            "LD_LIBRARY_PATH": str(host_runtime),
            "TZ": "UTC",
        }
        subprocess.run(
            [
                str(self.private_rust_root / "bin/cargo"),
                "clean",
                "--package",
                "trillionniumd",
                "--release",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--locked",
                "--offline",
            ],
            cwd=ROOT,
            env=environment,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            umask=0o077,
        )
        if not self.private_rust_root.is_dir():
            raise RuntimeError("Cargo clean removed the private Rust toolchain")

    def cargo_check(
        self, receipt: Path, *, target_mode: int = 0o700
    ) -> subprocess.CompletedProcess[str]:
        receipt = self.stage_artifact_fixture(receipt)
        self.clean_daemon_package_outputs()
        lane_root = self.lane_root
        sysroot = lane_root / "toolchain/sysroot"
        compiler_bin = sysroot / "usr/bin"
        gcc_libdir = sysroot / "usr/lib/gcc-cross/aarch64-linux-gnu/12"
        binutils_dir = sysroot / "usr/aarch64-linux-gnu/bin"
        host_runtime = sysroot / "usr/lib/x86_64-linux-gnu"
        compiler = compiler_bin / "aarch64-linux-gnu-gcc-12"
        archiver = compiler_bin / "aarch64-linux-gnu-ar"
        host_compiler = Path("/usr/bin/x86_64-linux-gnu-gcc-12")
        target_dir = self.cargo_target
        descriptors: list[int] = []
        try:
            os.chmod(target_dir, target_mode)
            descriptors.extend(
                os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                for path in (compiler, archiver, host_compiler)
            )
            compiler_fd = f"/proc/self/fd/{descriptors[0]}"
            archiver_fd = f"/proc/self/fd/{descriptors[1]}"
            host_compiler_fd = f"/proc/self/fd/{descriptors[2]}"
            rustflags = [
                "-C",
                "debuginfo=0",
                "-C",
                "strip=symbols",
                "-C",
                "codegen-units=1",
                "-C",
                "relocation-model=pic",
                "-C",
                f"linker={compiler_fd}",
                "-C",
                f"link-arg=--sysroot={sysroot}",
                "-C",
                f"link-arg=-B{compiler_bin}",
                "-C",
                f"link-arg=-B{gcc_libdir}",
                "-C",
                f"link-arg=-B{binutils_dir}",
                "-C",
                "link-arg=-pie",
                "-C",
                "link-arg=-Wl,--as-needed,-z,relro,-z,now,-z,noexecstack,--build-id=sha1",
            ]
            for source, destination in (
                (ROOT, "/usr/src/trillionnium-os"),
                (target_dir, "/usr/src/trillionnium-target"),
                (self.cargo_home, "/usr/src/trillionnium-cargo-home"),
                (
                    self.private_rust_root,
                    "/usr/src/trillionnium-rust-toolchain",
                ),
                (ROOT, "/usr/src/trillionnium-android"),
                (target_dir.parent, "/usr/src/trillionnium-empty-artifacts"),
                (lane_root, "/usr/src/trillionnium-manifest-parent"),
                (receipt.parent, "/usr/src/trillionnium-raw-elf-output"),
            ):
                rustflags.extend(
                    ("--remap-path-prefix", f"{source}={destination}")
                )
            native_flags = (
                f"--sysroot={sysroot} -B{compiler_bin} "
                f"-B{gcc_libdir} -B{binutils_dir}"
            )
            environment = {
                "HOME": str(Path.home()),
                "PATH": f"{self.private_rust_root / 'bin'}:/usr/bin:/bin",
                "CARGO_HOME": str(self.cargo_home),
                "RUSTC": str(self.private_rust_root / "bin/rustc"),
            }
            environment.update(
                {
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(rustflags),
                    "CARGO_BUILD_JOBS": "1",
                    "CARGO_CACHE_RUSTC_INFO": "0",
                    "CARGO_INCREMENTAL": "0",
                    "CARGO_NET_OFFLINE": "true",
                    "CARGO_TARGET_DIR": str(target_dir),
                    "NUM_JOBS": "1",
                    "SOURCE_DATE_EPOCH": "1785110400",
                    "LD_LIBRARY_PATH": str(host_runtime),
                    "CC_x86_64_unknown_linux_gnu": host_compiler_fd,
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": host_compiler_fd,
                    "CC_aarch64_unknown_linux_gnu": compiler_fd,
                    "AR_aarch64_unknown_linux_gnu": archiver_fd,
                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": compiler_fd,
                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR": archiver_fd,
                    "CFLAGS_aarch64_unknown_linux_gnu": native_flags,
                    "CXXFLAGS_aarch64_unknown_linux_gnu": native_flags,
                    "TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT": "userdebug",
                    "TRILLIONNIUM_P01_PRE_DAEMON_ARTIFACT_RECEIPT": str(receipt),
                    "TRILLIONNIUM_P01_TOOLCHAIN_MANIFEST": str(
                        self.toolchain_manifest
                    ),
                    "TRILLIONNIUM_P01_TARGET_SYSROOT": str(sysroot),
                    "TRILLIONNIUM_P01_TARGET_COMPILER_BIN": str(compiler_bin),
                    "TRILLIONNIUM_P01_TARGET_GCC_LIBDIR": str(gcc_libdir),
                    "TRILLIONNIUM_P01_TARGET_BINUTILS_DIR": str(binutils_dir),
                    "TRILLIONNIUM_P01_TARGET_HOST_RUNTIME_LIBDIR": str(
                        host_runtime
                    ),
                }
            )
            return subprocess.run(
                [
                    str(self.private_rust_root / "bin/cargo"),
                    "check",
                    "-p",
                    "trillionniumd",
                    "--release",
                    "--target",
                    "aarch64-unknown-linux-gnu",
                    "--no-default-features",
                    "--features",
                    "p0-launch-package-device-conformance",
                    "--locked",
                    "--offline",
                ],
                cwd=ROOT,
                env=environment,
                pass_fds=tuple(descriptors),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=600,
                umask=0o077,
            )
        finally:
            os.chmod(self.cargo_target, 0o700)
            for descriptor in descriptors:
                os.close(descriptor)

    def rewrite_receipt(self, path: Path, value: dict[str, object]) -> None:
        os.chmod(path, 0o600)
        path.write_bytes((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
        os.chmod(path, 0o444)

    def test_valid_receipt_drives_the_real_daemon_build_script(self) -> None:
        temporary, target = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = self.cargo_check(target / RECEIPT_NAME)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_group_writable_cargo_target_is_rejected(self) -> None:
        temporary, target = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = self.cargo_check(target / RECEIPT_NAME, target_mode=0o720)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Cargo target directory", result.stdout)

    def test_receipt_and_artifact_tampering_fail_before_daemon_compilation(self) -> None:
        cases: list[tuple[str, str]] = []

        temporary, target = self.fixture()
        self.addCleanup(temporary.cleanup)
        receipt = target / RECEIPT_NAME
        receipt.unlink()
        receipt.symlink_to(self.source / RECEIPT_NAME)
        result = self.cargo_check(receipt)
        cases.append(("receipt symlink", result.stdout))
        self.assertNotEqual(result.returncode, 0, result.stdout)

        temporary, target = self.fixture()
        self.addCleanup(temporary.cleanup)
        artifact = target / "trillionnium-agent-system-api-device-conformance"
        os.chmod(artifact, 0o700)
        value = bytearray(artifact.read_bytes())
        value[-1] ^= 1
        artifact.write_bytes(value)
        os.chmod(artifact, 0o555)
        result = self.cargo_check(target / RECEIPT_NAME)
        cases.append(("artifact cross-splice", result.stdout))
        self.assertNotEqual(result.returncode, 0, result.stdout)

        temporary, target = self.fixture()
        self.addCleanup(temporary.cleanup)
        receipt = target / RECEIPT_NAME
        value = json.loads(receipt.read_bytes())
        value["unexpected_authority"] = True
        self.rewrite_receipt(receipt, value)
        result = self.cargo_check(receipt)
        cases.append(("extra root field", result.stdout))
        self.assertNotEqual(result.returncode, 0, result.stdout)

        temporary, target = self.fixture()
        self.addCleanup(temporary.cleanup)
        receipt = target / RECEIPT_NAME
        os.chmod(receipt, 0o600)
        original = receipt.read_bytes()
        receipt.write_bytes(b'{"schema":"duplicate",' + original[1:])
        os.chmod(receipt, 0o444)
        result = self.cargo_check(receipt)
        cases.append(("duplicate JSON key", result.stdout))
        self.assertNotEqual(result.returncode, 0, result.stdout)

        temporary, target = self.fixture()
        self.addCleanup(temporary.cleanup)
        os.chmod(target / "trillionnium-codex-agent-0.144.1-p01-userdebug", 0o644)
        result = self.cargo_check(target / RECEIPT_NAME)
        cases.append(("wrong artifact mode", result.stdout))
        self.assertNotEqual(result.returncode, 0, result.stdout)

        temporary, target = self.fixture()
        self.addCleanup(temporary.cleanup)
        receipt = target / RECEIPT_NAME
        legacy = target / LEGACY_RECEIPT_NAME
        receipt.rename(legacy)
        result = self.cargo_check(legacy)
        cases.append(("legacy v6 filename", result.stdout))
        self.assertNotEqual(result.returncode, 0, result.stdout)

        for label, mutate in (
            (
                "legacy v6 schema",
                lambda value: value.__setitem__(
                    "schema",
                    "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v6",
                ),
            ),
            (
                "identity gate status drift",
                lambda value: value["legacy_descriptor_contamination_hold_gate"].__setitem__(
                    "status", "PASS_IDENTITY_INDEPENDENCE"
                ),
            ),
            (
                "legacy descriptor digest drift",
                lambda value: value["legacy_descriptor_contamination_hold_gate"][
                    "digests"
                ].__setitem__("canonical digest", "f" * 64),
            ),
            (
                "counterfactual falsely verified",
                lambda value: value["legacy_descriptor_contamination_hold_gate"][
                    "counterfactual_same_source_rebuild"
                ].__setitem__("verified", True),
            ),
            (
                "identity gate missing field",
                lambda value: value["legacy_descriptor_contamination_hold_gate"].pop(
                    "stable_principal_admission_split"
                ),
            ),
            (
                "compiler custody schema drift",
                lambda value: value["compiler"].__setitem__(
                    "schema", "org.trillionnium.untrusted-compiler.v1"
                ),
            ),
            (
                "compiler execution custody overclaim",
                lambda value: value["compiler"]["execution"].__setitem__(
                    "ambient_environment_inherited", True
                ),
            ),
            (
                "ELF inspector digest drift",
                lambda value: value["elf_inspector"].__setitem__(
                    "sha256", "e" * 64
                ),
            ),
            (
                "ELF inspector missing",
                lambda value: value.pop("elf_inspector"),
            ),
            (
                "daemon Cargo profile drift",
                lambda value: value["daemon_build_binding"][
                    "cargo_profile"
                ].__setitem__("name", "dev"),
            ),
            (
                "daemon target ABI drift",
                lambda value: value["daemon_build_binding"][
                    "target_profile"
                ].__setitem__("maximum_glibc", "GLIBC_2.37"),
            ),
            (
                "daemon Rust flag injection",
                lambda value: value["daemon_build_binding"]["build_policy"][
                    "normalized_rustflags"
                ].extend(["-C", "target-cpu=native"]),
            ),
        ):
            temporary, target = self.fixture()
            self.addCleanup(temporary.cleanup)
            receipt = target / RECEIPT_NAME
            value = json.loads(receipt.read_bytes())
            mutate(value)
            self.rewrite_receipt(receipt, value)
            result = self.cargo_check(receipt)
            cases.append((label, result.stdout))
            self.assertNotEqual(result.returncode, 0, result.stdout)

        for label, output in cases:
            self.assertIn("failed to run custom build command for `trillionniumd", output, label)


if __name__ == "__main__":
    unittest.main()
