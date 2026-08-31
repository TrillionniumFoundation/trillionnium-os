use std::collections::BTreeMap;
use std::env;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

const FEATURE_ENV: &str = "CARGO_FEATURE_P0_LAUNCH_PACKAGE_DEVICE_CONFORMANCE";
const CARGO_CFG_FEATURE_ENV: &str = "CARGO_CFG_FEATURE";
const VARIANT_ENV: &str = "TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT";
const RECEIPT_ENV: &str = "TRILLIONNIUM_P01_PRE_DAEMON_ARTIFACT_RECEIPT";
const TOOLCHAIN_MANIFEST_ENV: &str = "TRILLIONNIUM_P01_TOOLCHAIN_MANIFEST";
const TARGET_SYSROOT_ENV: &str = "TRILLIONNIUM_P01_TARGET_SYSROOT";
const TARGET_COMPILER_BIN_ENV: &str = "TRILLIONNIUM_P01_TARGET_COMPILER_BIN";
const TARGET_GCC_LIBDIR_ENV: &str = "TRILLIONNIUM_P01_TARGET_GCC_LIBDIR";
const TARGET_BINUTILS_DIR_ENV: &str = "TRILLIONNIUM_P01_TARGET_BINUTILS_DIR";
const TARGET_HOST_RUNTIME_LIBDIR_ENV: &str = "TRILLIONNIUM_P01_TARGET_HOST_RUNTIME_LIBDIR";
const TARGET_CC_ENV: &str = "CC_aarch64_unknown_linux_gnu";
const TARGET_AR_ENV: &str = "AR_aarch64_unknown_linux_gnu";
const TARGET_CFLAGS_ENV: &str = "CFLAGS_aarch64_unknown_linux_gnu";
const TARGET_CXXFLAGS_ENV: &str = "CXXFLAGS_aarch64_unknown_linux_gnu";
const CARGO_TARGET_LINKER_ENV: &str = "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER";
const CARGO_TARGET_AR_ENV: &str = "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR";
// cc-rs 1.2.62 consults all four target spellings for each tool variable and
// merges all four spellings for every *FLAGS variable.  The underscore target
// CC/AR/CFLAGS/CXXFLAGS names above are the only accepted target-native inputs;
// every alternate below must therefore be absent rather than merely shadowed.
const FORBIDDEN_NATIVE_BUILD_ENVIRONMENTS: &[&str] = &[
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
    "LIBSQLITE3_SYS_USE_PKG_CONFIG",
    "LIBSQLITE3_SYS_BUNDLING",
    "LIBSQLITE3_FLAGS",
    "SQLITE_MAX_VARIABLE_NUMBER",
    "SQLITE_MAX_EXPR_DEPTH",
    "SQLITE_MAX_COLUMN",
    "SQLITE3_INCLUDE_DIR",
    "SQLITE3_LIB_DIR",
    "SQLITE3_STATIC",
    "SQLCIPHER_INCLUDE_DIR",
    "SQLCIPHER_LIB_DIR",
    "SQLCIPHER_STATIC",
    "PKG_CONFIG",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_LIBDIR",
    "PKG_CONFIG_SYSROOT_DIR",
    "PKG_CONFIG_ALLOW_CROSS",
    "PKG_CONFIG_ALL_STATIC",
    "PKG_CONFIG_ALL_DYNAMIC",
    "TARGET_PKG_CONFIG_PATH",
    "TARGET_PKG_CONFIG_LIBDIR",
    "TARGET_PKG_CONFIG_SYSROOT_DIR",
    "PKG_CONFIG_PATH_aarch64_unknown_linux_gnu",
    "PKG_CONFIG_LIBDIR_aarch64_unknown_linux_gnu",
    "PKG_CONFIG_SYSROOT_DIR_aarch64_unknown_linux_gnu",
    "PKG_CONFIG_PATH_aarch64-unknown-linux-gnu",
    "PKG_CONFIG_LIBDIR_aarch64-unknown-linux-gnu",
    "PKG_CONFIG_SYSROOT_DIR_aarch64-unknown-linux-gnu",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
];
const SYSTEM_API_SHA256_ENV: &str = "TRILLIONNIUM_P01_SYSTEM_API_SHA256";
const CODEX_LAUNCHER_SHA256_ENV: &str = "TRILLIONNIUM_P01_CODEX_LAUNCHER_SHA256";
const CODEX_RUNTIME_SHA256_ENV: &str = "TRILLIONNIUM_P01_CODEX_RUNTIME_SHA256";
const DAEMON_BUILD_BINDING_SHA256_ENV: &str = "TRILLIONNIUM_P01_DAEMON_BUILD_BINDING_SHA256";
const FROZEN_SYSTEM_API_SHA256: &str =
    "5d5b92f9f190c40a3d84c82212fb1c81ef9bf3228ea7eb4ca42949af0b48cf55";
const FROZEN_REPLAY_SYNC_HELPER_SHA256: &str =
    "49e899b166472e3a663528c3a70f0db21644e5848a162aaab2f68ab1aa6dd927";
const FROZEN_HIGH_WATER_AUTHORITY_SHA256: &str =
    "e2339d5bd99747148f13b313d422450b9e20b6f4ade786cda829af6b883a4b5b";
const FROZEN_CODEX_RUNTIME_SHA256: &str =
    "124867cc1c0b13f56539880f19d8c7b59f96e25fd47d068df91ea27c99d1ce78";
const FROZEN_STABLE_PRINCIPAL_CONTRACT_SHA256: &str =
    "3e9bfcb04e48062c20bd7407635c1a27086a0de8c2fa5ca73963c946b984095b";
const FROZEN_STABLE_PRINCIPAL_CANONICAL_SHA256: &str =
    "a9c224116123deb49908beda3ab047fc98d6917cfeb62d60364033858cc57153";
const FROZEN_LEGACY_DESCRIPTOR_LAUNCHER_SHA256: &str =
    "edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c";
const FROZEN_LEGACY_DESCRIPTOR_CONTRACT_SHA256: &str =
    "5ecd89d3c9fedbbeb0ac1de32fba2b5e5e5d248048ddc9a9e0359a0a01903119";
const FROZEN_LEGACY_DESCRIPTOR_CANONICAL_SHA256: &str =
    "bc6c64abbb893e6e75ed708f87cf864e6c8f7503381371dc394409bddc4009c2";
const P01_PRE_DAEMON_RECEIPT_FILE: &str = "p01-userdebug-pre-daemon-artifact-set.v8.json";
const P01_PRE_DAEMON_RECEIPT_SCHEMA: &str =
    "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v8";
const DAEMON_BUILD_BINDING_SCHEMA: &str = "org.trillionnium.p01-userdebug-daemon-build-binding.v2";
const DAEMON_BUILD_BINDING_SHA256_SCOPE: &str =
    "sha256(canonical-json-utf8-sort-keys-indent-2-lf-of-daemon_build_binding)";
const IDENTITY_INDEPENDENCE_HOLD_STATUS: &str = "hold_identity_independence_evidence_unverified";
const P01_MEASUREMENT_SCHEMA: &str = "org.trillionnium.p01-userdebug-daemon-measurement.v4";
const P01_IDENTITY_HOLD_SCHEMA: &str =
    "org.trillionnium.p01-userdebug-identity-independence-hold.v2";
const LAUNCHER_BUILD_TOOL_SCHEMA: &str = "org.trillionnium.launcher-build-tool-custody.v1";
const LAUNCHER_BUILD_TOOL_MAXIMUM: u64 = 128 * 1024 * 1024;
const TOOLCHAIN_MANIFEST_MAXIMUM: u64 = 64 * 1024 * 1024;
const FROZEN_TOOLCHAIN_MANIFEST_SHA256: &str =
    "735fab7c0ded3d37e53ac8295c32e7a3a1547ba54e603e74f25e83de2f8c541f";
const FROZEN_TOOLCHAIN_TREE_DIGEST: &str =
    "6335b8cb911852156b10eec32ba08d9730b51a8ca0b0b04abfefa0b6ef7a4367";
const FROZEN_TOOLCHAIN_MANIFEST_ID: &str =
    "d3ef19017ab4499243936ff65db4d2b50fce1536a9127f2d7ea3e7468784ebb4";
const FROZEN_TARGET_COMPILER_SHA256: &str =
    "c7b8890354c8ddc0364addfeb8968597e197627bd1e338fb6ed705b578803846";
const FROZEN_TARGET_COMPILER_BYTES: u64 = 1_315_296;
const FROZEN_TARGET_ARCHIVER_SHA256: &str =
    "086da15d802a53c33c0aeccfb2de663f724edab8fdca7e10b242cfefe24673dc";
const FROZEN_TARGET_ARCHIVER_BYTES: u64 = 68_920;
const DAEMON_NORMALIZED_RUSTFLAGS: &[&str] = &[
    "-C",
    "debuginfo=0",
    "-C",
    "strip=symbols",
    "-C",
    "codegen-units=1",
    "-C",
    "relocation-model=pic",
    "-C",
    "linker=$RETAINED_LINKER",
    "-C",
    "link-arg=--sysroot=$TARGET_SYSROOT",
    "-C",
    "link-arg=-B$TARGET_COMPILER_BIN",
    "-C",
    "link-arg=-B$TARGET_GCC_LIBDIR",
    "-C",
    "link-arg=-B$TARGET_BINUTILS_DIR",
    "-C",
    "link-arg=-pie",
    "-C",
    "link-arg=-Wl,--as-needed,-z,relro,-z,now,-z,noexecstack,--build-id=sha1",
    "--remap-path-prefix",
    "$ABSOLUTE_SOURCE=/usr/src/trillionnium-os",
    "--remap-path-prefix",
    "$ABSOLUTE_SOURCE=/usr/src/trillionnium-target",
    "--remap-path-prefix",
    "$ABSOLUTE_SOURCE=/usr/src/trillionnium-cargo-home",
    "--remap-path-prefix",
    "$ABSOLUTE_SOURCE=/usr/src/trillionnium-rust-toolchain",
    "--remap-path-prefix",
    "$ABSOLUTE_SOURCE=/usr/src/trillionnium-android",
    "--remap-path-prefix",
    "$ABSOLUTE_SOURCE=/usr/src/trillionnium-empty-artifacts",
    "--remap-path-prefix",
    "$ABSOLUTE_SOURCE=/usr/src/trillionnium-manifest-parent",
    "--remap-path-prefix",
    "$ABSOLUTE_SOURCE=/usr/src/trillionnium-raw-elf-output",
];

#[derive(Clone, Copy)]
struct ExpectedArtifact {
    role: &'static str,
    file: &'static str,
    mode: u32,
    maximum: u64,
}

const EXPECTED_ARTIFACTS: [ExpectedArtifact; 4] = [
    ExpectedArtifact {
        role: "system_api_tool",
        file: "trillionnium-agent-system-api-device-conformance",
        mode: 0o555,
        maximum: 64 * 1024 * 1024,
    },
    ExpectedArtifact {
        role: "replay_sync_helper",
        file: "trillionnium-system-api-device-conformance-replay-sync",
        mode: 0o555,
        maximum: 64 * 1024 * 1024,
    },
    ExpectedArtifact {
        role: "high_water_authority",
        file: "trillionnium-direct-operation-custody-high-water",
        mode: 0o555,
        maximum: 64 * 1024 * 1024,
    },
    ExpectedArtifact {
        role: "codex_launcher",
        file: "trillionnium-codex-agent-0.144.1-p01-userdebug",
        mode: 0o555,
        maximum: 8 * 1024 * 1024,
    },
];

fn stable_identity(
    metadata: &fs::Metadata,
) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.permissions().mode(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn read_exact_regular_at(
    directory: &File,
    name: &str,
    expected_uid: u32,
    mode: u32,
    maximum: u64,
    label: &str,
) -> Vec<u8> {
    assert!(
        !name.is_empty() && !name.contains('/') && name != "." && name != "..",
        "P0 userdebug {label} name is not one fixed path component"
    );
    let name = CString::new(name).expect("P0 userdebug artifact name contains NUL");
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    assert!(
        descriptor >= 0,
        "cannot open P0 userdebug {label}: {}",
        std::io::Error::last_os_error()
    );
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let before = file
        .metadata()
        .unwrap_or_else(|error| panic!("cannot stat P0 userdebug {label}: {error}"));
    assert!(
        before.is_file()
            && before.nlink() == 1
            && before.len() > 0
            && before.len() <= maximum
            && before.uid() == expected_uid
            && before.permissions().mode() & 0o777 == mode,
        "P0 userdebug {label} is not the exact bounded immutable regular file"
    );
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).expect("P0 userdebug artifact length exceeds usize"),
    );
    file.read_to_end(&mut bytes)
        .unwrap_or_else(|error| panic!("cannot read P0 userdebug {label}: {error}"));
    let after = file
        .metadata()
        .unwrap_or_else(|error| panic!("cannot restat P0 userdebug {label}: {error}"));
    assert!(
        u64::try_from(bytes.len()) == Ok(before.len())
            && stable_identity(&before) == stable_identity(&after),
        "P0 userdebug {label} changed while it was measured"
    );
    bytes
}

fn sha256(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn validate_retained_native_tool_env(
    name: &str,
    expected_path: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
) -> String {
    let value = env::var(name).unwrap_or_else(|_| panic!("P0 userdebug daemon build omits {name}"));
    let descriptor = value
        .strip_prefix("/proc/self/fd/")
        .filter(|item| !item.is_empty() && item.bytes().all(|byte| byte.is_ascii_digit()))
        .unwrap_or_else(|| panic!("P0 userdebug daemon {name} is not a retained descriptor"));
    let mut file = File::open(&value)
        .unwrap_or_else(|error| panic!("cannot open P0 userdebug daemon {name}: {error}"));
    let before = file
        .metadata()
        .unwrap_or_else(|error| panic!("cannot stat P0 userdebug daemon {name}: {error}"));
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).expect("P0 userdebug native tool exceeds usize"),
    );
    file.read_to_end(&mut bytes)
        .unwrap_or_else(|error| panic!("cannot read P0 userdebug daemon {name}: {error}"));
    let after = file
        .metadata()
        .unwrap_or_else(|error| panic!("cannot restat P0 userdebug daemon {name}: {error}"));
    let expected_file = open_absolute_build_tool(expected_path, name);
    let expected_metadata = expected_file.metadata().unwrap_or_else(|error| {
        panic!("cannot stat P0 userdebug daemon expected {name} leaf: {error}")
    });
    assert!(
        before.is_file()
            && before.nlink() == 1
            && before.len() == expected_bytes
            && before.permissions().mode() & 0o7777 == 0o555
            && stable_identity(&before) == stable_identity(&after)
            && stable_identity(&before) == stable_identity(&expected_metadata)
            && sha256(&bytes) == expected_sha256,
        "P0 userdebug daemon {name} retained tool identity differs"
    );
    let _ = descriptor;
    value
}

fn open_custodied_absolute_directory(
    path: &Path,
    label: &str,
    exact_leaf_mode: Option<u32>,
) -> File {
    let components = path.components().collect::<Vec<_>>();
    assert!(
        matches!(components.first(), Some(Component::RootDir))
            && components.len() >= 2
            && components[1..]
                .iter()
                .all(|component| matches!(component, Component::Normal(_))),
        "P0 userdebug {label} is not a non-root canonical absolute directory"
    );
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/")
        .unwrap_or_else(|error| panic!("cannot open root for P0 userdebug {label}: {error}"));
    let effective_uid = unsafe { libc::geteuid() };
    for (index, component) in components[1..].iter().enumerate() {
        let Component::Normal(name) = component else {
            unreachable!("canonical directory components were checked above")
        };
        let name = CString::new(name.as_bytes())
            .unwrap_or_else(|_| panic!("P0 userdebug {label} contains NUL"));
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        assert!(
            descriptor >= 0,
            "cannot open P0 userdebug {label} without following links: {}",
            std::io::Error::last_os_error()
        );
        let child = unsafe { File::from_raw_fd(descriptor) };
        let metadata = child
            .metadata()
            .unwrap_or_else(|error| panic!("cannot stat P0 userdebug {label}: {error}"));
        let leaf = index == components.len() - 2;
        let mode = metadata.permissions().mode() & 0o7777;
        assert!(
            metadata.is_dir()
                && (if leaf {
                    metadata.uid() == effective_uid
                } else {
                    metadata.uid() == 0 || metadata.uid() == effective_uid
                })
                && mode & 0o022 == 0
                && exact_leaf_mode.is_none_or(|expected| !leaf || mode == expected),
            "P0 userdebug {label} traverses an untrusted or over-broad directory"
        );
        directory = child;
    }
    directory
}

fn open_nofollow_source_directory(path: &Path, label: &str) -> File {
    let components = path.components().collect::<Vec<_>>();
    assert!(
        matches!(components.first(), Some(Component::RootDir))
            && components.len() >= 2
            && components[1..]
                .iter()
                .all(|component| matches!(component, Component::Normal(_))),
        "P0 userdebug {label} is not a non-root canonical absolute directory"
    );
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/")
        .unwrap_or_else(|error| panic!("cannot open root for P0 userdebug {label}: {error}"));
    let effective_uid = unsafe { libc::geteuid() };
    for component in &components[1..] {
        let Component::Normal(name) = component else {
            unreachable!("canonical source-directory components were checked above")
        };
        let name = CString::new(name.as_bytes())
            .unwrap_or_else(|_| panic!("P0 userdebug {label} contains NUL"));
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        assert!(
            descriptor >= 0,
            "cannot open P0 userdebug {label} without following links: {}",
            std::io::Error::last_os_error()
        );
        let child = unsafe { File::from_raw_fd(descriptor) };
        let metadata = child
            .metadata()
            .unwrap_or_else(|error| panic!("cannot stat P0 userdebug {label}: {error}"));
        assert!(
            metadata.is_dir()
                && (metadata.uid() == 0 || metadata.uid() == effective_uid)
                && metadata.permissions().mode() & 0o002 == 0,
            "P0 userdebug {label} traverses an unowned or world-writable directory"
        );
        directory = child;
    }
    directory
}

fn open_private_cargo_descendant(
    target_directory: &File,
    target_path: &Path,
    path: &Path,
    label: &str,
) -> File {
    let relative = path.strip_prefix(target_path).unwrap_or_else(|_| {
        panic!("P0 userdebug {label} is outside the private Cargo target directory")
    });
    let components = relative.components().collect::<Vec<_>>();
    assert!(
        !components.is_empty()
            && components
                .iter()
                .all(|component| matches!(component, Component::Normal(_))),
        "P0 userdebug {label} is not a strict canonical Cargo target descendant"
    );
    let target_metadata = target_directory
        .metadata()
        .expect("cannot stat retained P0 userdebug Cargo target directory");
    let effective_uid = unsafe { libc::geteuid() };
    let mut directory = target_directory
        .try_clone()
        .expect("cannot retain P0 userdebug Cargo target directory");
    for component in components {
        let Component::Normal(name) = component else {
            unreachable!("strict descendant components were checked above")
        };
        let name = CString::new(name.as_bytes())
            .unwrap_or_else(|_| panic!("P0 userdebug {label} contains NUL"));
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        assert!(
            descriptor >= 0,
            "cannot open P0 userdebug {label} without following links: {}",
            std::io::Error::last_os_error()
        );
        let child = unsafe { File::from_raw_fd(descriptor) };
        let metadata = child
            .metadata()
            .unwrap_or_else(|error| panic!("cannot stat P0 userdebug {label}: {error}"));
        assert!(
            metadata.is_dir()
                && metadata.uid() == effective_uid
                && metadata.permissions().mode() & 0o022 == 0
                && metadata.dev() == target_metadata.dev(),
            "P0 userdebug {label} escapes private same-filesystem Cargo custody"
        );
        directory = child;
    }
    directory
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[allow(clippy::too_many_arguments)]
fn validate_target_native_environment(
    expected_sysroot: &Path,
    expected_compiler_bin: &Path,
    expected_gcc_libdir: &Path,
    expected_binutils: &Path,
    expected_host_runtime: &Path,
    lane_root: &Path,
    receipt_path: &Path,
    receipt_directory: &File,
) -> Vec<File> {
    for name in FORBIDDEN_NATIVE_BUILD_ENVIRONMENTS {
        assert!(
            env::var_os(name).is_none(),
            "P0 userdebug daemon build contains forbidden native environment override {name}"
        );
    }
    let compiler = validate_retained_native_tool_env(
        TARGET_CC_ENV,
        &expected_compiler_bin.join("aarch64-linux-gnu-gcc-12"),
        FROZEN_TARGET_COMPILER_BYTES,
        FROZEN_TARGET_COMPILER_SHA256,
    );
    let archiver = validate_retained_native_tool_env(
        TARGET_AR_ENV,
        &expected_compiler_bin.join("aarch64-linux-gnu-ar"),
        FROZEN_TARGET_ARCHIVER_BYTES,
        FROZEN_TARGET_ARCHIVER_SHA256,
    );
    assert_eq!(
        env::var(CARGO_TARGET_LINKER_ENV).as_deref(),
        Ok(compiler.as_str()),
        "P0 userdebug daemon Cargo target linker differs from cc-rs compiler"
    );
    assert_eq!(
        env::var(CARGO_TARGET_AR_ENV).as_deref(),
        Ok(archiver.as_str()),
        "P0 userdebug daemon Cargo target archiver differs from cc-rs archiver"
    );
    let native_flags = format!(
        "--sysroot={} -B{} -B{} -B{}",
        expected_sysroot.display(),
        expected_compiler_bin.display(),
        expected_gcc_libdir.display(),
        expected_binutils.display(),
    );
    for name in [TARGET_CFLAGS_ENV, TARGET_CXXFLAGS_ENV] {
        assert_eq!(
            env::var(name).as_deref(),
            Ok(native_flags.as_str()),
            "P0 userdebug daemon {name} differs from the closed native flags"
        );
    }

    let target_dir = PathBuf::from(
        env::var_os("CARGO_TARGET_DIR").expect("P0 userdebug daemon build omits CARGO_TARGET_DIR"),
    );
    assert!(
        target_dir.is_absolute()
            && target_dir.components().all(|component| {
                matches!(component, Component::RootDir | Component::Normal(_))
            }),
        "P0 userdebug daemon CARGO_TARGET_DIR is not canonical absolute syntax"
    );
    let manifest_directory = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .expect("P0 userdebug daemon build omits CARGO_MANIFEST_DIR"),
    );
    let source_directory =
        open_nofollow_source_directory(&manifest_directory, "Cargo source manifest directory");
    assert!(
        !paths_overlap(&target_dir, &manifest_directory)
            && !paths_overlap(&target_dir, lane_root)
            && !paths_overlap(
                &target_dir,
                receipt_path
                    .parent()
                    .expect("P0 userdebug receipt has no input directory"),
            ),
        "P0 userdebug Cargo target directory overlaps a source, toolchain, or receipt input"
    );
    let target_directory =
        open_custodied_absolute_directory(&target_dir, "Cargo target directory", Some(0o700));
    let lane_directory =
        open_custodied_absolute_directory(lane_root, "toolchain lane directory", None);
    let target_metadata = target_directory
        .metadata()
        .expect("cannot stat retained P0 userdebug Cargo target directory");
    let target_identity = (target_metadata.dev(), target_metadata.ino());
    for (label, directory) in [
        ("Cargo source manifest directory", &source_directory),
        ("toolchain lane directory", &lane_directory),
        ("receipt input directory", receipt_directory),
    ] {
        let metadata = directory
            .metadata()
            .unwrap_or_else(|error| panic!("cannot stat retained P0 userdebug {label}: {error}"));
        assert_ne!(
            target_identity,
            (metadata.dev(), metadata.ino()),
            "P0 userdebug Cargo target directory physically aliases {label}"
        );
    }
    let library_path =
        env::var_os("LD_LIBRARY_PATH").expect("P0 userdebug daemon build omits LD_LIBRARY_PATH");
    let mut snapshot_count = 0usize;
    let mut observed = std::collections::BTreeSet::new();
    let mut retained_directories = vec![target_directory, source_directory, lane_directory];
    for component in env::split_paths(&library_path) {
        assert!(
            component.is_absolute()
                && component
                    .components()
                    .all(|item| { matches!(item, Component::RootDir | Component::Normal(_)) })
                && observed.insert(component.clone()),
            "P0 userdebug daemon LD_LIBRARY_PATH is non-canonical or duplicated"
        );
        if component == expected_host_runtime {
            snapshot_count += 1;
            retained_directories.push(open_custodied_absolute_directory(
                &component,
                "snapshot host-runtime directory",
                None,
            ));
        } else {
            let directory = open_private_cargo_descendant(
                &retained_directories[0],
                &target_dir,
                &component,
                "Cargo-prepended runtime directory",
            );
            retained_directories.push(directory);
        }
    }
    assert_eq!(
        snapshot_count, 1,
        "P0 userdebug daemon LD_LIBRARY_PATH must contain the snapshot usr/lib exactly once"
    );
    retained_directories
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .unwrap_or_else(|| panic!("P0 userdebug receipt omitted {name}"))
}

fn exact_string(value: &Value, name: &str, expected: &str) {
    assert_eq!(
        field(value, name).as_str(),
        Some(expected),
        "P0 userdebug receipt {name} differs"
    );
}

fn exact_bool(value: &Value, name: &str, expected: bool) {
    assert_eq!(
        field(value, name).as_bool(),
        Some(expected),
        "P0 userdebug receipt {name} differs"
    );
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value != "0000000000000000000000000000000000000000000000000000000000000000"
}

fn valid_lower_hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_source_bom_binding(receipt: &Value) {
    let source = field(receipt, "source_bom")
        .as_object()
        .expect("P0 userdebug source BOM binding is not an object");
    let keys = source
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = [
        "authority",
        "bytes",
        "control_head",
        "file_sha256",
        "receipt_id",
        "resolved_manifest_sha256",
        "source_set_sha256",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys, expected,
        "P0 userdebug source BOM binding schema is not closed"
    );
    assert_eq!(
        source.get("authority").and_then(Value::as_str),
        Some("local_exact_clean_graph_not_build_or_release_authority"),
        "P0 userdebug source BOM binding overclaims authority"
    );
    let bytes = source
        .get("bytes")
        .and_then(Value::as_u64)
        .expect("P0 userdebug source BOM byte length is missing");
    assert!(
        bytes > 0 && bytes <= 16 * 1024 * 1024,
        "P0 userdebug source BOM byte length is invalid"
    );
    for name in [
        "file_sha256",
        "resolved_manifest_sha256",
        "source_set_sha256",
    ] {
        assert!(
            source
                .get(name)
                .and_then(Value::as_str)
                .is_some_and(valid_sha256),
            "P0 userdebug source BOM {name} is malformed"
        );
    }
    assert!(
        source
            .get("control_head")
            .and_then(Value::as_str)
            .is_some_and(|value| valid_lower_hex(value, &[40, 64])),
        "P0 userdebug source BOM control HEAD is malformed"
    );
    assert!(
        source
            .get("receipt_id")
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix("sha256:"))
            .is_some_and(valid_sha256),
        "P0 userdebug source BOM receipt id is malformed"
    );
}

fn open_absolute_build_tool(path: &Path, label: &str) -> File {
    let components = path.components().collect::<Vec<_>>();
    assert!(
        matches!(components.first(), Some(Component::RootDir))
            && components.len() >= 2
            && components[1..]
                .iter()
                .all(|component| matches!(component, Component::Normal(_))),
        "P0 userdebug {label} path is not canonical absolute syntax"
    );
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/")
        .expect("cannot open root directory for launcher build-tool custody");
    for component in &components[1..components.len() - 1] {
        let Component::Normal(name) = component else {
            unreachable!("canonical path components were checked above")
        };
        let name = CString::new(name.as_bytes())
            .expect("P0 userdebug launcher build-tool path contains NUL");
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        assert!(
            descriptor >= 0,
            "cannot open P0 userdebug {label} directory component: {}",
            std::io::Error::last_os_error()
        );
        let child = unsafe { File::from_raw_fd(descriptor) };
        let metadata = child
            .metadata()
            .unwrap_or_else(|error| panic!("cannot stat P0 userdebug {label} directory: {error}"));
        let effective_uid = unsafe { libc::geteuid() };
        assert!(
            metadata.is_dir()
                && (metadata.uid() == 0 || metadata.uid() == effective_uid)
                && metadata.permissions().mode() & 0o022 == 0,
            "P0 userdebug {label} path traverses an untrusted directory"
        );
        directory = child;
    }
    let Component::Normal(leaf) = components[components.len() - 1] else {
        unreachable!("canonical path components were checked above")
    };
    let leaf =
        CString::new(leaf.as_bytes()).expect("P0 userdebug launcher build-tool leaf contains NUL");
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    assert!(
        descriptor >= 0,
        "cannot open P0 userdebug {label}: {}",
        std::io::Error::last_os_error()
    );
    unsafe { File::from_raw_fd(descriptor) }
}

fn validate_launcher_build_tool(receipt: &Value, field_name: &str, expected_role: &str) {
    let tool_value = field(receipt, field_name);
    let tool = tool_value
        .as_object()
        .unwrap_or_else(|| panic!("P0 userdebug {field_name} custody is not an object"));
    let expected_keys = [
        "bytes",
        "complete_recursive_toolchain_closure",
        "execution",
        "gid",
        "link_count",
        "mode",
        "path",
        "role",
        "schema",
        "sha256",
        "target",
        "uid",
        "version",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        tool.keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        expected_keys,
        "P0 userdebug {field_name} custody schema is not closed"
    );
    exact_string(tool_value, "schema", LAUNCHER_BUILD_TOOL_SCHEMA);
    exact_string(tool_value, "role", expected_role);
    exact_string(tool_value, "target", "aarch64-linux-gnu");
    exact_bool(tool_value, "complete_recursive_toolchain_closure", false);
    let path_value = field(tool_value, "path")
        .as_str()
        .expect("P0 userdebug launcher build-tool path is not a string");
    let path = Path::new(path_value);
    println!("cargo:rerun-if-changed={}", path.display());
    let mut file = open_absolute_build_tool(path, field_name);
    let before = file
        .metadata()
        .unwrap_or_else(|error| panic!("cannot stat P0 userdebug {field_name}: {error}"));
    let mode = before.permissions().mode() & 0o7777;
    let effective_uid = unsafe { libc::geteuid() };
    assert!(
        before.is_file()
            && before.nlink() == 1
            && before.len() > 0
            && before.len() <= LAUNCHER_BUILD_TOOL_MAXIMUM
            && (before.uid() == 0 || before.uid() == effective_uid)
            && mode & 0o022 == 0
            && mode & 0o100 != 0,
        "P0 userdebug {field_name} physical custody is unsafe"
    );
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).expect("P0 launcher build tool exceeds usize"),
    );
    file.read_to_end(&mut bytes)
        .unwrap_or_else(|error| panic!("cannot read P0 userdebug {field_name}: {error}"));
    let after = file
        .metadata()
        .unwrap_or_else(|error| panic!("cannot restat P0 userdebug {field_name}: {error}"));
    let reopened = open_absolute_build_tool(path, field_name);
    let reopened_metadata = reopened.metadata().unwrap_or_else(|error| {
        panic!("cannot restat P0 userdebug {field_name} pathname: {error}")
    });
    assert!(
        u64::try_from(bytes.len()) == Ok(before.len())
            && stable_identity(&before) == stable_identity(&after)
            && stable_identity(&before) == stable_identity(&reopened_metadata),
        "P0 userdebug {field_name} changed while physically remeasured"
    );
    assert_eq!(
        field(tool_value, "bytes").as_u64(),
        Some(before.len()),
        "P0 userdebug {field_name} byte length differs"
    );
    assert_eq!(
        field(tool_value, "sha256").as_str(),
        Some(sha256(&bytes).as_str()),
        "P0 userdebug {field_name} digest differs"
    );
    assert_eq!(
        field(tool_value, "mode").as_str(),
        Some(format!("0{mode:o}").as_str()),
        "P0 userdebug {field_name} mode differs"
    );
    assert_eq!(
        field(tool_value, "uid").as_u64(),
        Some(u64::from(before.uid()))
    );
    assert_eq!(
        field(tool_value, "gid").as_u64(),
        Some(u64::from(before.gid()))
    );
    assert_eq!(
        field(tool_value, "link_count").as_u64(),
        Some(before.nlink())
    );
    assert!(
        field(tool_value, "version")
            .as_str()
            .is_some_and(|version| !version.is_empty()
                && version.len() <= 512
                && !version
                    .chars()
                    .any(|character| matches!(character, '\0' | '\n' | '\r'))),
        "P0 userdebug {field_name} version is malformed"
    );
    let execution_value = field(tool_value, "execution");
    let execution = execution_value
        .as_object()
        .expect("P0 userdebug launcher build-tool execution custody is not an object");
    assert_eq!(
        execution
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "all_invocations_used_same_open_file_description",
            "ambient_environment_inherited",
            "descriptor_and_path_stable_after_last_execution",
            "environment_allowlist",
            "measured_before_first_execution",
            "mechanism",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>(),
        "P0 userdebug {field_name} execution schema is not closed"
    );
    exact_string(
        execution_value,
        "mechanism",
        "retained_open_file_description_via_proc_self_fd",
    );
    for name in [
        "measured_before_first_execution",
        "all_invocations_used_same_open_file_description",
        "descriptor_and_path_stable_after_last_execution",
    ] {
        exact_bool(execution_value, name, true);
    }
    exact_bool(execution_value, "ambient_environment_inherited", false);
    assert_eq!(
        field(execution_value, "environment_allowlist"),
        &serde_json::json!([
            "LANG",
            "LC_ALL",
            "LD_LIBRARY_PATH",
            "PATH",
            "SOURCE_DATE_EPOCH",
            "TMPDIR",
            "TZ"
        ]),
        "P0 userdebug {field_name} environment allowlist differs"
    );
}

fn validate_identity_independence_hold_gate(receipt: &Value) {
    let gate_value = field(receipt, "legacy_descriptor_contamination_hold_gate");
    let gate = gate_value
        .as_object()
        .expect("P0 userdebug identity-independence gate is not an object");
    let actual_gate_keys = gate
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected_gate_keys = [
        "counterfactual_same_source_rebuild",
        "digests",
        "literal_digest_absence_verified",
        "stable_principal_admission_split",
        "status",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        actual_gate_keys, expected_gate_keys,
        "P0 userdebug identity-independence gate schema is not closed"
    );
    exact_string(gate_value, "status", IDENTITY_INDEPENDENCE_HOLD_STATUS);
    exact_bool(gate_value, "literal_digest_absence_verified", true);

    let digests_value = field(gate_value, "digests");
    let digests = digests_value
        .as_object()
        .expect("P0 userdebug identity-independence digests are not an object");
    assert_eq!(
        digests
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        ["canonical digest", "contract digest", "launcher identity"]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        "P0 userdebug identity-independence digest schema is not closed"
    );
    exact_string(
        digests_value,
        "canonical digest",
        FROZEN_LEGACY_DESCRIPTOR_CANONICAL_SHA256,
    );
    exact_string(
        digests_value,
        "contract digest",
        FROZEN_LEGACY_DESCRIPTOR_CONTRACT_SHA256,
    );
    exact_string(
        digests_value,
        "launcher identity",
        FROZEN_LEGACY_DESCRIPTOR_LAUNCHER_SHA256,
    );

    for name in [
        "counterfactual_same_source_rebuild",
        "stable_principal_admission_split",
    ] {
        let evidence_value = field(gate_value, name);
        let evidence = evidence_value.as_object().unwrap_or_else(|| {
            panic!("P0 userdebug identity-independence {name} is not an object")
        });
        assert_eq!(
            evidence
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            ["evidence_receipt", "required", "verified"]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            "P0 userdebug identity-independence {name} schema is not closed"
        );
        exact_bool(evidence_value, "required", true);
        exact_bool(evidence_value, "verified", false);
        assert!(
            field(evidence_value, "evidence_receipt").is_null(),
            "P0 userdebug identity-independence {name} must not claim evidence"
        );
    }
}

fn canonical_value_sha256(value: &Value) -> String {
    let mut canonical = serde_json::to_vec_pretty(value)
        .expect("P0 userdebug binding value cannot be canonicalized");
    canonical.push(b'\n');
    sha256(&canonical)
}

fn validate_toolchain_manifest(
    receipt: &Value,
    receipt_path: &Path,
    receipt_directory: &File,
) -> Vec<File> {
    let manifest_path = PathBuf::from(
        env::var(TOOLCHAIN_MANIFEST_ENV)
            .unwrap_or_else(|_| panic!("P0 userdebug daemon requires {TOOLCHAIN_MANIFEST_ENV}")),
    );
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    let mut file = open_absolute_build_tool(&manifest_path, "toolchain manifest");
    let before = file
        .metadata()
        .expect("cannot stat P0 userdebug toolchain manifest");
    let effective_uid = unsafe { libc::geteuid() };
    assert!(
        before.is_file()
            && before.nlink() == 1
            && before.len() > 0
            && before.len() <= TOOLCHAIN_MANIFEST_MAXIMUM
            && before.uid() == effective_uid
            && before.permissions().mode() & 0o777 == 0o444,
        "P0 userdebug toolchain manifest physical custody is unsafe"
    );
    let mut raw = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut raw)
        .expect("cannot read P0 userdebug toolchain manifest");
    let after = file
        .metadata()
        .expect("cannot restat P0 userdebug toolchain manifest");
    assert_eq!(
        stable_identity(&before),
        stable_identity(&after),
        "P0 userdebug toolchain manifest changed while measured"
    );
    assert_eq!(
        sha256(&raw),
        FROZEN_TOOLCHAIN_MANIFEST_SHA256,
        "P0 userdebug toolchain manifest digest differs"
    );
    let value: Value =
        serde_json::from_slice(&raw).expect("P0 userdebug toolchain manifest is not valid JSON");
    let mut canonical = serde_json::to_vec_pretty(&value)
        .expect("P0 userdebug toolchain manifest cannot be canonicalized");
    canonical.push(b'\n');
    assert_eq!(
        raw, canonical,
        "P0 userdebug toolchain manifest is not canonical"
    );
    let object = value
        .as_object()
        .expect("P0 userdebug toolchain manifest is not an object");
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "entries",
            "manifest_id",
            "schema",
            "source_date_epoch",
            "summary",
            "tree_digest",
        ],
        "P0 userdebug toolchain manifest schema is not closed"
    );
    exact_string(
        &value,
        "schema",
        "org.trillionnium.packaging.mobian-toolchain-snapshot-manifest.v1",
    );
    exact_string(&value, "tree_digest", FROZEN_TOOLCHAIN_TREE_DIGEST);
    exact_string(&value, "manifest_id", FROZEN_TOOLCHAIN_MANIFEST_ID);
    assert_eq!(
        field(&value, "source_date_epoch").as_u64(),
        Some(1_784_390_949)
    );
    let entries = field(&value, "entries")
        .as_array()
        .expect("P0 userdebug toolchain entries are not an array");
    assert_eq!(entries.len(), 33_930);
    assert_eq!(
        sha256(&serde_json::to_vec(entries).expect("cannot canonicalize toolchain entries")),
        FROZEN_TOOLCHAIN_TREE_DIGEST,
        "P0 userdebug toolchain tree digest is not reproducible"
    );
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .expect("toolchain manifest object disappeared")
        .remove("manifest_id");
    assert_eq!(
        sha256(&serde_json::to_vec(&unsigned).expect("cannot canonicalize toolchain manifest")),
        FROZEN_TOOLCHAIN_MANIFEST_ID,
        "P0 userdebug toolchain manifest_id is not reproducible"
    );
    let summary = field(&value, "summary")
        .as_object()
        .expect("P0 userdebug toolchain summary is not an object");
    assert_eq!(
        summary.get("entry_count").and_then(Value::as_u64),
        Some(33_930)
    );
    assert_eq!(
        summary.get("regular_bytes").and_then(Value::as_u64),
        Some(1_952_702_440)
    );
    for name in [
        "closed_world",
        "current_user_owned",
        "directories_mode_0500",
        "regular_files_mode_0444_or_0555",
        "regular_files_single_link",
        "symlink_targets_manifested",
    ] {
        assert_eq!(
            summary.get(name).and_then(Value::as_bool),
            Some(true),
            "P0 userdebug toolchain summary {name} differs"
        );
    }
    assert_eq!(
        summary
            .get("group_world_writable_entries")
            .and_then(Value::as_u64),
        Some(0)
    );

    let lane_root = manifest_path
        .parent()
        .expect("P0 userdebug toolchain manifest has no lane root");
    let expected_sysroot = lane_root.join("toolchain/sysroot");
    let expected_compiler_bin = expected_sysroot.join("usr/bin");
    let expected_gcc_libdir = expected_sysroot.join("usr/lib/gcc-cross/aarch64-linux-gnu/12");
    let expected_binutils = expected_sysroot.join("usr/aarch64-linux-gnu/bin");
    let expected_host_runtime = expected_sysroot.join("usr/lib/x86_64-linux-gnu");
    for (name, expected) in [
        (TARGET_SYSROOT_ENV, expected_sysroot.clone()),
        (TARGET_COMPILER_BIN_ENV, expected_compiler_bin.clone()),
        (TARGET_GCC_LIBDIR_ENV, expected_gcc_libdir.clone()),
        (TARGET_BINUTILS_DIR_ENV, expected_binutils.clone()),
        (
            TARGET_HOST_RUNTIME_LIBDIR_ENV,
            expected_host_runtime.clone(),
        ),
    ] {
        assert_eq!(
            env::var_os(name).as_deref(),
            Some(expected.as_os_str()),
            "P0 userdebug daemon {name} differs from the bound lane snapshot"
        );
    }
    let retained_native_directories = validate_target_native_environment(
        &expected_sysroot,
        &expected_compiler_bin,
        &expected_gcc_libdir,
        &expected_binutils,
        &expected_host_runtime,
        lane_root,
        receipt_path,
        receipt_directory,
    );
    let compiler_path = field(field(receipt, "compiler"), "path")
        .as_str()
        .expect("P0 userdebug compiler path is not a string");
    assert_eq!(
        Path::new(compiler_path),
        expected_compiler_bin.join("aarch64-linux-gnu-gcc-12"),
        "P0 userdebug launcher/final compiler is not the bound GCC12 ELF"
    );
    let inspector_path = field(field(receipt, "elf_inspector"), "path")
        .as_str()
        .expect("P0 userdebug ELF inspector path is not a string");
    assert_eq!(
        Path::new(inspector_path),
        expected_compiler_bin.join("aarch64-linux-gnu-readelf"),
        "P0 userdebug launcher/final ELF inspector is not the bound readelf ELF"
    );
    retained_native_directories
}

fn normalized_daemon_rustflags() -> Vec<String> {
    let encoded = env::var("CARGO_ENCODED_RUSTFLAGS")
        .expect("P0 userdebug daemon build omits CARGO_ENCODED_RUSTFLAGS");
    let retained_target_compiler =
        env::var(TARGET_CC_ENV).expect("P0 userdebug daemon build omits retained target compiler");
    let raw = encoded.split('\u{1f}').collect::<Vec<_>>();
    assert!(
        !raw.is_empty() && raw.iter().all(|item| !item.is_empty()),
        "P0 userdebug daemon Rust flags contain an empty token"
    );
    let mut normalized = Vec::with_capacity(raw.len());
    let mut index = 0usize;
    while index < raw.len() {
        let token = raw[index];
        if token == "--remap-path-prefix" {
            assert!(
                index + 1 < raw.len(),
                "P0 userdebug daemon path-remap flag lacks its value"
            );
            let (source, destination) = raw[index + 1]
                .rsplit_once('=')
                .expect("P0 userdebug daemon path-remap value is malformed");
            let source_path = Path::new(source);
            let normalized_source = source_path.components().collect::<PathBuf>();
            assert!(
                source_path.is_absolute()
                    && normalized_source.as_os_str().as_bytes() == source.as_bytes(),
                "P0 userdebug daemon path-remap source is not canonical absolute syntax"
            );
            normalized.push(token.to_owned());
            normalized.push(format!("$ABSOLUTE_SOURCE={destination}"));
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("link-arg=--sysroot=") {
            assert_eq!(
                Some(value),
                env::var(TARGET_SYSROOT_ENV).ok().as_deref(),
                "P0 userdebug daemon sysroot flag differs from its explicit environment"
            );
            normalized.push("link-arg=--sysroot=$TARGET_SYSROOT".to_owned());
        } else if let Some(value) = token.strip_prefix("link-arg=-B") {
            let normalized_value = if env::var(TARGET_COMPILER_BIN_ENV).as_deref() == Ok(value) {
                "$TARGET_COMPILER_BIN"
            } else if env::var(TARGET_GCC_LIBDIR_ENV).as_deref() == Ok(value) {
                "$TARGET_GCC_LIBDIR"
            } else if env::var(TARGET_BINUTILS_DIR_ENV).as_deref() == Ok(value) {
                "$TARGET_BINUTILS_DIR"
            } else {
                panic!("P0 userdebug daemon -B flag is outside the explicit toolchain")
            };
            normalized.push(format!("link-arg=-B{normalized_value}"));
        } else if let Some(value) = token.strip_prefix("linker=") {
            assert_eq!(
                value, retained_target_compiler,
                "P0 userdebug daemon Rust linker differs from the retained target compiler"
            );
            let descriptor = value
                .strip_prefix("/proc/self/fd/")
                .expect("P0 userdebug daemon retained Rust linker is not a descriptor");
            assert!(
                !descriptor.is_empty() && descriptor.bytes().all(|byte| byte.is_ascii_digit()),
                "P0 userdebug daemon retained linker descriptor is malformed"
            );
            normalized.push("linker=$RETAINED_LINKER".to_owned());
        } else {
            normalized.push(token.to_owned());
        }
        index += 1;
    }
    normalized
}

fn validate_daemon_build_binding(receipt: &Value) -> String {
    let binding_value = field(receipt, "daemon_build_binding");
    let binding = binding_value
        .as_object()
        .expect("P0 userdebug daemon build binding is not an object");
    assert_eq!(
        binding.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "build_policy",
            "cargo_profile",
            "feature_profile",
            "identity_independence_hold",
            "product_variant",
            "runtime_artifact_sha256",
            "schema",
            "sha256_scope",
            "stable_principal",
            "target_compiler_closure",
            "target_profile",
            "toolchain_snapshot",
        ],
        "P0 userdebug daemon build binding schema is not closed"
    );
    exact_string(binding_value, "schema", DAEMON_BUILD_BINDING_SCHEMA);
    exact_string(
        binding_value,
        "sha256_scope",
        DAEMON_BUILD_BINDING_SHA256_SCOPE,
    );
    exact_string(binding_value, "product_variant", "userdebug");

    let profile_value = field(binding_value, "feature_profile");
    let profile = profile_value
        .as_object()
        .expect("P0 userdebug daemon feature profile is not an object");
    assert_eq!(
        profile.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "cargo_package",
            "conformance_build_variant",
            "default_cargo_features",
            "enabled_cargo_features",
        ],
        "P0 userdebug daemon feature profile schema is not closed"
    );
    exact_string(profile_value, "cargo_package", "trillionniumd");
    exact_string(profile_value, "conformance_build_variant", "userdebug");
    assert_eq!(
        field(profile_value, "default_cargo_features"),
        &serde_json::json!([]),
        "P0 userdebug default Cargo feature profile differs"
    );
    assert_eq!(
        field(profile_value, "enabled_cargo_features"),
        &serde_json::json!(["p0-launch-package-device-conformance"]),
        "P0 userdebug enabled Cargo feature profile differs"
    );

    let cargo_profile_value = field(binding_value, "cargo_profile");
    let cargo_profile = cargo_profile_value
        .as_object()
        .expect("P0 userdebug daemon Cargo profile is not an object");
    assert_eq!(
        cargo_profile.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "debug",
            "debug_assertions",
            "incremental",
            "name",
            "opt_level",
            "strip",
        ],
        "P0 userdebug daemon Cargo profile schema is not closed"
    );
    assert_eq!(
        cargo_profile_value,
        &serde_json::json!({
            "name": "release",
            "opt_level": "3",
            "debug": 0,
            "debug_assertions": false,
            "incremental": false,
            "strip": "symbols",
        }),
        "P0 userdebug daemon Cargo profile differs"
    );
    assert_eq!(
        env::var("PROFILE").as_deref(),
        Ok("release"),
        "P0 userdebug daemon must use the release Cargo profile"
    );
    assert_eq!(
        env::var("OPT_LEVEL").as_deref(),
        Ok("3"),
        "P0 userdebug daemon release optimization level differs"
    );
    assert_eq!(
        env::var("DEBUG").as_deref(),
        Ok("false"),
        "P0 userdebug daemon release debug-info posture differs"
    );
    assert!(
        env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_none(),
        "P0 userdebug daemon release build enables debug assertions"
    );

    let build_policy_value = field(binding_value, "build_policy");
    let build_policy = build_policy_value
        .as_object()
        .expect("P0 userdebug daemon build policy is not an object");
    assert_eq!(
        build_policy.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "cargo_incremental",
            "host_runtime_execution_boundary",
            "normalized_native_environment",
            "normalized_rustflags",
            "selected_native_tools",
            "source_date_epoch",
        ],
        "P0 userdebug daemon build policy schema is not closed"
    );
    exact_string(build_policy_value, "cargo_incremental", "0");
    assert_eq!(
        field(build_policy_value, "source_date_epoch").as_u64(),
        Some(1785110400),
        "P0 userdebug daemon SOURCE_DATE_EPOCH policy differs"
    );
    assert_eq!(
        field(build_policy_value, "normalized_rustflags"),
        &serde_json::json!(DAEMON_NORMALIZED_RUSTFLAGS),
        "P0 userdebug daemon normalized Rust-flag policy differs"
    );
    assert_eq!(
        field(build_policy_value, "normalized_native_environment"),
        &serde_json::json!({
            "CC_aarch64_unknown_linux_gnu": "$RETAINED_TARGET_COMPILER",
            "AR_aarch64_unknown_linux_gnu": "$RETAINED_TARGET_ARCHIVER",
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "$RETAINED_TARGET_COMPILER",
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR": "$RETAINED_TARGET_ARCHIVER",
            "CFLAGS_aarch64_unknown_linux_gnu": "--sysroot=$TARGET_SYSROOT -B$TARGET_COMPILER_BIN -B$TARGET_GCC_LIBDIR -B$TARGET_BINUTILS_DIR",
            "CXXFLAGS_aarch64_unknown_linux_gnu": "--sysroot=$TARGET_SYSROOT -B$TARGET_COMPILER_BIN -B$TARGET_GCC_LIBDIR -B$TARGET_BINUTILS_DIR",
        }),
        "P0 userdebug daemon native environment policy differs"
    );
    assert_eq!(
        field(build_policy_value, "selected_native_tools"),
        &serde_json::json!({
            "compiler": {
                "relative_path": "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12",
                "bytes": 1_315_296,
                "sha256": FROZEN_TARGET_COMPILER_SHA256,
                "mode": "0555",
            },
            "archiver": {
                "relative_path": "toolchain/sysroot/usr/bin/aarch64-linux-gnu-ar",
                "bytes": 68_920,
                "sha256": FROZEN_TARGET_ARCHIVER_SHA256,
                "mode": "0555",
            },
        }),
        "P0 userdebug daemon selected native-tool policy differs"
    );
    assert_eq!(
        field(build_policy_value, "host_runtime_execution_boundary"),
        &serde_json::json!({
            "snapshot_usr_lib_relative_path": "toolchain/sysroot/usr/lib/x86_64-linux-gnu",
            "cargo_target_dir_subpaths_may_be_prepended": true,
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": false,
        }),
        "P0 userdebug daemon host-runtime execution boundary differs"
    );
    assert_eq!(
        env::var("CARGO_INCREMENTAL").as_deref(),
        Ok("0"),
        "P0 userdebug daemon build must explicitly disable Cargo incremental mode"
    );
    assert_eq!(
        env::var("SOURCE_DATE_EPOCH").as_deref(),
        Ok("1785110400"),
        "P0 userdebug daemon SOURCE_DATE_EPOCH differs"
    );
    assert_eq!(
        normalized_daemon_rustflags(),
        DAEMON_NORMALIZED_RUSTFLAGS,
        "P0 userdebug daemon Rust flags differ from the closed normalized allowlist"
    );

    let target_value = field(binding_value, "target_profile");
    let target = target_value
        .as_object()
        .expect("P0 userdebug daemon target profile is not an object");
    assert_eq!(
        target.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "architecture",
            "dynamic_interpreter",
            "libc_family",
            "maximum_glibc",
            "operating_system",
            "runtime_base_contract",
            "rust_target_triple",
        ],
        "P0 userdebug daemon target profile schema is not closed"
    );
    exact_string(
        target_value,
        "rust_target_triple",
        "aarch64-unknown-linux-gnu",
    );
    exact_string(target_value, "architecture", "aarch64");
    exact_string(target_value, "operating_system", "linux");
    exact_string(target_value, "libc_family", "glibc");
    exact_string(
        target_value,
        "dynamic_interpreter",
        "/lib/ld-linux-aarch64.so.1",
    );
    exact_string(target_value, "maximum_glibc", "GLIBC_2.36");
    exact_string(
        target_value,
        "runtime_base_contract",
        "debian-bookworm-arm64",
    );
    assert_eq!(
        env::var("TARGET").as_deref(),
        Ok("aarch64-unknown-linux-gnu"),
        "P0 userdebug daemon Cargo target differs from the closed target profile"
    );
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
        Ok("aarch64"),
        "P0 userdebug daemon Cargo target architecture differs"
    );
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("linux"),
        "P0 userdebug daemon Cargo target OS differs"
    );
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ENV").as_deref(),
        Ok("gnu"),
        "P0 userdebug daemon Cargo target libc environment differs"
    );

    let snapshot_value = field(binding_value, "toolchain_snapshot");
    let snapshot = snapshot_value
        .as_object()
        .expect("P0 userdebug daemon toolchain snapshot is not an object");
    assert_eq!(
        snapshot.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "closed_world",
            "entry_count",
            "manifest_bytes",
            "manifest_id",
            "manifest_schema",
            "manifest_sha256",
            "regular_bytes",
            "schema",
            "target_binutils_relative_path",
            "target_compiler_bin_relative_path",
            "target_compiler_relative_path",
            "target_gcc_libdir_relative_path",
            "target_host_runtime_libdir_relative_path",
            "target_sysroot_relative_path",
            "tree_digest",
        ],
        "P0 userdebug daemon toolchain snapshot schema is not closed"
    );
    exact_string(
        snapshot_value,
        "schema",
        "org.trillionnium.packaging.mobian-toolchain-snapshot-binding.v1",
    );
    exact_string(
        snapshot_value,
        "manifest_schema",
        "org.trillionnium.packaging.mobian-toolchain-snapshot-manifest.v1",
    );
    exact_string(
        snapshot_value,
        "manifest_sha256",
        FROZEN_TOOLCHAIN_MANIFEST_SHA256,
    );
    exact_string(snapshot_value, "manifest_id", FROZEN_TOOLCHAIN_MANIFEST_ID);
    exact_string(snapshot_value, "tree_digest", FROZEN_TOOLCHAIN_TREE_DIGEST);
    exact_bool(snapshot_value, "closed_world", true);
    assert_eq!(
        field(snapshot_value, "manifest_bytes").as_u64(),
        Some(8_375_893)
    );
    assert_eq!(field(snapshot_value, "entry_count").as_u64(), Some(33_930));
    assert_eq!(
        field(snapshot_value, "regular_bytes").as_u64(),
        Some(1_952_702_440)
    );
    for (name, expected) in [
        ("target_sysroot_relative_path", "toolchain/sysroot"),
        (
            "target_compiler_relative_path",
            "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12",
        ),
        (
            "target_compiler_bin_relative_path",
            "toolchain/sysroot/usr/bin",
        ),
        (
            "target_gcc_libdir_relative_path",
            "toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12",
        ),
        (
            "target_binutils_relative_path",
            "toolchain/sysroot/usr/aarch64-linux-gnu/bin",
        ),
        (
            "target_host_runtime_libdir_relative_path",
            "toolchain/sysroot/usr/lib/x86_64-linux-gnu",
        ),
    ] {
        exact_string(snapshot_value, name, expected);
    }

    assert_eq!(
        field(binding_value, "target_compiler_closure"),
        &serde_json::json!({
            "schema": "org.trillionnium.target-compiler-effective-closure.v1",
            "target": "aarch64-linux-gnu",
            "normalized_search_arguments": [
                "--sysroot=$TARGET_SYSROOT",
                "-B$TARGET_COMPILER_BIN",
                "-B$TARGET_GCC_LIBDIR",
                "-B$TARGET_BINUTILS_DIR",
            ],
            "reported_sysroot": "$TARGET_SYSROOT",
            "components": {
                "ld": {
                    "relative_path": "usr/bin/aarch64-linux-gnu-ld.bfd",
                    "bytes": 1_663_936,
                    "sha256": "e09a889c78a75e73ed096c9fa28905599e6813298b9ac839d10b02ffa96e7b08",
                    "mode": "0555",
                },
                "as": {
                    "relative_path": "usr/bin/aarch64-linux-gnu-as",
                    "bytes": 854_992,
                    "sha256": "49b906db048bd4be400bc885e3aed84e778cffa48a426fe5b9716bd80ea88e47",
                    "mode": "0555",
                },
                "cc1": {
                    "relative_path": "usr/lib/gcc-cross/aarch64-linux-gnu/12/cc1",
                    "bytes": 29_467_976,
                    "sha256": "bd201647ea988ff6060fc73595a3f7edbe4aff485e18efa4afd02c432dfffb17",
                    "mode": "0555",
                },
                "collect2": {
                    "relative_path": "usr/lib/gcc-cross/aarch64-linux-gnu/12/collect2",
                    "bytes": 639_192,
                    "sha256": "3ee4c136b021dce4b1157cb64b5eaeda9f49d4aa580dc74aed2e29f422a09a70",
                    "mode": "0555",
                },
                "Scrt1.o": {
                    "relative_path": "usr/lib/aarch64-linux-gnu/Scrt1.o",
                    "bytes": 1_704,
                    "sha256": "d03fc7a1a0b7cdbc1fb0a5c25425d3e1d2971a193c52f0ccdc40049234b7daae",
                    "mode": "0444",
                },
                "crtbeginS.o": {
                    "relative_path": "usr/lib/gcc-cross/aarch64-linux-gnu/12/crtbeginS.o",
                    "bytes": 3_472,
                    "sha256": "1e819bf5f6d4785a0ba792e34853f1d42d64e58a4d49bf788c27cc537885a194",
                    "mode": "0444",
                },
                "libc.so": {
                    "relative_path": "usr/lib/aarch64-linux-gnu/libc.so",
                    "bytes": 291,
                    "sha256": "cf5d6c74565de8a3e39b94ca1da75acedbb1f0d44dfc1633969477ae058badc3",
                    "mode": "0444",
                },
                "libgcc_s.so.1": {
                    "relative_path": "usr/aarch64-linux-gnu/lib/libgcc_s.so.1",
                    "bytes": 133_320,
                    "sha256": "c39939ec474dd03d9a8aa657d85fa71a8f879a3159bf1a5d19dff3b4788dfba2",
                    "mode": "0444",
                },
                "libgcc.a": {
                    "relative_path": "usr/lib/gcc-cross/aarch64-linux-gnu/12/libgcc.a",
                    "bytes": 334_174,
                    "sha256": "5cde35acdc58ad84b548efe9bade4ed8151154db35d7fc3bca1240db77e68dff",
                    "mode": "0444",
                },
            },
            "snapshot_tree_fully_remeasured_before_and_after_build": true,
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": false,
            "complete_host_execution_runtime_closure": false,
        }),
        "P0 userdebug daemon target compiler effective closure differs"
    );

    let runtime_value = field(binding_value, "runtime_artifact_sha256");
    let runtime = runtime_value
        .as_object()
        .expect("P0 userdebug daemon runtime-artifact binding is not an object");
    assert_eq!(
        runtime.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "codex_launcher",
            "high_water_authority",
            "replay_sync_helper",
            "system_api_tool",
        ],
        "P0 userdebug daemon runtime-artifact binding schema is not closed"
    );
    for (role, expected) in [
        ("system_api_tool", FROZEN_SYSTEM_API_SHA256),
        ("replay_sync_helper", FROZEN_REPLAY_SYNC_HELPER_SHA256),
        ("high_water_authority", FROZEN_HIGH_WATER_AUTHORITY_SHA256),
    ] {
        assert_eq!(
            runtime.get(role).and_then(Value::as_str),
            Some(expected),
            "P0 userdebug daemon build binding {role} digest differs"
        );
    }
    assert!(
        runtime
            .get("codex_launcher")
            .and_then(Value::as_str)
            .is_some_and(valid_sha256),
        "P0 userdebug daemon build binding launcher digest is malformed"
    );

    let stable_value = field(binding_value, "stable_principal");
    let stable = stable_value
        .as_object()
        .expect("P0 userdebug daemon stable-principal binding is not an object");
    assert_eq!(
        stable.keys().map(String::as_str).collect::<Vec<_>>(),
        ["authority", "canonical_sha256", "contract_sha256"],
        "P0 userdebug daemon stable-principal binding schema is not closed"
    );
    exact_string(stable_value, "authority", "stable_principal_registry_v2");
    exact_string(
        stable_value,
        "contract_sha256",
        FROZEN_STABLE_PRINCIPAL_CONTRACT_SHA256,
    );
    exact_string(
        stable_value,
        "canonical_sha256",
        FROZEN_STABLE_PRINCIPAL_CANONICAL_SHA256,
    );

    let identity_value = field(binding_value, "identity_independence_hold");
    let identity = identity_value
        .as_object()
        .expect("P0 userdebug daemon identity-HOLD binding is not an object");
    assert_eq!(
        identity.keys().map(String::as_str).collect::<Vec<_>>(),
        ["profile_sha256", "schema", "status"],
        "P0 userdebug daemon identity-HOLD binding schema is not closed"
    );
    exact_string(
        identity_value,
        "schema",
        "org.trillionnium.p01-userdebug-identity-independence-hold.v1",
    );
    exact_string(identity_value, "status", IDENTITY_INDEPENDENCE_HOLD_STATUS);
    assert_eq!(
        identity.get("profile_sha256").and_then(Value::as_str),
        Some(
            canonical_value_sha256(field(receipt, "legacy_descriptor_contamination_hold_gate",))
                .as_str()
        ),
        "P0 userdebug daemon identity-HOLD profile digest differs"
    );
    canonical_value_sha256(binding_value)
}

fn verify_artifact(
    receipt_dir_path: &Path,
    receipt_dir: &File,
    expected_uid: u32,
    artifacts: &serde_json::Map<String, Value>,
    expected: ExpectedArtifact,
) -> (String, Vec<u8>) {
    let record = artifacts
        .get(expected.role)
        .unwrap_or_else(|| panic!("P0 userdebug receipt omitted {}", expected.role));
    let object = record
        .as_object()
        .unwrap_or_else(|| panic!("P0 userdebug {} record is not an object", expected.role));
    assert_eq!(
        object.len(),
        3,
        "P0 userdebug {} record has an open schema",
        expected.role
    );
    assert_eq!(
        object.get("file").and_then(Value::as_str),
        Some(expected.file),
        "P0 userdebug {} filename differs",
        expected.role
    );
    let declared_sha256 = object
        .get("sha256")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("P0 userdebug {} digest is missing", expected.role));
    assert!(
        valid_sha256(declared_sha256),
        "P0 userdebug {} digest is malformed",
        expected.role
    );
    let declared_bytes = object
        .get("bytes")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("P0 userdebug {} byte length is missing", expected.role));
    let path = receipt_dir_path.join(expected.file);
    println!("cargo:rerun-if-changed={}", path.display());
    let bytes = read_exact_regular_at(
        receipt_dir,
        expected.file,
        expected_uid,
        expected.mode,
        expected.maximum,
        expected.role,
    );
    assert_eq!(
        u64::try_from(bytes.len()),
        Ok(declared_bytes),
        "P0 userdebug {} byte length differs",
        expected.role
    );
    let actual_sha256 = sha256(&bytes);
    assert_eq!(
        actual_sha256, declared_sha256,
        "P0 userdebug {} digest differs",
        expected.role
    );
    (actual_sha256, bytes)
}

fn validate_receipt(path: &Path) -> BTreeMap<&'static str, String> {
    let receipt_name = path
        .file_name()
        .expect("P0 userdebug receipt has no filename");
    assert_eq!(
        receipt_name.as_bytes(),
        P01_PRE_DAEMON_RECEIPT_FILE.as_bytes(),
        "P0 userdebug receipt filename differs"
    );
    let receipt_dir_path = path
        .parent()
        .expect("P0 userdebug receipt has no parent directory");
    let receipt_dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(receipt_dir_path)
        .unwrap_or_else(|error| panic!("cannot open P0 userdebug receipt directory: {error}"));
    let directory_before = receipt_dir
        .metadata()
        .expect("cannot stat P0 userdebug receipt directory");
    let expected_uid = unsafe { libc::geteuid() };
    assert!(
        directory_before.is_dir()
            && directory_before.uid() == expected_uid
            && directory_before.permissions().mode() & 0o022 == 0,
        "P0 userdebug receipt directory is not owner-controlled"
    );
    let receipt_bytes = read_exact_regular_at(
        &receipt_dir,
        P01_PRE_DAEMON_RECEIPT_FILE,
        expected_uid,
        0o444,
        128 * 1024,
        "artifact receipt",
    );
    let receipt: Value = serde_json::from_slice(&receipt_bytes)
        .expect("P0 userdebug artifact receipt is not valid JSON");
    let mut canonical = serde_json::to_vec_pretty(&receipt)
        .expect("P0 userdebug artifact receipt cannot be canonicalized");
    canonical.push(b'\n');
    assert_eq!(
        receipt_bytes, canonical,
        "P0 userdebug artifact receipt is not canonical or contains duplicate keys"
    );

    exact_string(&receipt, "schema", P01_PRE_DAEMON_RECEIPT_SCHEMA);
    exact_string(
        &receipt,
        "receipt_role",
        "final_daemon_build_binding_envelope",
    );
    exact_string(&receipt, "status", "host_built_device_evidence_hold");
    exact_string(&receipt, "product_variant", "userdebug");
    exact_string(
        &receipt,
        "principal_authority",
        "stable_principal_registry_v2",
    );
    exact_bool(
        &receipt,
        "legacy_descriptor_executable_identity_is_principal_authority",
        false,
    );
    exact_string(
        &receipt,
        "runtime_policy_launcher_measurement_migration",
        "active_launcher_separate_from_stable_principal",
    );
    exact_bool(&receipt, "product_effect_authority_available", false);
    exact_bool(&receipt, "accessibility_available", false);
    exact_bool(&receipt, "daemon_build_required", true);
    exact_bool(&receipt, "device_execution_verified", false);
    exact_bool(&receipt, "release_allowed", false);

    let root_keys = receipt
        .as_object()
        .expect("P0 userdebug receipt is not an object")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected_root_keys = [
        "accessibility_available",
        "artifacts",
        "compiler",
        "daemon_build_binding",
        "daemon_build_required",
        "dependency_graph",
        "device_execution_verified",
        "elf_inspector",
        "inputs",
        "legacy_descriptor_contamination_hold_gate",
        "product_variant",
        "legacy_descriptor_executable_identity_is_principal_authority",
        "principal_authority",
        "product_effect_authority_available",
        "receipt_role",
        "release_allowed",
        "runtime_policy_launcher_measurement_migration",
        "schema",
        "selected_system_api_sha256",
        "source_bom",
        "stable_principal_launcher_measurement",
        "status",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        root_keys, expected_root_keys,
        "P0 userdebug receipt root schema is not closed"
    );
    validate_source_bom_binding(&receipt);

    let stable_measurement = field(&receipt, "stable_principal_launcher_measurement")
        .as_object()
        .expect("P0 userdebug stable-principal launcher measurement is not an object");
    assert_eq!(
        stable_measurement
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "executable_identity_is_stable_registry_input",
            "launcher_executable_sha256",
            "launcher_identity_source",
            "stable_principal_canonical_sha256",
            "stable_principal_contract_sha256",
            "status",
        ],
        "P0 userdebug stable-principal measurement schema is not closed"
    );
    assert_eq!(
        stable_measurement
            .get("executable_identity_is_stable_registry_input")
            .and_then(Value::as_bool),
        Some(false),
        "P0 userdebug stable principal incorrectly contains executable identity"
    );
    assert_eq!(
        stable_measurement
            .get("launcher_identity_source")
            .and_then(Value::as_str),
        Some("measured_after_closed_launcher_inputs"),
        "P0 userdebug launcher identity source differs"
    );
    assert_eq!(
        stable_measurement.get("status").and_then(Value::as_str),
        Some("host_measurement_only_avb_slot_admission_absent"),
        "P0 userdebug stable-principal measurement overclaims admission"
    );
    assert_eq!(
        stable_measurement
            .get("stable_principal_contract_sha256")
            .and_then(Value::as_str),
        Some(FROZEN_STABLE_PRINCIPAL_CONTRACT_SHA256),
        "P0 userdebug stable-principal contract digest differs"
    );
    assert_eq!(
        stable_measurement
            .get("stable_principal_canonical_sha256")
            .and_then(Value::as_str),
        Some(FROZEN_STABLE_PRINCIPAL_CANONICAL_SHA256),
        "P0 userdebug stable-principal canonical digest differs"
    );
    validate_identity_independence_hold_gate(&receipt);
    let _retained_native_directories = validate_toolchain_manifest(&receipt, path, &receipt_dir);
    let daemon_build_binding_sha256 = validate_daemon_build_binding(&receipt);

    validate_launcher_build_tool(&receipt, "compiler", "compiler_driver");
    validate_launcher_build_tool(&receipt, "elf_inspector", "elf_inspector");

    let dependency_graph = field(&receipt, "dependency_graph")
        .as_object()
        .expect("P0 userdebug receipt dependency graph is not an object");
    assert_eq!(
        dependency_graph
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["acyclic", "edge_semantics", "edges", "forbidden_edges"],
        "P0 userdebug receipt dependency graph schema is not closed"
    );
    assert_eq!(
        dependency_graph.get("acyclic").and_then(Value::as_bool),
        Some(true),
        "P0 userdebug receipt dependency graph is not acyclic"
    );
    assert_eq!(
        dependency_graph
            .get("edge_semantics")
            .and_then(Value::as_str),
        Some("left artifact is a build input of the right artifact"),
        "P0 userdebug receipt dependency edge semantics differ"
    );
    let expected_edges = [
        "selected_system_api->codex_userdebug_launcher",
        "codex_runtime->codex_userdebug_launcher",
        "daemon_build_binding->p01_daemon_final_build",
        "selected_system_api->p01_daemon_final_build",
        "replay_sync_helper->p01_daemon_final_build",
        "high_water_authority->p01_daemon_final_build",
        "codex_userdebug_launcher->p01_daemon_final_build",
    ];
    let actual_edges = dependency_graph
        .get("edges")
        .and_then(Value::as_array)
        .expect("P0 userdebug receipt dependency edges are not an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("P0 userdebug receipt dependency edge is not a string")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_edges, expected_edges,
        "P0 userdebug receipt dependency edges differ"
    );
    let expected_forbidden_edges = [
        "p01_daemon_final_build->daemon_build_binding",
        "p01_daemon_final_build->selected_system_api",
        "p01_daemon_final_build->replay_sync_helper",
        "p01_daemon_final_build->codex_userdebug_launcher",
        "codex_userdebug_launcher->selected_system_api",
    ];
    let actual_forbidden_edges = dependency_graph
        .get("forbidden_edges")
        .and_then(Value::as_array)
        .expect("P0 userdebug receipt forbidden edges are not an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("P0 userdebug receipt forbidden edge is not a string")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_forbidden_edges, expected_forbidden_edges,
        "P0 userdebug receipt forbidden dependency edges differ"
    );

    let artifacts = field(&receipt, "artifacts")
        .as_object()
        .expect("P0 userdebug receipt artifacts are not an object");
    assert_eq!(
        artifacts.len(),
        EXPECTED_ARTIFACTS.len(),
        "P0 userdebug receipt artifact set is not closed"
    );
    let mut verified = BTreeMap::new();
    let mut artifact_bytes = BTreeMap::new();
    for expected in EXPECTED_ARTIFACTS {
        let (digest, bytes) = verify_artifact(
            receipt_dir_path,
            &receipt_dir,
            expected_uid,
            artifacts,
            expected,
        );
        verified.insert(expected.role, digest);
        artifact_bytes.insert(expected.role, bytes);
    }

    let inputs = field(&receipt, "inputs")
        .as_object()
        .expect("P0 userdebug receipt inputs are not an object");
    let expected_input_keys = [
        "codex_launcher_source_sha256",
        "codex_runtime_bytes",
        "codex_runtime_sha256",
        "high_water_authority_input_sha256",
        "replay_sync_helper_input_sha256",
        "system_api_tool_input_sha256",
    ];
    assert_eq!(
        inputs.keys().map(String::as_str).collect::<Vec<_>>(),
        expected_input_keys,
        "P0 userdebug receipt input schema is not closed"
    );
    assert!(
        inputs
            .get("codex_runtime_bytes")
            .and_then(Value::as_u64)
            .is_some_and(|bytes| bytes > 0 && bytes <= 512 * 1024 * 1024),
        "P0 userdebug receipt Codex runtime byte length is malformed"
    );
    for name in [
        "codex_launcher_source_sha256",
        "codex_runtime_sha256",
        "high_water_authority_input_sha256",
        "replay_sync_helper_input_sha256",
        "system_api_tool_input_sha256",
    ] {
        assert!(
            inputs
                .get(name)
                .and_then(Value::as_str)
                .is_some_and(valid_sha256),
            "P0 userdebug receipt input {name} is not a valid SHA-256"
        );
    }
    for (input, role) in [
        ("system_api_tool_input_sha256", "system_api_tool"),
        ("replay_sync_helper_input_sha256", "replay_sync_helper"),
        ("high_water_authority_input_sha256", "high_water_authority"),
    ] {
        assert_eq!(
            inputs.get(input).and_then(Value::as_str),
            verified.get(role).map(String::as_str),
            "P0 userdebug receipt input {input} differs from artifact {role}"
        );
    }
    for (role, expected) in [
        ("system_api_tool", FROZEN_SYSTEM_API_SHA256),
        ("replay_sync_helper", FROZEN_REPLAY_SYNC_HELPER_SHA256),
        ("high_water_authority", FROZEN_HIGH_WATER_AUTHORITY_SHA256),
    ] {
        assert_eq!(
            verified.get(role).map(String::as_str),
            Some(expected),
            "P0 userdebug artifact {role} differs from the independently frozen input"
        );
    }
    assert_eq!(
        inputs.get("codex_runtime_sha256").and_then(Value::as_str),
        Some(FROZEN_CODEX_RUNTIME_SHA256),
        "P0 userdebug Codex runtime differs from the frozen product runtime"
    );
    assert_eq!(
        field(&receipt, "selected_system_api_sha256").as_str(),
        verified.get("system_api_tool").map(String::as_str),
        "P0 userdebug selected System API digest differs from its measured artifact"
    );
    let runtime_binding = field(
        field(&receipt, "daemon_build_binding"),
        "runtime_artifact_sha256",
    )
    .as_object()
    .expect("P0 userdebug daemon runtime-artifact binding disappeared");
    for role in [
        "system_api_tool",
        "replay_sync_helper",
        "high_water_authority",
        "codex_launcher",
    ] {
        assert_eq!(
            runtime_binding.get(role).and_then(Value::as_str),
            verified.get(role).map(String::as_str),
            "P0 userdebug daemon build binding {role} differs from its physical artifact"
        );
    }

    let system_api_sha256 = verified
        .get("system_api_tool")
        .expect("verified System API disappeared");
    let codex_sha256 = verified
        .get("codex_launcher")
        .expect("verified Codex launcher disappeared");
    assert_eq!(
        stable_measurement
            .get("launcher_executable_sha256")
            .and_then(Value::as_str),
        Some(codex_sha256.as_str()),
        "P0 userdebug stable-principal measurement does not bind the launcher"
    );
    let codex = artifact_bytes
        .get("codex_launcher")
        .expect("verified Codex bytes disappeared");
    assert!(
        codex
            .windows(system_api_sha256.len())
            .any(|window| window == system_api_sha256.as_bytes())
            && codex
                .windows(FROZEN_CODEX_RUNTIME_SHA256.len())
                .any(|window| window == FROZEN_CODEX_RUNTIME_SHA256.as_bytes()),
        "P0 userdebug Codex launcher omits its measured runtime pins"
    );
    for role in [
        "system_api_tool",
        "replay_sync_helper",
        "high_water_authority",
    ] {
        let bytes = artifact_bytes
            .get(role)
            .unwrap_or_else(|| panic!("verified {role} bytes disappeared"));
        assert!(
            !bytes
                .windows(codex_sha256.len())
                .any(|window| window == codex_sha256.as_bytes()),
            "P0 userdebug upstream artifact {role} contains a reverse launcher pin"
        );
    }

    let replay = artifact_bytes
        .get("replay_sync_helper")
        .expect("verified replay-sync helper disappeared");
    for marker in [
        "trillionnium.p0-replay-sync-ack-confirmation.v1",
        "non_product_userdebug_daemon_custody",
        "P0-2 sealed replay authority changed before ACTIVATE",
    ] {
        assert!(
            replay
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "P0 userdebug replay-sync helper omits activated ABI marker {marker}"
        );
    }
    let retired_hold = "P0-2 external replay authority unavailable after fixed FD/context";
    assert!(
        !replay
            .windows(retired_hold.len())
            .any(|window| window == retired_hold.as_bytes()),
        "P0 userdebug receipt contains the retired deterministic-HOLD replay-sync helper"
    );

    verified.insert("receipt", sha256(&receipt_bytes));
    verified.insert("daemon_build_binding", daemon_build_binding_sha256);
    let directory_after = receipt_dir
        .metadata()
        .expect("cannot restat P0 userdebug receipt directory");
    assert_eq!(
        stable_identity(&directory_before),
        stable_identity(&directory_after),
        "P0 userdebug receipt directory changed during verification"
    );
    verified
}

fn write_p01_measurement_module(verified: &BTreeMap<&'static str, String>) {
    let system_api = verified
        .get("system_api_tool")
        .expect("verified P0 receipt omitted System API digest");
    let launcher = verified
        .get("codex_launcher")
        .expect("verified P0 receipt omitted Codex launcher digest");
    let daemon_build_binding = verified
        .get("daemon_build_binding")
        .expect("verified P0 receipt omitted daemon build binding digest");
    let record = format!(
        "schema={P01_MEASUREMENT_SCHEMA}\nvariant=userdebug\ndaemon_build_binding_sha256={daemon_build_binding}\nlauncher_sha256={launcher}\nsystem_api_sha256={system_api}\n"
    );
    let bytes = record
        .as_bytes()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let hold_record = format!(
        "schema={P01_IDENTITY_HOLD_SCHEMA}\ndaemon_build_binding_sha256={daemon_build_binding}\nstatus={IDENTITY_INDEPENDENCE_HOLD_STATUS}\nliteral_digest_absence_verified=true\nlegacy_descriptor_canonical_sha256={FROZEN_LEGACY_DESCRIPTOR_CANONICAL_SHA256}\nlegacy_descriptor_contract_sha256={FROZEN_LEGACY_DESCRIPTOR_CONTRACT_SHA256}\nlegacy_descriptor_launcher_identity_sha256={FROZEN_LEGACY_DESCRIPTOR_LAUNCHER_SHA256}\ncounterfactual_same_source_rebuild=required:true,verified:false,evidence_receipt:null\nstable_principal_admission_split=required:true,verified:false,evidence_receipt:null\n"
    );
    let hold_bytes = hold_record
        .as_bytes()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!(
        "// @generated by apps/trillionniumd/build.rs from the verified v8 binding envelope.\n\
         pub(crate) const P01_MEASUREMENT_SCHEMA: &str = \"{P01_MEASUREMENT_SCHEMA}\";\n\
         #[used]\n\
         #[unsafe(no_mangle)]\n\
         #[unsafe(link_section = \".trillionnium_p01_measurement_v4\")]\n\
         pub static TRILLIONNIUM_P01_DAEMON_MEASUREMENT_V4: [u8; {}] = [{bytes}];\n\
         #[used]\n\
         #[unsafe(no_mangle)]\n\
         #[unsafe(link_section = \".trillionnium_p01_identity_hold_v2\")]\n\
         pub static TRILLIONNIUM_P01_IDENTITY_INDEPENDENCE_HOLD_V2: [u8; {}] = [{hold_bytes}];\n",
        record.len(),
        hold_record.len(),
    );
    let output = PathBuf::from(
        env::var_os("OUT_DIR").expect("Cargo omitted OUT_DIR for P0 measurement generation"),
    )
    .join("p01_daemon_measurement_v4.rs");
    fs::write(&output, source).unwrap_or_else(|error| {
        panic!(
            "cannot write generated P0 daemon measurement {}: {error}",
            output.display()
        )
    });
}

fn main() {
    // Bind the final `codex.real` image independently of the launcher identity.
    println!("cargo:rustc-env={CODEX_RUNTIME_SHA256_ENV}={FROZEN_CODEX_RUNTIME_SHA256}");
    println!("cargo:rerun-if-env-changed={VARIANT_ENV}");
    println!("cargo:rerun-if-env-changed={RECEIPT_ENV}");
    for name in [
        TOOLCHAIN_MANIFEST_ENV,
        TARGET_SYSROOT_ENV,
        TARGET_COMPILER_BIN_ENV,
        TARGET_GCC_LIBDIR_ENV,
        TARGET_BINUTILS_DIR_ENV,
        TARGET_HOST_RUNTIME_LIBDIR_ENV,
        TARGET_CC_ENV,
        TARGET_AR_ENV,
        TARGET_CFLAGS_ENV,
        TARGET_CXXFLAGS_ENV,
        CARGO_TARGET_LINKER_ENV,
        CARGO_TARGET_AR_ENV,
        "CARGO_TARGET_DIR",
        "LD_LIBRARY_PATH",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_INCREMENTAL",
        "SOURCE_DATE_EPOCH",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    for name in FORBIDDEN_NATIVE_BUILD_ENVIRONMENTS {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var_os(FEATURE_ENV).is_none() {
        return;
    }
    assert_eq!(
        env::var(CARGO_CFG_FEATURE_ENV).as_deref(),
        Ok("p0-launch-package-device-conformance"),
        "P0 device-conformance daemon Cargo feature profile differs"
    );
    match env::var(VARIANT_ENV).as_deref() {
        Ok("userdebug") => println!("cargo:rustc-env={VARIANT_ENV}=userdebug"),
        _ => panic!("P0 device-conformance daemon requires exact userdebug build identity"),
    }
    let receipt_path = PathBuf::from(
        env::var(RECEIPT_ENV)
            .unwrap_or_else(|_| panic!("P0 userdebug daemon requires {RECEIPT_ENV}")),
    );
    assert!(
        receipt_path.is_absolute(),
        "P0 userdebug daemon receipt path must be absolute"
    );
    println!("cargo:rerun-if-changed={}", receipt_path.display());
    let verified = validate_receipt(&receipt_path);
    write_p01_measurement_module(&verified);
    for (environment, role) in [
        (SYSTEM_API_SHA256_ENV, "system_api_tool"),
        (CODEX_LAUNCHER_SHA256_ENV, "codex_launcher"),
        (DAEMON_BUILD_BINDING_SHA256_ENV, "daemon_build_binding"),
    ] {
        let digest = verified
            .get(role)
            .unwrap_or_else(|| panic!("P0 userdebug verified receipt omitted {role}"));
        println!("cargo:rustc-env={environment}={digest}");
    }
}
