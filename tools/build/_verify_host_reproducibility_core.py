#!/usr/bin/env python3
"""Compare two clean-source, Rust 1.93 release builds of selected Host/Core.

This tests byte reproducibility for the recorded local inputs. It is not a
hermetic build attestation, installation, signature, or release qualification.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "org.trillionnium.host-build-reproducibility.v1"
BINARIES = ("trillionnium-owner-open-r5-host", "trillionnium-owner-open-r5-core")
RUST_VERSION = "1.93.0"
MAX_LOG_BYTES = 32 * 1024 * 1024
IMPLEMENTATION_MANIFEST_SCHEMA = "org.trillionnium.host-build-reproducibility-implementation.v1"
IMPLEMENTATION_PATHS = (
    "tools/owner-open/authenticated_python_bootstrap.py",
    "tools/build/_verify_host_reproducibility_core.py",
    "tools/build/_verify_host_reproducibility_facade.py",
    "tools/build/verify_host_reproducibility.py",
    "tools/owner-open/owner_open_rootlinux_supervisor.py",
    "tools/perf/_run_product_baseline_core.py",
    "tools/perf/_run_product_baseline_facade.py",
    "tools/perf/run_product_baseline.py",
    "tools/owner-open/owner_open_connection_broker.py",
    "tools/owner-open/owner_open_connection_broker_v2.py",
    "tools/owner-open/owner_open_broker_admission_v2.py",
    "tools/owner-open/owner_open_broker_audit.py",
    "tools/owner-open/owner_open_broker_base_v2.py",
    "tools/owner-open/owner_open_broker_common.py",
    "tools/owner-open/owner_open_broker_connections.py",
    "tools/owner-open/owner_open_broker_convergence_v2.py",
    "tools/owner-open/owner_open_broker_mux.py",
    "tools/owner-open/owner_open_broker_runtime.py",
    "tools/owner-open/owner_open_broker_server_v2.py",
)


PINNED_IMPLEMENTATION_FILES: dict[str, dict[str, Any]] | None = None
PINNED_BOOTSTRAP_ATTESTATION: dict[str, Any] | None = None
EXECUTION_PASS_FDS: tuple[int, ...] = ()
OPEN_ADMITTED_FILE: Any = None
REOPEN_ADMITTED_IDENTITY: Any = None
SAME_ADMITTED_OBJECT: Any = None
MAX_PINNED_TOOL_BYTES = 512 * 1024 * 1024
MAX_PINNED_RUST_RUNTIME_BYTES = 768 * 1024 * 1024


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    require(resolved.is_file(), f"not a regular input: {path}")
    before = resolved.stat()
    digest_value = hashlib.sha256()
    with resolved.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest_value.update(block)
    after = resolved.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            f"input changed: {path}")
    return {"path": str(resolved), "size": before.st_size,
            "sha256": digest_value.hexdigest()}


def _admit_tool(
    path: Path,
    name: str,
    *,
    before_component: Any = None,
    after_final: Any = None,
    executable: bool = True,
    maximum: int = MAX_PINNED_TOOL_BYTES,
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    require(callable(OPEN_ADMITTED_FILE),
            "descriptor-rooted tool admission is not installed")
    return OPEN_ADMITTED_FILE(
        path,
        str(path.absolute()),
        maximum=maximum,
        executable=executable,
        before_component=before_component,
        after_final=after_final,
    )


def _reopen_tool(path: Path, name: str, *, executable: bool = True) -> dict[str, Any]:
    require(callable(REOPEN_ADMITTED_IDENTITY),
            "descriptor-rooted tool revalidation is not installed")
    return REOPEN_ADMITTED_IDENTITY(
        path,
        str(path.absolute()),
        maximum=MAX_PINNED_TOOL_BYTES,
        executable=executable,
    )


def _same_admitted(left: dict[str, Any], right: dict[str, Any]) -> bool:
    require(callable(SAME_ADMITTED_OBJECT),
            "descriptor-rooted identity comparison is not installed")
    return bool(SAME_ADMITTED_OBJECT(left, right))


def _hash_descriptor(descriptor: int, label: str) -> tuple[str, int, os.stat_result]:
    before = os.fstat(descriptor)
    require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    require(0 < before.st_size <= MAX_PINNED_TOOL_BYTES,
            f"{label} is empty or exceeds the pinned tool bound")
    digest_value = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        require(bool(block), f"short read while pinning {label}")
        digest_value.update(block)
        offset += len(block)
    after = os.fstat(descriptor)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            f"{label} changed while it was pinned")
    return digest_value.hexdigest(), before.st_size, before


def _write_descriptor(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        require(written > 0, "zero-progress write while creating sealed tool")
        offset += written


class PinnedTool:
    """Executable admitted by descriptor and copied into a write-sealed memfd."""

    _SEALS = (
        getattr(fcntl, "F_SEAL_WRITE", 0x0008)
        | getattr(fcntl, "F_SEAL_GROW", 0x0004)
        | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
        | getattr(fcntl, "F_SEAL_SEAL", 0x0001)
    )

    def __init__(
        self,
        source: Path,
        custody_root: Path,
        name: str,
        *,
        before_component: Any = None,
        after_final: Any = None,
        executable: bool = True,
        maximum: int = MAX_PINNED_TOOL_BYTES,
    ) -> None:
        self.requested_path = source.absolute()
        self.executable = executable
        payload, report, internal = _admit_tool(
            self.requested_path,
            name,
            before_component=before_component,
            after_final=after_final,
            executable=executable,
            maximum=maximum,
        )
        self._source_internal = internal
        require(hasattr(os, "memfd_create"), "sealed tool custody requires memfd_create")
        flags = getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(os, "MFD_ALLOW_SEALING", 0x0002)
        self.descriptor = os.memfd_create(f"trillionnium-{name}", flags)
        try:
            _write_descriptor(self.descriptor, payload)
            os.fchmod(self.descriptor, 0o500)
            fcntl.fcntl(self.descriptor, fcntl.F_ADD_SEALS, self._SEALS)
            require(fcntl.fcntl(self.descriptor, fcntl.F_GET_SEALS) == self._SEALS,
                    f"{name} memfd sealing is incomplete")
            os.set_inheritable(self.descriptor, True)
            self.execution_path = custody_root / name
            os.symlink(f"/proc/self/fd/{self.descriptor}", self.execution_path)
            link_state = os.lstat(self.execution_path)
            require(stat.S_ISLNK(link_state.st_mode), f"{name} execution link is invalid")
            current = _reopen_tool(self.requested_path, name, executable=executable)
            require(_same_admitted(self._source_internal, current),
                    f"{name} selected tool changed before custody completed")
            self.identity = {
                "path": internal["absolute_path"],
                "requested_path": str(self.requested_path),
                "size": report["size"],
                "sha256": report["sha256"],
                "execution_custody": "descriptor-rooted-linux-write-sealed-memfd-v2",
                "execution_path": str(self.execution_path),
            }
        except BaseException:
            os.close(self.descriptor)
            raise

    def assert_descriptor(self) -> None:
        digest_value, size, _ = _hash_descriptor(
            self.descriptor, self.execution_path.name
        )
        require(size == self.identity["size"] and
                digest_value == self.identity["sha256"],
                f"sealed tool bytes changed: {self.execution_path.name}")
        require(fcntl.fcntl(self.descriptor, fcntl.F_GET_SEALS) == self._SEALS,
                f"sealed tool lost write protection: {self.execution_path.name}")
        require(os.readlink(self.execution_path) == f"/proc/self/fd/{self.descriptor}",
                f"sealed tool execution link changed: {self.execution_path.name}")

    def assert_source_selection(self) -> None:
        current = _reopen_tool(self.requested_path, self.execution_path.name,
                               executable=self.executable)
        require(_same_admitted(self._source_internal, current),
                f"selected tool path or bytes moved: {self.requested_path}")

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


class PinnedRustRuntime:
    """Seal the two official SDK runtime ELFs without ambient loader paths.

    The standard-library sysroot and system loader dependencies remain recorded
    local inputs, not a recursively authenticated SDK.
    """

    def __init__(self, rustc: Path, custody_root: Path) -> None:
        require(rustc.name == "rustc" and rustc.parent.name == "bin",
                "Rust runtime requires the actual SDK bin/rustc path")
        self.sysroot = rustc.parent.parent
        self.source_directory = self.sysroot / "lib"
        self.execution_directory = custody_root / "rust-runtime"
        self.execution_directory.mkdir(mode=0o700)
        self.pins: dict[str, PinnedTool] = {}
        try:
            self.names = self._inventory()
            total = 0
            for name in self.names:
                # Descriptor-rooted admission rejects symlink components and
                # copies the exact opened bytes before any compiler executes.
                pin = PinnedTool(self.source_directory / name,
                                 self.execution_directory, name, executable=False,
                                 maximum=min(MAX_PINNED_TOOL_BYTES,
                                             MAX_PINNED_RUST_RUNTIME_BYTES - total))
                self.pins[name] = pin
                total += pin.identity["size"]
                require(total <= MAX_PINNED_RUST_RUNTIME_BYTES,
                        "Rust runtime exceeds the aggregate custody bound")
                require(os.pread(pin.descriptor, 4, 0) == b"\x7fELF",
                        f"Rust runtime member is not ELF: {name}")
            self.assert_source_selection()
        except BaseException:
            self.close()
            raise

    def _inventory(self) -> tuple[str, ...]:
        descriptor = os.open(self.source_directory, os.O_RDONLY | os.O_DIRECTORY
                             | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            names_list: list[str] = []
            with os.scandir(descriptor) as entries:
                for count, entry in enumerate(entries, start=1):
                    require(count <= 4096, "Rust SDK library directory exceeds entry bound")
                    if entry.name.startswith(("librustc_driver-", "libLLVM.so.")):
                        names_list.append(entry.name)
                        require(len(names_list) <= 2, "Rust runtime inventory is ambiguous")
            names = tuple(sorted(names_list))
        finally:
            os.close(descriptor)
        require(len(names) == 2 and
                sum(bool(re.fullmatch(r"librustc_driver-[0-9a-f]+\.so", name))
                    for name in names) == 1 and
                sum(bool(re.fullmatch(r"libLLVM\.so\.[A-Za-z0-9._-]+", name))
                    for name in names) == 1,
                "Rust SDK must contain exactly one driver and one LLVM runtime ELF")
        return names

    @property
    def descriptors(self) -> tuple[int, ...]:
        return tuple(pin.descriptor for pin in self.pins.values())

    def environment(self) -> dict[str, str]:
        return {"LD_LIBRARY_PATH": str(self.execution_directory)}

    def identity(self) -> dict[str, Any]:
        return {"sysroot": str(self.sysroot),
                "source_library_directory": str(self.source_directory),
                "execution_library_directory": str(self.execution_directory),
                "libraries": [dict(pin.identity) for pin in self.pins.values()],
                "ambient_loader_environment_inherited": False,
                "recursive_sysroot_attestation": False}

    def assert_descriptor(self) -> None:
        for pin in self.pins.values():
            pin.assert_descriptor()

    def assert_source_selection(self) -> None:
        require(self._inventory() == self.names, "Rust runtime inventory moved")
        for pin in self.pins.values():
            pin.assert_source_selection()

    def close(self) -> None:
        for pin in self.pins.values():
            pin.close()


def _live_repository_file_identity(relative: str) -> dict[str, Any]:
    require(relative in IMPLEMENTATION_PATHS,
            f"unregistered implementation path: {relative}")
    require(callable(OPEN_ADMITTED_FILE),
            "descriptor-rooted implementation admission is not installed")
    _, report, _ = OPEN_ADMITTED_FILE(
        ROOT / relative, relative, maximum=8 * 1024 * 1024, executable=False
    )
    return report


def repository_file_identity(relative: str) -> dict[str, Any]:
    if PINNED_IMPLEMENTATION_FILES is not None:
        require(set(PINNED_IMPLEMENTATION_FILES) == set(IMPLEMENTATION_PATHS),
                "pinned implementation inventory differs")
        value = PINNED_IMPLEMENTATION_FILES.get(relative)
        require(isinstance(value, dict) and
                set(value) == {"path", "size", "sha256"} and
                value["path"] == relative,
                f"invalid pinned implementation source: {relative}")
        return dict(value)
    return _live_repository_file_identity(relative)


def _manifest(files: list[dict[str, Any]]) -> dict[str, Any]:
    body = {"schema": IMPLEMENTATION_MANIFEST_SCHEMA, "files": files}
    return {**body, "manifest_sha256": sha256(canonical(body))}


def implementation_manifest() -> dict[str, Any]:
    return _manifest([repository_file_identity(relative)
                      for relative in IMPLEMENTATION_PATHS])


def live_implementation_manifest() -> dict[str, Any]:
    return _manifest([_live_repository_file_identity(relative)
                      for relative in IMPLEMENTATION_PATHS])


def validate_implementation_manifest(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict), "implementation manifest must be an object")
    require(set(value) == {"schema", "files", "manifest_sha256"},
            "implementation manifest keys differ")
    require(value["schema"] == IMPLEMENTATION_MANIFEST_SCHEMA,
            "implementation manifest schema differs")
    files = value["files"]
    require(isinstance(files, list) and len(files) == len(IMPLEMENTATION_PATHS),
            "implementation manifest file count differs")
    require([item.get("path") if isinstance(item, dict) else None for item in files] ==
            list(IMPLEMENTATION_PATHS), "implementation manifest paths differ")
    for item in files:
        require(isinstance(item, dict) and set(item) == {"path", "size", "sha256"},
                "implementation manifest entry keys differ")
        require(type(item["size"]) is int and item["size"] > 0,
                f"invalid implementation size: {item.get('path')}")
        digest_value = item["sha256"]
        require(isinstance(digest_value, str) and len(digest_value) == 64 and
                all(char in "0123456789abcdef" for char in digest_value),
                f"invalid implementation digest: {item.get('path')}")
    body = {"schema": value["schema"], "files": files}
    require(value["manifest_sha256"] == sha256(canonical(body)),
            "implementation manifest digest mismatch")
    return value


def bootstrap_attestation() -> dict[str, Any]:
    value = PINNED_BOOTSTRAP_ATTESTATION
    require(isinstance(value, dict), "missing authenticated bootstrap attestation")
    expected = {
        "schema", "policy_version", "transport", "outer_loader_policy",
        "bootstrap", "launcher", "direct_path_execution",
        "automatic_redispatch", "public_release",
    }
    require(set(value) == expected, "bootstrap attestation keys differ")
    require(value["schema"] == "org.trillionnium.authenticated-python-bootstrap.v1" and
            value["policy_version"] == "2026-09-09-v1",
            "bootstrap attestation version differs")
    require(value["transport"] == "captured-bootstrap-and-launcher-bytes-v1" and
            value["outer_loader_policy"] == "python-isolated-inline-descriptor-loader-v1",
            "bootstrap transport policy differs")
    require(value["direct_path_execution"] is False and
            value["automatic_redispatch"] is False and
            value["public_release"] is False,
            "bootstrap attestation widened authority")
    files = {item["path"]: item for item in implementation_manifest()["files"]}
    require(value["bootstrap"] == files["tools/owner-open/authenticated_python_bootstrap.py"],
            "bootstrap attestation does not bind implementation manifest")
    require(value["launcher"] == files["tools/build/verify_host_reproducibility.py"],
            "bootstrap attestation does not bind build launcher")
    return dict(value)


def query(command: list[str], cwd: Path, *, pass_fds: tuple[int, ...] = (),
          runtime: PinnedRustRuntime | None = None,
          executable: Path | None = None) -> str:
    # The authenticated facade installs its retained-session streaming query
    # before exposing this API. There is no unbounded private-core fallback.
    raise VerificationError("identity queries require the authenticated bounded facade")


def gcc_helper_configuration(pin: PinnedTool, repo: Path,
                             runtime: PinnedRustRuntime) -> dict[str, Any]:
    # Keep GCC's observed argv[0] while executing only the sealed descriptor.
    # GCC_EXEC_PREFIX affects helper, CRT and header searches: it is a finite
    # recorded recipe input, not recursive custody of the helper hierarchy.
    def gcc(*arguments: str) -> str:
        return query([str(pin.requested_path), *arguments], repo,
                     executable=pin.execution_path,
                     pass_fds=(pin.descriptor, *runtime.descriptors), runtime=runtime)

    target = gcc("-dumpmachine")
    version = gcc("-dumpversion")
    require(re.fullmatch(r"[A-Za-z0-9_.+-]{1,256}", target) is not None and
            re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", version) is not None,
            "this sealed C linker recipe requires an installed GNU GCC hierarchy")
    search = gcc("-print-search-dirs")
    installs = [line.removeprefix("install: ") for line in search.splitlines()
                if line.startswith("install: ")]
    require(len(installs) == 1 and "\x00" not in installs[0] and
            ":" not in installs[0], "GCC helper install path is ambiguous")
    raw = installs[0].removesuffix("/")
    install = Path(raw)
    require(install.is_absolute() and str(install) == raw and
            ".." not in install.parts and install.is_dir() and
            install.name == version and install.parent.name == target,
            "GCC helper install path must be a canonical target/version directory")
    prefix = install.parent.parent
    helpers = {"cc1": gcc("-print-prog-name=cc1"),
               "collect2": gcc("-print-prog-name=collect2"),
               "lto_plugin": gcc("-print-file-name=liblto_plugin.so")}
    for path in helpers.values():
        candidate = Path(path)
        require(candidate.is_absolute() and str(candidate) == path and
                ".." not in candidate.parts and "\x00" not in path and
                candidate.is_file(), "GCC helper discovery returned an invalid path")
    return {"gcc_exec_prefix": str(prefix) + "/", "install_directory": str(install),
            "target": target, "version": version, "helper_paths": helpers,
            "discovery_execution": "sealed-cc-with-selected-source-argv0",
            "helpers_recursively_attested": False,
            "ambient_gcc_environment_inherited": False}


def source_identity(repo: Path, expected_commit: str | None = None) -> dict[str, Any]:
    def git(*args: str) -> str:
        return query(["git", "--no-replace-objects", "-C", str(repo), *args], repo)
    require(git("rev-parse", "--show-toplevel") == str(repo), "repo root must be the Git top level")
    commit = git("rev-parse", "HEAD")
    require(expected_commit is None or commit == expected_commit, "source commit differs from expected commit")
    # Ignored build/cache/config files can influence Cargo too. This recipe
    # requires a pristine checkout, with all generated inputs outside it.
    status = git("status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=none")
    require(not status, "source must be clean, including absent untracked/ignored inputs")
    epoch = git("show", "-s", "--format=%ct", "HEAD")
    require(epoch.isdigit(), "commit timestamp is not a SOURCE_DATE_EPOCH")
    return {"commit": commit, "tree": git("rev-parse", "HEAD^{tree}"),
            "source_date_epoch": epoch, "cargo_lock": file_identity(repo / "Cargo.lock"),
            "manifest": file_identity(repo / "Cargo.toml"), "working_tree_clean": True}


def reject_ambient_config(repo: Path, cargo_home: Path) -> None:
    # Cargo searches every ancestor, even with an explicit --manifest-path.
    for root in (repo, *repo.parents):
        for leaf in ("config", "config.toml"):
            require(not (root / ".cargo" / leaf).exists() and not (root / ".cargo" / leaf).is_symlink(),
                    f"ambient Cargo configuration is outside this recipe: {root / '.cargo' / leaf}")
    for leaf in ("config", "config.toml"):
        require(not (cargo_home / leaf).exists() and not (cargo_home / leaf).is_symlink(),
                "input Cargo home must not provide ambient configuration")


def toolchain_identity(
    cargo: Path,
    rustc: Path,
    cc: Path,
    ar: Path,
    repo: Path,
    *,
    pinned: dict[str, PinnedTool] | None = None,
    runtime: PinnedRustRuntime | None = None,
) -> dict[str, Any]:
    selected = {"cargo": cargo, "rustc": rustc, "cc": cc, "ar": ar}
    if pinned is None:
        identities = {
            name: file_identity(path) for name, path in selected.items()
        }
        execution = {name: str(path) for name, path in selected.items()}
        pass_fds: tuple[int, ...] = ()
    else:
        require(set(pinned) == set(selected), "pinned tool inventory differs")
        identities = {name: dict(pin.identity) for name, pin in pinned.items()}
        execution = {
            name: str(pin.execution_path) for name, pin in pinned.items()
        }
        pass_fds = tuple(pin.descriptor for pin in pinned.values())
        for pin in pinned.values():
            pin.assert_descriptor()
    if runtime is not None:
        require(pinned is not None, "Rust runtime custody requires pinned tools")
        runtime.assert_descriptor()
        runtime.assert_source_selection()
        pass_fds += runtime.descriptors
        identities["rust_runtime"] = runtime.identity()
    cargo_version = query(
        [execution["cargo"], "--version"], repo, pass_fds=pass_fds, runtime=runtime
    )
    rust_version = query(
        [execution["rustc"], "--version", "--verbose"],
        repo,
        pass_fds=pass_fds,
        runtime=runtime,
    )
    require(cargo_version.startswith(f"cargo {RUST_VERSION} "),
            "Cargo must be exactly 1.93.0")
    require(rust_version.splitlines()[0].startswith(f"rustc {RUST_VERSION} "),
            "Rustc must be exactly 1.93.0")
    require(f"release: {RUST_VERSION}" in rust_version.splitlines(),
            "Rust release metadata differs")
    for name in ("cc", "ar"):
        identities[name]["version"] = query(
            [execution[name], "--version"], repo, pass_fds=pass_fds, runtime=runtime
        )
    if pinned is not None and runtime is not None:
        identities["cc"]["gcc_helpers"] = gcc_helper_configuration(pinned["cc"], repo, runtime)
    identities["cargo"]["version"] = cargo_version
    identities["rustc"]["version"] = rust_version
    sysroot_args = ["--sysroot", str(runtime.sysroot)] if runtime is not None else []
    identities["rust_sysroot"] = query(
        [execution["rustc"], *sysroot_args, "--print", "sysroot"],
        repo,
        pass_fds=pass_fds,
        runtime=runtime,
    )
    if runtime is not None:
        require(identities["rust_sysroot"] == str(runtime.sysroot),
                "sealed compiler sysroot differs from the selected SDK")
    identities["host_platform"] = {
        "sysname": os.uname().sysname,
        "release": os.uname().release,
        "machine": os.uname().machine,
    }
    return identities


def prepare_home(path: Path, cache: Path) -> None:
    path.mkdir(mode=0o700)
    for leaf in ("registry", "git"):
        source = cache / leaf
        if source.exists():
            require(source.is_dir(), "dependency cache entry must be a directory")
            (path / leaf).symlink_to(source.resolve(strict=True), target_is_directory=True)


def recipe(repo: Path, target: Path, home: Path, cache: Path, tools: dict, source: dict) -> tuple[list[str], dict[str, str]]:
    cargo = tools["cargo"].get("execution_path", tools["cargo"]["path"])
    rustc = tools["rustc"].get("execution_path", tools["rustc"]["path"])
    cc = tools["cc"].get("execution_path", tools["cc"]["path"])
    ar = tools["ar"].get("execution_path", tools["ar"]["path"])
    flags = [f"--remap-path-prefix={repo}=/source/trillionnium-os",
             f"--remap-path-prefix={target}=/build/target",
             f"--remap-path-prefix={home}=/build/cargo-home",
             f"--remap-path-prefix={cache}=/build/dependency-cache",
             "-C", f"linker={cc}", "-C", "link-arg=-Wl,--build-id=none"]
    env = {"PATH": f"{Path(rustc).parent}:/usr/bin:/bin", "HOME": str(home),
           "CARGO_HOME": str(home), "RUSTC": rustc, "CC": cc, "AR": ar,
           "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "CARGO_TERM_COLOR": "never",
           "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "1", "CARGO_NET_OFFLINE": "true",
           "SOURCE_DATE_EPOCH": source["source_date_epoch"], "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags)}
    if "rust_runtime" in tools:
        runtime = tools["rust_runtime"]
        flags.extend(["--sysroot", runtime["sysroot"]])
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
        env["LD_LIBRARY_PATH"] = runtime["execution_library_directory"]
    if "gcc_helpers" in tools["cc"]:
        env["GCC_EXEC_PREFIX"] = tools["cc"]["gcc_helpers"]["gcc_exec_prefix"]
    command = [cargo, "build", "--locked", "--offline", "--frozen", "--release",
               "--manifest-path", str(repo / "Cargo.toml"), "--target-dir", str(target),
               "-p", "trillionnium-owner-open-host"]
    for binary in BINARIES:
        command.extend(["--bin", binary])
    return command, env


def run_build(command: list[str], env: dict[str, str], repo: Path, log: Path, timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    count = 0
    digest = hashlib.sha256()
    try:
        assert process.stdout
        with log.open("xb") as output, selectors.DefaultSelector() as selector:
            os.chmod(log, 0o600)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic() - started < timeout, "Cargo build exceeded timeout")
                for key, _ in selector.select(0.1):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(block)
                    require(count <= MAX_LOG_BYTES, "Cargo build log exceeded byte bound")
                    output.write(block)
                    digest.update(block)
            output.flush()
            os.fsync(output.fileno())
        remaining = timeout - (time.monotonic() - started)
        require(remaining > 0, "Cargo did not finish before deadline")
        code = process.wait(timeout=remaining)
        return {"exit_code": code, "elapsed_seconds": time.monotonic() - started,
                "log": {"path": str(log), "bytes": count, "sha256": digest.hexdigest()}}
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()


def compare_artifacts(builds: list[dict]) -> dict[str, Any]:
    require(len(builds) == 2, "two completed builds are required")
    require(all(build.get("exit_code") == 0 for build in builds), "a Cargo build failed")
    require(builds[0]["source_before"] == builds[0]["source_after"] ==
            builds[1]["source_before"] == builds[1]["source_after"], "source identity drifted")
    require(builds[0]["tools_before"] == builds[0]["tools_after"] ==
            builds[1]["tools_before"] == builds[1]["tools_after"], "toolchain identity drifted")
    comparisons = []
    for name in BINARIES:
        a, b = builds[0]["artifacts"].get(name), builds[1]["artifacts"].get(name)
        require(isinstance(a, dict) and isinstance(b, dict), f"missing binary: {name}")
        require(type(a.get("size")) is int and type(b.get("size")) is int and a["size"] > 0 and b["size"] > 0,
                f"invalid binary size: {name}")
        require(all(isinstance(value.get("sha256"), str) and len(value["sha256"]) == 64 and
                    all(char in "0123456789abcdef" for char in value["sha256"]) for value in (a, b)),
                f"invalid binary digest: {name}")
        equal = a["size"] == b["size"] and a.get("sha256") == b.get("sha256")
        comparisons.append({"binary": name, "a": a, "b": b, "byte_digest_equal": equal})
    return {"status": "PASS_TWO_LOCAL_BUILDS_IDENTICAL" if all(row["byte_digest_equal"] for row in comparisons)
                      else "FAIL_ARTIFACT_DIFFERENCE",
            "passed": all(row["byte_digest_equal"] for row in comparisons), "comparisons": comparisons}


def verify(args: argparse.Namespace) -> dict[str, Any]:
    global EXECUTION_PASS_FDS
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "qualification": "L1_LOCAL_BUILD_REPRODUCIBILITY_ONLY",
        "public_release": False,
        "installation_performed": False,
        "signing_performed": False,
        "builds": [],
        "gate": {"status": "FAIL_PREFLIGHT", "passed": False},
        "errors": [],
        "limitations": [
            "No installed-target, image, device, signing or release qualification",
            "Same host/kernel and shared offline dependency cache, not independent-builder attestation",
            "Tool executables and the selected Rust driver/LLVM runtime ELFs run from write-sealed memfd snapshots; full sysroot, system linker/runtime libraries and cache trees are not recursively attested",
            "Path remapping and identical outputs do not establish a hermetic or trusted build",
        ],
    }
    pins: dict[str, PinnedTool] = {}
    runtime: PinnedRustRuntime | None = None
    prior_pass_fds = EXECUTION_PASS_FDS
    try:
        require(sys.platform == "linux", "this host recipe requires Linux")
        repo = args.repo_root.resolve(strict=True)
        cache = args.cargo_home.resolve(strict=True)
        build_root = args.build_root.resolve()
        require(cache.is_dir(), "input Cargo home is not a directory")
        require(not build_root.exists() and not build_root.is_symlink(),
                "build root must be new")
        parent = build_root.parent.resolve(strict=True)
        require(not parent.is_relative_to(repo) and not parent.is_relative_to(cache),
                "build root must be outside source and cache")
        require(not args.output.resolve().is_relative_to(repo),
                "report must be outside source checkout")
        reject_ambient_config(repo, cache)
        source = source_identity(repo, args.expected_commit)
        selected = {
            "cargo": args.cargo,
            "rustc": args.rustc,
            "cc": args.cc,
            "ar": args.ar,
        }
        resolved = [selected[name].resolve(strict=True)
                    for name in ("cargo", "rustc", "cc", "ar")]
        selected = dict(zip(("cargo", "rustc", "cc", "ar"), resolved, strict=True))
        with tempfile.TemporaryDirectory(
            prefix="tos-build-custody-", dir=parent
        ) as custody_directory:
            custody_root = Path(custody_directory)
            os.chmod(custody_root, 0o700)
            # Accumulate eagerly so a later admission failure cannot leak the
            # descriptors already created by earlier successful admissions.
            for name in ("cargo", "rustc", "cc", "ar"):
                pins[name] = PinnedTool(selected[name], custody_root, name)
            runtime = PinnedRustRuntime(selected["rustc"], custody_root)
            EXECUTION_PASS_FDS = tuple(
                pin.descriptor for pin in pins.values()
            ) + runtime.descriptors
            tools = toolchain_identity(*resolved, repo, pinned=pins, runtime=runtime)
            implementation = implementation_manifest()
            validate_implementation_manifest(implementation)
            bootstrap = bootstrap_attestation()
            harness = next(
                item for item in implementation["files"]
                if item["path"] == "tools/build/verify_host_reproducibility.py"
            )
            report.update({
                "source": source,
                "tools": tools,
                "dependency_cache": str(cache),
                "build_root": str(build_root),
                "harness": dict(harness),
                "implementation_manifest": implementation,
                "bootstrap_attestation": bootstrap,
                "execution_custody": "linux-write-sealed-tools-and-rust-runtime-memfds-v2",
            })
            build_root.mkdir(mode=0o700)
            for label in ("a", "b"):
                for pin in pins.values():
                    pin.assert_descriptor()
                runtime.assert_descriptor()
                target = build_root / f"target-{label}"
                home = build_root / f"cargo-home-{label}"
                prepare_home(home, cache)
                target.mkdir(mode=0o700)
                command, env = recipe(repo, target, home, cache, tools, source)
                before_source = source_identity(repo, source["commit"])
                before_tools = toolchain_identity(
                    *resolved, repo, pinned=pins, runtime=runtime
                )
                require(before_source == source and before_tools == tools,
                        "input identity changed before build")
                build = {
                    "label": label,
                    "command": command,
                    "environment": env,
                    "source_before": before_source,
                    "tools_before": before_tools,
                    "artifacts": {},
                }
                report["builds"].append(build)
                build.update(run_build(
                    command,
                    env,
                    repo,
                    build_root / f"cargo-{label}.log",
                    args.timeout_seconds,
                ))
                build["source_after"] = source_identity(repo, source["commit"])
                build["tools_after"] = toolchain_identity(
                    *resolved, repo, pinned=pins, runtime=runtime
                )
                require(build["exit_code"] == 0,
                        f"build {label} failed; inspect retained Cargo log")
                require(build["source_after"] == source and
                        build["tools_after"] == tools,
                        "source or pinned tools changed during build")
                for pin in pins.values():
                    pin.assert_descriptor()
                    pin.assert_source_selection()
                runtime.assert_descriptor()
                runtime.assert_source_selection()
                for binary in BINARIES:
                    path = target / "release" / binary
                    require(not path.is_symlink() and path.is_file() and
                            os.access(path, os.X_OK),
                            f"missing executable artifact: {binary}")
                    with path.open("rb") as stream:
                        require(stream.read(4) == b"\x7fELF",
                                f"artifact is not ELF: {binary}")
                    build["artifacts"][binary] = file_identity(path)
            require(live_implementation_manifest() == implementation,
                    "reproducibility implementation source paths changed during builds")
            report["gate"] = compare_artifacts(report["builds"])
    except (VerificationError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        report["errors"].append(str(error))
        report["gate"] = {"status": "FAIL_VERIFICATION", "passed": False}
    finally:
        EXECUTION_PASS_FDS = prior_pass_fds
        for pin in pins.values():
            pin.close()
        if runtime is not None:
            runtime.close()
    report["report_digest"] = sha256(canonical(report))
    return report

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--expected-commit")
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cc", type=Path, default=Path(shutil.which("cc") or "/missing/cc"))
    parser.add_argument("--ar", type=Path, default=Path(shutil.which("ar") or "/missing/ar"))
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout_seconds <= 7200:
        parser.error("timeout must be between 1 and 7200 seconds per build")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        require(not args.output.exists() and not args.output.is_symlink(), "report output must be new")
        require(args.output.parent.is_dir(), "report parent must exist")
        report = verify(args)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(report) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({"report": str(args.output), "gate": report["gate"]["status"], "errors": report["errors"]}))
        return 0 if report["gate"]["passed"] else 2
    except (VerificationError, OSError) as error:
        print(f"reproducibility verification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
