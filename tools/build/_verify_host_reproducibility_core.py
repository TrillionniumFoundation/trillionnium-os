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
    "tools/build/_verify_host_reproducibility_core.py",
    "tools/build/_verify_host_reproducibility_facade.py",
    "tools/build/verify_host_reproducibility.py",
    "tools/owner-open/owner_open_rootlinux_supervisor.py",
    "tools/perf/_run_product_baseline_core.py",
    "tools/perf/_run_product_baseline_facade.py",
    "tools/perf/run_product_baseline.py",
)


PINNED_IMPLEMENTATION_FILES: dict[str, dict[str, Any]] | None = None
EXECUTION_PASS_FDS: tuple[int, ...] = ()
OPEN_ADMITTED_FILE: Any = None
REOPEN_ADMITTED_IDENTITY: Any = None
SAME_ADMITTED_OBJECT: Any = None
MAX_PINNED_TOOL_BYTES = 512 * 1024 * 1024


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
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    require(callable(OPEN_ADMITTED_FILE),
            "descriptor-rooted tool admission is not installed")
    return OPEN_ADMITTED_FILE(
        path,
        str(path.absolute()),
        maximum=MAX_PINNED_TOOL_BYTES,
        executable=True,
        before_component=before_component,
        after_final=after_final,
    )


def _reopen_tool(path: Path, name: str) -> dict[str, Any]:
    require(callable(REOPEN_ADMITTED_IDENTITY),
            "descriptor-rooted tool revalidation is not installed")
    return REOPEN_ADMITTED_IDENTITY(
        path,
        str(path.absolute()),
        maximum=MAX_PINNED_TOOL_BYTES,
        executable=True,
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
    ) -> None:
        self.requested_path = source.absolute()
        payload, report, internal = _admit_tool(
            self.requested_path,
            name,
            before_component=before_component,
            after_final=after_final,
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
            current = _reopen_tool(self.requested_path, name)
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
        current = _reopen_tool(self.requested_path, self.execution_path.name)
        require(_same_admitted(self._source_internal, current),
                f"selected tool path or bytes moved: {self.requested_path}")

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


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


def query(command: list[str], cwd: Path, *, pass_fds: tuple[int, ...] = ()) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
        pass_fds=pass_fds,
    )
    require(len(result.stdout.encode()) <= 1024 * 1024,
            "identity query exceeded bound")
    return result.stdout.strip()


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
    cargo_version = query(
        [execution["cargo"], "--version"], repo, pass_fds=pass_fds
    )
    rust_version = query(
        [execution["rustc"], "--version", "--verbose"],
        repo,
        pass_fds=pass_fds,
    )
    require(cargo_version.startswith(f"cargo {RUST_VERSION} "),
            "Cargo must be exactly 1.93.0")
    require(rust_version.splitlines()[0].startswith(f"rustc {RUST_VERSION} "),
            "Rustc must be exactly 1.93.0")
    require(f"release: {RUST_VERSION}" in rust_version.splitlines(),
            "Rust release metadata differs")
    for name in ("cc", "ar"):
        identities[name]["version"] = query(
            [execution[name], "--version"], repo, pass_fds=pass_fds
        )
    identities["cargo"]["version"] = cargo_version
    identities["rustc"]["version"] = rust_version
    identities["rust_sysroot"] = query(
        [execution["rustc"], "--print", "sysroot"],
        repo,
        pass_fds=pass_fds,
    )
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
            "Tool executables run from write-sealed memfd snapshots; full sysroot, linker/runtime libraries and cache trees are not recursively attested",
            "Path remapping and identical outputs do not establish a hermetic or trusted build",
        ],
    }
    pins: dict[str, PinnedTool] = {}
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
            pins = {
                name: PinnedTool(selected[name], custody_root, name)
                for name in ("cargo", "rustc", "cc", "ar")
            }
            EXECUTION_PASS_FDS = tuple(
                pin.descriptor for pin in pins.values()
            )
            tools = toolchain_identity(*resolved, repo, pinned=pins)
            implementation = implementation_manifest()
            validate_implementation_manifest(implementation)
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
                "execution_custody": "linux-write-sealed-memfds-v1",
            })
            build_root.mkdir(mode=0o700)
            for label in ("a", "b"):
                for pin in pins.values():
                    pin.assert_descriptor()
                target = build_root / f"target-{label}"
                home = build_root / f"cargo-home-{label}"
                prepare_home(home, cache)
                target.mkdir(mode=0o700)
                command, env = recipe(repo, target, home, cache, tools, source)
                before_source = source_identity(repo, source["commit"])
                before_tools = toolchain_identity(
                    *resolved, repo, pinned=pins
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
                    *resolved, repo, pinned=pins
                )
                require(build["exit_code"] == 0,
                        f"build {label} failed; inspect retained Cargo log")
                require(build["source_after"] == source and
                        build["tools_after"] == tools,
                        "source or pinned tools changed during build")
                for pin in pins.values():
                    pin.assert_descriptor()
                    pin.assert_source_selection()
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
    except (VerificationError, OSError, subprocess.SubprocessError) as error:
        report["errors"].append(str(error))
        report["gate"] = {"status": "FAIL_VERIFICATION", "passed": False}
    finally:
        EXECUTION_PASS_FDS = prior_pass_fds
        for pin in pins.values():
            pin.close()
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
