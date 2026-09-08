#!/usr/bin/env python3
"""Compare two clean-source, Rust 1.93 release builds of selected Host/Core.

This tests byte reproducibility for the recorded local inputs. It is not a
hermetic build attestation, installation, signature, or release qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
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
    "tools/build/verify_host_reproducibility.py",
    "tools/owner-open/owner_open_rootlinux_supervisor.py",
    "tools/perf/_run_product_baseline_core.py",
    "tools/perf/run_product_baseline.py",
)


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
    path = path.resolve(strict=True)
    require(path.is_file(), f"not a regular input: {path}")
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), f"input changed: {path}")
    return {"path": str(path), "size": before.st_size, "sha256": digest.hexdigest()}


def repository_file_identity(relative: str) -> dict[str, Any]:
    require(relative in IMPLEMENTATION_PATHS, f"unregistered implementation path: {relative}")
    candidate = ROOT / relative
    require(not candidate.is_symlink(), f"implementation path is a symlink: {relative}")
    resolved_root = ROOT.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    require(resolved.is_relative_to(resolved_root), f"implementation path escaped repository: {relative}")
    identity = file_identity(candidate)
    return {"path": relative, "size": identity["size"], "sha256": identity["sha256"]}


def implementation_manifest() -> dict[str, Any]:
    files = [repository_file_identity(relative) for relative in IMPLEMENTATION_PATHS]
    body = {"schema": IMPLEMENTATION_MANIFEST_SCHEMA, "files": files}
    return {**body, "manifest_sha256": sha256(canonical(body))}


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


def query(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                            capture_output=True, text=True, timeout=20, check=True)
    require(len(result.stdout.encode()) <= 1024 * 1024, "identity query exceeded bound")
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


def toolchain_identity(cargo: Path, rustc: Path, cc: Path, ar: Path, repo: Path) -> dict[str, Any]:
    identities = {name: file_identity(path) for name, path in (("cargo", cargo), ("rustc", rustc), ("cc", cc), ("ar", ar))}
    cargo_version = query([str(cargo), "--version"], repo)
    rust_version = query([str(rustc), "--version", "--verbose"], repo)
    require(cargo_version.startswith(f"cargo {RUST_VERSION} "), "Cargo must be exactly 1.93.0")
    require(rust_version.splitlines()[0].startswith(f"rustc {RUST_VERSION} "), "Rustc must be exactly 1.93.0")
    require(f"release: {RUST_VERSION}" in rust_version.splitlines(), "Rust release metadata differs")
    for name, path in (("cc", cc), ("ar", ar)):
        identities[name]["version"] = query([str(path), "--version"], repo)
    identities["cargo"]["version"] = cargo_version
    identities["rustc"]["version"] = rust_version
    identities["rust_sysroot"] = query([str(rustc), "--print", "sysroot"], repo)
    identities["host_platform"] = {"sysname": os.uname().sysname, "release": os.uname().release,
                                   "machine": os.uname().machine}
    return identities


def prepare_home(path: Path, cache: Path) -> None:
    path.mkdir(mode=0o700)
    for leaf in ("registry", "git"):
        source = cache / leaf
        if source.exists():
            require(source.is_dir(), "dependency cache entry must be a directory")
            (path / leaf).symlink_to(source.resolve(strict=True), target_is_directory=True)


def recipe(repo: Path, target: Path, home: Path, cache: Path, tools: dict, source: dict) -> tuple[list[str], dict[str, str]]:
    cargo, rustc = tools["cargo"]["path"], tools["rustc"]["path"]
    cc, ar = tools["cc"]["path"], tools["ar"]["path"]
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
    report: dict[str, Any] = {"schema": SCHEMA, "qualification": "L1_LOCAL_BUILD_REPRODUCIBILITY_ONLY",
        "public_release": False, "installation_performed": False, "signing_performed": False,
        "builds": [], "gate": {"status": "FAIL_PREFLIGHT", "passed": False}, "errors": [],
        "limitations": ["No installed-target, image, device, signing or release qualification",
                        "Same host/kernel and shared offline dependency cache, not independent-builder attestation",
                        "Direct tool bytes/version and Cargo.lock bound; full sysroot/linker/runtime/cache trees are not recursively attested",
                        "Path remapping and identical outputs do not establish a hermetic or trusted build"]}
    try:
        require(sys.platform == "linux", "this host recipe requires Linux")
        repo = args.repo_root.resolve(strict=True)
        cache = args.cargo_home.resolve(strict=True)
        build_root = args.build_root.resolve()
        require(cache.is_dir(), "input Cargo home is not a directory")
        require(not build_root.exists() and not build_root.is_symlink(), "build root must be new")
        parent = build_root.parent.resolve(strict=True)
        require(not parent.is_relative_to(repo) and not parent.is_relative_to(cache), "build root must be outside source and cache")
        require(not args.output.resolve().is_relative_to(repo), "report must be outside source checkout")
        reject_ambient_config(repo, cache)
        source = source_identity(repo, args.expected_commit)
        resolved = [p.resolve(strict=True) for p in (args.cargo, args.rustc, args.cc, args.ar)]
        require(all(os.access(p, os.X_OK) for p in resolved), "build tools must be executable")
        tools = toolchain_identity(*resolved, repo)
        implementation = implementation_manifest()
        validate_implementation_manifest(implementation)
        report.update({"source": source, "tools": tools, "dependency_cache": str(cache),
                       "build_root": str(build_root), "harness": file_identity(Path(__file__)),
                       "implementation_manifest": implementation})
        build_root.mkdir(mode=0o700)
        for label in ("a", "b"):
            target = build_root / f"target-{label}"
            home = build_root / f"cargo-home-{label}"
            prepare_home(home, cache)
            target.mkdir(mode=0o700)
            command, env = recipe(repo, target, home, cache, tools, source)
            before_source = source_identity(repo, source["commit"])
            before_tools = toolchain_identity(*resolved, repo)
            require(before_source == source and before_tools == tools, "input identity changed before build")
            build = {"label": label, "command": command, "environment": env,
                     "source_before": before_source, "tools_before": before_tools, "artifacts": {}}
            report["builds"].append(build)
            build.update(run_build(command, env, repo, build_root / f"cargo-{label}.log", args.timeout_seconds))
            build["source_after"] = source_identity(repo, source["commit"])
            build["tools_after"] = toolchain_identity(*resolved, repo)
            require(build["exit_code"] == 0, f"build {label} failed; inspect retained Cargo log")
            require(build["source_after"] == source and build["tools_after"] == tools, "source or tools changed during build")
            for binary in BINARIES:
                path = target / "release" / binary
                require(not path.is_symlink() and path.is_file() and os.access(path, os.X_OK), f"missing executable artifact: {binary}")
                with path.open("rb") as stream:
                    require(stream.read(4) == b"\x7fELF", f"artifact is not ELF: {binary}")
                build["artifacts"][binary] = file_identity(path)
        require(implementation_manifest() == implementation,
                "reproducibility implementation changed during builds")
        report["gate"] = compare_artifacts(report["builds"])
    except (VerificationError, OSError, subprocess.SubprocessError) as error:
        report["errors"].append(str(error))
        report["gate"] = {"status": "FAIL_VERIFICATION", "passed": False}
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
