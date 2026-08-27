#!/usr/bin/env python3
"""Build a positive-allowlist Debian Bookworm Root-Linux base.

This is a host-side artifact builder.  It creates a fresh mmdebstrap tree from
an authenticated snapshot, rejects every package outside the frozen allowlist,
normalizes the tree into a deterministic read-only tar archive, and emits an
SPDX SBOM plus a custody receipt.

It deliberately does not update Android product pins, build an OTA, enable
fs-verity, install an image, or touch a device.  Final payload injection and
immutable-image publication are separate reviewed stages.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import Iterable, Mapping, Sequence
import urllib.request


SCHEMA = "org.trillionnium.root-linux.minimal-bookworm-build.v1"
RECEIPT_SCHEMA = "org.trillionnium.root-linux.minimal-bookworm-receipt.v1"
SPDX_VERSION = "SPDX-2.3"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
PACKAGE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?")
REVIEWED_SNAPSHOT_TIMESTAMP = "20260727T000000Z"
REVIEWED_SOURCE_DATE_EPOCH = 1_785_110_400
REVIEWED_KEYRING_VERSION = "2025.1"
REVIEWED_DEBIAN_SOURCE = (
    "deb [check-valid-until=no] "
    "https://snapshot.debian.org/archive/debian/20260727T000000Z "
    "bookworm main"
)
REVIEWED_SECURITY_SOURCE = (
    "deb [check-valid-until=no] "
    "https://snapshot.debian.org/archive/debian-security/20260727T000000Z "
    "bookworm-security main"
)
REVIEWED_DEBIAN_INRELEASE_URL = (
    "https://snapshot.debian.org/archive/debian/20260727T000000Z/"
    "dists/bookworm/InRelease"
)
REVIEWED_SECURITY_INRELEASE_URL = (
    "https://snapshot.debian.org/archive/debian-security/20260727T000000Z/"
    "dists/bookworm-security/InRelease"
)
VOLATILE_CHILDREN = (
    "dev",
    "home",
    "proc",
    "root",
    "run",
    "sys",
    "tmp",
    "var/cache",
    "var/log",
    "var/tmp",
)
HOST_BOUND_FILES = (
    "etc/hostname",
    "etc/hosts",
    "etc/machine-id",
    "etc/resolv.conf",
    "var/lib/dbus/machine-id",
)
FORBIDDEN_PATH_PREFIXES = (
    "home/",
    "root/",
    "usr/share/X11/",
    "usr/share/applications/",
    "usr/share/gnome",
    "usr/share/wayland-sessions/",
)


class BuildError(RuntimeError):
    """A fail-closed contract, input, build, or publication error."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BuildError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> object:
    raise BuildError(f"non-finite JSON value: {value}")


def load_json(path: Path, label: str) -> object:
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError(f"{label} is not strict UTF-8 JSON") from error


def mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise BuildError(f"{label} must be an object")
    return value


def exact_keys(
    value: Mapping[str, object], expected: set[str], label: str
) -> None:
    actual = set(value)
    if actual != expected:
        raise BuildError(
            f"{label} keys differ: missing={sorted(expected - actual)} "
            f"unknown={sorted(actual - expected)}"
        )


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise BuildError(f"{label} must be a non-empty string")
    return value


def require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise BuildError(f"{label} must be boolean")
    return value


def require_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BuildError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise BuildError(f"{label} is outside [{minimum}, {maximum}]")
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise BuildError(f"{label} must be a lowercase SHA-256")
    return value


def string_array(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        raise BuildError(f"{label} must be an array")
    result = [require_string(item, f"{label}[]") for item in value]
    if len(result) != len(set(result)):
        raise BuildError(f"{label} contains duplicates")
    return result


def validate_contract(value: object) -> dict[str, object]:
    root = dict(mapping(value, "contract"))
    exact_keys(
        root,
        {
            "schema",
            "suite",
            "architecture",
            "snapshot",
            "source_date_epoch",
            "requested_packages",
            "resolved_packages",
            "forbidden_package_names",
            "forbidden_package_prefixes",
            "normalization",
            "compression",
            "tools",
            "production",
        },
        "contract",
    )
    if root["schema"] != SCHEMA:
        raise BuildError("unsupported contract schema")
    if root["suite"] != "bookworm" or root["architecture"] != "arm64":
        raise BuildError("only Bookworm arm64 is supported")
    root["source_date_epoch"] = require_int(
        root["source_date_epoch"], "source_date_epoch", 1, 4_102_444_800
    )
    if root["source_date_epoch"] != REVIEWED_SOURCE_DATE_EPOCH:
        raise BuildError("source_date_epoch is not the reviewed snapshot epoch")

    snapshot = dict(mapping(root["snapshot"], "snapshot"))
    exact_keys(
        snapshot,
        {
            "timestamp",
            "debian_source",
            "security_source",
            "keyring_version",
            "keyring_deb_bytes",
            "keyring_deb_sha256",
            "keyring_payload_sha256",
            "debian_inrelease_url",
            "debian_inrelease_bytes",
            "debian_inrelease_sha256",
            "security_inrelease_url",
            "security_inrelease_bytes",
            "security_inrelease_sha256",
            "archive_signatures_required",
            "keyring_origin_independently_approved",
        },
        "snapshot",
    )
    if snapshot["timestamp"] != REVIEWED_SNAPSHOT_TIMESTAMP:
        raise BuildError("snapshot timestamp is not the reviewed value")
    reviewed_sources = {
        "debian_source": REVIEWED_DEBIAN_SOURCE,
        "security_source": REVIEWED_SECURITY_SOURCE,
    }
    for field, reviewed_source in reviewed_sources.items():
        source = require_string(snapshot[field], f"snapshot.{field}")
        if source != reviewed_source:
            raise BuildError(f"snapshot.{field} is not the exact reviewed source")
        snapshot[field] = source
    snapshot["keyring_version"] = require_string(
        snapshot["keyring_version"], "snapshot.keyring_version"
    )
    if snapshot["keyring_version"] != REVIEWED_KEYRING_VERSION:
        raise BuildError("snapshot.keyring_version is not the reviewed version")
    snapshot["keyring_deb_bytes"] = require_int(
        snapshot["keyring_deb_bytes"],
        "snapshot.keyring_deb_bytes",
        1,
        16 * 1024 * 1024,
    )
    snapshot["keyring_deb_sha256"] = require_sha256(
        snapshot["keyring_deb_sha256"], "snapshot.keyring_deb_sha256"
    )
    snapshot["keyring_payload_sha256"] = require_sha256(
        snapshot["keyring_payload_sha256"], "snapshot.keyring_payload_sha256"
    )
    reviewed_inrelease_urls = {
        "debian": REVIEWED_DEBIAN_INRELEASE_URL,
        "security": REVIEWED_SECURITY_INRELEASE_URL,
    }
    for prefix, reviewed_url in reviewed_inrelease_urls.items():
        url_field = f"{prefix}_inrelease_url"
        bytes_field = f"{prefix}_inrelease_bytes"
        sha_field = f"{prefix}_inrelease_sha256"
        url = require_string(snapshot[url_field], f"snapshot.{url_field}")
        if url != reviewed_url:
            raise BuildError(f"snapshot.{url_field} is not the exact reviewed URL")
        snapshot[url_field] = url
        snapshot[bytes_field] = require_int(
            snapshot[bytes_field], f"snapshot.{bytes_field}", 1, 1024 * 1024
        )
        snapshot[sha_field] = require_sha256(
            snapshot[sha_field], f"snapshot.{sha_field}"
        )
    if require_bool(
        snapshot["archive_signatures_required"],
        "snapshot.archive_signatures_required",
    ) is not True:
        raise BuildError("archive signatures must be required")
    require_bool(
        snapshot["keyring_origin_independently_approved"],
        "snapshot.keyring_origin_independently_approved",
    )
    root["snapshot"] = snapshot

    requested = string_array(root["requested_packages"], "requested_packages")
    if not requested:
        raise BuildError("requested_packages may not be empty")
    for package in requested:
        if PACKAGE_NAME_RE.fullmatch(package) is None:
            raise BuildError(f"invalid requested package name: {package}")
    root["requested_packages"] = requested

    packages = root["resolved_packages"]
    if not isinstance(packages, list) or not packages:
        raise BuildError("resolved_packages must be a non-empty array")
    normalized_packages: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(packages):
        package = dict(mapping(item, f"resolved_packages[{index}]"))
        exact_keys(package, {"name", "version", "architecture"}, f"resolved_packages[{index}]")
        name = require_string(package["name"], f"resolved_packages[{index}].name")
        version = require_string(package["version"], f"resolved_packages[{index}].version")
        architecture = require_string(
            package["architecture"], f"resolved_packages[{index}].architecture"
        )
        if PACKAGE_NAME_RE.fullmatch(name) is None:
            raise BuildError(f"invalid resolved package name: {name}")
        if name in seen:
            raise BuildError(f"duplicate resolved package: {name}")
        if architecture not in {"all", "arm64"}:
            raise BuildError(f"unexpected resolved package architecture: {architecture}")
        seen.add(name)
        normalized_packages.append(
            {"name": name, "version": version, "architecture": architecture}
        )
    root["resolved_packages"] = sorted(
        normalized_packages, key=lambda item: item["name"].encode("utf-8")
    )
    resolved_base_names = {
        item["name"].split(":", 1)[0] for item in root["resolved_packages"]
    }
    missing_requested = sorted(
        package.split(":", 1)[0]
        for package in requested
        if package.split(":", 1)[0] not in resolved_base_names
    )
    if missing_requested:
        raise BuildError(
            f"requested_packages absent from resolved allowlist: {missing_requested}"
        )

    root["forbidden_package_names"] = string_array(
        root["forbidden_package_names"], "forbidden_package_names"
    )
    root["forbidden_package_prefixes"] = string_array(
        root["forbidden_package_prefixes"], "forbidden_package_prefixes"
    )

    normalization = dict(mapping(root["normalization"], "normalization"))
    exact_keys(
        normalization,
        {
            "all_uid",
            "all_gid",
            "directory_mode",
            "regular_mode",
            "executable_mode",
            "absolute_symlink_rewrite",
            "special_files_allowed",
            "filesystem_write_bits_allowed",
        },
        "normalization",
    )
    required_normalization = {
        "all_uid": 0,
        "all_gid": 0,
        "directory_mode": "0555",
        "regular_mode": "0444",
        "executable_mode": "0555",
        "absolute_symlink_rewrite": "root_absolute_to_relative_v1",
        "special_files_allowed": False,
        "filesystem_write_bits_allowed": False,
    }
    if normalization != required_normalization:
        raise BuildError("normalization policy differs from the reviewed policy")

    compression = dict(mapping(root["compression"], "compression"))
    exact_keys(compression, {"algorithm", "level", "threads"}, "compression")
    if compression != {"algorithm": "zstd", "level": 19, "threads": 1}:
        raise BuildError("compression policy differs from zstd level 19 / one thread")

    tools = dict(mapping(root["tools"], "tools"))
    exact_keys(
        tools,
        {"mmdebstrap", "dpkg_deb", "dpkg_query", "gpgv", "zstd"},
        "tools",
    )
    normalized_tools: dict[str, dict[str, str]] = {}
    for name, value in tools.items():
        descriptor = dict(mapping(value, f"tools.{name}"))
        exact_keys(descriptor, {"sha256"}, f"tools.{name}")
        normalized_tools[name] = {
            "sha256": require_sha256(
                descriptor["sha256"], f"tools.{name}.sha256"
            )
        }
    root["tools"] = normalized_tools

    production = dict(mapping(root["production"], "production"))
    exact_keys(
        production,
        {
            "contract_confers_effect_authority",
            "product_pin_refresh_authorized",
            "device_write_authorized",
            "ota_signing_authorized",
            "release_promotion_authorized",
        },
        "production",
    )
    if any(require_bool(value, f"production.{key}") for key, value in production.items()):
        raise BuildError("base-rootfs contract must not authorize production effects")
    return root


def ensure_regular_no_symlink(path: Path, label: str) -> os.stat_result:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise BuildError(f"{label} contains a symlink component: {current}")
    info = absolute.stat()
    if not stat.S_ISREG(info.st_mode):
        raise BuildError(f"{label} must be a regular file")
    return info


def ensure_output_available(path: Path, label: str) -> None:
    parent = path.absolute().parent
    current = Path(parent.anchor)
    for component in parent.parts[1:]:
        current = current / component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise BuildError(f"{label} parent is unsafe: {current}")
    if path.exists() or path.is_symlink():
        raise BuildError(f"{label} already exists")


def run(command: Sequence[str], *, cwd: Path | None = None) -> bytes:
    try:
        return subprocess.run(
            list(command),
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except subprocess.CalledProcessError as error:
        stderr = error.stderr.decode("utf-8", "replace")[-4000:]
        raise BuildError(f"command failed: {command[0]}: {stderr}") from error


def keyring_payload(
    keyring_deb: Path, dpkg_deb: Path, work: Path
) -> tuple[Path, str]:
    extracted = work / "keyring"
    extracted.mkdir(mode=0o700)
    run([str(dpkg_deb), "-x", str(keyring_deb), str(extracted)])
    candidates = (
        extracted / "usr/share/keyrings/debian-archive-keyring.pgp",
        extracted / "usr/share/keyrings/debian-archive-keyring.gpg",
    )
    payload = next((item for item in candidates if item.is_file()), None)
    if payload is None or payload.is_symlink():
        raise BuildError("keyring package lacks a safe Debian archive keyring")
    return payload, sha256_file(payload)


def fetch_and_verify_inrelease(
    *,
    url: str,
    expected_bytes: int,
    expected_sha256: str,
    destination: Path,
    gpgv: Path,
    keyring: Path,
) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "trillionnium-rootfs-builder/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            final_url = response.geturl()
            if not final_url.startswith("https://snapshot.debian.org/"):
                raise BuildError("InRelease redirect left snapshot.debian.org HTTPS")
            content = response.read(1024 * 1024 + 1)
    except OSError as error:
        raise BuildError(f"cannot fetch pinned InRelease: {url}") from error
    if len(content) != expected_bytes or sha256_bytes(content) != expected_sha256:
        raise BuildError(f"pinned InRelease bytes or SHA-256 drifted: {url}")
    with destination.open("xb") as sink:
        sink.write(content)
        sink.flush()
        os.fsync(sink.fileno())
    run([str(gpgv), "--keyring", str(keyring), str(destination)])
    return {
        "url": url,
        "bytes": len(content),
        "sha256": sha256_bytes(content),
        "signature_verified": True,
    }


def mmdebstrap_command(
    contract: Mapping[str, object],
    mmdebstrap: Path,
    keyring: Path,
    destination: Path,
) -> list[str]:
    snapshot = mapping(contract["snapshot"], "snapshot")
    resolved_packages = contract["resolved_packages"]
    assert isinstance(resolved_packages, list)
    exact_packages = [
        f"{item['name']}={item['version']}" for item in resolved_packages
    ]
    return [
        str(mmdebstrap),
        "--mode=root",
        "--architectures=arm64",
        "--variant=custom",
        "--include=" + ",".join(exact_packages),
        "--keyring=" + str(keyring),
        '--aptopt=Acquire::Check-Valid-Until "false"',
        '--aptopt=Acquire::Languages "none"',
        "--dpkgopt=path-exclude=/usr/share/doc/*",
        "--dpkgopt=path-exclude=/usr/share/man/*",
        "--dpkgopt=path-exclude=/usr/share/locale/*",
        "bookworm",
        str(destination),
        str(snapshot["debian_source"]),
        str(snapshot["security_source"]),
    ]


def package_inventory(rootfs: Path, dpkg_query: Path) -> list[dict[str, str]]:
    output = run(
        [
            str(dpkg_query),
            "--admindir=" + str(rootfs / "var/lib/dpkg"),
            "-W",
            "-f=${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\n",
        ]
    ).decode("utf-8")
    result: list[dict[str, str]] = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 4 or fields[3] != "ii ":
            raise BuildError(f"unexpected dpkg-query row: {line!r}")
        name, version, architecture, _status = fields
        result.append(
            {"name": name, "version": version, "architecture": architecture}
        )
    return sorted(result, key=lambda item: item["name"].encode("utf-8"))


def validate_inventory(
    actual: list[dict[str, str]], contract: Mapping[str, object]
) -> None:
    expected = contract["resolved_packages"]
    if actual != expected:
        expected_by_name = {str(item["name"]): item for item in expected}  # type: ignore[index]
        actual_by_name = {item["name"]: item for item in actual}
        raise BuildError(
            "resolved package allowlist mismatch: "
            f"missing={sorted(set(expected_by_name) - set(actual_by_name))} "
            f"extra={sorted(set(actual_by_name) - set(expected_by_name))} "
            f"drift={sorted(name for name in set(expected_by_name) & set(actual_by_name) if expected_by_name[name] != actual_by_name[name])}"
        )
    forbidden = set(str(item) for item in contract["forbidden_package_names"])
    prefixes = tuple(str(item) for item in contract["forbidden_package_prefixes"])
    for item in actual:
        name = item["name"].split(":", 1)[0]
        if name in forbidden or name.startswith(prefixes):
            raise BuildError(f"forbidden package entered the rootfs: {name}")


def checked_child(root: Path, relative: str) -> Path:
    root_resolved = root.resolve()
    child = root / relative
    child_resolved = child.resolve(strict=False)
    if child_resolved == root_resolved or root_resolved not in child_resolved.parents:
        raise BuildError(f"unsafe rootfs cleanup target: {relative}")
    return child


def checked_cleanup_leaf(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise BuildError(f"unsafe cleanup leaf: {relative}")
    parent = root
    for component in parts[:-1]:
        parent = parent / component
        if parent.is_symlink():
            raise BuildError(f"cleanup leaf has a symlink parent: {relative}")
    return parent / parts[-1]


def normalize_volatile_tree(rootfs: Path) -> None:
    for relative in VOLATILE_CHILDREN:
        child = checked_child(rootfs, relative)
        if child.is_symlink():
            raise BuildError(f"volatile path is a symlink: {relative}")
        if child.exists():
            if child.is_dir():
                for entry in child.iterdir():
                    if entry.is_dir() and not entry.is_symlink():
                        shutil.rmtree(entry)
                    else:
                        entry.unlink()
            else:
                child.unlink()
        child.mkdir(parents=True, exist_ok=True)
    for relative in HOST_BOUND_FILES:
        child = checked_cleanup_leaf(rootfs, relative)
        if child.is_symlink():
            child.unlink()
            continue
        if child.exists():
            if not child.is_file():
                raise BuildError(f"host-bound path is not a regular file: {relative}")
            child.unlink()


def canonical_relative(path: Path, rootfs: Path) -> str:
    return path.relative_to(rootfs).as_posix()


def normalized_link(path: str, target: str) -> str:
    if not target or "\x00" in target or "\\" in target:
        raise BuildError(f"unsafe symlink target: {path} -> {target!r}")
    parent = PurePosixPath(path).parent
    if target.startswith("/"):
        destination = PurePosixPath(target.lstrip("/"))
        target = os.path.relpath(destination.as_posix(), parent.as_posix() or ".")
    resolved = PurePosixPath(os.path.normpath((parent / target).as_posix()))
    if resolved == PurePosixPath("..") or resolved.as_posix().startswith("../"):
        raise BuildError(f"symlink escapes rootfs: {path} -> {target}")
    return target


def sorted_tree(rootfs: Path) -> list[Path]:
    result = [rootfs]
    for directory, names, files in os.walk(rootfs, topdown=True, followlinks=False):
        names.sort(key=lambda item: item.encode("utf-8"))
        files.sort(key=lambda item: item.encode("utf-8"))
        base = Path(directory)
        result.extend(base / name for name in names)
        result.extend(base / name for name in files)
    deduplicated = {canonical_relative(item, rootfs): item for item in result}
    return [
        deduplicated[key]
        for key in sorted(
            deduplicated, key=lambda item: (item != ".", item.encode("utf-8"))
        )
    ]


def build_normalized_tar(rootfs: Path, output: Path, epoch: int) -> dict[str, int]:
    member_count = 0
    regular_bytes = 0
    hardlink_targets: dict[tuple[int, int], str] = {}
    with tarfile.open(output, "w:", format=tarfile.GNU_FORMAT) as archive:
        for path in sorted_tree(rootfs):
            relative = canonical_relative(path, rootfs)
            if relative != "." and any(
                relative.startswith(prefix) for prefix in FORBIDDEN_PATH_PREFIXES
            ):
                raise BuildError(f"forbidden headless-rootfs path: {relative}")
            info = path.lstat()
            member = tarfile.TarInfo(relative)
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = epoch
            member.pax_headers = {}
            if stat.S_ISDIR(info.st_mode):
                member.type = tarfile.DIRTYPE
                member.mode = 0o555
                member.size = 0
                archive.addfile(member)
            elif stat.S_ISREG(info.st_mode):
                member.mode = 0o555 if info.st_mode & 0o111 else 0o444
                identity = (info.st_dev, info.st_ino)
                hardlink_target = hardlink_targets.get(identity)
                if hardlink_target is not None:
                    member.type = tarfile.LNKTYPE
                    member.linkname = hardlink_target
                    member.size = 0
                    archive.addfile(member)
                else:
                    hardlink_targets[identity] = relative
                    member.type = tarfile.REGTYPE
                    member.size = info.st_size
                    regular_bytes += info.st_size
                    with path.open("rb") as source:
                        archive.addfile(member, source)
            elif stat.S_ISLNK(info.st_mode):
                member.type = tarfile.SYMTYPE
                member.mode = 0o777
                member.size = 0
                member.linkname = normalized_link(relative, os.readlink(path))
                archive.addfile(member)
            else:
                raise BuildError(f"special rootfs entry is forbidden: {relative}")
            member_count += 1
    return {"members": member_count, "regular_bytes": regular_bytes}


def compress_tar(zstd: Path, source: Path, destination: Path) -> None:
    with destination.open("xb") as sink:
        try:
            subprocess.run(
                [
                    str(zstd),
                    "-q",
                    "-19",
                    "--long=27",
                    "-T1",
                    "-c",
                    str(source),
                ],
                check=True,
                stdout=sink,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as error:
            raise BuildError(
                "zstd compression failed: "
                + error.stderr.decode("utf-8", "replace")[-2000:]
            ) from error
        sink.flush()
        os.fsync(sink.fileno())
    destination.chmod(0o444)


def spdx_sbom(
    packages: Iterable[Mapping[str, str]],
    contract_sha256: str,
    namespace_seed: str,
) -> dict[str, object]:
    package_rows = []
    relationships = []
    for index, item in enumerate(packages, start=1):
        package_id = f"SPDXRef-Package-{index}"
        name = item["name"]
        version = item["version"]
        architecture = item["architecture"]
        package_rows.append(
            {
                "SPDXID": package_id,
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": (
                            f"pkg:deb/debian/{name}@{version}?arch={architecture}"
                        ),
                    }
                ],
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": package_id,
            }
        )
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "trillionnium-root-linux-minimal-bookworm-arm64",
        "documentNamespace": (
            "https://trillionnium.org/spdx/root-linux/"
            + sha256_bytes((contract_sha256 + namespace_seed).encode("ascii"))
        ),
        "creationInfo": {
            "created": "2026-07-27T00:00:00Z",
            "creators": ["Tool: build_minimal_bookworm_rootfs.py"],
        },
        "packages": package_rows,
        "relationships": relationships,
    }


def publish_bytes(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as sink:
            sink.write(content)
            sink.flush()
            os.fsync(sink.fileno())
    finally:
        os.close(descriptor)


def publish_file(path: Path, source: Path) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as sink, source.open(
            "rb"
        ) as input_file:
            shutil.copyfileobj(input_file, sink, length=1024 * 1024)
            sink.flush()
            os.fsync(sink.fileno())
    finally:
        os.close(descriptor)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--keyring-deb", type=Path, required=True)
    parser.add_argument("--mmdebstrap", type=Path, default=Path("/usr/bin/mmdebstrap"))
    parser.add_argument("--dpkg-deb", type=Path, default=Path("/usr/bin/dpkg-deb"))
    parser.add_argument("--dpkg-query", type=Path, default=Path("/usr/bin/dpkg-query"))
    parser.add_argument("--gpgv", type=Path, default=Path("/usr/bin/gpgv"))
    parser.add_argument("--zstd", type=Path, default=Path("/usr/bin/zstd"))
    parser.add_argument("--work-parent", type=Path, required=True)
    parser.add_argument("--output-rootfs", type=Path, required=True)
    parser.add_argument("--output-sbom", type=Path, required=True)
    parser.add_argument("--output-receipt", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        raise BuildError("builder must run as root for reviewed mmdebstrap mode=root")
    contract_info = ensure_regular_no_symlink(args.contract, "contract")
    keyring_info = ensure_regular_no_symlink(args.keyring_deb, "keyring package")
    tool_names = ("mmdebstrap", "dpkg_deb", "dpkg_query", "gpgv", "zstd")
    for tool_name in tool_names:
        tool_path = getattr(args, tool_name)
        ensure_regular_no_symlink(tool_path, tool_name)
    for path, label in (
        (args.output_rootfs, "output rootfs"),
        (args.output_sbom, "output SBOM"),
        (args.output_receipt, "output receipt"),
    ):
        ensure_output_available(path, label)

    work_parent = args.work_parent.absolute()
    if work_parent.is_symlink() or not work_parent.is_dir():
        raise BuildError("work parent must be a real existing directory")
    contract = validate_contract(load_json(args.contract, "contract"))
    snapshot = mapping(contract["snapshot"], "snapshot")
    tool_contract = mapping(contract["tools"], "tools")
    for tool_name in tool_names:
        expected = mapping(tool_contract[tool_name], f"tools.{tool_name}")["sha256"]
        if sha256_file(getattr(args, tool_name)) != expected:
            raise BuildError(f"{tool_name} SHA-256 mismatch")
    if keyring_info.st_size != snapshot["keyring_deb_bytes"]:
        raise BuildError("keyring package byte-size mismatch")
    if sha256_file(args.keyring_deb) != snapshot["keyring_deb_sha256"]:
        raise BuildError("keyring package SHA-256 mismatch")

    work_value: Path | None = None
    try:
        work_value = Path(
            tempfile.mkdtemp(prefix="trillionnium-minimal-bookworm.", dir=work_parent)
        )
        if work_parent.resolve() not in work_value.resolve().parents:
            raise BuildError("temporary work directory escaped its parent")
        keyring, keyring_sha256 = keyring_payload(
            args.keyring_deb, args.dpkg_deb, work_value
        )
        if keyring_sha256 != snapshot["keyring_payload_sha256"]:
            raise BuildError("extracted keyring payload SHA-256 mismatch")
        inreleases = {
            prefix: fetch_and_verify_inrelease(
                url=str(snapshot[f"{prefix}_inrelease_url"]),
                expected_bytes=int(snapshot[f"{prefix}_inrelease_bytes"]),
                expected_sha256=str(snapshot[f"{prefix}_inrelease_sha256"]),
                destination=work_value / f"{prefix}.InRelease",
                gpgv=args.gpgv,
                keyring=keyring,
            )
            for prefix in ("debian", "security")
        }
        rootfs = work_value / "rootfs"
        run(mmdebstrap_command(contract, args.mmdebstrap, keyring, rootfs))
        packages = package_inventory(rootfs, args.dpkg_query)
        validate_inventory(packages, contract)
        normalize_volatile_tree(rootfs)

        tar_path = work_value / "rootfs.tar"
        archive_stats = build_normalized_tar(
            rootfs, tar_path, int(contract["source_date_epoch"])
        )
        compressed = work_value / "rootfs.tar.zst"
        compress_tar(args.zstd, tar_path, compressed)

        contract_sha256 = sha256_file(args.contract)
        sbom = spdx_sbom(packages, contract_sha256, sha256_file(compressed))
        sbom_content = json_bytes(sbom)
        receipt: dict[str, object] = {
            "schema": RECEIPT_SCHEMA,
            "contract": {
                "bytes": contract_info.st_size,
                "sha256": contract_sha256,
            },
            "keyring_deb": {
                "bytes": keyring_info.st_size,
                "sha256": sha256_file(args.keyring_deb),
                "payload_sha256": keyring_sha256,
                "origin_independently_approved": snapshot[
                    "keyring_origin_independently_approved"
                ],
            },
            "snapshot": {
                "timestamp": snapshot["timestamp"],
                "debian_source": snapshot["debian_source"],
                "security_source": snapshot["security_source"],
                "archive_signatures_required": True,
                "inrelease": inreleases,
            },
            "packages": {
                "allowlist_exact_match": True,
                "count": len(packages),
                "names": [item["name"] for item in packages],
            },
            "normalization": {
                "uid_gid": "0:0",
                "directories": "0555",
                "regular_files": "0444",
                "executables": "0555",
                "filesystem_write_bits_absent": True,
                "special_files_absent": True,
                "volatile_trees_empty": True,
                "home_and_root_empty": True,
                "absolute_symlinks_rewritten_relative": True,
            },
            "rootfs": {
                "bytes": compressed.stat().st_size,
                "sha256": sha256_file(compressed),
                **archive_stats,
            },
            "sbom": {
                "schema": SPDX_VERSION,
                "bytes": len(sbom_content),
                "sha256": sha256_bytes(sbom_content),
            },
            "tools": {
                name: {
                    "sha256": sha256_file(getattr(args, name)),
                    "path_basename": getattr(args, name).name,
                }
                for name in tool_names
            },
            "host_only": True,
            "product_pin_refresh_performed": False,
            "fsverity_enable_performed": False,
            "device_write_performed": False,
            "ota_signing_performed": False,
            "release_promotion_performed": False,
        }
        receipt["receipt_id"] = sha256_bytes(canonical_json_bytes(receipt))
        receipt_content = json_bytes(receipt)

        publish_file(args.output_rootfs, compressed)
        publish_bytes(args.output_sbom, sbom_content)
        publish_bytes(args.output_receipt, receipt_content)
        print(f"rootfs_sha256={receipt['rootfs']['sha256']}")  # type: ignore[index]
        print(f"sbom_sha256={receipt['sbom']['sha256']}")  # type: ignore[index]
        print(f"receipt_id={receipt['receipt_id']}")
        return 0
    finally:
        if work_value is not None:
            resolved_parent = work_parent.resolve()
            resolved_work = work_value.resolve(strict=False)
            if resolved_parent in resolved_work.parents and resolved_work != resolved_parent:
                shutil.rmtree(work_value, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as error:
        print(f"minimal Bookworm rootfs build denied: {error}", file=os.sys.stderr)
        raise SystemExit(2)
