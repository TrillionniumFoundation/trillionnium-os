#!/usr/bin/env python3
"""Evaluate the security-relevant Android adbroot product graph fail closed.

This is an L1 source/evaluated-graph verifier. It deliberately does not claim
that Soong, SELinux, target-files, an image, or a physical device was built.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any
import xml.etree.ElementTree as ET

SCHEMA = "org.trillionnium.owner-open.adbroot-evaluated-graph.v1"
CLAIM_CEILING = "EVALUATED_SECURITY_ANDROID_GRAPH_ONLY_NOT_SOONG_OR_SELINUX_COMPILED"
REPOSITORY = "TrillionniumFoundation/trillionnium-os"
PROGRAM_REVISION = "2026-08-31-g1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_INPUT_BYTES = 4 * 1024 * 1024

PRODUCT_PATH = Path(
    "android-integration/working-tree/vendor/trillionnium/owner-open/product.mk"
)
COMMON_PATH = Path(
    "android-integration/working-tree/vendor/trillionnium/config/common.mk"
)
COMMON_OWNER_OPEN_PATH = Path(
    "android-integration/working-tree/vendor/trillionnium/config/common_owner_open.mk"
)
MANIFEST_PATH = Path(
    "android-integration/manifest/manifests/trillionnium-fogos.xml"
)
ADBROOT_POLICY_DIR = Path(
    "android-integration/working-tree/vendor/trillionnium/owner-open/sepolicy/adbroot"
)
ADBROOT_POLICY_INSTALL_PATH = "vendor/trillionnium/owner-open/sepolicy/adbroot"
ADBROOT_OPT_IN = "TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT"

SUPPORTED_VARIANTS = ("user", "userdebug", "eng")
OPT_IN_CASES: tuple[tuple[str, str | None], ...] = (
    ("unset", None),
    ("false", "false"),
    ("true", "true"),
    ("malformed", "TRUE-or-1"),
)

COMMON_OWNER_OPEN_ACTIVE_LINES = (
    "$(call inherit-product, vendor/trillionnium/config/common.mk)",
    "$(call inherit-product, vendor/trillionnium/owner-open/product.mk)",
)

COMMON_SECURITY_ACTIVE_LINES = (
    "ifeq ($(TARGET_BUILD_VARIANT),eng)",
    "PRODUCT_SYSTEM_EXT_PROPERTIES += ro.adb.secure=0",
    "else",
    "ifdef WITH_ADB_INSECURE",
    "PRODUCT_SYSTEM_EXT_PROPERTIES += ro.adb.secure=0",
    "else",
    "PRODUCT_SYSTEM_EXT_PROPERTIES += ro.adb.secure=1",
    f"ifneq ($({ADBROOT_OPT_IN}),true)",
    "PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG := true",
    "endif",
    "endif",
    "PRODUCT_PRODUCT_PROPERTIES += persist.sys.strictmode.disable=true",
    "endif",
)

PRODUCT_PRIVILEGE_ACTIVE_LINES = (
    f"ifeq ($({ADBROOT_OPT_IN}),true)",
    "ifneq ($(filter userdebug eng,$(TARGET_BUILD_VARIANT)),)",
    "PRODUCT_PACKAGES += \\",
    "adb_root",
    "SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += \\",
    ADBROOT_POLICY_INSTALL_PATH,
    "endif",
    "endif",
)

EXPECTED_POLICY_STATEMENTS: dict[str, tuple[str, ...]] = {
    "adbd.te": (
        "allow adbd adbroot:binder call;",
        "allow adbd adbroot_service:service_manager find;",
    ),
    "adbroot.te": (
        "type adbroot, domain, coredomain;",
        "type adbroot_exec, exec_type, file_type, system_file_type;",
        "init_daemon_domain(adbroot)",
        "binder_use(adbroot)",
        "binder_service(adbroot)",
        "add_service(adbroot, adbroot_service)",
        "allow adbroot package_native_service:service_manager find;",
        "binder_call(adbroot, system_server)",
        "allow adbroot adbroot_data_file:dir rw_dir_perms;",
        "allow adbroot adbroot_data_file:file create_file_perms;",
        "set_prop(adbroot, shell_prop)",
        "set_prop(adbroot, ctl_adbd_prop)",
    ),
    "file.te": (
        "type adbroot_data_file, file_type, data_file_type, core_data_file_type;",
    ),
    "file_contexts": (
        "/(system_ext|system/system_ext)/bin/adb_root u:object_r:adbroot_exec:s0",
        "/data/adbroot(/.*)? u:object_r:adbroot_data_file:s0",
    ),
    "service.te": (
        "type adbroot_service, service_manager_type;",
    ),
    "service_contexts": (
        "adbroot_service u:object_r:adbroot_service:s0",
    ),
    "system_server.te": (
        "allow system_server adbroot_service:service_manager find;",
    ),
}

MANIFEST_PROJECTS = {
    "packages/modules/adb": "LineageOS/android_packages_modules_adb",
    "device/trillionnium/sepolicy": (
        "TrillionniumFoundation/android-device-trillionnium-sepolicy"
    ),
    "device/motorola/fogos": "LineageOS/android_device_motorola_fogos",
    "vendor/trillionnium": "TrillionniumFoundation/android-vendor-trillionnium",
}


class VerificationError(RuntimeError):
    """The evaluated Android privilege graph is incomplete or ambiguous."""


@dataclass(frozen=True)
class InputFile:
    path: str
    sha256: str
    bytes: int


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _receipt_digest(receipt: dict[str, Any]) -> str:
    clone = dict(receipt)
    clone["receipt_sha256"] = ""
    return hashlib.sha256(_canonical(clone)).hexdigest()


def _regular_text(repo_root: Path, relative: Path) -> tuple[str, InputFile]:
    path = repo_root / relative
    try:
        metadata = path.lstat()
    except OSError as error:
        raise VerificationError(f"required input is unavailable: {relative}: {error}") from error
    _require(not stat.S_ISLNK(metadata.st_mode), f"required input is a symlink: {relative}")
    _require(stat.S_ISREG(metadata.st_mode), f"required input is not a regular file: {relative}")
    _require(0 < metadata.st_size <= MAX_INPUT_BYTES, f"required input has invalid size: {relative}")
    try:
        content = path.read_bytes()
        text = content.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise VerificationError(f"required input is not strict UTF-8: {relative}: {error}") from error
    _require("\x00" not in text, f"required input contains NUL: {relative}")
    _require(content == text.encode("utf-8"), f"required input encoding drifted: {relative}")
    return text, InputFile(str(relative), hashlib.sha256(content).hexdigest(), len(content))


def _active_lines(text: str) -> tuple[str, ...]:
    result: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        result.append(re.sub(r"\s+", " ", line))
    return tuple(result)


def _conditional_block(text: str, start_line: str, label: str) -> tuple[str, int, int]:
    lines = text.splitlines()
    starts = [index for index, raw in enumerate(lines) if raw.strip() == start_line]
    _require(len(starts) == 1, f"{label} start must occur exactly once")
    start = starts[0]
    depth = 0
    for index in range(start, len(lines)):
        line = lines[index].strip()
        if re.match(r"^(ifeq|ifneq|ifdef|ifndef)\b", line):
            depth += 1
        elif line == "endif":
            depth -= 1
            _require(depth >= 0, f"{label} has an unmatched endif")
            if depth == 0:
                return "\n".join(lines[start : index + 1]) + "\n", start, index
    raise VerificationError(f"{label} is not terminated")


def _security_slices(
    common_text: str,
    common_owner_open_text: str,
    product_text: str,
) -> tuple[str, str]:
    _require(
        _active_lines(common_owner_open_text) == COMMON_OWNER_OPEN_ACTIVE_LINES,
        "common_owner_open.mk must unconditionally inherit common.mk then owner-open/product.mk exactly once",
    )

    common_block, common_start, common_end = _conditional_block(
        common_text,
        "ifeq ($(TARGET_BUILD_VARIANT),eng)",
        "common ADB security block",
    )
    _require(
        _active_lines(common_block) == COMMON_SECURITY_ACTIVE_LINES,
        "common ADB security block drifted from the reviewed evaluated contract",
    )
    common_lines = common_text.splitlines()
    for index, raw in enumerate(common_lines):
        if index < common_start or index > common_end:
            active = raw.strip()
            if active and not active.startswith("#"):
                _require(
                    ADBROOT_OPT_IN not in active
                    and "PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG" not in active
                    and "ro.adb.secure=" not in active,
                    "ADB security authority is referenced outside the reviewed common block",
                )

    product_block, product_start, product_end = _conditional_block(
        product_text,
        f"ifeq ($({ADBROOT_OPT_IN}),true)",
        "owner-open adbroot privilege block",
    )
    _require(
        _active_lines(product_block) == PRODUCT_PRIVILEGE_ACTIVE_LINES,
        "owner-open adbroot package/policy gate drifted from the reviewed evaluated contract",
    )
    product_lines = product_text.splitlines()
    privilege_tokens = (ADBROOT_OPT_IN, "adb_root", ADBROOT_POLICY_INSTALL_PATH)
    for index, raw in enumerate(product_lines):
        if product_start <= index <= product_end:
            continue
        active = raw.strip()
        if active and not active.startswith("#"):
            _require(
                not any(token in active for token in privilege_tokens),
                "adbroot authority is referenced outside the single reviewed product gate",
            )
    _require(
        not re.search(
            rf"^\s*(?:override\s+)?{re.escape(ADBROOT_OPT_IN)}\s*[:+?]?=",
            product_text,
            flags=re.MULTILINE,
        ),
        "product.mk must not assign its own adbroot opt-in",
    )
    return common_block, product_block


def _policy_inputs(repo_root: Path) -> tuple[list[InputFile], dict[str, Any]]:
    directory = repo_root / ADBROOT_POLICY_DIR
    try:
        metadata = directory.lstat()
    except OSError as error:
        raise VerificationError(f"adbroot policy directory is unavailable: {error}") from error
    _require(not stat.S_ISLNK(metadata.st_mode), "adbroot policy directory is a symlink")
    _require(stat.S_ISDIR(metadata.st_mode), "adbroot policy path is not a directory")
    actual_names = sorted(path.name for path in directory.iterdir())
    expected_names = sorted(EXPECTED_POLICY_STATEMENTS)
    _require(actual_names == expected_names, "adbroot policy input set drifted")

    inputs: list[InputFile] = []
    files: dict[str, Any] = {}
    for name in expected_names:
        relative = ADBROOT_POLICY_DIR / name
        text, input_file = _regular_text(repo_root, relative)
        normalized = tuple(
            re.sub(r"\s+", " ", raw.strip())
            for raw in text.splitlines()
            if raw.strip() and not raw.lstrip().startswith("#")
        )
        _require(
            normalized == EXPECTED_POLICY_STATEMENTS[name],
            f"adbroot policy statements drifted: {name}",
        )
        inputs.append(input_file)
        files[name] = {
            "path": input_file.path,
            "sha256": input_file.sha256,
            "bytes": input_file.bytes,
            "statements": list(normalized),
        }
    return inputs, files


def _manifest_projects(manifest_text: str) -> dict[str, dict[str, Any]]:
    _require(
        "<!DOCTYPE" not in manifest_text and "<!ENTITY" not in manifest_text,
        "manifest entities are forbidden",
    )
    try:
        root = ET.fromstring(manifest_text)
    except ET.ParseError as error:
        raise VerificationError(f"pinned Android manifest is malformed: {error}") from error
    _require(root.tag == "manifest", "pinned Android manifest root must be manifest")
    result: dict[str, dict[str, Any]] = {}
    projects = list(root.findall("project"))
    for path, expected_name in MANIFEST_PROJECTS.items():
        matches = [project for project in projects if project.get("path") == path]
        _require(len(matches) == 1, f"manifest must pin exactly one project at {path}")
        project = matches[0]
        name = project.get("name")
        revision = project.get("revision")
        _require(name == expected_name, f"manifest project name drifted at {path}")
        _require(
            isinstance(revision, str) and SHA_RE.fullmatch(revision) is not None,
            f"manifest revision is not an immutable SHA at {path}",
        )
        result[path] = {
            "name": name,
            "revision": revision,
            "remote": project.get("remote"),
            "groups": project.get("groups"),
        }
    return result


def _make_version(make: str) -> str:
    completed = subprocess.run(
        [make, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C"},
    )
    _require(completed.returncode == 0, "GNU Make version probe failed")
    first = completed.stdout.splitlines()[0] if completed.stdout else ""
    _require(first.startswith("GNU Make "), "evaluated graph requires GNU Make")
    return first


def _evaluate_case(
    *,
    make: str,
    make_version: str,
    common_block: str,
    product_block: str,
    variant: str,
    opt_in_state: str,
    opt_in_value: str | None,
) -> dict[str, Any]:
    _require(variant in SUPPORTED_VARIANTS, f"unsupported build variant: {variant}")
    assignment = (
        f"override {ADBROOT_OPT_IN} := {opt_in_value}\n"
        if opt_in_value is not None
        else f"override undefine {ADBROOT_OPT_IN}\n"
    )
    makefile = (
        "PRODUCT_PACKAGES := baseline_package\n"
        "PRODUCT_SYSTEM_EXT_PROPERTIES :=\n"
        "PRODUCT_PRODUCT_PROPERTIES :=\n"
        "SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS :=\n"
        "PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG :=\n"
        "override undefine WITH_ADB_INSECURE\n"
        f"override TARGET_BUILD_VARIANT := {variant}\n"
        f"{assignment}"
        f"{common_block}\n"
        f"{product_block}\n"
        ".PHONY: emit\n"
        "emit:\n"
        "\t@printf '%s\\n' 'PRODUCT_PACKAGES=$(strip $(PRODUCT_PACKAGES))'\n"
        "\t@printf '%s\\n' 'SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS=$(strip $(SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS))'\n"
        "\t@printf '%s\\n' 'PRODUCT_SYSTEM_EXT_PROPERTIES=$(strip $(PRODUCT_SYSTEM_EXT_PROPERTIES))'\n"
        "\t@printf '%s\\n' 'PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG=$(strip $(PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG))'\n"
    )
    completed = subprocess.run(
        [make, "--no-builtin-rules", "--no-builtin-variables", "-f", "-", "emit"],
        input=makefile,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C"},
    )
    _require(
        completed.returncode == 0,
        f"GNU Make failed for {variant}/{opt_in_state}: {completed.stderr.strip()}",
    )
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        _require(bool(separator) and key not in values, "evaluated Make output is malformed")
        values[key] = value.strip()
    expected_keys = {
        "PRODUCT_PACKAGES",
        "SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS",
        "PRODUCT_SYSTEM_EXT_PROPERTIES",
        "PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG",
    }
    _require(set(values) == expected_keys, "evaluated Make output keys drifted")

    packages = values["PRODUCT_PACKAGES"].split()
    policy_dirs = values["SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS"].split()
    properties = values["PRODUCT_SYSTEM_EXT_PROPERTIES"].split()
    not_debuggable = values["PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG"]
    enabled = opt_in_value == "true" and variant in {"userdebug", "eng"}

    _require(
        packages.count("adb_root") == (1 if enabled else 0),
        "adb_root package selection diverged from the guard",
    )
    _require(
        policy_dirs.count(ADBROOT_POLICY_INSTALL_PATH) == (1 if enabled else 0),
        "adbroot policy selection diverged from the guard",
    )
    _require(
        ("adb_root" in packages) == (ADBROOT_POLICY_INSTALL_PATH in policy_dirs),
        "service and policy authority are not coupled",
    )

    expected_secure = "0" if variant == "eng" else "1"
    secure_values = [
        item.split("=", 1)[1]
        for item in properties
        if item.startswith("ro.adb.secure=")
    ]
    _require(secure_values == [expected_secure], "ro.adb.secure evaluation drifted")
    expected_not_debuggable = (
        "true" if variant != "eng" and opt_in_value != "true" else ""
    )
    _require(
        not_debuggable == expected_not_debuggable,
        "PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG evaluation drifted",
    )

    return {
        "variant": variant,
        "opt_in_state": opt_in_state,
        "opt_in_value": opt_in_value,
        "make_version": make_version,
        "expected_privileged_lane": enabled,
        "service_authority_selected": "adb_root" in packages,
        "policy_authority_selected": ADBROOT_POLICY_INSTALL_PATH in policy_dirs,
        "property_control_authority_selected": enabled,
        "ro_adb_secure": expected_secure,
        "product_not_debuggable_in_userdebug": not_debuggable == "true",
        "malformed_opt_in_failed_closed": opt_in_state != "malformed" or not enabled,
        "passed": True,
    }


def evaluate_repository(
    repo_root: Path,
    *,
    source_commit: str,
    evaluated_commit: str,
    evaluated_tree: str,
    evaluation_kind: str,
    base_commit: str | None = None,
    parent_commits: tuple[str, ...] = (),
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    _require(
        SHA_RE.fullmatch(source_commit) is not None,
        "source commit must be a 40-character lowercase SHA",
    )
    _require(
        SHA_RE.fullmatch(evaluated_commit) is not None,
        "evaluated commit must be a 40-character lowercase SHA",
    )
    _require(
        SHA_RE.fullmatch(evaluated_tree) is not None,
        "evaluated tree must be a 40-character lowercase SHA",
    )
    _require(
        evaluation_kind in {"source_head", "synthetic_merge"},
        "evaluation kind is unsupported",
    )
    if evaluation_kind == "source_head":
        _require(
            evaluated_commit == source_commit,
            "source-head evaluation must run on the exact source commit",
        )
        _require(
            base_commit is None and not parent_commits,
            "source-head evaluation must not claim merge parents",
        )
    else:
        _require(
            base_commit is not None and SHA_RE.fullmatch(base_commit) is not None,
            "synthetic merge requires an exact base commit",
        )
        _require(
            parent_commits == (base_commit, source_commit),
            "synthetic merge parents must be ordered base then source",
        )
        _require(
            evaluated_commit not in parent_commits,
            "synthetic merge commit must differ from both parents",
        )

    inputs: list[InputFile] = []
    common_text, common_input = _regular_text(repo_root, COMMON_PATH)
    common_owner_open_text, common_owner_input = _regular_text(
        repo_root, COMMON_OWNER_OPEN_PATH
    )
    product_text, product_input = _regular_text(repo_root, PRODUCT_PATH)
    manifest_text, manifest_input = _regular_text(repo_root, MANIFEST_PATH)
    inputs.extend((common_input, common_owner_input, product_input, manifest_input))

    common_block, product_block = _security_slices(
        common_text, common_owner_open_text, product_text
    )
    policy_inputs, policy_files = _policy_inputs(repo_root)
    inputs.extend(policy_inputs)
    projects = _manifest_projects(manifest_text)

    make = shutil.which("make")
    _require(
        make is not None,
        "GNU Make is required for evaluated product-graph qualification",
    )
    make_version = _make_version(make)
    matrix = [
        _evaluate_case(
            make=make,
            make_version=make_version,
            common_block=common_block,
            product_block=product_block,
            variant=variant,
            opt_in_state=state,
            opt_in_value=value,
        )
        for variant in SUPPORTED_VARIANTS
        for state, value in OPT_IN_CASES
    ]
    _require(
        len(matrix) == 12 and all(case["passed"] for case in matrix),
        "Android privilege matrix is incomplete",
    )

    negative_cases = [case for case in matrix if not case["expected_privileged_lane"]]
    _require(
        len(negative_cases) == 10,
        "Android privilege matrix negative-case count drifted",
    )
    for case in negative_cases:
        _require(
            not case["service_authority_selected"],
            "negative case selected adb_root service authority",
        )
        _require(
            not case["policy_authority_selected"],
            "negative case selected adbroot policy authority",
        )
        _require(
            not case["property_control_authority_selected"],
            "negative case selected adbroot property authority",
        )

    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "program_revision": PROGRAM_REVISION,
        "repository": REPOSITORY,
        "evaluation_kind": evaluation_kind,
        "source_commit": source_commit,
        "base_commit": base_commit,
        "evaluated_commit": evaluated_commit,
        "evaluated_tree": evaluated_tree,
        "parent_commits": list(parent_commits),
        "make_engine": {"path": make, "version": make_version},
        "inputs": [
            input_file.__dict__
            for input_file in sorted(inputs, key=lambda value: value.path)
        ],
        "manifest_projects": projects,
        "product_inheritance": list(COMMON_OWNER_OPEN_ACTIVE_LINES),
        "policy_files": policy_files,
        "matrix": matrix,
        "matrix_case_count": len(matrix),
        "negative_case_count": len(negative_cases),
        "negative_cases_passed": True,
        "service_policy_property_coupled": True,
        "source_inputs_complete": True,
        "soong_compiled": False,
        "selinux_compiled": False,
        "target_files_built": False,
        "image_built": False,
        "installed": False,
        "physical_device_observed": False,
        "claim_ceiling": CLAIM_CEILING,
        "automatic_redispatch": False,
        "public_release": False,
        "receipt_sha256": "",
    }
    receipt["receipt_sha256"] = _receipt_digest(receipt)
    return receipt


def _git(repo_root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo_root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C"},
    )
    if completed.returncode != 0:
        raise VerificationError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--base-commit")
    parser.add_argument(
        "--evaluation-kind",
        required=True,
        choices=("source_head", "synthetic_merge"),
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    try:
        repo_root = args.repo_root.resolve()
        evaluated_commit = _git(repo_root, "rev-parse", "HEAD^{commit}")
        evaluated_tree = _git(repo_root, "rev-parse", "HEAD^{tree}")
        parents: tuple[str, ...] = ()
        if args.evaluation_kind == "synthetic_merge":
            parents = (
                _git(repo_root, "rev-parse", "HEAD^1^{commit}"),
                _git(repo_root, "rev-parse", "HEAD^2^{commit}"),
            )
        receipt = evaluate_repository(
            repo_root,
            source_commit=args.source_commit,
            base_commit=args.base_commit,
            evaluated_commit=evaluated_commit,
            evaluated_tree=evaluated_tree,
            evaluation_kind=args.evaluation_kind,
            parent_commits=parents,
        )
        encoded = (
            json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False) + "\n"
        )
        if args.output is None:
            sys.stdout.write(encoded)
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded, encoding="utf-8")
        return 0
    except (VerificationError, OSError, subprocess.SubprocessError) as error:
        print(
            f"owner-open adbroot evaluated graph failed: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
