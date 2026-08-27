#!/usr/bin/env python3
"""Fail closed if retired Agent execution features enter the production graph."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tomllib


SCHEMA = "org.trillionnium.production-agent-feature-gate.v2"
FORBIDDEN_FEATURES = (
    "legacy-plan-conformance",
    "legacy-plan-execution",
    "legacy-plan-methods",
    "legacy-authority-effects",
    "dev-conformance-fault-hook",
    "dev-overrides",
    "development-compatibility-lane",
)
PACKAGE_FEATURES = {
    "apps/trillionniumd/Cargo.toml": {
        "default": [],
        "dev-conformance-fault-hook": [
            "trillionnium-tool-runtime/dev-conformance-fault-hook"
        ],
        "p0-launch-package-device-conformance": [
            "trillionnium-os-types/p0-launch-package-device-conformance",
            "trillionnium-tool-runtime/p0-launch-package-provider-conformance",
        ],
        "legacy-plan-conformance": [
            "trillionnium-agent-api-uds/legacy-plan-methods",
            "trillionnium-dbus/legacy-plan-execution",
            "trillionnium-tool-runtime/legacy-authority-effects",
        ],
    },
    "crates/trillionnium-agent-api-uds/Cargo.toml": {
        "default": [],
        "legacy-plan-methods": [],
    },
    "crates/trillionnium-dbus/Cargo.toml": {
        "default": [],
        "legacy-plan-execution": [
            "trillionnium-tool-runtime/legacy-authority-effects"
        ],
    },
    "crates/trillionnium-tool-runtime/Cargo.toml": {
        "default": [],
        "dev-conformance-fault-hook": ["legacy-authority-effects"],
        "legacy-authority-effects": ["dep:p256"],
    },
    "crates/trillionnium-agent-direct-tools/Cargo.toml": {
        "default": [],
        "dev-overrides": [],
        "development-compatibility-lane": ["dev-overrides"],
        "trusted-context-hotpath": [],
        "production-durable-hotpath": ["trusted-context-hotpath"],
        "device-launch-package-conformance": [
            "trillionnium-os-types/p0-launch-package-device-conformance"
        ],
    },
}
WORKSPACE_PACKAGES = {
    "apps/trillionniumd": "trillionniumd",
    "crates/trillionnium-os-types": "trillionnium-os-types",
    "crates/trillionnium-agent-api-uds": "trillionnium-agent-api-uds",
    "crates/trillionnium-task-registry": "trillionnium-task-registry",
    "crates/trillionnium-policy-system": "trillionnium-policy-system",
    "crates/trillionnium-audit-sqlite": "trillionnium-audit-sqlite",
    "crates/trillionnium-privilege-broker-protocol": (
        "trillionnium-privilege-broker-protocol"
    ),
    "crates/trillionnium-tool-runtime": "trillionnium-tool-runtime",
    "crates/trillionnium-agent-direct-tools": "trillionnium-agent-direct-tools",
    "crates/trillionnium-shell-exec": "trillionnium-shell-exec",
    "crates/trillionnium-dbus": "trillionnium-dbus",
    "apps/trillionnium-agent-privilege-broker": (
        "trillionnium-agent-privilege-broker"
    ),
    "apps/trillionnium-agent-stdio-proxy": "trillionnium-agent-stdio-proxy",
}
DEFAULT_PACKAGES = (
    "apps/trillionniumd",
    "apps/trillionnium-agent-privilege-broker",
    "apps/trillionnium-agent-stdio-proxy",
    "crates/trillionnium-agent-direct-tools",
)
PRODUCTION_PACKAGES = (
    "trillionnium-agent-direct-tools",
    "trillionniumd",
)
PRODUCTION_FEATURES = (
    "trillionnium-agent-direct-tools/production-durable-hotpath",
)
RETIRED_PATHS = (
    Path("apps/trillionnium-shell"),
    Path("packaging/mobian"),
)
RETIRED_PRODUCT_TOKENS = (
    "trillionnium-shell",
    "shell-ui",
    "mobian",
)


class GateError(RuntimeError):
    pass


def regular_file(path: Path, maximum: int) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    metadata = os.lstat(absolute)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or not 1 <= metadata.st_size <= maximum
    ):
        raise GateError(f"unsafe_regular_file:{path}")
    return absolute.read_bytes()


def load_toml(path: Path) -> dict[str, object]:
    try:
        return tomllib.loads(regular_file(path, 1024 * 1024).decode("utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise GateError(f"invalid_cargo_manifest:{path}") from error


def validate_declared_features(workspace: Path) -> None:
    for relative, required in PACKAGE_FEATURES.items():
        manifest = load_toml(workspace / relative)
        features = manifest.get("features")
        if not isinstance(features, dict):
            raise GateError(f"missing_feature_table:{relative}")
        for name, expected in required.items():
            actual = features.get(name)
            if actual != expected:
                raise GateError(f"feature_contract_drift:{relative}:{name}")


def validate_workspace_packages(workspace: Path) -> list[Path]:
    root_manifest = load_toml(workspace / "Cargo.toml")
    workspace_table = root_manifest.get("workspace")
    if not isinstance(workspace_table, dict):
        raise GateError("workspace_table_missing")
    members = workspace_table.get("members")
    if members != list(WORKSPACE_PACKAGES):
        raise GateError("workspace_member_contract_drift")
    default_members = workspace_table.get("default-members")
    if default_members != list(DEFAULT_PACKAGES):
        raise GateError("workspace_default_member_contract_drift")

    manifests = [Path("Cargo.toml")]
    for relative, expected_name in WORKSPACE_PACKAGES.items():
        manifest_relative = Path(relative) / "Cargo.toml"
        manifest = load_toml(workspace / manifest_relative)
        package = manifest.get("package")
        if not isinstance(package, dict) or package.get("name") != expected_name:
            raise GateError(f"workspace_package_name_drift:{relative}")
        manifests.append(manifest_relative)
    return manifests


def require_absent(workspace: Path, relative: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(workspace / relative)))
    try:
        os.lstat(absolute)
    except FileNotFoundError:
        return
    except OSError as error:
        raise GateError(f"retired_path_absence_unverified:{relative}") from error
    raise GateError(f"retired_path_present:{relative}")


def reject_retired_tokens(
    workspace: Path, relative_paths: list[Path], root_builder_source: str
) -> None:
    sources = [("root_builder", root_builder_source)]
    for relative in relative_paths:
        sources.append(
            (
                relative.as_posix(),
                regular_file(workspace / relative, 1024 * 1024).decode("utf-8"),
            )
        )
    for source_name, source in sources:
        lowered = source.lower()
        for token in RETIRED_PRODUCT_TOKENS:
            # Treat hyphenated package names as one identifier.  This keeps
            # the retired `trillionnium-shell` package token rejected while
            # allowing the current, distinct `trillionnium-shell-exec`
            # workspace member to be audited normally.
            if re.search(
                rf"(?<![a-z0-9_-]){re.escape(token)}(?![a-z0-9_-])",
                lowered,
            ):
                raise GateError(f"retired_product_token:{source_name}:{token}")


def validate_root_builder(workspace: Path) -> str:
    relative = Path(
        "crates/trillionnium-agent-direct-tools/tools/build-root-linux-arm64.sh"
    )
    source_bytes = regular_file(workspace / relative, 1024 * 1024)
    source = source_bytes.decode("utf-8")
    if source.count("--no-default-features") != 1:
        raise GateError("root_builder_no_default_features_drift")
    production_feature = (
        "--features trillionnium-agent-direct-tools/production-durable-hotpath"
    )
    if source.count(production_feature) != 1:
        raise GateError("root_builder_durable_hotpath_feature_drift")
    if "--all-features" in source:
        raise GateError("root_builder_all_features_denied")
    if any(feature in source for feature in FORBIDDEN_FEATURES):
        raise GateError("root_builder_legacy_feature_denied")
    packages = re.findall(r"(?m)^\s+-p\s+([a-z0-9_-]+)\s*(?:\\)?$", source)
    if packages != list(PRODUCTION_PACKAGES):
        raise GateError("root_builder_package_contract_drift")
    if not re.search(
        r'"\$CARGO" build[\s\\]+.*--release[\s\\]+.*--locked[\s\\]+'
        r'.*--offline[\s\\]+.*--no-default-features[\s\\]+',
        source,
        re.DOTALL,
    ):
        raise GateError("root_builder_production_command_drift")
    return source


def cargo_feature_graph(workspace: Path, cargo: Path) -> str:
    command = [
        os.fspath(cargo),
        "tree",
        "--locked",
        "--offline",
        "-e",
        "normal,build,features",
    ]
    for package in PRODUCTION_PACKAGES:
        command.extend(("-p", package))
    command.extend(
        (
            "--no-default-features",
            "--features",
            ",".join(PRODUCTION_FEATURES),
        )
    )
    completed = subprocess.run(
        command,
        cwd=workspace,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        raise GateError("cargo_feature_graph_failed")
    return completed.stdout


def check(workspace: Path, cargo: Path) -> dict[str, object]:
    root = Path(os.path.abspath(os.fspath(workspace)))
    if not (root / "Cargo.toml").is_file():
        raise GateError("workspace_root_invalid")
    manifests = validate_workspace_packages(root)
    validate_declared_features(root)
    root_builder_source = validate_root_builder(root)
    for retired in RETIRED_PATHS:
        require_absent(root, retired)
    reject_retired_tokens(root, manifests, root_builder_source)
    graph = cargo_feature_graph(root, cargo)
    activated = sorted(feature for feature in FORBIDDEN_FEATURES if feature in graph)
    if activated:
        raise GateError("production_feature_activated:" + ",".join(activated))
    return {
        "schema": SCHEMA,
        "decision": "PASS_PRODUCTION_AGENT_FEATURE_GRAPH",
        "package": "trillionniumd",
        "packages": [
            *PRODUCTION_PACKAGES,
        ],
        "selected_features": list(PRODUCTION_FEATURES),
        "cargo_edges": ["normal", "build", "features"],
        "no_default_features": True,
        "forbidden_features": list(FORBIDDEN_FEATURES),
        "activated_forbidden_features": [],
        "retired_paths_absent": [path.as_posix() for path in RETIRED_PATHS],
        "retired_product_tokens_absent": list(RETIRED_PRODUCT_TOKENS),
        "legacy_execution_compiled": False,
        "public_release_allowed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, default=Path("cargo"))
    args = parser.parse_args()
    try:
        result = check(args.workspace, args.cargo)
    except Exception as error:
        result = {
            "schema": SCHEMA,
            "decision": "HOLD_PRODUCTION_AGENT_FEATURE_GRAPH",
            "failures": [str(error)],
            "legacy_execution_compiled": None,
            "public_release_allowed": False,
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["decision"].startswith("PASS_") else 2


if __name__ == "__main__":
    raise SystemExit(main())
