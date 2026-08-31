#!/usr/bin/env python3
"""Verify the single owner-open product entrypoint and install-manifest contract.

This is a source/packaging-shape gate. It cannot promote target Root Linux,
Android target-files, physical-device, fault or release evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tomllib
from typing import Any

CONTRACT = Path("docs/contracts/owner-open-product-entrypoint-v1.json")
EXPECTED_SCHEMA = "org.trillionnium.owner-open.product-entrypoint.v1"
EXPECTED_REVISION = "2026-08-29-r6"
EXPECTED_INSTALL_SCHEMA = "org.trillionnium.owner-open.install-manifest.v1"
ANDROID_OVERLAY = Path("android-integration/working-tree/vendor/trillionnium/config/common.mk")


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.facts: dict[str, Any] = {}

    @property
    def ok(self) -> bool:
        return not self.errors

    def check(self, condition: bool, message: str) -> None:
        if not condition:
            self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def value(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
            "facts": self.facts,
        }


def object_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def require_object(value: Any, label: str, report: Report) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    report.errors.append(f"{label} must be an object")
    return {}


def require_string(value: Any, label: str, report: Report) -> str:
    if isinstance(value, str) and value:
        return value
    report.errors.append(f"{label} must be a non-empty string")
    return ""


def cargo_bins(manifest: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    raw = manifest.get("bin", [])
    if not isinstance(raw, list):
        return result
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        path = item.get("path")
        if isinstance(name, str) and isinstance(path, str):
            result[name] = path
    return result


def verify(root: Path, *, strict_android: bool = False) -> Report:
    report = Report()
    try:
        contract = object_json(root / CONTRACT)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        report.errors.append(f"cannot parse product-entrypoint contract: {error}")
        return report

    report.check(contract.get("schema") == EXPECTED_SCHEMA, "product-entrypoint schema is invalid")
    report.check(
        contract.get("revision") == EXPECTED_REVISION,
        f"product-entrypoint revision must be {EXPECTED_REVISION}",
    )
    report.check(contract.get("automatic_redispatch") is False, "automatic_redispatch must be false")
    report.check(contract.get("public_release") is False, "source contract must not claim public release")

    manifest_rel = Path(require_string(contract.get("source_manifest"), "source_manifest", report))
    manifest_path = root / manifest_rel
    if not manifest_path.is_file():
        report.errors.append(f"owner-open Cargo manifest is absent: {manifest_rel}")
        return report
    try:
        with manifest_path.open("rb") as handle:
            manifest = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        report.errors.append(f"cannot parse owner-open Cargo manifest: {error}")
        return report
    package = manifest.get("package", {})
    report.check(
        isinstance(package, dict) and package.get("autobins") is False,
        "owner-open package must disable Cargo autobin discovery",
    )
    bins = cargo_bins(manifest)

    product = require_object(contract.get("product_entrypoint"), "product_entrypoint", report)
    product_bin = require_string(product.get("cargo_bin"), "product_entrypoint.cargo_bin", report)
    product_source = require_string(product.get("source_path"), "product_entrypoint.source_path", report)
    report.check(product.get("role") == "product_entrypoint", "product entrypoint role is invalid")
    report.check(
        bins.get(product_bin) == product_source,
        f"product Cargo bin does not bind the contracted source: {product_bin}={product_source}",
    )
    product_source_path = manifest_path.parent / product_source
    report.check(product_source_path.is_file(), f"product source is absent: {product_source_path.relative_to(root)}")

    internal_children = contract.get("internal_children", [])
    report.check(
        isinstance(internal_children, list) and len(internal_children) == 1,
        "product contract must contain exactly one internal execution core",
    )
    internal_bin = ""
    if isinstance(internal_children, list) and len(internal_children) == 1:
        child = require_object(internal_children[0], "internal child", report)
        internal_bin = require_string(child.get("cargo_bin"), "internal child cargo_bin", report)
        internal_source = require_string(child.get("source_path"), "internal child source_path", report)
        report.check(child.get("role") == "internal_execution_core", "internal child role is invalid")
        report.check(child.get("direct_product_install_entrypoint") is False, "internal core cannot be a product entrypoint")
        report.check(
            bins.get(internal_bin) == internal_source,
            f"internal Cargo bin does not bind the contracted source: {internal_bin}={internal_source}",
        )
        report.check(
            (manifest_path.parent / internal_source).is_file(),
            f"internal child source is absent: {manifest_path.parent / internal_source}",
        )

    non_product = contract.get("non_product_binaries", [])
    report.check(
        isinstance(non_product, list) and bool(non_product),
        "product contract must identify non-product binaries",
    )
    forbidden_bins: list[str] = []
    if isinstance(non_product, list):
        for index, raw in enumerate(non_product):
            item = require_object(raw, f"non_product_binaries[{index}]", report)
            name = require_string(item.get("cargo_bin"), f"non_product_binaries[{index}].cargo_bin", report)
            source = require_string(item.get("source_path"), f"non_product_binaries[{index}].source_path", report)
            marker = require_string(item.get("expected_marker"), f"non_product_binaries[{index}].expected_marker", report)
            report.check(item.get("forbidden_as_product_entrypoint") is True, f"{name} must be forbidden as product entrypoint")
            report.check(item.get("forbidden_android_product_package") is True, f"{name} must be forbidden in Android product inventory")
            report.check(bins.get(name) == source, f"non-product Cargo bin drifted: {name}={source}")
            source_path = manifest_path.parent / source
            report.check(source_path.is_file(), f"non-product source is absent: {source_path}")
            if source_path.is_file():
                report.check(marker in source_path.read_text(encoding="utf-8"), f"non-product marker is absent from {source_path}")
            forbidden_bins.append(name)

    options_path = manifest_path.parent / "src/bin/r5_transport_host/entry/options.rs"
    report.check(options_path.is_file(), "selected transport options source is absent")
    options_text = options_path.read_text(encoding="utf-8") if options_path.is_file() else ""
    required_cli = product.get("required_cli", [])
    report.check(isinstance(required_cli, list) and required_cli, "required_cli must be a non-empty list")
    if isinstance(required_cli, list):
        for option in required_cli:
            report.check(isinstance(option, str) and option in options_text, f"required product CLI token is absent: {option}")
    transport_options = product.get("transport_options", [])
    report.check(isinstance(transport_options, list) and transport_options, "transport_options must be non-empty")
    if isinstance(transport_options, list):
        for option in transport_options:
            report.check(isinstance(option, str) and option in options_text, f"transport option is absent: {option}")
    report.check(
        isinstance(internal_bin, str) and f'path.set_file_name("{internal_bin}")' in options_text,
        "default transport child does not resolve to the contracted sibling core",
    )
    report.check(product.get("default_internal_child") == internal_bin, "product default child identity drifted")

    template_rel = Path(
        require_string(contract.get("install_manifest_template"), "install_manifest_template", report)
    )
    template_path = root / template_rel
    report.check(template_path.is_file(), f"install manifest template is absent: {template_rel}")
    template: dict[str, Any] = {}
    if template_path.is_file():
        try:
            template = object_json(template_path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            report.errors.append(f"cannot parse install manifest template: {error}")
        else:
            report.check(template.get("schema") == EXPECTED_INSTALL_SCHEMA, "install manifest schema is invalid")
            report.check(template.get("status") == "UNMATERIALIZED_TEMPLATE", "install manifest must remain an explicit template")
            template_product = require_object(template.get("product_entrypoint"), "install product_entrypoint", report)
            report.check(template_product.get("cargo_bin") == product_bin, "install template product bin drifted")
            template_children = template.get("internal_children", [])
            report.check(
                isinstance(template_children, list)
                and len(template_children) == 1
                and isinstance(template_children[0], dict)
                and template_children[0].get("cargo_bin") == internal_bin,
                "install template internal child drifted",
            )
            template_forbidden = template.get("forbidden_installed_binaries", [])
            template_forbidden_bins = {
                str(item.get("cargo_bin"))
                for item in template_forbidden
                if isinstance(item, dict)
            } if isinstance(template_forbidden, list) else set()
            report.check(set(forbidden_bins) <= template_forbidden_bins, "install template omits a forbidden product binary")
            required_sections = {
                "source",
                "product_entrypoint",
                "internal_children",
                "provider",
                "identity",
                "namespaces",
                "cgroup",
                "sockets",
                "stores",
                "selinux",
                "restart",
                "emergency_stop",
                "evidence",
            }
            report.check(required_sections <= set(template), "install manifest template omits required deployment sections")
            report.check(template.get("automatic_redispatch") is False, "install template must disable automatic redispatch")
            report.check(template.get("public_release") is False, "install template must not claim public release")

    android = require_object(contract.get("android"), "android", report)
    required_module = require_string(android.get("required_module"), "android.required_module", report)
    required_internal = require_string(android.get("required_internal_module"), "android.required_internal_module", report)
    forbidden_modules = android.get("forbidden_modules", [])
    report.check(
        isinstance(forbidden_modules, list) and set(forbidden_bins) <= {str(value) for value in forbidden_modules},
        "Android contract omits a forbidden non-product binary",
    )
    overlay_path = root / ANDROID_OVERLAY
    android_installed = False
    internal_installed = False
    forbidden_hits: list[str] = []
    if overlay_path.is_file():
        overlay = overlay_path.read_text(encoding="utf-8")
        android_installed = required_module in overlay
        internal_installed = required_internal in overlay
        forbidden_hits = sorted(
            value for value in {str(item) for item in forbidden_modules if isinstance(item, str)}
            if value in overlay
        )
        if not android_installed or not internal_installed or forbidden_hits:
            message = (
                "Android product entrypoint is not materialized exactly: "
                f"product={android_installed} internal={internal_installed} forbidden={forbidden_hits}"
            )
            if strict_android:
                report.errors.append(message)
            else:
                report.warn(message)
    else:
        report.warn(f"Android audit overlay is absent: {ANDROID_OVERLAY}")

    report.facts.update(
        {
            "revision": contract.get("revision"),
            "cargo_bins": bins,
            "product_entrypoint": product_bin,
            "internal_execution_core": internal_bin,
            "forbidden_product_binaries": sorted(forbidden_bins),
            "install_manifest_template": str(template_rel),
            "source_entrypoint_selected": report.ok,
            "android_product_entrypoint_present": android_installed,
            "android_internal_core_present": internal_installed,
            "android_forbidden_product_hits": forbidden_hits,
            "target_install_qualified": False,
            "claim_ceiling": contract.get("claim_ceiling"),
            "public_release": False,
        }
    )
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--strict-android", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = verify(args.root.resolve(), strict_android=args.strict_android)
    if args.json:
        print(json.dumps(report.value(), indent=2, sort_keys=True))
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARN: {warning}", file=sys.stderr)
        if report.ok:
            print("owner-open product entrypoint source contract verified")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
