#!/usr/bin/env python3
"""Verify official Codex execution archives and package checksum bindings.

OpenAI's ``codex-package_SHA256SUMS`` binds the aggregate ``codex-package-*``
release assets.  The executable archives selected by Trillionnium OS are the
separate ``codex-*`` single-binary assets and are bound independently by the
GitHub release digest plus their Sigstore bundle.  This adapter makes that
relationship explicit instead of incorrectly comparing a bare archive digest
to a package-archive checksum line.

No authenticated Codex turn, target Root Linux installation, cryptographic
Sigstore certificate-chain validation, Android image, device effect, or public
release is claimed here.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "verify-owner-open-codex-artifacts.py"
SPEC = importlib.util.spec_from_file_location(
    "owner_open_codex_artifacts_v1_base", BASE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v1 Codex artifact verifier")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

CONTRACT = BASE.CONTRACT
EXPECTED_SCHEMA = BASE.EXPECTED_SCHEMA
CHECKSUM_BINDING_KEYS = {
    "role",
    "archive_filename",
    "checksum_filename",
    "url",
    "bytes",
    "sha256",
}


def validate_checksum_bindings(
    contract: dict[str, Any], archives: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    raw_bindings = contract.get("checksum_bindings")
    if not isinstance(raw_bindings, list) or len(raw_bindings) != len(archives):
        raise BASE.VerificationError(
            "checksum_bindings must contain exactly one package binding per selected archive"
        )
    tag = str(contract["upstream"]["release_tag"])
    archives_by_role = {str(item["role"]): item for item in archives}
    bindings: list[dict[str, Any]] = []
    seen_roles: set[str] = set()
    seen_names: set[str] = set()
    for index, raw in enumerate(raw_bindings):
        item = BASE.require_dict(raw, f"checksum_bindings[{index}]")
        if set(item) != CHECKSUM_BINDING_KEYS:
            raise BASE.VerificationError(
                "checksum binding keys differ: "
                f"missing={sorted(CHECKSUM_BINDING_KEYS - set(item))} "
                f"extra={sorted(set(item) - CHECKSUM_BINDING_KEYS)}"
            )
        role = BASE.require_string(item.get("role"), f"checksum binding {index} role")
        if role in seen_roles or role not in archives_by_role:
            raise BASE.VerificationError(
                f"checksum binding role is duplicated or unknown: {role}"
            )
        seen_roles.add(role)
        archive = archives_by_role[role]
        archive_filename = BASE.require_filename(
            item.get("archive_filename"), f"checksum binding {role} archive_filename"
        )
        if archive_filename != archive["filename"]:
            raise BASE.VerificationError(
                f"checksum binding archive filename differs for {role}"
            )
        checksum_filename = BASE.require_filename(
            item.get("checksum_filename"), f"checksum binding {role} checksum_filename"
        )
        expected_name = f"codex-package-{archive['architecture']}.tar.gz"
        if checksum_filename != expected_name:
            raise BASE.VerificationError(
                f"checksum binding package filename differs for {role}: "
                f"{checksum_filename} != {expected_name}"
            )
        if checksum_filename in seen_names:
            raise BASE.VerificationError(
                f"checksum binding package filename is duplicated: {checksum_filename}"
            )
        seen_names.add(checksum_filename)
        BASE.require_size(
            item.get("bytes"), BASE.MAX_ARCHIVE_BYTES, f"checksum binding {role} bytes"
        )
        BASE.require_sha(item.get("sha256"), f"checksum binding {role} sha256")
        expected_url = (
            f"{BASE.OFFICIAL_WEB_PREFIX}releases/download/{tag}/{checksum_filename}"
        )
        if item.get("url") != expected_url:
            raise BASE.VerificationError(
                f"checksum binding URL is not the exact official asset URL: {role}"
            )
        bindings.append(item)
    if seen_roles != set(archives_by_role):
        raise BASE.VerificationError("checksum bindings do not cover every selected archive")
    return bindings


def verify_checksum_list_v2(
    path: Path,
    specification: dict[str, Any],
    bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    expected_size = int(specification["bytes"])
    expected_digest = str(specification["sha256"])
    observed_digest, observed_size = BASE.sha256_file(
        path, BASE.MAX_CHECKSUM_BYTES, "Codex checksum list"
    )
    if observed_size != expected_size:
        raise BASE.VerificationError(
            f"checksum list size mismatch: {observed_size} != {expected_size}"
        )
    if observed_digest != expected_digest:
        raise BASE.VerificationError("checksum list SHA-256 mismatch")
    raw, _metadata = BASE.bounded_real_file(
        path, BASE.MAX_CHECKSUM_BYTES, "Codex checksum list"
    )
    entries = BASE.parse_checksum_list(raw)
    bound: dict[str, str] = {}
    for item in bindings:
        filename = str(item["checksum_filename"])
        expected = str(item["sha256"])
        if entries.get(filename) != expected:
            raise BASE.VerificationError(
                f"checksum list does not bind exact package archive digest: {filename}"
            )
        bound[filename] = expected
    return {
        "filename": path.name,
        "bytes": observed_size,
        "sha256": observed_digest,
        "entry_count": len(entries),
        "selected_package_archives_bound": True,
        "selected_package_archive_digests": bound,
        "selected_execution_archives_use_independent_release_and_sigstore_binding": True,
    }


def verify_package_release_metadata(
    asset_documents: list[Any], bindings: list[dict[str, Any]]
) -> dict[str, Any]:
    assets = BASE.release_asset_map(asset_documents)
    bound: dict[str, Any] = {}
    for specification in bindings:
        filename = str(specification["checksum_filename"])
        metadata = assets.get(filename)
        if metadata is None:
            raise BASE.VerificationError(
                f"upstream release metadata misses package checksum asset: {filename}"
            )
        if metadata.get("state") != "uploaded":
            raise BASE.VerificationError(
                f"upstream package checksum asset is not uploaded: {filename}"
            )
        if metadata.get("size") != specification["bytes"]:
            raise BASE.VerificationError(
                f"upstream package checksum asset size drifted: {filename}"
            )
        if metadata.get("digest") != f"sha256:{specification['sha256']}":
            raise BASE.VerificationError(
                f"upstream package checksum asset digest drifted: {filename}"
            )
        if metadata.get("browser_download_url") != specification["url"]:
            raise BASE.VerificationError(
                f"upstream package checksum asset URL drifted: {filename}"
            )
        asset_id = metadata.get("id")
        if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0:
            raise BASE.VerificationError(
                f"upstream package checksum asset ID malformed: {filename}"
            )
        bound[filename] = {
            "asset_id": asset_id,
            "bytes": metadata["size"],
            "digest": metadata["digest"],
        }
    return bound


def verify(
    root: Path,
    *,
    asset_dir: Path | None = None,
    release_json: Path | None = None,
    release_asset_json: list[Path] | None = None,
    probe: bool = False,
):
    release_asset_json = release_asset_json or []
    try:
        contract = BASE.load_contract(root / CONTRACT)
        archives = BASE.validate_contract(contract)
        bindings = validate_checksum_bindings(contract, archives)
    except (OSError, BASE.VerificationError) as error:
        report = BASE.Report()
        report.errors.append(str(error))
        return report

    original_checksum = BASE.verify_checksum_list
    original_release = BASE.verify_release_metadata

    def checksum_adapter(path, specification, _archives):
        return verify_checksum_list_v2(path, specification, bindings)

    def release_adapter(contract_value, release_document, asset_documents):
        facts = original_release(contract_value, release_document, asset_documents)
        facts["package_checksum_assets"] = verify_package_release_metadata(
            asset_documents, bindings
        )
        facts["package_checksum_metadata_match"] = True
        return facts

    BASE.verify_checksum_list = checksum_adapter
    BASE.verify_release_metadata = release_adapter
    try:
        report = BASE.verify(
            root,
            asset_dir=asset_dir,
            release_json=release_json,
            release_asset_json=release_asset_json,
            probe=probe,
        )
    finally:
        BASE.verify_checksum_list = original_checksum
        BASE.verify_release_metadata = original_release

    report.facts["checksum_binding_mode"] = (
        "package_archives_via_checksum_list;execution_archives_via_release_digest_and_sigstore"
    )
    report.facts["package_checksum_binding_contract_valid"] = True
    if asset_dir is not None and report.ok:
        report.facts["package_checksum_list_cross_check_passed"] = True
    else:
        report.facts.setdefault("package_checksum_list_cross_check_passed", False)
    if release_json is not None and release_asset_json and report.ok:
        report.facts["package_release_metadata_cross_check_passed"] = True
    else:
        report.facts.setdefault("package_release_metadata_cross_check_passed", False)
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--asset-dir", type=Path)
    parser.add_argument("--release-json", type=Path)
    parser.add_argument("--release-assets-json", type=Path, action="append", default=[])
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = verify(
        args.root,
        asset_dir=args.asset_dir,
        release_json=args.release_json,
        release_asset_json=args.release_assets_json,
        probe=args.probe,
    )
    if args.json:
        print(json.dumps(report.value(), ensure_ascii=False, sort_keys=True, indent=2))
    elif report.ok:
        for warning in report.warnings:
            print(f"WARNING: {warning}")
        print(
            "PASS_OWNER_OPEN_CODEX_ARTIFACTS_V2 "
            f"bytes_verified={str(report.facts['artifact_bytes_verified']).lower()} "
            f"package_checksums={str(report.facts['package_checksum_list_cross_check_passed']).lower()} "
            f"probe={str(report.facts['host_cli_identity_probe_passed']).lower()}"
        )
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
