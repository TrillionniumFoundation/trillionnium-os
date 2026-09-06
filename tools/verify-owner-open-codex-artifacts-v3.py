#!/usr/bin/env python3
"""Verify official Codex artifacts with legacy Sigstore media-type compatibility.

The selected OpenAI release bundles contain the required message signature,
archive digest and transparency-log material but omit the optional top-level
``mediaType`` field. This adapter accepts that exact structural form while
retaining all digest, signature-byte and transparency-log checks. It does not
claim cryptographic certificate-chain verification.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "verify-owner-open-codex-artifacts-v2.py"
SPEC = importlib.util.spec_from_file_location(
    "owner_open_codex_artifacts_v2_base", BASE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v2 Codex artifact verifier")
V2 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = V2
SPEC.loader.exec_module(V2)

BASE = V2.BASE
CONTRACT = V2.CONTRACT
EXPECTED_SCHEMA = V2.EXPECTED_SCHEMA


def verify_sigstore_bundle_v3(
    path: Path, specification: dict[str, Any], archive_digest: str
) -> dict[str, Any]:
    expected_size = int(specification["bytes"])
    expected_sha = str(specification["sha256"])
    observed_sha, observed_size = BASE.sha256_file(
        path, BASE.MAX_SIGSTORE_BYTES, "Codex Sigstore bundle"
    )
    if observed_size != expected_size:
        raise BASE.VerificationError("Codex Sigstore bundle size mismatch")
    if observed_sha != expected_sha:
        raise BASE.VerificationError("Codex Sigstore bundle SHA-256 mismatch")
    document = BASE.require_dict(
        BASE.strict_json_file(path, BASE.MAX_SIGSTORE_BYTES, "Codex Sigstore bundle"),
        "Codex Sigstore bundle",
    )
    raw_media_type = document.get("mediaType")
    if raw_media_type is None:
        media_type = "legacy-omitted"
        media_type_declared = False
    else:
        media_type = BASE.require_string(raw_media_type, "Sigstore mediaType")
        if not media_type.startswith("application/vnd.dev.sigstore.bundle.v"):
            raise BASE.VerificationError("Codex Sigstore bundle media type is unsupported")
        media_type_declared = True

    material = BASE.require_dict(
        document.get("verificationMaterial"), "Sigstore verificationMaterial"
    )
    signature = BASE.require_dict(
        document.get("messageSignature"), "Sigstore messageSignature"
    )
    digest = BASE.require_dict(signature.get("messageDigest"), "Sigstore messageDigest")
    algorithm = digest.get("algorithm")
    if algorithm not in {"SHA2_256", "SHA2_256_UNSPECIFIED", "SHA256"}:
        raise BASE.VerificationError(
            f"Sigstore digest algorithm is not SHA-256: {algorithm!r}"
        )
    encoded_digest = BASE.require_string(digest.get("digest"), "Sigstore digest")
    try:
        signed_digest = base64.b64decode(encoded_digest, validate=True)
    except ValueError as error:
        raise BASE.VerificationError("Sigstore digest is not canonical base64") from error
    if signed_digest != bytes.fromhex(archive_digest):
        raise BASE.VerificationError(
            "Sigstore bundle is not bound to the selected archive digest"
        )
    encoded_signature = BASE.require_string(
        signature.get("signature"), "Sigstore signature"
    )
    try:
        signature_bytes = base64.b64decode(encoded_signature, validate=True)
    except ValueError as error:
        raise BASE.VerificationError("Sigstore signature is not canonical base64") from error
    if len(signature_bytes) < 64:
        raise BASE.VerificationError("Sigstore signature is unexpectedly short")
    if not material:
        raise BASE.VerificationError("Sigstore verification material is empty")
    tlog_entries = material.get("tlogEntries")
    if not isinstance(tlog_entries, list) or not tlog_entries:
        raise BASE.VerificationError("Sigstore bundle has no transparency-log entry")
    return {
        "filename": path.name,
        "bytes": observed_size,
        "sha256": observed_sha,
        "media_type": media_type,
        "media_type_declared": media_type_declared,
        "archive_digest_bound": True,
        "transparency_log_entries": len(tlog_entries),
        "cryptographic_signature_verified": False,
    }


def verify(
    root: Path,
    *,
    asset_dir: Path | None = None,
    release_json: Path | None = None,
    release_asset_json: list[Path] | None = None,
    probe: bool = False,
):
    original = BASE.verify_sigstore_bundle
    BASE.verify_sigstore_bundle = verify_sigstore_bundle_v3
    try:
        report = V2.verify(
            root,
            asset_dir=asset_dir,
            release_json=release_json,
            release_asset_json=release_asset_json,
            probe=probe,
        )
    finally:
        BASE.verify_sigstore_bundle = original
    report.facts["sigstore_media_type_compatibility"] = (
        "declared_sigstore_v_media_type_or_legacy_omitted_with_full_message_signature"
    )
    report.facts["cryptographic_sigstore_verification"] = False
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
            "PASS_OWNER_OPEN_CODEX_ARTIFACTS_V3 "
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
