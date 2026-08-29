#!/usr/bin/env python3
"""Verify official Codex artifacts with legacy Cosign certificate encodings.

The selected OpenAI bundles use the legacy Cosign sign-blob shape and encode
``cert`` as canonical base64 certificate bytes.  Some older producers emit PEM
text directly.  This adapter accepts exactly those two encodings and then
requires the resulting certificate bytes to equal Rekor ``publicKey.content``.
All archive, signature, Rekor and package-checksum bindings from v4 remain
mandatory. Cryptographic trust-chain verification remains false.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
V4_PATH = SCRIPT_DIR / "verify-owner-open-codex-artifacts-v4.py"
SPEC = importlib.util.spec_from_file_location(
    "owner_open_codex_artifacts_v4_base", V4_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v4 Codex artifact verifier")
V4 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = V4
SPEC.loader.exec_module(V4)

BASE = V4.BASE
CONTRACT = V4.CONTRACT
EXPECTED_SCHEMA = V4.EXPECTED_SCHEMA


def certificate_bytes(value: Any) -> tuple[bytes, str]:
    text = BASE.require_string(value, "legacy Cosign cert")
    if text.startswith("-----BEGIN CERTIFICATE-----\n"):
        raw = text.encode("utf-8")
        if "\n-----END CERTIFICATE-----" not in text:
            raise BASE.VerificationError("legacy Cosign PEM certificate is incomplete")
        encoding = "pem_text"
    else:
        raw = V4.canonical_base64(value, "legacy Cosign cert", minimum=64)
        if raw.startswith(b"-----BEGIN CERTIFICATE-----\n"):
            if b"\n-----END CERTIFICATE-----" not in raw:
                raise BASE.VerificationError(
                    "legacy Cosign base64 PEM certificate is incomplete"
                )
            encoding = "base64_pem"
        elif raw[0] == 0x30:
            encoding = "base64_der"
        else:
            raise BASE.VerificationError(
                "legacy Cosign cert is neither PEM text nor canonical base64 certificate bytes"
            )
    if len(raw) > BASE.MAX_SIGSTORE_BYTES:
        raise BASE.VerificationError("legacy Cosign certificate exceeds its byte ceiling")
    return raw, encoding


def verify_legacy_cosign_bundle_v5(
    document: dict[str, Any], archive_digest: str
) -> dict[str, Any]:
    V4.exact_keys(document, V4.LEGACY_TOP_KEYS, "legacy Cosign bundle")
    signature_bytes = V4.canonical_base64(
        document.get("base64Signature"), "legacy Cosign base64Signature", minimum=64
    )
    published_certificate, certificate_encoding = certificate_bytes(document.get("cert"))

    rekor = BASE.require_dict(document.get("rekorBundle"), "legacy Cosign rekorBundle")
    V4.exact_keys(rekor, V4.LEGACY_REKOR_KEYS, "legacy Cosign rekorBundle")
    payload = BASE.require_dict(rekor.get("Payload"), "legacy Cosign Rekor Payload")
    V4.exact_keys(payload, V4.LEGACY_PAYLOAD_KEYS, "legacy Cosign Rekor Payload")
    integrated_time = V4.require_nonnegative_int(
        payload.get("integratedTime"), "legacy Cosign integratedTime"
    )
    if integrated_time == 0:
        raise BASE.VerificationError("legacy Cosign integratedTime must be positive")
    log_index = V4.require_nonnegative_int(
        payload.get("logIndex"), "legacy Cosign logIndex"
    )
    log_id = BASE.require_string(payload.get("logID"), "legacy Cosign logID")
    if V4.HEX64.fullmatch(log_id) is None:
        raise BASE.VerificationError("legacy Cosign logID must be lowercase SHA-256 hex")
    signed_entry_timestamp = V4.canonical_base64(
        rekor.get("SignedEntryTimestamp"),
        "legacy Cosign SignedEntryTimestamp",
        minimum=64,
    )
    body_bytes = V4.canonical_base64(
        payload.get("body"), "legacy Cosign Rekor body", minimum=32
    )
    body = BASE.require_dict(
        BASE.strict_json_bytes(body_bytes, "legacy Cosign Rekor body"),
        "legacy Cosign Rekor body",
    )
    api_version = BASE.require_string(body.get("apiVersion"), "Rekor apiVersion")
    if api_version != "0.0.1":
        raise BASE.VerificationError(
            f"legacy Cosign Rekor apiVersion is unsupported: {api_version!r}"
        )
    if body.get("kind") != "hashedrekord":
        raise BASE.VerificationError("legacy Cosign Rekor kind must be hashedrekord")
    spec = BASE.require_dict(body.get("spec"), "legacy Cosign Rekor spec")
    data = BASE.require_dict(spec.get("data"), "legacy Cosign Rekor data")
    digest = BASE.require_dict(data.get("hash"), "legacy Cosign Rekor data hash")
    algorithm = BASE.require_string(
        digest.get("algorithm"), "legacy Cosign Rekor hash algorithm"
    ).lower()
    if algorithm not in {"sha256", "sha2_256"}:
        raise BASE.VerificationError(
            f"legacy Cosign Rekor hash algorithm is not SHA-256: {algorithm!r}"
        )
    rekor_digest = BASE.require_sha(
        digest.get("value"), "legacy Cosign Rekor archive digest"
    )
    if rekor_digest != archive_digest:
        raise BASE.VerificationError(
            "legacy Cosign Rekor entry is not bound to the selected archive digest"
        )

    rekor_signature = BASE.require_dict(
        spec.get("signature"), "legacy Cosign Rekor signature"
    )
    body_signature = V4.canonical_base64(
        rekor_signature.get("content"),
        "legacy Cosign Rekor signature content",
        minimum=64,
    )
    if body_signature != signature_bytes:
        raise BASE.VerificationError(
            "legacy Cosign Rekor signature differs from base64Signature"
        )
    public_key = BASE.require_dict(
        rekor_signature.get("publicKey"), "legacy Cosign Rekor publicKey"
    )
    rekor_certificate = V4.canonical_base64(
        public_key.get("content"),
        "legacy Cosign Rekor publicKey content",
        minimum=64,
    )
    if rekor_certificate.rstrip(b"\r\n") != published_certificate.rstrip(b"\r\n"):
        raise BASE.VerificationError(
            "legacy Cosign Rekor public key differs from the published certificate"
        )
    return {
        "bundle_encoding": "cosign_legacy_sign_blob_bundle",
        "certificate_encoding": certificate_encoding,
        "archive_digest_bound": True,
        "signature_bytes_cross_bound": True,
        "certificate_bytes_cross_bound": True,
        "rekor_kind": "hashedrekord",
        "rekor_api_version": api_version,
        "rekor_log_id": log_id,
        "rekor_log_index": log_index,
        "rekor_integrated_time": integrated_time,
        "signed_entry_timestamp_bytes": len(signed_entry_timestamp),
        "signature_bytes": len(signature_bytes),
        "certificate_bytes": len(published_certificate),
        "cryptographic_signature_verified": False,
        "cryptographic_certificate_chain_verified": False,
        "cryptographic_rekor_set_verified": False,
    }


def verify(
    root: Path,
    *,
    asset_dir: Path | None = None,
    release_json: Path | None = None,
    release_asset_json: list[Path] | None = None,
    probe: bool = False,
):
    original = V4.verify_legacy_cosign_bundle
    V4.verify_legacy_cosign_bundle = verify_legacy_cosign_bundle_v5
    try:
        report = V4.verify(
            root,
            asset_dir=asset_dir,
            release_json=release_json,
            release_asset_json=release_asset_json,
            probe=probe,
        )
    finally:
        V4.verify_legacy_cosign_bundle = original
    report.facts["legacy_cosign_certificate_encodings"] = (
        "pem_text_or_canonical_base64_pem_or_der"
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
            "PASS_OWNER_OPEN_CODEX_ARTIFACTS_V5 "
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
