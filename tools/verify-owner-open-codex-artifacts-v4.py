#!/usr/bin/env python3
"""Verify official Codex artifacts and supported Sigstore bundle encodings.

The selected OpenAI release publishes legacy Cosign ``sign-blob --bundle``
JSON with ``base64Signature``, ``cert`` and ``rekorBundle``. Modern Sigstore
bundles remain accepted through the reviewed v3 verifier. For the legacy form
this adapter strictly cross-binds:

* the outer release archive to its GitHub release digest and contract;
* the Rekor hashedrekord SHA-256 to either that archive or its unique executable
  member, depending on which exact byte object upstream signed;
* the Rekor signature bytes to ``base64Signature``;
* the Rekor public-key bytes to the published certificate;
* the log identity, index, integration time and signed-entry timestamp.

This is structural and byte-level verification. Certificate-chain, identity
policy, Rekor SET and signature cryptography remain explicit later release
gates and are never promoted here.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
V3_PATH = SCRIPT_DIR / "verify-owner-open-codex-artifacts-v3.py"
SPEC = importlib.util.spec_from_file_location(
    "owner_open_codex_artifacts_v3_base", V3_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v3 Codex artifact verifier")
V3 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = V3
SPEC.loader.exec_module(V3)

V2 = V3.V2
BASE = V3.BASE
CONTRACT = V3.CONTRACT
EXPECTED_SCHEMA = V3.EXPECTED_SCHEMA
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LEGACY_TOP_KEYS = {"base64Signature", "cert", "rekorBundle"}
LEGACY_REKOR_KEYS = {"Payload", "SignedEntryTimestamp"}
LEGACY_PAYLOAD_KEYS = {"body", "integratedTime", "logID", "logIndex"}


def canonical_base64(value: Any, label: str, *, minimum: int = 1) -> bytes:
    encoded = BASE.require_string(value, label)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise BASE.VerificationError(f"{label} is not canonical base64") from error
    if len(decoded) < minimum:
        raise BASE.VerificationError(f"{label} is shorter than {minimum} bytes")
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise BASE.VerificationError(f"{label} has a noncanonical base64 encoding")
    return decoded


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise BASE.VerificationError(
            f"{label} keys differ: missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def require_nonnegative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise BASE.VerificationError(f"{label} must be a nonnegative integer")
    return value


def signed_subject_binding(
    rekor_digest: str,
    archive_digest: str,
    archive_member_digest: str | None,
) -> dict[str, Any]:
    if rekor_digest == archive_digest:
        return {
            "archive_digest_bound": True,
            "archive_member_digest_bound": False,
            "signed_subject_kind": "release_archive",
            "signed_subject_sha256": rekor_digest,
            "signed_subject_digest_bound": True,
        }
    if archive_member_digest is not None and rekor_digest == archive_member_digest:
        return {
            "archive_digest_bound": False,
            "archive_member_digest_bound": True,
            "signed_subject_kind": "unique_archive_member",
            "signed_subject_sha256": rekor_digest,
            "signed_subject_digest_bound": True,
        }
    raise BASE.VerificationError(
        "legacy Cosign Rekor entry is not bound to the selected archive digest "
        "or unique archive member digest"
    )


def verify_legacy_cosign_bundle(
    document: dict[str, Any],
    archive_digest: str,
    archive_member_digest: str | None = None,
) -> dict[str, Any]:
    exact_keys(document, LEGACY_TOP_KEYS, "legacy Cosign bundle")
    signature_bytes = canonical_base64(
        document.get("base64Signature"), "legacy Cosign base64Signature", minimum=64
    )
    certificate_text = BASE.require_string(document.get("cert"), "legacy Cosign cert")
    certificate_bytes = certificate_text.encode("utf-8")
    if (
        not certificate_text.startswith("-----BEGIN CERTIFICATE-----\n")
        or "\n-----END CERTIFICATE-----" not in certificate_text
        or len(certificate_bytes) > BASE.MAX_SIGSTORE_BYTES
    ):
        raise BASE.VerificationError("legacy Cosign cert is not a bounded PEM certificate")

    rekor = BASE.require_dict(document.get("rekorBundle"), "legacy Cosign rekorBundle")
    exact_keys(rekor, LEGACY_REKOR_KEYS, "legacy Cosign rekorBundle")
    payload = BASE.require_dict(rekor.get("Payload"), "legacy Cosign Rekor Payload")
    exact_keys(payload, LEGACY_PAYLOAD_KEYS, "legacy Cosign Rekor Payload")
    integrated_time = require_nonnegative_int(
        payload.get("integratedTime"), "legacy Cosign integratedTime"
    )
    if integrated_time == 0:
        raise BASE.VerificationError("legacy Cosign integratedTime must be positive")
    log_index = require_nonnegative_int(payload.get("logIndex"), "legacy Cosign logIndex")
    log_id = BASE.require_string(payload.get("logID"), "legacy Cosign logID")
    if HEX64.fullmatch(log_id) is None:
        raise BASE.VerificationError("legacy Cosign logID must be lowercase SHA-256 hex")
    signed_entry_timestamp = canonical_base64(
        rekor.get("SignedEntryTimestamp"),
        "legacy Cosign SignedEntryTimestamp",
        minimum=64,
    )
    body_bytes = canonical_base64(
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
        digest.get("value"), "legacy Cosign Rekor signed-object digest"
    )
    binding = signed_subject_binding(
        rekor_digest, archive_digest, archive_member_digest
    )

    rekor_signature = BASE.require_dict(
        spec.get("signature"), "legacy Cosign Rekor signature"
    )
    body_signature = canonical_base64(
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
    body_certificate = canonical_base64(
        public_key.get("content"),
        "legacy Cosign Rekor publicKey content",
        minimum=64,
    )
    if body_certificate.rstrip(b"\r\n") != certificate_bytes.rstrip(b"\r\n"):
        raise BASE.VerificationError(
            "legacy Cosign Rekor public key differs from the published certificate"
        )
    return {
        "bundle_encoding": "cosign_legacy_sign_blob_bundle",
        **binding,
        "signature_bytes_cross_bound": True,
        "certificate_bytes_cross_bound": True,
        "rekor_kind": "hashedrekord",
        "rekor_api_version": api_version,
        "rekor_log_id": log_id,
        "rekor_log_index": log_index,
        "rekor_integrated_time": integrated_time,
        "signed_entry_timestamp_bytes": len(signed_entry_timestamp),
        "signature_bytes": len(signature_bytes),
        "certificate_bytes": len(certificate_bytes),
        "cryptographic_signature_verified": False,
        "cryptographic_certificate_chain_verified": False,
        "cryptographic_rekor_set_verified": False,
    }


def verify_sigstore_bundle_v4(
    path: Path,
    specification: dict[str, Any],
    archive_digest: str,
    archive_member_digest: str | None = None,
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
    if set(document) == LEGACY_TOP_KEYS:
        facts = verify_legacy_cosign_bundle(
            document, archive_digest, archive_member_digest
        )
    else:
        facts = V3.verify_sigstore_bundle_v3(path, specification, archive_digest)
        facts.update(
            bundle_encoding="sigstore_bundle",
            archive_member_digest_bound=False,
            signed_subject_kind="release_archive",
            signed_subject_sha256=archive_digest,
            signed_subject_digest_bound=True,
        )
    return {
        "filename": path.name,
        "bytes": observed_size,
        "sha256": observed_sha,
        **facts,
    }


def verify(
    root: Path,
    *,
    asset_dir: Path | None = None,
    release_json: Path | None = None,
    release_asset_json: list[Path] | None = None,
    probe: bool = False,
):
    member_digests: dict[str, str] = {}
    original_archive = BASE.verify_archive
    original_sigstore = BASE.verify_sigstore_bundle

    def archive_adapter(path, specification, destination):
        facts, binary = original_archive(path, specification, destination)
        archive_digest = BASE.require_sha(
            facts.get("archive_sha256"), "verified Codex archive digest"
        )
        member_digest = BASE.require_sha(
            facts.get("archive_member_sha256"),
            "verified Codex archive member digest",
        )
        member_digests[archive_digest] = member_digest
        return facts, binary

    def sigstore_adapter(path, specification, archive_digest):
        return verify_sigstore_bundle_v4(
            path,
            specification,
            archive_digest,
            member_digests.get(archive_digest),
        )

    BASE.verify_archive = archive_adapter
    BASE.verify_sigstore_bundle = sigstore_adapter
    try:
        report = V2.verify(
            root,
            asset_dir=asset_dir,
            release_json=release_json,
            release_asset_json=release_asset_json,
            probe=probe,
        )
    finally:
        BASE.verify_archive = original_archive
        BASE.verify_sigstore_bundle = original_sigstore
    report.facts["sigstore_bundle_encodings"] = (
        "modern_sigstore_bundle_or_exact_legacy_cosign_sign_blob_bundle"
    )
    report.facts["legacy_cosign_signed_object_binding"] = (
        "exact_release_archive_or_verified_unique_archive_member"
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
            "PASS_OWNER_OPEN_CODEX_ARTIFACTS_V4 "
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
