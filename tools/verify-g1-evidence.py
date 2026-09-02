#!/usr/bin/env python3
"""Verify retained G1 evidence packages and emit a non-mutating promotion plan."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
EVIDENCE_TOOLS = SCRIPT_DIR / "evidence"
if str(EVIDENCE_TOOLS) not in sys.path:
    sys.path.insert(0, str(EVIDENCE_TOOLS))

from g1_evidence import (  # noqa: E402
    EvidenceError,
    promotion_plan,
    verify_evidence_directory,
    write_json,
)
from g1_evidence_types import strict_json_file  # noqa: E402


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--gap-register", type=Path)
    parser.add_argument("--current-source-commit")
    parser.add_argument(
        "--expected-subject",
        type=Path,
        help=(
            "detached current base/head/merge subject JSON (or a live report "
            "containing a subject); required for current COMPLETE promotion"
        ),
    )
    parser.add_argument(
        "--attestation",
        type=Path,
        help="out-of-band trusted attestation receipt (required for current COMPLETE packages)",
    )
    parser.add_argument(
        "--attestation-sha256",
        help="raw-byte SHA-256 supplied independently for --attestation",
    )
    parser.add_argument(
        "--attestation-signature",
        type=Path,
        help="detached RSA-SHA256 signature for --attestation",
    )
    parser.add_argument(
        "--attestation-public-key",
        type=Path,
        help="trusted public key for --attestation-signature",
    )
    parser.add_argument(
        "--attestation-public-key-sha256",
        help="raw-byte SHA-256 pin for --attestation-public-key (configured trust root)",
    )
    parser.add_argument("--report", type=Path)
    parser.add_argument("--promotion-plan", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    evidence_dir = (args.evidence_dir or root / "evidence/g1/candidates").resolve()
    gap_register = (args.gap_register or root / "docs/machine/gap-register.v2.json").resolve()
    try:
        expected_subject = None
        if args.expected_subject is not None:
            subject_path = args.expected_subject
            if subject_path.is_symlink():
                raise EvidenceError("expected subject must not be a symlink")
            subject_resolved = subject_path.resolve(strict=True)
            _require_subject_external(subject_path, subject_resolved, root, evidence_dir)
            subject_document = strict_json_file(subject_resolved, "expected subject")
            expected_subject = subject_document.get("subject", subject_document)
            if not isinstance(expected_subject, dict):
                raise EvidenceError("expected subject document must contain an object subject")
        report = verify_evidence_directory(
            evidence_dir,
            gap_register,
            current_source_commit=args.current_source_commit,
            expected_subject=expected_subject,
            attestation_path=args.attestation,
            attestation_sha256=args.attestation_sha256,
            attestation_signature_path=args.attestation_signature,
            attestation_public_key_path=args.attestation_public_key,
            attestation_public_key_sha256=args.attestation_public_key_sha256,
            repository_root=root,
        )
        plan = promotion_plan(report, gap_register)
    except (EvidenceError, OSError, ValueError) as error:
        print(f"G1 evidence verification failed: {error}", file=sys.stderr)
        return 2
    if args.report:
        write_json(args.report, report)
    if args.promotion_plan:
        write_json(args.promotion_plan, plan)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


def _require_subject_external(
    lexical: Path,
    resolved: Path,
    repository_root: Path,
    evidence_dir: Path,
) -> None:
    """Keep the live subject input outside repository-controlled JSON."""

    try:
        root = repository_root.resolve(strict=True)
        evidence_root = evidence_dir.resolve(strict=True)
        if (
            lexical.absolute().is_relative_to(root)
            or resolved.is_relative_to(root)
            or lexical.absolute().is_relative_to(evidence_root)
            or resolved.is_relative_to(evidence_root)
        ):
            raise EvidenceError("expected subject must be outside repository and evidence directories")
    except (OSError, RuntimeError) as error:
        raise EvidenceError(f"cannot validate expected subject path: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
