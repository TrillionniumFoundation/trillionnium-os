from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_TOOLS = ROOT / "tools" / "evidence"
if str(EVIDENCE_TOOLS) not in sys.path:
    sys.path.insert(0, str(EVIDENCE_TOOLS))

from g1_evidence import (  # noqa: E402
    CLASS_CLAIM_CEILING,
    CLASS_NEGATIVE_CLAIMS,
    CLASS_REQUIRED_TRUE,
    EvidenceError,
    load_gap_specs,
    package_id,
    promotion_plan,
    sha256_bytes,
    strict_json_bytes,
    validate_package,
    verify_evidence_directory,
    write_json,
)

GAP_REGISTER = ROOT / "docs" / "machine" / "gap-register.v2.json"
CANDIDATE = ROOT / "evidence" / "g1" / "candidates" / "pr34-l1-source-qualification.json"
NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)
SOURCE_COMMIT = "3f8fc683a90804ba39c731ad6790717758da381b"


class G1EvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gaps = load_gap_specs(GAP_REGISTER)
        self.base = json.loads(CANDIDATE.read_text(encoding="utf-8"))

    @staticmethod
    def resign(package: dict) -> dict:
        package["package_id"] = ""
        package["package_id"] = package_id(package)
        return package

    def l2_package(self) -> dict:
        package = deepcopy(self.base)
        package.update(
            level="L2",
            evidence_class="installed_rootlinux",
            gaps=["GAP-INSTALLED-CODEX-001", "GAP-ROOTLINUX-PLACEMENT-001"],
            observations={
                **{field: True for field in CLASS_REQUIRED_TRUE["installed_rootlinux"]},
                "automatic_redispatch_count": 0,
                "installed_manifest_sha256": "1" * 64,
            },
            claim_ceiling=CLASS_CLAIM_CEILING["installed_rootlinux"],
            negative_claims=sorted(CLASS_NEGATIVE_CLAIMS["installed_rootlinux"]),
        )
        package["lineage"] = {
            "parent_package_ids": [self.base["package_id"]],
            "predecessor_source_commit": self.base["lineage"]["predecessor_source_commit"],
        }
        package["roles"]["operator"] = {
            "principal": "target-operator",
            "identity_provider": "hardware-attestation",
            "evidence_id": "installed-rootlinux-run-1",
        }
        package["authorization"] = {
            "status": "APPROVED",
            "authority": "owner_device_authority",
            "scope": "installed Root Linux qualification only",
            "expires_at": package["expires_at"],
            "revoked": False,
            "evidence_id": "installed-rootlinux-authorization-1",
        }
        return self.resign(package)

    @staticmethod
    def write_trusted_attestation(
        path: Path, packages: list[dict]
    ) -> tuple[Path, str, Path, Path, str]:
        """Create a test-only signed receipt and return its pinned inputs."""
        receipt = {
            "schema": "org.trillionnium.g1.evidence-attestation.v1",
            "version": "1",
            "package_ids": sorted(package["package_id"] for package in packages),
            "source_commit": SOURCE_COMMIT,
            "authority": "test-independent-review",
            "verification_method": "test-rsa-signature",
            "trust_root": "g1-attestation-root-20260902",
            "signature_algorithm": "rsa-sha256",
            "independent_verification": True,
            "verified_at": "2026-09-01T00:00:00Z",
            "expires_at": "2026-12-31T00:00:00Z",
            "evidence_ids": ["test-attestation-1"],
        }
        content = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        path.write_bytes(content)
        private_key_path = path.with_suffix(".private.pem")
        public_key_path = path.with_suffix(".public.pem")
        signature_path = path.with_suffix(".sig")
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private_key_path),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            [
                "openssl",
                "rsa",
                "-in",
                str(private_key_path),
                "-pubout",
                "-out",
                str(public_key_path),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private_key_path),
                "-out",
                str(signature_path),
                str(path),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return (
            path,
            sha256_bytes(content),
            signature_path,
            public_key_path,
            sha256_bytes(public_key_path.read_bytes()),
        )

    def test_checked_in_l1_package_is_valid_and_promotable_for_bound_source(self) -> None:
        assessment = validate_package(
            deepcopy(self.base),
            self.gaps,
            current_source_commit=SOURCE_COMMIT,
            now=NOW,
        )
        self.assertTrue(assessment.promotable_for_current_source)
        self.assertEqual(assessment.evidence_class, "source_qualification")
        self.assertEqual(
            assessment.gaps,
            ("GAP-DOC-SINGLE-TRUTH-001", "GAP-GOVERNANCE-001"),
        )

    def test_valid_historical_package_does_not_promote_another_head(self) -> None:
        assessment = validate_package(
            deepcopy(self.base),
            self.gaps,
            current_source_commit="f" * 40,
            now=NOW,
        )
        self.assertTrue(assessment.structurally_valid)
        self.assertFalse(assessment.promotable_for_current_source)

    def test_current_complete_package_requires_out_of_band_attestation(self) -> None:
        package = deepcopy(self.base)
        current_head = "a" * 40
        package["source"]["commit"] = current_head
        self.resign(package)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_json(path / "forged-current.json", package)
            with self.assertRaisesRegex(EvidenceError, "out-of-band trusted attestation"):
                verify_evidence_directory(
                    path,
                    GAP_REGISTER,
                    current_source_commit=current_head,
                    now=NOW,
                )

    def test_current_complete_package_requires_detached_signature(self) -> None:
        package = deepcopy(self.base)
        current_head = "b" * 40
        package["source"]["commit"] = current_head
        self.resign(package)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_json(path / "current.json", package)
            receipt = {
                "schema": "org.trillionnium.g1.evidence-attestation.v1",
                "version": "1",
                "package_ids": [package["package_id"]],
                "source_commit": current_head,
                "authority": "test-independent-review",
                "verification_method": "test-rsa-signature",
                "trust_root": "g1-attestation-root-20260902",
                "signature_algorithm": "rsa-sha256",
                "independent_verification": True,
                "verified_at": "2026-09-01T00:00:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
                "evidence_ids": ["test-attestation-1"],
            }
            attestation_path = Path(temp).parent / "g1-attestation-no-signature.json"
            raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            attestation_path.write_bytes(raw)
            with self.assertRaisesRegex(EvidenceError, "detached trusted signature"):
                verify_evidence_directory(
                    path,
                    GAP_REGISTER,
                    current_source_commit=current_head,
                    now=NOW,
                    attestation_path=attestation_path,
                    attestation_sha256=sha256_bytes(raw),
                )

    def test_attestation_digest_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_json(path / "l1.json", self.base)
            attestation_path, _, attestation_signature_path, attestation_public_key_path, attestation_public_key_sha256 = self.write_trusted_attestation(
                Path(temp).parent / "g1-attestation-digest.json", [self.base]
            )
            with self.assertRaisesRegex(EvidenceError, "raw-byte digest"):
                verify_evidence_directory(
                    path,
                    GAP_REGISTER,
                    current_source_commit=SOURCE_COMMIT,
                    now=NOW,
                    attestation_path=attestation_path,
                    attestation_sha256="0" * 64,
                    attestation_signature_path=attestation_signature_path,
                    attestation_public_key_path=attestation_public_key_path,
                    attestation_public_key_sha256=attestation_public_key_sha256,
                    repository_root=ROOT,
                )

    def test_attestation_signature_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_json(path / "l1.json", self.base)
            (
                attestation_path,
                _,
                attestation_signature_path,
                attestation_public_key_path,
                attestation_public_key_sha256,
            ) = self.write_trusted_attestation(
                Path(temp).parent / "g1-attestation-signature.json", [self.base]
            )
            attestation_path.write_bytes(attestation_path.read_bytes() + b" \n")
            with self.assertRaisesRegex(EvidenceError, "detached signature is invalid"):
                verify_evidence_directory(
                    path,
                    GAP_REGISTER,
                    current_source_commit=SOURCE_COMMIT,
                    now=NOW,
                    attestation_path=attestation_path,
                    attestation_sha256=sha256_bytes(attestation_path.read_bytes()),
                    attestation_signature_path=attestation_signature_path,
                    attestation_public_key_path=attestation_public_key_path,
                    attestation_public_key_sha256=attestation_public_key_sha256,
                    repository_root=ROOT,
                )

    def test_attestation_public_key_pin_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_json(path / "l1.json", self.base)
            (
                attestation_path,
                attestation_sha256,
                attestation_signature_path,
                attestation_public_key_path,
                _,
            ) = self.write_trusted_attestation(
                Path(temp).parent / "g1-attestation-key-pin.json", [self.base]
            )
            with self.assertRaisesRegex(EvidenceError, "public-key digest"):
                verify_evidence_directory(
                    path,
                    GAP_REGISTER,
                    current_source_commit=SOURCE_COMMIT,
                    now=NOW,
                    attestation_path=attestation_path,
                    attestation_sha256=attestation_sha256,
                    attestation_signature_path=attestation_signature_path,
                    attestation_public_key_path=attestation_public_key_path,
                    attestation_public_key_sha256="0" * 64,
                    repository_root=ROOT,
                )

    def test_duplicate_json_member_is_rejected_recursively(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "duplicate JSON member"):
            strict_json_bytes(b'{"schema":"a","nested":{"x":1,"x":2}}', "fixture")

    def test_package_digest_mismatch_is_rejected(self) -> None:
        package = deepcopy(self.base)
        package["source"]["tree"] = "f" * 40
        with self.assertRaisesRegex(EvidenceError, "package_id does not match"):
            validate_package(package, self.gaps, now=NOW)

    def test_source_package_cannot_claim_public_release(self) -> None:
        package = deepcopy(self.base)
        package["public_release"] = True
        self.resign(package)
        with self.assertRaisesRegex(EvidenceError, "public_release"):
            validate_package(package, self.gaps, now=NOW)

    def test_complete_package_requires_independent_reviewer(self) -> None:
        package = deepcopy(self.base)
        package["roles"]["reviewer"] = deepcopy(package["roles"]["producer"])
        self.resign(package)
        with self.assertRaisesRegex(EvidenceError, "producer and reviewer"):
            validate_package(package, self.gaps, now=NOW)

    def test_evidence_class_cannot_close_another_class_gap(self) -> None:
        package = deepcopy(self.base)
        package["gaps"] = ["GAP-INSTALLED-CODEX-001"]
        self.resign(package)
        with self.assertRaisesRegex(EvidenceError, "requires installed_rootlinux"):
            validate_package(package, self.gaps, now=NOW)

    def test_expired_package_remains_valid_but_is_not_promotable(self) -> None:
        assessment = validate_package(
            deepcopy(self.base),
            self.gaps,
            current_source_commit=SOURCE_COMMIT,
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        )
        self.assertTrue(assessment.expired)
        self.assertFalse(assessment.promotable_for_current_source)

    def test_complete_l2_package_requires_lower_level_parent(self) -> None:
        package = self.l2_package()
        package["lineage"]["parent_package_ids"] = []
        self.resign(package)
        with self.assertRaisesRegex(EvidenceError, "requires parent packages"):
            validate_package(package, self.gaps, now=NOW)

    def test_directory_rejects_missing_parent_package(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_json(path / "l2.json", self.l2_package())
            with self.assertRaisesRegex(EvidenceError, "references missing parent"):
                verify_evidence_directory(
                    path,
                    GAP_REGISTER,
                    current_source_commit=SOURCE_COMMIT,
                    now=NOW,
                )

    def test_directory_accepts_exact_parent_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_json(path / "l1.json", self.base)
            l2 = self.l2_package()
            write_json(path / "l2.json", l2)
            attestation_path, attestation_sha256, attestation_signature_path, attestation_public_key_path, attestation_public_key_sha256 = self.write_trusted_attestation(
                Path(temp).parent / "g1-attestation.json", [self.base, l2]
            )
            report = verify_evidence_directory(
                path,
                GAP_REGISTER,
                current_source_commit=SOURCE_COMMIT,
                now=NOW,
                attestation_path=attestation_path,
                attestation_sha256=attestation_sha256,
                attestation_signature_path=attestation_signature_path,
                attestation_public_key_path=attestation_public_key_path,
                attestation_public_key_sha256=attestation_public_key_sha256,
                repository_root=ROOT,
            )
            self.assertEqual(report["package_count"], 2)
            self.assertEqual(
                report["promotable_gaps"]["GAP-INSTALLED-CODEX-001"],
                l2["package_id"],
            )
            self.assertNotIn("GAP-JOB-ADMISSION-001", report["unresolved_gaps"])

    def test_promotion_plan_never_enables_release_without_complete_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_json(path / "l1.json", self.base)
            attestation_path, attestation_sha256, attestation_signature_path, attestation_public_key_path, attestation_public_key_sha256 = self.write_trusted_attestation(
                Path(temp).parent / "g1-attestation.json", [self.base]
            )
            report = verify_evidence_directory(
                path,
                GAP_REGISTER,
                current_source_commit=SOURCE_COMMIT,
                now=NOW,
                attestation_path=attestation_path,
                attestation_sha256=attestation_sha256,
                attestation_signature_path=attestation_signature_path,
                attestation_public_key_path=attestation_public_key_path,
                attestation_public_key_sha256=attestation_public_key_sha256,
                repository_root=ROOT,
            )
            plan = promotion_plan(report, GAP_REGISTER)
            self.assertFalse(plan["zero_gap_after_plan"])
            self.assertFalse(plan["public_release_after_plan"])
            self.assertFalse(plan["automatic_redispatch"])

    def test_hold_package_cannot_promote(self) -> None:
        package = deepcopy(self.base)
        package["status"] = "HOLD"
        package["artifacts"] = []
        package["observations"] = {"exact_head_checks_passed": True}
        package["roles"] = {
            "producer": None,
            "operator": None,
            "reviewer": None,
            "authorizer": None,
        }
        package["authorization"] = {
            "status": "PENDING",
            "authority": "github_pull_request_review",
            "scope": "pending source qualification",
            "expires_at": package["expires_at"],
            "revoked": False,
            "evidence_id": "pending-review",
        }
        package["holds"] = [
            {
                "field": "independent_non_author_approval",
                "status": "NOT_OBSERVED",
                "reason": "No exact-head independent approval is present.",
            }
        ]
        self.resign(package)
        assessment = validate_package(
            package,
            self.gaps,
            current_source_commit=SOURCE_COMMIT,
            now=NOW,
        )
        self.assertEqual(assessment.status, "HOLD")
        self.assertFalse(assessment.promotable_for_current_source)


if __name__ == "__main__":
    unittest.main()
