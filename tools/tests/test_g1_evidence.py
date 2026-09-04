from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

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
from g1_evidence_contract import ATTESTATION_SCHEMA, ATTESTATION_VERSION  # noqa: E402

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
        # Keep the test subject aligned when a fixture intentionally moves its
        # source head; production callers must regenerate the whole subject.
        if "subject" in package and "source" in package:
            package["subject"]["head"]["commit"] = package["source"]["commit"]
            package["subject"]["head"]["tree"] = package["source"]["tree"]
            package["subject"]["merge"]["parents"][1] = package["source"]["commit"]
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
            "schema": ATTESTATION_SCHEMA,
            "version": ATTESTATION_VERSION,
            "package_ids": sorted(package["package_id"] for package in packages),
            "source_commit": SOURCE_COMMIT,
            "subject": packages[0]["subject"],
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
                    expected_subject=package["subject"],
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
                "schema": ATTESTATION_SCHEMA,
                "version": ATTESTATION_VERSION,
                "package_ids": [package["package_id"]],
                "source_commit": current_head,
                "subject": package["subject"],
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
                    expected_subject=package["subject"],
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
                    expected_subject=self.base["subject"],
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
                    expected_subject=self.base["subject"],
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
                    expected_subject=self.base["subject"],
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
        package["subject"]["head"]["tree"] = "f" * 40
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
                expected_subject=self.base["subject"],
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
                expected_subject=self.base["subject"],
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

    def test_still_valid_attestation_cannot_be_replayed_for_new_subject(self) -> None:
        """A fresh externally observed subject is mandatory for promotion."""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_json(path / "l1.json", self.base)
            (
                attestation_path,
                attestation_sha256,
                attestation_signature_path,
                attestation_public_key_path,
                attestation_public_key_sha256,
            ) = self.write_trusted_attestation(
                Path(temp).parent / "g1-attestation-replay.json", [self.base]
            )
            advanced = deepcopy(self.base["subject"])
            advanced["base"]["commit"] = "0" * 40
            advanced["base"]["tree"] = "1" * 40
            advanced["merge"]["parents"] = ["0" * 40, advanced["head"]["commit"]]
            with self.assertRaisesRegex(EvidenceError, "current expected subject"):
                verify_evidence_directory(
                    path,
                    GAP_REGISTER,
                    current_source_commit=SOURCE_COMMIT,
                    expected_subject=advanced,
                    now=NOW,
                    attestation_path=attestation_path,
                    attestation_sha256=attestation_sha256,
                    attestation_signature_path=attestation_signature_path,
                    attestation_public_key_path=attestation_public_key_path,
                    attestation_public_key_sha256=attestation_public_key_sha256,
                    repository_root=ROOT,
                )

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


class G1EvidenceByteBindingTest(unittest.TestCase):
    """Real signatures over ephemeral fixtures; never target/release evidence."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.key_directory = tempfile.TemporaryDirectory(prefix="g1-test-keys-")
        cls.addClassCleanup(cls.key_directory.cleanup)
        root = Path(cls.key_directory.name)
        base = json.loads(CANDIDATE.read_text(encoding="utf-8"))
        cls.valid = G1EvidenceTest.write_trusted_attestation(root / "valid.json", [base])
        cls.other = G1EvidenceTest.write_trusted_attestation(root / "other.json", [base])
        cls.original_run = staticmethod(subprocess.run)

    def setUp(self) -> None:
        import g1_evidence_core
        self.core = g1_evidence_core
        self.directory = tempfile.TemporaryDirectory(prefix="g1-byte-binding-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.base = json.loads(CANDIDATE.read_text(encoding="utf-8"))
        self.receipt, self.receipt_digest, self.signature, self.key, self.key_digest = (
            self.root / "receipt.json", self.valid[1], self.root / "receipt.sig",
            self.root / "public.pem", self.valid[4],
        )
        for target, source in ((self.receipt, self.valid[0]),
                               (self.signature, self.valid[2]), (self.key, self.valid[3])):
            target.write_bytes(source.read_bytes())
        self.gap_register = self.root / "gaps.json"
        self.gap_register.write_bytes(GAP_REGISTER.read_bytes())
        write_json(self.evidence / "l1.json", self.base)

    def verify_signature(self):
        trusted = self.core.load_trusted_attestation(
            self.receipt, self.receipt_digest, repository_root=ROOT,
        )
        return self.core.verify_attestation_signature(
            trusted, signature_path=self.signature, public_key_path=self.key,
            public_key_sha256=self.key_digest, repository_root=ROOT,
            evidence_dir=self.evidence,
        )

    def verify_directory(self):
        return verify_evidence_directory(
            self.evidence, self.gap_register, current_source_commit=SOURCE_COMMIT,
            expected_subject=self.base["subject"], now=NOW,
            attestation_path=self.receipt, attestation_sha256=self.receipt_digest,
            attestation_signature_path=self.signature, attestation_public_key_path=self.key,
            attestation_public_key_sha256=self.key_digest, repository_root=ROOT,
        )

    def swap_before_openssl(self, change):
        def invoke(command, **kwargs):
            if command[1] == "pkey":
                change()
            return self.original_run(command, **kwargs)
        return mock.patch.object(self.core.subprocess, "run", side_effect=invoke)

    def test_key_replacement_cannot_accept_signature_from_unpinned_key(self) -> None:
        # The signature is invalid under the pinned key. Replacing that pathname
        # after its digest check must not turn the signature into a valid one.
        self.signature.write_bytes(self.other[2].read_bytes())
        with self.swap_before_openssl(lambda: self.key.write_bytes(self.other[3].read_bytes())):
            with self.assertRaisesRegex(EvidenceError, "detached signature is invalid"):
                self.verify_signature()

    def test_receipt_replacement_cannot_verify_different_signed_bytes(self) -> None:
        original = self.receipt.read_bytes()
        different = original.replace(b"test-attestation-1", b"test-attestation-2")
        alternate = self.root / "different.json"
        alternate.write_bytes(different)
        self.original_run(
            ["openssl", "dgst", "-sha256", "-sign",
             str(self.valid[0].with_suffix(".private.pem")), "-out", str(self.signature),
             str(alternate)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with self.swap_before_openssl(lambda: self.receipt.write_bytes(different)):
            with self.assertRaisesRegex(EvidenceError, "detached signature is invalid"):
                self.verify_signature()

    def test_signature_replacement_cannot_upgrade_the_read_snapshot(self) -> None:
        valid_signature = self.signature.read_bytes()
        self.signature.write_bytes(b"\0" * len(valid_signature))
        with self.swap_before_openssl(lambda: self.signature.write_bytes(valid_signature)):
            with self.assertRaisesRegex(EvidenceError, "detached signature is invalid"):
                self.verify_signature()

    def mutate_after_signature(self, change):
        original = self.core._require_trusted_attestation_for_promotions
        def invoke(*args, **kwargs):
            result = original(*args, **kwargs)
            change()
            return result
        return mock.patch.object(
            self.core, "_require_trusted_attestation_for_promotions", side_effect=invoke,
        )

    def test_package_replacement_cannot_escape_attested_ids(self) -> None:
        changed = deepcopy(self.base)
        changed["roles"]["reviewer"]["principal"] = "unattested-replacement-reviewer"
        G1EvidenceTest.resign(changed)
        with self.mutate_after_signature(lambda: write_json(self.evidence / "l1.json", changed)):
            report = self.verify_directory()
        self.assertEqual(set(report["promotable_gaps"].values()), {self.base["package_id"]})
        self.assertEqual(report["trusted_attestation"]["package_ids"], [self.base["package_id"]])

    def test_added_l2_package_is_not_promoted_by_l1_only_attestation(self) -> None:
        helper = G1EvidenceTest(methodName="runTest")
        helper.setUp()
        l2 = helper.l2_package()
        with self.mutate_after_signature(lambda: write_json(self.evidence / "l2.json", l2)):
            report = self.verify_directory()
        self.assertNotIn("GAP-INSTALLED-CODEX-001", report["promotable_gaps"])
        self.assertIn("GAP-INSTALLED-CODEX-001", report["unresolved_gaps"])
        self.assertEqual(report["package_count"], 1)

    def test_gap_replacement_cannot_change_the_verified_snapshot(self) -> None:
        def close_gaps():
            value = json.loads(self.gap_register.read_bytes())
            for gap in value["gaps"]:
                gap["status"] = "CLOSED"
            write_json(self.gap_register, value)
        with self.mutate_after_signature(close_gaps):
            report = self.verify_directory()
        self.assertIn("GAP-RELEASE-001", report["unresolved_gaps"])
        self.assertFalse(report["all_gaps_promotable"])


    def test_plan_rejects_gap_changes_after_report_verification(self) -> None:
        report = self.verify_directory()
        value = json.loads(self.gap_register.read_bytes())
        for gap in value["gaps"]:
            if gap["id"] == "GAP-DOC-SINGLE-TRUTH-001":
                gap["status"] = "OPEN"
        write_json(self.gap_register, value)
        with self.assertRaisesRegex(EvidenceError, "gap definition snapshot differs"):
            promotion_plan(report, self.gap_register)

    def test_plan_rejects_unbound_detached_report(self) -> None:
        report = self.verify_directory()
        report.pop("gap_specs_sha256", None)
        with self.assertRaisesRegex(EvidenceError, "gap_specs_sha256"):
            promotion_plan(report, self.gap_register)

    def test_plan_roundtrip_preserves_semantic_gap_snapshot(self) -> None:
        report = json.loads(json.dumps(self.verify_directory()))
        value = json.loads(self.gap_register.read_bytes())
        self.gap_register.write_text(json.dumps(value, indent=4))
        plan = promotion_plan(report, self.gap_register)
        self.assertEqual(plan["gap_specs_sha256"], report["gap_specs_sha256"])
        self.assertEqual(len(plan["transitions"]), 2)
        self.assertFalse(plan["zero_gap_after_plan"])
        self.assertFalse(plan["public_release_after_plan"])

    def test_valid_snapshot_survives_later_input_path_removal(self) -> None:
        signature_digest = sha256_bytes(self.signature.read_bytes())
        def remove_paths():
            for path in (self.receipt, self.key, self.signature):
                path.unlink()
        with self.swap_before_openssl(remove_paths):
            metadata = self.verify_signature()
        self.assertEqual(metadata["public_key_sha256"], self.key_digest)
        self.assertEqual(metadata["signature_sha256"], signature_digest)

    def test_openssl_uses_sealed_descriptors_and_a_clean_environment(self) -> None:
        import errno
        observed = []
        def invoke(command, **kwargs):
            self.assertEqual(command[0], "/usr/bin/openssl")
            self.assertEqual(kwargs["cwd"], "/")
            self.assertNotIn("LD_PRELOAD", kwargs["env"])
            self.assertNotIn("OPENSSL_MODULES", kwargs["env"])
            self.assertEqual(kwargs["env"]["OPENSSL_CONF"], os.devnull)
            for descriptor in kwargs["pass_fds"]:
                observed.append(descriptor)
                with self.assertRaises(OSError) as write_error:
                    os.pwrite(descriptor, b"changed", 0)
                self.assertEqual(write_error.exception.errno, errno.EPERM)
                with self.assertRaises(OSError):
                    os.ftruncate(descriptor, 0)
            self.assertFalse({str(self.receipt), str(self.key), str(self.signature)} & set(command))
            if command[1] == "dgst":
                self.assertEqual(kwargs["input"], self.receipt.read_bytes())
            return self.original_run(command, **kwargs)
        with mock.patch.dict(os.environ, {"LD_PRELOAD": "/untrusted/no-library", "OPENSSL_MODULES": "/untrusted"}):
            with mock.patch.object(self.core.subprocess, "run", side_effect=invoke):
                self.verify_signature()
        self.assertEqual(len(observed), 3)
        for descriptor in set(observed):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_verifier_timeout_closes_all_sealed_descriptors(self) -> None:
        descriptors = []
        def fail(command, **kwargs):
            descriptors.extend(kwargs["pass_fds"])
            raise subprocess.TimeoutExpired(command, 10)
        before = len(list(Path("/proc/self/fd").iterdir()))
        with mock.patch.object(self.core.subprocess, "run", side_effect=fail):
            with self.assertRaisesRegex(EvidenceError, "type check failed"):
                self.verify_signature()
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_unavailable_sealing_has_no_pathname_fallback(self) -> None:
        with mock.patch.object(self.core.os, "memfd_create", side_effect=OSError("not supported")):
            with mock.patch.object(self.core.subprocess, "run") as openssl:
                with self.assertRaisesRegex(EvidenceError, "cannot seal"):
                    self.verify_signature()
                openssl.assert_not_called()

    def test_modified_parsed_receipt_cannot_diverge_from_signed_bytes(self) -> None:
        trusted = self.core.load_trusted_attestation(self.receipt, self.receipt_digest, repository_root=ROOT)
        trusted.receipt["authority"] = "not-in-signed-bytes"
        with self.assertRaisesRegex(EvidenceError, "parsed receipt differs"):
            self.core.verify_attestation_signature(
                trusted, signature_path=self.signature, public_key_path=self.key,
                public_key_sha256=self.key_digest, repository_root=ROOT, evidence_dir=self.evidence,
            )

    def test_trust_input_symlink_and_hardlink_are_rejected(self) -> None:
        alias = self.root / "alias.json"
        alias.symlink_to(self.receipt)
        with self.assertRaisesRegex(EvidenceError, "symlink"):
            self.core.load_trusted_attestation(alias, self.receipt_digest)
        alias.unlink()
        os.link(self.receipt, alias)
        with self.assertRaisesRegex(EvidenceError, "single-link"):
            self.core.load_trusted_attestation(alias, self.receipt_digest)

    def test_parent_symlink_is_rejected(self) -> None:
        alias = self.root / "alias-directory"
        alias.symlink_to(self.evidence, target_is_directory=True)
        with self.assertRaisesRegex(EvidenceError, "symlink"):
            self.core._read_regular_snapshot(alias / "l1.json", label="package", maximum=1024*1024)

    def test_fifo_and_directory_are_rejected_before_reading(self) -> None:
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (fifo, self.evidence):
            with self.subTest(path=path):
                with self.assertRaisesRegex(EvidenceError, "regular file"):
                    self.core._read_regular_snapshot(path, label="input", maximum=1024)

    def test_input_byte_limit_accepts_boundary_and_rejects_empty_or_excess(self) -> None:
        path = self.root / "bounded"
        path.write_bytes(b"abc")
        self.assertEqual(self.core._read_regular_snapshot(path, label="input", maximum=3), b"abc")
        for raw in (b"", b"abcd"):
            path.write_bytes(raw)
            with self.assertRaisesRegex(EvidenceError, "byte limit"):
                self.core._read_regular_snapshot(path, label="input", maximum=3)

    def test_in_place_change_during_snapshot_read_is_rejected(self) -> None:
        original_read = os.read
        called = False
        def mutate(descriptor, count):
            nonlocal called
            raw = original_read(descriptor, count)
            if not called:
                called = True
                self.receipt.write_bytes(self.receipt.read_bytes() + b" ")
            return raw
        with mock.patch.object(self.core.os, "read", side_effect=mutate):
            with self.assertRaisesRegex(EvidenceError, "changed while reading"):
                self.core.load_trusted_attestation(self.receipt, self.receipt_digest)

    def test_package_count_and_total_input_bytes_are_bounded(self) -> None:
        write_json(self.evidence / "second.json", self.base)
        with mock.patch.object(self.core, "MAX_PACKAGE_COUNT", 1):
            with self.assertRaisesRegex(EvidenceError, "package count"):
                self.verify_directory()
        (self.evidence / "second.json").unlink()
        with mock.patch.object(self.core, "MAX_EVIDENCE_INPUT_BYTES", 1):
            with self.assertRaisesRegex(EvidenceError, "input bytes"):
                self.verify_directory()
        with mock.patch.object(self.core, "MAX_PACKAGE_BYTES", 1):
            with self.assertRaisesRegex(EvidenceError, "byte limit"):
                self.verify_directory()


    def test_noncanonical_double_root_is_rejected(self) -> None:
        alias = Path("//" + str(self.receipt).lstrip("/"))
        with self.assertRaisesRegex(EvidenceError, "canonical absolute POSIX"):
            self.core.load_trusted_attestation(alias, self.receipt_digest)


if __name__ == "__main__":
    unittest.main()
