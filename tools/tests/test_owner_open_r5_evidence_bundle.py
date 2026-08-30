from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from owner_open_r5_capture_trust import (  # noqa: E402
    CAPTURE_DRIVER_SCHEMA,
    FIXED_BASE_ENVIRONMENT,
    assert_harness_identity,
    validate_capture_chain,
)
from owner_open_r5_evidence_bundle import (  # noqa: E402
    ARTIFACT_INDEX_SCHEMA,
    ATTESTATION_SCHEMA,
    EvidenceError,
    KIND_POLICIES,
    OBSERVATIONS_SCHEMA,
    PLAN_REVISION,
    RELEASE_AUTHORIZATION_SCHEMA,
    REPOSITORY,
    REVIEW_SCHEMA,
    validate_bundle,
)

FINALIZER = TOOLS / "finalize-owner-open-r5-evidence-bundle.py"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BundleFixture:
    def __init__(
        self,
        root: Path,
        *,
        kind: str = "installed_root_linux_process_matrix",
        producer: str = "capture-operator",
        operator: str = "target-operator",
        reviewer: str = "evidence-reviewer",
    ) -> None:
        self.root = root
        self.kind = kind
        self.policy = KIND_POLICIES[kind]
        self.level = str(self.policy["level"])
        self.gaps = sorted(self.policy["allowed_gaps"])[0:1]
        self.source_commit = "a" * 40
        self.source_tree = "b" * 40
        self.producer = producer
        self.operator = operator
        self.reviewer = reviewer
        self.bundle = root / "bundle"
        self.bundle.mkdir()
        (self.bundle / "raw").mkdir()
        self.attestation = root / "attestation-input.json"
        self.review = root / "review-input.json"
        self.release = root / "release-input.json"
        self._write_attestation()
        self._write_raw()
        self._write_observations()
        self._write_index()
        self._write_review()
        self._write_release()

    def _target(self) -> dict[str, str]:
        target = {
            "id": "target-01",
            "kind": self.kind,
            "fingerprint": "fingerprint-01",
        }
        if self.level == "L2":
            target["boot_id"] = "boot-01"
        elif self.level == "L3":
            target["build_id"] = "build-01"
        elif self.level == "L4":
            target.update(boot_id="boot-01", serial="SERIAL01")
        elif self.level == "L5":
            target["boot_id"] = "boot-01"
        elif self.level == "L6":
            target["authorization_domain"] = "release-domain-01"
        return target

    def _harness(self) -> dict[str, object]:
        return {
            "path": f"/opt/owner-open-r5/harnesses/{self.kind}",
            "bytes": 4096,
            "sha256": "c" * 64,
            "uid": 0,
            "gid": 0,
            "mode": "0755",
        }

    def _write_attestation(self) -> None:
        write_json(
            self.attestation,
            {
                "schema": ATTESTATION_SCHEMA,
                "plan_revision": PLAN_REVISION,
                "lane": self.level,
                "source_commit": self.source_commit,
                "source_tree": self.source_tree,
                "synthetic": False,
                "template": False,
                "captured_at": "2026-08-29T00:00:00Z",
                "expires_at": "2027-08-29T00:00:00Z",
                "environment": {
                    "id": "environment-01",
                    "owner": "independent-environment-owner",
                    "class": self.policy["environment_class"],
                    "independent_control": True,
                },
                "runner": {
                    "name": "runner-01",
                    "os": "linux",
                    "arch": "x86_64",
                    "labels": (
                        ["self-hosted", f"owner-open-r5-{self.level.lower()}"]
                        if self.level != "L1"
                        else ["ubuntu-latest"]
                    ),
                },
                "target": self._target(),
                "harness": self._harness(),
                "operator": {"login": self.operator},
            },
        )

    def _write_raw(self) -> None:
        for index, role in enumerate(sorted(self.policy["required_roles"])):
            if role == "release_authorization":
                continue
            path = self.bundle / "raw" / f"{index:02d}-{role}.txt"
            path.write_text(f"evidence role {role}\n", encoding="utf-8")
        dynamic_keys = {
            "OWNER_OPEN_R5_KIND",
            "OWNER_OPEN_R5_SOURCE_COMMIT",
            "OWNER_OPEN_R5_SOURCE_TREE",
            "OWNER_OPEN_R5_RAW_DIR",
            "OWNER_OPEN_R5_ARTIFACT_INDEX",
            "OWNER_OPEN_R5_OBSERVATIONS",
        }
        attestation_identity = {
            "path": f"/etc/owner-open-r5/attestations/{self.kind}.json",
            "bytes": self.attestation.stat().st_size,
            "sha256": sha256(self.attestation),
            "uid": 0,
            "gid": 0,
            "mode": "0644",
        }
        write_json(
            self.bundle / "raw/capture-driver.json",
            {
                "schema": CAPTURE_DRIVER_SCHEMA,
                "repository": REPOSITORY,
                "kind": self.kind,
                "source_commit": self.source_commit,
                "source_tree": self.source_tree,
                "synthetic": False,
                "harness": self._harness(),
                "target_attestation": attestation_identity,
                "run": {
                    "argv": [self._harness()["path"], "--fixed-fixture"],
                    "returncode": 0,
                    "started_at": "2026-08-29T23:00:00Z",
                    "finished_at": "2026-08-29T23:30:00Z",
                    "stdout_bytes": 0,
                    "stderr_bytes": 0,
                    "environment": {
                        "inherit_parent": False,
                        "base": dict(FIXED_BASE_ENVIRONMENT),
                        "keys": sorted(set(FIXED_BASE_ENVIRONMENT) | dynamic_keys),
                    },
                },
                "automatic_redispatch": False,
            },
        )

    def _write_observations(self) -> None:
        value = {
            "schema": OBSERVATIONS_SCHEMA,
            "kind": self.kind,
            "capture_driver_sha256": sha256(
                self.bundle / "raw/capture-driver.json"
            ),
        }
        value.update(self.policy["required_observations"])
        write_json(self.bundle / "observations.json", value)

    def _write_index(self) -> None:
        entries = []
        for path in sorted((self.bundle / "raw").iterdir()):
            role = (
                "capture_driver"
                if path.name == "capture-driver.json"
                else path.stem.split("-", 1)[1]
            )
            entries.append(
                {"path": path.relative_to(self.bundle).as_posix(), "role": role}
            )
        write_json(
            self.bundle / "artifact-index.json",
            {"schema": ARTIFACT_INDEX_SCHEMA, "artifacts": entries},
        )

    def _write_review(self) -> None:
        write_json(
            self.review,
            {
                "schema": REVIEW_SCHEMA,
                "plan_revision": PLAN_REVISION,
                "repository": REPOSITORY,
                "source_commit": self.source_commit,
                "source_tree": self.source_tree,
                "kind": self.kind,
                "evidence_level": self.level,
                "gap_ids": self.gaps,
                "approved": True,
                "reviewer": self.reviewer,
                "review_id": 987654,
                "reviewed_at": "2026-08-30T00:00:00Z",
                "negative_claims": [
                    "no claim beyond the declared evidence level"
                ],
            },
        )

    def _write_release(self) -> None:
        write_json(
            self.release,
            {
                "schema": RELEASE_AUTHORIZATION_SCHEMA,
                "plan_revision": PLAN_REVISION,
                "repository": REPOSITORY,
                "source_commit": self.source_commit,
                "source_tree": self.source_tree,
                "authorized": True,
                "public_release": True,
                "authorizer": "release-authorizer",
                "authorization_id": "release-auth-0001",
                "authorized_at": "2026-08-30T00:01:00Z",
            },
        )

    def finalizer_args(
        self, *, promotable: bool, replace: bool = False
    ) -> list[str]:
        args = [
            sys.executable,
            str(FINALIZER),
            "--bundle-dir",
            str(self.bundle),
            "--target-attestation",
            str(
                self.attestation
                if not replace
                else self.bundle / "target-attestation.json"
            ),
            "--kind",
            self.kind,
            "--evidence-level",
            self.level,
            "--branch",
            "feature/evidence",
            "--source-commit",
            self.source_commit,
            "--source-tree",
            self.source_tree,
            "--claim-ceiling",
            f"{self.level}_DECLARED_EVIDENCE_ONLY",
            "--producer-login",
            self.producer,
            "--workflow",
            "Owner-Open R5 target capture",
            "--workflow-run-id",
            "12345",
            "--workflow-run-attempt",
            "1",
            "--job",
            "capture",
            "--started-at",
            "2026-08-29T23:00:00Z",
            "--finished-at",
            "2026-08-29T23:30:00Z",
            "--negative-claim",
            "no claim beyond the declared evidence level",
            "--artifact-expires-at",
            "2027-08-29T00:00:00Z",
            "--immutable-location",
            "immutable://evidence/archive/0001",
            "--reproduction",
            "re-run the fixed target harness at the exact source commit",
        ]
        for gap in self.gaps:
            args.extend(["--gap-id", gap])
        if promotable:
            args.extend(
                ["--promotable", "--review-attestation", str(self.review)]
            )
        if replace:
            args.append("--replace-existing-capture")
        if self.kind == "signed_public_release":
            args.extend(
                [
                    "--release-authorization",
                    str(
                        self.bundle / "release-authorization.json"
                        if replace
                        else self.release
                    ),
                ]
            )
        return args

    def finalize(
        self, *, promotable: bool, replace: bool = False
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.finalizer_args(promotable=promotable, replace=replace),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )


class EvidenceBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_capture_then_independent_promotion(self) -> None:
        fixture = BundleFixture(self.root)
        capture = fixture.finalize(promotable=False)
        self.assertEqual(capture.returncode, 0, capture.stderr)
        report = validate_bundle(
            fixture.bundle / "manifest.json", require_promotable=False
        )
        self.assertTrue(report.ok, report.errors)
        trust = validate_capture_chain(fixture.bundle / "manifest.json")
        self.assertEqual(trust["harness_sha256"], "c" * 64)
        rejected = validate_bundle(
            fixture.bundle / "manifest.json", require_promotable=True
        )
        self.assertFalse(rejected.ok)
        promoted = fixture.finalize(promotable=True, replace=True)
        self.assertEqual(promoted.returncode, 0, promoted.stderr)
        report = validate_bundle(
            fixture.bundle / "manifest.json", require_promotable=True
        )
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.facts["reviewer"], fixture.reviewer)
        validate_capture_chain(fixture.bundle / "manifest.json")

    def test_capture_chain_rejects_inherited_parent_environment(self) -> None:
        fixture = BundleFixture(self.root)
        driver_path = fixture.bundle / "raw/capture-driver.json"
        driver = read_json(driver_path)
        driver["run"]["environment"]["inherit_parent"] = True
        write_json(driver_path, driver)
        fixture._write_observations()
        fixture._write_index()
        completed = fixture.finalize(promotable=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        with self.assertRaisesRegex(EvidenceError, "inherit_parent"):
            validate_capture_chain(fixture.bundle / "manifest.json")

    def test_attested_harness_mismatch_is_rejected(self) -> None:
        fixture = BundleFixture(self.root)
        observed = dict(fixture._harness())
        observed["sha256"] = "d" * 64
        with self.assertRaisesRegex(EvidenceError, "identity differs"):
            assert_harness_identity(
                observed, fixture._harness(), kind=fixture.kind
            )

    def test_target_capture_workflow_is_immutable_and_exact(self) -> None:
        workflow = (
            TOOLS.parent
            / ".github/workflows/owner-open-r5-target-evidence-capture.yml"
        ).read_text(encoding="utf-8")
        checkout = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
        upload = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
        self.assertEqual(workflow.count(checkout), 6)
        self.assertEqual(workflow.count(upload), 6)
        self.assertNotIn("actions/checkout@v4", workflow)
        self.assertNotIn("actions/upload-artifact@v4", workflow)
        self.assertNotIn("--untracked-files=no", workflow)
        self.assertEqual(workflow.count("--untracked-files=all"), 6)
        self.assertIn('PYTHONDONTWRITEBYTECODE: "1"', workflow)

    def test_raw_artifact_tamper_is_detected(self) -> None:
        fixture = BundleFixture(self.root)
        self.assertEqual(fixture.finalize(promotable=False).returncode, 0)
        target = next((fixture.bundle / "raw").iterdir())
        target.write_text("tampered\n", encoding="utf-8")
        report = validate_bundle(
            fixture.bundle / "manifest.json", require_promotable=False
        )
        self.assertFalse(report.ok)
        self.assertTrue(any("identity mismatch" in error for error in report.errors))

    def test_secret_shaped_artifact_is_rejected(self) -> None:
        fixture = BundleFixture(self.root)
        secret = fixture.bundle / "raw" / "credential-token.txt"
        secret.write_text("ghp_abcdefghijklmnopqrstuvwxyz123456\n", encoding="utf-8")
        index = read_json(fixture.bundle / "artifact-index.json")
        index["artifacts"].append(
            {"path": "raw/credential-token.txt", "role": "supplemental_log"}
        )
        write_json(fixture.bundle / "artifact-index.json", index)
        completed = fixture.finalize(promotable=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("secret/private-key shape", completed.stderr)

    def test_reviewer_must_differ_from_producer_and_operator(self) -> None:
        fixture = BundleFixture(
            self.root,
            producer="same-person",
            operator="target-operator",
            reviewer="same-person",
        )
        self.assertEqual(fixture.finalize(promotable=False).returncode, 0)
        promoted = fixture.finalize(promotable=True, replace=True)
        self.assertNotEqual(promoted.returncode, 0)
        self.assertIn("reviewer must differ from producer", promoted.stderr)

    def test_kind_policy_requires_all_roles(self) -> None:
        fixture = BundleFixture(self.root)
        index = read_json(fixture.bundle / "artifact-index.json")
        position = next(
            position
            for position, item in enumerate(index["artifacts"])
            if item["role"] in fixture.policy["required_roles"]
        )
        removed = index["artifacts"].pop(position)
        Path(fixture.bundle / removed["path"]).unlink()
        write_json(fixture.bundle / "artifact-index.json", index)
        completed = fixture.finalize(promotable=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("missing required artifact roles", completed.stderr)

    def test_l6_requires_distinct_human_authorization(self) -> None:
        fixture = BundleFixture(self.root, kind="signed_public_release")
        release = read_json(fixture.release)
        release["authorizer"] = fixture.reviewer
        write_json(fixture.release, release)
        self.assertEqual(fixture.finalize(promotable=False).returncode, 0)
        promoted = fixture.finalize(promotable=True, replace=True)
        self.assertNotEqual(promoted.returncode, 0)
        self.assertIn("authorizer must be independent", promoted.stderr)


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


if __name__ == "__main__":
    unittest.main()
