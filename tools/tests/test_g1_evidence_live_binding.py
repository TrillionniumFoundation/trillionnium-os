from __future__ import annotations

from copy import deepcopy
import base64
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_TOOLS = ROOT / "tools" / "evidence"
if str(EVIDENCE_TOOLS) not in sys.path:
    sys.path.insert(0, str(EVIDENCE_TOOLS))

from g1_evidence_types import package_id, sha256_bytes  # noqa: E402
from g1_evidence_core import write_json  # noqa: E402

MODULE_PATH = ROOT / "tools" / "verify-g1-evidence-live.py"
SPEC = importlib.util.spec_from_file_location("verify_g1_evidence_live", MODULE_PATH)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LIVE
SPEC.loader.exec_module(LIVE)

CANDIDATE = ROOT / "evidence" / "g1" / "candidates" / "pr34-l1-source-qualification.json"
NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)
SOURCE_COMMIT = "a" * 40
SOURCE_TREE = "b" * 40


class FakeApi:
    def __init__(self, values: dict[str, object], blobs: dict[str, bytes]):
        self.values = values
        self.blobs = blobs

    @staticmethod
    def response(value: object, url: str) -> LIVE.ApiResponse:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return LIVE.ApiResponse(value, raw, url, {})

    def get_json(self, path: str) -> LIVE.ApiResponse:
        if path not in self.values:
            raise LIVE.LiveBindingError(f"unexpected fake GitHub JSON request: {path}")
        return self.response(self.values[path], path)

    def get_all(self, path: str) -> list[object]:
        value = self.values[path]
        assert isinstance(value, list)
        return value

    def get_bytes(self, path: str) -> LIVE.ApiResponse:
        if path not in self.blobs:
            raise LIVE.LiveBindingError(f"unexpected fake GitHub byte request: {path}")
        blob = self.blobs[path]
        return LIVE.ApiResponse(blob, blob, path, {})


class LiveBindingTest(unittest.TestCase):
    @staticmethod
    def resign(package: dict) -> dict:
        package["package_id"] = ""
        package["package_id"] = package_id(package)
        return package

    def setUp(self) -> None:
        self.package = json.loads(CANDIDATE.read_text(encoding="utf-8"))
        self.package["source"]["commit"] = SOURCE_COMMIT
        self.package["source"]["tree"] = SOURCE_TREE
        self.package["source"]["repository"] = "example/repo"
        self.package["source"]["branch"] = "feature/test"
        self.package["source"]["pull_request"] = 34
        self.cargo_lock = b"[package]\nname = \"test\"\n"
        self.package["source"]["cargo_lock_sha256"] = sha256_bytes(self.cargo_lock)
        self.package["source"]["workflow_runs"] = [
            {
                "name": "G1 exact-head source qualification",
                "run_id": 1001,
                "attempt": 1,
                "result": "success",
                "artifact_id": 2001,
                "artifact_name": "g1-exact-head-test",
                "artifact_sha256": sha256_bytes(b"artifact-bytes"),
            }
        ]
        self.package["artifacts"] = [
            {
                "name": "g1-exact-head-test",
                "kind": "github_actions_artifact",
                "sha256": sha256_bytes(b"artifact-bytes"),
                "bytes": len(b"artifact-bytes"),
                "uri": "github-actions://example/repo/runs/1001/artifacts/2001",
                "retention_expires_at": "2026-12-31T00:00:00Z",
            }
        ]
        self.package["roles"]["producer"]["principal"] = "author"
        self.package["roles"]["producer"]["evidence_id"] = "pull-request-34-author"
        self.package["roles"]["reviewer"]["principal"] = "independent-reviewer"
        self.package["roles"]["reviewer"]["evidence_id"] = "pull-request-review-3001"
        self.package["roles"]["authorizer"]["principal"] = "independent-reviewer"
        self.package["roles"]["authorizer"]["evidence_id"] = "pull-request-review-3001"
        self.package["observations"]["review_id"] = 3001
        self.package["observations"]["review_commit"] = SOURCE_COMMIT
        self.package["observations"]["review_state"] = "APPROVED"
        self.package["package_id"] = ""
        self.package["package_id"] = package_id(self.package)

    def fake_api(self, *, review_state: str = "APPROVED", artifact_bytes: bytes = b"artifact-bytes") -> FakeApi:
        artifact_url = "https://objects.example/artifact.zip"
        values = {
            "repos/example/repo/pulls/34": {
                "number": 34,
                "head": {
                    "sha": SOURCE_COMMIT,
                    "ref": "feature/test",
                    "repo": {"full_name": "example/repo"},
                },
                "base": {"sha": "c" * 40, "ref": "main", "repo": {"full_name": "example/repo"}},
                "user": {"login": "author"},
                "state": "open",
                "draft": False,
            },
            "repos/example/repo/pulls/34/reviews": [
                {
                    "id": 3001,
                    "user": {"login": "independent-reviewer"},
                    "state": review_state,
                    "commit_id": SOURCE_COMMIT,
                    "submitted_at": "2026-09-01T12:00:00Z",
                }
            ],
            f"repos/example/repo/commits/{SOURCE_COMMIT}": {
                "sha": SOURCE_COMMIT,
                "commit": {"tree": {"sha": SOURCE_TREE}},
            },
            f"repos/example/repo/contents/Cargo.lock?ref={SOURCE_COMMIT}": {
                "path": "Cargo.lock",
                "encoding": "base64",
                "content": base64.b64encode(self.cargo_lock).decode(),
            },
            "repos/example/repo/actions/runs/1001": {
                "id": 1001,
                "name": "G1 exact-head source qualification",
                "head_sha": SOURCE_COMMIT,
                "run_attempt": 1,
                "status": "completed",
                "conclusion": "success",
            },
            "repos/example/repo/actions/artifacts/2001": {
                "id": 2001,
                "name": "g1-exact-head-test",
                "expired": False,
                "size_in_bytes": len(artifact_bytes),
                "expires_at": "2026-12-31T00:00:00Z",
                "workflow_run": {"id": 1001},
                "archive_download_url": artifact_url,
            },
        }
        return FakeApi(values, {artifact_url: artifact_bytes})

    def with_package_dir(self):
        temp = tempfile.TemporaryDirectory()
        path = Path(temp.name)
        write_json(path / "package.json", self.package)
        return temp, path

    def test_live_binding_reconciles_api_objects_and_artifact_bytes(self) -> None:
        temp, path = self.with_package_dir()
        try:
            report, receipt = LIVE.verify_live_binding(
                repo="example/repo",
                pr_number=34,
                source_commit=SOURCE_COMMIT,
                evidence_dir=path,
                api=self.fake_api(),
                now=NOW,
            )
            self.assertEqual(receipt["package_ids"], [self.package["package_id"]])
            self.assertEqual(receipt["source_commit"], SOURCE_COMMIT)
            self.assertEqual(report["review"]["id"], 3001)
            self.assertEqual(report["artifacts"][0]["sha256"], sha256_bytes(b"artifact-bytes"))
            self.assertEqual(report["receipt_sha256"], sha256_bytes(LIVE._receipt_bytes(receipt)))
        finally:
            temp.cleanup()

    def test_live_binding_rejects_changes_requested_review(self) -> None:
        temp, path = self.with_package_dir()
        try:
            with self.assertRaisesRegex(LIVE.LiveBindingError, "APPROVED review"):
                LIVE.verify_live_binding(
                    repo="example/repo",
                    pr_number=34,
                    source_commit=SOURCE_COMMIT,
                    evidence_dir=path,
                    api=self.fake_api(review_state="CHANGES_REQUESTED"),
                    now=NOW,
                )
        finally:
            temp.cleanup()

    def test_live_binding_rejects_artifact_digest_mismatch(self) -> None:
        temp, path = self.with_package_dir()
        try:
            with self.assertRaisesRegex(LIVE.LiveBindingError, "archive digest mismatch"):
                LIVE.verify_live_binding(
                    repo="example/repo",
                    pr_number=34,
                    source_commit=SOURCE_COMMIT,
                    evidence_dir=path,
                    api=self.fake_api(artifact_bytes=b"tampered"),
                    now=NOW,
                )
        finally:
            temp.cleanup()

    def test_live_binding_rejects_draft_pull_request(self) -> None:
        temp, path = self.with_package_dir()
        try:
            api = self.fake_api()
            api.values["repos/example/repo/pulls/34"]["draft"] = True
            with self.assertRaisesRegex(LIVE.LiveBindingError, "draft"):
                LIVE.verify_live_binding(
                    repo="example/repo",
                    pr_number=34,
                    source_commit=SOURCE_COMMIT,
                    evidence_dir=path,
                    api=api,
                    now=NOW,
                )
        finally:
            temp.cleanup()

    def test_live_binding_rejects_malformed_pull_request_shape(self) -> None:
        api = self.fake_api()
        api.values["repos/example/repo/pulls/34"]["head"] = "not-an-object"
        with self.assertRaisesRegex(LIVE.LiveBindingError, "pull request head is not an object"):
            LIVE._verify_pull_request(api, "example/repo", 34, SOURCE_COMMIT)

    def test_live_binding_rejects_malformed_review_shape(self) -> None:
        api = self.fake_api()
        api.values["repos/example/repo/pulls/34/reviews"][0]["user"] = "not-an-object"
        with self.assertRaisesRegex(LIVE.LiveBindingError, r"review\[0\]\.user is not an object"):
            LIVE._verify_review(api, "example/repo", 34, SOURCE_COMMIT, "author")

    def test_live_binding_rejects_malformed_commit_tree_shape(self) -> None:
        api = self.fake_api()
        api.values[f"repos/example/repo/commits/{SOURCE_COMMIT}"]["commit"] = "not-an-object"
        with self.assertRaisesRegex(LIVE.LiveBindingError, r"commit\.commit is not an object"):
            LIVE._verify_commit_tree(api, "example/repo", SOURCE_COMMIT, SOURCE_TREE)

    def test_live_binding_rejects_malformed_artifact_ownership_shape(self) -> None:
        api = self.fake_api()
        api.values["repos/example/repo/actions/artifacts/2001"]["workflow_run"] = "not-an-object"
        temp, path = self.with_package_dir()
        try:
            with self.assertRaisesRegex(LIVE.LiveBindingError, "workflow_run is not an object"):
                LIVE.verify_live_binding(
                    repo="example/repo",
                    pr_number=34,
                    source_commit=SOURCE_COMMIT,
                    evidence_dir=path,
                    api=api,
                    now=NOW,
                )
        finally:
            temp.cleanup()

    def test_live_binding_rejects_artifact_byte_count_mismatch(self) -> None:
        package = deepcopy(self.package)
        package["artifacts"][0]["bytes"] += 1
        self.resign(package)
        temp = tempfile.TemporaryDirectory()
        path = Path(temp.name)
        write_json(path / "package.json", package)
        try:
            with self.assertRaisesRegex(LIVE.LiveBindingError, "byte count"):
                LIVE.verify_live_binding(
                    repo="example/repo",
                    pr_number=34,
                    source_commit=SOURCE_COMMIT,
                    evidence_dir=path,
                    api=self.fake_api(),
                    now=NOW,
                )
        finally:
            temp.cleanup()

    def test_live_binding_rejects_unavailable_extra_artifact(self) -> None:
        package = deepcopy(self.package)
        package["artifacts"].append(
            {
                "name": "g1-extra-test",
                "kind": "github_actions_artifact",
                "sha256": sha256_bytes(b"extra"),
                "bytes": len(b"extra"),
                "uri": "github-actions://example/repo/runs/1001/artifacts/2002",
                "retention_expires_at": "2026-12-31T00:00:00Z",
            }
        )
        self.resign(package)
        temp = tempfile.TemporaryDirectory()
        path = Path(temp.name)
        write_json(path / "package.json", package)
        try:
            with self.assertRaisesRegex(LIVE.LiveBindingError, "unexpected fake GitHub JSON"):
                LIVE.verify_live_binding(
                    repo="example/repo",
                    pr_number=34,
                    source_commit=SOURCE_COMMIT,
                    evidence_dir=path,
                    api=self.fake_api(),
                    now=NOW,
                )
        finally:
            temp.cleanup()

    def test_live_binding_rejects_noncanonical_artifact_uri(self) -> None:
        package = deepcopy(self.package)
        package["artifacts"][0]["uri"] = "https://example.invalid/artifact.zip"
        self.resign(package)
        temp = tempfile.TemporaryDirectory()
        path = Path(temp.name)
        write_json(path / "package.json", package)
        try:
            with self.assertRaisesRegex(LIVE.LiveBindingError, "canonical github-actions artifact URI"):
                LIVE.verify_live_binding(
                    repo="example/repo",
                    pr_number=34,
                    source_commit=SOURCE_COMMIT,
                    evidence_dir=path,
                    api=self.fake_api(),
                    now=NOW,
                )
        finally:
            temp.cleanup()

    def test_external_output_rejects_existing_symlink_and_repository_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            outside = Path(temp) / "output.json"
            outside.symlink_to(CANDIDATE)
            with self.assertRaisesRegex(LIVE.LiveBindingError, "symlink"):
                LIVE._assert_external_output(
                    outside,
                    repository_root=ROOT,
                    evidence_dir=Path(temp),
                    label="output",
                )
        with self.assertRaisesRegex(LIVE.LiveBindingError, "outside"):
            LIVE._assert_external_output(
                ROOT / "tmp-live-output.json",
                repository_root=ROOT,
                evidence_dir=ROOT / "evidence" / "g1",
                label="output",
            )

    def test_token_file_rejects_symlink_and_controlled_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            token = directory / "token"
            token.write_text("secret\n", encoding="utf-8")
            token.chmod(0o600)
            self.assertEqual(
                LIVE._read_external_token(
                    token,
                    repository_root=ROOT,
                    evidence_dir=ROOT / "evidence" / "g1",
                ),
                "secret",
            )
            link = directory / "token-link"
            link.symlink_to(token)
            with self.assertRaisesRegex(LIVE.LiveBindingError, "must not be a symlink"):
                LIVE._read_external_token(
                    link,
                    repository_root=ROOT,
                    evidence_dir=ROOT / "evidence" / "g1",
                )
        with self.assertRaisesRegex(LIVE.LiveBindingError, "outside"):
            LIVE._read_external_token(
                ROOT / "tools" / "verify-g1-evidence-live.py",
                repository_root=ROOT,
                evidence_dir=ROOT / "evidence" / "g1",
            )

    def test_cli_api_base_cannot_forward_token_to_arbitrary_host(self) -> None:
        LIVE._require_official_api_base("https://api.github.com/")
        with self.assertRaisesRegex(LIVE.LiveBindingError, "official"):
            LIVE._require_official_api_base("https://attacker.example/")


if __name__ == "__main__":
    unittest.main()
