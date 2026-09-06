from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "verify-g1-pr-aggregate.py"
SPEC = importlib.util.spec_from_file_location("verify_g1_pr_aggregate", MODULE_PATH)
assert SPEC and SPEC.loader
AGG = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AGG
SPEC.loader.exec_module(AGG)

NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)


class FakeApi:
    def __init__(self, values: dict[str, object], blobs: dict[str, bytes]) -> None:
        self.values = values
        self.blobs = blobs
        self.calls: dict[str, int] = {}

    @staticmethod
    def _response(value: object, url: str) -> AGG.ApiResponse:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return AGG.ApiResponse(value, raw, url, {})

    def get_json(self, path: str) -> AGG.ApiResponse:
        self.calls[path] = self.calls.get(path, 0) + 1
        if path not in self.values:
            raise AGG.AggregateError(f"unexpected fake JSON request: {path}")
        value = self.values[path]
        if isinstance(value, list) and value and isinstance(value[0], AGG.ApiResponse):
            index = min(self.calls[path] - 1, len(value) - 1)
            return value[index]
        if callable(value):
            value = value(self.calls[path])
        return self._response(value, path)

    def get_bytes(self, path: str) -> AGG.ApiResponse:
        self.calls[path] = self.calls.get(path, 0) + 1
        if path not in self.blobs:
            raise AGG.AggregateError(f"unexpected fake byte request: {path}")
        raw = self.blobs[path]
        return AGG.ApiResponse(raw, raw, path, {})


class AggregateFixtureBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self.temp.name) / "repo"
        self.repo_root.mkdir()
        self._git("init")
        self._git("config", "user.name", "aggregate-test")
        self._git("config", "user.email", "aggregate-test@invalid")
        (self.repo_root / "Cargo.lock").write_text("# lock v1\n", encoding="utf-8")
        (self.repo_root / "README.md").write_text("base\n", encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-m", "base")
        self.base_commit = self._git("rev-parse", "HEAD")
        self.base_tree = self._git("rev-parse", "HEAD^{tree}")
        (self.repo_root / "README.md").write_text("head\n", encoding="utf-8")
        self._git("add", "README.md")
        self._git("commit", "-m", "head")
        self.head_commit = self._git("rev-parse", "HEAD")
        self.head_tree = self._git("rev-parse", "HEAD^{tree}")
        self.lock_sha = hashlib.sha256((self.repo_root / "Cargo.lock").read_bytes()).hexdigest()
        self.repo = "example/repo"
        self.pr_number = 34
        self.base_ref = "integration/base"
        self.head_ref = "feature/head"
        self.values: dict[str, object] = {}
        self.blobs: dict[str, bytes] = {}
        self._build_happy_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.repo_root), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    @staticmethod
    def _zip(files: dict[str, object]) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in files.items():
                archive.writestr(name, json.dumps(value, sort_keys=True, allow_nan=False))
        return output.getvalue()

    def _pr(self, *, base: str | None = None, head: str | None = None) -> dict[str, object]:
        return {
            "number": self.pr_number,
            "state": "open",
            "draft": True,
            "base": {
                "sha": base or self.base_commit,
                "ref": self.base_ref,
                "repo": {"full_name": self.repo},
            },
            "head": {
                "sha": head or self.head_commit,
                "ref": self.head_ref,
                "repo": {"full_name": self.repo},
            },
        }

    def _commit(self, sha: str, tree: str, parents: list[str]) -> dict[str, object]:
        return {
            "sha": sha,
            "commit": {"tree": {"sha": tree}},
            "parents": [{"sha": parent} for parent in parents],
        }

    def _run(self, run_id: int, workflow_name: str, filename: str, *, conclusion: str = "success") -> dict[str, object]:
        return {
            "id": run_id,
            "name": workflow_name,
            "path": f".github/workflows/{filename}",
            "event": "pull_request",
            "head_sha": self.head_commit,
            "head_branch": self.head_ref,
            "status": "completed",
            "conclusion": conclusion,
            "run_attempt": 1,
            "pull_requests": [
                {
                    "number": self.pr_number,
                    "base": {"sha": self.base_commit},
                    "head": {"sha": self.head_commit},
                }
            ],
        }

    def _jobs(self, run_id: int, names: set[str]) -> dict[str, object]:
        return {
            "jobs": [
                {
                    "id": run_id * 100 + index,
                    "run_id": run_id,
                    "name": name,
                    "status": "completed",
                    "conclusion": "success",
                    "steps": [
                        {"name": "run", "conclusion": "success"},
                        {"name": "post", "conclusion": "skipped"},
                    ],
                }
                for index, name in enumerate(sorted(names), 1)
            ]
        }

    def _artifact(self, artifact_id: int, run_id: int, name: str, raw: bytes) -> dict[str, object]:
        url = f"https://objects.example/{artifact_id}.zip"
        self.blobs[url] = raw
        return {
            "id": artifact_id,
            "name": name,
            "size_in_bytes": len(raw),
            "archive_download_url": url,
            "expired": False,
            "expires_at": "2026-12-31T00:00:00Z",
            "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "workflow_run": {"id": run_id, "head_sha": self.head_commit},
        }

    def _android_receipt(self, kind: str) -> dict[str, object]:
        merge = kind == "synthetic_merge"
        receipt: dict[str, object] = {
            "schema": "org.trillionnium.owner-open.adbroot-evaluated-graph.v1",
            "program_revision": AGG.PROGRAM_REVISION,
            "repository": self.repo,
            "source_commit": self.head_commit,
            "base_commit": self.base_commit if merge else None,
            "evaluated_commit": ("e" * 40) if merge else self.head_commit,
            "evaluated_tree": self.head_tree,
            "evaluation_kind": kind,
            "parent_commits": [self.base_commit, self.head_commit] if merge else [],
            "matrix_case_count": 12,
            "negative_case_count": 10,
            "negative_cases_passed": True,
            "source_inputs_complete": True,
            "service_policy_property_coupled": True,
            "soong_compiled": False,
            "selinux_compiled": False,
            "target_files_built": False,
            "image_built": False,
            "installed": False,
            "physical_device_observed": False,
            "claim_ceiling": "EVALUATED_SECURITY_ANDROID_GRAPH_ONLY_NOT_SOONG_OR_SELINUX_COMPILED",
            "automatic_redispatch": False,
            "public_release": False,
            "receipt_sha256": "",
        }
        receipt["receipt_sha256"] = hashlib.sha256(AGG._canonical(receipt)).hexdigest()
        return receipt

    def _evidence_report(self) -> dict[str, object]:
        return {
            "schema": "org.trillionnium.g1.evidence-verification-report.v2",
            "gap_specs_sha256": "7" * 64,
            "program_revision": AGG.PROGRAM_REVISION,
            "current_source_commit": self.head_commit,
            "package_count": 0,
            "packages": [],
            "all_gaps_promotable": False,
            "promotable_gaps": {},
            "unresolved_gaps": ["GAP-GOVERNANCE-001"],
            "trusted_attestation": None,
            "automatic_redispatch": False,
            "public_release": False,
        }

    def _promotion_plan(self) -> dict[str, object]:
        return {
            "schema": "org.trillionnium.g1.gap-promotion-plan.v1",
            "gap_specs_sha256": "7" * 64,
            "program_revision": AGG.PROGRAM_REVISION,
            "current_source_commit": self.head_commit,
            "transitions": [],
            "unresolved_gaps": ["GAP-GOVERNANCE-001"],
            "zero_gap_after_plan": False,
            "automatic_redispatch": False,
            "public_release_after_plan": False,
        }

