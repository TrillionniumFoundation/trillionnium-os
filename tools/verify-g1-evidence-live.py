#!/usr/bin/env python3
"""Read-only GitHub binding verifier for G1 evidence receipts.

This tool is the network-facing half of the evidence boundary.  It reconciles
the package JSON with live GitHub pull-request, review, workflow-run and
artifact objects, downloads every referenced artifact and checks its raw
archive digest, and only then emits a receipt for an independently controlled
signing step.  The offline core intentionally performs none of these network
operations.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler
import zipfile

SCRIPT_DIR = Path(__file__).resolve().parent
EVIDENCE_TOOLS = SCRIPT_DIR / "evidence"
if str(EVIDENCE_TOOLS) not in sys.path:
    sys.path.insert(0, str(EVIDENCE_TOOLS))

from g1_evidence_contract import (  # noqa: E402
    ATTESTATION_SCHEMA,
    ATTESTATION_SIGNATURE_ALGORITHM,
    ATTESTATION_TRUST_ROOT_ID,
    ATTESTATION_VERSION,
    LEVEL_ORDER,
)
from g1_evidence_core import load_gap_specs, validate_package  # noqa: E402
from g1_evidence_types import (  # noqa: E402
    EvidenceError,
    _git_sha,
    _identifier,
    _sha256,
    _timestamp,
    _validate_subject,
    package_id,
    sha256_bytes,
    strict_json_file,
)

DEFAULT_GAP_REGISTER = SCRIPT_DIR.parent / "docs" / "machine" / "gap-register.v2.json"
GITHUB_ARTIFACT_URI_RE = re.compile(
    r"^github-actions://(?P<repo>[^/]+/[^/]+)/runs/(?P<run_id>[1-9][0-9]*)/artifacts/(?P<artifact_id>[1-9][0-9]*)$"
)


class LiveBindingError(EvidenceError):
    """A live GitHub object does not bind the requested evidence."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LiveBindingError(message)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    """Require an API JSON value to be an object before using ``.get``."""

    _require(isinstance(value, Mapping), f"{label} is not an object")
    return value


def _strict_json_any(content: bytes, label: str) -> Any:
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, LiveBindingError) as error:
        raise LiveBindingError(f"{label} is not strict JSON: {error}") from error
    return value


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LiveBindingError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise LiveBindingError(f"non-finite JSON number {value}")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class ApiResponse:
    value: Any
    raw: bytes
    url: str
    headers: Mapping[str, str]


class GitHubApi:
    """Small read-only GitHub REST client with injectable base URL for tests."""

    def __init__(self, base_url: str = "https://api.github.com/", token: str | None = None, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.timeout = timeout
        self._no_redirect = build_opener(_NoRedirect())

    def _url(self, path_or_url: str) -> str:
        url = (
            path_or_url
            if path_or_url.startswith("http://") or path_or_url.startswith("https://")
            else urljoin(self.base_url, path_or_url.lstrip("/"))
        )
        parsed = urlparse(url)
        _require(parsed.scheme == "https", f"GitHub URL must use HTTPS: {url}")
        _require(bool(parsed.netloc), f"GitHub URL has no host: {url}")
        return url

    def _same_origin(self, url: str) -> bool:
        expected = urlparse(self.base_url)
        actual = urlparse(url)
        return (actual.scheme, actual.hostname, actual.port or 443) == (
            expected.scheme,
            expected.hostname,
            expected.port or 443,
        )

    def _request(self, url: str, *, authenticated: bool = True) -> ApiResponse:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "trillionnium-g1-evidence-live/1",
        }
        if authenticated and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(url, headers=headers, method="GET")
        try:
            with self._no_redirect.open(request, timeout=self.timeout) as response:
                raw = response.read()
                return ApiResponse(None, raw, response.geturl(), dict(response.headers.items()))
        except HTTPError as error:
            if error.code in {301, 302, 303, 307, 308} and error.headers.get("Location"):
                location = urljoin(url, error.headers["Location"])
                location_parsed = urlparse(location)
                _require(
                    location_parsed.scheme == "https" and bool(location_parsed.netloc),
                    "GitHub redirect must remain an HTTPS URL",
                )
                # Signed artifact URLs are fetched without forwarding the API token.
                return self._request(location, authenticated=False)
            detail = error.read().decode("utf-8", errors="replace")[:400]
            raise LiveBindingError(f"GitHub GET {url} failed HTTP {error.code}: {detail}") from error
        except URLError as error:
            raise LiveBindingError(f"GitHub GET {url} failed: {error}") from error
        except OSError as error:
            raise LiveBindingError(f"GitHub GET {url} failed: {error}") from error

    def get_json(self, path: str) -> ApiResponse:
        url = self._url(path)
        response = self._request(url, authenticated=self._same_origin(url))
        return ApiResponse(_strict_json_any(response.raw, url), response.raw, response.url, response.headers)

    def get_bytes(self, path_or_url: str) -> ApiResponse:
        url = self._url(path_or_url)
        return self._request(url, authenticated=self._same_origin(url))

    def get_all(self, path: str) -> list[Any]:
        page = 1
        result: list[Any] = []
        while True:
            separator = "&" if "?" in path else "?"
            response = self.get_json(f"{path}{separator}per_page=100&page={page}")
            _require(isinstance(response.value, list), f"GitHub response {response.url} is not an array")
            result.extend(response.value)
            if len(response.value) < 100:
                return result
            page += 1


def _iso_now(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_packages(
    evidence_dir: Path,
    source_commit: str,
    now: datetime,
    *,
    gap_register: Path,
) -> tuple[list[dict[str, Any]], list[str], str, str]:
    _require(evidence_dir.is_dir(), f"evidence directory does not exist: {evidence_dir}")
    gap_specs = load_gap_specs(gap_register)
    packages: list[dict[str, Any]] = []
    complete_ids: list[str] = []
    source_tree: str | None = None
    source_repository: str | None = None
    source_branch: str | None = None
    source_pull_request: int | None = None
    cargo_lock_sha256: str | None = None
    package_ids: set[str] = set()
    for path in sorted(evidence_dir.glob("*.json")):
        _require(not path.is_symlink(), f"{path} must not be a symlink")
        package = strict_json_file(path, str(path))
        try:
            assessment = validate_package(
                package,
                gap_specs,
                current_source_commit=source_commit,
                now=now,
            )
        except EvidenceError as error:
            raise LiveBindingError(f"{path} fails the evidence package contract: {error}") from error
        _require(
            assessment.evidence_class == "source_qualification",
            "live GitHub binding currently supports source-qualification packages only",
        )
        _require(assessment.package_id not in package_ids, f"duplicate package_id {assessment.package_id}")
        package_ids.add(assessment.package_id)
        _require(package_id(package) == package.get("package_id"), f"{path} package_id is not canonical")
        _require(package.get("status") == "COMPLETE", f"{path} is not COMPLETE; live attestation cannot promote HOLD evidence")
        _require(package.get("source", {}).get("commit") == source_commit, f"{path} source commit is not the requested head")
        expires = _timestamp(package["expires_at"], f"{path}.expires_at")
        _require(expires > now, f"{path} is expired")
        _require(not package["lineage"]["parent_package_ids"], f"{path} L1 source evidence must be a lineage root")
        authorization_expires = _timestamp(package["authorization"]["expires_at"], f"{path}.authorization.expires_at")
        _require(authorization_expires > now, f"{path} authorization has expired")
        _require(authorization_expires >= expires, f"{path} outlives its authorization")
        for artifact in package["artifacts"]:
            retained_until = _timestamp(
                artifact["retention_expires_at"],
                f"{path} artifact {artifact['name']}.retention_expires_at",
            )
            _require(retained_until > now, f"{path} artifact {artifact['name']} retention has expired")
            _require(retained_until >= expires, f"{path} outlives artifact {artifact['name']}")
        if source_tree is None:
            source_tree = package["source"]["tree"]
        _require(source_tree == package["source"]["tree"], f"{path} source tree differs across packages")
        source = package["source"]
        if source_repository is None:
            source_repository = source["repository"]
            source_branch = source["branch"]
            source_pull_request = source["pull_request"]
            cargo_lock_sha256 = source["cargo_lock_sha256"]
        _require(source_repository == source["repository"], f"{path} source repository differs across packages")
        _require(source_branch == source["branch"], f"{path} source branch differs across packages")
        _require(source_pull_request == source["pull_request"], f"{path} source pull request differs across packages")
        _require(cargo_lock_sha256 == source["cargo_lock_sha256"], f"{path} Cargo.lock digest differs across packages")
        packages.append(package)
        complete_ids.append(package["package_id"])
    _require(bool(packages), "live attestation requires at least one current COMPLETE package")
    assert source_tree is not None
    assert source_repository is not None and source_branch is not None
    assert source_pull_request is not None and cargo_lock_sha256 is not None
    by_id = {package["package_id"]: package for package in packages}
    for package in packages:
        level = LEVEL_ORDER[package["level"]]
        for parent_id in package["lineage"]["parent_package_ids"]:
            _require(parent_id in by_id, f"{package['package_id']} references missing parent {parent_id}")
            parent = by_id[parent_id]
            _require(LEVEL_ORDER[parent["level"]] < level, f"{package['package_id']} parent {parent_id} is not lower level")
            _require(parent["source"]["commit"] == source_commit, f"{package['package_id']} parent {parent_id} is not on the requested head")
    return packages, sorted(complete_ids), source_tree, cargo_lock_sha256


def _verify_pull_request(api: GitHubApi, repo: str, pr_number: int, source_commit: str) -> dict[str, Any]:
    response = api.get_json(f"repos/{repo}/pulls/{pr_number}")
    pr = _mapping(response.value, "pull request response")
    head = _mapping(pr.get("head"), "pull request head")
    base = _mapping(pr.get("base"), "pull request base")
    user = _mapping(pr.get("user"), "pull request user")
    head_repo = _mapping(head.get("repo"), "pull request head repository")
    base_repo = _mapping(base.get("repo"), "pull request base repository")
    _require(pr.get("number") == pr_number, "pull request number mismatch")
    _require(head.get("sha") == source_commit, "pull request head does not match source commit")
    author = user.get("login")
    _require(isinstance(author, str) and author, "pull request author is missing")
    head_ref = head.get("ref")
    base_ref = base.get("ref")
    base_sha = base.get("sha")
    _require(isinstance(head_ref, str) and head_ref, "pull request head branch is missing")
    _require(isinstance(base_ref, str) and base_ref, "pull request base branch is missing")
    _identifier(head_ref, "pull request head branch")
    _identifier(base_ref, "pull request base branch")
    _require(isinstance(base_sha, str) and base_sha, "pull request base commit is missing")
    _git_sha(base_sha, "pull request base commit")
    _require(pr.get("draft") is False, "pull request is still a draft")
    head_repository = head_repo.get("full_name")
    _require(
        isinstance(head_repository, str)
        and "/" in head_repository
        and head_repository != ""
        and ".." not in head_repository,
        "pull request head repository is malformed",
    )
    _identifier(head_repository, "pull request head repository")
    _require(
        base_repo.get("full_name") == repo,
        "pull request base repository differs from requested repository",
    )
    return {
        "number": pr_number,
        "head_sha": source_commit,
        "head_ref": head_ref,
        "head_repository": head_repository,
        "base_ref": base_ref,
        "base_sha": base_sha,
        "base_repository": base_repo["full_name"],
        "merge_commit_sha": pr.get("merge_commit_sha"),
        "author": author,
        "state": pr.get("state"),
        "draft": pr.get("draft"),
        "response_sha256": sha256_bytes(response.raw),
    }


def _verify_review(api: GitHubApi, repo: str, pr_number: int, source_commit: str, author: str) -> dict[str, Any]:
    reviews = api.get_all(f"repos/{repo}/pulls/{pr_number}/reviews")
    _require(isinstance(reviews, list), "GitHub reviews response is not an array")
    normalized: list[Mapping[str, Any]] = []
    for index, raw_item in enumerate(reviews):
        item = _mapping(raw_item, f"GitHub review[{index}]")
        submitted_at = item.get("submitted_at")
        # GitHub can return an unsubmitted pending review with a null
        # timestamp.  It cannot be an approval, so it is ignored after its
        # object shape has still been checked.
        if submitted_at is None:
            continue
        _require(isinstance(submitted_at, str) and submitted_at, f"GitHub review[{index}].submitted_at is invalid")
        _timestamp(submitted_at, "GitHub review.submitted_at")
        normalized.append(item)
    normalized.sort(key=lambda item: item.get("submitted_at", ""))

    def review_login(item: Mapping[str, Any], index: int) -> str | None:
        user = item.get("user")
        if user is None:
            return None
        return _mapping(user, f"GitHub review[{index}].user").get("login")  # type: ignore[return-value]

    exact_approvals = [
        item
        for index, item in enumerate(normalized)
        if item.get("state") == "APPROVED"
        and item.get("commit_id") == source_commit
        and review_login(item, index) not in {None, author}
    ]
    _require(bool(exact_approvals), "no independent APPROVED review is bound to the exact source commit")
    approval = exact_approvals[-1]
    later_changes = [
        item
        for item in normalized
        if item.get("submitted_at", "") >= approval.get("submitted_at", "")
        and item.get("state") in {"CHANGES_REQUESTED", "DISMISSED"}
    ]
    _require(not later_changes, "a later CHANGES_REQUESTED review invalidates the exact-head approval")
    reviewer = review_login(approval, normalized.index(approval))
    review_id = approval.get("id")
    _require(
        isinstance(reviewer, str)
        and reviewer
        and reviewer != author
        and type(review_id) is int
        and review_id > 0,
        "approved review identity is incomplete",
    )
    return {
        "id": review_id,
        "reviewer": reviewer,
        "commit_id": source_commit,
        "state": "APPROVED",
        "submitted_at": approval["submitted_at"],
        "response_sha256": sha256_bytes(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()),
    }


def _verify_commit_tree(api: GitHubApi, repo: str, source_commit: str, expected_tree: str) -> dict[str, Any]:
    response = api.get_json(f"repos/{repo}/commits/{source_commit}")
    value = _mapping(response.value, "commit response")
    _require(value.get("sha") == source_commit, "GitHub commit identity does not match requested source commit")
    commit = _mapping(value.get("commit"), "GitHub commit.commit")
    tree_object = _mapping(commit.get("tree"), "GitHub commit.tree")
    tree = tree_object.get("sha")
    _require(isinstance(tree, str) and tree, "GitHub commit tree is missing")
    _require(tree == expected_tree, "GitHub commit tree does not match evidence source.tree")
    return {"commit": source_commit, "tree": tree, "response_sha256": sha256_bytes(response.raw)}


def _verify_commit_identity(
    api: GitHubApi,
    repo: str,
    commit_sha: str,
    *,
    expected_tree: str | None = None,
    expected_parents: list[str] | None = None,
) -> dict[str, Any]:
    """Read a commit's tree and ordered parents from the live GitHub API."""

    _git_sha(commit_sha, "commit_sha")
    response = api.get_json(f"repos/{repo}/commits/{commit_sha}")
    value = _mapping(response.value, "commit response")
    _require(value.get("sha") == commit_sha, "GitHub commit identity does not match requested commit")
    commit = _mapping(value.get("commit"), "GitHub commit.commit")
    tree_object = _mapping(commit.get("tree"), "GitHub commit.tree")
    tree = tree_object.get("sha")
    _require(isinstance(tree, str) and tree, "GitHub commit tree is missing")
    _git_sha(tree, "GitHub commit tree")
    parent_objects = value.get("parents")
    _require(isinstance(parent_objects, list), "GitHub commit parents are missing")
    parents: list[str] = []
    for index, parent in enumerate(parent_objects):
        parent_mapping = _mapping(parent, f"GitHub commit parent[{index}]")
        parent_sha = parent_mapping.get("sha")
        _git_sha(parent_sha, f"GitHub commit parent[{index}].sha")
        parents.append(parent_sha)
    if expected_tree is not None:
        _require(tree == expected_tree, "GitHub commit tree does not match expected tree")
    if expected_parents is not None:
        _require(parents == expected_parents, "GitHub commit parents do not match expected ordered parents")
    return {
        "commit": commit_sha,
        "tree": tree,
        "parents": parents,
        "response_sha256": sha256_bytes(response.raw),
    }


def _verify_cargo_lock(
    api: GitHubApi,
    repo: str,
    source_commit: str,
    expected_sha256: str,
) -> dict[str, Any]:
    """Fetch Cargo.lock at the exact commit and bind its raw bytes."""

    response = api.get_json(f"repos/{repo}/contents/Cargo.lock?ref={source_commit}")
    value = response.value
    _require(isinstance(value, dict), "Cargo.lock response is not an object")
    _require(value.get("path") == "Cargo.lock", "GitHub returned an unexpected Cargo.lock path")
    _require(value.get("encoding") == "base64", "GitHub did not return Cargo.lock as base64")
    content = value.get("content")
    _require(isinstance(content, str) and content, "GitHub Cargo.lock content is missing")
    try:
        raw = base64.b64decode("".join(content.split()), validate=True)
    except (ValueError, binascii.Error) as error:
        raise LiveBindingError(f"GitHub Cargo.lock content is not valid base64: {error}") from error
    digest = sha256_bytes(raw)
    _require(digest == expected_sha256, "GitHub Cargo.lock digest does not match evidence source")
    return {
        "path": "Cargo.lock",
        "commit": source_commit,
        "bytes": len(raw),
        "sha256": digest,
        "response_sha256": sha256_bytes(response.raw),
    }


def _parse_artifact_uri(uri: str, label: str) -> tuple[str, int, int]:
    match = GITHUB_ARTIFACT_URI_RE.fullmatch(uri)
    _require(match is not None, f"{label} must use a canonical github-actions artifact URI")
    assert match is not None
    return match.group("repo"), int(match.group("run_id")), int(match.group("artifact_id"))


SYNTHETIC_MERGE_SCHEMA = "org.trillionnium.g1-synthetic-merge-evidence.v1"
SYNTHETIC_MERGE_KEYS = {
    "schema",
    "program_revision",
    "repository",
    "head_repository",
    "event_name",
    "pull_request_number",
    "base_ref",
    "head_ref",
    "base_commit",
    "base_tree",
    "head_commit",
    "head_tree",
    "parent_commits",
    "merge_commit",
    "merge_tree",
    "cargo_lock_sha256",
    "workflow_run_id",
    "workflow_attempt",
    "result",
    "claim_ceiling",
    "automatic_redispatch",
    "public_release",
}


def _positive_decimal(value: Any, label: str) -> int:
    """Accept the stringly-typed IDs emitted by GitHub Actions receipts."""

    if type(value) is int:
        _require(value > 0, f"{label} must be positive")
        return value
    _require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value) is not None, f"{label} is invalid")
    return int(value)


def _validate_synthetic_merge_receipt(value: Any, label: str) -> dict[str, Any]:
    """Validate the JSON *inside* a synthetic-merge artifact archive.

    Checking only the archive's outer SHA permits an old, validly retained ZIP
    to be replayed after a PR base moves.  Every provenance field is therefore
    checked before it can contribute to the signed subject.
    """

    receipt = _mapping(value, label)
    _require(set(receipt) == SYNTHETIC_MERGE_KEYS, f"{label} keys drift")
    _require(receipt["schema"] == SYNTHETIC_MERGE_SCHEMA, f"{label}.schema is unsupported")
    _require(receipt["program_revision"] == "2026-08-31-g1", f"{label}.program_revision drifted")
    for field in ("repository", "head_repository"):
        repository = receipt[field]
        _require(isinstance(repository, str) and "/" in repository, f"{label}.{field} is invalid")
        _identifier(repository, f"{label}.{field}")
    _require(receipt["event_name"] in {"pull_request", "workflow_dispatch"}, f"{label}.event_name is unsupported")
    pr_number = receipt["pull_request_number"]
    if pr_number is not None:
        pr_number = _positive_decimal(pr_number, f"{label}.pull_request_number")
    for field in ("base_ref", "head_ref"):
        ref = receipt[field]
        if ref is not None:
            _identifier(ref, f"{label}.{field}")
    for field in ("base_commit", "base_tree", "head_commit", "head_tree", "merge_commit", "merge_tree"):
        _git_sha(receipt[field], f"{label}.{field}")
    parents = receipt["parent_commits"]
    _require(isinstance(parents, list) and len(parents) == 2, f"{label}.parent_commits must contain two parents")
    for index, parent in enumerate(parents):
        _git_sha(parent, f"{label}.parent_commits[{index}]")
    _require(parents == [receipt["base_commit"], receipt["head_commit"]], f"{label}.parent_commits are not ordered base then head")
    _require(receipt["merge_commit"] not in parents, f"{label}.merge_commit must differ from parents")
    _sha256(receipt["cargo_lock_sha256"], f"{label}.cargo_lock_sha256")
    _positive_decimal(receipt["workflow_run_id"], f"{label}.workflow_run_id")
    _positive_decimal(receipt["workflow_attempt"], f"{label}.workflow_attempt")
    _require(receipt["result"] == "L1_SYNTHETIC_MERGE_SOURCE_CLOSURE_PASSED", f"{label}.result is not a pass")
    _require(receipt["claim_ceiling"] == "EXACT_TWO_PARENT_SOURCE_MERGE_GATES_PASSED_NOT_INSTALLED_TARGET", f"{label}.claim_ceiling drifted")
    _require(receipt["automatic_redispatch"] is False, f"{label}.automatic_redispatch must be false")
    _require(receipt["public_release"] is False, f"{label}.public_release must be false")
    normalized = dict(receipt)
    normalized["pull_request_number"] = pr_number
    normalized["workflow_run_id"] = _positive_decimal(receipt["workflow_run_id"], f"{label}.workflow_run_id")
    normalized["workflow_attempt"] = _positive_decimal(receipt["workflow_attempt"], f"{label}.workflow_attempt")
    return normalized


def _extract_synthetic_merge_receipt(raw: bytes, label: str) -> dict[str, Any]:
    """Extract exactly one bounded synthetic receipt from a GitHub artifact ZIP."""

    _require(len(raw) <= 256 * 1024 * 1024, f"{label} archive is unexpectedly large")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = [info for info in archive.infolist() if info.filename == "g1-synthetic-merge-evidence.json"]
            _require(len(members) == 1, f"{label} must contain exactly one synthetic merge receipt")
            member = members[0]
            _require(member.file_size <= 1024 * 1024, f"{label} synthetic receipt is too large")
            _require(member.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}, f"{label} uses unsupported compression")
            _require((member.flag_bits & 0x1) == 0, f"{label} synthetic receipt is encrypted")
            mode = (member.external_attr >> 16) & 0o170000
            _require(mode != 0o120000, f"{label} synthetic receipt must not be a symlink")
            content = archive.read(member)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, RuntimeError) as error:
        raise LiveBindingError(f"{label} is not a readable artifact ZIP: {error}") from error
    value = _strict_json_any(content, f"{label}/g1-synthetic-merge-evidence.json")
    return _validate_synthetic_merge_receipt(value, f"{label} synthetic merge receipt")


def _verify_workflows_and_artifacts(
    api: GitHubApi,
    repo: str,
    packages: Iterable[dict[str, Any]],
    source_commit: str,
    now: datetime,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    """Bind every package artifact to an exact successful GitHub run.

    The package has two independently retained references (workflow-run refs and
    artifact records).  Every workflow reference must have a matching artifact,
    while extra package artifacts are also fetched and checked rather than
    silently omitted.
    """

    package_list = list(packages)
    workflow_refs: dict[tuple[int, int], dict[str, Any]] = {}
    artifact_refs: dict[tuple[int, int], tuple[dict[str, Any], dict[str, Any]]] = {}
    for package in package_list:
        for run_ref in package["source"]["workflow_runs"]:
            key = (run_ref["run_id"], run_ref["artifact_id"])
            _require(key not in workflow_refs, f"duplicate workflow/artifact reference {key}")
            workflow_refs[key] = run_ref
        for artifact_ref in package["artifacts"]:
            _require(
                artifact_ref["kind"] == "github_actions_artifact",
                f"artifact {artifact_ref['name']} is not a GitHub Actions artifact",
            )
            artifact_repo, run_id, artifact_id = _parse_artifact_uri(
                artifact_ref["uri"], f"artifact {artifact_ref['name']}.uri"
            )
            _require(artifact_repo == repo, f"artifact {artifact_ref['name']} repository differs from requested repository")
            key = (run_id, artifact_id)
            _require(key not in artifact_refs, f"duplicate artifact reference {key}")
            artifact_refs[key] = (package, artifact_ref)

    _require(bool(workflow_refs), "live attestation requires workflow-run references")
    _require(
        set(workflow_refs).issubset(artifact_refs),
        "package workflow-run references are missing matching artifact records",
    )
    _require(
        {run_id for run_id, _artifact_id in artifact_refs}
        <= {run_id for run_id, _artifact_id in workflow_refs},
        "package artifact references use a workflow run not declared in source.workflow_runs",
    )

    run_responses: dict[int, tuple[dict[str, Any], ApiResponse]] = {}
    for run_id, _artifact_id in sorted(artifact_refs):
        if run_id in run_responses:
            continue
        response = api.get_json(f"repos/{repo}/actions/runs/{run_id}")
        run = _mapping(response.value, f"workflow run {run_id} response")
        _require(run.get("id") == run_id, f"workflow run {run_id} identity mismatch")
        _require(run.get("head_sha") == source_commit, f"workflow run {run_id} head does not match source commit")
        _require(
            run.get("status") == "completed" and run.get("conclusion") == "success",
            f"workflow run {run_id} is not terminal success",
        )
        _require(type(run.get("run_attempt")) is int and run["run_attempt"] > 0, f"workflow run {run_id} attempt is invalid")
        run_responses[run_id] = (run, response)

    for (run_id, artifact_id), run_ref in workflow_refs.items():
        run, _response = run_responses[run_id]
        _require(run.get("run_attempt") == run_ref["attempt"], f"workflow run {run_id} attempt mismatch")
        _require(run.get("name") == run_ref["name"], f"workflow run {run_id} workflow name mismatch")

    runs: list[dict[str, Any]] = []
    evidence_ids: list[str] = []
    for run_id in sorted(run_responses):
        run, response = run_responses[run_id]
        artifact_keys = sorted(key for key in artifact_refs if key[0] == run_id)
        runs.append(
            {
                "id": run_id,
                "name": run.get("name"),
                "head_sha": run.get("head_sha"),
                "run_attempt": run.get("run_attempt"),
                "artifact_ids": [key[1] for key in artifact_keys],
                "response_sha256": sha256_bytes(response.raw),
            }
        )
        evidence_ids.append(f"workflow-run-{run_id}")

    artifacts: list[dict[str, Any]] = []
    synthetic_receipts: list[dict[str, Any]] = []
    for key in sorted(artifact_refs):
        run_id, artifact_id = key
        package, declared = artifact_refs[key]
        run_ref = workflow_refs.get(key)
        run, _run_response = run_responses[run_id]
        response = api.get_json(f"repos/{repo}/actions/artifacts/{artifact_id}")
        artifact = _mapping(response.value, f"artifact {artifact_id} response")
        _require(artifact.get("id") == artifact_id, f"artifact {artifact_id} identity mismatch")
        if run_ref is not None:
            _require(artifact.get("name") == run_ref["artifact_name"], f"artifact {artifact_id} workflow reference name mismatch")
        _require(artifact.get("name") == declared["name"], f"artifact {artifact_id} package name mismatch")
        _require(artifact.get("expired") is False, f"artifact {artifact_id} is expired")
        artifact_expires_at = artifact.get("expires_at")
        _require(isinstance(artifact_expires_at, str), f"artifact {artifact_id} has no retention expiry")
        artifact_expiry = _timestamp(artifact_expires_at, f"artifact {artifact_id}.expires_at")
        _require(artifact_expiry > now, f"artifact {artifact_id} retention has expired")
        declared_expiry = _timestamp(declared["retention_expires_at"], f"artifact {artifact_id}.retention_expires_at")
        _require(declared_expiry <= artifact_expiry, f"artifact {artifact_id} package retention exceeds GitHub retention")
        workflow_run = _mapping(artifact.get("workflow_run"), f"artifact {artifact_id}.workflow_run")
        _require(workflow_run.get("id") == run_id, f"artifact {artifact_id} workflow ownership is not exact")
        archive_url = artifact.get("archive_download_url")
        _require(isinstance(archive_url, str) and archive_url, f"artifact {artifact_id} has no archive URL")
        archive = api.get_bytes(archive_url)
        archive_sha256 = sha256_bytes(archive.raw)
        if run_ref is not None:
            _require(archive_sha256 == run_ref["artifact_sha256"], f"artifact {artifact_id} archive digest mismatch (workflow reference)")
        _require(archive_sha256 == declared["sha256"], f"artifact {artifact_id} archive digest mismatch (package)")
        api_size = artifact.get("size_in_bytes")
        _require(type(api_size) is int and api_size > 0, f"artifact {artifact_id} size is invalid")
        _require(api_size == len(archive.raw), f"artifact {artifact_id} API size differs from downloaded bytes")
        _require(declared["bytes"] == api_size, f"artifact {artifact_id} package byte count differs from GitHub")
        if declared["name"].startswith("g1-synthetic-merge-"):
            synthetic_receipt = _extract_synthetic_merge_receipt(
                archive.raw, f"artifact {artifact_id} ({declared['name']})"
            )
            _require(
                declared["name"] == f"g1-synthetic-merge-{synthetic_receipt['merge_commit']}",
                f"artifact {artifact_id} name is not bound to its synthetic merge commit",
            )
            _require(
                synthetic_receipt["workflow_run_id"] == run_id,
                f"artifact {artifact_id} synthetic receipt workflow run is not exact",
            )
            _require(
                synthetic_receipt["workflow_attempt"] == run_ref["attempt"],
                f"artifact {artifact_id} synthetic receipt workflow attempt is not exact",
            )
            synthetic_receipts.append(synthetic_receipt)
        artifacts.append(
            {
                "id": artifact_id,
                "run_id": run_id,
                "name": artifact["name"],
                "size_in_bytes": api_size,
                "download_bytes": len(archive.raw),
                "sha256": archive_sha256,
                "response_sha256": sha256_bytes(response.raw),
                "archive_url": archive.url,
                "expires_at": artifact_expires_at,
            }
        )
        evidence_ids.append(f"artifact-{artifact_id}")
    return runs, artifacts, evidence_ids, synthetic_receipts


def verify_live_binding(
    *,
    repo: str,
    pr_number: int,
    source_commit: str,
    evidence_dir: Path,
    api: GitHubApi,
    now: datetime | None = None,
    gap_register: Path = DEFAULT_GAP_REGISTER,
    expected_base_branch: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a detailed live report and an unsigned receipt after all checks."""

    _require("/" in repo and not repo.startswith("http"), "repo must use owner/repository form")
    _git_sha(source_commit, "source_commit")
    reference_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    packages, package_ids, source_tree, cargo_lock_sha256 = _load_packages(
        evidence_dir,
        source_commit,
        reference_now,
        gap_register=gap_register,
    )
    pull_request = _verify_pull_request(api, repo, pr_number, source_commit)
    _require(pull_request["state"] == "open", "pull request is not open")
    if expected_base_branch is not None:
        _identifier(expected_base_branch, "expected_base_branch")
        _require(
            pull_request["base_ref"] == expected_base_branch,
            "pull request base branch does not match the requested integration branch",
        )
    for package in packages:
        source = package["source"]
        _require(
            source["repository"] == pull_request["head_repository"],
            f"{package['package_id']} source repository differs from pull-request head",
        )
        _require(source["pull_request"] == pr_number, f"{package['package_id']} source pull request differs from request")
        _require(source["branch"] == pull_request["head_ref"], f"{package['package_id']} source branch differs from pull request head")
    review = _verify_review(api, repo, pr_number, source_commit, pull_request["author"])
    for package in packages:
        roles = package["roles"]
        _require(
            roles["producer"]["principal"] == pull_request["author"],
            f"{package['package_id']} producer is not the live pull-request author",
        )
        _require(
            roles["reviewer"]["principal"] == review["reviewer"],
            f"{package['package_id']} reviewer is not the live independent reviewer",
        )
        _require(
            roles["authorizer"]["principal"] == review["reviewer"],
            f"{package['package_id']} authorizer is not the live independent reviewer",
        )
        observations = package["observations"]
        if package["evidence_class"] == "source_qualification":
            _require(
                observations.get("review_id") == review["id"]
                and observations.get("review_commit") == source_commit
                and observations.get("review_state") == "APPROVED",
                f"{package['package_id']} review observations are not bound to the live approval",
            )
    commit = _verify_commit_identity(
        api,
        repo,
        source_commit,
        expected_tree=source_tree,
    )
    base_commit = _verify_commit_identity(api, repo, pull_request["base_sha"])
    cargo_lock = _verify_cargo_lock(api, repo, source_commit, cargo_lock_sha256)
    workflows, artifacts, evidence_ids, synthetic_receipts = _verify_workflows_and_artifacts(
        api, repo, packages, source_commit, reference_now
    )
    _require(
        len(synthetic_receipts) == 1,
        "live source qualification requires exactly one current synthetic-merge receipt",
    )
    synthetic = synthetic_receipts[0]
    _require(synthetic["event_name"] == "pull_request", "synthetic merge receipt is not PR-bound")
    _require(synthetic["pull_request_number"] == pr_number, "synthetic merge receipt PR number is not exact")
    _require(synthetic["repository"] == pull_request["base_repository"], "synthetic merge base repository differs from live PR")
    _require(synthetic["head_repository"] == pull_request["head_repository"], "synthetic merge head repository differs from live PR")
    _require(synthetic["base_ref"] == pull_request["base_ref"], "synthetic merge base ref differs from live PR")
    _require(synthetic["head_ref"] == pull_request["head_ref"], "synthetic merge head ref differs from live PR")
    _require(synthetic["base_commit"] == pull_request["base_sha"], "synthetic merge base commit differs from live PR")
    _require(synthetic["head_commit"] == source_commit, "synthetic merge head commit differs from live PR")
    _require(synthetic["base_tree"] == base_commit["tree"], "synthetic merge base tree differs from live GitHub commit")
    _require(synthetic["head_tree"] == source_tree, "synthetic merge head tree differs from live source commit")
    _require(synthetic["cargo_lock_sha256"] == cargo_lock_sha256, "synthetic merge Cargo.lock digest differs from source package")
    # Re-read the PR after downloading and inspecting the archive.  This
    # closes the API-level TOCTOU window in which a base/head/ref could move
    # between the first PR response and subject construction.
    pull_request_final = _verify_pull_request(api, repo, pr_number, source_commit)
    identity_fields = (
        "head_sha",
        "head_ref",
        "head_repository",
        "base_ref",
        "base_sha",
        "base_repository",
        "merge_commit_sha",
    )
    _require(
        all(pull_request_final[field] == pull_request[field] for field in identity_fields),
        "pull request base/head identity changed during live binding",
    )
    subject = {
        "base": {
            "repository": pull_request["base_repository"],
            "ref": pull_request["base_ref"],
            "commit": pull_request["base_sha"],
            "tree": synthetic["base_tree"],
        },
        "head": {
            "repository": pull_request["head_repository"],
            "ref": pull_request["head_ref"],
            "commit": source_commit,
            "tree": source_tree,
        },
        "merge": {
            "kind": "deterministic_synthetic",
            "commit": synthetic["merge_commit"],
            "tree": synthetic["merge_tree"],
            "parents": list(synthetic["parent_commits"]),
        },
    }
    _validate_subject(subject)
    for package in packages:
        _require(
            package["subject"] == subject,
            f"{package['package_id']} subject does not match the current live base/head/merge",
        )
    github_merge: dict[str, Any] | None = None
    prospective_sha = pull_request.get("merge_commit_sha")
    if prospective_sha is not None:
        _git_sha(prospective_sha, "pull request merge_commit_sha")
        github_merge = _verify_commit_identity(
            api,
            repo,
            prospective_sha,
            expected_tree=synthetic["merge_tree"],
            expected_parents=[pull_request["base_sha"], source_commit],
        )
    artifact_expiries: list[datetime] = [
        _timestamp(item["expires_at"], "GitHub artifact.expires_at") for item in artifacts
    ]
    for package in packages:
        artifact_expiries.extend(_timestamp(item["retention_expires_at"], "artifact.retention_expires_at") for item in package["artifacts"])
    package_expiries = [_timestamp(package["expires_at"], "package.expires_at") for package in packages]
    expires_at = min(package_expiries + artifact_expiries) if artifact_expiries else min(package_expiries)
    _require(expires_at > reference_now, "all package/artifact retention windows have expired")
    receipt = {
        "schema": ATTESTATION_SCHEMA,
        "version": ATTESTATION_VERSION,
        "package_ids": package_ids,
        "source_commit": source_commit,
        "subject": subject,
        "authority": f"github-live-pr-{pr_number}",
        "verification_method": "github-api-review-run-artifact-digest",
        "trust_root": ATTESTATION_TRUST_ROOT_ID,
        "signature_algorithm": ATTESTATION_SIGNATURE_ALGORITHM,
        "independent_verification": True,
        "verified_at": _iso_now(reference_now),
        "expires_at": _iso_now(expires_at),
        "evidence_ids": sorted(set(evidence_ids + [f"review-{review['id']}", f"commit-{source_commit}"])),
    }
    report = {
        "schema": "org.trillionnium.g1.live-binding-report.v2",
        "repo": repo,
        "pull_request": pull_request,
        "review": review,
        "commit": commit,
        "base_commit": base_commit,
        "cargo_lock": cargo_lock,
        "subject": subject,
        "synthetic_merge": synthetic,
        "github_prospective_merge": github_merge,
        "source_binding": {
            "repository": repo,
            "pull_request": pr_number,
            "head_ref": pull_request["head_ref"],
            "head_repository": pull_request["head_repository"],
            "base_ref": pull_request["base_ref"],
            "base_sha": pull_request["base_sha"],
            "base_repository": pull_request["base_repository"],
        },
        "workflow_runs": workflows,
        "artifacts": artifacts,
        "package_ids": package_ids,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "receipt": receipt,
        "receipt_sha256": sha256_bytes(_receipt_bytes(receipt)),
    }
    return report, receipt


def _receipt_bytes(receipt: Mapping[str, Any]) -> bytes:
    return json.dumps(receipt, ensure_ascii=True, sort_keys=True, indent=2).encode("utf-8") + b"\n"


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> str:
    raw = _receipt_bytes(receipt)
    _write_external_bytes(path, raw, label="attestation output")
    return sha256_bytes(raw)


def _assert_external_output(path: Path, *, repository_root: Path, evidence_dir: Path, label: str) -> None:
    try:
        if "\x00" in str(path):
            raise LiveBindingError(f"{label} contains a NUL")
        if path.is_symlink() or path.exists():
            raise LiveBindingError(f"{label} already exists; refusing overwrite or symlink traversal")
        _require(path.parent.is_dir(), f"{label} parent directory must already exist")
        lexical = path.absolute()
        resolved = path.resolve(strict=False)
        root = repository_root.resolve(strict=True)
        evidence_root = evidence_dir.resolve(strict=True)
        parent_resolved = path.parent.resolve(strict=True)
        _require(
            not lexical.is_relative_to(root)
            and not lexical.is_relative_to(evidence_root)
            and not resolved.is_relative_to(root)
            and not resolved.is_relative_to(evidence_root)
            and not parent_resolved.is_relative_to(root)
            and not parent_resolved.is_relative_to(evidence_root),
            f"{label} must be outside the repository and evidence directories",
        )
    except LiveBindingError:
        raise
    except (OSError, RuntimeError) as error:
        raise LiveBindingError(f"cannot validate {label}: {error}") from error


def _read_external_token(path: Path, *, repository_root: Path, evidence_dir: Path) -> str:
    """Read a token only from a non-symlink file outside controlled inputs."""

    try:
        if "\x00" in str(path):
            raise LiveBindingError("token-file contains a NUL")
        if path.is_symlink():
            raise LiveBindingError("token-file must not be a symlink")
        lexical = path.absolute()
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise LiveBindingError("token-file is not a regular file")
        root = repository_root.resolve(strict=True)
        evidence_root = evidence_dir.resolve(strict=True)
        _require(
            not lexical.is_relative_to(root)
            and not resolved.is_relative_to(root)
            and not lexical.is_relative_to(evidence_root)
            and not resolved.is_relative_to(evidence_root),
            "token-file must be outside the repository and evidence directories",
        )
        metadata = resolved.stat()
        _require(not stat.S_IMODE(metadata.st_mode) & 0o077, "token-file must not be group/world accessible")
        _require(metadata.st_size <= 16 * 1024, "token-file is unexpectedly large")
        token = resolved.read_text(encoding="utf-8").strip()
        _require(bool(token), "token-file is empty")
        return token
    except LiveBindingError:
        raise
    except (OSError, RuntimeError, UnicodeError) as error:
        raise LiveBindingError(f"cannot read token-file: {error}") from error


def _require_official_api_base(value: str) -> None:
    """Prevent the CLI from forwarding a GitHub token to an arbitrary host."""

    parsed = urlparse(value)
    _require(
        parsed.scheme == "https"
        and parsed.hostname == "api.github.com"
        and parsed.port is None
        and parsed.username is None
        and parsed.password is None
        and parsed.query == ""
        and parsed.fragment == "",
        "--api-base must be the official https://api.github.com endpoint",
    )


def _write_external_bytes(path: Path, raw: bytes, *, label: str) -> None:
    """Create an already-validated external output without following symlinks."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short write while creating external output")
            offset += written
        os.fsync(descriptor)
    except OSError as error:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise LiveBindingError(f"cannot create {label}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--gap-register", type=Path, default=DEFAULT_GAP_REGISTER)
    parser.add_argument("--base-branch", required=True, help="expected protected integration base branch")
    parser.add_argument("--output", required=True, type=Path, help="unsigned attestation receipt output")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--repo-root", type=Path, default=SCRIPT_DIR.parent)
    parser.add_argument("--api-base", default="https://api.github.com/")
    parser.add_argument("--token-file", type=Path, help="file containing a GitHub token")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        repository_root = args.repo_root.resolve(strict=True)
        evidence_dir = args.evidence_dir.resolve(strict=True)
        gap_register = args.gap_register.resolve(strict=True)
        token = (
            _read_external_token(
                args.token_file,
                repository_root=repository_root,
                evidence_dir=evidence_dir,
            )
            if args.token_file
            else os.environ.get("GITHUB_TOKEN")
        )
        if not token:
            raise LiveBindingError("a GitHub token is required for authoritative live binding")
        _require_official_api_base(args.api_base)
        api = GitHubApi(args.api_base, token=token)
        _assert_external_output(
            args.output,
            repository_root=repository_root,
            evidence_dir=evidence_dir,
            label="attestation output",
        )
        if args.report:
            _assert_external_output(
                args.report,
                repository_root=repository_root,
                evidence_dir=evidence_dir,
                label="live report output",
            )
        report, receipt = verify_live_binding(
            repo=args.repo,
            pr_number=args.pr,
            source_commit=args.source_commit,
            evidence_dir=evidence_dir,
            api=api,
            gap_register=gap_register,
            expected_base_branch=args.base_branch,
        )
        receipt_sha256 = _write_receipt(args.output, receipt)
        report["receipt_sha256"] = receipt_sha256
        if args.report:
            report_raw = json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2).encode("utf-8") + b"\n"
            _write_external_bytes(args.report, report_raw, label="live report output")
        print(json.dumps({"receipt": str(args.output), "receipt_sha256": receipt_sha256, "report": str(args.report) if args.report else None}, sort_keys=True))
        return 0
    # A hostile or merely malformed API response must be reported as a
    # verification failure, never as a traceback.  The lower-level helpers
    # still raise their typed error for callers/tests; this boundary converts
    # shape errors before any output can be emitted.
    except (EvidenceError, OSError, TypeError, AttributeError, KeyError, ValueError) as error:
        print(f"G1 live evidence verification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
