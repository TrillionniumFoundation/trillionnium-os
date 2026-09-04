#!/usr/bin/env python3
"""Verify the closed-world review index for the cumulative G1 pull request.

The tracked index is an accountability map, not approval or promotion evidence.
It binds the exact live base/head file-change inventory (including rename and
removal semantics) to one and only one owner/security-domain slice per path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any
import urllib.error
import urllib.request

SCHEMA = "org.trillionnium.g1-pr-review-index.v1"
OBSERVATION_SCHEMA = "org.trillionnium.g1-pr-review-index-observation.v1"
REPORT_SCHEMA = "org.trillionnium.g1-pr-review-index-report.v1"
REPOSITORY = "TrillionniumFoundation/trillionnium-os"
INDEX_PATH = "governance/pr41-review-index.v1.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SLICE_ID = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
ALLOWED_STATUSES = {"added", "modified", "removed", "renamed", "copied", "changed", "unchanged"}
INDEX_KEYS = {
    "schema", "program_revision", "repository", "pull_request", "base",
    "review_predecessor", "head_binding", "expected", "changed_paths",
    "changes", "slices", "claim_ceiling", "automatic_redispatch",
    "integration_authorized", "promotion_authorized", "public_release",
}
EXPECTED_KEYS = {"path_count", "paths_sha256", "change_count", "changes_sha256"}
IDENTITY_KEYS = {"commit", "tree"}
SLICE_KEYS = {
    "id", "security_domain", "accountable_owner", "independent_reviewers",
    "review_order", "paths",
}
CHANGE_KEYS = {"path", "status", "previous_path"}


class ReviewIndexError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewIndexError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ReviewIndexError(f"non-finite JSON number {value}")


def load_json_bytes(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ReviewIndexError) as error:
        raise ReviewIndexError(f"{label} is not strict UTF-8 JSON: {error}") from error


def load_json(path: Path) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ReviewIndexError(f"cannot read {path}: {error}") from error
    return load_json_bytes(raw, str(path)), raw


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    require(
        actual == expected,
        f"{label} keys drift; missing={sorted(expected-actual)}, extra={sorted(actual-expected)}",
    )


def text(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value), f"{label} must be a non-empty string")
    require("\x00" not in value, f"{label} contains NUL")
    return value


def git_sha(value: Any, label: str) -> str:
    value = text(value, label)
    require(SHA40.fullmatch(value) is not None, f"{label} must be lowercase 40-hex")
    return value


def digest(value: Any, label: str) -> str:
    value = text(value, label)
    require(SHA256.fullmatch(value) is not None, f"{label} must be lowercase 64-hex")
    return value


def positive_int(value: Any, label: str, *, allow_zero: bool = False) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    require(value >= 0 if allow_zero else value > 0, f"{label} is outside its allowed range")
    return value


def normalize_path(value: Any, label: str) -> str:
    value = text(value, label)
    pure = PurePosixPath(value)
    require(not pure.is_absolute(), f"{label} must be repository-relative")
    require("." not in pure.parts and ".." not in pure.parts, f"{label} is not normalized")
    require("\\" not in value and value == pure.as_posix(), f"{label} is not POSIX-normalized")
    return value


def normalize_change(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    exact_keys(value, CHANGE_KEYS, label)
    path = normalize_path(value["path"], f"{label}.path")
    status = text(value["status"], f"{label}.status")
    require(status in ALLOWED_STATUSES, f"{label}.status is unsupported: {status}")
    previous = value["previous_path"]
    if status == "renamed":
        previous = normalize_path(previous, f"{label}.previous_path")
        require(previous != path, f"{label} rename source equals destination")
    else:
        require(previous is None, f"{label}.previous_path is only valid for renamed files")
    return {"path": path, "status": status, "previous_path": previous}


def canonical_paths_digest(paths: list[str]) -> str:
    hasher = hashlib.sha256()
    for path in sorted(paths):
        hasher.update(path.encode("utf-8"))
        hasher.update(b"\0")
    return hasher.hexdigest()


def canonical_changes_digest(changes: list[dict[str, Any]]) -> str:
    hasher = hashlib.sha256()
    for change in sorted(changes, key=lambda item: item["path"]):
        raw = json.dumps(
            change,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        hasher.update(raw)
        hasher.update(b"\n")
    return hasher.hexdigest()


def observation_from_changes(
    *,
    repository: str,
    pull_request: int,
    base_commit: str,
    base_tree: str,
    head_commit: str,
    head_tree: str,
    pages: int,
    raw_changes: list[dict[str, Any]],
) -> dict[str, Any]:
    changes = [normalize_change(item, f"changes[{index}]") for index, item in enumerate(raw_changes)]
    paths = [item["path"] for item in changes]
    require(len(paths) == len(set(paths)), "live pull request repeats a changed filename")
    paths = sorted(paths)
    changes = sorted(changes, key=lambda item: item["path"])
    return {
        "schema": OBSERVATION_SCHEMA,
        "repository": repository,
        "pull_request": pull_request,
        "base_commit": base_commit,
        "base_tree": base_tree,
        "head_commit": head_commit,
        "head_tree": head_tree,
        "api_pages": pages,
        "path_count": len(paths),
        "paths_sha256": canonical_paths_digest(paths),
        "change_count": len(changes),
        "changes_sha256": canonical_changes_digest(changes),
        "rename_count": sum(item["status"] == "renamed" for item in changes),
        "removal_count": sum(item["status"] == "removed" for item in changes),
        "changed_paths": paths,
        "changes": changes,
        "claim_ceiling": "LIVE_DIFF_OBSERVATION_ONLY_NO_REVIEW_OR_INTEGRATION_AUTHORITY",
        "integration_authorized": False,
        "promotion_authorized": False,
        "public_release": False,
    }


def _api_get(repository: str, path: str, token: str) -> Any:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "trillionnium-g1-review-index",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            require(response.status == 200, f"GitHub API returned HTTP {response.status}")
            raw = response.read(32 * 1024 * 1024 + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError) as error:
        raise ReviewIndexError(f"GitHub API read failed for {path}: {error}") from error
    require(len(raw) <= 32 * 1024 * 1024, f"GitHub API response too large for {path}")
    return load_json_bytes(raw, f"GitHub API {path}")


def git(root: Path, *args: str, check: bool = True) -> str:
    env = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C"}
    completed = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    if check and completed.returncode != 0:
        raise ReviewIndexError(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip() if completed.returncode == 0 else ""


def observe_live(
    *,
    root: Path,
    repository: str,
    pull_request: int,
    expected_base: str,
    expected_head: str,
    token: str,
) -> dict[str, Any]:
    require(repository == REPOSITORY, "review index repository is not canonical")
    positive_int(pull_request, "pull_request")
    git_sha(expected_base, "expected_base")
    git_sha(expected_head, "expected_head")
    require(bool(token), "GITHUB_TOKEN is required")
    root = root.resolve()
    require((root / ".git").exists(), "repository checkout has no .git directory")
    require(git(root, "rev-parse", "HEAD^{commit}") == expected_head, "checkout is not the exact PR head")
    require(git(root, "status", "--porcelain=v1", "--untracked-files=all") == "", "checkout is dirty")

    pull = _api_get(repository, f"/pulls/{pull_request}", token)
    require(isinstance(pull, dict), "pull request response is not an object")
    require(pull.get("state") == "open", "pull request is not open")
    require((pull.get("base") or {}).get("sha") == expected_base, "live PR base differs")
    require((pull.get("head") or {}).get("sha") == expected_head, "live PR head differs")

    raw_changes: list[dict[str, Any]] = []
    page = 1
    while True:
        require(page <= 100, "pull request file pagination exceeded 100 pages")
        value = _api_get(repository, f"/pulls/{pull_request}/files?per_page=100&page={page}", token)
        require(isinstance(value, list), f"pull request files page {page} is not an array")
        if not value:
            break
        for index, item in enumerate(value):
            require(isinstance(item, dict), f"pull request files page {page}[{index}] is not an object")
            status = item.get("status")
            previous = item.get("previous_filename") if status == "renamed" else None
            raw_changes.append(
                {
                    "path": item.get("filename"),
                    "status": status,
                    "previous_path": previous,
                }
            )
        if len(value) < 100:
            break
        page += 1

    head_tree = git(root, "rev-parse", f"{expected_head}^{{tree}}")
    base_tree = git(root, "rev-parse", f"{expected_base}^{{tree}}")
    return observation_from_changes(
        repository=repository,
        pull_request=pull_request,
        base_commit=expected_base,
        base_tree=base_tree,
        head_commit=expected_head,
        head_tree=head_tree,
        pages=page,
        raw_changes=raw_changes,
    )


def validate_index(index: Any, observation: dict[str, Any], *, index_sha256: str) -> dict[str, Any]:
    require(isinstance(index, dict), "review index root must be an object")
    exact_keys(index, INDEX_KEYS, "review index")
    require(index["schema"] == SCHEMA, "review index schema is unsupported")
    require(index["program_revision"] == "2026-08-31-g1", "review index program revision drifted")
    require(index["repository"] == observation["repository"], "review index repository differs")
    require(index["pull_request"] == observation["pull_request"], "review index PR differs")
    require(index["head_binding"] == "LIVE_PR_EXACT_HEAD_NO_SELF_REFERENCE", "review index head binding is unsafe")

    value = index["base"]
    require(isinstance(value, dict), "review index base must be an object")
    exact_keys(value, IDENTITY_KEYS, "review index base")
    require(git_sha(value["commit"], "base.commit") == observation["base_commit"], "review index base commit differs")
    require(git_sha(value["tree"], "base.tree") == observation["base_tree"], "review index base tree differs")

    predecessor = index["review_predecessor"]
    require(isinstance(predecessor, dict), "review_predecessor must be an object")
    exact_keys(predecessor, IDENTITY_KEYS, "review_predecessor")
    git_sha(predecessor["commit"], "review_predecessor.commit")
    git_sha(predecessor["tree"], "review_predecessor.tree")

    expected = index["expected"]
    require(isinstance(expected, dict), "review index expected must be an object")
    exact_keys(expected, EXPECTED_KEYS, "review index expected")
    path_count = positive_int(expected["path_count"], "expected.path_count")
    change_count = positive_int(expected["change_count"], "expected.change_count")
    paths_sha = digest(expected["paths_sha256"], "expected.paths_sha256")
    changes_sha = digest(expected["changes_sha256"], "expected.changes_sha256")

    raw_paths = index["changed_paths"]
    require(isinstance(raw_paths, list) and raw_paths, "changed_paths must be a non-empty array")
    paths = [normalize_path(item, f"changed_paths[{i}]") for i, item in enumerate(raw_paths)]
    require(paths == sorted(paths), "changed_paths must be sorted")
    require(len(paths) == len(set(paths)), "changed_paths contains duplicates")

    raw_changes = index["changes"]
    require(isinstance(raw_changes, list) and raw_changes, "changes must be a non-empty array")
    changes = [normalize_change(item, f"changes[{i}]") for i, item in enumerate(raw_changes)]
    require(changes == sorted(changes, key=lambda item: item["path"]), "changes must be sorted by path")
    require(len({item["path"] for item in changes}) == len(changes), "changes contains duplicate paths")
    require([item["path"] for item in changes] == paths, "changes and changed_paths differ")

    require(path_count == len(paths) == observation["path_count"], "review index path count differs from live diff")
    require(change_count == len(changes) == observation["change_count"], "review index change count differs from live diff")
    require(paths_sha == canonical_paths_digest(paths) == observation["paths_sha256"], "review index path digest differs from live diff")
    require(changes_sha == canonical_changes_digest(changes) == observation["changes_sha256"], "review index change digest differs from live diff")
    require(paths == observation["changed_paths"], "review index omits, adds or renames a live path")
    require(changes == observation["changes"], "review index change statuses or rename sources differ")

    slices = index["slices"]
    require(isinstance(slices, list) and slices, "review index slices must be non-empty")
    path_set = set(paths)
    seen_ids: set[str] = set()
    seen_orders: set[int] = set()
    assigned: dict[str, str] = {}
    slice_reports: list[dict[str, Any]] = []
    for i, item in enumerate(slices):
        require(isinstance(item, dict), f"slices[{i}] must be an object")
        exact_keys(item, SLICE_KEYS, f"slices[{i}]")
        slice_id = text(item["id"], f"slices[{i}].id")
        require(SLICE_ID.fullmatch(slice_id) is not None, f"slices[{i}].id is invalid")
        require(slice_id not in seen_ids, f"duplicate slice id {slice_id}")
        seen_ids.add(slice_id)
        domain = text(item["security_domain"], f"slices[{i}].security_domain")
        owner = text(item["accountable_owner"], f"slices[{i}].accountable_owner")
        reviewers = item["independent_reviewers"]
        require(isinstance(reviewers, list) and reviewers, f"slices[{i}].independent_reviewers must be non-empty")
        reviewers = [text(reviewer, f"slices[{i}].independent_reviewers") for reviewer in reviewers]
        require(len(reviewers) == len(set(reviewers)), f"slices[{i}] repeats a reviewer")
        require(owner not in reviewers, f"slices[{i}] owner cannot be its own independent reviewer")
        order = positive_int(item["review_order"], f"slices[{i}].review_order")
        require(order not in seen_orders, f"duplicate review order {order}")
        seen_orders.add(order)
        raw_slice_paths = item["paths"]
        require(isinstance(raw_slice_paths, list) and raw_slice_paths, f"slices[{i}].paths must be non-empty")
        slice_paths = [normalize_path(path, f"slices[{i}].paths") for path in raw_slice_paths]
        require(slice_paths == sorted(slice_paths), f"slices[{i}].paths must be sorted")
        require(len(slice_paths) == len(set(slice_paths)), f"slices[{i}] repeats a path")
        for path in slice_paths:
            require(path in path_set, f"slice {slice_id} contains a path outside the live diff: {path}")
            require(path not in assigned, f"path {path} belongs to both {assigned.get(path)} and {slice_id}")
            assigned[path] = slice_id
        slice_reports.append({
            "id": slice_id,
            "security_domain": domain,
            "accountable_owner": owner,
            "independent_reviewers": reviewers,
            "review_order": order,
            "path_count": len(slice_paths),
            "paths_sha256": canonical_paths_digest(slice_paths),
        })
    require(set(assigned) == path_set, f"review slices omit paths: {sorted(path_set-set(assigned))}")
    require(seen_orders == set(range(1, len(slices) + 1)), "review orders must be contiguous from 1")

    require(index["claim_ceiling"] == "CLOSED_WORLD_REVIEW_INDEX_ONLY_NO_APPROVAL_OR_INTEGRATION_AUTHORITY", "review index claim ceiling widened")
    for field in ("automatic_redispatch", "integration_authorized", "promotion_authorized", "public_release"):
        require(index[field] is False, f"review index {field} must remain false")

    return {
        "schema": REPORT_SCHEMA,
        "program_revision": index["program_revision"],
        "repository": index["repository"],
        "pull_request": index["pull_request"],
        "base": index["base"],
        "head": {"commit": observation["head_commit"], "tree": observation["head_tree"]},
        "review_predecessor": predecessor,
        "review_index_path": INDEX_PATH,
        "review_index_sha256": digest(index_sha256, "review_index_sha256"),
        "path_count": path_count,
        "paths_sha256": paths_sha,
        "change_count": change_count,
        "changes_sha256": changes_sha,
        "rename_count": observation["rename_count"],
        "removal_count": observation["removal_count"],
        "slices": sorted(slice_reports, key=lambda item: item["review_order"]),
        "result": "PASS_EXACT_HEAD_CLOSED_WORLD_REVIEW_INDEX",
        "claim_ceiling": index["claim_ceiling"],
        "automatic_redispatch": False,
        "integration_authorized": False,
        "promotion_authorized": False,
        "public_release": False,
    }


def validate_repository_identity(root: Path, report: dict[str, Any]) -> None:
    predecessor = report["review_predecessor"]
    require(git(root, "rev-parse", f"{predecessor['commit']}^{{commit}}") == predecessor["commit"], "review predecessor commit is unavailable")
    require(git(root, "rev-parse", f"{predecessor['commit']}^{{tree}}") == predecessor["tree"], "review predecessor tree differs")
    completed = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(root), "merge-base", "--is-ancestor", predecessor["commit"], report["head"]["commit"]],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C"},
    )
    require(completed.returncode == 0, "review predecessor is not an ancestor of the exact head")


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(raw, encoding="utf-8")
    os.replace(temporary, path)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--index", type=Path, default=Path(INDEX_PATH))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--base-commit", required=True)
    parser.add_argument("--head-commit", required=True)
    parser.add_argument("--observation-output", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--observe-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    try:
        observation = observe_live(
            root=root,
            repository=args.repository,
            pull_request=args.pr_number,
            expected_base=args.base_commit,
            expected_head=args.head_commit,
            token=os.environ.get("GITHUB_TOKEN", ""),
        )
        atomic_json(args.observation_output, observation)
        if args.observe_only:
            print(json.dumps(observation, sort_keys=True))
            return 0
        index_path = args.index if args.index.is_absolute() else root / args.index
        index, raw = load_json(index_path)
        report = validate_index(index, observation, index_sha256=hashlib.sha256(raw).hexdigest())
        validate_repository_identity(root, report)
        if args.output:
            atomic_json(args.output, report)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ReviewIndexError, subprocess.SubprocessError) as error:
        print(f"G1 review index verification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
