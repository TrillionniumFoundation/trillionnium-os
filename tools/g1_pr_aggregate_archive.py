"""Bounded GitHub Actions artifact download and safe ZIP decoding."""
from __future__ import annotations

from datetime import datetime
import io
from pathlib import PurePosixPath
import stat
from typing import Any, Mapping
import zipfile

from tools.g1_pr_aggregate_api import ApiResponse, GitHubApi
from tools.g1_pr_aggregate_common import (
    AggregateError,
    MAX_ARCHIVE_BYTES,
    MAX_MEMBER_BYTES,
    _digest,
    _identifier,
    _list,
    _mapping,
    _parse_time,
    _positive_int,
    _require,
    _sha256,
    _strict_json,
)

class _RepoApi:
    """Repository-bound adapter used to keep tests concise."""

    def __init__(self, api: GitHubApi, repository: str) -> None:
        self.api = api
        self.repository = repository

    def get_json(self, path: str) -> ApiResponse:
        return self.api.get_json(path.replace("{repo}", self.repository))

    def get_bytes(self, path: str) -> ApiResponse:
        return self.api.get_bytes(path)


def _zip_json_members(raw: bytes, expected_names: frozenset[str], label: str) -> dict[str, Any]:
    _require(0 < len(raw) <= MAX_ARCHIVE_BYTES, f"{label} has an invalid archive size")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            _require(len(names) == len(set(names)), f"{label} has duplicate ZIP members")
            _require(set(names) == set(expected_names), f"{label} member set drifted: expected {sorted(expected_names)}, got {sorted(names)}")
            result: dict[str, Any] = {}
            total = 0
            for info in infos:
                path = PurePosixPath(info.filename)
                _require(not path.is_absolute() and ".." not in path.parts, f"{label} contains an unsafe path")
                _require(not info.is_dir(), f"{label} contains a directory member")
                _require((info.flag_bits & 0x1) == 0, f"{label} contains an encrypted member")
                mode = (info.external_attr >> 16) & 0o170000
                _require(mode != stat.S_IFLNK, f"{label} contains a symlink member")
                _require(info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}, f"{label} uses unsupported compression")
                _require(0 <= info.file_size <= MAX_MEMBER_BYTES, f"{label}/{info.filename} is too large")
                total += info.file_size
                _require(total <= MAX_ARCHIVE_BYTES, f"{label} expands beyond the archive bound")
                result[info.filename] = _strict_json(archive.read(info), f"{label}/{info.filename}")
            return result
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, RuntimeError) as error:
        raise AggregateError(f"{label} is not a readable ZIP: {error}") from error


def _artifact_metadata(
    api: _RepoApi,
    run: Mapping[str, Any],
    now: datetime,
) -> tuple[list[Mapping[str, Any]], str]:
    run_id = _positive_int(run.get("id"), "workflow run id")
    response = api.get_json(f"repos/{{repo}}/actions/runs/{run_id}/artifacts?per_page=100")
    value = _mapping(response.value, f"workflow run {run_id} artifacts")
    artifacts = [
        _mapping(item, f"workflow run {run_id} artifact[{index}]")
        for index, item in enumerate(_list(value.get("artifacts"), f"workflow run {run_id} artifacts.artifacts"))
    ]
    ids: set[int] = set()
    names: set[str] = set()
    for artifact in artifacts:
        artifact_id = _positive_int(artifact.get("id"), "artifact id")
        name = _identifier(artifact.get("name"), f"artifact {artifact_id} name")
        _require(artifact_id not in ids and name not in names, "artifact IDs and names must be unique")
        ids.add(artifact_id)
        names.add(name)
        _require(artifact.get("expired") is False, f"artifact {artifact_id} is expired")
        _require(_parse_time(artifact.get("expires_at"), f"artifact {artifact_id}.expires_at") > now, f"artifact {artifact_id} retention has expired")
        owner = _mapping(artifact.get("workflow_run"), f"artifact {artifact_id}.workflow_run")
        _require(owner.get("id") == run_id, f"artifact {artifact_id} is owned by another workflow run")
        if owner.get("head_sha") is not None:
            _require(owner.get("head_sha") == run.get("head_sha"), f"artifact {artifact_id} head SHA mismatch")
    return artifacts, _digest(response.raw)


def _download_artifact(api: _RepoApi, artifact: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    artifact_id = _positive_int(artifact.get("id"), "artifact id")
    name = _identifier(artifact.get("name"), f"artifact {artifact_id} name")
    size = _positive_int(artifact.get("size_in_bytes"), f"artifact {artifact_id} size")
    _require(size <= MAX_ARCHIVE_BYTES, f"artifact {artifact_id} exceeds archive byte bound")
    digest_value = _identifier(artifact.get("digest"), f"artifact {artifact_id} digest")
    _require(digest_value.startswith("sha256:"), f"artifact {artifact_id} digest algorithm is unsupported")
    expected_digest = _sha256(digest_value.removeprefix("sha256:"), f"artifact {artifact_id} digest")
    archive_url = _identifier(artifact.get("archive_download_url"), f"artifact {artifact_id} archive URL")
    response = api.get_bytes(archive_url)
    _require(len(response.raw) == size, f"artifact {artifact_id} byte count differs from metadata")
    actual_digest = _digest(response.raw)
    _require(actual_digest == expected_digest, f"artifact {artifact_id} archive digest mismatch")
    return response.raw, {
        "id": artifact_id,
        "name": name,
        "size_in_bytes": size,
        "sha256": actual_digest,
        "expires_at": artifact["expires_at"],
        # Transport URLs can be short-lived bearer capabilities, including in
        # their paths. Retain only the repository-scoped API locator.
        "archive_api_path": f"repos/{api.repository}/actions/artifacts/{artifact_id}/zip",
    }


