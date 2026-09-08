"""Immutable G1 aggregate subject and direct source-workflow requirements.

The protected aggregate is a source-correctness gate. It consumes the exact
prospective-merge qualification because merge compatibility is a direct source
property. Android target evidence, review-index receipts, evidence intake and
release qualification remain separate promotion or release concerns.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Subject:
    repository: str
    pr_number: int
    base_ref: str
    base_commit: str
    base_tree: str
    head_repository: str
    head_ref: str
    head_commit: str
    head_tree: str


@dataclass(frozen=True)
class WorkflowRequirement:
    filename: str
    workflow_name: str
    job_names: frozenset[str]
    artifact_kind: str

    @property
    def path(self) -> str:
        return f".github/workflows/{self.filename}"


REQUIREMENTS = (
    WorkflowRequirement(
        filename="g1-synthetic-merge.yml",
        workflow_name="G1 synthetic-merge qualification",
        job_names=frozenset({"L1 exact two-parent merge source qualification"}),
        artifact_kind="synthetic",
    ),
)
