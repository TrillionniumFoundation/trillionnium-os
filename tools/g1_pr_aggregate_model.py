"""Immutable G1 aggregate subject and workflow requirements.

The protected pull-request aggregate is intentionally a source-correctness gate.
Promotion, device, evidence, release, and other qualification workflows are not
transitive prerequisites for ordinary pull requests; they run on their own
promotion/release paths instead of recursively qualifying CI with more CI.
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


# Deliberately empty for ordinary pull requests.
#
# The aggregate still verifies the exact live PR subject and all source jobs in
# its own workflow. Cross-workflow qualification (synthetic merge receipts,
# Android evaluated matrices, evidence intake, release/signing evidence) is a
# separate promotion concern and must not make CI itself a recursive admission
# authority.
REQUIREMENTS: tuple[WorkflowRequirement, ...] = ()
