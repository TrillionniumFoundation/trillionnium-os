"""Immutable G1 aggregate subject and workflow requirements."""
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
    WorkflowRequirement(
        filename="g1-android-privilege-matrix.yml",
        workflow_name="G1 Android privileged-lane evaluated matrix",
        job_names=frozenset(
            {
                "L1 Android adbroot source-head evaluated matrix",
                "L1 Android adbroot synthetic-merge evaluated matrix",
            }
        ),
        artifact_kind="android",
    ),
    WorkflowRequirement(
        filename="g1-evidence-intake.yml",
        workflow_name="G1 evidence intake qualification",
        job_names=frozenset(
            {
                "L1 strict evidence intake on exact source head",
                "L1 strict evidence intake on ordered synthetic merge",
            }
        ),
        artifact_kind="evidence",
    ),
)


