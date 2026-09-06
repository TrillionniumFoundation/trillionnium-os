#!/usr/bin/env python3
"""Apply the deterministic G1 synthetic-artifact-set repair."""
from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"{label}: expected one exact source occurrence, found {count}: {path}"
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worktree", type=Path, required=True)
    args = parser.parse_args()
    root = args.worktree.resolve()

    receipts = root / "tools/g1_pr_aggregate_receipts.py"
    replace_once(
        receipts,
        '''    if requirement.artifact_kind == "synthetic":
        matches = {name: value for name, value in by_name.items() if name.startswith("g1-synthetic-merge-")}
        _require(len(matches) == 1 and len(by_name) == 1, "synthetic workflow must emit exactly one merge artifact")
        return matches
''',
        '''    if requirement.artifact_kind == "synthetic":
        matches = {
            name: value
            for name, value in by_name.items()
            if name.startswith("g1-synthetic-merge-")
        }
        _require(
            len(matches) == 1,
            "synthetic workflow must emit exactly one semantic merge artifact",
        )
        semantic_name = next(iter(matches))
        diagnostic_name = f"g1-merge-test-diagnostics-{subject.head_commit}"
        _require(
            set(by_name) == {semantic_name, diagnostic_name},
            "synthetic workflow artifact set is incomplete or ambiguous",
        )
        return matches
''',
        "accept one exact-head diagnostic beside one semantic synthetic receipt",
    )

    fixture = root / "tools/tests/g1_pr_aggregate_fixture_legacy.py"
    replace_once(
        fixture,
        '''        synthetic_artifact = self._artifact(2001, 1001, f"g1-synthetic-merge-{'d' * 40}", synthetic_raw)
        self.values[f"repos/{self.repo}/actions/runs/1001/artifacts?per_page=100"] = {"artifacts": [synthetic_artifact]}
''',
        '''        synthetic_artifact = self._artifact(2001, 1001, f"g1-synthetic-merge-{'d' * 40}", synthetic_raw)
        diagnostic_raw = self._zip(
            {
                "g1-merge-test-diagnostics.json": {
                    "qualification": "DIAGNOSTIC_ONLY_NO_SOURCE_OR_TARGET_AUTHORITY"
                }
            }
        )
        diagnostic_artifact = self._artifact(
            2010,
            1001,
            f"g1-merge-test-diagnostics-{self.head_commit}",
            diagnostic_raw,
        )
        self.values[f"repos/{self.repo}/actions/runs/1001/artifacts?per_page=100"] = {
            "artifacts": [synthetic_artifact, diagnostic_artifact]
        }
''',
        "model the successful synthetic workflow's exact diagnostic artifact",
    )

    tests = root / "tools/tests/test_g1_pr_aggregate.py"
    replace_once(
        tests,
        '''    def test_artifact_digest_mismatch_fails(self) -> None:
''',
        '''    def test_synthetic_diagnostic_artifact_must_bind_exact_head(self) -> None:
        path = f"repos/{self.repo}/actions/runs/1001/artifacts?per_page=100"
        payload = deepcopy(self.values[path])
        assert isinstance(payload, dict)
        artifacts = payload["artifacts"]
        assert isinstance(artifacts, list) and len(artifacts) == 2
        diagnostic = artifacts[1]
        assert isinstance(diagnostic, dict)
        diagnostic["name"] = f"g1-merge-test-diagnostics-{'a' * 40}"
        self.values[path] = payload
        with self.assertRaisesRegex(AGG.AggregateError, "incomplete or ambiguous"):
            self.verify()

    def test_synthetic_artifact_set_rejects_a_third_artifact(self) -> None:
        path = f"repos/{self.repo}/actions/runs/1001/artifacts?per_page=100"
        payload = deepcopy(self.values[path])
        assert isinstance(payload, dict)
        artifacts = payload["artifacts"]
        assert isinstance(artifacts, list) and len(artifacts) == 2
        artifacts.append(
            self._artifact(
                2011,
                1001,
                "g1-unexpected-third-artifact",
                self._zip({"unexpected.json": {}}),
            )
        )
        self.values[path] = payload
        with self.assertRaisesRegex(AGG.AggregateError, "incomplete or ambiguous"):
            self.verify()

    def test_synthetic_artifact_set_rejects_a_second_semantic_receipt(self) -> None:
        path = f"repos/{self.repo}/actions/runs/1001/artifacts?per_page=100"
        payload = deepcopy(self.values[path])
        assert isinstance(payload, dict)
        artifacts = payload["artifacts"]
        assert isinstance(artifacts, list) and len(artifacts) == 2
        artifacts.append(
            self._artifact(
                2012,
                1001,
                f"g1-synthetic-merge-{'e' * 40}",
                self._zip({"not-consumed.json": {}}),
            )
        )
        self.values[path] = payload
        with self.assertRaisesRegex(
            AGG.AggregateError, "exactly one semantic merge artifact"
        ):
            self.verify()

    def test_artifact_digest_mismatch_fails(self) -> None:
''',
        "add strict synthetic artifact-set regressions",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
