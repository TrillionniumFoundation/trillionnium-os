from __future__ import annotations

import json
import os
import re
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = os.environ["REPOSITORY"]
ORG, _ = REPOSITORY.split("/", 1)
TOKEN = os.environ["GH_TOKEN"]
API = "https://api.github.com"
BRANCHES = [
    "codex/perf-harness-isolation-20260908",
    "codex/repository-truth-profiles-20260908",
    "codex/effect-lifecycle-model-20260908",
    "codex/executable-module-contracts-v1-20260909",
    "codex/performance-measurement-v1-20260909",
    "codex/observe-shadow-telemetry-v1-20260909",
]
TRANSIENT = re.compile(
    r"ECONNRESET|connection reset|HTTP (?:429|500|502|503|504)|"
    r"runner (?:was|has been) (?:lost|stopped)|The operation was canceled|"
    r"timed out waiting for a runner|artifact service.*unavailable|"
    r"temporary failure in name resolution|TLS handshake timeout",
    re.IGNORECASE,
)


def request(method: str, path: str, payload: object | None = None, *, accept: str = "application/vnd.github+json") -> object:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {TOKEN}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "trillionnium-source-ci-triage",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            raw = response.read(16 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        body = error.read(64 * 1024).decode("utf-8", "replace")
        raise RuntimeError(f"{method} {path}: HTTP {error.code}: {body}") from error
    if len(raw) > 16 * 1024 * 1024:
        raise RuntimeError(f"oversized response: {path}")
    if not raw:
        return None
    if accept == "application/vnd.github+json":
        return json.loads(raw)
    return raw.decode("utf-8", "replace")


def post(number: int, body: str) -> None:
    request("POST", f"/repos/{REPOSITORY}/issues/{number}/comments", {"body": body})


def pull_for(ref: str) -> dict[str, object] | None:
    head = urllib.parse.quote(f"{ORG}:{ref}", safe=":")
    values = request("GET", f"/repos/{REPOSITORY}/pulls?state=open&head={head}&per_page=10")
    assert isinstance(values, list)
    return max(values, key=lambda item: item["number"]) if values else None


def workflow_run_from_check(check: dict[str, object]) -> tuple[int, int] | None:
    details = str(check.get("details_url") or "")
    match = re.search(r"/actions/runs/(\d+)/job/(\d+)", details)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def latest_checks(head: str) -> dict[str, dict[str, object]]:
    value = request("GET", f"/repos/{REPOSITORY}/commits/{head}/check-runs?per_page=100")
    assert isinstance(value, dict)
    latest: dict[str, dict[str, object]] = {}
    for item in value.get("check_runs", []):
        name = str(item.get("name"))
        if name not in latest or int(item.get("id", 0)) > int(latest[name].get("id", 0)):
            latest[name] = item
    return latest


def job_log(job_id: int) -> str:
    try:
        value = request("GET", f"/repos/{REPOSITORY}/actions/jobs/{job_id}/logs", accept="application/vnd.github+json")
    except Exception as error:
        return f"log unavailable: {error}"
    return value if isinstance(value, str) else json.dumps(value)


def main() -> int:
    ledger: dict[str, object] = {
        "schema": "org.trillionnium.source-ci-triage.v1",
        "automatic_redispatch": False,
        "deterministic_failure_reruns": 0,
        "transient_failure_reruns": [],
        "observations": [],
    }
    seen: set[tuple[int, int]] = set()
    deadline = time.monotonic() + 35 * 60
    while time.monotonic() < deadline:
        active = None
        for ref in BRANCHES:
            pull = pull_for(ref)
            if pull is not None:
                active = pull
                break
        if active is None:
            ledger["observations"].append({"decision": "NO_OPEN_SOURCE_CANDIDATE"})
            break
        number = int(active["number"])
        head = str(active["head"]["sha"])
        checks = latest_checks(head)
        failed = [
            value
            for value in checks.values()
            if value.get("status") == "completed"
            and value.get("conclusion") in {"failure", "cancelled", "timed_out", "action_required", "startup_failure"}
        ]
        observation = {
            "pr": number,
            "head": head,
            "failed_checks": [str(item.get("name")) for item in failed],
            "pending_checks": [
                name for name, value in checks.items() if value.get("status") != "completed"
            ],
        }
        ledger["observations"].append(observation)
        for check in failed:
            identity = workflow_run_from_check(check)
            if identity is None or identity in seen:
                continue
            seen.add(identity)
            run_id, job_id = identity
            log = job_log(job_id)
            tail = log[-10000:]
            if TRANSIENT.search(tail):
                try:
                    request("POST", f"/repos/{REPOSITORY}/actions/runs/{run_id}/rerun-failed-jobs")
                except Exception as error:
                    observation.setdefault("rerun_errors", []).append(str(error))
                else:
                    ledger["transient_failure_reruns"].append(
                        {"pr": number, "head": head, "run_id": run_id, "job_id": job_id}
                    )
                    post(
                        number,
                        (
                            "## Transient CI failure rerun\n\n"
                            f"The failed job `{job_id}` in run `{run_id}` on exact head `{head}` "
                            "matched a bounded infrastructure/transmission failure signature. Only "
                            "failed jobs were rerun. No source result, review, promotion or evidence "
                            "was synthesized. A repeated failure will remain blocking."
                        ),
                    )
            else:
                post(
                    number,
                    (
                        "## Deterministic CI failure retained\n\n"
                        f"Exact head `{head}` has failed check `{check.get('name')}` in run `{run_id}` / "
                        f"job `{job_id}`. The unchanged object was not rerun because the log did not "
                        "match the reviewed transient-failure allowlist.\n\n"
                        f"```text\n{tail[-6000:]}\n```"
                    ),
                )
        time.sleep(45)

    Path("/tmp/source-ci-triage.json").write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
