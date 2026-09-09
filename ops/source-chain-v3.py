from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = os.environ["REPOSITORY"]
ORG, REPO = REPOSITORY.split("/", 1)
TOKEN = os.environ["GH_TOKEN"]
API = "https://api.github.com"
CANDIDATES = [
    {
        "ref": "codex/perf-harness-isolation-20260908",
        "number": 63,
        "title": "perf: isolate real Host/Core benchmark and reproducibility tooling",
    },
    {
        "ref": "codex/repository-truth-profiles-20260908",
        "number": 71,
        "title": "docs: make repository profiles and authority executable",
    },
    {
        "ref": "codex/effect-lifecycle-model-20260908",
        "number": None,
        "title": "docs: machine-verify the cross-module effect lifecycle",
    },
    {
        "ref": "codex/executable-module-contracts-v1-20260909",
        "number": None,
        "title": "contracts: generate executable module API, state and error schemas",
    },
    {
        "ref": "codex/performance-measurement-v1-20260909",
        "number": None,
        "title": "perf: stabilize baselines and bind stage/resource attribution",
    },
    {
        "ref": "codex/observe-shadow-telemetry-v1-20260909",
        "number": None,
        "title": "telemetry: add metric authority and deterministic observe/shadow control",
    },
]


def api_request(method: str, path: str, payload: object | None = None) -> object:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {TOKEN}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "trillionnium-source-chain-v3",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(16 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        body = error.read(64 * 1024).decode("utf-8", "replace")
        raise RuntimeError(f"{method} {path}: HTTP {error.code}: {body}") from error
    if len(raw) > 16 * 1024 * 1024:
        raise RuntimeError(f"oversized API response: {path}")
    return None if not raw else json.loads(raw)


def command(
    *args: str,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(args),
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        redacted_args = tuple("***" if TOKEN in value else value for value in args)
        raise RuntimeError(
            f"command failed {completed.returncode}: {redacted_args}\n"
            f"stdout:\n{completed.stdout[-12000:]}\n"
            f"stderr:\n{completed.stderr[-12000:]}"
        )
    return completed


def post(number: int, body: str) -> None:
    api_request("POST", f"/repos/{REPOSITORY}/issues/{number}/comments", {"body": body})


def main_identity() -> tuple[str, str]:
    value = api_request("GET", f"/repos/{REPOSITORY}/branches/main")
    assert isinstance(value, dict)
    commit = value["commit"]["sha"]
    detail = api_request("GET", f"/repos/{REPOSITORY}/git/commits/{commit}")
    assert isinstance(detail, dict)
    return commit, detail["tree"]["sha"]


def branch_exists(ref: str) -> bool:
    encoded = urllib.parse.quote(ref, safe="")
    try:
        api_request("GET", f"/repos/{REPOSITORY}/branches/{encoded}")
        return True
    except RuntimeError as error:
        if "HTTP 404" in str(error):
            return False
        raise


def pull_for(candidate: dict[str, object]) -> dict[str, object] | None:
    ref = str(candidate["ref"])
    expected_number = candidate.get("number")
    if isinstance(expected_number, int):
        value = api_request("GET", f"/repos/{REPOSITORY}/pulls/{expected_number}")
        assert isinstance(value, dict)
        if value["head"]["ref"] != ref:
            raise RuntimeError(
                f"PR #{expected_number} belongs to {value['head']['ref']}, expected {ref}"
            )
        return value
    head = urllib.parse.quote(f"{ORG}:{ref}", safe=":")
    values = api_request(
        "GET", f"/repos/{REPOSITORY}/pulls?state=all&head={head}&per_page=20"
    )
    assert isinstance(values, list)
    if not values:
        return None
    selected = max(values, key=lambda item: item["number"])
    detail = api_request("GET", f"/repos/{REPOSITORY}/pulls/{selected['number']}")
    assert isinstance(detail, dict)
    return detail


def ensure_pull(candidate: dict[str, object]) -> dict[str, object] | None:
    pull = pull_for(candidate)
    if pull is not None:
        return pull
    ref = str(candidate["ref"])
    if not branch_exists(ref):
        return None
    value = api_request(
        "POST",
        f"/repos/{REPOSITORY}/pulls",
        {
            "title": str(candidate["title"]),
            "head": ref,
            "base": "main",
            "draft": True,
            "maintainer_can_modify": True,
            "body": (
                "Parent program: #51\n\n"
                "Dependency-ordered source candidate. Keep Draft until the exact current "
                "base/head/tree, complete exact-head and deterministic ordered-parent "
                "synthetic-merge workflows, two fresh non-author reviews and zero unresolved "
                "threads are all established. Ordinary protected integration only. Source "
                "success grants no installed-target, Android, physical-device, destructive-fault, "
                "signing, OTA or release authority; `automatic_redispatch=false`, "
                "`zero_gap=false` and `public_release=false` remain binding."
            ),
        },
    )
    assert isinstance(value, dict)
    return value


def status_records(root: Path) -> list[dict[str, object]]:
    raw = command(
        "git", "diff", "--cached", "--name-status", "-z", "-M", "origin/main", cwd=root
    ).stdout
    tokens = raw.split("\0")
    if tokens and tokens[-1] == "":
        tokens.pop()
    records: list[dict[str, object]] = []
    index = 0
    while index < len(tokens):
        status_token = tokens[index]
        index += 1
        code = status_token[0]
        if code == "R":
            previous, path = tokens[index], tokens[index + 1]
            index += 2
            records.append({"path": path, "status": "renamed", "previous_path": previous})
        elif code == "C":
            _, path = tokens[index], tokens[index + 1]
            index += 2
            records.append({"path": path, "status": "copied", "previous_path": None})
        else:
            path = tokens[index]
            index += 1
            records.append(
                {
                    "path": path,
                    "status": {"A": "added", "M": "modified", "D": "removed"}.get(
                        code, "changed"
                    ),
                    "previous_path": None,
                }
            )
    return sorted(records, key=lambda item: str(item["path"]))


def rebuild_review_index(
    root: Path,
    number: int,
    main_sha: str,
    main_tree: str,
    predecessor: str,
    predecessor_tree: str,
) -> list[dict[str, object]]:
    index_path = root / "governance/pr41-review-index.v1.json"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    if not index_path.exists():
        index_path.write_text("{}\n", encoding="utf-8")
    command("git", "add", "-A", cwd=root)
    records = status_records(root)
    if not any(item["path"] == "governance/pr41-review-index.v1.json" for item in records):
        records.append(
            {
                "path": "governance/pr41-review-index.v1.json",
                "status": "modified",
                "previous_path": None,
            }
        )
        records.sort(key=lambda item: str(item["path"]))
    verifier = root / "tools/verify_g1_review_index.py"
    spec = importlib.util.spec_from_file_location("review_index_v3", verifier)
    if spec is None or spec.loader is None:
        raise RuntimeError("review-index authority is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    for _ in range(2):
        observation = {
            "repository": REPOSITORY,
            "pull_request": number,
            "base_commit": main_sha,
            "base_tree": main_tree,
            "head_commit": predecessor,
            "head_tree": predecessor_tree,
            "changes": records,
        }
        value = module.propose_index(
            observation,
            predecessor_commit=predecessor,
            predecessor_tree=predecessor_tree,
            accountable_owner="ProfHepta",
            runtime_reviewer="Tomasrgbsf",
            evidence_reviewer="Franksudoman",
        )
        index_path.write_text(
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            + "\n",
            encoding="utf-8",
        )
        command("git", "add", "-A", cwd=root)
        final_records = status_records(root)
        if final_records == records:
            return records
        records = final_records
    raise RuntimeError("review-index inventory did not converge")


def focused_preflight(root: Path) -> None:
    command("git", "diff", "--cached", "--check", cwd=root)
    command("python3", "-m", "compileall", "-q", "tools", cwd=root)
    for script, arguments in (
        ("tools/docs/generate_global_docs.py", ["--check"]),
        ("tools/docs/verify_global_docs.py", []),
        ("tools/docs/verify_repository_authority.py", []),
        ("tools/docs/verify_effect_lifecycle.py", ["--model-check", "--json"]),
    ):
        if (root / script).exists():
            command("python3", script, *arguments, cwd=root)
    selected = []
    for name in (
        "tools.tests.test_repository_authority",
        "tools.tests.test_effect_lifecycle",
        "tools.tests.test_executable_module_contracts",
        "tools.tests.test_module_contracts",
        "tools.tests.test_run_product_baseline",
        "tools.tests.test_verify_host_reproducibility",
        "tools.tests.test_product_baseline_process_group_cleanup",
        "tools.tests.test_telemetry_control",
        "tools.tests.test_metric_catalog",
    ):
        if (root / (name.replace(".", "/") + ".py")).exists():
            selected.append(name)
    if selected:
        command("python3", "-m", "unittest", *selected, "-v", cwd=root)


def converge(pull: dict[str, object], main_sha: str, main_tree: str) -> dict[str, object]:
    number = int(pull["number"])
    ref = str(pull["head"]["ref"])
    head = str(pull["head"]["sha"])
    root = Path("/tmp/source-chain-v3")
    if root.exists():
        command("rm", "-rf", str(root))
    clone_url = f"https://x-access-token:{TOKEN}@github.com/{REPOSITORY}.git"
    environment = dict(os.environ)
    environment.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "LANG": "C"})
    command("git", "clone", "--no-tags", "--branch", ref, clone_url, str(root), env=environment)
    command("git", "fetch", "--no-tags", "origin", "main", cwd=root, env=environment)
    observed = command("git", "rev-parse", "HEAD", cwd=root).stdout.strip()
    if observed != head:
        raise RuntimeError(f"candidate moved during clone: expected {head}, got {observed}")
    fetched_main = command("git", "rev-parse", "origin/main", cwd=root).stdout.strip()
    if fetched_main != main_sha:
        raise RuntimeError(f"protected main moved during clone: expected {main_sha}, got {fetched_main}")
    predecessor_tree = command("git", "rev-parse", "HEAD^{tree}", cwd=root).stdout.strip()
    command("git", "config", "user.name", "Qian QI", cwd=root)
    command(
        "git",
        "config",
        "user.email",
        "102159240+ProfHepta@users.noreply.github.com",
        cwd=root,
    )

    ancestor = (
        command("git", "merge-base", "--is-ancestor", main_sha, "HEAD", cwd=root, check=False).returncode
        == 0
    )
    if not ancestor:
        merge = command("git", "merge", "--no-ff", "--no-commit", "origin/main", cwd=root, check=False)
        if merge.returncode != 0:
            command("git", "merge", "--abort", cwd=root, check=False)
            raise RuntimeError(f"clean convergence failed: {merge.stderr[-6000:]}")
    else:
        command("git", "reset", "--mixed", "HEAD", cwd=root)

    records = rebuild_review_index(
        root, number, main_sha, main_tree, head, predecessor_tree
    )
    focused_preflight(root)
    has_changes = (
        command("git", "diff", "--cached", "--quiet", cwd=root, check=False).returncode != 0
    )
    if has_changes:
        command("git", "commit", "-m", f"chore: converge PR #{number} with current main", cwd=root)
    else:
        command(
            "git",
            "commit",
            "--allow-empty",
            "-m",
            f"chore: requalify PR #{number} on current main",
            cwd=root,
        )
    new_head = command("git", "rev-parse", "HEAD", cwd=root).stdout.strip()
    new_tree = command("git", "rev-parse", "HEAD^{tree}", cwd=root).stdout.strip()
    if not ancestor:
        parents = command("git", "show", "-s", "--format=%P", "HEAD", cwd=root).stdout.split()
        if main_sha not in parents:
            raise RuntimeError("protected main is not a convergence parent")
    command("git", "push", "origin", f"HEAD:{ref}", cwd=root, env=environment)

    exact = (
        "## Current exact subject\n\n"
        "```text\n"
        "base branch:        main\n"
        f"base commit:        {main_sha}\n"
        f"base tree:          {main_tree}\n"
        f"review predecessor: {head}\n"
        f"head commit:        {new_head}\n"
        f"head tree:          {new_tree}\n"
        f"changed paths:      {len(records)}\n"
        "```\n\n"
        "This source object is explicitly rebound to the current protected main. Any "
        "base/head/tree/workflow/review movement invalidates qualification. No old-head "
        "check, receipt or review transfers.\n\n"
    )
    old_body = str(pull.get("body") or "")
    if old_body.startswith("## Current exact subject"):
        next_heading = old_body.find("\n## ", 4)
        old_body = old_body[next_heading + 1 :] if next_heading >= 0 else ""
    api_request("PATCH", f"/repos/{REPOSITORY}/pulls/{number}", {"body": exact + old_body})
    try:
        api_request(
            "POST",
            f"/repos/{REPOSITORY}/pulls/{number}/requested_reviewers",
            {"reviewers": ["Tomasrgbsf", "Franksudoman"]},
        )
    except RuntimeError as error:
        if "HTTP 422" not in str(error):
            raise
    post(
        number,
        (
            "## Current-main convergence published\n\n"
            f"`{ref}` moved from `{head}` to `{new_head}` and is bound to protected "
            f"`main@{main_sha}`. Focused preflight passed. Full exact-head and deterministic "
            "ordered-parent synthetic-merge workflows plus fresh decisions from "
            "`Tomasrgbsf` and `Franksudoman` remain required. No administrator bypass, "
            "automatic redispatch or L2-L6 authority is granted."
        ),
    )
    return {
        "pr": number,
        "ref": ref,
        "old_head": head,
        "new_head": new_head,
        "new_tree": new_tree,
        "main": main_sha,
        "changed_paths": len(records),
        "decision": "CURRENT_MAIN_CANDIDATE_PUBLISHED",
    }


def main() -> int:
    ledger: dict[str, object] = {
        "schema": "org.trillionnium.source-chain-convergence.v3",
        "automatic_redispatch": False,
        "administrator_bypass": False,
        "zero_gap": False,
        "public_release": False,
        "events": [],
    }
    deadline = time.monotonic() + 40 * 60
    while time.monotonic() < deadline:
        target = None
        for candidate in CANDIDATES:
            pull = ensure_pull(candidate)
            if pull is None:
                event = {"ref": candidate["ref"], "decision": "BRANCH_OR_PULL_MISSING"}
                ledger["events"].append(event)
                post(51, f"Source-chain controller stopped fail-closed: `{candidate['ref']}` is unavailable.")
                Path("/tmp/source-chain-v3.json").write_text(
                    json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                return 0
            if bool(pull.get("merged")):
                continue
            if pull.get("state") != "open":
                event = {
                    "pr": pull["number"],
                    "ref": candidate["ref"],
                    "decision": "CLOSED_WITHOUT_MERGE",
                }
                ledger["events"].append(event)
                Path("/tmp/source-chain-v3.json").write_text(
                    json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                return 0
            target = pull
            break
        if target is None:
            ledger["events"].append({"decision": "ALL_SOURCE_CANDIDATES_MERGED"})
            break

        main_sha, main_tree = main_identity()
        body = str(target.get("body") or "")
        if target["base"]["sha"] == main_sha and main_sha in body:
            ledger["events"].append(
                {
                    "pr": target["number"],
                    "ref": target["head"]["ref"],
                    "head": target["head"]["sha"],
                    "main": main_sha,
                    "decision": "WAITING_FOR_CI_REVIEW_OR_ORDINARY_MERGE",
                }
            )
            time.sleep(30)
            continue
        try:
            event = converge(target, main_sha, main_tree)
        except Exception as error:
            event = {
                "pr": target["number"],
                "ref": target["head"]["ref"],
                "head": target["head"]["sha"],
                "main": main_sha,
                "decision": "CONVERGENCE_FAILED_CLOSED",
                "error": str(error),
            }
            ledger["events"].append(event)
            post(
                int(target["number"]),
                (
                    "## Source convergence failed closed\n\n"
                    f"The current candidate could not be safely converged with `main@{main_sha}`. "
                    "No force push, automatic conflict resolution, review dismissal or administrator "
                    "bypass was used.\n\n"
                    f"```text\n{str(error)[-6000:]}\n```"
                ),
            )
            break
        ledger["events"].append(event)
        time.sleep(30)

    Path("/tmp/source-chain-v3.json").write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
