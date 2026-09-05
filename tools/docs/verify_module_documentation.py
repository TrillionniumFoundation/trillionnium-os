#!/usr/bin/env python3
"""Fail-closed verifier for detailed Trillionnium OS module documentation."""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

INDEX_KEYS = {
    "schema", "program_revision", "status", "catalog_path",
    "budget_provenance_path", "required_sections",
    "minimum_document_bytes", "modules",
}
INDEX_ENTRY_KEYS = {"id", "doc_path"}
PROVENANCE_KEYS = {
    "schema", "program_revision", "status", "activation_mode", "measured",
    "catalog_fields", "workload_profiles", "qualification_rule", "modules",
}
PROVENANCE_ENTRY_KEYS = {
    "id", "classification", "measured", "sample_count", "evidence_id",
    "measurement_environment", "last_calibrated_at", "activation",
}
REQUIRED_SECTIONS = ('## 1. Identity and maturity', '## 2. Responsibilities', '## 3. Non-goals and authority boundary', '## 4. Context, dependencies and data flow', '## 5. API and protocol contract', '## 6. State model and ownership', '## 7. Ordering, concurrency and backpressure', '## 8. Effect, cancellation and uncertainty semantics', '## 9. Resource budget and SLO status', '## 10. Persistence, recovery and reconciliation', '## 11. Security and trust boundaries', '## 12. Failure matrix and degraded behavior', '## 13. Compatibility, migration and rollback', '## 14. Observability', '## 15. Verification and evidence', '## 16. Deployment and runbook', '## 17. Open gaps and exit criteria')

EDITORIAL = re.compile(r"\b(?:TODO|TBD|FIXME|PLACEHOLDER)\b|same\s+as\s+above", re.I)


class VerificationError(Exception):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise VerificationError(message)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON member {key!r}")
        value[key] = item
    return value


def _constant(value: str) -> None:
    raise VerificationError(f"non-finite JSON number {value}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except (OSError, ValueError) as error:
        raise VerificationError(f"{path} is not strict JSON: {error}") from error
    require(isinstance(value, dict), f"{path} root must be an object")
    return value


def exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    actual = set(value)
    require(
        actual == keys,
        f"{label} keys drift; missing={sorted(keys-actual)}, extra={sorted(actual-keys)}",
    )


def string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label} must be a string")
    require("\x00" not in value, f"{label} contains NUL")
    return value


def strings(value: Any, label: str, *, empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    require(empty or bool(value), f"{label} must not be empty")
    result = [string(item, f"{label}[{i}]") for i, item in enumerate(value)]
    duplicates = [item for item, count in Counter(result).items() if count > 1]
    require(not duplicates, f"{label} duplicates: {duplicates}")
    return result


def repo_path(root: Path, value: Any, label: str) -> Path:
    text = string(value, label)
    pure = PurePosixPath(text)
    require(not pure.is_absolute(), f"{label} must be relative")
    require("." not in pure.parts and ".." not in pure.parts, f"{label} is not normalized")
    require("\\" not in text and text == pure.as_posix(), f"{label} is not POSIX-normalized")
    candidate = root.joinpath(*pure.parts)
    resolved = candidate.resolve(strict=False)
    require(resolved.is_relative_to(root.resolve()), f"{label} escapes repository")
    cursor = candidate
    while cursor != root and cursor.exists():
        require(not cursor.is_symlink(), f"{label} traverses symlink {cursor}")
        cursor = cursor.parent
    return candidate


def catalog_modules(catalog: dict[str, Any]) -> tuple[list[str], dict[str, dict[str, Any]]]:
    value = catalog.get("modules")
    require(isinstance(value, list) and bool(value), "catalog.modules must be non-empty")
    order: list[str] = []
    mapped: dict[str, dict[str, Any]] = {}
    for i, module in enumerate(value):
        require(isinstance(module, dict), f"catalog.modules[{i}] must be an object")
        module_id = string(module.get("id"), f"catalog.modules[{i}].id")
        require(module_id not in mapped, f"duplicate catalog module {module_id}")
        order.append(module_id)
        mapped[module_id] = module
    return order, mapped


def visible_prose(text: str) -> str:
    """Do not accept required contract text hidden in comments or examples."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    lines: list[str] = []
    fence: str | None = None
    for line in text.splitlines():
        stripped = line.lstrip()
        marker = "`" if stripped.startswith("```") else "~" if stripped.startswith("~~~") else None
        if marker:
            if fence is None:
                fence = marker
            elif fence == marker:
                fence = None
            continue
        if fence is None:
            lines.append(line)
    require(fence is None, "module document contains an unterminated code fence")
    return "\n".join(lines)


def verify_headings(text: str, headings: list[str], module_id: str) -> None:
    actual = re.findall(r"^## .*", visible_prose(text), re.M)
    require(actual == headings, f"{module_id} sections are missing, duplicated or out of order")


def verify_contract_prose(text: str, module: dict[str, Any]) -> None:
    """Bind human-readable fields to values, not merely a nearby schema name.

    This proves documentation/catalog consistency only. It does not prove
    enforcement of the budgets in a target process, nor a measured SLO.
    """
    module_id = module["id"]
    prose = visible_prose(text)
    sections: dict[int, str] = {}
    matches = list(re.finditer(r"^## ([0-9]+)\. .*", prose, re.M))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(prose)
        sections[int(match.group(1))] = prose[match.end():end]

    def line(section: int, prefix: str, expected: str) -> None:
        actual = [item.strip() for item in sections[section].splitlines()
                  if item.strip().startswith(prefix)]
        require(actual == [expected], f"{module_id} section {section} contract drift: {prefix}")

    def field(section: int, label: str, value: Any) -> None:
        prefix = f"- {label}:"
        line(section, prefix, f"{prefix} `{value}`")

    for label, key in (("Module ID", "id"), ("Module version", "module_version"),
                       ("Plane", "plane"), ("Primary owner", "owner_team"),
                       ("Backup owner", "backup_team"), ("Maturity", "maturity")):
        field(1, label, module[key])
    dependencies = ", ".join(f"`{value}`" for value in module["dependencies"]) or "none"
    line(4, "Direct dependencies:", f"Direct dependencies: {dependencies}.")
    api = module["api_contract"]
    field(5, "API schema", api["schema"])
    for label, key in (("Catalog input labels", "inputs"), ("Catalog output labels", "outputs"),
                       ("Catalog error labels", "errors")):
        value = ", ".join(f"`{item}`" for item in api[key])
        line(5, f"- {label}:", f"- {label}: {value}")
    policy = module["compatibility"]["unknown_fields"]
    wording = "rejected" if policy == "reject" else "preserved"
    line(5, "- Unknown fields:", f"- Unknown fields: {wording} unless a future compatibility revision explicitly changes the rule.")
    line(5, "- Versioning:", f"- Versioning: semantic version `{api['version']}`; incompatible changes require a new version and migration evidence.")
    state = module["state_contract"]
    for label, key in (("State schema", "schema"), ("Partition key", "partition"), ("Durability class", "durability")):
        field(6, label, state[key])
    authority = "authoritative" if state["authoritative"] else "non-authoritative"
    line(6, "- State authority:", f"- State authority: **{authority}**")
    owned = "`" + "; ".join(module["state_owned"]) + "`" if module["state_owned"] else "none"
    line(6, "- State owned:", f"- State owned: {owned}")
    retention = state["retention"]
    line(6, "- Retention ceiling:", f"- Retention ceiling: {retention['max_items']} items and {retention['max_bytes']} bytes per declared bounded in-memory window.")
    terminal = " and ".join(f"`{value}`" for value in state["terminal_states"])
    line(6, "- Terminal vocabulary:", f"- Terminal vocabulary: {terminal}; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.")
    concurrency = module["concurrency_contract"]
    for label, key in (("Ordering key", "ordering_key"), ("Maximum declared concurrency", "max_concurrency"),
                       ("Admission resource", "admission_resource"), ("Lease source", "lease_source"),
                       ("Lock scope", "lock_scope"), ("Backpressure", "backpressure"),
                       ("Lease expiry", "lease_expiry"), ("Duplicate/conflict rule", "duplicate_conflict")):
        field(7, label, concurrency[key])
    line(7, "- Timeout ceiling:", f"- Timeout ceiling: `{concurrency['timeout_ms']}` milliseconds")
    resources, slo = module["resource_contract"], module["slo"]
    rows = [("CPU weight", resources['cpu_weight'], ""),
            ("Memory", resources['memory_bytes'], " bytes"),
            ("File descriptors", resources['fd_count'], ""),
            ("Processes", resources['process_count'], ""),
            ("Threads", resources['thread_count'], ""),
            ("I/O rate", resources['io_bytes_per_sec'], " bytes/s"),
            ("Queue items", resources['queue_items'], ""),
            ("Queue bytes", resources['queue_bytes'], ""),
            ("Store bytes", resources['store_bytes'], ""),
            ("Operation timeout", resources['timeout_ms'], " ms"),
            ("Recovery target", resources['recovery_ms'], " ms"),
            ("Provisional P99 target", slo['latency_p99_ms'], " ms"),
            ("Provisional throughput target", slo['throughput_per_sec'], "/s"),
            ("Provisional availability target", slo['availability_percent'], "%"),
            ("SLO recovery target", slo['recovery_ms'], " ms"),
            ("SLO measurement window", slo['measurement_window_sec'], " s")]
    for label, value, unit in rows:
        line(9, f"| {label} |", f"| {label} | {value}{unit} |")
    gaps = ", ".join(f"`{value}`" for value in module["open_gaps"]) or "none"
    line(17, "Open machine gaps:", f"Open machine gaps: {gaps}.")


def verify_implementation_links(root: Path, text: str, module_id: str) -> None:
    """Resolve explicit implementation declarations without executing source.

    Declaration existence and test-file links are source navigation checks,
    not a proof of wire compatibility or an installed-target claim.
    """
    prose = visible_prose(text)
    sources = re.findall(r"^- Implementation source: `([^`]+)` — `([A-Za-z_][A-Za-z0-9_]*)`$", prose, re.M)
    tests = re.findall(r"^- Verification source: `([^`]+)`$", prose, re.M)
    require(bool(sources) and bool(tests), f"{module_id} lacks concrete source/test bindings")
    for relative, symbol in sources:
        path = repo_path(root, relative, f"{module_id} implementation source")
        require(path.is_file(), f"{module_id} implementation file missing: {relative}")
        source = path.read_text(encoding="utf-8")
        if path.suffix == ".py":
            try:
                tree = ast.parse(source, filename=relative)
            except SyntaxError as error:
                raise VerificationError(f"{module_id} invalid Python binding: {error}") from error
            found = any(isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                        and node.name == symbol for node in ast.walk(tree))
        elif path.suffix == ".rs":
            found = re.search(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:fn|struct|enum|trait|type|const)\s+"
                              + re.escape(symbol) + r"\b", source, re.M) is not None
        else:
            raise VerificationError(f"{module_id} unsupported declaration language: {relative}")
        require(found, f"{module_id} implementation declaration missing: {relative}::{symbol}")
    for relative in tests:
        path = repo_path(root, relative, f"{module_id} verification source")
        require(path.is_file(), f"{module_id} verification file missing: {relative}")
        require(path.suffix in {".rs", ".py"}, f"{module_id} verification source must be code")



def verify_provenance(path: Path, module_order: list[str]) -> None:
    value = load_json(path)
    exact_keys(value, PROVENANCE_KEYS, "resource provenance")
    require(value["schema"] == "org.trillionnium.resource-budget-provenance.v1", "bad provenance schema")
    require(value["status"] == "PROVISIONAL_SOURCE_CEILINGS_UNMEASURED", "provenance must be unmeasured")
    require(value["activation_mode"] == "OBSERVE_ONLY", "budget activation must be observe-only")
    require(value["measured"] is False, "budget provenance claims measurement")
    require(value["catalog_fields"] == ["resource_contract", "slo"], "catalog field scope drifted")
    require(
        strings(value["workload_profiles"], "workload_profiles")
        == [f"WL-{i:02d}" for i in range(1, 13)],
        "workload profile set drifted",
    )
    string(value["program_revision"], "provenance.program_revision")
    string(value["qualification_rule"], "provenance.qualification_rule")
    entries = value["modules"]
    require(isinstance(entries, list), "provenance.modules must be an array")
    ids: list[str] = []
    for i, entry in enumerate(entries):
        require(isinstance(entry, dict), f"provenance.modules[{i}] must be an object")
        exact_keys(entry, PROVENANCE_ENTRY_KEYS, f"provenance.modules[{i}]")
        module_id = string(entry["id"], f"provenance.modules[{i}].id")
        ids.append(module_id)
        require(
            entry == {
                "id": module_id,
                "classification": "ADMISSION_CEILING_AND_PROVISIONAL_OBJECTIVE",
                "measured": False,
                "sample_count": 0,
                "evidence_id": None,
                "measurement_environment": None,
                "last_calibrated_at": None,
                "activation": "OBSERVE_ONLY",
            },
            f"{module_id} has unqualified budget provenance",
        )
    require(ids == module_order, "provenance module order/set drifted")


def verify_component_readmes(root: Path, catalog: dict[str, Any]) -> None:
    try:
        cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"Cargo.toml parse failed: {error}") from error
    members = cargo.get("workspace", {}).get("default-members")
    require(isinstance(members, list) and bool(members), "Cargo default-members missing")
    require(members == catalog.get("default_source_closure"), "Cargo default-members drift from catalog")
    for i, member in enumerate(members):
        directory = repo_path(root, member, f"default-members[{i}]")
        readme = directory / "README.md"
        require(directory.is_dir(), f"default member directory missing: {member}")
        require(readme.is_file() and not readme.is_symlink(), f"default member README missing: {member}")
        require(len(readme.read_bytes()) >= 256, f"default member README truncated: {member}")
        text = readme.read_text(encoding="utf-8")
        try:
            package = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))["package"]["name"]
        except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
            raise VerificationError(f"component package manifest missing: {member}") from error
        require(f"cargo test --locked -p {package} --all-targets" in text,
                f"default member lacks exact local test command: {member}")
        links = re.findall(r"\]\(([^)]+docs/modules/(MOD-[A-Z-]+)\.md)\)", text)
        known = {module["id"] for module in catalog["modules"]}
        require(bool(links), f"default member lacks a detailed module link: {member}")
        for target, module_id in links:
            require(module_id in known, f"default member links an unknown module: {member}")
            require((directory / target).resolve() == (root / f"docs/modules/{module_id}.md").resolve(),
                    f"default member module link escapes its contract: {member}")



def verify_index_and_documents(root: Path) -> None:
    machine = root / "docs/machine"
    catalog = load_json(machine / "module-catalog.v1.json")
    docset = load_json(machine / "doc-set.v1.json")
    index = load_json(machine / "module-document-index.v1.json")
    exact_keys(index, INDEX_KEYS, "module document index")
    require(index["schema"] == "org.trillionnium.module-document-index.v1", "bad index schema")
    require(index["status"] == "ACTIVE_CANDIDATE_SOURCE_DOCUMENTATION", "bad index status")
    require(index["catalog_path"] == "docs/machine/module-catalog.v1.json", "catalog path drifted")
    require(
        index["budget_provenance_path"] == "docs/machine/resource-budget-provenance.v1.json",
        "provenance path drifted",
    )
    headings = strings(index["required_sections"], "required_sections")
    require(tuple(headings) == REQUIRED_SECTIONS, "required section set drifted")
    require(index["program_revision"] == catalog["program_revision"], "index program revision drifted")
    minimum = index["minimum_document_bytes"]
    require(type(minimum) is int and minimum >= 4096, "minimum_document_bytes is too small")

    order, modules = catalog_modules(catalog)
    entries = index["modules"]
    require(isinstance(entries, list), "index.modules must be an array")
    required_files = set(strings(docset.get("required_files"), "doc-set.required_files"))
    authority = {
        "docs/MODULE_DOCUMENTATION_POLICY.md",
        "docs/machine/module-document-index.v1.json",
        "docs/machine/resource-budget-provenance.v1.json",
    }
    require(authority <= required_files, "module documentation authority is absent from doc-set")
    for relative in authority:
        path = repo_path(root, relative, "authority path")
        require(path.is_file() and not path.is_symlink(), f"authority file missing: {relative}")

    ids: list[str] = []
    paths: list[str] = []
    for i, entry in enumerate(entries):
        require(isinstance(entry, dict), f"index.modules[{i}] must be an object")
        exact_keys(entry, INDEX_ENTRY_KEYS, f"index.modules[{i}]")
        module_id = string(entry["id"], f"index.modules[{i}].id")
        ids.append(module_id)
        require(module_id in modules, f"unknown indexed module {module_id}")
        module = modules[module_id]
        relative = string(entry["doc_path"], f"{module_id}.doc_path")
        require(relative == f"docs/modules/{module_id}.md", f"{module_id} doc path drifted")
        require(relative in required_files, f"{module_id} document is absent from doc-set")
        paths.append(relative)
        path = repo_path(root, relative, f"{module_id}.doc_path")
        require(path.is_file() and not path.is_symlink(), f"{module_id} document missing")
        raw = path.read_bytes()
        require(len(raw) >= minimum, f"{module_id} document truncated")
        text = raw.decode("utf-8")
        verify_headings(text, headings, module_id)
        verify_contract_prose(text, module)
        verify_implementation_links(root, text, module_id)
        require(EDITORIAL.search(text) is None, f"{module_id} contains editorial marker")
        required = [
            f"# {module_id} — {module.get('name')}",
            f"Primary owner: `{module.get('owner_team')}`",
            f"Backup owner: `{module.get('backup_team')}`",
            f"Maturity: `{module.get('maturity')}`",
            f"API schema: `{module.get('api_contract', {}).get('schema')}`",
            f"State schema: `{module.get('state_contract', {}).get('schema')}`",
            f"Evidence ceiling: **{module.get('evidence_contract', {}).get('claim_ceiling')}**.",
            "Automatic redispatch: **forbidden**.",
            "Measurement status: **unmeasured until qualified evidence**.",
            "Resource budget authority: `docs/machine/resource-budget-provenance.v1.json`.",
        ]
        for literal in required:
            require(literal in text, f"{module_id} omits {literal!r}")
        for j, source in enumerate(module.get("paths", [])):
            require(repo_path(root, source, f"{module_id}.paths[{j}]").exists(), f"{module_id} source missing")
            require(f"`{source}`" in text, f"{module_id} omits source path {source}")
        for dependency in module.get("dependencies", []):
            require(f"`{dependency}`" in text, f"{module_id} omits dependency {dependency}")
        gaps = module.get("open_gaps", [])
        require(isinstance(gaps, list), f"{module_id}.open_gaps must be an array")
        if gaps:
            for gap in gaps:
                require(gap in text, f"{module_id} omits gap {gap}")
        else:
            require("Open machine gaps: none." in text, f"{module_id} omits no-gap declaration")

    require(ids == order, "index module order/set drifted")
    require(len(paths) == len(set(paths)), "module document paths are not unique")
    actual = {
        str(path.relative_to(root))
        for path in (root / "docs/modules").glob("*.md")
        if path.is_file()
    }
    require(actual == set(paths), "unregistered or missing module documents exist")
    provenance_path = repo_path(root, index["budget_provenance_path"], "provenance path")
    require(load_json(provenance_path)["program_revision"] == catalog["program_revision"], "budget program revision drifted")
    verify_provenance(provenance_path, order)
    verify_component_readmes(root, catalog)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    try:
        verify_index_and_documents(args.root)
    except (VerificationError, UnicodeError) as error:
        print(f"module documentation verification failed: {error}", file=sys.stderr)
        return 1
    print("module documentation verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
