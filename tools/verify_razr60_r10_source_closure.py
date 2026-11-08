#!/usr/bin/env python3
"""Verify the retained R10 source checkpoint without importing its runtime."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat


CHECKPOINT = Path(
    "projects/razr60/phone-local-v150/acceptance/"
    "r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/"
    "source-closure-r10-20261107"
)
HASH = re.compile(r"[0-9a-f]{64}\Z")
FROZEN_PINS = {
    "frozen/native/runtime/MANIFEST.json":
        "94e945e55f4cda2c9d2c4bd473f6fdb8ec6eca425610db4fd59af1814f5fca02",
    "frozen/native/root-chain/SOURCE-MANIFEST.json":
        "43bbc6ac86758d31ed03d55a5cac0e24db5a021b161d2161a4f52a58980d8da2",
    "frozen/native/dependencies/DEPENDENCIES.json":
        "e15ea67c76bcc17a80627abe9a5ff19c79c87a10c977c2643416571f88f26fb7",
    "frozen/native/COMBINATION.json":
        "7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411",
    "frozen/native/runtime/source/late_boundary.py":
        "f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7",
    "preparation/r10/freeze_native_bound_runtime_r10_fc33.py":
        "7db072079c16ca6485d3ea6083eec5adf1054ebe0e6850d6eabf352745603b36",
}
NEGATIVE_CLAIMS = {
    "source_checkpoint_only": True,
    "runtime_adopted": False,
    "build_executed_by_publication": False,
    "installation_qualified": False,
    "ready_qualified": False,
    "fixed19_credits_added": 0,
    "phone_or_model_requests": 0,
    "automatic_redispatch": False,
    "historical_green_ci_reused": False,
    "github_independent_review_supplied": False,
}
DEVELOPMENT_ANCESTOR_PINS = {
    "b41562fffbdca9e4f6d82d3cde74f83cf701c8a75a36457cf8a48f970a554006",
    "2d019f99ace6faa9061c6e886b2ed544c145b3b763fc13d423165d20d41a7b99",
    "7b0f12a9bdf3a8910da53c894837024c4ef8437f890ad9a9010371c037a4ec35",
    "778de1056af3a6781d1e722a9a7511191ad98f0ff1487b35d4c24a4e6f08de3c",
    "752319c82b1d6155c9ced9f15790040cd18f2bdf9febefc169a71e4f74111c8a",
    "f4a1ca8f685fecd792c961b76cbf135bd9d1ee2182e530e87948161680523779",
    "6a40b4982a638c0e8eb4f0e4547f3115d9935d4416a3f0b08f9b0d4b40e56ec5",
    "90dc397ce9d18a1b35f20821a5a35665d55a73d2f254c0069178d695e8c2c4ac",
    "07e5c8346e6676098a248aab41ac8a4f5fe3e45b90eddef06e833cbc8e43886a",
    "2e98f742e41e753405a6d74a40c6df1669a5adb769c9502f7805ac166f494ee1",
    "3617b222fd3e2ce46de68eeaa7c9f2af067cf09d3ba3c0b5660eabdc75f5060c",
    "d4bb3f0527fc5bbba36198210e275f8aa051253c53873aea12c995fa9a208af0",
}
ANCESTRY_METADATA = {
    "preparation/r10/R10-SOURCE-PLAN.json",
    "preparation/r10/INDEPENDENT-CORE-SOURCE-REVIEW.json",
    "preparation/r10/INDEPENDENT-WHOLE-SOURCE-REVIEW.json",
    "release/reviewed/R10-SOURCE-SELECTION.json",
}


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def strict_json(data: bytes) -> dict:
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "duplicate JSON key")
            value[key] = item
        return value

    def nonfinite(_):
        raise ValueError("nonfinite JSON")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)


def member_path(root: Path, name: str) -> Path:
    need(type(name) is str and name != "", "empty member path")
    relative = PurePosixPath(name)
    need(not relative.is_absolute() and str(relative) == name
         and all(part not in (".", "..") for part in relative.parts),
         "noncanonical member path")
    path = root
    for part in relative.parts:
        path /= part
        need(not path.is_symlink(), "symlink in source checkpoint")
    return path


def verify_members(root: Path, rows: list) -> dict[str, bytes]:
    need(type(rows) is list and bool(rows), "source membership is empty")
    names = [row["path"] for row in rows]
    need(names == sorted(set(names)), "source membership is not sorted and unique")
    contents = {}
    for row in rows:
        name = row["path"]
        path = member_path(root, name)
        need(path.suffix in {".py", ".sh", ".json", ".md", ".patch"},
             "private or binary archive is not a source member")
        need(type(row["bytes"]) is int and 0 <= row["bytes"] <= 2 * 1024 * 1024
             and HASH.fullmatch(row["sha256"]) is not None,
             "invalid source descriptor")
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode), "source member is not a regular file")
        data = path.read_bytes()
        after = path.lstat()
        need(stable_stat_identity(before) == stable_stat_identity(after),
             "source member changed during read")
        need(len(data) == row["bytes"]
             and hashlib.sha256(data).hexdigest() == row["sha256"],
             "source bytes differ: " + name)
        contents[name] = data
    return contents


def stable_stat_identity(value) -> tuple:
    """Keep nanosecond mutation evidence, excluding read-induced access time."""
    return tuple(getattr(value, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    ))


def check_family(contents: dict[str, bytes], prefix: str, manifest_name: str,
                 expected_count: int) -> dict:
    manifest = strict_json(contents[prefix + manifest_name])
    files = manifest["files"]
    need(len(files) == expected_count, "original family membership count differs")
    paths = [row["path"] for row in files]
    need(len(set(paths)) == expected_count, "original family has duplicate members")
    for row in files:
        name = prefix + row["path"]
        need(name in contents, "original family source is missing")
        raw = contents[name]
        need(len(raw) == row["bytes"]
             and hashlib.sha256(raw).hexdigest() == row["sha256"],
             "original family source identity differs")
    actual = {name.removeprefix(prefix) for name in contents
              if name.startswith(prefix) and name != prefix + manifest_name}
    need(actual == set(paths), "unexpected file in original frozen family")
    return manifest


def at_json_pointer(value, pointer: str):
    if pointer == "":
        return value
    need(type(pointer) is str and pointer.startswith("/"), "invalid source JSON pointer")
    for segment in pointer[1:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        try:
            value = value[int(segment)] if isinstance(value, list) else value[segment]
        except (ValueError,TypeError,KeyError,IndexError) as error:
            raise ValueError("source JSON pointer does not resolve") from error
    return value


def static_source_values(data: bytes) -> dict[int, object]:
    """Read literal source descriptors without executing source or importing it."""
    names = {}

    def value(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return names[node.id]
        if isinstance(node, (ast.List, ast.Tuple)):
            return [value(item) for item in node.elts]
        if isinstance(node, ast.Dict) and all(key is not None for key in node.keys):
            return {value(key): value(item) for key, item in zip(node.keys, node.values)}
        if isinstance(node, ast.BinOp):
            left, right = value(node.left), value(node.right)
            if isinstance(node.op, ast.Add) and type(left) is type(right) is str:
                return left + right
            if isinstance(node.op, ast.Div) and isinstance(left, PurePosixPath) and type(right) is str:
                return left / right
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.keywords:
            arguments = [value(item) for item in node.args]
            if node.func.id == "Path" and all(isinstance(item, (str, PurePosixPath)) for item in arguments):
                return PurePosixPath(*arguments)
            if node.func.id == "str" and len(arguments) == 1 and isinstance(arguments[0], (str, PurePosixPath)):
                return str(arguments[0])
        raise ValueError("unsupported static source expression")

    found = {}
    for node in ast.parse(data).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                resolved = value(node.value)
            except (ValueError, KeyError, TypeError):
                continue
            names[node.targets[0].id] = resolved
            found[node.lineno] = resolved
    return found


def verify_external_bindings(contents: dict[str, bytes]) -> int:
    index = strict_json(contents["EXTERNAL-SOURCE-BINDINGS.json"])
    need(index["schema"] == "hepta.razr60.r10.external-source-bindings.v1",
         "external source binding schema differs")
    rows = index["source_bindings"]
    need(len(rows) == 518, "external source descriptor count differs")
    keys = [(row["path"], row["sha256"]) for row in rows]
    need(keys == sorted(set(keys)), "external source descriptors are not sorted and unique")
    exemptions = index["unmaterialized_development_ancestors"]
    need(len(exemptions) == 12
         and {row["descriptor"]["sha256"] for row in exemptions} == DEVELOPMENT_ANCESTOR_PINS,
         "development ancestor exemption set differs")
    by_key = {(row["descriptor"]["path"], row["descriptor"]["sha256"]): row
              for row in exemptions}
    unresolved = set()
    resolved = 0
    parsed_sources = {}
    for row in rows:
        key = (row["path"], row["sha256"])
        need(type(row["path"]) is str and str(PurePosixPath(row["path"])) == row["path"]
             and ".." not in PurePosixPath(row["path"]).parts
             and type(row["bytes"]) is int and row["bytes"] > 0
             and HASH.fullmatch(row["sha256"]) is not None,
             "invalid original external source descriptor")
        if "checkpoint_path" in row:
            name = row["checkpoint_path"]
            need(name in contents, "resolved external source member is missing")
            raw = contents[name]
            need(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
                 "resolved external source binding differs")
            need("resolution" not in row, "resolved source also claims an exemption")
            references = row["source_references"]
            need(bool(references), "resolved source has no original descriptor reference")
            for reference in references:
                origin = reference["member"]
                need(origin.startswith(("frozen/", "preparation/", "release/", "external-source/")),
                     "source binding references generated metadata")
                if origin.endswith(".json"):
                    original = at_json_pointer(strict_json(contents[origin]), reference["json_pointer"])
                else:
                    need(origin.endswith(".py"), "invalid descriptor source type")
                    if origin not in parsed_sources:
                        parsed_sources[origin] = static_source_values(contents[origin])
                    original = at_json_pointer(parsed_sources[origin][reference["python_assignment_line"]],
                                               reference["json_pointer"])
                need(isinstance(original, dict)
                     and {field: original.get(field) for field in ("path", "bytes", "sha256")} ==
                         {field: row[field] for field in ("path", "bytes", "sha256")},
                     "resolved source differs from its original descriptor")
            resolved += 1
            continue
        need(key in by_key and row.get("resolution") == "ancestry_or_external_source_not_materialized",
             "unapproved missing external source")
        unresolved.add(key)
        exemption = by_key[key]
        need(exemption["descriptor"] == row
             and exemption["required_for_manifest_materialization"] is False
             and exemption["historical_derivation_reexecution_established"] is False,
             "development ancestor descriptor or boundary differs")
        references = exemption["metadata_references"]
        need(bool(references), "development ancestor has no original metadata reference")
        for reference in references:
            name = reference["member"]
            need(name in ANCESTRY_METADATA, "development exemption points outside review metadata")
            original = at_json_pointer(strict_json(contents[name]), reference["json_pointer"])
            need(isinstance(original, dict)
                 and {field: original.get(field) for field in ("path", "bytes", "sha256")} ==
                     {field: row[field] for field in ("path", "bytes", "sha256")},
                 "development exemption does not bind original metadata")
        needle = row["path"].encode()
        need(all(needle not in raw for name, raw in contents.items() if name.endswith((".py", ".sh"))),
             "unmaterialized development path is referenced by executable source")
    need(unresolved == set(by_key), "unused or missing development ancestor exemption")
    return resolved


def verify_checkpoint(root: Path) -> dict:
    manifest = strict_json((root / "MANIFEST.json").read_bytes())
    need(manifest["schema"] == "hepta.razr60.r10.public-source-checkpoint.v1",
         "source checkpoint schema differs")
    need(manifest["negative_claims"] == NEGATIVE_CLAIMS,
         "source checkpoint claim ceiling differs")
    need(manifest["source_ancestor"]["commit"] ==
         "22e6105c2effe102c0f120a906752003aedfb37d", "source ancestor differs")
    contents = verify_members(root, manifest["files"])
    actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
    need(actual == set(contents) | {"MANIFEST.json"}, "unlisted checkpoint file")
    for name, digest in FROZEN_PINS.items():
        need(hashlib.sha256(contents[name]).hexdigest() == digest,
             "frozen R10 identity was reassigned: " + name)
    runtime = check_family(contents, "frozen/native/runtime/", "MANIFEST.json", 38)
    chain = check_family(contents, "frozen/native/root-chain/", "SOURCE-MANIFEST.json", 3)
    need(chain["frozen_component_package_sha256"] ==
         FROZEN_PINS["frozen/native/runtime/MANIFEST.json"], "root/runtime binding differs")
    need(runtime["current_combination_sha256"] ==
         FROZEN_PINS["frozen/native/COMBINATION.json"], "runtime/combination binding differs")
    dependencies = strict_json(contents["frozen/native/dependencies/DEPENDENCIES.json"])
    for row in dependencies["selected_files"]:
        name = "frozen/native/" + row["retained_member"]
        need(name in contents, "selected external dependency is missing")
        raw = contents[name]
        need(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
             "selected external dependency source differs")
    resolved_external_sources = verify_external_bindings(contents)
    python_files = 0
    for name, data in contents.items():
        if name.endswith(".py"):
            ast.parse(data.decode("utf-8"), filename=name)
            python_files += 1
        elif name.endswith(".json"):
            strict_json(data)
    candidate = strict_json(contents["unadopted/topology-20261107/CANDIDATE-MANIFEST.json"])
    need(candidate["state"] == "UNADOPTED_PURE_FUNCTION_CANDIDATE"
         and candidate["runtime_admission"] is False
         and candidate["historical_sources_changed"] is False
         and candidate["whole_stage_budget_verified"] is False,
         "unadopted candidate was promoted")
    derived = strict_json(contents["unadopted/topology-20261107/DERIVED-CANDIDATE-MANIFEST.json"])
    need(derived["state"] == "UNADOPTED_DERIVED_FUNCTION_CANDIDATES"
         and derived["runtime_admission"] is False
         and derived["native_case_credit"] == 0
         and derived["whole_stage_budget_verified"] is False,
         "derived candidate was promoted")
    need([row["id"] for row in derived["functions"]] ==
         ["source-parent-inventory", "retained-r8-scope"], "derived function set differs")
    for row in derived["functions"]:
        need(row["whole_byte_inverse_verified"] is True
             and all(row[field] is False for field in (
                 "historical_source_bytes_changed", "historical_reader_function_replaced_in_runtime",
                 "original_module_provenance_reassigned", "validation_result_cache",
                 "production_selector_implemented")), "derived function claim ceiling differs")
        for field in ("original_source", "fragment", "patch"):
            descriptor = row[field]
            raw = contents["unadopted/topology-20261107/" + descriptor["path"]]
            need(len(raw) == descriptor["bytes"]
                 and hashlib.sha256(raw).hexdigest() == descriptor["sha256"],
                 "derived function source binding differs")
    verify_selector_candidate(contents)
    return {
        "schema": "hepta.razr60.r10.source-closure-check.v1",
        "result": "PASS_SOURCE_BYTES_AND_STRUCTURE_ONLY",
        "members": len(contents), "python_sources_parsed": python_files,
        "native_runtime_members": 38, "root_chain_members": 3,
        "selected_external_dependencies": len(dependencies["selected_files"]),
        "resolved_external_source_bindings": resolved_external_sources,
        "explicit_unmaterialized_development_ancestors": 12,
        "runtime_imported": False, "runtime_adopted": False,
        "phone_or_model_requests": 0, "fixed19_credits_added": 0,
        "whole_stage_budget_verified": False,
    }


def verify_selector_candidate(contents: dict[str, bytes]) -> None:
    prefix = "unadopted/topology-20261107/"
    selector = strict_json(contents[prefix + "SELECTOR-CANDIDATE-MANIFEST.json"])
    need(selector["schema"] == "hepta.UNADOPTED.reader-selector-candidate.v1"
         and selector["state"] == "OFFLINE_TESTED_NOT_PRODUCTION_ADOPTED"
         and selector["native_case_credit"] == 0
         and selector["production_policy_status"] == "HOLD"
         and selector["source_parent_boundary_reader_status"] == "HOLD_REQUIRES_NEW_PROVENANCE_POLICY"
         and all(selector[field] is False for field in (
             "runtime_admission", "production_selector_adopted", "validation_result_cache",
             "live_observation_cache", "original_module_globals_reassigned", "original_source_bytes_changed",
             "source_parent_full_boundary_composed", "new_runtime_policy_or_freeze_provided",
             "whole_stage_budget_verified"))
         and selector["new_code_provenance_is_separate"] is True,
         "offline selector claim ceiling differs")
    pins = {
        "selector_source": "de7dc784654dec65f0e6d2d7fd81918caf9c3c634d152295c1fb7928cf04a5c2",
        "bound_loader_source": "4aa4fb101dca5f4532c70ec071231b036df6e63940d08d6613305be6cb699b82",
    }
    for field, digest in pins.items():
        need(selector[field]["sha256"] == digest, "offline selector identity was reassigned")
    for row in [selector["selector_source"], selector["bound_loader_source"], *selector["original_sources"]]:
        raw = contents[prefix + row["path"]]
        need(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
             "offline selector source binding differs")
    need([row["kind"] for row in selector["constructions"]] ==
         ["r7-reader", "r8-reader", "r8-scope", "r9-reader", "r9-scope"],
         "offline selector construction set differs")
    for row in selector["constructions"]:
        need(row["original_module_mutated"] is False
             and row["reference_source_bytes_changed"] is False
             and row["fresh_module_globals"] is True
             and row["whole_byte_inverse_verified"] is True
             and row["derived_source"]["sha256"] != row["original_source"]["sha256"],
             "offline selector provenance boundary differs")
    delivery = strict_json(contents[prefix + "PORTABLE-DELIVERY-MANIFEST-v2.json"])
    need(delivery["state"] == "UNADOPTED_OFFLINE_SELECTOR_INCREMENT"
         and delivery["v1_all_35_files_unchanged"] is True,
         "offline selector delivery boundary differs")
    for manifest_name, count in (("PORTABLE-DELIVERY-MANIFEST-v1.json", 35),
                                 ("PORTABLE-DELIVERY-MANIFEST-v2.json", 11)):
        manifest = strict_json(contents[prefix + manifest_name])
        need(len(manifest["files"]) == count
             and len({row["path"] for row in manifest["files"]}) == count,
             "offline selector delivery membership differs")
        for row in manifest["files"]:
            raw = contents[prefix + row["path"]]
            need(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
                 "offline candidate delivery source differs")
    for private in delivery["private_evidence_do_not_import"]:
        need(prefix + private["artifact"] not in contents, "private selector evidence was published")


def materialize_checkpoint(root: Path, output: Path) -> dict:
    """Rebuild the public current-source tree from complete checked members.

    The output remains a source tree. Host-specific original evidence, a new
    freeze/admission, and adopted release authority are not manufactured here.
    """
    report = verify_checkpoint(root)
    manifest = strict_json((root / "MANIFEST.json").read_bytes())
    rows = [row for row in manifest["files"] if row["path"].startswith(
        ("frozen/", "preparation/", "release/", "external-source/"))]
    contents = verify_members(root, rows)
    need(not output.exists() and not output.is_symlink(), "output must be absent")
    output.mkdir(parents=False)
    for name, raw in contents.items():
        target = member_path(output, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
    verify_members(output, rows)
    result = {
        "schema": "hepta.razr60.r10.materialized-source.v1",
        "checkpoint_manifest_sha256": hashlib.sha256((root / "MANIFEST.json").read_bytes()).hexdigest(),
        "members": len(rows), "native_runtime_members": report["native_runtime_members"],
        "source_bytes_exact": True, "runtime_adopted": False,
        "private_evidence_reconstructed": False, "phone_or_model_requests": 0,
        "fixed19_credits_added": 0,
    }
    (output / "MATERIALIZATION.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--materialize", type=Path,
                        help="Create an absent directory containing the exact current-source members")
    args = parser.parse_args()
    root = args.repo_root / CHECKPOINT
    result = (materialize_checkpoint(root, args.materialize) if args.materialize is not None
              else verify_checkpoint(root))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
