#!/usr/bin/env python3
"""Prepare only the exact source dependency candidate; no target operations."""
from pathlib import Path
import json
import shutil
import subprocess
import sys

r = Path(sys.argv[1]).resolve(strict=True)
def run(*args):
    return subprocess.run(args, cwd=r, check=True, timeout=180, capture_output=False)
def git_value(*args):
    return subprocess.run(("git", *args), cwd=r, check=True, timeout=30,
                          capture_output=True, text=True).stdout.strip()
if git_value("rev-parse", "HEAD") != "b6cb785d4fde6427a1ae99ffc12f0679353aaaff":
    raise SystemExit("source parent mismatch")
if git_value("rev-parse", "HEAD^{tree}") != "2e02c303fce0470dcb7063bfcb31155de964d3db" or git_value("status", "--porcelain"):
    raise SystemExit("source tree mismatch or dirty source")

p=r/'tools/docs/verify_repository_authority.py'
s=p.read_text()
s=s.replace('    "evidence_requirements",\n}', '    "evidence_requirements", "deferred_dependencies",\n}')
s=s.replace('BLOCKED_CAPABILITY_KEYS = {"id", "reason"}', '''BLOCKED_CAPABILITY_KEYS = {"id", "reason"}
DEFERRED_DEPENDENCY_KEYS = {
    "source_module", "dependency_module", "classification", "blocking_gap", "reason",
}''')
marker='def verify_profiles(root: Path) -> dict[str, Any]:\n'
helper='''def verify_profile_dependencies(
    root: Path,
    profile: dict[str, Any],
    module_map: dict[str, dict[str, Any]],
    module_paths: dict[str, list[str]],
    selected_paths: list[str],
) -> None:
    """Check the selected source graph, never mint installed/runtime authority.

    A missing target may be deferred only as a named planned-only edge with an
    unresolved target-qualification gap owned by its selected source module.
    There is no wildcard, optional runtime dependency, or fallback behavior.
    """
    profile_id = profile["id"]
    selected = set(profile["selected_modules"])
    edges: set[tuple[str, str]] = set()
    for source in sorted(selected):
        for target in string_list(
            module_map[source].get("dependencies"), f"{source}.dependencies", allow_empty=True
        ):
            require(target in module_map, f"{source} has unknown dependency {target}")
            require(target != source, f"{source} has a self dependency")
            edges.add((source, target))
    missing = {(source, target) for source, target in edges if target not in selected}
    deferred = profile["deferred_dependencies"]
    require(isinstance(deferred, list), f"{profile_id}.deferred_dependencies must be an array")
    require(len(deferred) <= len(edges), f"{profile_id} has too many deferred dependencies")
    gap_catalog = load_json(root / "docs/machine/gap-register.v2.json")
    gap_items = gap_catalog.get("gaps")
    require(isinstance(gap_items, list), "gap register must contain a gaps array")
    gaps: dict[str, dict[str, Any]] = {}
    for gap in gap_items:
        require(isinstance(gap, dict), "gap entry must be an object")
        gap_id = text(gap.get("id"), "gap id")
        require(gap_id not in gaps, "gap register repeats an id")
        gaps[gap_id] = gap
    observed: set[tuple[str, str]] = set()
    for index, entry in enumerate(deferred):
        label = f"{profile_id}.deferred_dependencies[{index}]"
        require(isinstance(entry, dict), f"{label} must be an object")
        exact_keys(entry, DEFERRED_DEPENDENCY_KEYS, label)
        source = text(entry["source_module"], f"{label}.source_module")
        target = text(entry["dependency_module"], f"{label}.dependency_module")
        edge = (source, target)
        require(edge not in observed, f"{label} duplicates a deferred edge")
        require(edge in missing, f"{label} is not a missing selected-source dependency")
        require(entry["classification"] == "PLANNED_ONLY", f"{label} classification must be PLANNED_ONLY")
        maturity = module_map[target].get("maturity")
        require(isinstance(maturity, str) and maturity.startswith("PLANNED_"),
                f"{label} cannot defer a non-planned module")
        require(all(path.startswith("planned/") for path in module_paths[target]),
                f"{label} planned module has a non-planned source path")
        require(not any(paths_overlap(path, planned) for path in selected_paths
                        for planned in module_paths[target]),
                f"{label} planned source is already selected")
        gap_id = text(entry["blocking_gap"], f"{label}.blocking_gap")
        require(gap_id in gaps, f"{label} references an unknown blocking gap")
        gap = gaps[gap_id]
        require(gap.get("status") in {"OPEN", "SOURCE_CLOSED_PENDING_EVIDENCE", "EXTERNAL_HOLD"},
                f"{label} blocking gap is not unresolved")
        require(gap.get("exit_level") in {"L2", "L3", "L4", "L5", "L6"},
                f"{label} blocking gap is not target qualification")
        owners = string_list(gap.get("modules"), f"{gap_id}.modules")
        require(source in owners, f"{label} blocking gap does not cover the source module")
        reason = text(entry["reason"], f"{label}.reason")
        try:
            reason_bytes = reason.encode("utf-8", "strict")
        except UnicodeError as error:
            raise VerificationError(f"{label} reason is not valid UTF-8") from error
        require(len(reason_bytes) <= 1024
                and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in reason),
                f"{label} reason exceeds bounded single-line text")
        observed.add(edge)
    require(observed == missing,
            f"{profile_id} undeclared missing dependencies: {sorted(missing-observed)}")


'''
assert marker in s
s=s.replace(marker,helper+marker)
marker='        capabilities = raw["offered_capabilities"]\n'
assert marker in s
s=s.replace(marker,'        verify_profile_dependencies(root, raw, module_map, module_paths, selected_paths)\n\n'+marker)
p.write_text(s)
p=r/'docs/machine/product-profile-catalog.v1.json'
v=json.loads(p.read_text())
for profile in v['profiles']:
    profile['deferred_dependencies']=[]
v['profiles'][0]['deferred_dependencies']=[{
 'source_module':'MOD-ROOTLINUX',
 'dependency_module':'MOD-GLOBAL-CONTROL',
 'classification':'PLANNED_ONLY',
 'blocking_gap':'GAP-ROOTLINUX-PLACEMENT-001',
 'reason':'The default source profile does not select the planned control-plane implementation. Installed admission, lease and resource behavior remain unqualified; this declaration neither supplies a local lease substitute nor authorizes runtime activation.'}]
p.write_text(json.dumps(v,indent=2)+'\n')
p=r/'tools/docs/generate_global_docs.py'
s=p.read_text()
start=s.index('def product_profile_status() -> str:')
end=s.index('def effect_lifecycle_status() -> str:',start)
part=s[start:end]
old='''    lines += [
        "",
        "A sealed profile contributes no current product capability.'''
new='''    modules = {item["id"]: item for item in load("module-catalog.v1.json")["modules"]}
    lines += [
        "",
        "## Selected source dependencies and explicit planned edges",
        "",
        "This graph is a source-selection projection, not an installed service graph.",
        "Every selected module dependency is either selected or explicitly deferred.",
        "Deferral never supplies an optional runtime dependency, lease substitute or",
        "controller activation; its named target-qualification gap must remain unresolved.",
        "",
        "| Profile | Source module | Dependency | Selection | Blocking gap |",
        "| --- | --- | --- | --- | --- |",
    ]
    for profile in data["profiles"]:
        selected = set(profile["selected_modules"])
        deferred = {
            (item["source_module"], item["dependency_module"]): item
            for item in profile["deferred_dependencies"]
        }
        for source in sorted(selected):
            for target in sorted(modules[source]["dependencies"]):
                entry = deferred.get((source, target))
                selection = "PLANNED_ONLY" if entry else "SELECTED_SOURCE"
                gap = entry["blocking_gap"] if entry else "none"
                lines.append(
                    f"| `{profile['id']}` | `{source}` | `{target}` | `{selection}` | `{gap}` |"
                )
    lines += [
        "",
        "A sealed profile contributes no current product capability.'''
assert old in part
part=part.replace(old,new)
s=s[:start]+part+s[end:]
p.write_text(s)
p=r/'docs/GLOBAL_ARCHITECTURE.md'
s=p.read_text()
needle='## 3. State ownership\n'
addition='''### 2.1 Selected source versus target architecture

The four-plane diagram and module dependency catalog include planned modules.
The default product profile is the selected source subset recorded in
`machine/product-profile-catalog.v1.json`; its checked projection is
`generated/PRODUCT_PROFILE_STATUS.md`. It is not evidence of an installed
runtime process graph.

Each profile now requires `deferred_dependencies`, including an empty array
when no dependency is deferred. Older profile records without that field fail
closed and must be regenerated/reviewed with the verifier and projection. Every
dependency of a selected module must also be selected unless one exact
`PLANNED_ONLY` edge names an unresolved L2-or-higher gap covering its source
module. The target must have a planned maturity and only `planned/` source
paths, and none of those paths may already be selected. Unknown, duplicated,
stale or overbroad exceptions are rejected; a closed gap cannot retain its
planned-edge exception.

The present explicit edge is `MOD-ROOTLINUX -> MOD-GLOBAL-CONTROL`, held by
`GAP-ROOTLINUX-PLACEMENT-001`. Root Linux's normative `module_instance_lease`
contract is unchanged. This source-profile declaration does not invent a local
lease provider or demonstrate that lease admission works without a controller.
Before installed qualification, either select and qualify the required
implementation, or make an explicit reviewed architecture/contract change and
qualify the resulting installed behavior. Remove the exception only with the
corresponding source and evidence transition. No control mode is activated here.

Cargo feature/dependency checks, Android evaluated build graphs and installed
identity remain separate gates. A selected logical edge is not proof of a Rust
import or a running service, and a planned logical edge never excuses an actual
unselected product dependency. This distinction prevents source selection from
silently becoming a claim of target completeness.

'''
assert needle in s
s=s.replace(needle,addition+needle)
p.write_text(s)
p=r/'docs/modules/MOD-ROOTLINUX.md'
s=p.read_text()
needle='Direct dependencies: `MOD-EXECUTION-CORE`, `MOD-PROVIDER`, `MOD-GLOBAL-CONTROL`.\n'
assert needle in s
s=s.replace(needle,needle+'''
This logical graph includes the planned control-plane edge. The default source
profile records that edge as `PLANNED_ONLY`, held by
`GAP-ROOTLINUX-PLACEMENT-001`; see `docs/GLOBAL_ARCHITECTURE.md` section 2.1 and
`docs/generated/PRODUCT_PROFILE_STATUS.md`. It does not select a controller,
replace the `module_instance_lease` contract with an invented local lease, or
establish an installed admission path. The profile verifier rejects a missing
selected dependency without its explicit planned-edge declaration. Installed
qualification must reconcile this edge by selecting the required implementation
or by a separately reviewed contract change backed by target evidence.
''')
p.write_text(s)
shutil.copyfile(Path(__file__).with_name('profile_dependency_test.py'), r/'tools/tests/test_profile_dependency_closure.py')
run(sys.executable, 'tools/docs/generate_global_docs.py')
run(sys.executable, '-m', 'unittest', 'tools.tests.test_profile_dependency_closure', 'tools.tests.test_repository_authority', '-q')
run(sys.executable, 'tools/docs/verify_global_docs.py')
run(sys.executable, 'tools/docs/generate_global_docs.py', '--check')
run('git', 'add', '--all')
if git_value('write-tree') != '2b49ef0de817b00e92e7131e781b6e992023e31c':
    raise SystemExit('candidate tree mismatch')
print('source_preparation_only=true\npublic_release=false\ncandidate_tree=2b49ef0de817b00e92e7131e781b6e992023e31c')
