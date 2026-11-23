"""Host-only binding of the published v35 source, compiler outputs and signed APK.

The historical root SOURCE-MANIFEST is an ordinary inventory member, never the
current identity. No phone access, installation, key generation or APK execution.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from types import ModuleType
import zipfile

COMMIT = '8d4bf8531811b189d1605c10ef85bdd0afe55225'
TREE = 'a8d13b8c378f8416f1ac5215a7ce3c49ab20ace9'
PORTABLE_SHA = '92b5ea91a894e897722e7dac11b753edfb4b7c652e79adfdc252135e7e6c6d46'
FILE_COUNT = 1201
INPUT_COUNT = 164
PACKAGE = "org.trillionnium.hepta.local"
VERSION_CODE = 35
VERSION_NAME = '0.35.0-local-owner-authorization'
CERT_SHA = "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
ASSET = "assets/hepta-build-identity.json"
SDK_COMMIT = "071f609995470bdb0e0769ab964754adfaab7e47"
LLAMA_COMMIT = "19cce6919992fdffd92e0ac152caaf1e2b8f254e"
HEX = re.compile(r"[0-9a-f]{64}\Z")
HELPERS = ("warm_receipts", "model_profiles", "phone_acceptance", "phone_inventory")
PUBLICATION_SHA = 'a32959854e869568ae624bad7bda9542d1af0de53db83b18b8ba10b7e6f53a9c'
EXPECTED_INVENTORY_SHA = '1509a69de68ff1bbe2b30727fbf46ee6ef2ded1d4b2e8f2dc0cfee705ab76dd9'
PREPARED_BUILD_RECEIPT_SHA = '079190ce7fe35dc6e4284c4cb7dd674c568f41918540f09f8956dce24dce9cbf'
RUN_HOST_CHECKS_SHA = '1513f179c1dba314f018b948f917a2b16a437bc4841ac9e59f1a207c671910e4'
HOST_CHECK_NAMES = ['java-compile', 'ActionFreshnessHostTest', 'AppCatalogueHostTest', 'BudgetHostTest', 'CompactEvidenceHostTest', 'CompactSequenceHostTest', 'CompactTaskHistoryHostTest', 'DiagnosticStartupGateHostTest', 'DispatchedActionSequenceHostTest', 'Gemma4ProfileHostTest', 'ImeObservationHostTest', 'Lfm25MoeProfileHostTest', 'LocalPolicyHostTest', 'MemoryAvailabilityHostTest', 'MobiMindContractHostTest', 'MobiMindSessionContractHostTest', 'MobileAgentProfilesHostTest', 'ModelProfileHostTest', 'Nanbeige42ProfileHostTest', 'ObservationStabilityHostTest', 'ObservedAppLabelsHostTest', 'ObservedChildTextHostTest', 'ObservedScrollActionsHostTest', 'ObservedTargetLabelsHostTest', 'ObservedTextProjectionHostTest', 'ObservedTransitionProjectionHostTest', 'ObservedWindowMetadataHostTest', 'PersistentActionPolicyHostTest', 'PromptActionDomainHostTest', 'PromptCapabilityProjectionHostTest', 'Qwen35ProfileHostTest', 'ReadableActionHistoryHostTest', 'RecentActionProjectionHostTest', 'RecoveryAcknowledgementHostTest', 'RecoveryDispatchHostTest', 'RecoverySlotHandoffHostTest', 'RepeatActionGuardHostTest', 'RepeatClickProjectionHostTest', 'SameStateNoEffectGuardHostTest', 'ScrollGrammarHostTest', 'SessionRecoveryHostTest', 'UiVenusContractHostTest', 'UiVenusInputContractHostTest', 'UiVenusProcessContractHostTest', 'UiVenusRequestContractHostTest', 'UiVenusSessionContractHostTest', 'WarmProcessSessionHostTest', 'ActionDecisionHostTest', 'DecisionGrammarHostTest', 'grammar-recognition', 'app-label-grammar-recognition', 'scroll-grammar-recognition', 'completion-protocol', 'same-state-no-effect-grammar', 'qualification-scope', 'owner-authorization', 'owner-grammar', 'python-tools', 'mobimind-private-staging', 'ui-venus-q4_0-provenance', 'lfm25_profile_contract-compile', 'lfm25_profile_contract', 'mobile_agent_profiles_contract-compile', 'mobile_agent_profiles_contract', 'model_profile_contract-compile', 'model_profile_contract', 'nanbeige42_profile_contract-compile', 'nanbeige42_profile_contract', 'parent_death_contract-compile', 'parent_death_contract', 'phase_timing_contract-compile', 'phase_timing_contract', 'prompt_budget_contract-compile', 'prompt_budget_contract', 'publish_contract-compile', 'publish_contract', 'qwen35_profile_contract-compile', 'qwen35_profile_contract', 'sha256_probe-compile', 'sha256_probe', 'sha256-hashlib-differential', 'native-adapter-syntax', 'private-prompt-evidence', 'task-worker-native-lifecycle', 'profile-sampler']
HOST_INPUT_COUNT = 268
GATE_PLAN_SOURCE_SHA = 'fb23147cb06244e06537cc651602c1f53613258654dafb1617a0389d16bbe395'


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict(data):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "duplicate JSON key: " + key)
            value[key] = item
        return value
    def bad(value):
        raise ValueError("non-finite JSON: " + value)
    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()


def write_new(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def stat_key(value):
    return tuple(getattr(value, key) for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))


def regular(path, limit=64 << 20, allow_empty=False):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)),
         "absolute non-symlink input required: " + str(path))
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and (0 if allow_empty else 1) <= before.st_size <= limit,
             "regular nonempty bounded input required: " + str(path))
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    need(len(raw) == before.st_size and stat_key(before) == stat_key(after) == stat_key(path.stat()),
         "input changed during read: " + str(path))
    return raw, stat_key(before)


def bound_json(path, expected):
    need(isinstance(expected, str) and HEX.fullmatch(expected), "explicit full SHA required")
    raw, _ = regular(path, 2 << 20)
    need(sha(raw) == expected, "proof SHA differs: " + str(path))
    value = strict(raw)
    need(isinstance(value, dict), "proof must be a JSON object")
    return value


def safe_relative(value):
    need(isinstance(value, str) and value and "\\" not in value, "unsafe inventory path")
    path = PurePosixPath(value)
    need(path.parts and not path.is_absolute() and str(path) == value and not any(p in ("", ".", "..") for p in path.parts),
         "unsafe inventory path")
    return value


def verify_inventory(source, inventory):
    need(inventory.get("schema") == "hepta.independent-v35-source-integration.v1"
         and inventory.get("source_commit") == COMMIT and inventory.get("source_tree") == TREE
         and inventory.get("actual_source_assembly_verified") is True
         and type(inventory.get("file_count")) is int and inventory["file_count"] == FILE_COUNT,
         "actual complete published v35 inventory required")
    rows = inventory.get("files")
    need(isinstance(rows, list) and len(rows) == FILE_COUNT, "complete source file count differs")
    portable, pins = [], {}
    for row in rows:
        need(isinstance(row, dict), "bad inventory row")
        name = safe_relative(row.get("path"))
        need(name not in pins and type(row.get("bytes")) is int and row["bytes"] >= 0
             and isinstance(row.get("sha256"), str) and HEX.fullmatch(row["sha256"])
             and isinstance(row.get("git_blob_sha"), str) and re.fullmatch(r"[0-9a-f]{40}", row["git_blob_sha"]),
             "duplicate or malformed inventory row")
        pins[name] = {key: row[key] for key in ("path", "bytes", "sha256", "git_blob_sha")}
        portable.append(pins[name])
    need(list(pins) == sorted(pins), "source inventory is not in canonical path order")
    digest = sha(json.dumps(portable, sort_keys=True, separators=(",", ":")).encode())
    need(digest == PORTABLE_SHA == inventory.get("portable_inventory_sha256"),
         "inventory does not match the published v35 content")
    verify_source_files(source, pins)
    return pins


def verify_source_files(source, pins):
    need(source.is_absolute() and source.is_dir() and not source.is_symlink(), "absolute regular source directory required")
    for name, row in pins.items():
        path = source / name
        if row["bytes"] == 0:
            need(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents))
                 and path.stat().st_size == 0, "empty source member differs: " + name)
            raw = b""
        else:
            raw, _ = regular(path, 8 << 20)
        need(len(raw) == row["bytes"] and sha(raw) == row["sha256"]
             and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == row["git_blob_sha"],
             "source differs from published inventory: " + name)
    # Build output/key directories may exist, but no extra importable host driver
    # may enter the verified tools namespace. Actual compiler inputs are checked
    # separately by the published source_inputs function below.
    for path in (source / "tools").glob("*.py"):
        need(path.relative_to(source).as_posix() in pins, "unlisted importable host driver")


def isolated_module(name, path):
    need(name not in sys.modules, "unexpected preloaded identity module")
    raw, _ = regular(path, 8 << 20)
    value = ModuleType(name)
    value.__file__, value.__package__ = str(path), ""
    # Compile the just-read source bytes; do not trust an unlisted timestamp-valid
    # __pycache__ beside a correctly hashed .py source file.
    exec(compile(raw, str(path), "exec"), value.__dict__)
    return value


def load_source_modules(source, pins):
    tools = source / "tools"
    names = {path.stem for path in tools.glob("*.py")}
    def check_loaded():
        for name in names:
            if name in sys.modules:
                actual = getattr(sys.modules[name], "__file__", None)
                need(actual is not None and Path(actual).resolve() == (tools / (name + ".py")).resolve(),
                     "preloaded/imported driver came from a different source: " + name)
    check_loaded()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(tools))
    modules = {}
    # The dependency order is explicit: the latter two import only the preceding
    # verified local modules. Standard-library imports keep Python's normal path.
    for name in HELPERS:
        path = tools / (name + ".py")
        raw, _ = regular(path, 8 << 20)
        need(sha(raw) == pins["tools/" + name + ".py"]["sha256"], "driver changed before source compilation")
        module = ModuleType(name)
        module.__file__, module.__package__ = str(path), ""
        sys.modules[name] = module
        exec(compile(raw, str(path), "exec"), module.__dict__)
        modules[name] = module
    check_loaded()
    for name in names:
        if name in sys.modules:
            raw, _ = regular(tools / (name + ".py"), 8 << 20)
            need(sha(raw) == pins["tools/" + name + ".py"]["sha256"], "imported driver changed")
    return modules["phone_acceptance"], modules["phone_inventory"], modules["model_profiles"]


def host_gate_contract(source):
    """Reproduce only the pinned producer's selectors; never run its test driver."""
    paths = set(source.glob("*.py"))
    for directory, extensions in (("src", ("*.java",)), ("tests", ("*.java", "*.py")),
                                  ("native", ("*.c", "*.h", "*.inc", "*.py")), ("tools", ("*.py",))):
        for extension in extensions:
            paths.update((source / directory).rglob(extension))
    inputs = []
    for path in sorted(paths):
        raw, _ = regular(path, 8 << 20, allow_empty=True)
        inputs.append({"path": str(path.relative_to(source)), "sha256": sha(raw)})
    runner, _ = regular(source / "tools/run_host_checks.py", 1 << 20)
    need(sha(runner) == RUN_HOST_CHECKS_SHA, "host runner differs from frozen publication")
    names = _derive_host_names(runner.decode("utf-8"), [row["path"] for row in inputs])
    need(names == HOST_CHECK_NAMES and len(inputs) == HOST_INPUT_COUNT,
         "actual host gate names/input count differ from frozen producer")
    return inputs, names


def verify_host_gate(args):
    raw = bound_json(args.host_checks, args.host_checks_sha256)
    qualification = bound_json(args.host_gate_qualification, args.host_gate_qualification_sha256)
    inputs, names = host_gate_contract(args.source)
    checks = raw.get("checks")
    need(raw.get("schema") == "hepta.host-checks.v3" and raw.get("scope") == "host_only"
         and raw.get("all_pass") is True and raw.get("phone_tested") is False
         and raw.get("external_model_used") is False and raw.get("source_inputs") == inputs
         and isinstance(checks, list) and [row.get("name") for row in checks] == names,
         "original complete host gate does not bind current source/check sequence")
    for row in checks:
        need(type(row.get("exit_code")) is int and row["exit_code"] == 0, "original host check did not pass")
        for stream in ("stdout", "stderr"):
            data, _ = regular(args.host_checks.parent / (row["name"] + "." + stream), 16 << 20, allow_empty=True)
            need(sha(data) == row.get(stream + "_sha256"), "host check log differs from original record")
    runner, _ = regular(args.source / "tools/run_host_checks.py", 1 << 20)
    item = qualification.get("full_host_checks", {})
    need(qualification.get("schema") == "hepta.v35-applicable-host-gates.v1"
         and qualification.get("source_commit") == COMMIT and qualification.get("source_tree") == TREE
         and qualification.get("source_integration_sha256") == args.source_inventory_sha256
         and item.get("sha256") == args.host_checks_sha256 and item.get("schema") == raw["schema"]
         and item.get("all_pass") is True and type(item.get("check_records")) is int and item["check_records"] == len(checks)
         and item.get("all_records_exit_zero") is True and item.get("source_input_set_matches_current") is True
         and type(item.get("source_input_count")) is int and item["source_input_count"] == len(inputs)
         and item.get("runner_source_sha256") == sha(runner), "applicable gate qualification differs from independently read original gate")
    return {"host_checks_sha256": args.host_checks_sha256,
            "host_gate_qualification_sha256": args.host_gate_qualification_sha256,
            "check_records": len(checks), "source_input_count": len(inputs), "all_records_exit_zero": True,
            "runner_source_sha256": sha(runner), "all_original_log_hashes_verified": True,
            "historical_extra_runner": qualification.get("historical_extra_runner")}


def verify_zip(apk_raw, asset, build, static, build_output):
    import io
    expected = {"classes.dex": build_output / "dex/classes.dex", "base.apk": build_output / "base.apk",
                "libhepta_local_runner.so": build_output / "libhepta_local_runner.so"}
    artifacts, payloads = {}, {}
    for row in build.get("artifacts", []):
        name = Path(row["path"]).name
        need(name in expected and name not in artifacts, "unexpected or repeated compiler output")
        raw, _ = regular(expected[name])
        need(type(row.get("bytes")) is int and len(raw) == row["bytes"] and sha(raw) == row.get("sha256"),
             "compiled output differs: " + name)
        artifacts[name], payloads[name] = row["sha256"], raw
    need(set(artifacts) == set(expected), "complete actual compiler outputs required")
    with zipfile.ZipFile(io.BytesIO(apk_raw)) as z, zipfile.ZipFile(io.BytesIO(payloads["base.apk"])) as base:
        need(len(z.namelist()) == len(set(z.namelist())) and len(base.namelist()) == len(set(base.namelist())),
             "duplicate APK ZIP entry")
        need(z.getinfo(ASSET).file_size <= 131072 and z.read(ASSET) == asset, "signed APK actual-build asset differs")
        need(z.getinfo("classes.dex").file_size == len(payloads["classes.dex"])
             and sha(z.read("classes.dex")) == artifacts["classes.dex"], "signed APK DEX differs from compiler output")
        need(ASSET not in base.namelist(), "unexpected build identity in compiler base APK")
        for info in base.infolist():
            need(info.file_size <= 8 << 20 and z.getinfo(info.filename).file_size == info.file_size
                 and z.read(info.filename) == base.read(info.filename), "compiled base member differs in signed APK")
        libraries = static.get("libraries")
        need(isinstance(libraries, list) and libraries, "static runtime library evidence absent")
        names = set()
        for row in libraries:
            name = row.get("name")
            need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_+.-]+[.]so", name) and name not in names,
                 "unexpected runtime library")
            names.add(name)
            info = z.getinfo("lib/arm64-v8a/" + name)
            need(type(row.get("bytes")) is int and 0 < row["bytes"] <= 64 << 20 and info.file_size == row["bytes"]
                 and sha(z.read(info.filename)) == row.get("sha256"), "packaged runtime library differs")
            if name == "libhepta_local_runner.so":
                need(row["sha256"] == artifacts[name], "local runner differs from compiler output")
        need("libhepta_local_runner.so" in names
             and {n for n in z.namelist() if n.startswith("lib/")} == {"lib/arm64-v8a/" + n for n in names},
             "packaged runtime library set differs")
        allowed = set(base.namelist()) | {ASSET, "classes.dex"} | {"lib/arm64-v8a/" + n for n in names}
        need(all(name in allowed or re.fullmatch(r"META-INF/(?:MANIFEST[.]MF|[A-Za-z0-9_-]+[.](?:SF|RSA|DSA|EC))", name)
                 for name in z.namelist()), "unexpected signed APK payload outside compiler/static closure")
    return artifacts


def load_bundle(args):
    source = args.source
    inventory = bound_json(args.source_inventory, args.source_inventory_sha256)
    pins = verify_inventory(source, inventory)
    need(args.build_receipt_sha256 == PREPARED_BUILD_RECEIPT_SHA, "compiler receipt differs from helper preparation")
    build = bound_json(args.build_receipt, args.build_receipt_sha256)
    need(build.get("schema") == "hepta.local-model.mac-build.v2" and build.get("source_head_from_ci") == COMMIT
         and build.get("runtime") == "llama_cpp" and type(build.get("java_target")) is int and build["java_target"] == 8
         and build.get("geniex_source_commit") == SDK_COMMIT and build.get("llama_source_commit") == LLAMA_COMMIT,
         "actual v35 compiler receipt identity differs")
    sys.dont_write_bytecode = True
    identity = isolated_module("verified_v35_build_identity", source / "tools/build_identity.py")
    inputs = identity.source_inputs(source)
    need(len(inputs) == INPUT_COUNT and build.get("source_inputs") == inputs, "actual compiler source inputs differ")
    asset = identity.actual_build_identity(source, build)
    need(HEX.fullmatch(args.build_asset_sha256) and sha(asset) == args.build_asset_sha256,
         "actual build asset SHA differs; predicted assets are insufficient")
    value = strict(asset)
    need(value.get("schema") == "hepta.actual-build-inputs.v1" and type(value.get("version_code")) is int
         and value["version_code"] == VERSION_CODE and value.get("source_inputs") == inputs,
         "actual build asset contract differs")
    static = bound_json(args.static_acceptance, args.static_acceptance_sha256)
    need(static.get("schema") == "hepta.local-model.static-acceptance.v3" and static.get("package") == PACKAGE
         and type(static.get("version_code")) is int and static["version_code"] == VERSION_CODE
         and static.get("version_name") == VERSION_NAME and static.get("permissions") == []
         and static.get("actual_build_identity_asset") == ASSET
         and static.get("actual_build_identity_sha256") == args.build_asset_sha256
         and static.get("apk_sha256") == args.apk_sha256 and static.get("abi") == ["arm64-v8a"]
         and static.get("fallback_allowed") is False and static.get("dsp_arch") == "v79",
         "final signed APK static acceptance differs")
    apk_raw, apk_stat = regular(args.apk)
    need(HEX.fullmatch(args.apk_sha256) and sha(apk_raw) == args.apk_sha256
         and type(static.get("apk_bytes")) is int and static["apk_bytes"] == len(apk_raw), "signed APK SHA/size differs")
    artifacts = verify_zip(apk_raw, asset, build, static, args.build_output)
    gate = verify_host_gate(args)
    modules = load_source_modules(source, pins)
    need(build.get("model_profiles") == static.get("model_profiles") == modules[2].PROFILES,
         "compiled/static/source model registries differ")
    proof = {"source_commit": COMMIT, "source_tree": TREE, "complete_source_inventory_sha256": args.source_inventory_sha256,
             "portable_source_inventory_sha256": PORTABLE_SHA, "source_file_count": len(pins),
             "actual_build_identity_sha256": args.build_asset_sha256, "actual_build_identity_asset": ASSET,
             "actual_build_source_input_count": len(inputs), "build_receipt_sha256": args.build_receipt_sha256,
             "static_acceptance_sha256": args.static_acceptance_sha256, "apk_sha256": args.apk_sha256,
             "apk_bytes": len(apk_raw), "apk_stat": list(apk_stat), "compiled_artifacts": artifacts,
             "actual_complete_source_files_verified": True, "actual_signed_apk_payload_verified": True,
             "host_signature_independently_verified": False, "phone_contacted": False}
    proof.update(host_checks_sha256=args.host_checks_sha256,
                 host_gate_qualification_sha256=args.host_gate_qualification_sha256, applicable_host_gate=gate)
    return modules, pins, proof


def recheck_bundle(args, pins, proof):
    verify_source_files(args.source, pins)
    for path, digest in ((args.source_inventory, args.source_inventory_sha256),
                         (args.build_receipt, args.build_receipt_sha256),
                         (args.static_acceptance, args.static_acceptance_sha256)):
        bound_json(path, digest)
    verify_host_gate(args)
    raw, current = regular(args.apk)
    need(sha(raw) == args.apk_sha256 and list(current) == proof["apk_stat"], "signed APK changed before mutation")


def verify_signature(apk, expected_sha, signer, output, label):
    raw, before = regular(apk)
    need(sha(raw) == expected_sha, "host APK SHA differs before signature verification")
    signer = Path(signer).expanduser()
    need(signer.is_absolute() and signer.is_file() and os.access(signer, os.X_OK), "absolute host apksigner required")
    argv = [str(signer), "verify", "--verbose", "--print-certs", str(apk)]
    result = subprocess.run(argv, capture_output=True, timeout=30, check=False)
    write_new(output / (label + ".stdout.txt"), result.stdout)
    write_new(output / (label + ".stderr.txt"), result.stderr)
    write_new(output / (label + ".command.json"), encoded({"argv": argv, "exit_code": result.returncode}))
    signers = re.findall(rb"(?m)^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-f]{64})\r?$", result.stdout)
    one = re.findall(rb"(?m)^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})\r?$", result.stdout)
    need(result.returncode == 0 and signers == one == [CERT_SHA.encode()], "exact original single signer not verified")
    need(stat_key(apk.stat()) == before, "host APK changed during signature verification")
    return {"path": str(apk), "sha256": expected_sha, "bytes": len(raw), "stat": list(before),
            "certificate_sha256": CERT_SHA, "signature_verified": True}


def add_arguments(parser):
    for name in ("source", "source-inventory", "build-receipt", "static-acceptance", "build-output", "apk", "host-checks", "host-gate-qualification"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-inventory-sha256", "build-receipt-sha256", "static-acceptance-sha256", "apk-sha256", "build-asset-sha256", "host-checks-sha256", "host-gate-qualification-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--aapt2", required=True)
    parser.add_argument("--apksigner", required=True)


def report_fields(proof):
    return {key: proof[key] for key in ("source_commit", "source_tree", "complete_source_inventory_sha256",
        "portable_source_inventory_sha256", "actual_build_identity_sha256", "actual_build_identity_asset",
        "build_receipt_sha256", "static_acceptance_sha256", "host_checks_sha256", "host_gate_qualification_sha256")}


# Static name derivation from reviewed gate_plan.py SHA256 fb23147cb06244e06537cc651602c1f53613258654dafb1617a0389d16bbe395
"""Static plan of reviewed run_host_checks loops; no imported source execution."""
import ast
from pathlib import PurePosixPath


def _derive_host_names(source,paths):
    tree=ast.parse(source);main=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main']
    if len(main)!=1:raise ValueError('host main missing/duplicate')
    main=main[0];paths=set(paths)
    selected=[n for n in main.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='tests' for t in n.targets)]
    expected=ast.parse("sorted((ROOT/'tests').glob('*HostTest.java'))+[ROOT/'tests/action-parser/ActionDecisionHostTest.java',ROOT/'tests/action-grammar/DecisionGrammarHostTest.java']",mode='eval').body
    if len(selected)!=1 or ast.dump(selected[0].value)!=ast.dump(expected):raise ValueError('host test-selector shape changed; explicit review required')
    tests=sorted(p for p in paths if str(PurePosixPath(p).parent)=='tests' and PurePosixPath(p).name.endswith('HostTest.java'))
    tests+=['tests/action-parser/ActionDecisionHostTest.java','tests/action-grammar/DecisionGrammarHostTest.java']
    if any(p not in paths for p in tests):raise ValueError('host test missing from full inventory')
    native=sorted(p for p in paths if str(PurePosixPath(p).parent)=='native/tests' and PurePosixPath(p).suffix=='.c')
    native_iter=ast.parse("sorted((ROOT/'native/tests').glob('*.c'))",mode='eval').body
    def calls(n):return any(isinstance(x,ast.Call) and isinstance(x.func,ast.Name) and x.func.id=='run' for x in ast.walk(n))
    def value(n,env):
        if isinstance(n,ast.Constant) and isinstance(n.value,str):return n.value
        if isinstance(n,ast.Name) and n.id in env:return env[n.id]
        if isinstance(n,ast.Attribute) and n.attr=='stem' and isinstance(n.value,ast.Name):return PurePosixPath(env[n.value.id]).stem
        if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add):return value(n.left,env)+value(n.right,env)
        raise ValueError('unreviewed dynamic host check name')
    def block(nodes,env):
        result=[]
        for n in nodes:
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) or not calls(n):continue
            if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='run':
                result.append(value(n.value.args[0],env))
            elif isinstance(n,ast.Try):
                if any(calls(x) for x in n.handlers+n.finalbody+n.orelse):raise ValueError('unreviewed recovery/finally host check')
                result+=block(n.body,env)
            elif isinstance(n,ast.For) and isinstance(n.target,ast.Name) and not n.orelse:
                if n.target.id=='test' and isinstance(n.iter,ast.Name) and n.iter.id=='tests':items=tests
                elif n.target.id=='source' and ast.dump(n.iter)==ast.dump(native_iter):items=native
                else:raise ValueError('unreviewed host check loop')
                for item in items:result+=block(n.body,dict(env,**{n.target.id:item,'name':PurePosixPath(item).stem}))
            elif isinstance(n,ast.If):
                condition=ast.parse("source.stem=='sha256_probe'",mode='eval').body
                if ast.dump(n.test)!=ast.dump(condition) or 'source' not in env:raise ValueError('unreviewed conditional host check')
                result+=block(n.body if PurePosixPath(env['source']).stem=='sha256_probe' else n.orelse,env)
            else:raise ValueError('unreviewed host run invocation shape')
        return result
    names=block(main.body,{})
    if not names or len(names)!=len(set(names)):raise ValueError('host checks empty/duplicate')
    return names


# Appended unchanged to the version-bound identity module by prepare_helpers.py.
# Linux cooperative advisory exclusion, not a device-wide or adversarial lock.
import contextlib
import errno
import fcntl
import functools

OPERATION_LOCK_PATH = "/home/alex/.local/state/hepta/razr-operation.lock"
_ACTIVE_OPERATION_LOCK = None


def _operation_file_key(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink)


def _operation_path_info(path):
    need(path.is_absolute() and all(not item.is_symlink() for item in (path, *path.parents)),
         "operation lock requires its existing absolute non-symlink path")
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
         and info.st_nlink == 1 and not info.st_mode & 0o022,
         "operation lock must be an existing owned regular single-link file, not writable by others")
    return info


class _OperationLockLease:
    def __init__(self, path, fd, record):
        self.path, self.fd, self.record = path, fd, record
        self.identity = _operation_file_key(os.fstat(fd))
        self.acquired = False

    def check(self, label):
        try:
            need(self.acquired, "operation lock was not acquired")
            path_info = _operation_path_info(self.path)
            held = os.fstat(self.fd)
            need(_operation_file_key(path_info) == _operation_file_key(held) == self.identity,
                 "operation lock pathname or held file identity changed")
        except Exception as error:
            self.record.update(continuity_verified=False, last_check=label,
                               last_check_error=type(error).__name__ + ": " + str(error))
            raise
        self.record["continuity_checks"] += 1
        self.record["last_check"] = label
        self.record["continuity_verified"] = True


def require_operation_lock(label="before_phone_command"):
    lease = _ACTIVE_OPERATION_LOCK
    need(lease is not None, "phone operation requires the active helper operation lock")
    lease.check(label)
    return lease


def guard_adb(adb):
    """Keep the original command signature/result/error; add only a lock check.

    The existing app_bytes method calls this same instance's command method.
    No command, retry, lock reacquisition or replacement is introduced.
    """
    lease = require_operation_lock("guard_adb")
    need(not getattr(adb, "_hepta_operation_lock_guarded", False), "ADB command already wrapped")
    command = adb.command

    @functools.wraps(command)
    def guarded(*args, **kwargs):
        need(_ACTIVE_OPERATION_LOCK is lease, "ADB command escaped its original operation-lock lifetime")
        lease.check("adb.command")
        return command(*args, **kwargs)

    adb.command = guarded
    adb._hepta_operation_lock_guarded = True
    return adb


@contextlib.contextmanager
def operation_lock(report):
    """Hold the existing fixed lock for the entire execute call, never wait/retry.

    Every guarded ADB call checks the still-held fd and pathname identity; the
    direct upgrade install subprocess has an additional explicit check. A command
    already submitted cannot be revoked if another process ignores this lock.
    """
    global _ACTIVE_OPERATION_LOCK
    need(_ACTIVE_OPERATION_LOCK is None, "nested operation lock is refused")
    need(isinstance(report, dict), "mutable operation report required")
    record = {"schema": "hepta.cooperative-operation-lock.v1", "path": OPERATION_LOCK_PATH,
              "cooperative_advisory_only": True, "nonblocking": True,
              "created": False, "truncated": False, "reacquisition_attempted": False,
              "acquired": False, "released": False, "continuity_verified": False,
              "continuity_checks": 0,
              "boundary": "participating host processes only; already submitted commands cannot be revoked"}
    report["operation_lock"] = record
    path = Path(OPERATION_LOCK_PATH)
    fd, lease, body_error = None, None, None
    try:
        before = _operation_path_info(path)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        need(_operation_file_key(os.fstat(fd)) == _operation_file_key(before),
             "operation lock changed while opening")
        lease = _OperationLockLease(path, fd, record)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                record["held_by_another_operator"] = True
                raise RuntimeError("operation lock is held by another operator; no phone contact") from error
            raise
        lease.acquired = True
        record.update(acquired=True, held_device=lease.identity[0], held_inode=lease.identity[1], owner_uid=lease.identity[2])
        _ACTIVE_OPERATION_LOCK = lease
        lease.check("acquired_before_execute")
        yield lease
    except BaseException as error:
        body_error = error
        raise
    finally:
        exit_error = None
        if lease is not None and lease.acquired:
            try:
                lease.check("execute_exit")
            except Exception as error:
                exit_error = error
        # Clear only this context's reference; never close or unlock somebody else's fd.
        if _ACTIVE_OPERATION_LOCK is lease:
            _ACTIVE_OPERATION_LOCK = None
        if fd is not None:
            try:
                if lease is not None and lease.acquired:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError as error:
                record["release_error"] = type(error).__name__ + ": " + str(error)
                if exit_error is None:
                    exit_error = error
            finally:
                try:
                    os.close(fd)
                    if lease is not None and lease.acquired:
                        record["released"] = True
                except OSError as error:
                    record["close_error"] = type(error).__name__ + ": " + str(error)
                    if exit_error is None:
                        exit_error = error
        if body_error is None and exit_error is not None:
            raise exit_error

