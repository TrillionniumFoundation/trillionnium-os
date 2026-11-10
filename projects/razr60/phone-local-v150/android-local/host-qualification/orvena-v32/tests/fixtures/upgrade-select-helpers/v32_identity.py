"""Host-only binding of the published v32 source, compiler outputs and signed APK.

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

COMMIT = "e07c6624b7309b0acf3fe10e31b0605a29e3e72d"
TREE = "81955c2053ba24cab0783c9cb7636a49c0f186de"
PORTABLE_SHA = "b9c1355c16658c354550aad818053e9e5d8bb12ce7150d7b861de109a1000b90"
FILE_COUNT = 1194
INPUT_COUNT = 163
PACKAGE = "org.trillionnium.hepta.local"
VERSION_CODE = 32
VERSION_NAME = "0.32.0-local-scoped-tools"
CERT_SHA = "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
ASSET = "assets/hepta-build-identity.json"
SDK_COMMIT = "071f609995470bdb0e0769ab964754adfaab7e47"
LLAMA_COMMIT = "19cce6919992fdffd92e0ac152caaf1e2b8f254e"
HEX = re.compile(r"[0-9a-f]{64}\Z")
HELPERS = ("warm_receipts", "model_profiles", "phone_acceptance", "phone_inventory")


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
    need(inventory.get("schema") == "hepta.independent-v32-source-integration.v1"
         and inventory.get("source_commit") == COMMIT and inventory.get("source_tree") == TREE
         and inventory.get("actual_source_assembly_verified") is True
         and type(inventory.get("file_count")) is int and inventory["file_count"] == FILE_COUNT,
         "actual complete published v32 inventory required")
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
         "inventory does not match the published final-r2 content")
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
    tests = sorted((source / "tests").glob("*HostTest.java")) + [
        source / "tests/action-parser/ActionDecisionHostTest.java",
        source / "tests/action-grammar/DecisionGrammarHostTest.java"]
    names = ["java-compile"] + [path.stem for path in tests] + [
        "grammar-recognition", "app-label-grammar-recognition", "scroll-grammar-recognition", "completion-protocol",
        "same-state-no-effect-grammar", "qualification-scope", "python-tools", "mobimind-private-staging", "ui-venus-q4_0-provenance"]
    for path in sorted((source / "native/tests").glob("*.c")):
        names += [path.stem + "-compile", path.stem]
        if path.stem == "sha256_probe":
            names.append("sha256-hashlib-differential")
    names += ["native-adapter-syntax", "private-prompt-evidence", "task-worker-native-lifecycle", "profile-sampler"]
    need(len(names) == len(set(names)), "ambiguous host gate check names")
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
    need(qualification.get("schema") == "hepta.v32-applicable-host-gates.v1"
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
            need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+[.]so", name) and name not in names,
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
    build = bound_json(args.build_receipt, args.build_receipt_sha256)
    need(build.get("schema") == "hepta.local-model.mac-build.v2" and build.get("source_head_from_ci") == COMMIT
         and build.get("runtime") == "llama_cpp" and type(build.get("java_target")) is int and build["java_target"] == 8
         and build.get("geniex_source_commit") == SDK_COMMIT and build.get("llama_source_commit") == LLAMA_COMMIT,
         "actual v32 compiler receipt identity differs")
    sys.dont_write_bytecode = True
    identity = isolated_module("verified_v32_build_identity", source / "tools/build_identity.py")
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
