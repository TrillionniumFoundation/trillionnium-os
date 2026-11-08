#!/usr/bin/env python3
"""Build only the pinned text converter. No model/inference runtime is linked."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent
OLD = '            fprintf(stderr, "WARNING: JSON schema conversion was incomplete: %s\\n", string_join(_warnings, "; ").c_str());'
NEW = '            throw std::invalid_argument("JSON schema conversion was incomplete: " + string_join(_warnings, "; "));'
SCALAR_RULE = r'[^"\\\x7F\x00-\x1F\uD800-\uDFFF] | [\\] (["\\bfnrt] | "u" ([0-9a-cA-Ce-fE-F] [0-9a-fA-F]{3} | [dD] [0-7] [0-9a-fA-F]{2}))'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--cxx", default="c++")
    ap.add_argument("--android", action="store_true")
    ap.add_argument("--static", action="store_true", help="Fully static executable for direct GNUroot/Android execution")
    args = ap.parse_args()
    pins = json.loads((ROOT / "SOURCE-PINS.json").read_bytes())
    for row in pins["upstream"]:
        raw = (ROOT / row["path"]).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if blob != row["git_blob_sha1"] or sha(raw) != row["sha256"]:
            raise SystemExit("pinned source differs: " + row["path"])
    if sha((ROOT / "support.cpp").read_bytes()) != pins["helpers"]["file_sha256"]:
        raise SystemExit("extracted helper bytes differ")
    source = (ROOT / "upstream/json-schema-to-grammar.cpp").read_text()
    if source.count(OLD) != 1:
        raise SystemExit("warning failure patch does not apply exactly once")
    patched = source.replace(OLD, NEW)
    expected_patch = "".join(difflib.unified_diff(source.splitlines(True), patched.splitlines(True),
        fromfile="a/common/json-schema-to-grammar.cpp", tofile="b/common/json-schema-to-grammar.cpp"))
    if expected_patch.encode() != (ROOT / "fail-closed-warnings.patch").read_bytes():
        raise SystemExit("reviewed warning patch differs")
    char_lines = [line for line in source.splitlines() if line.startswith('    {"char",')]
    if len(char_lines) != 1:
        raise SystemExit("Unicode scalar patch does not apply exactly once")
    char_line = '    {"char", {R"gbnf(' + SCALAR_RULE + ')gbnf", {}}},'
    unicode_patched = source.replace(char_lines[0], char_line)
    unicode_patch = "".join(difflib.unified_diff(source.splitlines(True), unicode_patched.splitlines(True),
        fromfile="a/common/json-schema-to-grammar.cpp", tofile="b/common/json-schema-to-grammar.cpp"))
    if unicode_patch.encode() != (ROOT / "scalar-string.patch").read_bytes():
        raise SystemExit("reviewed Unicode scalar patch differs")
    patched = patched.replace(char_lines[0], char_line)
    args.out = args.out.resolve()
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    generated = args.out / "json-schema-to-grammar.cpp"
    generated.write_text(patched)
    executable = args.out / "hepta-schema-gbnf"
    command = [args.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
               "-I" + str(ROOT / "upstream"), "-I" + str(ROOT / "compat"),
               str(ROOT / "converter.cpp"), str(ROOT / "support.cpp"), str(generated)]
    command += [str(ROOT / "upstream" / (name + ".cpp"))
                for name in ("json-schema", "json", "trie", "unicode")]
    if args.android:
        command += ["-static-libstdc++"]
    if args.static:
        command += ["-static"]
    command += ["-o", str(executable)]
    started = time.monotonic()
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    elapsed = time.monotonic() - started
    (args.out / "compiler.stdout").write_bytes(completed.stdout)
    (args.out / "compiler.stderr").write_bytes(completed.stderr)
    record = {"schema": "hepta.standalone-schema-converter-build.v1",
        "status": "HOST_OR_ANDROID_BUILD_ONLY_NOT_PHONE_VALIDATED" if completed.returncode == 0 else "BUILD_FAILED",
        "returncode": completed.returncode, "elapsed_seconds": elapsed, "command": command,
        "source_pins_sha256": sha((ROOT / "SOURCE-PINS.json").read_bytes()),
        "warning_patch_sha256": sha(expected_patch.encode()),
        "unicode_scalar_patch_sha256": sha(unicode_patch.encode()),
        "patched_converter_sha256": sha(patched.encode()), "model_loaded": False,
        "links_model_or_npu_runtime": False, "android_target": args.android,
        "fully_static_requested": args.static,
        "compiler_stdout_sha256": sha(completed.stdout), "compiler_stderr_sha256": sha(completed.stderr),
        "files": {str(path.relative_to(ROOT)): sha(path.read_bytes())
                  for path in [ROOT / "converter.cpp", ROOT / "support.cpp",
                               ROOT / "compat/common.h", ROOT / "compat/ggml.h"]}}
    if completed.returncode == 0:
        record["executable"] = str(executable)
        record["executable_bytes"] = executable.stat().st_size
        record["executable_sha256"] = sha(executable.read_bytes())
    (args.out / "BUILD-MANIFEST.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))
    raise SystemExit(completed.returncode)

if __name__ == "__main__":
    main()
