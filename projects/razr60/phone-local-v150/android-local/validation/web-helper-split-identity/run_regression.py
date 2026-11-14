#!/usr/bin/env python3
"""Run the complete production APK split-path method under explicit host IO stubs.

No Android execution, APK build, network, phone commands or metadata repair.
The test cases are independent PackageManager metadata inputs. The exact method
is extracted from the supplied production file, rather than reimplemented.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def extract_method(source):
    signature = "private static TreeMap<String,String> paths(ApplicationInfo info)throws Exception"
    if source.count(signature) != 1:
        raise ValueError("one exact production paths method required")
    start = source.index(signature)
    opening = source.index("{", start)
    depth, state, escaped = 0, "code", False
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index:index + 2]
        if state == "line":
            if char == "\n":
                state = "code"
        elif state == "block":
            if following == "*/":
                state = "code"
                index += 1
        elif state in ("string", "character"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == ('"' if state == "string" else "'"):
                state = "code"
        elif following in ("//", "/*"):
            state = "line" if following == "//" else "block"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "character"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
        index += 1
    raise ValueError("complete production method missing")


PREFIX = """import java.util.TreeMap;
import java.util.Map;

// Explicit Android PackageManager IO boundary: only fields paths() reads.
final class ApplicationInfo {
    String sourceDir;
    String[] splitSourceDirs;
    String[] splitNames;
}
// The production predicate's failure behavior; no metadata acceptance logic.
final class WebEvidenceJson {
    static void need(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}
public final class PathsProbe {
"""

SUFFIX = r"""
    private static int cases, failed;
    private static ApplicationInfo info(String base, String[] paths, String[] names) {
        ApplicationInfo value = new ApplicationInfo();
        value.sourceDir = base;
        value.splitSourceDirs = paths;
        value.splitNames = names;
        return value;
    }
    private static TreeMap<String,String> expected(String[] paths, String[] names) {
        TreeMap<String,String> value = new TreeMap<String,String>();
        value.put("base", "/data/app/base.apk");
        for (int index = 0; paths != null && index < paths.length; index++) {
            value.put("split:" + names[index], paths[index]);
        }
        return value;
    }
    private static void positive(String name, ApplicationInfo value, Map<String,String> wanted) {
        cases++;
        try {
            TreeMap<String,String> actual = paths(value);
            if (!actual.equals(wanted)) throw new AssertionError("mapping differs");
            System.out.println("PASS " + name);
        } catch (Exception | AssertionError error) {
            failed++;
            System.out.println("FAIL " + name + " " + error.getClass().getSimpleName() + ": " + error.getMessage());
        }
    }
    private static void negative(String name, ApplicationInfo value) {
        cases++;
        try {
            paths(value);
            failed++;
            System.out.println("FAIL " + name + " metadata unexpectedly accepted");
        } catch (IllegalArgumentException expected) {
            System.out.println("PASS " + name);
        } catch (Exception unexpected) {
            failed++;
            System.out.println("FAIL " + name + " unexpected " + unexpected.getClass().getSimpleName());
        }
    }
    public static void main(String[] args) {
        String base = "/data/app/base.apk";
        TreeMap<String,String> baseOnly = expected(null, null);
        positive("no_splits_null_null", info(base, null, null), baseOnly);
        positive("no_splits_null_empty", info(base, null, new String[0]), baseOnly);
        positive("no_splits_empty_null", info(base, new String[0], null), baseOnly);
        positive("no_splits_empty_empty", info(base, new String[0], new String[0]), baseOnly);
        String[] onePath = {"/data/app/split_feature.apk"};
        String[] oneName = {"feature"};
        positive("one_split_exact_mapping", info(base, onePath, oneName), expected(onePath, oneName));
        String[] manyPaths = new String[32], manyNames = new String[32];
        for (int index = 0; index < 32; index++) {
            manyPaths[index] = "/data/app/split_" + index + ".apk";
            manyNames[index] = "feature_" + index;
        }
        positive("32_splits_exact_mapping", info(base, manyPaths, manyNames), expected(manyPaths, manyNames));
        String[] orderedPaths = {"/data/app/z.apk", "/data/app/a.apk"};
        String[] orderedNames = {"z.feature", "a-Feature_0"};
        positive("unordered_split_mapping_preserved", info(base, orderedPaths, orderedNames), expected(orderedPaths, orderedNames));
        String maxName = new String(new char[120]).replace('\0', 'x');
        positive("120_character_split_name", info(base, onePath, new String[]{maxName}), expected(onePath, new String[]{maxName}));
        negative("missing_base_path", info(null, null, null));
        negative("null_paths_nonempty_names", info(base, null, oneName));
        negative("empty_paths_nonempty_names", info(base, new String[0], oneName));
        negative("nonempty_paths_null_names", info(base, onePath, null));
        negative("nonempty_paths_empty_names", info(base, onePath, new String[0]));
        negative("more_paths_than_names", info(base, new String[]{"a", "b"}, oneName));
        negative("more_names_than_paths", info(base, onePath, new String[]{"a", "b"}));
        String[] tooManyPaths = new String[33], tooManyNames = new String[33];
        for (int index = 0; index < 33; index++) {
            tooManyPaths[index] = "/data/app/split_" + index + ".apk";
            tooManyNames[index] = "feature_" + index;
        }
        negative("33_splits_refused", info(base, tooManyPaths, tooManyNames));
        negative("null_split_path", info(base, new String[]{null}, oneName));
        negative("null_split_name", info(base, onePath, new String[]{null}));
        negative("empty_split_name", info(base, onePath, new String[]{""}));
        negative("slash_split_name", info(base, onePath, new String[]{"../feature"}));
        negative("colon_split_name", info(base, onePath, new String[]{"split:feature"}));
        negative("whitespace_split_name", info(base, onePath, new String[]{"feature one"}));
        negative("unicode_split_name", info(base, onePath, new String[]{"功能"}));
        negative("121_character_split_name", info(base, onePath, new String[]{maxName + "x"}));
        negative("duplicate_split_name", info(base, new String[]{"a", "b"}, new String[]{"feature", "feature"}));
        System.out.println("COUNTS " + cases + " " + failed);
        if (failed != 0) System.exit(1);
    }
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="actual production WebHelperIdentity.java")
    parser.add_argument("--output", type=Path, required=True, help="new host-only evidence directory")
    parser.add_argument("--java", default=shutil.which("java"))
    parser.add_argument("--javac", default=shutil.which("javac"))
    parser.add_argument("--compiler-via-java", action="store_true", help="use the existing jdk.compiler module")
    parser.add_argument("--development-platform-only", action="store_true", help="explicit supplemental source/target8 check, not release8")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    raw = args.source.read_bytes()
    source = raw.decode("utf-8")
    method = extract_method(source)
    before = hashlib.sha256(raw).hexdigest()
    if not args.java or (not args.javac and not args.compiler_via_java):
        raise ValueError("existing Java compiler/runtime must be supplied")
    compiler = [args.java, "-m", "jdk.compiler/com.sun.tools.javac.Main"] if args.compiler_via_java else [args.javac]
    flags = ["-source", "8", "-target", "8", "-Xlint:-options"] if args.development_platform_only else ["--release", "8"]
    report = {"schema": "hepta.web-helper-split-identity.host.v1", "source_file": str(args.source.resolve()),
        "source_sha256": before, "source_git_blob_sha1": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
        "actual_extracted_method_sha256": hashlib.sha256(method.encode()).hexdigest(),
        "compiler_contract": "source_target8_supplemental" if args.development_platform_only else "release8_Xlint_all_Werror",
        "full_production_method_extracted": True, "android_io": "explicit ApplicationInfo field stub",
        "phone_contacted": False, "android_runtime_tested": False, "apk_built": False,
        "full_source_closure_verified": False, "tests_passed": False}
    with tempfile.TemporaryDirectory(prefix="web-helper-paths-") as temp:
        work = Path(temp)
        unit = work / "PathsProbe.java"
        unit.write_text(PREFIX + method + "\n" + SUFFIX, encoding="utf-8")
        compile_argv = compiler + flags + ["-encoding", "UTF-8", "-Xlint:all", "-Werror", "-d", str(work), str(unit)]
        compiled = subprocess.run(compile_argv, capture_output=True, timeout=60, check=False)
        (args.output / "compile.stdout").write_bytes(compiled.stdout)
        (args.output / "compile.stderr").write_bytes(compiled.stderr)
        report.update(compiler_argv=compile_argv, compiler_exit_code=compiled.returncode)
        if compiled.returncode == 0:
            executed = subprocess.run([args.java, "-cp", str(work), "PathsProbe"], capture_output=True, timeout=30, check=False)
            (args.output / "cases.stdout").write_bytes(executed.stdout)
            (args.output / "cases.stderr").write_bytes(executed.stderr)
            rows = executed.stdout.decode("utf-8").splitlines()
            counts = [line.split() for line in rows if line.startswith("COUNTS ")]
            report.update(test_exit_code=executed.returncode, case_count=int(counts[0][1]) if len(counts) == 1 else None,
                failed_cases=[line for line in rows if line.startswith("FAIL ")],
                tests_passed=executed.returncode == 0 and len(counts) == 1 and counts[0][1:] == ["25", "0"])
    report["source_unchanged_after_test"] = hashlib.sha256(args.source.read_bytes()).hexdigest() == before
    report["tests_passed"] = report["tests_passed"] and report["source_unchanged_after_test"]
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["tests_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
