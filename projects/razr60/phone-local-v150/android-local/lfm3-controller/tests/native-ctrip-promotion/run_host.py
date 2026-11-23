"""Run the original Ctrip promotion AX and managed-session regression on a host."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--json-jar", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    out.mkdir(exist_ok=False, parents=True)
    spec = importlib.util.spec_from_file_location("native_closure", root / "tests/native-search-planning/host_closure.py")
    closure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(closure)
    if hashlib.sha256(args.json_jar.read_bytes()).hexdigest() != closure.JSON_SHA:
        raise RuntimeError("Pinned org.json JAR required")
    provider = root / "tests/native-app-provider"
    sources = [provider / (name + ".java") for name in (
        "NativeAppProviderHostTest", "NativeCtripLoginLoadingHostTest", "NativeCtripLoginExitHostTest",
        "NativeCtripDateReservationHostTest")]
    sources += [root / "tests/native-app-fixtures/NativeXmlFixture.java",
                root / "src/org/trillionnium/hepta/local/NativeCtripFormObservation.java",
                Path(__file__).with_name("NativeCtripPromotionHostTest.java")]
    sources, _ = closure.prepare(root, out / "closure", sources)
    classes = out / "classes"
    classes.mkdir()
    java = args.java_home / "bin"
    subprocess.run([java / "javac", "--release", "8", "-encoding", "UTF-8", "-proc:none", "-d", classes,
                    "-classpath", args.json_jar, *dict.fromkeys(sources)], check=True)
    subprocess.run([java / "java", "-classpath", str(classes) + os.pathsep + str(args.json_jar),
                    "org.trillionnium.hepta.local.NativeCtripPromotionHostTest", provider / "fixtures"], check=True)


if __name__ == "__main__":
    main()
