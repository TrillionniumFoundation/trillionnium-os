#!/usr/bin/env python3
"""Run a captured Unicode/screenshot builder with explicit SDK/JDK locations.

Only the SDK and JDK Path assignments are substituted in the in-memory AST.
The captured script, application source, compiler flags and packaging code are
unchanged. Output must be new. This command never contacts an Android device.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
BUILDERS = {
    "unicode-v148r2": "0ade6f3c59b75ee2c23eb14e17fde6d665b30a6a7029d8b38a69c2b76e2150a4",
    "screen-codec-v148r1": "550573eed2be2a1bd08b38a4f717c4e9b00915fedd2dd92cb1a33e44fe22869a",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=sorted(BUILDERS))
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    script = HERE / args.component / "build.py"
    original = script.read_bytes()
    if hashlib.sha256(original).hexdigest() != BUILDERS[args.component]:
        parser.error("captured builder hash changed")
    roots = {"SDK": args.sdk_root.resolve(strict=True), "JDK": args.jdk.resolve(strict=True)}
    out = args.out.resolve()
    if out.exists():
        parser.error("output must not exist")
    out.parent.mkdir(parents=True, exist_ok=True)
    tree = ast.parse(original, filename=str(script))
    replaced = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in roots:
                node.value = ast.Call(func=ast.Name(id="Path", ctx=ast.Load()),
                                      args=[ast.Constant(value=str(roots[target.id]))], keywords=[])
                replaced.append(target.id)
    if sorted(replaced) != ["JDK", "SDK"]:
        parser.error("expected exactly the SDK and JDK assignments")
    ast.fix_missing_locations(tree)
    sys.argv = [str(script), "--out", str(out)]
    exec(compile(tree, str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
    unchanged = script.read_bytes() == original
    receipt = {"schema": "razr60-relocated-dex-helper-v1", "component": args.component,
               "builder_sha256": BUILDERS[args.component], "builder_unchanged": unchanged,
               "sdk_root": str(roots["SDK"]), "jdk": str(roots["JDK"]),
               "substituted_assignments": sorted(replaced), "phone_operations": 0,
               "build_receipt": "BUILD-RECEIPT.json"}
    (out / "RELOCATION-RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if not unchanged:
        raise RuntimeError("captured builder changed during build")


if __name__ == "__main__":
    main()
