#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: patch-generator.py ORIGINAL PATCHED")
    original, patched = map(Path, sys.argv[1:])
    source = original.read_text(encoding="utf-8")
    anchor = "def rust_source() -> bytes:\n"
    formatter = '''def rustfmt_bytes(raw: bytes) -> bytes:
    completed = subprocess.run(
        ["rustfmt", "--edition", "2021"],
        input=raw,
        capture_output=True,
        check=False,
        timeout=60,
    )
    require(completed.returncode == 0, f"rustfmt rejected generated source: {completed.stderr.decode('utf-8', 'replace')}")
    require(bool(completed.stdout), "rustfmt returned empty generated source")
    return completed.stdout


'''
    if formatter not in source:
        if anchor not in source:
            raise SystemExit("rust source anchor missing")
        source = source.replace(anchor, formatter + anchor, 1)
    source = source.replace("def rust_source() -> bytes:\n    return b'''", "def rust_source() -> bytes:\n    return rustfmt_bytes(b'''", 1)
    boundary = "'''\n\n\ndef rust_test_source() -> bytes:"
    if boundary not in source:
        raise SystemExit("rust source closing boundary missing")
    source = source.replace(boundary, "''')\n\n\ndef rust_test_source() -> bytes:", 1)
    source = source.replace("def rust_test_source() -> bytes:\n    return b'''", "def rust_test_source() -> bytes:\n    return rustfmt_bytes(b'''", 1)
    boundary = "'''\n\n\ndef android_verifier_source() -> bytes:"
    if boundary not in source:
        raise SystemExit("rust test closing boundary missing")
    source = source.replace(boundary, "''')\n\n\ndef android_verifier_source() -> bytes:", 1)
    source = source.replace(
        'if any(item==CATALOG_PATH for item in value) and CONTRACT_CATALOG_PATH not in value: value.append(CONTRACT_CATALOG_PATH); value.sort()',
        'if any(item==CATALOG_PATH for item in value) and CONTRACT_CATALOG_PATH not in value: value.append(CONTRACT_CATALOG_PATH)'
    ).replace(
        'if any(item=="docs/START_HERE.md" for item in value) and STATUS_PATH not in value: value.append(STATUS_PATH); value.sort()',
        'if any(item=="docs/START_HERE.md" for item in value) and STATUS_PATH not in value: value.append(STATUS_PATH)'
    )
    patched.write_text(source, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
