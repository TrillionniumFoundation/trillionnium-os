"""Bind cached Android outputs to the exact current source used to build them."""
import hashlib
from pathlib import Path


def source_inputs(root):
    root = Path(root)
    paths = {root / "AndroidManifest.xml", root / "build_mac.py", root / "assemble_pocket4.py",
             root / "tools/build_identity.py", root / "tools/verify_runtime.py", root / "tools/fetch_pinned_runtime.py"}
    paths.update((root / "src").rglob("*.java"))
    paths.update((root / "res").rglob("*.xml"))
    for extension in ("*.c", "*.h", "*.inc", "*.py"):
        paths.update((root / "native").rglob(extension))
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise RuntimeError("Build inputs must be existing regular source files")
    return [{"path": str(p.relative_to(root)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in sorted(paths)]


def verify_source_inputs(root, receipt):
    if receipt.get("source_inputs") != source_inputs(root):
        raise RuntimeError("Cached Android outputs were not built from the current exact source; rebuild before assembly")
