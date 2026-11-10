"""Bind cached Android outputs to the exact current source used to build them."""
import hashlib
from pathlib import Path


def source_inputs(root):
    root = Path(root)
    paths = {root / "AndroidManifest.xml", root / "build_mac.py", root / "assemble_pocket4.py",
             root / "tools/build_identity.py", root / "tools/verify_runtime.py", root / "tools/fetch_pinned_runtime.py",root / "tools/model_profiles.py",
             root / "tools/verify_mobimind_runtime.py", root / "tools/verify_ui_venus_runtime.py", root / "provenance/mobimind-worker-r4-build.json",
             root / "provenance/mobimind-worker-r4/SOURCE-MANIFEST.json"}
    paths.update((root / "src").rglob("*.java"))
    paths.update((root / "res").rglob("*.xml"))
    for extension in ("*.c", "*.h", "*.inc", "*.py", "*.json"):
        paths.update((root / "native").rglob(extension))
    for extension in ("*.c", "*.h", "*.inc", "*.py", "*.json", "*.txt", "*.jinja"):
        paths.update((root / "provenance/ui-venus-app-r1").rglob(extension))
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise RuntimeError("Build inputs must be existing regular source files")
    return [{"path": str(p.relative_to(root)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in sorted(paths)]


def verify_source_inputs(root, receipt):
    if receipt.get("source_inputs") != source_inputs(root):
        raise RuntimeError("Cached Android outputs were not built from the current exact source; rebuild before assembly")


def actual_build_identity(root, receipt):
    """Deterministic asset; verify actual compiler inputs first, then bind their full map.

    The generated asset is not a source input. The root historical SOURCE-MANIFEST
    is not read. Explicit subordinate provenance files in source_inputs remain
    ordinary hashed build inputs; they do not identify the current Java source.
    """
    import json
    import xml.etree.ElementTree as ET
    root = Path(root)
    inputs = source_inputs(root)
    if receipt.get("source_inputs") != inputs:
        raise RuntimeError("Actual build identity requires the exact compiler source inputs")
    manifest = (root / "AndroidManifest.xml").read_bytes()
    expected_manifest = next(row["sha256"] for row in inputs if row["path"] == "AndroidManifest.xml")
    if hashlib.sha256(manifest).hexdigest() != expected_manifest:
        raise RuntimeError("Manifest changed while binding build identity")
    version = ET.fromstring(manifest).get(
        "{http://schemas.android.com/apk/res/android}versionCode")
    if not version or not version.isdecimal() or int(version) < 1:
        raise RuntimeError("Actual manifest version required for build identity")
    payload = {"schema": "hepta.actual-build-inputs.v1", "version_code": int(version),
               "source_inputs": inputs}
    return (json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
