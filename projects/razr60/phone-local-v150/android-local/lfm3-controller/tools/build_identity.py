"""Bind cached Android outputs to the exact current source used to build them."""
import hashlib
import json
import os
import re
import stat
from pathlib import Path
import xml.etree.ElementTree as ET


def selected_variant(environ):
    variant = environ.get("HEPTA_BUILD_VARIANT", "release")
    if variant not in ("release", "diagnostic"):
        raise RuntimeError("HEPTA_BUILD_VARIANT must be release or diagnostic")
    return variant


def build_configuration(root, variant):
    if variant not in ("release", "diagnostic"):
        raise RuntimeError("Unknown Android build variant")
    manifest = (Path(root) / "AndroidManifest.xml").read_bytes()
    return _configuration(manifest, variant)


def _configuration(manifest, variant):
    try:
        applications = ET.fromstring(manifest).findall("application")
    except ET.ParseError as error:
        raise RuntimeError("Invalid source Android manifest") from error
    if (len(applications) != 1 or
            applications[0].get("{http://schemas.android.com/apk/res/android}debuggable") != "false"):
        raise RuntimeError("Source manifest must explicitly disable application debugging")
    return {"variant": variant, "debuggable": variant == "diagnostic",
            "manifest_source_sha256": hashlib.sha256(manifest).hexdigest(),
            "aapt2_link_flags": ["--debug-mode"] if variant == "diagnostic" else []}


def verified_build_configuration(root, receipt, manifest=None):
    value = receipt.get("build_configuration")
    if (type(value) is not dict or set(value) != {
            "variant", "debuggable", "manifest_source_sha256", "aapt2_link_flags"} or
            value.get("variant") not in ("release", "diagnostic") or
            type(value.get("debuggable")) is not bool or
            type(value.get("aapt2_link_flags")) is not list):
        raise RuntimeError("Current compiler receipt requires an explicit build configuration")
    expected = (_configuration(manifest, value["variant"]) if manifest is not None else
                build_configuration(root, value["variant"]))
    if value != expected:
        raise RuntimeError("Compiler build configuration differs from its exact source and variant")
    return expected


def claim_build_output(root, variant, environ):
    """Use one explicitly marked directory per flavor, including transported outputs."""
    if variant not in ("release", "diagnostic"):
        raise RuntimeError("Unknown Android build variant")
    default = Path(root) / ("out" if variant == "release" else "out-diagnostic")
    out = Path(environ.get("HEPTA_BUILD_OUT", str(default))).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    marker = out / "build-variant.json"
    data = (json.dumps({"schema": "hepta.android-build-variant.v1", "variant": variant},
                       sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if not marker.exists() and not marker.is_symlink():
        if any(out.iterdir()):
            raise RuntimeError("Unmarked build output must be a new empty directory")
        with marker.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != len(data):
            raise RuntimeError("Invalid build output variant marker")
        actual = stream.read(len(data) + 1)
    if actual != data:
        raise RuntimeError("Build output directory belongs to a different variant")
    return out, {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def compiled_debuggable(manifest_dump):
    """Require the sole application node's explicit typed AAPT2 boolean attribute."""
    applications = []
    values = []
    active = None
    for line in manifest_dump.splitlines():
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if stripped.startswith("E:"):
            if active is not None and indent <= active:
                active = None
            if re.fullmatch(r"E: application(?: \(line=\d+\))?", stripped):
                applications.append(indent)
                active = indent
            elif active is not None:
                active = None  # Attributes of a child are never application attributes.
        if "android:debuggable" in stripped:
            # The pinned Linux AAPT2 uses typed PrettyPrint (unquoted true/false);
            # SDK AAPT2 also has the explicit TYPE_INT_BOOLEAN hexadecimal form.
            match = re.fullmatch(r"A: (?:android|http://schemas\.android\.com/apk/res/android):debuggable\(0x0101000f\)=(true|false|\(type 0x12\)0x0|\(type 0x12\)0xffffffff)", stripped)
            if match is None or active is None or indent != active + 2:
                raise RuntimeError("Malformed or non-application compiled debugging attribute")
            values.append(match.group(1) in ("true", "(type 0x12)0xffffffff"))
    if len(applications) != 1 or len(values) != 1:
        raise RuntimeError("Actual APK must have exactly one typed application debugging attribute")
    return values[0]


def source_inputs(root):
    root = Path(root)
    paths = {root / "AndroidManifest.xml", root / "build_mac.py", root / "assemble_pocket4.py",
             root / "tools/build_identity.py", root / "tools/verify_runtime.py", root / "tools/fetch_pinned_runtime.py",root / "tools/model_profiles.py",
             root / "tools/verify_mobimind_runtime.py", root / "tools/verify_ui_venus_runtime.py", root / "provenance/mobimind-worker-r4-build.json",
             root / "provenance/mobimind-worker-r4/SOURCE-MANIFEST.json"}
    paths.update((root / "src").rglob("*.java"))
    paths.update((root / "res").rglob("*.xml"))
    for extension in ("*.c", "*.cpp", "*.h", "*.inc", "*.py", "*.json"):
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
    verified_build_configuration(root, receipt)


def actual_build_identity(root, receipt):
    """Deterministic asset; verify actual compiler inputs first, then bind their full map.

    The generated asset is not a source input. The root historical SOURCE-MANIFEST
    is not read. Explicit subordinate provenance files in source_inputs remain
    ordinary hashed build inputs; they do not identify the current Java source.
    """
    root = Path(root)
    inputs = source_inputs(root)
    if receipt.get("source_inputs") != inputs:
        raise RuntimeError("Actual build identity requires the exact compiler source inputs")
    manifest = (root / "AndroidManifest.xml").read_bytes()
    expected_manifest = next(row["sha256"] for row in inputs if row["path"] == "AndroidManifest.xml")
    if hashlib.sha256(manifest).hexdigest() != expected_manifest:
        raise RuntimeError("Manifest changed while binding build identity")
    configuration = verified_build_configuration(root, receipt, manifest)
    version = ET.fromstring(manifest).get(
        "{http://schemas.android.com/apk/res/android}versionCode")
    if not version or not version.isdecimal() or int(version) < 1:
        raise RuntimeError("Actual manifest version required for build identity")
    payload = {"schema": "hepta.actual-build-inputs.v1", "version_code": int(version),
               "source_inputs": inputs, "build_configuration": configuration}
    return (json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
