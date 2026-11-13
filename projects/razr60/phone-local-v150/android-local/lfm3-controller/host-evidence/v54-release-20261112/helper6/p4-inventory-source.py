#!/usr/bin/env python3
"""Bounded host-only inventory. Never builds, signs, downloads, imports apps, or uses ADB."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

CONFIG = json.loads(r'''{"schema":"hepta.helper6-pocket4-readonly-inventory-config.v1","root":"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-inventory-r1","source_path":"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-inventory-r1.py","scan_roots":["/home/alex/hepta-local-007f-20261111","/home/alex/razr-local-ai-20261109-82d1243e"],"known":[{"bytes":129146,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/BUILD-RESULT.json","sha256":"cce5d75af6af48fb00b72b96475d686b61b89538c60cbd424fd99e79c58396a8","role":"actual_helper5_input"},{"bytes":7313,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/SOURCE-INVENTORY.json","sha256":"0cb6c955bb3c816aa10ae81c063a599d7ce4c9ce4ede5c166af5e480235751dc","role":"actual_helper5_input"},{"bytes":1340480,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/helper-unsigned.apk","sha256":"fd697439cc78e14ae5428b48a4e1d8479a13f31ce1c357269c5365217aa57142","role":"actual_helper5_input"},{"bytes":128049,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/provenance/BASE-BUILD-RESULT.json","sha256":"021815261d930ce2e21de877a149a560908a74371dc08e169a1b2a116ef9fdec","role":"actual_helper5_input"},{"bytes":14006,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/provenance/BASE-CONTRACT-RESULT.json","sha256":"3f8a2ec3587789ee37fef0294cec2203bf95911eefc307b78e68105bf95f1490","role":"actual_helper5_input"},{"bytes":22167,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/provenance/BUILD.py","sha256":"dd67a66b15544e450a891cd0f5ded302faf9bf017255173777b92efaef170e26","role":"actual_helper5_input"},{"bytes":155587,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/provenance/CANDIDATE.json","sha256":"7e59fcd9dcc4d15cce60e35973151cf6320aec175e8f528217887fc4866a2056","role":"actual_helper5_input"},{"bytes":13787,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/provenance/CONTRACT-RESULT.json","sha256":"0894411f12d42722d58debbd18908867b6e58440bc43eb04a1de1cbc6a5e1a43","role":"actual_helper5_input"},{"bytes":486209,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/provenance/DEPENDENCY-RESULT.json","sha256":"08c8c0dbc5677643da0aeb202314a4c26fda76ee2904696cd18aea102715cdc0","role":"actual_helper5_input"},{"bytes":8620,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/provenance/R8-RESULT.json","sha256":"d4aa66ea4105c13ba8b6e1c2540a3aeb74d3a3f70ddcf128818d4aad08ac5eeb","role":"actual_helper5_input"},{"bytes":6574,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/provenance/RUNTIME-SELECTION.json","sha256":"33b74075c27c9b99c2bd1ea00be8e68c42464b6b41b413e6652a687497c223d1","role":"actual_helper5_input"},{"bytes":92623,"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/source.tar.gz","sha256":"efeda404b4f68d2d0fe4646d34e75c395b9995791fc6361d8244aa7ba2012824","role":"actual_helper5_input"},{"path":"/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-inputs-r1.tar.gz","bytes":1571517,"sha256":"75671c2f81e2a9f9f31ccc58ed78fe12503a955b75f05b70d7e3e7e5aae0d1a7","role":"actual_helper5_bundle"},{"path":"/home/alex/hepta-v31-nanbeige42-e59-r1/toolchains/old-jdk17-revalidation-r1/RESULT.json","bytes":null,"sha256":"349939390c8b19e8cea03e28ce6c5bc2c1d010dd06d3a435b7f1517221f0dd1c","role":"prior_jdk_revalidation_receipt"},{"path":"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/java","bytes":14544,"sha256":"bb70208200cb6538b877d80478141194a716edb591f4910ec106589291e99196","requested_path":"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/java","role":"qualified_java"},{"path":"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/javac","bytes":14592,"sha256":"2aaf03d13aeb80b8269696f2dcd9f4937d7366bbc68f91fdc703cf157e8f39c4","requested_path":"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/javac","role":"qualified_javac"}],"required_jars":[{"id":"jar-00","role":"runtime_jar","bytes":6304,"sha256":"f97daae3e5fa12312593041412661117b7d82fa70ff2a1db45bb7092f1ce19ee","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/00/classes.jar"},{"id":"jar-01","role":"runtime_jar","bytes":56126,"sha256":"9aab326d9492800991854360ac248f493ce7f7c3183519309b78ace9e240f6f6","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/01/classes.jar"},{"id":"jar-02","role":"runtime_jar","bytes":8290,"sha256":"fa5e67ffcc52a0413f4b39c2737b43c1ba6c6975b4bd4a4ea8627549e766285b","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/02/classes.jar"},{"id":"jar-03","role":"runtime_jar","bytes":11249,"sha256":"4b80b337779b526e64b0ee0ca9e0df43b808344d145f8e9b1c42a134dac57ad8","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/03/classes.jar"},{"id":"jar-04","role":"runtime_jar","bytes":41692,"sha256":"9c8d117b5c2bc120a1cdfeb857e05b495b16c36013570372a708f7827e3ac9f9","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/04/classes.jar"},{"id":"jar-05","role":"runtime_jar","bytes":675389,"sha256":"6dad2c3643d2e11e8ccf63c9af57d3e36ed4cfa5caa1930f44f4f90f2990fd50","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/05/classes.jar"},{"id":"jar-06","role":"runtime_jar","bytes":20306,"sha256":"7bad7a188804adea6fa1f35d5ef99b705f20bd93ecadde484760ff86b535fefc","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/06/classes.jar"},{"id":"jar-07","role":"runtime_jar","bytes":9055,"sha256":"14ec31f2b5f8d3eb1db1fb664035e3ee44b7f8f3fa91c072b6ccc41cd478b1df","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/07/classes.jar"},{"id":"jar-08","role":"runtime_jar","bytes":31906,"sha256":"23ab2138b5cce78bf6e93f941197ec150eba39c8ab143b1164ecbbf796157ac6","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/08/classes.jar"},{"id":"jar-09","role":"runtime_jar","bytes":229240,"sha256":"ea0593af13e18e9678c9017b1af3977011708676b8234ba28c5d3fc82c536fbf","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/09/classes.jar"},{"id":"jar-10","role":"runtime_jar","bytes":198936,"sha256":"19f102efe9629f8eabc63853ad15c533e47c47f91fca09285c5bde86e59f91d4","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/10/classes.jar"},{"id":"jar-11","role":"runtime_jar","bytes":1524620,"sha256":"e771fe74250a943e8f6346713201ff1d8cb95c3a5d1a91a22b65a9e04f6a8901","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/11/classes.jar"},{"id":"jar-12","role":"runtime_jar","bytes":17536,"sha256":"ace2a10dc8e2d5fd34925ecac03e4988b2c0f851650c94b8cef49ba1bd111478","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/12/classes.jar"},{"id":"jar-13","role":"runtime_jar","bytes":3819,"sha256":"1fad6e6be7557781e4d33729d49ae1cdc8fdda6fe477bb0cc68ce351eafdfbab","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-code3-build-r1/dependencies/13/classes.jar"},{"id":"jar-14","role":"official_r8_d8_8_13_17","bytes":18279079,"sha256":"d31fd0dc751d48740009cdd9a485126acb1d0d14c59b9f05579479940f4adf74","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-r8-official-8_13_17-r2/r8-8.13.17.jar"},{"id":"jar-15","role":"compile_sdk34","bytes":26361808,"sha256":"6cea1df3efb77103ac3e2beb9bf4718964b0e0869ab16d39d29d5cbae1c147ad","original_mac_path":"/Users/qianqi/Library/Android/sdk/platforms/android-34/android.jar"},{"id":"jar-16","role":"host_org_json_only","bytes":78332,"sha256":"3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed","original_mac_path":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-r3-dependency-closure-r2/artifacts/org.json/json/20240303/json-20240303.jar"}],"which_names":["aapt2","d8","zipalign","javac"],"direct_tools":[{"role":"prior_actual_aapt2","path":"/usr/bin/aapt2"}],"limits":{"seconds":45,"entries":240000,"depth":24,"candidates":1024,"per_file_bytes":67108864,"total_hash_bytes":536870912,"json_bytes":8388608,"receipt_urls":256},"old_mac":{"root":"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v55-web-helper-code6-build-r1","key":"007f-v55-web-helper-code6-build-r1","status":"unknown","preserved":true},"exact_helper6_candidate":{"git":"65401752c7c3bbe8cfbcf755a6cb33bf8534c9c7","bytes":733346,"sha256":"0ad3bb424013b522f8812eaa11531780ac832c6d4064191017885d387b20d49a","source_files":43,"runtime_java":41,"focused_java":55,"cases":[23,36,18]},"receipts_with_public_dependency_metadata":["/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/provenance/DEPENDENCY-RESULT.json","/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/provenance/R8-RESULT.json"],"resource_zip_expected_sha_available":false,"source_archive_handling":"hash only; no extraction, compiler, signing key or phone operation"}''')
ROOT = Path(CONFIG["root"])
LIMITS = CONFIG["limits"]
STARTED = time.monotonic()
DEADLINE = STARTED + LIMITS["seconds"]
HASHED_BYTES = 0
TRACKED = {}
CACHE = {}
SEEN_URLS = set()
SCAN = {"entries": 0, "directories": 0, "candidates": 0, "symlinks_skipped": 0,
        "special_files_skipped": 0, "excluded_git_directories": 0, "errors": [],
        "complete": True}
RESULT = {"schema": "hepta.helper6-pocket4-readonly-inventory.v1",
          "started_epoch": time.time(), "completed": False, "inventory_complete": False,
          "known": [], "tool_locations": [], "discovered": [], "required_jars": [],
          "receipt_url_observations": [], "scan": SCAN, "error": None,
          "phone_contacted": False, "adb_executed": False, "build_executed": False,
          "signed": False, "downloaded": False, "production_imported": False,
          "ready_for_build": False, "mac_operation": CONFIG["old_mac"],
          "candidate": CONFIG["exact_helper6_candidate"],
          "scope": {
              "roots": CONFIG["scan_roots"],
              "filenames": ["*.jar", "compiled-res.zip"],
              "regular_files_only": True, "follow_scan_symlinks": False,
              "skip_directory_basename": ".git",
              "hashes_are_file_availability_not_execution_proof": True,
              "current_full_jdk_tree_revalidated": False,
              "official_urls_not_inferred_or_fetched": True,
              "originals_check": "stable descriptor while reading plus final path identity",
              "limits": LIMITS}}

class InventoryLimit(Exception):
    pass

def tick():
    if time.monotonic() >= DEADLINE:
        raise InventoryLimit("fixed inventory deadline reached")

def ident(s):
    return {k: getattr(s, k) for k in
            ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
             "st_size", "st_mtime_ns", "st_ctime_ns")}

def stable_read(path, keep=False, maximum=None):
    global HASHED_BYTES
    tick()
    p = Path(path)
    if not p.is_absolute() or str(p.resolve(strict=True)) != str(p):
        raise ValueError("file path is not an absolute non-symlink path")
    before = os.lstat(str(p))
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("not a regular file")
    maximum = LIMITS["per_file_bytes"] if maximum is None else maximum
    if before.st_size > maximum:
        raise ValueError("file exceeds configured size limit")
    old = CACHE.get(str(p))
    if old is not None and old[0]["identity"] == ident(before) and (not keep or old[1] is not None):
        return old
    if HASHED_BYTES + before.st_size > LIMITS["total_hash_bytes"]:
        raise InventoryLimit("total hash byte budget reached")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(str(p), flags)
    try:
        opened = os.fstat(fd)
        if ident(opened) != ident(before):
            raise ValueError("path changed before descriptor read")
        digest = hashlib.sha256()
        chunks = [] if keep else None
        count, first = 0, b""
        while True:
            tick()
            part = os.read(fd, 131072)
            if not part:
                break
            count += len(part)
            HASHED_BYTES += len(part)
            if count > maximum or HASHED_BYTES > LIMITS["total_hash_bytes"]:
                raise InventoryLimit("read byte budget reached")
            if not first:
                first = part[:8]
            digest.update(part)
            if chunks is not None:
                chunks.append(part)
        after = os.fstat(fd)
        last = os.lstat(str(p))
        if count != before.st_size or ident(before) != ident(after) or ident(after) != ident(last):
            raise ValueError("file changed across read")
        if str(p.resolve(strict=True)) != str(p):
            raise ValueError("path changed to symlink across read")
        row = {"path": str(p), "bytes": count, "sha256": digest.hexdigest(),
               "identity": ident(after), "prefix_hex": first.hex(), "status": "read"}
        raw = b"".join(chunks) if chunks is not None else None
        TRACKED[str(p)] = ident(after)
        CACHE[str(p)] = (row, raw)
        return row, raw
    finally:
        os.close(fd)

def observation(path, keep=False, maximum=None):
    try:
        row, raw = stable_read(path, keep, maximum)
        return dict(row), raw
    except InventoryLimit:
        raise
    except Exception as exc:
        return {"path": str(path), "status": "unavailable",
                "error": type(exc).__name__ + ": " + str(exc)}, None

def receipt_urls(value, path="", depth=0):
    tick()
    if depth > 32:
        raise ValueError("receipt metadata depth budget reached")
    if isinstance(value, str):
        if value.startswith(("https://", "http://")) and len(value) <= 4096 and value not in SEEN_URLS:
            SEEN_URLS.add(value)
            if len(RESULT["receipt_url_observations"]) >= LIMITS["receipt_urls"]:
                RESULT["receipt_urls_truncated"] = True
                return
            RESULT["receipt_url_observations"].append(
                {"json_pointer": path, "url": value, "downloaded": False,
                 "official_origin_verified": False})
    elif isinstance(value, dict):
        for key in sorted(value):
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            receipt_urls(value[key], path + "/" + escaped, depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            receipt_urls(item, path + "/" + str(index), depth + 1)

def inspect_known():
    for expected in CONFIG["known"]:
        keep = expected["path"].endswith(".json")
        row, raw = observation(expected["path"], keep,
                               LIMITS["json_bytes"] if keep else None)
        row["role"] = expected["role"]
        row["expected_bytes"] = expected.get("bytes")
        row["expected_sha256"] = expected["sha256"]
        row["matches_expected"] = (
            row.get("status") == "read" and row.get("sha256") == expected["sha256"]
            and (expected.get("bytes") is None or row.get("bytes") == expected["bytes"]))
        RESULT["known"].append(row)
        if row["matches_expected"] and raw is not None:
            parsed = json.loads(raw.decode("utf-8"))
            if expected["path"] in CONFIG["receipts_with_public_dependency_metadata"]:
                start = len(RESULT["receipt_url_observations"])
                receipt_urls(parsed)
                for item in RESULT["receipt_url_observations"][start:]:
                    item["receipt_path"] = expected["path"]
                    item["receipt_sha256"] = expected["sha256"]
            if expected["path"].endswith("/inputs/BUILD-RESULT.json"):
                keys = ("all_pass", "version_code", "version_name", "source_file_count",
                        "runtime_java_input_count", "generated_java_count",
                        "compiled_member_count", "unchanged_compiled_payload_count",
                        "source_inventory_sha256")
                RESULT["prior_pinned_build_fields"] = {k: parsed.get(k) for k in keys}
    RESULT["known_pins_all_match"] = all(r["matches_expected"] for r in RESULT["known"])

def tool_location(name, requested):
    row = {"name": name, "requested_path": requested, "executed": False}
    if requested is None:
        row["status"] = "not_in_PATH"
        return row
    try:
        resolved = str(Path(requested).resolve(strict=True))
        observed, unused = observation(resolved)
        row.update(observed)
        row["resolved_path"] = resolved
        row["requested_path"] = requested
        row["requested_is_symlink_or_has_symlink_parent"] = resolved != requested
        if str(Path(requested).resolve(strict=True)) != resolved:
            raise ValueError("tool resolution changed across read")
    except InventoryLimit:
        raise
    except Exception as exc:
        row["status"] = "unavailable"
        row["error"] = type(exc).__name__ + ": " + str(exc)
    return row

def inspect_tools():
    for name in CONFIG["which_names"]:
        tick()
        RESULT["tool_locations"].append(tool_location(name, shutil.which(name)))
    for item in CONFIG["direct_tools"]:
        RESULT["tool_locations"].append(tool_location(item["role"], item["path"]))

def scan_root(root):
    p = Path(root)
    report = {"path": str(p), "completed": False, "entries_before": SCAN["entries"]}
    RESULT.setdefault("scan_roots", []).append(report)
    try:
        if str(p.resolve(strict=True)) != str(p) or not p.is_dir():
            raise ValueError("scan root is not a non-symlink directory")
        stack = [(p, 0)]
        while stack:
            tick()
            directory, depth = stack.pop()
            if directory == ROOT:
                continue
            if depth > LIMITS["depth"]:
                raise InventoryLimit("scan depth budget reached")
            if str(directory.resolve(strict=True)) != str(directory):
                SCAN["symlinks_skipped"] += 1
                continue
            try:
                children = []
                with os.scandir(str(directory)) as entries:
                    for entry in entries:
                        tick()
                        SCAN["entries"] += 1
                        if SCAN["entries"] > LIMITS["entries"]:
                            raise InventoryLimit("directory entry budget reached")
                        children.append(entry.name)
                SCAN["directories"] += 1
                for name in sorted(children, reverse=True):
                    tick()
                    child = directory / name
                    info = os.lstat(str(child))
                    if stat.S_ISLNK(info.st_mode):
                        SCAN["symlinks_skipped"] += 1
                    elif stat.S_ISDIR(info.st_mode):
                        if name == ".git":
                            SCAN["excluded_git_directories"] += 1
                        else:
                            stack.append((child, depth + 1))
                    elif stat.S_ISREG(info.st_mode):
                        if name.endswith(".jar") or name == "compiled-res.zip":
                            SCAN["candidates"] += 1
                            if SCAN["candidates"] > LIMITS["candidates"]:
                                raise InventoryLimit("candidate file budget reached")
                            row, unused = observation(str(child))
                            row["kind"] = "compiled_resource_zip" if name == "compiled-res.zip" else "jar"
                            row["scan_root"] = str(p)
                            if row["status"] != "read":
                                SCAN["complete"] = False
                            RESULT["discovered"].append(row)
                    else:
                        SCAN["special_files_skipped"] += 1
            except InventoryLimit:
                raise
            except Exception as exc:
                SCAN["complete"] = False
                SCAN["errors"].append({"path": str(directory),
                                      "error": type(exc).__name__ + ": " + str(exc)})
        report["completed"] = True
    except InventoryLimit:
        raise
    except Exception as exc:
        SCAN["complete"] = False
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        report["entries_after"] = SCAN["entries"]

def match_inputs():
    good = [r for r in RESULT["discovered"] if r.get("status") == "read"]
    for expected in CONFIG["required_jars"]:
        row = dict(expected)
        row["p4_exact_matches"] = [
            r["path"] for r in good
            if r["kind"] == "jar" and r["bytes"] == expected["bytes"]
            and r["sha256"] == expected["sha256"]]
        row["found"] = bool(row["p4_exact_matches"])
        RESULT["required_jars"].append(row)
    RESULT["all_17_known_jars_found"] = all(r["found"] for r in RESULT["required_jars"])
    RESULT["compiled_resource_zip_candidates"] = [
        {"path": r["path"], "bytes": r["bytes"], "sha256": r["sha256"],
         "matches_original_mac_resource_zip": None}
        for r in good if r["kind"] == "compiled_resource_zip"]
    RESULT["resource_zip_expected_sha_available"] = False

def final_identities():
    changed = []
    for path, before in sorted(TRACKED.items()):
        try:
            if ident(os.lstat(path)) != before or str(Path(path).resolve(strict=True)) != path:
                changed.append({"path": path, "error": "identity changed"})
        except Exception as exc:
            changed.append({"path": path, "error": type(exc).__name__ + ": " + str(exc)})
    RESULT["read_files_final_identity_count"] = len(TRACKED)
    RESULT["read_files_final_identities_unchanged"] = not changed
    RESULT["changed_read_files"] = changed

def write_new(name, raw):
    target = ROOT / name
    with target.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(target), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

# The claim is deliberately outside the handler. A duplicate cannot rewrite this run.
os.umask(0o077)
ROOT.mkdir(mode=0o700)
try:
    source = globals().get("__source_raw__")
    if not isinstance(source, bytes):
        raise ValueError("exact source bytes must be supplied by the reviewed stable-FD loader")
    RESULT["source"] = write_new("SOURCE.py", source)
    inspect_known()
    inspect_tools()
    for scan_path in CONFIG["scan_roots"]:
        scan_root(scan_path)
    match_inputs()
    RESULT["completed"] = True
except Exception as exc:
    RESULT["error"] = type(exc).__name__ + ": " + str(exc)
finally:
    final_identities()
    RESULT["hashed_bytes"] = HASHED_BYTES
    RESULT["finished_epoch"] = time.time()
    RESULT["elapsed_seconds"] = round(time.monotonic() - STARTED, 6)
    RESULT["inventory_complete"] = (RESULT["completed"] and SCAN["complete"]
                                    and RESULT["read_files_final_identities_unchanged"])
    RESULT["exit_code"] = 0 if RESULT["inventory_complete"] else 2
    RESULT["next_step_requires"] = [
        "Review actual local JAR/resource matches and fresh Linux tool identities.",
        "Revalidate the complete JDK closure and freeze a concrete Linux build input map.",
        "Verify missing inputs' official original URLs and full hashes before any download.",
        "Do not sign or install any artifact from the still-unknown Mac operation."]
    raw_result = (json.dumps(RESULT, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    receipt = write_new("RESULT.json", raw_result)
    summary = {"schema": RESULT["schema"], "result": receipt,
               "completed": RESULT["completed"], "inventory_complete": RESULT["inventory_complete"],
               "known_pins_all_match": RESULT.get("known_pins_all_match", False),
               "all_17_known_jars_found": RESULT.get("all_17_known_jars_found", False),
               "candidate_file_count": SCAN["candidates"], "error": RESULT["error"],
               "exit_code": RESULT["exit_code"], "ready_for_build": False,
               "build_executed": False, "signed": False, "phone_contacted": False}
    write_new("SUMMARY.json", (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    print(json.dumps(summary, sort_keys=True), flush=True)
sys.exit(RESULT["exit_code"])
