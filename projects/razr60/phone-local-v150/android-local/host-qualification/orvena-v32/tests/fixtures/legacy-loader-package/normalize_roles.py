#!/usr/bin/env python3
"""Host-only conversion of the retained exact-package identity reader result."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "drivers"))
import qualification_scope as scope


def normalize(raw, expected_sha, original_path):
    scope.need(scope.sha(raw) == expected_sha, "installed identity original SHA differs")
    value = scope.strict(raw)
    scope.need(value.get("schema") == "hepta.scope-role-installed-identity.v1" and value.get("status") == "complete"
               and type(value.get("phone_mutations")) is int and value["phone_mutations"] == 0
               and value.get("actions_or_inference_started") is False and value.get("collection_user") == 0
               and value.get("parser_revision") == "r2-indented-exact-package-block"
               and scope.equal(value.get("before"), value.get("after")), "role reader did not finish stable read-only collection")
    scope.need(set(value.get("roles", {})) == set(scope.ROLES), "role reader membership differs")
    roles = {}
    for role, package in scope.ROLES.items():
        entry = value["roles"][role]; apks = entry.get("apks")
        scope.need(entry.get("package") == package and entry.get("enabled") is True and entry.get("identity_stable") is True
                   and isinstance(apks, dict) and set(apks) == {"base"}
                   and entry.get("split_mapping") == "single observed base APK; no splits",
                   "this parser only normalizes the actually observed single-base identity")
        rows = [{"key": key, "sha256": item["sha256"]} for key, item in sorted(apks.items())]
        rendered = "".join(row["key"] + "\t" + row["sha256"] + "\n" for row in rows)
        digest = scope.apk_set_sha(rows)
        scope.need(entry.get("apk_set_rows_utf8") == rendered and entry.get("apk_set_sha256") == digest,
                   "APK set recomputation differs")
        scope.need(entry.get("apk_paths") == [apks["base"].get("path")]
                   and scope.positive_int(apks["base"].get("bytes")), "base path/bytes differ")
        roles[role] = {"package": package, "uid": entry["uid"], "version_code": entry["long_version_code"],
                       "enabled": True, "apk_rows": rows, "apk_set_sha256": digest, "stable_before_after": True}
    return {"schema": "hepta.scope-installed-role-identities.v1", "launcher_component": value["launcher_component"],
            "roles": roles, "original_evidence": [{"path": str(Path(original_path).resolve()), "sha256": expected_sha}]}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original", type=Path, required=True); p.add_argument("--original-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    value = normalize(scope.read(a.original), a.original_sha256, a.original)
    scope.private_write(a.output, scope.encoded(value))
    print(json.dumps({"output": str(a.output.resolve()), "sha256": scope.sha(scope.read(a.output)), "phone_contacted": False}))
