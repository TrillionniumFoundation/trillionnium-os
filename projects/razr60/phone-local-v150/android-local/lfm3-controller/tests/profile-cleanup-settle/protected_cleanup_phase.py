"""Exact whole-file proof copy only. All callers compile current production bytes."""
from pathlib import Path
import hashlib
import json
SPEC_SHA = "f985e8c34e201d0a92cba00c0b9d3347f8b197d9c822a057de715a56e892a9d4"
def predecessor(relative, raw):
    if type(relative) is not str or type(raw) is not bytes:
        raise ValueError("exact cleanup predecessor input types required")
    path = Path(__file__).resolve().with_name("production-predecessor.json")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SPEC_SHA:
        raise ValueError("fixed cleanup predecessor data differs")
    spec = json.loads(data)
    if (set(spec) != {"schema", "proof_only_not_compiled", "files"}
            or spec["schema"] != "hepta.profile-cleanup-phase.exact-predecessor.v1"
            or spec["proof_only_not_compiled"] is not True or relative not in spec["files"]):
        raise ValueError("closed cleanup predecessor member required")
    row = spec["files"][relative]
    actual = (len(raw), hashlib.sha256(raw).hexdigest())
    previous = (row["previous_bytes"], row["previous_sha256"])
    if actual == previous:
        return raw
    if actual != (row["current_bytes"], row["current_sha256"]):
        raise ValueError("reviewed whole cleanup source required")
    lines = raw.decode("utf-8", errors="strict").splitlines(keepends=True)
    limit = len(lines)
    for edit in reversed(row["inverse_edits"]):
        start, end = edit["start"], edit["end"]
        if type(start) is not int or type(end) is not int or not 0 <= start <= end <= limit:
            raise ValueError("exact inverse coordinates required")
        if lines[start:end] != edit["current"]:
            raise ValueError("exact inverse whole changed block required")
        lines[start:end] = edit["previous"]
        limit = start
    restored = "".join(lines).encode("utf-8")
    if (len(restored), hashlib.sha256(restored).hexdigest()) != previous:
        raise ValueError("whole f4 predecessor identity required")
    return restored
