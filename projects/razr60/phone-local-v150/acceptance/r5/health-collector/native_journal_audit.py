"""Read-only verification of the pinned native event-store v1 record format.

Source: frozen source7/crates/trillionnium-owner-open-event-store/src/lib.rs,
SHA256 99b2f280ba4798cd8ee3f74fa9e9c901893c3a4949800dc13083d5842ac38018.
RecordPreimage field order is a Rust struct; payload Value maps are sorted.
Floats are deliberately unsupported: Python formatting is not Rust serde/ryu.
A filtered turn proves no unobserved global predecessor or whole-store chain.
"""
import hashlib
import json

SCOPE_FIELDS = ("session_id", "profile_id", "task_id", "turn_id", "turn_stream_id")
RECORD_FIELDS = ("schema", "store_seq", "turn_seq", "scope", "event_id", "kind",
                 "payload", "payload_sha256", "previous_record_sha256")

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict_loads(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("nonfinite JSON number: " + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)

def canonical_value(value):
    if value is None or type(value) in (str, bool):
        return value
    if type(value) is int:
        if not -(2**63) <= value <= 2**64-1:
            raise ValueError("integer outside serde_json i64/u64")
        return value
    if type(value) is float:
        raise ValueError("float serialization requires original Rust/ryu verifier")
    if isinstance(value, list):
        return [canonical_value(item) for item in value]
    if isinstance(value, dict):
        return {key: canonical_value(value[key]) for key in sorted(value)}
    raise ValueError("unsupported JSON value")

def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")

def record_hashes(row):
    if set(row) != set(RECORD_FIELDS) | {"record_sha256"}:
        raise ValueError("native event record fields differ")
    if row["schema"] != "trillionnium.owner-open.event-record.v1":
        raise ValueError("native event record schema differs")
    scope = row["scope"]
    if set(scope) != set(SCOPE_FIELDS) or any(not isinstance(scope[k],str) or not scope[k]
                                            for k in SCOPE_FIELDS):
        raise ValueError("native record scope differs")
    payload = canonical_value(row["payload"])
    payload_hash = sha(encode(payload))
    preimage = {key: row[key] for key in RECORD_FIELDS}
    preimage["scope"] = {key: scope[key] for key in SCOPE_FIELDS}
    preimage["payload"] = payload
    return payload_hash, sha(encode(preimage))

def verify_records(records, scope):
    checks, errors, unsupported = [], [], []
    seen = {}
    for index, row in enumerate(records):
        try:
            store_seq = row["store_seq"]
            if type(store_seq) is not int or store_seq < 0:
                raise ValueError("invalid store sequence")
            if store_seq in seen:
                raise ValueError("duplicate store sequence in supplied evidence")
            seen[store_seq] = row
            payload_hash, record_hash = record_hashes(row)
            if payload_hash != row["payload_sha256"] or record_hash != row["record_sha256"]:
                raise ValueError("native record payload/preimage hash differs")
            checks.append(store_seq)
        except (KeyError, TypeError, ValueError, UnicodeError) as error:
            issue = {"input_index": index, "store_seq": row.get("store_seq") if isinstance(row,dict) else None,
                     "error": str(error)}
            (unsupported if "float serialization" in str(error) else errors).append(issue)
    ordered = sorted(seen.values(), key=lambda row: row["store_seq"])
    adjacent, gaps = [], []
    for previous, current in zip(ordered, ordered[1:]):
        if current["store_seq"] == previous["store_seq"] + 1:
            if current["previous_record_sha256"] != previous["record_sha256"]:
                errors.append({"store_seq": current["store_seq"], "error": "global predecessor hash differs"})
            else:
                adjacent.append([previous["store_seq"], current["store_seq"]])
        else:
            gaps.append([previous["store_seq"], current["store_seq"]])
    selected = [row for row in ordered if row.get("scope") == scope]
    if not selected:
        errors.append({"error": "selected scope has no original native records"})
    elif [row["turn_seq"] for row in selected] != list(range(len(selected))):
        errors.append({"error": "selected scope turn_seq is incomplete, duplicated or unordered"})
    frames = []
    for row in selected:
        try:
            frame = row["payload"]["frame"]
            if any(frame.get(key) != scope[key] for key in SCOPE_FIELDS):
                raise ValueError("native frame scope differs")
            if frame.get("kind") != row["kind"] or frame.get("event_id") != row["event_id"]:
                raise ValueError("native frame event identity differs")
            frames.append(frame)
        except (KeyError, TypeError, ValueError) as error:
            errors.append({"store_seq":row["store_seq"],"error":str(error)})
    if frames:
        if [frame.get("host_seq") for frame in frames] != list(range(len(frames))):
            errors.append({"error":"native frame host sequence incomplete"})
        if frames[0].get("kind") != "turn.accepted" or frames[-1].get("kind") != "turn.end":
            errors.append({"error":"selected native turn lacks accepted/end boundary"})
        digests = [row["payload"].get("request_sha256") for row in selected]
        if not isinstance(digests[0],str) or len(set(digests)) != 1:
            errors.append({"error":"native turn request binding differs across records"})
        elif any(frame.get("payload",{}).get("turn_request_sha256") != digests[0] for frame in frames):
            errors.append({"error":"native frame request binding differs"})
    return {
        "status": "PASS" if not errors and not unsupported else "UNVERIFIED" if unsupported and not errors else "FAIL",
        "record_count":len(records), "record_hashes_verified":len(checks),
        "selected_scope_record_count":len(selected),
        "adjacent_global_predecessor_links_verified":len(adjacent),
        "unobserved_global_sequence_gaps":gaps,
        "global_chain_complete":False,
        "global_chain_limit":"Only supplied adjacent records checked; no unseen predecessor/genesis attested.",
        "errors":errors,"unsupported":unsupported,
        "selected_records":selected,"frames":frames,
    }
