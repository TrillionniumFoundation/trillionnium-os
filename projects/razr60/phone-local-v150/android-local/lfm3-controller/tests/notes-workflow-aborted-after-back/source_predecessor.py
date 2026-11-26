"""Proof-only bridge for the reviewed v13 client in the original v12 gate.

This returns a historical byte string solely for the old equality comparison.
It never creates compiler inputs. The current client must still be compiled by
the caller's actual dependency producer; this helper does not attest class origin.
"""
import hashlib
import json

INVERSE_SHA256 = "f8f79a1644cb561f79186a03f6982d8f0eafe39c65178b827d9fa8199a260f5d"
CLIENT = "src/org/trillionnium/hepta/local/PublicPersonalNotesRecoveryClient.java"
OLD_SHA256 = "2d8db023a62b3c8f1410bacf0b3af0f2632cb474714020badac79963052bab5d"
NEW_SHA256 = "d80c2e7c725980b07e5ae6f2a425f5f914cc8c3db7a4c5d8dc6ec55a009df0de"

def need(value, message):
    if not value:
        raise RuntimeError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def client_predecessor(current, historical, inverse):
    need(type(current) is bytes and type(historical) is bytes and type(inverse) is bytes,
         "v13 client proof requires immutable byte inputs")
    need(len(current) == 47894 and digest(current) == NEW_SHA256,
         "v13 client complete reviewed source changed")
    need(len(historical) == 41092 and digest(historical) == OLD_SHA256,
         "v13 client complete historical source changed")
    need(len(inverse) == 15099 and digest(inverse) == INVERSE_SHA256,
         "v13 complete inverse specification changed")
    spec = json.loads(inverse.decode("utf-8"))
    need(spec["schema"] == "hepta.notes-v13-exact-source-inverse.v1",
         "v13 inverse schema changed")
    rows = [row for row in spec["production"] if row["path"] == CLIENT]
    need(len(rows) == 1, "v13 inverse client entry must be unique")
    row = rows[0]
    need(row["candidate_sha256"] == NEW_SHA256 and row["base_sha256"] == OLD_SHA256
         and len(row["edits"]) == 16, "v13 inverse client identity changed")
    old_lines = historical.decode("utf-8").splitlines(keepends=True)
    new_lines = current.decode("utf-8").splitlines(keepends=True)
    previous_old = previous_new = 0
    for edit in row["edits"]:
        a0, a1, b0, b1 = (edit[key] for key in ("a0", "a1", "b0", "b1"))
        need(all(type(x) is int for x in (a0, a1, b0, b1))
             and previous_old <= a0 <= a1 <= len(old_lines)
             and previous_new <= b0 <= b1 <= len(new_lines),
             "v13 inverse edits overlap or escape the complete source")
        old = "".join(old_lines[a0:a1]).encode("utf-8")
        new = "".join(new_lines[b0:b1]).encode("utf-8")
        need(digest(old) == edit["old_sha256"] and digest(new) == edit["new_sha256"],
             "v13 inverse exact source segment changed")
        previous_old, previous_new = a1, b1
    restored = list(new_lines)
    for edit in reversed(row["edits"]):
        restored[edit["b0"]:edit["b1"]] = old_lines[edit["a0"]:edit["a1"]]
    proof = "".join(restored).encode("utf-8")
    need(proof == historical and len(proof) == 41092 and digest(proof) == OLD_SHA256,
         "v13 client inverse is not the complete original source")
    return proof
