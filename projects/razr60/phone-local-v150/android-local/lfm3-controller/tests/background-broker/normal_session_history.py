"""Exact proof-only BackgroundSession inverse for normal public-profile close budgeting."""
from hashlib import sha256
CURRENT_BYTES = 156411
CURRENT_SHA = "928b207a6b254c127a839955567aec07b056af06ecfdefa0161e47baeae9ec7f"
PRIOR_BYTES = 156312
PRIOR_SHA = "8109ceb4acc2d2c8577bc5fc5e8d37ce259117100e42b846a601a371f1641eb1"
CURRENT_SPAN = "                int closeBudget=publicOwnGroupScope!=null&&profileTarget()!=null?8000:3500;\n                JSONObject response=call(\"close\",null,closeBudget);accept(response,false);\n"
PRIOR_SPAN = "                JSONObject response=call(\"close\",null,3500);accept(response,false);\n"

def predecessor(name, text):
    if name != "BackgroundSession.java":
        raise RuntimeError("unknown normal cleanup Session source")
    raw = text.encode("utf-8")
    if len(raw) == PRIOR_BYTES and sha256(raw).hexdigest() == PRIOR_SHA:
        return text, {"applied": False, "source_sha256": PRIOR_SHA, "proof_only": True}
    if len(raw) != CURRENT_BYTES or sha256(raw).hexdigest() != CURRENT_SHA:
        raise RuntimeError("unreviewed normal cleanup whole Session source")
    if text.count(CURRENT_SPAN) != 1:
        raise RuntimeError("normal cleanup Session inverse span is not unique")
    restored = text.replace(CURRENT_SPAN, PRIOR_SPAN, 1).encode("utf-8")
    if len(restored) != PRIOR_BYTES or sha256(restored).hexdigest() != PRIOR_SHA:
        raise RuntimeError("normal cleanup Session inverse differs from entire f4c0 source")
    return restored.decode("utf-8"), {
        "applied": True, "actual_bytes": CURRENT_BYTES, "actual_sha256": CURRENT_SHA,
        "restored_bytes": PRIOR_BYTES, "restored_sha256": PRIOR_SHA,
        "exact_spans": 1, "proof_only": True, "actual_compilation_uses_current_source": True}
