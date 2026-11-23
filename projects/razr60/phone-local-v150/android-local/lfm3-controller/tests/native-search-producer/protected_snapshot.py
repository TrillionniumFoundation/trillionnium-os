"""Verify the unchanged predecessor of the wide-search-only comparator delta."""
import hashlib

CURRENT = "dbc72e40e410334c9db300308dc0dfec60339a8e4c3018661239c1a959438d05"
PARENT = "4b44a759dd41f60c6c693c60d500a83fa8ec83962eb7f6b8d6dd5be95953ad6b"

def predecessor(raw):
    if hashlib.sha256(raw).hexdigest() != CURRENT:
        raise ValueError("reviewed current Xiaomi comparator required")
    start = b"    /** The retained switcher stays the action target."
    end = b"    private static Map<String,Object> stableHintFacts("
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise ValueError("wide search helper boundaries")
    proof = raw[:raw.index(start)] + raw[raw.index(end, raw.index(start)):]
    for revised, original in (
        (b"searchHintChildren(snapshot.nodes,node)", b"searchHintChildren(snapshot,node)"),
        (b"searchHintChildren(final Map<String,Node> nodes,", b"searchHintChildren(final Snapshot snapshot,"),
        (b'return nodes.get(node.path+"/"+index);', b'return snapshot.node(node.path+"/"+index);'),
    ):
        if proof.count(revised) != 1:
            raise ValueError("wide search child collector attachment")
        proof = proof.replace(revised, original, 1)
    if hashlib.sha256(proof).hexdigest() != PARENT:
        raise ValueError("unrelated original comparator changed")
    return proof
