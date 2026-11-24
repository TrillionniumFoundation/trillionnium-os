"""Verify the unchanged predecessor of the wide-search-only comparator delta."""
import hashlib

CURRENT = "dbc72e40e410334c9db300308dc0dfec60339a8e4c3018661239c1a959438d05"
PARENT = "4b44a759dd41f60c6c693c60d500a83fa8ec83962eb7f6b8d6dd5be95953ad6b"

# Exact proof-copy inverse for the separately reviewed typed banner coverage change.
# Actual new production sources still compile; this only retains the old Ctrip pin.
BANNER_CURRENT = "de5a0bcd74250ce051595bc9200802ad019a99a69babc18dd9ecc229a6e2afac"
BANNER_INVERSE = (
    (
        b'    // A transition may partition the same full banner rectangle among blank\n'
        b'    // direct children. Exact horizontal coverage above rejects any gap, overlap\n'
        b'    // or changed capability; it never clips bounds or supplies an input target.\n',
        b'    // Full-width page swaps have equal visible coverage. The typed attempt\n'
        b'    // classifies only these direct blank children, never the container, the\n'
        b'    // search target or a coordinate. A partially visible neighbour is excluded.\n',
    ),
    (
        b'        boolean visiblePageChanged=false;\n'
        b'        for(int slot=0;slot<banner.children;slot++){\n'
        b'            String child=banner.path+"/"+slot;\n'
        b'            Node old=a.node(child),fresh=b.node(child);\n'
        b'            visiblePageChanged|=(old.visible()||fresh.visible())&&!old.v.equals(fresh.v);\n'
        b'        }\n'
        b'        return visiblePageChanged?banner.path:null;\n'
        b'    }\n',
        b'        String first=null,second=null;\n'
        b'        for(int slot=0;slot<banner.children;slot++){\n'
        b'            String child=banner.path+"/"+slot;\n'
        b'            Node old=a.node(child),fresh=b.node(child);\n'
        b'            if(old.visible()){\n'
        b'                if(first!=null||!old.bounds.equals(banner.bounds))return null;\n'
        b'                first=child;\n'
        b'            }\n'
        b'            if(fresh.visible()){\n'
        b'                if(second!=null||!fresh.bounds.equals(banner.bounds))return null;\n'
        b'                second=child;\n'
        b'            }\n'
        b'        }\n'
        b'        return first!=null&&second!=null&&!first.equals(second)?banner.path:null;\n'
        b'    }\n',
    ),
)

def predecessor(raw):
    if hashlib.sha256(raw).hexdigest() == BANNER_CURRENT:
        for revised, previous in BANNER_INVERSE:
            if raw.count(revised) != 1:
                raise ValueError("reviewed banner inverse must have one exact attachment")
            raw = raw.replace(revised, previous, 1)
        if hashlib.sha256(raw).hexdigest() != CURRENT:
            raise ValueError("banner coverage must reverse to the complete prior comparator")
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
