"""Strict proof-copy inverse for the reviewed partial-edge refusal classifier.
Callers compile the actual current comparator. This helper grants no action,
role, dispatch, recovery or model authority and accepts no unknown source.
"""
import hashlib

CURRENT_BYTES=87557
CURRENT_SHA256="c1df34cb7613f7b50e206b89140e1518556343f438fe43594ff27ca1c5db3346"
PREDECESSOR_BYTES=87473
PREDECESSOR_SHA256="400db829f8b5942d9ad4a43a1bbbc18d96fe2138964482146b8cd08fd63ea593"
INVERSES=[('        List<Integer> r=n.bounds,outer=banner.bounds;\n        long width=(long)r.get(2)-r.get(0),bannerWidth=(long)outer.get(2)-outer.get(0);\n        return r.get(1).equals(outer.get(1))&&r.get(3).equals(outer.get(3))\n                &&width>0&&width<bannerWidth\n', '        List<Integer> r=n.bounds,outer=banner.bounds;\n        return r.get(1).equals(outer.get(1))&&r.get(3).equals(outer.get(3))\n                &&(long)r.get(2)-r.get(0)==1\n'), ('    // 0 hidden, 1 full page, 2 partial visible edge beside a full page.\n', '    // 0 hidden, 1 full page, 2 one-pixel visible edge beside a full page.\n'), ('     * page and its partial edge neighbour are recorded as overlapping. They\n', '     * page and its one-pixel edge neighbour are recorded as overlapping. They\n')]

def predecessor(raw):
    if not isinstance(raw,bytes):
        raise ValueError("complete comparator source bytes required")
    identity=(len(raw),hashlib.sha256(raw).hexdigest())
    if identity==(PREDECESSOR_BYTES,PREDECESSOR_SHA256):
        return raw
    if identity!=(CURRENT_BYTES,CURRENT_SHA256):
        raise ValueError("reviewed complete partial-edge comparator required")
    proof=raw
    for current,prior in INVERSES:
        current,prior=current.encode("utf-8"),prior.encode("utf-8")
        if proof.count(current)!=1:
            raise ValueError("partial-edge inverse must attach exactly once")
        proof=proof.replace(current,prior,1)
    if (len(proof),hashlib.sha256(proof).hexdigest())!=(PREDECESSOR_BYTES,PREDECESSOR_SHA256):
        raise ValueError("partial-edge inverse must recover the complete 712 comparator")
    return proof
