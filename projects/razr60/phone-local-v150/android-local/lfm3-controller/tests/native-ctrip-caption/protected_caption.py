#!/usr/bin/env python3
"""Exact proof-only inverse of the reviewed passive Ctrip caption extension.

The current production source remains the compiler input.  This helper only
connects its complete-file identity to the existing protected predecessor.
"""
import hashlib

CURRENT_BYTES = 88545
CURRENT_SHA256 = "46c6aed0dfb6279c5b56ec80095a5d2fead6c3c95335f70d5a47a98bef52e0f6"
PREDECESSOR_BYTES = 87557
PREDECESSOR_SHA256 = "c1df34cb7613f7b50e206b89140e1518556343f438fe43594ff27ca1c5db3346"

INVERSES = (
    (
        '                    else need(ctripBannerCaption(x),"actual passive activity/ad caption");\n',
        '                    else need("android.widget.TextView".equals(x.cls)&&(CP+"label_text").equals(x.view)\n'
        '                            &&"活动".equals(x.text)&&x.desc.isEmpty(),"actual passive activity label");\n',
    ),
    (
        '                        // A caption switch must carry the actual reference for each\n'
        '                        // literal; hidden leaves retain no projected label/reference.\n'
        '                        if(ctripBannerCaption(a)&&ctripBannerCaption(z)&&!a.text.equals(z.text))\n'
        '                            requireSearchInputReference(snap,node);\n',
        '',
    ),
    (
        '            proof.put("banner_caption_literals",Arrays.asList("活动","广告"));\n'
        '            proof.put("caption_change_requires_actual_reference",true);\n',
        '',
    ),
    (
        '    /** Only the two recorded noninteractive caption literals. The containing\n'
        '     * exact banner, complete form, raw geometry and all capabilities are still\n'
        '     * checked by ctripFormRegions; this value predicate supplies no authority. */\n'
        '    private static boolean ctripBannerCaption(Node node){\n'
        '        return "android.widget.TextView".equals(node.cls)&&(CP+"label_text").equals(node.view)\n'
        '                &&node.children==0&&node.desc.isEmpty()&&("活动".equals(node.text)||"广告".equals(node.text));\n'
        '    }\n',
        '',
    ),
    (
        '        if(ctripBannerCaption(a)&&ctripBannerCaption(z)){left.remove("text");right.remove("text");}\n',
        '',
    ),
)


def predecessor(raw):
    if not isinstance(raw, bytes):
        raise ValueError("caption predecessor requires complete source bytes")
    identity = (len(raw), hashlib.sha256(raw).hexdigest())
    if identity == (PREDECESSOR_BYTES, PREDECESSOR_SHA256):
        return raw
    if identity != (CURRENT_BYTES, CURRENT_SHA256):
        raise ValueError("unknown complete caption source identity")
    proof = raw
    for current, prior in INVERSES:
        current = current.encode("utf-8")
        prior = prior.encode("utf-8")
        if proof.count(current) != 1:
            raise ValueError("exact reviewed caption inverse occurrence required")
        proof = proof.replace(current, prior, 1)
    if (len(proof), hashlib.sha256(proof).hexdigest()) != (PREDECESSOR_BYTES, PREDECESSOR_SHA256):
        raise ValueError("caption inverse must reproduce the complete protected predecessor")
    return proof
