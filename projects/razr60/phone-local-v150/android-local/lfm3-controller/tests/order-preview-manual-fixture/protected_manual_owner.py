"""Exact proof of the two already-reviewed manual OWNER additions.
Only a proof copy is returned; callers compile the actual current source.
"""
import hashlib

BEFORE_BYTES = 23763
BEFORE_SHA256 = "65c87f6254ac109223ddb643f0ef7dd9763c5690414b7ccb8a50e4bc921c6447"
AFTER_BYTES = 24497
AFTER_SHA256 = "fbdd7688e6cb0582001d6f1d5142437be0dd8c25a0d98102b8c0f7023baedd81"
# Identical complete insertions to run_observer_host.MANUAL_GOAL_INSERTIONS.
_INSERTIONS = (
    '\n    // An explicit, finite fixture owner. This is not a suffix added to a query owner.\n    private static final Pattern MANUAL_PREVIEW_FIXTURE = Pattern.compile("测试采集订单预览\\\\[(?<manualPurpose>preview_open_sku|preview_select_requested_variant|preview_open_confirmation)\\\\]："+SHOP+"准备购买"+UNIT+ITEM\n            +"[，,]预算不超过"+CAP+"[，,]核对商品、数量和总额后停在订单确认页"+NO_TRANSACTION);\n'.encode("utf-8"),
    '            Matcher manual=MANUAL_PREVIEW_FIXTURE.matcher(owner);\n            if(manual.matches())return new NativeAppGoal(owner,explicitlySelectedPackage,manual,\n                    "complete_literal_manual_order_preview_fixture.v1/"+manual.group("manualPurpose"),new OrderPreview(manual));\n'.encode("utf-8"),
)

def predecessor(raw):
    if type(raw) is not bytes:
        raise ValueError("exact bytes required for manual OWNER proof")
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) == BEFORE_BYTES and digest == BEFORE_SHA256:
        return raw
    if len(raw) != AFTER_BYTES or digest != AFTER_SHA256:
        raise ValueError("unreviewed complete manual OWNER source")
    proof = raw
    for inserted in _INSERTIONS:
        if proof.count(inserted) != 1:
            raise ValueError("unique complete manual OWNER insertion required")
        proof = proof.replace(inserted, b"", 1)
    if len(proof) != BEFORE_BYTES or hashlib.sha256(proof).hexdigest() != BEFORE_SHA256:
        raise ValueError("complete preceding read-only OWNER source required")
    return proof
