"""Exact whole-file R4-to-R3 proof; never substitutes compiled production."""
import hashlib

CURRENT_SHA = '74f1a4d677b3cff97f7814a539a5692af4d63c894d55da455fb4df9eaf8024af'
PARENT_SHA = 'fea7aa9179e1ec55a75ae869e594d6fe35d5a3b3faf0d3c4727e1e04da0ab829'
INVERSES = [('    private static final Pattern DETAIL_PRICE_ROLE=Pattern.compile(\n            "(?:券后|补贴后|到手|实付|优惠|活动|会员|分期|单|销售|零售|售)价|价格|月供|首付|每期|分期金额|现价|原价|划线价|参考价|总价|应付|实付");\n', ''), ('            Object t=row.get("text"),d=row.get("description"),l=row.get("label");\n            if(!(t instanceof String)||!(d instanceof String)||(l!=null&&!(l instanceof String)))return page(frame,"product_detail_unverified","complete_detail_literal_fields_required",null,null);\n            // Unretained complete-census rows have no projected label; their text/description are still checked.\n            String text=(String)t,description=(String)d,label=l==null?"":(String)l;\n', '            Object t=row.get("text"),d=row.get("description");\n            if(!(t instanceof String)||!(d instanceof String))return page(frame,"product_detail_unverified","complete_detail_literal_fields_required",null,null);\n            String text=(String)t,description=(String)d;\n'), ('            // Only the already validated mirrored price/rich roles may expose price labels.\n            if(detailMoney(label)&&!pricePath.equals(path)&&!mirrorPath.equals(path)&&!richPath.equals(path)\n                    &&!PROMOTION.matcher(label).matches())\n                return page(frame,"product_detail_unverified","competing_detail_label_price_required_absent",null,null);\n', ''), ("        // Explicit price/payment roles also apply when currency and amount occupy different nodes.\n        // Bare numbers (for example the sales-rank 1), 评价 and 性价比 are not monetary roles.\n        return value.indexOf('¥')>=0||value.indexOf('￥')>=0||DETAIL_MONEY.matcher(value).find()\n                ||DETAIL_PRICE_ROLE.matcher(value).find();\n", "        return value.indexOf('¥')>=0||value.indexOf('￥')>=0||DETAIL_MONEY.matcher(value).find();\n")]

def predecessor(raw):
    if not isinstance(raw, bytes):
        raise ValueError("source must be bytes")
    digest = hashlib.sha256(raw).hexdigest()
    if digest == PARENT_SHA:
        return raw
    if digest != CURRENT_SHA:
        raise ValueError("unrecognized complete source")
    text = raw.decode("utf-8", errors="strict")
    for current, previous in INVERSES:
        if text.count(current) != 1:
            raise ValueError("inverse block is not unique")
        text = text.replace(current, previous, 1)
    result = text.encode("utf-8")
    if hashlib.sha256(result).hexdigest() != PARENT_SHA:
        raise ValueError("whole predecessor differs")
    return result
