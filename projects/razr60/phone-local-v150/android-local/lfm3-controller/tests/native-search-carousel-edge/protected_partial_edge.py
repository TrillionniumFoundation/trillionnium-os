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


CAPTION_BYTES=88545
CAPTION_SHA256="46c6aed0dfb6279c5b56ec80095a5d2fead6c3c95335f70d5a47a98bef52e0f6"
CAPTION_INVERSES=[('                    need(x.children==0,"banner leaves cannot hide descendants");\n                    if(child==0)need("android.widget.ImageView".equals(x.cls)&&x.view.isEmpty()\n                            &&x.text.isEmpty()&&"广告素材".equals(x.desc),"actual passive banner image");\n                    else need(ctripBannerCaption(x),"actual passive activity/ad caption");\n                }\n                need(after.nodes.containsKey(p)&&z.children==2,"same complete banner page");\n            }\n', '                    need(x.children==0,"banner leaves cannot hide descendants");\n                    if(child==0)need("android.widget.ImageView".equals(x.cls)&&x.view.isEmpty()\n                            &&x.text.isEmpty()&&"广告素材".equals(x.desc),"actual passive banner image");\n                    else need("android.widget.TextView".equals(x.cls)&&(CP+"label_text").equals(x.view)\n                            &&"活动".equals(x.text)&&x.desc.isEmpty(),"actual passive activity label");\n                }\n                need(after.nodes.containsKey(p)&&z.children==2,"same complete banner page");\n            }\n'), ('                        Node a=before.node(node.path),z=after.node(node.path);\n                        need(sameBannerNodeFacts(a,z)&&a.bounds.get(1).equals(z.bounds.get(1))\n                                &&a.bounds.get(3).equals(z.bounds.get(3)),"only observed horizontal banner movement");\n                        // A caption switch must carry the actual reference for each\n                        // literal; hidden leaves retain no projected label/reference.\n                        if(ctripBannerCaption(a)&&ctripBannerCaption(z)&&!a.text.equals(z.text))\n                            requireSearchInputReference(snap,node);\n                    }\n                    if(node.visible()){\n                        // Use the raw reported bounds.  A child is never clipped to a\n', '                        Node a=before.node(node.path),z=after.node(node.path);\n                        need(sameBannerNodeFacts(a,z)&&a.bounds.get(1).equals(z.bounds.get(1))\n                                &&a.bounds.get(3).equals(z.bounds.get(3)),"only observed horizontal banner movement");\n                    }\n                    if(node.visible()){\n                        // Use the raw reported bounds.  A child is never clipped to a\n'), ('            Map<String,Object> allowed=new TreeMap<String,Object>();allowed.put(YEAR,date.path);allowed.put(QUERY,query.path);\n            proof.put("form_purpose_target_paths",allowed);\n            proof.put("date_bounds",date.bounds);proof.put("query_bounds",query.bounds);\n            proof.put("banner_caption_literals",Arrays.asList("活动","广告"));\n            proof.put("caption_change_requires_actual_reference",true);\n            proof.put("foreign_visible_hit_rectangles",0);proof.put("grants_action_authority",false);\n            proof.put("whole_screen_pixels_stable",false);proof.put("fresh_same_scope_comparison_required",true);\n        }catch(IllegalArgumentException rejected){\n', '            Map<String,Object> allowed=new TreeMap<String,Object>();allowed.put(YEAR,date.path);allowed.put(QUERY,query.path);\n            proof.put("form_purpose_target_paths",allowed);\n            proof.put("date_bounds",date.bounds);proof.put("query_bounds",query.bounds);\n            proof.put("foreign_visible_hit_rectangles",0);proof.put("grants_action_authority",false);\n            proof.put("whole_screen_pixels_stable",false);proof.put("fresh_same_scope_comparison_required",true);\n        }catch(IllegalArgumentException rejected){\n'), ('                ||!"hepta.observed-ime-enter.v1|true|false|null".equals(s(node.v,"ime_enter")))return false;\n        return pager||"hepta.observed-scroll-actions.v1|observed".equals(s(node.v,"scroll_actions"));\n    }\n    /** Only the two recorded noninteractive caption literals. The containing\n     * exact banner, complete form, raw geometry and all capabilities are still\n     * checked by ctripFormRegions; this value predicate supplies no authority. */\n    private static boolean ctripBannerCaption(Node node){\n        return "android.widget.TextView".equals(node.cls)&&(CP+"label_text").equals(node.view)\n                &&node.children==0&&node.desc.isEmpty()&&("活动".equals(node.text)||"广告".equals(node.text));\n    }\n    private static boolean sameBannerNodeFacts(Node a,Node z){\n        Map<String,Object> left=new TreeMap<String,Object>(a.v),right=new TreeMap<String,Object>(z.v);\n        for(String key:Arrays.asList("bounds","visible","label","ref_signature_sha256")){left.remove(key);right.remove(key);}\n        if(ctripBannerCaption(a)&&ctripBannerCaption(z)){left.remove("text");right.remove("text");}\n        return left.equals(right);\n    }\n\n', '                ||!"hepta.observed-ime-enter.v1|true|false|null".equals(s(node.v,"ime_enter")))return false;\n        return pager||"hepta.observed-scroll-actions.v1|observed".equals(s(node.v,"scroll_actions"));\n    }\n    private static boolean sameBannerNodeFacts(Node a,Node z){\n        Map<String,Object> left=new TreeMap<String,Object>(a.v),right=new TreeMap<String,Object>(z.v);\n        for(String key:Arrays.asList("bounds","visible","label","ref_signature_sha256")){left.remove(key);right.remove(key);}\n        return left.equals(right);\n    }\n\n')]

def caption_predecessor(raw):
    """Proof copy only; all callers still compile the complete current source."""
    if (len(raw),hashlib.sha256(raw).hexdigest())!=(CAPTION_BYTES,CAPTION_SHA256):
        return raw
    proof=raw
    for current,prior in CAPTION_INVERSES:
        current,prior=current.encode("utf-8"),prior.encode("utf-8")
        if proof.count(current)!=1:
            raise ValueError("caption inverse must attach exactly once")
        proof=proof.replace(current,prior,1)
    if (len(proof),hashlib.sha256(proof).hexdigest())!=(CURRENT_BYTES,CURRENT_SHA256):
        raise ValueError("caption inverse must recover the complete 5b comparator")
    return proof

def predecessor(raw):
    if not isinstance(raw,bytes):
        raise ValueError("complete comparator source bytes required")
    raw=caption_predecessor(raw)
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
