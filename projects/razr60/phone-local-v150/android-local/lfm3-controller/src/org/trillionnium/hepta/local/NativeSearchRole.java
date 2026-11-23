package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Pure complete-census search semantics. A proof is planning data, never a node,
 * a dispatch capability, a stable full frame, or evidence of a product price. */
final class NativeSearchRole {
    static final String ROLE="xiaomi_home_open_search";
    final String roleId,targetPath,iconPath,navbarPath;
    final Map<String,Object> facts,authority;
    final Map<String,Map<String,Object>> ancestors;
    final NativeActionSnapshotCheck.Snapshot first,second;
    final boolean fullTreeEqual;
    final List<String> changedPaths,enclosures;
    private final Map<String,Object> proof;

    private NativeSearchRole(NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b){
        need(a!=null&&b!=null,"two complete actual censuses required");
        first=a;second=b;
        Map<String,Object> ae=stableEnvelope(a),be=stableEnvelope(b);
        need(ae.equals(be),"window/display/IME/ownership changed");authority=immutable(ae);
        facts=immutable(NativeActionSnapshotCheck.searchPlanningRoleFacts(a));
        need(facts.equals(NativeActionSnapshotCheck.searchPlanningRoleFacts(b)),"search role/hint structure or global page roles changed");
        targetPath=string(facts,"target_path");iconPath=string(facts,"icon_path");navbarPath=string(facts,"navbar_path");
        Set<String> hints=new TreeSet<String>(Arrays.asList(targetPath,string(facts,"hint_path"),string(facts,"term_path")));
        Set<String> protectedPaths=new TreeSet<String>();
        // The accessibility tree may flatten every navigation label directly
        // under root 0. Its parent is then a shared ancestor, not a navbar
        // subtree. Protect each actual complete navigation role and every
        // actual ancestor; retain its geometry in the disjointness proof.
        Set<String> protectedRoots=new TreeSet<String>(Arrays.asList(targetPath,iconPath));
        for(NativeActionSnapshotCheck.Node node:a.nodes.values())
            if("com.xiaomi.shop.plugin.homepage:id/main_view_nav_bar_text".equals(node.view))protectedRoots.add(node.path);
        Map<String,Map<String,Object>> fixedAncestors=new TreeMap<String,Map<String,Object>>();
        for(String root:protectedRoots){
            for(String path:a.nodes.keySet())if(inside(path,root))protectedPaths.add(path);
            for(String path:b.nodes.keySet())if(inside(path,root))protectedPaths.add(path);
            String parent=parent(root);
            while(parent!=null){
                NativeActionSnapshotCheck.Node old=a.node(parent),fresh=b.node(parent);
                need(old.v.equals(fresh.v),"actual role ancestor changed: "+parent);
                fixedAncestors.put(parent,old.v);parent=parent(parent);
            }
        }
        for(String path:protectedPaths)if(!hints.contains(path)){
            NativeActionSnapshotCheck.Node old=a.nodes.get(path),fresh=b.nodes.get(path);
            need(old!=null&&fresh!=null&&old.v.equals(fresh.v),"protected search/icon/navigation subtree changed: "+path);
        }
        ancestors=Collections.unmodifiableMap(fixedAncestors);
        Map<String,Object> identity=new TreeMap<String,Object>();identity.put("role",ROLE);identity.put("authority",authority);
        identity.put("role_facts",facts);identity.put("actual_ancestors",ancestors);
        roleId=NativeAppEvidence.fingerprint(identity);
        Set<String> paths=new TreeSet<String>(a.nodes.keySet());paths.addAll(b.nodes.keySet());
        List<String> changed=new ArrayList<String>();Set<String> regions=new TreeSet<String>();
        for(String path:paths){
            NativeActionSnapshotCheck.Node old=a.nodes.get(path),fresh=b.nodes.get(path);
            if(old!=null&&fresh!=null&&old.v.equals(fresh.v))continue;
            changed.add(path);
            if(hints.contains(path))continue; // Shared strict hint contract above already recomputed all actual references.
            need(!protectedPaths.contains(path)&&!ancestors.containsKey(path),"protected role changed: "+path);
            String enclosure=parent(path);boolean proved=false;
            while(enclosure!=null){
                if(enclosure(a,b,enclosure,protectedPaths)){
                    regions.add(enclosure);proved=true;break;
                }
                enclosure=parent(enclosure);
            }
            need(proved,"changed node has no fixed complete disjoint enclosure: "+path);
        }
        // Keep a disjoint antichain: a proven outer enclosure subsumes its
        // proven inner one. No change can be assigned to two variable regions.
        Set<String> antichain=new TreeSet<String>(regions);
        for(String inner:regions)for(String outer:regions)if(!inner.equals(outer)&&inside(inner,outer))antichain.remove(inner);
        Map<String,Object> classification=new TreeMap<String,Object>();
        for(String path:changed){
            if(hints.contains(path)){classification.put(path,"validated_search_hint");continue;}
            String only=null;for(String enclosure:antichain)if(inside(path,enclosure)){need(only==null,"overlapping enclosure classification");only=enclosure;}
            need(only!=null,"unclassified actual difference");classification.put(path,only);
        }
        changedPaths=Collections.unmodifiableList(changed);enclosures=Collections.unmodifiableList(new ArrayList<String>(antichain));
        fullTreeEqual=changed.isEmpty();
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema","hepta.native-search-role-proof.v1");out.put("role",ROLE);out.put("role_id",roleId);
        out.put("target_path",targetPath);out.put("first_census_sha256",a.sha);out.put("second_census_sha256",b.sha);
        out.put("complete_pair",true);out.put("full_tree_equal",fullTreeEqual);out.put("changed_paths",changedPaths);
        out.put("fixed_disjoint_enclosures",enclosures);out.put("changed_path_classification",classification);out.put("role_facts",facts);out.put("actual_ancestors",ancestors);
        out.put("protected_role_roots",new ArrayList<String>(protectedRoots));
        out.put("hint_is_owner_query",false);out.put("navigation_only",true);out.put("generic_action_authority",false);
        out.put("query_or_price_verified",false);out.put("grants_dispatch",false);proof=immutable(out);
    }

    /** Classifies a complete loading shell becoming a supported search home.
     * This is only a reason to end an unsuccessful initial read. It creates no
     * planning Role, Frame, node permission, Offer or effect; a successor must
     * collect a completely new pair. Never classify an exception message. */
    static Map<String,Object> loadingToSearch(NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b){
        need(a!=null&&b!=null&&stableEnvelope(a).equals(stableEnvelope(b)),"loading transition ownership/window changed");
        need(NativeAppGoal.XIAOMI_PACKAGE.equals(a.env.get("package")),"loading transition App");
        Map<String,Object> currentRole=NativeActionSnapshotCheck.searchPlanningRoleFacts(b);
        String prefix="com.xiaomi.shop.plugin.homepage:id/";
        Set<String> expectedButtons=new TreeSet<String>(Arrays.asList("main_bottom_home","main_bottom_category",
                "main_bottom_discovery","main_bottom_cart","main_bottom_mine"));
        Set<String> expectedLabels=new TreeSet<String>(Arrays.asList("首页","分类","服务","购物车","我的"));
        Set<String> buttons=new TreeSet<String>(),labels=new TreeSet<String>();
        NativeActionSnapshotCheck.Node root=a.node("0");
        int width=((Number)a.env.get("width")).intValue(),height=((Number)a.env.get("height")).intValue();
        need(root.cls.equals("android.widget.FrameLayout")&&root.bounds.equals(Arrays.asList(0,0,width,height))
                &&root.children==13&&a.nodes.size()==14&&root.parent.isEmpty()&&root.view.isEmpty(),"complete flat home loading shell required");
        int pagers=0,tabs=0,messages=0;
        for(NativeActionSnapshotCheck.Node n:a.nodes.values()){
            need(Boolean.TRUE.equals(n.v.get("enabled"))&&!Boolean.TRUE.equals(n.v.get("editable"))
                    &&!Boolean.TRUE.equals(n.v.get("scrollable"))&&!Boolean.TRUE.equals(n.v.get("focused"))
                    &&!Boolean.TRUE.equals(n.v.get("password"))&&!Boolean.TRUE.equals(n.v.get("checkable"))
                    &&!Boolean.TRUE.equals(n.v.get("checked"))&&"hepta.observed-scroll-actions.v1|observed".equals(n.v.get("scroll_actions")),
                    "loading shell capabilities are not neutral");
            if(n==root){need(n.visible()&&neutralLoadingContainer(n),"loading root must be a visible neutral container");continue;}
            need("0".equals(parent(n.path))&&n.children==0&&n.parent.equals(root.cls),"complete direct loading child slots required");
            if((prefix+"sliding_layout").equals(n.view)){
                need(++tabs==1&&n.cls.equals("android.widget.HorizontalScrollView")&&Boolean.FALSE.equals(n.v.get("visible"))
                        &&neutralLoadingContainer(n),"loading tab placeholder differs");continue;
            }
            need(Boolean.TRUE.equals(n.v.get("visible"))&&positive(n.bounds)&&contains(root.bounds,n.bounds),"actual visible loading node bounds");
            if((prefix+"home_3_vp").equals(n.view)){
                need(++pagers==1&&n.cls.equals("androidx.viewpager.widget.ViewPager")&&n.bounds.equals(root.bounds)
                        &&neutralLoadingContainer(n),"loading pager is not empty");
            }else if((prefix+"msgLayout").equals(n.view)){
                need(++messages==1&&n.cls.equals("android.widget.RelativeLayout")&&n.click()&&n.text.isEmpty()
                        &&"消息".equals(n.desc)&&"消息".equals(n.label)&&Boolean.FALSE.equals(n.v.get("selected")),"loading message control differs");
            }else if((prefix+"main_view_nav_bar_text").equals(n.view)){
                need(n.cls.equals("android.widget.TextView")&&!Boolean.TRUE.equals(n.v.get("clickable"))
                        &&!Boolean.TRUE.equals(n.v.get("action_click"))&&expectedLabels.contains(n.text)&&labels.add(n.text)
                        &&n.desc.isEmpty()&&n.text.equals(n.label)&&Boolean.valueOf("首页".equals(n.text)).equals(n.v.get("selected"))
                        &&(long)n.bounds.get(1)*3>=(long)height*2,"complete selected-home labels required");
            }else if(n.view.startsWith(prefix)&&expectedButtons.contains(n.view.substring(prefix.length()))){
                String key=n.view.substring(prefix.length());
                need(n.cls.equals("android.view.View")&&n.click()&&n.text.isEmpty()&&buttons.add(key)
                        &&Boolean.valueOf("main_bottom_home".equals(key)).equals(n.v.get("selected"))
                        &&(long)n.bounds.get(1)*3>=(long)height*2,"complete loading navigation controls required");
            }else throw new IllegalArgumentException("native search role: unknown loading-shell content: "+n.path);
        }
        need(pagers==1&&tabs==1&&messages==1&&buttons.equals(expectedButtons)&&labels.equals(expectedLabels),"all loading-shell roles required");
        need(((Number)b.env.get("captured_elapsed_ms")).longValue()>((Number)a.env.get("captured_elapsed_ms")).longValue(),"actual forward loading transition");
        Map<String,Object> evidence=new LinkedHashMap<String,Object>();
        evidence.put("schema","hepta.native-search-loading-transition.v1");evidence.put("first_census_sha256",a.sha);
        evidence.put("second_census_sha256",b.sha);evidence.put("first_phase","complete_navigation_only_home");
        evidence.put("second_phase","complete_supported_search_home");evidence.put("current_role_facts_sha256",NativeAppEvidence.fingerprint(currentRole));
        evidence.put("original_pair_accepted",false);evidence.put("planning_created",false);evidence.put("grants_action_authority",false);
        evidence.put("fresh_full_pair_required",true);return immutable(evidence);
    }
    private static boolean neutralLoadingContainer(NativeActionSnapshotCheck.Node n){
        return n.text.isEmpty()&&n.desc.isEmpty()&&n.label==null&&!Boolean.TRUE.equals(n.v.get("clickable"))
                &&!Boolean.TRUE.equals(n.v.get("action_click"))&&Boolean.FALSE.equals(n.v.get("selected"));
    }

    static NativeSearchRole compare(NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b){return new NativeSearchRole(a,b);}
    void requireSameRole(NativeSearchRole current){need(current!=null&&roleId.equals(current.roleId),"new current search role differs from the offered role");}
    Map<String,Object> evidence(){return proof;}

    /** Complete root/ancestor facts stay exact. Common ancestors with the search
     * chain are allowed only when every field is unchanged. Geometry is proved
     * against the fixed enclosure, not by inventing per-parent clipping rules. */
    private static boolean enclosure(NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b,
            String path,Set<String> protectedPaths){
        if("0".equals(path))return false;
        for(String protectedPath:protectedPaths)if(inside(path,protectedPath)||inside(protectedPath,path))return false;
        NativeActionSnapshotCheck.Node old=a.nodes.get(path),fresh=b.nodes.get(path);
        if(old==null||fresh==null||!old.v.equals(fresh.v)||!old.visible())return false;
        for(String ancestor=parent(path);ancestor!=null;ancestor=parent(ancestor)){
            NativeActionSnapshotCheck.Node x=a.nodes.get(ancestor),y=b.nodes.get(ancestor);
            if(x==null||y==null||!x.v.equals(y.v))return false;
        }
        for(String protectedPath:protectedPaths){
            NativeActionSnapshotCheck.Node x=a.nodes.get(protectedPath),y=b.nodes.get(protectedPath);
            if(x==null||y==null||intersects(old.bounds,x.bounds)||intersects(fresh.bounds,y.bounds))return false;
        }
        return completeFootprint(a,old)&&completeFootprint(b,fresh);
    }

    private static boolean completeFootprint(NativeActionSnapshotCheck.Snapshot snapshot,NativeActionSnapshotCheck.Node enclosure){
        for(NativeActionSnapshotCheck.Node node:snapshot.nodes.values())if(inside(node.path,enclosure.path)){
            // Snapshot construction has already proved exact package/window and every child slot.
            if(Boolean.TRUE.equals(node.v.get("visible"))){
                if(!positive(node.bounds)||!contains(enclosure.bounds,node.bounds))return false;
            }else{
                // Keep raw hidden coordinates. A nonpositive subtree normally
                // has no visible descendant; the narrow carousel edge proof
                // below instead accounts for every descendant in the fixed viewport.
                if(positive(node.bounds)){
                    if(!contains(enclosure.bounds,node.bounds))return false;
                }else{
                    boolean visibleDescendant=false;
                    for(NativeActionSnapshotCheck.Node descendant:snapshot.nodes.values())
                        if(!descendant.path.equals(node.path)&&inside(descendant.path,node.path)
                                &&Boolean.TRUE.equals(descendant.v.get("visible")))visibleDescendant=true;
                    if(visibleDescendant&&!boundedEmptyCarouselEdge(snapshot,enclosure,node))return false;
                }
            }
        }
        return true;
    }
    /** Only the authenticated Xiaomi search home's fixed carousel viewport may
     * bound visible descendants of a horizontally empty hidden edge node. This
     * proves disjoint observed footprints, never a parent/child clipping rule or
     * an input target. Raw bounds, visibility and full census values stay exact. */
    private static boolean boundedEmptyCarouselEdge(NativeActionSnapshotCheck.Snapshot snapshot,
            NativeActionSnapshotCheck.Node enclosure,NativeActionSnapshotCheck.Node hidden){
        if(!NativeAppGoal.XIAOMI_PACKAGE.equals(snapshot.env.get("package"))
                ||!"androidx.recyclerview.widget.RecyclerView".equals(enclosure.cls)
                ||!"com.xiaomi.shop:id/recycle_view".equals(enclosure.view)
                ||!Boolean.TRUE.equals(enclosure.v.get("visible"))||!positive(enclosure.bounds)
                ||!Boolean.TRUE.equals(enclosure.v.get("enabled"))||!Boolean.TRUE.equals(enclosure.v.get("scrollable"))
                ||!Boolean.FALSE.equals(enclosure.v.get("clickable"))||!Boolean.FALSE.equals(enclosure.v.get("action_click"))
                ||!Boolean.FALSE.equals(enclosure.v.get("editable"))||!Boolean.FALSE.equals(enclosure.v.get("password"))
                ||!Boolean.FALSE.equals(hidden.v.get("visible")))return false;
        List<Integer> viewport=enclosure.bounds,raw=hidden.bounds;
        if(raw.get(1)>=raw.get(3)||raw.get(1)<viewport.get(1)||raw.get(3)>viewport.get(3))return false;
        boolean right=raw.get(0)>=viewport.get(2)&&raw.get(2).equals(viewport.get(2));
        boolean left=raw.get(0).equals(viewport.get(0))&&raw.get(2)<=viewport.get(0);
        if(!left&&!right)return false;
        boolean visibleDescendant=false;
        for(NativeActionSnapshotCheck.Node descendant:snapshot.nodes.values())
            if(!descendant.path.equals(hidden.path)&&inside(descendant.path,hidden.path)){
                if(Boolean.TRUE.equals(descendant.v.get("visible"))){
                    visibleDescendant=true;
                    if(!positive(descendant.bounds)||!contains(viewport,descendant.bounds))return false;
                }else if(positive(descendant.bounds)&&!contains(viewport,descendant.bounds))return false;
            }
        return visibleDescendant;
    }
    static Map<String,Object> stableEnvelope(NativeActionSnapshotCheck.Snapshot value){
        Map<String,Object> out=new TreeMap<String,Object>(value.env);out.remove("captured_elapsed_ms");out.remove("visited");return out;
    }
    private static String parent(String path){int cut=path.lastIndexOf('/');return cut<0?null:path.substring(0,cut);}
    private static boolean inside(String path,String root){return path.equals(root)||path.startsWith(root+"/");}
    private static boolean positive(List<Integer> r){return r.get(0)<r.get(2)&&r.get(1)<r.get(3);}
    private static boolean contains(List<Integer> a,List<Integer> b){return b.get(0)>=a.get(0)&&b.get(1)>=a.get(1)&&b.get(2)<=a.get(2)&&b.get(3)<=a.get(3);}
    private static boolean intersects(List<Integer> a,List<Integer> b){return positive(a)&&positive(b)&&Math.max(a.get(0),b.get(0))<Math.min(a.get(2),b.get(2))&&Math.max(a.get(1),b.get(1))<Math.min(a.get(3),b.get(3));}
    private static String string(Map<String,Object> value,String key){Object s=value.get(key);need(s instanceof String,"role field "+key);return (String)s;}
    private static Map<String,Object> immutable(Map<String,Object> value){return NativeAppEvidence.immutableMap(value);}
    private static void need(boolean value,String why){if(!value)throw new IllegalArgumentException("native search role: "+why);}
}

