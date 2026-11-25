package org.trillionnium.hepta.local;

import java.time.LocalDate;
import java.util.*;
import java.util.regex.*;
import org.trillionnium.hepta.local.NativeActionSnapshotCheck.Node;
import org.trillionnium.hepta.local.NativeActionSnapshotCheck.Snapshot;

/** Read-only historical form pairing over two COMPLETE actual native censuses.
 * This is not an Action Intent, a dispatch permit, a query proof or a replacement
 * graph. Every node participates; no compact diagnostic or retained-row subset
 * can supply a census. The caller separately checks current ownership, supported
 * installation, original request time, unknown events and publication window.
 * The existing action comparator and final selected-node chain remain mandatory.
 */
final class NativeCtripFormObservation {
    private static final String CTRIP=NativeActionSnapshotCheck.CTRIP,CP=CTRIP+":id/";
    private static final Set<String> FORM_IDS=NativeActionSnapshotCheck.FORM_IDS;
    private static final Set<String> ROLES=NativeActionSnapshotCheck.ROLES;
    private static final String[] TILE_IDS=NativeActionSnapshotCheck.TILE_IDS;
    private static final Pattern DATE=NativeActionSnapshotCheck.DATE;
    private NativeCtripFormObservation(){}

    /** Reconstruct the exact comparison envelope from two complete AX values.
     * This adapter grants nothing and does not discard or rewrite any node. */
    static Map<String,Object> compareAxCensuses(Map<String,Object> first,Map<String,Object> second,
            Map<String,Object> binding,String installedSet){
        return compare(axSnapshot(first,binding,installedSet),axSnapshot(second,binding,installedSet));
    }
    private static Snapshot axSnapshot(Map<String,Object> census,Map<String,Object> binding,String installedSet){
        Map<String,Object> id=axMap(census,"identity"),window=axMap(census,"window"),profile=axMap(census,"profile_owner");
        need(CTRIP.equals(id.get("package"))&&installedSet!=null&&installedSet.matches("[0-9a-f]{64}"),"actual Ctrip installed AX form");
        Map<String,Object> env=new TreeMap<String,Object>();
        String[][] names={{"task_id","task_id"},{"owner_sha256","owner_sha256"},{"target_sha256","execution_target_sha256"},
                {"authorization_sha256","task_authorization_sha256"},{"selection_sha256","actual_selection_sha256"},
                {"goal_sha256","native_goal_sha256"},{"background_generation","background_generation"},{"package","package"},
                {"display_id","display_id"},{"window_id","window_id"},{"rotation","rotation"},{"width","width"},{"height","height"}};
        for(String[] pair:names)env.put(pair[0],id.get(pair[1]));
        env.put("installed_set_sha256",installedSet);env.put("origin_observation_id",binding.get("observation_id"));
        for(String key:NativeActionSnapshotCheck.PROFILE_IDENTITY)env.put(key,profile.get(key));
        env.put("root_bounds",Arrays.asList(id.get("left"),id.get("top"),id.get("right"),id.get("bottom")));
        env.put("window_metadata_sha256",NativeActionSnapshotCheck.hash(s(window,"metadata")));
        env.put("reported_windows_sha256",axFingerprint(census.get("reported_windows")));
        env.put("reported_windows_complete",Boolean.TRUE);env.put("ime_visibility","hidden");
        env.put("captured_elapsed_ms",census.get("census_captured_elapsed_ms"));env.put("full_native_complete",census.get("complete"));
        env.put("visited",census.get("visited"));env.put("pending",census.get("pending"));
        env.put("node_omissions",census.get("node_budget_omissions"));env.put("text_omissions",census.get("text_budget_omissions"));
        long omitted=time(census,"child_slots_omitted");need(omitted>=0&&omitted<=Integer.MAX_VALUE,"complete child slots");
        env.put("child_omissions",Integer.valueOf((int)omitted));
        need("hidden".equals(census.get("ime_visibility")),"actual known hidden IME required");
        Object raw=census.get("nodes");need(raw instanceof List,"all actual AX node values required");
        List<Node> nodes=new ArrayList<Node>();for(Object item:(List<?>)raw){
            need(item instanceof Map,"actual node map");nodes.add(new Node(axObject(item)));}
        return new Snapshot(env,nodes);
    }
    private static Map<String,Object> axMap(Map<String,Object> parent,String key){return axObject(parent.get(key));}
    private static Map<String,Object> axObject(Object value){
        need(value instanceof Map,"actual AX object required");Map<String,Object> out=new TreeMap<String,Object>();
        for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet()){need(e.getKey() instanceof String,"actual AX string key");out.put((String)e.getKey(),e.getValue());}
        return out;
    }
    /** Same length-prefixed value digest as the existing native action envelope. */
    private static String axFingerprint(Object value){StringBuilder out=new StringBuilder();axCanonical(value,out,0);return NativeActionSnapshotCheck.hash(out.toString());}
    private static void axCanonical(Object value,StringBuilder out,int depth){
        need(depth<=16,"actual AX window nesting bound");
        if(value==null){out.append('n');return;}
        if(value instanceof String){String text=(String)value;out.append('s').append(text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length).append(':').append(text);return;}
        if(value instanceof Boolean){out.append(Boolean.TRUE.equals(value)?'t':'f');return;}
        if(value instanceof Integer||value instanceof Long){out.append('i').append(value).append(';');return;}
        if(value instanceof Map){out.append('{');for(Map.Entry<String,Object> e:axObject(value).entrySet()){
            axCanonical(e.getKey(),out,depth+1);axCanonical(e.getValue(),out,depth+1);}out.append('}');return;}
        if(value instanceof List){out.append('[');for(Object item:(List<?>)value)axCanonical(item,out,depth+1);out.append(']');return;}
        throw new IllegalArgumentException("actual AX window scalar type");
    }

    static Map<String,Object> compare(Snapshot before,Snapshot after){
        need(before!=null&&after!=null,"two complete actual form censuses");
        need(before.env.keySet().equals(NativeActionSnapshotCheck.PROFILE_ENVELOPE)
                &&after.env.keySet().equals(NativeActionSnapshotCheck.PROFILE_ENVELOPE),"managed profile form only");
        need(CTRIP.equals(s(before.env,"package"))&&CTRIP.equals(s(after.env,"package")),"Ctrip form only");
        long first=time(before.env,"captured_elapsed_ms"),last=time(after.env,"captured_elapsed_ms");
        need(last>=first&&last-first<=12000,"ordered original observation pair");
        Map<String,Object> a=new TreeMap<String,Object>(before.env),z=new TreeMap<String,Object>(after.env);
        for(String k:Arrays.asList("captured_elapsed_ms","visited")){a.remove(k);z.remove(k);}
        need(a.equals(z),"window/display/IME/owner/installation/profile differs");
        Scope left=form(before),right=form(after);
        need(left.roots.equals(right.roots)&&left.facts.equals(right.facts),"complete form semantics differ");
        need(roleFacts(before).equals(roleFacts(after)),"global form/calendar/result roles or ambiguity changed");
        for(String p:left.ancestors)need(before.node(p).v.equals(after.node(p).v),"actual form ancestor changed: "+p);
        Set<String> all=union(before.nodes.keySet(),after.nodes.keySet());
        for(String p:all)if(protectedPath(p,left.roots))
            need(before.nodes.containsKey(p)&&after.nodes.containsKey(p)&&before.node(p).v.equals(after.node(p).v),
                    "complete protected form subtree changed: "+p);
        Set<String> regions=anchors(before,after,left);List<String> changed=new ArrayList<String>();
        NativeActionSnapshotCheck.CtripFormRegion actionRegion=NativeActionSnapshotCheck.ctripFormRegions(before,after,left.roots);
        regions.addAll(actionRegion.roots);
        for(String p:all){
            Node x=before.nodes.get(p),y=after.nodes.get(p);if(x!=null&&y!=null&&x.v.equals(y.v))continue;
            String region=null;for(String root:regions)if(p.equals(root)||under(p,root)){
                need(region==null,"overlapping variable regions");region=root;
            }
            need(region!=null,"unclassified complete census change: "+p);changed.add(p);
        }
        Map<String,Object> out=new TreeMap<String,Object>();
        out.put("schema","hepta.ctrip-native-form-observation-pair.v1");
        out.put("before_snapshot_sha256",before.sha);out.put("after_snapshot_sha256",after.sha);
        out.put("before_visited_nodes",before.nodes.size());out.put("after_visited_nodes",after.nodes.size());
        out.put("protected_subtrees",new ArrayList<String>(left.roots));
        out.put("checked_ancestors",new ArrayList<String>(left.ancestors));
        out.put("variable_branch_anchors",new ArrayList<String>(regions));out.put("changed_paths",changed);
        out.put("changed_paths_truncated",false);out.put("full_census_compared",true);
        out.put("literal_form_facts",left.facts);out.put("year_inferred",false);
        if(!actionRegion.roots.isEmpty())out.put("ctrip_form_action_region",actionRegion.evidence);
        out.put("whole_graph_equal",changed.isEmpty());out.put("same_instant_pixels_and_ax_claimed",false);
        out.put("published_pair_is_current_tree_claimed",false);out.put("fully_unoccluded_claimed",false);
        out.put("fresh_action_validation_required",true);out.put("grants_action_authority",false);
        out.put("query_history_proved",false);out.put("business_completion_verified",false);
        return freeze(out);
    }

    /** Compact transport only. The complete proof is preserved in a new immutable
     * task-side artifact; this digest/ref grants no authority and changes no facts. */
    static Map<String,Object> captureSummary(Map<String,Object> proof,String artifact,int bytes,String digest,String part){
        need(proof!=null&&"hepta.ctrip-native-form-observation-pair.v1".equals(proof.get("schema"))
                &&Boolean.FALSE.equals(proof.get("grants_action_authority")),"complete readonly form proof");
        need(artifact!=null&&artifact.matches("[0-9a-f]{32}-form-history\\.json")&&bytes>0&&bytes<=786432
                &&digest!=null&&digest.matches("[0-9a-f]{64}")
                &&Arrays.asList("sampling","pre_encoding","post_encoding").contains(part),"complete proof artifact binding");
        Map<String,Object> out=new TreeMap<String,Object>(proof);
        Object facts=out.remove("literal_form_facts");
        out.put("schema","hepta.ctrip-native-form-capture-summary.v1");
        out.put("complete_comparison_sha256",axFingerprint(proof));
        out.put("literal_form_facts_sha256",axFingerprint(facts));
        out.put("literal_form_facts_in_complete_artifact",true);
        out.put("literal_departure_date",axObject(facts).get("literal_departure_date"));
        Object entered=out.get("entered_open_read_permit");
        if(entered!=null){Map<String,Object> full=axObject(entered),small=new TreeMap<String,Object>();
            small.put("schema","hepta.native-post-effect-read-permit-summary.v1");
            for(String key:Arrays.asList("original_observation_id","original_model_run_id","original_action_sha256","purpose",
                    "effect_entered","worker_drained","action_replayed"))if(full.containsKey(key))small.put(key,full.get(key));
            small.put("complete_permit_sha256",axFingerprint(entered));small.put("grants_action_authority",false);
            out.put("entered_open_read_permit",small);
        }
        Object region=out.get("ctrip_form_action_region");
        if(region!=null){Map<String,Object> small=new TreeMap<String,Object>();Map<String,Object> full=axObject(region);
            small.put("schema",full.get("schema"));small.put("scope_sha256",axFingerprint(region));
            small.put("form_purpose_target_paths",full.get("form_purpose_target_paths"));
            small.put("fresh_same_scope_comparison_required",true);small.put("grants_action_authority",false);
            out.put("ctrip_form_action_region",small);
        }
        Map<String,Object> ref=new TreeMap<String,Object>();ref.put("file",artifact);ref.put("bytes",bytes);
        ref.put("sha256",digest);ref.put("part",part);out.put("complete_comparison_artifact",ref);
        return freeze(out);
    }

    private static final class Scope {
        final Set<String> roots=new TreeSet<String>(),ancestors=new TreeSet<String>();final Map<String,Object> facts=new TreeMap<String,Object>();
        void protect(Snapshot s,String path){Node n=s.node(path);need(n.usable(),"visible actual semantic container");roots.add(path);String p=path;
            while(true){Node a=s.node(p);need(a.usable()&&contains(a.bounds,n.bounds),"enabled actual containing ancestry");ancestors.add(p);if("0".equals(p))break;p=parent(p);}}
    }
    private static Scope form(Snapshot s){
        Scope out=new Scope();
        noOverlay(s);List<Node> values=new ArrayList<Node>();for(String name:FORM_IDS){Node n=oneId(s,CP+name);values.add(n);out.facts.put(name,n.v);}
        Node from=oneId(s,CP+"tv_depart_city"),to=oneId(s,CP+"tv_arrival_city"),date=oneId(s,CP+"tv_depart_date"),query=oneId(s,CP+"bt_submit_inquire");
        need("北京".equals(from.text)&&"上海".equals(to.text)&&"1成人".equals(oneId(s,CP+"tv_adult_count").text)&&"0儿童".equals(oneId(s,CP+"tv_child_count").text)&&"0婴儿".equals(oneId(s,CP+"tv_baby_count").text),"same supported route/passengers");
        need(date.click()&&query.click()&&"查 询".equals(query.text),"actual date and normal query controls");
        Matcher m=DATE.matcher(date.text);need(m.matches(),"literal full form date");LocalDate.of(2000,Integer.parseInt(m.group(1)),Integer.parseInt(m.group(2)));
        String originalScope=parent(parent(query.path));for(Node n:values)need(under(n.path,originalScope),"same actual form scope");
        Node trip=oneDesc(s,"单程"),round=oneDesc(s,"往返"),multi=oneDesc(s,"多程"),economy=oneDesc(s,"经济舱");
        need(b(trip.v,"selected")&&!b(round.v,"selected")&&!b(multi.v,"selected")&&parent(trip.path).equals(parent(round.path))&&parent(trip.path).equals(parent(multi.path))&&under(trip.path,parent(originalScope)),"actual single-trip choice");
        need(b(economy.v,"selected")&&under(economy.path,originalScope),"actual economy choice");
        for(Node n:Arrays.asList(trip,round,multi,economy)){values.add(n);out.facts.put(n.desc,n.v);}
        String root=commonParent(values);need(!"0".equals(root)&&!root.equals(parent(originalScope)),"bounded whole form container");
        out.protect(s,root);for(Node n:values)need(n.within(s.node(root)),"all semantic fields within actual form");
        out.facts.put("literal_departure_date",date.text);out.facts.put("year_inferred",false);
        return out;
    }
    private static Map<String,Object> roleFacts(Snapshot snapshot){
        Map<String,Object> out=new TreeMap<String,Object>();
        for(Node n:snapshot.nodes.values()){
            String id=n.view.startsWith(CP)?n.view.substring(CP.length()):"";
            if(FORM_IDS.contains(id)||Arrays.asList(TILE_IDS).contains(id)
                    ||"calendar_month_title_left_tv".equals(id)||"calendar_list".equals(id)
                    ||ROLES.contains(n.view)||ROLES.contains(n.desc)||"机票".equals(n.text))out.put(n.path,n.v);
        }
        return out;
    }
    private static boolean neutralFlags(Node node){
        for(String flag:Arrays.asList("editable","password","focused","checkable","checked","selected"))if(b(node.v,flag))return false;
        return true;
    }
    /** Roots are derived from complete, real ancestry and sibling relationships.
     * No numeric path (including 0/0/7) is whitelisted. All changed/new/deleted
     * descendants must be fully present in one of these fixed disjoint regions. */
    private static Set<String> anchors(Snapshot old,Snapshot fresh,Scope scope){Set<String> out=new TreeSet<String>();
        for(Node a:old.nodes.values()){
            if("0".equals(a.path)||scope.ancestors.contains(a.path)||protectedPath(a.path,scope.roots)||protectedPath(a.path,out))continue;
            boolean nested=!scope.ancestors.contains(parent(a.path));
            if(nested&&!nestedCtripBranch(old,fresh,scope,a))continue;
            Node z=fresh.nodes.get(a.path);if(z==null||!a.visible()||!z.visible())continue;
            if(nested&&(!passiveNestedBranch(old,a)||!passiveNestedBranch(fresh,z)))continue;
            Map<String,Object> x=new TreeMap<String,Object>(a.v),y=new TreeMap<String,Object>(z.v);
            for(String k:Arrays.asList("text","description","label","ref_signature_sha256","children")){x.remove(k);y.remove(k);}
            if(neutralHorizontalScrollMetadata(a,z)){x.remove("scroll_actions");y.remove("scroll_actions");}
            if(!x.equals(y))continue;boolean clear=true;
            for(String p:scope.roots)if(intersects(a.bounds,old.node(p).bounds))clear=false;
            if(clear&&neutral(old,a,scope)&&neutral(fresh,z,scope))out.add(a.path);
        }return out;
    }
    /** A partially overlapping outer container is never a variable region.
     * For this read-only Ctrip form pair only, a deeper region may be
     * considered when every intervening, non-protected ancestor is unchanged
     * in every census field and still contains the candidate's whole bounds.
     * The caller separately proves the candidate and all visible descendants
     * disjoint from the complete protected form in both full snapshots. */
    private static boolean nestedCtripBranch(Snapshot old,Snapshot fresh,Scope scope,Node candidate){
        String p=parent(candidate.path);
        for(int depth=0;depth<64;depth++){
            if(scope.ancestors.contains(p))return true;
            if("0".equals(p)||protectedPath(p,scope.roots))return false;
            Node a=old.nodes.get(p),z=fresh.nodes.get(p);
            if(a==null||z==null||!a.usable()||!z.usable()||!nestedCtripAncestor(a)||!nestedCtripAncestor(z)
                    ||!a.v.equals(z.v)||!contains(a.bounds,candidate.bounds)||!contains(z.bounds,candidate.bounds))return false;
            p=parent(p);
        }
        return false;
    }
    /** A stable containing pager may expose known horizontal navigation.
     * Other intermediate nodes remain passive; a clickable/scrolling descendant
     * cannot be bypassed by selecting an even smaller variable anchor below it. */
    private static boolean nestedCtripAncestor(Node node){
        if(!neutralFlags(node)||b(node.v,"clickable")||b(node.v,"action_click")
                ||!"hepta.observed-ime-enter.v1|true|false|null".equals(s(node.v,"ime_enter"))
                ||node.v.get("input_sha256")!=null)return false;
        if(!b(node.v,"scrollable"))return ("hepta.observed-scroll-actions.v1|observed").equals(s(node.v,"scroll_actions"));
        return ("androidx.viewpager.widget.ViewPager".equals(node.cls)
                ||"android.support.v4.view.ViewPager".equals(node.cls)
                ||"android.widget.HorizontalScrollView".equals(node.cls))
                &&knownHorizontalScrollActions(s(node.v,"scroll_actions"));
    }
    /** New nested regions have no observed input capability in either complete census.
     * Unknown action metadata is not absence. Existing direct sibling rules
     * retain their separate, narrower-purpose carousel contract. */
    private static boolean passiveNestedBranch(Snapshot snapshot,Node anchor){
        String emptyScroll="hepta.observed-scroll-actions.v1|observed";
        String absentIme="hepta.observed-ime-enter.v1|true|false|null";
        for(Node node:snapshot.nodes.values())if(node.path.equals(anchor.path)||under(node.path,anchor.path)){
            if(!neutralFlags(node)||b(node.v,"clickable")||b(node.v,"action_click")||b(node.v,"scrollable")
                    ||!emptyScroll.equals(s(node.v,"scroll_actions"))||!absentIme.equals(s(node.v,"ime_enter"))
                    ||node.v.get("input_sha256")!=null)return false;
        }
        return true;
    }
    /** Only metadata of an already proved disjoint, neutral carousel may vary.
     * Only this read-only form pairing uses the classification; no scroll gains authority. */
    private static boolean neutralHorizontalScrollMetadata(Node a,Node z){
        return "android.widget.HorizontalScrollView".equals(a.cls)&&a.cls.equals(z.cls)
                &&b(a.v,"scrollable")&&b(z.v,"scrollable")
                &&knownHorizontalScrollActions(s(a.v,"scroll_actions"))&&knownHorizontalScrollActions(s(z.v,"scroll_actions"));
    }
    private static boolean knownHorizontalScrollActions(String value){
        return value.matches("hepta\\.observed-scroll-actions\\.v1\\|observed(?:\\|forward)?(?:\\|backward)?(?:\\|left)?(?:\\|right)?")
                &&(value.contains("|left")||value.contains("|right"));
    }
    private static boolean neutral(Snapshot s,Node anchor,Scope scope){
        for(Node n:s.nodes.values())if(n.path.equals(anchor.path)||under(n.path,anchor.path)){
            for(String flag:Arrays.asList("editable","password","focused","checkable","checked","selected"))if(b(n.v,flag))return false;
            if(n.v.get("input_sha256")!=null||!"hepta.observed-ime-enter.v1|true|false|null".equals(s(n.v,"ime_enter")))return false;
            String actions=s(n.v,"scroll_actions");
            if(b(n.v,"scrollable")){
                if(!("android.widget.HorizontalScrollView".equals(n.cls)
                        ||"androidx.viewpager.widget.ViewPager".equals(n.cls)
                        ||"android.support.v4.view.ViewPager".equals(n.cls))||!knownHorizontalScrollActions(actions))return false;
            }else if(!"hepta.observed-scroll-actions.v1|observed".equals(actions))return false;
            if(n.visible()){
                if(!contains(anchor.bounds,n.bounds))return false;
                for(String p:scope.roots)if(intersects(n.bounds,s.node(p).bounds))return false;
            }
        }return true;
    }
    private static void noOverlay(Snapshot s){for(String role:Arrays.asList("列表页头部重新搜索","单程TripSwitcherCity","单程TripSwitcherDate"))need(!role(s,role),"research overlay veto");}
    private static boolean role(Snapshot s,String value){for(Node n:s.nodes.values())if(n.usable()&&value.equals(n.view)&&value.equals(n.desc))return true;return false;}
    private static List<Node> findId(Snapshot s,String id){List<Node> out=new ArrayList<Node>();for(Node n:s.nodes.values())if(n.usable()&&id.equals(n.view))out.add(n);return out;}
    private static Node oneId(Snapshot s,String id){List<Node> out=findId(s,id);need(out.size()==1,"unique resource: "+id);return out.get(0);}
    private static Node oneDesc(Snapshot s,String value){List<Node> out=new ArrayList<Node>();for(Node n:s.nodes.values())if(n.usable()&&"android.widget.LinearLayout".equals(n.cls)&&value.equals(n.desc))out.add(n);need(out.size()==1,"unique actual selection: "+value);return out.get(0);}
    private static String commonParent(List<Node> nodes){String p=parent(nodes.get(0).path);for(Node n:nodes)while(!under(n.path,p)){need(!"0".equals(p),"common actual ancestor");p=parent(p);}return p;}
    private static boolean protectedPath(String p,Set<String> roots){for(String root:roots)if(p.equals(root)||under(p,root))return true;return false;}
    private static boolean under(String p,String root){return p.startsWith(root+"/");}
    private static String parent(String p){int n=p.lastIndexOf('/');need(n>0,"actual parent missing");return p.substring(0,n);}
    private static int index(String p){return Integer.parseInt(p.substring(p.lastIndexOf('/')+1));}
    private static boolean path(String p){return p!=null&&p.length()<=240&&p.matches("0(?:/(?:0|[1-9][0-9]{0,3})){0,63}");}
    private static boolean contains(List<Integer> a,List<Integer> b){return a.get(0)<=b.get(0)&&a.get(1)<=b.get(1)&&a.get(2)>=b.get(2)&&a.get(3)>=b.get(3);}
    private static boolean intersects(List<Integer> a,List<Integer> b){return a.get(0)<b.get(2)&&b.get(0)<a.get(2)&&a.get(1)<b.get(3)&&b.get(1)<a.get(3);}
    private static Set<String> union(Set<String> a,Set<String> b){Set<String> out=new TreeSet<String>(a);out.addAll(b);return out;}
    private static String s(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof String,"string: "+k);return(String)v;}
    private static boolean b(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof Boolean,"actual boolean: "+k);return(Boolean)v;}
    private static int i(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof Integer,"integer: "+k);return(Integer)v;}
    private static long time(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof Long||v instanceof Integer,"integer time: "+k);return((Number)v).longValue();}
    private static void need(boolean yes,String message){if(!yes)throw new IllegalArgumentException(message);}
    private static Map<String,Object> freeze(Map<String,Object> m){Map<String,Object> out=new TreeMap<String,Object>();for(Map.Entry<String,Object> e:m.entrySet())out.put(e.getKey(),copy(e.getValue(),0));return Collections.unmodifiableMap(out);}
    private static Object copy(Object v,int depth){need(depth<16,"nesting budget");if(v==null||v instanceof String||v instanceof Boolean||v instanceof Integer||v instanceof Long)return v;
        if(v instanceof List){List<Object> out=new ArrayList<Object>();for(Object x:(List<?>)v)out.add(copy(x,depth+1));return Collections.unmodifiableList(out);}
        if(v instanceof Map){Map<String,Object> out=new TreeMap<String,Object>();for(Map.Entry<?,?> e:((Map<?,?>)v).entrySet()){need(e.getKey() instanceof String,"string key");out.put((String)e.getKey(),copy(e.getValue(),depth+1));}return Collections.unmodifiableMap(out);}throw new IllegalArgumentException("non-value in snapshot");}
}
