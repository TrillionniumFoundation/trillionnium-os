package org.trillionnium.hepta.local;

import java.util.*;
import org.trillionnium.hepta.local.NativeActionSnapshotCheck.Node;
import org.trillionnium.hepta.local.NativeActionSnapshotCheck.Snapshot;

/** Complete-census proof for the installed managed Xiaomi empty search editor.
 * Only the observed recommendation chips may vary inside their fixed, disjoint
 * ScrollView. This is neither a replacement graph nor an input capability.
 * The original model action, domain, NodeRef, final live chain and one claim
 * remain necessary. Every other node, including offscreen nodes, stays exact. */
final class NativeXiaomiSearchInputObservation {
    static final String PACKAGE="com.xiaomi.shop",PHASE="search_input",QUERY_PATH="0/1";
    static final long VERSION_CODE=20261010L;
    static final String BASE_APK_SHA256="95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373";
    private static final String FRAME="android.widget.FrameLayout",VIEW="android.view.ViewGroup",TEXT="android.widget.TextView";
    private static final String SCROLL="hepta.observed-scroll-actions.v1|observed",IME="hepta.observed-ime-enter.v1|true|false|null";
    private static final Set<String> VARIABLE=new TreeSet<String>(Arrays.asList("bounds","text","label","ref_signature_sha256","visible"));
    private NativeXiaomiSearchInputObservation(){}

    /** Reconstruct the exact comparison envelope from two complete AX values.
     * This adapter grants nothing and does not discard or rewrite any node. */
    static Map<String,Object> compareAxCensuses(Map<String,Object> first,Map<String,Object> second,
            Map<String,Object> binding,String installedSet){
        need(binding!=null,"actual original AX binding required");
        for(Map.Entry<String,Object> e:axMap(first,"identity").entrySet())
            need(binding.containsKey(e.getKey())&&Objects.equals(binding.get(e.getKey()),e.getValue()),"first input census/binding differs: "+e.getKey());
        need(Objects.equals(binding.get("profile_action_identity"),first.get("profile_owner"))
                &&Objects.equals(binding.get("profile_window"),first.get("profile_window")),"original input profile binding differs");
        Snapshot a=axSnapshot(first,binding,installedSet),b=axSnapshot(second,binding,installedSet);
        need(time(b.env,"captured_elapsed_ms")-time(a.env,"captured_elapsed_ms")<=12000,"original AX input-pair deadline");
        return compare(a,b);
    }
    private static Snapshot axSnapshot(Map<String,Object> census,Map<String,Object> binding,String installedSet){
        need(Boolean.TRUE.equals(census.get("complete"))&&Boolean.FALSE.equals(census.get("truncated")),"complete untruncated input AX census required");
        Map<String,Object> id=axMap(census,"identity"),window=axMap(census,"window"),profile=axMap(census,"profile_owner");
        requireAxWindow(census,id,window,profile);
        need(PACKAGE.equals(id.get("package"))&&installedSet!=null&&installedSet.matches("[0-9a-f]{64}"),"actual installed Xiaomi empty-input AX pair");
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
    private static void requireAxWindow(Map<String,Object> census,Map<String,Object> id,Map<String,Object> window,Map<String,Object> profile){
        for(String key:Arrays.asList("package","window_id","display_id","rotation","left","top","right","bottom","width","height"))
            need(Objects.equals(id.get(key),window.get(key)),"actual input window/identity differs: "+key);
        need(window.get("metadata") instanceof String&&!s(window,"metadata").isEmpty(),"complete actual input window metadata");
        Map<String,Object> report=axMap(census,"reported_windows");
        need(report.keySet().equals(new TreeSet<String>(Arrays.asList("display_id","other_window_roots_traversed","target_layer","target_window_id","unreported_windows_excluded","windows")))
                &&Objects.equals(report.get("display_id"),id.get("display_id"))&&Objects.equals(report.get("target_window_id"),id.get("window_id"))
                &&Boolean.FALSE.equals(report.get("other_window_roots_traversed"))&&Boolean.FALSE.equals(report.get("unreported_windows_excluded")),"complete explicit reported input window set");
        Object raw=report.get("windows");need(raw instanceof List&&((List<?>)raw).size()==1,"one actual focused application window required");
        Map<String,Object> actual=axObject(((List<?>)raw).get(0));
        need(actual.keySet().equals(new TreeSet<String>(Arrays.asList("active","bounds","display_id","focused","layer","type","window_id")))
                &&actual.get("active") instanceof Boolean&&Boolean.TRUE.equals(actual.get("focused"))
                &&Integer.valueOf(1).equals(actual.get("type"))&&Objects.equals(actual.get("window_id"),id.get("window_id"))
                &&Objects.equals(actual.get("display_id"),id.get("display_id"))&&Objects.equals(actual.get("layer"),report.get("target_layer"))
                &&actual.get("layer") instanceof Integer
                &&Objects.equals(actual.get("bounds"),Arrays.asList(id.get("left"),id.get("top"),id.get("right"),id.get("bottom"))),"actual target application window differs");
        Map<String,Object> owner=axMap(census,"profile_window");
        String[][] names={{"profile_target_sha256","target_identity_sha256"},{"profile_user_id","user_id"},
                {"profile_user_serial","user_serial"},{"profile_full_uid","full_uid"},{"profile_task_id","task_id"},
                {"profile_parent_task_id","parent_task_id"},{"profile_task_token_id","task_token_id"}};
        need(profile.keySet().equals(NativeActionSnapshotCheck.PROFILE_IDENTITY),"complete managed profile owner");
        for(String[] pair:names)need(Objects.equals(profile.get(pair[0]),owner.get(pair[1])),"profile owner/window differs: "+pair[0]);
        need(Objects.equals(owner.get("generation"),id.get("background_generation"))
                &&Objects.equals(owner.get("display_id"),id.get("display_id"))&&Objects.equals(owner.get("window_id"),id.get("window_id")),"actual profile display/window/generation differs");
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

    static Map<String,Object> compare(Snapshot before,Snapshot after){return compare(before,after,null);}
    /** Separate filled-button action predicate; never admits historical input
     * publication or relaxes the existing empty-editor observation predicate. */
    static Map<String,Object> compareFilledQuery(Snapshot before,Snapshot after,String literal){
        need("AX3000T".equalsIgnoreCase(literal),"supported immutable product literal required");
        return compare(before,after,literal);
    }
    private static Map<String,Object> compare(Snapshot before,Snapshot after,String literal){
        need(before!=null&&after!=null,"two complete actual input censuses");
        need(before.env.keySet().equals(NativeActionSnapshotCheck.PROFILE_ENVELOPE)
                &&after.env.keySet().equals(NativeActionSnapshotCheck.PROFILE_ENVELOPE),"managed-profile input only");
        need(PACKAGE.equals(s(before.env,"package"))&&PACKAGE.equals(s(after.env,"package")),"Xiaomi input only");
        long first=time(before.env,"captured_elapsed_ms"),last=time(after.env,"captured_elapsed_ms");
        need(last>=first&&last-first<=90000,"original input observation age");
        Map<String,Object> a=new TreeMap<String,Object>(before.env),b=new TreeMap<String,Object>(after.env);
        a.remove("captured_elapsed_ms");b.remove("captured_elapsed_ms");
        need(a.equals(b),"input window/display/IME/owner/installation/profile differs");
        need(before.nodes.keySet().equals(after.nodes.keySet()),"complete input node membership changed");
        Template left=template(before,literal),right=template(after,literal);
        need(left.chips.equals(right.chips)&&left.carousel.equals(right.carousel),"recommendation membership changed");
        List<String> changed=new ArrayList<String>();
        for(String path:before.nodes.keySet()){
            Node x=before.node(path),y=after.node(path);if(x.v.equals(y.v))continue;
            need(left.chips.contains(path)||left.carousel.equals(path),"change outside complete recommendation regions: "+path);
            Map<String,Object> old=new TreeMap<String,Object>(x.v),fresh=new TreeMap<String,Object>(y.v);
            Set<String> fields=left.carousel.equals(path)?new TreeSet<String>(Arrays.asList("scroll_actions","ref_signature_sha256")):VARIABLE;
            for(String key:fields){old.remove(key);fresh.remove(key);}
            need(old.equals(fresh),"recommendation capability/structure changed: "+path);changed.add(path);
        }
        Map<String,Object> out=new TreeMap<String,Object>();
        out.put("schema",literal==null?"hepta.xiaomi-native-empty-search-input-pair.v1":"hepta.xiaomi-native-filled-query-pair.v1");
        out.put("phase",literal==null?PHASE:"search_submit");
        out.put("toolbar_shape","observed_frame_layout_direct_children.v1");out.put("query_path",QUERY_PATH);
        out.put("empty_query",literal==null);out.put("literal_goal_revalidated_by_session",false);
        if(literal!=null){out.put("query_literal",literal);out.put("normal_search_path","0/2");}
        out.put("before_snapshot_sha256",before.sha);out.put("after_snapshot_sha256",after.sha);
        out.put("before_visited_nodes",before.nodes.size());out.put("after_visited_nodes",after.nodes.size());
        out.put("protected_subtrees",Arrays.asList("0/0","0/1","0/2","0/3","0/4","0/5"));
        out.put("checked_ancestors",Collections.singletonList("0"));
        out.put("variable_branch_anchors",Collections.singletonList("0/6"));out.put("variable_chip_paths",new ArrayList<String>(left.chips));
        out.put("variable_carousel_path",left.carousel);out.put("variable_carousel_fields",Arrays.asList("scroll_actions","ref_signature_sha256"));
        out.put("changed_paths",changed);out.put("changed_paths_truncated",false);out.put("full_census_compared",true);
        out.put("whole_graph_equal",changed.isEmpty());out.put("published_pair_is_current_tree_claimed",false);
        out.put("fixed_disjoint_enclosure",before.node("0/6").bounds);out.put("all_coordinates_checked_without_normalization",true);
        out.put("fresh_action_validation_required",true);out.put("grants_action_authority",false);
        out.put("query_dispatched",false);out.put("business_completion_verified",false);
        return ObservationCaptureEvidence.freezeMap(out);
    }
    private static final class Template {
        final Set<String> chips;final String carousel;
        Template(Set<String> chips,String carousel){this.chips=chips;this.carousel=carousel;}
    }
    private static Template template(Snapshot snapshot,String literal){
        boolean filled=literal!=null;
        Node root=snapshot.node("0"),field=snapshot.node(QUERY_PATH),toggle=snapshot.node("0/0"),normal=snapshot.node(filled?"0/2":"0/4");
        need(FRAME.equals(root.cls)&&root.parent.isEmpty()&&root.usable()&&root.children==7
                &&root.text.isEmpty()&&root.desc.isEmpty()&&root.view.isEmpty()&&!b(root.v,"clickable")
                &&!b(root.v,"action_click")&&passiveMetadata(root),"complete direct-root editor");
        need("android.widget.EditText".equals(field.cls)&&FRAME.equals(field.parent)&&field.usable()
                &&field.children==0&&field.view.isEmpty()&&(filled?literal.equals(field.text):field.text.isEmpty())&&field.desc.isEmpty()
                &&(filled?literal:"").equals(field.label)&&b(field.v,"editable")&&b(field.v,"clickable")&&b(field.v,"action_click")
                &&!b(field.v,"scrollable")&&SCROLL.equals(s(field.v,"scroll_actions"))&&IME.equals(s(field.v,"ime_enter"))
                &&(filled?ObservedImeEnter.completeTextHash(literal).equals(field.v.get("input_sha256")):field.v.get("input_sha256")==null)
                &&neutralSelection(field),"original unique exact query field");
        NativeActionSnapshotCheck.requireSearchInputReference(snapshot,field);
        int edits=0,searchLabels=0;
        for(Node node:snapshot.nodes.values()){
            if(b(node.v,"editable"))edits++;
            if(node.usable()&&"搜索".equals(node.text))searchLabels++;
        }
        need(edits==1&&searchLabels==2,"unique editor and two explicit search labels");
        toolbarButton(snapshot,toggle);toolbarButton(snapshot,normal);
        need(toggle.bounds.get(2)<normal.bounds.get(0)&&toggle.bounds.get(0)<=field.bounds.get(0)
                &&normal.bounds.get(2)>=field.bounds.get(2)&&toggle.bounds.get(1)>=field.bounds.get(1)
                &&normal.bounds.get(1)>=field.bounds.get(1)
                &&Math.min(toggle.bounds.get(3),normal.bounds.get(3))>Math.max(toggle.bounds.get(1),normal.bounds.get(1)),"normal search and mode toggle remain distinct");
        Node enclosure=snapshot.node("0/6");
        need("android.widget.ScrollView".equals(enclosure.cls)&&FRAME.equals(enclosure.parent)&&enclosure.usable()
                &&enclosure.children>=3&&enclosure.children<=128&&!b(enclosure.v,"clickable")&&!b(enclosure.v,"action_click")
                &&b(enclosure.v,"scrollable")&&neutralSelection(enclosure)&&!b(enclosure.v,"editable")
                &&enclosure.text.isEmpty()&&enclosure.desc.isEmpty()&&enclosure.view.isEmpty()
                &&s(enclosure.v,"scroll_actions").matches("hepta\\.observed-scroll-actions\\.v1\\|observed(?:\\|forward)?(?:\\|backward)?(?:\\|up)?(?:\\|down)?")
                &&IME.equals(s(enclosure.v,"ime_enter"))&&enclosure.v.get("input_sha256")==null,"fixed complete recommendation ScrollView");
        int bottom=0;for(int i=0;i<6;i++){
            Node n=snapshot.node("0/"+i);need(FRAME.equals(n.parent)&&coordinatesWithin(root,n),"actual root child containment");
            // Filled search moves its two static suggestion panels to 0/4 and
            // 0/5. They remain byte-exact protected subtrees; only 0/0..0/3
            // form the actual query/action toolbar above the fixed enclosure.
            if(!filled||i<4)bottom=Math.max(bottom,Math.max(n.bounds.get(1),n.bounds.get(3)));
        }
        need(enclosure.bounds.get(1)>=bottom&&coordinatesWithin(root,enclosure),"recommendations disjoint from entire query/action toolbar");
        int recommendationStart=0;
        if("搜索历史".equals(snapshot.node("0/6/0").text)){
            requireSingleHistoryPrefix(snapshot,enclosure);
            recommendationStart=2;
        }
        Node heading=snapshot.node("0/6/"+recommendationStart),refresh=snapshot.node("0/6/"+(recommendationStart+1));
        need(TEXT.equals(heading.cls)&&"android.widget.ScrollView".equals(heading.parent)&&heading.children==0
                &&heading.usable()&&"猜你想搜".equals(heading.text)&&!b(heading.v,"clickable")
                &&!b(heading.v,"action_click")&&passiveMetadata(heading)&&coordinatesWithin(enclosure,heading),"actual recommendation section heading");
        need(VIEW.equals(refresh.cls)&&"android.widget.ScrollView".equals(refresh.parent)&&refresh.children==0
                &&refresh.usable()&&refresh.text.isEmpty()&&refresh.desc.isEmpty()&&refresh.view.isEmpty()
                &&b(refresh.v,"clickable")&&b(refresh.v,"action_click")&&passiveMetadata(refresh)
                &&coordinatesWithin(enclosure,refresh),"same observed recommendation refresh control");
        Set<String> chips=new TreeSet<String>();Node carousel=null;
        for(int index=recommendationStart+2;index<enclosure.children;index++){
            Node chip=snapshot.node("0/6/"+index);
            if(!VIEW.equals(chip.cls)||chip.children!=1){carousel=chip;break;}
            need(index<34,"bounded complete recommendation chip run");
            Node text=snapshot.node(chip.path+"/0");
            need("android.widget.ScrollView".equals(chip.parent)&&chip.view.isEmpty()&&chip.text.isEmpty()&&chip.desc.isEmpty()
                    &&b(chip.v,"clickable")&&b(chip.v,"action_click")&&b(chip.v,"enabled")&&passiveMetadata(chip)
                    &&TEXT.equals(text.cls)&&VIEW.equals(text.parent)&&text.children==0&&text.view.isEmpty()&&text.desc.isEmpty()
                    &&!text.text.trim().isEmpty()&&!b(text.v,"clickable")&&!b(text.v,"action_click")&&b(text.v,"enabled")
                    &&passiveMetadata(text),"complete unchanged chip capabilities");
            need(coordinatesWithin(enclosure,chip)&&coordinatesWithin(enclosure,text),"all changed chip coordinates remain in fixed enclosure");
            NativeActionSnapshotCheck.requireSearchInputReference(snapshot,chip);
            NativeActionSnapshotCheck.requireSearchInputReference(snapshot,text);
            chips.add(chip.path);chips.add(text.path);
        }
        need(!chips.isEmpty()&&carousel!=null,"complete recommendation chips and their next carousel required");
        need("android.widget.HorizontalScrollView".equals(carousel.cls)&&"android.widget.ScrollView".equals(carousel.parent)
                &&carousel.children==0&&carousel.usable()&&carousel.text.isEmpty()&&carousel.desc.isEmpty()&&carousel.view.isEmpty()
                &&"".equals(carousel.label)&&!b(carousel.v,"clickable")&&!b(carousel.v,"action_click")
                &&!b(carousel.v,"editable")&&b(carousel.v,"scrollable")&&neutralSelection(carousel)
                &&IME.equals(s(carousel.v,"ime_enter"))&&carousel.v.get("input_sha256")==null
                &&Arrays.asList(SCROLL+"|forward|right",SCROLL+"|backward|left",SCROLL+"|forward|backward|left|right")
                    .contains(s(carousel.v,"scroll_actions"))
                &&coordinatesWithin(enclosure,carousel),"fixed passive horizontal carousel leaf and known boundary directions");
        NativeActionSnapshotCheck.requireSearchInputReference(snapshot,carousel);
        return new Template(chips,carousel.path);
    }
    /** The recorded one-item history prefix is protected, never variable.
     * It grants no history-item click or query submission. The complete pair
     * comparison still requires every prefix node to be byte-for-byte equal. */
    private static void requireSingleHistoryPrefix(Snapshot snapshot,Node enclosure){
        Node heading=snapshot.node("0/6/0"),item=snapshot.node("0/6/1"),text=snapshot.node("0/6/1/0");
        need(TEXT.equals(heading.cls)&&"android.widget.ScrollView".equals(heading.parent)&&heading.children==0
                &&heading.usable()&&heading.view.isEmpty()&&heading.desc.isEmpty()
                &&"搜索历史".equals(heading.text)&&"搜索历史".equals(heading.label)
                &&!b(heading.v,"clickable")&&!b(heading.v,"action_click")&&passiveMetadata(heading)
                &&coordinatesWithin(enclosure,heading),"complete observed search-history heading");
        need(VIEW.equals(item.cls)&&"android.widget.ScrollView".equals(item.parent)&&item.children==1
                &&item.click()&&item.view.isEmpty()&&item.text.isEmpty()&&item.desc.isEmpty()
                &&"AX3000T".equals(item.label)&&passiveMetadata(item)
                &&TEXT.equals(text.cls)&&VIEW.equals(text.parent)&&text.children==0&&text.usable()
                &&text.view.isEmpty()&&text.desc.isEmpty()&&"AX3000T".equals(text.text)&&"AX3000T".equals(text.label)
                &&!b(text.v,"clickable")&&!b(text.v,"action_click")&&passiveMetadata(text)
                &&coordinatesWithin(enclosure,item)&&coordinatesWithin(item,text)
                &&heading.bounds.get(3)<=item.bounds.get(1)
                &&item.bounds.get(3)<=snapshot.node("0/6/2").bounds.get(1),"complete observed single search-history item");
        NativeActionSnapshotCheck.requireSearchInputReference(snapshot,heading);
        NativeActionSnapshotCheck.requireSearchInputReference(snapshot,item);
        NativeActionSnapshotCheck.requireSearchInputReference(snapshot,text);
    }
    private static void toolbarButton(Snapshot s,Node button){
        Node label=s.node(button.path+"/0");
        need(VIEW.equals(button.cls)&&FRAME.equals(button.parent)&&button.children==1&&button.click()
                &&button.view.isEmpty()&&button.text.isEmpty()&&button.desc.isEmpty()&&"搜索".equals(button.label)
                &&passiveMetadata(button)&&TEXT.equals(label.cls)&&VIEW.equals(label.parent)&&label.children==0
                &&label.usable()&&label.view.isEmpty()&&"搜索".equals(label.text)&&label.desc.isEmpty()
                &&"搜索".equals(label.label)&&!b(label.v,"clickable")&&!b(label.v,"action_click")
                &&passiveMetadata(label)&&coordinatesWithin(button,label),"complete actual search control/label");
        NativeActionSnapshotCheck.requireSearchInputReference(s,button);NativeActionSnapshotCheck.requireSearchInputReference(s,label);
    }
    private static boolean neutralSelection(Node n){
        return !b(n.v,"password")&&!b(n.v,"focused")&&!b(n.v,"selected")&&!b(n.v,"checked")&&!b(n.v,"checkable");
    }
    private static boolean passiveMetadata(Node n){return neutralSelection(n)&&!b(n.v,"editable")&&!b(n.v,"scrollable")
            &&SCROLL.equals(s(n.v,"scroll_actions"))&&IME.equals(s(n.v,"ime_enter"))&&n.v.get("input_sha256")==null;}
    /** Keep Android's clipped coordinates verbatim, including reversed hidden
     * endpoints. Both endpoints must still be inside the fixed disjoint region. */
    private static boolean coordinatesWithin(Node a,Node b){return b.bounds.get(0)>=a.bounds.get(0)&&b.bounds.get(0)<=a.bounds.get(2)
            &&b.bounds.get(2)>=a.bounds.get(0)&&b.bounds.get(2)<=a.bounds.get(2)
            &&b.bounds.get(1)>=a.bounds.get(1)&&b.bounds.get(1)<=a.bounds.get(3)
            &&b.bounds.get(3)>=a.bounds.get(1)&&b.bounds.get(3)<=a.bounds.get(3);}
    private static String s(Map<String,Object> m,String k){return NativeActionSnapshotCheck.s(m,k);}
    private static boolean b(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof Boolean,"actual boolean: "+k);return(Boolean)v;}
    private static long time(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof Integer||v instanceof Long,"actual elapsed time: "+k);return((Number)v).longValue();}
    private static void need(boolean ok,String why){if(!ok)throw new IllegalArgumentException(why);}
}
