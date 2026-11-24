package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;

/** Complete recorded d7 censuses and explicit counterfactual refusals.
 * No Android ports, PhoneObservation, Session, permission or input is created.
 * The recorded type rejection contains only a partial current diagnostic;
 * a synthetic direction-mask case is never represented as that missing census. */
public final class NativeXiaomiSearchInputHostTest {
    private static final String SCROLL="hepta.observed-scroll-actions.v1|observed";
    private static final String AX_NAME="a57e1dedb06a4e739823379bd472f953-native-ax.json";
    private static final List<Map<String,Object>> RESULTS=new ArrayList<Map<String,Object>>();
    private static JSONObject fixture,ax,failed,action;
    private static String installed;
    private static int assertions;
    interface Test {void run()throws Exception;}
    interface Change {void run(JSONObject value)throws Exception;}
    private NativeXiaomiSearchInputHostTest(){}
    static void check(boolean ok,String reason){assertions++;if(!ok)throw new AssertionError(reason);}
    static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    static void one(String name,String inputKind,Test test){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);row.put("input_kind",inputKind);
        try{test.run();row.put("passed",true);}
        catch(Throwable error){row.put("passed",false);row.put("error",error.toString());
            java.io.StringWriter trace=new java.io.StringWriter();error.printStackTrace(new java.io.PrintWriter(trace));row.put("stack",trace.toString());}
        RESULTS.add(row);
    }
    static void denied(Test test)throws Exception{
        boolean rejected=false;try{test.run();}catch(IllegalArgumentException|IllegalStateException expected){rejected=true;}
        check(rejected,"actual pure predicate must refuse this counterfactual");
    }
    static String hash(String value)throws Exception{
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder out=new StringBuilder();for(byte b:digest)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
    }
    static JSONObject source(String name){return new JSONObject(fixture.getJSONObject("source_files").getJSONObject(name).getString("raw_utf8"));}
    static JSONObject node(JSONObject value,String path){
        JSONArray nodes=value.getJSONArray("nodes");for(int i=0;i<nodes.length();i++){JSONObject n=nodes.getJSONObject(i);if(path.equals(n.getString("path")))return n;}
        throw new AssertionError("test fixture has no node "+path);
    }
    static JSONObject rawNode(JSONObject value,String path){
        JSONArray nodes=value.getJSONArray("native_nodes");for(int i=0;i<nodes.length();i++){JSONObject n=nodes.getJSONObject(i);if(path.equals(n.getString("path")))return n;}
        throw new AssertionError("recorded endpoint has no node "+path);
    }
    static void canonical(Object value,StringBuilder out){
        if(value==null){out.append('n');return;}
        if(value instanceof String){String s=(String)value;out.append('s').append(s.getBytes(StandardCharsets.UTF_8).length).append(':').append(s);return;}
        if(value instanceof Boolean){out.append(Boolean.TRUE.equals(value)?'t':'f');return;}
        if(value instanceof Integer||value instanceof Long){out.append('i').append(value).append(';');return;}
        if(value instanceof List){out.append('[');for(Object v:(List<?>)value)canonical(v,out);out.append(']');return;}
        if(value instanceof Map){Map<String,Object> sorted=new TreeMap<String,Object>();
            for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())sorted.put((String)e.getKey(),e.getValue());
            out.append('{');for(Map.Entry<String,Object> e:sorted.entrySet()){canonical(e.getKey(),out);canonical(e.getValue(),out);}out.append('}');return;}
        throw new AssertionError("unrecognized fixture scalar");
    }
    static String windowHash(JSONObject report)throws Exception{StringBuilder b=new StringBuilder();canonical(report.toMap(),b);return hash(b.toString());}
    /** Full original node values. Only missing comparison-envelope clocks and
     * installed/observation bindings are supplied from explicit recorded carriers. */
    static JSONObject endpoint(String side)throws Exception{
        JSONObject raw=failed.getJSONObject(side),read=raw.getJSONObject("read"),env=copy(raw.getJSONObject("identity"));
        env.put("installed_set_sha256",installed).put("origin_observation_id",ax.getJSONObject("binding").getString("observation_id"))
            .put("window_metadata_sha256",raw.getString("window_metadata_sha256"))
            .put("reported_windows_sha256",windowHash(read.getJSONObject("reported_windows")))
            .put("reported_windows_complete",read.getBoolean("reported_windows_complete"))
            .put("ime_visibility",read.getString("ime_visibility"))
            .put("captured_elapsed_ms",read.getLong("read_completed_elapsed_ms"))
            .put("full_native_complete",read.getBoolean("native_observation_complete"))
            .put("visited",read.getInt("visited_nodes")).put("pending",read.getInt("pending_nodes_at_stop"))
            .put("node_omissions",read.getInt("nodes_omitted_by_node_limit"))
            .put("text_omissions",read.getInt("nodes_omitted_by_text_limit"))
            .put("child_omissions",read.getInt("child_slots_omitted_by_traversal_limit"));
        return new JSONObject().put("envelope",env).put("nodes",new JSONArray(raw.getJSONArray("native_nodes").toString()));
    }
    static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject value){
        List<NativeActionSnapshotCheck.Node> nodes=new ArrayList<NativeActionSnapshotCheck.Node>();JSONArray raw=value.getJSONArray("nodes");
        for(int i=0;i<raw.length();i++)nodes.add(new NativeActionSnapshotCheck.Node(raw.getJSONObject(i).toMap()));
        return new NativeActionSnapshotCheck.Snapshot(value.getJSONObject("envelope").toMap(),nodes);
    }
    static Map<String,Object> compare(JSONObject a,JSONObject b){return NativeXiaomiSearchInputObservation.compare(snapshot(a),snapshot(b));}
    static Map<String,Object> compareAx(JSONObject a,JSONObject b,JSONObject binding){
        return NativeXiaomiSearchInputObservation.compareAxCensuses(a.toMap(),b.toMap(),binding.toMap(),installed);
    }
    static void noAuthority(Map<String,Object> proof){
        for(String key:Arrays.asList("grants_action_authority","query_dispatched","business_completion_verified","published_pair_is_current_tree_claimed","literal_goal_revalidated_by_session"))
            check(Boolean.FALSE.equals(proof.get(key)),"no authority/completion claim: "+key);
        check(Boolean.TRUE.equals(proof.get("full_census_compared")),"entire census compared");
        check(Boolean.TRUE.equals(proof.get("fresh_action_validation_required")),"fresh action still required");
        check(Boolean.FALSE.equals(proof.get("changed_paths_truncated")),"complete changed path list");
    }
    static Map<String,Object> nodeMap(JSONArray rows){
        Map<String,Object> out=new TreeMap<String,Object>();for(int i=0;i<rows.length();i++){JSONObject n=rows.getJSONObject(i);check(out.put(n.getString("path"),n.toMap())==null,"unique recorded paths");}return out;
    }
    static String flags(JSONObject n){
        StringBuilder s=new StringBuilder();for(String key:Arrays.asList("clickable","editable","scrollable","enabled","focused","password","selected","checkable","checked")){
            if(s.length()>0)s.append('|');s.append(n.getBoolean(key));}
        return s.append('|').append(n.getString("scroll_actions")).append('|').append(n.getString("ime_enter")).append('|')
                .append(n.isNull("input_sha256")?"null":n.getString("input_sha256")).toString();
    }
    /** Independent leaf-signature assembly. Used only for the explicitly
     * synthetic passive carousel; recorded references are never rewritten. */
    static void refreshLeafReference(JSONObject n)throws Exception{
        check(n.getInt("children")==0&&!n.getBoolean("clickable"),"counterfactual reference helper only handles passive leaves");
        JSONArray r=n.getJSONArray("bounds");String rect="Rect("+r.getInt(0)+", "+r.getInt(1)+" - "+r.getInt(2)+", "+r.getInt(3)+")";
        String sep=String.valueOf((char)1);
        String base=hash(n.getString("package")+sep+n.getInt("window_id")+sep+n.getString("class")+sep+n.getString("view_id")+sep+rect+sep
                +n.getString("text")+sep+n.getString("description")+sep+n.getBoolean("enabled")+"|"+n.getBoolean("clickable")+"|"+n.getBoolean("editable")+"|"+n.getBoolean("scrollable"));
        String full=ObservedChildText.notApplicable().bind(base)+"\nscroll_actions="+n.getString("scroll_actions")
                +"\nime_enter="+n.getString("ime_enter")+"|focused="+n.getBoolean("focused")+"|full_input="+(n.isNull("input_sha256")?"null":n.getString("input_sha256"));
        n.put("ref_signature_sha256",hash(full));
    }
    static void mutateSecond(String name,Change change){
        one(name,"synthetic_negative_from_recorded_nodes",()->{JSONObject a=endpoint("before"),b=endpoint("after");change.run(b);denied(()->compare(a,b));});
    }
    static void mutateBoth(String name,Change change){
        one(name,"synthetic_negative_on_both_endpoints",()->{JSONObject a=endpoint("before"),b=endpoint("after");change.run(a);change.run(b);denied(()->compare(a,b));});
    }
    static void mutateAx(String name,Change change){
        one(name,"synthetic_negative_from_recorded_ax",()->{JSONObject a=copy(ax.getJSONObject("first")),b=copy(ax.getJSONObject("second"));change.run(b);denied(()->compareAx(a,b,copy(ax.getJSONObject("binding"))));});
    }
    /** Explicit synthetic carrier for the established Ctrip fixture. It shares
     * no recorded Xiaomi app identity, and creates no Android authority. */
    static JSONObject history(boolean form)throws Exception{
        JSONObject receipt=copy(ax);
        if(form){
            NativeActionSnapshotCheckHostTest.Fixture f=FormPairHostTest.managedForm();
            NativeActionSnapshotCheck.Snapshot sample=f.snapshot();
            JSONObject identity=copy(receipt.getJSONObject("first").getJSONObject("identity"));
            String[][] names={{"task_id","task_id"},{"owner_sha256","owner_sha256"},{"execution_target_sha256","target_sha256"},
                    {"task_authorization_sha256","authorization_sha256"},{"actual_selection_sha256","selection_sha256"},
                    {"native_goal_sha256","goal_sha256"},{"background_generation","background_generation"},{"package","package"},
                    {"display_id","display_id"},{"window_id","window_id"},{"rotation","rotation"},{"width","width"},{"height","height"}};
            for(String[] name:names)identity.put(name[0],sample.env.get(name[1]));
            List<?> bounds=(List<?>)sample.env.get("root_bounds");
            for(int i=0;i<4;i++)identity.put(Arrays.asList("left","top","right","bottom").get(i),bounds.get(i));
            identity.put("app_tree_sha256",hash("synthetic_ctrip_form_tree")).put("observation_state_sha256",hash("synthetic_ctrip_form_state"));
            JSONObject owner=new JSONObject();for(String k:NativeActionSnapshotCheck.PROFILE_IDENTITY)owner.put(k,sample.env.get(k));
            JSONObject profile=copy(receipt.getJSONObject("first").getJSONObject("profile_window"));
            String[][] profileNames={{"profile_target_sha256","target_identity_sha256"},{"profile_user_id","user_id"},
                    {"profile_user_serial","user_serial"},{"profile_full_uid","full_uid"},{"profile_task_id","task_id"},
                    {"profile_parent_task_id","parent_task_id"},{"profile_task_token_id","task_token_id"}};
            for(String[] name:profileNames)profile.put(name[1],sample.env.get(name[0]));
            profile.put("generation",sample.env.get("background_generation")).put("display_id",sample.env.get("display_id")).put("window_id",sample.env.get("window_id"));
            for(String side:Arrays.asList("first","second")){
                JSONObject c=receipt.getJSONObject(side),window=copy(c.getJSONObject("window"));
                for(String k:Arrays.asList("package","window_id","display_id","rotation","left","top","right","bottom","width","height"))window.put(k,identity.get(k));
                window.put("metadata","synthetic_complete_ctrip_form_window");
                JSONObject windows=copy(c.getJSONObject("reported_windows")),w=windows.getJSONArray("windows").getJSONObject(0);
                windows.put("display_id",identity.get("display_id")).put("target_window_id",identity.get("window_id"));
                w.put("display_id",identity.get("display_id")).put("window_id",identity.get("window_id")).put("bounds",new JSONArray(bounds));
                JSONArray nodes=new JSONArray();for(NativeActionSnapshotCheck.Node n:sample.nodes.values()){
                    JSONObject full=new JSONObject();for(Map.Entry<String,Object> e:n.v.entrySet())full.put(e.getKey(),e.getValue()==null?JSONObject.NULL:e.getValue());
                    nodes.put(full);}
                c.put("identity",copy(identity)).put("profile_owner",copy(owner)).put("profile_window",copy(profile))
                    .put("window",window).put("reported_windows",windows).put("nodes",nodes).put("visited",nodes.length()).put("retained",nodes.length());
            }
            JSONObject binding=receipt.getJSONObject("binding");for(String k:identity.keySet())binding.put(k,identity.get(k));
            binding.put("observation_id",sample.env.get("origin_observation_id")).put("profile_action_identity",copy(owner)).put("profile_window",copy(profile));
        }
        String set=form?NativeActionSnapshotCheckHostTest.H:installed;
        Map<String,Object> proof=form
                ?NativeCtripFormObservation.compareAxCensuses(receipt.getJSONObject("first").toMap(),receipt.getJSONObject("second").toMap(),receipt.getJSONObject("binding").toMap(),set)
                :compareAx(receipt.getJSONObject("first"),receipt.getJSONObject("second"),receipt.getJSONObject("binding"));
        JSONObject h=new JSONObject().put("phase",form?"ctrip_single_flight_form":"search_input").put("installed_set_sha256",set)
                .put("provider_version_code",form?1779:20261010)
                .put("provider_base_apk_sha256",form?"666ce1e8234682c89247d5109c5cfa36451c6e67238ee38a545c2d84c88360fa":"95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373")
                .put("comparison",new JSONObject(new String(ObservationCaptureEvidence.canonicalBytes(proof),StandardCharsets.UTF_8)));
        receipt.put("schema",form?"hepta.native-ax-form-history.v1":"hepta.native-ax-empty-search-input-history.v1")
                .put("kind",form?ObservationCaptureEvidence.NATIVE_AX_FORM_HISTORY:ObservationCaptureEvidence.NATIVE_AX_INPUT_HISTORY)
                .put(form?"form_history":"input_history",h).put(form?"historical_form_planning_only":"historical_empty_input_planning_only",true)
                .put("published_pair_is_current_tree_claimed",false);
        return receipt;
    }
    static ObservationCaptureEvidence sealHistory(JSONObject receipt,boolean form){
        Map<String,Object> value=receipt.toMap();
        byte[] bytes=form?ObservationCaptureEvidence.nativeAxFormHistoryBytes(value):ObservationCaptureEvidence.nativeAxInputHistoryBytes(value);
        return form?ObservationCaptureEvidence.fromSealedNativeAxFormHistory(value,bytes,ObservationCaptureEvidence.hash(bytes))
                :ObservationCaptureEvidence.fromSealedNativeAxInputHistory(value,bytes,ObservationCaptureEvidence.hash(bytes));
    }
    static void historyCases(){
        one("synthetic_valid_ctrip_history_control","synthetic_existing_form_fixture",()->{
            ObservationCaptureEvidence proof=sealHistory(history(true),true);
            check(proof.formHistory()&&!proof.inputHistory()&&proof.planningHistory(),"valid existing form-history control");
            check(Boolean.FALSE.equals(proof.evidence().get("grants_action_authority")),"form control grants nothing");
        });
        one("input_history_from_actual_equal_ax_is_planning_only","synthetic_receipt_wrapper_over_recorded_ax",()->{
            ObservationCaptureEvidence proof=sealHistory(history(false),false);
            check(proof.inputHistory()&&!proof.formHistory()&&proof.planningHistory(),"explicit input-only kind");
            check(Boolean.FALSE.equals(proof.evidence().get("grants_action_authority")),"input receipt grants nothing");
            proof.requireInputHistoryTarget("0/1");
            for(String path:Arrays.asList("0/4","0/6/2","0/6/12"))denied(()->proof.requireInputHistoryTarget(path));
        });
        for(boolean form:Arrays.asList(Boolean.FALSE,Boolean.TRUE)){
            final boolean isForm=form;
            one((form?"form":"input")+"_history_rejects_other_kind_object","synthetic_cross_kind_negative",()->{
                JSONObject r=history(isForm);r.put(isForm?"input_history":"form_history",new JSONObject());
                denied(()->sealHistory(r,isForm));
            });
            for(boolean flag:Arrays.asList(Boolean.FALSE,Boolean.TRUE)){
                final boolean value=flag;
                one((form?"form":"input")+"_history_rejects_other_kind_flag_"+flag,"synthetic_cross_kind_negative",()->{
                    JSONObject r=history(isForm);r.put(isForm?"historical_empty_input_planning_only":"historical_form_planning_only",value);
                    denied(()->sealHistory(r,isForm));
                });
            }
            one((form?"form":"input")+"_history_rejects_other_factory","synthetic_cross_kind_negative",()->{
                JSONObject r=history(isForm);denied(()->sealHistory(r,!isForm));
            });
        }
    }
    static void cases()throws Exception{
        one("original_receipts_are_hash_exact","recorded",()->{
            JSONObject files=fixture.getJSONObject("source_files");
            String[][] pins={{AX_NAME,"cead0f45a6d883c55dcb24d46f9afece606ec15740ac116b85a52a5f5ab7c03d"},
                {"failed-native-census.json","be09146bb19dab51d1d27b61ef82d49fe6dee4f3afdabc78c71dd302394bf32b"},
                {"step-02-action.json","f53b0f25060d48cb0757e391f0e06f216589245fe4561ddc198a5aa081801705"}};
            for(String[] pin:pins){JSONObject row=files.getJSONObject(pin[0]);String raw=row.getString("raw_utf8");
                check(hash(raw).equals(pin[1])&&row.getString("sha256").equals(pin[1]),"original raw receipt hash");
                check(raw.getBytes(StandardCharsets.UTF_8).length==row.getInt("bytes"),"original raw receipt length");}
            check(!fixture.getBoolean("actual_type_current_census_retained"),"partial current not promoted to complete census");
            check("ae070b251cd4977754c498f24a527de1d28e38df878fdd2628fe8cfb3f026eab".equals(installed),"recorded managed installation carrier");
        });
        one("recorded_pair_has_only_twenty_chip_value_changes","recorded",()->{
            Map<String,Object> a=nodeMap(failed.getJSONObject("before").getJSONArray("native_nodes")),b=nodeMap(failed.getJSONObject("after").getJSONArray("native_nodes"));
            check(a.size()==180&&b.size()==180&&a.keySet().equals(b.keySet()),"recorded full census sizes, not an admission policy");
            List<String> changed=new ArrayList<String>();for(String p:a.keySet())if(!a.get(p).equals(b.get(p)))changed.add(p);
            check(changed.equals(fixture.getJSONObject("recorded_full_pair").getJSONArray("changed_paths").toList()),"exact recorded changed path set");
            check(nodeMap(ax.getJSONObject("first").getJSONArray("nodes")).equals(b)&&nodeMap(ax.getJSONObject("second").getJSONArray("nodes")).equals(b),"published nodes equal later failed after");
            for(String p:changed){JSONObject x=copy(rawNode(failed.getJSONObject("before"),p)),y=copy(rawNode(failed.getJSONObject("after"),p));
                for(String k:Arrays.asList("bounds","text","label","ref_signature_sha256","visible")){x.remove(k);y.remove(k);}
                check(x.toMap().equals(y.toMap()),"all chip capabilities and topology unchanged");}
        });
        one("real_later_complete_pair_is_accepted_without_dispatch","recorded_nodes_with_explicit_clock_carriers",()->{
            Map<String,Object> p=compare(endpoint("before"),endpoint("after"));noAuthority(p);
            check(((List<?>)p.get("changed_paths")).size()==20,"real complete comparison accounts for twenty changes");
            check("0/1".equals(p.get("query_path"))&&Boolean.TRUE.equals(p.get("empty_query")),"only original empty query editor");
        });
        one("real_published_ax_pair_is_accepted_without_dispatch","recorded",()->{
            Map<String,Object> p=compareAx(ax.getJSONObject("first"),ax.getJSONObject("second"),ax.getJSONObject("binding"));noAuthority(p);
            check(((List<?>)p.get("changed_paths")).isEmpty(),"published pair really identical");
        });
        one("real_hidden_reversed_rectangles_are_kept_verbatim","recorded_nodes_with_explicit_clock_carriers",()->{
            int inverted=0;JSONObject b=endpoint("after");JSONArray nodes=b.getJSONArray("nodes");
            for(int i=0;i<nodes.length();i++){JSONObject n=nodes.getJSONObject(i);if(n.getString("path").matches("0/6/(?:[2-9]|1[01])(?:/0)?")){
                JSONArray r=n.getJSONArray("bounds");if(r.getInt(3)<r.getInt(1)){inverted++;check(!n.getBoolean("visible")&&n.isNull("label")&&n.isNull("ref_signature_sha256"),"hidden reversed values are original");}}}
            check(inverted==12,"actual clipped chip endpoints retained");compare(endpoint("before"),b);
        });
        one("partial_type_diagnostic_does_not_equal_later_complete_census","recorded_and_hash_reconstruction",()->{
            JSONObject d=action.getJSONObject("action_execution").getJSONObject("freshness_diagnostic");
            check(d.getBoolean("node_differences_truncated")&&!d.getBoolean("complete_tree_claimed"),"actual current diagnostic is explicitly partial");
            check(!d.getJSONObject("after").getString("observation_state_sha256").equals(failed.getJSONObject("before").getString("observation_state_sha256")),"same tree hash does not give same full state");
            JSONObject before=copy(rawNode(failed.getJSONObject("after"),"0/6/12")),after=copy(before);
            after.put("scroll_actions",SCROLL+"|backward|left");JSONObject fact=fixture.getJSONObject("carousel_counterfactual");
            check(hash(flags(before)).equals(fact.getString("before_state_flags_sha256"))&&hash(flags(after)).equals(fact.getString("after_state_flags_sha256")),"one mask change reproduces the two retained state hashes");
            check(!action.getBoolean("accepted")&&!action.getBoolean("dispatched")&&action.getBoolean("stale"),"original refused input is unchanged");
        });
        for(String suffix:Arrays.asList("|backward|left","|forward|right")){
            one("synthetic_carousel_boundary_mask_"+suffix.replace('|','_'),"synthetic_counterfactual_not_actual_current_census",()->{
                JSONObject a=endpoint("before"),b=endpoint("after"),n=node(b,"0/6/12");n.put("scroll_actions",SCROLL+suffix);refreshLeafReference(n);
                Map<String,Object> p=compare(a,b);noAuthority(p);
                check(((List<?>)p.get("changed_paths")).size()==21&&((List<?>)p.get("changed_paths")).contains("0/6/12"),"complete chips plus one fixed carousel mask");
            });
        }
        one("synthetic_nine_chip_shape_proves_no_fixed_180_or_ten_rule","synthetic_counterfactual_not_recorded_layout",()->{
            JSONObject a=endpoint("before"),b=endpoint("after");
            for(JSONObject x:Arrays.asList(a,b)){
                JSONArray old=x.getJSONArray("nodes"),rows=new JSONArray();
                for(int i=0;i<old.length();i++){JSONObject n=copy(old.getJSONObject(i));String path=n.getString("path");
                    if(path.equals("0/6/11")||path.equals("0/6/11/0"))continue;
                    if(path.startsWith("0/6/")){String tail=path.substring(4);int cut=tail.indexOf('/');String head=cut<0?tail:tail.substring(0,cut);
                        int index=Integer.parseInt(head);if(index>=12)n.put("path","0/6/"+(index-1)+(cut<0?"":tail.substring(cut)));}
                    if("0/6".equals(path))n.put("children",n.getInt("children")-1);rows.put(n);}
                x.put("nodes",rows);x.getJSONObject("envelope").put("visited",rows.length());}
            Map<String,Object> p=compare(a,b);noAuthority(p);check(((Number)p.get("before_visited_nodes")).intValue()==178,"different complete node count accepted");
            check(((List<?>)p.get("variable_chip_paths")).size()==18,"nine complete chips derived from shape");check("0/6/11".equals(p.get("variable_carousel_path")),"carousel follows the actual chip run");
        });
        mutateBoth("nonempty_query_even_if_equal",x->node(x,"0/1").put("text","AX3000T"));
        mutateBoth("focused_query_even_if_equal",x->node(x,"0/1").put("focused",true));
        mutateBoth("password_query_even_if_equal",x->node(x,"0/1").put("password",true));
        mutateBoth("disabled_query_even_if_equal",x->node(x,"0/1").put("enabled",false));
        mutateBoth("second_hidden_editable_is_rejected",x->node(x,"0/6/14/0").put("editable",true));
        mutateSecond("query_geometry_change",x->node(x,"0/1").put("bounds",new JSONArray(Arrays.asList(163,130,1074,334))));
        mutateSecond("toolbar_hint_change",x->node(x,"0/2").put("text","changed"));
        mutateBoth("search_label_ambiguity_or_replacement",x->node(x,"0/4/0").put("text","购买"));
        mutateBoth("unknown_eighth_root_child",x->{JSONObject n=copy(node(x,"0/5"));n.put("path","0/7");x.getJSONArray("nodes").put(n);node(x,"0").put("children",8);x.getJSONObject("envelope").put("visited",181);});
        mutateSecond("fixed_refresh_control_change",x->node(x,"0/6/1").put("description","refresh changed"));
        mutateBoth("different_recommendation_header",x->node(x,"0/6/0").put("text","广告"));
        mutateBoth("enclosure_overlaps_toolbar",x->node(x,"0/6").put("bounds",new JSONArray(Arrays.asList(0,300,1224,2992))));
        mutateSecond("fixed_offscreen_subtree_change",x->node(x,"0/6/14/0").put("description","changed offscreen"));
        mutateSecond("fixed_second_carousel_scroll_mask_change",x->node(x,"0/6/13").put("scroll_actions",SCROLL+"|backward|left"));
        for(String flag:Arrays.asList("clickable","action_click","enabled","editable","scrollable","focused","password","selected","checkable","checked")){
            mutateBoth("chip_capability_"+flag,x->{JSONObject n=node(x,"0/6/2");n.put(flag,!n.getBoolean(flag));});
        }
        mutateSecond("chip_unknown_scroll_actions",x->node(x,"0/6/2").put("scroll_actions",SCROLL+"|forward"));
        mutateSecond("chip_ime_capability_change",x->node(x,"0/6/2").put("ime_enter","hepta.observed-ime-enter.v1|true|true|search"));
        mutateSecond("chip_label_must_match_actual_child",x->node(x,"0/6/2").put("label","forged"));
        mutateSecond("chip_reference_must_match_complete_fields",x->node(x,"0/6/2").put("ref_signature_sha256",installed));
        mutateSecond("hidden_chip_cannot_keep_reference",x->node(x,"0/6/10").put("ref_signature_sha256",installed));
        mutateSecond("hidden_chip_cannot_keep_label",x->node(x,"0/6/10").put("label","forged"));
        for(int axis=0;axis<4;axis++){final int index=axis;
            mutateSecond("hidden_reversed_endpoint_outside_region_"+axis,x->{JSONArray r=node(x,"0/6/10").getJSONArray("bounds");r.put(index,index%2==0?1225:2993);});}
        mutateSecond("duplicate_native_path",x->{JSONArray rows=x.getJSONArray("nodes");rows.put(copy(rows.getJSONObject(0)));x.getJSONObject("envelope").put("visited",rows.length());});
        mutateSecond("missing_native_child_even_with_adjusted_count",x->{JSONArray rows=x.getJSONArray("nodes");rows.remove(rows.length()-1);x.getJSONObject("envelope").put("visited",rows.length());});
        mutateSecond("wrong_actual_parent_class",x->node(x,"0/6/2/0").put("parent_class","android.widget.FrameLayout"));
        mutateSecond("reported_visited_is_not_retained_subset",x->x.getJSONObject("envelope").put("visited",58));
        for(String k:Arrays.asList("pending","node_omissions","text_omissions","child_omissions"))
            mutateSecond("complete_census_rejects_"+k,x->x.getJSONObject("envelope").put(k,1));
        for(String suffix:Arrays.asList("|forward|down","|up","|right","|forward|backward|left|right|down","|unknown")){
            mutateSecond("carousel_unsupported_mask_"+suffix.replace('|','_'),x->{JSONObject n=node(x,"0/6/12");n.put("scroll_actions",SCROLL+suffix);refreshLeafReference(n);});
        }
        mutateSecond("carousel_ref_must_be_recomputed_after_mask",x->node(x,"0/6/12").put("scroll_actions",SCROLL+"|backward|left"));
        mutateSecond("carousel_arbitrary_ref_is_rejected",x->node(x,"0/6/12").put("ref_signature_sha256",installed));
        mutateSecond("carousel_fixed_geometry_change",x->{JSONObject n=node(x,"0/6/12");n.put("bounds",new JSONArray(Arrays.asList(35,928,1190,1268)));refreshLeafReference(n);});
        mutateBoth("carousel_crosses_enclosure",x->{JSONObject n=node(x,"0/6/12");n.put("bounds",new JSONArray(Arrays.asList(-1,928,1190,1268)));refreshLeafReference(n);});
        mutateBoth("carousel_hidden_or_overlay_state_rejected",x->node(x,"0/6/12").put("visible",false).put("label",JSONObject.NULL).put("ref_signature_sha256",JSONObject.NULL));
        mutateBoth("carousel_descendant_makes_unknown_subtree",x->{JSONObject n=copy(node(x,"0/6/2/0"));n.put("path","0/6/12/0").put("parent_class","android.widget.HorizontalScrollView");x.getJSONArray("nodes").put(n);node(x,"0/6/12").put("children",1);x.getJSONObject("envelope").put("visited",181);});
        for(String key:Arrays.asList("text","description","view_id"))
            mutateSecond("carousel_fixed_"+key,x->{JSONObject n=node(x,"0/6/12");n.put(key,"changed");refreshLeafReference(n);});
        for(String key:Arrays.asList("task_id","owner_sha256","target_sha256","authorization_sha256","selection_sha256","installed_set_sha256","goal_sha256","profile_target_sha256"))
            mutateSecond("envelope_binding_"+key,x->x.getJSONObject("envelope").put(key,"task_id".equals(key)?"00000000000000000000000000000000":String.join("",Collections.nCopies(64,"0"))));
        mutateSecond("profile_window_leaf_changes",x->x.getJSONObject("envelope").put("profile_task_id",1000076));
        mutateSecond("unknown_or_visible_ime",x->x.getJSONObject("envelope").put("ime_visibility","visible"));
        mutateSecond("backward_comparison_clock",x->x.getJSONObject("envelope").put("captured_elapsed_ms",857847704L));
        mutateSecond("existing_ninety_second_limit_not_extended",x->x.getJSONObject("envelope").put("captured_elapsed_ms",857937706L));
        mutateAx("ax_complete_false",x->x.put("complete",false));
        mutateAx("ax_truncated_even_if_complete_true",x->x.put("truncated",true));
        mutateAx("ax_pending_node_omission",x->x.put("pending",1));
        mutateAx("ax_reported_windows_missing",x->x.put("reported_windows",JSONObject.NULL));
        mutateAx("ax_reported_window_set_cannot_be_filtered",x->x.getJSONObject("reported_windows").put("unreported_windows_excluded",true));
        mutateAx("ax_overlay_second_window",x->{JSONArray a=x.getJSONObject("reported_windows").getJSONArray("windows");JSONObject w=copy(a.getJSONObject(0));w.put("window_id",2313).put("layer",1);a.put(w);});
        mutateAx("ax_window_identity_mismatch",x->x.getJSONObject("window").put("window_id",2313));
        mutateAx("ax_profile_leaf_mismatch",x->x.getJSONObject("profile_owner").put("profile_task_id",1000076));
        mutateAx("ax_profile_window_generation_mismatch",x->x.getJSONObject("profile_window").put("generation","00000000-0000-0000-0000-000000000000"));
        mutateAx("ax_unknown_ime_rejected",x->x.put("ime_visibility","unknown"));
        mutateAx("ax_existing_twelve_second_limit",x->x.put("census_captured_elapsed_ms",ax.getJSONObject("first").getLong("census_captured_elapsed_ms")+12001L));
        one("ax_wrong_binding_is_not_accepted","synthetic_negative_from_recorded_ax",()->{
            JSONObject binding=copy(ax.getJSONObject("binding"));binding.put("owner_sha256",installed);
            denied(()->compareAx(ax.getJSONObject("first"),ax.getJSONObject("second"),binding));
        });
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("fixture and output paths required");
        fixture=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        ax=source(AX_NAME);failed=source("failed-native-census.json");action=source("step-02-action.json");
        installed=fixture.getJSONObject("profile_target_from_original_prompt").getString("apk_set_sha256");
        cases();historyCases();boolean pass=true;List<String> names=new ArrayList<String>();for(Map<String,Object> r:RESULTS){pass&=Boolean.TRUE.equals(r.get("passed"));names.add((String)r.get("name"));}
        check(new TreeSet<String>(names).size()==names.size(),"unique case names");
        JSONObject report=new JSONObject().put("schema","hepta.xiaomi-empty-input-host-cases.v1").put("all_pass",pass)
                .put("cases",RESULTS.size()).put("assertions",assertions).put("case_names",names).put("results",RESULTS)
                .put("phone_operations",0).put("android_execution",false).put("model_executed",false).put("business_completion_verified",false)
                .put("actual_type_full_current_census_available",false).put("carousel_positive_is_synthetic_counterfactual",true);
        Path output=Paths.get(args[1]);Files.write(output,(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("cases="+RESULTS.size()+" assertions="+assertions+" all_pass="+pass);
        if(!pass)System.exit(1);
    }
}
