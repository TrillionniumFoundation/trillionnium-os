package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;

/** Archived values and explicit mutations; no Android node, model or input exists here. */
public final class NativeSearchBannerRecoveryHostTest {
    private static final String RAW_SHA="cb97f512faccc62e826157b09181a503abc32c14c53b58fb4fca583e2fcf19ec";
    private static final String C_SHA="7542bae2d85c4060ba69830cb29263ecfeb86eedf5a4f0c22b3c4386f794bca3";
    private static final String D_SHA="b964653b61328c37e666659d86d34b4502d3314522f46a7bc27c0eb874b01e2a";
    private static final String BANNER="0/0/1/0/0",FULL=BANNER+"/4",EDGE=BANNER+"/5",EXTRA=BANNER+"/6",TARGET="0/0/3";
    private static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    private static int assertions;
    private static JSONObject original,execution;
    interface Check {void run()throws Exception;}
    interface Mutation {void apply(JSONObject c,JSONObject d)throws Exception;}
    private static void yes(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void one(String name,Check check){
        int before=assertions;Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        try{check.run();row.put("passed",true);}catch(Exception|AssertionError error){row.put("passed",false);row.put("error",error.getClass().getName()+": "+error.getMessage());}
        row.put("assertions",assertions-before);cases.add(row);
    }
    private static JSONObject copy(String name)throws Exception{return new JSONObject(execution.getJSONObject("C".equals(name)?"current_C":"latest_D").toString());}
    private static JSONObject node(JSONObject graph,String path)throws Exception{
        JSONArray rows=graph.getJSONArray("nodes");JSONObject found=null;
        for(int i=0;i<rows.length();i++)if(path.equals(rows.getJSONObject(i).getString("path"))){yes(found==null,"unique complete path");found=rows.getJSONObject(i);}
        if(found==null)throw new AssertionError("absent raw path: "+path);return found;
    }
    private static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject graph)throws Exception{return NativeSearchPlanning.readSnapshot(NativeSearchPlanning.map(graph));}
    private static String hash(String value){return QualificationScope.hash(value.getBytes(StandardCharsets.UTF_8));}
    private static String field(String value){return value.length()+":"+value;}
    // Actual empty-complete descendant reference construction, recomputed after
    // synthetic changes so negative geometry does not hide behind a stale hash.
    private static String emptyReference(JSONObject n)throws Exception{
        JSONArray b=n.getJSONArray("bounds");
        String rect="Rect("+b.getInt(0)+", "+b.getInt(1)+" - "+b.getInt(2)+", "+b.getInt(3)+")";
        String base=hash(n.getString("package")+"\u0001"+n.getInt("window_id")+"\u0001"+n.getString("class")+"\u0001"+
            n.getString("view_id")+"\u0001"+rect+"\u0001"+n.getString("text")+"\u0001"+n.getString("description")+"\u0001"+
            n.getBoolean("enabled")+"|"+n.getBoolean("clickable")+"|"+n.getBoolean("editable")+"|"+n.getBoolean("scrollable"));
        String child=hash(field(ObservedChildText.SOURCE)+field("empty")+field("")+field("false")+field(base)+field("true"));
        String tree=hash(field(base)+field(child));
        return hash(tree+"\nscroll_actions="+n.getString("scroll_actions")+"\nime_enter="+n.getString("ime_enter")+
                    "|focused="+n.getBoolean("focused")+"|full_input=null");
    }
    private static void refresh(JSONObject n)throws Exception{if(n.getBoolean("visible"))n.put("ref_signature_sha256",emptyReference(n));}
    private static void geometry(JSONObject graph,String path,int l,int t,int r,int b)throws Exception{
        JSONObject n=node(graph,path);n.put("bounds",new JSONArray(Arrays.asList(l,t,r,b)));refresh(n);
    }
    private static void show(JSONObject graph,String path,int l,int t,int r,int b)throws Exception{
        JSONObject n=node(graph,path);n.put("visible",true).put("label","");geometry(graph,path,l,t,r,b);
    }
    private static void hide(JSONObject graph,String path)throws Exception{
        node(graph,path).put("visible",false).put("label",JSONObject.NULL).put("ref_signature_sha256",JSONObject.NULL)
            .put("bounds",new JSONArray(Arrays.asList(0,0,0,931)));
    }
    private static NativeSearchRole compare(int mode,NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b){
        return mode==0?NativeSearchRole.compare(a,b):mode==1?NativeSearchRole.compareForPlanning(a,b):NativeSearchRole.compareForExecution(a,b);
    }
    private static void onlyRefusal(JSONObject c,JSONObject d)throws Exception{
        NativeActionSnapshotCheck.Snapshot a=snapshot(c),b=snapshot(d);
        yes(NativeActionSnapshotCheck.rejectedSearchBannerMotion(a,b,TARGET),"eligible only for typed refusal, not role/effect");
        Set<String> hints=new TreeSet<String>(Arrays.asList(TARGET,TARGET+"/0",TARGET+"/0/0"));
        yes(NativeActionSnapshotCheck.fullPageSearchBannerSwap(a,b,TARGET,hints)==null,"overlap never passes full-page coverage");
        for(int mode=0;mode<3;mode++){
            boolean refused=false;
            try{compare(mode,a,b);}catch(NativeSearchRole.RejectedBannerMotion expected){
                refused=true;yes(expected.first==a&&expected.second==b,"typed refusal retains the original immutable pair");
            }
            yes(refused,"strict/planning/execution never return a Role for the old overlapping pair");
        }
    }
    private static void notRecovery(JSONObject c,JSONObject d)throws Exception{
        boolean eligible=false;
        try{eligible=NativeActionSnapshotCheck.rejectedSearchBannerMotion(snapshot(c),snapshot(d),TARGET);}
        catch(IllegalArgumentException malformed){/* Explicit incomplete/foreign schemas must be refused before classification. */}
        yes(!eligible,"invalid geometry, state, schema or outside change cannot enter recovery classification");
        for(int mode=0;mode<3;mode++){
            boolean refused=false;try{compare(mode,snapshot(c),snapshot(d));}catch(IllegalArgumentException expected){refused=true;}
            yes(refused,"invalid complete pair cannot grant even a pure search Role");
        }
    }
    private static void reject(String name,Mutation mutation){one(name,()->{JSONObject c=copy("C"),d=copy("D");mutation.apply(c,d);notRecovery(c,d);});}
    public static void main(String[] args)throws Exception{
        Path input=Paths.get(args[0]),output=Paths.get(args[1]);byte[] raw=Files.readAllBytes(input);
        yes(raw.length==213701&&RAW_SHA.equals(QualificationScope.hash(raw)),"exact untouched archived action original");
        original=new JSONObject(new String(raw,StandardCharsets.UTF_8));
        execution=original.getJSONObject("action_execution").getJSONObject("native_search_execution");
        one("actual_b813_original_receipt_remains_failed_and_not_stale",()->{
            yes(!original.getBoolean("accepted")&&!original.getBoolean("dispatched")&&!original.getBoolean("stale"),"historical old outcome is not rewritten as recoverable");
            JSONObject attempt=original.getJSONObject("attempt");
            yes(!attempt.getBoolean("claimed")&&attempt.getInt("state")==0&&attempt.isNull("revalidation"),"actual old intent was never claimed");
            yes(attempt.getLong("deadline_elapsed_ms")-attempt.getLong("started_elapsed_ms")==24000,"original navigation attempt was 24 seconds");
            yes(!execution.getBoolean("platform_call_invoked")&&!execution.getBoolean("coordinates_used_for_input"),"actual platform call was not entered");
        });
        one("actual_b813_exact_complete_pair_and_hashes",()->{
            NativeActionSnapshotCheck.Snapshot c=snapshot(copy("C")),d=snapshot(copy("D"));
            yes(C_SHA.equals(c.sha)&&D_SHA.equals(d.sha),"actual production canonical snapshot fingerprints");
            yes(c.nodes.size()==75&&d.nodes.size()==75&&c.nodes.keySet().equals(d.nodes.keySet()),"all complete nodes preserved");
            List<String> changed=new ArrayList<String>();for(String path:c.nodes.keySet())if(!c.node(path).v.equals(d.node(path).v))changed.add(path);
            yes(changed.equals(Arrays.asList(EDGE,EXTRA,BANNER+"/7",BANNER+"/8")),"exact four original changed paths");
            yes(c.node(EDGE).bounds.equals(Arrays.asList(1224,0,1224,931))&&!c.node(EDGE).visible(),"original hidden empty edge");
            yes(d.node(EDGE).bounds.equals(Arrays.asList(1222,0,1224,931))&&d.node(EDGE).visible(),"actual two-pixel edge");
            yes(c.node(TARGET).v.equals(d.node(TARGET).v)&&c.node("0/0/4").v.equals(d.node("0/0/4").v),"actual search targets unchanged");
            yes(emptyReference(node(copy("D"),EDGE)).equals(d.node(EDGE).v.get("ref_signature_sha256")),"actual two-pixel ref fully explained");
        });
        one("actual_b813_two_pixel_pair_only_becomes_typed_refusal",()->onlyRefusal(copy("C"),copy("D")));
        one("reverse_actual_pair_only_becomes_typed_refusal",()->onlyRefusal(copy("D"),copy("C")));
        for(final int width:new int[]{1,2,3,17,1223}){
            one("right_partial_edge_width_"+width+"_never_grants_role",()->{JSONObject d=copy("D");geometry(d,EDGE,1224-width,0,1224,931);onlyRefusal(copy("C"),d);});
            one("left_partial_edge_width_"+width+"_never_grants_role",()->{JSONObject d=copy("D");geometry(d,EDGE,0,0,width,931);onlyRefusal(copy("C"),d);});
        }
        reject("zero_width_visible_edge_rejected",(c,d)->geometry(d,EDGE,1224,0,1224,931));
        reject("negative_width_visible_edge_rejected",(c,d)->geometry(d,EDGE,1225,0,1224,931));
        reject("full_width_second_page_is_not_partial_edge",(c,d)->geometry(d,EDGE,0,0,1224,931));
        reject("edge_wider_than_banner_rejected",(c,d)->geometry(d,EDGE,-1,0,1224,931));
        reject("wide_int_subtraction_cannot_wrap_to_partial",(c,d)->geometry(d,EDGE,Integer.MIN_VALUE,0,1224,931));
        reject("positive_interior_edge_not_attached_rejected",(c,d)->geometry(d,EDGE,1,0,3,931));
        reject("edge_top_gap_rejected",(c,d)->geometry(d,EDGE,1222,1,1224,931));
        reject("edge_bottom_gap_rejected",(c,d)->geometry(d,EDGE,1222,0,1224,930));
        reject("two_edges_in_one_frame_rejected",(c,d)->show(d,EXTRA,0,0,2,931));
        reject("one_edge_in_each_frame_rejected",(c,d)->show(c,EDGE,1223,0,1224,931));
        reject("missing_full_page_rejected",(c,d)->hide(d,FULL));
        reject("extra_full_page_rejected",(c,d)->show(d,EXTRA,0,0,1224,931));
        reject("unknown_node_field_rejected",(c,d)->node(d,EDGE).put("invented_metadata",true));
        reject("unknown_envelope_field_rejected",(c,d)->d.getJSONObject("envelope").put("invented_metadata",true));
        reject("foreign_package_rejected",(c,d)->node(d,EDGE).put("package","foreign.app"));
        reject("foreign_window_rejected",(c,d)->node(d,EDGE).put("window_id",2865));
        reject("incomplete_census_rejected",(c,d)->d.getJSONObject("envelope").put("child_omissions",1));
        reject("outside_banner_change_rejected",(c,d)->node(d,"0/5").put("selected",false));
        reject("target_geometry_change_rejected",(c,d)->node(d,TARGET).put("bounds",new JSONArray(Arrays.asList(155,287,1000,375))));
        reject("target_reference_change_rejected",(c,d)->node(d,TARGET).put("ref_signature_sha256",hash("changed")));
        reject("icon_change_rejected",(c,d)->node(d,"0/0/4").put("selected",true));
        reject("actual_banner_ancestor_change_rejected",(c,d)->node(d,"0/0/1/0").put("selected",true));
        reject("actual_banner_container_change_rejected",(c,d)->node(d,BANNER).put("selected",true));
        reject("blank_label_change_rejected",(c,d)->node(d,EDGE).put("label","new content"));
        reject("unexplained_blank_reference_rejected",(c,d)->node(d,EDGE).put("ref_signature_sha256",hash("unknown reference")));
        reject("blank_text_change_with_new_reference_rejected",(c,d)->{JSONObject n=node(d,EDGE);n.put("text","new content");refresh(n);});
        reject("blank_description_change_with_new_reference_rejected",(c,d)->{JSONObject n=node(d,EDGE);n.put("description","new content");refresh(n);});
        for(final String key:new String[]{"enabled","clickable","action_click","editable","scrollable","focused","password","selected","checkable","checked"}){
            reject("changed_"+key+"_with_new_reference_rejected",(c,d)->{JSONObject n=node(d,EDGE);n.put(key,!n.getBoolean(key));refresh(n);});
        }
        reject("new_input_hash_rejected",(c,d)->node(d,EDGE).put("input_sha256",hash("input")));
        reject("changed_scroll_metadata_rejected",(c,d)->{JSONObject n=node(d,EDGE);n.put("scroll_actions","hepta.observed-scroll-actions.v1|observed|forward");refresh(n);});
        reject("changed_ime_metadata_rejected",(c,d)->{JSONObject n=node(d,EDGE);n.put("ime_enter","hepta.observed-ime-enter.v1|false|false|null");refresh(n);});
        reject("missing_banner_child_rejected",(c,d)->{JSONArray rows=d.getJSONArray("nodes");for(int i=0;i<rows.length();i++)if(EXTRA.equals(rows.getJSONObject(i).getString("path"))){rows.remove(i);break;}d.getJSONObject("envelope").put("visited",rows.length());});
        one("unchanged_full_pair_keeps_original_semantics",()->{
            NativeActionSnapshotCheck.Snapshot c=snapshot(copy("C"));
            yes(!NativeActionSnapshotCheck.rejectedSearchBannerMotion(c,c,TARGET),"equal pair is not a recovery reason");
            NativeSearchRole role=NativeSearchRole.compareForExecution(c,c);yes(role.fullTreeEqual&&!role.fullPageSwap,"original equal pair semantics retained");
            yes(Boolean.FALSE.equals(role.evidence().get("grants_dispatch")),"pure equal Role is still not a dispatch permit");
        });
        one("archive_and_original_values_unchanged",()->{
            yes(Arrays.equals(raw,Files.readAllBytes(input)),"actual file never modified");
            yes(C_SHA.equals(snapshot(copy("C")).sha)&&D_SHA.equals(snapshot(copy("D")).sha),"mutations were isolated copies");
        });
        boolean all=true;for(Map<String,Object> row:cases)all&=Boolean.TRUE.equals(row.get("passed"));
        Map<String,Object> result=new LinkedHashMap<String,Object>();
        result.put("schema","hepta.xiaomi-banner-refusal-recovery-host.v1");result.put("all_pass",all);
        result.put("cases",cases.size());result.put("assertions",assertions);result.put("case_results",cases);
        result.put("actual_action_sha256",RAW_SHA);result.put("actual_C_sha256",C_SHA);result.put("actual_D_sha256",D_SHA);
        result.put("historical_receipt_modified",false);result.put("original_pair_role_or_dispatch_granted",false);
        result.put("android_or_model_executed",false);result.put("business_verified",false);
        byte[] encoded=(NativeSearchPlanning.json(result).toString(2)+"\n").getBytes(StandardCharsets.UTF_8);
        Files.write(output,encoded);System.out.write(encoded);if(!all)throw new AssertionError("banner refusal recovery cases failed");
    }
}
