package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONArray;
import org.json.JSONObject;

/** Generated history prefixes over the already-public filled-query fixture.
 * These are explicitly synthetic scenes, not the 6127 device capture or a
 * replay of any Android action. Original public fixture bytes stay unchanged. */
public final class NativeXiaomiFilledHistoryHostTest {
    private static JSONObject fixture;
    private static final List<Map<String,Object>> RESULTS=new ArrayList<Map<String,Object>>();
    private static int assertions;
    interface Test { void run() throws Exception; }
    interface Change { void run(JSONObject before,JSONObject after) throws Exception; }
    private NativeXiaomiFilledHistoryHostTest(){}
    static void check(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    static JSONObject node(JSONObject value,String path){return NativeXiaomiQueryStabilityHostTest.node(value,path);}
    static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject value){return NativeXiaomiQueryStabilityHostTest.snapshot(value);}
    static void resign(JSONObject value,String path)throws Exception{NativeXiaomiHistoryPrefixPortableTest.resign(value,path);}
    static void one(String name,Test test){
        Map<String,Object> row=new LinkedHashMap<String,Object>();
        row.put("name",name);row.put("input_kind","synthetic_history_added_to_existing_public_filled_fixture");
        int start=assertions;
        try{test.run();row.put("passed",true);}catch(Throwable failure){
            row.put("passed",false);row.put("error",failure.toString());
            java.io.StringWriter trace=new java.io.StringWriter();failure.printStackTrace(new java.io.PrintWriter(trace));row.put("stack",trace.toString());
        }
        row.put("assertions",assertions-start);RESULTS.add(row);
    }
    static void denied(String fragment,Test test)throws Exception{
        boolean refused=false;
        try{test.run();}catch(IllegalArgumentException|IllegalStateException failure){
            refused=true;check(failure.getMessage()!=null&&failure.getMessage().contains(fragment),
                    "specific refusal "+fragment+"; actual="+failure.getMessage());
        }
        check(refused,"production predicate must refuse");
    }
    static JSONObject history(String side,int count)throws Exception{
        JSONObject value=copy(fixture.getJSONObject(side));
        JSONObject heading=copy(node(value,"0/6/0")),chip=copy(node(value,"0/6/2")),term=copy(node(value,"0/6/2/0"));
        int top=node(value,"0/6").getJSONArray("bounds").getInt(1)+2;
        int bottom=heading.getJSONArray("bounds").getInt(1)-2,mid=(top+bottom)/2;
        check(bottom-top>=16,"synthetic prefix stays in existing empty geometric space");
        JSONArray old=value.getJSONArray("nodes"),out=new JSONArray();int prefix=count+1;
        for(int i=0;i<old.length();i++){
            JSONObject raw=copy(old.getJSONObject(i));String path=raw.getString("path");
            if(path.startsWith("0/6/")){
                String[] parts=path.split("/");parts[2]=String.valueOf(Integer.parseInt(parts[2])+prefix);
                raw.put("path",String.join("/",parts));
            }
            out.put(raw);
        }
        value.put("nodes",out);node(value,"0/6").put("children",node(value,"0/6").getInt("children")+prefix);
        heading.put("path","0/6/0").put("text","搜索历史").put("label","搜索历史")
                .put("bounds",new JSONArray(Arrays.asList(54,top,234,mid-2)));out.put(heading);
        for(int i=0;i<count;i++){
            String path="0/6/"+(i+1),label=i==0?"电视":"净水器";
            JSONObject parent=copy(chip),text=copy(term);
            parent.put("path",path).put("label",label)
                    .put("bounds",new JSONArray(Arrays.asList(54+300*i,mid+2,320+300*i,bottom)));
            text.put("path",path+"/0").put("text",label).put("label",label)
                    .put("bounds",new JSONArray(Arrays.asList(60+300*i,mid+4,300+300*i,bottom-2)));
            out.put(parent).put(text);
        }
        value.getJSONObject("envelope").put("visited",out.length());
        resign(value,"0/6/0");
        for(int i=0;i<count;i++){resign(value,"0/6/"+(i+1)+"/0");resign(value,"0/6/"+(i+1));}
        return value;
    }
    static NativeActionSnapshotCheck.Intent intent(JSONObject before,JSONObject after,String purpose,String path,String literal){
        Map<String,Object> env=before.getJSONObject("envelope").toMap(),identity=new TreeMap<String,Object>();
        for(String key:NativeActionSnapshotCheck.PROFILE_AUTHORITY)identity.put(key,env.get(key));
        JSONObject target=node(before,path);long now=after.getJSONObject("envelope").getLong("captured_elapsed_ms");
        return new NativeActionSnapshotCheck.Intent(purpose,"com.xiaomi.shop",path,target.getString("label"),
                target.getString("ref_signature_sha256"),"11111111111111111111111111111111","n2",
                NativeActionSnapshotCheck.hash("explicit synthetic filled-history query intent; not device authority"),null,
                identity,now-1,now+7999,literal);
    }
    static Map<String,Object> compare(JSONObject before,JSONObject after){
        return NativeActionSnapshotCheck.compare(intent(before,after,NativeActionSnapshotCheck.SUBMIT_QUERY,"0/2","AX3000T"),
                snapshot(before),snapshot(after),after.getJSONObject("envelope").getLong("captured_elapsed_ms"));
    }
    static void noAuthority(Map<String,Object> proof){
        for(String key:Arrays.asList("grants_dispatch","grants_action_authority","query_dispatched","business_completion_verified",
                "business_verified","published_pair_is_current_tree_claimed","query_history_proved_by_comparator",
                "provider_frame_constructed","session_observed_called","history_terms_are_query_or_result_evidence"))
            check(Boolean.FALSE.equals(proof.get(key)),"no authority/completion: "+key);
        check(Boolean.TRUE.equals(proof.get("live_node_chain_window_and_one_effect_recheck_required")),"original final live checks remain");
        check(Boolean.TRUE.equals(proof.get("full_census_compared")),"complete native tree remains mandatory");
    }
    static void negative(String name,String reason,Change change){
        one(name,()->{JSONObject before=history("before",1),after=history("after",1);change.run(before,after);denied(reason,()->compare(before,after));});
    }
    static void cases(){
        for(final int count:new int[]{1,3})one("stable_synthetic_history_"+count+"_terms_filled_query",()->{
            JSONObject before=history("before",count),after=history("after",count);Map<String,Object> proof=compare(before,after);noAuthority(proof);
            check(Integer.valueOf(count+1).equals(proof.get("fixed_history_prefix_children")),"prefix is structurally located, not AX3000T-history hardcoding");
            check("AX3000T".equals(proof.get("query_literal"))&&"0/2".equals(proof.get("target_path")),"original literal and click target preserved");
            check(((List<?>)proof.get("changed_paths")).size()==20,"only existing fixture recommendation drift permitted");
        });
        one("same_tree_history_still_has_no_dispatch_authority",()->{
            JSONObject before=history("before",1),after=copy(before);
            after.getJSONObject("envelope").put("captured_elapsed_ms",fixture.getJSONObject("after").getJSONObject("envelope").getLong("captured_elapsed_ms"));
            Map<String,Object> proof=compare(before,after);noAuthority(proof);check(((List<?>)proof.get("changed_paths")).isEmpty(),"no synthetic drift fabricated");
        });
        negative("history_content_change_with_valid_refs","change outside complete recommendation regions",(a,b)->{
            node(b,"0/6/1").put("label","空气净化器");node(b,"0/6/1/0").put("text","空气净化器").put("label","空气净化器");
            resign(b,"0/6/1/0");resign(b,"0/6/1");
        });
        negative("wrong_history_heading","actual fixed search history heading",(a,b)->node(b,"0/6/0").put("text","热搜").put("label","热搜"));
        negative("missing_recommendation_heading","actual recommendation section heading",(a,b)->node(b,"0/6/2").put("text","推荐"));
        negative("duplicate_recommendation_heading","unique actual recommendation section heading",(a,b)->node(b,"0/6/0").put("text","猜你想搜"));
        negative("corrupt_history_reference","input-region complete reference differs",(a,b)->node(b,"0/6/1/0").put("ref_signature_sha256",NativeActionSnapshotCheck.hash("synthetic corruption")));
        negative("history_must_not_overlap_recommendation_heading","history remains before recommendations",(a,b)->{
            JSONObject n=node(b,"0/6/1");JSONArray bounds=copy(n).getJSONArray("bounds");
            bounds.put(3,node(b,"0/6/2").getJSONArray("bounds").getInt(1)+1);n.put("bounds",bounds);
        });
        negative("original_query_literal_changed","original unique exact query field",(a,b)->node(b,"0/1").put("text","AX3000"));
        negative("original_selected_button_label_changed","original filled-query button/ref/label changed",(a,b)->node(b,"0/2").put("label","立即购买"));
        negative("original_owner_binding_changed","binding changed",(a,b)->b.getJSONObject("envelope").put("owner_sha256",NativeActionSnapshotCheck.hash("synthetic different owner")));
        negative("original_profile_uid_changed","binding changed",(a,b)->b.getJSONObject("envelope").put("profile_full_uid",1010486));
        one("history_does_not_grant_mode_toggle_target",()->{
            JSONObject a=history("before",1),b=history("after",1);
            denied("original filled-query button/ref/label changed",()->NativeActionSnapshotCheck.compare(intent(a,b,NativeActionSnapshotCheck.SUBMIT_QUERY,"0/0","AX3000T"),snapshot(a),snapshot(b),b.getJSONObject("envelope").getLong("captured_elapsed_ms")));
        });
        one("original_eight_second_action_deadline_still_expires",()->{
            JSONObject a=history("before",1),b=history("after",1);NativeActionSnapshotCheck.Intent in=intent(a,b,NativeActionSnapshotCheck.SUBMIT_QUERY,"0/2","AX3000T");
            denied("original age/deadline/clock",()->NativeActionSnapshotCheck.compare(in,snapshot(a),snapshot(b),in.deadline));
        });
        one("ordinary_empty_editor_observation_does_not_accept_filled_history",()->{
            JSONObject a=history("before",1),b=history("after",1);
            denied("original unique exact query field",()->NativeXiaomiSearchInputObservation.compare(snapshot(a),snapshot(b)));
        });
        one("set_query_purpose_stays_rejected_for_filled_editor",()->{
            JSONObject a=history("before",1),b=history("after",1);
            denied("original unique exact query field",()->NativeActionSnapshotCheck.compare(intent(a,b,NativeActionSnapshotCheck.SET_QUERY,"0/1",null),snapshot(a),snapshot(b),b.getJSONObject("envelope").getLong("captured_elapsed_ms")));
        });
        one("search_navigation_purpose_does_not_gain_history_exception",()->{
            JSONObject a=history("before",1),b=history("after",1);
            denied("fresh home only",()->NativeActionSnapshotCheck.compare(intent(a,b,NativeActionSnapshotCheck.SEARCH,"0/4",null),snapshot(a),snapshot(b),b.getJSONObject("envelope").getLong("captured_elapsed_ms")));
        });
    }
    public static void main(String[] args)throws Exception{
        fixture=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        cases();boolean pass=true;List<String> names=new ArrayList<String>();
        for(Map<String,Object> row:RESULTS){pass&=Boolean.TRUE.equals(row.get("passed"));names.add((String)row.get("name"));}
        JSONObject report=new JSONObject().put("schema","hepta.xiaomi-filled-history-public-cases.v1").put("all_pass",pass)
                .put("cases",RESULTS.size()).put("assertions",assertions).put("case_names",names).put("results",RESULTS)
                .put("all_history_scenes_synthetic",true).put("new_private_device_census_used",false)
                .put("android_execution",false).put("phone_operations",0).put("business_success_claimed",false);
        Files.write(Paths.get(args[1]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("cases="+RESULTS.size()+" assertions="+assertions+" all_pass="+pass);
        if(!pass)System.exit(1);
    }
}
