package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.JSONObject;

/** Full recorded node rows with explicitly rebound host replay clocks.
 * No Android API, model, dispatch permission or historical success is supplied. */
public final class CtripPurposeGeometryHost {
    private interface Work { Object run() throws Exception; }
    private static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    private static int assertions;
    private static Map<String,Object> fixture;
    private static Map<String,Object> map(Object value){if(!(value instanceof Map))throw new IllegalArgumentException("map");Map<String,Object> r=new LinkedHashMap<String,Object>();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())r.put((String)e.getKey(),e.getValue());return r;}
    private static Object copy(Object value){
        if(value instanceof Map){Map<String,Object> r=new LinkedHashMap<String,Object>();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())r.put((String)e.getKey(),copy(e.getValue()));return r;}
        if(value instanceof List){List<Object> r=new ArrayList<Object>();for(Object item:(List<?>)value)r.add(copy(item));return r;}return value;
    }
    private static Map<String,Object> side(String name){return map(copy(map(fixture.get("pairs")).get(name)));}
    private static Map<String,Object> node(Map<String,Object> side,String path){
        for(Object item:(List<?>)side.get("nodes")){Map<String,Object> n=map(item);if(path.equals(n.get("path")))return n;}
        throw new IllegalArgumentException("missing node "+path);
    }
    private static void putNode(Map<String,Object> side,String path,String key,Object value){
        List<?> rows=(List<?>)side.get("nodes");
        for(int index=0;index<rows.size();index++){Object item=rows.get(index);if(path.equals(((Map<?,?>)item).get("path"))){
            @SuppressWarnings("unchecked") Map<String,Object> n=(Map<String,Object>)item;n.put(key,value);return;}}
        throw new IllegalArgumentException("missing mutation node "+path);
    }
    private static void putEnv(Map<String,Object> side,String key,Object value){
        @SuppressWarnings("unchecked") Map<String,Object> env=(Map<String,Object>)side.get("env");env.put(key,value);
    }
    private static NativeActionSnapshotCheck.Snapshot snapshot(Map<String,Object> side){
        List<NativeActionSnapshotCheck.Node> rows=new ArrayList<NativeActionSnapshotCheck.Node>();
        for(Object item:(List<?>)side.get("nodes"))rows.add(new NativeActionSnapshotCheck.Node(map(item)));
        return new NativeActionSnapshotCheck.Snapshot(map(side.get("env")),rows);
    }
    private static Map<String,Object> planning(Map<String,Object> first,Map<String,Object> second){
        return NativeCtripFormObservation.compareForTargetPlanning(snapshot(first),snapshot(second));
    }
    private static Map<String,Object> qualification(Map<String,Object> first,Map<String,Object> second){
        return map(planning(first,second).get("form_purpose_geometry"));
    }
    private static NativeActionSnapshotCheck.Intent intent(String purpose,String path,NativeActionSnapshotCheck.Snapshot before){
        NativeActionSnapshotCheck.Node n=before.node(path);Map<String,Object> identity=new TreeMap<String,Object>();
        for(String key:NativeActionSnapshotCheck.PROFILE_AUTHORITY)identity.put(key,before.env.get(key));
        long started=((Number)before.env.get("captured_elapsed_ms")).longValue()+1;
        return new NativeActionSnapshotCheck.Intent(purpose,NativeActionSnapshotCheck.CTRIP,path,n.label,
                (String)n.v.get("ref_signature_sha256"),"11111111111111111111111111111111","n33",
                NativeActionSnapshotCheck.hash("host-only same proposed action"),NativeActionSnapshotCheck.QUERY.equals(purpose)?
                NativeActionSnapshotCheck.hash("host-only calendar/year query-history binding; not actual phone history"):null,
                identity,started,started+8000);
    }
    private static Object action(String purpose,String path,Map<String,Object> first,Map<String,Object> second){
        NativeActionSnapshotCheck.Snapshot a=snapshot(first),z=snapshot(second);
        return NativeActionSnapshotCheck.compare(intent(purpose,path,a),a,z,((Number)z.env.get("captured_elapsed_ms")).longValue()+1);
    }
    private static void need(boolean condition,String message){assertions++;if(!condition)throw new AssertionError(message);}
    private static void one(String name,boolean expected,Work work)throws Exception{
        boolean accepted=false;String error=null;
        try{work.run();accepted=true;}catch(IllegalArgumentException refusal){error=refusal.getMessage();}
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);row.put("expected_accept",expected);row.put("accepted",accepted);row.put("refusal",error);
        cases.add(row);need(expected==accepted,name+": unexpected "+(accepted?"accept":"refusal: "+error));
    }
    public static void main(String[] args)throws Exception{
        fixture=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8)).toMap();
        final Map<String,Object> first=side("before"),second=side("after");
        need(((List<?>)first.get("nodes")).size()==276&&((List<?>)second.get("nodes")).size()==276,"all recorded nodes retained");
        one("recorded_pair_still_rejected_by_original_strict_entry",false,()->NativeCtripFormObservation.compare(snapshot(first),snapshot(second)));
        one("recorded_pair_qualified_only_for_two_direct_native_targets",true,()->{
            Map<String,Object> p=planning(first,second),q=map(p.get("form_purpose_geometry"));
            need("hepta.ctrip-native-form-purpose-pair.v1".equals(p.get("schema")),"distinct purpose proof");
            need(((Map<?,?>)q.get("targets")).keySet().equals(new TreeSet<String>(Arrays.asList(NativeActionSnapshotCheck.YEAR,NativeActionSnapshotCheck.QUERY))),"exact two purposes");
            need("0/0/0".equals(q.get("header_path"))&&((Number)q.get("complete_form_node_count")).intValue()==26,"actual full header and form");
            need(((List<?>)p.get("changed_paths")).size()==21,"all real changed paths classified");
            need(Boolean.FALSE.equals(q.get("header_action_set_proved"))&&Boolean.FALSE.equals(q.get("drawing_order_proved"))
                    &&Boolean.FALSE.equals(q.get("trip_tab_actions_authorized"))&&Boolean.FALSE.equals(q.get("grants_dispatch")),"no inferred or dispatch authority");
            need(!p.containsKey("literal_form_facts")&&p.containsKey("literal_form_facts_sha256"),"compact new proof retains complete fact digest");
            Files.write(Paths.get(args[1]),new JSONObject(p).toString(2).getBytes(StandardCharsets.UTF_8));return p;
        });
        one("equal_pair_keeps_original_strict_first_qualification",true,()->{
            Map<String,Object> p=planning(first,first);
            need("hepta.ctrip-native-form-observation-pair.v1".equals(p.get("schema"))&&!p.containsKey("form_purpose_geometry"),"strict first path unchanged");return p;
        });
        one("recorded_year_action_comparator_accepts_purpose_geometry",true,()->action(NativeActionSnapshotCheck.YEAR,"0/0/2/5",first,second));
        one("recorded_query_comparator_with_explicit_host_history_accepts",true,()->action(NativeActionSnapshotCheck.QUERY,"0/0/2/13",first,second));
        String[][] mutations={
            {"trip_selected_changed","0/0/2/0/0","selected","false"},
            {"return_trip_selected_changed","0/0/2/0/1","selected","true"},
            {"multi_trip_selected_changed","0/0/2/0/2","selected","true"},
            {"cabin_selected_changed","0/0/2/8/0","selected","false"},
            {"date_changed","0/0/2/5","text","11月27日后天"},
            {"departure_city_changed","0/0/2/1","text","天津"},
            {"arrival_city_changed","0/0/2/4","text","杭州"},
            {"adult_count_changed","0/0/2/9","text","2成人"},
            {"child_count_changed","0/0/2/10","text","1儿童"},
            {"infant_count_changed","0/0/2/11","text","1婴儿"},
            {"query_label_changed","0/0/2/13","text","预 订"},
            {"header_semantic_text_changed","0/0/0/1/1","text","登录"},
            {"header_click_capability_changed","0/0/0/1","clickable","true"},
            {"header_action_click_changed","0/0/0/1","action_click","true"},
            {"header_selection_changed","0/0/0/1","selected","true"},
            {"header_foreign_package","0/0/0/1/0","package","foreign.app"},
            {"target_reference_changed","0/0/2/5","ref_signature_sha256","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
            {"header_unknown_scroll_metadata","0/0/0","scroll_actions","hepta.observed-scroll-actions.v1|unknown"}
        };
        for(String[] m:mutations)one(m[0],false,()->{
            Map<String,Object> z=side("after");Object v="true".equals(m[3])?Boolean.TRUE:"false".equals(m[3])?Boolean.FALSE:m[3];
            putNode(z,m[1],m[2],v);return planning(first,z);
        });
        one("header_root_extended_into_nontrip_fields",false,()->{Map<String,Object> a=side("before"),z=side("after");
            putNode(a,"0/0/0","bounds",Arrays.asList(0,0,1224,850));putNode(z,"0/0/0","bounds",Arrays.asList(0,0,1224,850));return planning(a,z);});
        one("header_descendant_after_overflow_into_date",false,()->{Map<String,Object> z=side("after");putNode(z,"0/0/0/1/0","bounds",Arrays.asList(0,0,1224,900));return planning(first,z);});
        one("header_descendant_before_overflow_into_date",false,()->{Map<String,Object> a=side("before");putNode(a,"0/0/0/1/0","bounds",Arrays.asList(0,0,1224,900));return planning(a,second);});
        one("hidden_positive_descendant_cannot_escape_region",false,()->{Map<String,Object> z=side("after");putNode(z,"0/0/0/0/0","bounds",Arrays.asList(70,800,1200,900));putNode(z,"0/0/0/0/0","visible",false);return planning(first,z);});
        one("same_target_shifted_geometry",false,()->{Map<String,Object> z=side("after");putNode(z,"0/0/2/5","bounds",Arrays.asList(80,793,416,937));return planning(first,z);});
        one("duplicate_complete_node_path",false,()->{Map<String,Object> z=side("after");@SuppressWarnings("unchecked") List<Object> nodes=(List<Object>)z.get("nodes");nodes.add(copy(nodes.get(0)));putEnv(z,"visited",nodes.size());return planning(first,z);});
        one("missing_header_child_slot",false,()->{Map<String,Object> z=side("after");@SuppressWarnings("unchecked") List<Object> nodes=(List<Object>)z.get("nodes");nodes.removeIf(n->"0/0/0/0/0".equals(((Map<?,?>)n).get("path")));putEnv(z,"visited",nodes.size());return planning(first,z);});
        one("foreign_display",false,()->{Map<String,Object> z=side("after");putEnv(z,"display_id",617);return planning(first,z);});
        one("foreign_window",false,()->{Map<String,Object> z=side("after");putNode(z,"0/0/0/1/0","window_id",9999);return planning(first,z);});
        one("reported_window_set_changed",false,()->{Map<String,Object> z=side("after");putEnv(z,"reported_windows_sha256",NativeActionSnapshotCheck.hash("different window census"));return planning(first,z);});
        one("profile_identity_changed",false,()->{Map<String,Object> z=side("after");putEnv(z,"profile_task_id",1000086);return planning(first,z);});
        one("request_pair_clock_limit_unchanged",false,()->{Map<String,Object> z=side("after");putEnv(z,"captured_elapsed_ms",((Number)map(first.get("env")).get("captured_elapsed_ms")).longValue()+12001);return planning(first,z);});
        one("year_purpose_cannot_click_query",false,()->action(NativeActionSnapshotCheck.YEAR,"0/0/2/13",first,second));
        one("year_purpose_cannot_click_return_trip",false,()->action(NativeActionSnapshotCheck.YEAR,"0/0/2/0/1",first,second));
        one("generic_purpose_cannot_use_certificate",false,()->{
            NativeActionSnapshotCheck.Snapshot a=snapshot(first);
            NativeActionSnapshotCheck.requireCtripPurposeSource(qualification(first,second),"click","0/0/2/5",a);return null;});
        one("captured_constraint_rejects_later_changed_census_as_original",false,()->{
            NativeActionSnapshotCheck.requireCtripPurposeSource(qualification(first,second),NativeActionSnapshotCheck.YEAR,"0/0/2/5",snapshot(second));return null;});
        one("captured_constraint_rejects_other_observation",false,()->{
            Map<String,Object> a=side("before");putEnv(a,"origin_observation_id","22222222222222222222222222222222");
            NativeActionSnapshotCheck.requireCtripPurposeSource(qualification(first,second),NativeActionSnapshotCheck.YEAR,"0/0/2/5",snapshot(a));return null;});
        one("captured_constraint_rejects_other_owner",false,()->{
            Map<String,Object> a=side("before");putEnv(a,"owner_sha256",NativeActionSnapshotCheck.hash("another owner"));
            NativeActionSnapshotCheck.requireCtripPurposeSource(qualification(first,second),NativeActionSnapshotCheck.YEAR,"0/0/2/5",snapshot(a));return null;});
        one("action_original_eight_second_deadline_unchanged",false,()->{
            NativeActionSnapshotCheck.Snapshot a=snapshot(first),z=snapshot(second);NativeActionSnapshotCheck.Intent in=intent(NativeActionSnapshotCheck.YEAR,"0/0/2/5",a);
            return NativeActionSnapshotCheck.compare(in,a,z,in.deadline);});
        one("query_needs_separate_real_history_binding",false,()->{
            NativeActionSnapshotCheck.Snapshot a=snapshot(first);NativeActionSnapshotCheck.Intent good=intent(NativeActionSnapshotCheck.QUERY,"0/0/2/13",a);
            return new NativeActionSnapshotCheck.Intent(good.purpose,good.pkg,good.path,good.label,good.refSha256,good.run,good.node,good.actionSha,null,good.identity,good.started,good.deadline);});
        one("old_form_constraint_is_not_a_calendar_source",false,()->{
            Map<String,Object> a=side("before"),z=side("after");
            putNode(a,"0/0/2/5","view_id","ctrip.android.view:id/calendar_month_title_left_tv");
            putNode(z,"0/0/2/5","view_id","ctrip.android.view:id/calendar_month_title_left_tv");return planning(a,z);});
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema","hepta.ctrip-purpose-geometry-host-cases.v1");
        out.put("all_pass",true);out.put("cases",cases.size());out.put("assertions",assertions);out.put("case_results",cases);
        out.put("phone_operations",0);out.put("model_executed",false);out.put("actual_android_execution",false);
        out.put("recorded_complete_nodes",276);out.put("host_query_history_is_not_phone_history",true);
        out.put("recorded_clock_scope",fixture.get("clock_binding"));
        Files.write(Paths.get(args[2]),new JSONObject(out).toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println(new JSONObject(out).toString());
    }
}
