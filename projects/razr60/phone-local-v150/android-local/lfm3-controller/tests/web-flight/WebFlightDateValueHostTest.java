package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.webprotocol.*;

/** Retained real date DOM/AX values through the actual production pure domain parser.
 * Archived labels/receipt metadata are host value carriers, never reconstructed native
 * authority or authenticated IPC. Frame clock uses the recorded post-observation display
 * recheck inside the bracket because capturedElapsedMillis is not serialized in AX JSON. */
public final class WebFlightDateValueHostTest {
    private static int assertions,cases;
    private static final JSONArray names=new JSONArray();
    private interface Work {void run()throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Work run)throws Exception{run.run();cases++;names.put(name);}
    private static JSONObject read(Path p)throws Exception{return new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));}
    private static int[] bounds(JSONArray a){return new int[]{a.getInt(0),a.getInt(1),a.getInt(2),a.getInt(3)};}
    private static Rect rect(JSONArray a){int[] b=bounds(a);return new Rect(b[0],b[1],b[2],b[3]);}
    private static List<String> strings(JSONArray a){List<String> out=new ArrayList<String>();for(int i=0;i<a.length();i++)out.add(a.getString(i));return out;}
    private static PhoneObservation frame(JSONObject scope,boolean omitCounts)throws Exception{
        JSONObject v=scope.getJSONObject("observation"),w=v.getJSONObject("window"),bg=v.getJSONObject("background_session");
        List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
        JSONArray rows=v.getJSONArray("nodes");
        Map<String,JSONObject> byPath=new HashMap<String,JSONObject>();
        for(int i=0;i<rows.length();i++){JSONObject n=rows.getJSONObject(i);byPath.put(n.getJSONObject("native_tree_position").getString("path"),n);}
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i);ObservedChildText.Result child=ObservedChildText.notApplicable();
            if(n.has("child_text_status")){
                List<ObservedChildText.Source> sources=new ArrayList<ObservedChildText.Source>();
                JSONArray original=n.optJSONArray("child_text_sources");
                if(original!=null)for(int j=0;j<original.length();j++){
                    JSONObject x=original.getJSONObject(j);
                    String sourcePath=n.getJSONObject("native_tree_position").getString("path")+"/"+x.getString("descendant_path");
                    JSONObject descendant=byPath.get(sourcePath);
                    if(descendant==null)throw new AssertionError("archived child source not retained: "+sourcePath);
                    String property=x.getString("property"),text=descendant.getString(property);
                    if(!WebEvidenceJson.sha(text).equals(x.getString("text_sha256")))throw new AssertionError("original descendant string hash differs");
                    sources.add(new ObservedChildText.Source(x.getString("descendant_path"),property,text,x.getString("node_signature"),x.getString("view_id")));
                }
                Constructor<ObservedChildText.Result> ctor=ObservedChildText.Result.class.getDeclaredConstructor(
                        String.class,String.class,boolean.class,int.class,List.class,List.class,String.class,boolean.class);ctor.setAccessible(true);
                child=ctor.newInstance(n.optString("child_text",""),n.getString("child_text_status"),n.getBoolean("child_text_truncated"),
                        n.getInt("child_text_visited"),sources,Collections.<int[]>emptyList(),n.optString("child_text_root_signature",""),n.getBoolean("child_text_sources_complete"));
                if("derived".equals(child.status)&&!child.bind(child.rootSignature).equals(n.getString("node_app_tree_sha256")))
                    throw new AssertionError("archived derived-label fingerprint differs");
            }
            JSONObject pos=n.getJSONObject("native_tree_position"),ime=n.getJSONObject("ime_enter");
            ObservedImeEnter enter=ime.getBoolean("observed")?(ime.getBoolean("present")?ObservedImeEnter.present(ime.isNull("action_label")?null:ime.getString("action_label")):ObservedImeEnter.ABSENT):ObservedImeEnter.UNKNOWN;
            nodes.add(new PhoneObservation.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),
                    n.optString("text",""),n.optString("description",""),rect(n.getJSONArray("bounds")),n.optBoolean("clickable",false),
                    n.optBoolean("editable",false),n.optBoolean("scrollable",false),n.optBoolean("enabled",true),n.optBoolean("focused",false),
                    n.optBoolean("password",false),child,n.getBoolean("scroll_actions_observed")?ObservedScrollActions.observed(strings(n.getJSONArray("scroll_directions"))):ObservedScrollActions.UNKNOWN,
                    enter,n.isNull("input_text_sha256")?null:n.getString("input_text_sha256"),n.getBoolean("submit_available"),
                    n.getString("node_app_tree_sha256"),pos.getString("path"),pos.getString("parent_class")));
        }
        JSONObject c=v.getJSONObject("collection");
        PhoneObservation.CollectionStats counts=omitCounts?null:new PhoneObservation.CollectionStats(c.getInt("visit_limit"),c.getInt("node_limit"),
                c.getInt("text_utf16_exclusive_limit"),c.getInt("visited_nodes"),c.getInt("retained_nodes"),c.getInt("retained_text_utf16"),
                c.getInt("pending_nodes_at_stop"),c.getInt("nodes_omitted_by_node_limit"),c.getInt("nodes_omitted_by_text_limit"),
                c.getLong("child_slots_omitted_by_traversal_limit"),c.getLong("elapsed_ms"));
        long rechecked=scope.getJSONObject("background_session").getJSONObject("app_display_readback").getLong("observed_ended_elapsed_ms");
        return new PhoneObservation(v.getString("observation_id"),v.getString("package"),rechecked,v.getInt("screen_width"),v.getInt("screen_height"),
                v.getInt("rotation"),v.getInt("window_id"),rect(w.getJSONArray("root_bounds")),null,v.getString("screen_sha256"),
                v.getString("observation_state_sha256"),new ObservationState(v.getString("app_tree_sha256"),v.getBoolean("ime_visible")?ImeVisibility.VISIBLE:ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(bounds(w.getJSONArray("root_bounds")),w.getString("root_class"),w.getInt("type"),w.getInt("display_id"),
                        bounds(w.getJSONArray("bounds")),w.getString("title")),v.getBoolean("nodes_truncated"),nodes,bg.getString("generation"),
                bg.getString("bootstrap_package"),strings(bg.getJSONArray("allowed_packages")),counts);
    }
    private static WebEvidenceReceipt receipt(JSONObject raw)throws Exception{
        JSONObject c=raw.getJSONObject("capture");
        WebDomStability.Result stable=WebDomStability.verify(c.getString("before_dom_raw_utf8"),c.getString("dom_raw_utf8"),
                WebTaskPurpose.FLIGHT_POLICY_ID,c.getJSONObject("dom_stability"));
        // This reconstructs a checked-value carrier only. It does not call verify(),
        // impersonate the helper UID, or claim the live authenticated reply was replayed.
        JSONObject callback=new JSONObject().put("status","captured").put("binding_sha256",raw.getString("binding_sha256"))
                .put("webview_instance",c.getString("webview_instance")).put("navigation_epoch",c.getLong("navigation_epoch"))
                .put("actual_display_id",c.getInt("display_id")).put("actual_window_id",c.getInt("actual_window_id"))
                .put("request_nonce",c.getString("challenge"));
        Constructor<WebEvidenceReceipt> ctor=WebEvidenceReceipt.class.getDeclaredConstructor(JSONObject.class,String.class,String.class,String.class,
                boolean.class,boolean.class,WebDomStability.Result.class,JSONObject.class);ctor.setAccessible(true);
        return ctor.newInstance(callback,raw.toString(),c.toString(),c.getString("dom_raw_utf8"),false,false,stable,null);
    }

    private static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    private static JSONObject node(JSONObject scope,String id){
        JSONArray nodes=scope.getJSONObject("observation").getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++)if(id.equals(nodes.getJSONObject(i).getString("id")))return nodes.getJSONObject(i);
        throw new AssertionError("fixture node absent: "+id);
    }
    /** Rebind only a deliberately mutated host child's production fingerprint.
     * This synthetic negative fixture is not a live native observation. */
    private static void rebindSyntheticChild(JSONObject scope,String id)throws Exception{
        JSONObject target=node(scope,id),pos=target.getJSONObject("native_tree_position");
        Map<String,JSONObject> byPath=new HashMap<String,JSONObject>();
        JSONArray nodes=scope.getJSONObject("observation").getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++){JSONObject n=nodes.getJSONObject(i);byPath.put(n.getJSONObject("native_tree_position").getString("path"),n);}
        List<ObservedChildText.Source> sources=new ArrayList<ObservedChildText.Source>();
        JSONArray original=target.getJSONArray("child_text_sources");
        for(int i=0;i<original.length();i++){
            JSONObject x=original.getJSONObject(i),desc=byPath.get(pos.getString("path")+"/"+x.getString("descendant_path"));
            sources.add(new ObservedChildText.Source(x.getString("descendant_path"),x.getString("property"),
                    desc.getString(x.getString("property")),x.getString("node_signature"),x.getString("view_id")));
        }
        Constructor<ObservedChildText.Result> ctor=ObservedChildText.Result.class.getDeclaredConstructor(
                String.class,String.class,boolean.class,int.class,List.class,List.class,String.class,boolean.class);ctor.setAccessible(true);
        ObservedChildText.Result child=ctor.newInstance(target.optString("child_text",""),target.getString("child_text_status"),
                target.getBoolean("child_text_truncated"),target.getInt("child_text_visited"),sources,Collections.<int[]>emptyList(),
                target.getString("child_text_root_signature"),target.getBoolean("child_text_sources_complete"));
        target.put("node_app_tree_sha256",child.bind(child.rootSignature));
    }
    private static JSONObject domNode(JSONObject dom,String path){
        JSONArray nodes=dom.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++)if(path.equals(nodes.getJSONObject(i).getString("path")))return nodes.getJSONObject(i);
        throw new AssertionError("fixture DOM path absent: "+path);
    }
    private static JSONObject changedDom(JSONObject raw,JSONObject dom)throws Exception{
        JSONObject result=copy(raw),c=result.getJSONObject("capture");String text=dom.toString();
        WebDomStability.Result stable=WebDomStability.evaluate(text,text,WebTaskPurpose.FLIGHT_POLICY_ID);
        c.put("dom_raw_utf8",text).put("before_dom_raw_utf8",text).put("dom_sha256",WebEvidenceJson.sha(text))
                .put("before_dom_sha256",WebEvidenceJson.sha(text)).put("dom_stability",stable.evidence())
                .put("dom_stability_sha256",WebDomCanonical.sha256(stable.evidence()));
        c.getJSONObject("capture_geometry").put("dom_stability_sha256",WebDomCanonical.sha256(stable.evidence()));
        return result;
    }
    private static WebFlightDomain domain(JSONObject raw,JSONObject scope)throws Exception{
        JSONObject binding=raw.getJSONObject("binding");WebTaskPurpose purpose=WebTaskPurpose.fromOwner(binding.getString("owner"));
        WebEvidenceReceipt receipt=receipt(raw);
        return WebFlightDomain.observed(binding.getString("task_id"),purpose.flight,
                purpose.authorization.bind(binding.getString("task_id")),frame(scope,false),receipt,receipt.bindingSha);
    }
    private static void noDate(WebFlightDomain domain,String reason){
        check(domain.purpose("n20")==null&&domain.purpose("n24")==null,reason+" must not fall back to wrapper");
        check(!domain.nativeValueMatches("date"),reason+" must not create date readback");
    }
    private static void noDate(JSONObject raw,JSONObject scope,String reason)throws Exception{
        try{noDate(domain(raw,scope),reason);}
        catch(IllegalArgumentException strictParserRefusal){check(true,reason+" rejected by original strict parser");}
    }
    public static void main(String[] args)throws Exception{
        Path dir=Paths.get(args[0]),output=Paths.get(args[1]);check(!Files.exists(output),"create-only output");
        final JSONObject raw=read(dir.resolve("actual-capture.json")),scope=read(dir.resolve("actual-scope.json"));
        final JSONObject dom=new JSONObject(raw.getJSONObject("capture").getString("dom_raw_utf8"));
        final String path="0/1/0/0/0/2/0/2/0/0/1/1/0";
        boolean legacy=args.length==3&&"legacy".equals(args[2]);
        if(legacy){
            test("actual_v62_wrapper_capability_and_missing_date_readback_reproduced",()->{
                WebFlightDomain old=domain(raw,scope);
                check("choose_departure_date".equals(old.purpose("n20"))&&old.purpose("n24")==null,"original wrapper mapping differs");
                check(!old.nativeValueMatches("date"),"original split/combined date mismatch must remain");
            });
        }else{
            test("actual_inner_native_date_target_replaces_wrapper",()->{
                WebFlightDomain d=domain(raw,scope);
                check(d.purpose("n20")==null&&"choose_departure_date".equals(d.purpose("n24")),"actual inner value not the only date target");
                check("11月14日周六".equals(d.capability("n24").get("native_label")),"native target literal was inferred");
                check(Boolean.FALSE.equals(d.capability("n24").get("dom_rect_used_as_target")),"DOM target coordinates introduced");
            });
            test("actual_split_dom_and_combined_native_value_readback",()->{
                WebFlightDomain d=domain(raw,scope);check(d.nativeValueMatches("date"),"actual date strings not read back");
                Map<String,Object> proof=d.nativeReadbacks.get("date");
                check(Arrays.asList("出发日期","11月14日","周六").equals(proof.get("observed_literal_texts")),"original DOM pieces changed");
                check("11月14日周六".equals(proof.get("observed_native_value")),"native complete literal differs");
                check(Boolean.TRUE.equals(proof.get("exact_join_without_normalization")),"join contract absent");
                check(Boolean.FALSE.equals(proof.get("calendar_opened_verified"))&&proof.get("displayed_year")==null,"calendar/year inferred");
            });
            test("readback_is_not_owner_date_or_query_confirmation",()->{
                WebFlightDomain d=domain(raw,scope);WebFlightProgress p=WebFlightProgress.begin(d).observed(d);
                check(!p.selectionConfirmed("date",d)&&!p.queryReady(d)&&!p.queryDispatched(),"11/14 readback became 2026/11/17 confirmation");
                WebFlightDomain restricted=d.withProgress(p);
                check(!restricted.resultReady()&&!restricted.clickIds.contains("n10"),"date readback bypassed query or result gate");
            });
            test("disabled_inner_target_never_falls_back",()->{
                JSONObject s=copy(scope);node(s,"n24").put("enabled",false);noDate(raw,s,"disabled inner");
            });
            test("foreign_inner_native_class_refused",()->{
                JSONObject s=copy(scope);node(s,"n24").put("class_name","android.widget.Button");noDate(raw,s,"wrong native class");
            });
            test("password_inner_target_refused",()->{
                JSONObject s=copy(scope);node(s,"n24").put("password",true);noDate(raw,s,"password inner");
            });
            test("editable_inner_target_refused",()->{
                JSONObject s=copy(scope);node(s,"n24").put("editable",true);noDate(raw,s,"editable inner");
            });
            test("incomplete_inner_derived_sources_refused",()->{
                JSONObject s=copy(scope);node(s,"n24").put("child_text_sources_complete",false);rebindSyntheticChild(s,"n24");noDate(raw,s,"incomplete child sources");
            });
            test("duplicate_clickable_descendant_counts_before_enabled_filter",()->{
                JSONObject s=copy(scope),duplicate=copy(node(s,"n24"));duplicate.put("id","duplicate-disabled").put("enabled",false).put("text","11月14日周六");
                for(String key:new ArrayList<String>(duplicate.keySet()))if(key.startsWith("child_text"))duplicate.remove(key);
                duplicate.getJSONObject("native_tree_position").put("path",node(s,"n20").getJSONObject("native_tree_position").getString("path")+"/2");
                s.getJSONObject("observation").getJSONArray("nodes").put(duplicate);
                noDate(raw,s,"duplicate disabled inner");
            });
            test("inner_target_outside_native_parent_refused",()->{
                JSONObject s=copy(scope);node(s,"n24").put("bounds",new JSONArray(new int[]{142,716,370,758}));noDate(raw,s,"outside parent");
            });
            test("unknown_dom_descendant_refused_without_parent_fallback",()->{
                JSONObject d=copy(dom),extra=copy(domNode(d,path+"/1/0/0"));
                extra.put("path",path+"/1/0/1").put("parent_path",path+"/1/0").put("text","额外信息");
                d.getJSONArray("nodes").put(extra);
                d.put("visited",d.getJSONArray("nodes").length()).put("text_utf16_units",d.getInt("text_utf16_units")+extra.getString("text").length());
                noDate(changedDom(raw,d),scope,"unknown DOM descendant");
            });
            test("hidden_dom_value_control_refused",()->{
                JSONObject d=copy(dom);domNode(d,path+"/1").put("hidden_attr",true);noDate(changedDom(raw,d),scope,"hidden DOM value");
            });
            test("linked_dom_value_control_refused",()->{
                JSONObject d=copy(dom);domNode(d,path+"/1").put("href_raw","/book").put("href_resolved","https://m.csair.com/book");
                noDate(changedDom(raw,d),scope,"linked DOM value");
            });
            test("wrong_dom_weekday_not_normalized",()->{
                JSONObject d=copy(dom);domNode(d,path+"/1/0/0").put("text","周日");noDate(changedDom(raw,d),scope,"different weekday");
            });
            test("different_dom_day_not_inferred_from_owner",()->{
                JSONObject d=copy(dom);domNode(d,path+"/1/0").put("text","11月17日");noDate(changedDom(raw,d),scope,"different day");
            });
            test("missing_native_value_leaf_cannot_be_replaced_by_label",()->{
                JSONObject s=copy(scope);node(s,"n28").put("text","出发日期");
                boolean rejected=false;try{noDate(raw,s,"missing native value");}catch(AssertionError expected){rejected=expected.getMessage().contains("original descendant string hash differs");}
                check(rejected,"archived child source hash must reject changed literal before production");
            });
            test("truncated_collection_cannot_map_nested_target",()->{
                JSONObject s=copy(scope);s.getJSONObject("observation").getJSONObject("collection").put("pending_nodes_at_stop",1);
                noDate(raw,s,"truncated collection");
            });
        }
        JSONObject result=new JSONObject().put("schema","hepta.flight-date-real-fixture-host.v1").put("all_pass",true)
                .put("cases",cases).put("assertions",assertions).put("case_names",names).put("legacy_mode",legacy)
                .put("actual_fixture_bytes_preserved",true).put("actual_production_domain_parser",true)
                .put("negative_mutations_synthetic",true).put("live_authenticated_ipc_replayed",false)
                .put("live_native_authority_reconstructed",false).put("calendar_opened_on_phone_verified",false)
                .put("phone_operations",0).put("query_dispatched",false).put("business_verified",false);
        Files.write(output,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(result.toString());
    }
}
