package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.webprotocol.*;

/** Retained real DOM/AX/outcome values through real pure parsers and extracted retry methods.
 * Archived labels/receipt metadata are host value carriers, never reconstructed native
 * authority or authenticated IPC. Frame clock uses the recorded post-observation display
 * recheck inside the bracket because capturedElapsedMillis is not serialized in AX JSON. */
public final class WebCityObservationFixtureHostTest {
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
    private static final class Fixture {
        final JSONObject firstRaw,lastRaw,lastScope,outcome;final WebTaskPurpose purpose;
        final WebFlightDomain before;final ActionDecision action;final PhoneObservation firstFrame,lastFrame;
        final WebEvidenceReceipt first,last;final WebDomStability.Result bracket;final WebCityObservationRetryProjection current;
        final LegacyCityObservationRetryProjection old;final Object token;
        Fixture(Path dir)throws Exception{
            JSONObject index=read(dir.resolve("PROVENANCE.json"));Map<String,JSONObject> values=new HashMap<String,JSONObject>();
            JSONArray files=index.getJSONArray("files");for(int i=0;i<files.length();i++){JSONObject f=files.getJSONObject(i);values.put(f.getString("role"),read(dir.resolve(f.getString("name"))));}
            firstRaw=values.get("first_capture");lastRaw=values.get("last_capture");lastScope=values.get("last_frame");outcome=values.get("outcome");
            JSONObject binding=firstRaw.getJSONObject("binding");purpose=WebTaskPurpose.fromOwner(binding.getString("owner"));
            WebEvidenceReceipt source=receipt(values.get("before_capture"));PhoneObservation sourceFrame=frame(values.get("before_frame"),false);
            before=WebFlightDomain.observed(binding.getString("task_id"),purpose.flight,purpose.authorization.bind(binding.getString("task_id")),sourceFrame,source,source.bindingSha);
            action=ActionDecision.parse(values.get("action").getJSONObject("action").toString());
            current=new WebCityObservationRetryProjection(before,purpose);old=new LegacyCityObservationRetryProjection(before,purpose);
            token=current.token(before,action,outcome.getString("model_run_id"),outcome.getBoolean("accepted"),outcome.getBoolean("dispatched"),
                    outcome.getBoolean("stale"),outcome.getLong("dispatch_before_elapsed_ms"),outcome.getLong("dispatch_after_elapsed_ms"));
            first=receipt(firstRaw);last=receipt(lastRaw);firstFrame=frame(values.get("first_frame"),false);lastFrame=frame(lastScope,false);
            bracket=WebDomStability.evaluate(first.domRaw(),last.beforeDomRaw(),purpose.sitePolicyId);
        }
        boolean retry(PhoneObservation actual,WebEvidenceReceipt b,WebDomStability.Result between)throws Exception{
            current.now(last.ended+1);return current.retry(first,b,actual,false,between,token,last.ended+60000);
        }
    }
    public static void main(String[] args)throws Exception{
        Path dir=Paths.get(args[0]),output=Paths.get(args[1]);check(!Files.exists(output),"create-only output");
        test("actual_four_dom_strings_equal_complete_arrival_picker",()->{
            Fixture f=new Fixture(dir);check(f.first.beforeDomRaw().equals(f.first.domRaw())&&f.first.domRaw().equals(f.last.beforeDomRaw())&&f.last.beforeDomRaw().equals(f.last.domRaw()),"original four strings differ");
            check(f.bracket.rawEqual&&"arrival".equals(CsairCityPicker.read(f.first.dom()).kind),"not actual complete arrival picker");
            check(f.lastFrame.collectionStats.visited==620&&f.lastFrame.collectionStats.retained==61&&!f.lastFrame.collectionStats.truncated(),"actual AX counters differ");
            check(f.first.ended<=f.lastFrame.capturedElapsedMillis&&f.lastFrame.capturedElapsedMillis<=f.last.started,"recorded post-AX recheck not within actual bracket");
        });
        test("actual_header_geometry_drift_remains_unstable",()->{
            Fixture f=new Fixture(dir);check(!WebCityObservationRetryProjection.same(f.firstFrame,f.lastFrame),"actual changed tree cannot be stable");
            Map<String,PhoneObservation.Node> byId=new HashMap<String,PhoneObservation.Node>();for(PhoneObservation.Node n:f.firstFrame.nodes)byId.put(n.id,n);
            int differences=0;for(PhoneObservation.Node n:f.lastFrame.nodes){PhoneObservation.Node before=byId.get(n.id);if(!n.bounds.equals(before.bounds)){differences++;check("n17".equals(n.id)||"n18".equals(n.id),"unexpected changed native bounds");}}
            check(differences==2,"original two header-node changes lost");
        });
        test("actual_v61_retry_refusal_preserved_new_read_only_retry_admitted",()->{
            Fixture f=new Fixture(dir);check(f.token!=null&&"choose_arrival_city".equals(f.before.purpose(f.action.nodeId)),"actual pure source target was not arrival control");
            f.old.now(f.last.ended+1);check(!f.old.retry(f.first,f.last,f.lastFrame,false,f.bracket,null,f.last.ended+60000),"old complete picker must not retry");
            check(f.retry(f.lastFrame,f.last,f.bracket)&&f.current.retries()==1&&f.current.records()==1,"new actual-value bracket cannot enter bounded retry");
            check(!WebCityObservationRetryProjection.same(f.firstFrame,f.lastFrame),"retry must not relabel old pair as stable");
        });
        test("actual_values_without_native_dispatch_do_not_create_retry_source",()->{
            Fixture f=new Fixture(dir);check(f.current.token(f.before,f.action,f.outcome.getString("model_run_id"),true,false,false,
                    f.outcome.getLong("dispatch_before_elapsed_ms"),f.outcome.getLong("dispatch_after_elapsed_ms"))==null,"planned-only native action grants retry");
        });
        test("actual_values_missing_complete_ax_counts_refused",()->{
            Fixture f=new Fixture(dir);check(!f.retry(frame(f.lastScope,true),f.last,f.bracket)&&f.current.retries()==0,"archived flat rows cannot invent complete traversal");
        });
        test("actual_values_without_four_dom_proof_refused",()->{
            Fixture f=new Fixture(dir);check(!f.retry(f.lastFrame,f.last,null)&&f.current.retries()==0,"missing full cross-capture DOM proof grants retry");
        });
        JSONObject result=new JSONObject().put("schema","hepta.city-observation-real-fixture-host.v1").put("all_pass",true).put("cases",cases)
                .put("assertions",assertions).put("case_names",names).put("phone_operations",0).put("action_replays",0).put("query_replays",0)
                .put("business_verified",false).put("actual_fixture_bytes_preserved",true).put("actual_production_pure_domain_parser",true)
                .put("exact_current_and_legacy_retry_methods",true).put("live_authenticated_ipc_replayed",false).put("live_native_authority_reconstructed",false)
                .put("future_page_stability_proven",false).put("host_value_carriers","retained labels, checked receipt metadata, and recorded post-AX recheck clock");
        Files.write(output,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(result.toString());
    }
}
