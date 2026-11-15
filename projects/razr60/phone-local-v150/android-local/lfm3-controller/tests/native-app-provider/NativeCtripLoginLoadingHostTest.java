package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Actual R18 AX semantics, with the account field explicitly redacted.
 * Task/lease/NodeRef/installed identity, model and dispatch remain host doubles.
 * No Android IPC, phone, login, consent or model inference is executed. */
final class NativeCtripLoginLoadingHostTest {
    static Path fixtures;static int checks;static final List<String> names=new ArrayList<String>();
    interface Test {void run()throws Exception;}
    static void check(boolean yes,String why){checks++;if(!yes)throw new AssertionError(why);}
    static void reject(Test t,String why)throws Exception{checks++;try{t.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}throw new AssertionError(why);}
    static void one(String name,Test t)throws Exception{t.run();names.add(name);}
    static String hash(String text){return NativeAppEvidence.hash(text);}
    static JSONObject raw(String name)throws Exception{return new JSONObject(new String(Files.readAllBytes(fixtures.resolve(name)),StandardCharsets.UTF_8));}
    static JSONObject login()throws Exception{return raw("ctrip-login-r18-redacted.json");}
    static JSONObject loading()throws Exception{return raw("ctrip-loading-r18.json");}
    static JSONObject node(JSONObject r,String id){JSONArray ns=r.getJSONArray("nodes");for(int i=0;i<ns.length();i++)if(id.equals(ns.getJSONObject(i).getString("id")))return ns.getJSONObject(i);throw new AssertionError(id);}
    static void remove(JSONObject r,String id){JSONArray ns=r.getJSONArray("nodes");for(int i=0;i<ns.length();i++)if(id.equals(ns.getJSONObject(i).getString("id"))){ns.remove(i);r.getJSONObject("collection").put("retained_nodes",ns.length());return;}throw new AssertionError(id);}
    static NativeAppProviderHostTest.Harness harness(String name)throws Exception{return new NativeAppProviderHostTest.Harness("login-loading:"+name);}
    static NativeAppEvidence.Frame frame(NativeAppProviderHostTest.Harness h,JSONObject r)throws Exception{
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();List<NotesCompletionEvidence.Node> retained=new ArrayList<NotesCompletionEvidence.Node>();
        JSONArray rows=r.getJSONArray("nodes");
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i),pos=n.getJSONObject("native_tree_position"),sel=n.getJSONObject("native_selection_state");
            JSONArray b=n.getJSONArray("bounds");String text=n.optString("text",""),desc=n.optString("description","");
            String label=ObservedTargetLabels.project(text.isEmpty()?desc:text);
            Set<String> dirs=new TreeSet<String>();JSONArray ds=n.optJSONArray("scroll_directions");if(ds!=null)for(int k=0;k<ds.length();k++)dirs.add(ds.getString(k));
            Boolean selected=sel.optBoolean("observed")?Boolean.valueOf(sel.getBoolean("selected")):null;
            NativeAppEvidence.Node x=new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),
                    text,desc,pos.getString("path"),pos.getString("parent_class"),n.getString("node_app_tree_sha256"),label,
                    b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),n.optBoolean("enabled",true),n.optBoolean("password"),
                    n.optBoolean("clickable"),n.optBoolean("editable"),n.optBoolean("scrollable"),selected,
                    selected==null?null:Boolean.valueOf(sel.getBoolean("checkable")),selected==null?null:Boolean.valueOf(sel.getBoolean("checked")),dirs);
            nodes.add(x);retained.add(new NotesCompletionEvidence.Node(x.id,x.packageName,x.text,x.label,x.viewId,null,new int[]{x.left,x.top,x.right,x.bottom},
                    x.editable,x.clickable,x.scrollable,x.enabled,x.password,ObservedChildText.notApplicable(),x.signature));
        }
        h.observation++;h.time+=10;String obs=hash(h.task+":redacted-AX-host:"+h.observation).substring(0,32);JSONObject w=r.getJSONObject("window");
        int width=r.getInt("screen_width"),height=r.getInt("screen_height"),type=w.getInt("type");JSONArray bounds=w.getJSONArray("bounds");
        boolean truncated=r.optBoolean("nodes_truncated"),metadata=!r.optBoolean("host_metadata_missing");
        JSONObject counts=r.getJSONObject("collection");boolean complete=counts.getInt("retained_nodes")==nodes.size()&&counts.optInt("pending_nodes_at_stop")==0
                &&counts.optInt("child_slots_omitted_by_traversal_limit")==0&&counts.optInt("nodes_omitted_by_node_limit")==0&&counts.optInt("nodes_omitted_by_text_limit")==0;
        h.completion=new NotesCompletionEvidence.Frame(obs,r.getString("package"),70,7,NativeAppProviderHostTest.GENERATION,type,metadata,truncated,retained);
        String completionSha=TaskCompletionGate.webFrameSha(h.completion);
        if(completionSha==null)completionSha=hash("synthetic-incomplete-completion:"+obs); // unavailable metadata has no TCG completion hash
        return new NativeAppEvidence.Frame(h.task,NativeAppProviderHostTest.goal().ownerSha256,h.selected.target.targetSha256,h.auth.sha256,
                hash("synthetic-selection-wire:"+h.selected.target.targetSha256),obs,r.getString("package"),NativeAppProviderHostTest.GENERATION,
                hash("synthetic-AX-tree:"+r.toString()),hash("synthetic-AX-state:"+r.toString()),hash("synthetic-image-not-opened"),
                hash("synthetic-redacted-AX-record:"+obs+":"+r.toString()),completionSha,7,70,r.getInt("rotation"),
                width,height,bounds.getInt(0),bounds.getInt(1),bounds.getInt(2),bounds.getInt(3),h.time,truncated,complete,nodes,type,metadata);
    }
    static void observe(NativeAppProviderHostTest.Harness h,JSONObject r)throws Exception{h.frame=frame(h,r);h.session.observed(h.frame);h.gate.observed(h.completion);}
    static NativeCtripFlightPage.Page inspect(JSONObject r)throws Exception{return NativeCtripFlightPage.inspect(NativeAppProviderHostTest.goal(),frame(harness("inspect"),r));}
    static void unavailable(JSONObject r)throws Exception{NativeCtripFlightPage.Page p=inspect(r);check(NativeCtripFlightPage.UNAVAILABLE.equals(p.phase),"unsupported shape stays unavailable");check(p.form==null&&p.homeFlight==null&&p.quotes.isEmpty(),"no business fields or actions");}
    static void noEffects(NativeAppDomain d){check(d.clickIds.isEmpty()&&d.resourceClickIds.isEmpty()&&d.editValues.isEmpty()&&!d.backAllowed&&!d.resultReady,"no effect or successful result permission");}
    static ActionDecision action(NativeAppProviderHostTest.Harness h,String kind,String status,String id)throws Exception{
        JSONObject j=new JSONObject().put("action",kind).put("package",h.frame.packageName).put("observation_id",h.frame.observationId);
        if(status!=null)j.put("status",status).put("summary","synthetic host result");
        if("wait".equals(kind))j.put("milliseconds",500);
        if(id!=null)j.put("node_id",id).put("node_label",h.frame.byId.get(id).label);
        return ActionDecision.parse(j.toString(),ActionDecision.IME_ACTION_SCHEMA);
    }
    static DecisionGrammar grammar(NativeAppProviderHostTest.Harness h){
        Map<String,String> pairs=new TreeMap<String,String>();for(NativeAppEvidence.Node n:h.frame.nodes)pairs.put(n.id,n.label);
        NativeAppDomain d=h.session.domain();
        return DecisionGrammar.createImeAuthorized(h.frame.observationId,h.frame.packageName,Collections.<String>emptySet(),d.clickIds,d.editValues.keySet(),
                Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),
                ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,h.frame.observationId,h.frame.packageName,pairs),
                ObservedAppLabels.create(ObservedAppLabels.SCHEMA,h.frame.observationId,h.frame.packageName,Collections.<String,String>emptyMap()),
                h.owner.frame(),true,d.toolMask(new HashSet<String>(Arrays.asList("click","type","back","open","scroll","submit","wait","done"))),d.resultReady);
    }
    static void query17(NativeAppProviderHostTest.Harness h)throws Exception{
        h.observe("form17.xml");h.perform("inspect_departure_year","calendar14.xml");h.perform("return_from_calendar","form17.xml");
        h.issue(h.action("query_observed_form"),true,true,false);
    }
    static void addRole(JSONObject r,String role){JSONObject x=new JSONObject(node(r,"n2").toString());x.put("id","n99").put("view_id",role).put("description",role).put("text","");
        x.getJSONObject("native_tree_position").put("path","0/9");r.getJSONArray("nodes").put(x);r.getJSONObject("collection").put("retained_nodes",r.getJSONArray("nodes").length());}
    static void denyInstalled(long version,String apk)throws Exception{
        NativeAppProviderHostTest.Harness h=harness("installed");
        reject(()->new NativeAppSession(h.task,h.owner,h.selected,new NativeAppEvidence.Installed(NativeAppGoal.CTRIP_PACKAGE,10367,version,Collections.singletonMap("base",apk)),
                hash("synthetic-selection-wire:"+h.selected.target.targetSha256),NativeAppProviderHostTest.GENERATION,7,
                new NativeAppSession.InstalledVerifier(){public void verify(){}},new NativeAppSession.Journal(){public void write(String leaf,Map<String,Object> value){}}),"exact installed identity required");
    }
    public static void main(String[] args)throws Exception{
        fixtures=Paths.get(args[0]);NativeAppProviderHostTest.fixtures=fixtures;Path output=Paths.get(args[1]);
        one("actual_redacted_login_ax_recognized_without_any_effect_or_result",()->{
            NativeAppProviderHostTest.Harness h=harness("actual");observe(h,login());check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"observed login phase");
            noEffects(h.session.domain());check(h.session.domain().missing.contains("native_ctrip_login_requires_user_handling"),"truthful blocker");
            check(!h.gate.verified(h.completion),"not a flight result");
            JSONObject view=new JSONObject(h.session.domain().promptEvidence()).getJSONObject("provider");
            check(view.getBoolean("requires_user_handling")&&!view.getBoolean("credentials_or_agreement_actions_available"),"public obstruction without account actions");
        });
        one("account_value_does_not_participate_in_recognition_or_public_projection",()->{
            JSONObject r=login();node(r,"n1").put("text","[SECOND ARTIFICIAL ACCOUNT]").put("description","[SECOND ARTIFICIAL ACCOUNT]");
            NativeAppProviderHostTest.Harness h=harness("redaction");observe(h,r);check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"account independent");
            check(!new JSONObject(h.session.domain().promptEvidence()).toString().contains("SECOND ARTIFICIAL ACCOUNT"),"no account field projected");
        });
        one("login_exact_authorized_grammar_only_wait_and_incomplete_done",()->{
            NativeAppProviderHostTest.Harness h=harness("grammar");observe(h,login());DecisionGrammar g=grammar(h);
            check(g.actions.size()==2&&new TreeSet<String>(g.actions).equals(new TreeSet<String>(Arrays.asList("wait","done")))&&!g.successAllowed,"no effect grammar or success");
            h.session.domain().requireCurrent(action(h,"done","partial",null));h.session.domain().requireCurrent(action(h,"done","failure",null));
        });
        one("login_button_agreement_return_and_done_success_are_refused",()->{
            NativeAppProviderHostTest.Harness h=harness("reject-actions");observe(h,login());
            for(String id:new String[]{"n0","n3","n4","n5","n7","n9","n11"})reject(()->h.session.domain().requireCurrent(action(h,"click",null,id)),"no login or agreement or return click");
            reject(()->h.session.domain().requireCurrent(action(h,"back",null,null)),"no back");
            reject(()->h.session.domain().requireCurrent(action(h,"done","success",null)),"no success");
        });
        one("login_foreign_package_is_not_recognized",()->{JSONObject r=login();r.put("package","foreign.app");unavailable(r);});
        one("login_foreign_owner_is_not_recognized",()->{NativeAppProviderHostTest.Harness h=harness("owner");NativeAppEvidence.Frame f=frame(h,login());check(NativeCtripFlightPage.UNAVAILABLE.equals(NativeCtripFlightPage.inspect(NativeAppProviderHostTest.goal(),NativeAppProviderHostTest.altered(f,hash("foreign"),f.targetSha,f.generation,true,false)).phase),"owner required");});
        one("login_wrong_installed_version_is_refused",()->denyInstalled(1778,NativeCtripFlightPage.BASE_APK_SHA256));
        one("login_wrong_installed_apk_is_refused",()->denyInstalled(1779,hash("different-apk")));
        one("login_installed_identity_rechecked_before_observation",()->{NativeAppProviderHostTest.Harness h=harness("installed-recheck");h.installedCurrent=false;reject(()->observe(h,login()),"installed reread");});
        one("login_nonapplication_window_is_unavailable",()->{JSONObject r=login();r.getJSONObject("window").put("type",2);unavailable(r);});
        one("login_unknown_window_metadata_is_unavailable",()->{JSONObject r=login();r.put("host_metadata_missing",true);unavailable(r);});
        one("login_incomplete_collection_is_unavailable",()->{JSONObject r=login();r.getJSONObject("collection").put("pending_nodes_at_stop",1);unavailable(r);});
        one("login_truncated_collection_is_unavailable",()->{JSONObject r=login();r.put("nodes_truncated",true);unavailable(r);});
        one("each_required_login_anchor_is_required",()->{for(String id:new String[]{"n2","n3","n4","n5","n6","n7","n9","n11","n13"}){JSONObject r=login();remove(r,id);unavailable(r);}});
        one("login_wrong_resource_text_or_class_is_unavailable",()->{for(String key:new String[]{"view_id","text","class_name"}){JSONObject r=login();node(r,"n3").put(key,"unrecognized");unavailable(r);}});
        one("duplicate_and_foreign_duplicate_login_anchors_are_not_silently_ignored",()->{for(String pkg:new String[]{NativeAppGoal.CTRIP_PACKAGE,"foreign.app"}){JSONObject r=login();JSONObject n=new JSONObject(node(r,"n3").toString()).put("id","n99").put("package",pkg);n.getJSONObject("native_tree_position").put("path","0/0/99");r.getJSONArray("nodes").put(n);r.getJSONObject("collection").put("retained_nodes",15);unavailable(r);}});
        one("offscreen_login_anchor_is_unavailable",()->{JSONObject r=login();node(r,"n3").getJSONArray("bounds").put(0,-1);unavailable(r);});
        one("disabled_password_editable_scrollable_and_selection_changes_are_unavailable",()->{
            for(String key:new String[]{"enabled","password","editable","scrollable","clickable"}){JSONObject r=login();node(r,"n3").put(key,!"enabled".equals(key)&&!"clickable".equals(key));unavailable(r);}
            for(String key:new String[]{"selected","checkable","checked"}){JSONObject r=login();node(r,"n13").getJSONObject("native_selection_state").put(key,true);unavailable(r);}
        });
        one("missing_selection_tuple_cannot_recognize_login",()->{JSONObject r=login();node(r,"n13").getJSONObject("native_selection_state").put("observed",false);unavailable(r);});
        one("login_anchors_require_same_observed_scroll_container",()->{JSONObject r=login();node(r,"n4").getJSONObject("native_tree_position").put("path","0/1/6");unavailable(r);});
        one("login_agreement_indicator_requires_same_parent_and_bounds",()->{JSONObject r=login();node(r,"n13").getJSONObject("native_tree_position").put("path","0/0/15/0");unavailable(r);});
        one("overlapping_login_controls_are_unavailable",()->{JSONObject r=login();node(r,"n4").put("bounds",node(r,"n3").getJSONArray("bounds"));unavailable(r);});
        one("login_mixed_with_flight_form_result_home_or_calendar_is_unavailable",()->{
            for(String role:new String[]{"ctrip.android.view:id/bt_submit_inquire","单程列表页","ctrip.android.view:id/home_grid_flight_widget","ctrip.android.view:id/calendar_month_title_left_tv"}){JSONObject r=login();addRole(r,role);unavailable(r);}
        });
        one("unknown_page_does_not_gain_login_or_flight_capability",()->{JSONObject r=login();JSONArray rows=new JSONArray().put(node(r,"n0"));r.put("nodes",rows);r.getJSONObject("collection").put("retained_nodes",1);unavailable(r);});
        one("pending_query_login_reports_blocker_without_creating_query_or_result",()->{
            NativeAppProviderHostTest.Harness h=harness("pending-login");query17(h);observe(h,login());
            check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"login overrides pending projection");noEffects(h.session.domain());check(!h.gate.verified(h.completion),"login is not query result");
        });
        one("pending_login_done_and_final_observation_keep_query_unproved",()->{
            for(String status:new String[]{"partial","failure"}){
                NativeAppProviderHostTest.Harness h=harness("pending-done:"+status);query17(h);observe(h,login());
                h.issue(action(h,"done",status,null),true,false,false);observe(h,login());
                check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"final current login still reported");noEffects(h.session.domain());
                JSONObject progress=new JSONObject(h.session.evidence()).getJSONObject("progress");
                check(progress.isNull("last_query_date")&&!progress.isNull("pending"),"login and incomplete done never close the query transition");
                check(!h.gate.verified(h.completion)&&!NativeAppProviderHostTest.passed(h.normal()),"normal cleanup cannot make blocked query a completed flight search");
            }
        });
        one("pending_login_preserves_original_transition_deadline",()->{
            NativeAppProviderHostTest.Harness h=harness("pending-login-deadline");query17(h);observe(h,login());h.time+=15001;observe(h,login());
            reject(()->h.session.domain(),"expired original query transition remains invalid");
            JSONObject evidence=new JSONObject(h.session.evidence());
            check(evidence.getBoolean("invalid")&&"actual_native_transition_observation_deadline".equals(evidence.getString("invalid_reason")),"original deadline not extended by login recognition");
            check(evidence.getJSONObject("progress").isNull("last_query_date")&&!h.gate.verified(h.completion),"no query proof or result after deadline");
        });
        one("actual_query_loading_page_has_date_strip_but_no_complete_card",()->{NativeCtripFlightPage.Page p=inspect(loading());check(NativeCtripFlightPage.RESULTS.equals(p.phase)&&p.quotes.isEmpty(),"actual loading results retained");check(java.time.LocalDate.of(2026,11,17).equals(p.displayedMonthDay(java.time.LocalDate.of(2026,11,17))),"actual date rail retained");});
        one("same_target_query_proof_with_empty_cards_waits_without_requery_back",()->{
            NativeAppProviderHostTest.Harness h=harness("loading");query17(h);observe(h,loading());NativeAppDomain d=h.session.domain();noEffects(d);
            check(d.missing.contains("native_target_query_waiting_for_complete_cards")&&!d.missing.contains("target_date_form_and_explicit_query_required"),"missing cards not missing query");
            JSONObject v=new JSONObject(d.promptEvidence()).getJSONObject("provider");check("2026-11-17".equals(v.getString("last_explicit_query_date")),"query proof preserved");
            check(grammar(h).actions.size()==2&&new TreeSet<String>(grammar(h).actions).equals(new TreeSet<String>(Arrays.asList("wait","done")))&&!grammar(h).successAllowed,"only incomplete continuation");
        });
        one("complete_cards_after_loading_can_complete_without_a_second_query",()->{
            NativeAppProviderHostTest.Harness h=harness("loading-complete");query17(h);observe(h,loading());h.observe("result17.xml");
            check(h.session.domain().resultReady&&h.gate.verified(h.completion),"same original target query plus complete cards");check(h.target("query_observed_form")==null,"no duplicate query grant");
        });
        one("loading_without_same_task_query_proof_keeps_original_back_requirement",()->{
            NativeAppProviderHostTest.Harness h=harness("no-proof");observe(h,loading());check(h.session.domain().backAllowed&&h.session.domain().missing.contains("same_task_explicit_query_missing"),"no proof still requires form");check(!h.session.domain().resultReady,"no unproved result");
        });
        one("non_target_query_then_target_result_date_still_requires_target_form_query",()->{
            NativeAppProviderHostTest.Harness h=harness("wrong-query-date");h.year();h.perform("query_observed_form","result14.xml");observe(h,loading());
            check(h.session.domain().backAllowed&&h.session.domain().missing.contains("target_date_form_and_explicit_query_required"),"non-target proof cannot be upgraded");check(!h.session.domain().resultReady,"no result");
        });
        one("target_query_with_wrong_current_result_date_keeps_date_navigation",()->{
            NativeAppProviderHostTest.Harness h=harness("wrong-shown");query17(h);h.observe("result17.xml");h.observe("result14.xml");
            check(!h.session.domain().resultReady&&!h.session.domain().missing.contains("native_target_query_waiting_for_complete_cards"),"wrong current date not treated as target loading");
            boolean nav=false;for(String p:h.session.domain().purposes.values())if(p.startsWith("navigate_departure_date:"))nav=true;check(nav,"original bounded date navigation retained");
        });
        one("stale_undispatched_query_never_becomes_target_loading_proof",()->{
            NativeAppProviderHostTest.Harness h=harness("stale-query");h.observe("form17.xml");h.perform("inspect_departure_year","calendar14.xml");h.perform("return_from_calendar","form17.xml");
            h.issue(h.action("query_observed_form"),false,false,true);observe(h,loading());
            check(!h.session.domain().resultReady&&h.session.domain().missing.contains("same_task_explicit_query_missing"),"stale proposal creates no query proof");
        });
        one("complete_cards_without_query_proof_remain_unverified",()->{NativeAppProviderHostTest.Harness h=harness("cached-cards");h.observe("result17.xml");check(!h.session.domain().resultReady&&h.session.domain().backAllowed,"complete cached quotes are not task completion");});
        one("loading_then_login_has_truthful_blocker_and_no_return_permission",()->{NativeAppProviderHostTest.Harness h=harness("loading-login");query17(h);observe(h,loading());observe(h,login());check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"real observed next phase");noEffects(h.session.domain());});
        one("login_revokes_previously_ready_flight_cards",()->{NativeAppProviderHostTest.Harness h=harness("ready-login");h.ready();observe(h,login());noEffects(h.session.domain());check(!h.gate.verified(h.completion),"login cannot reuse prior result");});
        one("incomplete_loading_observation_never_receives_result_or_navigation",()->{NativeAppProviderHostTest.Harness h=harness("incomplete-loading");query17(h);JSONObject r=loading();r.put("nodes_truncated",true);observe(h,r);noEffects(h.session.domain());check(!h.gate.verified(h.completion),"incomplete post-query frame no result");});
        Map<String,Object> out=NativeAppEvidence.map();out.put("schema","hepta.native-ctrip-login-loading-host.v1");out.put("all_pass",true);
        out.put("case_names",names);out.put("cases",names.size());out.put("assertions",checks);out.put("phone_operations",0);out.put("android_runtime",false);
        out.put("model_executed",false);out.put("business_verified",false);out.put("account_field_artificially_redacted",true);
        Files.write(output,(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println("ctrip login/loading "+names.size()+" cases / "+checks+" assertions");
    }
}
