package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Exact, unmodified 19-node SMS login record from the failed ebb383 run.
 * Existing host query XML and synthetic task/window/model/outcome fixtures are
 * composed with the actual production Session, domain and grammar. This is not
 * a phone rerun, successful login, result query or physical-screen assertion. */
final class NativeCtripSmsLoginHostTest {
    static int assertions;
    static final List<String> names=new ArrayList<String>();
    interface Test {void run()throws Exception;}
    static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static void reject(Test test,String why)throws Exception{assertions++;try{test.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}throw new AssertionError(why);}
    static void one(String name,Test test)throws Exception{test.run();names.add(name);}
    static String hash(String text){return NativeAppEvidence.hash(text);}
    static JSONObject sms()throws Exception{return NativeCtripLoginLoadingHostTest.raw("ctrip-sms-login-r18.json");}
    static JSONObject node(JSONObject r,String id){return NativeCtripLoginLoadingHostTest.node(r,id);}
    static void observe(NativeAppProviderHostTest.Harness h,JSONObject r)throws Exception{NativeCtripLoginLoadingHostTest.observe(h,r);}
    static NativeAppProviderHostTest.Harness fresh(String name)throws Exception{return NativeCtripLoginExitHostTest.fresh("sms:"+name);}
    static NativeAppProviderHostTest.Harness queried(String name)throws Exception{return NativeCtripLoginExitHostTest.queried("sms:"+name);}
    static NativeAppProviderHostTest.Harness atSms(String name)throws Exception{NativeAppProviderHostTest.Harness h=queried(name);observe(h,sms());return h;}
    static JSONObject progress(NativeAppSession s){return NativeCtripLoginExitHostTest.progress(s);}
    static ActionDecision action(NativeAppProviderHostTest.Harness h,String kind,String status,String id)throws Exception{return NativeCtripLoginLoadingHostTest.action(h,kind,status,id);}
    static void noReturn(NativeAppProviderHostTest.Harness h){NativeAppDomain d=h.session.domain();check(d.clickIds.isEmpty()&&d.resourceClickIds.isEmpty()&&d.editValues.isEmpty()&&!d.backAllowed&&!d.resultReady,"no return, account, system Back or result authority");}
    static void onlyReturn(NativeAppProviderHostTest.Harness h){
        NativeAppDomain d=h.session.domain();check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(d.phase),"actual SMS login recognized");
        check(d.clickIds.equals(Collections.singleton("n0"))&&d.resourceClickIds.equals(Collections.singleton("n0"))&&d.editValues.isEmpty()&&!d.backAllowed&&!d.resultReady,"only exact empty-label resource return");
        check(d.purposes.equals(Collections.singletonMap("n0",NativeCtripFlightPage.LOGIN_EXIT)),"same query-bound one-use return purpose");
        check(h.frame.byId.get("n0").label.isEmpty()&&h.frame.byId.get("n0").text.isEmpty()&&h.frame.byId.get("n0").description.isEmpty(),"no observed label fabricated");
    }
    static void mutated(JSONObject r)throws Exception{NativeAppProviderHostTest.Harness h=queried("mutation:"+names.size()+":"+assertions);observe(h,r);noReturn(h);}
    static void duplicate(JSONObject r,String id,String pkg){JSONObject n=new JSONObject(node(r,id).toString()).put("id","n99").put("package",pkg);n.getJSONObject("native_tree_position").put("path","0/0/0/99");r.getJSONArray("nodes").put(n);r.getJSONObject("collection").put("retained_nodes",r.getJSONArray("nodes").length());}
    static void returned(NativeAppProviderHostTest.Harness h,String xml)throws Exception{NativeCtripLoginExitHostTest.returned(h,xml);}

    public static void main(String[] args)throws Exception{
        NativeAppProviderHostTest.fixtures=Paths.get(args[0]);NativeCtripLoginLoadingHostTest.fixtures=Paths.get(args[0]);Path output=Paths.get(args[1]);
        one("actual_19_node_sms_login_is_recognized_without_query_or_action",()->{
            JSONObject r=sms();check(r.getJSONArray("nodes").length()==19&&r.getJSONObject("collection").getInt("retained_nodes")==19,"actual complete 19-node graph");
            check(r.getJSONObject("window").getInt("display_id")==261&&r.getInt("window_id")==1353,"original archived window/display retained as provenance");
            NativeAppProviderHostTest.Harness h=fresh("actual");observe(h,r);
            check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"regression: SMS must not require absent bLoginBtn");noReturn(h);
            JSONObject v=new JSONObject(h.session.domain().promptEvidence()).getJSONObject("provider");
            check(v.getBoolean("requires_user_handling")&&!v.getBoolean("credentials_or_agreement_actions_available")&&!v.getBoolean("public_browsing_requires_login_verified"),"truthful obstruction without login authority or mandatory-login claim");
        });
        one("proved_query_grants_only_exact_unlabelled_sms_return",()->{
            NativeAppProviderHostTest.Harness h=atSms("positive");onlyReturn(h);
            check(progress(h.session).getInt("actual_model_actions")==3&&!progress(h.session).getBoolean("flight_login_exit_attempted"),"recognition never dispatches automatically");
            h.session.domain().requireCurrent(h.action(NativeCtripFlightPage.LOGIN_EXIT));
            check(!h.frame.byId.get("n6").enabled&&!h.session.domain().permitsResourceClick("n6"),"disabled OTP button is evidence only");
        });
        one("empty_resource_pair_survives_actual_grammar_without_inferred_label",()->{
            NativeAppProviderHostTest.Harness h=atSms("grammar");DecisionGrammar g=NativeCtripLoginLoadingHostTest.grammar(h);
            check(new TreeSet<String>(g.actions).equals(new TreeSet<String>(Arrays.asList("click","wait","done")))&&!g.successAllowed,"bounded same model grammar");
            PromptActionDomain.requireTextOnlyClick(h.action(NativeCtripFlightPage.LOGIN_EXIT),g.targets,h.session.domain().clickIds);
            JSONObject e=new JSONObject(h.session.domain().promptEvidence()).getJSONObject("resource_clicks").getJSONObject("n0");
            check(e.getString("view_id").equals("ctrip.android.view:id/ivTitleBarLeftBtn")&&e.getString("native_tree_path").equals("0/0/0/0")&&e.getString("node_label").isEmpty()&&!e.getBoolean("visible_label_inferred"),"resource identity does not invent visible Back text");
            check(e.getInt("provider_version_code")==1779&&e.getString("provider_base_apk_sha256").equals(NativeCtripFlightPage.BASE_APK_SHA256),"same installed-provider identity");
            check(h.session.domain().clicks(Collections.<String>emptySet()).isEmpty(),"resource exception cannot override repeat-policy removal");
        });
        one("calendar_or_cached_result_without_actual_query_has_no_sms_return",()->{
            NativeAppProviderHostTest.Harness h=fresh("calendar-only");h.year();observe(h,sms());noReturn(h);
            h=fresh("cached-only");h.observe("result14.xml");observe(h,sms());noReturn(h);
            h=fresh("unresolved-query");h.year();h.issue(h.action("query_observed_form"),true,true,false);observe(h,sms());noReturn(h);
        });
        one("sms_credentials_registration_agreement_other_controls_back_and_success_remain_denied",()->{
            NativeAppProviderHostTest.Harness h=atSms("denied");
            for(int i=1;i<19;i++){final String id="n"+i;reject(()->h.session.domain().requireCurrent(action(h,"click",null,id)),"nonreturn node is not granted");}
            reject(()->h.session.domain().requireCurrent(action(h,"back",null,null)),"no system Back fallback");
            reject(()->h.session.domain().requireCurrent(action(h,"done","success",null)),"no success on login");
            JSONObject j=new JSONObject().put("action","type").put("package",h.frame.packageName).put("observation_id",h.frame.observationId).put("node_id","n5").put("node_label",h.frame.byId.get("n5").label).put("text","synthetic-not-a-phone-number");
            reject(()->h.session.domain().requireCurrent(ActionDecision.parse(j.toString(),ActionDecision.IME_ACTION_SCHEMA)),"no credential typing");
        });
        one("sms_required_anchors_disabled_otp_and_variant_are_exact",()->{
            for(String id:new String[]{"n1","n2","n3","n6","n7","n8","n12","n13","n14","n16","n18"}){JSONObject r=sms();NativeCtripLoginLoadingHostTest.remove(r,id);mutated(r);}
            for(String key:new String[]{"text","description","class_name","view_id"}){JSONObject r=sms();node(r,"n6").put(key,"unrecognized");mutated(r);}
            JSONObject r=sms();node(r,"n6").put("enabled",true);mutated(r);
            r=sms();node(r,"n2").put("text","其他登录");mutated(r);
            for(String id:new String[]{"n2","n6"}){r=sms();duplicate(r,id,NativeAppGoal.CTRIP_PACKAGE);mutated(r);}
            r=sms();node(r,"n9").put("view_id","ctrip.android.view:id/bLoginBtn");mutated(r);
        });
        one("sms_anchor_scope_selection_and_geometry_are_observed",()->{
            for(String id:new String[]{"n2","n3","n6","n12","n18"}){JSONObject r=sms();node(r,id).getJSONObject("native_tree_position").put("path","0/8/99");mutated(r);}
            JSONObject r=sms();node(r,"n2").getJSONObject("native_tree_position").put("parent_class","android.widget.ScrollView");mutated(r);
            r=sms();node(r,"n18").getJSONObject("native_selection_state").put("checked",true);mutated(r);
            r=sms();node(r,"n6").put("bounds",node(r,"n7").getJSONArray("bounds"));mutated(r);
            r=sms();node(r,"n18").put("bounds",node(r,"n2").getJSONArray("bounds"));mutated(r);
        });
        one("missing_duplicate_or_foreign_sms_return_has_no_fallback",()->{
            JSONObject r=sms();NativeCtripLoginLoadingHostTest.remove(r,"n0");mutated(r);
            for(String pkg:new String[]{NativeAppGoal.CTRIP_PACKAGE,"foreign.app"}){r=sms();duplicate(r,"n0",pkg);mutated(r);}
        });
        one("sms_return_resource_label_class_package_scope_and_geometry_are_exact",()->{
            for(String key:new String[]{"view_id","text","description","class_name","package"}){JSONObject r=sms();node(r,"n0").put(key,"unrecognized");mutated(r);}
            for(String path:new String[]{"0/0/1/0","0/0/0/99"}){JSONObject r=sms();node(r,"n0").getJSONObject("native_tree_position").put("path",path);mutated(r);}
            JSONObject r=sms();node(r,"n0").getJSONObject("native_tree_position").put("parent_class","android.widget.ScrollView");mutated(r);
            r=sms();node(r,"n0").put("bounds",node(r,"n2").getJSONArray("bounds"));mutated(r);
            r=sms();node(r,"n0").getJSONArray("bounds").put(0,-1);mutated(r);
        });
        one("sms_return_enabled_clickable_noneditable_and_selection_are_exact",()->{
            for(String key:new String[]{"enabled","clickable","editable","password","scrollable"}){JSONObject r=sms();node(r,"n0").put(key,!"enabled".equals(key)&&!"clickable".equals(key));mutated(r);}
            for(String key:new String[]{"selected","checkable","checked"}){JSONObject r=sms();node(r,"n0").getJSONObject("native_selection_state").put(key,true);mutated(r);}
            JSONObject r=sms();node(r,"n0").getJSONObject("native_selection_state").put("observed",false);mutated(r);
            r=sms();node(r,"n0").put("scroll_directions",new JSONArray().put("down"));mutated(r);
        });
        one("incomplete_nonapplication_or_mixed_business_sms_frame_has_no_return",()->{
            JSONObject r=sms();r.getJSONObject("collection").put("pending_nodes_at_stop",1);mutated(r);
            r=sms();r.put("nodes_truncated",true);mutated(r);
            r=sms();r.getJSONObject("window").put("type",2);mutated(r);
            r=sms();r.put("host_metadata_missing",true);mutated(r);
            for(String id:new String[]{"bt_submit_inquire","home_grid_flight_widget","calendar_month_title_left_tv"}){r=sms();node(r,"n9").put("view_id","ctrip.android.view:id/"+id);mutated(r);}
        });
        one("sms_model_must_name_current_observation_and_actual_empty_label",()->{
            NativeAppProviderHostTest.Harness h=atSms("binding");ActionDecision a=h.action(NativeCtripFlightPage.LOGIN_EXIT);observe(h,sms());reject(()->h.session.domain().requireCurrent(a),"old observation cannot dispatch");
            JSONObject j=new JSONObject().put("action","click").put("package",h.frame.packageName).put("observation_id",h.frame.observationId).put("node_id","n0").put("node_label","返回");
            reject(()->h.session.domain().requireCurrent(ActionDecision.parse(j.toString(),ActionDecision.IME_ACTION_SCHEMA)),"resource purpose cannot invent a visible label");
            NativeAppDomain d=h.session.domain();
            reject(()->new NativeAppDomain(h.frame,NativeCtripFlightPage.HOME,d.clickIds,d.editValues,d.purposes,false,Collections.<String,Object>emptyMap(),null,Collections.<String>emptyList()),"other phase cannot grant SMS resource");
            reject(()->new NativeAppDomain(h.frame,d.phase,d.clickIds,d.editValues,Collections.singletonMap("n0","login"),false,Collections.<String,Object>emptyMap(),null,Collections.<String>emptyList()),"different purpose cannot grant resource");
        });
        one("sms_installed_identity_retirement_owner_target_and_generation_still_bind",()->{
            NativeAppProviderHostTest.Harness h=atSms("installed");ActionDecision a=h.action(NativeCtripFlightPage.LOGIN_EXIT);h.installedCurrent=false;reject(()->h.issue(a,true,true,false),"installation rechecked before proposal");
            NativeAppProviderHostTest.Harness retired=atSms("retired");ActionDecision b=retired.action(NativeCtripFlightPage.LOGIN_EXIT);retired.session.retire();reject(()->retired.issue(b,true,true,false),"retired task");
            for(int i=0;i<3;i++){NativeAppProviderHostTest.Harness x=queried("foreign"+i);NativeAppEvidence.Frame f=NativeCtripLoginLoadingHostTest.frame(x,sms());
                NativeAppEvidence.Frame bad=NativeAppProviderHostTest.altered(f,i==0?hash("other owner"):f.ownerSha,i==1?hash("other target"):f.targetSha,i==2?"12345678-1234-4234-8234-123456789abd":f.generation,true,false);
                reject(()->x.session.observed(bad),"same task authority still required");}
        });
        one("sms_stale_and_unknown_outcomes_never_enable_second_return",()->{
            NativeAppProviderHostTest.Harness stale=atSms("stale");stale.issue(stale.action(NativeCtripFlightPage.LOGIN_EXIT),false,false,true);observe(stale,sms());noReturn(stale);check(progress(stale.session).getBoolean("flight_login_exit_attempted"),"stale proposal still consumed");
            NativeAppProviderHostTest.Harness h=atSms("unknown");ActionDecision a=h.action(NativeCtripFlightPage.LOGIN_EXIT);String run=hash("sms-unknown-model").substring(0,32);h.owner.check(a,run);h.session.beforeModelAction(4,a,run,h.time+1);
            check(progress(h.session).getBoolean("flight_login_exit_attempted"),"reserved before unknown outcome");reject(()->observe(h,sms()),"no new observation before actual outcome");reject(()->h.session.beforeModelAction(5,a,hash("sms-second-model").substring(0,32),h.time+2),"no second in-flight action");
        });
        one("sms_return_only_preserves_same_query_and_never_proves_wrong_date",()->{
            NativeAppProviderHostTest.Harness h=atSms("same-result");returned(h,"result14.xml");JSONObject p=progress(h.session);check(p.isNull("pending")&&"2026-11-14".equals(p.getString("last_query_date")),"same exploratory query retained");
            JSONObject proof=p.getJSONArray("transitions").getJSONObject(p.getJSONArray("transitions").length()-1);check(proof.getBoolean("navigation_only")&&!proof.getBoolean("query_or_result_proof_created")&&!h.gate.verified(h.completion),"return creates no query or target-date success");
            observe(h,sms());noReturn(h);
            h=atSms("wrong-date");returned(h,"result17.xml");check(!progress(h.session).isNull("pending")&&!h.session.domain().resultReady&&!h.gate.verified(h.completion),"target-looking cache cannot replace explicit query");
        });
        one("sms_success_still_needs_original_target_query_cards_and_cleanup",()->{
            NativeAppProviderHostTest.Harness h=fresh("target");NativeCtripLoginLoadingHostTest.query17(h);h.observe("result17.xml");observe(h,sms());onlyReturn(h);returned(h,"result17.xml");check(h.gate.verified(h.completion),"actual same-target query fixture remains usable");h.claim();check(NativeAppProviderHostTest.passed(h.normal()),"all normal terminal gates remain necessary");
            check(!NativeAppProviderHostTest.passed(h.terminal(0,false,true,true,true,false,true,true,true,h.task,hash("worker").substring(0,32),hash("receipt"),h.lastRun)),"unknown cleanup cannot be success");
        });
        one("sms_profile_full_uid_and_current_owned_window_remain_required",()->{
            NativeCtripLoginExitHostTest.ProfileHarness h=new NativeCtripLoginExitHostTest.ProfileHarness("sms-profile");h.queried();NativeAppEvidence.Frame f=NativeCtripLoginLoadingHostTest.frame(h.raw,sms());h.accept(f,h.window(f.capturedElapsedMs));
            check(h.session.domain().resourceClickIds.equals(Collections.singleton("n0"))&&h.frame.profileWindow.fullUid==1010367,"actual SMS shape retains managed-profile resource authority");h.issue(NativeCtripFlightPage.LOGIN_EXIT);h.xml("result14.xml");check(progress(h.session).isNull("pending")&&!h.gate.verified(h.raw.completion),"same-profile navigation does not complete wrong date");
            NativeCtripLoginExitHostTest.ProfileHarness missing=new NativeCtripLoginExitHostTest.ProfileHarness("sms-missing-proof");missing.queried();NativeAppEvidence.Frame mf=NativeCtripLoginLoadingHostTest.frame(missing.raw,sms());reject(()->missing.accept(mf,null),"no profile window proof");
            ProfileTarget other=NativeCtripLoginExitHostTest.profile(11,11);WindowOwnership w=missing.window(other,500,400,"12345678-1234-4234-8234-123456789aaa",mf.capturedElapsedMs);reject(()->missing.accept(mf,w),"another user/full UID is not the task owner");
        });
        one("sms_phone_field_never_enters_return_projection",()->{
            JSONObject r=sms();node(r,"n5").put("text","[ARTIFICIAL ACCOUNT SENTINEL]").put("description","[ARTIFICIAL ACCOUNT SENTINEL]");NativeAppProviderHostTest.Harness h=queried("account-independent");observe(h,r);onlyReturn(h);check(!new JSONObject(h.session.domain().promptEvidence()).toString().contains("ARTIFICIAL ACCOUNT SENTINEL"),"account values neither identify the page nor enter return facts");
        });
        Map<String,Object> out=NativeAppEvidence.map();out.put("schema","hepta.native-ctrip-sms-login-host.v1");out.put("all_pass",true);out.put("cases",names.size());out.put("assertions",assertions);out.put("case_names",names);
        out.put("phone_operations",0);out.put("android_runtime",false);out.put("model_executed",false);out.put("business_verified",false);out.put("source_bytes_modified",false);
        out.put("fixture_sha256","c2aa485a10fd22e9c7c3a48b08e246313d31232e91d40fbf29f1779b0edca2b7");out.put("uid_window_dispatch_boundaries","synthetic host proofs/outcomes and historical query XML; exact actual 19-node SMS graph, production validation executed");
        Files.write(output,(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println("ctrip SMS login "+names.size()+" cases / "+assertions+" assertions");
    }
}
