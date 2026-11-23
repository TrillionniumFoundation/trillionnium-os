package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Production Session/provider on the immutable redacted actual login graph and
 * original query XML. Models, task IDs, UID/window proofs and dispatch outcomes
 * below are explicit host fixtures; this never performs Phone/Android IPC. */
final class NativeCtripLoginExitHostTest {
    static int assertions;
    static final List<String> names=new ArrayList<String>();
    interface Test {void run()throws Exception;}
    static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static void reject(Test test,String why)throws Exception{assertions++;try{test.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}throw new AssertionError(why);}
    static void one(String name,Test test)throws Exception{test.run();names.add(name);}
    static String hash(String s){return NativeAppEvidence.hash(s);}
    static NativeAppProviderHostTest.Harness fresh(String name)throws Exception{return new NativeAppProviderHostTest.Harness("ctrip-exit:"+name);}
    static JSONObject login()throws Exception{return NativeCtripLoginLoadingHostTest.login();}
    static JSONObject node(JSONObject r,String id){return NativeCtripLoginLoadingHostTest.node(r,id);}
    static void observe(NativeAppProviderHostTest.Harness h,JSONObject r)throws Exception{NativeCtripLoginLoadingHostTest.observe(h,r);}
    static NativeAppProviderHostTest.Harness queried(String name)throws Exception{
        NativeAppProviderHostTest.Harness h=fresh(name);h.year();h.perform("query_observed_form","result14.xml");return h;
    }
    static NativeAppProviderHostTest.Harness atLogin(String name)throws Exception{
        NativeAppProviderHostTest.Harness h=queried(name);observe(h,login());return h;
    }
    static JSONObject progress(NativeAppSession s){return new JSONObject(s.evidence()).getJSONObject("progress");}
    static void noReturn(NativeAppProviderHostTest.Harness h){
        NativeAppDomain d=h.session.domain();
        check(d.clickIds.isEmpty()&&!d.backAllowed&&d.editValues.isEmpty()&&!d.resultReady,"no navigation/account/result grant");
    }
    static void onlyReturn(NativeAppProviderHostTest.Harness h){
        NativeAppDomain d=h.session.domain();
        check(d.clickIds.equals(Collections.singleton("n0"))&&d.resourceClickIds.isEmpty()&&d.editValues.isEmpty()&&!d.backAllowed&&!d.resultReady,"only exact visible return click");
        check(NativeCtripFlightPage.LOGIN_EXIT.equals(d.purposes.get("n0"))&&d.purposes.size()==1,"one named Ctrip purpose");
        JSONObject p=new JSONObject(d.promptEvidence()).getJSONObject("provider");
        check(!p.getBoolean("credentials_or_agreement_actions_available")&&!p.getBoolean("public_browsing_requires_login_verified"),"no credential authority or mandatory-login claim");
    }
    static void mutatedReturn(JSONObject r)throws Exception{
        NativeAppProviderHostTest.Harness h=queried("mutated:"+names.size()+":"+assertions);observe(h,r);noReturn(h);
    }
    static ActionDecision click(NativeAppProviderHostTest.Harness h,String id)throws Exception{return NativeCtripLoginLoadingHostTest.action(h,"click",null,id);}
    static void returned(NativeAppProviderHostTest.Harness h,String xml)throws Exception{h.issue(h.action(NativeCtripFlightPage.LOGIN_EXIT),true,true,false);h.observe(xml);}
    static void pending(NativeAppProviderHostTest.Harness h){check(!progress(h.session).isNull("pending")&&!h.session.domain().resultReady&&h.session.domain().clickIds.isEmpty(),"unproved return remains pending without result");}

    static final class Binding implements BackgroundTaskTarget.SelectionBinding {
        final BackgroundTaskTarget target;
        Binding(ProfileTarget p){target=BackgroundTaskTarget.resolveExplicitSelection(NativeAppProviderHostTest.OWNER,ProfileTarget.CTRIP,Collections.singleton(ProfileTarget.CTRIP),p);}
        public BackgroundTaskTarget executionTarget(){return target;}
    }
    static ProfileTarget profile(int user,long serial){return new ProfileTarget(new ProfileIdentity(user,serial,0,"android.os.usertype.profile.MANAGED"),
            user*100000+10367,ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.business.splash.CtripSplashActivity",1779,
            Collections.singletonMap("base",NativeCtripFlightPage.BASE_APK_SHA256),Collections.singleton(hash("synthetic-profile-signer")));}
    static final class ProfileHarness {
        final NativeAppProviderHostTest.Harness raw;
        final ProfileTarget profile=profile(10,10);
        final Binding selection=new Binding(profile);
        final TaskAuthorization auth=TaskAuthorization.parse(NativeAppProviderHostTest.OWNER).forExecutionSelection(selection);
        final TaskAuthorization.Gate owner;
        final NativeAppSession session;
        final TaskCompletionGate gate;
        final String wire;
        NativeAppEvidence.Frame frame;
        int step;
        ProfileHarness(String name)throws Exception{
            raw=fresh("profile:"+name);owner=auth.bind(raw.task);wire=hash("synthetic-profile-selection:"+selection.target.targetSha256);
            session=new NativeAppSession(raw.task,owner,selection,new NativeAppEvidence.Installed(profile),wire,NativeAppProviderHostTest.GENERATION,7,
                    ()->{if(!raw.installedCurrent)throw new IllegalStateException("synthetic installed identity changed");},(leaf,value)->{});
            gate=new TaskCompletionGate(raw.task,NativeAppProviderHostTest.OWNER,auth,selection);gate.bindNativeSession(session);
        }
        WindowOwnership window(ProfileTarget p,int leaf,int parent,String token,long at){return new WindowOwnership(p,NativeAppProviderHostTest.GENERATION,7,70,leaf,parent,token,
                "12345678-1234-4234-8234-123456789abb",p.profile.userId,p.profile.serial,p.fullUid,at-1,at+1000);}
        WindowOwnership window(long at){return window(profile,500,400,"12345678-1234-4234-8234-123456789aaa",at);}
        NativeAppEvidence.Frame remap(NativeAppEvidence.Frame f,WindowOwnership w){return new NativeAppEvidence.Frame(raw.task,auth.instructionSha256,selection.target.targetSha256,auth.sha256,wire,
                f.observationId,f.packageName,f.generation,f.treeSha,f.stateSha,f.screenshotSha,f.sourceRecordSha,f.completionFrameSha,
                f.displayId,f.windowId,f.rotation,f.width,f.height,f.left,f.top,f.right,f.bottom,f.capturedElapsedMs,f.nodesTruncated,f.collectionComplete,f.nodes,f.windowType,f.metadataObserved,w);}
        void accept(NativeAppEvidence.Frame f,WindowOwnership w)throws Exception{frame=remap(f,w);session.observed(frame);gate.observed(raw.completion);}
        void xml(String name)throws Exception{NativeAppEvidence.Frame f=raw.frame(name);accept(f,window(f.capturedElapsedMs));}
        void loginPage()throws Exception{NativeAppEvidence.Frame f=NativeCtripLoginLoadingHostTest.frame(raw,login());accept(f,window(f.capturedElapsedMs));}
        ActionDecision action(String purpose)throws Exception{
            String id=null;for(Map.Entry<String,String> e:session.domain().purposes.entrySet())if(purpose.equals(e.getValue()))id=e.getKey();
            check(id!=null,"profile exact current purpose");
            JSONObject j=new JSONObject().put("action","back".equals(id)?"back":"click").put("package",frame.packageName).put("observation_id",frame.observationId);
            if(!"back".equals(id))j.put("node_id",id).put("node_label",frame.byId.get(id).label);
            return ActionDecision.parse(j.toString(),ActionDecision.IME_ACTION_SCHEMA);
        }
        void issue(String purpose)throws Exception{
            ActionDecision a=action(purpose);String run=hash(raw.task+":profile-model:"+ ++step).substring(0,32);raw.time+=10;owner.check(a,run);
            session.beforeModelAction(step,a,run,raw.time);session.modelActionOutcome(a,run,true,true,false,hash("synthetic-profile-receipt:"+step),++raw.time);
        }
        void queried()throws Exception{xml("form14.xml");issue("inspect_departure_year");xml("calendar14.xml");issue("return_from_calendar");xml("form14.xml");issue("query_observed_form");xml("result14.xml");}
    }
    public static void main(String[] args)throws Exception{
        NativeAppProviderHostTest.fixtures=Paths.get(args[0]);NativeCtripLoginLoadingHostTest.fixtures=Paths.get(args[0]);Path output=Paths.get(args[1]);
        one("observed_return_after_actual_query_is_one_model_only_click",()->{
            NativeAppProviderHostTest.Harness h=atLogin("positive");onlyReturn(h);
            check(progress(h.session).getInt("actual_model_actions")==3&&!progress(h.session).getBoolean("flight_login_exit_attempted"),"recognition issues no action");
            DecisionGrammar grammar=NativeCtripLoginLoadingHostTest.grammar(h);
            check(new TreeSet<String>(grammar.actions).equals(new TreeSet<String>(Arrays.asList("click","wait","done")))&&!grammar.successAllowed,"bounded actual grammar");
        });
        one("login_without_actual_query_result_chain_has_no_return",()->{NativeAppProviderHostTest.Harness h=fresh("noquery");observe(h,login());noReturn(h);});
        one("calendar_year_without_query_has_no_return",()->{NativeAppProviderHostTest.Harness h=fresh("yearonly");h.year();observe(h,login());noReturn(h);});
        one("cached_result_without_query_cannot_authorize_return",()->{NativeAppProviderHostTest.Harness h=fresh("cached");h.observe("result14.xml");observe(h,login());noReturn(h);});
        one("dispatched_query_with_unresolved_result_has_no_return",()->{NativeAppProviderHostTest.Harness h=fresh("pending");h.year();h.issue(h.action("query_observed_form"),true,true,false);observe(h,login());noReturn(h);});
        one("stale_query_never_authorizes_login_return",()->{NativeAppProviderHostTest.Harness h=fresh("stale-query");h.year();h.issue(h.action("query_observed_form"),false,false,true);h.observe("result14.xml");observe(h,login());noReturn(h);});
        one("credentials_agreement_registration_system_back_and_success_remain_denied",()->{
            NativeAppProviderHostTest.Harness h=atLogin("other-actions");
            for(String id:new String[]{"n3","n4","n5","n7","n9","n11"})reject(()->h.session.domain().requireCurrent(click(h,id)),"only return, no login/consent");
            reject(()->h.session.domain().requireCurrent(NativeCtripLoginLoadingHostTest.action(h,"back",null,null)),"no system Back");
            reject(()->h.session.domain().requireCurrent(NativeCtripLoginLoadingHostTest.action(h,"done","success",null)),"no success on login");
        });
        one("account_identifier_never_enters_return_projection",()->{
            NativeAppProviderHostTest.Harness h=queried("redaction");JSONObject r=login();node(r,"n1").put("text","ARTIFICIAL_PRIVATE_ACCOUNT").put("description","ARTIFICIAL_PRIVATE_ACCOUNT");observe(h,r);onlyReturn(h);
            check(!new JSONObject(h.session.domain().promptEvidence()).toString().contains("ARTIFICIAL_PRIVATE_ACCOUNT"),"account value not projected");
        });
        one("missing_return_control_is_not_replaced_by_system_back",()->{JSONObject r=login();NativeCtripLoginLoadingHostTest.remove(r,"n0");mutatedReturn(r);});
        one("duplicate_or_foreign_duplicate_return_is_ambiguous",()->{
            for(String pkg:new String[]{NativeAppGoal.CTRIP_PACKAGE,"foreign.app"}){JSONObject r=login(),n=new JSONObject(node(r,"n0").toString()).put("id","n99").put("package",pkg);n.getJSONObject("native_tree_position").put("path","0/0/99");r.getJSONArray("nodes").put(n);r.getJSONObject("collection").put("retained_nodes",15);mutatedReturn(r);}
        });
        one("return_identity_text_description_class_package_are_exact",()->{
            for(String key:new String[]{"view_id","text","description","class_name","package"}){JSONObject r=login();node(r,"n0").put(key,"unrecognized");mutatedReturn(r);}
        });
        one("return_enabled_clickable_noneditable_nonpassword_nonscroll_are_required",()->{
            for(String key:new String[]{"enabled","clickable","editable","password","scrollable"}){JSONObject r=login();node(r,"n0").put(key,!"enabled".equals(key)&&!"clickable".equals(key));mutatedReturn(r);}
        });
        one("return_selection_and_scroll_directions_are_exact",()->{
            for(String key:new String[]{"selected","checkable","checked"}){JSONObject r=login();node(r,"n0").getJSONObject("native_selection_state").put(key,true);mutatedReturn(r);}
            JSONObject r=login();node(r,"n0").getJSONObject("native_selection_state").put("observed",false);mutatedReturn(r);
            r=login();node(r,"n0").put("scroll_directions",new JSONArray().put("down"));mutatedReturn(r);
        });
        one("return_tree_scope_order_and_geometry_are_required",()->{
            for(String path:new String[]{"0/1/0","0/0/99"}){JSONObject r=login();node(r,"n0").getJSONObject("native_tree_position").put("path",path);mutatedReturn(r);}
            JSONObject r=login();node(r,"n0").getJSONObject("native_tree_position").put("parent_class","android.widget.FrameLayout");mutatedReturn(r);
            r=login();node(r,"n0").put("bounds",node(r,"n2").getJSONArray("bounds"));mutatedReturn(r);
            r=login();node(r,"n0").getJSONArray("bounds").put(0,-1);mutatedReturn(r);
        });
        one("incomplete_truncated_or_nonapplication_login_has_no_return",()->{
            JSONObject r=login();r.getJSONObject("collection").put("pending_nodes_at_stop",1);mutatedReturn(r);
            r=login();r.put("nodes_truncated",true);mutatedReturn(r);
            r=login();r.getJSONObject("window").put("type",2);mutatedReturn(r);
            r=login();r.put("host_metadata_missing",true);mutatedReturn(r);
        });
        one("model_must_name_exact_current_observation_and_label",()->{
            NativeAppProviderHostTest.Harness h=atLogin("action-binding");ActionDecision a=h.action(NativeCtripFlightPage.LOGIN_EXIT);
            observe(h,login());reject(()->h.session.domain().requireCurrent(a),"old observation");
            JSONObject j=new JSONObject().put("action","click").put("package",h.frame.packageName).put("observation_id",h.frame.observationId).put("node_id","n0").put("node_label","关闭");
            reject(()->h.session.domain().requireCurrent(ActionDecision.parse(j.toString(),ActionDecision.IME_ACTION_SCHEMA)),"invented label");
        });
        one("installed_identity_is_rechecked_before_return_proposal",()->{NativeAppProviderHostTest.Harness h=atLogin("apk");ActionDecision a=h.action(NativeCtripFlightPage.LOGIN_EXIT);h.installedCurrent=false;reject(()->h.issue(a,true,true,false),"changed installation");});
        one("retired_task_cannot_dispatch_return",()->{NativeAppProviderHostTest.Harness h=atLogin("retired");ActionDecision a=h.action(NativeCtripFlightPage.LOGIN_EXIT);h.session.retire();reject(()->h.issue(a,true,true,false),"retired task");});
        one("foreign_owner_target_and_generation_cannot_rebind_return",()->{
            for(int i=0;i<3;i++){NativeAppProviderHostTest.Harness h=queried("foreign"+i);NativeAppEvidence.Frame f=NativeCtripLoginLoadingHostTest.frame(h,login());
                NativeAppEvidence.Frame bad=NativeAppProviderHostTest.altered(f,i==0?hash("other owner"):f.ownerSha,i==1?hash("other target"):f.targetSha,i==2?"12345678-1234-4234-8234-123456789abd":f.generation,true,false);
                reject(()->h.session.observed(bad),"foreign identity");}
        });
        one("stale_undispatched_return_consumes_the_single_proposal",()->{
            NativeAppProviderHostTest.Harness h=atLogin("stale-return");h.issue(h.action(NativeCtripFlightPage.LOGIN_EXIT),false,false,true);observe(h,login());noReturn(h);
            check(progress(h.session).getBoolean("flight_login_exit_attempted"),"stale still consumes");
        });
        one("unknown_outcome_preserves_inflight_and_never_retries",()->{
            NativeAppProviderHostTest.Harness h=atLogin("unknown");ActionDecision a=h.action(NativeCtripFlightPage.LOGIN_EXIT);String run=hash("unknown-model").substring(0,32);
            h.owner.check(a,run);h.session.beforeModelAction(4,a,run,h.time+1);
            check(progress(h.session).getBoolean("flight_login_exit_attempted"),"reserved before unknown outcome");
            reject(()->observe(h,login()),"no new observation before actual outcome");reject(()->h.session.beforeModelAction(5,a,hash("second-model").substring(0,32),h.time+2),"no second in-flight action");
        });
        one("rejected_or_stale_dispatched_return_invalidates_session",()->{
            for(boolean stale:new boolean[]{false,true}){NativeAppProviderHostTest.Harness h=atLogin("bad-outcome:"+stale);h.issue(h.action(NativeCtripFlightPage.LOGIN_EXIT),!stale?false:true,true,stale);reject(()->h.session.domain(),"unaccepted effect");}
        });
        one("same_login_after_return_remains_blocked_without_second_click",()->{NativeAppProviderHostTest.Harness h=atLogin("same-login");h.issue(h.action(NativeCtripFlightPage.LOGIN_EXIT),true,true,false);observe(h,login());noReturn(h);check(!progress(h.session).isNull("pending"),"not a verified dismissal");});
        one("return_only_closes_on_same_proved_query_date_and_owner",()->{
            NativeAppProviderHostTest.Harness h=atLogin("same-result");returned(h,"result14.xml");JSONObject p=progress(h.session);check(p.isNull("pending")&&"2026-11-14".equals(p.getString("last_query_date")),"same exploratory query preserved");
            JSONObject proof=p.getJSONArray("transitions").getJSONObject(p.getJSONArray("transitions").length()-1);
            check(proof.getBoolean("navigation_only")&&!proof.getBoolean("query_or_result_proof_created"),"return not query proof");check(!h.gate.verified(h.completion),"wrong target date not success");
        });
        one("wrong_date_result_after_return_stays_pending_and_unverified",()->{NativeAppProviderHostTest.Harness h=atLogin("wrong-date");returned(h,"result17.xml");pending(h);check(!h.gate.verified(h.completion),"target-looking cache not new query");});
        one("form_home_and_unknown_return_destinations_do_not_close_query_chain",()->{
            NativeAppProviderHostTest.Harness h=atLogin("form-after");returned(h,"form14.xml");pending(h);
            h=atLogin("unknown-after");h.issue(h.action(NativeCtripFlightPage.LOGIN_EXIT),true,true,false);JSONObject r=login();r.put("nodes",new JSONArray().put(node(r,"n0")));r.getJSONObject("collection").put("retained_nodes",1);observe(h,r);pending(h);
        });
        one("original_fifteen_second_transition_deadline_is_not_renewed",()->{NativeAppProviderHostTest.Harness h=atLogin("timeout");h.issue(h.action(NativeCtripFlightPage.LOGIN_EXIT),true,true,false);h.time+=15001;h.observe("result14.xml");reject(()->h.session.domain(),"original transition deadline");});
        one("later_login_after_successful_return_cannot_get_a_second_exit",()->{NativeAppProviderHostTest.Harness h=atLogin("twice");returned(h,"result14.xml");observe(h,login());noReturn(h);});
        one("original_target_query_and_complete_cards_can_still_complete_after_return",()->{
            NativeAppProviderHostTest.Harness h=fresh("target");NativeCtripLoginLoadingHostTest.query17(h);h.observe("result17.xml");observe(h,login());onlyReturn(h);returned(h,"result17.xml");
            check(h.gate.verified(h.completion),"same target query and fresh actual cards");h.claim();check(NativeAppProviderHostTest.passed(h.normal()),"normal0 and all original terminal gates still needed");
        });
        one("successful_return_with_unknown_cleanup_never_becomes_success",()->{
            NativeAppProviderHostTest.Harness h=fresh("cleanup");NativeCtripLoginLoadingHostTest.query17(h);h.observe("result17.xml");observe(h,login());returned(h,"result17.xml");h.claim();
            check(!NativeAppProviderHostTest.passed(h.terminal(0,false,true,true,true,false,true,true,true,h.task,hash("worker").substring(0,32),hash("receipt"),h.lastRun)),"cleanup remains mandatory");
        });
        one("partial_done_and_return_navigation_never_complete_wrong_date",()->{
            NativeAppProviderHostTest.Harness h=atLogin("partial");returned(h,"result14.xml");h.issue(NativeCtripLoginLoadingHostTest.action(h,"done","partial",null),true,false,false);h.observe("result14.xml");
            check(!NativeAppProviderHostTest.passed(h.normal()),"partial is never success");
        });
        one("calendar_prompt_keeps_same_back_only_tools_and_does_not_choose_date",()->{
            NativeAppProviderHostTest.Harness h=fresh("calendar");h.observe("form14.xml");h.perform("inspect_departure_year","calendar14.xml");NativeAppDomain d=h.session.domain();
            check(d.clickIds.isEmpty()&&d.backAllowed&&"return_from_calendar".equals(d.purposes.get("back"))&&!d.resultReady,"unchanged calendar action domain");
            JSONObject v=new JSONObject(d.promptEvidence()).getJSONObject("provider");check(v.getString("next_goal").contains("back")&&v.getString("next_goal").contains("未暴露"),"explicit observation-based return instruction");
            check(progress(h.session).isNull("proved_form_date"),"header is not selected target date");
        });
        one("profile_full_uid_and_owned_window_are_retained_for_return",()->{
            ProfileHarness h=new ProfileHarness("valid");h.queried();h.loginPage();check(h.session.domain().clickIds.equals(Collections.singleton("n0")),"profile return candidate");
            check(h.frame.profileWindow.fullUid==1010367,"full profile UID");h.issue(NativeCtripFlightPage.LOGIN_EXIT);h.xml("result14.xml");
            check(progress(h.session).isNull("pending")&&!h.gate.verified(h.raw.completion),"same profile navigation, wrong date not success");
        });
        one("profile_missing_window_or_other_user_proof_cannot_grant_return",()->{
            ProfileHarness h=new ProfileHarness("missing");h.queried();NativeAppEvidence.Frame f=NativeCtripLoginLoadingHostTest.frame(h.raw,login());reject(()->h.accept(f,null),"no ownership proof");
            ProfileTarget other=profile(11,11);WindowOwnership w=h.window(other,500,400,"12345678-1234-4234-8234-123456789aaa",f.capturedElapsedMs);
            reject(()->h.accept(f,w),"other profile/user/full UID");
        });
        one("profile_parent_uid_remapping_and_expired_window_are_refused",()->{
            ProfileHarness h=new ProfileHarness("bad-proof");h.queried();NativeAppEvidence.Frame f=NativeCtripLoginLoadingHostTest.frame(h.raw,login());
            reject(()->new WindowOwnership(h.profile,NativeAppProviderHostTest.GENERATION,7,70,500,400,"12345678-1234-4234-8234-123456789aaa","12345678-1234-4234-8234-123456789abb",10,10,10367,f.capturedElapsedMs,f.capturedElapsedMs+1000),"no parent UID remapping");
            WindowOwnership expired=h.window(f.capturedElapsedMs-1001);reject(()->h.accept(f,expired),"old ownership proof cannot be renewed");
        });
        one("profile_leaf_parent_or_token_replacement_cannot_prove_return",()->{
            for(int i=0;i<3;i++){ProfileHarness h=new ProfileHarness("replacement"+i);h.queried();h.loginPage();h.issue(NativeCtripFlightPage.LOGIN_EXIT);NativeAppEvidence.Frame f=h.raw.frame("result14.xml");
                WindowOwnership w=h.window(h.profile,i==0?501:500,i==1?401:400,i==2?"12345678-1234-4234-8234-123456789aac":"12345678-1234-4234-8234-123456789aaa",f.capturedElapsedMs);
                h.accept(f,w);check(!progress(h.session).isNull("pending")&&!h.session.domain().resultReady,"owned lineage replacement not navigation success");}
        });
        Map<String,Object> out=NativeAppEvidence.map();out.put("schema","hepta.native-ctrip-login-exit-host.v1");out.put("all_pass",true);
        out.put("case_names",names);out.put("cases",names.size());out.put("assertions",assertions);out.put("phone_operations",0);out.put("android_runtime",false);
        out.put("model_executed",false);out.put("business_verified",false);out.put("account_field_artificially_redacted",true);
        out.put("uid_window_dispatch_boundaries","synthetic host proofs and outcomes; original production validation executed");
        Files.write(output,(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println("ctrip bounded login exit "+names.size()+" cases / "+assertions+" assertions");
    }
}
