package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Original five AX nodes supplied explicitly. Task, lease, clock, installed
 * identity, worker cleanup and terminal IO are host fixtures, never phone proof. */
final class NativeCtripOnboardingHostTest {
    static final String PHASE="ctrip_first_launch_privacy";
    static Path before,after;
    static int assertions,mismatches;
    static final List<String> names=new ArrayList<String>(),regressions=new ArrayList<String>();
    interface Call {void run()throws Exception;}
    static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    static void target(boolean value,String name){assertions++;if(!value){mismatches++;regressions.add(name);}}
    static void one(String name,Call call)throws Exception{call.run();check(!names.contains(name),"unique case");names.add(name);}
    static JSONObject read(Path p)throws Exception{return new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));}
    static JSONObject raw()throws Exception{return read(before);}
    static JSONObject node(JSONObject r,String id){return NativeCtripLoginLoadingHostTest.node(r,id);}
    static NativeAppProviderHostTest.Harness harness(String name)throws Exception{return new NativeAppProviderHostTest.Harness("first-launch:"+name);}
    static void observe(NativeAppProviderHostTest.Harness h,JSONObject r)throws Exception{NativeCtripLoginLoadingHostTest.observe(h,r);}
    static NativeCtripFlightPage.Page inspect(JSONObject r)throws Exception{return NativeCtripLoginLoadingHostTest.inspect(r);}
    static void noEffects(NativeAppDomain d){check(d.clickIds.isEmpty()&&d.resourceClickIds.isEmpty()&&d.editValues.isEmpty()
            &&d.purposes.isEmpty()&&!d.backAllowed&&!d.resultReady,"classification grants no effect or result");}
    static void unavailable(JSONObject r)throws Exception{NativeCtripFlightPage.Page p=inspect(r);
        check(NativeCtripFlightPage.UNAVAILABLE.equals(p.phase),"changed/incomplete graph must stay unavailable");
        check(p.homeFlight==null&&p.form==null&&p.quotes.isEmpty(),"unavailable does not fabricate a native page");}
    static void deny(Call c,String why)throws Exception{assertions++;try{c.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}throw new AssertionError(why);}
    static Map<String,Object> terminal(NativeAppProviderHostTest.Harness h)throws Exception{
        h.session.retire();
        TaskCompletionGate.Check c=h.gate.terminalNativeCheck(h.session,h.completion,h.owner.frame(),h.step,null,false,
                true,true,true,true,false,true,true,Integer.valueOf(0),true,h.task,
                "11111111111111111111111111111111",NativeAppEvidence.hash("explicit-host-normal-worker-receipt"));
        check(!c.verified,"onboarding never becomes verified completion");
        return c.evidence;
    }
    static Map<String,Object> explain(NativeAppProviderHostTest.Harness h,Map<String,Object> e){
        return LocalTaskController.OutcomeExplanation.create(h.task,h.selected.target.ownerSha256,"failed",true,false,h.completion,e,null);
    }
    @SuppressWarnings("unchecked") static Map<String,Object> copy(Map<String,Object> value){return (Map<String,Object>)cloneValue(value);}
    static Object cloneValue(Object value){
        if(value instanceof Map<?,?>){Map<String,Object> out=new LinkedHashMap<String,Object>();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())out.put((String)e.getKey(),cloneValue(e.getValue()));return out;}
        if(value instanceof List<?>){List<Object> out=new ArrayList<Object>();for(Object x:(List<?>)value)out.add(cloneValue(x));return out;}
        return value;
    }
    @SuppressWarnings("unchecked") static Map<String,Object> at(Map<String,Object> value,String path){
        Map<String,Object> current=value;for(String p:path.split("/"))current=(Map<String,Object>)current.get(p);return current;
    }
    public static void main(String[] args)throws Exception{
        before=Paths.get(args[0]);after=Paths.get(args[1]);NativeAppProviderHostTest.fixtures=Paths.get(args[2]);
        NativeCtripLoginLoadingHostTest.fixtures=Paths.get(args[2]);Path output=Paths.get(args[3]);
        one("actual_before_five_nodes_are_first_launch_not_offline_or_flight",()->{
            JSONObject r=raw();check(r.getJSONArray("nodes").length()==5,"exact original five-node record");
            NativeAppProviderHostTest.Harness h=harness("before");observe(h,r);noEffects(h.session.domain());
            target(PHASE.equals(h.session.domain().phase),"actual_before_phase");
            check(!h.gate.verified(h.completion),"actual privacy frame is not result proof");
        });
        one("actual_after_five_nodes_keep_same_readonly_classification",()->{
            NativeAppProviderHostTest.Harness h=harness("after");observe(h,read(after));noEffects(h.session.domain());
            target(PHASE.equals(h.session.domain().phase),"actual_after_phase");
        });
        one("actual_prompt_explains_initialization_and_no_query_without_projected_city_facts",()->{
            NativeAppProviderHostTest.Harness h=harness("prompt");observe(h,raw());
            JSONObject v=new JSONObject(h.session.domain().promptEvidence()).getJSONObject("provider");
            target(v.optBoolean("observed_first_launch_privacy")&&v.optBoolean("initialization_required")
                    &&v.has("flight_query_attempted")&&!v.getBoolean("flight_query_attempted")
                    &&!v.optBoolean("credentials_or_agreement_actions_available")
                    &&v.optString("next_goal").contains("携程首次启动指引尚未完成，未执行机票查询")
                    &&!v.has("from")&&!v.has("to")&&!v.has("date")&&!v.has("adults"),
                    "actual_prompt_blocker");
            check(!v.toString().contains("离线")&&!v.toString().contains("查询已完成"),"no invented offline/query status");
        });
        one("grammar_and_postparse_keep_only_wait_and_incomplete_done",()->{
            NativeAppProviderHostTest.Harness h=harness("grammar");observe(h,raw());
            DecisionGrammar g=NativeCtripLoginLoadingHostTest.grammar(h);
            check(new TreeSet<String>(g.actions).equals(new TreeSet<String>(Arrays.asList("wait","done")))&&!g.successAllowed,"only wait/incomplete done");
            h.session.domain().requireCurrent(NativeCtripLoginLoadingHostTest.action(h,"done","failure",null));
            h.session.domain().requireCurrent(NativeCtripLoginLoadingHostTest.action(h,"done","partial",null));
            deny(()->h.session.domain().requireCurrent(NativeCtripLoginLoadingHostTest.action(h,"click",null,"n2")),"no automatic consent");
            deny(()->h.session.domain().requireCurrent(NativeCtripLoginLoadingHostTest.action(h,"click",null,"n3")),"no automatic refusal");
            deny(()->h.session.domain().requireCurrent(NativeCtripLoginLoadingHostTest.action(h,"back",null,null)),"no return permission");
            deny(()->h.session.domain().requireCurrent(NativeCtripLoginLoadingHostTest.action(h,"done","success",null)),"no success permission");
        });
        one("each_missing_actual_anchor_is_unavailable",()->{
            for(String id:new String[]{"n0","n1","n2","n3","n4"}){JSONObject r=raw();NativeCtripLoginLoadingHostTest.remove(r,id);unavailable(r);}
        });
        one("wrong_frame_or_individual_node_package_is_unavailable",()->{
            JSONObject r=raw();r.put("package","example.foreign");unavailable(r);
            for(String id:new String[]{"n0","n1","n2","n3","n4"}){r=raw();node(r,id).put("package","example.foreign");unavailable(r);}
        });
        one("wrong_resource_label_class_parent_and_geometry_are_unavailable",()->{
            JSONObject r=raw();node(r,"n2").put("view_id","ctrip.android.view:id/other");unavailable(r);
            r=raw();node(r,"n3").put("text","不同意并退出");unavailable(r);
            r=raw();node(r,"n0").put("class_name","android.widget.Button");unavailable(r);
            r=raw();node(r,"n4").getJSONObject("native_tree_position").put("parent_class","android.widget.FrameLayout");unavailable(r);
            r=raw();node(r,"n2").put("bounds",new JSONArray(Arrays.asList(223,1000,1000,2179)));unavailable(r);
            r=raw();node(r,"n1").put("scroll_directions",new JSONArray(Collections.singletonList("up")));unavailable(r);
        });
        one("disabled_interactive_or_unobserved_state_never_recognizes",()->{
            JSONObject r=raw();node(r,"n2").put("enabled",false);unavailable(r);
            r=raw();node(r,"n4").put("clickable",true);unavailable(r);
            r=raw();node(r,"n0").put("editable",true);unavailable(r);
            r=raw();node(r,"n4").put("password",true);unavailable(r);
            r=raw();node(r,"n3").getJSONObject("native_selection_state").put("checked",true);unavailable(r);
            r=raw();node(r,"n2").getJSONObject("native_selection_state").put("observed",false);unavailable(r);
        });
        one("duplicate_and_mixed_flight_records_are_unavailable",()->{
            JSONObject r=raw(),extra=new JSONObject(node(r,"n2").toString());extra.put("id","n99");
            extra.getJSONObject("native_tree_position").put("path","0/9");r.getJSONArray("nodes").put(extra);
            r.getJSONObject("collection").put("retained_nodes",6);unavailable(r);
            r=raw();node(r,"n4").put("view_id","ctrip.android.view:id/bt_submit_inquire");unavailable(r);
            r=raw();NativeCtripLoginLoadingHostTest.addRole(r,"单程列表页");unavailable(r);
        });
        one("incomplete_truncated_or_unknown_window_refuses_classification",()->{
            JSONObject r=raw();r.getJSONObject("collection").put("pending_nodes_at_stop",1);unavailable(r);
            r=raw();r.put("nodes_truncated",true);unavailable(r);
            r=raw();r.put("host_metadata_missing",true);unavailable(r);
            r=raw();r.getJSONObject("window").put("type",2);unavailable(r);
        });
        one("body_is_only_bounded_observed_text_not_terms_acceptance",()->{
            JSONObject r=raw();node(r,"n4").put("text","感谢您使用携程旅行！ [explicit host bounded-text variant]");
            NativeAppProviderHostTest.Harness h=harness("body");observe(h,r);noEffects(h.session.domain());
            // A bounded body is sufficient to classify the initial blocker; no consent is inferred.
            if(PHASE.equals(inspect(raw()).phase))check(PHASE.equals(h.session.domain().phase),"whole legal terms are not synthesized");
        });
        one("neighboring_home_login_and_form_phases_keep_existing_capabilities",()->{
            NativeAppProviderHostTest.Harness h=harness("home");
            h.observe("home.xml");
            check(NativeCtripFlightPage.HOME.equals(h.session.domain().phase)&&h.session.domain().clickIds.size()==1,"existing labelled home remains");
            h=harness("login");observe(h,NativeCtripLoginLoadingHostTest.login());
            check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"existing login remains");
            h=harness("form");h.observe("form17.xml");
            check(NativeCtripFlightPage.FORM.equals(h.session.domain().phase)&&h.target("inspect_departure_year")!=null
                    &&h.target("query_observed_form")==null,"original calendar-year requirement remains");
        });
        one("typed_terminal_ui_prefers_observed_initialization_fact_and_keeps_failure",()->{
            NativeAppProviderHostTest.Harness h=harness("terminal");observe(h,raw());
            h.issue(NativeCtripLoginLoadingHostTest.action(h,"done","failure",null),true,false,false);observe(h,read(after));
            Map<String,Object> e=terminal(h),reason=explain(h,e);
            target("native_ctrip_first_launch_privacy".equals(reason.get("code"))
                    &&String.valueOf(reason.get("message")).startsWith("携程首次启动指引尚未完成，未执行机票查询"),"actual_terminal_ui");
            check(!Boolean.TRUE.equals(e.get("completion_verified")),"failed terminal stays failed");
            if(!reason.isEmpty()){
                check(Boolean.FALSE.equals(reason.get("business_verified"))&&Boolean.FALSE.equals(reason.get("grants_tool_authority")),"display-only fact");
                String shown=LocalTaskController.OutcomeExplanation.display("模型声称：离线，查询已完成",reason);
                check(shown.startsWith((String)reason.get("message"))&&shown.contains("任务记录："),"fact is primary; original model record labelled");
                for(String field:new String[]{"observed_first_launch_privacy","initialization_required"}){
                    Map<String,Object> bad=copy(e);at(bad,"native_app_session/current_domain/provider").put(field,false);
                    check(explain(h,bad).isEmpty(),"provider blocker binding required");
                }
                Map<String,Object> bad=copy(e);at(bad,"native_app_session/current_domain/provider").put("credentials_or_agreement_actions_available",true);
                check(explain(h,bad).isEmpty(),"no authority-bearing blocker projection");
                bad=copy(e);at(bad,"native_app_session/current_domain/source_frame").put("observation_id","00000000000000000000000000000000");
                check(explain(h,bad).isEmpty(),"fresh final frame binding retained");
                check(LocalTaskController.OutcomeExplanation.create(h.task,h.selected.target.ownerSha256,"failed",false,false,h.completion,e,null).isEmpty(),"cleanup unknown remains primary");
                check(LocalTaskController.OutcomeExplanation.create(h.task,h.selected.target.ownerSha256,"controller_verified_done",true,true,h.completion,e,null).isEmpty(),"success not changed by explanation");
            }
        });
        one("prior_query_attempt_is_not_erased_if_privacy_reappears",()->{
            NativeAppProviderHostTest.Harness h=harness("query-history");NativeCtripLoginLoadingHostTest.query17(h);observe(h,raw());noEffects(h.session.domain());
            Map<?,?> view=(Map<?,?>)h.session.domain().evidence().get("provider");
            if(PHASE.equals(h.session.domain().phase)){
                check(Boolean.TRUE.equals(view.get("flight_query_attempted"))&&!String.valueOf(view.get("next_goal")).contains("未执行机票查询"),"actual prior attempt is retained");
                Map<String,Object> e=terminal(h),reason=explain(h,e);
                check(!reason.isEmpty()&&!String.valueOf(reason.get("message")).contains("未执行机票查询"),"terminal does not erase query history");
            }
        });
        JSONObject result=new JSONObject().put("schema","hepta.ctrip-first-launch-host.v1").put("all_pass",mismatches==0)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",names)
                .put("regression_mismatches",mismatches).put("regression_names",regressions)
                .put("phone_operations",0).put("android_runtime",false).put("model_executed",false).put("business_verified",false)
                .put("actual_five_node_inputs",true).put("task_lease_installed_worker_cleanup_envelope","explicit host fixtures");
        Files.write(output,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(result.toString());if(mismatches!=0)System.exit(3);
    }
}
