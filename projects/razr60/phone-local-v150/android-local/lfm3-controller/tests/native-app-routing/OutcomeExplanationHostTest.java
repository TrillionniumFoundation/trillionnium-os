package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

/** Real provider/session/terminal and result presentation with explicit host
 * installed-identity, clock, model-cleanup and Android IO fixtures. No phone effects. */
public final class OutcomeExplanationHostTest {
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void passed(String name){check(!names.contains(name),"unique case: "+name);names.add(name);}
    private static final class Binding implements BackgroundTaskTarget.SelectionBinding {
        final BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(SyntheticXiaomiNativeLoginFixture.OWNER,
                NativeAppGoal.XIAOMI_PACKAGE,Collections.singleton(NativeAppGoal.XIAOMI_PACKAGE));
        public BackgroundTaskTarget executionTarget(){return target;}
    }
    private static final class NativeFixture {
        final Binding selection=new Binding();
        final String task,owner;
        final NotesCompletionEvidence.Frame frame;
        final Map<String,Object> evidence;
        NativeFixture()throws Exception{
            NativeAppEvidence.Frame f=SyntheticXiaomiNativeLoginFixture.frame();task=f.taskId;owner=selection.target.ownerSha256;
            TaskAuthorization auth=TaskAuthorization.parse(SyntheticXiaomiNativeLoginFixture.OWNER).forExecutionSelection(selection);
            TaskAuthorization.Gate gate=auth.bind(task);
            List<NotesCompletionEvidence.Node> nodes=new ArrayList<NotesCompletionEvidence.Node>();
            for(NativeAppEvidence.Node n:f.nodes)nodes.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label,n.viewId,
                    n.editable?NativeAppEvidence.hash(n.text):null,new int[]{n.left,n.top,n.right,n.bottom},n.editable,n.clickable,n.scrollable,
                    n.enabled,n.password,ObservedChildText.notApplicable(),n.signature,n.className,n.path));
            frame=new NotesCompletionEvidence.Frame(f.observationId,f.packageName,f.windowId,f.displayId,f.generation,1,true,false,nodes);
            String selectionSha=NativeAppEvidence.hash("explicit synthetic presentation selection");
            NativeAppEvidence.Frame actual=new NativeAppEvidence.Frame(task,owner,selection.target.targetSha256,auth.sha256,selectionSha,
                    f.observationId,f.packageName,f.generation,f.treeSha,f.stateSha,f.screenshotSha,f.sourceRecordSha,
                    TaskCompletionGate.webFrameSha(frame),f.displayId,f.windowId,f.rotation,f.width,f.height,
                    f.left,f.top,f.right,f.bottom,f.capturedElapsedMs,false,true,f.nodes,1,true);
            NativeAppSession session=new NativeAppSession(task,gate,selection,new NativeAppEvidence.Installed(f.packageName,12345,20261010L,
                    Collections.singletonMap("base","95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373")),
                    selectionSha,f.generation,f.displayId,new NativeAppSession.InstalledVerifier(){public void verify(){}},
                    new NativeAppSession.Journal(){public void write(String leaf,Map<String,Object> value){}});
            TaskCompletionGate completion=new TaskCompletionGate(task,SyntheticXiaomiNativeLoginFixture.OWNER,auth,selection);
            completion.bindNativeSession(session);session.observed(actual);completion.observed(frame);
            check(NativeXiaomiProductPage.LOGIN.equals(session.domain().phase),"actual provider recognizes the complete synthetic login graph");
            session.retire();
            // Cleanup/process booleans are explicit host boundary values; a failed
            // goal has no success claim, and remains unverified by the real terminal.
            TaskCompletionGate.Check terminal=completion.terminalNativeCheck(session,frame,gate.frame(),1,null,false,
                    true,true,true,true,false,true,true,Integer.valueOf(0),true,task,
                    "11111111111111111111111111111111",NativeAppEvidence.hash("synthetic worker receipt"));
            check(!terminal.verified,"the failed host goal must not become verified");evidence=copy(terminal.evidence);
        }
        Map<String,Object> explain(Map<String,Object> e){return LocalTaskController.OutcomeExplanation.create(task,owner,"failed",true,false,frame,e,null);}
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> copy(Map<String,Object> value){return (Map<String,Object>)cloneValue(value);}
    private static Object cloneValue(Object value){
        if(value instanceof Map<?,?>){Map<String,Object> out=new LinkedHashMap<String,Object>();
            for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())out.put((String)e.getKey(),cloneValue(e.getValue()));return out;}
        if(value instanceof List<?>){List<Object> out=new ArrayList<Object>();for(Object x:(List<?>)value)out.add(cloneValue(x));return out;}
        return value;
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> at(Map<String,Object> value,String path){
        Map<String,Object> current=value;for(String part:path.split("/"))current=(Map<String,Object>)current.get(part);return current;
    }
    private static void nativeCases(NativeFixture f)throws Exception{
        Map<String,Object> explanation=f.explain(f.evidence);
        check("native_xiaomi_login_page".equals(explanation.get("code")),"bound actual provider blocker is visible");
        check(f.frame.observationId.equals(explanation.get("observation_id"))
                &&TaskCompletionGate.webFrameSha(f.frame).equals(explanation.get("completion_frame_sha256")),"explanation names its exact final observation");
        check(Boolean.FALSE.equals(explanation.get("business_verified"))&&Boolean.FALSE.equals(explanation.get("grants_tool_authority")),"explanation grants neither completion nor action");
        passed("actual_provider_terminal_explains_login_without_verifying_goal");
        Map<String,Object> blocked=copy(f.evidence);at(blocked,"native_app_session/current_domain").put("phase",NativeXiaomiProductPage.LOGIN_BLOCKED);
        check("native_xiaomi_login_page".equals(f.explain(blocked).get("code")),"explicit host login-budget phase remains an observed login explanation");
        passed("same_login_frame_in_reserved_exit_phase_is_explained");
        String[][] faults={
            {"terminal_native_completion","schema","wrong"},{"terminal_native_completion","task_id","wrong"},
            {"terminal_native_completion","owner_sha256","wrong"},{"terminal_native_completion","execution_target_sha256","wrong"},
            {"terminal_native_completion","authorization_sha256","wrong"},{"terminal_native_completion","one_terminal_attempt","false"},
            {"terminal_native_completion","action_domain_retired","false"},{"terminal_native_completion","all_cleanup_known","false"},
            {"terminal_native_completion","background_released","false"},{"terminal_native_completion","scope_rechecked_after_worker_exit","false"},
            {"terminal_native_completion","installed_app_rechecked_after_cleanup","false"},{"terminal_native_completion","owner_rechecked","false"},
            {"terminal_native_completion","native_normal0_parent_session_bound","false"},{"terminal_native_completion","cancelled","true"},
            {"terminal_native_completion","completion_verified","true"},{"native_app_session","schema","wrong"},
            {"native_app_session","task_id","wrong"},{"native_app_session","owner_sha256","wrong"},
            {"native_app_session","invalid","true"},{"native_app_session","action_domain_retired","false"},
            {"native_app_session/current_domain","schema","wrong"},{"native_app_session/current_domain","observation_id","wrong"},
            {"native_app_session/current_domain","package","wrong"},{"native_app_session/current_domain","background_generation","wrong"},
            {"native_app_session/current_domain","phase","unrecognized_native_page"},{"native_app_session/current_domain","result_ready","true"},
            {"native_app_session/current_domain/provider","observed_login_page","false"},
            {"native_app_session/current_domain/source_frame","schema","wrong"},{"native_app_session/current_domain/source_frame","task_id","wrong"},
            {"native_app_session/current_domain/source_frame","owner_sha256","wrong"},{"native_app_session/current_domain/source_frame","observation_id","wrong"},
            {"native_app_session/current_domain/source_frame","package","wrong"},{"native_app_session/current_domain/source_frame","background_generation","wrong"},
            {"native_app_session/current_domain/source_frame","display_id","zero"},{"native_app_session/current_domain/source_frame","window_id","zero"},
            {"native_app_session/current_domain/source_frame","window_type","zero"},{"native_app_session/current_domain/source_frame","retained_nodes","zero"},
            {"native_app_session/current_domain/source_frame","completion_frame_sha256","wrong"},
            {"native_app_session/current_domain/source_frame","window_metadata_observed","false"},
            {"native_app_session/current_domain/source_frame","actual_collection_complete","false"},
            {"native_app_session/current_domain/source_frame","nodes_truncated","true"}
        };
        for(String[] fault:faults){Map<String,Object> changed=copy(f.evidence);
            Object value="true".equals(fault[2])?Boolean.TRUE:"false".equals(fault[2])?Boolean.FALSE:"zero".equals(fault[2])?Integer.valueOf(0):fault[2];
            at(changed,fault[0]).put(fault[1],value);check(f.explain(changed).isEmpty(),"mismatched blocker evidence must not be displayed: "+Arrays.toString(fault));
            passed("native_reject_"+fault[0].replace('/','_')+"_"+fault[1]);}
        Map<String,Object> changed=copy(f.evidence);changed.put("identity_failure","installed_native_app_identity_changed_after_cleanup");
        check(f.explain(changed).isEmpty(),"changed installed identity suppresses the previous provider explanation");passed("native_reject_changed_installed_identity");
        changed=copy(f.evidence);changed.remove("native_app_session");check(f.explain(changed).isEmpty(),"no guessed blocker without actual provider session");passed("native_reject_missing_session");
        NotesCompletionEvidence.Frame other=new NotesCompletionEvidence.Frame("22222222222222222222222222222222",f.frame.packageName,
                f.frame.windowId,f.frame.displayId,f.frame.backgroundGeneration,1,true,false,f.frame.nodes);
        check(LocalTaskController.OutcomeExplanation.create(f.task,f.owner,"failed",true,false,other,f.evidence,null).isEmpty(),"old frame cannot describe a newer final observation");
        passed("native_reject_old_observation_against_actual_final_frame");
        for(String status:new String[]{"cancelled","blocked","model_reported_done","controller_verified_done"}){
            check(LocalTaskController.OutcomeExplanation.create(f.task,f.owner,status,true,false,f.frame,f.evidence,null).isEmpty(),"original terminal precedence: "+status);
            passed("terminal_preserves_"+status);
        }
        check(LocalTaskController.OutcomeExplanation.create(f.task,f.owner,"failed",false,false,f.frame,f.evidence,null).isEmpty(),"unknown cleanup remains primary");passed("terminal_preserves_unknown_cleanup");
        check(LocalTaskController.OutcomeExplanation.create(f.task,f.owner,"partial",true,true,f.frame,f.evidence,null).isEmpty(),"completed result must not acquire blocker text");passed("terminal_preserves_completed_result");
        String raw="模型报告无法完成：未知";Map<String,Object> snapshot=f.explain(f.evidence);
        LocalTaskController.TaskResult result=new LocalTaskController.TaskResult(f.task,"failed",raw,6,null,null,false,true,null,null,false,f.evidence,snapshot);
        check(raw.equals(result.summary)&&result.displaySummary.endsWith(raw)&&"failed".equals(result.status)
                &&result.cleanupKnown&&!result.completionVerified&&!result.modelReportedSuccess,"original model outcome/status/cleanup remain unchanged");
        snapshot.put("message","changed after publication");check(!result.displaySummary.contains("changed after publication")
                &&!"changed after publication".equals(result.userExplanation.get("message")),"result snapshots its display-only facts");
        boolean immutable=false;try{result.userExplanation.put("message","changed");}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"published explanation is immutable");passed("task_result_keeps_raw_outcome_and_immutable_explanation");
        LocalTaskController.TaskResult legacy=new LocalTaskController.TaskResult(f.task,"failed",raw,6,null,null,false,true,null,null);
        check(raw.equals(legacy.displaySummary)&&legacy.userExplanation.isEmpty(),"legacy result construction retains exact text");passed("legacy_result_is_unchanged");
    }
    private static JSONObject launchFixture(String task,String owner)throws Exception{
        String generation="00000000-0000-4000-8000-000000000099",name="hepta-bg-"+generation;
        JSONObject response=new JSONObject().put("version",1).put("request_id","00000000-0000-4000-8000-000000000098")
                .put("generation",generation).put("state","RELEASED").put("display_id",9).put("display_name",name)
                .put("expires_elapsed_ms",9000L).put("ok",false).put("dispatched",false).put("operation","launch")
                .put("error","APP_ALREADY_ON_MAIN_DISPLAY").put("terminal_reason","APP_ALREADY_ON_MAIN_DISPLAY");
        return new JSONObject().put("schema","hepta.background-session.v1").put("task_id",task).put("owner_sha256",owner)
                .put("generation",generation).put("state","RELEASED").put("display_id",9).put("display_name",name)
                .put("expires_elapsed_ms",9000L).put("retired",true).put("bootstrap_dispatched",false)
                .put("broker_process_exit_observed",true).put("broker_process_exit_code",0).put("last_broker_response",response);
    }
    private static void launchCases(NativeFixture f)throws Exception{
        JSONObject background=launchFixture(f.task,f.owner);
        Map<String,Object> empty=Collections.emptyMap();
        Map<String,Object> reason=LocalTaskController.OutcomeExplanation.create(f.task,f.owner,"failed",true,false,null,empty,background);
        check("APP_ALREADY_ON_MAIN_DISPLAY".equals(reason.get("code"))&&Boolean.FALSE.equals(reason.get("grants_tool_authority")),"exact bound broker refusal gives owner guidance only");
        passed("released_undispatched_main_display_refusal_is_explained");
        String[][] faults={{"outer","task_id","wrong"},{"outer","owner_sha256","wrong"},{"outer","state","ACTIVE"},
                {"outer","retired","false"},{"outer","bootstrap_dispatched","true"},{"outer","broker_process_exit_observed","false"},
                {"outer","broker_process_exit_code","wrong"},{"response","generation","wrong"},{"response","display_id","wrong"},
                {"response","version","wrong"},{"response","state","ACTIVE"},{"response","display_name","wrong"},
                {"response","expires_elapsed_ms","wrong"},{"response","ok","true"},{"response","dispatched","true"},
                {"response","operation","back"},{"response","error","APP_ALREADY_ON_OTHER_DISPLAY"},{"response","terminal_reason","wrong"}};
        for(String[] fault:faults){JSONObject changed=new JSONObject(background.toString());
            Object value="true".equals(fault[2])?Boolean.TRUE:"false".equals(fault[2])?Boolean.FALSE:fault[2];
            if("outer".equals(fault[0]))changed.put(fault[1],value);
            else{JSONObject response=changed.getJSONObject("last_broker_response");response.put(fault[1],value);
                changed.put("last_broker_response",response);}
            check(LocalTaskController.OutcomeExplanation.create(f.task,f.owner,"failed",true,false,null,empty,changed).isEmpty(),"wrong broker evidence must keep raw error: "+Arrays.toString(fault));
            passed("launch_reject_"+fault[0]+"_"+fault[1]);}
    }
    private static void unknownCases()throws Exception{
        String task="33333333333333333333333333333333",owner="打开系统设置查看存储空间";
        TaskAuthorization auth=TaskAuthorization.parse(owner);TaskCompletionGate completion=new TaskCompletionGate(task,owner,auth);
        Map<String,Object> value=completion.evidence(null);
        check(TaskCompletionGate.UNKNOWN.equals(completion.contract.kind),"actual parser supplies an unsupported complete-goal contract");
        Map<String,Object> reason=LocalTaskController.OutcomeExplanation.create(task,auth.instructionSha256,"partial",true,false,null,value,null);
        check("goal_verifier_unavailable".equals(reason.get("code"))&&!completion.verified(null),"unsupported goal is explained without a completion claim");
        passed("actual_unknown_goal_reports_verification_limit");
        Map<String,Object> changed=copy(value);changed.put("missing",Collections.emptyList());
        check(LocalTaskController.OutcomeExplanation.create(task,auth.instructionSha256,"partial",true,false,null,changed,null).isEmpty(),"missing verifier evidence cannot be invented");passed("unknown_reject_missing_reason");
        changed=copy(value);at(changed,"contract").put("owner_sha256","wrong");
        check(LocalTaskController.OutcomeExplanation.create(task,auth.instructionSha256,"partial",true,false,null,changed,null).isEmpty(),"unsupported contract must be bound to actual owner");passed("unknown_reject_other_owner_contract");
    }
    public static void main(String[] args)throws Exception{
        NativeFixture fixture=new NativeFixture();nativeCases(fixture);launchCases(fixture);unknownCases();
        JSONObject result=new JSONObject().put("schema","hepta.outcome-explanation-host.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",new org.json.JSONArray(names))
                .put("phone_operations",0).put("android_runtime",false).put("model_inference",false).put("provider_or_business_verified",false);
        Files.write(Paths.get(args[0]),result.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println(result.toString());
    }
}
