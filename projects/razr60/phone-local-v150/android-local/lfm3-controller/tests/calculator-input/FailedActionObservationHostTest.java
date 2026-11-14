package org.trillionnium.hepta.local;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual LocalTaskController and extracted production service dispatch, with
 * explicit Android/native IO fakes.  An unknown text-field task avoids relying
 * on the new Calculator guard to reach the failed-dispatch diagnostic branch.
 * No result of this test is a new phone/native/Calculator completion receipt. */
public final class FailedActionObservationHostTest {
    private static final String OWNER="在当前测试文本框输入一份诊断样本。";
    private static final String INPUT="31*47",OBSERVED="explicit host observation after an uncertain write";
    private static final String READBACK_FAILURE="文本操作已发送，但原文回读未通过；不重试";
    private static final List<Object> cases=new ArrayList<Object>();
    private static int checks;
    private static void check(boolean condition,String why){checks++;if(!condition)throw new AssertionError(why);}
    private static JSONObject json(Path path)throws Exception{return new JSONObject(new String(Files.readAllBytes(path),StandardCharsets.UTF_8));}

    private static final class Model implements LocalInference {
        final QualificationScopeHostTest.Env env;
        int calls,ends,cancellations,observationsAtRequest;String task;
        Model(QualificationScopeHostTest.Env env){this.env=env;}
        public LocalRuntimeConfig configuration(){return env.runtime;}
        public void beginTask(String id){task=id;}
        public void cancelTask(){cancellations++;}
        public TaskCleanup endTask(){ends++;return new TaskCleanup(true,true,true,0,TaskCompletionGateHostTest.id(831),task,true,QualificationScopeHostTest.H);}
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int maximumTokens,long timeout,Callback callback){
            calls++;observationsAtRequest=env.service.observations;
            check(calls==1,"no repeated native request after a failed dispatched write");
            check(image==null&&prompt.endsWith("\nOWNER\n"+OWNER),"ordinary text-only input and immutable OWNER retained");
            check(grammar.actions.contains("type"),"unknown text-field task reaches the actual writable-field branch");
            try{
                JSONObject action=new JSONObject().put("reason","explicit native IO fake selects one observed text field").put("action","type")
                        .put("observation_id",env.service.current.id).put("package",env.service.current.packageName)
                        .put("node_label",grammar.targets.labels.get("n0")).put("node_id","n0").put("text",INPUT);
                callback.onSuccess(action.toString(),TaskCompletionGateHostTest.id(830));
            }catch(Exception invalid){throw new IllegalStateException(invalid);}
            return ()->{};
        }
    }

    private static void run(String mode)throws Exception{
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            Model model=new Model(e);final int[] diagnosticReads={0};
            // The fake Android SET_TEXT API accepts once. Its delayed readback
            // differs or refresh fails. Production service determines the outcome.
            e.service.effectHook=()->{
                if("refresh-unavailable".equals(mode))e.service.node.refreshResult=false;
                else e.service.node.text=OBSERVED;
                if("cancel-before-diagnostic".equals(mode))e.controller.stop();
            };
            e.service.observationRows=()->{
                if(e.service.node.actions>0){
                    diagnosticReads[0]++;
                    if("diagnostic-fails".equals(mode))throw new IllegalStateException("synthetic diagnostic observer unavailable");
                    if("cancel-during-diagnostic".equals(mode))e.controller.stop();
                }
                return java.util.Collections.singletonList(TaskCompletionGateHostTest.row("n0",e.service.node.pkg,e.service.node.text,"synthetic:id/entry",
                        new android.graphics.Rect(10,10,500,150),true,true,false));
            };
            e.controller=new LocalTaskController(e.service,model);
            final LocalTaskController.TaskResult[] terminal={null};CountDownLatch finished=new CountDownLatch(1);
            check(e.controller.start(OWNER,null,new LocalTaskController.Listener(){public void onState(String ignored){}public void onFinished(LocalTaskController.TaskResult result){terminal[0]=result;finished.countDown();}}),"actual controller starts unknown text-field task");
            check(finished.await(10,TimeUnit.SECONDS),"bounded controller test completes");
            LocalTaskController.TaskResult result=terminal[0];check(result!=null&&result.evidenceDirectory!=null,"actual controller terminal record exists");
            Path directory=result.evidenceDirectory.toPath();JSONObject action=json(directory.resolve("step-01-action.json"));
            JSONObject before=json(directory.resolve("step-01-before.json")),saved=json(directory.resolve("result.json"));
            check(model.calls==1&&model.ends==1&&e.service.node.actions==1&&e.service.effects()==1,"one inference, one Android effect, one worker cleanup; no retry");
            check(!action.getBoolean("accepted")&&action.getBoolean("dispatched")&&!action.getBoolean("stale")&&action.getBoolean("model_issued"),"failed dispatched outcome is preserved verbatim");
            check(action.getJSONObject("action").getString("text").equals(INPUT),"literal attempted payload retained");
            check(saved.getInt("steps")==1&&!saved.getBoolean("model_reported_success")&&!saved.getBoolean("completion_verified")
                    &&!saved.getBoolean("goal_independently_verified")&&saved.getBoolean("cleanup_known"),"no diagnostic path promotes completion or hides cleanup");
            check(before.getString("observation_id").equals(saved.getString("final_observation_id")),"diagnostic never replaces authoritative final/before observation");
            check(!Files.exists(directory.resolve("step-01-after.json"))&&!Files.exists(directory.resolve("step-01-completion-check.json")),"no successful after/completion proof created for rejected effect");
            try(Stream<Path> paths=Files.list(directory)){check(paths.noneMatch(p->p.getFileName().toString().startsWith("step-02-")),"no later planner or action step");}
            check(!saved.getJSONObject("completion_evidence").getBoolean("observation_chain_verified")
                    &&!saved.getJSONObject("completion_evidence").getBoolean("terminal_binding_and_cleanup_verified"),"completion remains unverified after all diagnostics");
            boolean cancelled=mode.startsWith("cancel-");
            check((cancelled?"cancelled":"failed").equals(saved.getString("status")),"existing terminal cancellation/failure classification retained");
            if(cancelled){check(model.cancellations>=1&&saved.getString("summary").contains("已停止"),"existing stop semantics retained; original action error remains separately recorded");}
            else check(READBACK_FAILURE.equals(action.getString("detail"))&&saved.getString("summary").equals(action.getString("detail")),"diagnostic error cannot replace original failed readback summary");

            Path diagnosticPath=directory.resolve("step-01-failed-after-diagnostic.json");
            boolean attempted=!"cancel-before-diagnostic".equals(mode);
            check(diagnosticReads[0]==(attempted?1:0)&&e.service.observations==model.observationsAtRequest+(attempted?1:0),"one additional observation at most; cancellation before entry does not observe");
            String diagnosticSha=null,observationSha=null;
            if(!attempted){
                check(!Files.exists(diagnosticPath)&&!Files.exists(directory.resolve("step-01-failed-after.json")),"pre-diagnostic stop does not start or fabricate diagnostic evidence");
                check(action.getString("detail").contains("任务已停止"),"cancelled dispatched action retains its actual callback error");
            }else{
                JSONObject diagnostic=json(diagnosticPath);diagnosticSha=ObservedImeEnter.hash(new String(Files.readAllBytes(diagnosticPath),StandardCharsets.UTF_8));
                check("hepta.failed-action-readonly-observation.v1".equals(diagnostic.getString("schema"))
                        &&diagnostic.getString("task_id").equals(saved.getString("task_id"))&&diagnostic.getInt("step")==1
                        &&diagnostic.getString("model_run_id").equals(action.getString("model_run_id"))
                        &&diagnostic.getString("before_observation_id").equals(before.getString("observation_id")),"diagnostic bound to original task/run/before/action step");
                check(!diagnostic.getBoolean("original_accepted")&&diagnostic.getBoolean("original_dispatched")
                        &&diagnostic.getString("original_detail").equals(action.getString("detail"))
                        &&!diagnostic.getBoolean("effect_retried")&&!diagnostic.getBoolean("completion_advanced")&&diagnostic.getInt("observation_attempts")==1,
                        "diagnostic retains failure and cannot authorize action or completion");
                boolean observed="changed-text".equals(mode)||"refresh-unavailable".equals(mode);
                check(diagnostic.getBoolean("observed")==observed,"real diagnostic success/failure is recorded without promotion");
                Path failedAfter=directory.resolve("step-01-failed-after.json");
                if(observed){
                    JSONObject after=json(failedAfter);observationSha=ObservedImeEnter.hash(new String(Files.readAllBytes(failedAfter),StandardCharsets.UTF_8));
                    check("step-01-failed-after.json".equals(diagnostic.getString("observation_file"))&&observationSha.equals(diagnostic.getString("observation_sha256"))
                            &&after.getString("observation_id").equals(diagnostic.getString("observation_id"))&&!after.getString("observation_id").equals(saved.getString("final_observation_id")),
                            "separate actual diagnostic JSON raw hash/id, never relabeled successful after");
                    JSONObject node=after.getJSONArray("nodes").getJSONObject(0);String expected="refresh-unavailable".equals(mode)?INPUT:OBSERVED;
                    check(expected.equals(node.getString("text"))&&ObservedImeEnter.hash(expected).equals(node.getString("input_text_sha256")),"actual post-failure raw text is retained, not guessed from attempted payload");
                }else{
                    check(!Files.exists(failedAfter)&&diagnostic.has("observation_error"),"failed/cancelled observation cannot fabricate raw after or trigger retry");
                    if("diagnostic-fails".equals(mode))check(diagnostic.getString("observation_error").contains("synthetic diagnostic observer unavailable"),"secondary observation error kept in separate diagnostic only");
                }
            }
            cases.add(new JSONObject().put("name",mode).put("passed",true).put("task_id",saved.getString("task_id"))
                    .put("terminal_status",saved.getString("status")).put("model_requests",model.calls).put("effect_calls",e.service.effects())
                    .put("diagnostic_observations",diagnosticReads[0]).put("diagnostic_sha256",diagnosticSha==null?JSONObject.NULL:diagnosticSha)
                    .put("diagnostic_raw_observation_sha256",observationSha==null?JSONObject.NULL:observationSha)
                    .put("phone_tested",false).put("native_inference",false));
            System.out.println("PASS failed-dispatch diagnostic "+mode+"; original outcome retained; host IO only");
        }
    }

    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);QualificationScopeHostTest.output=out.resolve("service-io");Files.createDirectories(QualificationScopeHostTest.output);
        for(String mode:new String[]{"changed-text","refresh-unavailable","diagnostic-fails","cancel-during-diagnostic","cancel-before-diagnostic"})run(mode);
        Files.write(out.resolve("RESULT.json"),new JSONObject().put("passed",true).put("checks",checks).put("cases",new JSONArray(cases))
                .put("actual_controller_and_service_dispatch",true).put("android_and_native_io_are_fakes",true).put("phone_tested",false)
                .put("no_effect_retry_or_completion_promotion",true).toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS "+checks+" one-shot failed-action observation checks; cases="+cases.size()+"; phone_tested=false");
    }
}
