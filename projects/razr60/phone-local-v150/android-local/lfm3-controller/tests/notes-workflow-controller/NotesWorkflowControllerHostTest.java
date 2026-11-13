package org.trillionnium.hepta.local;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentTarget;

/** Executes the actual controller/service using explicitly synthetic Android
 * effects and native callbacks. A host pass is never a phone or NPU proof. */
public final class NotesWorkflowControllerHostTest {
    private static int assertions;
    private static final List<String> cases=new ArrayList<String>();
    private static final String P=TaskCompletionGateHostTest.P,BODY=TaskCompletionGateHostTest.BODY,H=TaskCompletionGateHostTest.H;
    private static final String OWNER=TaskCompletionGateHostTest.OWNER;
    private static final String NATURAL="新建笔记："+BODY;
    private static void check(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    private static JSONObject read(Path p)throws Exception{return new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));}
    @SuppressWarnings("unchecked") private static JSONObject object(Object raw){
        if(raw instanceof JSONObject)return (JSONObject)raw;
        if(raw instanceof Map<?,?>)return new JSONObject((Map<String,Object>)raw);
        throw new AssertionError("actual object required");
    }
    private static JSONArray array(JSONObject p,String key)throws Exception{
        Object raw=p.get(key);if(raw instanceof JSONArray)return (JSONArray)raw;
        if(raw instanceof Collection<?>)return new JSONArray((Collection<?>)raw);
        throw new AssertionError("actual array required: "+key);
    }
    private static final class Model implements LocalInference {
        final QualificationScopeHostTest.Env env;
        final TaskCompletionGateHostTest.Model io;
        final String mode,owner;
        String task;int calls,ends;
        Model(QualificationScopeHostTest.Env env,String mode,String owner){
            this.env=env;this.mode=mode;this.owner=owner;
            io=new TaskCompletionGateHostTest.Model(env,"draft",owner);io.setup();
            if("observation_fails_after_back".equals(mode)){
                final java.util.function.Supplier<List<PhoneObservation.Node>> original=env.service.observationRows;
                env.service.observationRows=()->{if(io.phase==2)throw new IllegalStateException("synthetic read failure after a real fake Back effect");return original.get();};
            }
        }
        public LocalRuntimeConfig configuration(){return env.runtime;}
        public void beginTask(String task){this.task=task;}
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int maximum,long timeout,Callback callback){
            calls++;
            try{
                check(calls==1,"verified workflow must not request another model decision: "+mode);
                check(prompt.endsWith("\nOWNER\n"+owner),"immutable OWNER remains exact");
                check(!grammar.successAllowed,"the initial empty completion cannot advertise success");
                FixedIntentTarget target=grammar.fixedIntentTargets.get("notes.create");check(target!=null,"model receives the ordinary fixed entry");
                String raw=new JSONObject().put("reason","synthetic native parent creation only").put("action","notes.create")
                        .put("observation_id",grammar.observationId).put("app_label",ObservedAppLabels.project(target.appLabel))
                        .put("package",target.packageName).put("text",BODY).toString();
                callback.onSuccess(raw,TaskCompletionGateHostTest.id(9001));
            }catch(Exception failure){throw new IllegalStateException(failure);}
            return ()->{};
        }
        public TaskCleanup endTask(){
            ends++;
            if("close_cancel".equals(mode))env.controller.stop();
            if("close_owner_retired".equals(mode))env.service.taskAuthorization.retire();
            if("close_identity_changed".equals(mode))try{
                QualificationScopeHostTest.write(Paths.get(env.pm.packages.get(P).applicationInfo.sourceDir),
                        "synthetic changed installed bytes after workflow".getBytes(StandardCharsets.UTF_8),0644);
            }catch(Exception failure){throw new IllegalStateException(failure);}
            if("no_worker".equals(mode))return TaskCleanup.noWorker();
            if("cleanup_unknown".equals(mode))return new TaskCleanup(false,true,false,null,
                    TaskCompletionGateHostTest.id(9090),task,false,null);
            return new TaskCleanup(true,true,true,"nonzero_exit".equals(mode)?9:0,
                    TaskCompletionGateHostTest.id(9090),"foreign_session_task".equals(mode)?TaskCompletionGateHostTest.id(9999):task,
                    !"bad_receipt".equals(mode),"missing_session_hash".equals(mode)?null:H);
        }
    }
    private static void runCase(String mode,String owner,String expected,boolean verified)throws Exception{
        try(QualificationScopeHostTest.Env env=new QualificationScopeHostTest.Env(false)){
            TaskCompletionGateHostTest.installPackage(env,"notes.create");
            Model model=new Model(env,mode,owner);env.controller=new LocalTaskController(env.service,model);
            CountDownLatch done=new CountDownLatch(1);LocalTaskController.TaskResult[] box={null};
            check(env.controller.start(owner,null,new LocalTaskController.Listener(){
                public void onState(String state){}
                public void onFinished(LocalTaskController.TaskResult result){box[0]=result;done.countDown();}
            }),"ordinary synthetic task starts");
            check(done.await(10,TimeUnit.SECONDS),"bounded actual controller terminal: "+mode);
            LocalTaskController.TaskResult result=box[0];
            check(result!=null&&expected.equals(result.status),"honest terminal: "+mode+" / "+(result==null?"missing":result.status+" "+result.summary));
            check(result.completionVerified==verified&&!result.modelReportedSuccess,"controller proof never manufactures a model success: "+mode);
            check(model.calls==1&&model.ends==1&&result.steps==1,"exactly one model parent and one teardown: "+mode);
            Path dir=result.evidenceDirectory.toPath();JSONObject raw=read(dir.resolve("result.json"));
            check(!raw.getBoolean("model_reported_success")&&raw.isNull("model_done_status")&&raw.isNull("model_done_summary"),"original absence of model done is preserved");
            check(!raw.getBoolean("model_done_synthesized")&&raw.getBoolean("completion_verified")==verified,"explicit result actor and completion are independent");
            check(verified?"controller/tool_workflow".equals(raw.getString("completion_actor")):raw.isNull("completion_actor"),"only fully accepted terminal gets controller completion actor");
            JSONObject parent=read(dir.resolve("step-01-action.json"));
            JSONObject parentAction=parent.getJSONObject("action");
            check("notes.create".equals(parentAction.getString("action"))&&BODY.equals(parentAction.getString("text")),"parent remains the actual model create/payload");
            JSONObject fixed=parent.getJSONObject("fixed_intent");
            check("draft_opened".equals(fixed.getString("requested_outcome"))&&!fixed.getBoolean("saved_or_search_results_verified"),"original fixed Intent receipt still proves draft only");
            check(Files.exists(dir.resolve("fixed-intent-01-attempt.json"))&&!Files.exists(dir.resolve("fixed-intent-02-attempt.json")),"one durable fixed-entry attempt, no retry");
            check(!Files.exists(dir.resolve("step-02-action.json"))&&!Files.exists(dir.resolve("step-02-model-0.json")),"children are not additional model steps or runs");
            if("observation_fails_after_back".equals(mode)){
                check(env.service.opens==1&&env.service.navigations==1&&env.service.node.actions==0,"uncertain after frame stops after one Back, no replay or click");
                check(Files.exists(dir.resolve("step-01-tool-child-01-action.json"))
                        &&!Files.exists(dir.resolve("step-01-tool-child-01-after.json")),"raw child acknowledgement is retained without inventing an after frame");
                check(Files.exists(dir.resolve("step-01-notes-workflow-aborted.json")),"partial effect abort is durably explicit");
                check(!raw.getJSONObject("completion_evidence").getBoolean("observation_chain_verified"),"failed observation cannot promote completion");
            }else{
                check(env.service.opens==1&&env.service.navigations==1&&env.service.node.actions==1,"exact actual fake create, Back, same-item click");
                JSONObject workflow=read(dir.resolve("step-01-notes-workflow-result.json"));
                check(workflow.getBoolean("workflow_verified")&&workflow.getBoolean("accepted_as_completion_proof"),"actual workflow chain existed before terminal gates");
                check(!workflow.getBoolean("model_issued")&&!workflow.getBoolean("model_done_synthesized"),"workflow has its own actor");
                check(workflow.getBoolean("grant_consumed")&&workflow.getBoolean("grant_retired"),"single-use grant consumed and retired");
                check("draft_opened".equals(workflow.getString("fixed_intent_outcome_unchanged")),"workflow never rewrites fixed entry semantics");
                JSONArray children=array(workflow,"children");check(children.length()==2,"this synthetic surface requires one Back and one click");
                for(int i=0;i<2;i++){
                    String childName=String.format(java.util.Locale.ROOT,"step-01-tool-child-%02d",i+1);
                    JSONObject child=read(dir.resolve(childName+"-action.json"));
                    check("tool_child".equals(child.getString("actor_kind"))&&!child.getBoolean("model_issued"),"child is never model-issued");
                    check(ActionDecision.TOOL_CHILD_SCHEMA.equals(child.getString("action_schema")),"internal request has a separate schema");
                    check(TaskCompletionGateHostTest.id(9001).equals(child.getString("parent_model_run_id"))
                            &&fixed.getString("attempt_id").equals(child.getString("parent_fixed_intent_attempt_id")),"same real parent run/ledger links every child");
                    check(child.getBoolean("accepted")&&child.getBoolean("dispatched")&&!child.getBoolean("stale"),"child's service facts are explicit");
                    JSONObject service=child.getJSONObject("tool_child");
                    check("tool_child".equals(service.getString("actor_kind"))&&!service.getBoolean("model_issued")
                            &&service.getBoolean("service_entered")&&!service.getBoolean("grant_retired"),"live service supplies its original child acknowledgement");
                    check(Files.exists(dir.resolve(childName+"-before.json"))&&Files.exists(dir.resolve(childName+"-after.json"))
                            &&Files.exists(dir.resolve(childName+"-proof.json")),"each accepted child keeps actual before/after/proof");
                    JSONObject record=object(children.get(i));
                    check(record.getBoolean("live_lease_verified"),"child callback retained the same active task lease");
                }
                JSONArray proofs=array(raw.getJSONObject("completion_evidence"),"proofs");boolean childProof=false;
                for(int i=0;i<proofs.length();i++){
                    JSONObject p=object(proofs.get(i));String kind=p.getString("kind");
                    check(!"same_observed_list_item_reopened".equals(kind),"tool children do not fabricate the legacy model-click proof");
                    if("tool_child_same_observed_list_item_reopened".equals(kind)){childProof=true;check(!p.getBoolean("model_issued"),"separate proof records actual actor");}
                }
                check(childProof,"separate tool-child proof is present");
                check(array(raw.getJSONObject("completion_evidence"),"model_success_claims").length()==0,"no model done claim is appended");
                check(raw.getBoolean("controller_completion_requested"),"terminal candidate is explicit even when later rejected");
                if(!verified)check(!raw.getJSONObject("completion_evidence").getBoolean("terminal_binding_and_cleanup_verified"),"post-workflow gate failure removes terminal completion");
            }
            if("cleanup_unknown".equals(mode)){
                check(!result.cleanupKnown&&!env.service.acquireTask(TaskCompletionGateHostTest.id(9191),()->{}),"unknown cleanup retains the task lease");
                env.service.releaseTask(result.taskId); // Explicit fake-environment teardown only.
            }else check(result.cleanupKnown,"known teardown retained");
            cases.add(mode+(NATURAL.equals(owner)?"_natural":"_literal"));
        }
    }
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);QualificationScopeHostTest.output=out;
        runCase("complete",OWNER,"controller_verified_done",true);
        runCase("complete",NATURAL,"controller_verified_done",true);
        runCase("no_worker",OWNER,"partial",false);
        runCase("bad_receipt",OWNER,"failed",false);
        runCase("foreign_session_task",OWNER,"partial",false);
        runCase("missing_session_hash",OWNER,"partial",false);
        runCase("nonzero_exit",OWNER,"partial",false);
        runCase("close_identity_changed",OWNER,"partial",false);
        runCase("close_owner_retired",OWNER,"failed",false);
        runCase("close_cancel",OWNER,"cancelled",false);
        runCase("cleanup_unknown",OWNER,"blocked",false);
        runCase("observation_fails_after_back",OWNER,"failed",false);
        JSONObject report=new JSONObject().put("schema","hepta.notes-workflow-controller-host.v1").put("passed",true)
                .put("cases",new JSONArray(cases)).put("assertions",assertions).put("actual_controller_and_service_code",true)
                .put("android_and_native_io_are_synthetic",true).put("phone_tested",false).put("native_inference",false);
        Files.write(out.resolve("TEST-RESULTS.json"),report.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS "+assertions+" actual workflow controller assertions; cases="+cases.size()+"; phone_tested=false; native_io_is_fake=true");
    }
}
