package org.trillionnium.hepta.local;

import android.os.SystemClock;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.json.JSONObject;

/** Real ordinary public RuntimeInferenceAdapter factory -> original VLM task ->
 * complete LTC calendar model waiter -> private Adapter receipt -> real Session
 * registration -> actual fresh pixel producer. Native return/Android/kernel and
 * negative settings publication are explicit host ports. No authority object is
 * constructed by reflection, no model or input is run, and no business succeeds. */
public final class NativeCalendarRuntimeAdapterHostTest {
    static final String TASK=NativeCalendarDateSessionHostTest.TASK;
    static final long START=NativeCalendarDateSessionHostTest.START;
    static int checks;static Path out;
    static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    interface Work {void run()throws Exception;}
    static void check(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    static int total(){return checks+NativeCalendarDateFreshHostTest.checks+NativeCalendarDateModelHostTest.checks+NativeCalendarDateSessionHostTest.assertions;}
    static Object field(Object value,String name)throws Exception{return NativeCalendarDateModelHostTest.field(value,name);}
    static void refuse(Work action)throws Exception{boolean refused=false;try{action.run();}
        catch(IllegalArgumentException|IllegalStateException|IOException expected){refused=true;}
        check(refused,"original identity/currentness must reject");}
    static void one(String name,Work action){Map<String,Object> result=new LinkedHashMap<String,Object>();result.put("name",name);int before=total();
        try{action.run();result.put("passed",true);}catch(Throwable failure){result.put("passed",false);result.put("error",failure.toString());
            StringWriter trace=new StringWriter();failure.printStackTrace(new PrintWriter(trace));result.put("stack",trace.toString());}
        result.put("assertions",total()-before);cases.add(result);}
    static void noRegistration(RuntimeCalendarFixture.Env e)throws Exception{
        check(!e.journals.contains("native-calendar-model-registration.json"),"rejected binding wrote no successful registry entry");
        check(!e.journals.contains("native-calendar-fresh-read-attempt.json"),"rejected binding did not begin a new read");
        check(e.service.captureCalls==0,"no independent fresh capture started");
    }

    public static void main(String[] args)throws Exception{
        NativeCalendarDateFreshHostTest.setup(args);out=Paths.get(args[0]);
        NativeCalendarDateModelHostTest.lfmTemplate=Files.readAllBytes(Paths.get(args[3]));
        check(MobiMindContract.sha(NativeCalendarDateModelHostTest.lfmTemplate).equals(VlmResultContract.LFM3_VL_2B.templateSha256),"actual original LFM3-VL template, never GUI substitution");
        one("ordinary_runtime_LTC_private_receipt_registry_and_actual_fresh_publication",()->{try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env()){
            Object binding=field(e.router,"binding");
            check(e.controller.inference==e.router&&e.offer.inference==e.router,"LTC and Offer retain the ordinary wrapper, not a replacement VLM");
            check(field(binding,"delegate")==e.adapter&&field(binding,"runtime")==e.engine.runtimeGeneration(),"actual factory captures exact delegate and generation");
            check(!((Boolean)field(e.offer,"callbackIssued")),"Offer and grammar must exist before callback issuance");
            check(e.offer.grammar()==e.grammar,"pre-callback grammar remains usable");
            NativeAppEvidence.Frame original=e.session.domain().frame;
            e.register();VlmInferenceAdapter.AcceptedRequest proof=e.proof();
            check(proof!=null&&e.controller.activeInference==null,"actual model waiter registered and cleared only its own handle");
            proof.requireBound(e.adapter,e.source,e.grammar);
            refuse(()->proof.requireBound(e.router,e.source,e.grammar));
            VlmInferenceAdapter wrong=new VlmInferenceAdapter(e.context,e.engine);
            refuse(()->proof.requireBound(wrong,e.source,e.grammar));
            check(e.offer.runtime==e.router.configuration()&&field(e.router,"binding")==binding,"no implicit runtime or delegate switch");
            check(Arrays.equals(e.raw,Files.readAllBytes(new File((File)field(e.round,"directory"),"raw.txt").toPath())),"actual original raw bytes including surrounding newlines preserved");
            e.service.inlinePublication=true;final boolean[] resourceCompletion={false};
            e.service.beforePublishHook=()->{int[] n=e.service.hostReadCounters();check(n[0]==1&&n[1]==1&&!e.service.observationIoBusy.get(),"read counters/resources complete before callback");resourceCompletion[0]=true;};
            NativeAppSession.CalendarPermit permit=e.await(true);
            check(resourceCompletion[0]&&e.service.callbackInsideWorker,"actual publication callback ordering exercised without asserting Runnable return");
            check(e.session.domain().frame==original&&e.service.current!=e.sourcePhone,"new capture does not replace original native domain");
            check(e.service.graphReads==2&&e.service.captureCalls==1,"actual complete pixel finisher ran one capture");
            check(permit.deadlineElapsed==START+13000&&((Number)e.model.evidence().get("model_received_elapsed_ms")).longValue()==START+5000,"original callback plus eight-second deadline is unchanged");
            e.source.requireCurrent();permit.requireForAction(e.session,e.background);NativeCalendarDateFreshHostTest.noEffect(permit);
            check(e.service.hostOriginalWaiterAbandoned()&&!e.controller.cancelled.get(),"successful waiter retirement is distinct from task cancellation");
            Files.write(out.resolve("POSITIVE-PERMIT.json"),new JSONObject(permit.evidence()).toString(2).getBytes(StandardCharsets.UTF_8));
            for(Constructor<?> c:RuntimeInferenceAdapter.CalendarModelBinding.class.getDeclaredConstructors())if(!c.isSynthetic())check(Modifier.isPrivate(c.getModifiers()),"runtime binding token has private constructor");
            for(Constructor<?> c:VlmInferenceAdapter.AcceptedRequest.class.getDeclaredConstructors())if(!c.isSynthetic())check(Modifier.isPrivate(c.getModifiers()),"accepted request retains private Adapter producer");
            permit.close();LocalInference.TaskCleanup cleanup=e.closeTaskResult();check(cleanup.cleanupKnown&&cleanup.receiptValid&&cleanup.processExitObserved&&Integer.valueOf(0).equals(cleanup.exitCode),"actual aggregate task finalizer observes normal returned process");
        }});
        one("unbegun_wrapper_wrong_task_and_equal_but_distinct_configuration_rejected",()->{try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env()){
            RuntimeInferenceAdapter.CalendarModelBinding token=e.router.bindCalendarModel(TASK,e.offer.runtime);
            check(token.requireCurrent(TASK,e.offer.runtime)==e.adapter,"bound original delegate available");
            refuse(()->e.router.bindCalendarModel("66666666666666666666666666666666",e.offer.runtime));
            refuse(()->e.router.bindCalendarModel(TASK,NativeCalendarDateSessionHostTest.gui()));
            RuntimeInferenceAdapter unbegun=new RuntimeInferenceAdapter(e.context,e.engine);
            refuse(()->unbegun.bindCalendarModel(TASK,e.offer.runtime));
            check(e.executor.size()==0&&e.offer.grammar()==e.grammar,"binding checks neither launch nor consume Offer grammar");noRegistration(e);
        }});
        one("new_RuntimeGeneration_before_callback_refuses_even_with_same_configuration_object",()->{try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env()){
            LocalModelEngine.RuntimeGeneration prior=e.engine.fixtureReplaceRuntime(e.offer.runtime);
            try{refuse(()->e.offer.modelCallback(new NativeCalendarDateFreshHostTest.Signal()));
                check(e.executor.size()==0,"stale runtime never reaches native launch");noRegistration(e);}
            finally{e.engine.fixtureRestoreRuntime(prior);}
        }});
        one("ending_ended_and_same_task_new_Binding_cannot_reuse_original_receipt",()->{try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env()){
            e.register();RuntimeInferenceAdapter.CalendarModelBinding token=e.router.bindCalendarModel(TASK,e.offer.runtime);
            Object oldBinding=field(e.router,"binding");AtomicReference<LocalInference.TaskCleanup> result=new AtomicReference<LocalInference.TaskCleanup>();AtomicReference<Throwable> error=new AtomicReference<Throwable>();
            Thread ending=new Thread(()->{try{result.set(e.router.endTask(TASK));}catch(Throwable failure){error.set(failure);}},"real-router-ending-boundary");ending.start();Runnable finisher=e.executor.take();
            check(Boolean.TRUE.equals(field(oldBinding,"ending")),"real endTask marks original binding ending before delegate finalizer");
            refuse(()->token.requireCurrent(TASK,e.offer.runtime));refuse(()->e.model.requireForFreshObservation());
            finisher.run();ending.join(5000);check(!ending.isAlive()&&error.get()==null&&result.get().cleanupKnown,"actual endTask completed");
            refuse(()->token.requireCurrent(TASK,e.offer.runtime));
            e.router.beginTask(TASK);check(field(e.router,"binding")!=oldBinding,"real beginTask creates a different Binding even for the same task id");
            refuse(()->token.requireCurrent(TASK,e.offer.runtime));refuse(()->e.model.requireForFreshObservation());
            check(!e.journals.contains("native-calendar-fresh-read-attempt.json"),"old receipt cannot migrate to fresh read after a new binding");
        }});
        one("actual_router_cancel_before_private_proof_prevents_controller_registration",()->{try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env()){
            e.startControllerModel();e.prepareNativeReturn();e.router.cancelTask();e.engine.fixtureAwaitCancel();e.finishNativeReturn();e.finishController(false);
            check(e.offer.closed(),"actual failed/cancelled callback closes the Offer");noRegistration(e);
            refuse(()->e.offer.registerModelReply());
        }});
        one("actual_router_cancel_after_registration_prevents_new_fresh_read",()->{try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env()){
            e.register();e.router.cancelTask();e.engine.fixtureAwaitCancel();
            refuse(()->e.model.requireForFreshObservation());refuse(()->e.model.beginFreshObservation(e.background));
            check(e.offer.closed()&&e.service.captureCalls==0,"cancelled actual Adapter provenance never becomes fresh capture permission");
        }});
        one("generation_replacement_between_callback_and_registration_is_rejected",()->{try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env()){
            e.deliverOnly();check(e.delivery.proof!=null&&!e.offer.closed(),"actual callback received private delegate proof before replacement");
            LocalModelEngine.RuntimeGeneration prior=e.engine.fixtureReplaceRuntime(e.offer.runtime);
            try{refuse(()->e.offer.registerModelReply());check(e.offer.closed(),"failed registration retires one-use Offer");noRegistration(e);}
            finally{e.engine.fixtureRestoreRuntime(prior);}
        }});
        one("late_actual_private_proof_after_original_binding_ended_is_not_delivered_as_current",()->{try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env()){
            NativeCalendarDateFreshHostTest.Signal signal=new NativeCalendarDateFreshHostTest.Signal();
            VlmInferenceAdapter.AcceptedRequestCallback actual=e.offer.modelCallback(signal);
            AtomicReference<VlmInferenceAdapter.AcceptedRequest> held=new AtomicReference<VlmInferenceAdapter.AcceptedRequest>();
            VlmInferenceAdapter.AcceptedRequestCallback delayed=new VlmInferenceAdapter.AcceptedRequestCallback(){
                public void onAcceptedRequest(VlmInferenceAdapter.AcceptedRequest p){held.set(p);}
                public void onSuccess(String raw,String id){throw new AssertionError("typed request must not fall back to raw success");}
                public void onFailure(String detail,boolean known){throw new AssertionError(detail);}};
            e.issue(delayed);e.finishNativeReturn();check(held.get()!=null,"proof is produced by actual finisher before explicit delivery delay");
            LocalInference.TaskCleanup cleanup=e.closeTaskResult();check(cleanup.cleanupKnown,"original task actually ended");
            actual.onAcceptedRequest(held.get());check(signal.ready==0&&signal.failed==1&&e.offer.closed(),"retired original binding rejects delayed proof");
            refuse(()->e.offer.registerModelReply());noRegistration(e);
        }});
        one("new_runtime_at_actual_fresh_publication_rejected_without_Permit",()->{try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env()){
            e.register();AtomicReference<LocalModelEngine.RuntimeGeneration> prior=new AtomicReference<LocalModelEngine.RuntimeGeneration>();
            e.service.beforePublishHook=()->{prior.set(e.engine.fixtureReplaceRuntime(e.offer.runtime));};
            try{e.await(false);check(prior.get()!=null,"replacement occurred inside actual pixel publication sequence");
                check(e.offer.closed()&&e.service.captureCalls==1&&!e.journals.contains("native-calendar-permit-attempt.json"),"fresh publication rejects changed generation before any Permit journal");
                check(field(e.service,"nativeCalendarTracked")==null,"failed fresh callback retires its own tracker");}
            finally{if(prior.get()!=null)e.engine.fixtureRestoreRuntime(prior.get());}
        }});
        one("original_CurrentFrame_retirement_prevents_private_receipt_and_no_replacement_image",()->{try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env()){
            e.startControllerModel();e.prepareNativeReturn();e.sourceRetired=true;e.finishNativeReturn();e.finishController(false);
            check(e.offer.closed(),"real current-frame failure closes original Offer");noRegistration(e);
            check(e.service.current==e.sourcePhone,"no newer image silently substituted for the original request");
            e.sourceRetired=false;
        }});
        one("lfm3vl_tools_early_selection_gate_is_closed_before_any_bootstrap",()->{
            String owner="在携程查询2026年11月27日北京到上海的单程机票，1名成人，读取真实航班和票价。只查询，不预订、不提交订单、不支付。";
            org.trillionnium.hepta.background.ProfileTarget profile=NativeProfileIdentityHostTest.ctrip();
            BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(owner,profile.packageName,Collections.singleton(profile.packageName),profile);
            BackgroundSession.Selection selected=new BackgroundSession.Selection(target,true);
            TaskAuthorization auth=TaskAuthorization.parse(owner).forExecutionSelection(selected);
            LocalRuntimeConfig tools=new LocalRuntimeConfig(ModelProfile.LFM3_VL_2B,"npu",8192,4,false);
            LocalTaskController.requireLfm3VlToolsSelection(tools,owner,auth,selected,target.nativeGoal);
            check(target.nativeGoal==selected.taskTarget.nativeGoal&&target.nativeGoal.toolCeiling.contains("click")
                    &&!target.nativeGoal.toolCeiling.contains("submit"),"same immutable read-only literal goal admitted without granting an action");
            refuse(()->LocalTaskController.requireLfm3VlToolsSelection(tools,owner,auth,null,target.nativeGoal));
            BackgroundSession.Selection regular=new BackgroundSession.Selection(target,false);
            refuse(()->LocalTaskController.requireLfm3VlToolsSelection(tools,owner,TaskAuthorization.parse(owner).forExecutionSelection(regular),regular,target.nativeGoal));
            refuse(()->LocalTaskController.requireLfm3VlToolsSelection(tools,owner+" ",auth,selected,target.nativeGoal));
            refuse(()->LocalTaskController.requireLfm3VlToolsSelection(tools,owner,TaskAuthorization.parse(owner),selected,target.nativeGoal));
            NativeAppGoal equivalent=NativeAppGoal.parse(owner,profile.packageName);
            refuse(()->LocalTaskController.requireLfm3VlToolsSelection(tools,owner,auth,selected,equivalent));
            String legacy=NativeCalendarDateSessionHostTest.OWNER;
            BackgroundTaskTarget legacyTarget=BackgroundTaskTarget.resolveExplicitSelection(legacy,profile.packageName,Collections.singleton(profile.packageName),profile);
            BackgroundSession.Selection legacySelection=new BackgroundSession.Selection(legacyTarget,true);
            refuse(()->LocalTaskController.requireLfm3VlToolsSelection(tools,legacy,TaskAuthorization.parse(legacy).forExecutionSelection(legacySelection),legacySelection,legacyTarget.nativeGoal));
            org.trillionnium.hepta.background.ProfileTarget wrongVersion=new org.trillionnium.hepta.background.ProfileTarget(profile.profile,profile.fullUid,
                    profile.packageName,profile.packageName+"/SyntheticActivity",profile.versionCode+1,profile.apkHashes,Collections.singleton(profile.apkHashes.get("base")));
            BackgroundTaskTarget wrongTarget=BackgroundTaskTarget.resolveExplicitSelection(owner,profile.packageName,Collections.singleton(profile.packageName),wrongVersion);
            BackgroundSession.Selection wrongSelection=new BackgroundSession.Selection(wrongTarget,true);
            refuse(()->LocalTaskController.requireLfm3VlToolsSelection(tools,owner,TaskAuthorization.parse(owner).forExecutionSelection(wrongSelection),wrongSelection,wrongTarget.nativeGoal));
            LocalTaskController.requireLfm3VlToolsSelection(NativeCalendarDateSessionHostTest.gui(),null,null,null,null);
            LocalTaskController.requireLfm3VlToolsSelection(new LocalRuntimeConfig(ModelProfile.LFM3_VL_2B,"npu",8192,4,true),null,null,null,null);
            check(true,"original GUI and observation modes do not acquire the new route restriction");
        });
        one("lfm3vl_pinned_template_actual_adapter_private_proof_and_calendar_chain",()->{
            LocalRuntimeConfig tools=new LocalRuntimeConfig(ModelProfile.LFM3_VL_2B,"npu",8192,4,false);
            try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env(tools)){
                check(e.offer.runtime==tools&&e.router.configuration()==tools&&e.adapter.configuration()==tools,"same exact configuration object through wrapper and private delegate");
                e.register();VlmInferenceAdapter.AcceptedRequest proof=e.proof();
                check(ModelProfile.LFM3_VL_2B.id.equals(proof.evidence().get("profile"))
                        &&Boolean.FALSE.equals(proof.evidence().get("visual_observation_only")),"LFM3-VL accepted receipt retains actual tools identity");
                proof.requireBound(e.adapter,e.source,e.grammar);
                check(e.grammar.actions.equals(Collections.singletonList(NativeCalendarDateIntent.ACTION))&&e.grammar.doneStatuses.isEmpty(),"same calendar grammar cannot claim task success or dispatch arbitrary actions");
                NativeAppSession.CalendarPermit permit=e.await(true);permit.requireForAction(e.session,e.background);
                NativeCalendarDateFreshHostTest.noEffect(permit);permit.close();
                LocalInference.TaskCleanup cleanup=e.closeTaskResult();
                check(cleanup.cleanupKnown&&cleanup.receiptValid&&cleanup.processExitObserved&&Integer.valueOf(0).equals(cleanup.exitCode),"original aggregate cleanup retires the same LFM3-VL task");
            }
        });
        one("lfm3vl_calendar_binding_cannot_migrate_to_observe_or_replaced_generation",()->{
            try(RuntimeCalendarFixture.Env e=new RuntimeCalendarFixture.Env(new LocalRuntimeConfig(ModelProfile.LFM3_VL_2B,"npu",8192,4,false))){
                RuntimeInferenceAdapter.CalendarModelBinding token=e.router.bindCalendarModel(TASK,e.offer.runtime);
                LocalModelEngine.RuntimeGeneration prior=e.engine.fixtureReplaceRuntime(new LocalRuntimeConfig(ModelProfile.LFM3_VL_2B,"npu",8192,4,true));
                try{
                    refuse(()->token.requireCurrent(TASK,e.offer.runtime));
                    refuse(()->e.offer.modelCallback(new NativeCalendarDateFreshHostTest.Signal()));
                    check(e.executor.size()==0,"observation or replaced runtime cannot launch the old calendar tools request");noRegistration(e);
                }finally{e.engine.fixtureRestoreRuntime(prior);}
            }
        });
        boolean ok=true;for(Map<String,Object> value:cases)ok&=Boolean.TRUE.equals(value.get("passed"));
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("all_pass",ok);report.put("cases",cases.size());report.put("assertions",total());report.put("case_results",cases);
        report.put("actual_public_runtime_constructor_and_default_factory",true);report.put("actual_LTC_calendar_model_waiter",true);
        report.put("actual_Adapter_private_receipt_and_Session_registry",true);report.put("actual_fresh_pixel_producer_publication",true);
        report.put("worker_read_accounting_and_resources_complete_before_callback",true);report.put("executor_runnable_return_before_callback_proven",false);
        report.put("model_or_Android_executions",0);report.put("input_attempts",0);report.put("business_or_ROM_qualification",false);
        Files.write(out.resolve("CASES.json"),new JSONObject(report).toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println(new JSONObject(report).toString());LocalModelEngine.fixtureShutdownCancellation();
        if(!ok)throw new AssertionError("calendar runtime identity cases failed");
    }
}
