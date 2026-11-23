package org.trillionnium.hepta.local;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.JSONObject;

/** Actual Session registry + Adapter private finishRequest producer.
 * The existing model fixture supplies only returned-process/Android/kernel ports.
 * No proof/Offer constructor is called by tests. Reflection only reuses those
 * explicit ports and reads private accounting; no authority field is injected. */
public final class NativeCalendarDateRegistryHostTest {
    static final long START=NativeCalendarDateSessionHostTest.START;
    static Path out,root;static int checks;
    static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    interface Work{void run()throws Exception;}
    static int total(){return checks+NativeCalendarDateModelHostTest.checks+NativeCalendarDateSessionHostTest.assertions;}
    static void check(boolean v,String why){checks++;if(!v)throw new AssertionError(why);}
    static void refuses(Work body)throws Exception{boolean refused=false;try{body.run();}
        catch(IllegalArgumentException|IllegalStateException|IOException|ActionDecision.InvalidActionException expected){refused=true;}
        check(refused,"expected closed refusal");}
    static void one(String name,Work body){Map<String,Object> r=new LinkedHashMap<String,Object>();r.put("name",name);int before=total();
        try{body.run();r.put("passed",true);}catch(Throwable error){r.put("passed",false);r.put("error",error.toString());
            StringWriter trace=new StringWriter();error.printStackTrace(new PrintWriter(trace));r.put("stack",trace.toString());}
        r.put("assertions",total()-before);cases.add(r);}
    static Object field(Object o,String key)throws Exception{return NativeCalendarDateModelHostTest.field(o,key);}
    static final class Signal implements NativeAppSession.CalendarModelSignal{
        int ready,failed;boolean known;String detail;
        public void onModelReady(){ready++;}
        public void onModelFailure(String value,boolean cleanup){failed++;detail=value;known=cleanup;}
    }
    static final class Delivery implements VlmInferenceAdapter.AcceptedRequestCallback{
        final Signal signal=new Signal();
        final VlmInferenceAdapter.AcceptedRequestCallback actual;
        VlmInferenceAdapter.AcceptedRequest proof;Object round;int opaqueCallbacks,rawCallbacks;
        Delivery(NativeAppSession.CalendarOffer offer)throws Exception{actual=offer.modelCallback(signal);}
        public void onAcceptedRequest(VlmInferenceAdapter.AcceptedRequest value){proof=value;opaqueCallbacks++;actual.onAcceptedRequest(value);}
        public void onSuccess(String raw,String id){rawCallbacks++;actual.onSuccess(raw,id);}
        public void onFailure(String detail,boolean cleanup){actual.onFailure(detail,cleanup);}
    }
    static Delivery issue(NativeCalendarDateModelHostTest.Environment e)throws Exception{
        Delivery d=new Delivery(e.offer);
        e.adapter.generateObserved("固定日期协议","真实宿主边界测试，不执行模型或Android输入",e.frame,e.grammar,256,120000,d);
        e.executor.take(); // The real native launch is replaced by the explicit existing returned-process fixture.
        d.round=field(field(e.adapter,"task"),"current");e.guard.round=d.round;e.lastRound=d.round;
        NativeCalendarDateModelHostTest.prepareReturned(e,d.round);return d;
    }
    static Delivery deliver(NativeCalendarDateModelHostTest.Environment e,long arrival)throws Exception{
        Delivery d=issue(e);e.nativeEnv.clock.now=arrival;NativeCalendarDateModelHostTest.finish(e,d.round);return d;
    }
    static Path journal(NativeCalendarDateModelHostTest.Environment e){return e.nativeEnv.directory.resolve("native-calendar-model-registration.json");}
    static Map<String,Object> object(Path p)throws Exception{return VlmResultContract.jsonObject(Files.readAllBytes(p));}
    static long number(Map<String,Object> value,String key){return ((Number)value.get(key)).longValue();}
    static void noPermit(Map<String,Object> e){
        check(Boolean.FALSE.equals(e.get("fresh_capture_consumed"))&&Boolean.FALSE.equals(e.get("calendar_permit_issued"))
            &&Boolean.FALSE.equals(e.get("android_dispatch_authority")),"provenance must not confer fresh capture or Android input");}
    static NativeAppSession.CalendarOffer otherOffer(NativeCalendarDateModelHostTest.Environment e,
            NativeCalendarDateSessionHostTest.Env other)throws Exception{
        NativeAppEvidence.Frame f=other.calendarFrame;
        LocalInference.CurrentFrame image=new LocalInference.CurrentFrame(other.image.toFile(),NativeCalendarDateSessionHostTest.TASK,
            other.goal.ownerSha256,f.observationId,f.generation,f.packageName,f.screenshotSha,f.width,f.height,f.displayId,f.windowId,f.rotation,
            f.capturedElapsedMs,other.owner.getBytes(StandardCharsets.UTF_8),()->{if(!other.live)throw new IllegalStateException("other source retired");});
        NativeCalendarDateEnvelope envelope=NativeCalendarDateEnvelope.capture(other.goal,f,image,other.profile,e.adapter.configuration(),other.clock);
        NativeAppSession.CalendarOffer offer=other.session.offerCalendarDate(envelope,e.adapter,other.clock,START+30000);offer.grammar();return offer;
    }
    static void mutate(Path p)throws Exception{Files.write(p,new byte[]{32},StandardOpenOption.APPEND);}
    public static void main(String[] args)throws Exception{
        out=Paths.get(args[0]);root=Paths.get(args[1]);Files.createDirectory(root);
        NativeCalendarDateModelHostTest.out=out;NativeCalendarDateModelHostTest.root=root;
        NativeCalendarDateModelHostTest.template=Files.readAllBytes(Paths.get(args[2]));
        check(MobiMindContract.sha(NativeCalendarDateModelHostTest.template).equals(VlmResultContract.GUI_OWL_4B.templateSha256),"actual pinned GUI template");
        NativeCalendarDateSessionHostTest.work=root;
        java.awt.image.BufferedImage image=new java.awt.image.BufferedImage(1224,2992,java.awt.image.BufferedImage.TYPE_INT_RGB);
        for(int y=0;y<image.getHeight();y++)for(int x=0;x<image.getWidth();x++){int c=(x*31+y*17)&255;image.setRGB(x,y,(c<<16)|(((c+41)&255)<<8)|((c+79)&255));}
        ByteArrayOutputStream png=new ByteArrayOutputStream();check(javax.imageio.ImageIO.write(image,"png",png),"host PNG encoder");
        NativeCalendarDateSessionHostTest.png=png.toByteArray();

        one("actual_private_adapter_callback_then_worker_registry_after_original_two_seconds",()->{
            try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                Delivery d=deliver(e,START+5000);
                check(d.proof!=null&&d.opaqueCallbacks==1&&d.rawCallbacks==0&&d.signal.ready==1&&d.signal.failed==0,"actual producer callback required");
                check(!Files.exists(journal(e)),"callback only stores provenance and wakes; no worker registration file yet");
                check(Arrays.equals(e.raw,d.proof.rawText().getBytes(StandardCharsets.UTF_8)),"native raw bytes remain exact");
                e.nativeEnv.clock.now=START+5300;NativeAppSession.CalendarModelRequest request=e.offer.registerModelReply();
                Map<String,Object> receipt=object(journal(e)),value=request.evidence();noPermit(value);noPermit(receipt);
                check(number(value,"model_received_elapsed_ms")==START+5000&&number(value,"original_action_deadline_elapsed_ms")==START+13000,
                    "registration must not renew callback arrival plus eight seconds");
                check(number(value,"registered_elapsed_ms")==START+5300&&number(receipt,"ordinal")==2,"actual worker completion time and existing native ordinal");
                check(((Set<?>)field(e.nativeEnv.session,"usedRuns")).contains(d.proof.requestId()),"actual shared run registry consumed");
                check(number(value,"original_task_deadline_elapsed_ms")==START+30000,"original task deadline retained");
                request.requireForFreshObservation();refuses(()->e.offer.registerModelReply());
                check(Files.exists(journal(e)),"the original registration file remains the only durable record");
                LocalInference.TaskCleanup end=e.end();check(end.cleanupKnown&&end.receiptValid&&end.processExitObserved,"real host aggregate model cleanup");
                refuses(()->request.requireForFreshObservation());
            }});
        one("duplicate_actual_callback_closes_without_renewal_or_second_registration",()->{
            try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                Delivery d=deliver(e,START+5000);e.nativeEnv.clock.now=START+5100;d.actual.onAcceptedRequest(d.proof);
                check(d.signal.ready==1&&d.signal.failed==1&&e.offer.closed(),"duplicate callback rejected, not a new arrival");
                refuses(()->e.offer.registerModelReply());check(!Files.exists(journal(e)),"no durable successful model registration");
                refuses(()->e.nativeEnv.session.offerCalendarDate(e.offer.source,e.adapter,e.nativeEnv.clock,START+30000));
            }});
        one("same_goal_values_other_actual_session_cannot_borrow_private_proof",()->{
            try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                Delivery d=deliver(e,START+5000);NativeCalendarDateSessionHostTest.Env other=new NativeCalendarDateSessionHostTest.Env();
                check(other.goal!=e.nativeEnv.goal&&other.goal.contractSha256.equals(e.nativeEnv.goal.contractSha256),"equal goal value, different real Session owner");
                NativeAppSession.CalendarOffer offer=otherOffer(e,other);Delivery wrong=new Delivery(offer);wrong.actual.onAcceptedRequest(d.proof);
                check(wrong.signal.ready==1,"callback only records pending provenance, it does not assert authority");
                refuses(()->offer.registerModelReply());check(offer.closed(),"wrong original frame/grammar/Session closes registration");
                e.offer.registerModelReply().requireForFreshObservation();
            }});
        one("non_adapter_offer_never_gets_private_producer_callback",()->{
            NativeCalendarDateSessionHostTest.Env e=new NativeCalendarDateSessionHostTest.Env();NativeAppSession.CalendarOffer offer=e.offer();offer.grammar();
            refuses(()->offer.modelCallback(new Signal()));check(e.model.calls==0,"no hidden model or permissive fake producer");
        });
        one("legacy_raw_success_signal_cannot_register_model_provenance",()->{
            try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                Delivery d=new Delivery(e.offer);d.actual.onSuccess(new String(e.raw,StandardCharsets.UTF_8),NativeCalendarDateSessionHostTest.id());
                check(d.signal.ready==0&&d.signal.failed==1&&e.offer.closed(),"opaque actual producer is mandatory");
                refuses(()->e.offer.registerModelReply());check(!Files.exists(journal(e)),"raw/file-only claims grant nothing");
            }});
        one("actual_callback_at_original_task_deadline_closes_even_with_proof",()->{
            try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                Delivery d=deliver(e,START+30000);check(d.proof!=null&&d.signal.ready==0&&d.signal.failed==1&&e.offer.closed(),"late Session callback refused");
                refuses(()->e.offer.registerModelReply());check(!Files.exists(journal(e)),"expired callback cannot write accepted registration");
            }});
        one("registration_rejects_original_action_expiry_and_backwards_clock",()->{
            for(long time:new long[]{START+13000,START+4999}){
                try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                    deliver(e,START+5000);e.nativeEnv.clock.now=time;refuses(()->e.offer.registerModelReply());
                    check(e.offer.closed()&&!Files.exists(journal(e)),"expiry or clock regression remains closed");
                    e.nativeEnv.clock.now=START+6000;refuses(()->e.offer.registerModelReply());
                }}
        });
        one("callback_budget_is_capped_by_original_task_and_not_renewed_for_fresh_observation",()->{
            try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                deliver(e,START+29500);e.nativeEnv.clock.now=START+29999;NativeAppSession.CalendarModelRequest r=e.offer.registerModelReply();
                check(number(r.evidence(),"original_action_deadline_elapsed_ms")==START+30000,"task cap overrides later arrival plus eight seconds");
                r.requireForFreshObservation();e.nativeEnv.clock.now=START+30000;refuses(()->r.requireForFreshObservation());
            }});
        one("changed_actual_app_receipt_refuses_before_and_after_registration",()->{
            for(boolean after:new boolean[]{false,true}){
                try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                    Delivery d=deliver(e,START+5000);NativeAppSession.CalendarModelRequest registered=after?e.offer.registerModelReply():null;
                    mutate(new File((File)field(d.round,"directory"),"app-receipt.json").toPath());
                    if(after)refuses(()->registered.requireForFreshObservation());else refuses(()->e.offer.registerModelReply());
                    check(after||e.offer.closed(),"private receipt change is not repaired or accepted");
                }}
        });
        one("actual_gate_retirement_and_reobserved_domain_invalidate_original_registration",()->{
            for(boolean retired:new boolean[]{true,false}){
                try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                    deliver(e,START+5000);
                    if(retired)e.nativeEnv.gate.retire();else e.nativeEnv.session.observed(e.nativeEnv.frame(
                        NativeCalendarDateSessionHostTest.calendarNodes(),START+5010,NativeCalendarDateSessionHostTest.id()));
                    refuses(()->e.offer.registerModelReply());check(e.offer.closed(),"current original Session/domain required");
                }}
        });
        one("create_only_journal_failure_consumes_run_slot_and_cannot_retry_after_file_removed",()->{
            try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                Delivery d=deliver(e,START+5000);NativeCalendarDateSessionHostTest.privateWrite(journal(e),"{}".getBytes(StandardCharsets.UTF_8));
                refuses(()->e.offer.registerModelReply());check(e.offer.closed(),"journal collision closes original Offer");
                check(((Set<?>)field(e.nativeEnv.session,"usedRuns")).contains(d.proof.requestId())&&((Number)field(e.nativeEnv.session,"ordinal")).intValue()==2,
                    "actual common run slot and native budget remain consumed on persistence failure");
                Files.delete(journal(e));refuses(()->e.offer.registerModelReply());
                refuses(()->e.nativeEnv.session.offerCalendarDate(e.offer.source,e.adapter,e.nativeEnv.clock,START+30000));
                check(!Files.exists(journal(e)),"failure is not relabelled as durable accepted registration");
            }});
        one("actual_next_round_and_cancellation_invalidate_registered_provenance",()->{
            for(boolean cancel:new boolean[]{false,true}){
                try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                    deliver(e,START+5000);NativeAppSession.CalendarModelRequest registered=e.offer.registerModelReply();
                    if(cancel)e.adapter.cancelTask();else{
                        Object next=e.request();refuses(()->registered.requireForFreshObservation());
                        NativeCalendarDateModelHostTest.call(e.adapter,"finishRequest",next,new IOException("explicit host launch not executed"));
                    }
                    refuses(()->registered.requireForFreshObservation());refuses(()->e.offer.registerModelReply());
                }}
        });
        one("actual_private_proof_does_not_replace_strict_fixed_date_intent_parser",()->{
            try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                e.raw=new String(e.raw,StandardCharsets.UTF_8).replace("2026-11-25","2026-11-24").getBytes(StandardCharsets.UTF_8);
                Delivery d=deliver(e,START+5000);check(d.proof!=null&&d.signal.ready==1,"host native sidecars verified; semantic claim still untrusted");
                refuses(()->e.offer.registerModelReply());check(e.offer.closed()&&!Files.exists(journal(e)),"wrong date cannot become registration");
                check(((Set<?>)field(e.nativeEnv.session,"usedRuns")).contains(d.proof.requestId()),"invalid semantic response consumes the original model slot");
            }});
        one("final_currentness_rejection_after_success_file_never_reaches_registry",()->{
            try(NativeCalendarDateModelHostTest.Environment e=new NativeCalendarDateModelHostTest.Environment()){
                Delivery d=issue(e);e.guard.refuseAfterDelivery=true;e.nativeEnv.clock.now=START+5000;NativeCalendarDateModelHostTest.finish(e,d.round);
                Map<String,Object> file=object(new File((File)field(d.round,"directory"),"app-delivery.json").toPath());
                check(Boolean.TRUE.equals(file.get("success_admitted"))&&d.proof==null&&d.signal.ready==0&&d.signal.failed==1,"actual final guard overrides prior file");
                refuses(()->e.offer.registerModelReply());check(!Files.exists(journal(e)),"file success is not model registry authority");
            }});
        boolean all=true;for(Map<String,Object> c:cases)all&=Boolean.TRUE.equals(c.get("passed"));
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("schema","hepta.calendar-private-model-registry-host.v1");
        report.put("all_pass",all);report.put("cases",cases.size());report.put("assertions",total());report.put("results",cases);
        report.put("setup_assertions",2);report.put("actual_adapter_private_producer_and_session_registry",true);
        report.put("private_proof_or_offer_constructor_invoked_by_fixture",false);report.put("native_process_android_clock_and_generation_cleanup_synthetic",true);
        report.put("fresh_observation_or_calendar_permit_executed",false);report.put("phone_actions",0);report.put("model_executions",0);
        report.put("android_effect_or_date_success_verified",false);
        Files.write(out.resolve("CASES.json"),(new JSONObject(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        LocalModelEngine.fixtureShutdownCancellation();System.out.println(new JSONObject(report).toString());
        if(!all)throw new AssertionError("calendar private model registry host gate failed");
    }
}
