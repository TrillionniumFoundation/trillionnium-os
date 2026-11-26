package org.trillionnium.hepta.local;
import android.content.Context;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.json.JSONObject;

/** Actual Adapter/finishRequest/private AcceptedRequest and actual Session grammar.
 * Android UID/context, returned native process, kernel generation cleanup and
 * complete native sidecars are explicit host fixtures. No model or input runs.
 * Reflection is confined to that platform boundary and negative corruption;
 * no AcceptedRequest/Offer constructor or accepted/contract flags are fabricated. */
public final class NativeCalendarDateModelHostTest {
    static final String TASK=NativeCalendarDateSessionHostTest.TASK;
    static Path root,out;static byte[] template,lfmTemplate;static int checks;
    static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    interface Work{void run()throws Exception;}
    static void check(boolean v,String why){checks++;if(!v)throw new AssertionError(why);}
    static void refuses(Work work)throws Exception{boolean failed=false;try{work.run();}
        catch(IllegalArgumentException|IllegalStateException|IOException expected){failed=true;}check(failed,"required refusal missing");}
    static void one(String name,Work body){Map<String,Object> r=new LinkedHashMap<String,Object>();r.put("name",name);int before=checks;
        try{body.run();r.put("passed",true);}catch(Throwable error){r.put("passed",false);r.put("error",error.toString());
            StringWriter s=new StringWriter();error.printStackTrace(new PrintWriter(s));r.put("stack",s.toString());}
        r.put("assertions",checks-before);cases.add(r);}
    static Object field(Object target,String name)throws Exception{
        Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);
    }
    static void field(Object target,String name,Object value)throws Exception{
        Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);f.set(target,value);
    }
    static Object call(Object target,String name,Object... args)throws Exception{
        Class<?> type=target instanceof Class<?>?(Class<?>)target:target.getClass();
        for(Method method:type.getDeclaredMethods())if(method.getName().equals(name)&&method.getParameterTypes().length==args.length){
            method.setAccessible(true);
            try{return method.invoke(target instanceof Class<?>?null:target,args);}
            catch(InvocationTargetException wrapper){
                Throwable cause=wrapper.getCause();if(cause instanceof Exception)throw (Exception)cause;
                if(cause instanceof Error)throw (Error)cause;throw new AssertionError(cause);
            }
        }
        throw new NoSuchMethodException(name);
    }
    static final class ManualExecutor extends AbstractExecutorService {
        private final Queue<Runnable> queue=new ArrayDeque<>();
        boolean shutdown,reject;int attempts;
        @Override public synchronized void execute(Runnable value){
            attempts++;
            if(shutdown||reject)throw new java.util.concurrent.RejectedExecutionException("host queue refusal");
            queue.add(value);notifyAll();
        }
        synchronized Runnable take()throws Exception{
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
            while(queue.isEmpty()&&System.nanoTime()<deadline)wait(10);
            if(queue.isEmpty())throw new AssertionError("expected one queued engine work item");return queue.remove();
        }
        synchronized int size(){return queue.size();}
        @Override public synchronized void shutdown(){shutdown=true;}
        @Override public synchronized List<Runnable> shutdownNow(){
            shutdown=true;List<Runnable> out=new ArrayList<>(queue);queue.clear();return out;
        }
        @Override public synchronized boolean isShutdown(){return shutdown;}
        @Override public synchronized boolean isTerminated(){return shutdown&&queue.isEmpty();}
        @Override public boolean awaitTermination(long timeout,TimeUnit unit){return isTerminated();}
    }
    static class FakeProcess extends Process {
        volatile boolean alive;final int code;int destroys,forces;
        CountDownLatch destroyEntered,destroyRelease;
        FakeProcess(boolean alive,int code){this.alive=alive;this.code=code;}
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public InputStream getInputStream(){return new ByteArrayInputStream(new byte[0]);}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public int waitFor(){alive=false;return code;}
        @Override public boolean waitFor(long timeout,TimeUnit unit){return !alive;}
        public int exitValue(){if(alive)throw new IllegalThreadStateException();return code;}
        public void destroy(){
            destroys++;if(destroyEntered!=null)destroyEntered.countDown();
            if(destroyRelease!=null)try{destroyRelease.await(5,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}
            alive=false;
        }
        @Override public Process destroyForcibly(){forces++;alive=false;return this;}
        @Override public boolean isAlive(){return alive;}
    }

    static final class Callback implements VlmInferenceAdapter.AcceptedRequestCallback {
        final LocalModelEngine engine;VlmInferenceAdapter.AcceptedRequest proof;int accepted,legacy,failure;String error;boolean known,throwOnProof;
        Callback(LocalModelEngine engine){this.engine=engine;}
        public void onSuccess(String raw,String id){legacy++;throw new AssertionError("typed callback must not receive unbound raw");}
        public void onAcceptedRequest(VlmInferenceAdapter.AcceptedRequest value){
            check(engine.isBusy(),"actual task model reservation held at proof callback");proof=value;accepted++;
            if(throwOnProof)throw new IllegalStateException("explicit callback rejection");
        }
        public void onFailure(String message,boolean cleanup){failure++;error=message;known=cleanup;}
    }
    static final class Guard implements LocalInference.Currentness {
        boolean current=true,refuseAfterDelivery,refuseAfterFinished,expireAtProof;int calls;Object round;
        public void requireCurrent()throws Exception{
            calls++;if(!current)throw new IllegalStateException("explicit source lifetime retired");
            if(round!=null){
                File directory=(File)field(round,"directory");
                if(refuseAfterDelivery&&new File(directory,"app-delivery.json").exists())throw new IllegalStateException("last source check retired");
                if(Boolean.TRUE.equals(field(round,"finished"))){
                    if(refuseAfterFinished)throw new IllegalStateException("proof publication source retired");
                    if(expireAtProof){field(round,"deadline",System.nanoTime()-1L);expireAtProof=false;}
                }
            }
        }
    }
    static final class Environment implements AutoCloseable {
        final NativeCalendarDateSessionHostTest.Env nativeEnv;
        final File files;final Context context;final ManualExecutor executor=new ManualExecutor();
        final LocalModelEngine engine;final VlmInferenceAdapter adapter;final Guard guard=new Guard();
        final NativeAppSession.CalendarOffer offer;final LocalInference.CurrentFrame frame;final DecisionGrammar grammar;
        byte[] raw;Object lastRound;Callback lastCallback;
        Environment()throws Exception{
            LocalModelEngine.fixtureReset();OwnedGenerationScope.reset();android.system.Os.failFsyncPath=null;
            nativeEnv=new NativeCalendarDateSessionHostTest.Env();files=nativeEnv.directory.toFile();context=new Context(files);
            engine=new LocalModelEngine(context,NativeCalendarDateSessionHostTest.gui(),executor);adapter=new VlmInferenceAdapter(context,engine);
            NativeAppEvidence.Frame f=nativeEnv.calendarFrame;
            frame=new LocalInference.CurrentFrame(nativeEnv.image.toFile(),TASK,nativeEnv.goal.ownerSha256,f.observationId,f.generation,
                f.packageName,f.screenshotSha,f.width,f.height,f.displayId,f.windowId,f.rotation,f.capturedElapsedMs,
                nativeEnv.owner.getBytes(StandardCharsets.UTF_8),guard);
            NativeCalendarDateEnvelope source=NativeCalendarDateEnvelope.capture(nativeEnv.goal,f,frame,nativeEnv.profile,adapter.configuration(),nativeEnv.clock);
            offer=nativeEnv.session.offerCalendarDate(source,adapter,nativeEnv.clock,NativeCalendarDateSessionHostTest.START+30000);grammar=offer.grammar();
            raw=("\n"+NativeCalendarDateSessionHostTest.raw(source)+" \n").getBytes(StandardCharsets.UTF_8);
            adapter.beginTask(TASK);
        }
        Object request()throws Exception{return request(new Callback(engine));}
        Object request(Callback cb)throws Exception{
            adapter.generateObserved("只返回固定日历选择协议","在原图的目标月份区域定位目标日期；不证明效果",frame,grammar,256,120000,cb);
            executor.take(); // Only native launch is not executed. The real finisher is executed below.
            Object round=field(field(adapter,"task"),"current");guard.round=round;lastRound=round;lastCallback=cb;return round;
        }
        VlmInferenceAdapter.AcceptedRequest finishGood()throws Exception{
            Object round=request();prepareReturned(this,round);call(adapter,"finishRequest",round,null);
            check(lastCallback.accepted==1&&lastCallback.failure==0&&lastCallback.legacy==0,"actual private proof missing: "+lastCallback.error);
            return lastCallback.proof;
        }
        LocalInference.TaskCleanup end()throws Exception{
            if(field(adapter,"task")==null)return adapter.endTask(TASK);
            AtomicReference<LocalInference.TaskCleanup> result=new AtomicReference<LocalInference.TaskCleanup>();
            AtomicReference<Throwable> error=new AtomicReference<Throwable>();
            Thread thread=new Thread(()->{try{result.set(adapter.endTask(TASK));}catch(Throwable failure){error.set(failure);}},"calendar-host-task-finisher");
            thread.start();executor.take().run();thread.join(5000);
            check(!thread.isAlive()&&error.get()==null,"actual aggregate finisher failed: "+error.get());return result.get();
        }
        public void close(){
            try{if(field(adapter,"task")!=null)end();engine.fixtureAwaitCancel();}
            catch(Exception failure){throw new AssertionError(failure);}
            finally{executor.shutdownNow();engine.close();LocalModelEngine.fixtureReset();OwnedGenerationScope.reset();android.system.Os.failFsyncPath=null;}
        }
    }
    static final Map<Object,byte[]> environmentRaw=new IdentityHashMap<Object,byte[]>();
    @SuppressWarnings("unchecked")
    static Map<String,byte[]> inputs(Object round)throws Exception{return (Map<String,byte[]>)field(round,"originalInputs");}
    @SuppressWarnings("unchecked")
    static Map<String,Object> map(Object value){return (Map<String,Object>)value;}
    static FakeProcess prepareReturned(Environment e,Object round)throws Exception{
        call(e.adapter,"prepareInputs",round);
        Object parent=call(Class.forName("org.trillionnium.hepta.local.VlmInferenceAdapter$Parent"),"read");
        field(round,"parent",parent);
        String generation=(String)field(round,"generation"),token=(String)field(round,"token");
        OwnedGenerationScope scope=new OwnedGenerationScope(e.files,new File(e.files,"host-no-native-worker"),generation,TASK,token);
        field(round,"scope",scope);
        FakeProcess process=new FakeProcess(false,0);field(round,"process",process);
        OwnedWorkerCancellation cancellation=(OwnedWorkerCancellation)field(round,"cancellation");
        cancellation.attach(process,generation,TASK);
        Object owner=field(round,"owner");LocalModelEngine.TaskExternalLease lease=(LocalModelEngine.TaskExternalLease)field(owner,"lease");
        lease.attach(process,cancellation);
        field(round,"exitObserved",true);field(round,"exitCode",0);
        environmentRaw.put(round,e.raw);nativeOutputs(round,scope);return process;
    }
    static void nativeOutputs(Object round,OwnedGenerationScope scope)throws Exception{
        File dir=(File)field(round,"directory");Map<String,byte[]> in=inputs(round),side=new LinkedHashMap<>();
        Map<String,Object> q=VlmResultContract.jsonObject(in.get("request.json"));
        Map<String,Object> owner=VlmResultContract.jsonObject(in.get("owner.json"));
        byte[] identity=MobiMindPrivateFiles.read(new File((File)field(round,"generationDirectory"),"worker-generation.identity"),2047,true).bytes;
        VlmResultContract.Profile p=VlmResultContract.named((String)q.get("profile"));
        byte[] actualTemplate=p==VlmResultContract.LFM3_VL_2B?lfmTemplate:template;
        if(p==VlmResultContract.LFM3_VL_2B)check(actualTemplate!=null&&sha(actualTemplate).equals(p.templateSha256),"actual pinned LFM3-VL template fixture");
        side.put("raw.txt",environmentRaw.get(round));side.put("gguf-chat-template.jinja",actualTemplate);
        String system=new String(in.get("system.txt"),StandardCharsets.UTF_8);
        String formatted="<|im_start|>system\n"+system
                +"<|im_end|>\n<|im_start|>user\n<__media__>"+new String(in.get("prompt.txt"),StandardCharsets.UTF_8)
                +"<|im_end|>\n<|im_start|>assistant\n";
        if(p==VlmResultContract.LFM3_VL_2B)formatted="<|startoftext|>"+(system.isEmpty()?"":"<|im_start|>system\n"+system+"<|im_end|>\n")
                +"<|im_start|>user\n<__media__>"+new String(in.get("prompt.txt"),StandardCharsets.UTF_8)
                +"<|im_end|>\n<|im_start|>assistant\n<think></think>";
        side.put("formatted-prompt.txt",b(formatted));
        Map<String,Object> text=new LinkedHashMap<>(),image=new LinkedHashMap<>();
        text.put("index",0);text.put("type",0);text.put("tokens",127);text.put("positions",127);
        text.put("token_ids_sha256_le32",sha(b("synthetic-host-token-ids")));
        image.put("index",1);image.put("type",1);image.put("tokens",80);image.put("positions",9);
        image.put("image_sha256",sha(in.get("screen.png")));side.put("chunks.json",json(Arrays.asList(text,image)));
        Map<String,Object> r=new LinkedHashMap<>();
        r.put("schema","hepta.vlm.result.v1");r.put("request_id",q.get("request_id"));r.put("task_id",TASK);
        r.put("generation",q.get("generation"));r.put("scope_token",owner.get("scope_token"));r.put("profile",p.id);
        r.put("request_sha256",sha(in.get("request.json")));r.put("generation_identity_sha256",sha(identity));
        for(String name:new String[]{"owner","prompt","system","image","grammar"})r.put(name+"_sha256",q.get(name+"_sha256"));
        r.put("app_uid",scope.expected.uid);r.put("app_pid",scope.expected.appPid);r.put("worker_pid",scope.workerPid);
        r.put("expected_app_uid",scope.expected.uid);r.put("expected_parent_pid",scope.expected.appPid);
        r.put("app_start_ticks",scope.expected.appStart);r.put("boot_id",scope.expected.boot);r.put("parent_death_signal",9);
        r.put("observed_parent_pid_before",scope.expected.appPid);r.put("observed_parent_pid_after",scope.expected.appPid);
        r.put("model_filename",p.modelFilename);r.put("model_bytes",p.modelBytes);r.put("model_sha256",p.modelSha256);
        r.put("projector_filename",p.projectorFilename);r.put("projector_bytes",p.projectorBytes);r.put("projector_sha256",p.projectorSha256);
        LocalInference.CurrentFrame actualFrame=(LocalInference.CurrentFrame)field(round,"frame");r.put("image_width",actualFrame.width);r.put("image_height",actualFrame.height);r.put("current_frame",owner);
        r.put("context_tokens",8192);r.put("max_output_tokens",q.get("max_tokens"));r.put("image_max_tokens",1024);
        r.put("started_monotonic_ns",field(round,"submitted"));r.put("deadline_monotonic_ns",q.get("deadline_monotonic_ns"));
        r.put("sampler","current-frame-gbnf-then-greedy");r.put("grammar_root","root");
        for(String key:("parent_verified_before private_scope_verified_before model_files_full_sha_verified runtime_files_full_sha_verified "
                +"same_chunks_counted_and_evaluated mtmd_internal_image_preprocessing generation_completed full_multimodal_admission_passed "
                +"eog_observed parent_verified_after scope_unchanged_after").split(" "))r.put(key,true);
        for(String key:("template_enable_thinking native_tools_argument automatic_device_fallback zero_cpu_operations_proven context_shift_used "
                +"input_image_transformed_by_worker actions_dispatched action_authorized business_completion_verified process_exit_observed cleanup_known").split(" "))r.put(key,false);
        r.put("lm_device","HTP0");r.put("vision_device","GPUOpenCL");
        r.put("lm_device_description","host fixture only");r.put("vision_device_description","host fixture only");
        r.put("vision_max_allocation_bytes",1073741824L);r.put("architecture",p.architecture);
        r.put("tokenizer_pre",p.tokenizerPre);r.put("tokenizer_model",p.tokenizerModel);
        r.put("chat_template_sha256",p.templateSha256);r.put("chat_template_bytes",actualTemplate.length);
        r.put("template_now_unix_ms",System.currentTimeMillis());
        r.put("formatted_prompt_sha256",sha(side.get("formatted-prompt.txt")));r.put("chunks_sha256",sha(side.get("chunks.json")));
        r.put("prompt_tokens",207);r.put("prompt_positions",136);r.put("image_tokens",80);
        r.put("output_reserved_tokens",q.get("max_tokens"));r.put("prefill_return_code",0);r.put("prefill_positions",136);
        r.put("generated_tokens_including_eog",3);r.put("final_position",138);
        r.put("native_return_code",0);r.put("error","none");r.put("cancel_signal",0);
        r.put("ended_monotonic_ns",System.nanoTime());r.put("raw_sha256",sha(side.get("raw.txt")));r.put("raw_bytes",side.get("raw.txt").length);
        check(r.keySet().equals(VlmResultContract.requiredReceiptFields()),"synthetic receipt must match exact contract field set");
        for(Map.Entry<String,byte[]> entry:side.entrySet())MobiMindPrivateFiles.writeNew(new File(dir,entry.getKey()),entry.getValue());
        MobiMindPrivateFiles.writeNew(new File(dir,"native-result.json"),json(r));
    }
    static void finish(Environment e,Object round)throws Exception{call(e.adapter,"finishRequest",round,null);}
    static byte[] b(String text){return text.getBytes(StandardCharsets.UTF_8);}
    static String sha(byte[] bytes){return MobiMindContract.sha(bytes);}
    static byte[] json(Object object){return b(VlmResultContract.canonicalJson(object));}
    static byte[] png(int pixel)throws Exception{
        java.awt.image.BufferedImage image=new java.awt.image.BufferedImage(1,1,java.awt.image.BufferedImage.TYPE_INT_ARGB);
        image.setRGB(0,0,pixel);ByteArrayOutputStream out=new ByteArrayOutputStream();
        if(!javax.imageio.ImageIO.write(image,"png",out))throw new AssertionError("host PNG fixture encoder missing");
        return out.toByteArray();
    }

    public static void main(String[] args)throws Exception{
        out=Paths.get(args[0]);root=Paths.get(args[1]);Files.createDirectory(root);template=Files.readAllBytes(Paths.get(args[2]));
        check(MobiMindContract.sha(template).equals(VlmResultContract.GUI_OWL_4B.templateSha256),"actual pinned GUI template");
        NativeCalendarDateSessionHostTest.work=root;
        java.awt.image.BufferedImage image=new java.awt.image.BufferedImage(1224,2992,java.awt.image.BufferedImage.TYPE_INT_RGB);
        for(int y=0;y<image.getHeight();y++)for(int x=0;x<image.getWidth();x++){int c=(x*31+y*17)&255;image.setRGB(x,y,(c<<16)|(((c+41)&255)<<8)|((c+79)&255));}
        ByteArrayOutputStream encoded=new ByteArrayOutputStream();check(javax.imageio.ImageIO.write(image,"png",encoded),"actual PNG");NativeCalendarDateSessionHostTest.png=encoded.toByteArray();
        one("actual_finish_private_proof_preserves_whitespace_utf8_and_holds_task",()->{try(Environment e=new Environment()){
            VlmInferenceAdapter.AcceptedRequest p=e.finishGood();p.requireBound(e.adapter,e.frame,e.grammar);
            check(Arrays.equals(e.raw,p.rawText().getBytes(StandardCharsets.UTF_8)),"raw text must retain all bytes, not trim");
            check(MobiMindContract.sha(e.raw).equals(p.evidence().get("raw_sha256")),"actual native raw hash bound");
            check(Boolean.FALSE.equals(p.evidence().get("grants_android_dispatch"))&&Boolean.FALSE.equals(p.evidence().get("date_or_business_verified")),"model provenance is no effect proof");
            int declared=0;for(Constructor<?> c:p.getClass().getDeclaredConstructors())if(!c.isSynthetic()){declared++;check(Modifier.isPrivate(c.getModifiers()),"private source producer constructor only");}check(declared==1,"one source constructor; Java 8 synthetic access bridge is not a source factory");
            check(e.engine.isBusy()&&Boolean.TRUE.equals(field(e.lastRound,"retired")),"actual request retired without releasing task");
            LocalInference.TaskCleanup terminal=e.end();check(terminal.cleanupKnown&&terminal.receiptValid&&terminal.processExitObserved,"actual aggregate host contract");}});
        one("last_current_frame_refusal_overrides_success_admitted_file",()->{try(Environment e=new Environment()){
            Object r=e.request();prepareReturned(e,r);e.guard.refuseAfterDelivery=true;call(e.adapter,"finishRequest",r,null);
            Map<String,Object> d=VlmResultContract.jsonObject(Files.readAllBytes(new File((File)field(r,"directory"),"app-delivery.json").toPath()));
            check(Boolean.TRUE.equals(d.get("success_admitted"))&&e.lastCallback.accepted==0&&e.lastCallback.failure==1,"success file alone cannot produce proof");
            check(field(r,"acceptedCalendarRequest")==null&&new File((File)field(r,"directory"),"app-delivery-rejection.json").isFile(),"last refusal retained");}});
        one("post_retirement_proof_currentness_refusal_is_not_a_raw_callback",()->{try(Environment e=new Environment()){
            Object r=e.request();prepareReturned(e,r);e.guard.refuseAfterFinished=true;call(e.adapter,"finishRequest",r,null);
            check(e.lastCallback.accepted==0&&e.lastCallback.legacy==0&&e.lastCallback.failure==1&&field(r,"acceptedCalendarRequest")==null,"late private proof source guard");}});
        one("cancelled_returned_native_process_never_produces_proof",()->{try(Environment e=new Environment()){
            Object r=e.request();prepareReturned(e,r);e.adapter.cancelTask();call(e.adapter,"finishRequest",r,null);
            check(e.lastCallback.accepted==0&&e.lastCallback.failure==1&&e.lastCallback.known,"real task cancellation vs cleanup");}});
        one("cancellation_after_delivery_invalidates_same_private_proof",()->{try(Environment e=new Environment()){
            VlmInferenceAdapter.AcceptedRequest p=e.finishGood();e.adapter.cancelTask();refuses(()->p.requireBound(e.adapter,e.frame,e.grammar));}});
        one("same_values_cannot_substitute_engine_frame_or_grammar",()->{try(Environment e=new Environment()){
            VlmInferenceAdapter.AcceptedRequest p=e.finishGood();VlmInferenceAdapter other=new VlmInferenceAdapter(e.context,e.engine);
            refuses(()->p.requireBound(other,e.frame,e.grammar));
            LocalInference.CurrentFrame f=new LocalInference.CurrentFrame(e.frame.image,TASK,e.frame.ownerSha256,e.frame.observationId,e.frame.backgroundGeneration,
                e.frame.packageName,e.frame.imageSha256,e.frame.width,e.frame.height,e.frame.displayId,e.frame.windowId,e.frame.rotation,e.frame.capturedElapsedMillis,
                e.frame.taskOwnerEvidence(),e.guard);refuses(()->p.requireBound(e.adapter,f,e.grammar));
            NativeCalendarDateSessionHostTest.Env otherNative=new NativeCalendarDateSessionHostTest.Env();DecisionGrammar g=otherNative.offer().grammar();
            refuses(()->p.requireBound(e.adapter,e.frame,g));}});
        one("private_producer_does_not_mint_duplicate_proof",()->{try(Environment e=new Environment()){
            e.finishGood();refuses(()->call(e.adapter,"produceAcceptedCalendarRequest",e.lastRound));check(e.lastCallback.accepted==1,"single delivered proof");}});
        one("new_actual_request_retires_prior_proof_even_same_frame_values",()->{try(Environment e=new Environment()){
            VlmInferenceAdapter.AcceptedRequest p=e.finishGood();Object next=e.request();refuses(()->p.requireBound(e.adapter,e.frame,e.grammar));
            call(e.adapter,"finishRequest",next,new IOException("explicit host native launch not executed"));check(e.lastCallback.accepted==0,"no fabricated second native response");}});
        one("changed_app_receipt_refuses_original_proof",()->{try(Environment e=new Environment()){
            VlmInferenceAdapter.AcceptedRequest p=e.finishGood();Files.write(new File((File)field(e.lastRound,"directory"),"app-receipt.json").toPath(),b("{}"));
            refuses(()->p.requireBound(e.adapter,e.frame,e.grammar));}});
        one("changed_delivery_receipt_refuses_original_proof",()->{try(Environment e=new Environment()){
            VlmInferenceAdapter.AcceptedRequest p=e.finishGood();Files.write(new File((File)field(e.lastRound,"directory"),"app-delivery.json").toPath(),b("{}"));
            refuses(()->p.requireBound(e.adapter,e.frame,e.grammar));}});
        one("changed_raw_bytes_refuse_original_proof",()->{try(Environment e=new Environment()){
            VlmInferenceAdapter.AcceptedRequest p=e.finishGood();Files.write(new File((File)field(e.lastRound,"directory"),"raw.txt").toPath(),b("changed"));
            refuses(()->p.requireBound(e.adapter,e.frame,e.grammar));}});
        one("proof_publication_cannot_outlive_original_model_deadline",()->{try(Environment e=new Environment()){
            Object r=e.request();prepareReturned(e,r);e.guard.expireAtProof=true;call(e.adapter,"finishRequest",r,null);
            check(e.lastCallback.accepted==0&&e.lastCallback.failure==1&&field(r,"acceptedCalendarRequest")==null,"late proof refused without refreshed deadline");}});
        one("native_raw_mismatch_is_rejected_by_actual_contract",()->{try(Environment e=new Environment()){
            Object r=e.request();prepareReturned(e,r);Files.write(new File((File)field(r,"directory"),"raw.txt").toPath(),b("changed"));call(e.adapter,"finishRequest",r,null);
            check(e.lastCallback.accepted==0&&e.lastCallback.failure==1&&field(r,"acceptedCalendarRequest")==null,"native verification cannot be bypassed");}});
        one("callback_failure_invalidates_already_delivered_private_reference",()->{try(Environment e=new Environment()){
            Callback cb=new Callback(e.engine);cb.throwOnProof=true;Object r=e.request(cb);prepareReturned(e,r);call(e.adapter,"finishRequest",r,null);
            check(cb.accepted==1&&cb.proof!=null&&!Boolean.TRUE.equals(field(r,"accepted")),"callback exception retained as failed request");
            refuses(()->cb.proof.requireBound(e.adapter,e.frame,e.grammar));}});
        boolean all=true;for(Map<String,Object> r:cases)all&=Boolean.TRUE.equals(r.get("passed"));
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("schema","hepta.calendar-model-private-producer-host.v1");
        report.put("all_pass",all);report.put("cases",cases.size());report.put("assertions",checks);report.put("results",cases);
        report.put("actual_adapter_source_and_finish_request",true);report.put("actual_session_offer_grammar",true);
        report.put("native_process_sidecars_android_and_generation_cleanup_synthetic",true);report.put("private_proof_constructor_invoked_by_fixture",false);
        report.put("phone_actions",0);report.put("model_executions",0);report.put("android_effect_or_calendar_success_verified",false);
        Files.write(out.resolve("CASES.json"),(new JSONObject(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        LocalModelEngine.fixtureShutdownCancellation();System.out.println(new JSONObject(report).toString());
        if(!all)throw new AssertionError("calendar Adapter host contract failed");
    }
}
