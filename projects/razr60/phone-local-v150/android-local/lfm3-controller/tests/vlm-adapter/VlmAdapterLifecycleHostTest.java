package org.trillionnium.hepta.local;

import android.content.Context;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONObject;

/** Platform fixtures are deliberate; source/receipt/lease/cancellation logic is real. */
public final class VlmAdapterLifecycleHostTest {
    static final String TASK="11111111111111111111111111111111",G1="22222222222222222222222222222222";
    static final String G2="33333333333333333333333333333333",S1="44444444444444444444444444444444";
    static final String S2="55555555555555555555555555555555",OTHER="66666666666666666666666666666666";
    static final String OWNER="请在后台记录：明天带伞。",PACKAGE="com.example.notes";
    static byte[] template,PNG;
    static Path root;
    static int checks;
    static final List<Map<String,Object>> cases=new ArrayList<>();
    interface Work {void run()throws Exception;}
    static void check(boolean value,String reason){checks++;if(!value)throw new AssertionError(reason);}
    static void rejects(Work work)throws Exception{
        try{work.run();throw new AssertionError("expected refusal");}
        catch(IllegalArgumentException|IllegalStateException expected){checks++;}
    }
    static void test(String name,Work work)throws Exception{
        Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);int start=checks;
        try{work.run();row.put("pass",true);}
        catch(Exception|AssertionError failure){row.put("pass",false);row.put("error",failure.toString());throw failure;}
        finally{row.put("assertions",checks-start);cases.add(row);}
    }
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
    static final class Guard implements LocalInference.Currentness {
        final AtomicInteger checks=new AtomicInteger();volatile boolean current=true;
        volatile int failAt=Integer.MAX_VALUE;
        public void requireCurrent(){int n=checks.incrementAndGet();if(!current||n>=failAt)throw new IllegalStateException("host live ownership retired");}
    }
    static final class Callback implements LocalInference.Callback {
        final LocalModelEngine engine;volatile int success,failure;volatile boolean cleanup;
        volatile String raw,error,run;boolean throwOnSuccess;
        Callback(LocalModelEngine engine){this.engine=engine;}
        public void onSuccess(String text,String id){
            check(engine.isBusy(),"task slot must still be held during callback");
            raw=text;run=id;success++;if(throwOnSuccess)throw new IllegalStateException("host callback failure");
        }
        public void onFailure(String message,boolean known){
            check(engine.isBusy(),"failed callback cannot release task slot");error=message;cleanup=known;failure++;
        }
    }
    static final class Environment implements AutoCloseable {
        final File files;final Context context;final ManualExecutor executor=new ManualExecutor();
        final LocalModelEngine engine;final VlmInferenceAdapter adapter;final Guard guard=new Guard();
        Environment(String name)throws Exception{this(name,false);}
        Environment(String name,boolean observe)throws Exception{
            LocalModelEngine.fixtureReset();OwnedGenerationScope.reset();android.system.Os.failFsyncPath=null;
            files=root.resolve(name).toFile();Files.createDirectories(files.toPath());
            context=new Context(files);engine=new LocalModelEngine(context,
                    new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4,observe),executor);
            adapter=new VlmInferenceAdapter(context,engine);
        }
        LocalInference.CurrentFrame frame(int index,boolean current)throws Exception{return frame(index,current,PNG);}
        LocalInference.CurrentFrame frame(int index,boolean current,byte[] bytes)throws Exception{
            File image=new File(files,"screen-"+index+".png");MobiMindPrivateFiles.writeNew(image,bytes);
            String observation=String.format(java.util.Locale.ROOT,"%032x",index+10);
            return new LocalInference.CurrentFrame(image,TASK,MobiMindContract.sha(b(OWNER)),observation,
                    "background-7",PACKAGE,MobiMindContract.sha(bytes),1,1,7,91,0,1234567,b(OWNER),current?guard:null);
        }
        DecisionGrammar grammar(LocalInference.CurrentFrame frame){return new DecisionGrammar(TASK,OWNER,frame.observationId,PACKAGE);}
        Object request(int index,Callback callback)throws Exception{
            LocalInference.CurrentFrame frame=frame(index,true);
            adapter.generateObserved("完整原始提示 "+index,"原始系统指令",frame,grammar(frame),256,120000,callback);
            executor.take(); // Native launch is replaced by the explicit platform fixture below.
            return field(field(adapter,"task"),"current");
        }
        LocalInference.TaskCleanup end()throws Exception{
            AtomicReference<LocalInference.TaskCleanup> result=new AtomicReference<>();
            AtomicReference<Throwable> failed=new AtomicReference<>();
            Thread thread=new Thread(()->{try{result.set(adapter.endTask());}catch(Throwable e){failed.set(e);}},"host-task-finisher");
            thread.start();executor.take().run();thread.join(5000);
            check(!thread.isAlive()&&failed.get()==null,"aggregate finisher did not return");
            return result.get();
        }
        public void close(){
            try{engine.fixtureAwaitCancel();}catch(Exception failure){throw new AssertionError(failure);}
            executor.shutdownNow();engine.close();LocalModelEngine.fixtureReset();OwnedGenerationScope.reset();
            android.system.Os.failFsyncPath=null;
        }
    }
    static OwnedGenerationScope.Cleanup proof(String task,String generation,String token,boolean known)throws Exception{
        return new OwnedGenerationScope.Cleanup(known,true,false,new JSONObject().put("task_id",task)
                .put("worker_generation",generation).put("scope_token",token)
                .put("direct_process_exit_observed",true).put("cleanup_known",known));
    }
    static void leaseLifecycle()throws Exception{
        try(Environment e=new Environment("lease")){
            LocalModelEngine.TaskExternalLease lease=e.engine.reserveTaskExternal(TASK);
            check(e.engine.isBusy(),"reservation owns global slot");
            rejects(()->e.engine.reserveTaskExternal(OTHER));rejects(()->e.engine.reserveExternal(OTHER));
            OwnedWorkerCancellation c1=lease.prepareRequest(G1,S1);
            check(c1.snapshot().cooperativeGraceMillis==8000&&c1.finishFutureMillis()==22000,"visual child must use default 8+8/22 timing");
            rejects(()->lease.prepareRequest(G2,S2));rejects(()->lease.retireRequest(null,true,0,null,true));
            rejects(()->lease.retireRequest(null,false,null,null,false));
            lease.retireRequest(null,false,null,null,true);
            check(e.engine.isBusy()&&!lease.requestPending(),"unstarted child release must retain task");
            rejects(()->lease.prepareRequest(G1,S2));
            OwnedWorkerCancellation c2=lease.prepareRequest(G2,S2);FakeProcess child=new FakeProcess(true,0);
            lease.attach(child,c2);rejects(()->lease.attach(new FakeProcess(false,0),c2));
            rejects(()->lease.retireRequest(child,true,0,proof(TASK,G2,S2,true),true));
            child.alive=false;
            rejects(()->lease.retireRequest(child,false,0,proof(TASK,G2,S2,true),true));
            rejects(()->lease.retireRequest(child,true,1,proof(TASK,G2,S2,true),true));
            rejects(()->lease.retireRequest(child,true,0,proof(TASK,G2,S1,true),true));
            rejects(()->lease.retireRequest(child,true,0,proof(OTHER,G2,S2,true),true));
            rejects(()->lease.retireRequest(child,true,0,proof(TASK,G2,S2,false),true));
            rejects(()->lease.retireRequest(child,true,0,proof(TASK,G2,S2,true),false));
            lease.retireRequest(child,true,0,proof(TASK,G2,S2,true),true);
            check(e.engine.isBusy()&&lease.current(),"physical exit and child retirement cannot release task");
            lease.endRequests();rejects(()->lease.prepareRequest(OTHER,S1));
            rejects(()->lease.releaseAfterTerminalPublication(false));
            lease.releaseAfterTerminalPublication(true);check(!e.engine.isBusy(),"committed task terminal releases slot");
            LocalModelEngine.ExternalRunLease next=e.engine.reserveExternal(OTHER);next.releaseAfterTerminalPublication(true);
            check(!e.engine.isBusy(),"unchanged diagnostic path admitted after clean task");
        }
    }
    static void capturedStop()throws Exception{
        try(Environment e=new Environment("captured-stop")){
            LocalModelEngine.TaskExternalLease lease=e.engine.reserveTaskExternal(TASK);
            OwnedWorkerCancellation cancellation=lease.prepareRequest(G1,S1);
            FakeProcess child=new FakeProcess(true,143);child.destroyEntered=new CountDownLatch(1);child.destroyRelease=new CountDownLatch(1);
            lease.attach(child,cancellation);e.engine.cancelActive();
            check(child.destroyEntered.await(5,TimeUnit.SECONDS),"captured Stop did not reach exact child");
            check(lease.isCancellationRequested(),"Stop immediately blocks new work");
            rejects(()->lease.prepareRequest(G2,S2));e.engine.cancelActive();
            child.alive=false;check(child.waitFor(0,TimeUnit.MILLISECONDS),"fixture exact child exit observed");
            lease.retireRequest(child,true,143,proof(TASK,G1,S1,true),true);lease.endRequests();
            lease.releaseAfterTerminalPublication(true);
            check(e.engine.isBusy(),"pending captured signal must retain admission after native cleanup");
            rejects(()->e.engine.reserveExternal(OTHER));
            child.destroyRelease.countDown();e.engine.fixtureAwaitCancel();
            check(child.destroys==1&&child.forces==0&&!e.engine.isBusy(),"duplicate Stop resent signal or failed to drain");
        }
    }
    public static final class RealChild {public static void main(String[] args)throws Exception{System.out.println("READY");System.out.flush();Thread.sleep(30000);}}
    static void realHeldProcess()throws Exception{
        try(Environment e=new Environment("real-child")){
            LocalModelEngine.TaskExternalLease lease=e.engine.reserveTaskExternal(TASK);
            OwnedWorkerCancellation cancellation=lease.prepareRequest(G1,S1);
            String java=new File(System.getProperty("java.home"),"bin/java").getPath();
            Process child=new ProcessBuilder(java,"-cp",System.getProperty("java.class.path"),RealChild.class.getName()).start();
            try{
                check(new java.io.BufferedReader(new java.io.InputStreamReader(child.getInputStream(),StandardCharsets.UTF_8)).readLine().equals("READY"),"real child not ready");
                lease.attach(child,cancellation);lease.cancel();OwnedWorkerCancellation.Exit exit=cancellation.awaitCancellation();
                check(exit.observed&&exit.code!=null&&!child.isAlive(),"real held Process exit not observed");
                check(cancellation.snapshot().termAttempts==1&&cancellation.snapshot().forceAttempts==0,"real child signal authority differed");
                lease.retireRequest(child,true,exit.code,proof(TASK,G1,S1,true),true);
                check(e.engine.isBusy(),"real child exit released whole task");
                lease.endRequests();lease.releaseAfterTerminalPublication(true);check(!e.engine.isBusy(),"real child task did not release after terminal");
            }finally{if(child.isAlive()){child.destroyForcibly();child.waitFor(3,TimeUnit.SECONDS);}}
        }
    }
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
        nativeOutputs(round,scope);return process;
    }
    static void nativeOutputs(Object round,OwnedGenerationScope scope)throws Exception{
        File dir=(File)field(round,"directory");Map<String,byte[]> in=inputs(round),side=new LinkedHashMap<>();
        Map<String,Object> q=VlmResultContract.jsonObject(in.get("request.json"));
        Map<String,Object> owner=VlmResultContract.jsonObject(in.get("owner.json"));
        byte[] identity=MobiMindPrivateFiles.read(new File((File)field(round,"generationDirectory"),"worker-generation.identity"),2047,true).bytes;
        side.put("raw.txt",b("{}"));side.put("gguf-chat-template.jinja",template);
        side.put("formatted-prompt.txt",b("<|im_start|>system\n"+new String(in.get("system.txt"),StandardCharsets.UTF_8)
                +"<|im_end|>\n<|im_start|>user\n<__media__>"+new String(in.get("prompt.txt"),StandardCharsets.UTF_8)
                +"<|im_end|>\n<|im_start|>assistant\n"));
        Map<String,Object> text=new LinkedHashMap<>(),image=new LinkedHashMap<>();
        text.put("index",0);text.put("type",0);text.put("tokens",127);text.put("positions",127);
        text.put("token_ids_sha256_le32",sha(b("synthetic-host-token-ids")));
        image.put("index",1);image.put("type",1);image.put("tokens",80);image.put("positions",9);
        image.put("image_sha256",sha(in.get("screen.png")));side.put("chunks.json",json(Arrays.asList(text,image)));
        VlmResultContract.Profile p=VlmResultContract.GUI_OWL_4B;
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
        r.put("image_width",1);r.put("image_height",1);r.put("current_frame",owner);
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
        r.put("chat_template_sha256",p.templateSha256);r.put("chat_template_bytes",template.length);
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
    static void twoRounds()throws Exception{
        try(Environment e=new Environment("two-rounds")){
            e.adapter.beginTask(TASK);Object task=field(e.adapter,"task");String logical=(String)field(task,"generation");
            Callback first=new Callback(e.engine);Object a=e.request(1,first);prepareReturned(e,a);finish(e,a);
            check(first.success==1&&first.failure==0&&"{}".equals(first.raw),"first raw was not accepted unchanged: "+first.error);
            check(e.engine.isBusy(),"first completed generation released global slot");
            rejects(()->e.engine.reserveExternal(OTHER));
            Callback second=new Callback(e.engine);Object b=e.request(2,second);prepareReturned(e,b);finish(e,b);
            check(second.success==1&&second.failure==0&&"{}".equals(second.raw),"second raw was not accepted unchanged: "+second.error);
            check(!field(a,"generation").equals(field(b,"generation"))&&!field(a,"requestId").equals(field(b,"requestId"))
                    &&!field(a,"token").equals(field(b,"token")),"serial requests reused an identity");
            check(e.engine.isBusy()&&OwnedGenerationScope.cleanupCalls==2,"both generation cleanups must precede task release");
            LocalInference.TaskCleanup result=e.end();
            check(result.cleanupKnown&&result.processStarted&&result.processExitObserved&&result.receiptValid
                    &&Integer.valueOf(0).equals(result.exitCode)&&logical.equals(result.generation),"aggregate normal terminal failed");
            check(!e.engine.isBusy()&&e.adapter.endTask()==result,"terminal release or idempotence failed");
            Map<String,Object> aggregate=VlmResultContract.jsonObject(Files.readAllBytes(new File((File)field(task,"directory"),"vlm-task-terminal.json").toPath()));
            check("hepta.vlm.task-aggregate.v1".equals(aggregate.get("schema"))&&Boolean.TRUE.equals(aggregate.get("serial_generations"))
                    &&((List<?>)aggregate.get("requests")).size()==2,"aggregate used a fake warm-session schema");
            check(!new String(json(aggregate),StandardCharsets.UTF_8).contains("hepta.geniex-task-session"),"GenieX native close was fabricated");
        }
    }
    static void scopedTaskCleanup()throws Exception{
        try(Environment e=new Environment("task-scoped-cleanup")){
            LocalInference.TaskCleanup empty=e.adapter.endTask(OTHER);
            check(empty.cleanupKnown&&!empty.processStarted&&!empty.processExitObserved
                    &&OTHER.equals(empty.taskId)&&empty.generation==null&&empty.receiptSha256==null
                    &&empty.exitCode==null&&!e.engine.isBusy()&&e.executor.size()==0,
                    "pre-reservation failure borrowed a model session");
            e.adapter.beginTask(TASK);Object task=field(e.adapter,"task");
            rejects(()->e.adapter.endTask(OTHER));
            check(field(e.adapter,"task")==task&&e.engine.isBusy()&&e.executor.size()==0,
                    "foreign task cleanup touched the owned model reservation");
            Callback callback=new Callback(e.engine);Object round=e.request(1,callback);
            prepareReturned(e,round);finish(e,round);LocalInference.TaskCleanup previous=e.end();
            check(previous.receiptValid&&previous.processStarted&&TASK.equals(previous.taskId),
                    "prior completed task fixture missing actual bound aggregate");
            check(e.adapter.endTask(TASK)==previous,"same task repeated close lost its original receipt");
            int submissions=e.executor.attempts;
            LocalInference.TaskCleanup bootstrapFailure=e.adapter.endTask(OTHER);
            check(bootstrapFailure!=previous&&OTHER.equals(bootstrapFailure.taskId)
                    &&bootstrapFailure.cleanupKnown&&!bootstrapFailure.processStarted&&!bootstrapFailure.processExitObserved
                    &&bootstrapFailure.generation==null&&bootstrapFailure.exitCode==null&&bootstrapFailure.receiptSha256==null,
                    "new bootstrap failure inherited the prior task model session");
            check(e.adapter.endTask(TASK)==previous&&!e.engine.isBusy()&&submissions==e.executor.attempts,
                    "no-worker terminal mutated prior proof or submitted native cleanup work");
            e.adapter.beginTask(OTHER);LocalInference.TaskCleanup reserved=e.end();
            check(OTHER.equals(reserved.taskId)&&reserved.generation!=null&&!reserved.generation.equals(previous.generation)
                    &&reserved.cleanupKnown&&!reserved.processStarted&&!reserved.receiptValid&&!e.engine.isBusy(),
                    "new reserved no-process task did not retain its own aggregate");
            check(e.adapter.endTask(OTHER)==reserved,"new task repeated close returned a different receipt");
        }
    }
    static final class CleanupOnly implements LocalInference {
        final TaskCleanup proof;int calls;
        CleanupOnly(TaskCleanup proof){this.proof=proof;}
        public LocalRuntimeConfig configuration(){throw new AssertionError("cleanup must not read configuration");}
        public TaskCleanup endTask(){calls++;return proof;}
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int maximum,long timeout,LocalInference.Callback callback){
            throw new AssertionError("cleanup must not start inference");
        }
    }
    static void cleanupBindingBoundary()throws Exception{
        CleanupOnly empty=new CleanupOnly(LocalInference.TaskCleanup.noWorker());
        LocalInference.TaskCleanup none=empty.endTask(TASK);
        check(TASK.equals(none.taskId)&&none.cleanupKnown&&!none.processStarted&&empty.calls==1,
                "legacy empty sentinel did not acquire the captured task identity");
        rejects(()->empty.endTask(null));rejects(()->empty.endTask("not-a-task"));
        check(empty.calls==1,"invalid expected task reached adapter cleanup");
        CleanupOnly foreign=new CleanupOnly(new LocalInference.TaskCleanup(true,true,true,0,G1,OTHER,true,S1));
        rejects(()->foreign.endTask(TASK));
        CleanupOnly unbound=new CleanupOnly(new LocalInference.TaskCleanup(true,true,true,0,G1,null,true,S1));
        rejects(()->unbound.endTask(TASK));
        CleanupOnly unknown=new CleanupOnly(new LocalInference.TaskCleanup(false,false,false,null,null,null,false,null));
        rejects(()->unknown.endTask(TASK));
        LocalInference.TaskCleanup actualUnknown=new LocalInference.TaskCleanup(false,true,false,null,G1,TASK,false,null);
        check(new CleanupOnly(actualUnknown).endTask(TASK)==actualUnknown,
                "same-task unknown cleanup was rewritten or promoted");
        rejects(()->new CleanupOnly(null).endTask(TASK));
    }
    static void callbackAfterCleanup()throws Exception{
        try(Environment e=new Environment("callback-order")){
            e.adapter.beginTask(TASK);Callback callback=new Callback(e.engine);Object round=e.request(1,callback);prepareReturned(e,round);
            OwnedGenerationScope.entered=new CountDownLatch(1);OwnedGenerationScope.proceed=new CountDownLatch(1);
            AtomicReference<Throwable> error=new AtomicReference<>();
            Thread finisher=new Thread(()->{try{finish(e,round);}catch(Throwable failure){error.set(failure);}},"host-generation-finisher");
            finisher.start();check(OwnedGenerationScope.entered.await(5,TimeUnit.SECONDS),"generation cleanup was not entered");
            check(callback.success==0&&callback.failure==0&&e.engine.isBusy(),"callback escaped before generation cleanup");
            LocalInference.CurrentFrame next=e.frame(2,true);
            rejects(()->e.adapter.generateObserved("p","s",next,e.grammar(next),256,120000,new Callback(e.engine)));
            OwnedGenerationScope.proceed.countDown();finisher.join(5000);
            check(!finisher.isAlive()&&error.get()==null&&callback.success==1,"cleanup-complete callback failed: "+callback.error);
            check(e.engine.isBusy(),"callback cannot release task slot");check(e.end().receiptValid,"normal aggregate after delayed cleanup");
        }
    }
    static void missingCurrentFrame()throws Exception{
        try(Environment e=new Environment("missing-current")){
            e.adapter.beginTask(TASK);Callback callback=new Callback(e.engine);
            rejects(()->e.adapter.generate("p","s",null,null,256,120000,callback));
            rejects(()->e.adapter.generateObserved("p","s",null,null,256,120000,callback));
            LocalInference.CurrentFrame legacy=e.frame(1,false);DecisionGrammar grammar=e.grammar(legacy);
            rejects(()->e.adapter.generateObserved("p","s",legacy,grammar,256,120000,callback));
            LocalInference.CurrentFrame frame=e.frame(2,true);
            rejects(()->e.adapter.generateObserved("p","s",frame,e.grammar(frame),257,120000,callback));
            rejects(()->e.adapter.generateObserved("p","s",frame,e.grammar(frame),256,120001,callback));
            rejects(()->e.adapter.generateObserved("p","s",frame,e.grammar(frame),256,999,callback));
            rejects(()->e.adapter.generateObserved("<__media__>","s",frame,e.grammar(frame),256,120000,callback));
            rejects(()->e.adapter.generateObserved("p","\ud800",frame,e.grammar(frame),256,120000,callback));
            rejects(()->e.adapter.generateObserved("p","s",frame,new DecisionGrammar(TASK,OWNER,OTHER,PACKAGE),256,120000,callback));
            byte[] original=frame.taskOwnerEvidence();original[0]^=1;
            check(Arrays.equals(frame.taskOwnerEvidence(),b(OWNER)),"current frame owner evidence is mutable");
            check(e.executor.size()==0&&callback.success==0&&callback.failure==0,"rejected frame queued native work");
            LocalInference.TaskCleanup result=e.end();
            check(result.cleanupKnown&&!result.processStarted&&!result.receiptValid&&!e.engine.isBusy(),"no-worker aggregate invented a successful inference");
        }
    }
    static void unknownCleanup(boolean force)throws Exception{
        try(Environment e=new Environment(force?"forced-generation":"unknown-generation")){
            e.adapter.beginTask(TASK);OwnedGenerationScope.nextKnown=force;OwnedGenerationScope.nextForce=force;
            Callback callback=new Callback(e.engine);Object round=e.request(1,callback);prepareReturned(e,round);finish(e,round);
            check(callback.success==0&&callback.failure==1,"unverified/forced generation produced success");
            check(callback.cleanup==force,"actual cleanup and successful inference were conflated");
            LocalInference.TaskCleanup result=e.end();
            check(!result.receiptValid&&result.exitCode==null&&result.cleanupKnown==force,"invalid generation became aggregate exit zero");
            check(e.engine.isBusy()!=force,"unknown cleanup released the shared slot");
            if(!force)rejects(()->e.engine.reserveExternal(OTHER));
        }
    }
    static void invalidRaw()throws Exception{
        try(Environment e=new Environment("invalid-raw")){
            e.adapter.beginTask(TASK);Callback callback=new Callback(e.engine);Object round=e.request(1,callback);prepareReturned(e,round);
            Files.write(new File((File)field(round,"directory"),"raw.txt").toPath(),b("changed"));
            finish(e,round);check(callback.success==0&&callback.failure==1&&callback.cleanup,"raw mismatch not rejected with known cleanup");
            LocalInference.CurrentFrame next=e.frame(2,true);
            rejects(()->e.adapter.generateObserved("p","s",next,e.grammar(next),256,120000,new Callback(e.engine)));
            check(e.executor.size()==0,"failure automatically queued another generation");
            LocalInference.TaskCleanup result=e.end();
            check(result.cleanupKnown&&!result.receiptValid&&result.exitCode==null,"failed raw binding became aggregate success");
        }
    }
    static void liveCallbackRetirement()throws Exception{
        try(Environment e=new Environment("live-callback-retirement")){
            e.adapter.beginTask(TASK);Callback callback=new Callback(e.engine);Object round=e.request(1,callback);prepareReturned(e,round);
            e.guard.failAt=e.guard.checks.get()+3;finish(e,round);
            check(callback.success==0&&callback.failure==1&&callback.cleanup,"last live ownership check did not reject callback");
            check(new File((File)field(round,"directory"),"app-delivery-rejection.json").isFile(),"late callback refusal was not recorded");
            LocalInference.TaskCleanup result=e.end();check(result.cleanupKnown&&!result.receiptValid&&result.exitCode==null,"retired frame became task success");
        }
    }
    static void cancelBeforeStart()throws Exception{
        try(Environment e=new Environment("cancel-before-start")){
            e.adapter.beginTask(TASK);Callback callback=new Callback(e.engine);LocalInference.CurrentFrame frame=e.frame(1,true);
            LocalInference.Handle handle=e.adapter.generateObserved("p","s",frame,e.grammar(frame),256,120000,callback);
            Object round=field(field(e.adapter,"task"),"current");handle.cancel();
            long start=(Long)field(round,"finishSubmitted"),deadline=(Long)field(round,"finishDeadline");
            e.adapter.cancelTask();handle.cancel();
            check(start==(Long)field(round,"finishSubmitted")&&deadline==(Long)field(round,"finishDeadline")
                    &&deadline-start==TimeUnit.MILLISECONDS.toNanos(22000),"repeated Stop renewed finisher budget");
            e.executor.take().run();
            check(callback.success==0&&callback.failure==1&&callback.cleanup&&field(round,"process")==null,"pre-launch Stop started or accepted a worker");
            check(OwnedGenerationScope.cleanupCalls==0,"unstarted request invented generation cleanup");
            LocalInference.TaskCleanup result=e.end();
            check(result.cleanupKnown&&!result.processStarted&&!result.receiptValid&&result.exitCode==null,"cancelled unstarted task invented exit");
        }
    }
    static void cancelReturnedProcess()throws Exception{
        try(Environment e=new Environment("cancel-returned")){
            e.adapter.beginTask(TASK);Callback callback=new Callback(e.engine);Object round=e.request(1,callback);
            FakeProcess child=prepareReturned(e,round);e.adapter.cancelTask();finish(e,round);
            check(callback.success==0&&callback.failure==1&&callback.cleanup&&child.destroys==0,"late Stop became success or signaled an exited process");
            LocalInference.TaskCleanup result=e.end();
            check(result.cleanupKnown&&result.processExitObserved&&!result.receiptValid&&result.exitCode==null,
                    "late Stop manufactured success or a nonzero worker exit");
        }
    }
    static void publicationFailure(boolean aggregate)throws Exception{
        try(Environment e=new Environment(aggregate?"aggregate-publication":"request-publication")){
            e.adapter.beginTask(TASK);Object task=field(e.adapter,"task");Callback callback=new Callback(e.engine);
            Object round=e.request(1,callback);prepareReturned(e,round);
            if(!aggregate)android.system.Os.failFsyncPath=new File((File)field(round,"directory"),"app-receipt.json").getPath();
            finish(e,round);
            if(aggregate){
                check(callback.success==1,"setup round must have a verified callback");
                android.system.Os.failFsyncPath=new File((File)field(task,"directory"),"vlm-task-terminal.json").getPath();
            }else check(callback.success==0&&callback.failure==1&&!callback.cleanup,"request publication failure accepted/released child");
            LocalInference.TaskCleanup result=e.end();
            check(!result.cleanupKnown&&!result.receiptValid&&e.engine.isBusy(),"publication failure released the shared slot");
            rejects(()->e.engine.reserveExternal(OTHER));
        }
    }
    static void pendingFailure()throws Exception{
        try(Environment e=new Environment("pending-failure")){
            MobiMindPrivateFiles.writeNew(new File(e.files,"runs"),b("not a directory"));
            rejects(()->e.adapter.beginTask(TASK));
            check(e.engine.isBusy(),"failed pending reservation lost task ownership");
            LocalInference.TaskCleanup result=e.end();check(!result.cleanupKnown&&e.engine.isBusy(),"uncommitted pending task was released");
        }
    }
    static void pendingTamper()throws Exception{
        try(Environment e=new Environment("pending-tamper")){
            e.adapter.beginTask(TASK);Object task=field(e.adapter,"task");
            Files.write(new File((File)field(task,"directory"),"vlm-task-pending.json").toPath(),b("{}"));
            LocalInference.TaskCleanup result=e.end();
            check(!result.cleanupKnown&&!result.receiptValid&&e.engine.isBusy(),"changed pending journal was trusted");
        }
    }
    static void callbackThrows()throws Exception{
        try(Environment e=new Environment("callback-throws")){
            e.adapter.beginTask(TASK);Callback callback=new Callback(e.engine);callback.throwOnSuccess=true;
            Object round=e.request(1,callback);prepareReturned(e,round);finish(e,round);
            check(callback.success==1&&callback.failure==0&&e.engine.isBusy(),"callback failure lost ownership or double-delivered");
            LocalInference.TaskCleanup result=e.end();check(result.cleanupKnown&&!result.receiptValid&&result.exitCode==null,"failed callback became aggregate success");
        }
    }
    static void nativeIdentityIsNotExpected()throws Exception{
        try(Environment e=new Environment("native-identity")){
            e.adapter.beginTask(TASK);Callback callback=new Callback(e.engine);Object round=e.request(1,callback);prepareReturned(e,round);
            File nativeFile=new File((File)field(round,"directory"),"native-result.json");
            Map<String,Object> nativeResult=VlmResultContract.jsonObject(Files.readAllBytes(nativeFile.toPath()));
            nativeResult.put("worker_pid",((Number)nativeResult.get("worker_pid")).longValue()+1);
            Files.write(nativeFile.toPath(),json(nativeResult));finish(e,round);
            check(callback.success==0&&callback.failure==1&&callback.cleanup,"native result supplied its own expected process identity");
            LocalInference.TaskCleanup result=e.end();check(!result.receiptValid&&result.exitCode==null,"foreign native PID became success");
        }
    }
    static void noInternet()throws Exception{
        try(Environment e=new Environment("internet-refusal")){
            e.adapter.beginTask(TASK);e.context.manager.info.requestedPermissions=new String[]{"android.permission.INTERNET"};
            Callback callback=new Callback(e.engine);LocalInference.CurrentFrame frame=e.frame(1,true);
            e.adapter.generateObserved("p","s",frame,e.grammar(frame),256,120000,callback);e.executor.take().run();
            check(callback.success==0&&callback.failure==1&&callback.cleanup&&callback.error.contains("INTERNET"),"APK INTERNET was not rejected before worker launch");
            LocalInference.TaskCleanup result=e.end();check(!result.processStarted&&result.cleanupKnown,"permission preflight launched a worker");
        }
    }
    static void submissionRefused()throws Exception{
        try(Environment e=new Environment("submission-refused")){
            e.adapter.beginTask(TASK);e.executor.reject=true;Callback callback=new Callback(e.engine);LocalInference.CurrentFrame frame=e.frame(1,true);
            e.adapter.generateObserved("p","s",frame,e.grammar(frame),256,120000,callback);
            check(callback.success==0&&callback.failure==1&&callback.cleanup&&e.executor.size()==0,"rejected queue retried native work");
            LocalInference.TaskCleanup result=e.adapter.endTask();
            check(!result.cleanupKnown&&!result.receiptValid&&e.engine.isBusy(),"rejected aggregate finisher released slot");
            Object task=field(e.adapter,"task");Object submitted=field(task,"finishSubmitted"),deadline=field(task,"finishDeadline");
            int attempts=e.executor.attempts;LocalInference.TaskCleanup repeated=e.adapter.endTask();
            check(e.executor.attempts==attempts&&e.executor.size()==0,"rejected task finisher was submitted again");
            check(submitted.equals(field(task,"finishSubmitted"))&&deadline.equals(field(task,"finishDeadline")),"repeated endTask renewed original finisher budget");
            check(!repeated.cleanupKnown&&!repeated.receiptValid&&e.engine.isBusy(),"repeated rejected finisher fabricated cleanup");
        }
    }
    static void purePixels()throws Exception{
        VlmInferenceAdapter.PixelFacts black=new VlmInferenceAdapter.PixelFacts(2,2);
        black.row(new int[]{0xff000000,0xff000000});
        rejects(()->black.evidence());
        black.row(new int[]{0x01000000,0xff000000});
        Map<String,Object> a=black.evidence();
        check(Boolean.TRUE.equals(a.get("all_rgb_zero"))&&Boolean.FALSE.equals(a.get("fully_transparent"))
                &&Boolean.FALSE.equals(a.get("available"))&&((Number)a.get("pixels_scanned")).longValue()==4,"strict RGB-zero scan differs");
        rejects(()->black.row(new int[]{1,2}));
        VlmInferenceAdapter.PixelFacts transparent=new VlmInferenceAdapter.PixelFacts(2,1);
        transparent.row(new int[]{0x00000001,0x00ffffff});Map<String,Object> t=transparent.evidence();
        check(Boolean.FALSE.equals(t.get("all_rgb_zero"))&&Boolean.TRUE.equals(t.get("fully_transparent"))
                &&Boolean.FALSE.equals(t.get("available")),"transparent nonblack pixels admitted");
        VlmInferenceAdapter.PixelFacts nearBlack=new VlmInferenceAdapter.PixelFacts(4096,1);
        int[] row=new int[4096];Arrays.fill(row,0xff000000);row[4095]=0xff000001;nearBlack.row(row);
        check(Boolean.TRUE.equals(nearBlack.evidence().get("available")),"single nonzero RGB was rejected by a darkness threshold");
        VlmInferenceAdapter.PixelFacts visible=new VlmInferenceAdapter.PixelFacts(1,1);visible.row(new int[]{0x01ffffff});
        check(Boolean.TRUE.equals(visible.evidence().get("available")),"nonzero alpha was treated as fully transparent");
        rejects(()->new VlmInferenceAdapter.PixelFacts(8192,8192));
        rejects(()->new VlmInferenceAdapter.PixelFacts(0,1));
        rejects(()->new VlmInferenceAdapter.PixelFacts(2,1).row(new int[]{1}));
    }
    static void unavailablePixels(String name,int pixel)throws Exception{
        try(Environment e=new Environment(name)){
            e.adapter.beginTask(TASK);Callback callback=new Callback(e.engine);byte[] original=png(pixel);
            LocalInference.CurrentFrame frame=e.frame(1,true,original);
            e.adapter.generateObserved("original prompt","original system",frame,e.grammar(frame),256,120000,callback);
            Object round=field(field(e.adapter,"task"),"current");e.executor.take().run();
            check(callback.success==0&&callback.failure==1&&callback.cleanup&&callback.error.contains("VISUAL_FRAME_UNAVAILABLE"),
                    "unavailable visual frame did not terminate before native launch: "+callback.error);
            check(field(round,"process")==null&&OwnedGenerationScope.cleanupCalls==0,"blank frame launched native or invented worker cleanup");
            File dir=(File)field(round,"directory");
            check(Arrays.equals(original,Files.readAllBytes(new File(dir,"screen.png").toPath())),"original PNG bytes were altered");
            Map<String,Object> app=VlmResultContract.jsonObject(Files.readAllBytes(new File(dir,"app-receipt.json").toPath()));
            Map<String,Object> quality=map(app.get("original_frame_quality"));
            check(Boolean.FALSE.equals(quality.get("available"))&&Boolean.FALSE.equals(quality.get("ratio_threshold_used"))
                    &&sha(original).equals(quality.get("original_png_sha256"))
                    &&((Number)quality.get("captured_elapsed_ms")).longValue()==frame.capturedElapsedMillis,
                    "original quality/time/hash evidence missing");
            Map<String,Object> owner=VlmResultContract.jsonObject(Files.readAllBytes(new File(dir,"owner.json").toPath()));
            check(frame.ownerSha256.equals(owner.get("task_owner_sha256"))
                    &&((Number)owner.get("display_id")).longValue()==7,"unavailable image lost original owner/display");
            check(!new File(dir,"native-result.json").exists()&&!new File(dir,"raw.txt").exists(),"blank frame fabricated native output");
            LocalInference.TaskCleanup result=e.end();check(result.cleanupKnown&&!result.processStarted&&!result.receiptValid
                    &&result.exitCode==null&&!e.engine.isBusy(),"blank-frame failure invented inference success");
        }
    }
    static void modes()throws Exception{
        try(Environment observe=new Environment("observe-mode",true)){
            check(observe.adapter.acceptsObservedImage()&&!observe.adapter.modelOutputDispatchAllowed()
                    &&observe.adapter.requestCompletionGraceMillis()==24000,"explicit observe mode/grace differs");
        }
        try(Environment tools=new Environment("tools-mode")){
            check(tools.adapter.modelOutputDispatchAllowed(),"explicit tools mode denied controller parsing");
        }
    }
    /** Real host directories/symlinks; the Android UID projection remains an explicit fixture. */
    static final class CacheEnvironment implements AutoCloseable {
        final Path base,app;final Context context;final ManualExecutor executor=new ManualExecutor();
        final LocalModelEngine engine;final VlmInferenceAdapter adapter;
        final Map<String,Object> audit=new LinkedHashMap<>();
        CacheEnvironment(String name)throws Exception{
            base=root.resolve("cache-"+name);app=base.resolve("data/data/org.trillionnium.hepta.local");
            Files.createDirectories(app.resolve("files"));Files.createDirectories(app.resolve("cache"));
            context=new Context(app.resolve("files").toFile());
            engine=new LocalModelEngine(context,new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4,false),executor);
            adapter=new VlmInferenceAdapter(context,engine);
        }
        File resolve()throws Exception{return (File)call(adapter,"kernelCacheDirectory",audit);}
        void refused(String reason,String stage)throws Exception{
            try{resolve();throw new AssertionError("untrusted cache path admitted");}
            catch(java.io.IOException expected){check(reason.equals(expected.getMessage()),"cache refusal came from a different boundary: "+expected);}
            check(stage.equals(audit.get("kernel_cache_preparation_stage"))
                    &&!audit.containsKey("configured_opencl_kernel_cache_directory"),"failed cache path was marked configured");
        }
        public void close(){android.system.Os.foreignOwnerPath=null;executor.shutdownNow();engine.close();}
    }
    static int mode(Path path)throws Exception{return ((Number)Files.getAttribute(path,"unix:mode")).intValue()&0777;}
    static void canonicalCache()throws Exception{
        try(CacheEnvironment e=new CacheEnvironment("canonical")){
            Files.setAttribute(e.app.resolve("cache"),"unix:mode",02771);
            File kernels=e.resolve();
            check(kernels.equals(e.app.resolve("cache/hepta-vlm-opencl-kernels").toFile()),"canonical cache target differs");
            check(mode(e.app.resolve("cache"))==0700&&mode(kernels.toPath())==0700,"private cache modes were not retained");
            Path existing=kernels.toPath().resolve("existing-kernel");Files.write(existing,b("keep existing kernel cache"));
            check(e.resolve().equals(kernels)&&Arrays.equals(Files.readAllBytes(existing),b("keep existing kernel cache")),"cache reuse deleted or replaced existing contents");
            check("ready".equals(e.audit.get("kernel_cache_preparation_stage"))
                    &&kernels.getPath().equals(e.audit.get("configured_opencl_kernel_cache_directory")),"successful cache path not audited");
        }
    }
    static void frameworkParentAliasCache()throws Exception{
        try(CacheEnvironment e=new CacheEnvironment("framework-parent-alias")){
            Path user=e.base.resolve("data/user");Files.createDirectories(user);
            Files.createSymbolicLink(user.resolve("0"),e.base.resolve("data/data"));
            e.context.cacheDirectory=user.resolve("0/org.trillionnium.hepta.local/cache").toFile();
            File supplied=e.context.getCacheDir();
            check(!supplied.getAbsoluteFile().equals(supplied.getCanonicalFile()),"fixture does not reproduce the old whole-path refusal");
            File kernels=e.resolve();
            check(kernels.equals(e.app.resolve("cache/hepta-vlm-opencl-kernels").toFile()),"framework parent alias selected a different app cache");
            check(supplied.getPath().equals(e.audit.get("context_cache_directory"))
                    &&supplied.getAbsolutePath().equals(e.audit.get("context_cache_absolute_directory"))
                    &&e.app.toString().equals(e.audit.get("canonical_context_cache_parent"))
                    &&e.app.toString().equals(e.audit.get("canonical_app_data_directory"))
                    &&e.app.resolve("cache").toString().equals(e.audit.get("selected_cache_canonical_directory")),"original and canonical cache paths were conflated in audit");
            check(Files.isSymbolicLink(user.resolve("0"))&&Files.isDirectory(kernels.toPath()),"framework alias was rewritten or canonical child was not created");
        }
    }
    static void cacheLeafAlias()throws Exception{
        try(CacheEnvironment e=new CacheEnvironment("leaf-alias")){
            Path target=e.base.resolve("untrusted-cache-target");Files.createDirectories(target);Files.setAttribute(target,"unix:mode",0755);
            Files.delete(e.app.resolve("cache"));Files.createSymbolicLink(e.app.resolve("cache"),target);
            e.refused("directory must be canonical","cache");
            check(Files.isSymbolicLink(e.app.resolve("cache"))&&mode(target)==0755
                    &&!Files.exists(target.resolve("hepta-vlm-opencl-kernels")),"cache leaf alias was followed or mutated");
            check(target.toString().equals(e.audit.get("selected_cache_canonical_directory")),"rejected cache alias lost diagnostic target");
        }
    }
    static void kernelChildAlias()throws Exception{
        try(CacheEnvironment e=new CacheEnvironment("child-alias")){
            Path target=e.base.resolve("untrusted-kernel-target");Files.createDirectories(target);Files.setAttribute(target,"unix:mode",0755);
            Path child=e.app.resolve("cache/hepta-vlm-opencl-kernels");Files.createSymbolicLink(child,target);
            e.refused("directory must be canonical","kernel_child");
            check(Files.isSymbolicLink(child)&&mode(target)==0755,"kernel child alias was followed or chmodded");
        }
    }
    static void foreignCacheParent()throws Exception{
        try(CacheEnvironment e=new CacheEnvironment("foreign-parent")){
            Path foreign=e.base.resolve("another-app");Files.createDirectories(foreign);
            e.context.cacheDirectory=foreign.resolve("cache").toFile();
            e.refused("private kernel cache parent differs from app data","parent");
            check(!Files.exists(foreign.resolve("cache")),"foreign app parent caused cache creation");
            check(foreign.toString().equals(e.audit.get("canonical_context_cache_parent")),"refused foreign parent missing from audit");
        }
    }
    static void invalidCacheRoots()throws Exception{
        try(CacheEnvironment e=new CacheEnvironment("invalid-context")){
            e.context.cacheDirectory=null;e.refused("private kernel cache root unavailable","context");
            check(e.audit.containsKey("context_cache_directory")&&e.audit.get("context_cache_directory")==null,"null framework cache was not recorded");
            e.audit.clear();e.context.cacheDirectory=new File("relative/cache");e.refused("private kernel cache root unavailable","context");
            e.audit.clear();e.context.cacheDirectory=e.app.resolve("code_cache").toFile();e.refused("private kernel cache root unavailable","context");
            check(!Files.exists(e.app.resolve("code_cache")),"unrequested alternate cache leaf was created");
        }
    }
    static void nonDirectoryCache(boolean child)throws Exception{
        try(CacheEnvironment e=new CacheEnvironment(child?"child-file":"root-file")){
            Path target=e.app.resolve(child?"cache/hepta-vlm-opencl-kernels":"cache");
            if(!child)Files.delete(target);Files.write(target,b("ordinary file must remain"));
            e.refused("directory must be app-owned",child?"kernel_child":"cache");
            check(Arrays.equals(Files.readAllBytes(target),b("ordinary file must remain")),"non-directory cache path was overwritten");
        }
    }
    static void foreignOwnedCache(boolean child)throws Exception{
        try(CacheEnvironment e=new CacheEnvironment(child?"child-owner":"root-owner")){
            Path target=e.app.resolve(child?"cache/hepta-vlm-opencl-kernels":"cache");
            Files.createDirectories(target);Files.setAttribute(target,"unix:mode",0755);
            android.system.Os.foreignOwnerPath=target.toString();
            e.refused("directory must be app-owned",child?"kernel_child":"cache");
            check(mode(target)==0755,"foreign-owned fixture cache was chmodded before refusal");
        }
    }
    public static void main(String[] args)throws Exception{
        root=Paths.get(args[0]);Files.createDirectories(root);template=Files.readAllBytes(Paths.get(args[1]));PNG=png(0xffffffff);
        boolean passed=false;
        try{
            test("serial_lease_exact_child_and_scope_token",VlmAdapterLifecycleHostTest::leaseLifecycle);
            test("captured_stop_drain_preserves_shared_admission",VlmAdapterLifecycleHostTest::capturedStop);
            test("actual_host_Process_stop_exit_does_not_release_task",VlmAdapterLifecycleHostTest::realHeldProcess);
            test("two_rounds_one_task_slot_and_aggregate",VlmAdapterLifecycleHostTest::twoRounds);
            test("pre_begin_failure_cannot_reuse_previous_task_cleanup",VlmAdapterLifecycleHostTest::scopedTaskCleanup);
            test("captured_task_cleanup_rejects_foreign_or_unbound_proofs",VlmAdapterLifecycleHostTest::cleanupBindingBoundary);
            test("callback_waits_for_generation_cleanup",VlmAdapterLifecycleHostTest::callbackAfterCleanup);
            test("missing_frame_currentness_bad_grammar_and_bounds",VlmAdapterLifecycleHostTest::missingCurrentFrame);
            test("unknown_generation_cleanup_retains_slot",()->unknownCleanup(false));
            test("forced_generation_is_failure_with_known_cleanup",()->unknownCleanup(true));
            test("raw_hash_mismatch_no_retry",VlmAdapterLifecycleHostTest::invalidRaw);
            test("live_owner_retired_at_last_callback_check",VlmAdapterLifecycleHostTest::liveCallbackRetirement);
            test("repeated_stop_before_start_never_renews_deadline",VlmAdapterLifecycleHostTest::cancelBeforeStart);
            test("stop_race_preserves_actual_zero_exit_without_success",VlmAdapterLifecycleHostTest::cancelReturnedProcess);
            test("request_publication_failure_retains_slot",()->publicationFailure(false));
            test("aggregate_publication_failure_retains_slot",()->publicationFailure(true));
            test("pending_publication_failure_retains_slot",VlmAdapterLifecycleHostTest::pendingFailure);
            test("pending_journal_changed_before_aggregate",VlmAdapterLifecycleHostTest::pendingTamper);
            test("callback_exception_no_release_or_double_delivery",VlmAdapterLifecycleHostTest::callbackThrows);
            test("independent_expected_identity_not_from_native_result",VlmAdapterLifecycleHostTest::nativeIdentityIsNotExpected);
            test("APK_INTERNET_rejected_before_launch",VlmAdapterLifecycleHostTest::noInternet);
            test("executor_refusal_never_requeues_model",VlmAdapterLifecycleHostTest::submissionRefused);
            test("full_pixel_scan_exact_zero_alpha_and_no_ratio",VlmAdapterLifecycleHostTest::purePixels);
            test("all_black_original_frame_rejected",()->unavailablePixels("all-black",0xff000000));
            test("all_transparent_original_frame_rejected",()->unavailablePixels("transparent-black",0x00000000));
            test("transparent_colour_original_frame_rejected",()->unavailablePixels("transparent-colour",0x00abcdef));
            test("explicit_observe_tools_modes_and_24s_cleanup_grace",VlmAdapterLifecycleHostTest::modes);
            test("canonical_context_cache_retains_private_modes_and_contents",VlmAdapterLifecycleHostTest::canonicalCache);
            test("framework_parent_alias_accepted_and_original_paths_audited",VlmAdapterLifecycleHostTest::frameworkParentAliasCache);
            test("cache_leaf_symlink_refused_without_target_mutation",VlmAdapterLifecycleHostTest::cacheLeafAlias);
            test("kernel_child_symlink_refused_without_target_mutation",VlmAdapterLifecycleHostTest::kernelChildAlias);
            test("different_app_cache_parent_refused",VlmAdapterLifecycleHostTest::foreignCacheParent);
            test("null_relative_and_alternate_context_cache_refused",VlmAdapterLifecycleHostTest::invalidCacheRoots);
            test("cache_root_regular_file_refused",()->nonDirectoryCache(false));
            test("kernel_child_regular_file_refused",()->nonDirectoryCache(true));
            test("foreign_owned_cache_root_refused",()->foreignOwnedCache(false));
            test("foreign_owned_kernel_child_refused",()->foreignOwnedCache(true));
            check(android.graphics.BitmapFactory.decoded==android.graphics.BitmapFactory.recycled,"decoded inspection bitmap leaked");
            passed=true;System.out.println("PASS "+cases.size()+" lifecycle cases / "+checks+" assertions; native generation helper and launch are fixtures");
        }finally{
            LocalModelEngine.fixtureShutdownCancellation();
            Map<String,Object> report=new LinkedHashMap<>();report.put("all_pass",passed);report.put("case_count",cases.size());
            report.put("assertions",checks);report.put("cases",cases);report.put("actual_host_process_used",true);
            report.put("Android_BitmapFactory_fixture","Java ImageIO host surrogate; production uses Android BitmapFactory with original PNG");
            report.put("native_model_launch_simulated",true);report.put("native_generation_helper_simulated",true);
            report.put("phone_operations",0);report.put("model_inference",false);report.put("android_runtime",false);
            Files.write(Paths.get(args[2]),json(report));
        }
    }
}
