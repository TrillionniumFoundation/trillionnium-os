package org.trillionnium.hepta.local;
import android.system.Os;import android.os.Looper;import android.app.ActivityManager;
import java.io.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.nio.file.attribute.PosixFilePermissions;import java.lang.reflect.*;
import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import org.json.*;
/** Executes the complete production Engine class with explicit host platform ports.
 * Host Android Context/Looper/memory are explicit boundaries. Every accepted run is refused
 * by lowMemory before weight/native access; no native runner or model is present. */
public final class RuntimeGenerationHostTest {
 private static int cases,assertions;private static Path output;private static final JSONArray rows=new JSONArray();
 private static final List<LocalModelEngine> engines=new ArrayList<LocalModelEngine>();
 private interface Work{void run()throws Exception;}
 private static final byte[] ORIGINAL=("{\"schema\":\"hepta.local-runtime.v1\",\"compute\":\"npu\",\"context_tokens\":8192,\"threads\":4}\n").getBytes(StandardCharsets.UTF_8);
 private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
 private static void reject(Work body)throws Exception{boolean denied=false;try{body.run();}catch(Exception expected){denied=true;}check(denied,"must reject");}
 private static Object field(Object object,String name)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
 private static void set(Object object,String name,Object value)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);f.set(object,value);}
 @SuppressWarnings("unchecked") private static AtomicReference<LocalModelEngine.RunHandle> processSlot()throws Exception{Field f=LocalModelEngine.class.getDeclaredField("PROCESS_ACTIVE");f.setAccessible(true);return(AtomicReference<LocalModelEngine.RunHandle>)f.get(null);}
 @SuppressWarnings("unchecked") private static AtomicReference<LocalModelEngine.RunHandle> active(LocalModelEngine e)throws Exception{return(AtomicReference<LocalModelEngine.RunHandle>)field(e,"active");}
 private static ThreadPoolExecutor executor(LocalModelEngine e)throws Exception{return(ThreadPoolExecutor)field(e,"executor");}
 private static LocalModelEngine.RuntimeGeneration generation(LocalModelEngine e)throws Exception{return(LocalModelEngine.RuntimeGeneration)field(e,"runtime");}
 private static Path fresh(String name)throws Exception{Path f=output.resolve(String.format(Locale.ROOT,"%03d-",cases)+name);Files.createDirectory(f);Files.setPosixFilePermissions(f,PosixFilePermissions.fromString("rwx------"));Files.createDirectory(f.resolve("model"));Files.setPosixFilePermissions(f.resolve("model"),PosixFilePermissions.fromString("rwx------"));write(f.resolve("model/runtime-config.json"),ORIGINAL);return f;}
 private static void write(Path path,byte[] data)throws Exception{Files.write(path,data,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));}
 private static LocalModelEngine engine(Path files){LocalModelEngine e=new LocalModelEngine(new android.content.Context(files.toFile()));engines.add(e);return e;}
 private static LocalModelEngine.Request request(){return new LocalModelEngine.Request("only 42",null,null,128,120000);}
 private static void idleExecutor(LocalModelEngine e)throws Exception{long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);while(executor(e).getActiveCount()!=0||!executor(e).getQueue().isEmpty()){if(System.nanoTime()>until)throw new AssertionError("actual executor did not drain");Thread.yield();}}
 private static LocalModelEngine.Result once(LocalModelEngine e)throws Exception{
  AtomicReference<LocalModelEngine.Result> got=new AtomicReference<LocalModelEngine.Result>();CountDownLatch done=new CountDownLatch(1);
  e.start(request(),r->{got.set(r);done.countDown();});check(done.await(5,TimeUnit.SECONDS),"actual callback completed");idleExecutor(e);
  LocalModelEngine.Result r=got.get();check(r!=null&&"insufficient_memory".equals(r.status),"synthetic lowMemory stops before native");
  check(!r.inferenceCompleted&&!r.receipt.optBoolean("process_started",false),"no native inference");return r;
 }
 private static void run(String name,Work test)throws Exception{
  Os.reset();Looper.resetMain();LocalProbeApplication.permissionBlocked=false;ActivityManager.low=true;ActivityManager.available=0;
  check(processSlot().get()==null,"independent case starts with no process owner");
  int prior=assertions;JSONObject row=new JSONObject().put("name",name);rows.put(row);
  try{test.run();row.put("passed",true);cases++;}
  catch(Throwable failure){row.put("passed",false).put("error",failure.toString());throw failure;}
  finally{row.put("assertions",assertions-prior);}
 }
 private static void tests()throws Exception{
  run("startup-pending-blocks-with-both-slots-empty",()->{
   Path f=fresh("pending");RuntimeConfigTransaction.prepare(f.toFile(),RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,"gpu"),true);LocalModelEngine e=engine(f);
   check(e.settingsBlocked()&&e.isBusy(),"pending is surfaced as blocked");
   check(processSlot().get()==null&&active(e).get()==null,"pending test does not depend on occupied slot");
   reject(()->e.start(request(),r->{throw new AssertionError("blocked once callback");}));
   reject(()->e.beginWarmTask("11111111111111111111111111111111"));
   reject(()->e.reserveExternal("22222222222222222222222222222222"));
   reject(()->e.reserveSettings(false));
   check(processSlot().get()==null&&active(e).get()==null,"rejected entries publish no owner");
   LocalModelEngine.SettingsReservation restore=e.reserveSettings(true);restore.requireOwned();e.finishSettings(restore,false);
   check(e.settingsBlocked()&&processSlot().get()==null,"unsuccessful restore keeps durable fence without retaining completed slot");
  });
  run("failed-settings-completion-blocks-without-slot",()->{
   LocalModelEngine e=engine(fresh("failed"));LocalModelEngine.SettingsReservation lease=e.reserveSettings(false);e.finishSettings(lease,false);
   check(e.settingsBlocked()&&processSlot().get()==null&&active(e).get()==null,"unknown storage only blocks flag");
   reject(()->e.start(request(),r->{}));reject(()->e.beginWarmTask("33333333333333333333333333333333"));reject(()->e.reserveExternal("44444444444444444444444444444444"));
  });
  run("unknown-private-settings-directory-blocks-startup",()->{
   Path f=fresh("unknown");Files.createDirectory(f.resolve("runtime-settings"));Os.chmod(f.resolve("runtime-settings").toString(),0755);
   LocalModelEngine e=engine(f);check(e.settingsBlocked(),"untrusted settings directory fails closed");reject(()->e.reserveExternal("55555555555555555555555555555555"));check(processSlot().get()==null,"no partial owner");
  });
  run("settings-reservation-is-exclusive-and-not-external",()->{
   LocalModelEngine e=engine(fresh("exclusive"));LocalModelEngine.SettingsReservation lease=e.reserveSettings(false);
   check(processSlot().get()!=null&&active(e).get()==null,"settings owns only process gate");
   reject(()->e.reserveSettings(false));reject(()->e.reserveExternal("66666666666666666666666666666666"));reject(()->e.start(request(),r->{}));reject(()->e.beginWarmTask("77777777777777777777777777777777"));
   for(Method method:lease.getClass().getDeclaredMethods())check(!method.getName().equals("attach")&&!method.getName().equals("cancel"),"settings has no child/signal capability");
   e.cancelActive();lease.requireOwned();check(active(e).get()==null,"visible Stop cannot borrow a settings child");e.finishSettings(lease,true);check(!e.isBusy(),"legitimate exact completion releases process gate");
  });
  run("main-thread-required-for-settings",()->{
   LocalModelEngine e=engine(fresh("main"));AtomicReference<Throwable> result=new AtomicReference<Throwable>();
   Thread t=new Thread(()->{try{e.reserveSettings(false);}catch(Throwable error){result.set(error);}});t.start();t.join(2000);
   check(result.get() instanceof IllegalStateException,"worker cannot originate settings");check(processSlot().get()==null,"worker rejection leaves slot absent");
  });
  run("real-executor-active-and-queued-work-block-settings",()->{
   LocalModelEngine e=engine(fresh("queue"));CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
   executor(e).execute(()->{entered.countDown();try{release.await();}catch(InterruptedException err){Thread.currentThread().interrupt();}});
   try{check(entered.await(2,TimeUnit.SECONDS),"real worker active");check(processSlot().get()==null,"queue guard independently checked");reject(()->e.reserveSettings(false));
    executor(e).execute(()->{});check(executor(e).getQueue().size()==1,"real pending queue exists");reject(()->e.reserveSettings(false));}
   finally{release.countDown();}idleExecutor(e);LocalModelEngine.SettingsReservation lease=e.reserveSettings(false);e.finishSettings(lease,true);
  });
  run("foreign-settings-lease-cannot-publish-or-release",()->{
   LocalModelEngine owner=engine(fresh("owner")),foreign=engine(fresh("foreign"));LocalModelEngine.SettingsReservation lease=owner.reserveSettings(false);
   LocalModelEngine.RuntimeGeneration next=LocalModelEngine.generation(RuntimeConfigTransaction.current(((java.io.File)field(owner,"files"))),new ModelFileVerifier());
   reject(()->foreign.publishSettings(lease,next));reject(()->foreign.finishSettings(lease,true));lease.requireOwned();owner.finishSettings(lease,true);
  });
  run("once-receipts-use-new-immutable-generation-after-commit",()->{
   Path f=fresh("generations");LocalModelEngine e=engine(f);LocalModelEngine.RuntimeGeneration old=generation(e);
   LocalModelEngine.Result first=once(e);check(first.receipt.getString("runtime_generation_id").equals(old.id),"first receipt binds old generation");
   check(first.receipt.getString("compute_requested").equals("npu"),"first route is original NPU");
   Field cached=ModelFileVerifier.class.getDeclaredField("verifiedPath");cached.setAccessible(true);cached.set(old.verifier,"synthetic-old-cache-marker");
   LocalModelEngine.SettingsReservation lease=e.reserveSettings(false);byte[] target=RuntimeConfigTransaction.selected(ModelProfile.LFM25_8B_A1B.id,"gpu");
   RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),target,true);RuntimeConfigTransaction.Snapshot applied=tx.apply();
   LocalModelEngine.RuntimeGeneration next=LocalModelEngine.generation(applied,new ModelFileVerifier());e.publishSettings(lease,next);tx.commit();e.finishSettings(lease,true);
   check(generation(e)==next&&next!=old&&next.verifier!=old.verifier&&cached.get(next.verifier)==null,"published generation owns fresh verifier without old cache");
   check(old.config.profile==ModelProfile.LFM3&&old.config.compute.equals("npu"),"old immutable snapshot remains original");
   LocalModelEngine.Result second=once(e);
   check(second.receipt.getString("runtime_generation_id").equals(next.id)&&second.receipt.getString("runtime_configuration_sha256").equals(applied.sha()),"second receipt binds exact new config");
   check(second.receipt.getString("compute_requested").equals("gpu")&&second.receipt.getString("model_profile").equals(ModelProfile.LFM25_8B_A1B.id),"new profile and device in same request");
   check(second.receipt.getLong("minimum_available_memory_bytes")==7L<<30,"new profile budget is used");check(e==engines.get(engines.size()-1),"same external engine object retained");
  });
  run("warm-owner-and-request-retain-one-generation",()->{
   Path f=fresh("warm");LocalModelEngine e=engine(f);LocalModelEngine.RuntimeGeneration before=generation(e);LocalModelEngine.WarmTask task=e.beginWarmTask("88888888888888888888888888888888");
   check(field(task,"runtime")==before,"warm owner captures one runtime");reject(()->e.reserveSettings(false));
   CountDownLatch done=new CountDownLatch(1);AtomicReference<LocalModelEngine.Result> got=new AtomicReference<LocalModelEngine.Result>();
   LocalModelEngine.RunHandle handle=e.startWarmRequest(task,request(),r->{got.set(r);done.countDown();});
   check(field(handle,"runtime")==before,"warm request uses owner's same snapshot");check(done.await(5,TimeUnit.SECONDS),"warm preflight callback completed");idleExecutor(e);
   check(got.get()!=null&&got.get().receipt.getString("runtime_generation_id").equals(before.id),"actual warm receipt retains generation");
   check(!got.get().inferenceCompleted,"lowMemory denies any actual model");reject(()->e.reserveSettings(false));
   LocalInference.TaskCleanup cleanup=e.finishWarmTask(task);check(cleanup.cleanupKnown,"no-start warm finalization is known");idleExecutor(e);check(processSlot().get()==null&&!e.isBusy(),"actual warm no-start finalization releases original owner");
  });
  run("warm-npu-and-gpu-cancellation-policy-bound-at-creation",()->{
   for(String compute:new String[]{"npu","gpu"}){
    Path f=fresh("policy-"+compute);write(f.resolve("model/runtime-config.json"),RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,compute));LocalModelEngine e=engine(f);
    LocalModelEngine.WarmTask task=e.beginWarmTask(compute.equals("npu")?"99999999999999999999999999999999":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    check(((LocalModelEngine.RuntimeGeneration)field(task,"runtime")).config.compute.equals(compute),"warm cancellation owner uses selected generation");
    OwnedWorkerCancellation cancellation=(OwnedWorkerCancellation)field(task,"cancellation");
    OwnedWorkerCancellation expected=compute.equals("npu")?OwnedWorkerCancellation.forWarmNpu(task.generation(),task.taskId):new OwnedWorkerCancellation(task.generation(),task.taskId);
    check(cancellation.finishFutureMillis()==expected.finishFutureMillis(),"real policy timeout matches captured compute");
    check(e.finishWarmTask(task).cleanupKnown,"no-start finalization remains valid");idleExecutor(e);
   }
  });
  run("config-change-rejects-captured-source-before-inference",()->{
   Path f=fresh("source-change");LocalModelEngine e=engine(f);LocalModelEngine.RuntimeGeneration original=generation(e);
   write(f.resolve("model/runtime-config.json"),RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,"gpu"));
   reject(()->original.source.unchanged());check(generation(e)==original&&e.configuration().compute.equals("npu"),"external file mutation never silently refreshes the shell");
   AtomicReference<LocalModelEngine.Result> got=new AtomicReference<LocalModelEngine.Result>();CountDownLatch done=new CountDownLatch(1);e.start(request(),r->{got.set(r);done.countDown();});check(done.await(5,TimeUnit.SECONDS),"actual invalid-source callback");idleExecutor(e);
   check(got.get()!=null&&!got.get().inferenceCompleted&&!got.get().receipt.optBoolean("process_started",false),"invalid captured source starts no native model");check(processSlot().get()==null,"known no-start failure drains owner");
  });
  run("model-admission-uses-real-negative-budget-and-weight-size-gates",()->{
   Path f=fresh("weight");LocalModelEngine e=engine(f);LocalModelEngine.SettingsReservation lease=e.reserveSettings(false);
   for(ModelProfile profile:new ModelProfile[]{ModelProfile.LFM3,ModelProfile.LFM25_8B_A1B}){
    ActivityManager.low=true;reject(()->e.verifySettingsModel(lease,new LocalRuntimeConfig(profile,"npu",8192,4)));
    ActivityManager.low=false;ActivityManager.available=12L<<30;write(f.resolve("model").resolve(profile.fileName),new byte[]{1,2,3});
    reject(()->e.verifySettingsModel(lease,new LocalRuntimeConfig(profile,"gpu",8192,4)));
   }
   lease.requireOwned();e.finishSettings(lease,true);ActivityManager.low=true;ActivityManager.available=0;
  });
  run("changed-generation-under-lease-fails-closed",()->{
   LocalModelEngine e=engine(fresh("lease-generation"));LocalModelEngine.SettingsReservation lease=e.reserveSettings(false);LocalModelEngine.RuntimeGeneration prior=generation(e);
   set(e,"runtime",LocalModelEngine.generation(prior.source,new ModelFileVerifier()));reject(()->lease.requireOwned());reject(()->e.finishSettings(lease,true));
   check(processSlot().get()!=null,"unknown generation does not release slot");set(e,"runtime",prior);e.finishSettings(lease,true);
  });
  run("closed-engine-refuses-new-settings",()->{LocalModelEngine e=engine(fresh("closed"));e.close();reject(()->e.reserveSettings(false));reject(()->e.reserveSettings(true));check(processSlot().get()==null,"closed engine does not acquire");});
  run("independent-permission-barrier-retained",()->{
   LocalModelEngine e=engine(fresh("permission"));LocalProbeApplication.permissionBlocked=true;check(e.isBusy(),"permission block still appears busy");reject(()->e.start(request(),r->{}));reject(()->e.beginWarmTask("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));reject(()->e.reserveExternal("cccccccccccccccccccccccccccccccc"));LocalProbeApplication.permissionBlocked=false;
  });
 }
 private static void shutdown()throws Exception{
  for(LocalModelEngine e:engines){e.close();executor(e).awaitTermination(3,TimeUnit.SECONDS);}
  Object queue=TaskCancellationQueue.processQueue();Field f=queue.getClass().getDeclaredField("executor");f.setAccessible(true);Object value=f.get(queue);
  if(value instanceof ExecutorService){((ExecutorService)value).shutdown();((ExecutorService)value).awaitTermination(3,TimeUnit.SECONDS);}
 }
 public static void main(String[] args)throws Exception{
  output=Paths.get(args[0]);Files.createDirectory(output);boolean pass=false;Throwable error=null;
  try{tests();check(processSlot().get()==null,"all actual process slots released");pass=true;}catch(Throwable failure){error=failure;failure.printStackTrace();}
  finally{try{shutdown();}catch(Throwable failure){pass=false;if(error==null)error=failure;failure.printStackTrace();}}
  JSONObject report=new JSONObject().put("schema","hepta.local-model-settings-generation-host.v1").put("passed",pass).put("cases",cases).put("assertions",assertions).put("case_results",rows)
   .put("full_production_engine_class",true).put("real_executor_and_process_admission",true).put("android_context_looper_memory_synthetic",true).put("uid_fd_directory_fsync_surrogates",true)
   .put("accepted_requests_stopped_before_native_by_synthetic_lowMemory",true).put("positive_model_hash_or_hardware_qualification",false).put("phone_operations",0).put("native_model_executed",false).put("error",error==null?JSONObject.NULL:error.toString());
  Files.write(output.resolve("RESULT.json"),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(report.toString());if(!pass)System.exit(1);
 }
}
