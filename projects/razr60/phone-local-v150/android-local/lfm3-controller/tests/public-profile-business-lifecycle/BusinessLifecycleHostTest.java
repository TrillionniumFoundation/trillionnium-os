package org.trillionnium.hepta.local;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;

/** Actual App/Engine + LTS/HA/Flight lifecycle members.
 * Receipts, task storage and Android UI are explicit ports; no phone authority. */
public final class BusinessLifecycleHostTest {
 private interface Checked {void run()throws Exception;}
 private static int cases,assertions;
 private static final List<LocalProbeApplication> apps=new ArrayList<LocalProbeApplication>();
 private static final class Env {
  final LocalProbeApplication app;final LocalTaskSession session;
  final LocalTaskController controller;final HeptaAccessibilityService service;final BackgroundSession background;
  final Object originalBarrier;
  Env(boolean existing)throws Exception{
   LocalTaskSession.initialBlocked=true;app=new LocalProbeApplication();app.onCreate();apps.add(app);session=app.taskSession();
   controller=existing?new LocalTaskController():null;background=existing?new BackgroundSession():null;
   service=new HeptaAccessibilityService();service.ownedController=controller;service.taskBackground=background;
   service.lease=existing?HostFacts.TASK:null;HeptaAccessibilityService.hostConnect(service);session.hostSeed(controller);
   originalBarrier=field(app,"recoveryBarrier");
  }
 }
 private static void check(boolean ok,String what){assertions++;if(!ok)throw new AssertionError(what);}
 private static void rejects(Checked action)throws Exception{
  boolean denied=false;try{action.run();}catch(IllegalStateException|RejectedExecutionException|IOException expected){denied=true;}
  check(denied,"actual production path should reject");
 }
 private static Object field(Object value,String name)throws Exception{
  Field f=value.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(value);
 }
 private static void set(Object value,String name,Object next)throws Exception{
  Field f=value.getClass().getDeclaredField(name);f.setAccessible(true);f.set(value,next);
 }
 private static AtomicReference<?> global()throws Exception{
  Field f=LocalModelEngine.class.getDeclaredField("PROCESS_ACTIVE");f.setAccessible(true);return (AtomicReference<?>)f.get(null);
 }
 private static ThreadPoolExecutor modelPool(Env e)throws Exception{return (ThreadPoolExecutor)field(e.app.modelEngine(),"executor");}
 private static void await(BooleanSupplier condition,String what)throws Exception{
  long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);
  while(!condition.getAsBoolean()&&System.nanoTime()<end)Thread.sleep(1);
  check(condition.getAsBoolean(),what);
 }
 private static void serialDone(Env e)throws Exception{e.session.hostExecutor().submit(()->{}).get(4,TimeUnit.SECONDS);}
 private static void assertHeld(Env e)throws Exception{
  check(field(e.app,"backgroundRecoveryAttempt")!=null,"real Application owns background reservation");
  check(e.app.modelEngine().isBusy(),"actual model admission slot remains busy");
  check(!e.app.canAcknowledgeControlRecovery(),"actual control acknowledgement excluded during background borrow");
  check(!e.session.canAcknowledgeInterruption(),"actual Session ACK gate remains closed during recovery");
 }
 private static void assertReturned(Env e)throws Exception{
  check(field(e.app,"backgroundRecoveryAttempt")==null,"background borrow actually returned");
  check(field(e.app,"recoveryBarrier")==e.originalBarrier,"same original barrier retained");
  check(e.app.modelEngine().isBusy(),"cleanup did not release process-wide model barrier");
  check(e.session.isBlocked()&&!e.session.isRunning()&&!e.session.isRecovering(),"old task still blocked and no auto execution");
  check(HostFacts.TASK.equals(e.session.hostTask()),"old task identity preserved");
  check(e.session.retainedCalls==0,"background close did not invoke control ACK callback");
 }
 private static void successfulPort(){
  BackgroundSession.hostWork=c->{c.checkBusiness(HostFacts.TASK,HostFacts.OWNER);return BackgroundSession.hostKnown();};
 }
 private static void clean()throws Exception{
  if(PublicProfileBusinessRecoveryClient.workPending())PublicProfileBusinessRecoveryClient.hostReleaseOwnedChecker();
  android.os.Handler.drain();
  for(LocalProbeApplication app:apps){
   app.taskSession().hostExecutor().shutdownNow();
   check(app.taskSession().hostExecutor().awaitTermination(4,TimeUnit.SECONDS),"real serial recovery executor ended");
   app.modelEngine().close();
   ThreadPoolExecutor pool=(ThreadPoolExecutor)field(app.modelEngine(),"executor");pool.shutdownNow();
   check(pool.awaitTermination(4,TimeUnit.SECONDS),"real model executor ended");
  }
  await(()->!TaskCancellationQueue.processQueue().pending(),"real process cancellation queue drained");
  android.os.Handler.drain();apps.clear();PublicProfileBusinessRecoveryClient.hostAssertDrained();
  // Host test isolation only, after all real children, readers and executors ended.
  global().set(null);HeptaAccessibilityService.hostConnect(null);
 }
 private static void run(String name,Checked body)throws Exception{
  clean();android.os.Looper.resetMain();android.os.Handler.reset();
  BackgroundSession.hostLeasePresent=true;BackgroundSession.calls=0;BackgroundSession.last=null;
  WebFlightSession.hostKnown=true;ProfilePermissionUiSession.busy=false;
  MobiMindModelEngine.initialBlocked=false;UiVenusModelEngine.initialBlocked=false;BackgroundPermissionSession.initialBlocked=false;
  successfulPort();int before=assertions;body.run();cases++;
  System.out.println("PASS case="+name+" assertions="+(assertions-before));
 }
 private static void finishNormally(Env e)throws Exception{
  serialDone(e);check(android.os.Handler.pending()==1,"one actual main completion queued");
  android.os.Handler.drain();assertReturned(e);
 }
 private static final class ThrowAfterExecute extends AbstractExecutorService {
  final ExecutorService delegate;ThrowAfterExecute(ExecutorService d){delegate=d;}
  public void execute(Runnable r){delegate.execute(r);throw new IllegalStateException("explicit host dispatch uncertainty after acceptance");}
  public void shutdown(){delegate.shutdown();}
  public List<Runnable> shutdownNow(){return delegate.shutdownNow();}
  public boolean isShutdown(){return delegate.isShutdown();}
  public boolean isTerminated(){return delegate.isTerminated();}
  public boolean awaitTermination(long n,TimeUnit unit)throws InterruptedException{return delegate.awaitTermination(n,unit);}
 }
 public static void main(String[] args)throws Exception{
  if(args.length==1&&args[0].equals("--owned-child")){
   if(System.in.read()!=1)throw new IOException("owned child release missing");
   System.out.print("OWNED_HOST_CHECKER_EOF\n");System.out.flush();return;
  }
  try{
   run("nonnull_service_worker_main_and_separate_control",()->{
    Env e=new Env(true);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
    BackgroundSession.hostWork=c->{c.checkBusiness(HostFacts.TASK,HostFacts.OWNER);entered.countDown();release.await();c.check();return BackgroundSession.hostKnown();};
    byte[] originalControl=HostFacts.OLD_CONTROL.clone(),originalResult=HostFacts.OLD_RESULT.clone(),originalLatch=HostFacts.OLD_LATCH.clone();
    e.session.hostStart();check(entered.await(4,TimeUnit.SECONDS),"real serial worker entered");assertHeld(e);
    rejects(()->e.app.modelEngine().start(new LocalModelEngine.Request(),()->{}));
    rejects(()->e.app.modelEngine().reserveExternal(UUID.randomUUID().toString().replace("-","")));
    rejects(()->e.app.reserveControlRecovery());
    release.countDown();serialDone(e);assertHeld(e);
    check(!BackgroundSession.hostLeasePresent&&!e.session.hasBackgroundLease(),"lease-only port retired before UI callback");
    check(e.background.accepts==0,"service not accepted on worker");android.os.Handler.drain();assertReturned(e);
    check(e.background.accepts==1,"actual typed service branch accepted once");
    check(BackgroundSession.last.businessRecovery.persistedChecks==1&&BackgroundSession.last.businessRecovery.originalChecks==1,"actual service rechecks typed persisted originals");
    check(Arrays.equals(originalControl,HostFacts.OLD_CONTROL)&&Arrays.equals(originalResult,HostFacts.OLD_RESULT)&&Arrays.equals(originalLatch,HostFacts.OLD_LATCH),"immutable old-record ports unchanged");
    check(e.session.canAcknowledgeInterruption(),"separate owner acknowledgement becomes eligible only after cleanup callback");
    LocalModelEngine.RecoveryReservation ack=e.app.reserveControlRecovery();
    check(ack!=null&&e.session.isBlocked(),"explicit separate control borrow still does not acknowledge");
    ack.close();android.os.Handler.drain();check(e.session.isBlocked(),"uncommitted control attempt keeps old blocked state");
   });
   run("real_owned_child_and_reader_hold_slot_until_drain",()->{
    Env e=new Env(true);
    BackgroundSession.hostWork=c->{c.check();PublicProfileBusinessRecoveryClient.hostStartOwnedChecker();return BackgroundSession.hostKnown();};
    e.session.hostStart();serialDone(e);assertHeld(e);
    check(PublicProfileBusinessRecoveryClient.workPending()&&e.service.observationReadWorkPending(),"actual owned checker/reader pending");
    check(android.os.Handler.pending()==0&&e.background.accepts==0,"no main acceptance before real drain");
    check(e.service.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"own checker does not self-deadlock the typed idle check");
    rejects(()->e.service.acceptBackgroundReconciliation(BackgroundSession.last));
    PublicProfileBusinessRecoveryClient.hostReleaseOwnedChecker();
    check(!PublicProfileBusinessRecoveryClient.workPending()&&android.os.Handler.pending()==1,"real exit plus EOF schedules one main callback");
    android.os.Handler.drain();assertReturned(e);check(e.background.accepts==1,"acceptance follows actual drain");
   });
   run("failed_checker_keeps_lease_and_waits_for_real_drain",()->{
    Env e=new Env(true);
    BackgroundSession.hostWork=c->{c.check();PublicProfileBusinessRecoveryClient.hostStartOwnedChecker();throw new IOException("explicit failed checker port");};
    e.session.hostStart();serialDone(e);assertHeld(e);check(android.os.Handler.pending()==0,"failure does not fake checker exit");
    PublicProfileBusinessRecoveryClient.hostReleaseOwnedChecker();android.os.Handler.drain();assertReturned(e);
    check(e.background.accepts==0&&BackgroundSession.hostLeasePresent&&!e.session.canAcknowledgeInterruption(),"failed cleanup preserves lease and blocks acknowledgement");
   });
   run("main_post_refusal_returns_only_background_borrow",()->{
    Env e=new Env(true);android.os.Handler.acceptPosts=false;e.session.hostStart();serialDone(e);
    assertReturned(e);check(android.os.Handler.pending()==0&&e.background.accepts==0,"post refusal cannot invent UI acceptance");
    android.os.Handler.acceptPosts=true;
   });
   run("replaced_live_service_refuses_main_acceptance",()->{
    Env e=new Env(true);e.session.hostStart();serialDone(e);
    HeptaAccessibilityService.hostConnect(new HeptaAccessibilityService());android.os.Handler.drain();assertReturned(e);
    check(e.background.accepts==0,"old service cannot accept after replacement");
   });
   run("changed_owner_epoch_refuses_main_acceptance",()->{
    Env e=new Env(true);e.session.hostStart();serialDone(e);e.session.hostEpochChange();
    android.os.Handler.drain();assertReturned(e);check(e.background.accepts==0,"stale owner epoch refused");
   });
   run("changed_instruction_on_worker_prevents_lease_port",()->{
    Env e=new Env(true);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
    BackgroundSession.hostWork=c->{entered.countDown();release.await();c.checkBusiness(HostFacts.TASK,HostFacts.OWNER);return BackgroundSession.hostKnown();};
    e.session.hostStart();check(entered.await(4,TimeUnit.SECONDS),"worker entered before owner mutation");
    e.session.hostOwnerChange();release.countDown();serialDone(e);android.os.Handler.drain();assertReturned(e);
    check(BackgroundSession.hostLeasePresent&&e.background.accepts==0,"owner mismatch cannot reach lease retirement");
   });
   run("actual_service_queue_and_ownership_predicates",()->{
    Env e=new Env(true);HeptaAccessibilityService s=e.service;
    check(s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"actual nonnull service initial idle");
    s.activeObservation=new Object();check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"observation blocks");s.activeObservation=null;
    s.activeNativeSearchObservation=new Object();check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"native observation blocks");s.activeNativeSearchObservation=null;
    s.capturePending=true;check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"capture blocks");s.capturePending=false;
    s.observationIoBusy.set(true);check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"actual IO atomic blocks");s.observationIoBusy.set(false);
    s.actionSlot.busy=true;check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"action queue blocks");s.actionSlot.busy=false;
    ProfilePermissionUiSession.busy=true;check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"permission action blocks");ProfilePermissionUiSession.busy=false;
    s.nativeCancellationQueue.busy=true;check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"native cancel queue blocks");s.nativeCancellationQueue.busy=false;
    s.lease="foreign";check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"foreign lease blocks");s.lease=HostFacts.TASK;
    e.background.ownerSha256=HostFacts.OTHER;check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"foreign owner blocks");e.background.ownerSha256=HostFacts.OWNER;
    e.background.eligible=false;check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"ineligible session blocks");e.background.eligible=true;
    e.controller.running=true;check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"running controller blocks");e.controller.running=false;
    s.taskWeb=new WebFlightSession();s.taskWeb.isReleased=false;check(!s.publicProfileBusinessReconciliationIdle(e.controller,HostFacts.TASK,HostFacts.OWNER),"unreleased web blocks");s.taskWeb=null;
    check(!s.publicProfileBusinessReconciliationIdle(new LocalTaskController(),HostFacts.TASK,HostFacts.OWNER),"foreign controller identity blocks");
    check(!s.publicProfileBusinessReconciliationIdle(e.controller,"not-a-task",HostFacts.OWNER),"invalid typed task rejected");
   });
   run("actual_journal_queue_blocks_owner_entry",()->{
    Env e=new Env(true);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
    e.session.hostJournal().submit(()->{entered.countDown();release.await();},r->{});
    check(entered.await(4,TimeUnit.SECONDS)&&e.session.hostJournal().pending(),"real serial journal pending");
    rejects(()->e.session.hostStart());check(field(e.app,"backgroundRecoveryAttempt")==null&&BackgroundSession.calls==0,"pending journal cannot borrow or retire");
    release.countDown();serialDone(e);android.os.Handler.drain();check(!e.session.hostJournal().pending(),"real journal callback acknowledged");
   });
   run("actual_model_executor_tail_blocks_background_borrow",()->{
    Env e=new Env(true);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);ThreadPoolExecutor pool=modelPool(e);
    pool.execute(()->{entered.countDown();try{release.await();}catch(InterruptedException x){Thread.currentThread().interrupt();}});pool.execute(()->{});
    check(entered.await(4,TimeUnit.SECONDS),"actual model executor active");rejects(()->e.session.hostStart());
    check(field(e.app,"backgroundRecoveryAttempt")==null&&!e.session.isRecovering()&&BackgroundSession.calls==0,"model tail rejects before worker and returns original barrier");
    release.countDown();await(()->pool.getActiveCount()==0&&pool.getQueue().isEmpty(),"real model executor drained");
   });
   run("actual_serial_executor_rejection_retains_barrier",()->{
    Env e=new Env(true);e.session.hostExecutor().shutdown();rejects(()->e.session.hostStart());assertReturned(e);
    check(BackgroundSession.calls==0&&BackgroundSession.hostLeasePresent,"rejection never entered cleanup port");
   });
   run("uncertain_accepted_submission_retains_until_actual_completion",()->{
    Env e=new Env(true);ExecutorService actual=e.session.hostExecutor();CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
    BackgroundSession.hostWork=c->{entered.countDown();release.await();c.check();return BackgroundSession.hostKnown();};
    set(e.session,"recoveryWorker",new ThrowAfterExecute(actual));rejects(()->e.session.hostStart());
    check(entered.await(4,TimeUnit.SECONDS),"uncertain submission actually entered worker");assertHeld(e);
    release.countDown();actual.submit(()->{}).get(4,TimeUnit.SECONDS);android.os.Handler.drain();assertReturned(e);
    check(e.background.accepts==1,"only actual later completion may accept and return");
   });
   run("duplicate_cleanup_cannot_submit_second_worker",()->{
    Env e=new Env(true);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
    BackgroundSession.hostWork=c->{entered.countDown();release.await();c.check();return BackgroundSession.hostKnown();};
    e.session.hostStart();check(entered.await(4,TimeUnit.SECONDS),"first worker entered");rejects(()->e.session.hostStart());
    check(BackgroundSession.calls==1,"only one business recovery worker");release.countDown();finishNormally(e);
   });
   run("actual_typed_acceptance_revalidates_receipt_ports",()->{
    Env e=new Env(true);BackgroundSession.Cleanup c=BackgroundSession.hostKnown();
    c.known=false;rejects(()->e.service.acceptBackgroundReconciliation(c));c.known=true;
    c.prelaunchRecovery=new Object();rejects(()->e.service.acceptBackgroundReconciliation(c));c.prelaunchRecovery=null;
    c.evidence.put("business_receipt_sha256","bad");rejects(()->e.service.acceptBackgroundReconciliation(c));c.evidence.put("business_receipt_sha256",HostFacts.RECEIPT);
    c.businessRecovery.persisted=false;rejects(()->e.service.acceptBackgroundReconciliation(c));c.businessRecovery.persisted=true;
    c.businessRecovery.originals=false;rejects(()->e.service.acceptBackgroundReconciliation(c));
    check(e.background.accepts==0,"no bad typed receipt reaches session accept");
   });
   run("actual_close_ownership_failure_remains_blocked",()->{
    Env e=new Env(true);e.session.hostStart();serialDone(e);
    Object foreign=field(e.originalBarrier,"handle");global().getClass().getMethod("set",Object.class).invoke(global(),foreign);
    android.os.Handler.drain();check(e.session.isBlocked()&&!e.session.isRecovering(),"close failure stays blocked");
    check(Boolean.TRUE.equals(field(e.app,"backgroundRecoveryCloseFailed"))&&!e.app.canAcknowledgeControlRecovery(),"actual failed-return latch prevents ACK");
    check(global().get()==foreign&&e.background.accepts==0,"foreign slot untouched and acceptance rejected");
   });
   run("startup_null_controller_uses_same_typed_lifecycle",()->{
    Env e=new Env(false);e.session.hostStart();finishNormally(e);
    check(e.service.ownedController==null&&e.service.taskBackground==null,"startup does not recreate prior controller or background instance");
    check(BackgroundSession.last.businessRecovery.persistedChecks==1&&BackgroundSession.last.businessRecovery.originalChecks==1,"startup typed receipt still revalidated");
    check(e.session.canAcknowledgeInterruption(),"startup cleanup still requires separate owner acknowledgement");
   });
   clean();System.out.println("PASS lifecycle_cases="+cases+" assertions="+assertions);
  }finally{
   clean();ExecutorService q=(ExecutorService)field(TaskCancellationQueue.processQueue(),"executor");
   q.shutdown();check(q.awaitTermination(4,TimeUnit.SECONDS),"final cancellation executor ended");
  }
 }
}
