package org.trillionnium.hepta.local;

import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Actual Application and exact Engine reservation/admission/drain members.
 * Android/session/diagnostic flags and non-executed IO are explicit host ports.
 * No native exit, filesystem receipt, Android effect or cleanup proof is minted.
 */
public final class BackgroundRecoveryModelHostTest {
    private interface Checked {void run()throws Exception;}
    private static int cases,assertions;
    private static final List<LocalProbeApplication> apps=new ArrayList<LocalProbeApplication>();
    private static void check(boolean ok,String detail){assertions++;if(!ok)throw new AssertionError(detail);}
    private static void rejects(Checked call)throws Exception{
        boolean denied=false;try{call.run();}catch(IllegalStateException expected){denied=true;}
        check(denied,"expected exact production rejection");
    }
    private static Object field(Object owner,String name)throws Exception{
        Field f=owner.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(owner);
    }
    private static void set(Object owner,String name,Object value)throws Exception{
        Field f=owner.getClass().getDeclaredField(name);f.setAccessible(true);f.set(owner,value);
    }
    private static AtomicReference<?> global()throws Exception{
        Field f=LocalModelEngine.class.getDeclaredField("PROCESS_ACTIVE");f.setAccessible(true);
        return (AtomicReference<?>)f.get(null);
    }
    private static ThreadPoolExecutor executor(LocalProbeApplication a)throws Exception{
        return (ThreadPoolExecutor)field(a.modelEngine(),"executor");
    }
    private static LocalModelEngine.RecoveryReservation actual(LocalProbeApplication.BackgroundRecoveryReservation h)throws Exception{
        return (LocalModelEngine.RecoveryReservation)field(h,"reservation");
    }
    private static void awaitIdle(ThreadPoolExecutor pool)throws Exception{
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        while((pool.getActiveCount()!=0||!pool.getQueue().isEmpty())&&System.nanoTime()<end)Thread.sleep(1);
        check(pool.getActiveCount()==0&&pool.getQueue().isEmpty(),"actual host executor really drained");
    }
    private static void awaitCancellation()throws Exception{
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        while(TaskCancellationQueue.processQueue().pending()&&System.nanoTime()<end)Thread.sleep(1);
        check(!TaskCancellationQueue.processQueue().pending(),"actual cancellation queue drained");
    }
    private static void worker(Checked action)throws Exception{
        AtomicReference<Throwable> failed=new AtomicReference<Throwable>();
        Thread t=new Thread(()->{try{action.run();}catch(Throwable e){failed.set(e);}});
        t.start();t.join(3000);check(!t.isAlive(),"host worker ended");
        if(failed.get()!=null)throw new AssertionError("worker failed",failed.get());
    }
    private static LocalProbeApplication app(boolean blocked){
        LocalTaskSession.initialBlocked=blocked;LocalProbeApplication a=new LocalProbeApplication();a.onCreate();apps.add(a);return a;
    }
    private static LocalProbeApplication app(){return app(true);}
    private static void clean()throws Exception{
        for(LocalProbeApplication a:apps){
            a.modelEngine().close();
            ThreadPoolExecutor pool=executor(a);pool.shutdownNow();
            check(pool.awaitTermination(3,TimeUnit.SECONDS),"host executor shutdown");
        }
        awaitCancellation();apps.clear();
        // Fixture isolation only, after every host worker is joined. No child can be attached by these tests.
        global().set(null);
    }
    private static void run(String name,Checked action)throws Exception{
        clean();android.os.Looper.resetMain();android.os.Handler.reset();
        LocalTaskSession.initialBlocked=true;MobiMindModelEngine.initialBlocked=false;
        UiVenusModelEngine.initialBlocked=false;BackgroundPermissionSession.initialBlocked=false;
        int before=assertions;
        action.run();cases++;
        System.out.println("PASS case="+name+" assertions="+(assertions-before));
    }
    private static Object carrier(String nested)throws Exception{
        // Negative occupancy only. These host carriers have no operational or permission API.
        Constructor<?> c=Class.forName("org.trillionnium.hepta.local.LocalModelEngine$"+nested).getDeclaredConstructor();
        c.setAccessible(true);return c.newInstance();
    }
    private static void occupyWarm(LocalModelEngine engine,Object marker)throws Exception{
        Object ref=field(engine,"warmActive");
        ref.getClass().getMethod("set",Object.class).invoke(ref,marker);
    }
    private static CountDownLatch holdExecutor(LocalProbeApplication a,boolean queued)throws Exception{
        CountDownLatch started=new CountDownLatch(1),finish=new CountDownLatch(1);
        executor(a).execute(()->{started.countDown();try{finish.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}});
        check(started.await(3,TimeUnit.SECONDS),"real executor task entered");
        if(queued)executor(a).execute(()->{});
        return finish;
    }
    public static void main(String[] args)throws Exception{
        try{
            run("existing_barrier_borrow_check_and_close_retain",()->{
                LocalProbeApplication a=app();Object barrier=field(a,"recoveryBarrier");
                LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                h.check();worker(()->h.check());
                check(field(a,"recoveryBarrier")==barrier,"same startup barrier");
                check(a.modelEngine().isBusy(),"slot remains occupied");
                check(!a.canAcknowledgeControlRecovery(),"background borrow excludes ack");
                h.close();check(field(a,"recoveryBarrier")==barrier,"close retains original barrier");
                check(a.taskSession().blocked&&a.taskSession().retainedCalls==0,"no task acknowledgement or control callback");
                check(a.canAcknowledgeControlRecovery(),"later distinct acknowledgement is eligible");
            });
            run("direct_engine_start_and_diagnostic_cannot_overlap",()->{
                LocalProbeApplication a=app();LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                rejects(()->a.modelEngine().start(new LocalModelEngine.Request(),()->{}));
                rejects(()->a.modelEngine().reserveExternal(UUID.randomUUID().toString().replace("-","")));
                check(executor(a).getQueue().isEmpty()&&executor(a).getActiveCount()==0,"denied before native IO was enqueued");
                h.check();h.close();
            });
            run("main_thread_reservation_only",()->{
                LocalProbeApplication a=app();worker(()->rejects(()->a.reserveBackgroundRecovery()));
                check(field(a,"backgroundRecoveryAttempt")==null,"no worker-created reservation");
            });
            run("duplicate_background_and_control_borrows_refused",()->{
                LocalProbeApplication a=app();LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                rejects(()->a.reserveBackgroundRecovery());rejects(()->a.reserveControlRecovery());
                h.check();h.close();LocalModelEngine.RecoveryReservation later=a.reserveControlRecovery();
                check(later!=null,"actual existing control entry remains available only afterward");later.close();
            });
            run("control_borrow_blocks_background_without_replacing_owner",()->{
                LocalProbeApplication a=app();LocalModelEngine.RecoveryReservation control=a.reserveControlRecovery();
                Object owner=global().get();rejects(()->a.reserveBackgroundRecovery());
                check(global().get()==owner,"existing control owner unchanged");control.close();
            });
            run("unblocked_or_running_task_cannot_reserve",()->{
                LocalProbeApplication a=app(false);rejects(()->a.reserveBackgroundRecovery());
                check(global().get()==null,"unblocked refusal acquires nothing");
                a.taskSession().blocked=true;a.taskSession().running=true;
                rejects(()->a.reserveBackgroundRecovery());check(global().get()==null,"running refusal acquires nothing");
            });
            run("current_session_changes_reject_without_releasing_slot",()->{
                LocalProbeApplication a=app();LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                Object owner=global().get();a.taskSession().running=true;rejects(()->h.check());
                a.taskSession().running=false;a.taskSession().blocked=false;rejects(()->h.check());
                check(global().get()==owner,"failed checks do not release reservation");
                a.taskSession().blocked=true;h.close();
            });
            run("recovering_and_marker_removal_do_not_end_reservation",()->{
                LocalProbeApplication a=app();a.taskSession().recovering=true;a.taskSession().backgroundLease=true;
                LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                Object owner=global().get();a.taskSession().backgroundLease=false;h.check();
                check(global().get()==owner&&a.taskSession().recovering,"current marker hint cannot release model slot");
                h.close();check(a.taskSession().recovering,"caller owns recovering lifecycle");
            });
            run("permission_work_refused_before_and_during_borrow",()->{
                LocalProbeApplication a=app();a.backgroundPermissionPreparation().blocked=true;
                rejects(()->a.reserveBackgroundRecovery());a.backgroundPermissionPreparation().blocked=false;
                LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                a.backgroundPermissionPreparation().running=true;rejects(()->h.check());
                a.backgroundPermissionPreparation().running=false;h.close();
            });
            run("visual_and_ui_venus_work_refused",()->{
                LocalProbeApplication a=app();a.mobiMindDiagnostic().busy=true;rejects(()->a.reserveBackgroundRecovery());
                a.mobiMindDiagnostic().busy=false;LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                a.uiVenusDiagnostic().blocked=true;rejects(()->h.check());a.uiVenusDiagnostic().blocked=false;h.close();
            });
            run("settings_ui_busy_refused_without_borrow",()->{
                LocalProbeApplication a=app();a.modelSettings().hostBusy=true;Object owner=global().get();
                rejects(()->a.reserveBackgroundRecovery());check(global().get()==owner,"settings refusal leaves startup barrier");
                a.modelSettings().hostBusy=false;LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                a.modelSettings().hostBusy=true;rejects(()->h.check());a.modelSettings().hostBusy=false;h.close();
            });
            run("actual_import_slot_refuses_then_allows_background_retry",()->{
                LocalProbeApplication a=app(false);a.modelImport().beginHostIo();a.taskSession().blocked=true;
                Object owner=global().get();rejects(()->a.reserveBackgroundRecovery());
                check(global().get()==owner,"import shared owner retained");
                a.modelImport().finishHostIo();LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                h.check();h.close();
            });
            run("actual_running_executor_tail_refuses_and_retains_for_retry",()->{
                LocalProbeApplication a=app(false);a.taskSession().blocked=true;
                CountDownLatch finish=holdExecutor(a,false);
                rejects(()->a.reserveBackgroundRecovery());Object barrier=field(a,"recoveryBarrier");
                check(barrier!=null&&field(a,"backgroundRecoveryAttempt")==null,"failed admission returns newly retained barrier");
                finish.countDown();awaitIdle(executor(a));
                LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();h.check();h.close();
                check(field(a,"recoveryBarrier")==barrier,"retry uses exact retained barrier");
            });
            run("actual_running_and_queued_work_fail_current_drain",()->{
                LocalProbeApplication a=app();LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                CountDownLatch finish=holdExecutor(a,true);
                check(executor(a).getActiveCount()==1&&executor(a).getQueue().size()==1,"real active and queued tail present");
                rejects(()->h.check());finish.countDown();awaitIdle(executor(a));h.check();h.close();
            });
            run("warm_occupancy_refuses_and_retains_barrier",()->{
                LocalProbeApplication a=app();occupyWarm(a.modelEngine(),carrier("WarmTask"));
                rejects(()->a.reserveBackgroundRecovery());check(field(a,"backgroundRecoveryAttempt")==null,"failed warm drain returned borrow");
                occupyWarm(a.modelEngine(),null);LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();h.check();h.close();
            });
            run("settings_reservation_occupancy_refuses_and_retries",()->{
                LocalProbeApplication a=app();set(a.modelEngine(),"settingsReservation",carrier("SettingsReservation"));
                rejects(()->a.reserveBackgroundRecovery());set(a.modelEngine(),"settingsReservation",null);
                LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();h.check();h.close();
            });
            run("captured_cancel_rejects_then_fresh_borrow_succeeds",()->{
                LocalProbeApplication a=app();LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                a.modelEngine().cancelActive();rejects(()->h.check());awaitCancellation();h.close();
                LocalProbeApplication.BackgroundRecoveryReservation next=a.reserveBackgroundRecovery();next.check();next.close();
            });
            run("wrong_engine_and_wrong_app_cannot_borrow_foreign_slot",()->{
                LocalProbeApplication a=app();LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                LocalModelEngine.RecoveryReservation actual=actual(h);
                LocalProbeApplication foreign=app(false);foreign.taskSession().blocked=true;
                rejects(()->foreign.modelEngine().requireBackgroundRecoveryQuiescent(actual));
                rejects(()->foreign.reserveBackgroundRecovery());
                check(!foreign.modelEngine().backgroundRecoveryReturnedToBarrier(actual),"foreign engine cannot certify close");
                h.check();h.close();
            });
            run("close_from_worker_is_idempotent_and_has_no_ack_callback",()->{
                LocalProbeApplication a=app();LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                LocalModelEngine.RecoveryReservation actual=actual(h);check(!a.modelEngine().backgroundRecoveryReturnedToBarrier(actual),"active is not returned");
                worker(()->h.close());h.close();
                check(a.modelEngine().backgroundRecoveryReturnedToBarrier(actual),"actual close restored both slots");
                check(a.taskSession().retainedCalls==0&&a.taskSession().blocked&&a.modelEngine().isBusy(),"no old control callback or auto-release");
                rejects(()->h.check());
            });
            run("engine_close_never_turns_into_cleanup_ack",()->{
                LocalProbeApplication a=app();LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                a.modelEngine().close();awaitCancellation();rejects(()->h.check());h.close();
                check(a.taskSession().blocked&&!a.canAcknowledgeControlRecovery(),"closed engine remains blocked");
            });
            run("foreign_slot_is_not_overwritten_on_failed_return",()->{
                LocalProbeApplication a=app();LocalProbeApplication.BackgroundRecoveryReservation h=a.reserveBackgroundRecovery();
                LocalModelEngine.RunHandle foreign=(LocalModelEngine.RunHandle)field(field(a,"recoveryBarrier"),"handle");
                global().getClass().getMethod("set",Object.class).invoke(global(),foreign);
                rejects(()->h.check());rejects(()->h.close());
                check(global().get()==foreign,"foreign non-null slot not overwritten");
                check(Boolean.TRUE.equals(field(a,"backgroundRecoveryCloseFailed")),"failed return stays explicitly blocked");
                rejects(()->a.reserveBackgroundRecovery());check(!a.canAcknowledgeControlRecovery(),"no control acknowledgement after failed return");
            });
            clean();
            System.out.println("PASS background_cases="+cases+" assertions="+assertions);
        }finally{
            clean();
            ExecutorService cancellation=(ExecutorService)field(TaskCancellationQueue.processQueue(),"executor");
            cancellation.shutdown();check(cancellation.awaitTermination(3,TimeUnit.SECONDS),"final actual cancellation executor closed");
        }
    }
}
