package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/** Actual Application + exact extracted Engine recovery path; dependencies are explicit host fixtures. */
public final class RecoveryApplicationHostTest {
    private static int cases,assertions;
    private interface Checked {void run()throws Exception;}
    private static void check(boolean yes,String message){assertions++;if(!yes)throw new AssertionError(message);}
    private static void same(Object a,Object b,String message){check(a==b,message);}
    private static void rejects(Checked work)throws Exception{
        boolean denied=false;try{work.run();}catch(IllegalStateException expected){denied=true;}
        check(denied,"expected recovery rejection");
    }
    private static Object field(Object object,String name)throws Exception{
        java.lang.reflect.Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);
    }
    /** Host scheduling barrier only; Stop itself stays the exact nonblocking production method. */
    private static void awaitCancellation(LocalProbeApplication app,Object lease)throws Exception{
        LocalModelEngine.RunHandle owner=(LocalModelEngine.RunHandle)field(lease,"handle");
        TaskCancellationQueue.Ticket ticket=(TaskCancellationQueue.Ticket)field(app.modelEngine(),"lastCancellation");
        check(ticket!=null&&ticket.ownedBy(owner)&&ticket.taskId==null&&owner.runId.equals(ticket.runId),
                "await only the exact captured recovery/external run");
        check(ticket.awaitDrain(2000),"real cancellation worker did not drain within host bound");
        check(!TaskCancellationQueue.processQueue().pending(),"drained cancellation still owns process admission");
    }
    private static void shutdownCancellationWorker()throws Exception{
        java.util.concurrent.ExecutorService executor=(java.util.concurrent.ExecutorService)
                field(TaskCancellationQueue.processQueue(),"executor");
        executor.shutdown();
        if(!executor.awaitTermination(2,java.util.concurrent.TimeUnit.SECONDS))
            throw new AssertionError("host cancellation executor did not terminate");
        if(TaskCancellationQueue.processQueue().pending())throw new AssertionError("host cancellation remained pending");
    }
    private static void reset()throws Exception{
        check(!TaskCancellationQueue.processQueue().pending(),"prior exact cancellation must drain before fixture reset");
        android.os.Looper.resetMain();android.os.Handler.reset();
        LocalTaskSession.initialBlocked=true;
        MobiMindModelEngine.initialBlocked=false;UiVenusModelEngine.initialBlocked=false;
        BackgroundPermissionSession.initialBlocked=false;
        java.lang.reflect.Field f=LocalModelEngine.class.getDeclaredField("PROCESS_ACTIVE");f.setAccessible(true);
        ((AtomicReference<?>)f.get(null)).set(null);
    }
    private static LocalProbeApplication app()throws Exception{
        reset();LocalProbeApplication a=new LocalProbeApplication();a.onCreate();return a;
    }
    private static void worker(Checked work)throws Exception{
        AtomicReference<Throwable> failure=new AtomicReference<Throwable>();
        Thread thread=new Thread(()->{try{work.run();}catch(Throwable e){failure.set(e);}});
        thread.start();thread.join(5000);check(!thread.isAlive(),"worker ended");
        if(failure.get()!=null)throw new AssertionError("worker failure",failure.get());
    }
    private static final class Store implements RecoveryJournalTransaction.Store {
        final Map<String,byte[]> data=new HashMap<String,byte[]>();
        @Override public byte[] read(String name){byte[] b=data.get(name);return b==null?null:b.clone();}
        @Override public List<String> pendingBarriers(){
            List<String> out=new ArrayList<String>();
            for(String name:data.keySet())if(name.startsWith(RecoveryJournalTransaction.PENDING_PREFIX))out.add(name);
            return out;
        }
        @Override public void create(String name,byte[] bytes){
            if(data.containsKey(name))throw new IllegalStateException("exclusive create failed");data.put(name,bytes.clone());
        }
        @Override public void replaceActive(byte[] expected,byte[] replacement,String tx){
            if(!Arrays.equals(expected,read(RecoveryJournalTransaction.ACTIVE)))throw new IllegalStateException("active changed");
            data.put(RecoveryJournalTransaction.ACTIVE,replacement.clone());
        }
        @Override public void removeIfEqual(String name,byte[] expected){
            if(!Arrays.equals(expected,read(name)))throw new IllegalStateException("remove changed");data.remove(name);
        }
        @Override public void sync(){}
    }
    private static RecoveryJournalTransaction.Proof proof(int uid,String tx)throws Exception{
        Store store=new Store();
        store.data.put(RecoveryJournalTransaction.ACTIVE,"prior".getBytes(StandardCharsets.UTF_8));
        store.data.put(RecoveryJournalTransaction.LATCH,"interrupted".getBytes(StandardCharsets.UTF_8));
        List<RecoveryQuiescence.Sample> samples=Arrays.asList(
                new RecoveryQuiescence.Sample(uid,77,1234,1000,0,true),
                new RecoveryQuiescence.Sample(uid,77,1234,1750,0,true),
                new RecoveryQuiescence.Sample(uid,77,1234,2500,0,true));
        final long[] at={2500};
        return RecoveryJournalTransaction.acknowledge(store,uid,77,tx,UUID.randomUUID().toString().replace("-",""),
                123456,samples,()->{},()->new RecoveryQuiescence.Sample(uid,77,1234,(at[0]+=750),0,true),
                ack->"{\"fixture\":\"idle bytes; Session policy tested separately\"}".getBytes(StandardCharsets.UTF_8));
    }
    private static void install(LocalProbeApplication app,LocalModelEngine.RecoveryReservation reservation)throws Exception{
        app.completeControlRecovery(reservation,proof(10001,reservation.transactionId()),()->app.taskSession().blocked=false);
    }
    private static void run(String name,Checked test)throws Exception{
        test.run();cases++;System.out.println("PASS "+name);
    }
    private static LocalProbeApplication idleApp()throws Exception{
        reset();LocalTaskSession.initialBlocked=false;LocalProbeApplication a=new LocalProbeApplication();a.onCreate();return a;
    }
    private static void permissionCases()throws Exception{
        cases=0;assertions=0;
        run("uninitialized_or_foreign_application_fails_closed",()->{
            reset();LocalProbeApplication uninitialized=new LocalProbeApplication();
            check(uninitialized.permissionPreparationBlocksWork(),"unclassified permission state blocks");
            check(LocalProbeApplication.permissionPreparationBlocks(new android.content.Context()),"foreign Context blocks");
            rejects(()->LocalProbeApplication.requirePermissionPreparationIdle(uninitialized));
            LocalProbeApplication a=idleApp();
            android.content.Context service=new android.content.Context(){@Override public android.content.Context getApplicationContext(){return a;}};
            check(!LocalProbeApplication.permissionPreparationBlocks(service),"owned application Context accepted");
        });
        run("permission_only_block_does_not_create_control_barrier",()->{
            reset();LocalTaskSession.initialBlocked=false;BackgroundPermissionSession.initialBlocked=true;
            LocalProbeApplication a=new LocalProbeApplication();a.onCreate();
            check(a.modelEngine().isBusy(),"independent permission block appears busy");
            same(field(a,"recoveryBarrier"),null,"permission block is not a control recovery barrier");
            check(!a.taskSession().blocked,"permission block does not rewrite task state");
            check(!a.canAcknowledgeControlRecovery(),"control cannot acknowledge permission block");
            rejects(()->a.prepareBackgroundPermissionFromOwnerButton());
            check(a.backgroundPermissionPreparation().starts==0,"blocked permission never launches");
        });
        run("permission_block_preserves_exact_existing_control_barrier",()->{
            reset();BackgroundPermissionSession.initialBlocked=true;LocalProbeApplication a=new LocalProbeApplication();a.onCreate();
            Object barrier=field(a,"recoveryBarrier");check(barrier!=null,"original task barrier is still constructed");
            check(!a.canAcknowledgeControlRecovery(),"permission block gates recovery borrow");
            rejects(()->a.reserveControlRecovery());
            a.backgroundPermissionPreparation().blocked=false;
            same(field(a,"recoveryBarrier"),barrier,"permission classification does not replace task barrier");
            check(a.taskSession().blocked&&a.canAcknowledgeControlRecovery(),"old task still requires explicit recovery");
            LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();r.close();
            same(field(a,"recoveryBarrier"),barrier,"failed recovery returns exact old barrier");
        });
        run("owner_button_reserves_real_external_slot_once",()->{
            LocalProbeApplication a=idleApp();BackgroundPermissionSession p=a.backgroundPermissionPreparation();
            a.prepareBackgroundPermissionFromOwnerButton();
            check(p.running&&p.starts==1&&a.modelEngine().isBusy(),"one visible preparation owns slot");
            same(a.backgroundPermissionPreparation(),p,"Application retains same preparation Session");
            rejects(()->a.prepareBackgroundPermissionFromOwnerButton());
            rejects(()->a.modelEngine().reserveExternal("11111111111111111111111111111111"));
            rejects(()->a.modelEngine().reserveRecoveryBarrier());
            check(p.starts==1,"refused overlaps do not start another preparation");
            p.observeNoStartAndPublishTerminal();check(!a.modelEngine().isBusy(),"own no-start terminal releases own slot");
            check(!a.taskSession().blocked&&!a.taskSession().running,"permission flow does not start or block task");
        });
        run("owner_button_refuses_every_existing_task_state",()->{
            for(int state=0;state<4;state++){
                LocalProbeApplication a=idleApp();LocalTaskSession t=a.taskSession();
                if(state==0)t.running=true;if(state==1)t.blocked=true;if(state==2)t.recovering=true;if(state==3)t.backgroundLease=true;
                rejects(()->a.prepareBackgroundPermissionFromOwnerButton());
                check(a.backgroundPermissionPreparation().starts==0,"task state "+state+" prevents preparation");
                check(t.running==(state==0)&&t.blocked==(state==1)&&t.recovering==(state==2)&&t.backgroundLease==(state==3),"task state preserved");
            }
        });
        run("owner_button_refuses_both_diagnostic_owners",()->{
            for(int state=0;state<4;state++){
                LocalProbeApplication a=idleApp();
                if(state==0)a.mobiMindDiagnostic().busy=true;if(state==1)a.mobiMindDiagnostic().blocked=true;
                if(state==2)a.uiVenusDiagnostic().busy=true;if(state==3)a.uiVenusDiagnostic().blocked=true;
                rejects(()->a.prepareBackgroundPermissionFromOwnerButton());
                check(a.backgroundPermissionPreparation().starts==0,"diagnostic state "+state+" prevents preparation");
            }
        });
        run("permission_and_control_recovery_cannot_share_slot",()->{
            LocalProbeApplication a=app();LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();
            rejects(()->a.prepareBackgroundPermissionFromOwnerButton());
            check(a.backgroundPermissionPreparation().starts==0,"borrowed control slot excludes preparation");
            r.close();check(a.taskSession().blocked,"preparation rejection leaves old recovery untouched");
        });
        run("direct_engine_recovery_entries_check_permission_gate",()->{
            LocalProbeApplication a=app();LocalModelEngine model=a.modelEngine();
            LocalModelEngine.RecoveryBarrier barrier=(LocalModelEngine.RecoveryBarrier)field(a,"recoveryBarrier");
            a.backgroundPermissionPreparation().blocked=true;
            check(!model.canReserveRecovery(barrier),"direct eligibility denies permission block");
            rejects(()->model.reserveRecovery(barrier));
            same(field(a,"recoveryBarrier"),barrier,"denied direct reserve preserves barrier");
            a.backgroundPermissionPreparation().blocked=false;
            check(model.canReserveRecovery(barrier),"own old barrier remains available after independent gate ends");
        });
        run("permission_change_during_recovery_install_prevents_commit",()->{
            LocalProbeApplication a=app();Object barrier=field(a,"recoveryBarrier");
            LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();RecoveryJournalTransaction.Proof p=proof(10001,r.transactionId());
            rejects(()->a.completeControlRecovery(r,p,()->{a.taskSession().blocked=false;a.backgroundPermissionPreparation().blocked=true;}));
            r.close();same(field(a,"recoveryBarrier"),barrier,"changed permission cannot release original barrier");
            check(a.taskSession().blocked&&!a.canAcknowledgeControlRecovery(),"failed fresh permission check reblocks task");
            a.backgroundPermissionPreparation().blocked=false;check(a.canAcknowledgeControlRecovery(),"subsequent explicit recovery remains possible");
        });
        run("direct_external_entry_denies_gate_without_creating_slot",()->{
            LocalProbeApplication a=idleApp();a.backgroundPermissionPreparation().blocked=true;
            rejects(()->a.modelEngine().reserveExternal("22222222222222222222222222222222"));
            a.backgroundPermissionPreparation().blocked=false;check(!a.modelEngine().isBusy(),"denied external call never occupies slot");
            LocalModelEngine.ExternalRunLease lease=a.modelEngine().reserveExternal("33333333333333333333333333333333");
            lease.releaseAfterTerminalPublication(false);check(a.modelEngine().isBusy(),"unknown cleanup retains actual slot");
            rejects(()->a.prepareBackgroundPermissionFromOwnerButton());
            lease.releaseAfterTerminalPublication(true);check(!a.modelEngine().isBusy(),"only owned terminal releases actual slot");
        });
        run("permission_owner_button_is_main_thread_only",()->{
            LocalProbeApplication a=idleApp();worker(()->rejects(()->a.prepareBackgroundPermissionFromOwnerButton()));
            check(a.backgroundPermissionPreparation().starts==0&&!a.modelEngine().isBusy(),"off-main owner call has no effects");
        });
        run("application_termination_cancels_but_does_not_fake_cleanup",()->{
            LocalProbeApplication a=idleApp();a.prepareBackgroundPermissionFromOwnerButton();
            BackgroundPermissionSession p=a.backgroundPermissionPreparation();LocalModelEngine.ExternalRunLease lease=p.lease;
            a.onTerminate();check(p.closed&&lease.isCancellationRequested(),"Application closes and cancels owned preparation");
            check(a.modelEngine().isBusy()&&p.running,"termination does not claim process cleanup or release slot");
            lease.releaseAfterTerminalPublication(true);p.running=false;
            awaitCancellation(a,lease);
            check(!a.modelEngine().isBusy(),"explicit fixture no-start terminal can settle cancelled owned slot");
        });
        System.out.println("PASS permission_cases="+cases+" assertions="+assertions);
    }
    public static void main(String[] args)throws Exception{
        try{runCases();}finally{shutdownCancellationWorker();}
    }
    private static void runCases()throws Exception{
        run("control_startup_barrier_can_be_borrowed",()->{
            LocalProbeApplication a=app();check(a.modelEngine().isBusy(),"startup slot held");check(a.canAcknowledgeControlRecovery(),"control confirmation allowed");
            LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();check(r.transactionId().matches("[0-9a-f]{32}"),"fresh UUID");
            check(!r.isCancellationRequested(),"fresh cancellation flag");r.close();check(a.taskSession().blocked,"failure remains blocked");
        });
        run("ordinary_idle_cannot_create_recovery",()->{
            reset();LocalTaskSession.initialBlocked=false;LocalProbeApplication a=new LocalProbeApplication();a.onCreate();
            check(!a.modelEngine().isBusy(),"no startup barrier");check(!a.canAcknowledgeControlRecovery(),"ordinary idle is not interrupted");
            rejects(()->a.reserveControlRecovery());
        });
        run("new_control_block_can_acquire_no_child_barrier",()->{
            reset();LocalTaskSession.initialBlocked=false;LocalProbeApplication a=new LocalProbeApplication();a.onCreate();a.taskSession().blocked=true;
            LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();check(a.modelEngine().isBusy(),"fresh barrier borrowed");r.close();check(a.canAcknowledgeControlRecovery(),"retry allowed");
        });
        run("both_diagnostic_owners_block_control_recovery",()->{
            reset();MobiMindModelEngine.initialBlocked=true;LocalProbeApplication a=new LocalProbeApplication();a.onCreate();
            check(!a.canAcknowledgeControlRecovery(),"Mobi blocked");rejects(()->a.reserveControlRecovery());
            reset();UiVenusModelEngine.initialBlocked=true;LocalProbeApplication b=new LocalProbeApplication();b.onCreate();
            check(!b.canAcknowledgeControlRecovery(),"UiVenus blocked");rejects(()->b.reserveControlRecovery());
        });
        run("busy_diagnostic_cannot_be_acknowledged_away",()->{
            LocalProbeApplication a=app();a.uiVenusDiagnostic().busy=true;
            check(!a.canAcknowledgeControlRecovery(),"UiVenus running");rejects(()->a.reserveControlRecovery());
            a.uiVenusDiagnostic().busy=false;a.mobiMindDiagnostic().busy=true;
            check(!a.canAcknowledgeControlRecovery(),"Mobi running");rejects(()->a.reserveControlRecovery());
        });
        run("commit_intent_does_not_clear_application_barrier",()->{
            LocalProbeApplication a=app();Object barrier=field(a,"recoveryBarrier");LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();
            install(a,r);same(field(a,"recoveryBarrier"),barrier,"barrier retained before close");
            check(a.modelEngine().isBusy(),"slot still occupied");check(!a.canAcknowledgeControlRecovery(),"same attempt not reborrowed");
            r.close();same(field(a,"recoveryBarrier"),null,"actual successful close clears reference");
            check(!a.modelEngine().isBusy(),"actual successful close releases");check(!a.canAcknowledgeControlRecovery(),"new idle not recovery eligible");
        });
        run("late_cancel_restores_barrier_and_fresh_retry",()->{
            LocalProbeApplication a=app();Object barrier=field(a,"recoveryBarrier");LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();
            install(a,r);a.modelEngine().cancelActive();r.close();
            same(field(a,"recoveryBarrier"),barrier,"cancel keeps exact barrier");check(a.modelEngine().isBusy(),"cancel keeps slot closed");
            check(a.taskSession().blocked&&a.taskSession().retainedCalls==1,"cancel marks session blocked");
            awaitCancellation(a,r);
            LocalModelEngine.RecoveryReservation next=a.reserveControlRecovery();
            check(!next.transactionId().equals(r.transactionId()),"retry new UUID");check(!next.isCancellationRequested(),"retry fresh cancel flag");
            next.close();
        });
        run("worker_close_posts_and_keeps_reference_until_main",()->{
            LocalProbeApplication a=app();Object barrier=field(a,"recoveryBarrier");LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();install(a,r);
            worker(()->{a.modelEngine().cancelActive();r.close();});
            same(field(a,"recoveryBarrier"),barrier,"worker notification cannot clear reference");check(a.modelEngine().isBusy(),"worker rollback held");
            check(android.os.Handler.pending()==1,"main notification posted");check(a.taskSession().retainedCalls==0,"Session callback not on worker");
            android.os.Handler.drain();check(a.taskSession().blocked&&a.taskSession().retainedCalls==1,"main callback blocks");
            awaitCancellation(a,r);
            check(a.canAcknowledgeControlRecovery(),"retry available after main handling");
        });
        run("successful_worker_close_clears_only_from_actual_receipt",()->{
            LocalProbeApplication a=app();Object barrier=field(a,"recoveryBarrier");LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();install(a,r);
            worker(()->r.close());same(field(a,"recoveryBarrier"),barrier,"reference waits for main receipt");
            check(!a.modelEngine().isBusy(),"actual close released slot");android.os.Handler.drain();
            same(field(a,"recoveryBarrier"),null,"main receipt clears successful barrier");check(a.taskSession().retainedCalls==0,"success not reblocked");
        });
        run("refused_main_post_reconciles_on_next_main_entry",()->{
            LocalProbeApplication a=app();Object barrier=field(a,"recoveryBarrier");LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();install(a,r);
            android.os.Handler.acceptPosts=false;worker(()->{a.modelEngine().cancelActive();r.close();});
            same(field(a,"recoveryBarrier"),barrier,"failed post does not discard owner");awaitCancellation(a,r);check(a.canAcknowledgeControlRecovery(),"next main entry reconciles");
            check(a.taskSession().retainedCalls==1,"retained callback eventually runs");check(a.taskSession().blocked,"session blocked");
        });
        run("stale_posted_notification_cannot_clear_new_attempt",()->{
            LocalProbeApplication a=app();LocalModelEngine.RecoveryReservation old=a.reserveControlRecovery();install(a,old);
            worker(()->{a.modelEngine().cancelActive();old.close();});
            awaitCancellation(a,old);
            check(a.canAcknowledgeControlRecovery(),"main settles old close before post");
            LocalModelEngine.RecoveryReservation next=a.reserveControlRecovery();android.os.Handler.drain();
            same(field(a,"controlRecoveryAttempt"),next,"old notification ignored");check(!next.isCancellationRequested(),"new attempt remains owned");next.close();
        });
        run("retained_callback_exception_never_releases_barrier",()->{
            LocalProbeApplication a=app();Object barrier=field(a,"recoveryBarrier");LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();install(a,r);
            a.taskSession().failRetained=true;a.modelEngine().cancelActive();r.close();
            same(field(a,"recoveryBarrier"),barrier,"exception retains reference");check(a.modelEngine().isBusy(),"exception retains slot");
            check(a.taskSession().blocked,"callback blocked first");check(!a.canAcknowledgeControlRecovery(),"unknown callback refuses new borrow");
            rejects(()->a.reserveControlRecovery());
            awaitCancellation(a,r);
        });
        run("retained_callback_reentry_does_not_reconcile_twice",()->{
            LocalProbeApplication a=app();LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();install(a,r);
            a.taskSession().duringRetained=()->check(!a.canAcknowledgeControlRecovery(),"reentrant eligibility sees current attempt");
            a.modelEngine().cancelActive();r.close();check(a.taskSession().retainedCalls==1,"single callback");awaitCancellation(a,r);check(a.canAcknowledgeControlRecovery(),"retry after callback return");
        });
        run("install_exception_after_state_change_is_reblocked",()->{
            LocalProbeApplication a=app();Object barrier=field(a,"recoveryBarrier");LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();
            RecoveryJournalTransaction.Proof p=proof(10001,r.transactionId());
            rejects(()->a.completeControlRecovery(r,p,()->{a.taskSession().blocked=false;throw new IllegalStateException("injected install failure");}));
            r.close();same(field(a,"recoveryBarrier"),barrier,"install error retains barrier");
            check(a.taskSession().blocked,"partial installation reblocked");check(a.canAcknowledgeControlRecovery(),"new explicit retry available");
        });
        run("proof_uid_and_transaction_are_bound",()->{
            LocalProbeApplication a=app();LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();final int[] installs={0};
            RecoveryJournalTransaction.Proof wrongUid=proof(10002,r.transactionId()),wrongTx=proof(10001,UUID.randomUUID().toString().replace("-",""));
            rejects(()->a.completeControlRecovery(r,wrongUid,()->installs[0]++));
            rejects(()->a.completeControlRecovery(r,wrongTx,()->installs[0]++));
            check(installs[0]==0,"foreign proof never installs");r.close();check(a.modelEngine().isBusy(),"foreign proof never releases");
        });
        run("precommit_cancel_never_runs_install",()->{
            LocalProbeApplication a=app();LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();RecoveryJournalTransaction.Proof p=proof(10001,r.transactionId());
            a.modelEngine().cancelActive();final int[] installs={0};rejects(()->a.completeControlRecovery(r,p,()->installs[0]++));
            check(installs[0]==0,"cancel prevents install");r.close();awaitCancellation(a,r);check(a.canAcknowledgeControlRecovery(),"fresh retry allowed");
        });
        run("diagnostic_change_during_install_prevents_commit",()->{
            LocalProbeApplication a=app();LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();RecoveryJournalTransaction.Proof p=proof(10001,r.transactionId());
            rejects(()->a.completeControlRecovery(r,p,()->{a.taskSession().blocked=false;a.uiVenusDiagnostic().busy=true;}));
            r.close();check(a.modelEngine().isBusy()&&a.taskSession().blocked,"no release after competing diagnostic");
            check(!a.canAcknowledgeControlRecovery(),"busy diagnostic still blocks");
        });
        run("old_close_is_idempotent_after_retry",()->{
            LocalProbeApplication a=app();LocalModelEngine.RecoveryReservation old=a.reserveControlRecovery();old.close();
            LocalModelEngine.RecoveryReservation next=a.reserveControlRecovery();old.close();
            same(field(a,"controlRecoveryAttempt"),next,"old close leaves new reference");check(!next.isCancellationRequested(),"old close does not cancel retry");next.close();
        });
        System.out.println("PASS cases="+cases+" assertions="+assertions);
        permissionCases();
    }
}
