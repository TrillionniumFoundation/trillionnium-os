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
    private static void reset()throws Exception{
        android.os.Looper.resetMain();android.os.Handler.reset();
        LocalTaskSession.initialBlocked=true;
        MobiMindModelEngine.initialBlocked=false;UiVenusModelEngine.initialBlocked=false;
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
    public static void main(String[] args)throws Exception{
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
            same(field(a,"recoveryBarrier"),barrier,"failed post does not discard owner");check(a.canAcknowledgeControlRecovery(),"next main entry reconciles");
            check(a.taskSession().retainedCalls==1,"retained callback eventually runs");check(a.taskSession().blocked,"session blocked");
        });
        run("stale_posted_notification_cannot_clear_new_attempt",()->{
            LocalProbeApplication a=app();LocalModelEngine.RecoveryReservation old=a.reserveControlRecovery();install(a,old);
            worker(()->{a.modelEngine().cancelActive();old.close();});
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
        });
        run("retained_callback_reentry_does_not_reconcile_twice",()->{
            LocalProbeApplication a=app();LocalModelEngine.RecoveryReservation r=a.reserveControlRecovery();install(a,r);
            a.taskSession().duringRetained=()->check(!a.canAcknowledgeControlRecovery(),"reentrant eligibility sees current attempt");
            a.modelEngine().cancelActive();r.close();check(a.taskSession().retainedCalls==1,"single callback");check(a.canAcknowledgeControlRecovery(),"retry after callback return");
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
            check(installs[0]==0,"cancel prevents install");r.close();check(a.canAcknowledgeControlRecovery(),"fresh retry allowed");
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
    }
}
