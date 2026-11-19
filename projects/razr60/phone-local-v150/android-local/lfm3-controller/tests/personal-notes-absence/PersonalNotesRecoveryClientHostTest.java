package org.trillionnium.hepta.local;

import android.content.Context;
import android.net.LocalSocket;
import android.os.SystemClock;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.RecoveryControllerIdentity;

/** Actual client/BackgroundSession/PrivateFiles; only Android transport, PM and clock are synthetic. */
public final class PersonalNotesRecoveryClientHostTest {
    private static final org.trillionnium.hepta.background.PersonalNotesAbsenceHostTest.Fixture fixture;
    static {try{fixture=new org.trillionnium.hepta.background.PersonalNotesAbsenceHostTest.Fixture();}catch(Exception e){throw new ExceptionInInitializerError(e);}}
    private static int checks,assertions;
    private static final JSONArray names=new JSONArray();
    private static final String GEN="11111111-2222-4333-8444-555555555555",TASK="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    interface Work {void run()throws Exception;}
    private static void need(boolean value)throws Exception{assertions++;if(!value)throw new AssertionError("public client boundary");}
    private static void reject(Work run)throws Exception{try{run.run();}catch(Exception refused){assertions++;return;}throw new AssertionError("unconfirmed public recovery accepted");}
    private static void test(String name,Work work)throws Exception{
        LocalSocket.reset();LocalSocket.missing=true;FakePersonalNotesRecoveryProcess.reset();android.os.Looper.worker=true;
        android.provider.Settings.Global.boot=7;android.system.Os.failUnlink=false;android.system.Os.failFsyncPath=null;
        android.system.Os.corruptPublicArchiveOnSync=false;android.system.Os.afterPublicCommitSync=null;
        RecoveryControllerIdentity.changed=false;work.run();checks++;names.put(name);
    }
    private static final class Env implements AutoCloseable {
        final Path dir,task,journal;final Context context;final BackgroundSession session;
        final Map<Path,byte[]> originalFiles=new LinkedHashMap<Path,byte[]>();
        Env()throws Exception{
            dir=Files.createTempDirectory("hepta-public-recovery-host-").toRealPath();context=new Context(dir.toFile());
            JSONObject old=new JSONObject(new String(fixture.inputs.get("journal"),StandardCharsets.UTF_8));
            JSONObject owner=new JSONObject(new String(fixture.inputs.get("owner"),StandardCharsets.UTF_8));
            SystemClock.now=fixture.created;
            String instruction=owner.getString("instruction"),pkg="com.motorola.stylus";
            BackgroundTaskTarget chosen=BackgroundTaskTarget.resolveExplicitSelection(instruction,pkg,Collections.singleton(pkg));
            session=BackgroundSession.experimentalPublicOwnGroup(context,TASK,instruction,new BackgroundSession.Selection(chosen,false,true),new QualificationScopeConfig.FilesRoot(context));
            // Recreate only an already-failed in-memory object for typed-receipt acceptance tests.
            // Static reconciliation itself consumes authored synthetic original bytes below.
            field(session,"generation",GEN);field(session,"socketName",old.getString("socket"));field(session,"displayName",old.getString("display_name"));
            PublicOwnGroupPolicy.Scope scope=PublicOwnGroupPolicy.Scope.fromWire(old.getString("public_own_group_scope_wire"));field(session,"publicOwnGroupScope",scope);
            Field key=BackgroundSession.class.getDeclaredField("publicScopeOwner");key.setAccessible(true);Object ownerKey=key.get(session);
            PublicOwnGroupPolicy.LiveLease lease=new PublicOwnGroupPolicy.LiveLease(ownerKey,scope);lease.retire(ownerKey);field(session,"publicScopeLease",lease);
            field(session,"retired",true);field(session,"spawnAttempted",true);field(session,"bootstrapDispatched",true);field(session,"displayId",fixture.display);field(session,"brokerExitObserved",false);field(session,"state","CLEANUP_UNKNOWN");
            MobiMindPrivateFiles.directory(dir.resolve("control-tasks").toFile(),true);task=dir.resolve("control-tasks").resolve(TASK);MobiMindPrivateFiles.directory(task.toFile(),true);
            journal=dir.resolve(BackgroundSession.JOURNAL);MobiMindPrivateFiles.writeNew(journal.toFile(),fixture.inputs.get("journal"));
            MobiMindPrivateFiles.writeNew(dir.resolve("control-session.json").toFile(),fixture.control.toString().getBytes(StandardCharsets.UTF_8));
            for(String[] pair:new String[][]{{"owner","owner.json"},{"bootstrap","background-bootstrap.json"},{"cleanup","background-cleanup.json"},{"result","result.json"},{"broker_receipt","background-broker-"+GEN+".json"},{"broker_output","background-broker-"+GEN+".bin"}}){
                Path out=task.resolve(pair[1]);byte[] b=fixture.inputs.get(pair[0]);MobiMindPrivateFiles.writeNew(out.toFile(),b);originalFiles.put(out,b);}
            SystemClock.now=fixture.now;
        }
        void originalsUnchanged()throws Exception{for(Map.Entry<Path,byte[]> entry:originalFiles.entrySet())need(Arrays.equals(entry.getValue(),Files.readAllBytes(entry.getKey())));}
        long commits()throws Exception{try(java.util.stream.Stream<Path> stream=Files.list(task)){return stream.filter(p->p.getFileName().toString().matches("background-personal-notes-absence-[0-9a-f-]+\\.json")).count();}}
        long attempts()throws Exception{try(java.util.stream.Stream<Path> stream=Files.list(task)){return stream.filter(p->p.getFileName().toString().endsWith(".attempt.json")).count();}}
        public void close()throws IOException{
            android.system.Os.failUnlink=false;android.system.Os.failFsyncPath=null;android.system.Os.afterPublicCommitSync=null;
            try(java.util.stream.Stream<Path> stream=Files.walk(dir)){for(Path p:stream.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(p);}
        }
    }
    private static void field(Object object,String name,Object value)throws Exception{Field f=BackgroundSession.class.getDeclaredField(name);f.setAccessible(true);f.set(object,value);}
    private static BackgroundSession.ReconciliationCheck idle(){return ()->{if(FakePersonalNotesRecoveryProcess.cancelled)throw new IOException("synthetic owner epoch retired");};}
    public static void main(String[] args)throws Exception{
        if(args.length!=0)throw new IllegalArgumentException("self-contained synthetic host gate");
        test("synthetic_originals_new_receipt_then_only_exact_lease_retired",()->{try(Env e=new Env()){
            need(e.session.personalNotesRecoveryEligible());BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context,idle());
            need(c.known&&c.personalNotesRecovery!=null&&c.prelaunchRecovery==null&&c.postlaunchRecovery==null&&c.publicProfileRecovery==null);
            need(!Files.exists(e.journal)&&e.commits()==1&&FakePersonalNotesRecoveryProcess.calls==1&&LocalSocket.connections==0);
            need(!c.evidence.getBoolean("broker_released")&&!c.evidence.getBoolean("historical_broker_release_observed"));
            c.personalNotesRecovery.persist(e.context);need(e.commits()==1);e.originalsUnchanged();
            reject(()->e.session.acceptReconciliation(new JSONObject(c.evidence.toString())));
            reject(()->e.session.acceptReconciliation(new BackgroundSession.Cleanup(true,c.evidence)));
            e.session.acceptReconciliation(c);need(e.session.released());e.originalsUnchanged();
            need(BackgroundSession.reconcile(e.context,idle()).known&&FakePersonalNotesRecoveryProcess.calls==1);
        }});
        test("failed_checker_exit_preserves_old_failure_and_writes_failed_attempt",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.exit=70;reject(()->BackgroundSession.reconcile(e.context,idle()));
            need(Files.exists(e.journal)&&e.commits()==0&&e.attempts()==1&&LocalSocket.connections==0);e.originalsUnchanged();
            try(java.util.stream.Stream<Path> stream=Files.list(e.task)){Path p=stream.filter(x->x.getFileName().toString().endsWith(".attempt.json")).findFirst().get();
                JSONObject a=new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));need(!a.getBoolean("cleanup_known")&&!a.getBoolean("lease_retired")&&a.getInt("exit_code")==70
                        &&"NOTES_ABSENCE_SYNTHETIC_FAILURE".equals(a.getString("checker_error")));}
        }});
        test("trailing_stdout_rejected_without_lease_retirement",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.suffix="{}";reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("incomplete_eof_rejected_and_attempt_retained",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.readFailure=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0&&e.attempts()==1);e.originalsUnchanged();
        }});
        test("new_owned_checker_timeout_never_signals_old_pid",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.timeout=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0&&FakePersonalNotesRecoveryProcess.destroyed==1);e.originalsUnchanged();
        }});
        test("wrong_request_rejected",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.badNonce=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("epoch_changed_after_process_rejected",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.afterReply=()->FakePersonalNotesRecoveryProcess.cancelled=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("current_installed_apk_changed_rejected",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.afterReply=()->RecoveryControllerIdentity.changed=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("journal_changed_after_sampling_rejected",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.afterReply=()->{try{Files.write(e.journal,new byte[]{1});}catch(Exception x){throw new RuntimeException(x);}};
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("current_control_changed_after_sampling_rejected",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.afterReply=()->{try{Files.write(e.dir.resolve("control-session.json"),new byte[]{1});}catch(Exception x){throw new RuntimeException(x);}};
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("journal_replaced_same_bytes_inode_aba_rejected",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.afterReply=()->{try{byte[] b=Files.readAllBytes(e.journal);Path replacement=e.dir.resolve("replacement");MobiMindPrivateFiles.writeNew(replacement.toFile(),b);Files.move(replacement,e.journal,java.nio.file.StandardCopyOption.REPLACE_EXISTING);}catch(Exception x){throw new RuntimeException(x);}};
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("journal_changed_after_durable_receipt_cas_rejected",()->{try(Env e=new Env()){
            android.system.Os.afterPublicCommitSync=()->{try{Files.write(e.journal,new byte[]{1});}catch(Exception x){throw new RuntimeException(x);}};
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==1&&!e.session.released());e.originalsUnchanged();
        }});
        test("receipt_fsync_failure_keeps_old_lease",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.afterReply=()->android.system.Os.failFsyncPath=e.task.resolve("background-personal-notes-absence-"+FakePersonalNotesRecoveryProcess.lastRequest.requestId+".json").toString();
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&!e.session.released());e.originalsUnchanged();
        }});
        test("archive_corruption_keeps_old_lease",()->{try(Env e=new Env()){
            android.system.Os.corruptPublicArchiveOnSync=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&!e.session.released());e.originalsUnchanged();
        }});
        test("unlink_failure_keeps_old_lease_and_new_receipt",()->{try(Env e=new Env()){
            android.system.Os.failUnlink=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==1&&!e.session.released());e.originalsUnchanged();
        }});
        test("display_appears_after_samples_rejects_without_removal",()->{try(Env e=new Env()){
            FakePersonalNotesRecoveryProcess.afterReply=()->e.context.displays.displays.put(777,new android.view.Display(777,e.session.displayName));
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.context.displays.getDisplay(777)!=null);e.originalsUnchanged();
        }});
        test("same_typed_receipt_cannot_release_new_lease",()->{try(Env e=new Env()){
            BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context,idle());MobiMindPrivateFiles.writeNew(e.journal.toFile(),new byte[]{1});
            reject(()->e.session.acceptReconciliation(c));need(Files.exists(e.journal)&&!e.session.released());e.originalsUnchanged();
        }});
        test("notes_service_gate_preserves_each_independent_worker_and_web_lease",()->{try(Env e=new Env()){
            PersonalNotesRecoveryIdleFixture f=new PersonalNotesRecoveryIdleFixture(e.session);need(f.personalNotesReconciliationIdle(f.ownedController));
            need(!f.prelaunchReconciliationIdle(f.ownedController)&&!f.postlaunchReconciliationIdle(f.ownedController)&&!f.publicProfileReconciliationIdle(f.ownedController));
            f.pendingAction=true;need(!f.personalNotesReconciliationIdle(f.ownedController));f.pendingAction=false;
            f.pendingObservation=true;need(!f.personalNotesReconciliationIdle(f.ownedController));f.pendingObservation=false;
            f.pendingNative=true;need(!f.personalNotesReconciliationIdle(f.ownedController));f.pendingNative=false;
            f.capturePending=true;need(!f.personalNotesReconciliationIdle(f.ownedController));f.capturePending=false;
            f.taskWeb=new PersonalNotesRecoveryIdleFixture.Web();need(!f.personalNotesReconciliationIdle(f.ownedController));f.taskWeb=null;
            f.activeObservation=new Object();need(!f.personalNotesReconciliationIdle(f.ownedController));f.activeObservation=null;
            f.ownedController.running=true;need(!f.personalNotesReconciliationIdle(f.ownedController));f.ownedController.running=false;
            f.lease="different-task";need(!f.personalNotesReconciliationIdle(f.ownedController));f.lease=TASK;
            need(f.personalNotesReconciliationIdle(f.ownedController));e.originalsUnchanged();
        }});
        test("receipt_corruption_rejects_in_memory_acceptance",()->{try(Env e=new Env()){
            BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context,idle());Files.write(Paths.get(c.evidence.getString("personal_notes_receipt_path")),new byte[]{1});
            reject(()->e.session.acceptReconciliation(c));need(!e.session.released());e.originalsUnchanged();
        }});
        test("no_business_evidence_no_recovery_process",()->{try(Env e=new Env()){
            Files.delete(e.task.resolve("result.json"));reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&FakePersonalNotesRecoveryProcess.calls==0);
        }});
        test("dispatched_step_file_rejects_before_checker",()->{try(Env e=new Env()){
            MobiMindPrivateFiles.writeNew(e.task.resolve("step-00-action.json").toFile(),new byte[]{1});reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&FakePersonalNotesRecoveryProcess.calls==0);e.originalsUnchanged();
        }});
        test("ttl_before_expiry_retains_existing_close_path",()->{try(Env e=new Env()){
            SystemClock.now=e.session.expiresElapsed-1;BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context,idle());
            need(!c.known&&FakePersonalNotesRecoveryProcess.calls==0&&LocalSocket.connections>0&&Files.exists(e.journal));e.originalsUnchanged();
        }});
        System.out.println(new JSONObject().put("schema","hepta.personal-notes-recovery-client-host-tests.v1").put("passed",true).put("checks",checks)
                .put("assertions",assertions).put("cases",names).put("actual_client_except_owned_process_factory",true).put("actual_background_session",true)
                .put("android_transport_clock_pm_fixtures_synthetic",true).put("phone_contacted",false).put("android_runtime",false));
    }
}
