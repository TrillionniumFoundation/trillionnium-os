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
public final class PublicProfileRecoveryClientHostTest {
    private static Path fixture;
    private static int checks,assertions;
    private static final JSONArray names=new JSONArray();
    private static final String GEN="2a746961-06d0-4a8e-9f53-2d34cadbaa99",TASK="9579cd438a7f46b598c2c21b714f02b3";
    interface Work {void run()throws Exception;}
    private static void need(boolean value)throws Exception{assertions++;if(!value)throw new AssertionError("public client boundary");}
    private static void reject(Work run)throws Exception{try{run.run();}catch(Exception refused){assertions++;return;}throw new AssertionError("unconfirmed public recovery accepted");}
    private static void test(String name,Work work)throws Exception{
        LocalSocket.reset();LocalSocket.missing=true;FakePublicRecoveryProcess.reset();android.os.Looper.worker=true;
        android.provider.Settings.Global.boot=83;android.system.Os.failUnlink=false;android.system.Os.failFsyncPath=null;
        android.system.Os.corruptPublicArchiveOnSync=false;android.system.Os.afterPublicCommitSync=null;
        RecoveryControllerIdentity.changed=false;work.run();checks++;names.put(name);
    }
    private static final class Env implements AutoCloseable {
        final Path dir,task,journal;final Context context;final BackgroundSession session;
        final Map<Path,byte[]> originalFiles=new LinkedHashMap<Path,byte[]>();
        Env()throws Exception{
            dir=Files.createTempDirectory("hepta-public-recovery-host-").toRealPath();context=new Context(dir.toFile());
            JSONObject old=new JSONObject(new String(Files.readAllBytes(fixture.resolve("background-session.json")),StandardCharsets.UTF_8));
            JSONObject owner=new JSONObject(new String(Files.readAllBytes(fixture.resolve("owner.json")),StandardCharsets.UTF_8));
            SystemClock.now=old.getLong("created_elapsed_ms");ProfileTarget target=ProfileTarget.fromWire(old.getString("profile_target_wire"));
            String instruction=owner.getString("instruction");BackgroundTaskTarget chosen=BackgroundTaskTarget.resolveExplicitSelection(instruction,target.packageName,Collections.singleton(target.packageName),target);
            session=BackgroundSession.experimentalPublicOwnGroup(context,TASK,instruction,new BackgroundSession.Selection(chosen,true),new QualificationScopeConfig.FilesRoot(context));
            // Recreate only an already-failed in-memory object for typed-receipt acceptance tests.
            // Static reconciliation itself consumes byte-exact real archived originals below.
            field(session,"generation",GEN);field(session,"socketName",old.getString("socket"));field(session,"displayName",old.getString("display_name"));
            PublicOwnGroupPolicy.Scope scope=PublicOwnGroupPolicy.Scope.fromWire(old.getString("public_own_group_scope_wire"));field(session,"publicOwnGroupScope",scope);
            Field key=BackgroundSession.class.getDeclaredField("publicScopeOwner");key.setAccessible(true);Object ownerKey=key.get(session);
            PublicOwnGroupPolicy.LiveLease lease=new PublicOwnGroupPolicy.LiveLease(ownerKey,scope);lease.retire(ownerKey);field(session,"publicScopeLease",lease);
            field(session,"retired",true);field(session,"spawnAttempted",true);field(session,"brokerExitObserved",true);field(session,"brokerExitCode",70);field(session,"state","CLEANUP_UNKNOWN");
            MobiMindPrivateFiles.directory(dir.resolve("control-tasks").toFile(),true);task=dir.resolve("control-tasks").resolve(TASK);MobiMindPrivateFiles.directory(task.toFile(),true);
            journal=dir.resolve(BackgroundSession.JOURNAL);MobiMindPrivateFiles.writeNew(journal.toFile(),Files.readAllBytes(fixture.resolve("background-session.json")));
            for(String leaf:new String[]{"owner.json","background-bootstrap.json","background-cleanup.json","result.json","background-broker-"+GEN+".json","background-broker-"+GEN+".bin"}){
                Path out=task.resolve(leaf);byte[] b=Files.readAllBytes(fixture.resolve(leaf));MobiMindPrivateFiles.writeNew(out.toFile(),b);originalFiles.put(out,b);}
            SystemClock.now=old.getLong("expires_elapsed_ms")+3000;
        }
        void originalsUnchanged()throws Exception{for(Map.Entry<Path,byte[]> entry:originalFiles.entrySet())need(Arrays.equals(entry.getValue(),Files.readAllBytes(entry.getKey())));}
        long commits()throws Exception{try(java.util.stream.Stream<Path> stream=Files.list(task)){return stream.filter(p->p.getFileName().toString().matches("background-public-absence-[0-9a-f-]+\\.json")).count();}}
        long attempts()throws Exception{try(java.util.stream.Stream<Path> stream=Files.list(task)){return stream.filter(p->p.getFileName().toString().endsWith(".attempt.json")).count();}}
        public void close()throws IOException{
            android.system.Os.failUnlink=false;android.system.Os.failFsyncPath=null;android.system.Os.afterPublicCommitSync=null;
            try(java.util.stream.Stream<Path> stream=Files.walk(dir)){for(Path p:stream.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(p);}
        }
    }
    private static void field(Object object,String name,Object value)throws Exception{Field f=BackgroundSession.class.getDeclaredField(name);f.setAccessible(true);f.set(object,value);}
    private static BackgroundSession.ReconciliationCheck idle(){return ()->{if(FakePublicRecoveryProcess.cancelled)throw new IOException("synthetic owner epoch retired");};}
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("exact actual originals directory");fixture=Paths.get(args[0]);
        org.trillionnium.hepta.background.PublicProfileAbsenceHostTest.loadArchivedRecents(fixture);
        test("actual_originals_new_receipt_then_only_exact_lease_retired",()->{try(Env e=new Env()){
            need(e.session.publicProfileRecoveryEligible());BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context,idle());
            need(c.known&&c.publicProfileRecovery!=null&&c.prelaunchRecovery==null&&c.postlaunchRecovery==null);
            need(!Files.exists(e.journal)&&e.commits()==1&&FakePublicRecoveryProcess.calls==1&&LocalSocket.connections==0);
            need(!c.evidence.getBoolean("broker_released")&&c.evidence.getBoolean("historical_creation_unknown"));
            c.publicProfileRecovery.persist(e.context);need(e.commits()==1);e.originalsUnchanged();
            reject(()->e.session.acceptReconciliation(new JSONObject(c.evidence.toString())));
            reject(()->e.session.acceptReconciliation(new BackgroundSession.Cleanup(true,c.evidence)));
            e.session.acceptReconciliation(c);need(e.session.released());e.originalsUnchanged();
            need(BackgroundSession.reconcile(e.context,idle()).known&&FakePublicRecoveryProcess.calls==1);
        }});
        test("failed_checker_exit_preserves_old_failure_and_writes_failed_attempt",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.exit=70;reject(()->BackgroundSession.reconcile(e.context,idle()));
            need(Files.exists(e.journal)&&e.commits()==0&&e.attempts()==1&&LocalSocket.connections==0);e.originalsUnchanged();
            try(java.util.stream.Stream<Path> stream=Files.list(e.task)){Path p=stream.filter(x->x.getFileName().toString().endsWith(".attempt.json")).findFirst().get();
                JSONObject a=new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));need(!a.getBoolean("cleanup_known")&&!a.getBoolean("lease_retired")&&a.getInt("exit_code")==70
                        &&"PUBLIC_RECOVERY_SYNTHETIC_FAILURE".equals(a.getString("checker_error")));}
        }});
        test("trailing_stdout_rejected_without_lease_retirement",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.suffix="{}";reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("incomplete_eof_rejected_and_attempt_retained",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.readFailure=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0&&e.attempts()==1);e.originalsUnchanged();
        }});
        test("new_owned_checker_timeout_never_signals_old_pid",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.timeout=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0&&FakePublicRecoveryProcess.destroyed==1);e.originalsUnchanged();
        }});
        test("wrong_request_rejected",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.badNonce=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("epoch_changed_after_process_rejected",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.afterReply=()->FakePublicRecoveryProcess.cancelled=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("current_installed_apk_changed_rejected",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.afterReply=()->RecoveryControllerIdentity.changed=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("journal_changed_after_sampling_rejected",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.afterReply=()->{try{Files.write(e.journal,new byte[]{1});}catch(Exception x){throw new RuntimeException(x);}};
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("journal_replaced_same_bytes_inode_aba_rejected",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.afterReply=()->{try{byte[] b=Files.readAllBytes(e.journal);Path replacement=e.dir.resolve("replacement");MobiMindPrivateFiles.writeNew(replacement.toFile(),b);Files.move(replacement,e.journal,java.nio.file.StandardCopyOption.REPLACE_EXISTING);}catch(Exception x){throw new RuntimeException(x);}};
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==0);e.originalsUnchanged();
        }});
        test("journal_changed_after_durable_receipt_cas_rejected",()->{try(Env e=new Env()){
            android.system.Os.afterPublicCommitSync=()->{try{Files.write(e.journal,new byte[]{1});}catch(Exception x){throw new RuntimeException(x);}};
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==1&&!e.session.released());e.originalsUnchanged();
        }});
        test("receipt_fsync_failure_keeps_old_lease",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.afterReply=()->android.system.Os.failFsyncPath=e.task.resolve("background-public-absence-"+FakePublicRecoveryProcess.lastRequest.requestId+".json").toString();
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&!e.session.released());e.originalsUnchanged();
        }});
        test("archive_corruption_keeps_old_lease",()->{try(Env e=new Env()){
            android.system.Os.corruptPublicArchiveOnSync=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&!e.session.released());e.originalsUnchanged();
        }});
        test("unlink_failure_keeps_old_lease_and_new_receipt",()->{try(Env e=new Env()){
            android.system.Os.failUnlink=true;reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.commits()==1&&!e.session.released());e.originalsUnchanged();
        }});
        test("display_appears_after_samples_rejects_without_removal",()->{try(Env e=new Env()){
            FakePublicRecoveryProcess.afterReply=()->e.context.displays.displays.put(777,new android.view.Display(777,e.session.displayName));
            reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&e.context.displays.getDisplay(777)!=null);e.originalsUnchanged();
        }});
        test("same_typed_receipt_cannot_release_new_lease",()->{try(Env e=new Env()){
            BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context,idle());MobiMindPrivateFiles.writeNew(e.journal.toFile(),new byte[]{1});
            reject(()->e.session.acceptReconciliation(c));need(Files.exists(e.journal)&&!e.session.released());e.originalsUnchanged();
        }});
        test("valid_private_receipt_cannot_release_public_lease",()->{try(Env e=new Env()){
            BackgroundSession.Cleanup publicResult=BackgroundSession.reconcile(e.context,idle());
            org.trillionnium.hepta.background.ProfilePrelaunchRecovery.Request oldRequest=org.trillionnium.hepta.background.ProfilePrelaunchRecovery.request(
                    publicResult.publicProfileRecovery.request.original("journal"),10481,"77777777-7777-4777-8777-777777777777",SystemClock.now,83);
            JSONObject oldProof=org.trillionnium.hepta.background.RecoveryProofFixture.reply(oldRequest);SystemClock.now=oldRequest.started+20;
            org.trillionnium.hepta.background.ProfilePrelaunchRecovery.validate(oldProof,oldRequest,SystemClock.now,83);
            java.lang.reflect.Constructor<ProfileRecoveryClient.Receipt> constructor=ProfileRecoveryClient.Receipt.class.getDeclaredConstructor(
                    org.trillionnium.hepta.background.ProfilePrelaunchRecovery.Request.class,JSONObject.class,byte[].class,String.class,long.class);
            constructor.setAccessible(true);ProfileRecoveryClient.Receipt oldReceipt=constructor.newInstance(oldRequest,oldProof,oldProof.toString().getBytes(StandardCharsets.UTF_8),"synthetic-private-checker",SystemClock.now);
            oldReceipt.persist(e.context);oldReceipt.requirePersisted();
            java.lang.reflect.Constructor<BackgroundSession.Cleanup> cleanup=BackgroundSession.Cleanup.class.getDeclaredConstructor(boolean.class,JSONObject.class,ProfileRecoveryClient.Receipt.class);
            cleanup.setAccessible(true);BackgroundSession.Cleanup privateResult=cleanup.newInstance(true,oldReceipt.evidence(),oldReceipt);
            reject(()->e.session.acceptReconciliation(privateResult));need(!e.session.released());
            e.session.acceptReconciliation(publicResult);need(e.session.released());e.originalsUnchanged();
        }});
        test("public_service_gate_preserves_each_independent_worker_and_web_lease",()->{try(Env e=new Env()){
            PublicRecoveryIdleFixture f=new PublicRecoveryIdleFixture(e.session);need(f.publicProfileReconciliationIdle(f.ownedController));
            need(!f.prelaunchReconciliationIdle(f.ownedController)&&!f.postlaunchReconciliationIdle(f.ownedController));
            f.pendingAction=true;need(!f.publicProfileReconciliationIdle(f.ownedController));f.pendingAction=false;
            f.pendingObservation=true;need(!f.publicProfileReconciliationIdle(f.ownedController));f.pendingObservation=false;
            f.pendingNative=true;need(!f.publicProfileReconciliationIdle(f.ownedController));f.pendingNative=false;
            f.capturePending=true;need(!f.publicProfileReconciliationIdle(f.ownedController));f.capturePending=false;
            f.taskWeb=new PublicRecoveryIdleFixture.Web();need(!f.publicProfileReconciliationIdle(f.ownedController));f.taskWeb=null;
            f.activeObservation=new Object();need(!f.publicProfileReconciliationIdle(f.ownedController));f.activeObservation=null;
            f.ownedController.running=true;need(!f.publicProfileReconciliationIdle(f.ownedController));f.ownedController.running=false;
            f.lease="different-task";need(!f.publicProfileReconciliationIdle(f.ownedController));f.lease=TASK;
            need(f.publicProfileReconciliationIdle(f.ownedController));e.originalsUnchanged();
        }});
        test("receipt_corruption_rejects_in_memory_acceptance",()->{try(Env e=new Env()){
            BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context,idle());Files.write(Paths.get(c.evidence.getString("public_profile_receipt_path")),new byte[]{1});
            reject(()->e.session.acceptReconciliation(c));need(!e.session.released());e.originalsUnchanged();
        }});
        test("no_business_evidence_no_recovery_process",()->{try(Env e=new Env()){
            Files.delete(e.task.resolve("result.json"));reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&FakePublicRecoveryProcess.calls==0);
        }});
        test("dispatched_step_file_rejects_before_checker",()->{try(Env e=new Env()){
            MobiMindPrivateFiles.writeNew(e.task.resolve("step-00-action.json").toFile(),new byte[]{1});reject(()->BackgroundSession.reconcile(e.context,idle()));need(Files.exists(e.journal)&&FakePublicRecoveryProcess.calls==0);e.originalsUnchanged();
        }});
        test("ttl_before_expiry_retains_existing_close_path",()->{try(Env e=new Env()){
            SystemClock.now=e.session.expiresElapsed-1;BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context,idle());
            need(!c.known&&FakePublicRecoveryProcess.calls==0&&LocalSocket.connections>0&&Files.exists(e.journal));e.originalsUnchanged();
        }});
        System.out.println(new JSONObject().put("schema","hepta.public-profile-recovery-client-host-tests.v1").put("passed",true).put("checks",checks)
                .put("assertions",assertions).put("cases",names).put("actual_client_except_owned_process_factory",true).put("actual_background_session",true)
                .put("android_transport_clock_pm_fixtures_synthetic",true).put("phone_contacted",false).put("android_runtime",false));
    }
}
