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
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.PublicProfileBusinessAbsenceRecovery;
import org.trillionnium.hepta.background.PublicProfileBusinessRecoveryHostTest;
import org.trillionnium.hepta.background.RecoveryControllerIdentity;

/** Full actual Client/Inputs/WorkerGenerationProof/PrivateFiles/BackgroundSession.
 * Android stat/UID/clock, PM and the newly owned root process are explicit host fixtures.
 * No opaque Receipt is forged or reflectively constructed; no phone or root census runs. */
public final class PublicProfileBusinessClientHostTest {
    static Map<String,byte[]> originals;
    static int cases,assertions;
    static final JSONArray names=new JSONArray();
    interface Work {void run()throws Exception;}
    static void need(boolean v)throws Exception{assertions++;if(!v)throw new AssertionError("business client boundary");}
    static void reject(Work w)throws Exception{try{w.run();}catch(Exception expected){assertions++;return;}throw new AssertionError("business recovery unexpectedly accepted");}
    static JSONObject object(byte[] b){return new JSONObject(new String(b,StandardCharsets.UTF_8));}
    static void awaitDrain()throws Exception{long end=System.nanoTime()+TimeUnitNanos.THREE_SECONDS;while(PublicProfileBusinessRecoveryClient.workPending()&&System.nanoTime()<end)Thread.sleep(2);need(!PublicProfileBusinessRecoveryClient.workPending());}
    static final class TimeUnitNanos {static final long THREE_SECONDS=3000000000L;private TimeUnitNanos(){}}
    static void test(String name,Work work)throws Exception{
        awaitDrain();LocalSocket.reset();LocalSocket.missing=true;FakeBusinessRecoveryProcess.reset();android.os.Looper.worker=true;
        android.provider.Settings.Global.boot=83;android.system.Os.failUnlink=false;android.system.Os.failFsyncPath=null;
        android.system.Os.corruptBusinessArchiveOnSync=false;android.system.Os.afterBusinessCommitSync=null;
        android.system.Os.resultPath=null;RecoveryControllerIdentity.changed=false;LocalProbeApplication.permissionBusy=false;
        work.run();awaitDrain();cases++;names.put(name);
    }
    static void field(Object o,String name,Object value)throws Exception{Field f=BackgroundSession.class.getDeclaredField(name);f.setAccessible(true);f.set(o,value);}
    static final class Env implements AutoCloseable {
        final Path dir,journal,task,result;final Context context;final BackgroundSession session;
        final String taskId,ownerSha,generation;final byte[] control;final TreeSet<String> membership;
        Env()throws Exception{
            dir=Files.createTempDirectory("hepta-business-client-host-").toRealPath();context=new Context(dir.toFile());
            JSONObject old=object(originals.get(PublicProfileBusinessAbsenceRecovery.JOURNAL));taskId=old.getString("task_id");ownerSha=old.getString("owner_sha256");generation=old.getString("generation");
            JSONObject owner=object(originals.get("control-tasks/"+taskId+"/owner.json"));SystemClock.now=old.getLong("created_elapsed_ms");
            ProfileTarget target=ProfileTarget.fromWire(old.getString("profile_target_wire"));String instruction=owner.getString("instruction");
            BackgroundTaskTarget selected=BackgroundTaskTarget.resolveExplicitSelection(instruction,target.packageName,Collections.singleton(target.packageName),target);
            session=BackgroundSession.experimentalPublicOwnGroup(context,taskId,instruction,new BackgroundSession.Selection(selected,true),new QualificationScopeConfig.FilesRoot(context));
            field(session,"generation",generation);field(session,"socketName",old.getString("socket"));field(session,"displayName",old.getString("display_name"));
            PublicOwnGroupPolicy.Scope scope=PublicOwnGroupPolicy.Scope.fromWire(old.getString("public_own_group_scope_wire"));field(session,"publicOwnGroupScope",scope);
            Field key=BackgroundSession.class.getDeclaredField("publicScopeOwner");key.setAccessible(true);Object ownerKey=key.get(session);
            PublicOwnGroupPolicy.LiveLease lease=new PublicOwnGroupPolicy.LiveLease(ownerKey,scope);lease.retire(ownerKey);field(session,"publicScopeLease",lease);
            field(session,"retired",true);field(session,"spawnAttempted",true);field(session,"profileLaunchAttempted",true);field(session,"bootstrapDispatched",true);
            field(session,"brokerExitObserved",true);field(session,"brokerExitCode",0);field(session,"state","CLEANUP_UNKNOWN");field(session,"displayId",old.getInt("display_id"));
            for(Map.Entry<String,byte[]> e:originals.entrySet()){Path p=dir.resolve(e.getKey());mkdir(p.getParent());MobiMindPrivateFiles.writeNew(p.toFile(),e.getValue());}
            journal=dir.resolve(PublicProfileBusinessAbsenceRecovery.JOURNAL);task=dir.resolve("control-tasks").resolve(taskId);result=task.resolve("result.json");
            mkdir(dir.resolve("session-recovery"));control=Files.readAllBytes(dir.resolve(PublicProfileBusinessAbsenceRecovery.CONTROL));membership=members(task);
            JSONObject ref=object(control).optJSONObject("task_result_reference");
            android.system.Os.resultPath=result.toString();android.system.Os.resultHostInode=((Number)Files.getAttribute(result,"unix:ino")).longValue();
            if(ref!=null){android.system.Os.resultOriginalInode=ref.getLong("file_inode");android.system.Os.resultOriginalDevice=ref.getLong("file_device");}
            FakeBusinessRecoveryProcess.root=dir;SystemClock.now=old.getLong("expires_elapsed_ms")+3000;
        }
        void mkdir(Path p)throws Exception{if(p.equals(dir))return;mkdir(p.getParent());MobiMindPrivateFiles.directory(p.toFile(),false);}
        BackgroundSession.BusinessReconciliationCheck check(){return new BackgroundSession.BusinessReconciliationCheck(){
            public void check()throws Exception{if(FakeBusinessRecoveryProcess.cancelled)throw new IOException("actual reservation fixture retired");}
            public void checkBusiness(String task,String owner)throws Exception{check();if(!taskId.equals(task)||!ownerSha.equals(owner))throw new IOException("wrong task/owner");}
        };}
        BackgroundSession.Cleanup recover()throws Exception{return BackgroundSession.reconcileBusiness(context,check());}
        long commits()throws IOException{Path r=dir.resolve("session-recovery");try(java.util.stream.Stream<Path> s=Files.walk(r)){return s.filter(p->p.getFileName().toString().equals("receipt.json")).count();}}
        void unchanged()throws Exception{
            for(Map.Entry<String,byte[]> e:originals.entrySet())if(!PublicProfileBusinessAbsenceRecovery.JOURNAL.equals(e.getKey()))need(Arrays.equals(e.getValue(),Files.readAllBytes(dir.resolve(e.getKey()))));
            need(membership.equals(members(task)));need(Arrays.equals(control,Files.readAllBytes(dir.resolve(PublicProfileBusinessAbsenceRecovery.CONTROL))));
        }
        public void close()throws IOException{
            FakeBusinessRecoveryProcess.drainRelease.countDown();android.system.Os.failUnlink=false;android.system.Os.failFsyncPath=null;android.system.Os.afterBusinessCommitSync=null;
            try(java.util.stream.Stream<Path> s=Files.walk(dir)){for(Path p:s.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(p);}
        }
    }
    static TreeSet<String> members(Path p)throws IOException{TreeSet<String> r=new TreeSet<String>();try(java.util.stream.Stream<Path>s=Files.list(p)){s.forEach(f->r.add(f.getFileName().toString()));}return r;}
    static void replaceSameBytes(Path p)throws Exception{Path next=p.resolveSibling(p.getFileName()+".host-replacement");MobiMindPrivateFiles.writeNew(next.toFile(),Files.readAllBytes(p));Files.move(next,p,StandardCopyOption.REPLACE_EXISTING);}
    static Runnable operation(Work w){return ()->{try{w.run();}catch(Exception e){throw new RuntimeException(e);}};}
    public static void main(String[] args)throws Exception{
        boolean visual=args.length==3&&"--visual".equals(args[2]);
        if(args.length!=2&&!visual)throw new IllegalArgumentException("external path map, new report and optional --visual required");
        originals=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[0]));
        test("competing_terminal_appears_during_owned_checker",()->{try(Env e=new Env()){
            String generation=object(Files.readAllBytes(e.result)).getJSONObject("model_session").getString("worker_generation");
            Path other=e.dir.resolve("runs").resolve(generation).resolve(visual?"app-session-receipt.json":"vlm-task-terminal.json");
            FakeBusinessRecoveryProcess.afterReply=operation(()->MobiMindPrivateFiles.writeNew(other.toFile(),new byte[]{123,125}));
            reject(e::recover);need(Files.exists(e.journal)&&FakeBusinessRecoveryProcess.calls==1&&e.commits()==0);e.unchanged();
        }});
        if(visual){
            test("visual_originals_checker_durable_receipt_and_one_lease_retirement",()->{try(Env e=new Env()){
                need(PublicProfileBusinessRecoveryClient.hasBusinessOrigin(e.context));
                BackgroundSession.Cleanup cleanup=e.recover();need(cleanup.known&&cleanup.businessRecovery!=null);
                need(!Files.exists(e.journal)&&e.commits()==1&&FakeBusinessRecoveryProcess.calls==1&&LocalSocket.connections==0);
                need(cleanup.evidence.getInt("model_requests")==1&&cleanup.evidence.getInt("business_steps")>0);
                need(!cleanup.evidence.getBoolean("rewrites_original_task_result")&&!cleanup.evidence.getBoolean("automatic_resume"));
                e.session.acceptReconciliation(cleanup);need(e.session.released());reject(()->e.session.acceptReconciliation(cleanup));e.unchanged();
            }});
        }else{
        test("actual_complete_originals_durable_receipt_only_lease_retired",()->{try(Env e=new Env()){
            need(originals.size()==132&&e.membership.size()==105&&Files.size(e.result)==547419);need(PublicProfileBusinessRecoveryClient.hasBusinessOrigin(e.context));
            BackgroundSession.Cleanup c=e.recover();need(c.known&&c.businessRecovery!=null&&c.publicProfileRecovery==null&&c.prelaunchRecovery==null);
            need(!Files.exists(e.journal)&&e.commits()==1&&FakeBusinessRecoveryProcess.calls==1&&LocalSocket.connections==0);
            need(c.evidence.getInt("business_steps")==7&&c.evidence.getInt("model_requests")==7&&!c.evidence.getBoolean("broker_released"));
            need(!c.evidence.getBoolean("rewrites_original_task_result")&&!c.evidence.getBoolean("acknowledges_control_session")&&!c.evidence.getBoolean("automatic_resume"));
            c.businessRecovery.persist();need(e.commits()==1);reject(()->e.session.acceptReconciliation(new BackgroundSession.Cleanup(true,c.evidence)));
            e.session.acceptReconciliation(c);need(e.session.released());reject(()->e.session.acceptReconciliation(c));e.unchanged();
            JSONObject saved=object(Files.readAllBytes(Paths.get(c.evidence.getString("business_receipt_path"))));
            need(saved.getJSONObject("transport").getBoolean("output_eof")&&saved.getJSONObject("transport").getInt("exit_code")==0);
            need(saved.getJSONObject("complete_original_archive").getInt("bytes")>547419);
        }});
        test("main_thread_rejected_before_process",()->{try(Env e=new Env()){android.os.Looper.worker=false;reject(e::recover);need(FakeBusinessRecoveryProcess.calls==0&&Files.exists(e.journal));e.unchanged();}});
        test("retired_actual_queue_check_rejected_before_process",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.cancelled=true;reject(e::recover);need(FakeBusinessRecoveryProcess.calls==0&&Files.exists(e.journal));e.unchanged();}});
        test("historical_model_exit_missing_rejected_before_process",()->{try(Env e=new Env()){
            Path raw=e.dir.resolve("runs/"+object(originals.get("control-tasks/"+e.taskId+"/result.json")).getJSONObject("model_session").getString("worker_generation")+"/worker-generation.identity");
            Files.delete(raw);reject(e::recover);need(FakeBusinessRecoveryProcess.calls==0&&Files.exists(e.journal));
        }});
        test("checker_nonzero_exit_never_retires_lease",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.exit=70;reject(e::recover);need(Files.exists(e.journal)&&e.commits()==0);e.unchanged();}});
        test("wrong_request_nonce_rejected",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.badNonce=true;reject(e::recover);need(Files.exists(e.journal)&&e.commits()==0);e.unchanged();}});
        test("trailing_stdout_rejected",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.suffix="{}";reject(e::recover);need(Files.exists(e.journal)&&e.commits()==0);e.unchanged();}});
        test("incomplete_eof_rejected",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.readFailure=true;reject(e::recover);need(Files.exists(e.journal)&&e.commits()==0);e.unchanged();}});
        test("unknown_process_and_reader_drain_holds_capacity_and_callback",()->{try(Env e=new Env()){
            FakeBusinessRecoveryProcess.delayedDrain=true;reject(e::recover);need(PublicProfileBusinessRecoveryClient.workPending()&&FakeBusinessRecoveryProcess.destroyed==1&&Files.exists(e.journal));
            AtomicBoolean completed=new AtomicBoolean();PublicProfileBusinessRecoveryClient.afterOwnedCheckerDrain(()->completed.set(true));need(!completed.get());
            reject(e::recover);need(FakeBusinessRecoveryProcess.calls==1&&!completed.get());FakeBusinessRecoveryProcess.drainRelease.countDown();awaitDrain();
            long end=System.nanoTime()+TimeUnitNanos.THREE_SECONDS;while(!completed.get()&&System.nanoTime()<end)Thread.sleep(2);need(completed.get());e.unchanged();
        }});
        test("current_apk_change_after_proof_rejected",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.afterReply=()->RecoveryControllerIdentity.changed=true;reject(e::recover);need(Files.exists(e.journal)&&e.commits()==0);e.unchanged();}});
        test("owner_reservation_retired_after_proof_rejected",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.afterReply=()->FakeBusinessRecoveryProcess.cancelled=true;reject(e::recover);need(Files.exists(e.journal)&&e.commits()==0);e.unchanged();}});
        test("extra_task_file_after_root_samples_rejected",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.afterReply=operation(()->MobiMindPrivateFiles.writeNew(e.task.resolve("unexpected.json").toFile(),new byte[]{1}));reject(e::recover);need(Files.exists(e.journal)&&e.commits()==0);}});
        test("same_bytes_journal_inode_aba_rejected",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.afterReply=operation(()->replaceSameBytes(e.journal));reject(e::recover);need(Files.exists(e.journal)&&e.commits()==0);e.unchanged();}});
        test("same_bytes_task_result_inode_aba_rejected",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.afterReply=operation(()->replaceSameBytes(e.result));reject(e::recover);need(Files.exists(e.journal)&&e.commits()==0);e.unchanged();}});
        test("archive_readback_corruption_rejected_before_cas",()->{try(Env e=new Env()){android.system.Os.corruptBusinessArchiveOnSync=true;reject(e::recover);need(Files.exists(e.journal)&&!e.session.released());e.unchanged();}});
        test("receipt_fsync_failure_rejected_before_cas",()->{try(Env e=new Env()){
            FakeBusinessRecoveryProcess.afterReply=()->android.system.Os.failFsyncPath=e.dir.resolve("session-recovery/business-absence-"+FakeBusinessRecoveryProcess.lastRequest.requestId+"/receipt.json").toString();
            reject(e::recover);need(Files.exists(e.journal)&&!e.session.released());e.unchanged();
        }});
        test("journal_changed_after_durable_receipt_rejected",()->{try(Env e=new Env()){android.system.Os.afterBusinessCommitSync=operation(()->Files.write(e.journal,new byte[]{1}));reject(e::recover);need(Files.exists(e.journal)&&e.commits()==1);e.unchanged();}});
        test("deadline_after_durable_receipt_rejected",()->{try(Env e=new Env()){android.system.Os.afterBusinessCommitSync=()->SystemClock.now=FakeBusinessRecoveryProcess.lastRequest.deadline;reject(e::recover);need(Files.exists(e.journal)&&e.commits()==1);e.unchanged();}});
        test("display_reappears_after_root_samples_rejected",()->{try(Env e=new Env()){FakeBusinessRecoveryProcess.afterReply=()->e.context.displays.displays.put(777,new android.view.Display(777,e.session.displayName));reject(e::recover);need(Files.exists(e.journal)&&!e.session.released());e.unchanged();}});
        test("unlink_failure_preserves_receipt_and_lease",()->{try(Env e=new Env()){android.system.Os.failUnlink=true;reject(e::recover);need(Files.exists(e.journal)&&e.commits()==1&&!e.session.released());e.unchanged();}});
        test("old_opaque_receipt_cannot_release_replacement_lease",()->{try(Env e=new Env()){BackgroundSession.Cleanup c=e.recover();MobiMindPrivateFiles.writeNew(e.journal.toFile(),originals.get(PublicProfileBusinessAbsenceRecovery.JOURNAL));reject(()->e.session.acceptReconciliation(c));need(!e.session.released());e.unchanged();}});
        test("original_zero_step_entry_still_rejects_positive_business",()->{try(Env e=new Env()){reject(()->BackgroundSession.reconcile(e.context,()->{}));need(Files.exists(e.journal)&&FakeBusinessRecoveryProcess.calls==0);e.unchanged();}});
        }
        JSONObject report=new JSONObject().put("schema","hepta.business-client-host-cases.v1").put("status","PASS").put("cases",cases).put("assertions",assertions).put("case_names",names)
            .put("actual_complete_client_and_background_session",true).put("opaque_receipt_created_only_by_actual_client",true)
            .put("root_transport_pm_android_stat_clock_synthetic",true).put("phone_operations",0);
        Files.write(Paths.get(args[1]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(report.toString());
    }
}
