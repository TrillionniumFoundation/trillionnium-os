package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import android.os.SystemClock;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.BrokerProtocol;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.PublicProfileBusinessAbsenceRecovery;
import org.trillionnium.hepta.background.PublicProfileBusinessRecoveryHostTest;
import static org.trillionnium.hepta.local.PublicProfileBusinessClientHostTest.*;

/** Actual Prepared/cleanup client/private IO/absence client/exact lease CAS.
 * Original 8ca evidence is unchanged. Adding the new Bootstrap is an explicit
 * successor counterfactual; socket/root-process/Android boundaries are synthetic.
 * Neither a broker effect nor an Android current-absence proof is produced here. */
public final class RetainedProfileCleanupClientHostTest {
    private static Map<String,byte[]> retained,normal;
    private RetainedProfileCleanupClientHostTest(){}

    private static void retained(String name,Work work)throws Exception{
        originals=retained;HeptaAccessibilityService.cleanupBackground=null;test(name,work);
    }
    private static RetainedProfileCleanupClient.Bootstrap configure(Env e)throws Exception{
        JSONObject old=object(Files.readAllBytes(e.journal));
        PublicOwnGroupPolicy.Scope scope=PublicOwnGroupPolicy.Scope.fromWire(old.getString("public_own_group_scope_wire"));
        RetainedProfileCleanupClient.Bootstrap bootstrap=RetainedProfileCleanupClient.create(scope);
        need(bootstrap!=null);bootstrap.persist(e.context,new QualificationScopeConfig.FilesRoot(e.context));
        bootstrap.addJournalFields(old);Files.write(e.journal,old.toString().getBytes(StandardCharsets.UTF_8));
        field(e.session,"retainedCleanup",bootstrap);
        return bootstrap;
    }
    private static void oldUnconfirmed(Env e)throws Exception{
        field(e.session,"brokerExitObserved",false);field(e.session,"brokerExitCode",null);
    }
    private static PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup prepared(Env e)throws Exception{
        return PublicProfileBusinessRecoveryClient.prepareRetainedCleanup(e.context,
                MobiMindPrivateFiles.read(e.journal.toFile(),16384,true),e.check());
    }
    private static Path claim(Env e){return e.dir.resolve("session-recovery/retained-cleanup-claims/"+e.generation+".json");}
    private static Path key(Env e){return e.dir.resolve("session-recovery/retained-cleanup-keys/"+e.generation+".json");}
    private static Path cleanupReceipt(Env e)throws Exception{
        Path result=null;
        try(java.util.stream.Stream<Path> files=Files.walk(e.dir.resolve("session-recovery"))){
            for(Path p:files.toArray(Path[]::new))if(p.getFileName().toString().equals("receipt.json")
                    &&p.getParent().getFileName().toString().startsWith("retained-cleanup-")){
                need(result==null);result=p;
            }
        }
        need(result!=null);return result;
    }
    private static long businessReceipts(Env e)throws Exception{
        try(java.util.stream.Stream<Path> files=Files.walk(e.dir.resolve("session-recovery"))){
            return files.filter(p->p.getFileName().toString().equals("receipt.json")
                    &&p.getParent().getFileName().toString().startsWith("business-absence-")).count();
        }
    }
    private static byte[] framed(JSONObject value)throws Exception{
        ByteArrayOutputStream out=new ByteArrayOutputStream();BrokerProtocol.writeFrame(out,value.toString().getBytes(StandardCharsets.UTF_8));return out.toByteArray();
    }
    private static BrokerProtocol.RetainedCleanupRequest outbound(byte[] bytes)throws Exception{
        DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes));int size=in.readInt();
        need(size>0&&size<=4096);byte[] body=new byte[size];in.readFully(body);need(in.read()==-1);
        return BrokerProtocol.RetainedCleanupRequest.parse(body);
    }
    private static JSONObject reply(BrokerProtocol.RetainedCleanupRequest request,PublicProfileBusinessAbsenceRecovery.Request prior)throws Exception{
        JSONObject interval=new JSONObject().put("schema","hepta.retained-profile-cleanup-interval.v1")
                .put("generation",prior.generation).put("target_sha256",prior.target.sha256)
                .put("display_id",prior.displayId).put("root_task_id",prior.ownedRootTaskId).put("leaf_task_id",prior.ownedLeafTaskId)
                .put("current_tasks_absent",true).put("current_display_absent",true).put("outside_live_tasks_unchanged",true)
                .put("business_admission_restored",false).put("old_failure_rewritten",false);
        return new JSONObject().put("schema","hepta.retained-profile-cleanup-attempt.v1")
                .put("request",new JSONObject(request.evidence())).put("claimed",true).put("entered",true).put("finished",true)
                .put("current_absence_verified",true).put("failure",JSONObject.NULL).put("business_admission_restored",false)
                .put("business_deadline_extended",false).put("old_failure_rewritten",false).put("request_replayed",false)
                .put("finished_elapsed_ms",SystemClock.elapsedRealtime()).put("interval",interval);
    }
    private static void successPort(Env e)throws Exception{
        final PublicProfileBusinessAbsenceRecovery.Request prior=prepared(e).request;
        need(prior.retainedAfterBusiness&&prior.retainedCurrentAbsenceRequired()&&prior.steps==1&&prior.modelRequests==1);
        LocalSocket.missing=false;LocalSocket.responder=bytes->{
            need(Files.exists(claim(e)));need(FakeBusinessRecoveryProcess.calls==0);
            BrokerProtocol.RetainedCleanupRequest request=outbound(bytes);
            need(new JSONObject(request.evidence()).getString("generation").equals(e.generation));
            return framed(reply(request,prior));
        };
    }
    private static void honestCurrentAbsence(Env e,BackgroundSession.Cleanup value)throws Exception{
        need(value.known&&value.businessRecovery!=null&&!Files.exists(e.journal));
        JSONObject proof=value.businessRecovery.proof();
        need(proof.getBoolean("historical_model_exit_verified")&&!proof.getBoolean("historical_broker_release_observed"));
        need(!proof.getBoolean("business_dispatch_absent_in_original_receipts")&&proof.getBoolean("current_absence_verified"));
        need(proof.has("original_history_refusal")&&!value.evidence.getBoolean("broker_released"));
        need(FakeBusinessRecoveryProcess.calls==1&&businessReceipts(e)==1);
        e.session.acceptReconciliation(value);need(e.session.released());reject(()->e.session.acceptReconciliation(value));e.unchanged();
    }
    private static void noSecretInRecords(Env e)throws Exception{
        String nonce=object(Files.readAllBytes(key(e))).getString("nonce");
        Path dir=cleanupReceipt(e).getParent();
        for(String name:new String[]{"request.json","receipt.json","manifest.json"})
            need(!new String(Files.readAllBytes(dir.resolve(name)),StandardCharsets.UTF_8).contains(nonce));
        need(!new String(Files.readAllBytes(dir.resolve("originals.bin")),StandardCharsets.UTF_8).contains(nonce));
    }
    private static Process hostChild(long delay,int exit)throws Exception{
        return new ProcessBuilder(Paths.get(System.getProperty("java.home"),"bin","java").toString(),"-cp",
                System.getProperty("java.class.path"),RetainedProfileCleanupClientHostTest.class.getName(),
                "--owned-host-child",Long.toString(delay),Integer.toString(exit)).start();
    }
    private static void endHostChild(Process child)throws Exception{
        if(child.isAlive())child.destroyForcibly();need(child.waitFor(3,TimeUnit.SECONDS));
    }
    private static Thread reader(Process child){
        Thread value=new Thread(()->{try{while(child.getInputStream().read()!=-1){};}catch(IOException failure){throw new IllegalStateException(failure);}},"explicit-host-child-reader");
        value.start();return value;
    }
    public static void main(String[] args)throws Exception{
        if(args.length==3&&"--owned-host-child".equals(args[0])){
            Thread.sleep(Long.parseLong(args[1]));System.exit(Integer.parseInt(args[2]));return;
        }
        if(args.length!=3)throw new IllegalArgumentException("retained path map, report, normal path map required");
        retained=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[0]));
        normal=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[2]));
        originals=normal;
        test("actual_prepared_normal_sealed_release_with_new_key_skips_cleanup_rpc",()->{try(Env e=new Env()){
            configure(e);need(!prepared(e).request.retainedCurrentAbsenceRequired());
            BackgroundSession.Cleanup value=e.recover();need(value.known&&LocalSocket.connections==0&&FakeBusinessRecoveryProcess.calls==1);
            need(value.businessRecovery.proof().getBoolean("historical_broker_release_observed")&&!Files.exists(claim(e)));
            e.session.acceptReconciliation(value);need(e.session.released());e.unchanged();
        }});
        retained("legacy_no_nonce_actual_8ca_still_uses_only_independent_absence",()->{try(Env e=new Env()){
            oldUnconfirmed(e);honestCurrentAbsence(e,e.recover());need(LocalSocket.connections==0);
        }});
        retained("success_reply_is_separate_from_current_absence_and_old_failure",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);successPort(e);
            BackgroundSession.Cleanup value=e.recover();honestCurrentAbsence(e,value);need(LocalSocket.connections==1);
            JSONObject receipt=object(Files.readAllBytes(cleanupReceipt(e)));
            need(receipt.getBoolean("request_bytes_attempted")&&receipt.get("failure")==JSONObject.NULL);
            need(!receipt.getBoolean("lease_retired")&&!receipt.getBoolean("control_session_acknowledged"));
            need(receipt.getBoolean("independent_current_absence_still_required"));noSecretInRecords(e);
        }});
        retained("success_reply_without_independent_absence_cannot_retire_lease_then_no_replay",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);successPort(e);FakeBusinessRecoveryProcess.exit=70;
            reject(e::recover);need(Files.exists(e.journal)&&!e.session.released()&&businessReceipts(e)==0&&Files.exists(claim(e)));
            need(LocalSocket.connections==1);FakeBusinessRecoveryProcess.exit=0;FakeBusinessRecoveryProcess.calls=0;
            BackgroundSession.Cleanup value=e.recover();honestCurrentAbsence(e,value);need(LocalSocket.connections==1);noSecretInRecords(e);
        }});
        retained("lost_reply_remains_failed_but_independent_absence_can_close",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);LocalSocket.missing=false;
            LocalSocket.responder=bytes->{outbound(bytes);need(Files.exists(claim(e)));throw new IOException("explicit lost cleanup reply");};
            honestCurrentAbsence(e,e.recover());JSONObject receipt=object(Files.readAllBytes(cleanupReceipt(e)));
            need(receipt.getBoolean("request_bytes_attempted")&&receipt.get("response")==JSONObject.NULL);
            need(receipt.getString("failure").contains("lost cleanup reply"));noSecretInRecords(e);
        }});
        retained("missing_endpoint_never_becomes_absence_without_checker",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);FakeBusinessRecoveryProcess.exit=70;reject(e::recover);
            need(Files.exists(e.journal)&&!Files.exists(claim(e))&&LocalSocket.sent.length==0&&FakeBusinessRecoveryProcess.calls==1);
            JSONObject receipt=object(Files.readAllBytes(cleanupReceipt(e)));need(!receipt.getBoolean("request_bytes_attempted")&&receipt.get("failure")!=JSONObject.NULL);e.unchanged();
        }});
        retained("missing_endpoint_after_actual_exit_can_only_close_via_checker",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);honestCurrentAbsence(e,e.recover());
            need(!Files.exists(claim(e))&&LocalSocket.sent.length==0);need(object(Files.readAllBytes(cleanupReceipt(e))).get("failure")!=JSONObject.NULL);
        }});
        retained("wrong_socket_uid_sends_no_bytes_and_cannot_fake_absence",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);LocalSocket.missing=false;LocalSocket.peerUid=2000;FakeBusinessRecoveryProcess.exit=70;
            reject(e::recover);need(Files.exists(e.journal)&&LocalSocket.sent.length==0&&!Files.exists(claim(e)));
            need(!object(Files.readAllBytes(cleanupReceipt(e))).getBoolean("request_bytes_attempted"));e.unchanged();
        }});
        retained("malformed_cleanup_reply_is_preserved_and_cannot_fake_absence",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);LocalSocket.missing=false;LocalSocket.responder=bytes->framed(new JSONObject().put("cleanup_known",true));
            FakeBusinessRecoveryProcess.exit=70;reject(e::recover);need(Files.exists(e.journal)&&Files.exists(claim(e)));
            need(object(Files.readAllBytes(cleanupReceipt(e))).get("failure")!=JSONObject.NULL);e.unchanged();
        }});
        retained("missing_private_key_rejects_before_socket_or_checker",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);Files.delete(key(e));reject(e::recover);
            need(LocalSocket.connections==0&&FakeBusinessRecoveryProcess.calls==0&&Files.exists(e.journal));e.unchanged();
        }});
        retained("wrong_nonce_commitment_rejects_before_socket_or_checker",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);JSONObject key=object(Files.readAllBytes(key(e)));
            key.put("nonce",String.join("",java.util.Collections.nCopies(64,"f")));Files.write(key(e),key.toString().getBytes(StandardCharsets.UTF_8));
            reject(e::recover);need(LocalSocket.connections==0&&FakeBusinessRecoveryProcess.calls==0&&Files.exists(e.journal));e.unchanged();
        }});
        retained("real_model_exit_input_missing_rejects_before_first_cleanup_byte",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);String model=object(Files.readAllBytes(e.result)).getJSONObject("model_session").getString("worker_generation");
            Path identity=e.dir.resolve("runs/"+model+"/worker-generation.identity");need(Files.exists(identity));Files.delete(identity);
            reject(e::recover);need(LocalSocket.connections==0&&FakeBusinessRecoveryProcess.calls==0&&Files.exists(e.journal)&&!Files.exists(claim(e)));
        }});
        retained("cancelled_real_owner_reservation_rejects_before_cleanup_connection",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);FakeBusinessRecoveryProcess.cancelled=true;reject(e::recover);
            need(LocalSocket.connections==0&&FakeBusinessRecoveryProcess.calls==0&&Files.exists(e.journal));e.unchanged();
        }});
        retained("main_thread_rejects_before_cleanup_connection",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);android.os.Looper.worker=false;reject(e::recover);
            need(LocalSocket.connections==0&&FakeBusinessRecoveryProcess.calls==0&&Files.exists(e.journal));e.unchanged();
        }});
        retained("actual_client_aftereffect_waits_original_host_process_and_reader",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);successPort(e);Process child=hostChild(250,70);Thread output=reader(child);
            try{
                field(e.session,"brokerProcess",child);field(e.session,"brokerOutputThread",output);
                HeptaAccessibilityService.cleanupBackground=e.session;
                honestCurrentAbsence(e,e.recover());need(!child.isAlive()&&!output.isAlive()&&child.exitValue()==70);
            }finally{HeptaAccessibilityService.cleanupBackground=null;endHostChild(child);output.join(3000);}
        }});
        retained("original_host_process_wait_timeout_does_not_signal_or_claim_exit",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);Process child=hostChild(3000,70);
            try{
                field(e.session,"brokerProcess",child);long end=SystemClock.now+25;
                reject(()->e.session.awaitRetainedBrokerExit(e.taskId,e.generation,e.ownerSha,end));
                need(child.isAlive()&&!e.session.publicProfileBusinessRecoveryEligible()&&Files.exists(e.journal));e.unchanged();
            }finally{endHostChild(child);}
        }});
        retained("exited_original_host_process_with_undrained_reader_remains_unknown",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);Process child=hostChild(0,70);need(child.waitFor(3,TimeUnit.SECONDS));
            CountDownLatch release=new CountDownLatch(1);Thread output=new Thread(()->{try{release.await();}catch(InterruptedException error){Thread.currentThread().interrupt();}},"explicit-undrained-reader");output.start();
            try{
                field(e.session,"brokerProcess",child);field(e.session,"brokerOutputThread",output);
                reject(()->e.session.awaitRetainedBrokerExit(e.taskId,e.generation,e.ownerSha,SystemClock.now+25));
                need(output.isAlive()&&Files.exists(e.journal)&&!e.session.released());e.unchanged();
            }finally{release.countDown();output.join(3000);endHostChild(child);}
        }});
        retained("wrong_generation_cannot_wait_or_promote_original_host_process",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);Process child=hostChild(3000,70);
            try{
                field(e.session,"brokerProcess",child);
                reject(()->e.session.awaitRetainedBrokerExit(e.taskId,"99999999-9999-4999-8999-999999999999",e.ownerSha,SystemClock.now+500));
                need(child.isAlive()&&Files.exists(e.journal)&&!e.session.released());e.unchanged();
            }finally{endHostChild(child);}
        }});
        retained("reader_drained_after_original_deadline_cannot_promote_exit",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);Process child=hostChild(0,70);need(child.waitFor(3,TimeUnit.SECONDS));
            final long end=SystemClock.now+500;
            Thread output=new Thread(()->{try{Thread.sleep(20);SystemClock.now=end;}catch(InterruptedException error){Thread.currentThread().interrupt();}},"explicit-late-reader-clock");
            try{
                field(e.session,"brokerProcess",child);field(e.session,"brokerOutputThread",output);output.start();
                reject(()->e.session.awaitRetainedBrokerExit(e.taskId,e.generation,e.ownerSha,end));
                need(!output.isAlive()&&!e.session.released()&&Files.exists(e.journal));e.unchanged();
            }finally{output.join(3000);endHostChild(child);}
        }});
        retained("replaced_original_process_reference_cannot_be_promoted_after_wait",()->{try(Env e=new Env()){
            oldUnconfirmed(e);configure(e);Process child=hostChild(250,70),other=hostChild(3000,70);
            Thread replacement=new Thread(()->{try{Thread.sleep(40);field(e.session,"brokerProcess",other);}catch(Exception failure){throw new IllegalStateException(failure);}},"explicit-process-replacement");
            try{
                field(e.session,"brokerProcess",child);replacement.start();
                reject(()->e.session.awaitRetainedBrokerExit(e.taskId,e.generation,e.ownerSha,SystemClock.now+2000));
                need(!child.isAlive()&&other.isAlive()&&!e.session.released());e.unchanged();
            }finally{replacement.join(3000);endHostChild(child);endHostChild(other);}
        }});
        JSONObject report=new JSONObject().put("status","PASS").put("cases",cases).put("assertions",assertions).put("names",names)
                .put("actual_prepared_client_private_io_and_lease_cas",true).put("actual_device_cleanup",false)
                .put("socket_root_proc_android_stat_pm_are_synthetic",true).put("new_bootstrap_on_old_evidence_is_explicit_counterfactual",true)
                .put("phone_operations",0);
        Files.write(Paths.get(args[1]),report.toString(2).getBytes(StandardCharsets.UTF_8));System.out.println(report.toString());
    }
}
