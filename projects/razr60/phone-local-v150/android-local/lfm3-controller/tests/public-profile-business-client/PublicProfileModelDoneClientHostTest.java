package org.trillionnium.hepta.local;

import static org.trillionnium.hepta.local.PublicProfileBusinessClientHostTest.*;
import android.net.LocalSocket;
import android.os.SystemClock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.json.JSONObject;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.PublicProfileBusinessRecoveryHostTest;
import org.trillionnium.hepta.background.RecoveryControllerIdentity;

/** Actual historical payloads, existing real Client/lease CAS, synthetic Android
 * ports and current absence. A fresh host-only retained-cleanup key is generated;
 * the current journal's key binding is explicitly counterfactual, not phone data. */
public final class PublicProfileModelDoneClientHostTest {
    private static final String SOURCE="fresh_public_profile_absence_after_verified_model_done_cleanup_failure";
    private PublicProfileModelDoneClientHostTest(){}
    private static Env configured()throws Exception{
        Env e=new Env();JSONObject old=object(Files.readAllBytes(e.journal));
        RetainedProfileCleanupClient.Bootstrap key=RetainedProfileCleanupClient.create(PublicOwnGroupPolicy.Scope.fromWire(old.getString("public_own_group_scope_wire")));
        need(key!=null);key.persist(e.context,new QualificationScopeConfig.FilesRoot(e.context));key.addJournalFields(old);
        Files.write(e.journal,old.toString().getBytes(StandardCharsets.UTF_8));field(e.session,"retainedCleanup",key);
        field(e.session,"brokerExitObserved",false);field(e.session,"brokerExitCode",null);
        return e;
    }
    private static PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup prepared(Env e)throws Exception{
        return PublicProfileBusinessRecoveryClient.prepareRetainedCleanup(e.context,MobiMindPrivateFiles.read(e.journal.toFile(),16384,true),e.check());
    }
    private static long businessCommits(Env e)throws Exception{
        try(java.util.stream.Stream<java.nio.file.Path> paths=Files.walk(e.dir.resolve("session-recovery"))){
            return paths.filter(p->p.getFileName().toString().equals("receipt.json")&&p.getParent().getFileName().toString().startsWith("business-absence-")).count();
        }
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("actual original path map and fresh report required");
        originals=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[0]));
        test("actual_model_done_shape_prepared_before_any_cleanup_byte",()->{try(Env e=new Env()){
            PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup p=prepared(e);
            need(SOURCE.equals(p.request.source())&&p.request.retainedAfterBusiness&&p.request.steps>0&&p.request.modelRequests>0);
            need(FakeBusinessRecoveryProcess.calls==0&&LocalSocket.connections==0&&Files.exists(e.journal));e.unchanged();
        }});
        test("synthetic_current_absence_commits_only_original_lease",()->{try(Env e=configured()){
            BackgroundSession.Cleanup c=e.recover();need(c.known&&c.businessRecovery!=null&&!Files.exists(e.journal));
            need(businessCommits(e)==1&&FakeBusinessRecoveryProcess.calls==1);
            JSONObject p=c.businessRecovery.proof();
            need(SOURCE.equals(p.getString("source"))&&p.getBoolean("current_absence_verified")&&!p.getBoolean("historical_broker_release_observed"));
            need(!p.getBoolean("rewrites_business_outcome")&&!p.getBoolean("acknowledges_control_session")&&!p.getBoolean("automatic_resume"));
            need(!c.evidence.getBoolean("broker_released")&&!c.evidence.getBoolean("rewrites_original_task_result"));
            JSONObject old=object(Files.readAllBytes(e.result));need(old.getBoolean("model_reported_success")&&!old.getBoolean("completion_verified")&&!old.getBoolean("cleanup_known"));
            need(!old.getJSONObject("completion_evidence").getBoolean("business_verified"));
            e.session.acceptReconciliation(c);need(e.session.released());reject(()->e.session.acceptReconciliation(c));e.unchanged();
        }});
        test("cleanup_reply_or_missing_endpoint_never_replaces_absence",()->{try(Env e=configured()){
            FakeBusinessRecoveryProcess.exit=70;reject(e::recover);
            need(Files.exists(e.journal)&&businessCommits(e)==0&&!e.session.released());e.unchanged();
        }});
        test("wrong_owned_checker_nonce_refused",()->{try(Env e=configured()){
            FakeBusinessRecoveryProcess.badNonce=true;reject(e::recover);need(Files.exists(e.journal)&&businessCommits(e)==0);e.unchanged();
        }});
        test("journal_inode_aba_after_current_samples_refused",()->{try(Env e=configured()){
            FakeBusinessRecoveryProcess.afterReply=operation(()->replaceSameBytes(e.journal));
            reject(e::recover);need(Files.exists(e.journal)&&businessCommits(e)==0&&!e.session.released());e.unchanged();
        }});
        test("original_result_inode_aba_after_current_samples_refused",()->{try(Env e=configured()){
            FakeBusinessRecoveryProcess.afterReply=operation(()->replaceSameBytes(e.result));
            reject(e::recover);need(Files.exists(e.journal)&&businessCommits(e)==0);e.unchanged();
        }});
        test("current_apk_change_after_proof_refused",()->{try(Env e=configured()){
            FakeBusinessRecoveryProcess.afterReply=()->RecoveryControllerIdentity.changed=true;
            reject(e::recover);need(Files.exists(e.journal)&&businessCommits(e)==0);e.unchanged();
        }});
        test("archive_corruption_never_grants_lease_cas",()->{try(Env e=configured()){
            android.system.Os.corruptBusinessArchiveOnSync=true;reject(e::recover);
            need(Files.exists(e.journal)&&!e.session.released());e.unchanged();
        }});
        test("deadline_after_durable_receipt_refused",()->{try(Env e=configured()){
            android.system.Os.afterBusinessCommitSync=()->SystemClock.now=FakeBusinessRecoveryProcess.lastRequest.deadline;
            reject(e::recover);need(Files.exists(e.journal)&&!e.session.released());e.unchanged();
        }});
        test("serialized_known_flag_is_not_opaque_receipt",()->{try(Env e=configured()){
            BackgroundSession.Cleanup c=e.recover();reject(()->e.session.acceptReconciliation(new BackgroundSession.Cleanup(true,c.evidence)));
            need(!e.session.released());e.session.acceptReconciliation(c);need(e.session.released());e.unchanged();
        }});
        test("opaque_receipt_cannot_retire_replacement_lease",()->{try(Env e=configured()){
            byte[] journal=Files.readAllBytes(e.journal);BackgroundSession.Cleanup c=e.recover();
            MobiMindPrivateFiles.writeNew(e.journal.toFile(),journal);reject(()->e.session.acceptReconciliation(c));
            need(!e.session.released());e.unchanged();
        }});
        test("unverified_model_claim_rejected_before_cleanup_connection",()->{try(Env e=configured()){
            JSONObject r=object(Files.readAllBytes(e.result));r.getJSONObject("completion_evidence").put("model_success_claim_verified",false);
            Files.write(e.result,r.toString().getBytes(StandardCharsets.UTF_8));
            reject(()->prepared(e));need(FakeBusinessRecoveryProcess.calls==0&&LocalSocket.connections==0&&Files.exists(e.journal));
        }});
        JSONObject report=new JSONObject().put("schema","hepta.business-model-done-client-host-cases.v1").put("status","PASS")
                .put("cases",cases).put("assertions",assertions).put("case_names",names)
                .put("actual_complete_client_and_background_session",true).put("opaque_receipt_created_only_by_actual_client",true)
                .put("historical_originals_preserved",true).put("business_outcome_upgraded",false)
                .put("current_journal_key_binding_synthetic",true).put("root_transport_pm_android_stat_clock_synthetic",true).put("phone_operations",0);
        Files.write(Paths.get(args[1]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(report.toString());
    }
}
