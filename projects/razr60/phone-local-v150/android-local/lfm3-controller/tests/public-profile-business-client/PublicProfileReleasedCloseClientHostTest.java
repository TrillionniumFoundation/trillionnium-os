package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import android.os.SystemClock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.json.JSONObject;
import org.trillionnium.hepta.background.PublicProfileBusinessAbsenceRecovery;
import org.trillionnium.hepta.background.PublicProfileBusinessRecoveryHostTest;
import org.trillionnium.hepta.background.RecoveryControllerIdentity;
import static org.trillionnium.hepta.local.PublicProfileBusinessClientHostTest.*;

/** Actual Client/Session/CAS plus actual retained client. Android/PM/stat/clock
 * and the read-only root Process are existing explicit host IO boundaries. */
public final class PublicProfileReleasedCloseClientHostTest {
    private PublicProfileReleasedCloseClientHostTest(){}
    private static void noRetainedEffect(Env e)throws Exception{
        need(LocalSocket.connections==0&&LocalSocket.sent.length==0&&LocalSocket.events.isEmpty());
        need(!Files.exists(e.dir.resolve("session-recovery/retained-cleanup-claims")));
        need(!Files.exists(e.dir.resolve("session-recovery/retained-cleanup-keys")));
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("complete original path map and new result required");
        originals=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[0]));
        test("actual_released_history_skips_dead_retained_socket_and_only_retires_lease",()->{try(Env e=new Env()){
            need(originals.size()==76&&e.membership.size()==58&&Files.size(e.result)==2008108);
            need(e.taskId.equals("02d27deccfce45eaacd15003203e321a")&&PublicProfileBusinessRecoveryClient.hasBusinessOrigin(e.context));
            need(RetainedProfileCleanupClient.configured(object(originals.get(PublicProfileBusinessAbsenceRecovery.JOURNAL))));
            BackgroundSession.Cleanup c=e.recover();
            need(c.known&&c.businessRecovery!=null&&!Files.exists(e.journal)&&e.commits()==1&&FakeBusinessRecoveryProcess.calls==1);
            need(!FakeBusinessRecoveryProcess.lastRequest.retainedCurrentAbsenceRequired());noRetainedEffect(e);
            JSONObject p=c.businessRecovery.proof(),old=object(Files.readAllBytes(e.result));
            need(p.getBoolean("current_absence_verified")&&p.getBoolean("historical_broker_release_observed")
                    &&p.getInt("model_requests")==4&&p.getInt("business_steps")==4);
            need(!p.getBoolean("rewrites_business_outcome")&&!p.getBoolean("acknowledges_control_session"));
            need(!c.evidence.getBoolean("broker_released")&&!c.evidence.getBoolean("rewrites_original_task_result")
                    &&!c.evidence.getBoolean("acknowledges_control_session")&&!c.evidence.getBoolean("automatic_resume"));
            need(old.getString("status").equals("blocked")&&!old.getBoolean("cleanup_known")&&!old.getBoolean("model_reported_success"));
            e.session.acceptReconciliation(c);need(e.session.released());reject(()->e.session.acceptReconciliation(c));
            reject(e::recover);need(FakeBusinessRecoveryProcess.calls==1);noRetainedEffect(e);e.unchanged();
        }});
        test("original_expiry_plus_grace_still_required_before_checker",()->{try(Env e=new Env()){
            SystemClock.now=object(originals.get(PublicProfileBusinessAbsenceRecovery.JOURNAL)).getLong("expires_elapsed_ms")+2000;
            reject(e::recover);need(Files.exists(e.journal)&&e.commits()==0&&FakeBusinessRecoveryProcess.calls==0);noRetainedEffect(e);e.unchanged();
        }});
        test("fresh_checker_failure_keeps_old_lease_and_failure",()->{try(Env e=new Env()){
            FakeBusinessRecoveryProcess.exit=70;reject(e::recover);
            need(Files.exists(e.journal)&&e.commits()==0&&FakeBusinessRecoveryProcess.calls==1);noRetainedEffect(e);e.unchanged();
        }});
        test("fresh_checker_incomplete_eof_cannot_commit",()->{try(Env e=new Env()){
            FakeBusinessRecoveryProcess.readFailure=true;reject(e::recover);
            need(Files.exists(e.journal)&&e.commits()==0&&FakeBusinessRecoveryProcess.calls==1);noRetainedEffect(e);e.unchanged();
        }});
        test("current_installed_identity_change_cannot_commit",()->{try(Env e=new Env()){
            FakeBusinessRecoveryProcess.afterReply=()->RecoveryControllerIdentity.changed=true;reject(e::recover);
            need(Files.exists(e.journal)&&e.commits()==0);noRetainedEffect(e);e.unchanged();
        }});
        test("current_display_reappearance_preserves_lease_after_durable_receipt",()->{try(Env e=new Env()){
            FakeBusinessRecoveryProcess.afterReply=()->e.context.displays.displays.put(717,new android.view.Display(717,e.session.displayName));
            String refusal;
            try{e.recover();throw new AssertionError("reappearing display must not retire the lease");}
            catch(java.io.IOException expected){refusal=expected.getMessage();}
            JSONObject observed=new JSONObject().put("case","current_display_reappearance_preserves_lease_after_durable_receipt")
                    .put("refusal",refusal).put("durable_receipts",e.commits()).put("journal_present",Files.exists(e.journal))
                    .put("journal_original_bytes",java.util.Arrays.equals(Files.readAllBytes(e.journal),originals.get(PublicProfileBusinessAbsenceRecovery.JOURNAL)))
                    .put("session_released",e.session.released()).put("checker_calls",FakeBusinessRecoveryProcess.calls)
                    .put("socket_connections",LocalSocket.connections).put("socket_sent_bytes",LocalSocket.sent.length);
            System.out.println(observed.toString());
            need("业务恢复提交前原租约或实际显示发生变化".equals(refusal));
            need(observed.getLong("durable_receipts")==1);need(observed.getBoolean("journal_present"));
            need(observed.getBoolean("journal_original_bytes"));need(!observed.getBoolean("session_released"));
            need(observed.getInt("checker_calls")==1);noRetainedEffect(e);e.unchanged();
        }});
        test("deadline_after_durable_receipt_still_preserves_lease",()->{try(Env e=new Env()){
            android.system.Os.afterBusinessCommitSync=()->SystemClock.now=FakeBusinessRecoveryProcess.lastRequest.deadline;
            reject(e::recover);need(Files.exists(e.journal)&&e.commits()==1&&!e.session.released());noRetainedEffect(e);e.unchanged();
        }});
        JSONObject report=new JSONObject().put("schema","hepta.business-released-close-client-host-cases.v1").put("status","PASS")
                .put("cases",cases).put("assertions",assertions).put("case_names",names)
                .put("actual_complete_client_background_session_and_retained_client",true)
                .put("original_files",76).put("original_task_files",58).put("root_transport_pm_android_stat_clock_synthetic",true)
                .put("phone_current_absence_verified",false).put("phone_operations",0);
        if(Files.exists(Paths.get(args[1])))throw new java.io.IOException("fresh output required");
        Files.write(Paths.get(args[1]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(report.toString());
    }
}
