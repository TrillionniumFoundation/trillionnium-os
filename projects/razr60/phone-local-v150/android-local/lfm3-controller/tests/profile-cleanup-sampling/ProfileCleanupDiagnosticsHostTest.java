package org.trillionnium.hepta.background;
import java.util.Map;
import org.json.JSONObject;
/** Complete production nested audit, extracted byte-for-byte; no Android runtime. */
public final class ProfileCleanupDiagnosticsHostTest {
    private static int assertions;
    private static void yes(boolean v,String why){assertions++;if(!v)throw new AssertionError(why);}
    public static void main(String[] args){
        BackgroundDisplayBroker.ProfileCleanupFailureAudit audit=new BackgroundDisplayBroker.ProfileCleanupFailureAudit();
        yes(audit.evidence().get("first_failure")==null,"invented initial failure");
        audit.phase(BackgroundDisplayBroker.ProfileCleanupFailureAudit.Phase.TASK_RETIRE);
        audit.record("PROFILE_RECENTS_DEADLINE",1000,2400,2395);
        Map<?,?> first=(Map<?,?>)audit.evidence().get("first_failure");
        yes("TASK_RETIRE".equals(first.get("phase")),"phase absent");
        yes("PROFILE_RECENTS_DEADLINE".equals(first.get("code")),"first refusal hidden by close reason");
        yes(Long.valueOf(1000).equals(first.get("cleanup_started_elapsed_ms")),"start changed");
        yes(Long.valueOf(2400).equals(first.get("task_reads_deadline_elapsed_ms")),"deadline changed");
        yes(Long.valueOf(2395).equals(first.get("observed_elapsed_ms")),"observed time changed");
        audit.phase(BackgroundDisplayBroker.ProfileCleanupFailureAudit.Phase.FINAL_PUBLIC_RECENTS);
        audit.record("cleanup_deadline",1000,2400,2500);
        yes(first.equals(audit.evidence().get("first_failure")),"watchdog overwrote first failure");
        BackgroundDisplayBroker.ProfileCleanupFailureAudit deadline=new BackgroundDisplayBroker.ProfileCleanupFailureAudit();
        deadline.phase(BackgroundDisplayBroker.ProfileCleanupFailureAudit.Phase.DISPLAY_RELEASE);
        deadline.record("cleanup_deadline",1000,2400,2500);
        yes("PROFILE_CLEANUP_DEADLINE".equals(((Map<?,?>)deadline.evidence().get("first_failure")).get("code")),"watchdog code lost");
        BackgroundDisplayBroker.ProfileCleanupFailureAudit bounded=new BackgroundDisplayBroker.ProfileCleanupFailureAudit();
        bounded.record("arbitrary private text and\\npage contents",1000,2400,2500);
        yes("PROFILE_CLEANUP_FAILURE_UNCLASSIFIED".equals(((Map<?,?>)bounded.evidence().get("first_failure")).get("code")),"arbitrary text retained");
        for(String key:new String[]{"diagnostics_grant_authority","provides_cleanup_proof","allows_input_or_model_resumption"})
            yes(Boolean.FALSE.equals(audit.evidence().get(key)),"diagnostic grants authority: "+key);
        try{audit.evidence().clear();throw new AssertionError("mutable evidence");}catch(UnsupportedOperationException expected){assertions++;}
        try{first.clear();throw new AssertionError("mutable failure");}catch(UnsupportedOperationException expected){assertions++;}
        System.out.println(new JSONObject().put("passed",true).put("assertions",assertions)
                .put("original_close_reason_changed",false).put("phone_qualification",false));
    }
}
