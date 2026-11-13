import java.util.HashMap;
import java.util.Map;
import org.trillionnium.hepta.local.SessionRecovery;

/** Pure decisions only: this does not simulate Android AtomicFile or an Android process restart. */
public final class SessionRecoveryHostTest {
    private static int assertions;
    private static final int UID = 10234;
    private static final String TASK = "1234567890abcdef1234567890abcdef";
    private static final String HASH = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    private static Map<String, Object> terminal(String status) {
        Map<String, Object> value = new HashMap<String, Object>();
        value.put("schema", "hepta.local-session.v1");
        value.put("status", status);
        value.put("state", "previous task result");
        value.put("app_uid", UID);
        value.put("updated_wall_ms", 123456L);
        value.put("task_id", "not_started".equals(status) || "cancelled_before_start".equals(status) ? null : TASK);
        value.put("origin", "user_button");
        value.put("instruction_sha256", HASH);
        value.put("debug_nonce_sha256", null);
        value.put("pending", false);
        value.put("running", false);
        value.put("blocked", false);
        value.put("cleanup_known", true);
        value.put("external_model", false);
        value.put("automatic_resume", false);
        return value;
    }

    private static void check(boolean condition, String name) {
        assertions++;
        if (!condition) throw new AssertionError(name);
    }

    private static void blocked(Map<String, Object> value, String name) {
        SessionRecovery.Decision result = SessionRecovery.evaluate(value, UID);
        check(!result.allowNewTask, name);
        check(!result.automaticResume, name + " never resumes");
    }

    public static void main(String[] args) {
        check(SessionRecovery.noPriorRecord().allowNewTask, "absent record may start fresh");
        check(!SessionRecovery.noPriorRecord().automaticResume, "fresh never replays");
        check(!SessionRecovery.unreadableRecord().allowNewTask, "unreadable is not absent");
        check(!SessionRecovery.unreadableRecord().automaticResume, "unreadable never resumes");
        for (String state : new String[]{"not_started", "cancelled_before_start", "model_reported_done", "controller_verified_done", "partial", "failed", "cancelled"}) {
            SessionRecovery.Decision result = SessionRecovery.evaluate(terminal(state), UID);
            check(result.allowNewTask, state + " clean terminal permits a new task");
            check(result.priorRecordValid && !result.automaticResume, state + " retained, never replayed");
            SessionRecovery.Decision latched = SessionRecovery.evaluate(terminal(state), UID, true);
            check(!latched.allowNewTask && !latched.automaticResume, state + " cannot bypass persistent latch");
            check("persistent_interruption_latch".equals(latched.reason), state + " latch wins before terminal admission");
        }
        SessionRecovery.Decision noBaseLatched = SessionRecovery.evaluate(null, UID, true);
        check(!noBaseLatched.allowNewTask && !noBaseLatched.automaticResume, "latch alone blocks even with no base record");
        check("persistent_interruption_latch".equals(noBaseLatched.reason), "missing base does not erase latch");
        Map<String, Object> corruptBase = new HashMap<String, Object>();
        SessionRecovery.Decision corruptLatched = SessionRecovery.evaluate(corruptBase, UID, true);
        check(!corruptLatched.allowNewTask, "unreadable base plus latch stays blocked");
        check("persistent_interruption_latch".equals(corruptLatched.reason), "latch takes precedence over corrupt base");
        // The loader passes existence only. Empty/malformed latch content cannot turn this boolean off.
        check(!SessionRecovery.evaluate(terminal("failed"), UID, true).allowNewTask, "partial latch never authorizes reset");
        for (String state : new String[]{"pending", "running", "blocked", "interrupted", "termination_unknown", "idle", "completed", "future_status", "controller_claimed_done", "controller_verified_done_extra"}) {
            blocked(terminal(state), state + " is not known clean terminal");
        }
        for (String flag : new String[]{"pending", "running", "blocked"}) {
            Map<String, Object> value = terminal("failed"); value.put(flag, true);
            blocked(value, "active flag " + flag + " overrides terminal text");
        }
        Map<String, Object> value = terminal("model_reported_done"); value.put("cleanup_known", false);
        blocked(value, "done text cannot establish cleanup");
        value = terminal("controller_verified_done"); value.put("cleanup_known", false);
        blocked(value, "controller completion text cannot establish cleanup");
        value = terminal("controller_verified_done"); value.put("task_id", null);
        blocked(value, "controller completion requires its actual task reservation");
        value = terminal("controller_verified_done"); value.put("app_uid", UID + 1);
        blocked(value, "controller completion cannot borrow another app UID");
        for (String flag : new String[]{"pending", "running", "blocked", "cleanup_known", "external_model", "automatic_resume"}) {
            value = terminal("failed"); value.remove(flag); blocked(value, "missing " + flag);
            value = terminal("failed"); value.put(flag, "false"); blocked(value, "string is not boolean " + flag);
        }
        value = terminal("failed"); value.put("schema", "hepta.local-session.v2"); blocked(value, "unknown schema");
        value = terminal("failed"); value.put("app_uid", UID + 1); blocked(value, "wrong app UID");
        value = terminal("failed"); value.put("app_uid", (double)UID); blocked(value, "floating UID");
        value = terminal("failed"); value.put("updated_wall_ms", "123456"); blocked(value, "string timestamp");
        value = terminal("failed"); value.put("updated_wall_ms", 0L); blocked(value, "zero timestamp");
        value = terminal("failed"); value.put("automatic_resume", true); blocked(value, "resume from old contract refused");
        value = terminal("failed"); value.put("external_model", true); blocked(value, "unrecognized external-model receipt");
        value = terminal("failed"); value.put("task_id", null); blocked(value, "started terminal requires task identity");
        value = terminal("not_started"); value.put("task_id", TASK); blocked(value, "not-started cannot hide assigned task");
        value = terminal("failed"); value.put("instruction_sha256", null); blocked(value, "terminal requires owner binding");
        value = terminal("failed"); value.put("origin", null); blocked(value, "terminal requires origin");
        value = terminal("failed"); value.put("task_id", "../other"); blocked(value, "bad task identity");
        value = terminal("failed"); value.put("origin", "private_debug_nonce"); blocked(value, "debug result requires nonce");
        value.put("debug_nonce_sha256", HASH);
        check(SessionRecovery.evaluate(value, UID).allowNewTask, "clean nonce-bound debug terminal");
        value = terminal("running"); value.put("running", true); value.put("cleanup_known", false);
        SessionRecovery.Decision interrupted = SessionRecovery.evaluate(value, UID);
        check(TASK.equals(interrupted.taskId) && HASH.equals(interrupted.instructionSha256), "interrupted identifiers retained");
        check(!interrupted.allowNewTask && !interrupted.automaticResume, "retained identity is not authorization to replay");
        blocked(null, "null record is unreadable, not absent");
        System.out.println("{\"all_pass\":true,\"assertions\":" + assertions
                + ",\"android_or_phone_tested\":false,\"scope\":\"pure_session_recovery_decisions\"}");
    }
}
