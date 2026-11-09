package org.trillionnium.hepta.local;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Pure recovery policy. A previous process can never resume or replay a task. */
public final class SessionRecovery {
    private static final Set<String> CLEAN_TERMINAL = new HashSet<String>(Arrays.asList(
            "not_started", "cancelled_before_start", "model_reported_done", "partial", "failed", "cancelled"));
    private static final Set<String> NOT_STARTED = new HashSet<String>(Arrays.asList(
            "not_started", "cancelled_before_start"));

    private SessionRecovery() {}

    public static final class Decision {
        public final boolean allowNewTask, priorRecordValid;
        public final boolean automaticResume = false;
        public final String reason, priorStatus, taskId, origin, instructionSha256, nonceSha256;

        private Decision(boolean allowed, boolean valid, String reason, Map<String, Object> value) {
            this.allowNewTask = allowed;
            this.priorRecordValid = valid;
            this.reason = reason;
            this.priorStatus = safeString(value, "status", 80);
            this.taskId = hex(value, "task_id", 32);
            this.origin = safeString(value, "origin", 80);
            this.instructionSha256 = hex(value, "instruction_sha256", 64);
            this.nonceSha256 = hex(value, "debug_nonce_sha256", 64);
        }
    }

    /** Only an actually absent record is a fresh session; read/parse errors are different. */
    public static Decision noPriorRecord() {
        return new Decision(true, true, "no_prior_record", null);
    }

    public static Decision unreadableRecord() {
        return new Decision(false, false, "unreadable_or_uncommitted_prior_record", null);
    }

    public static Decision evaluate(Map<String, Object> value, int expectedAppUid) {
        return evaluate(value, expectedAppUid, false);
    }

    /** Latch presence wins even when its contents are unreadable or the base record looks clean. */
    public static Decision evaluate(Map<String, Object> value, int expectedAppUid, boolean interruptionLatchPresent) {
        return evaluate(value, expectedAppUid, interruptionLatchPresent, null);
    }

    /** The new administrative idle state needs a verified persisted proof, never a JSON flag alone. */
    public static Decision evaluate(Map<String, Object> value, int expectedAppUid, boolean interruptionLatchPresent,
            RecoveryJournalTransaction.Proof acknowledgement) {
        if (interruptionLatchPresent) {
            return new Decision(false, false, "persistent_interruption_latch", value);
        }
        if (value == null || expectedAppUid < 10000
                || !"hepta.local-session.v1".equals(value.get("schema"))
                || integral(value.get("app_uid")) != expectedAppUid
                || integral(value.get("updated_wall_ms")) <= 0
                || safeString(value, "status", 80) == null
                || !(value.get("state") instanceof String)
                || !(value.get("pending") instanceof Boolean)
                || !(value.get("running") instanceof Boolean)
                || !(value.get("blocked") instanceof Boolean)
                || !(value.get("cleanup_known") instanceof Boolean)
                || !Boolean.FALSE.equals(value.get("external_model"))
                || !Boolean.FALSE.equals(value.get("automatic_resume"))
                || !nullableHex(value, "task_id", 32)
                || !nullableHex(value, "instruction_sha256", 64)
                || !nullableHex(value, "debug_nonce_sha256", 64)
                || !value.containsKey("origin")
                || (value.get("origin") != null && safeString(value, "origin", 80) == null)) {
            return new Decision(false, false, "invalid_or_incomplete_prior_record", value);
        }
        String status = (String)value.get("status");
        if (!Boolean.FALSE.equals(value.get("pending")) || !Boolean.FALSE.equals(value.get("running"))
                || !Boolean.FALSE.equals(value.get("blocked")) || !Boolean.TRUE.equals(value.get("cleanup_known"))) {
            return new Decision(false, true, "prior_activity_or_cleanup_unresolved", value);
        }
        if (RecoveryJournalTransaction.IDLE_STATUS.equals(status)) {
            boolean verified=acknowledgement!=null&&acknowledgement.matches(value,expectedAppUid);
            return new Decision(verified, true, verified?"owner_acknowledged_new_idle_old_cleanup_unknown"
                    :"new_idle_has_no_verified_acknowledgement", value);
        }
        if (!CLEAN_TERMINAL.contains(status)) {
            return new Decision(false, true, "prior_status_is_not_known_clean_terminal", value);
        }
        // A clean result must still identify the task reservation that produced it.
        if (hex(value, "instruction_sha256", 64) == null || safeString(value, "origin", 80) == null
                || (!NOT_STARTED.contains(status) && hex(value, "task_id", 32) == null)
                || (NOT_STARTED.contains(status) && value.get("task_id") != null)) {
            return new Decision(false, false, "terminal_record_has_invalid_identity", value);
        }
        if ("private_debug_nonce".equals(value.get("origin")) && hex(value, "debug_nonce_sha256", 64) == null) {
            return new Decision(false, false, "debug_terminal_record_has_no_nonce_binding", value);
        }
        return new Decision(true, true, "known_clean_terminal_no_replay", value);
    }

    private static long integral(Object value) {
        return value instanceof Integer || value instanceof Long ? ((Number)value).longValue() : -1;
    }

    private static boolean nullableHex(Map<String, Object> value, String name, int length) {
        return value.containsKey(name) && (value.get(name) == null || hex(value, name, length) != null);
    }

    private static String hex(Map<String, Object> value, String name, int length) {
        String text = safeString(value, name, length);
        return text != null && text.length() == length && text.matches("[0-9a-f]+") ? text : null;
    }

    private static String safeString(Map<String, Object> value, String name, int maxLength) {
        Object candidate = value == null ? null : value.get(name);
        if (!(candidate instanceof String)) return null;
        String text = (String)candidate;
        return !text.isEmpty() && text.length() <= maxLength && text.indexOf('\0') < 0 ? text : null;
    }
}
