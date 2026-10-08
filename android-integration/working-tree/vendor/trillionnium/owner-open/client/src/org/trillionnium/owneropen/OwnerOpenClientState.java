package org.trillionnium.owneropen;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/** Non-secret client read model. This class cannot connect, submit or replay an effect. */
public final class OwnerOpenClientState {
    public static final String SCHEMA = "org.trillionnium.owneropen.client-session.v1";
    private static final Pattern UUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

    // Distinct Host interfaces. None is the durable turn.inspect frame-index domain.
    public enum CursorDomain {
        TRANSPORT_EVENT("transport_event"),
        JOB_RUNTIME_EVENT("job_runtime_event"),
        JOB_JOURNAL_RECORD("job_journal_record");

        public final String wireName;

        CursorDomain(String wireName) {
            this.wireName = wireName;
        }
    }

    public static final class Cursor {
        public final CursorDomain domain;
        // Digest of the verified non-secret producer instance/epoch, not a token or credential.
        public final String producerEpochSha256;
        public final long inclusiveCursor;

        public Cursor(CursorDomain domain, String producerEpochSha256, long inclusiveCursor) {
            this.domain = Objects.requireNonNull(domain, "cursor domain");
            if (producerEpochSha256 == null || producerEpochSha256.length() != 64
                    || !SHA256.matcher(producerEpochSha256).matches()) {
                throw new IllegalArgumentException("invalid producer epoch digest");
            }
            if (inclusiveCursor < 0) {
                throw new IllegalArgumentException("cursor exceeds signed nonnegative range");
            }
            this.producerEpochSha256 = producerEpochSha256;
            this.inclusiveCursor = inclusiveCursor;
        }
    }

    public final String sessionId;
    public final String taskId;
    public final String turnId;
    public final Map<CursorDomain, Cursor> cursors;

    public OwnerOpenClientState(String sessionId, String taskId, String turnId,
            Map<CursorDomain, Cursor> cursors) {
        this.sessionId = requireIdentity(sessionId, "session-");
        this.taskId = requireIdentity(taskId, "task-");
        this.turnId = turnId == null ? null : requireIdentity(turnId, "turn-");
        Objects.requireNonNull(cursors, "cursors");
        if (cursors.size() > CursorDomain.values().length || (turnId == null && !cursors.isEmpty())) {
            throw new IllegalArgumentException("cursors require one selected turn");
        }
        EnumMap<CursorDomain, Cursor> copy = new EnumMap<>(CursorDomain.class);
        int visited = 0;
        for (Map.Entry<CursorDomain, Cursor> entry : cursors.entrySet()) {
            Cursor cursor = Objects.requireNonNull(entry.getValue(), "cursor");
            if (++visited > CursorDomain.values().length || entry.getKey() != cursor.domain
                    || copy.containsKey(cursor.domain)) {
                throw new IllegalArgumentException("cursor domain mismatch");
            }
            copy.put(cursor.domain, cursor);
        }
        this.cursors = Collections.unmodifiableMap(copy);
    }

    public static OwnerOpenClientState identity(String sessionId, String taskId, String turnId) {
        return new OwnerOpenClientState(sessionId, taskId, turnId,
                Collections.emptyMap());
    }

    /** Caller must invoke this only for a new explicit user Send, never during restore. */
    public OwnerOpenClientState selectTurnForExplicitSend(String newTurnId) {
        requireIdentity(newTurnId, "turn-");
        if (newTurnId.equals(turnId)) {
            throw new IllegalArgumentException("new Send must have a new turn identity");
        }
        return identity(sessionId, taskId, newTurnId);
    }

    /** The caller advances only after validating and consuming the corresponding read evidence. */
    public OwnerOpenClientState withObservedCursor(Cursor observed) {
        Objects.requireNonNull(observed, "observed cursor");
        if (turnId == null) {
            throw new IllegalArgumentException("no selected turn");
        }
        Cursor previous = cursors.get(observed.domain);
        if (previous != null && (!previous.producerEpochSha256.equals(observed.producerEpochSha256)
                || observed.inclusiveCursor < previous.inclusiveCursor)) {
            throw new IllegalArgumentException("cursor requires explicit epoch reconciliation");
        }
        EnumMap<CursorDomain, Cursor> next = new EnumMap<>(CursorDomain.class);
        next.putAll(cursors);
        next.put(observed.domain, observed);
        return new OwnerOpenClientState(sessionId, taskId, turnId, next);
    }

    /** Pure selection for an explicit read request. It never starts transport or an effect. */
    public long cursorForExplicitInspect(CursorDomain domain, String verifiedProducerEpochSha256) {
        Objects.requireNonNull(domain, "cursor domain");
        if (turnId == null || verifiedProducerEpochSha256 == null
                || verifiedProducerEpochSha256.length() != 64
                || !SHA256.matcher(verifiedProducerEpochSha256).matches()) {
            throw new IllegalArgumentException("inspect needs selected turn and verified epoch");
        }
        Cursor selected = cursors.get(domain);
        if (selected == null) {
            return 0;
        }
        if (!selected.producerEpochSha256.equals(verifiedProducerEpochSha256)) {
            throw new IllegalArgumentException("inspect producer epoch changed; reconcile explicitly");
        }
        return selected.inclusiveCursor;
    }

    static void requireSuccessor(OwnerOpenClientState previous, OwnerOpenClientState next) {
        if (!previous.sessionId.equals(next.sessionId) || !previous.taskId.equals(next.taskId)) {
            throw new IllegalArgumentException("session/task replacement requires a separate workflow");
        }
        if (!Objects.equals(previous.turnId, next.turnId)) {
            if (next.turnId == null || !next.cursors.isEmpty()) {
                throw new IllegalArgumentException("new selected turn must have empty cursors");
            }
            return;
        }
        for (Cursor previousCursor : previous.cursors.values()) {
            Cursor nextCursor = next.cursors.get(previousCursor.domain);
            if (nextCursor == null
                    || !previousCursor.producerEpochSha256.equals(nextCursor.producerEpochSha256)
                    || nextCursor.inclusiveCursor < previousCursor.inclusiveCursor) {
                throw new IllegalArgumentException("cursor removal/epoch change/regression rejected");
            }
        }
    }

    private static String requireIdentity(String value, String prefix) {
        if (value == null || value.length() != prefix.length() + 36 || !value.startsWith(prefix)
                || !UUID.matcher(value.substring(prefix.length())).matches()) {
            throw new IllegalArgumentException("invalid local client identity");
        }
        return value;
    }
}
