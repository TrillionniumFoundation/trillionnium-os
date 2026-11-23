package org.trillionnium.hepta.displayprobe;

import java.util.HashSet;

/** One created display, a group separated from all physical displays, and one original deadline.
 * Other virtual displays may share the group and its awake state. The lease controls only
 * its own power token; it confers no input or task/display cleanup authority over peers. */
final class OwnedDisplayPowerLease {
    static final long MAX_DURATION_MS = 900000L;
    static final int STATE_ON = 2;

    interface Clock { long elapsedRealtime(); }
    interface InitialWait {
        void observed(Scope scope, long elapsedMs) throws Exception;
        void pause(long millis) throws Exception;
    }
    interface ScreenLock {
        void acquire(long timeoutMs) throws Exception;
        boolean isHeld();
        void release() throws Exception;
    }
    interface Platform {
        Scope readScope() throws Exception;
        ScreenLock newScreenLock(int exactDisplayId) throws Exception;
    }
    static final class Scope {
        final int displayId, groupId, state;
        final String uniqueId;
        final int[] displayIds, groupIds, types;
        Scope(int displayId, int groupId, String uniqueId, int state,
                int[] displayIds, int[] groupIds, int[] types) {
            this.displayId = displayId; this.groupId = groupId;
            this.uniqueId = uniqueId; this.state = state;
            this.displayIds = displayIds == null ? null : displayIds.clone();
            this.groupIds = groupIds == null ? null : groupIds.clone();
            this.types = types == null ? null : types.clone();
        }
    }

    private final Platform platform;
    private final Clock clock;
    final int displayId, groupId;
    final String uniqueId;
    final long deadlineElapsedMs;
    private ScreenLock lock;
    private boolean acquired, closed;
    private Scope lastValidatedScope;
    private long acquiredElapsedMs, requestedTimeoutMs;

    OwnedDisplayPowerLease(Platform platform, Clock clock, int displayId, int groupId,
            String uniqueId, long deadlineElapsedMs) {
        if (platform == null || clock == null || displayId <= 1 || groupId <= 0
                || uniqueId == null || uniqueId.isEmpty())
            throw new SecurityException("owned screen lease identity unavailable");
        this.platform = platform; this.clock = clock;
        this.displayId = displayId; this.groupId = groupId; this.uniqueId = uniqueId;
        this.deadlineElapsedMs = deadlineElapsedMs;
        remaining();
    }

    private long remaining() {
        long now = clock.elapsedRealtime();
        if (now < 0 || deadlineElapsedMs <= now || deadlineElapsedMs - now > MAX_DURATION_MS)
            throw new SecurityException("owned screen lease deadline unavailable or expired");
        return deadlineElapsedMs - now;
    }

    private void validateIdentity(Scope scope) {
        if (scope == null || scope.displayId != displayId || scope.groupId != groupId
                || !uniqueId.equals(scope.uniqueId)
                || scope.displayIds == null || scope.groupIds == null || scope.types == null
                || scope.displayIds.length != scope.groupIds.length || scope.displayIds.length != scope.types.length
                || scope.displayIds.length < 3 || scope.displayIds.length > 4096)
            throw new SecurityException("owned screen lease scope differs");
        HashSet<Integer> ids = new HashSet<Integer>();
        int ownedMembers = 0;
        boolean main = false, cover = false, own = false;
        for (int i = 0; i < scope.displayIds.length; i++) {
            int id = scope.displayIds[i], group = scope.groupIds[i], type = scope.types[i];
            if (id < 0 || group < 0 || !ids.add(Integer.valueOf(id)))
                throw new SecurityException("complete display group census unavailable");
            if ((id == 0 || id == 1) ? type != 1 : type != 5)
                throw new SecurityException("physical or unknown display outside the reviewed physical pair");
            if (id == 0) main = group != groupId;
            if (id == 1) cover = group != groupId;
            if (id == displayId) own = group == groupId;
            if (group == groupId) {
                ownedMembers++;
            }
        }
        if (!main || !cover || !own || ownedMembers < 1)
            throw new SecurityException("owned display or physical group separation unavailable");
        lastValidatedScope = scope;
    }

    private void validate(Scope scope) {
        validateIdentity(scope);
        if (scope.state != STATE_ON)
            throw new SecurityException("owned screen lease scope differs");
    }

    /** Read-only initial readiness; the original strict acquire always reads again. */
    synchronized void awaitInitialOn(long initializationDeadline, InitialWait wait) throws Exception {
        long started = clock.elapsedRealtime();
        if (closed || acquired || lock != null || wait == null || started < 0
                || initializationDeadline <= started || initializationDeadline - started > 5000
                || initializationDeadline > deadlineElapsedMs)
            throw new SecurityException("original display initialization budget unavailable");
        while (true) {
            remaining();
            long now = clock.elapsedRealtime();
            if (now < started || now >= initializationDeadline)
                throw new SecurityException("created display did not become ON within initialization budget");
            Scope actual = platform.readScope();
            validateIdentity(actual);
            wait.observed(actual, clock.elapsedRealtime());
            now = clock.elapsedRealtime();
            if (now < started || now >= initializationDeadline)
                throw new SecurityException("created display readiness arrived after initialization budget");
            if (actual.state == STATE_ON) return;
            // Only initial UNKNOWN/OFF can be observed while awaiting automatic creation.
            // Neither state grants a lock, wake call, input, or a renewed deadline.
            if (actual.state != 0 && actual.state != 1)
                throw new SecurityException("unexpected initial display power state");
            wait.pause(Math.min(25L, initializationDeadline - now));
        }
    }

    synchronized void acquire() throws Exception {
        if (closed || acquired || lock != null)
            throw new SecurityException("owned screen lease is single use");
        try {
            validate(platform.readScope());
            long timeout = remaining();
            lock = platform.newScreenLock(displayId);
            if (lock == null) throw new SecurityException("display-scoped screen lock unavailable");
            acquiredElapsedMs = clock.elapsedRealtime();
            requestedTimeoutMs = remaining();
            if (requestedTimeoutMs > timeout) throw new SecurityException("monotonic clock moved backwards");
            lock.acquire(requestedTimeoutMs);
            acquired = true;
            requireLive();
        } catch (Exception failure) {
            try { close(); } catch (Exception cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    synchronized void requireLive() throws Exception {
        try {
            remaining();
            if (closed || !acquired || lock == null || !lock.isHeld())
                throw new SecurityException("owned screen lease is not held");
            validate(platform.readScope());
            remaining();
        } catch (Exception failure) {
            try { close(); } catch (Exception cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    synchronized int[] groupMembers() {
        if (lastValidatedScope == null) throw new SecurityException("validated group census unavailable");
        int count = 0;
        for (int group : lastValidatedScope.groupIds) if (group == groupId) count++;
        int[] members = new int[count]; int index = 0;
        for (int i = 0; i < lastValidatedScope.displayIds.length; i++)
            if (lastValidatedScope.groupIds[i] == groupId) members[index++] = lastValidatedScope.displayIds[i];
        return members;
    }

    synchronized long acquiredElapsedMs() { return acquiredElapsedMs; }
    synchronized long requestedTimeoutMs() { return requestedTimeoutMs; }
    synchronized boolean isHeld() { return !closed && acquired && lock != null && lock.isHeld(); }

    public synchronized void close() throws Exception {
        if (closed) return;
        closed = true;
        if (lock != null && lock.isHeld()) lock.release();
        if (lock != null && lock.isHeld()) throw new SecurityException("owned screen lease release unproved");
    }
}
