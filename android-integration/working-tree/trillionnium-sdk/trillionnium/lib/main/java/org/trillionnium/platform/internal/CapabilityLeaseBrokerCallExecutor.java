/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/** Bounded off-Binder executor for issuer broker storage and receipt work. */
final class CapabilityLeaseBrokerCallExecutor implements AutoCloseable {
    static final String ERROR_SATURATED = "capability_lease_broker_saturated";
    static final String ERROR_RATE_LIMITED = "capability_lease_broker_rate_limited";
    static final String ERROR_TIMEOUT = "capability_lease_broker_timeout";
    static final String ERROR_INTERRUPTED = "capability_lease_broker_interrupted";
    static final String ERROR_INDETERMINATE = "capability_lease_broker_indeterminate";

    private static final int DEFAULT_QUEUE_CAPACITY = 4;
    private static final int DEFAULT_MAX_OUTSTANDING_PER_UID = 2;
    private static final int DEFAULT_MAX_CALLS_PER_WINDOW = 16;
    private static final long DEFAULT_WINDOW_NANOS = TimeUnit.SECONDS.toNanos(10);
    private static final long DEFAULT_TIMEOUT_MILLIS = 10_000;

    interface NanoClock {
        long nowNanos();
    }

    private final Object mLock = new Object();
    private final Map<Integer, UidState> mUidStates = new HashMap<>();
    private final ThreadPoolExecutor mExecutor;
    private final int mMaxOutstandingPerUid;
    private final int mMaxCallsPerWindow;
    private final long mWindowNanos;
    private final long mTimeoutMillis;
    private final NanoClock mClock;
    private boolean mClosed;
    private boolean mPoisoned;

    CapabilityLeaseBrokerCallExecutor() {
        this(
                DEFAULT_QUEUE_CAPACITY,
                DEFAULT_MAX_OUTSTANDING_PER_UID,
                DEFAULT_MAX_CALLS_PER_WINDOW,
                DEFAULT_WINDOW_NANOS,
                DEFAULT_TIMEOUT_MILLIS,
                System::nanoTime);
    }

    CapabilityLeaseBrokerCallExecutor(
            int queueCapacity,
            int maxOutstandingPerUid,
            int maxCallsPerWindow,
            long windowNanos,
            long timeoutMillis,
            NanoClock clock) {
        if (queueCapacity <= 0 || maxOutstandingPerUid <= 0 || maxCallsPerWindow <= 0
                || windowNanos <= 0 || timeoutMillis <= 0 || clock == null) {
            throw new IllegalArgumentException("invalid capability-lease executor bounds");
        }
        mMaxOutstandingPerUid = maxOutstandingPerUid;
        mMaxCallsPerWindow = maxCallsPerWindow;
        mWindowNanos = windowNanos;
        mTimeoutMillis = timeoutMillis;
        mClock = clock;
        mExecutor = new ThreadPoolExecutor(
                1,
                1,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity),
                runnable -> {
                    Thread thread = new Thread(
                            runnable, "trillionnium-capability-lease-issuer");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    <T> T call(int verifiedUid, Callable<T> work) throws Exception {
        if (verifiedUid < 10_000 || work == null) {
            throw new SecurityException("capability_lease_broker_caller_denied");
        }
        admit(verifiedUid);
        TrackedFutureTask<T> task = new TrackedFutureTask<>(verifiedUid, work);
        try {
            mExecutor.execute(task);
        } catch (RejectedExecutionException saturated) {
            task.releaseWithoutRun();
            throw new CallException(closedFailure());
        }
        try {
            return task.get(mTimeoutMillis, TimeUnit.MILLISECONDS);
        } catch (TimeoutException timeout) {
            if (cancelAndReleaseIfQueued(task)) {
                // The task never began, so there is no possible durable mutation.
                throw new CallException(ERROR_TIMEOUT);
            }
            poison();
            throw new CallException(ERROR_INDETERMINATE);
        } catch (InterruptedException interrupted) {
            boolean definitelyNotStarted = cancelAndReleaseIfQueued(task);
            if (!definitelyNotStarted) poison();
            Thread.currentThread().interrupt();
            throw new CallException(definitelyNotStarted
                    ? ERROR_INTERRUPTED : ERROR_INDETERMINATE);
        } catch (CancellationException canceled) {
            throw new CallException(closedFailure());
        } catch (ExecutionException failed) {
            Throwable cause = failed.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new CallException(ERROR_SATURATED);
        }
    }

    private void admit(int uid) throws CallException {
        synchronized (mLock) {
            if (mClosed) throw new CallException(ERROR_SATURATED);
            if (mPoisoned) throw new CallException(ERROR_INDETERMINATE);
            long now = mClock.nowNanos();
            UidState state = mUidStates.get(uid);
            if (state == null) {
                state = new UidState(now);
                mUidStates.put(uid, state);
            } else if (now < state.windowStartNanos
                    || now - state.windowStartNanos >= mWindowNanos) {
                state.windowStartNanos = now;
                state.callsInWindow = 0;
            }
            if (state.callsInWindow >= mMaxCallsPerWindow) {
                throw new CallException(ERROR_RATE_LIMITED);
            }
            if (state.outstanding >= mMaxOutstandingPerUid) {
                throw new CallException(ERROR_SATURATED);
            }
            state.callsInWindow++;
            state.outstanding++;
        }
    }

    private boolean cancelAndReleaseIfQueued(TrackedFutureTask<?> task) {
        task.cancel(true);
        if (mExecutor.remove(task)) {
            task.releaseWithoutRun();
            return true;
        }
        return false;
    }

    private void poison() {
        final List<Runnable> abandoned;
        synchronized (mLock) {
            // A started durable call may ignore interruption and commit after its waiter times out.
            // Keep this transport closed for the rest of the process rather than admit retries
            // against an outcome whose publication boundary is no longer synchronously observed.
            if (mPoisoned) return;
            mPoisoned = true;
            abandoned = mExecutor.shutdownNow();
        }
        cancelAndRelease(abandoned);
    }

    private String closedFailure() {
        synchronized (mLock) {
            return mPoisoned ? ERROR_INDETERMINATE : ERROR_SATURATED;
        }
    }

    private void release(int uid) {
        synchronized (mLock) {
            UidState state = mUidStates.get(uid);
            if (state == null || state.outstanding <= 0) {
                throw new IllegalStateException("capability-lease executor accounting corrupt");
            }
            state.outstanding--;
            long now = mClock.nowNanos();
            if (state.outstanding == 0
                    && (now < state.windowStartNanos
                            || now - state.windowStartNanos >= mWindowNanos)) {
                mUidStates.remove(uid);
            }
        }
    }

    int outstandingForTest(int uid) {
        synchronized (mLock) {
            UidState state = mUidStates.get(uid);
            return state == null ? 0 : state.outstanding;
        }
    }

    @Override
    public void close() {
        final List<Runnable> abandoned;
        synchronized (mLock) {
            if (mClosed) return;
            mClosed = true;
            abandoned = mExecutor.shutdownNow();
        }
        cancelAndRelease(abandoned);
    }

    private void cancelAndRelease(List<Runnable> abandoned) {
        for (Runnable runnable : abandoned) {
            if (runnable instanceof TrackedFutureTask<?>) {
                TrackedFutureTask<?> task = (TrackedFutureTask<?>) runnable;
                task.cancel(false);
                task.releaseWithoutRun();
            }
        }
    }

    private final class TrackedFutureTask<T> extends FutureTask<T> {
        private final int mUid;
        private final AtomicBoolean mReleased = new AtomicBoolean();

        TrackedFutureTask(int uid, Callable<T> work) {
            super(work);
            mUid = uid;
        }

        @Override
        public void run() {
            try {
                super.run();
            } finally {
                releaseOnce();
            }
        }

        void releaseWithoutRun() {
            releaseOnce();
        }

        private void releaseOnce() {
            if (mReleased.compareAndSet(false, true)) {
                release(mUid);
            }
        }
    }

    private static final class UidState {
        long windowStartNanos;
        int callsInWindow;
        int outstanding;

        UidState(long windowStartNanos) {
            this.windowStartNanos = windowStartNanos;
        }
    }

    static final class CallException extends Exception {
        private static final long serialVersionUID = 1L;

        final String code;

        CallException(String code) {
            super(code);
            this.code = code;
        }
    }
}
