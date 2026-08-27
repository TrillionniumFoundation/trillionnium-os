/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.platform.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public final class CapabilityLeaseBrokerCallExecutorTest {
    private static final int UID = 10_123;

    @Test
    public void perUidOutstandingLimitRejectsBeforeUnboundedQueueing() throws Exception {
        CapabilityLeaseBrokerCallExecutor calls = executor(4, 2, 100, 5_000, new AtomicLong());
        ExecutorService callers = Executors.newFixedThreadPool(2);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            Future<String> first = callers.submit(() -> calls.call(UID, () -> {
                started.countDown();
                release.await();
                return "first";
            }));
            if (!started.await(1, TimeUnit.SECONDS)) fail("worker did not start");
            Future<String> second = callers.submit(() -> calls.call(UID, () -> "second"));
            awaitOutstanding(calls, UID, 2);
            assertCallError(CapabilityLeaseBrokerCallExecutor.ERROR_SATURATED,
                    () -> calls.call(UID, () -> "third"));
            release.countDown();
            assertEquals("first", first.get(1, TimeUnit.SECONDS));
            assertEquals("second", second.get(1, TimeUnit.SECONDS));
        } finally {
            release.countDown();
            callers.shutdownNow();
            calls.close();
        }
    }

    @Test
    public void timedOutRunningCallRetainsUidOccupancyUntilWorkActuallyStops() throws Exception {
        CapabilityLeaseBrokerCallExecutor calls = executor(2, 1, 100, 50, new AtomicLong());
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            assertCallError(CapabilityLeaseBrokerCallExecutor.ERROR_INDETERMINATE,
                    () -> calls.call(UID, () -> {
                        started.countDown();
                        boolean done = false;
                        while (!done) {
                            try {
                                release.await();
                                done = true;
                            } catch (InterruptedException ignored) {
                                // Simulate storage code that has not reached a safe stop point yet.
                            }
                        }
                        return "late";
                    }));
            if (!started.await(1, TimeUnit.SECONDS)) fail("worker did not start");
            assertEquals(1, calls.outstandingForTest(UID));
            assertCallError(CapabilityLeaseBrokerCallExecutor.ERROR_INDETERMINATE,
                    () -> calls.call(UID, () -> "must-not-run"));
            release.countDown();
            awaitOutstanding(calls, UID, 0);
            assertCallError(CapabilityLeaseBrokerCallExecutor.ERROR_INDETERMINATE,
                    () -> calls.call(UID, () -> "must-never-run"));
        } finally {
            release.countDown();
            calls.close();
        }
    }

    @Test
    public void uncertainTimeoutCancelsAdmittedQueueAndPermanentlyPoisonsTransport()
            throws Exception {
        CapabilityLeaseBrokerCallExecutor calls = executor(2, 2, 100, 500, new AtomicLong());
        ExecutorService callers = Executors.newFixedThreadPool(2);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean queuedRan = new AtomicBoolean();
        try {
            Future<String> first = callers.submit(() -> calls.call(UID, () -> {
                started.countDown();
                boolean done = false;
                while (!done) {
                    try {
                        release.await();
                        done = true;
                    } catch (InterruptedException ignored) {
                        // The uncertain durable call remains in progress after timeout.
                    }
                }
                return "possibly-committed";
            }));
            assertTrue(started.await(1, TimeUnit.SECONDS));
            Thread.sleep(100);
            Future<String> queued = callers.submit(() -> calls.call(UID, () -> {
                queuedRan.set(true);
                return "must-not-run";
            }));
            awaitOutstanding(calls, UID, 2);
            assertEquals(CapabilityLeaseBrokerCallExecutor.ERROR_INDETERMINATE,
                    futureCallError(first));
            assertEquals(CapabilityLeaseBrokerCallExecutor.ERROR_INDETERMINATE,
                    futureCallError(queued));
            assertFalse(queuedRan.get());
            release.countDown();
            awaitOutstanding(calls, UID, 0);
            assertCallError(CapabilityLeaseBrokerCallExecutor.ERROR_INDETERMINATE,
                    () -> calls.call(UID, () -> "must-never-run"));
        } finally {
            release.countDown();
            callers.shutdownNow();
            calls.close();
        }
    }

    @Test
    public void fixedWindowRateLimitFailsClosedAndResetsOnlyAfterWindow() throws Exception {
        AtomicLong now = new AtomicLong(100);
        CapabilityLeaseBrokerCallExecutor calls = executor(2, 2, 2, 1_000, now);
        try {
            assertEquals("one", calls.call(UID, () -> "one"));
            assertEquals("two", calls.call(UID, () -> "two"));
            assertCallError(CapabilityLeaseBrokerCallExecutor.ERROR_RATE_LIMITED,
                    () -> calls.call(UID, () -> "three"));
            now.addAndGet(TimeUnit.SECONDS.toNanos(11));
            assertEquals("reset", calls.call(UID, () -> "reset"));
        } finally {
            calls.close();
        }
    }

    private static CapabilityLeaseBrokerCallExecutor executor(
            int queueCapacity,
            int maxOutstanding,
            int maxCalls,
            long timeoutMillis,
            AtomicLong now) {
        return new CapabilityLeaseBrokerCallExecutor(
                queueCapacity,
                maxOutstanding,
                maxCalls,
                TimeUnit.SECONDS.toNanos(10),
                timeoutMillis,
                now::get);
    }

    private static void awaitOutstanding(
            CapabilityLeaseBrokerCallExecutor calls, int uid, int expected) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        while (calls.outstandingForTest(uid) != expected && System.nanoTime() < deadline) {
            Thread.sleep(1);
        }
        assertEquals(expected, calls.outstandingForTest(uid));
    }

    private static void assertCallError(String expected, Call action) throws Exception {
        try {
            action.run();
            fail("expected capability-lease executor failure");
        } catch (CapabilityLeaseBrokerCallExecutor.CallException failure) {
            assertEquals(expected, failure.code);
        }
    }

    private static String futureCallError(Future<?> future) throws Exception {
        try {
            future.get(2, TimeUnit.SECONDS);
            fail("expected capability-lease executor failure");
            throw new AssertionError();
        } catch (ExecutionException failure) {
            if (!(failure.getCause() instanceof CapabilityLeaseBrokerCallExecutor.CallException)) {
                throw failure;
            }
            return ((CapabilityLeaseBrokerCallExecutor.CallException) failure.getCause()).code;
        }
    }

    private interface Call {
        void run() throws Exception;
    }
}
