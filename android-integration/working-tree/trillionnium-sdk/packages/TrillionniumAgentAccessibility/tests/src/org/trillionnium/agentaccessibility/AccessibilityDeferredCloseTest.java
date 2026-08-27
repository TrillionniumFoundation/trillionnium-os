/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.agentaccessibility;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class AccessibilityDeferredCloseTest {
    @Test
    public void closeWaitsUntilInterruptedWorkerActuallyTerminates() throws Exception {
        ThreadPoolExecutor worker = executor();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch closed = new CountDownLatch(1);
        AtomicReference<Exception> failure = new AtomicReference<>();
        worker.execute(() -> {
            started.countDown();
            boolean done = false;
            while (!done) {
                try {
                    release.await();
                    done = true;
                } catch (InterruptedException ignored) {
                    // Keep the worker alive past shutdownNow to exercise deferred ownership.
                }
            }
        });
        assertTrue(started.await(1, TimeUnit.SECONDS));
        worker.shutdownNow();
        Thread closer = AccessibilityDeferredClose.closeAfterTermination(
                new ExecutorService[] {worker}, closed::countDown, failure::set);
        assertFalse(closed.await(100, TimeUnit.MILLISECONDS));
        release.countDown();
        assertTrue(closed.await(1, TimeUnit.SECONDS));
        closer.join(1_000);
        if (failure.get() != null) fail(failure.get().toString());
    }

    @Test
    public void shutdownFromWorkerDoesNotSelfJoinBeforeDeferredClose() throws Exception {
        ThreadPoolExecutor worker = executor();
        CountDownLatch closed = new CountDownLatch(1);
        AtomicReference<Exception> failure = new AtomicReference<>();
        worker.execute(() -> {
            worker.shutdownNow();
            AccessibilityDeferredClose.closeAfterTermination(
                    new ExecutorService[] {worker}, closed::countDown, failure::set);
        });
        assertTrue(closed.await(1, TimeUnit.SECONDS));
        if (failure.get() != null) fail(failure.get().toString());
    }

    private static ThreadPoolExecutor executor() {
        return new ThreadPoolExecutor(
                1,
                1,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(1),
                runnable -> {
                    Thread thread = new Thread(runnable, "accessibility-close-test");
                    thread.setDaemon(true);
                    return thread;
                });
    }
}
