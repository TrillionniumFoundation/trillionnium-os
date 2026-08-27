/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.agentaccessibility;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/** Owns the replay-ledger close only after every retired backend worker has terminated. */
final class AccessibilityDeferredClose {
    interface CloseAction {
        void close() throws Exception;
    }

    interface FailureReporter {
        void report(Exception failure);
    }

    private AccessibilityDeferredClose() {}

    static Thread closeAfterTermination(
            ExecutorService[] workers,
            CloseAction closeAction,
            FailureReporter failureReporter) {
        if (workers == null || closeAction == null || failureReporter == null) {
            throw new IllegalArgumentException("invalid deferred close ownership");
        }
        ExecutorService[] ownedWorkers = workers.clone();
        for (ExecutorService worker : ownedWorkers) {
            if (worker == null) {
                throw new IllegalArgumentException("missing deferred close worker");
            }
        }
        Thread closer = new Thread(() -> {
            boolean interrupted = false;
            for (ExecutorService worker : ownedWorkers) {
                while (!worker.isTerminated()) {
                    try {
                        worker.awaitTermination(1, TimeUnit.DAYS);
                    } catch (InterruptedException ignored) {
                        // Closing the ledger early is unsafe. Finish ownership transfer first.
                        interrupted = true;
                    }
                }
            }
            try {
                closeAction.close();
            } catch (Exception failure) {
                failureReporter.report(failure);
            } finally {
                if (interrupted) Thread.currentThread().interrupt();
            }
        }, "trillionnium-accessibility-ledger-close");
        closer.setDaemon(true);
        closer.start();
        return closer;
    }
}
