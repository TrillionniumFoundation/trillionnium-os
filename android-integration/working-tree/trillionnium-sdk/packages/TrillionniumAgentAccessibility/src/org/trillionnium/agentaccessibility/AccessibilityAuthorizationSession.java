/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.agentaccessibility;

/**
 * Process-local generation binding for Android's per-user Accessibility authorization.
 *
 * <p>A generation is usable only while the injected OS authorization source still reports the
 * exact service enabled. Reconnects always receive a new generation, so queued work from an old
 * bind cannot become authorized by a later user grant.</p>
 */
final class AccessibilityAuthorizationSession {
    interface AuthorizationSource {
        boolean isSystemUserExplicitlyAuthorized();
    }

    private final AuthorizationSource mSource;
    private long mGenerationCounter;
    private long mActiveGeneration;

    AccessibilityAuthorizationSession(AuthorizationSource source) {
        if (source == null) throw new IllegalArgumentException("missing authorization source");
        mSource = source;
    }

    synchronized long activateIfAuthorized() {
        mActiveGeneration = 0;
        if (!authorized()) return 0;
        if (mGenerationCounter == Long.MAX_VALUE) return 0;
        long generation = ++mGenerationCounter;
        mActiveGeneration = generation;
        if (!authorized()) {
            mActiveGeneration = 0;
            return 0;
        }
        return generation;
    }

    synchronized boolean isCurrentAndAuthorized(long generation) {
        return generation > 0 && generation == mActiveGeneration && authorized()
                && generation == mActiveGeneration;
    }

    synchronized boolean isCurrent(long generation) {
        return generation > 0 && generation == mActiveGeneration;
    }

    synchronized void deactivate() {
        mActiveGeneration = 0;
    }

    private boolean authorized() {
        try {
            return mSource.isSystemUserExplicitlyAuthorized();
        } catch (RuntimeException unavailable) {
            return false;
        }
    }
}
