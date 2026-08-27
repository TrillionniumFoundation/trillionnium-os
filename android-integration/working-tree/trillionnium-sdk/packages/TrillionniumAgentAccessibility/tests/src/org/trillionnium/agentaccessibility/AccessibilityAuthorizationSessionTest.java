/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.agentaccessibility;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class AccessibilityAuthorizationSessionTest {
    @Test
    public void disabledSourceNeverActivates() {
        MutableAuthorization source = new MutableAuthorization(false);
        AccessibilityAuthorizationSession session =
                new AccessibilityAuthorizationSession(source);

        long generation = session.activateIfAuthorized();

        assertTrue(generation == 0);
        assertFalse(session.isCurrentAndAuthorized(generation));
    }

    @Test
    public void revokeInvalidatesCurrentGenerationAndReconnectDoesNotReviveOldWork() {
        MutableAuthorization source = new MutableAuthorization(true);
        AccessibilityAuthorizationSession session =
                new AccessibilityAuthorizationSession(source);
        long first = session.activateIfAuthorized();
        assertTrue(first > 0);
        assertTrue(session.isCurrentAndAuthorized(first));

        source.authorized = false;
        assertFalse(session.isCurrentAndAuthorized(first));

        source.authorized = true;
        long second = session.activateIfAuthorized();
        assertTrue(second > 0);
        assertNotEquals(first, second);
        assertFalse(session.isCurrentAndAuthorized(first));
        assertTrue(session.isCurrentAndAuthorized(second));
    }

    @Test
    public void authorizationSourceFailureIsClosed() {
        AccessibilityAuthorizationSession session = new AccessibilityAuthorizationSession(
                () -> { throw new IllegalStateException("framework unavailable"); });
        assertTrue(session.activateIfAuthorized() == 0);
        assertFalse(session.isCurrentAndAuthorized(1));
    }

    private static final class MutableAuthorization
            implements AccessibilityAuthorizationSession.AuthorizationSource {
        boolean authorized;

        MutableAuthorization(boolean authorized) {
            this.authorized = authorized;
        }

        @Override
        public boolean isSystemUserExplicitlyAuthorized() {
            return authorized;
        }
    }
}
