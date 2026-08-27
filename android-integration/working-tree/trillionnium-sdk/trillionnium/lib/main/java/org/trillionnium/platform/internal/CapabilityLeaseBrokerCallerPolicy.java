/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

/** Closed role/operation and identity-pin policy for enrolled broker Binder façades. */
final class CapabilityLeaseBrokerCallerPolicy {
    enum Role { AI_SHELL, ISSUER, ACCESSIBILITY }

    enum Operation {
        UI_POLL(Role.AI_SHELL),
        UI_ACK_SUBMISSION(Role.AI_SHELL),
        ISSUER_FETCH(Role.ISSUER),
        ISSUER_SUBMIT(Role.ISSUER),
        ISSUER_QUERY_SUBMISSION(Role.ISSUER),
        ISSUER_CANCEL(Role.ISSUER),
        BACKEND_CREATE(Role.ACCESSIBILITY),
        BACKEND_FETCH_RECEIPT(Role.ACCESSIBILITY),
        BACKEND_ACK_PREPARED(Role.ACCESSIBILITY);

        final Role requiredRole;

        Operation(Role requiredRole) {
            this.requiredRole = requiredRole;
        }
    }

    static final class CallerPin {
        final Role role;
        final String packageName;
        final String signerSha256;
        final String selinuxContext;

        CallerPin(Role role, String packageName, String signerSha256, String selinuxContext) {
            if (role == null || packageName == null
                    || !packageName.matches("[a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*)+")
                    || packageName.length() > 128
                    || signerSha256 == null || !signerSha256.matches("[0-9a-f]{64}")
                    || signerSha256.equals("0".repeat(64))
                    || selinuxContext == null
                    || selinuxContext.length() > 128
                    || !selinuxContext.matches("u:r:[a-z0-9_]+:s0")) {
                throw new IllegalArgumentException("invalid broker caller pin");
            }
            this.role = role;
            this.packageName = packageName;
            this.signerSha256 = signerSha256;
            this.selinuxContext = selinuxContext;
        }
    }

    static final class ObservedCaller {
        final int uid;
        final int pid;
        final int androidUserId;
        final boolean applicationUid;
        final String packageName;
        final int packagesForUid;
        final String signerSha256;
        final String selinuxContext;

        ObservedCaller(int uid, int pid, int androidUserId, boolean applicationUid,
                String packageName, int packagesForUid, String signerSha256,
                String selinuxContext) {
            this.uid = uid;
            this.pid = pid;
            this.androidUserId = androidUserId;
            this.applicationUid = applicationUid;
            this.packageName = packageName;
            this.packagesForUid = packagesForUid;
            this.signerSha256 = signerSha256;
            this.selinuxContext = selinuxContext;
        }
    }

    static final class VerifiedCaller {
        final Role role;
        final int uid;
        final int pid;

        private VerifiedCaller(Role role, int uid, int pid) {
            this.role = role;
            this.uid = uid;
            this.pid = pid;
        }
    }

    private CapabilityLeaseBrokerCallerPolicy() {}

    static VerifiedCaller verify(Operation operation, CallerPin pin, ObservedCaller caller) {
        if (operation == null || pin == null || caller == null
                || operation.requiredRole != pin.role || caller.uid < 10_000 || caller.pid <= 0
                || caller.androidUserId != 0 || !caller.applicationUid
                || caller.packagesForUid != 1 || !pin.packageName.equals(caller.packageName)
                || !pin.signerSha256.equals(caller.signerSha256)
                || !pin.selinuxContext.equals(caller.selinuxContext)) {
            throw new SecurityException("capability_lease_broker_caller_denied");
        }
        return new VerifiedCaller(pin.role, caller.uid, caller.pid);
    }
}
