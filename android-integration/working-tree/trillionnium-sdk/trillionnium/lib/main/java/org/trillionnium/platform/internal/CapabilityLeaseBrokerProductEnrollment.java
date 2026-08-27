/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import android.content.Context;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Fail-closed product activation boundary for the live broker lifecycle. */
final class CapabilityLeaseBrokerProductEnrollment {
    private static final Path TRUST_CONFIG = Path.of(
            "/system_ext/etc/trillionnium/capability-lease-trust.v1.json");
    private static final int MAX_TRUST_BYTES = 512 * 1024;

    private CapabilityLeaseBrokerProductEnrollment() {}

    static CapabilityLeaseBrokerService.Enrollment load(Context context) throws Exception {
        if (context == null || android.os.Process.myUid() != android.os.Process.SYSTEM_UID) {
            throw new SecurityException("capability_lease_system_server_identity_denied");
        }
        byte[] encoded = Files.readAllBytes(TRUST_CONFIG);
        if (encoded.length == 0 || encoded.length > MAX_TRUST_BYTES) {
            throw new SecurityException("capability_lease_trust_config_unavailable");
        }
        CapabilityLeaseTrustConfigLoader.Result trust = CapabilityLeaseTrustConfigLoader.load(
                new String(encoded, StandardCharsets.UTF_8));
        if (!(trust instanceof CapabilityLeaseTrustConfigLoader.Enabled)) {
            throw new SecurityException("capability_lease_trust_disabled");
        }

        // A trust JSON is necessary but never sufficient.  Product activation also requires an
        // independently generated caller-pin source, the measured receipt/destination providers,
        // and an OS-owned hardware rollback-epoch proof.  None has a production producer in the
        // current tree, so an enabled JSON alone must remain unable to publish Binder authority.
        throw new SecurityException(CapabilityLeaseRollbackEpochStateProof.STATUS);
    }
}
