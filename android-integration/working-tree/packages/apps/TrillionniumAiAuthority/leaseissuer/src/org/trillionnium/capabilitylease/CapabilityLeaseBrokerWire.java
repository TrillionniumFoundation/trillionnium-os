/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.capabilitylease;

/** Strict decoder for the fixed Binder pending-view tuple. */
final class CapabilityLeaseBrokerWire {
    private CapabilityLeaseBrokerWire() {}

    static CapabilityLeaseBrokerClient.PendingChallenge decodePendingView(String[] view) {
        if (view == null || view.length != CapabilityLeaseUiProtocol.VIEW_FIELDS
                || !CapabilityLeaseUiProtocol.VIEW_SCHEMA.equals(view[0])) {
            throw denied();
        }
        return new CapabilityLeaseBrokerClient.PendingChallenge(
                require(view[0]), require(view[1]), require(view[2]), require(view[3]),
                parseInt(view[4]), require(view[5]), parseLong(view[6]),
                parseLong(view[7]));
    }

    static CapabilityLeaseBrokerClient.Submission decodeSubmissionStatus(
            String handle, String expectedOperationId, String[] status) {
        String exactHandle = LeasePendingHandle.requireExact(handle);
        String exactExpectedOperationId =
                CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                        expectedOperationId);
        if (status == null
                || status.length != CapabilityLeaseUiProtocol.SUBMISSION_STATUS_FIELDS
                || !CapabilityLeaseUiProtocol.SUBMISSION_STATUS_SCHEMA.equals(status[0])
                || !exactExpectedOperationId.equals(status[2])) {
            throw denied();
        }
        return new CapabilityLeaseBrokerClient.Submission(
                exactHandle, require(status[1]), require(status[2]), present(status[3]),
                require(status[4]));
    }

    private static String present(String value) {
        if (value == null) throw denied();
        return value;
    }

    private static String require(String value) {
        if (value == null || value.isEmpty()) throw denied();
        return value;
    }

    private static int parseInt(String value) {
        long parsed = parseLong(value);
        if (parsed > Integer.MAX_VALUE) throw denied();
        return (int) parsed;
    }

    private static long parseLong(String value) {
        String exact = require(value);
        if (!exact.matches("0|[1-9][0-9]{0,18}")) throw denied();
        try {
            long parsed = Long.parseLong(exact);
            if (parsed < 0 || !Long.toString(parsed).equals(exact)) throw denied();
            return parsed;
        } catch (NumberFormatException invalid) {
            throw denied();
        }
    }

    private static SecurityException denied() {
        return new SecurityException("capability_lease_broker_response_denied");
    }
}
