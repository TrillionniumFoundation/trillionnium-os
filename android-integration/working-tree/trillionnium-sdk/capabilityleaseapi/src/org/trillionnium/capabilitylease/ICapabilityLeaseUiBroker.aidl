/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.capabilitylease;

/** @hide */
interface ICapabilityLeaseUiBroker {
    /**
     * Returns one broker-authored immutable pending view.
     *
     * The fixed array layout is:
     * schema, exact challenge, exact HTTPS URI, destination host, subject user,
     * provider id, wall-clock expiry, elapsed-realtime expiry.
     */
    String[] fetchExactChallenge(String transportSchema, String pendingHandle);

    /**
     * Submits the exact hardware-signed receipt into durable quarantine.
     *
     * The fixed result layout is: status schema, state, submission operation id,
     * receipt id, exact status-tuple digest. A successful return does not release
     * the receipt to any effect backend.
     */
    String[] submitExactReceipt(String transportSchema, String pendingHandle,
            String submissionOperationId, String exactReceipt);

    /** Re-reads one exact durable submission outcome after a lost reply or restart. */
    String[] querySubmissionStatus(
            String transportSchema, String pendingHandle, String submissionOperationId);

    /**
     * Records that AiShell received and verified the exact quarantined result tuple.
     * Only this outer delivery acknowledgement may release it to the backend.
     */
    String[] acknowledgeSubmissionDelivery(String transportSchema, String pendingHandle,
            String submissionOperationId, String receiptId, String statusTupleSha256);

    /** Cancels one still-pending handle. */
    void cancelPending(String transportSchema, String pendingHandle);
}
