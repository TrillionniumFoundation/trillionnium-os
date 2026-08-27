/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.capabilitylease;

/**
 * Issuer-role-only seam to the OS capability-lease broker.
 *
 * <p>The broker must authenticate the calling UID/package/signing certificate/SELinux domain on
 * every call. A fetched view is one immutable broker record: its exact challenge bytes and its
 * presentation fields are not independently caller-selectable. The transport is product-wired but
 * the service remains feature/enrollment HOLD until the trust config is enabled.
 * </p>
 */
interface CapabilityLeaseBrokerClient {
    PendingChallenge fetchExactChallenge(String pendingHandle) throws Exception;

    Submission submitExactReceipt(String pendingHandle, String exactReceipt) throws Exception;

    Submission querySubmissionStatus(String pendingHandle, String submissionOperationId)
            throws Exception;

    void cancelPending(String pendingHandle) throws Exception;

    /** Atomic broker-authored view of one pending open-URI challenge. */
    final class PendingChallenge {
        static final String VIEW_SCHEMA = CapabilityLeaseUiProtocol.VIEW_SCHEMA;
        private final String mExactChallenge;
        private final String mExactHttpsUri;
        private final String mDestinationHost;
        private final int mSubjectUserId;
        private final String mProviderId;
        private final long mExpiresAtMs;
        private final long mExpiresElapsedRealtimeMs;

        PendingChallenge(String viewSchema, String exactChallenge, String exactHttpsUri,
                String destinationHost, int subjectUserId, String providerId, long expiresAtMs,
                long expiresElapsedRealtimeMs) {
            if (!VIEW_SCHEMA.equals(viewSchema)) {
                throw new SecurityException("capability_lease_broker_view_schema_denied");
            }
            mExactChallenge = CapabilityLeaseUiProtocol.requireChallenge(exactChallenge);
            mExactHttpsUri = CapabilityLeaseUiProtocol.requireUri(exactHttpsUri);
            mDestinationHost = CapabilityLeaseUiProtocol.requireHost(destinationHost);
            if (subjectUserId != 0 || expiresAtMs <= 0 || expiresElapsedRealtimeMs < 0
                    || !CapabilityLeaseContract.CODEX_PROVIDER_ID.equals(providerId)) {
                throw new SecurityException("capability_lease_broker_view_denied");
            }
            mSubjectUserId = subjectUserId;
            mProviderId = providerId;
            mExpiresAtMs = expiresAtMs;
            mExpiresElapsedRealtimeMs = expiresElapsedRealtimeMs;
        }

        String exactChallenge() { return mExactChallenge; }
        String exactHttpsUri() { return mExactHttpsUri; }
        String destinationHost() { return mDestinationHost; }
        int subjectUserId() { return mSubjectUserId; }
        String providerId() { return mProviderId; }
        long expiresAtMs() { return mExpiresAtMs; }
        long expiresElapsedRealtimeMs() { return mExpiresElapsedRealtimeMs; }

        void requireSameImmutableView(PendingChallenge other) {
            if (other == null || !mExactChallenge.equals(other.mExactChallenge)
                    || !mExactHttpsUri.equals(other.mExactHttpsUri)
                    || !mDestinationHost.equals(other.mDestinationHost)
                    || mSubjectUserId != other.mSubjectUserId
                    || !mProviderId.equals(other.mProviderId)
                    || mExpiresAtMs != other.mExpiresAtMs
                    || mExpiresElapsedRealtimeMs != other.mExpiresElapsedRealtimeMs) {
                throw new SecurityException("capability_lease_broker_view_drift_denied");
            }
        }

    }

    /** Minimal broker acknowledgement; exact receipt bytes never return to AiShell. */
    final class Submission {
        static final String STATUS_SUBMITTED = "submitted";
        static final String STATUS_INDETERMINATE = "indeterminate";
        private final String mStatus;
        private final String mReceiptId;
        private final String mSubmissionOperationId;
        private final String mStatusTupleSha256;

        Submission(String handle, String status, String submissionOperationId,
                String receiptId, String statusTupleSha256) {
            String exactHandle = LeasePendingHandle.requireExact(handle);
            String exactStatus = CapabilityLeaseUiProtocol.requireSubmissionStatus(status);
            String exactOperationId = CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                    submissionOperationId);
            String exactReceiptId = receiptId == null ? "" : receiptId;
            boolean receiptRequired = STATUS_SUBMITTED.equals(exactStatus)
                    || STATUS_INDETERMINATE.equals(exactStatus)
                    || CapabilityLeaseUiProtocol.STATUS_DELIVERY_READY.equals(exactStatus)
                    || CapabilityLeaseUiProtocol.STATUS_CONSUMED.equals(exactStatus);
            if (receiptRequired) {
                exactReceiptId = CapabilityLeaseUiProtocol.requireReceiptId(exactReceiptId);
            } else if (!exactReceiptId.isEmpty()) {
                throw new SecurityException("capability_lease_broker_submission_denied");
            }
            String exactTupleSha256 =
                    CapabilityLeaseUiProtocol.requireSubmissionStatusTupleSha256(
                            statusTupleSha256);
            String expectedTupleSha256 =
                    CapabilityLeaseUiProtocol.deriveSubmissionStatusTupleSha256(
                            exactHandle, exactOperationId, exactStatus, exactReceiptId);
            if (!expectedTupleSha256.equals(exactTupleSha256)) {
                throw new SecurityException("capability_lease_broker_submission_denied");
            }
            mStatus = exactStatus;
            mReceiptId = exactReceiptId;
            mSubmissionOperationId = exactOperationId;
            mStatusTupleSha256 = exactTupleSha256;
        }

        String status() { return mStatus; }
        String receiptId() { return mReceiptId; }
        String submissionOperationId() { return mSubmissionOperationId; }
        String statusTupleSha256() { return mStatusTupleSha256; }
        boolean deliveryAcknowledged() {
            return STATUS_SUBMITTED.equals(mStatus)
                    || CapabilityLeaseUiProtocol.STATUS_DELIVERY_READY.equals(mStatus)
                    || CapabilityLeaseUiProtocol.STATUS_CONSUMED.equals(mStatus);
        }
    }

    /** The submit ran, so only durable status recovery may determine its outcome. */
    final class SubmissionIndeterminateException extends Exception {
        private static final long serialVersionUID = 1L;
        private final String mSubmissionOperationId;

        SubmissionIndeterminateException(String submissionOperationId, Throwable cause) {
            super("capability_lease_broker_submission_indeterminate", cause);
            mSubmissionOperationId = CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                    submissionOperationId);
        }

        String submissionOperationId() { return mSubmissionOperationId; }
    }
}
