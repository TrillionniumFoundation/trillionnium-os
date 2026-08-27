/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Role-separated broker façades with per-call verification.
 *
 * <p>The issuer Binder transport synchronously obtains an operation-bound authorization before
 * dispatching storage or receipt work. The System API backend uses the local façade; the backend
 * external façade remains unregistered while its measured caller transport is on HOLD.
 */
final class CapabilityLeaseBrokerServiceFacades {
    interface CallerVerifier {
        CapabilityLeaseBrokerCallerPolicy.VerifiedCaller verify(
                CapabilityLeaseBrokerCallerPolicy.Operation operation);
    }

    final class UiFacade {
        CapabilityLeasePendingBroker.ResultStatus poll(String handle) throws Exception {
            verify(CapabilityLeaseBrokerCallerPolicy.Operation.UI_POLL);
            return mBroker.pollForUi(handle);
        }

        AuthorizedCall authorizeIssuerFetch() {
            return authorize(CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_FETCH);
        }

        AuthorizedCall authorizeIssuerSubmit() {
            return authorize(CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_SUBMIT);
        }

        AuthorizedCall authorizeIssuerQuerySubmission() {
            return authorize(
                    CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_QUERY_SUBMISSION);
        }

        AuthorizedCall authorizeUiAcknowledgeSubmission() {
            return authorize(CapabilityLeaseBrokerCallerPolicy.Operation.UI_ACK_SUBMISSION);
        }

        AuthorizedCall authorizeIssuerCancel() {
            return authorize(CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_CANCEL);
        }

        CapabilityLeasePendingBroker.PendingView fetchForIssuer(
                AuthorizedCall authorization, String handle) throws Exception {
            authorization.consume(CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_FETCH);
            return mBroker.fetchForIssuer(handle);
        }

        CapabilityLeasePendingBroker.Submission submitFromIssuer(
                AuthorizedCall authorization, String handle, String submissionOperationId,
                String exactReceipt)
                throws Exception {
            authorization.consume(CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_SUBMIT);
            return mBroker.submitFromIssuer(handle, submissionOperationId, exactReceipt);
        }

        CapabilityLeasePendingBroker.SubmissionStatus querySubmissionFromIssuer(
                AuthorizedCall authorization, String handle, String submissionOperationId)
                throws Exception {
            authorization.consume(
                    CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_QUERY_SUBMISSION);
            return mBroker.querySubmissionFromIssuer(handle, submissionOperationId);
        }

        CapabilityLeasePendingBroker.SubmissionStatus acknowledgeSubmissionDelivery(
                AuthorizedCall authorization, String handle, String submissionOperationId,
                String receiptId, String statusTupleSha256) throws Exception {
            authorization.consume(
                    CapabilityLeaseBrokerCallerPolicy.Operation.UI_ACK_SUBMISSION);
            return mBroker.acknowledgeSubmissionDelivery(handle, submissionOperationId,
                    receiptId, statusTupleSha256);
        }

        void cancelFromIssuer(AuthorizedCall authorization, String handle) throws Exception {
            authorization.consume(CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_CANCEL);
            mBroker.cancelFromIssuer(handle);
        }
    }

    final class BackendFacade {
        String createOpenUri(CapabilityLeasePendingBroker.PendingOpenUriRequest request)
                throws Exception {
            verify(CapabilityLeaseBrokerCallerPolicy.Operation.BACKEND_CREATE);
            return mBroker.createOpenUri(request);
        }

        CapabilityLeasePendingBroker.ReceiptDelivery fetchReceipt(String handle)
                throws Exception {
            verify(CapabilityLeaseBrokerCallerPolicy.Operation.BACKEND_FETCH_RECEIPT);
            return mBroker.fetchReceiptForBackend(handle);
        }

        void acknowledgePrepared(String handle, String receiptId) throws Exception {
            verify(CapabilityLeaseBrokerCallerPolicy.Operation.BACKEND_ACK_PREPARED);
            mBroker.acknowledgeBackendPrepared(handle, receiptId);
        }
    }

    final class LocalSystemApiFacade {
        String createOpenUri(CapabilityLeasePendingBroker.PendingOpenUriRequest request)
                throws Exception {
            return mBroker.createOpenUri(request);
        }

        CapabilityLeasePendingBroker.PendingView prepareOpenUri(
                CapabilityLeasePendingBroker.PendingOpenUriRequest request)
                throws Exception {
            return mBroker.prepareOpenUriForLocalBackend(request);
        }

        CapabilityLeasePendingBroker.ReceiptDelivery fetchReceipt(String handle)
                throws Exception {
            return mBroker.fetchReceiptForBackend(handle);
        }

        void acknowledgePrepared(String handle, String receiptId) throws Exception {
            mBroker.acknowledgeBackendPrepared(handle, receiptId);
        }
    }

    private final CapabilityLeasePendingBroker mBroker;
    private final CallerVerifier mCallerVerifier;
    final UiFacade ui = new UiFacade();
    final BackendFacade backend = new BackendFacade();
    final LocalSystemApiFacade localSystemApi = new LocalSystemApiFacade();

    CapabilityLeaseBrokerServiceFacades(
            CapabilityLeasePendingBroker broker, CallerVerifier callerVerifier) {
        if (broker == null || callerVerifier == null) {
            throw new IllegalArgumentException("invalid broker service façade");
        }
        mBroker = broker;
        mCallerVerifier = callerVerifier;
    }

    private AuthorizedCall authorize(CapabilityLeaseBrokerCallerPolicy.Operation operation) {
        return new AuthorizedCall(operation, verify(operation));
    }

    private CapabilityLeaseBrokerCallerPolicy.VerifiedCaller verify(
            CapabilityLeaseBrokerCallerPolicy.Operation operation) {
        CapabilityLeaseBrokerCallerPolicy.VerifiedCaller caller =
                mCallerVerifier.verify(operation);
        if (caller == null || caller.role != operation.requiredRole) {
            throw new SecurityException("capability_lease_broker_caller_denied");
        }
        return caller;
    }

    /** Single-use evidence that the original Binder caller was verified for one exact operation. */
    static final class AuthorizedCall {
        private final CapabilityLeaseBrokerCallerPolicy.Operation mOperation;
        private final CapabilityLeaseBrokerCallerPolicy.VerifiedCaller mCaller;
        private final AtomicBoolean mConsumed = new AtomicBoolean();

        private AuthorizedCall(
                CapabilityLeaseBrokerCallerPolicy.Operation operation,
                CapabilityLeaseBrokerCallerPolicy.VerifiedCaller caller) {
            mOperation = operation;
            mCaller = caller;
        }

        int uid() {
            return mCaller.uid;
        }

        private CapabilityLeaseBrokerCallerPolicy.VerifiedCaller consume(
                CapabilityLeaseBrokerCallerPolicy.Operation expected) {
            if (expected == null || mOperation != expected
                    || mCaller.role != expected.requiredRole
                    || !mConsumed.compareAndSet(false, true)) {
                throw new SecurityException("capability_lease_broker_caller_denied");
            }
            return mCaller;
        }
    }
}
