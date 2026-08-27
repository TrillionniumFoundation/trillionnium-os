/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import android.os.ServiceSpecificException;

import org.trillionnium.capabilitylease.CapabilityLeaseUiProtocol;
import org.trillionnium.capabilitylease.ICapabilityLeaseUiBroker;

/** Binder transport for the issuer-only view of the in-process durable broker. */
final class CapabilityLeaseUiBrokerBinder extends ICapabilityLeaseUiBroker.Stub {
    private final CapabilityLeaseBrokerServiceFacades.UiFacade mUi;
    private final CapabilityLeaseBrokerCallExecutor mCalls;

    CapabilityLeaseUiBrokerBinder(CapabilityLeaseBrokerServiceFacades.UiFacade ui) {
        this(ui, new CapabilityLeaseBrokerCallExecutor());
    }

    CapabilityLeaseUiBrokerBinder(
            CapabilityLeaseBrokerServiceFacades.UiFacade ui,
            CapabilityLeaseBrokerCallExecutor calls) {
        if (ui == null || calls == null) {
            throw new IllegalArgumentException("missing capability-lease UI transport dependency");
        }
        mUi = ui;
        mCalls = calls;
    }

    @Override
    public String[] fetchExactChallenge(String transportSchema, String pendingHandle) {
        try {
            CapabilityLeaseUiProtocol.requireTransportSchema(transportSchema);
            String handle = CapabilityLeaseUiProtocol.requirePendingHandle(pendingHandle);
            // Capture and verify the original remote identity on this Binder thread. Storage and
            // large-field validation run only after that evidence has been sealed into the token.
            CapabilityLeaseBrokerServiceFacades.AuthorizedCall authorization =
                    mUi.authorizeIssuerFetch();
            return mCalls.call(authorization.uid(), () -> {
                CapabilityLeasePendingBroker.PendingView view =
                        mUi.fetchForIssuer(authorization, handle);
                if (view == null || !handle.equals(view.handle) || view.subjectUserId != 0
                        || view.expiresAtMs <= 0 || view.expiresElapsedRealtimeMs < 0) {
                    throw new SecurityException("capability_lease_broker_view_denied");
                }
                return new String[] {
                        CapabilityLeaseUiProtocol.VIEW_SCHEMA,
                        CapabilityLeaseUiProtocol.requireChallenge(view.exactChallenge),
                        CapabilityLeaseUiProtocol.requireUri(view.exactHttpsUri),
                        CapabilityLeaseUiProtocol.requireHost(view.destinationHost),
                        Integer.toString(view.subjectUserId),
                        CapabilityLeaseUiProtocol.requireProvider(view.providerId),
                        Long.toString(view.expiresAtMs),
                        Long.toString(view.expiresElapsedRealtimeMs),
                };
            });
        } catch (SecurityException denied) {
            throw denied;
        } catch (CapabilityLeaseBrokerCallExecutor.CallException failure) {
            throw callFailure(failure, "");
        } catch (Exception unavailable) {
            throw unavailable();
        }
    }

    @Override
    public String[] submitExactReceipt(String transportSchema, String pendingHandle,
            String submissionOperationId, String exactReceipt) {
        String operationId = "";
        try {
            CapabilityLeaseUiProtocol.requireTransportSchema(transportSchema);
            String handle = CapabilityLeaseUiProtocol.requirePendingHandle(pendingHandle);
            operationId = CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                    submissionOperationId);
            CapabilityLeaseBrokerServiceFacades.AuthorizedCall authorization =
                    mUi.authorizeIssuerSubmit();
            final String exactOperationId = operationId;
            return mCalls.call(authorization.uid(), () -> {
                String receipt = CapabilityLeaseUiProtocol.requireReceipt(exactReceipt);
                String derivedOperationId =
                        CapabilityLeaseUiProtocol.deriveSubmissionOperationId(handle, receipt);
                if (!exactOperationId.equals(derivedOperationId)) {
                    throw new SecurityException(
                            "capability_lease_broker_submission_operation_denied");
                }
                CapabilityLeasePendingBroker.Submission submitted =
                        mUi.submitFromIssuer(
                                authorization, handle, exactOperationId, receipt);
                return encodeStatus(handle, submitted.status,
                        submitted.submissionOperationId, submitted.receiptId,
                        submitted.statusTupleSha256);
            });
        } catch (SecurityException denied) {
            throw denied;
        } catch (CapabilityLeaseBrokerCallExecutor.CallException failure) {
            throw callFailure(failure, operationId);
        } catch (Exception unavailable) {
            throw unavailable();
        }
    }

    @Override
    public String[] querySubmissionStatus(
            String transportSchema, String pendingHandle, String submissionOperationId) {
        String operationId = "";
        try {
            CapabilityLeaseUiProtocol.requireTransportSchema(transportSchema);
            String handle = CapabilityLeaseUiProtocol.requirePendingHandle(pendingHandle);
            operationId = CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                    submissionOperationId);
            CapabilityLeaseBrokerServiceFacades.AuthorizedCall authorization =
                    mUi.authorizeIssuerQuerySubmission();
            final String exactOperationId = operationId;
            return mCalls.call(authorization.uid(), () -> {
                CapabilityLeasePendingBroker.SubmissionStatus status =
                        mUi.querySubmissionFromIssuer(
                                authorization, handle, exactOperationId);
                return encodeStatus(handle, status.status,
                        status.submissionOperationId, status.receiptId,
                        status.statusTupleSha256);
            });
        } catch (SecurityException denied) {
            throw denied;
        } catch (CapabilityLeaseBrokerCallExecutor.CallException failure) {
            throw callFailure(failure, operationId);
        } catch (Exception unavailable) {
            throw unavailable();
        }
    }

    @Override
    public String[] acknowledgeSubmissionDelivery(String transportSchema, String pendingHandle,
            String submissionOperationId, String receiptId, String statusTupleSha256) {
        String operationId = "";
        try {
            CapabilityLeaseUiProtocol.requireTransportSchema(transportSchema);
            String handle = CapabilityLeaseUiProtocol.requirePendingHandle(pendingHandle);
            operationId = CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                    submissionOperationId);
            String exactReceiptId = CapabilityLeaseUiProtocol.requireReceiptId(receiptId);
            String exactTupleSha256 =
                    CapabilityLeaseUiProtocol.requireSubmissionStatusTupleSha256(
                            statusTupleSha256);
            // Unlike submit/query, this authorization is AI_SHELL-bound. Receipt release proves
            // that the outer Activity-result consumer received and verified the exact tuple.
            CapabilityLeaseBrokerServiceFacades.AuthorizedCall authorization =
                    mUi.authorizeUiAcknowledgeSubmission();
            final String exactOperationId = operationId;
            return mCalls.call(authorization.uid(), () -> {
                CapabilityLeasePendingBroker.SubmissionStatus status =
                        mUi.acknowledgeSubmissionDelivery(authorization, handle,
                                exactOperationId, exactReceiptId, exactTupleSha256);
                return encodeStatus(handle, status.status,
                        status.submissionOperationId, status.receiptId,
                        status.statusTupleSha256);
            });
        } catch (SecurityException denied) {
            throw denied;
        } catch (CapabilityLeaseBrokerCallExecutor.CallException failure) {
            throw callFailure(failure, operationId);
        } catch (Exception unavailable) {
            throw unavailable();
        }
    }

    @Override
    public void cancelPending(String transportSchema, String pendingHandle) {
        try {
            CapabilityLeaseUiProtocol.requireTransportSchema(transportSchema);
            String handle = CapabilityLeaseUiProtocol.requirePendingHandle(pendingHandle);
            CapabilityLeaseBrokerServiceFacades.AuthorizedCall authorization =
                    mUi.authorizeIssuerCancel();
            mCalls.call(authorization.uid(), () -> {
                mUi.cancelFromIssuer(authorization, handle);
                return null;
            });
        } catch (SecurityException denied) {
            throw denied;
        } catch (CapabilityLeaseBrokerCallExecutor.CallException failure) {
            throw callFailure(failure, "");
        } catch (Exception unavailable) {
            throw unavailable();
        }
    }

    private static String[] encodeStatus(String handle, String status,
            String operationId, String receiptId, String statusTupleSha256) {
        String exactHandle = CapabilityLeaseUiProtocol.requirePendingHandle(handle);
        String exactStatus = CapabilityLeaseUiProtocol.requireSubmissionStatus(status);
        String exactOperationId =
                CapabilityLeaseUiProtocol.requireSubmissionOperationId(operationId);
        String exactReceiptId = receiptId == null ? "" : receiptId;
        String expectedDigest = CapabilityLeaseUiProtocol.deriveSubmissionStatusTupleSha256(
                exactHandle, exactOperationId, exactStatus, exactReceiptId);
        if (!expectedDigest.equals(
                CapabilityLeaseUiProtocol.requireSubmissionStatusTupleSha256(
                        statusTupleSha256))) {
            throw new SecurityException("capability_lease_broker_submission_status_denied");
        }
        return new String[] {
                CapabilityLeaseUiProtocol.SUBMISSION_STATUS_SCHEMA,
                exactStatus,
                exactOperationId,
                exactReceiptId,
                expectedDigest,
        };
    }

    private static ServiceSpecificException callFailure(
            CapabilityLeaseBrokerCallExecutor.CallException failure,
            String submissionOperationId) {
        if (failure != null
                && CapabilityLeaseBrokerCallExecutor.ERROR_INDETERMINATE.equals(failure.code)) {
            String operationId = submissionOperationId == null ? "" : submissionOperationId;
            return new ServiceSpecificException(
                    CapabilityLeaseUiProtocol.ERROR_INDETERMINATE,
                    "capability_lease_broker_indeterminate:" + operationId);
        }
        return unavailable();
    }

    private static ServiceSpecificException unavailable() {
        return new ServiceSpecificException(
                CapabilityLeaseUiProtocol.ERROR_UNAVAILABLE,
                "capability_lease_broker_unavailable");
    }
}
