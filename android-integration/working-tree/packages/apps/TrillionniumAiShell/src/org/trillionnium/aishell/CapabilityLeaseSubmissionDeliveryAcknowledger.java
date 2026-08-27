/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.aishell;

import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.ServiceManager;

import org.trillionnium.capabilitylease.CapabilityLeaseBrokerNames;
import org.trillionnium.capabilitylease.CapabilityLeaseUiProtocol;
import org.trillionnium.capabilitylease.ICapabilityLeaseUiBroker;

/**
 * Outer delivery boundary for a quarantined capability-lease submission.
 *
 * <p>This method must be called only after AiShell receives the Activity result. The broker
 * authenticates this process as the AI_SHELL role; the issuer cannot call the same release
 * operation. No receipt or status is accepted from an Agent/model wire.</p>
 */
final class CapabilityLeaseSubmissionDeliveryAcknowledger {
    private static final String ACTION_REQUEST_CAPABILITY_LEASE =
            "org.trillionnium.capabilitylease.action.REQUEST_CAPABILITY_LEASE";
    private static final String ISSUER_PACKAGE = "org.trillionnium.capabilitylease";
    private static final String EXTRA_PENDING_HANDLE = "capability_lease_pending_handle";
    private static final String EXTRA_STATUS = "capability_lease_status";
    private static final String EXTRA_RECEIPT_ID = "capability_lease_receipt_id";
    private static final String EXTRA_SUBMISSION_OPERATION_ID =
            "capability_lease_submission_operation_id";
    private static final String EXTRA_STATUS_TUPLE_SHA256 =
            "capability_lease_submission_status_tuple_sha256";

    private CapabilityLeaseSubmissionDeliveryAcknowledger() {}

    static void acknowledgeReceivedResult(Intent result, String expectedHandle) throws Exception {
        DeliveredResult delivered = requireDeliveredResult(result, expectedHandle);
        if (!CapabilityLeaseUiProtocol.STATUS_INDETERMINATE.equals(delivered.status)
                || delivered.receiptId.isEmpty() || delivered.tupleSha256.isEmpty()) {
            throw denied();
        }
        String expectedTupleSha256 =
                CapabilityLeaseUiProtocol.deriveSubmissionStatusTupleSha256(
                        delivered.handle, delivered.operationId, delivered.status,
                        CapabilityLeaseUiProtocol.requireReceiptId(delivered.receiptId));
        if (!expectedTupleSha256.equals(
                CapabilityLeaseUiProtocol.requireSubmissionStatusTupleSha256(
                        delivered.tupleSha256))) {
            throw denied();
        }

        ICapabilityLeaseUiBroker broker = connect();
        String[] released = broker.acknowledgeSubmissionDelivery(
                CapabilityLeaseUiProtocol.TRANSPORT_SCHEMA, delivered.handle,
                delivered.operationId, delivered.receiptId, delivered.tupleSha256);
        requireReleasedTuple(released, delivered.handle,
                delivered.operationId, delivered.receiptId);
    }

    /** Builds the issuer-role status recovery request for a started submit whose reply was lost. */
    static Intent recoveryRequestForIndeterminateResult(
            Intent result, String expectedHandle) {
        DeliveredResult delivered = requireDeliveredResult(result, expectedHandle);
        if (!CapabilityLeaseUiProtocol.STATUS_INDETERMINATE.equals(delivered.status)
                || !delivered.receiptId.isEmpty() || !delivered.tupleSha256.isEmpty()) {
            throw denied();
        }
        return new Intent(ACTION_REQUEST_CAPABILITY_LEASE)
                .setPackage(ISSUER_PACKAGE)
                .putExtra(EXTRA_PENDING_HANDLE, delivered.handle)
                .putExtra(EXTRA_SUBMISSION_OPERATION_ID, delivered.operationId);
    }

    private static DeliveredResult requireDeliveredResult(
            Intent result, String expectedHandle) {
        String handle = CapabilityLeaseUiProtocol.requirePendingHandle(expectedHandle);
        if (result == null || result.getAction() != null || result.getData() != null
                || result.getClipData() != null || result.getType() != null
                || result.getCategories() != null || result.getSelector() != null) {
            throw denied();
        }
        Bundle extras = result.getExtras();
        if (extras == null || extras.size() != 5) throw denied();
        String deliveredHandle = exactString(extras, EXTRA_PENDING_HANDLE);
        String status = exactString(extras, EXTRA_STATUS);
        String receiptId = exactString(extras, EXTRA_RECEIPT_ID);
        String operationId = exactString(extras, EXTRA_SUBMISSION_OPERATION_ID);
        String tupleSha256 = exactString(extras, EXTRA_STATUS_TUPLE_SHA256);
        if (!handle.equals(CapabilityLeaseUiProtocol.requirePendingHandle(deliveredHandle))
                || !CapabilityLeaseUiProtocol.STATUS_INDETERMINATE.equals(
                        CapabilityLeaseUiProtocol.requireSubmissionStatus(status))) {
            throw denied();
        }
        return new DeliveredResult(handle, status,
                CapabilityLeaseUiProtocol.requireSubmissionOperationId(operationId),
                receiptId, tupleSha256);
    }

    private static ICapabilityLeaseUiBroker connect() {
        IBinder binder = ServiceManager.getService(CapabilityLeaseBrokerNames.UI);
        ICapabilityLeaseUiBroker broker = ICapabilityLeaseUiBroker.Stub.asInterface(binder);
        if (binder == null || broker == null || !binder.isBinderAlive()) throw unavailable();
        return broker;
    }

    private static void requireReleasedTuple(
            String[] value, String handle, String operationId, String receiptId) {
        if (value == null
                || value.length != CapabilityLeaseUiProtocol.SUBMISSION_STATUS_FIELDS
                || !CapabilityLeaseUiProtocol.SUBMISSION_STATUS_SCHEMA.equals(value[0])
                || !CapabilityLeaseUiProtocol.STATUS_SUBMITTED.equals(value[1])
                || !operationId.equals(value[2]) || !receiptId.equals(value[3])
                || !CapabilityLeaseUiProtocol
                        .deriveSubmissionStatusTupleSha256(
                                handle, operationId, value[1], receiptId)
                        .equals(CapabilityLeaseUiProtocol
                                .requireSubmissionStatusTupleSha256(value[4]))) {
            throw denied();
        }
    }

    private static String exactString(Bundle extras, String key) {
        Object value = extras.get(key);
        if (!(value instanceof String)) throw denied();
        return (String) value;
    }

    private static final class DeliveredResult {
        final String handle;
        final String status;
        final String operationId;
        final String receiptId;
        final String tupleSha256;

        DeliveredResult(String handle, String status, String operationId,
                String receiptId, String tupleSha256) {
            this.handle = handle;
            this.status = status;
            this.operationId = operationId;
            this.receiptId = receiptId;
            this.tupleSha256 = tupleSha256;
        }
    }

    private static SecurityException denied() {
        return new SecurityException("capability_lease_submission_delivery_denied");
    }

    private static SecurityException unavailable() {
        return new SecurityException("capability_lease_submission_delivery_unavailable");
    }
}
