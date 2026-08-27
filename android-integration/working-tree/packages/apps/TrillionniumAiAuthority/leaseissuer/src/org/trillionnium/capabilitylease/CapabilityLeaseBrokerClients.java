/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.capabilitylease;

import android.os.IBinder;
import android.os.ServiceSpecificException;
import android.os.ServiceManager;

/** Product connection point to the role-separated system_server broker UI facade. */
final class CapabilityLeaseBrokerClients {
    private CapabilityLeaseBrokerClients() {}

    static CapabilityLeaseBrokerClient connect() {
        IBinder binder = ServiceManager.getService(CapabilityLeaseBrokerNames.UI);
        ICapabilityLeaseUiBroker broker =
                ICapabilityLeaseUiBroker.Stub.asInterface(binder);
        if (binder == null || broker == null || !binder.isBinderAlive()) {
            return UnavailableClient.INSTANCE;
        }
        return new BinderClient(broker);
    }

    private static final class BinderClient implements CapabilityLeaseBrokerClient {
        private final ICapabilityLeaseUiBroker mBroker;

        BinderClient(ICapabilityLeaseUiBroker broker) {
            if (broker == null) throw new IllegalArgumentException("missing broker");
            mBroker = broker;
        }

        @Override
        public PendingChallenge fetchExactChallenge(String pendingHandle) throws Exception {
            String handle = LeasePendingHandle.requireExact(pendingHandle);
            String[] view = mBroker.fetchExactChallenge(
                    CapabilityLeaseUiProtocol.TRANSPORT_SCHEMA, handle);
            return CapabilityLeaseBrokerWire.decodePendingView(view);
        }

        @Override
        public Submission submitExactReceipt(String pendingHandle, String exactReceipt)
                throws Exception {
            String handle = LeasePendingHandle.requireExact(pendingHandle);
            String receipt = CapabilityLeaseUiProtocol.requireReceipt(exactReceipt);
            String operationId = CapabilityLeaseUiProtocol.deriveSubmissionOperationId(
                    handle, receipt);
            try {
                String[] status = mBroker.submitExactReceipt(
                        CapabilityLeaseUiProtocol.TRANSPORT_SCHEMA, handle,
                        operationId, receipt);
                CapabilityLeaseBrokerClient.Submission decoded =
                        CapabilityLeaseBrokerWire.decodeSubmissionStatus(
                                handle, operationId, status);
                if (CapabilityLeaseUiProtocol.STATUS_NOT_STARTED.equals(decoded.status())
                        || CapabilityLeaseUiProtocol.STATUS_CANCELED.equals(decoded.status())
                        || CapabilityLeaseUiProtocol.STATUS_EXPIRED.equals(decoded.status())) {
                    throw new SecurityException(
                            "capability_lease_broker_submission_denied");
                }
                return decoded;
            } catch (ServiceSpecificException failure) {
                throw mapFailure(failure, operationId);
            }
        }

        @Override
        public Submission querySubmissionStatus(
                String pendingHandle, String submissionOperationId) throws Exception {
            String handle = LeasePendingHandle.requireExact(pendingHandle);
            String operationId = CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                    submissionOperationId);
            try {
                return CapabilityLeaseBrokerWire.decodeSubmissionStatus(
                        handle, operationId, mBroker.querySubmissionStatus(
                                CapabilityLeaseUiProtocol.TRANSPORT_SCHEMA,
                                handle, operationId));
            } catch (ServiceSpecificException failure) {
                throw mapFailure(failure, operationId);
            }
        }

        @Override
        public void cancelPending(String pendingHandle) throws Exception {
            mBroker.cancelPending(CapabilityLeaseUiProtocol.TRANSPORT_SCHEMA,
                    LeasePendingHandle.requireExact(pendingHandle));
        }

    }

    private enum UnavailableClient implements CapabilityLeaseBrokerClient {
        INSTANCE;

        @Override public PendingChallenge fetchExactChallenge(String pendingHandle) {
            LeasePendingHandle.requireExact(pendingHandle);
            throw unavailable();
        }

        @Override public Submission submitExactReceipt(String pendingHandle, String exactReceipt) {
            LeasePendingHandle.requireExact(pendingHandle);
            throw unavailable();
        }

        @Override public Submission querySubmissionStatus(
                String pendingHandle, String submissionOperationId) {
            LeasePendingHandle.requireExact(pendingHandle);
            CapabilityLeaseUiProtocol.requireSubmissionOperationId(submissionOperationId);
            throw unavailable();
        }

        @Override public void cancelPending(String pendingHandle) {
            LeasePendingHandle.requireExact(pendingHandle);
            throw unavailable();
        }

        private static SecurityException unavailable() {
            return new SecurityException("capability_lease_broker_client_unavailable");
        }
    }

    private static Exception mapFailure(
            ServiceSpecificException failure, String operationId) {
        if (failure != null
                && failure.errorCode == CapabilityLeaseUiProtocol.ERROR_INDETERMINATE) {
            return new CapabilityLeaseBrokerClient.SubmissionIndeterminateException(
                    operationId, failure);
        }
        return new SecurityException("capability_lease_broker_client_unavailable", failure);
    }
}
