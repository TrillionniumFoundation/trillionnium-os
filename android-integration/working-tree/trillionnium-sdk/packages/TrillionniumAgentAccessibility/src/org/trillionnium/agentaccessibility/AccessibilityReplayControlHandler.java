/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.agentaccessibility;

import org.trillionnium.agentidentity.AgentDescriptor;
import org.trillionnium.agentidentity.AgentDescriptorRegistry;

import java.io.InputStream;

/**
 * Package-private Accessibility replay-control handler.
 *
 * <p>The owning service injects both values only after stable kernel credential and SO_PEERSEC
 * authentication on a separate fixed-binary socket. The frame itself cannot select either value.
 */
final class AccessibilityReplayControlHandler {
    static final String ERROR_PEER_DENIED = "control_peer_denied";
    static final String ERROR_ROLE_DENIED = "control_role_denied";
    static final String ERROR_INTERNAL = "control_internal_error";

    private final AgentDescriptor mBoundAgent;
    private final AccessibilityReplayLedger mReplayLedger;

    /** Endpoint-local role assigned after kernel authentication, never decoded from a frame. */
    enum AuthenticatedRole {
        ADAPTER,
        REPLAY_SYNC
    }

    /** Live authorization recheck invoked after the full frame is read, before ledger mutation. */
    interface BeforeMutationGate {
        void requireCurrent();
    }

    AccessibilityReplayControlHandler(
            AgentDescriptor boundAgent, AccessibilityReplayLedger replayLedger) {
        if (!AgentDescriptorRegistry.productAllowlist().contains(boundAgent)
                || replayLedger == null) {
            throw new IllegalArgumentException("invalid replay control binding");
        }
        mBoundAgent = boundAgent;
        mReplayLedger = replayLedger;
    }

    /** Consumes one complete connection input and returns one fixed binary response frame. */
    byte[] handleSingleFrame(
            AgentDescriptor authenticatedAgent,
            AuthenticatedRole authenticatedRole,
            InputStream connectionInput,
            BeforeMutationGate beforeMutation)
            throws ControlException {
        if (beforeMutation == null
                || authenticatedAgent != mBoundAgent
                || !AgentDescriptorRegistry.productAllowlist().contains(authenticatedAgent)) {
            throw new ControlException(ERROR_PEER_DENIED);
        }
        final AccessibilityReplayControlProtocol.Request request;
        try {
            request = AccessibilityReplayControlProtocol.readSingleRequest(connectionInput);
        } catch (AccessibilityReplayControlProtocol.DecodeException e) {
            throw new ControlException(e.code);
        } catch (RuntimeException e) {
            throw new ControlException(ERROR_INTERNAL);
        }

        try {
            if (request.operation == AccessibilityReplayControlProtocol.OP_ACTIVATE) {
                if (authenticatedRole != AuthenticatedRole.ADAPTER) {
                    throw new ControlException(ERROR_ROLE_DENIED);
                }
                beforeMutation.requireCurrent();
                AccessibilityReplayLedger.EpochActivation result =
                        mReplayLedger.activateEpochFromTrustedAdapter(
                                authenticatedAgent, request.epoch);
                return AccessibilityReplayControlProtocol.encodeActivationResponse(result);
            }
            if (request.operation == AccessibilityReplayControlProtocol.OP_ACK) {
                if (authenticatedRole != AuthenticatedRole.REPLAY_SYNC) {
                    throw new ControlException(ERROR_ROLE_DENIED);
                }
                beforeMutation.requireCurrent();
                mReplayLedger.acknowledgeCommittedFromTrustedAdapter(
                        authenticatedAgent,
                        request.epoch,
                        request.throughSequence,
                        request.ackSha256,
                        request.ackChainSha256);
                return AccessibilityReplayControlProtocol.encodeAckResponse(
                        request.epoch,
                        request.throughSequence,
                        request.ackSha256,
                        request.ackChainSha256);
            }
            throw new ControlException(ERROR_INTERNAL);
        } catch (AccessibilityReplayLedger.ReplayException e) {
            throw new ControlException(closedReplayError(e.code));
        } catch (ControlException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new ControlException(ERROR_INTERNAL);
        }
    }

    private static String closedReplayError(String code) {
        if (code == null) {
            return ERROR_INTERNAL;
        }
        switch (code) {
            case "operation_ack_reclamation_inactive":
            case "operation_epoch_rotation_denied":
            case "operation_epoch_state_conflict":
            case "operation_epoch_inactive":
            case "operation_ack_retry_conflict":
            case "operation_ack_not_monotonic":
            case "operation_ack_chain_mismatch":
            case "operation_ack_not_committed_contiguous":
            case AccessibilityReplayLedger.ERROR_LEDGER_UNAVAILABLE:
                return code;
            default:
                return ERROR_INTERNAL;
        }
    }

    static final class ControlException extends Exception {
        private static final long serialVersionUID = 1L;

        final String code;

        ControlException(String code) {
            super(code);
            this.code = code;
        }
    }
}
