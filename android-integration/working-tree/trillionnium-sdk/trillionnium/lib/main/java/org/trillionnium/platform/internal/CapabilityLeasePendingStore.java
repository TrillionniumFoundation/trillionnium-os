/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import org.trillionnium.agentidentity.AgentDescriptor;
import org.trillionnium.agentidentity.AgentDescriptorRegistry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/** Atomic durable store for broker-owned capability-lease pending records. */
interface CapabilityLeasePendingStore {
    enum State {
        PENDING,
        /** Validated receipt held until AiShell acknowledges delivery of the exact result tuple. */
        INDETERMINATE,
        SUBMITTED,
        DELIVERY_READY,
        CONSUMED,
        CANCELED,
        EXPIRED
    }

    final class Record {
        private static final int MAX_CHALLENGE_BYTES = 64 * 1024;
        private static final int MAX_RECEIPT_BYTES = 256 * 1024;

        final String handle;
        final AgentDescriptor creatorPeerIdentity;
        final String prepareRequestId;
        final String authenticatedTaskBindingSha256;
        final String prepareCanonicalRequestSha256;
        final String workflowId;
        final String taskId;
        final String bootIdSha256;
        final String providerId;
        final String exactHttpsUri;
        final String exactChallenge;
        final long issuedAtMs;
        final long expiresAtMs;
        final long notBeforeElapsedMs;
        final long expiresElapsedMs;
        final State state;
        final String receiptId;
        final String receiptSha256;
        final String exactReceipt;

        Record(String handle, AgentDescriptor creatorPeerIdentity, String prepareRequestId,
                String authenticatedTaskBindingSha256, String prepareCanonicalRequestSha256,
                String workflowId, String taskId, String bootIdSha256, String providerId,
                String exactHttpsUri, String exactChallenge,
                long issuedAtMs, long expiresAtMs, long notBeforeElapsedMs,
                long expiresElapsedMs, State state, String receiptId,
                String receiptSha256, String exactReceipt) {
            this.handle = require(handle, "lease-pending-[0-9a-f]{64}", 78, "invalid handle");
            if (creatorPeerIdentity == null) {
                throw new IllegalArgumentException("invalid creator peer");
            }
            this.creatorPeerIdentity = creatorPeerIdentity;
            this.prepareRequestId = require(prepareRequestId,
                    "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", 128,
                    "invalid prepare request id");
            this.authenticatedTaskBindingSha256 = requireNonzeroDigest(
                    authenticatedTaskBindingSha256, "invalid authenticated task binding");
            this.prepareCanonicalRequestSha256 = requireNonzeroDigest(
                    prepareCanonicalRequestSha256, "invalid canonical prepare digest");
            this.workflowId = require(workflowId,
                    "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", 128, "invalid workflow");
            this.taskId = require(taskId,
                    "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", 128, "invalid task");
            this.bootIdSha256 = requireNonzeroDigest(bootIdSha256, "invalid boot digest");
            if (!AgentDescriptorRegistry.isProductProviderId(providerId)) {
                throw new IllegalArgumentException("invalid provider");
            }
            if (!creatorPeerIdentity.providerId().equals(providerId)) {
                throw new IllegalArgumentException("creator/provider mismatch");
            }
            this.providerId = providerId;
            this.exactHttpsUri = requireText(exactHttpsUri, 4 * 1024, "invalid URI");
            this.exactChallenge = requireText(
                    exactChallenge, MAX_CHALLENGE_BYTES, "invalid challenge");
            if (issuedAtMs <= 0 || expiresAtMs <= issuedAtMs
                    || notBeforeElapsedMs < 0 || expiresElapsedMs <= notBeforeElapsedMs) {
                throw new IllegalArgumentException("invalid record clocks");
            }
            this.issuedAtMs = issuedAtMs;
            this.expiresAtMs = expiresAtMs;
            this.notBeforeElapsedMs = notBeforeElapsedMs;
            this.expiresElapsedMs = expiresElapsedMs;
            if (state == null) throw new IllegalArgumentException("missing state");
            this.state = state;
            this.receiptId = emptyToNull(receiptId);
            this.receiptSha256 = emptyToNull(receiptSha256);
            this.exactReceipt = emptyToNull(exactReceipt);
            validateState();
        }

        Record transition(State nextState, String nextReceiptId, String nextReceiptSha256,
                String nextExactReceipt) {
            return new Record(handle, creatorPeerIdentity, prepareRequestId,
                    authenticatedTaskBindingSha256, prepareCanonicalRequestSha256,
                    workflowId, taskId, bootIdSha256, providerId, exactHttpsUri, exactChallenge,
                    issuedAtMs, expiresAtMs,
                    notBeforeElapsedMs, expiresElapsedMs, nextState, nextReceiptId,
                    nextReceiptSha256, nextExactReceipt);
        }

        void requireValidTransitionFrom(Record expected) throws IOException {
            if (expected == null || !handle.equals(expected.handle)
                    || creatorPeerIdentity != expected.creatorPeerIdentity
                    || !prepareRequestId.equals(expected.prepareRequestId)
                    || !constantTimeEquals(authenticatedTaskBindingSha256,
                            expected.authenticatedTaskBindingSha256)
                    || !constantTimeEquals(prepareCanonicalRequestSha256,
                            expected.prepareCanonicalRequestSha256)
                    || !workflowId.equals(expected.workflowId)
                    || !taskId.equals(expected.taskId)
                    || !bootIdSha256.equals(expected.bootIdSha256)
                    || !providerId.equals(expected.providerId)
                    || !exactHttpsUri.equals(expected.exactHttpsUri)
                    || !exactChallenge.equals(expected.exactChallenge)
                    || issuedAtMs != expected.issuedAtMs
                    || expiresAtMs != expected.expiresAtMs
                    || notBeforeElapsedMs != expected.notBeforeElapsedMs
                    || expiresElapsedMs != expected.expiresElapsedMs
                    || !validStateTransition(expected.state, state)) {
                throw new IOException("invalid pending record transition");
            }
            requireValidReceiptTransitionFrom(expected);
        }

        String fileName() {
            return handle.substring("lease-pending-".length()) + ".entry";
        }

        private void validateState() {
            switch (state) {
                case PENDING:
                case CANCELED:
                case EXPIRED:
                    requireNoReceipt();
                    return;
                case INDETERMINATE:
                case SUBMITTED:
                case DELIVERY_READY:
                    requireReceiptMetadata();
                    requireText(exactReceipt, MAX_RECEIPT_BYTES, "missing exact receipt");
                    if (!constantTimeEquals(receiptSha256, sha256ExactReceipt(exactReceipt))) {
                        throw new IllegalArgumentException("exact receipt digest mismatch");
                    }
                    return;
                case CONSUMED:
                    requireReceiptMetadata();
                    if (exactReceipt != null) {
                        throw new IllegalArgumentException("consumed receipt retained");
                    }
                    return;
                default:
                    throw new IllegalArgumentException("unknown state");
            }
        }

        private static boolean validStateTransition(State from, State to) {
            switch (from) {
                case PENDING:
                    return to == State.INDETERMINATE
                            || to == State.CANCELED || to == State.EXPIRED;
                case INDETERMINATE:
                    return to == State.SUBMITTED || to == State.EXPIRED;
                case SUBMITTED:
                    return to == State.DELIVERY_READY || to == State.EXPIRED;
                case DELIVERY_READY:
                    return to == State.CONSUMED || to == State.EXPIRED;
                case CONSUMED:
                case CANCELED:
                case EXPIRED:
                    return false;
                default:
                    return false;
            }
        }

        private void requireValidReceiptTransitionFrom(Record expected) throws IOException {
            if ((expected.state == State.INDETERMINATE && state == State.SUBMITTED)
                    || (expected.state == State.SUBMITTED
                            && state == State.DELIVERY_READY)) {
                if (!constantTimeEquals(receiptId, expected.receiptId)
                        || !constantTimeEquals(receiptSha256, expected.receiptSha256)
                        || !constantTimeTextEquals(exactReceipt, expected.exactReceipt)) {
                    throw new IOException("pending receipt binding drift");
                }
                return;
            }
            if (expected.state == State.DELIVERY_READY && state == State.CONSUMED
                    && (!constantTimeEquals(receiptId, expected.receiptId)
                            || !constantTimeEquals(receiptSha256, expected.receiptSha256)
                            || exactReceipt != null)) {
                throw new IOException("pending receipt binding drift");
            }
        }

        private void requireNoReceipt() {
            if (receiptId != null || receiptSha256 != null || exactReceipt != null) {
                throw new IllegalArgumentException("unexpected receipt state");
            }
        }

        private void requireReceiptMetadata() {
            requireDigest(receiptId, "invalid receipt id");
            requireDigest(receiptSha256, "invalid receipt digest");
        }

        private static String emptyToNull(String value) {
            return value == null || value.isEmpty() ? null : value;
        }

        private static String require(String value, String regex, int maxBytes, String reason) {
            String item = requireText(value, maxBytes, reason);
            if (!item.matches(regex)) throw new IllegalArgumentException(reason);
            return item;
        }

        private static String requireDigest(String value, String reason) {
            if (value == null || !value.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException(reason);
            }
            return value;
        }

        private static String requireNonzeroDigest(String value, String reason) {
            String digest = requireDigest(value, reason);
            if (digest.equals("0".repeat(64))) throw new IllegalArgumentException(reason);
            return digest;
        }

        private static boolean constantTimeEquals(String left, String right) {
            return left != null && right != null && MessageDigest.isEqual(
                    left.getBytes(StandardCharsets.US_ASCII),
                    right.getBytes(StandardCharsets.US_ASCII));
        }

        private static boolean constantTimeTextEquals(String left, String right) {
            return left != null && right != null && MessageDigest.isEqual(
                    left.getBytes(StandardCharsets.UTF_8),
                    right.getBytes(StandardCharsets.UTF_8));
        }

        private static String sha256ExactReceipt(String exactReceipt) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                        exactReceipt.getBytes(StandardCharsets.UTF_8));
                char[] output = new char[digest.length * 2];
                char[] alphabet = "0123456789abcdef".toCharArray();
                for (int index = 0; index < digest.length; index++) {
                    int item = digest[index] & 0xff;
                    output[index * 2] = alphabet[item >>> 4];
                    output[index * 2 + 1] = alphabet[item & 0x0f];
                }
                return new String(output);
            } catch (NoSuchAlgorithmException impossible) {
                throw new AssertionError("SHA-256 unavailable", impossible);
            }
        }

        private static String requireText(String value, int maxBytes, String reason) {
            if (value == null || value.isEmpty()
                    || value.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
                throw new IllegalArgumentException(reason);
            }
            return value;
        }
    }

    final class CompactionWatermark {
        private static final String DOMAIN =
                "org.trillionnium.capability-lease-terminal-compaction.v1";
        private static final String GENESIS_ROOT = sha256(DOMAIN.getBytes(StandardCharsets.UTF_8));

        final long epoch;
        final String previousRootSha256;
        final String rootSha256;
        final String lastHandle;
        final String lastRecordSha256;

        CompactionWatermark(long epoch, String previousRootSha256, String rootSha256,
                String lastHandle, String lastRecordSha256) {
            if (epoch < 0) throw new IllegalArgumentException("invalid compaction epoch");
            this.epoch = epoch;
            this.previousRootSha256 = requireDigest(previousRootSha256);
            this.rootSha256 = requireDigest(rootSha256);
            this.lastHandle = emptyToNull(lastHandle);
            this.lastRecordSha256 = emptyToNull(lastRecordSha256);
            if (epoch == 0) {
                if (!GENESIS_ROOT.equals(this.previousRootSha256)
                        || !GENESIS_ROOT.equals(this.rootSha256)
                        || this.lastHandle != null || this.lastRecordSha256 != null) {
                    throw new IllegalArgumentException("invalid compaction genesis");
                }
            } else if (this.lastHandle == null
                    || !this.lastHandle.matches("lease-pending-[0-9a-f]{64}")
                    || this.lastRecordSha256 == null
                    || !this.lastRecordSha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("invalid compaction watermark");
            }
        }

        static CompactionWatermark genesis() {
            return new CompactionWatermark(0, GENESIS_ROOT, GENESIS_ROOT, null, null);
        }

        CompactionWatermark next(Record terminal) throws IOException {
            if (terminal == null || terminal.state != State.CONSUMED
                    && terminal.state != State.CANCELED && terminal.state != State.EXPIRED
                    || epoch == Long.MAX_VALUE) {
                throw new IOException("invalid terminal compaction candidate");
            }
            String recordSha256 = sha256(CapabilityLeasePendingRecordCodec.encode(terminal));
            return next(terminal.handle, recordSha256);
        }

        CompactionWatermark next(String terminalHandle, String terminalRecordSha256)
                throws IOException {
            if (terminalHandle == null
                    || !terminalHandle.matches("lease-pending-[0-9a-f]{64}")
                    || terminalRecordSha256 == null
                    || !terminalRecordSha256.matches("[0-9a-f]{64}")
                    || epoch == Long.MAX_VALUE) {
                throw new IOException("invalid terminal compaction digest");
            }
            long nextEpoch = epoch + 1;
            String nextRoot = sha256((DOMAIN + '\n' + rootSha256 + '\n' + nextEpoch + '\n'
                    + terminalHandle + '\n' + terminalRecordSha256)
                    .getBytes(StandardCharsets.UTF_8));
            return new CompactionWatermark(nextEpoch, rootSha256, nextRoot,
                    terminalHandle, terminalRecordSha256);
        }

        void requireValidSuccessor(CompactionWatermark previous, Record terminal)
                throws IOException {
            CompactionWatermark expected = previous.next(terminal);
            if (epoch != expected.epoch || !previousRootSha256.equals(expected.previousRootSha256)
                    || !rootSha256.equals(expected.rootSha256)
                    || !lastHandle.equals(expected.lastHandle)
                    || !lastRecordSha256.equals(expected.lastRecordSha256)) {
                throw new IOException("invalid compaction successor");
            }
        }

        boolean exactState(CompactionWatermark other) {
            return other != null && epoch == other.epoch
                    && previousRootSha256.equals(other.previousRootSha256)
                    && rootSha256.equals(other.rootSha256)
                    && equalNullable(lastHandle, other.lastHandle)
                    && equalNullable(lastRecordSha256, other.lastRecordSha256);
        }

        private static boolean equalNullable(String left, String right) {
            return left == null ? right == null : left.equals(right);
        }

        private static String emptyToNull(String value) {
            return value == null || value.isEmpty() ? null : value;
        }

        private static String requireDigest(String value) {
            if (value == null || !value.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("invalid compaction digest");
            }
            return value;
        }

        private static String sha256(byte[] value) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
                char[] output = new char[digest.length * 2];
                char[] alphabet = "0123456789abcdef".toCharArray();
                for (int index = 0; index < digest.length; index++) {
                    int item = digest[index] & 0xff;
                    output[index * 2] = alphabet[item >>> 4];
                    output[index * 2 + 1] = alphabet[item & 0x0f];
                }
                return new String(output);
            } catch (NoSuchAlgorithmException impossible) {
                throw new AssertionError("SHA-256 unavailable", impossible);
            }
        }
    }

    /**
     * Permanent replay identity written before a terminal pending record may be unlinked.
     *
     * <p>The tombstone retains every field needed to return the original handle for an exact
     * prepare retry and to reject drift in peer, boot, request, canonical Direct/task binding,
     * workflow, task, provider, or URI. It intentionally omits the large challenge/receipt body.
     */
    final class RetirementTombstone {
        final long epoch;
        final String previousRootSha256;
        final String rootSha256;
        final String terminalRecordSha256;
        final String handle;
        final AgentDescriptor creatorPeerIdentity;
        final String prepareRequestId;
        final String authenticatedTaskBindingSha256;
        final String prepareCanonicalRequestSha256;
        final String workflowId;
        final String taskId;
        final String bootIdSha256;
        final String providerId;
        final String exactHttpsUri;
        final State terminalState;
        final String receiptId;
        final String receiptSha256;

        RetirementTombstone(long epoch, String previousRootSha256, String rootSha256,
                String terminalRecordSha256, String handle,
                AgentDescriptor creatorPeerIdentity, String prepareRequestId,
                String authenticatedTaskBindingSha256,
                String prepareCanonicalRequestSha256, String workflowId, String taskId,
                String bootIdSha256, String providerId, String exactHttpsUri,
                State terminalState, String receiptId, String receiptSha256) {
            if (epoch <= 0 || previousRootSha256 == null
                    || !previousRootSha256.matches("[0-9a-f]{64}")
                    || rootSha256 == null || !rootSha256.matches("[0-9a-f]{64}")
                    || terminalRecordSha256 == null
                    || !terminalRecordSha256.matches("[0-9a-f]{64}")
                    || handle == null || !handle.matches("lease-pending-[0-9a-f]{64}")
                    || creatorPeerIdentity == null
                    || prepareRequestId == null
                    || !prepareRequestId.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
                    || !nonzeroDigest(authenticatedTaskBindingSha256)
                    || !nonzeroDigest(prepareCanonicalRequestSha256)
                    || workflowId == null
                    || !workflowId.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
                    || taskId == null
                    || !taskId.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
                    || !nonzeroDigest(bootIdSha256)
                    || !AgentDescriptorRegistry.isProductProviderId(providerId)
                    || !creatorPeerIdentity.providerId().equals(providerId)
                    || exactHttpsUri == null || exactHttpsUri.isEmpty()
                    || exactHttpsUri.getBytes(StandardCharsets.UTF_8).length > 4 * 1024
                    || !terminal(terminalState)) {
                throw new IllegalArgumentException("invalid pending retirement tombstone");
            }
            String normalizedReceiptId = emptyToNull(receiptId);
            String normalizedReceiptSha256 = emptyToNull(receiptSha256);
            if (terminalState == State.CONSUMED) {
                if (!digest(normalizedReceiptId) || !digest(normalizedReceiptSha256)) {
                    throw new IllegalArgumentException("invalid consumed retirement receipt");
                }
            } else if (normalizedReceiptId != null || normalizedReceiptSha256 != null) {
                throw new IllegalArgumentException("unexpected retirement receipt");
            }
            this.epoch = epoch;
            this.previousRootSha256 = previousRootSha256;
            this.rootSha256 = rootSha256;
            this.terminalRecordSha256 = terminalRecordSha256;
            this.handle = handle;
            this.creatorPeerIdentity = creatorPeerIdentity;
            this.prepareRequestId = prepareRequestId;
            this.authenticatedTaskBindingSha256 = authenticatedTaskBindingSha256;
            this.prepareCanonicalRequestSha256 = prepareCanonicalRequestSha256;
            this.workflowId = workflowId;
            this.taskId = taskId;
            this.bootIdSha256 = bootIdSha256;
            this.providerId = providerId;
            this.exactHttpsUri = exactHttpsUri;
            this.terminalState = terminalState;
            this.receiptId = normalizedReceiptId;
            this.receiptSha256 = normalizedReceiptSha256;
        }

        static RetirementTombstone from(Record terminal, CompactionWatermark watermark)
                throws IOException {
            if (terminal == null || !terminal(terminal.state) || watermark == null
                    || !terminal.handle.equals(watermark.lastHandle)) {
                throw new IOException("invalid pending retirement candidate");
            }
            String recordSha256 = recordSha256(terminal);
            if (!recordSha256.equals(watermark.lastRecordSha256)) {
                throw new IOException("pending retirement record digest mismatch");
            }
            return new RetirementTombstone(watermark.epoch,
                    watermark.previousRootSha256, watermark.rootSha256,
                    recordSha256, terminal.handle, terminal.creatorPeerIdentity,
                    terminal.prepareRequestId, terminal.authenticatedTaskBindingSha256,
                    terminal.prepareCanonicalRequestSha256, terminal.workflowId,
                    terminal.taskId, terminal.bootIdSha256, terminal.providerId,
                    terminal.exactHttpsUri, terminal.state, terminal.receiptId,
                    terminal.receiptSha256);
        }

        String fileName() {
            return handle.substring("lease-pending-".length()) + ".tombstone";
        }

        String prepareReplayKey() {
            return creatorPeerIdentity.replayKey(prepareRequestId);
        }

        String authenticatedTaskReplayKey() {
            return creatorPeerIdentity.replayKey(
                    "task-binding:" + authenticatedTaskBindingSha256);
        }

        CompactionWatermark watermark() {
            return new CompactionWatermark(epoch, previousRootSha256, rootSha256,
                    handle, terminalRecordSha256);
        }

        void requireValidSuccessor(CompactionWatermark previous) throws IOException {
            CompactionWatermark expected = previous.next(handle, terminalRecordSha256);
            if (!watermark().exactState(expected)) {
                throw new IOException("invalid pending retirement tombstone chain");
            }
        }

        void requireMatchesRecord(Record record) throws IOException {
            if (record == null || !terminal(record.state)
                    || !handle.equals(record.handle)
                    || creatorPeerIdentity != record.creatorPeerIdentity
                    || !prepareRequestId.equals(record.prepareRequestId)
                    || !constantTimeEquals(authenticatedTaskBindingSha256,
                            record.authenticatedTaskBindingSha256)
                    || !constantTimeEquals(prepareCanonicalRequestSha256,
                            record.prepareCanonicalRequestSha256)
                    || !workflowId.equals(record.workflowId) || !taskId.equals(record.taskId)
                    || !bootIdSha256.equals(record.bootIdSha256)
                    || !providerId.equals(record.providerId)
                    || !exactHttpsUri.equals(record.exactHttpsUri)
                    || terminalState != record.state
                    || !equalNullable(receiptId, record.receiptId)
                    || !equalNullable(receiptSha256, record.receiptSha256)
                    || !terminalRecordSha256.equals(recordSha256(record))) {
                throw new IOException("pending retirement record mismatch");
            }
        }

        private static String recordSha256(Record record) throws IOException {
            return sha256(CapabilityLeasePendingRecordCodec.encode(record));
        }

        private static boolean terminal(State state) {
            return state == State.CONSUMED || state == State.CANCELED
                    || state == State.EXPIRED;
        }

        private static boolean digest(String value) {
            return value != null && value.matches("[0-9a-f]{64}");
        }

        private static boolean nonzeroDigest(String value) {
            return digest(value) && !value.equals("0".repeat(64));
        }

        private static String emptyToNull(String value) {
            return value == null || value.isEmpty() ? null : value;
        }

        private static boolean constantTimeEquals(String left, String right) {
            return left != null && right != null && MessageDigest.isEqual(
                    left.getBytes(StandardCharsets.US_ASCII),
                    right.getBytes(StandardCharsets.US_ASCII));
        }

        private static boolean equalNullable(String left, String right) {
            return left == null ? right == null : left.equals(right);
        }

        private static String sha256(byte[] value) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
                char[] output = new char[digest.length * 2];
                char[] alphabet = "0123456789abcdef".toCharArray();
                for (int index = 0; index < digest.length; index++) {
                    int item = digest[index] & 0xff;
                    output[index * 2] = alphabet[item >>> 4];
                    output[index * 2 + 1] = alphabet[item & 0x0f];
                }
                return new String(output);
            } catch (NoSuchAlgorithmException impossible) {
                throw new AssertionError("SHA-256 unavailable", impossible);
            }
        }
    }

    /**
     * Reports that the compaction watermark reached its durable commit point, but cleanup could
     * not be proven complete in this process. The caller must adopt {@link #watermark} and poison
     * the live broker until a restart performs the normal watermark recovery.
     */
    final class CompactionCommittedException extends IOException {
        private static final long serialVersionUID = 1L;

        final CompactionWatermark watermark;

        CompactionCommittedException(CompactionWatermark watermark, Throwable cause) {
            super("terminal compaction committed but cleanup is indeterminate", cause);
            if (watermark == null || watermark.epoch <= 0) {
                throw new IllegalArgumentException("invalid committed compaction watermark");
            }
            this.watermark = watermark;
        }

        void requireExact(CompactionWatermark expected) throws IOException {
            if (expected == null || watermark.epoch != expected.epoch
                    || !watermark.previousRootSha256.equals(expected.previousRootSha256)
                    || !watermark.rootSha256.equals(expected.rootSha256)
                    || !watermark.lastHandle.equals(expected.lastHandle)
                    || !watermark.lastRecordSha256.equals(expected.lastRecordSha256)) {
                throw new IOException("committed compaction outcome mismatch");
            }
        }
    }

    /**
     * Reports that a replacement reached its verified durable commit point, but the caller did
     * not receive an ordinary success result. The live broker must adopt {@link #replacement}
     * and remain poisoned until restart reloads the durable record set.
     */
    final class ReplacementCommittedException extends IOException {
        private static final long serialVersionUID = 1L;

        final Record replacement;

        ReplacementCommittedException(Record replacement, Throwable cause) {
            super("pending replacement committed but completion is indeterminate", cause);
            if (replacement == null) {
                throw new IllegalArgumentException("missing committed pending replacement");
            }
            this.replacement = replacement;
        }

        void requireExact(Record expected) throws IOException {
            if (expected == null || !Arrays.equals(
                    CapabilityLeasePendingRecordCodec.encode(replacement),
                    CapabilityLeasePendingRecordCodec.encode(expected))) {
                throw new IOException("committed pending replacement outcome mismatch");
            }
        }
    }

    /**
     * Reports that a new pending record reached its verified durable commit point, but the caller
     * did not receive an ordinary success result. The live broker must adopt {@link #record} and
     * remain poisoned until restart reloads the durable record set.
     */
    final class CreateCommittedException extends IOException {
        private static final long serialVersionUID = 1L;

        final Record record;

        CreateCommittedException(Record record, Throwable cause) {
            super("pending create committed but completion is indeterminate", cause);
            if (record == null || record.state != State.PENDING) {
                throw new IllegalArgumentException("invalid committed pending create");
            }
            this.record = record;
        }

        void requireExact(Record expected) throws IOException {
            if (expected == null || !Arrays.equals(
                    CapabilityLeasePendingRecordCodec.encode(record),
                    CapabilityLeasePendingRecordCodec.encode(expected))) {
                throw new IOException("committed pending create outcome mismatch");
            }
        }
    }

    /** Loads the complete retained set exactly once. Malformation fails the store closed. */
    Map<String, Record> load() throws IOException;

    /** Durably creates one record and its directory entry before returning. */
    void create(Record record) throws IOException;

    /** Atomically replaces exactly the expected prior bytes with one valid transition. */
    void replace(Record expected, Record replacement) throws IOException;

    CompactionWatermark loadCompactionWatermark() throws IOException;

    /** Loads every permanent replay tombstone; entries are never deleted or summarized away. */
    default Map<String, RetirementTombstone> loadRetirementTombstones() throws IOException {
        return Collections.emptyMap();
    }

    void compactTerminal(Record expected, CompactionWatermark replacement) throws IOException;

    /** True only when this live store instance can no longer prove a coherent durable view. */
    default boolean isPoisoned() {
        return false;
    }
}
