/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.capabilitylease;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Fixed process-boundary schema and pre-allocation bounds for the issuer broker. */
public final class CapabilityLeaseUiProtocol {
    public static final String TRANSPORT_SCHEMA =
            "org.trillionnium.capabilitylease.ui-broker.v1";
    public static final String VIEW_SCHEMA =
            "org.trillionnium.capabilitylease.pending-issuer-view.v1";
    public static final String SUBMISSION_STATUS_SCHEMA =
            "org.trillionnium.capabilitylease.submission-status.v1";
    public static final String STATUS_NOT_STARTED = "not_started";
    public static final String STATUS_INDETERMINATE = "indeterminate";
    public static final String STATUS_SUBMITTED = "submitted";
    public static final String STATUS_DELIVERY_READY = "delivery_ready";
    public static final String STATUS_CONSUMED = "consumed";
    public static final String STATUS_CANCELED = "canceled";
    public static final String STATUS_EXPIRED = "expired";
    public static final int ERROR_UNAVAILABLE = 1;
    public static final int ERROR_INDETERMINATE = 2;
    public static final int VIEW_FIELDS = 8;
    public static final int SUBMISSION_STATUS_FIELDS = 5;
    public static final int MAX_CHALLENGE_BYTES = 64 * 1024;
    public static final int MAX_URI_BYTES = 4 * 1024;
    public static final int MAX_HOST_BYTES = 253;
    public static final int MAX_PROVIDER_BYTES = 128;
    public static final int MAX_RECEIPT_BYTES = 256 * 1024;
    public static final int RECEIPT_ID_HEX_CHARS = 64;
    private static final String HANDLE_PREFIX = "lease-pending-";
    private static final int HANDLE_DIGEST_CHARS = 64;
    private static final String SUBMISSION_OPERATION_PREFIX = "lease-submit-";
    private static final String SUBMISSION_OPERATION_DOMAIN =
            "org.trillionnium.capabilitylease.submission-operation.v1\0";
    private static final String SUBMISSION_STATUS_DOMAIN =
            "org.trillionnium.capabilitylease.submission-status-tuple.v1\0";

    private CapabilityLeaseUiProtocol() {}

    public static void requireTransportSchema(String schema) {
        if (!TRANSPORT_SCHEMA.equals(schema)) {
            throw denied("capability_lease_broker_transport_schema_denied");
        }
    }

    public static String requirePendingHandle(String handle) {
        if (handle == null
                || handle.length() != HANDLE_PREFIX.length() + HANDLE_DIGEST_CHARS
                || !handle.startsWith(HANDLE_PREFIX)) {
            throw denied("capability_lease_broker_handle_denied");
        }
        for (int index = HANDLE_PREFIX.length(); index < handle.length(); index++) {
            char item = handle.charAt(index);
            if (!((item >= '0' && item <= '9') || (item >= 'a' && item <= 'f'))) {
                throw denied("capability_lease_broker_handle_denied");
            }
        }
        return handle;
    }

    public static String requireReceipt(String receipt) {
        return boundedUtf8(receipt, MAX_RECEIPT_BYTES,
                "capability_lease_broker_receipt_denied");
    }

    public static String requireChallenge(String challenge) {
        return boundedUtf8(challenge, MAX_CHALLENGE_BYTES,
                "capability_lease_broker_challenge_denied");
    }

    public static String requireUri(String uri) {
        return boundedSingleLine(uri, MAX_URI_BYTES,
                "capability_lease_broker_uri_denied");
    }

    public static String requireHost(String host) {
        return boundedSingleLine(host, MAX_HOST_BYTES,
                "capability_lease_broker_host_denied");
    }

    public static String requireProvider(String provider) {
        return boundedSingleLine(provider, MAX_PROVIDER_BYTES,
                "capability_lease_broker_provider_denied");
    }

    public static String requireReceiptId(String receiptId) {
        if (receiptId == null || receiptId.length() != RECEIPT_ID_HEX_CHARS) {
            throw denied("capability_lease_broker_submission_denied");
        }
        for (int index = 0; index < receiptId.length(); index++) {
            char item = receiptId.charAt(index);
            if (!((item >= '0' && item <= '9') || (item >= 'a' && item <= 'f'))) {
                throw denied("capability_lease_broker_submission_denied");
            }
        }
        return receiptId;
    }

    /** Derives the stable operation id known before a synchronous submit result is delivered. */
    public static String deriveSubmissionOperationId(String handle, String exactReceipt) {
        String receipt = requireReceipt(exactReceipt);
        return deriveSubmissionOperationIdFromReceiptSha256(
                requirePendingHandle(handle), sha256(receipt.getBytes(StandardCharsets.UTF_8)));
    }

    /** Reconstructs the same operation id from broker-custodied receipt metadata after restart. */
    public static String deriveSubmissionOperationIdFromReceiptSha256(
            String handle, String receiptSha256) {
        String exactHandle = requirePendingHandle(handle);
        String exactReceiptSha256 = requireSha256(
                receiptSha256, "capability_lease_broker_receipt_digest_denied");
        return SUBMISSION_OPERATION_PREFIX + sha256((SUBMISSION_OPERATION_DOMAIN
                + exactHandle + '\0' + exactReceiptSha256).getBytes(StandardCharsets.UTF_8));
    }

    public static String requireSubmissionOperationId(String operationId) {
        if (operationId == null
                || operationId.length()
                        != SUBMISSION_OPERATION_PREFIX.length() + RECEIPT_ID_HEX_CHARS
                || !operationId.startsWith(SUBMISSION_OPERATION_PREFIX)) {
            throw denied("capability_lease_broker_submission_operation_denied");
        }
        requireSha256(operationId.substring(SUBMISSION_OPERATION_PREFIX.length()),
                "capability_lease_broker_submission_operation_denied");
        return operationId;
    }

    public static String requireSubmissionStatus(String status) {
        if (!STATUS_NOT_STARTED.equals(status) && !STATUS_INDETERMINATE.equals(status)
                && !STATUS_SUBMITTED.equals(status) && !STATUS_DELIVERY_READY.equals(status)
                && !STATUS_CONSUMED.equals(status) && !STATUS_CANCELED.equals(status)
                && !STATUS_EXPIRED.equals(status)) {
            throw denied("capability_lease_broker_submission_status_denied");
        }
        return status;
    }

    /** Digest acknowledged only by AiShell after it receives and verifies the full result tuple. */
    public static String deriveSubmissionStatusTupleSha256(String handle, String operationId,
            String status, String receiptId) {
        String exactHandle = requirePendingHandle(handle);
        String exactOperationId = requireSubmissionOperationId(operationId);
        String exactStatus = requireSubmissionStatus(status);
        String exactReceiptId = receiptId == null ? "" : receiptId;
        boolean receiptRequired = STATUS_INDETERMINATE.equals(exactStatus)
                || STATUS_SUBMITTED.equals(exactStatus)
                || STATUS_DELIVERY_READY.equals(exactStatus)
                || STATUS_CONSUMED.equals(exactStatus);
        if (receiptRequired) {
            exactReceiptId = requireReceiptId(exactReceiptId);
        } else if (!exactReceiptId.isEmpty()) {
            throw denied("capability_lease_broker_submission_status_denied");
        }
        return sha256((SUBMISSION_STATUS_DOMAIN + SUBMISSION_STATUS_SCHEMA + '\0'
                + exactHandle + '\0' + exactOperationId + '\0' + exactStatus + '\0'
                + exactReceiptId).getBytes(StandardCharsets.UTF_8));
    }

    public static String requireSubmissionStatusTupleSha256(String digest) {
        return requireSha256(digest,
                "capability_lease_broker_submission_status_digest_denied");
    }

    private static String boundedUtf8(String value, int maxBytes, String reason) {
        // The UTF-16 precheck avoids allocating a large UTF-8 array for an already-invalid input.
        if (value == null || value.isEmpty() || value.length() > maxBytes
                || value.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
            throw denied(reason);
        }
        return value;
    }

    private static String boundedSingleLine(String value, int maxBytes, String reason) {
        String item = boundedUtf8(value, maxBytes, reason);
        for (int index = 0; index < item.length(); index++) {
            char character = item.charAt(index);
            if (Character.isISOControl(character) || Character.isWhitespace(character)
                    || Character.getType(character) == Character.FORMAT) {
                throw denied(reason);
            }
        }
        return item;
    }

    private static String requireSha256(String value, String reason) {
        if (value == null || value.length() != RECEIPT_ID_HEX_CHARS) throw denied(reason);
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (!((item >= '0' && item <= '9') || (item >= 'a' && item <= 'f'))) {
                throw denied(reason);
            }
        }
        return value;
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            char[] encoded = new char[digest.length * 2];
            char[] alphabet = "0123456789abcdef".toCharArray();
            for (int index = 0; index < digest.length; index++) {
                int item = digest[index] & 0xff;
                encoded[index * 2] = alphabet[item >>> 4];
                encoded[index * 2 + 1] = alphabet[item & 0x0f];
            }
            return new String(encoded);
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError("SHA-256 unavailable", impossible);
        }
    }

    private static SecurityException denied(String reason) {
        return new SecurityException(reason);
    }
}
