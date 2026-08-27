/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.capabilitylease;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.graphics.Color;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.os.SystemClock;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicBoolean;

/** OS-owned, hardware-signed consent ceremony for one broker-custodied capability lease. */
public final class CapabilityLeaseActivity extends Activity {
    public static final String ACTION_REQUEST_CAPABILITY_LEASE =
            LeaseIssuerTrust.REQUEST_ACTION;
    public static final String EXTRA_PENDING_HANDLE = "capability_lease_pending_handle";
    public static final String EXTRA_STATUS = "capability_lease_status";
    public static final String EXTRA_RECEIPT_ID = "capability_lease_receipt_id";
    public static final String EXTRA_SUBMISSION_OPERATION_ID =
            "capability_lease_submission_operation_id";
    public static final String EXTRA_SUBMISSION_STATUS_TUPLE_SHA256 =
            "capability_lease_submission_status_tuple_sha256";
    static final String STATUS_SUBMITTED = "submitted";
    static final String STATUS_INDETERMINATE = "indeterminate";
    static final String STATUS_DENIED = "denied";
    static final String STATUS_EXPIRED = "expired";
    static final String STATUS_UNAVAILABLE = "unavailable";

    private final AtomicBoolean mCompleted = new AtomicBoolean(false);
    private String mPendingHandle;
    private String mBrokerChallengeJson;
    private JSONObject mChallenge;
    private CapabilityLeaseBrokerClient mBroker;
    private CapabilityLeaseBrokerClient.PendingChallenge mBrokerView;
    private CapabilityLeasePresentation mPresentation;
    private ReceiptSigner mReceiptSigner;
    private CapabilityLeaseIssuanceLedger mIssuanceLedger;
    private CountDownTimer mExpiryTimer;
    private TextView mRemainingView;
    private Button mAllowButton;
    private int mLaunchedFromUid = -1;
    private boolean mCallerAuthenticated;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setHideOverlayWindows(true);
        setRecentsScreenshotEnabled(false);
        setFinishOnTouchOutside(false);
        setResult(RESULT_CANCELED);
        try {
            mLaunchedFromUid = getLaunchedFromUid();
            SystemUserBoundary.requireProcessAndCaller(android.os.Process.myUid(),
                    mLaunchedFromUid, "capability_lease_unsupported_android_user");
            requireAuthenticatedAiShellCaller();
            mCallerAuthenticated = true;

            Intent request = getIntent();
            if (request == null
                    || !ACTION_REQUEST_CAPABILITY_LEASE.equals(request.getAction())
                    || request.getData() != null || request.getClipData() != null
                    || request.getType() != null || request.getCategories() != null
                    || request.getSelector() != null
                    || request.getExtras() == null
                    || (request.getExtras().size() != 1 && request.getExtras().size() != 2)
                    || !request.hasExtra(EXTRA_PENDING_HANDLE)
                    || (request.getExtras().size() == 2
                            && !request.hasExtra(EXTRA_SUBMISSION_OPERATION_ID))) {
                throw new SecurityException("capability_lease_intent_surface_denied");
            }
            Object rawHandle = request.getExtras().get(EXTRA_PENDING_HANDLE);
            if (!(rawHandle instanceof String)) {
                throw new SecurityException("capability_lease_pending_handle_type_denied");
            }
            mPendingHandle = LeasePendingHandle.requireExact((String) rawHandle);

            // The broker API is issuer-role authenticated. Product enrollment remains HOLD, and
            // there is no fallback that parses caller-authored challenge or destination content.
            mBroker = CapabilityLeaseBrokerClients.connect();
            if (request.hasExtra(EXTRA_SUBMISSION_OPERATION_ID)) {
                Object rawOperationId = request.getExtras().get(
                        EXTRA_SUBMISSION_OPERATION_ID);
                if (!(rawOperationId instanceof String)) {
                    throw new SecurityException(
                            "capability_lease_submission_operation_type_denied");
                }
                CapabilityLeaseBrokerClient.Submission recovered =
                        mBroker.querySubmissionStatus(mPendingHandle,
                                CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                                        (String) rawOperationId));
                finishWithStatus(recovered.status(), recovered.receiptId(),
                        recovered.submissionOperationId(), recovered.statusTupleSha256());
                return;
            }
            mBrokerView = mBroker.fetchExactChallenge(mPendingHandle);
            mBrokerChallengeJson = mBrokerView.exactChallenge();
            long nowElapsedMs = SystemClock.elapsedRealtime();
            mChallenge = CapabilityLeaseContract.parseChallenge(mBrokerChallengeJson,
                    mLaunchedFromUid, currentBootIdSha256(), System.currentTimeMillis(),
                    nowElapsedMs);
            mPresentation = CapabilityLeasePresentation.requireExact(
                    mChallenge, mBrokerView, nowElapsedMs);

            mReceiptSigner = new ReceiptSigner(getApplicationContext());
            if (!mReceiptSigner.isHardwareBacked() || !mReceiptSigner.hasAttestationChain()) {
                throw new SecurityException("hardware_receipt_signer_unavailable");
            }
            android.content.Context deviceProtected = createDeviceProtectedStorageContext();
            if (!deviceProtected.isDeviceProtectedStorage()) {
                throw new SecurityException("capability_lease_device_storage_unavailable");
            }
            mIssuanceLedger = new CapabilityLeaseIssuanceLedger(
                    deviceProtected.getNoBackupFilesDir().toPath(),
                    new AndroidDurableFileOps(),
                    CapabilityLeaseIssuanceLedger.Limits.PRODUCTION);
            buildConsentUi();
            startExpiryTimer();
        } catch (Exception denied) {
            if (mCallerAuthenticated) finishWithStatus(STATUS_UNAVAILABLE, "");
            else finish();
        }
    }

    @Override protected void onStop() {
        super.onStop();
        if (!isChangingConfigurations() && !mCompleted.get()) deny();
    }

    @Override protected void onDestroy() {
        if (mExpiryTimer != null) mExpiryTimer.cancel();
        super.onDestroy();
    }

    private void requireAuthenticatedAiShellCaller() throws Exception {
        String callerPackage = getCallingPackage();
        if (!LeaseIssuerTrust.UI_PACKAGE.equals(callerPackage)) {
            throw new SecurityException("capability_lease_caller_package_denied");
        }
        ApplicationInfo caller = getPackageManager().getApplicationInfo(callerPackage, 0);
        if (caller.uid != mLaunchedFromUid) {
            throw new SecurityException("capability_lease_caller_uid_mismatch");
        }
    }

    private void buildConsentUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.rgb(8, 12, 16));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (20 * getResources().getDisplayMetrics().density);
        root.setPadding(padding, padding, padding, padding);
        scroll.addView(root);

        root.addView(text("Allow this exact HTTPS URI once?", 24, Color.WHITE));
        root.addView(text(
                "Trillionnium Capability Lease will issue a hardware-signed, boot-bound lease. "
                        + "It authorizes only the exact URI shown below and does not execute it.",
                14, Color.rgb(130, 220, 196)));
        root.addView(text(
                "Exact HTTPS URI (complete):\n" + mPresentation.exactUri()
                        + "\n\nDestination host:\n" + mPresentation.destinationHost()
                        + "\n\nAndroid user: " + mPresentation.subjectUserId()
                        + "\nProvider: " + providerLabel(mPresentation.providerId())
                        + "\nAuthorization: one use only",
                16, Color.rgb(255, 211, 128)));
        mRemainingView = text("", 15, Color.WHITE);
        root.addView(mRemainingView);

        mAllowButton = secureButton("Allow once", view -> allowOnce());
        Button deny = secureButton("Deny", view -> deny());
        root.addView(mAllowButton);
        root.addView(deny);
        updateRemaining();
        setContentView(scroll);
    }

    private void startExpiryTimer() {
        long remainingMs = mPresentation.expiresElapsedRealtimeMs()
                - SystemClock.elapsedRealtime();
        if (remainingMs <= 0) {
            expire();
            return;
        }
        mExpiryTimer = new CountDownTimer(remainingMs, 250L) {
            @Override public void onTick(long ignored) { updateRemaining(); }
            @Override public void onFinish() { expire(); }
        }.start();
    }

    private void updateRemaining() {
        if (mRemainingView == null) return;
        long seconds = mPresentation.remainingSeconds(SystemClock.elapsedRealtime());
        mRemainingView.setText("Remaining: " + seconds + " seconds");
        if (mAllowButton != null) mAllowButton.setEnabled(seconds > 0);
    }

    private Button secureButton(String label, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setFilterTouchesWhenObscured(true);
        button.setOnTouchListener((view, event) -> {
            int obscured = MotionEvent.FLAG_WINDOW_IS_OBSCURED
                    | MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED;
            if ((event.getFlags() & obscured) != 0) {
                deny();
                return true;
            }
            return false;
        });
        button.setOnClickListener(listener);
        return button;
    }

    private TextView text(String value, int sp, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setSingleLine(false);
        view.setHorizontallyScrolling(false);
        view.setEllipsize(null);
        int padding = (int) (10 * getResources().getDisplayMetrics().density);
        view.setPadding(0, padding, 0, padding);
        return view;
    }

    private void allowOnce() {
        if (!mCompleted.compareAndSet(false, true)) return;
        String receiptId = "";
        String submissionOperationId = "";
        try {
            SystemUserBoundary.requireProcessAndCaller(android.os.Process.myUid(),
                    mLaunchedFromUid, "capability_lease_unsupported_android_user");
            requireAuthenticatedAiShellCaller();
            CapabilityLeaseBrokerClient.PendingChallenge confirmedView =
                    mBroker.fetchExactChallenge(mPendingHandle);
            mBrokerView.requireSameImmutableView(confirmedView);
            long nowElapsedMs = SystemClock.elapsedRealtime();
            JSONObject confirmedChallenge = CapabilityLeaseContract.parseChallenge(
                    confirmedView.exactChallenge(), mLaunchedFromUid, currentBootIdSha256(),
                    System.currentTimeMillis(), nowElapsedMs);
            CapabilityLeasePresentation.requireExact(
                    confirmedChallenge, confirmedView, nowElapsedMs);
            String leaseId = confirmedChallenge.getString("lease_id");
            CapabilityLeaseIssuanceLedger.Result issuance = mIssuanceLedger.issueOrReplay(
                    leaseId, mBrokerChallengeJson, this::signExactReceiptAfterPrepared);

            long nowWallMs = System.currentTimeMillis();
            nowElapsedMs = SystemClock.elapsedRealtime();
            JSONObject challenge = CapabilityLeaseContract.parseChallenge(mBrokerChallengeJson,
                    mLaunchedFromUid, currentBootIdSha256(), nowWallMs, nowElapsedMs);
            CapabilityLeasePresentation.requireExact(challenge, mBrokerView, nowElapsedMs);
            String exactReceipt = issuance.exactReceipt();
            JSONObject verified = CapabilityLeaseContract.parseReceiptEnvelope(
                    exactReceipt, challenge, nowWallMs, nowElapsedMs);
            mReceiptSigner.requireOwnTrustMetadata(verified);
            mReceiptSigner.verify(CapabilityLeaseContract.canonicalReceiptForSignature(verified),
                    verified.getString("receipt_signature"));
            CapabilityLeaseBrokerClient.Submission submitted =
                    mBroker.submitExactReceipt(mPendingHandle, exactReceipt);
            receiptId = verified.getString("receipt_id");
            if (!receiptId.equals(submitted.receiptId())) {
                throw new SecurityException("capability_lease_broker_receipt_id_denied");
            }
            submissionOperationId = submitted.submissionOperationId();
            finishWithStatus(submitted.status(), receiptId, submissionOperationId,
                    submitted.statusTupleSha256());
        } catch (CapabilityLeaseBrokerClient.SubmissionIndeterminateException uncertain) {
            // The submit worker started, so an ordinary unavailable result would invite an unsafe
            // retry. AiShell receives the stable operation id and must relaunch/query after the
            // broker restarts; no delivery ACK or backend release occurs on this path.
            finishWithStatus(STATUS_INDETERMINATE, receiptId,
                    uncertain.submissionOperationId(), "");
        } catch (Exception denied) {
            finishWithStatus(STATUS_UNAVAILABLE, "");
        }
    }

    /** Called by the ledger exactly once, and only after PREPARED is durably committed. */
    private String signExactReceiptAfterPrepared() throws Exception {
        long nowWallMs = System.currentTimeMillis();
        long nowElapsedMs = SystemClock.elapsedRealtime();
        JSONObject challenge = CapabilityLeaseContract.parseChallenge(mBrokerChallengeJson,
                mLaunchedFromUid, currentBootIdSha256(), nowWallMs, nowElapsedMs);
        CapabilityLeasePresentation.requireExact(challenge, mBrokerView, nowElapsedMs);
        JSONObject receipt = CapabilityLeaseContract.newUnsignedReceipt(
                challenge, nowWallMs, nowElapsedMs);
        mReceiptSigner.annotate(receipt);
        receipt.put("receipt_signature", mReceiptSigner.sign(
                CapabilityLeaseContract.canonicalReceiptForSignature(receipt)));
        receipt.put("receipt_id", CapabilityLeaseContract.sha256(
                CapabilityLeaseContract.canonicalReceipt(receipt, false)));
        String exactReceipt = CanonicalJson.encode(receipt);
        JSONObject verified = CapabilityLeaseContract.parseReceiptEnvelope(
                exactReceipt, challenge, nowWallMs, nowElapsedMs);
        mReceiptSigner.requireOwnTrustMetadata(verified);
        mReceiptSigner.verify(CapabilityLeaseContract.canonicalReceiptForSignature(verified),
                verified.getString("receipt_signature"));
        return exactReceipt;
    }

    private void deny() {
        if (!mCompleted.compareAndSet(false, true)) return;
        try {
            if (mBroker != null && mPendingHandle != null) mBroker.cancelPending(mPendingHandle);
            finishWithStatus(STATUS_DENIED, "");
        } catch (Exception unavailable) {
            finishWithStatus(STATUS_UNAVAILABLE, "");
        }
    }

    private void expire() {
        if (!mCompleted.compareAndSet(false, true)) return;
        try {
            if (mBroker != null && mPendingHandle != null) mBroker.cancelPending(mPendingHandle);
            finishWithStatus(STATUS_EXPIRED, "");
        } catch (Exception unavailable) {
            finishWithStatus(STATUS_UNAVAILABLE, "");
        }
    }

    private void finishWithStatus(String status, String receiptId) {
        finishWithStatus(status, receiptId, "", "");
    }

    private void finishWithStatus(String status, String receiptId,
            String submissionOperationId, String statusTupleSha256) {
        mCompleted.set(true);
        Intent result = new Intent();
        result.putExtra(EXTRA_PENDING_HANDLE, mPendingHandle);
        result.putExtra(EXTRA_STATUS, status);
        result.putExtra(EXTRA_RECEIPT_ID, receiptId);
        result.putExtra(EXTRA_SUBMISSION_OPERATION_ID, submissionOperationId);
        result.putExtra(EXTRA_SUBMISSION_STATUS_TUPLE_SHA256, statusTupleSha256);
        setResult(STATUS_SUBMITTED.equals(status) || STATUS_INDETERMINATE.equals(status)
                        || CapabilityLeaseUiProtocol.STATUS_DELIVERY_READY.equals(status)
                        || CapabilityLeaseUiProtocol.STATUS_CONSUMED.equals(status)
                ? RESULT_OK : RESULT_CANCELED, result);
        finish();
    }

    private static String currentBootIdSha256() throws Exception {
        String bootId = new String(Files.readAllBytes(
                Paths.get("/proc/sys/kernel/random/boot_id")), StandardCharsets.US_ASCII).trim();
        if (!bootId.matches("[0-9a-fA-F-]{36}")) {
            throw new SecurityException("capability_lease_boot_id_unavailable");
        }
        return CapabilityLeaseContract.sha256(bootId);
    }

    private static String providerLabel(String provider) {
        if (!CapabilityLeaseContract.CODEX_PROVIDER_ID.equals(provider)) {
            throw new SecurityException("capability_lease_provider_label_denied");
        }
        return "Codex";
    }
}
