/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.agentaccessibility;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.GestureDescription;
import android.content.ComponentName;
import android.content.Intent;
import android.graphics.Path;
import android.graphics.Rect;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.UserHandle;
import android.util.Slog;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.trillionnium.agentidentity.AgentDescriptor;
import org.trillionnium.agentidentity.AgentDescriptorRegistry;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/** Accessibility-native direct backend. It is alive only while Android binds this service. */
public final class AgentAccessibilityService extends AccessibilityService {
    private static final String TAG = "TrillionniumA11y";
    private static final String BACKEND = "accessibility";
    static final String REPLAY_CONTROL_SOCKET_NAME =
            "trillionnium_accessibility_replay_control";
    private static final int SOCKET_READ_TIMEOUT_MS = 15_000;
    private static final int MAX_PENDING_REQUESTS = 16;
    private static final int MAX_PENDING_REPLAY_CONTROL_REQUESTS = 4;
    private static final int MAX_SNAPSHOT_NODES = 1024;
    private static final int MAX_SNAPSHOT_DEPTH = 32;
    private static final long GESTURE_CALLBACK_GRACE_MS = 5_000;
    private static final int MAX_REPLAY_ENTRIES_PER_PEER = 128;
    private static final long MAX_REPLAY_RESERVED_BYTES_PER_PEER = 48L * 1024 * 1024;
    private static final int MAX_EFFECT_RESPONSE_BYTES = 128 * 1024;
    private static final long MAX_REPLAY_WAIT_MS = 70_000;

    private final Object mLifecycleLock = new Object();
    private final AccessibilityAuthorizationSession mAuthorization =
            new AccessibilityAuthorizationSession(this::isSystemUserExplicitlyAuthorized);
    private final Set<LocalSocket> mOwnedSockets = new HashSet<>();
    private final Set<ExecutorService> mWorkerExecutors = new HashSet<>();
    private final AtomicLong mUiEpoch = new AtomicLong(1);
    private final AtomicLong mGeneration = new AtomicLong();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());

    private volatile boolean mRunning;
    private volatile LocalServerSocket mServer;
    private volatile LocalServerSocket mReplayControlServer;
    private volatile ThreadPoolExecutor mRequests;
    private volatile ThreadPoolExecutor mReplayControlRequests;
    private volatile AccessibilityReplayLedger mReplayLedger;
    private volatile long mPublishedGeneration;
    private volatile long mPublishedEpoch;

    @Override
    public void onCreate() {
        super.onCreate();
        AccessibilityReplayJournal.DurableStore store = null;
        try {
            store = AccessibilityReplayFile.open(this);
            mReplayLedger = new AccessibilityReplayLedger(
                    MAX_REPLAY_ENTRIES_PER_PEER,
                    MAX_REPLAY_RESERVED_BYTES_PER_PEER,
                    MAX_REPLAY_WAIT_MS,
                    store);
        } catch (IOException | RuntimeException e) {
            if (store != null) {
                try {
                    store.close();
                } catch (IOException ignored) {
                    // The backend remains fail-closed; preserve the initialization failure.
                }
            }
            Slog.wtf(TAG, "persistent replay journal unavailable; backend held closed", e);
        }
    }

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        invalidateTree();
        stopDirectBackend();
        long authorizationGeneration = mAuthorization.activateIfAuthorized();
        if (authorizationGeneration == 0) {
            Slog.e(TAG, "explicit per-user Accessibility authorization unavailable; held closed");
            return;
        }
        startDirectBackend(authorizationGeneration);
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        invalidateTree();
    }

    @Override
    public void onInterrupt() {
        invalidateTree();
    }

    @Override
    public boolean onUnbind(Intent intent) {
        stopDirectBackend();
        return super.onUnbind(intent);
    }

    @Override
    public void onDestroy() {
        final AccessibilityReplayLedger ledger;
        final ExecutorService[] workers;
        synchronized (mLifecycleLock) {
            stopDirectBackendLocked();
            ledger = mReplayLedger;
            mReplayLedger = null;
            workers = mWorkerExecutors.toArray(new ExecutorService[0]);
            mWorkerExecutors.clear();
        }
        if (ledger != null) {
            AccessibilityDeferredClose.closeAfterTermination(
                    workers,
                    ledger::close,
                    failure -> Slog.w(TAG, "persistent replay journal close failed", failure));
        }
        super.onDestroy();
    }

    private void startDirectBackend(long authorizationGeneration) {
        synchronized (mLifecycleLock) {
            if (mRunning) {
                return;
            }
            if (!mAuthorization.isCurrentAndAuthorized(authorizationGeneration)) {
                mAuthorization.deactivate();
                Slog.e(TAG, "Accessibility authorization changed before backend start");
                return;
            }
            if (mReplayLedger == null) {
                mAuthorization.deactivate();
                Slog.wtf(TAG, "persistent replay journal unavailable; socket not started");
                return;
            }
            ThreadPoolExecutor requests = new ThreadPoolExecutor(
                    1,
                    1,
                    0L,
                    TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(MAX_PENDING_REQUESTS),
                    runnable -> {
                        Thread thread = new Thread(
                                runnable, "trillionnium-accessibility-request");
                        thread.setDaemon(true);
                        return thread;
                    });
            ThreadPoolExecutor replayControlRequests = new ThreadPoolExecutor(
                    1,
                    1,
                    0L,
                    TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(MAX_PENDING_REPLAY_CONTROL_REQUESTS),
                    runnable -> {
                        Thread thread = new Thread(
                                runnable,
                                "trillionnium-accessibility-replay-control-request");
                        thread.setDaemon(true);
                        return thread;
                    });
            mWorkerExecutors.removeIf(ExecutorService::isTerminated);
            mWorkerExecutors.add(requests);
            mWorkerExecutors.add(replayControlRequests);
            mRequests = requests;
            mReplayControlRequests = replayControlRequests;
            mRunning = true;
            Thread acceptThread = new Thread(
                    () -> serveDirect(
                            requests, replayControlRequests, authorizationGeneration),
                    "trillionnium-accessibility-accept");
            acceptThread.setDaemon(true);
            acceptThread.start();
            Thread replayControlThread = new Thread(
                    () -> serveReplayControl(
                            requests, replayControlRequests, authorizationGeneration),
                    "trillionnium-accessibility-replay-control-accept");
            replayControlThread.setDaemon(true);
            replayControlThread.start();
        }
    }

    private void stopDirectBackend() {
        synchronized (mLifecycleLock) {
            stopDirectBackendLocked();
        }
    }

    private void stopDirectBackendLocked() {
        mRunning = false;
        mAuthorization.deactivate();
        LocalServerSocket server = mServer;
        mServer = null;
        LocalServerSocket replayControlServer = mReplayControlServer;
        mReplayControlServer = null;
        closeQuietly(server);
        closeQuietly(replayControlServer);
        closeOwnedSocketsLocked();
        ThreadPoolExecutor requests = mRequests;
        mRequests = null;
        ThreadPoolExecutor replayControlRequests = mReplayControlRequests;
        mReplayControlRequests = null;
        if (requests != null) {
            requests.shutdownNow();
        }
        if (replayControlRequests != null) {
            replayControlRequests.shutdownNow();
        }
        invalidateTree();
    }

    private void stopDirectBackendIfCurrent(
            ThreadPoolExecutor requests, ThreadPoolExecutor replayControlRequests) {
        synchronized (mLifecycleLock) {
            if (mRequests == requests && mReplayControlRequests == replayControlRequests) {
                stopDirectBackendLocked();
            }
        }
    }

    private boolean isSystemUserExplicitlyAuthorized() {
        if (UserHandle.myUserId() != UserHandle.USER_SYSTEM) return false;
        return AccessibilityUserAuthorizationGate.isExplicitlyEnabled(
                this, new ComponentName(this, AgentAccessibilityService.class));
    }

    /** Re-checks the live Android grant and tears down only the matching bind generation. */
    private boolean authorizationUsableOrStop(long authorizationGeneration) {
        if (mAuthorization.isCurrentAndAuthorized(authorizationGeneration)) return true;
        synchronized (mLifecycleLock) {
            if (mAuthorization.isCurrent(authorizationGeneration)) {
                stopDirectBackendLocked();
            }
        }
        return false;
    }

    private void serveDirect(
            ThreadPoolExecutor requests, ThreadPoolExecutor replayControlRequests,
            long authorizationGeneration) {
        LocalServerSocket publishedServer = null;
        try (LocalServerSocket server = new LocalServerSocket(
                AccessibilityProtocol.SOCKET_NAME)) {
            if (!publishServerIfCurrent(
                    server, false, requests, replayControlRequests,
                    authorizationGeneration)) {
                return;
            }
            publishedServer = server;
            while (mRunning
                    && mRequests == requests
                    && mReplayControlRequests == replayControlRequests) {
                LocalSocket socket = server.accept();
                try {
                    if (!authorizationUsableOrStop(authorizationGeneration)) {
                        throw new SecurityException("accessibility_authorization_revoked");
                    }
                    AgentDescriptor peerIdentity = DirectPeerPolicy.verify(socket);
                    socket.setSoTimeout(SOCKET_READ_TIMEOUT_MS);
                    if (!trackSocketIfCurrent(
                            socket, requests, replayControlRequests,
                            authorizationGeneration)) {
                        closeQuietly(socket);
                        continue;
                    }
                    requests.execute(() -> handleOwnedSocket(
                            socket, peerIdentity, authorizationGeneration));
                } catch (RejectedExecutionException e) {
                    untrackOwnedSocket(socket);
                    closeQuietly(socket);
                    Slog.w(TAG, "request queue is full");
                } catch (SecurityException | IOException e) {
                    untrackOwnedSocket(socket);
                    closeQuietly(socket);
                    Slog.w(TAG, "rejected direct Accessibility peer");
                }
            }
        } catch (IOException e) {
            if (mRunning && mRequests == requests) {
                Slog.e(TAG, "direct Accessibility socket stopped", e);
            }
        } finally {
            clearPublishedServerIfSame(publishedServer, false);
            stopDirectBackendIfCurrent(requests, replayControlRequests);
        }
    }

    private void serveReplayControl(
            ThreadPoolExecutor requests, ThreadPoolExecutor replayControlRequests,
            long authorizationGeneration) {
        LocalServerSocket publishedServer = null;
        try (LocalServerSocket server = new LocalServerSocket(REPLAY_CONTROL_SOCKET_NAME)) {
            if (!publishServerIfCurrent(
                    server, true, requests, replayControlRequests,
                    authorizationGeneration)) {
                return;
            }
            publishedServer = server;
            while (mRunning
                    && mRequests == requests
                    && mReplayControlRequests == replayControlRequests) {
                LocalSocket socket = server.accept();
                try {
                    if (!authorizationUsableOrStop(authorizationGeneration)) {
                        throw new SecurityException("accessibility_authorization_revoked");
                    }
                    AgentDescriptorRegistry.ReplayControlPeer peerIdentity =
                            DirectPeerPolicy.verifyReplayControl(socket);
                    socket.setSoTimeout(SOCKET_READ_TIMEOUT_MS);
                    if (!trackSocketIfCurrent(
                            socket, requests, replayControlRequests,
                            authorizationGeneration)) {
                        closeQuietly(socket);
                        continue;
                    }
                    replayControlRequests.execute(
                            () -> handleOwnedReplayControlSocket(
                                    socket, peerIdentity, authorizationGeneration));
                } catch (RejectedExecutionException e) {
                    untrackOwnedSocket(socket);
                    closeQuietly(socket);
                    Slog.w(TAG, "replay-control request queue is full");
                } catch (SecurityException | IOException e) {
                    untrackOwnedSocket(socket);
                    closeQuietly(socket);
                    Slog.w(TAG, "rejected Accessibility replay-control peer");
                }
            }
        } catch (IOException e) {
            if (mRunning && mReplayControlRequests == replayControlRequests) {
                Slog.e(TAG, "Accessibility replay-control socket stopped", e);
            }
        } finally {
            clearPublishedServerIfSame(publishedServer, true);
            stopDirectBackendIfCurrent(requests, replayControlRequests);
        }
    }

    /**
     * Publishes a listener only while both executors still identify this bind generation.
     *
     * <p>Android may reconnect the Accessibility service while an old accept thread is still
     * unwinding. Without this generation check, that old thread can overwrite the new
     * generation's server field with a soon-to-close socket. A later unbind would then fail to
     * close the live abstract socket.
     */
    private boolean publishServerIfCurrent(
            LocalServerSocket server,
            boolean replayControl,
            ThreadPoolExecutor requests,
            ThreadPoolExecutor replayControlRequests,
            long authorizationGeneration) {
        synchronized (mLifecycleLock) {
            if (!mRunning
                    || mRequests != requests
                    || mReplayControlRequests != replayControlRequests
                    || !mAuthorization.isCurrent(authorizationGeneration)) {
                return false;
            }
            if (replayControl) {
                mReplayControlServer = server;
            } else {
                mServer = server;
            }
            return true;
        }
    }

    private void clearPublishedServerIfSame(
            LocalServerSocket server, boolean replayControl) {
        synchronized (mLifecycleLock) {
            if (replayControl) {
                if (mReplayControlServer == server) {
                    mReplayControlServer = null;
                }
            } else if (mServer == server) {
                mServer = null;
            }
        }
    }

    private void handleOwnedReplayControlSocket(
            LocalSocket socket, AgentDescriptorRegistry.ReplayControlPeer peerIdentity,
            long authorizationGeneration) {
        try (LocalSocket owned = socket) {
            if (!authorizationUsableOrStop(authorizationGeneration)) {
                throw new SecurityException("accessibility_authorization_revoked");
            }
            AccessibilityReplayControlHandler.AuthenticatedRole role =
                    replayControlRole(peerIdentity);
            AccessibilityReplayLedger ledger = mReplayLedger;
            if (ledger == null) {
                throw new SecurityException("replay_ledger_unavailable");
            }
            AccessibilityReplayControlHandler handler =
                    new AccessibilityReplayControlHandler(
                            peerIdentity.descriptor(), ledger);
            byte[] response =
                    handler.handleSingleFrame(
                            peerIdentity.descriptor(), role, owned.getInputStream(), () -> {
                                if (!authorizationUsableOrStop(authorizationGeneration)) {
                                    throw new SecurityException(
                                            "accessibility_authorization_revoked");
                                }
                            });
            OutputStream output = owned.getOutputStream();
            output.write(response);
            output.flush();
        } catch (AccessibilityReplayControlHandler.ControlException
                | IOException
                | RuntimeException e) {
            // The fixed helper treats close as a terminal HOLD. Do not expose parser/store detail
            // through the ordinary model-facing Accessibility protocol.
            Slog.w(TAG, "Accessibility replay-control exchange rejected");
        } finally {
            untrackOwnedSocket(socket);
        }
    }

    private static AccessibilityReplayControlHandler.AuthenticatedRole replayControlRole(
            AgentDescriptorRegistry.ReplayControlPeer peerIdentity) {
        if (peerIdentity == null
                || peerIdentity.endpoint()
                        != AgentDescriptorRegistry.ReplayControlEndpoint.ACCESSIBILITY) {
            throw new SecurityException("replay_control_endpoint_denied");
        }
        AgentDescriptorRegistry.ReplayControlRole role = peerIdentity.role();
        if (role == AgentDescriptorRegistry.ReplayControlRole.ADAPTER) {
            return AccessibilityReplayControlHandler.AuthenticatedRole.ADAPTER;
        }
        if (role == AgentDescriptorRegistry.ReplayControlRole.REPLAY_SYNC) {
            return AccessibilityReplayControlHandler.AuthenticatedRole.REPLAY_SYNC;
        }
        throw new SecurityException("replay_control_role_denied");
    }

    private void handleOwnedSocket(LocalSocket socket, AgentDescriptor peerIdentity,
            long authorizationGeneration) {
        try (LocalSocket owned = socket) {
            String requestId = "invalid";
            AccessibilityProtocol.Request request = null;
            byte[] response;
            try {
                if (!authorizationUsableOrStop(authorizationGeneration)) {
                    throw new SecurityException("accessibility_authorization_revoked");
                }
                request = AccessibilityProtocol.parseRequest(
                        peerIdentity,
                        AccessibilityProtocol.readFrame(owned.getInputStream()));
                requestId = request.requestId;
                response = executeWithReplay(request, authorizationGeneration);
            } catch (AccessibilityProtocol.ProtocolException e) {
                response = encodeResponse(errorResponse(requestId, e.code), requestId);
            } catch (IOException e) {
                response = encodeResponse(
                        errorResponse(requestId, "request_io_failed"), requestId);
            } catch (RuntimeException e) {
                Slog.e(TAG, "direct Accessibility request failed", e);
                boolean snapshotRequest = request != null
                        && "snapshot".equals(request.action.type);
                JSONObject error = snapshotRequest
                        ? snapshotErrorResponse(
                                requestId, request.action.snapshotMode, "internal_error")
                        : errorResponse(requestId, "internal_error");
                if (snapshotRequest) {
                    put(error, "replay_scope", AccessibilityReplayPolicy.READ_ONLY_REPLAY_SCOPE);
                }
                response = encodeResponse(error, requestId);
            }
            writeResponse(owned.getOutputStream(), response);
        } catch (IOException e) {
            // Effect results stay in mReplayLedger, so retries cannot repeat the effect. A
            // snapshot has no UI effect and intentionally re-samples current state on retry.
            Slog.w(TAG, "direct Accessibility response failed");
        } finally {
            untrackOwnedSocket(socket);
        }
    }

    private boolean trackSocketIfCurrent(
            LocalSocket socket,
            ThreadPoolExecutor requests,
            ThreadPoolExecutor replayControlRequests,
            long authorizationGeneration) {
        synchronized (mLifecycleLock) {
            return mRunning
                    && mRequests == requests
                    && mReplayControlRequests == replayControlRequests
                    && mAuthorization.isCurrent(authorizationGeneration)
                    && socket != null
                    && mOwnedSockets.add(socket);
        }
    }

    private void untrackOwnedSocket(LocalSocket socket) {
        synchronized (mLifecycleLock) {
            mOwnedSockets.remove(socket);
        }
    }

    private void closeOwnedSocketsLocked() {
        for (LocalSocket socket : mOwnedSockets) {
            closeQuietly(socket);
        }
        mOwnedSockets.clear();
    }

    private byte[] executeWithReplay(
            AccessibilityProtocol.Request request, long authorizationGeneration) {
        if (!AccessibilityReplayPolicy.requiresDurableReplay(request.action.type)) {
            // Snapshot is a read-only observation. A retry intentionally samples current UI
            // state again, so it must not consume the finite lifetime effect ledger.
            return executeReadOnly(request, authorizationGeneration);
        }
        try {
            if (AccessibilityOperationId.parse(request.requestId) == null) {
                return encodeResponse(
                        errorResponse(request.requestId, "operation_epoch_required"),
                        request.requestId);
            }
        } catch (IllegalArgumentException e) {
            return encodeResponse(
                    errorResponse(request.requestId, "invalid_operation_id"),
                    request.requestId);
        }
        AccessibilityReplayLedger ledger = mReplayLedger;
        if (ledger == null) {
            return encodeResponse(
                    errorResponse(request.requestId,
                            AccessibilityReplayLedger.ERROR_LEDGER_UNAVAILABLE),
                    request.requestId);
        }
        try {
            return ledger.executeClassified(
                    request.peerIdentity,
                    request.requestId,
                    request.canonicalIdentity(),
                    MAX_EFFECT_RESPONSE_BYTES,
                    () -> {
                        JSONObject response;
                        try {
                            response = execute(request, authorizationGeneration);
                        } catch (RuntimeException e) {
                            Slog.e(TAG, "direct Accessibility effect failed", e);
                            response = errorResponse(request.requestId, "internal_error");
                            put(response, "effect_outcome",
                                    AccessibilityGestureOutcome
                                            .EFFECT_OUTCOME_INDETERMINATE);
                        }
                        byte[] encoded = encodeResponse(response, request.requestId);
                        return effectOutcomeIsIndeterminate(response)
                                ? AccessibilityReplayLedger.CommittedResult
                                        .indeterminate(encoded)
                                : AccessibilityReplayLedger.CommittedResult.committed(encoded);
                    });
        } catch (AccessibilityReplayLedger.ReplayException e) {
            return encodeResponse(errorResponse(request.requestId, e.code), request.requestId);
        }
    }

    private byte[] executeReadOnly(
            AccessibilityProtocol.Request request, long authorizationGeneration) {
        JSONObject response;
        try {
            response = execute(request, authorizationGeneration);
        } catch (RuntimeException e) {
            Slog.e(TAG, "direct Accessibility read-only observation failed", e);
            response = "snapshot".equals(request.action.type)
                    ? snapshotErrorResponse(
                            request.requestId, request.action.snapshotMode, "internal_error")
                    : errorResponse(request.requestId, "internal_error");
        }
        put(response, "replay_scope", AccessibilityReplayPolicy.READ_ONLY_REPLAY_SCOPE);
        return encodeResponse(response, request.requestId);
    }

    private JSONObject execute(
            AccessibilityProtocol.Request request, long authorizationGeneration) {
        AccessibilityProtocol.Action action = request.action;
        if (!authorizationUsableOrStop(authorizationGeneration)) {
            return "snapshot".equals(action.type)
                    ? snapshotErrorResponse(request.requestId, action.snapshotMode,
                            "accessibility_authorization_revoked")
                    : errorResponse(request.requestId, "accessibility_authorization_revoked");
        }
        if ("snapshot".equals(action.type)) {
            return executeSnapshot(request.requestId, action.windowId, action.snapshotMode,
                    authorizationGeneration);
        }
        if ("batch".equals(action.type)) {
            return executeBatch(request.requestId, action.actions, authorizationGeneration);
        }
        OperationResult result = executePrimitive(action, authorizationGeneration);
        return operationResponse(request.requestId, action.type, result);
    }

    private JSONObject executeSnapshot(String requestId, Integer requestedWindowId,
            String snapshotMode, long authorizationGeneration) {
        for (int attempt = 0; attempt < 2; attempt++) {
            if (!authorizationUsableOrStop(authorizationGeneration)) {
                return snapshotErrorResponse(requestId, snapshotMode,
                        "accessibility_authorization_revoked");
            }
            long startEpoch = mUiEpoch.get();
            long generation = mGeneration.incrementAndGet();
            AccessibilityNodeInfo root = null;
            try {
                root = obtainRoot(requestedWindowId);
                if (root == null) {
                    return snapshotErrorResponse(requestId, snapshotMode,
                            requestedWindowId == null ? "no_active_window" : "window_not_found");
                }
                int windowId = root.getWindowId();
                SnapshotState state = new SnapshotState(generation, windowId);
                JSONObject tree = encodeNode(root, "r", 0, state, snapshotMode, false);
                if (tree == null) {
                    return snapshotErrorResponse(requestId, snapshotMode, "snapshot_empty");
                }
                long endEpoch = mUiEpoch.get();
                if (startEpoch != endEpoch) {
                    continue;
                }
                if (!authorizationUsableOrStop(authorizationGeneration)) {
                    return snapshotErrorResponse(requestId, snapshotMode,
                            "accessibility_authorization_revoked");
                }
                mPublishedGeneration = generation;
                mPublishedEpoch = startEpoch;

                JSONObject response = baseResponse(requestId, true);
                put(response, "action", "snapshot");
                put(response, "snapshot_mode", snapshotMode);
                put(response, "generation", generation);
                put(response, "window_id", windowId);
                put(response, "truncated", state.truncated);
                put(response, "root", tree);
                return response;
            } catch (RuntimeException e) {
                if (startEpoch != mUiEpoch.get()) {
                    continue;
                }
                Slog.w(TAG, "snapshot failed without a tree event", e);
                return snapshotErrorResponse(requestId, snapshotMode, "snapshot_failed");
            } finally {
                recycle(root);
            }
        }
        return snapshotErrorResponse(requestId, snapshotMode, "ui_changed");
    }

    private JSONObject executeBatch(String requestId, List<AccessibilityProtocol.Action> actions,
            long authorizationGeneration) {
        JSONArray results = new JSONArray();
        int completed = 0;
        for (int i = 0; i < actions.size(); i++) {
            AccessibilityProtocol.Action action = actions.get(i);
            OperationResult result = executePrimitive(action, authorizationGeneration);
            JSONObject item = new JSONObject();
            put(item, "index", i);
            put(item, "action", action.type);
            put(item, "ok", result.ok);
            if (!result.ok) {
                put(item, "error", result.error);
            }
            results.put(item);
            if (!result.ok) {
                JSONObject response = errorResponse(requestId, "batch_action_failed");
                put(response, "action", "batch");
                put(response, "atomic", false);
                put(response, "replay_scope", "whole_request");
                put(response, "failed_index", i);
                put(response, "completed", completed);
                put(response, "failed_action_effect", "indeterminate");
                put(response, "remaining_not_attempted", actions.size() - i - 1);
                put(response, "results", results);
                return response;
            }
            completed++;
        }
        JSONObject response = baseResponse(requestId, true);
        put(response, "action", "batch");
        put(response, "atomic", false);
        put(response, "replay_scope", "whole_request");
        put(response, "completed", completed);
        put(response, "results", results);
        return response;
    }

    private OperationResult executePrimitive(
            AccessibilityProtocol.Action action, long authorizationGeneration) {
        try {
            switch (action.type) {
                case "click":
                    return performNodeAction(action.nodeId, AccessibilityNodeInfo.ACTION_CLICK,
                            null, authorizationGeneration);
                case "set_text": {
                    Bundle arguments = new Bundle();
                    arguments.putCharSequence(
                            AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                            action.text);
                    return performNodeAction(
                            action.nodeId, AccessibilityNodeInfo.ACTION_SET_TEXT, arguments,
                            authorizationGeneration);
                }
                case "scroll":
                    return performNodeAction(action.nodeId, scrollAction(action.direction), null,
                            authorizationGeneration);
                case "global_action":
                    if (!authorizationUsableOrStop(authorizationGeneration)) {
                        return OperationResult.error("accessibility_authorization_revoked");
                    }
                    return OperationResult.of(performGlobalAction(globalAction(action.globalAction)),
                            "global_action_failed");
                case "gesture":
                    return performGesture(
                            action.points, action.durationMs, authorizationGeneration);
                default:
                    return OperationResult.error("unsupported_action");
            }
        } catch (BackendException e) {
            return OperationResult.error(e.code);
        } catch (SecurityException e) {
            return OperationResult.error("operation_denied");
        } catch (RuntimeException e) {
            Slog.w(TAG, "Accessibility primitive failed: " + action.type, e);
            return OperationResult.error("operation_failed");
        }
    }

    private OperationResult performNodeAction(String id, int action, Bundle arguments,
            long authorizationGeneration)
            throws BackendException {
        long expectedEpoch = mPublishedEpoch;
        AccessibilityNodeInfo node = resolveNode(id, expectedEpoch);
        try {
            assertFresh(expectedEpoch);
            if (!authorizationUsableOrStop(authorizationGeneration)) {
                return OperationResult.error("accessibility_authorization_revoked");
            }
            boolean succeeded = arguments == null
                    ? node.performAction(action)
                    : node.performAction(action, arguments);
            return OperationResult.of(succeeded, "node_action_failed");
        } finally {
            recycle(node);
        }
    }

    private OperationResult performGesture(List<AccessibilityProtocol.Point> points,
            long durationMs, long authorizationGeneration) {
        Path path = new Path();
        AccessibilityProtocol.Point first = points.get(0);
        path.moveTo(first.x, first.y);
        if (points.size() == 1) {
            path.lineTo(first.x, first.y);
        } else {
            for (int i = 1; i < points.size(); i++) {
                AccessibilityProtocol.Point point = points.get(i);
                path.lineTo(point.x, point.y);
            }
        }

        GestureDescription description;
        try {
            description = new GestureDescription.Builder()
                    .addStroke(new GestureDescription.StrokeDescription(path, 0, durationMs))
                    .build();
        } catch (IllegalArgumentException e) {
            return OperationResult.error("invalid_gesture");
        }

        AccessibilityGestureOutcome outcome = new AccessibilityGestureOutcome();
        if (!authorizationUsableOrStop(authorizationGeneration)) {
            return OperationResult.error("accessibility_authorization_revoked");
        }
        boolean dispatched = dispatchGesture(description, new GestureResultCallback() {
            @Override
            public void onCompleted(GestureDescription gestureDescription) {
                outcome.onCompleted();
            }

            @Override
            public void onCancelled(GestureDescription gestureDescription) {
                outcome.onCancelled();
            }
        }, mMainHandler);
        if (!dispatched) {
            return OperationResult.error("gesture_dispatch_failed");
        }
        try {
            return OperationResult.fromGesture(
                    outcome.await(durationMs + GESTURE_CALLBACK_GRACE_MS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return OperationResult.fromGesture(outcome.interrupted());
        }
    }

    private AccessibilityNodeInfo resolveNode(String id, long expectedEpoch)
            throws BackendException {
        NodeRef ref = NodeRef.parse(id);
        if (ref.generation != mPublishedGeneration
                || expectedEpoch == 0
                || expectedEpoch != mUiEpoch.get()) {
            throw new BackendException("stale_node");
        }
        AccessibilityNodeInfo current = obtainRoot(ref.windowId);
        if (current == null) {
            throw new BackendException("stale_node");
        }
        try {
            for (int childIndex : ref.path) {
                if (childIndex < 0 || childIndex >= current.getChildCount()) {
                    throw new BackendException("stale_node");
                }
                AccessibilityNodeInfo child = current.getChild(childIndex);
                if (child == null) {
                    throw new BackendException("stale_node");
                }
                recycle(current);
                current = child;
            }
            assertFresh(expectedEpoch);
            AccessibilityNodeInfo resolved = current;
            current = null;
            return resolved;
        } finally {
            recycle(current);
        }
    }

    private void assertFresh(long expectedEpoch) throws BackendException {
        if (expectedEpoch == 0
                || expectedEpoch != mPublishedEpoch
                || expectedEpoch != mUiEpoch.get()) {
            throw new BackendException("stale_node");
        }
    }

    private AccessibilityNodeInfo obtainRoot(Integer requestedWindowId) {
        if (requestedWindowId == null) {
            return getRootInActiveWindow();
        }
        return obtainRoot(requestedWindowId.intValue());
    }

    private AccessibilityNodeInfo obtainRoot(int windowId) {
        if (windowId < 0) {
            return getRootInActiveWindow();
        }
        List<AccessibilityWindowInfo> windows = getWindows();
        if (windows == null) {
            return null;
        }
        AccessibilityNodeInfo root = null;
        for (AccessibilityWindowInfo window : windows) {
            try {
                if (root == null && window != null && window.getId() == windowId) {
                    root = window.getRoot();
                }
            } finally {
                recycle(window);
            }
        }
        return root;
    }

    private JSONObject encodeNode(AccessibilityNodeInfo node, String path, int depth,
            SnapshotState state, String snapshotMode, boolean passwordAncestor) {
        if (state.remaining == 0) {
            state.truncated = true;
            return null;
        }
        state.remaining--;
        String nodeId = "g" + state.generation + ":w" + state.windowId + ":" + path;
        JSONObject encoded = new JSONObject();
        put(encoded, "node_id", nodeId);
        put(encoded, "window_id", state.windowId);
        put(encoded, "class_name", AccessibilitySnapshotRedaction.boundedText(
                node.getClassName()));
        put(encoded, "package", AccessibilitySnapshotRedaction.boundedText(
                node.getPackageName()));
        put(encoded, "view_id", AccessibilitySnapshotRedaction.boundedText(
                node.getViewIdResourceName()));
        boolean password = node.isPassword();
        boolean passwordSubtree = passwordAncestor || password;
        // The helper decides redaction before invoking either getter, so protected values never
        // materialize as Strings in metadata-only mode or anywhere below a password node.
        put(encoded, "text", AccessibilitySnapshotRedaction.visibleBoundedValue(
                snapshotMode, passwordSubtree, node::getText));
        put(encoded, "content_description", AccessibilitySnapshotRedaction.visibleBoundedValue(
                snapshotMode, passwordSubtree, node::getContentDescription));
        put(encoded, "clickable", node.isClickable());
        put(encoded, "editable", node.isEditable());
        put(encoded, "scrollable", node.isScrollable());
        put(encoded, "enabled", node.isEnabled());
        put(encoded, "focused", node.isFocused());
        put(encoded, "selected", node.isSelected());
        put(encoded, "password", password);

        Rect bounds = new Rect();
        node.getBoundsInScreen(bounds);
        JSONObject encodedBounds = new JSONObject();
        put(encodedBounds, "left", bounds.left);
        put(encodedBounds, "top", bounds.top);
        put(encodedBounds, "right", bounds.right);
        put(encodedBounds, "bottom", bounds.bottom);
        put(encoded, "bounds", encodedBounds);

        JSONArray actions = new JSONArray();
        if (node.isClickable()) {
            actions.put("click");
        }
        if (node.isEditable()) {
            actions.put("set_text");
        }
        if (node.isScrollable()) {
            actions.put("scroll");
        }
        put(encoded, "actions", actions);

        JSONArray children = new JSONArray();
        int childCount = node.getChildCount();
        if (depth >= MAX_SNAPSHOT_DEPTH && childCount > 0) {
            state.truncated = true;
        } else {
            for (int i = 0; i < childCount; i++) {
                if (state.remaining == 0) {
                    state.truncated = true;
                    break;
                }
                AccessibilityNodeInfo child = node.getChild(i);
                if (child == null) {
                    continue;
                }
                try {
                    String childPath = "r".equals(path) ? Integer.toString(i) : path + "." + i;
                    JSONObject encodedChild = encodeNode(
                            child, childPath, depth + 1, state, snapshotMode,
                            passwordAncestor || password);
                    if (encodedChild != null) {
                        children.put(encodedChild);
                    }
                } finally {
                    recycle(child);
                }
            }
        }
        put(encoded, "children", children);
        return encoded;
    }

    private byte[] encodeResponse(JSONObject response, String requestId) {
        byte[] bytes = response.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > AccessibilityProtocol.MAX_RESPONSE_BYTES) {
            mPublishedGeneration = 0;
            mPublishedEpoch = 0;
            String snapshotMode = snapshotModeFromResponse(response);
            JSONObject bounded = snapshotMode == null
                    ? errorResponse(requestId, "response_too_large")
                    : snapshotErrorResponse(requestId, snapshotMode, "response_too_large");
            if (snapshotMode != null) {
                put(bounded, "replay_scope", AccessibilityReplayPolicy.READ_ONLY_REPLAY_SCOPE);
            }
            bytes = bounded.toString().getBytes(StandardCharsets.UTF_8);
        }
        if (bytes.length == 0 || bytes.length > AccessibilityProtocol.MAX_RESPONSE_BYTES) {
            throw new IllegalStateException("could not encode a bounded Accessibility response");
        }
        return bytes;
    }

    private static void writeResponse(OutputStream output, byte[] bytes) throws IOException {
        output.write(bytes);
        output.write('\n');
        output.flush();
    }

    private static JSONObject operationResponse(String requestId, String action,
            OperationResult result) {
        JSONObject response = baseResponse(requestId, result.ok);
        put(response, "action", action);
        if (!result.ok) {
            put(response, "error", result.error);
            if (result.effectOutcome != null) {
                put(response, "effect_outcome", result.effectOutcome);
            }
        }
        return response;
    }

    private static JSONObject errorResponse(String requestId, String error) {
        JSONObject response = baseResponse(validRequestId(requestId) ? requestId : "invalid", false);
        put(response, "error", error);
        return response;
    }

    private static boolean effectOutcomeIsIndeterminate(JSONObject response) {
        return AccessibilityGestureOutcome.EFFECT_OUTCOME_INDETERMINATE.equals(
                response.opt("effect_outcome"))
                || AccessibilityGestureOutcome.EFFECT_OUTCOME_INDETERMINATE.equals(
                        response.opt("failed_action_effect"));
    }

    private static JSONObject snapshotErrorResponse(String requestId, String snapshotMode,
            String error) {
        JSONObject response = errorResponse(requestId, error);
        put(response, "action", "snapshot");
        put(response, "snapshot_mode", snapshotMode);
        return response;
    }

    private static String snapshotModeFromResponse(JSONObject response) {
        Object value = response.opt("snapshot_mode");
        if (AccessibilityProtocol.SNAPSHOT_MODE_METADATA_ONLY.equals(value)) {
            return AccessibilityProtocol.SNAPSHOT_MODE_METADATA_ONLY;
        }
        if (AccessibilityProtocol.SNAPSHOT_MODE_FULL_TEXT.equals(value)) {
            return AccessibilityProtocol.SNAPSHOT_MODE_FULL_TEXT;
        }
        return null;
    }

    private static JSONObject baseResponse(String requestId, boolean ok) {
        JSONObject response = new JSONObject();
        put(response, "protocol", AccessibilityProtocol.PROTOCOL);
        put(response, "request_id", requestId);
        put(response, "ok", ok);
        put(response, "backend", BACKEND);
        put(response, "idempotency_capacity_entries_per_peer",
                MAX_REPLAY_ENTRIES_PER_PEER);
        put(response, "idempotency_capacity_reserved_bytes_per_peer",
                MAX_REPLAY_RESERVED_BYTES_PER_PEER);
        put(response, "idempotency_reclamation_status",
                AccessibilityReplayLedger.ACK_RECLAMATION_STATUS);
        return response;
    }

    private static void put(JSONObject object, String name, Object value) {
        try {
            object.put(name, value);
        } catch (JSONException e) {
            throw new IllegalStateException("failed to encode response", e);
        }
    }

    private static boolean validRequestId(String value) {
        return AccessibilityRequestId.isValid(value);
    }

    private static int scrollAction(String direction) {
        switch (direction) {
            case "forward":
                return AccessibilityNodeInfo.ACTION_SCROLL_FORWARD;
            case "backward":
                return AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD;
            case "up":
                return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_UP.getId();
            case "down":
                return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_DOWN.getId();
            case "left":
                return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_LEFT.getId();
            case "right":
                return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_RIGHT.getId();
            default:
                throw new IllegalArgumentException("unsupported scroll direction");
        }
    }

    private static int globalAction(String action) {
        switch (action) {
            case "back":
                return GLOBAL_ACTION_BACK;
            case "home":
                return GLOBAL_ACTION_HOME;
            case "recents":
                return GLOBAL_ACTION_RECENTS;
            case "notifications":
                return GLOBAL_ACTION_NOTIFICATIONS;
            case "quick_settings":
                return GLOBAL_ACTION_QUICK_SETTINGS;
            case "power_dialog":
                return GLOBAL_ACTION_POWER_DIALOG;
            case "lock_screen":
                return GLOBAL_ACTION_LOCK_SCREEN;
            case "take_screenshot":
                return GLOBAL_ACTION_TAKE_SCREENSHOT;
            default:
                throw new IllegalArgumentException("unsupported global action");
        }
    }

    private void invalidateTree() {
        mUiEpoch.incrementAndGet();
    }

    private static void closeQuietly(LocalSocket socket) {
        if (socket == null) {
            return;
        }
        try {
            socket.close();
        } catch (IOException ignored) {
            // The peer is already rejected; there is no recovery action.
        }
    }

    private static void closeQuietly(LocalServerSocket socket) {
        if (socket == null) {
            return;
        }
        try {
            socket.close();
        } catch (IOException ignored) {
            // Another listener has already initiated fail-closed backend teardown.
        }
    }

    @SuppressWarnings("deprecation")
    private static void recycle(AccessibilityNodeInfo node) {
        if (node != null) {
            node.recycle();
        }
    }

    @SuppressWarnings("deprecation")
    private static void recycle(AccessibilityWindowInfo window) {
        if (window != null) {
            window.recycle();
        }
    }

    private static final class SnapshotState {
        final long generation;
        final int windowId;
        int remaining = MAX_SNAPSHOT_NODES;
        boolean truncated;

        SnapshotState(long generation, int windowId) {
            this.generation = generation;
            this.windowId = windowId;
        }
    }

    private static final class NodeRef {
        final long generation;
        final int windowId;
        final int[] path;

        NodeRef(long generation, int windowId, int[] path) {
            this.generation = generation;
            this.windowId = windowId;
            this.path = path;
        }

        static NodeRef parse(String value) throws BackendException {
            try {
                if (value == null || !value.startsWith("g")) {
                    throw new NumberFormatException();
                }
                int windowMarker = value.indexOf(":w", 1);
                int pathMarker = value.indexOf(':', windowMarker + 2);
                if (windowMarker < 2 || pathMarker < windowMarker + 3) {
                    throw new NumberFormatException();
                }
                long generation = Long.parseLong(value.substring(1, windowMarker));
                int windowId = Integer.parseInt(value.substring(windowMarker + 2, pathMarker));
                if (generation <= 0 || windowId < -1) {
                    throw new NumberFormatException();
                }
                String encodedPath = value.substring(pathMarker + 1);
                if ("r".equals(encodedPath)) {
                    return new NodeRef(generation, windowId, new int[0]);
                }
                String[] components = encodedPath.split("\\.", -1);
                if (components.length == 0 || components.length > MAX_SNAPSHOT_DEPTH) {
                    throw new NumberFormatException();
                }
                int[] path = new int[components.length];
                for (int i = 0; i < components.length; i++) {
                    path[i] = Integer.parseInt(components[i]);
                    if (path[i] < 0 || path[i] > MAX_SNAPSHOT_NODES) {
                        throw new NumberFormatException();
                    }
                }
                return new NodeRef(generation, windowId, path);
            } catch (NumberFormatException | IndexOutOfBoundsException e) {
                throw new BackendException("invalid_node_id");
            }
        }
    }

    private static final class OperationResult {
        final boolean ok;
        final String error;
        final String effectOutcome;

        OperationResult(boolean ok, String error, String effectOutcome) {
            this.ok = ok;
            this.error = error;
            this.effectOutcome = effectOutcome;
        }

        static OperationResult of(boolean ok, String error) {
            return ok ? new OperationResult(true, null, null) : error(error);
        }

        static OperationResult error(String error) {
            return new OperationResult(false, error, null);
        }

        static OperationResult fromGesture(AccessibilityGestureOutcome.Result result) {
            return new OperationResult(result.ok, result.error, result.effectOutcome);
        }
    }

    private static final class BackendException extends Exception {
        final String code;

        BackendException(String code) {
            super(code);
            this.code = code;
        }
    }
}
