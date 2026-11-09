package org.trillionnium.owneropen;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/** Thin client for the credential-terminating Android owner-open ingress. */
public final class OwnerOpenClient implements AutoCloseable {
    public interface Listener {
        void onFrame(String rawJsonLine);
        void onDisconnected(String reason);
    }

    private static final String SOCKET_NAME = "trillionnium_owner_open";
    private static final ScheduledExecutorService CONTROL_DEADLINES =
            Executors.newSingleThreadScheduledExecutor(task -> {
                Thread thread = new Thread(task, "owner-open-control-deadline");
                thread.setDaemon(true);
                return thread;
            });
    private static final int REQUEST_TIMEOUT_MILLISECONDS = 120_000;

    private final Object lock = new Object();
    private final Listener listener;
    private final ExecutorService reader = Executors.newSingleThreadExecutor();
    private final AtomicLong requestSequence = new AtomicLong(1);
    private final AtomicBoolean locallyInhibited = new AtomicBoolean(false);
    private final AtomicBoolean closed = new AtomicBoolean(true);
    private final String clientInstance = "android-client-" + UUID.randomUUID();
    // The broker requires one contiguous semantic Host-frame sequence per
    // authenticated connection.  This is deliberately separate from the
    // request ID sequence: a reconnect starts a fresh broker Client stream at
    // seq=0, while request IDs remain process-lifetime unique.
    private long nextClientFrameSequence;
    // A reader can still be unwinding after connect() replaces its socket. The
    // generation and socket identity bind cleanup to the connection that
    // created the reader, so an old reader can never close a newer connection.
    private long connectionGeneration;
    private LocalSocket socket;
    private InputStream input;
    private OutputStream output;

    public OwnerOpenClient(Listener listener) {
        this.listener = listener;
    }

    public void connect() throws IOException {
        if (locallyInhibited.get()) throw new IOException("local emergency inhibit; status only");
        final long generation;
        final LocalSocket ownedSocket;
        final InputStream ownedInput;
        synchronized (lock) {
            closeLocked();
            LocalSocket candidate = new LocalSocket();
            try {
                candidate.connect(new LocalSocketAddress(
                        SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT));
                InputStream candidateInput = new BufferedInputStream(candidate.getInputStream());
                OutputStream candidateOutput = new BufferedOutputStream(candidate.getOutputStream());
                candidate.setSoTimeout(5_000);
                OwnerOpenFrame.writeLine(candidateOutput, OwnerOpenFrame.ingressConnect());
                String acknowledgement = OwnerOpenFrame.readLine(candidateInput);
                if (!OwnerOpenFrame.hasKind(acknowledgement, "broker.hello.ack")) {
                    throw new IOException("ingress did not return broker.hello.ack: " + acknowledgement);
                }
                candidate.setSoTimeout(0);
                if (locallyInhibited.get()) throw new IOException("emergency intent fenced connection");
                generation = ++connectionGeneration;
                socket = candidate;
                input = candidateInput;
                output = candidateOutput;
                nextClientFrameSequence = 0;
                ownedSocket = candidate;
                ownedInput = candidateInput;
                closed.set(false);
                listener.onFrame(acknowledgement);
            } catch (IOException | RuntimeException error) {
                if (socket == candidate) {
                    closeLocked();
                } else {
                    try {
                        candidate.close();
                    } catch (IOException ignored) {
                    }
                }
                throw error;
            }
        }
        reader.execute(() -> readLoop(generation, ownedSocket, ownedInput));
    }

    /** Local dispatch fence is set before durable UI intent or network I/O. */
    public void inhibitLocally() { locallyInhibited.set(true); }

    /** Independent finite control socket; no broker/model or normal-operation lock. */
    public String emergencyControl(String operationId, boolean explicitStop) throws IOException {
        if (explicitStop) inhibitLocally();
        String request = OwnerOpenFrame.emergencyControl(operationId, explicitStop);
        try (LocalSocket control = new LocalSocket()) {
            // Materialize the descriptor before scheduling close so the deadline
            // includes connect, write and the entire reply, not each byte read.
            control.getOutputStream(); // LocalSocket.setSoTimeout does not create fd.
            control.setSoTimeout(5_000);
            ScheduledFuture<?> deadline = CONTROL_DEADLINES.schedule(() -> {
                try { control.shutdownInput(); } catch (IOException ignored) { }
                try { control.shutdownOutput(); } catch (IOException ignored) { }
                try { control.close(); } catch (IOException ignored) { }
            }, 5_000, TimeUnit.MILLISECONDS);
            try {
                control.connect(new LocalSocketAddress(SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT));
                OutputStream controlOutput = new BufferedOutputStream(control.getOutputStream());
                OwnerOpenFrame.writeLine(controlOutput, request);
                String reply = OwnerOpenFrame.readLine(
                        new BufferedInputStream(control.getInputStream()), 4096);
                if (!OwnerOpenFrame.hasKind(reply, "emergency.result")) {
                    throw new IOException("invalid emergency control reply; outcome unknown");
                }
                // Never clears the local fence or proves old effects did not occur.
                return reply;
            } finally {
                deadline.cancel(false);
            }
        }
    }

    public boolean isConnected() {
        return !closed.get();
    }

    public String startTurn(String sessionId, String taskId, String turnId, String prompt)
            throws IOException {
        String frame = OwnerOpenFrame.turnStart(sessionId, taskId, turnId, prompt);
        return send(frame, List.of("turn.accepted", "host.error"));
    }

    public String cancelTurn(String sessionId, String turnId) throws IOException {
        String frame = OwnerOpenFrame.turnCancel(sessionId, turnId);
        return send(frame, List.of("turn.cancel.accepted", "host.error"));
    }

    public String inspectTurn(String sessionId, String taskId, String turnId, long cursor)
            throws IOException {
        String frame = OwnerOpenFrame.turnInspect(sessionId, taskId, turnId, cursor, 256);
        return send(frame, List.of("turn.inspect.result", "host.error"));
    }

    public String inspectTurn(String sessionId, String taskId, String turnId,
            String requestSha256, long cursor) throws IOException {
        if (requestSha256 == null) throw new IOException("restored Inspect requires original request digest");
        String frame = OwnerOpenFrame.turnInspect(sessionId, taskId, turnId, requestSha256, cursor, 256);
        return send(frame, List.of("turn.inspect.result", "host.error"));
    }

    /** Correlate the explicit read before its actual wire write, including fast replies. */
    public String inspectTurn(String sessionId, String taskId, String turnId,
            String requestSha256, long cursor, java.util.function.Consumer<String> beforeWrite) throws IOException {
        if (requestSha256 == null || beforeWrite == null) throw new IOException("Inspect binding required");
        String frame = OwnerOpenFrame.turnInspect(sessionId, taskId, turnId, requestSha256, cursor, 256);
        return send(frame, List.of("turn.inspect.result", "host.error"), beforeWrite);
    }

    private String send(String frame, List<String> expectedKinds) throws IOException {
        return send(frame, expectedKinds, ignored -> {});
    }

    private String send(String frame, List<String> expectedKinds,
            java.util.function.Consumer<String> beforeWrite) throws IOException {
        String requestId = clientInstance + ":" + requestSequence.getAndIncrement();
        synchronized (lock) {
            if (locallyInhibited.get()) throw new IOException("local emergency inhibit; no dispatch");
            if (closed.get() || output == null) {
                throw new IOException("owner-open ingress is not connected");
            }
            try {
                String clientFrame = OwnerOpenFrame.withClientTransportSequence(
                        frame, nextClientFrameSequence);
                String request = OwnerOpenFrame.brokerRequest(
                        requestId, clientFrame, expectedKinds, REQUEST_TIMEOUT_MILLISECONDS);
                beforeWrite.accept(requestId);
                OwnerOpenFrame.writeLine(output, request);
                nextClientFrameSequence++;
            } catch (IOException error) {
                closeLocked();
                throw error;
            }
        }
        return requestId;
    }

    private void readLoop(long generation, LocalSocket ownedSocket, InputStream ownedInput) {
        String reason = "owner-open ingress closed";
        try {
            while (isCurrent(generation, ownedSocket)) {
                String frame = OwnerOpenFrame.readLine(ownedInput);
                if (!isCurrent(generation, ownedSocket)) break;
                listener.onFrame(frame);
            }
        } catch (IOException | RuntimeException error) {
            reason = error.toString();
        } finally {
            boolean notify = false;
            synchronized (lock) {
                if (isCurrentLocked(generation, ownedSocket)) {
                    closeLocked();
                    notify = true;
                }
            }
            if (notify) {
                listener.onDisconnected(reason);
            }
        }
    }

    private boolean isCurrent(long generation, LocalSocket ownedSocket) {
        synchronized (lock) {
            return isCurrentLocked(generation, ownedSocket);
        }
    }

    private boolean isCurrentLocked(long generation, LocalSocket ownedSocket) {
        return !closed.get() && connectionGeneration == generation && socket == ownedSocket;
    }

    @Override
    public void close() {
        synchronized (lock) {
            closeLocked();
        }
    }

    public void shutdown() {
        close();
        reader.shutdownNow();
    }

    private void closeLocked() {
        closed.set(true);
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
        socket = null;
        input = null;
        output = null;
        nextClientFrameSequence = 0;
    }
}
