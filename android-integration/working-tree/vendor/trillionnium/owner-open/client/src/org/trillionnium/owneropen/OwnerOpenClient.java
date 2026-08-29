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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/** Thin client for the credential-terminating Android owner-open ingress. */
public final class OwnerOpenClient implements AutoCloseable {
    public interface Listener {
        void onFrame(String rawJsonLine);
        void onDisconnected(String reason);
    }

    private static final String SOCKET_NAME = "trillionnium_owner_open";
    private static final int REQUEST_TIMEOUT_MILLISECONDS = 120_000;

    private final Object lock = new Object();
    private final Listener listener;
    private final ExecutorService reader = Executors.newSingleThreadExecutor();
    private final AtomicLong requestSequence = new AtomicLong(1);
    private final AtomicBoolean closed = new AtomicBoolean(true);
    private final String clientInstance = "android-client-" + UUID.randomUUID();
    private LocalSocket socket;
    private InputStream input;
    private OutputStream output;

    public OwnerOpenClient(Listener listener) {
        this.listener = listener;
    }

    public void connect() throws IOException {
        synchronized (lock) {
            closeLocked();
            LocalSocket candidate = new LocalSocket();
            try {
                candidate.connect(new LocalSocketAddress(
                        SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT));
                InputStream candidateInput = new BufferedInputStream(candidate.getInputStream());
                OutputStream candidateOutput = new BufferedOutputStream(candidate.getOutputStream());
                String acknowledgement = OwnerOpenFrame.readLine(candidateInput);
                if (!OwnerOpenFrame.hasKind(acknowledgement, "broker.hello.ack")) {
                    throw new IOException("ingress did not return broker.hello.ack: " + acknowledgement);
                }
                socket = candidate;
                input = candidateInput;
                output = candidateOutput;
                closed.set(false);
                listener.onFrame(acknowledgement);
            } catch (IOException | RuntimeException error) {
                try {
                    candidate.close();
                } catch (IOException ignored) {
                }
                throw error;
            }
        }
        reader.execute(this::readLoop);
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

    private String send(String frame, List<String> expectedKinds) throws IOException {
        String requestId = clientInstance + ":" + requestSequence.getAndIncrement();
        String request = OwnerOpenFrame.brokerRequest(
                requestId, frame, expectedKinds, REQUEST_TIMEOUT_MILLISECONDS);
        synchronized (lock) {
            if (closed.get() || output == null) {
                throw new IOException("owner-open ingress is not connected");
            }
            try {
                OwnerOpenFrame.writeLine(output, request);
            } catch (IOException error) {
                closeLocked();
                throw error;
            }
        }
        return requestId;
    }

    private void readLoop() {
        String reason = "owner-open ingress closed";
        try {
            while (!closed.get()) {
                InputStream current;
                synchronized (lock) {
                    current = input;
                }
                if (current == null) {
                    break;
                }
                listener.onFrame(OwnerOpenFrame.readLine(current));
            }
        } catch (IOException | RuntimeException error) {
            reason = error.toString();
        } finally {
            synchronized (lock) {
                closeLocked();
            }
            listener.onDisconnected(reason);
        }
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
    }
}
