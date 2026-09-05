from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLIENT = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/client/src"
    / "org/trillionnium/owneropen/OwnerOpenClient.java"
)
FRAME = CLIENT.with_name("OwnerOpenFrame.java")


class OwnerOpenAndroidClientReconnectTest(unittest.TestCase):
    def read(self, path: Path) -> str:
        self.assertTrue(path.is_file(), path)
        return path.read_text(encoding="utf-8")

    def test_reader_owns_socket_and_input_across_executor_boundary(self) -> None:
        source = self.read(CLIENT)
        connect_start = source.index("public void connect() throws IOException")
        connect_end = source.index("public boolean isConnected()", connect_start)
        connect = source[connect_start:connect_end]

        # These locals are assigned while lock is held and are the only values
        # handed to the asynchronous reader.  Referencing the mutable fields in
        # the lambda lets a queued reader observe a later connection's socket.
        self.assertIn("final LocalSocket ownedSocket;", connect)
        self.assertIn("final InputStream ownedInput;", connect)
        self.assertIn("ownedSocket = candidate;", connect)
        self.assertIn("ownedInput = candidateInput;", connect)
        self.assertIn(
            "reader.execute(() -> readLoop(generation, ownedSocket, ownedInput));",
            connect,
        )
        self.assertNotIn("reader.execute(this::readLoop)", connect)
        self.assertNotIn("readLoop(generation, socket, input)", connect)
        self.assertLess(connect.index("ownedSocket = candidate;"), connect.index("reader.execute"))
        self.assertLess(connect.index("ownedInput = candidateInput;"), connect.index("reader.execute"))

    def test_stale_reader_cannot_close_new_generation(self) -> None:
        source = self.read(CLIENT)
        loop_start = source.index("private void readLoop(")
        current_start = source.index("private boolean isCurrentLocked(", loop_start)
        loop = source[loop_start:current_start]
        current = source[current_start:source.index("@Override", current_start)]

        self.assertIn(
            "private void readLoop(long generation, LocalSocket ownedSocket, InputStream ownedInput)",
            loop,
        )
        self.assertIn("while (isCurrent(generation, ownedSocket))", loop)
        self.assertIn("OwnerOpenFrame.readLine(ownedInput)", loop)
        self.assertIn("if (isCurrentLocked(generation, ownedSocket))", loop)
        self.assertIn("closeLocked();", loop)
        self.assertIn("notify = true;", loop)
        self.assertIn("!closed.get()", current)
        self.assertIn("connectionGeneration == generation", current)
        self.assertIn("socket == ownedSocket", current)

    def test_rapid_reconnect_keeps_new_socket_open(self) -> None:
        """Run the client against two gated fake LocalSockets.

        The first reader is deliberately held in readLine after connect() has
        replaced its socket.  Releasing it after the second connect() makes the
        stale-reader cleanup race deterministic: an unguarded finally would
        close the second socket and make this test fail.
        """
        compiler = shutil.which("javac")
        java = shutil.which("java")
        if compiler is None or java is None:
            self.skipTest("a JDK is required for the host reconnect harness")

        socket_address = textwrap.dedent(
            """
            package android.net;

            public final class LocalSocketAddress {
                public enum Namespace { ABSTRACT }

                public LocalSocketAddress(String name, Namespace namespace) {}
            }
            """
        )
        socket = textwrap.dedent(
            r"""
            package android.net;

            import java.io.ByteArrayOutputStream;
            import java.io.IOException;
            import java.io.InputStream;
            import java.io.OutputStream;
            import java.nio.charset.StandardCharsets;
            import java.util.concurrent.CountDownLatch;
            import java.util.concurrent.LinkedBlockingQueue;
            import java.util.concurrent.TimeUnit;

            public final class LocalSocket implements AutoCloseable {
                private static final LinkedBlockingQueue<Endpoint> ENDPOINTS =
                        new LinkedBlockingQueue<>();
                private final Endpoint endpoint;

                public LocalSocket() {
                    endpoint = ENDPOINTS.poll();
                    if (endpoint == null) {
                        throw new IllegalStateException("no fake endpoint installed");
                    }
                }

                public static void install(Endpoint... endpoints) {
                    ENDPOINTS.clear();
                    for (Endpoint endpoint : endpoints) {
                        ENDPOINTS.add(endpoint);
                    }
                }

                public void connect(LocalSocketAddress address) throws IOException {}

                public InputStream getInputStream() throws IOException {
                    return endpoint.input;
                }

                public OutputStream getOutputStream() throws IOException {
                    return endpoint.output;
                }

                @Override
                public void close() throws IOException {
                    endpoint.close();
                }

                public static final class Endpoint {
                    private final GateInputStream input;
                    private final OutputStream output = new ByteArrayOutputStream();
                    private final boolean releaseOnClose;
                    private volatile boolean closed;

                    public Endpoint(boolean releaseOnClose) {
                        this.releaseOnClose = releaseOnClose;
                        this.input = new GateInputStream();
                    }

                    public boolean awaitReaderEntered(long timeout, TimeUnit unit)
                            throws InterruptedException {
                        return input.entered.await(timeout, unit);
                    }

                    public void releaseReader() {
                        input.release.countDown();
                    }

                    public boolean wasClosed() {
                        return closed;
                    }

                    public String written() {
                        return new String(
                                ((ByteArrayOutputStream) output).toByteArray(),
                                StandardCharsets.UTF_8);
                    }

                    private void close() {
                        closed = true;
                        if (releaseOnClose) {
                            input.release.countDown();
                        }
                    }

                    private final class GateInputStream extends InputStream {
                        private final byte[] acknowledgement =
                                "{\"kind\":\"broker.hello.ack\"}\n"
                                        .getBytes(StandardCharsets.UTF_8);
                        private final CountDownLatch entered = new CountDownLatch(1);
                        private final CountDownLatch release = new CountDownLatch(1);
                        private int offset;

                        @Override
                        public int read() throws IOException {
                            byte[] one = new byte[1];
                            int count = read(one, 0, 1);
                            return count < 0 ? -1 : one[0] & 0xff;
                        }

                        @Override
                        public int read(byte[] bytes, int off, int len) throws IOException {
                            if (len == 0) {
                                return 0;
                            }
                            if (offset < acknowledgement.length) {
                                int count = Math.min(len, acknowledgement.length - offset);
                                System.arraycopy(acknowledgement, offset, bytes, off, count);
                                offset += count;
                                return count;
                            }
                            entered.countDown();
                            try {
                                if (!release.await(5, TimeUnit.SECONDS)) {
                                    throw new IOException("reader gate timed out");
                                }
                            } catch (InterruptedException error) {
                                Thread.currentThread().interrupt();
                                throw new IOException("reader gate interrupted", error);
                            }
                            throw new IOException("reader gate released");
                        }
                    }
                }
            }
            """
        )
        harness = textwrap.dedent(
            r"""
            import android.net.LocalSocket;
            import java.util.concurrent.ExecutorService;
            import java.util.concurrent.Executors;
            import java.util.concurrent.Future;
            import java.util.concurrent.TimeUnit;
            import java.util.concurrent.atomic.AtomicInteger;
            import org.trillionnium.owneropen.OwnerOpenClient;

            public final class ReconnectRaceHarness {
                private static void require(boolean value, String message) {
                    if (!value) {
                        throw new AssertionError(message);
                    }
                }

                public static void main(String[] args) throws Exception {
                    LocalSocket.Endpoint first = new LocalSocket.Endpoint(false);
                    LocalSocket.Endpoint second = new LocalSocket.Endpoint(true);
                    LocalSocket.install(first, second);
                    AtomicInteger disconnects = new AtomicInteger();
                    OwnerOpenClient client = new OwnerOpenClient(new OwnerOpenClient.Listener() {
                        @Override
                        public void onFrame(String rawJsonLine) {}

                        @Override
                        public void onDisconnected(String reason) {
                            disconnects.incrementAndGet();
                        }
                    });
                    ExecutorService reconnectExecutor = Executors.newSingleThreadExecutor();
                    try {
                        client.connect();
                        require(first.awaitReaderEntered(5, TimeUnit.SECONDS),
                                "first reader did not reach the gate");
                        client.startTurn("session-1", "task-1", "turn-1", "first");
                        require(first.written().contains(
                                        "\"direction\":\"client_to_host\",\"seq\":0"),
                                "first frame did not start at seq=0");

                        Future<?> reconnect = reconnectExecutor.submit(() -> {
                            client.connect();
                            return null;
                        });
                        reconnect.get(5, TimeUnit.SECONDS);
                        require(client.isConnected(), "second connect did not remain connected");
                        require(!second.wasClosed(), "second socket closed during reconnect");
                        client.cancelTurn("session-1", "turn-1");
                        client.inspectTurn("session-1", "task-1", "turn-1", 0);
                        require(second.written().contains(
                                        "\"direction\":\"client_to_host\",\"seq\":0"),
                                "reconnected frame did not restart at seq=0");
                        require(second.written().contains(
                                        "\"direction\":\"client_to_host\",\"seq\":1"),
                                "second reconnected frame did not advance to seq=1");

                        // Let the old reader unwind only after generation two is installed.
                        first.releaseReader();
                        require(second.awaitReaderEntered(5, TimeUnit.SECONDS),
                                "second reader did not start");
                        require(client.isConnected(), "stale reader disconnected generation two");
                        require(!second.wasClosed(), "stale reader closed generation two");
                        require(disconnects.get() == 0,
                                "stale reader emitted a disconnect callback");
                    } finally {
                        first.releaseReader();
                        second.releaseReader();
                        client.shutdown();
                        reconnectExecutor.shutdownNow();
                    }
                    System.out.println("rapid-reconnect PASS");
                }
            }
            """
        )

        temp_parent = "/run/user/1000" if Path("/run/user/1000").is_dir() else None
        with tempfile.TemporaryDirectory(dir=temp_parent) as directory:
            root = Path(directory)
            (root / "android/net").mkdir(parents=True)
            (root / "android/net/LocalSocketAddress.java").write_text(
                socket_address, encoding="utf-8"
            )
            (root / "android/net/LocalSocket.java").write_text(socket, encoding="utf-8")
            harness_path = root / "ReconnectRaceHarness.java"
            harness_path.write_text(harness, encoding="utf-8")
            classes = root / "classes"
            classes.mkdir()
            compile_result = subprocess.run(
                [
                    compiler,
                    "-d",
                    str(classes),
                    str(root / "android/net/LocalSocketAddress.java"),
                    str(root / "android/net/LocalSocket.java"),
                    str(FRAME),
                    str(CLIENT),
                    str(harness_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [java, "-cp", str(classes), "ReconnectRaceHarness"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            self.assertIn("rapid-reconnect PASS", run_result.stdout)

    def test_frame_wire_boundary_matches_native_total_limit(self) -> None:
        """Run the Java codec at the native ingress' LF-inclusive boundary."""
        compiler = shutil.which("javac")
        java = shutil.which("java")
        if compiler is None or java is None:
            self.skipTest("a JDK is required for the host frame-boundary harness")

        harness = textwrap.dedent(
            r"""
            import java.io.ByteArrayInputStream;
            import java.io.IOException;
            import java.io.InputStream;
            import java.io.OutputStream;
            import java.nio.charset.StandardCharsets;
            import java.util.Collections;
            import org.trillionnium.owneropen.OwnerOpenFrame;

            public final class FrameBoundaryHarness {
                private interface Action {
                    void run() throws Exception;
                }

                private static void require(boolean value, String message) {
                    if (!value) {
                        throw new AssertionError(message);
                    }
                }

                private static void expect(
                        Class<? extends Throwable> expected, Action action) throws Exception {
                    try {
                        action.run();
                    } catch (Throwable error) {
                        if (expected.isInstance(error)) {
                            return;
                        }
                        throw new AssertionError(
                                "expected " + expected.getSimpleName()
                                        + " but got " + error.getClass().getSimpleName(),
                                error);
                    }
                    throw new AssertionError("expected " + expected.getSimpleName());
                }

                private static String ascii(int length) {
                    char[] value = new char[length];
                    java.util.Arrays.fill(value, 'x');
                    return new String(value);
                }

                private static int utf8Length(String value) {
                    return value.getBytes(StandardCharsets.UTF_8).length;
                }

                private static String jsonFrame(int length) {
                    String prefix = "{\"x\":\"";
                    String suffix = "\"}";
                    require(length >= prefix.length() + suffix.length(),
                            "frame length is too small");
                    return prefix + ascii(length - prefix.length() - suffix.length()) + suffix;
                }

                private static final class GeneratedLineInputStream extends InputStream {
                    private final int payloadBytes;
                    private final boolean terminated;
                    private int offset;

                    GeneratedLineInputStream(int payloadBytes, boolean terminated) {
                        this.payloadBytes = payloadBytes;
                        this.terminated = terminated;
                    }

                    @Override
                    public int read() {
                        if (offset < payloadBytes) {
                            offset++;
                            return 'x';
                        }
                        if (terminated && offset == payloadBytes) {
                            offset++;
                            return '\n';
                        }
                        return -1;
                    }
                }

                private static final class CountingOutputStream extends OutputStream {
                    private int bytes;

                    @Override
                    public void write(int value) {
                        bytes++;
                    }

                    @Override
                    public void write(byte[] value, int offset, int length) {
                        bytes += length;
                    }
                }

                public static void main(String[] args) throws Exception {
                    int maximum = OwnerOpenFrame.MAX_LINE_BYTES;
                    String maxMinusOne = ascii(maximum - 1);

                    // Native ReadLine counts LF, so payload MAX-1 is exactly
                    // one accepted MAX-byte wire line.
                    String read = OwnerOpenFrame.readLine(
                            new GeneratedLineInputStream(maximum - 1, true));
                    require(read.length() == maximum - 1,
                            "MAX-1 payload was not accepted by readLine");
                    CountingOutputStream output = new CountingOutputStream();
                    OwnerOpenFrame.writeLine(output, maxMinusOne);
                    require(output.bytes == maximum,
                            "MAX-1 payload did not produce a MAX-byte wire line");

                    // A MAX-byte payload would become MAX+1 bytes after LF.
                    expect(IllegalArgumentException.class,
                            () -> OwnerOpenFrame.writeLine(
                                    new CountingOutputStream(), ascii(maximum)));
                    expect(IOException.class,
                            () -> OwnerOpenFrame.readLine(
                                    new GeneratedLineInputStream(maximum, true)));

                    // Exercise requireEncodedBound through the public broker
                    // envelope at both sides of the same byte boundary.
                    String baseFrame = "{\"x\":\"\"}";
                    String baseRequest = OwnerOpenFrame.brokerRequest(
                            "r", baseFrame, Collections.singletonList("hello"), 1);
                    int envelopeOverhead = utf8Length(baseRequest) - utf8Length(baseFrame);
                    String fittingFrame = jsonFrame(maximum - 1 - envelopeOverhead);
                    String fittingRequest = OwnerOpenFrame.brokerRequest(
                            "r", fittingFrame, Collections.singletonList("hello"), 1);
                    require(utf8Length(fittingRequest) == maximum - 1,
                            "requireEncodedBound rejected the MAX-1 payload envelope");
                    String oversizedFrame = jsonFrame(maximum - envelopeOverhead);
                    expect(IllegalArgumentException.class,
                            () -> OwnerOpenFrame.brokerRequest(
                                    "r", oversizedFrame, Collections.singletonList("hello"), 1));

                    // Keep a direct byte-stream check in the harness so the
                    // exact accepted total is explicit and regression-proof.
                    byte[] exactWire = (maxMinusOne + "\n").getBytes(StandardCharsets.UTF_8);
                    require(exactWire.length == maximum,
                            "MAX-1 payload plus LF is not MAX bytes");
                    require(OwnerOpenFrame.readLine(new ByteArrayInputStream(exactWire))
                                    .length() == maximum - 1,
                            "exact MAX-byte wire line did not round-trip");
                    System.out.println("frame-boundary PASS");
                }
            }
            """
        )

        temp_parent = "/run/user/1000" if Path("/run/user/1000").is_dir() else None
        with tempfile.TemporaryDirectory(dir=temp_parent) as directory:
            root = Path(directory)
            harness_path = root / "FrameBoundaryHarness.java"
            harness_path.write_text(harness, encoding="utf-8")
            classes = root / "classes"
            classes.mkdir()
            compile_result = subprocess.run(
                [compiler, "-d", str(classes), str(FRAME), str(harness_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [java, "-cp", str(classes), "FrameBoundaryHarness"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            self.assertIn("frame-boundary PASS", run_result.stdout)


if __name__ == "__main__":
    unittest.main()
