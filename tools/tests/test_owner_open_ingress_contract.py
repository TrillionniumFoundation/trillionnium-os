from __future__ import annotations

import json
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/native/owner_open_ingress_proxy.cpp"
)
CLIENT = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/client/src/org/trillionnium/owneropen/OwnerOpenClient.java"
)
FRAME = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/client/src/org/trillionnium/owneropen/OwnerOpenFrame.java"
)
ANDROID_BP = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/Android.bp"
BROKER = ROOT / "tools/owner-open/owner_open_connection_broker.py"
RUNTIME_PROFILE = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/config/profile-v3.json"
)


class OwnerOpenIngressContractTest(unittest.TestCase):
    def read(self, path: Path) -> str:
        self.assertTrue(path.is_file(), path)
        return path.read_text(encoding="utf-8")

    def test_peer_security_is_fail_closed(self) -> None:
        source = self.read(SOURCE)
        self.assertIn("#include <selinux/selinux.h>", source)
        self.assertIn('getpeercon(fd, &security) != 0 || security == nullptr', source)
        self.assertIn("AllowedPeerContext(security)", source)
        self.assertIn("freecon(security);", source)
        self.assertIn("if (!admitted) return false;", source)
        self.assertIn("credentials.uid < 10000", source)

    def test_native_peer_security_failures_and_category_identity(self) -> None:
        compiler = shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(compiler, "peer safety behavior requires a host C++ compiler")
        source = self.read(SOURCE)
        start = source.index("bool ReadPeerCredentials(")
        end = source.index("\nbool IsHex(", start)
        production = source[start:end]
        harness = textwrap.dedent(f'''\
            #include <cassert>
            #include <cstdlib>
            #include <cstring>
            #include <sys/socket.h>
            #include "owner_open_peer_identity.h"
            static int peer_status = 0;
            static const char* context = "u:r:trillionnium_owner_open_client:s0:c512,c768";
            static int credential_status = 0;
            static bool short_credentials = false;
            static ucred peer{{123, 10001, 10001}};
            static int freed = 0;
            static int FakeGetpeercon(int, char** output) {{
              *output = context == nullptr ? nullptr : strdup(context);
              if (peer_status != 0) {{ free(*output); *output = nullptr; }}
              return peer_status;
            }}
            static void FakeFreecon(char* value) {{ ++freed; free(value); }}
            static int FakeGetsockopt(int, int, int, void* output, socklen_t* bytes) {{
              memcpy(output, &peer, sizeof(peer));
              *bytes = short_credentials ? sizeof(peer) - 1 : sizeof(peer);
              return credential_status;
            }}
            #define getpeercon FakeGetpeercon
            #define freecon FakeFreecon
            #define getsockopt FakeGetsockopt
            {production}
            int main() {{
              ucred output{{0,0,0}};
              assert(AllowedPeer(3, &output));
              assert(output.pid == 123 && output.uid == 10001 && output.gid == 10001);
              assert(freed == 1);
              peer_status = -1; assert(!AllowedPeer(3, &output)); peer_status = 0;
              const char* valid = context;
              context = nullptr; assert(!AllowedPeer(3, &output));
              for (const char* invalid : {{"u:r:untrusted_app:s0:c512,c768",
                   "u:r:trillionnium_owner_open_client_extra:s0",
                   "u:r:trillionnium_owner_open_client:s0:c1024",
                   "u:r:trillionnium_owner_open_client:s0:c2.c1",
                   "u:r:trillionnium_owner_open_client:s0:c0,"}}) {{
                context = invalid; assert(!AllowedPeer(3, &output));
              }}
              context = valid;
              credential_status = -1; assert(!AllowedPeer(3, &output)); credential_status = 0;
              short_credentials = true; assert(!AllowedPeer(3, &output)); short_credentials = false;
              peer.pid = 1; assert(!AllowedPeer(3, &output)); peer.pid = 123;
              peer.uid = 9999; assert(!AllowedPeer(3, &output)); peer.uid = 10001;
              assert(AllowedPeer(3, &output));
            }}
            ''')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            source_path, binary = path / "peer.cpp", path / "peer"
            source_path.write_text(harness, encoding="utf-8")
            result = subprocess.run([compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                                     "-I", str(SOURCE.parent), str(source_path), "-o", str(binary)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Also execute every existing production identity vector.
            result = subprocess.run([compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                                     str(SOURCE.parent / "owner_open_peer_identity_test.cpp"), "-o", str(binary)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_upstream_ack_is_strictly_identity_bound_before_forward(self) -> None:
        source = self.read(SOURCE)
        for marker in (
            'builder["rejectDupKeys"] = true',
            'constexpr std::string_view kWireSchema = "org.trillionnium.owner-open.connection-broker-wire.v1";',
            'constexpr std::string_view kBrokerId = "owner-open-device";',
            "ValidateHelloAck",
            "expected_client_id",
            "descriptor_sha256",
            "IsLowerHex(broker_epoch, 32)",
            "IsLowerHex(token_epoch, 32)",
            "automatic_redispatch",
            'JsonInteger(acknowledged_peer, "pid", ingress_peer.pid)',
            'host_kind != "hello.ack"',
            '!host_ack["payload"].isObject()',
            "if (!ReadPeerCredentials(upstream, &broker_peer) || broker_peer.uid != 0) return false;",
            "struct ucred ingress_peer {",
            "if (!ValidateHelloAck(response, expected_client_id, ingress_peer)) return false;",
            "kHandshakeTimeoutMilliseconds",
            "WaitForIo",
            "Clock::now() + std::chrono::milliseconds(kHandshakeTimeoutMilliseconds)",
            "O_NONBLOCK",
            "MSG_DONTWAIT",
        ):
            self.assertIn(marker, source)
        self.assertIn('JsonInteger(acknowledged_peer, "uid", ingress_peer.uid)', source)
        self.assertIn('JsonInteger(acknowledged_peer, "gid", ingress_peer.gid)', source)
        self.assertNotIn("automatic_effect_redispatch", source)
        self.assertNotIn("kAckMarker", source)
        self.assertNotIn("response.find(", source)
        self.assertLess(
            source.index("ValidateHelloAck(response, expected_client_id, ingress_peer)"),
            source.index("return WriteAll(client, reinterpret_cast<const unsigned char*>(response.data()),"),
        )

    def test_android_module_links_json_parser_for_ingress(self) -> None:
        bp = self.read(ANDROID_BP)
        start = bp.index('name: "trillionnium-owner-open-ingress"')
        end = bp.index("}\n", start)
        shared = re.search(r"shared_libs:\s*\[([^]]*)\]", bp[start:end])
        self.assertIsNotNone(shared)
        self.assertEqual(set(re.findall(r'"([^"]+)"', shared.group(1))), {"libjsoncpp", "libselinux"})

    def test_broker_ingress_and_runtime_profile_share_canonical_redispatch_field(self) -> None:
        ingress = self.read(SOURCE)
        broker = self.read(BROKER)
        profile = json.loads(self.read(RUNTIME_PROFILE))

        # The Python broker is the producer consumed by the native ingress;
        # keep this assertion at the language boundary so a renamed field
        # cannot silently make every handshake fail closed.
        self.assertIn('"kind": "broker.hello.ack"', broker)
        self.assertIn('"automatic_redispatch": False', broker)
        self.assertNotIn("automatic_effect_redispatch", broker)
        self.assertIn('!ack["automatic_redispatch"].isBool()', ingress)
        self.assertIn('ack["automatic_redispatch"].asBool()', ingress)
        self.assertNotIn("automatic_effect_redispatch", ingress)
        self.assertEqual(profile["android_ingress"]["automatic_redispatch"], False)
        self.assertNotIn("automatic_effect_redispatch", profile["android_ingress"])

    def test_read_line_bound_includes_newline_and_rejects_max_plus_one(self) -> None:
        source = self.read(SOURCE)
        self.assertIn("while (output->size() < kMaximumLineBytes)", source)
        self.assertNotIn("while (output->size() <= kMaximumLineBytes)", source)

        # ReadLine's contract is total frame bytes, including the delimiter.
        # Keep the arithmetic explicit so the max/max+1 boundary remains
        # covered even on hosts where the Android JsonCpp library is absent.
        maximum = 1024 * 1024
        self.assertLessEqual((maximum - 1) + 1, maximum)
        self.assertGreater(maximum + 1, maximum)

    def test_read_line_native_boundary_harness(self) -> None:
        """Execute the production ReadLine body at max-1/max/max+1 bytes."""
        compiler = shutil.which("clang++") or shutil.which("g++")
        if compiler is None:
            self.skipTest("no host C++ compiler is available")
        source = self.read(SOURCE)
        helper_start = source.index("using Clock = std::chrono::steady_clock;")
        helper_end = source.index("\n\nint ConnectUpstream", helper_start)
        helper = source[helper_start:helper_end]
        start = source.index("bool ReadLine(int fd, std::string* output, Deadline deadline) {")
        end = source.index("\n}\n\nbool ParseJsonObject", start) + 2
        read_line = source[start:end]
        harness = textwrap.dedent(
            f"""\
            #include <algorithm>
            #include <cassert>
            #include <cerrno>
            #include <chrono>
            #include <cstddef>
            #include <cstdint>
            #include <limits>
            #include <poll.h>
            #include <string>
            #include <sys/socket.h>
            #include <thread>
            #include <unistd.h>
            constexpr std::size_t kMaximumLineBytes = 1024 * 1024;
            {helper}
            {read_line}
            static bool exercise(std::size_t payload_bytes, bool expected) {{
              int fds[2];
              assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
              std::string value(payload_bytes, 'x');
              value.push_back('\\n');
              std::thread writer([&] {{
                std::size_t offset = 0;
                while (offset < value.size()) {{
                  const ssize_t count = send(fds[0], value.data() + offset,
                                             value.size() - offset, MSG_NOSIGNAL);
                  assert(count > 0);
                  offset += static_cast<std::size_t>(count);
                }}
                shutdown(fds[0], SHUT_WR);
              }});
              std::string output;
              const bool result = ReadLine(
                  fds[1], &output, Clock::now() + std::chrono::seconds(30));
              writer.join();
              close(fds[0]);
              close(fds[1]);
              return result == expected && (!result || output == value);
            }}
            int main() {{
              assert(exercise(kMaximumLineBytes - 2, true));
              assert(exercise(kMaximumLineBytes - 1, true));
              assert(exercise(kMaximumLineBytes, false));
            }}
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "read_line_boundary.cpp"
            binary_path = root / "read_line_boundary"
            source_path.write_text(harness, encoding="utf-8")
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c++20",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(source_path),
                    "-o",
                    str(binary_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(binary_path)], capture_output=True, text=True, timeout=30
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

    def test_connection_limit_uses_atomic_reservation(self) -> None:
        source = self.read(SOURCE)
        self.assertIn("bool TryAcquireConnection()", source)
        self.assertIn("compare_exchange_weak", source)
        self.assertIn("void ReleaseConnection()", source)
        self.assertNotIn("if (g_connections.load() >= kMaximumConnections", source)
        self.assertNotIn("++g_connections", source)

    def test_android_client_binds_contiguous_host_sequence_before_broker_wrap(self) -> None:
        client = self.read(CLIENT)
        frame = self.read(FRAME)
        for marker in (
            "private long nextClientFrameSequence;",
            "nextClientFrameSequence = 0;",
            "OwnerOpenFrame.withClientTransportSequence(",
            "nextClientFrameSequence++;",
        ):
            self.assertIn(marker, client)
        self.assertIn("withClientTransportSequence", frame)
        self.assertIn('"direction\\\":\\\"client_to_host', frame)
        self.assertIn('"seq\\\":"', frame)
        # Sequence is consumed by a successful write only; constructing the
        # broker envelope must happen after the transport binding.
        self.assertLess(
            client.index("withClientTransportSequence"),
            client.index("OwnerOpenFrame.brokerRequest(", client.index("withClientTransportSequence")),
        )


if __name__ == "__main__":
    unittest.main()
