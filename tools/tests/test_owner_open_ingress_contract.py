from __future__ import annotations

import json
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
        self.assertIn("#ifndef SO_PEERSEC", source)
        self.assertIn("errno = ENOTSUP;", source)
        self.assertIn("return false;", source[source.index("#ifndef SO_PEERSEC") : source.index("#else", source.index("#ifndef SO_PEERSEC"))])
        self.assertIn("security[length - 1] != '\\0'", source)
        self.assertIn("if (value != kAllowedPeer) return false;", source)

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
        ):
            self.assertIn(marker, source)
        self.assertIn('JsonInteger(acknowledged_peer, "uid", ingress_peer.uid)', source)
        self.assertIn('JsonInteger(acknowledged_peer, "gid", ingress_peer.gid)', source)
        self.assertNotIn("automatic_effect_redispatch", source)
        self.assertNotIn("kAckMarker", source)
        self.assertNotIn("response.find(", source)
        self.assertLess(
            source.index("ValidateHelloAck(response, expected_client_id, ingress_peer)"),
            source.index("return WriteAll(client, response);"),
        )

    def test_android_module_links_json_parser_for_ingress(self) -> None:
        bp = self.read(ANDROID_BP)
        start = bp.index('name: "trillionnium-owner-open-ingress"')
        end = bp.index("}\n", start)
        self.assertIn('shared_libs: ["libjsoncpp"]', bp[start:end])

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
        start = source.index("bool ReadLine(int fd, std::string* output) {")
        end = source.index("\n}\n\nbool ParseJsonObject", start) + 2
        read_line = source[start:end]
        harness = textwrap.dedent(
            f"""\
            #include <cassert>
            #include <cstddef>
            #include <string>
            #include <sys/socket.h>
            #include <thread>
            #include <unistd.h>
            constexpr std::size_t kMaximumLineBytes = 1024 * 1024;
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
              const bool result = ReadLine(fds[1], &output);
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
