"""Real host subprocess cleanup on transport EOF; no Codex/model invocation."""
from pathlib import Path
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time
import types
import unittest

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "tools/owner-open/host-codex-relay/provider_codex_host.py"
spec = importlib.util.spec_from_file_location("emergency_host_relay_fixture", ENTRY)
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class OwnerOpenHostRelayEmergencyDisconnectTest(unittest.TestCase):
    def test_eof_terminates_current_host_round_and_retained_claim_refuses_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            evidence = folder / "evidence"
            (evidence / "claims").mkdir(parents=True, mode=0o700)
            run = folder / "round"
            run.mkdir()
            pid_path = folder / "host-child-pid"
            fake = folder / "finite-host-fixture"
            # This child is not Codex and makes no network/model/phone call.
            fake.write_text("#!" + sys.executable + "\nimport os, pathlib, time\n"
                            + "pathlib.Path(" + repr(str(pid_path)) + ").write_text(str(os.getpid()))\n"
                            + "while True: time.sleep(0.1)\n")
            fake.chmod(0o700)
            args = types.SimpleNamespace(codex=str(fake), cwd=folder, timeout=10,
                                         model="HOST_FIXTURE_ONLY", evidence=evidence)
            peer, server = socket.socketpair()
            source, sink = server.makefile("rb", buffering=0), server.makefile("wb", buffering=0)
            adapter = relay.CodexAdapter(args, source, sink, run)
            errors = []
            turn = {"protocol": relay.PROTOCOL, "kind": "turn.start", "seq": 0,
                    "turn": {"session_id": "s", "profile_id": "p", "task_id": "t",
                             "turn_id": "u", "turn_stream_id": "stream-one",
                             "user_input": "host cancellation fixture"}}
            peer.sendall(json.dumps(turn).encode() + b"\n")
            adapter.receive(expected="turn.start", timeout=1)

            def round_worker():
                try:
                    adapter.completion([])
                except relay.ProviderError as error:
                    errors.append(str(error))

            thread = threading.Thread(target=round_worker)
            thread.start()
            deadline = time.monotonic() + 3
            while not pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(pid_path.exists(), "host fixture process did not start")
            pid = int(pid_path.read_text())
            peer.close()
            thread.join(3)
            self.assertFalse(thread.is_alive(), "EOF stranded current host round")
            self.assertTrue(any("unknown; no redispatch" in error for error in errors), errors)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            status = json.loads((run / "codex-01.status.json").read_text())
            self.assertLess(status["returncode"], 0)
            self.assertTrue(status["relay_no_relaunch_fallback_or_redispatch"])
            self.assertFalse((run / "dispatch-000.json").exists())
            adapter.frames.close()
            adapter.inputs.close()
            source.close()
            sink.close()
            server.close()

            # The accepted semantic identity survives the adapter replacement.
            run2 = folder / "replacement"
            run2.mkdir()
            peer2, server2 = socket.socketpair()
            source2, sink2 = server2.makefile("rb", buffering=0), server2.makefile("wb", buffering=0)
            replacement = relay.CodexAdapter(args, source2, sink2, run2)
            try:
                turn["turn"]["turn_stream_id"] = "stream-two"
                peer2.sendall(json.dumps(turn).encode() + b"\n")
                with self.assertRaisesRegex(relay.ProviderError, "already accepted.*no redispatch"):
                    replacement.receive(expected="turn.start", timeout=1)
                self.assertEqual(len(list((evidence / "claims").iterdir())), 1)
                self.assertFalse((run2 / "codex-01.status.json").exists())
            finally:
                replacement.frames.close()
                replacement.inputs.close()
                source2.close()
                sink2.close()
                peer2.close()
                server2.close()


if __name__ == "__main__":
    unittest.main()
