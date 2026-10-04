"""Real local subprocess bridge tests; the native endpoint is a controlled fake.

These never authenticate, contact a model, execute the supplied command or
assert installed Android/RootLinux/Codex qualification.
"""
from __future__ import annotations

import hashlib
import base64
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "crates/trillionnium-owner-open-provider-jsonl/python/codex_app_server_provider.py"
PROTOCOL = "trillionnium.owner-open.provider-jsonl.v1"
TURN = dict(session_id="session", profile_id="profile", task_id="task",
            turn_id="turn", turn_stream_id="stream", user_input="exact user request")
COMMAND = "printf '%s' '$x; `literal`'; ordinary arbitrary shell text"
NATIVE = '''#!{python}
import json, sys, time
def read():
    return json.loads(sys.stdin.readline())
def send(x):
    print(json.dumps(x),flush=True)
assert read()['method']=='initialize'
send({{'id':1,'result':{{'userAgent':'controlled fake'}}}})
assert read()['method']=='initialized'
thread=read()
assert thread['method'] in ('thread/start','thread/resume')
assert thread['method']=='thread/resume' or thread['params']['environments']==[]
send({{'id':2,'result':{{'thread':{{'id':'native-thread'}}}}}})
turn=read()
assert turn['params']['environments']==[]
assert turn['params']['input'][0]['text']=='exact user request'
send({{'method':'turn/started','params':{{'threadId':'native-thread','turn':{{'id':'native-turn'}}}}}})
send({{'id':3,'result':{{'turn':{{'id':'native-turn'}}}}}})
mode={mode!r}
if mode=='stall':
    time.sleep(60)
elif mode=='wrong-scope':
    send({{'method':'item/agentMessage/delta','params':{{'threadId':'different-thread','turnId':'native-turn','itemId':'message-1','delta':'must not be delivered'}}}})
elif mode=='final-message':
    send({{'method':'item/completed','params':{{'threadId':'native-thread','turnId':'native-turn','item':{{'type':'agentMessage','id':'message-1','text':'complete without deltas'}}}}}})
    send({{'method':'turn/completed','params':{{'threadId':'native-thread','turn':{{'id':'native-turn','status':'completed'}}}}}})
elif mode=='unknown-request':
    send({{'id':99,'method':'item/commandExecution/requestApproval','params':{{}}}})
elif mode in ('tool','tool-large','duplicate'):
    callback={{'id':99,'method':'item/tool/call','params':{{'threadId':'native-thread','turnId':'native-turn','callId':'native-call','tool':'trillionnium_shell_exec','arguments':{{'command':{command!r},'env':{{'X':'$()'}},'stdin':'literal input'}}}}}}
    send(callback)
    result=read()
    outcome=json.loads(result['result']['contentItems'][0]['text'])
    assert outcome['terminal']['kind']=='unknown'
    if mode=='tool-large':
        assert outcome['events']==[] and outcome['events_truncated']==True
        assert outcome['bridge_observation_gap']['output_bytes']==16777216
        assert outcome['terminal']['output_truncated']==False
        assert outcome['observation_sha256']=='a'*64
        assert outcome['generation']==7 and outcome['registry']['call_id']=='native-call'
    if mode=='duplicate':
        send(callback)
        time.sleep(60)
    else:
        send({{'method':'item/agentMessage/delta','params':{{'threadId':'native-thread','turnId':'native-turn','itemId':'message-1','delta':'observed unknown'}}}})
        send({{'method':'item/completed','params':{{'threadId':'native-thread','turnId':'native-turn','item':{{'type':'agentMessage','id':'message-1','text':'observed unknown'}}}}}})
        send({{'method':'turn/completed','params':{{'threadId':'native-thread','turn':{{'id':'native-turn','status':'completed'}}}}}})
else:
    send({{'method':'turn/completed','params':{{'threadId':'native-thread','turn':{{'id':'native-turn','status':mode}}}}}})
time.sleep(60)
'''


class ProviderProcessTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.state = self.directory / "state"
        self.state.mkdir(mode=0o700)
        self.processes = []
        self.home = self.directory / "home"
        self.codex_home = self.directory / "codex-home"
        self.home.mkdir(mode=0o700)
        self.codex_home.mkdir(mode=0o700)

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        self.temporary.cleanup()

    def launch(self, mode):
        native = self.directory / "native"
        native.write_text(NATIVE.format(python=sys.executable, mode=mode, command=COMMAND))
        native.chmod(0o700)
        config = self.directory / "config.json"
        config.write_text(json.dumps(dict(schema="org.trillionnium.owner-open.codex-app-server-config.v1",
            codex_executable=str(native), codex_sha256=hashlib.sha256(native.read_bytes()).hexdigest(),
            dynamic_tool_format="0.144.1-function", state_directory=str(self.state),
            home_directory=str(self.home), codex_home=str(self.codex_home), codex_config_sha256=None)))
        config.chmod(0o600)
        process = subprocess.Popen([sys.executable, str(ADAPTER), "--config", str(config)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=0)
        self.processes.append(process)
        self.send(process, 0, "turn.start", turn=TURN)
        return process

    def send(self, process, seq, kind, **fields):
        process.stdin.write(json.dumps(dict(protocol=PROTOCOL, seq=seq, kind=kind, **fields)).encode()+b"\n")
        process.stdin.flush()

    def receive(self, process):
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=8), "bridge output deadline")
        line = process.stdout.readline()
        if not line:
            self.fail(process.stderr.read().decode())
        return json.loads(line)

    def test_tool_observation_unchanged_and_terminal_after_retirement(self):
        process = self.launch("tool")
        call = self.receive(process)
        self.assertEqual(call["kind"], "tool.call")
        self.assertEqual(call["call"]["command"], COMMAND)
        self.assertEqual(call["call"]["env"], {"X":"$()"})
        self.assertEqual(call["call"]["stdin"], "literal input")
        self.send(process, 1, "tool.result", call_id="native-call", status="terminal",
                  terminal={"kind":"unknown","automatic_redispatch":False})
        delta = self.receive(process)
        terminal = self.receive(process)
        self.assertEqual(delta["text"], "observed unknown")
        self.assertEqual(terminal["kind"], "turn.complete")
        self.assertEqual([call["seq"], delta["seq"], terminal["seq"]], [0,1,2])
        self.assertEqual(process.wait(timeout=5), 0)

    def test_failed_native_turn_is_not_success(self):
        process = self.launch("failed")
        self.assertEqual(self.receive(process)["kind"], "turn.fail")
        self.assertEqual(process.wait(timeout=5), 1)

    def test_default_sixteen_mib_host_output_preserves_terminal_and_explicit_gap(self):
        process = self.launch("tool-large")
        self.assertEqual(self.receive(process)["kind"], "tool.call")
        payload = base64.b64encode(b"x" * (16 * 1024 * 1024)).decode()
        self.send(process, 1, "tool.result", call_id="native-call", status="terminal", generation=7,
            terminal={"kind": "unknown", "output_truncated": False}, observation_sha256="a" * 64,
            registry={"call_id": "native-call"}, events=[{"call_id": "native-call", "seq": 3,
                "event": {"kind": "output", "encoding": "base64", "data": payload,
                          "byte_count": 16 * 1024 * 1024}}])
        self.assertEqual(self.receive(process)["text"], "observed unknown")
        self.assertEqual(self.receive(process)["kind"], "turn.complete")
        self.assertEqual(process.wait(timeout=5), 0)

    def test_final_native_message_without_delta_reaches_host(self):
        process = self.launch("final-message")
        frame = self.receive(process)
        self.assertEqual(frame["event"], "model.message")
        self.assertEqual(frame["text"], "complete without deltas")
        self.assertEqual(self.receive(process)["kind"], "turn.complete")
        self.assertEqual(process.wait(timeout=5), 0)

    def test_interrupted_native_turn_is_cancelled(self):
        process = self.launch("interrupted")
        self.assertEqual(self.receive(process)["kind"], "turn.cancelled")
        self.assertEqual(process.wait(timeout=5), 0)

    def test_wrong_scope_and_unsupported_approval_request_fail_closed(self):
        for mode in ("wrong-scope", "unknown-request"):
            with self.subTest(mode=mode):
                process = self.launch(mode)
                self.assertEqual(self.receive(process)["kind"], "turn.fail")
                self.assertEqual(process.wait(timeout=5), 1)

    def test_duplicate_callback_is_not_redispatched(self):
        process = self.launch("duplicate")
        self.assertEqual(self.receive(process)["kind"], "tool.call")
        self.send(process, 1, "tool.result", call_id="native-call", status="terminal",
                  terminal={"kind":"unknown"})
        self.assertEqual(self.receive(process)["kind"], "turn.fail")
        self.assertEqual(process.wait(timeout=5), 1)

    def test_host_cancel_retires_native_process(self):
        process = self.launch("stall")
        self.send(process, 1, "turn.cancel", turn={k:v for k,v in TURN.items() if k!="user_input"})
        frame = self.receive(process)
        self.assertEqual(frame["kind"], "turn.cancelled")
        self.assertEqual(process.wait(timeout=5), 0)


if __name__ == "__main__":
    unittest.main()
