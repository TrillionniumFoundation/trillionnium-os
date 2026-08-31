from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "owner-open" / "owner_open_connection_broker.py"

COMMON = r'''
import json, os, sys, time
from pathlib import Path
record = Path(os.environ["UPSTREAM_RECORD"])
fields = (
    "session_id", "profile_id", "task_id", "turn_id", "turn_stream_id",
    "call_id", "job_id", "operation_id", "attachment_id", "request_sha256"
)
host_sequence=[1000]
def remember(frame):
    with record.open("a") as f:
        f.write(json.dumps({"at": time.monotonic(), "frame": frame}, sort_keys=True)+"\n")
def correlation(frame):
    payload=frame.get("payload",{})
    result={}
    for name in fields:
        value=frame.get(name,payload.get(name))
        if isinstance(value,str): result[name]=value
    return result
def response_kind(frame):
    return {
        "job.start":"job.start.result",
        "job.inspect":"job.inspect.result",
        "job.write":"job.control.result",
    }.get(frame["kind"], "host.error")
def emit(frame):
    global host_sequence
    corr=correlation(frame)
    payload={"status":"ok","automatic_redispatch":False,**corr}
    value={"kind":response_kind(frame),"direction":"host_to_client","payload":payload,**corr}
    if "seq" in frame:
        value["seq"]=host_sequence[0]
        host_sequence[0]+=1
    for name in ("broker_request_id", "broker_request_sha256", "broker_request_upstream_seq"):
        if name in frame: value[name]=frame[name]
    print(json.dumps(value,separators=(",",":")),flush=True)
def handshake():
    frame=json.loads(next(sys.stdin)); remember(frame)
    assert frame["kind"]=="hello"
    print(json.dumps({"kind":"hello.ack","seq":0,"direction":"host_to_client","payload":{}}),flush=True)
'''

CROSS_KEY = "#!/usr/bin/env python3\n" + COMMON + r'''
handshake()
first=json.loads(next(sys.stdin)); remember(first)
second=json.loads(next(sys.stdin)); remember(second)
emit(second)
emit(first)
for line in sys.stdin:
    frame=json.loads(line); remember(frame); emit(frame)
'''

SAME_KEY = "#!/usr/bin/env python3\n" + COMMON + r'''
handshake()
first=True
for line in sys.stdin:
    frame=json.loads(line); remember(frame)
    if first:
        first=False
        time.sleep(0.20)
    emit(frame)
'''

LATE_RESULT = "#!/usr/bin/env python3\n" + COMMON + r'''
handshake()
first=json.loads(next(sys.stdin)); remember(first)
time.sleep(0.20)
emit(first)
second=json.loads(next(sys.stdin)); remember(second); emit(second)
for line in sys.stdin:
    frame=json.loads(line); remember(frame); emit(frame)
'''

DELAYED_UNSEQUENCED_DUPLICATE = "#!/usr/bin/env python3\n" + COMMON + r'''
handshake()
first=json.loads(next(sys.stdin)); remember(first); emit(first)
second=json.loads(next(sys.stdin)); remember(second)
duplicate=dict(first)
duplicate.pop("seq", None)
duplicate.pop("broker_request_id", None)
duplicate.pop("broker_request_sha256", None)
emit(duplicate)
emit(second)
for line in sys.stdin:
    frame=json.loads(line); remember(frame); emit(frame)
'''

SLOW_LATE_RESULT = "#!/usr/bin/env python3\n" + COMMON + r'''
handshake()
first=json.loads(next(sys.stdin)); remember(first)
time.sleep(0.40)
emit(first)
for line in sys.stdin:
    frame=json.loads(line); remember(frame); emit(frame)
'''


def read_line(sock: socket.socket, timeout: float = 5.0) -> dict:
    sock.settimeout(timeout)
    data=bytearray()
    while True:
        chunk=sock.recv(1)
        if not chunk:
            raise EOFError("socket closed")
        if chunk==b"\n":
            return json.loads(data)
        data.extend(chunk)


def send(sock: socket.socket, value: dict) -> None:
    sock.sendall(json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n")


class Harness:
    upstream_source = CROSS_KEY

    def setUp(self) -> None:
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.upstream=self.root/"upstream.py"
        self.upstream.write_text(self.upstream_source)
        self.upstream.chmod(0o700)
        self.record=self.root/"upstream.jsonl"
        self.socket_path=self.root/"broker.sock"
        self.descriptor=self.root/"broker.json"
        self.token=self.root/"broker.token"
        env=os.environ.copy(); env["UPSTREAM_RECORD"]=str(self.record)
        self.process=subprocess.Popen([
            sys.executable,str(BROKER),
            "--socket",str(self.socket_path),
            "--descriptor",str(self.descriptor),
            "--token-file",str(self.token),
            "--broker-id","mux-test",
            "--upstream",str(self.upstream),
            "--max-inflight-requests","4",
            "--max-pending-requests","16",
        ],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and not self.descriptor.exists():
            if self.process.poll() is not None:
                break
            time.sleep(0.01)
        if not self.descriptor.exists():
            out,err=self.process.communicate(timeout=2)
            self.fail(f"broker did not start: {out!r} {err!r}")
        self.descriptor_value=json.loads(self.descriptor.read_text())
        self.token_value=self.token.read_text().strip()
        self.assertEqual(self.descriptor_value["max_inflight_requests"],4)
        self.assertEqual(self.descriptor_value["scheduler_version"],2)
        self.assertIs(self.descriptor_value["automatic_redispatch"],False)

    def tearDown(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=2)
        for pipe in (self.process.stdout,self.process.stderr):
            if pipe: pipe.close()
        self.temp.cleanup()

    def connect(self, client_id: str) -> socket.socket:
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        sock.connect(str(self.socket_path))
        send(sock,{"kind":"broker.hello","broker_epoch":self.descriptor_value["broker_epoch"],"client_id":client_id,"token":self.token_value})
        ack=read_line(sock)
        self.assertEqual(ack["kind"],"broker.hello.ack")
        return sock

    @staticmethod
    def request(sock: socket.socket, request_id: str, seq: int, job_id: str, timeout_ms: int = 2000) -> None:
        scope={
            "session_id":"session-mux",
            "profile_id":"profile-mux",
            "task_id":"task-mux",
            "turn_id":"turn-mux",
            "turn_stream_id":"stream-mux",
        }
        send(sock,{
            "kind":"request",
            "request_id":request_id,
            "frame":{
                "kind":"job.inspect",
                "seq":seq,
                "direction":"client_to_host",
                "payload":{**scope,"job_id":job_id},
            },
            "expected_kinds":["job.inspect.result"],
            "expected_job_id":job_id,
            "timeout_ms":timeout_ms,
        })

    @staticmethod
    def terminal(sock: socket.socket, request_id: str, timeout: float = 5.0) -> tuple[dict,list[dict]]:
        observed=[]
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            value=read_line(sock,max(0.05,deadline-time.monotonic()))
            observed.append(value)
            if value.get("kind") in {"result","error"} and value.get("request_id")==request_id:
                return value,observed
        raise AssertionError(f"no terminal for {request_id}: {observed}")

    def records(self) -> list[dict]:
        if not self.record.exists():
            return []
        return [json.loads(line) for line in self.record.read_text().splitlines()]


class CrossKeyMuxTest(Harness, unittest.TestCase):
    upstream_source = CROSS_KEY

    def test_reverse_terminal_order_stays_bound_to_exact_owner(self) -> None:
        first=self.connect("client-a"); second=self.connect("client-b")
        try:
            self.request(first,"request-a",0,"job-a")
            self.request(second,"request-b",0,"job-b")
            second_terminal,_=self.terminal(second,"request-b")
            first_terminal,_=self.terminal(first,"request-a")
            self.assertEqual(second_terminal["broker_response_connection_id"],"client-b")
            self.assertEqual(first_terminal["broker_response_connection_id"],"client-a")
            self.assertNotEqual(
                first_terminal["broker_request_upstream_seq"],
                second_terminal["broker_request_upstream_seq"],
            )
        finally:
            first.close(); second.close()
        frames=[record["frame"] for record in self.records()]
        self.assertEqual([frame["kind"] for frame in frames],["hello","job.inspect","job.inspect"])


class SameKeySerializationTest(Harness, unittest.TestCase):
    upstream_source = SAME_KEY

    def test_second_same_key_is_not_written_before_first_terminal(self) -> None:
        first=self.connect("client-a"); second=self.connect("client-b")
        try:
            self.request(first,"request-a",0,"same-job")
            self.request(second,"request-b",0,"same-job")
            time.sleep(0.08)
            frames=[record["frame"] for record in self.records()]
            self.assertEqual([frame["kind"] for frame in frames],["hello","job.inspect"])
            self.terminal(first,"request-a")
            self.terminal(second,"request-b")
        finally:
            first.close(); second.close()
        frames=[record["frame"] for record in self.records()]
        self.assertEqual(len(frames),3)
        self.assertEqual(frames[1]["broker_ordering_key"],frames[2]["broker_ordering_key"])


class LateResultIsolationTest(Harness, unittest.TestCase):
    upstream_source = LATE_RESULT

    def test_timed_out_result_cannot_terminalize_new_request(self) -> None:
        first=self.connect("client-a"); second=self.connect("client-b")
        try:
            self.request(first,"request-old",0,"job-old",timeout_ms=50)
            old_terminal,_=self.terminal(first,"request-old")
            self.assertEqual(old_terminal["kind"],"error")
            self.assertEqual(old_terminal["code"],"unknown_after_timeout")
            self.request(second,"request-new",0,"job-new",timeout_ms=2000)
            new_terminal,observed=self.terminal(second,"request-new")
            self.assertEqual(new_terminal["kind"],"result")
            self.assertEqual(new_terminal["frame"]["payload"]["job_id"],"job-new")
            self.assertFalse(any(
                value.get("kind")=="result" and value.get("request_id")=="request-old"
                for value in observed
            ))
            self.assertFalse(any(
                value.get("kind")=="observation"
                and value.get("frame",{}).get("payload",{}).get("job_id")=="job-old"
                for value in observed
            ))
        finally:
            first.close(); second.close()
        frames=[record["frame"] for record in self.records()]
        self.assertEqual(sum(frame.get("payload",{}).get("job_id")=="job-old" for frame in frames),1)
        self.assertEqual(sum(frame.get("payload",{}).get("job_id")=="job-new" for frame in frames),1)


class DelayedUnsequencedDuplicateTest(Harness, unittest.TestCase):
    upstream_source = DELAYED_UNSEQUENCED_DUPLICATE

    def test_omitted_sequence_duplicate_cannot_bind_new_active_request(self) -> None:
        first=self.connect("client-a"); second=self.connect("client-b")
        try:
            self.request(first,"request-old",0,"same-job")
            old_terminal,_=self.terminal(first,"request-old")
            self.assertEqual(old_terminal["kind"],"result")
            self.request(second,"request-new",0,"same-job")
            new_terminal,observed=self.terminal(second,"request-new")
            self.assertEqual(new_terminal["kind"],"result")
            self.assertEqual(new_terminal["frame"]["payload"]["job_id"],"same-job")
            # The duplicate has no broker sequence or request id.  It must be
            # isolated rather than becoming a second terminal for request-new.
            self.assertEqual(
                sum(v.get("kind")=="result" and v.get("request_id")=="request-new" for v in observed),
                1,
            )
            self.assertFalse(any(
                v.get("kind")=="observation"
                and "seq" not in v.get("frame", {})
                and "broker_request_id" not in v.get("frame", {})
                for v in observed
            ))
        finally:
            first.close(); second.close()
        frames=[record["frame"] for record in self.records()]
        self.assertEqual(sum(frame["kind"]=="job.inspect" for frame in frames),2)


class SameKeyTimeoutFenceTest(Harness, unittest.TestCase):
    upstream_source = SLOW_LATE_RESULT

    def test_timeout_fences_waiters_and_future_same_key_without_redispatch(self) -> None:
        first=self.connect("client-a"); waiting=self.connect("client-b")
        try:
            self.request(first,"request-first",0,"same-job",timeout_ms=150)
            deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                if len(self.records()) >= 2:
                    break
                time.sleep(0.005)
            else:
                self.fail("first same-key request was not forwarded")
            self.request(waiting,"request-waiting",0,"same-job",timeout_ms=2000)
            first_terminal,_=self.terminal(first,"request-first")
            waiting_terminal,_=self.terminal(waiting,"request-waiting")
            self.assertEqual(first_terminal["code"],"unknown_after_timeout")
            self.assertEqual(waiting_terminal["code"],"ordering_key_uncertain")

            self.request(first,"request-future",1,"same-job",timeout_ms=2000)
            future_terminal,future_observed=self.terminal(first,"request-future")
            self.assertEqual(future_terminal["code"],"ordering_key_uncertain")
            self.assertFalse(any(
                value.get("kind")=="observation"
                and value.get("frame",{}).get("payload",{}).get("job_id")=="same-job"
                for value in future_observed
            ))
            time.sleep(0.25)
        finally:
            first.close(); waiting.close()
        frames=[record["frame"] for record in self.records()]
        self.assertEqual(
            sum(frame.get("payload",{}).get("job_id")=="same-job" for frame in frames),
            1,
        )


if __name__ == "__main__":
    unittest.main()
