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
release=Path(os.environ["UPSTREAM_RELEASE"])
for line in sys.stdin:
    frame=json.loads(line); remember(frame)
    if first:
        first=False
        # Publish the first frame before waiting for the test.  This gives
        # the assertion a deterministic observation point while keeping the
        # upstream terminal pending, so a second same-key write cannot be
        # hidden by scheduler/process timing.
        while not release.exists():
            time.sleep(0.005)
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

# The broker writes requests to a bounded pipe.  This upstream intentionally
# consumes only the handshake and then stops reading; an oversized request
# therefore fills the pipe and leaves the broker's bounded write waiting.  A
# timeout worker must still retire another accepted request while that write
# is blocked (the old process-wide transition lock made the worker wait for
# the full five-second write deadline).
BLOCKED_WRITE = "#!/usr/bin/env python3\n" + COMMON + r'''
def raw_handshake():
    # Avoid TextIOWrapper read-ahead: it could consume the oversized request
    # while reading the hello line and accidentally make the broker write
    # appear writable.
    data=bytearray()
    while True:
        chunk=os.read(0,1)
        if not chunk:
            raise RuntimeError("broker closed before hello")
        data.extend(chunk)
        if chunk == b"\n":
            break
    frame=json.loads(data)
    remember(frame)
    assert frame["kind"]=="hello"
    print(json.dumps({"kind":"hello.ack","seq":0,"direction":"host_to_client","payload":{}}),flush=True)
raw_handshake()
time.sleep(30.0)
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
    max_inflight_requests = 4

    def setUp(self) -> None:
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.upstream=self.root/"upstream.py"
        self.upstream.write_text(self.upstream_source)
        self.upstream.chmod(0o700)
        self.record=self.root/"upstream.jsonl"
        self.upstream_release=self.root/"upstream.release"
        self.socket_path=self.root/"broker.sock"
        self.descriptor=self.root/"broker.json"
        self.token=self.root/"broker.token"
        env=os.environ.copy()
        env["UPSTREAM_RECORD"]=str(self.record)
        env["UPSTREAM_RELEASE"]=str(self.upstream_release)
        self.process=subprocess.Popen([
            sys.executable,str(BROKER),
            "--socket",str(self.socket_path),
            "--descriptor",str(self.descriptor),
            "--token-file",str(self.token),
            "--broker-id","mux-test",
            "--upstream",str(self.upstream),
            "--max-inflight-requests",str(self.max_inflight_requests),
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
        self.assertEqual(
            self.descriptor_value["max_inflight_requests"],
            self.max_inflight_requests,
        )
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
    def request_with_blob(
        sock: socket.socket,
        request_id: str,
        seq: int,
        job_id: str,
        *,
        blob_bytes: int,
        timeout_ms: int,
    ) -> None:
        """Send one protocol-valid request large enough to fill stdin."""

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
                "payload":{**scope,"job_id":job_id,"blob":"x"*blob_bytes},
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

    def wait_for_records(self, count: int, timeout: float = 2.0) -> list[dict]:
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            records=self.records()
            if len(records)>=count:
                return records
            time.sleep(0.005)
        self.fail(f"upstream did not record {count} frames: {self.records()}")
        return []


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
            # Leave ample room for the bounded observation wait and slow
            # journal fsyncs; this test is about ordering, not timeout
            # convergence.
            self.request(first,"request-a",0,"same-job",timeout_ms=10_000)
            self.request(second,"request-b",0,"same-job",timeout_ms=10_000)
            records=self.wait_for_records(2)
            frames=[record["frame"] for record in records]
            self.assertEqual([frame["kind"] for frame in frames],["hello","job.inspect"])
            self.upstream_release.touch()
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


class BlockedWriteConvergenceTest(Harness, unittest.TestCase):
    upstream_source = BLOCKED_WRITE
    # One dispatcher makes the first active reservation deterministic; the
    # unrelated request remains pending behind the global inflight bound.  Its
    # distinct ordering key makes this a cross-key regression for the old
    # process-wide transition lock: timeout and audit terminalization must
    # proceed while the first pipe write waits.
    max_inflight_requests = 1

    def test_unrelated_timeout_progresses_while_upstream_write_is_blocked(self) -> None:
        first=self.connect("client-a"); waiting=self.connect("client-b")
        try:
            # 900 KiB is below the broker's 1 MiB line bound but larger than a
            # Linux pipe's available capacity after the handshake.
            self.request_with_blob(
                first,
                "request-blocked",
                0,
                "blocked-job",
                blob_bytes=900_000,
                timeout_ms=10_000,
            )
            # Wait for durable acceptance before admitting the waiter.  The
            # oversized request takes long enough to parse/hash that a blind
            # short sleep can otherwise let the waiter win the first active
            # reservation on a loaded host.
            audit_path=Path(self.descriptor_value["audit_file"])
            deadline=time.monotonic()+3.0
            while time.monotonic()<deadline:
                records=(
                    [json.loads(line) for line in audit_path.read_text().splitlines()]
                    if audit_path.exists()
                    else []
                )
                if any(
                    record.get("stage")=="broker.accepted"
                    and record.get("request_id")=="request-blocked"
                    for record in records
                ):
                    break
                time.sleep(0.01)
            else:
                self.fail("oversized request was not durably accepted")
            # With no competing work, one additional scheduling turn is
            # sufficient for the sole dispatcher to enter the blocked write.
            time.sleep(0.20)
            self.request(
                waiting,
                "request-waiting",
                0,
                "unrelated-job",
                timeout_ms=150,
            )
            started=time.monotonic()
            terminal,_=self.terminal(waiting,"request-waiting",timeout=2.0)
            elapsed=time.monotonic()-started
            self.assertEqual(terminal["kind"],"error")
            self.assertEqual(terminal["code"],"timeout_before_forward")
            self.assertLess(elapsed,2.0)
        finally:
            first.close(); waiting.close()


class ActiveBlockedWriteTimeoutTest(Harness, unittest.TestCase):
    """An active request waiting for the writer expires without fencing its key."""

    upstream_source = BLOCKED_WRITE
    # Two dispatcher reservations let the second request become active while
    # the first worker owns the byte-stream gate and is stalled in its bounded
    # pipe write.  This exercises the active (rather than pending) timeout
    # classification introduced for the write-wait interval.
    max_inflight_requests = 2

    def test_active_timeout_before_writer_has_no_ordering_fence(self) -> None:
        first=self.connect("client-a"); second=self.connect("client-b")
        try:
            self.request_with_blob(
                first,
                "request-blocked-active",
                0,
                "blocked-active-job",
                blob_bytes=900_000,
                timeout_ms=10_000,
            )
            audit_path=Path(self.descriptor_value["audit_file"])
            deadline=time.monotonic()+3.0
            while time.monotonic()<deadline:
                records=(
                    [json.loads(line) for line in audit_path.read_text().splitlines()]
                    if audit_path.exists()
                    else []
                )
                if any(
                    record.get("stage")=="broker.accepted"
                    and record.get("request_id")=="request-blocked-active"
                    for record in records
                ):
                    break
                time.sleep(0.01)
            else:
                self.fail("oversized active request was not durably accepted")
            # Give the first dispatcher a turn to acquire the writer and fill
            # the upstream pipe before the second request is admitted.
            time.sleep(0.20)
            self.request_with_blob(
                second,
                "request-writer-wait",
                0,
                "writer-wait-job",
                blob_bytes=900_000,
                timeout_ms=150,
            )
            terminal,_=self.terminal(second,"request-writer-wait",timeout=2.0)
            self.assertEqual(terminal["kind"],"error")
            self.assertEqual(terminal["code"],"timeout_before_forward")
            records=[json.loads(line) for line in audit_path.read_text().splitlines()]
            selected=[
                record for record in records
                if record.get("request_id")=="request-writer-wait"
            ]
            self.assertEqual(
                [record["stage"] for record in selected],
                ["broker.accepted","broker.terminal"],
            )
            self.assertEqual(selected[-1]["details"]["status"],"timeout_before_forward")
            self.assertIs(selected[-1]["details"]["effect_may_have_started"],False)
            # The timeout was before any write attempt, so this ordering key
            # remains usable.  A same-key follow-up therefore reaches the
            # writer wait and receives the same bounded timeout, rather than
            # an ``ordering_key_uncertain`` admission rejection.
            self.request(
                second,
                "request-writer-wait-future",
                1,
                "writer-wait-job",
                timeout_ms=150,
            )
            future_terminal,_=self.terminal(second,"request-writer-wait-future",timeout=2.0)
            self.assertEqual(future_terminal["code"],"timeout_before_forward")
        finally:
            first.close(); second.close()


if __name__ == "__main__":
    unittest.main()
