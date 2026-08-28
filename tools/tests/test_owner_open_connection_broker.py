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
CLIENT = ROOT / "owner-open" / "owner_open_broker_client.py"

FAKE_UPSTREAM = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
record = Path(os.environ["UPSTREAM_RECORD"])
for line in sys.stdin:
    frame=json.loads(line)
    with record.open("a") as f: f.write(json.dumps(frame,sort_keys=True)+"\n")
    kind=frame["kind"]; seq=frame["seq"]; payload=frame.get("payload",{}); job=payload.get("job_id")
    def emit(k,p):
        value={"kind":k,"seq":seq,"direction":"host_to_client","payload":p}
        if job:value["job_id"]=job
        print(json.dumps(value,separators=(",",":")),flush=True)
    if kind=="hello": emit("hello.ack",{"long_running_jobs":True})
    elif kind=="job.start":
        emit("job.started",{"pid":123,"cursor":0})
        time.sleep(0.05)
        emit("job.start.result",{"status":"started","automatic_redispatch":False})
    elif kind=="job.inspect": emit("job.inspect.result",{"status":"found","read_only":True,"automatic_redispatch":False})
    elif kind in {"job.write","job.resize","job.close_stdin","job.kill"}: emit("job.control.result",{"status":"applied","automatic_redispatch":False})
    else: emit("host.error",{"message":"unsupported"})
'''


def line(sock: socket.socket, timeout: float = 5) -> dict:
    sock.settimeout(timeout)
    data=bytearray()
    while True:
        chunk=sock.recv(1)
        if not chunk: raise EOFError("socket closed")
        if chunk==b"\n": return json.loads(data)
        data.extend(chunk)


def send(sock: socket.socket, value: dict) -> None:
    sock.sendall(json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n")


class BrokerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.upstream=self.root/"upstream.py"
        self.record=self.root/"upstream.jsonl"
        self.socket=self.root/"broker.sock"
        self.descriptor=self.root/"broker.json"
        self.token=self.root/"broker.token"
        self.upstream.write_text(FAKE_UPSTREAM)
        self.upstream.chmod(0o700)
        env=os.environ.copy(); env["UPSTREAM_RECORD"]=str(self.record)
        self.process=subprocess.Popen([
            sys.executable,str(BROKER),"--socket",str(self.socket),"--descriptor",str(self.descriptor),"--token-file",str(self.token),"--broker-id","broker-test","--upstream",str(self.upstream)
        ],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and not self.descriptor.exists():
            if self.process.poll() is not None: break
            time.sleep(0.02)
        if not self.descriptor.exists():
            out,err=self.process.communicate(timeout=2)
            self.fail(f"broker did not start: {out!r} {err!r}")
        self.token_value=self.token.read_text().strip()

    def tearDown(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=2)
        for pipe in (self.process.stdout,self.process.stderr):
            if pipe: pipe.close()
        self.temp.cleanup()

    def connect(self, client_id: str, token: str | None = None) -> socket.socket:
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); sock.connect(str(self.socket))
        send(sock,{"kind":"broker.hello","client_id":client_id,"token":token or self.token_value})
        ack=line(sock)
        self.assertEqual(ack["kind"],"broker.hello.ack")
        self.assertEqual(ack["client_id"],client_id)
        return sock

    def request(self, client: socket.socket, request_id: str, frame: dict, expected: list[str]) -> None:
        payload=frame.get("payload",{})
        send(client,{"kind":"request","request_id":request_id,"frame":frame,"expected_kinds":expected,"expected_job_id":payload.get("job_id"),"timeout_ms":5000})

    def collect_until(self, client: socket.socket, request_id: str) -> list[dict]:
        values=[]
        for _ in range(20):
            value=line(client); values.append(value)
            if value.get("kind")=="result" and value.get("request_id")==request_id: return values
        self.fail(f"no result for {request_id}: {values}")

    def test_two_clients_share_one_upstream_with_owner_results_and_broadcast_observations(self) -> None:
        first=self.connect("client-a"); second=self.connect("client-b")
        try:
            self.request(first,"req-a",{"kind":"job.start","seq":9,"direction":"client_to_host","payload":{"job_id":"job-a"}},["job.start.result"])
            self.request(second,"req-b",{"kind":"job.inspect","seq":1,"direction":"client_to_host","payload":{"job_id":"job-b"}},["job.inspect.result"])
            first_values=self.collect_until(first,"req-a")
            second_values=self.collect_until(second,"req-b")
            self.assertTrue(any(v.get("kind")=="observation" and v.get("frame",{}).get("kind")=="job.started" for v in first_values))
            self.assertTrue(any(v.get("kind")=="observation" for v in second_values))
            self.assertEqual(sum(v.get("kind")=="result" and v.get("request_id")=="req-a" for v in first_values),1)
            self.assertFalse(any(v.get("kind")=="result" and v.get("request_id")=="req-a" for v in second_values))
        finally:
            first.close(); second.close()
        frames=[json.loads(x) for x in self.record.read_text().splitlines()]
        self.assertEqual([f["kind"] for f in frames],["hello","job.start","job.inspect"])
        self.assertEqual([f["seq"] for f in frames],[0,1,2])

    def test_bad_token_is_rejected(self) -> None:
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); sock.connect(str(self.socket))
        try:
            send(sock,{"kind":"broker.hello","client_id":"bad","token":"0"*64})
            value=line(sock)
            self.assertEqual(value["kind"],"error")
            self.assertIn("token",value["message"])
        finally: sock.close()

    def test_owner_disconnect_does_not_cancel_or_redispatch_accepted_request(self) -> None:
        owner=self.connect("owner"); observer=self.connect("observer")
        self.request(owner,"req-once",{"kind":"job.start","seq":0,"direction":"client_to_host","payload":{"job_id":"job-once"}},["job.start.result"])
        owner.close()
        observations=[]
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            value=line(observer); observations.append(value)
            if value.get("kind")=="observation" and value.get("frame",{}).get("kind")=="job.start.result": break
        observer.close()
        self.assertTrue(any(v.get("frame",{}).get("kind")=="job.start.result" for v in observations))
        frames=[json.loads(x) for x in self.record.read_text().splitlines()]
        self.assertEqual(sum(f["kind"]=="job.start" for f in frames),1)

    def test_stdio_client_preserves_host_surface(self) -> None:
        child=subprocess.Popen([
            sys.executable,str(CLIENT),"--descriptor",str(self.descriptor),"--client-id","stdio-client"
        ],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            assert child.stdin and child.stdout
            child.stdin.write(json.dumps({"kind":"hello","seq":0,"payload":{}})+"\n")
            child.stdin.flush(); hello=json.loads(child.stdout.readline())
            self.assertEqual(hello["kind"],"hello.ack")
            child.stdin.write(json.dumps({"kind":"job.inspect","seq":1,"direction":"client_to_host","payload":{"job_id":"job-x"}})+"\n")
            child.stdin.flush()
            observed=json.loads(child.stdout.readline())
            self.assertEqual(observed["kind"],"job.inspect.result")
        finally:
            if child.stdin: child.stdin.close()
            child.wait(timeout=5)
            if child.stdout: child.stdout.close()
            if child.stderr: child.stderr.close()


if __name__=="__main__": unittest.main()
