"""Actual Java wire -> Python ordering -> opt-in real Rust Host, local stub only."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
FRAME = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/client/src/org/trillionnium/owneropen/OwnerOpenFrame.java"
SCOPE = ("session-11111111-1111-4111-8111-111111111111",
         "task-22222222-2222-4222-8222-222222222222",
         "turn-33333333-3333-4333-8333-333333333333")
sys.path.insert(0, str(ROOT / "tools/owner-open"))
from owner_open_broker_mux import MuxError, ordering_key_for_frame

HARNESS = r'''
import java.util.List;
import java.util.Collections;
import org.trillionnium.owneropen.*;
public final class Wire {
  public static void main(String[] a) throws Exception {
    String s=a[1], t=a[2], u=a[3], prompt="local stub only";
    if(a[0].equals("evidence")) {
      OwnerOpenTurnEvidence e=OwnerOpenTurnEvidence.parse(
        new String(System.in.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));
      OwnerOpenClientState selected=new OwnerOpenClientState(s,t,u,
        OwnerOpenFrame.turnRequestSha256(s,t,u,prompt),Collections.emptyMap());
      System.out.println(e.matches(selected)+":"+e.completeReadback); return;
    }
    String f; List<String> kinds;
    switch(a[0]) {
      case "start": f=OwnerOpenFrame.turnStart(s,t,u,prompt);
        kinds=List.of("turn.accepted","host.error"); break;
      case "cancel": f=OwnerOpenFrame.turnCancel(s,t,u);
        kinds=List.of("turn.cancel.accepted","host.error"); break;
      case "inspect": f=OwnerOpenFrame.turnInspect(s,t,u,
        OwnerOpenFrame.turnRequestSha256(s,t,u,prompt),0,64);
        kinds=List.of("turn.inspect.result","host.error"); break;
      default: throw new IllegalArgumentException(a[0]);
    }
    System.out.println(OwnerOpenFrame.brokerRequest("android-client-test:"+a[4],
      OwnerOpenFrame.withClientTransportSequence(f,Long.parseLong(a[4])),kinds,Integer.parseInt(a[5])));
  }
}
'''

PROVIDER = r'''import json, os, sys
from pathlib import Path
root=Path(sys.argv[1])
start=json.loads(sys.stdin.readline())
stat=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()
with (root/'provider.json').open('x') as f:
    json.dump({'pid':os.getpid(),'start_ticks':int(stat[19]),'start':start},f)
print(json.dumps({'protocol':'trillionnium.owner-open.provider-jsonl.v1',
 'kind':'provider.event','seq':0,'event':'model.message','text':'stub is active'}),flush=True)
cancel=json.loads(sys.stdin.readline())
with (root/'provider-cancel.json').open('x') as f: json.dump(cancel,f)
assert cancel['kind']=='turn.cancel', cancel
print(json.dumps({'protocol':'trillionnium.owner-open.provider-jsonl.v1',
 'kind':'turn.cancelled','seq':1,'summary':'local stub cancellation acknowledged'}),flush=True)
'''


def alive(pid: int, start: int) -> bool:
    try:
        fields=Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()
        return int(fields[19]) == start
    except FileNotFoundError:
        return False


class JavaTurnScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("javac") or not shutil.which("java"):
            raise unittest.SkipTest("JDK required for actual Java serialization")
        cls.temp=tempfile.TemporaryDirectory()
        cls.classes=Path(cls.temp.name)
        harness=cls.classes/"Wire.java"; harness.write_text(HARNESS)
        subprocess.run(["javac","-Xlint:all","-Werror","-d",str(cls.classes),str(FRAME),
                       str(FRAME.with_name("OwnerOpenTurnEvidence.java")),
                       str(FRAME.with_name("OwnerOpenClientState.java")),str(harness)],
                       check=True,capture_output=True,timeout=30)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def wire_bytes(self, kind, scope=SCOPE, seq=0, timeout_ms=5000):
        return subprocess.run(["java","-cp",str(self.classes),"Wire",kind,*scope,str(seq),str(timeout_ms)],
                              check=True,capture_output=True,timeout=5).stdout

    def wire(self, kind, scope=SCOPE, seq=0, timeout_ms=5000):
        return json.loads(self.wire_bytes(kind,scope,seq,timeout_ms))

    def test_actual_three_serializers_share_complete_canonical_scope(self):
        frames=[self.wire(k)["frame"] for k in ("start","inspect","cancel")]
        keys=[ordering_key_for_frame(f,"android-test") for f in frames]
        self.assertEqual(len(set(keys)),1)
        for frame in frames:
            p=frame["payload"]
            self.assertEqual(p["profile_id"],"owner-open")
            self.assertRegex(p["turn_stream_id"],r"^r5-stream-[0-9a-f]{64}$")
        for index in range(3):
            scope=list(SCOPE); scope[index]+="-other"
            self.assertNotEqual(keys[0],ordering_key_for_frame(self.wire("cancel",scope)["frame"],"android-test"))

    def test_partial_mirrored_and_unknown_scope_remain_rejected(self):
        for field in ("session_id","profile_id","task_id","turn_id","turn_stream_id"):
            for kind in ("start","cancel","inspect"):
                frame=self.wire(kind)["frame"]; del frame["payload"][field]
                with self.subTest(kind=kind,field=field), self.assertRaises(MuxError):
                    ordering_key_for_frame(frame,"android-test")
        frame=self.wire("start")["frame"]; frame["task_id"]="conflicting-task"
        with self.assertRaisesRegex(MuxError,"conflicting mirrored"):
            ordering_key_for_frame(frame,"android-test")
        frame=self.wire("start")["frame"]; frame["kind"]="turn.future"
        with self.assertRaisesRegex(MuxError,"unsupported request kind"):
            ordering_key_for_frame(frame,"android-test")

    def test_actual_broker_host_active_cancel_and_durable_inspect(self):
        host=os.environ.get("OWNER_OPEN_TEST_HOST")
        core=os.environ.get("OWNER_OPEN_TEST_CORE")
        if not host or not core:
            self.skipTest("explicit locally built Host/core paths required; not an end-to-end PASS")
        for binary in (host,core): self.assertTrue(Path(binary).is_file(),binary)
        trace=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); root.chmod(0o700)
            # Cargo debug executables have a hardlink in deps and may inherit
            # group-write permissions. The real broker deliberately rejects
            # those; independent byte copies satisfy its production pin gate.
            for original,leaf in ((host,"host"),(core,"core")):
                shutil.copyfile(original,root/leaf); (root/leaf).chmod(0o700)
            host=str(root/"host"); core=str(root/"core")
            provider=root/"provider.py"; provider.write_text(PROVIDER)
            args=["--transport-core",core,"--provider",sys.executable,"--provider-arg",str(provider),
                  "--provider-arg",str(root),"--provider-cwd",str(root),
                  "--event-store",str(root/"events.jsonl")]
            command=[sys.executable,"-B","-E",str(ROOT/"tools/owner-open/owner_open_connection_broker_v2.py"),
                     "--socket",str(root/"broker.sock"),"--descriptor",str(root/"descriptor.json"),
                     "--token-file",str(root/"token"),"--broker-id","java-wire-test","--upstream",host]
            command += ["--upstream-arg="+arg for arg in args]
            process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            sock=None; provider_identity=None
            try:
                deadline=time.monotonic()+5
                while not (root/"descriptor.json").exists() and time.monotonic()<deadline:
                    if process.poll() is not None: break
                    time.sleep(0.01)
                self.assertTrue((root/"descriptor.json").exists(),"broker did not start")
                desc=json.loads((root/"descriptor.json").read_text())
                sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); sock.connect(str(root/"broker.sock"))
                stream=sock.makefile("rb")
                def send(value, raw=None):
                    raw=raw if raw is not None else json.dumps(value,separators=(",",":")).encode()+b"\n"
                    trace.append({"sent":value,"raw_utf8":raw.decode()}); sock.sendall(raw)
                def read():
                    sock.settimeout(6); raw=stream.readline(1024*1024)
                    self.assertTrue(raw.endswith(b"\n"),raw)
                    value=json.loads(raw); trace.append({"received":value,"raw_utf8":raw.decode()}); return value
                def request(kind, scope=SCOPE, seq=0, expect_unknown=False):
                    raw=self.wire_bytes(kind,scope,seq,1000 if expect_unknown else 5000)
                    value=json.loads(raw); send(value,raw)
                    for _ in range(100):
                        result=read()
                        if result.get("request_id")==value["request_id"] and result.get("kind") in ("result","error"):
                            if expect_unknown:
                                self.assertEqual(result["kind"],"error",result)
                                self.assertEqual(result["code"],"unknown_after_timeout",result)
                                return result
                            self.assertEqual(result["kind"],"result",result)
                            if kind in ("start","inspect"):
                                parsed=subprocess.run(["java","-cp",str(self.classes),"Wire","evidence",*scope],
                                    input=json.dumps(result).encode(),capture_output=True,timeout=5)
                                self.assertEqual(parsed.returncode,0,parsed.stderr.decode())
                                closed=kind=="inspect" and result["frame"]["payload"]["complete"]
                                self.assertEqual(parsed.stdout.decode().strip(),"true:"+str(closed).lower())
                            return result["frame"]
                    self.fail("no correlated terminal broker result")
                send({"kind":"broker.hello","client_id":"android-client-test","broker_epoch":desc["broker_epoch"],
                      "token":(root/"token").read_text().strip()})
                self.assertEqual(read()["kind"],"broker.hello.ack")
                self.assertEqual(request("start")["kind"],"turn.accepted")
                deadline=time.monotonic()+5
                while not (root/"provider.json").exists() and time.monotonic()<deadline: time.sleep(0.01)
                provider_identity=json.loads((root/"provider.json").read_text())
                pid=provider_identity["pid"]; start=provider_identity["start_ticks"]
                self.assertTrue(alive(pid,start),"provider must still run after start acknowledgement")
                # Wrong-scope errors cannot be assigned to this active turn:
                # the broker conservatively reports UNKNOWN, never success.
                # No fixture augments the actual Java scope or retries it.
                wrong_scopes=[]
                for index in range(3):
                    wrong=list(SCOPE); wrong[index]=wrong[index].replace("11111111","aaaaaaaa").replace("22222222","bbbbbbbb").replace("33333333","cccccccc")
                    wrong_scopes.append(wrong)
                for seq,scope in enumerate(wrong_scopes,1):
                    request("cancel",scope,seq,expect_unknown=True)
                    self.assertTrue(alive(pid,start),"wrong scope cancelled the provider")
                    self.assertFalse((root/"provider-cancel.json").exists())
                inspected=request("inspect",seq=4)
                self.assertEqual(inspected["kind"],"turn.inspect.result",inspected)
                self.assertEqual(inspected["payload"]["status"],"found")
                self.assertFalse(inspected["payload"]["complete"])
                self.assertTrue(alive(pid,start))
                before=time.monotonic(); cancelled=request("cancel",seq=5)
                self.assertEqual(cancelled["kind"],"turn.cancel.accepted",cancelled)
                self.assertLess(time.monotonic()-before,5,"cancel blocked behind the active turn")
                deadline=time.monotonic()+5
                while alive(pid,start) and time.monotonic()<deadline: time.sleep(0.01)
                self.assertFalse(alive(pid,start),"captured provider PID/start remains after cancellation")
                terminal=None
                for seq in range(6,26):
                    terminal=request("inspect",seq=seq)["payload"]
                    if terminal.get("complete"): break
                    time.sleep(0.02)
                self.assertTrue(terminal["complete"],terminal)
                ends=[f for f in terminal["frames"] if f["kind"]=="turn.end"]
                self.assertEqual(len(ends),1,terminal)
                self.assertEqual(ends[0]["payload"]["status"],"cancelled")
                self.assertEqual(json.loads((root/"provider-cancel.json").read_text())["kind"],"turn.cancel")
                self.assertEqual(sum(row.get("sent",{}).get("frame",{}).get("kind")=="turn.start" for row in trace),1)
                stream.close(); sock.close(); sock=None
            finally:
                if sock is not None: sock.close()
                if process.poll() is None: process.terminate()
                try: out,err=process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); out,err=process.communicate(timeout=5)
                if provider_identity and alive(provider_identity["pid"],provider_identity["start_ticks"]):
                    os.kill(provider_identity["pid"],15)
                capture=os.environ.get("OWNER_OPEN_TEST_TRACE")
                if capture:
                    Path(capture).write_text(json.dumps({"trace":trace,"provider_identity":provider_identity,
                        "broker_stdout":out.decode(),"broker_stderr":err.decode(),"scope":"local stub; no phone/model qualification"},indent=2)+"\n")


if __name__=="__main__": unittest.main()
