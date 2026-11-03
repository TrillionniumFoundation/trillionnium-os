#!/usr/bin/env python3
"""Four focused Linux-host checks. This fixture intentionally keeps host UID 1000.
It is not proof that Android/SELinux accepts UID2000 or a phone operation succeeds.
"""
from pathlib import Path
import base64,hashlib,importlib.util,json,os,secrets,select,shlex,signal,socket,struct,subprocess,sys,time
B=Path(__file__).resolve().parent
R=B/("credential-cleanup-"+secrets.token_hex(8));R.mkdir(mode=0o700)
sp=importlib.util.spec_from_file_location("client",B/"tool_client.py")
c=importlib.util.module_from_spec(sp);sp.loader.exec_module(c)
c.ALLOWED_SERVER_UIDS=(0,2000,os.getuid())
assert os.getuid()!=0,"this host fixture must be nonroot and must not attempt uid2000"
results=[];active=[];sockets=[]
def save(name,value):
 p=R/name
 with p.open("x") as f:json.dump(value,f,indent=2);f.write("\n")
def start(state,name):
 sock="hepta_fixture_r5_"+secrets.token_hex(8)
 err=(R/(name+"-"+secrets.token_hex(3)+".stderr")).open("xb")
 p=subprocess.Popen([str(B/"sidecar-native-fixture"),"--state-dir",str(state),"--socket-name",sock,
                     "--fixture-uid",str(os.getuid()),"--fixture-shell","/bin/sh"],
                    stdout=subprocess.PIPE,stderr=err,start_new_session=True)
 err.close();active.append(p)
 assert select.select([p.stdout],[],[],5)[0],"fixture server startup timed out"
 h=json.loads(p.stdout.readline())
 return p,sock,h
def stop(p):
 if p.poll() is None:
  p.terminate()
  try:p.wait(timeout=7)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=1)
 if p in active:active.remove(p)
def payload(command,aid=None,**extra):
 return dict(version=1,op="execute",action_id=aid or secrets.token_hex(16),
             command_sha256=hashlib.sha256(command.encode()).hexdigest(),
             command=command,timeout_ms=3000,**extra)
def req(q,sock):
 return c.request(q,sock,7)
def safe(r,state):
 assert r["state"]==state and r["terminal"] is True
 for k in ["effect_started","process_group_established","waitpid_joined","process_group_absent",
           "intent_parent_sync_complete","execution_credentials_verified"]:assert r[k] is True,k
 assert r["execution_credentials_scope"]=="host_fixture_current_identity_not_android_shell"
 assert r["execution_uid"]==r["execution_euid"]==os.getuid()
 assert r["execution_gid"]==r["execution_egid"]==os.getgid()
 assert r["execution_supplementary_group_count"]==len(os.getgroups())
 assert r["dispatch_count"]==1
def inspect(aid,sock):
 return c.inspect(aid,include_output=True,socket_name=sock)
try:
 state=R/"normal-state";p,sock,h=start(state,"normal");assert h["state"]=="ready"
 observed_code="import os,json; print(json.dumps(dict(uid=os.getresuid(),gid=os.getresgid(),groups=os.getgroups(),pgid=os.getpgrp(),sid=os.getsid(0))))"
 q=payload(shlex.quote(sys.executable)+" -c "+shlex.quote(observed_code))
 response=req(q,sock);r=response["receipt"];safe(r,"completed");assert r["exit_code"]==0
 identity=json.loads(base64.b64decode(response["stdout_b64"]))
 assert identity["uid"]==[os.getuid()]*3 and identity["gid"]==[os.getgid()]*3
 assert identity["groups"]==os.getgroups()
 assert identity["pgid"]==identity["sid"]==r["pgid"]==r["pid"]
 save("01-current-host-identity.json",{"request":q,"response":response,"independent_identity":identity})
 results.append({"case":"fixture_identity_and_same_group","status":"PASS","android_uid2000_proven":False})

 primary="primary-"+secrets.token_hex(16)+"\n";late="late-"+secrets.token_hex(16)+"\n"
 q=payload("printf %s "+shlex.quote(primary)+"; sleep 2; printf %s "+shlex.quote(late))
 wire=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sockets.append(wire)
 wire.connect("\0"+sock);raw=c._json_bytes(q);wire.sendall(struct.pack(">I",len(raw))+raw)
 deadline=time.monotonic()+1.5;log=state/"actions"/q["action_id"]/"stdout.bin"
 while True:
  started=c.inspect(q["action_id"],socket_name=sock)["receipt"]
  raw=log.read_bytes() if log.exists() else b""
  if started.get("effect_started") is True and started.get("execution_credentials_verified") is True and raw==primary.encode():
   assert started["execution_uid"]==os.getuid();break
  assert time.monotonic()<deadline and not started.get("terminal");time.sleep(.02)
 wire.close();sockets.remove(wire)
 deadline=time.monotonic()+5
 while True:
  response=inspect(q["action_id"],sock)
  if response["receipt"].get("terminal"):break
  assert time.monotonic()<deadline;time.sleep(.02)
 safe(response["receipt"],"cancelled");assert response["receipt"]["error"]=="client_disconnected"
 assert base64.b64decode(response["stdout_b64"])==primary.encode()
 frozen=(state/"actions"/q["action_id"]/"receipt.json").read_bytes()
 time.sleep(2.1)
 assert log.read_bytes()==primary.encode()
 assert (state/"actions"/q["action_id"]/"receipt.json").read_bytes()==frozen
 save("02-cancel-original.json",{"request":q,"response":response,"late_output_absent":True,
                               "receipt_sha256":hashlib.sha256(frozen).hexdigest()})
 results.append({"case":"cancel_after_verified_fixture_credentials","status":"PASS","same_owned_group_joined":True})
 stop(p)

 state=R/"credential-failure-state";p,sock,h=start(state,"failure");assert h["state"]=="ready"
 q=payload("printf EFFECT_MUST_NOT_EXECUTE",_fixture_credentials_fail=True)
 response=req(q,sock);r=response["receipt"]
 assert r["terminal"] is True and r["state"]=="indeterminate" and r["effect_started"] is None
 assert r["execution_credentials_verified"] is False and r["execution_uid"] is None and r["execution_gid"] is None
 assert r["waitpid_joined"] is True and r["process_group_absent"] is True
 assert base64.b64decode(response["stdout_b64"])==b""
 assert b"hepta_execution_credentials_failed_before_exec" in base64.b64decode(response["stderr_b64"])
 original=state/"actions"/q["action_id"]/"receipt.json";before=original.read_bytes()
 stop(p);p,sock,h=start(state,"failure-restart");assert h["state"]=="recovery_required"
 fresh=payload("printf REPLAY_MUST_NOT_EXECUTE")
 blocked=req(fresh,sock)
 assert blocked["receipt"]["state"]=="recovery_required"
 assert not (state/"actions"/fresh["action_id"]).exists() and original.read_bytes()==before
 save("03-credential-failure-restart.json",{"original_request":q,"original_response":response,
                                         "blocked_request":fresh,"blocked_response":blocked,
                                         "original_receipt_unchanged":True})
 results.append({"case":"credential_setup_failure_no_exec_and_restart_gate","status":"PASS"})
 stop(p)

 state=R/"production-refusal-must-not-create"
 response=subprocess.run([str(B/"sidecar-native-production-guard-check"),"--state-dir",str(state),
                          "--socket-name","hepta_prod_refusal_"+secrets.token_hex(8)],
                         capture_output=True,timeout=3)
 assert response.returncode==1 and b"production_parent_uid_must_be_root" in response.stderr
 assert response.stdout==b"" and not state.exists()
 save("04-production-unprivileged-refusal.json",{"returncode":response.returncode,
        "stderr":response.stderr.decode(),"host_uid":os.getuid(),"state_not_created":True})
 results.append({"case":"real_production_build_refuses_nonroot_parent","status":"PASS"})

 summary={"status":"PASS","scope":"four targeted Linux host identity/cleanup checks; no Android credentials or phone qualification",
          "count":len(results),"results":results,"phone_operations":0,"host_uid":os.getuid(),
          "host_fixture_did_not_drop_to_2000":True,
          "actual_android_credential_drop":"PENDING_ROOT_PHONE_TEST",
          "source_sha256":hashlib.sha256((B/"phone_tool_sidecar.cpp").read_bytes()).hexdigest(),
          "evidence_dir":str(R)}
 save("RESULT.json",summary)
 (B/"TARGETED-R5-RESULT.json").write_text(json.dumps(summary,indent=2)+"\n")
 print(json.dumps(summary))
finally:
 for wire in sockets:wire.close()
 for p in list(active):stop(p)
