#!/usr/bin/env python3
from pathlib import Path
import hashlib, importlib.util, json, os, secrets, subprocess, time, signal
B=Path(__file__).resolve().parent;R=B/("restart-unknown-"+secrets.token_hex(8));R.mkdir(mode=0o700)
sp=importlib.util.spec_from_file_location("client",B/"tool_client.py");c=importlib.util.module_from_spec(sp);sp.loader.exec_module(c);c.ALLOWED_SERVER_UIDS=(0,2000,os.getuid())
state=R/"state";socket_name="hepta_fixture_r4_"+secrets.token_hex(8)
def start():
 p=subprocess.Popen([str(B/"sidecar-native-fixture"),"--state-dir",str(state),"--socket-name",socket_name,"--fixture-uid",str(os.getuid()),"--fixture-shell","/bin/sh"],stdout=subprocess.PIPE,stderr=(R/("server-"+secrets.token_hex(4)+".stderr")).open("wb"),start_new_session=True)
 return p,json.loads(p.stdout.readline())
def stop(p):
 p.terminate()
 try:p.wait(timeout=7)
 except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
def request(action,command,**extra):
 return c.request(dict(version=1,op="execute",action_id=action,command_sha256=hashlib.sha256(command.encode()).hexdigest(),command=command,timeout_ms=2000,**extra),socket_name,6)
p=None
try:
 p,h=start();assert h["state"]=="ready"
 aid=secrets.token_hex(16);marker=R/"forbidden-original-effect"
 o=request(aid,"printf forbidden >> "+str(marker),_fixture_omit_handshake=True);r=o["receipt"]
 assert r["terminal"] is True and r["state"]=="indeterminate" and r["effect_started"] is None
 receipt=state/"actions"/aid/"receipt.json";before=receipt.read_bytes()
 assert not marker.exists();stop(p);p=None
 p,h=start();assert h["state"]=="recovery_required"
 assert c.request({"version":1,"op":"health"},socket_name,5)["state"]=="recovery_required"
 inspected=c.inspect(aid,socket_name=socket_name)["receipt"]
 assert inspected["terminal"] is True and inspected["state"]=="indeterminate"
 newaid=secrets.token_hex(16);newmarker=R/"forbidden-after-restart"
 result=request(newaid,"printf forbidden >> "+str(newmarker))
 assert result["receipt"]["state"]=="recovery_required"
 assert not newmarker.exists() and not (state/"actions"/newaid).exists()
 assert receipt.read_bytes()==before
 out={"status":"PASS","scope":"r4_restart_of_sealed_unknown_only","phone_actions":0,"count":1,
      "old_action_id":aid,"blocked_action_id":newaid,"old_receipt_sha256":hashlib.sha256(before).hexdigest(),
      "sealed_terminal_remains_indeterminate":True,"recovery_required_after_restart":True,
      "new_effect_dispatched":False,"old_receipt_bytes_unchanged":True,
      "source_sha256":hashlib.sha256((B/"phone_tool_sidecar.cpp").read_bytes()).hexdigest(),"evidence_dir":str(R)}
 (B/"TARGETED-R4-RESULT.json").write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2),flush=True)
finally:
 if p:stop(p)
