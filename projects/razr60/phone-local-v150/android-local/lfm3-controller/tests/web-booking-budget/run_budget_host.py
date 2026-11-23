#!/usr/bin/env python3
"""Exact production observation methods; real retained DOM, explicitly simulated IO/time/native boundaries."""
import argparse, ast, hashlib, importlib.util, json, subprocess, time
from pathlib import Path
def sha(raw): return hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser()
 for name in ("source","baseline-session","output","java-home","json-jar","pending-capture","ready-capture"):
  p.add_argument("--"+name,type=Path,required=True)
 a=p.parse_args(); root=a.source.resolve(); out=a.output.resolve(); out.mkdir(parents=True,exist_ok=False)
 report={"schema":"hepta.booking-budget-host.v1","all_pass":False,"phone_contacted":False,
  "native_authority_proven":False,"clock_ipc_ack_and_native_observations_mocked":True,
  "real_booking_pending_detector_used":True,"repeated_future_capture_sequence_synthetic":True,
  "stages":[]}
 bound={}
 def read(path):
  raw=path.read_bytes(); bound[path]=sha(raw); return raw
 def run(name,args,expected=0,reason=None):
  started=time.monotonic()
  r=subprocess.run(list(map(str,args)),cwd=root,stdin=subprocess.DEVNULL,capture_output=True,timeout=100)
  (out/(name+".stdout")).write_bytes(r.stdout); (out/(name+".stderr")).write_bytes(r.stderr)
  entry={"name":name,"exit_code":r.returncode,"expected_exit_code":expected,"elapsed_s":time.monotonic()-started,
    "stdout_sha256":sha(r.stdout),"stderr_sha256":sha(r.stderr)}
  report["stages"].append(entry)
  assert r.returncode==expected,(name,r.returncode,r.stderr.decode(errors="replace")[-4000:])
  if reason: assert reason in r.stderr.decode(errors="replace"),(name,"different counterfactual rejection")
 try:
  assert sha(read(a.pending_capture))=="7dffa93d1f1b836378046a507b4a5adfc4225fc0e227f92b806b16f1e474ab22"
  assert sha(read(a.ready_capture))=="2c0de52ef00841bca97d4fcc72bf4d5203e56e29a4c5878d865342e2fa41da79"
  assert sha(read(a.json_jar))=="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
  old=read(a.baseline_session); current=read(root/"src/org/trillionnium/hepta/local/WebFlightSession.java")
  assert sha(old)=="ee2b2f8c1a236e6e0297db549381001877c7d00374c412b8078e83d66d919b98"
  assert sha(current)=="dd45a9b72319bdc52a78152b13f62a849914d97b83146afb7435581a86fa6286"
  extractor_path=root/"tests/action-worker/run_host_tests.py"
  read(extractor_path)
  spec=importlib.util.spec_from_file_location("host_method_extractor",extractor_path)
  extractor=importlib.util.module_from_spec(spec); spec.loader.exec_module(extractor)
  query=root/"tests/web-flight/run_query_host_tests.py"
  parsed=ast.parse(read(query).decode())
  paths=next(ast.literal_eval(n.value) for n in parsed.body if isinstance(n,ast.Assign)
    and any(isinstance(t,ast.Name) and t.id=="PURE_PATHS" for t in n.targets))
  inputs=[root/v for v in paths if v!="tests/web-flight/WebFlightQueryHostTest.java"]
  inputs += [root/"src/org/trillionnium/hepta/local/WebObservationTiming.java",root/"src/org/trillionnium/hepta/local/TaskDisplayText.java"]
  for item in inputs: read(item)
  template_path=Path(__file__).resolve().with_name("WebBookingBudgetHost.template")
  template=read(template_path).decode()
  assert template.count("/* EXACT_PRODUCTION_METHODS */")==1
  signatures=["PhoneObservation observe(PhoneObservation initial,Observer observer,long deadline)",
    "private boolean retryLoadingDocument(WebEvidenceReceipt first,WebEvidenceReceipt last,PhoneObservation frame,",
    "private static boolean sameFrame(PhoneObservation a,PhoneObservation b)",
    "private static String loadingKey(WebEvidenceReceipt receipt)"]
  report["template_sha256"]=sha(template.encode())
  for label,session,budget in (("baseline",old,6000),("candidate",current,16000)):
   folder=out/label;folder.mkdir()
   methods=[extractor.body(session.decode(),s) for s in signatures]
   java=folder/"WebBookingBudgetHost.java"
   java.write_text(template.replace("/* EXACT_PRODUCTION_METHODS */","\n\n".join(methods)))
   report[label]={"session_sha256":sha(session),"generated_java_sha256":sha(java.read_bytes()),
    "methods":[{"signature":s,"sha256":sha(v.encode())} for s,v in zip(signatures,methods)]}
   classes=folder/"classes"
   run(label+"-compile",[a.java_home/"bin/javac","--release","8","-encoding","UTF-8","-proc:none",
    "-cp",a.json_jar,"-d",classes,*inputs,java])
   modes=[("counterfactual",1,"instrumented capture deadline"),("boundaries",0,None)] if label=="baseline" else [("all",0,None)]
   for mode,expected,reason in modes:
    receipt=folder/(mode+".json")
    run(label+"-"+mode,[a.java_home/"bin/java","-cp",str(classes)+":"+str(a.json_jar),
      "org.trillionnium.hepta.local.WebBookingBudgetHost",a.pending_capture,a.ready_capture,receipt,mode,budget],expected,reason)
    if expected==0: report[label][mode]=json.loads(receipt.read_text())
  assert all(sha(p.read_bytes())==v for p,v in bound.items()),"read-only input changed"
  report["inputs"]=[{"path":str(p),"sha256":v} for p,v in bound.items()]
  report["all_pass"]=True
 except Exception as e:
  report["error"]=str(e)
 finally:
  (out/"RESULT.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
 print(json.dumps({"all_pass":report["all_pass"],"error":report.get("error"),"result":str(out/"RESULT.json")},ensure_ascii=False))
 return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
