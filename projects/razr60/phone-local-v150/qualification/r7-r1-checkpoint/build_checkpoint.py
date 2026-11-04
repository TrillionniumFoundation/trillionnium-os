#!/usr/bin/env python3
"""Read existing frozen r7-r1 originals, run the original aggregator, and publish a safe projection.
No phone, network, service, model, task registration, task execution, source mutation or Git operation.
"""
import argparse,collections,datetime,hashlib,json,math,os,stat,subprocess,sys,time,types
from pathlib import Path
SOURCE="7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab"
COMBO="ab038c5533a7459c8bb4d94cca008ca0f61ade0d90ad6db0e8ece3ab1af99ae8"
CANON="87609ca2d6b6701071a1f175acd417e1f3036617884dc09666b9154de25e93f8"
PROTOCOL="d68dd5c17d0ec061f52b60656918867453d67217ac2dc8f5eb43be7dd3ffdf43"
AGG="c3b91281a1076ac6fd782fe722eeedae7384817dcbd89060e94b095be48ce083"
AUDITOR="da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf"
PINS={
"acceptance-r7-host-cancel-faults-r1/ATTEMPTS.json":"d6c05da9630093cafa24cceda88b09659ad308ecfc3849f47c785d035afbcc26",
"acceptance-r7-host-negative-r1/ATTEMPTS.json":"65a88627e5565cd36c47fdef555151dde05233e6712c6e3827cccd8edc710a11",
"acceptance-r7-host-negative-r1/inputs-r1/combination.json":COMBO,
"acceptance-r7/fixed-acceptance-set-r7.json":PROTOCOL,
"acceptance-r7/aggregate_protocol_r7.py":AGG,
"acceptance-r7/business-collector-r7-r1/native_journal_audit.py":AUDITOR,
"health-r7-originals-01/health-audit-01/REPORT.json":"5885d85bfc458caab654910591a7c3f746c6af4c4fe3d378f37a0d47f7714e82",
"health-r7-closure-r1/ROOT-CLOSURE.json":"1c1dd50bdc710dc90dad6b95054120ef6a7cf3a566be4a32ce46f73a6f3105f0",
"health-r7-originals-01/COLLECTOR-RESULT.json":"a7d42f8b22936a4f7d1fed784207df035970debc22690b16154d282faa70ff9d",
"health-r7-originals-01/CAPTURE-TERMINAL.json":"a31b028a296d05d777d1f118d7c4e7710631b0f6901fc85acf4f1c4e11242f9a",
"visual-r7-originals-01/business-audit-01/REPORT.json":"c3b79bc4ba2cc73e2404ab00264cef0fbe1f0abc4f066470a9c66a546531a35e",
"visual-r7-closure-r1/ROOT-CLOSURE.json":"7eb5ad2669f9d91c886fb121c2ead51b0f80d43ef60b09a8bc10a87912052ca4",
"visual-r7-originals-01/COLLECTOR-RESULT.json":"8833dbed9b88d9021ff7fae8d4d2e76e77c0ed9450af5f3e0ffd551611f9c4af",
"visual-r7-originals-01/CAPTURE-RESULT.json":"15ee5a74f7c9dbbf73d5ec05767bcc359f708cbf78a2ccbfafb1a927db7bc393",
"visual-r7-originals-01/CAPTURE-TERMINAL.json":"6734155883bb956ba97fb0a35583b7175c489a054390027a7edb5dc1aa1a0af7",
"visual-r7-originals-01/EXPORT-RESULT.json":"24a7071b3800068c3217af2c8ccb62ea2c490111f040b88322585e2f0d739398",
"unicode-r7-originals-01/business-audit-01/REPORT.json":"566ac78bfab6e871809aa40516dcc65abb816b73bcca0da6b904a2645715f2eb",
"unicode-r7-closure-r1/ROOT-CLOSURE.json":"80aaab5347fb405f72696e36349fe7ea5c40b318a62cc72fc67ec97fb53b9225",
"unicode-r7-originals-01/COLLECTOR-RESULT.json":"292163dfb8368a3a5305f46e6ea177bea8be7bcc609d85b12072c4f32ec1a2b9",
"unicode-r7-originals-01/CAPTURE-RESULT.json":"e99be9f7325176a4d7733fd98c594c8a7c9ccc252527bee81e6210d9b26998b3",
"unicode-r7-originals-01/CAPTURE-TERMINAL.json":"411ba0b03ef5c653b53158e4f3861d746643048d1fa5c2339386e5d9530ca2ee",
"unicode-r7-originals-01/EXPORT-RESULT.json":"80321ae76b53d7669770335939ecef1f0d0c87824a5bee8549a43e9c0365d3fa",
"resource-sampler-r7-r1/before-health/REPORT.json":"61799dc6a71d170b6317f9615f79f3f22028709efdb3dc9a49314d9effc85eb2",
"resource-sampler-r7-r1/after-health/REPORT.json":"e7d67f588c5129012690756e5e90d10ef4debe1e379f17162219e58aaf8b7892",
"resource-sampler-r7-r1/before-visual/REPORT.json":"427ec44162fbf682d8c13086884beba445bb5ddb4aeabf6feba4cc616d172de0",
"resource-sampler-r7-r1/after-visual/REPORT.json":"eae0660ec3ad037066e968cdf259b4d1963a215cf8c3c4056fcf41af7e371567",
"resource-sampler-r7-r1/before-unicode/REPORT.json":"ca58a6843b95a7c8ad2711a1c79a70ee7cb36ca4b126248eff5e479ee3b51dfd",
"resource-sampler-r7-r1/after-unicode/REPORT.json":"45f858b61097d855d8405e26b7f88fdb3c562bb9c4de062cdcbd6177c77bfe1e",
}
def require(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def jbytes(x):return (json.dumps(x,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def canonical(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
def strict(raw):
 def pairs(items):
  x={}
  for k,v in items:
   require(k not in x,"duplicate JSON key");x[k]=v
  return x
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError("nonfinite JSON")))
def ident(s):return tuple(getattr(s,k) for k in ("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_nlink"))
class Reads:
 def __init__(self):self.rows={};self.cache={}
 def read(self,path,pin=None):
  p=Path(path).absolute();k=str(p)
  if k in self.cache:
   raw=self.cache[k]
   require(pin is None or sha(raw)==pin,"cached input pin differs");return raw
  require(p.parent.resolve()==p.parent,"noncanonical input parent")
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   a=os.fstat(fd);require(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=64*1024*1024,"input bound")
   with os.fdopen(fd,"rb",closefd=False) as f:raw=f.read(64*1024*1024+1)
   require(ident(a)==ident(os.fstat(fd))==ident(p.lstat()) and len(raw)==a.st_size,"input changed during read")
  finally:os.close(fd)
  require(pin is None or sha(raw)==pin,"input pin differs:"+str(p))
  self.cache[k]=raw;self.rows[k]={"path":k,"bytes":len(raw),"sha256":sha(raw),"identity":list(ident(a))}
  return raw
 def json(self,path,pin=None):return strict(self.read(path,pin))
 def stable(self):
  require(all(ident(Path(k).lstat())==tuple(v["identity"]) for k,v in self.rows.items()),"input changed after read")
def write_new(path,raw):
 p=Path(path);require(p.parent.resolve()==p.parent,"noncanonical output parent")
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 return {"path":str(p),"bytes":len(raw),"sha256":sha(raw)}
def ref(base,name):return {"path":str(base/name),"sha256":PINS[name]}
def module_from(path,raw):
 m=types.ModuleType("quality_native_audit");m.__file__=str(path);exec(compile(raw,str(path),"exec"),m.__dict__);return m
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--base",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
 a=p.parse_args();base=a.base.absolute();out=a.out.absolute();os.umask(0o077)
 require(base.resolve()==base and out.parent.resolve()==out.parent,"root paths canonical")
 out.mkdir(mode=0o700,exist_ok=False)
 R=Reads();values={}
 for name,pin in PINS.items():
  raw=R.read(base/name,pin)
  if name.endswith(".json"):values[name]=strict(raw)
 combo=values["acceptance-r7-host-negative-r1/inputs-r1/combination.json"]
 protocol=values["acceptance-r7/fixed-acceptance-set-r7.json"]
 require(sha(canonical(combo))==CANON and combo["state"]=="frozen","full frozen combination")
 five=values["acceptance-r7-host-cancel-faults-r1/ATTEMPTS.json"]
 seven=values["acceptance-r7-host-negative-r1/ATTEMPTS.json"]
 require(len(five)==5 and len(seven)==7,"host sample counts")
 rows=five+seven
 require(len({x["case_id"] for x in rows})==12,"distinct fixed host/component cases")
 require(all(x["candidate_manifest_sha256"]==SOURCE and x["combination_manifest_sha256"]==COMBO
  and x["combination_sha256"]==CANON and x["protocol_result"]=="PASS" and x["model_request_count"]==0 and x["phone_actions"]==0
  and all(t["passed"] is True for t in x["assertions"]) for x in rows),"host source/layer/result bindings")
 require(sum(len(x["assertions"]) for x in five)==154 and sum(len(x["assertions"]) for x in seven)==322,"runtime and closure check counts")
 host_rows=[dict(x) for x in rows]
 # These are existing exported evidence, never freshly executed fixtures.
 for row in rows:
  for item in row["evidence"]:R.read(item["path"],item["sha256"])
 native_path=base/"acceptance-r7/business-collector-r7-r1/native_journal_audit.py"
 auditor=module_from(native_path,R.read(native_path,AUDITOR))
 reports={};closures={};native_summaries={};business=[]
 labels=[("health","HEALTH"),("visual","E2E-01"),("unicode","E2E-02")]
 for label,case in labels:
  stem=label+"-r7-originals-01/"
  reportname=stem+("health-audit-01/" if label=="health" else "business-audit-01/")+"REPORT.json"
  closurename=label+"-r7-closure-r1/ROOT-CLOSURE.json"
  q=values[reportname];c=values[closurename];reports[label]=q;closures[label]=c
  process=values[stem+"COLLECTOR-RESULT.json"];captureterminal=values[stem+"CAPTURE-TERMINAL.json"]
  require(q["candidate_source_seal_sha256"]==SOURCE and c["source_seal_sha256"]==SOURCE
   and c["combination_manifest_sha256"]==COMBO,"current production source/full combination")
  require(c["source_report_sha256"]==PINS[reportname] and process["report_sha256"]==PINS[reportname]
   and c["source_collector_result_sha256"]==PINS[stem+"COLLECTOR-RESULT.json"],"report/closure/process pin")
  require(type(process["process_exit_code"]) is int and process["process_exit_code"]==0
   and process["original_capture_complete"] is True
   and type(captureterminal["actor_rc"]) is int and captureterminal["actor_rc"]==0
   and type(captureterminal["phone_process_rc"]) is int and captureterminal["phone_process_rc"]==0
   and captureterminal["capture_process_completed_zero"] is True,"actual collector/capture terminals")
  require(c["scope"]==q["scope"] and c["native_request_sha256"]==q["native_turn_request_sha256"]
   and c["owner_utf8_sha256"]==q["request_utf8_sha256"],"different owner and native digest domains")
  require(c["original_draft_restored_exact"] is True and c["original_draft_submitted"] is False
   and c["automatic_replay"] is False and c["http_worker_joined"] is True and c["slot_after_idle"] is True,"cleanup closure")
  for item in q["inputs"]:R.read(item["source"],item["sha256"])
  selected=[x for x in q["inputs"] if Path(x["source"]).name=="selected-native-raw.jsonl"]
  require(len(selected)==1,"one original selected native byte stream")
  raw=R.read(selected[0]["source"],c["source_native_raw_sha256"])
  require(raw.endswith(b"\n"),"complete native line boundary")
  records=[auditor.strict_loads(line) for line in raw.splitlines() if line]
  audit=auditor.verify_records(records,q["scope"])
  require(audit["status"]=="PASS" and audit["errors"]==[] and audit["unsupported"]==[]
   and audit["record_hashes_verified"]==c["native_hashes_verified"]
   and audit["adjacent_global_predecessor_links_verified"]==c["adjacent_global_links_verified"]
   and audit["global_chain_complete"] is False,"independent selected native integrity")
  require(audit["frames"][-1]["payload"]["status"]==c["native_status"],"original native terminal")
  native_summaries[label]={k:v for k,v in audit.items() if k not in ("frames","selected_records")}
  require(q["observed_model_request_count"]==1 and c["model_requests"]==1
   and q["checks"]["all_model_rounds_real_terminal_and_cleanup"] is True,"one original bounded model round")
  if label=="health":
   require(c["health_qualification_pass"] is True and c["actual_main_exit_codes_all_zero"] is True
    and q["health_qualification_pass"] is True and q["proof_complete"] is True
    and q["observed_tool_dispatch_count"]==0 and c["native_status"]=="completed"
    and q["checks"]["health_exact_new_nonce_summary"] is True
    and q["checks"]["health_nonce_not_forced_by_schema"] is True,"health qualification")
   continue
  capture=values[stem+"CAPTURE-RESULT.json"];export=values[stem+"EXPORT-RESULT.json"]
  require(capture["state"]=="CAPTURED_BOUND_ORIGINALS" and capture["export_complete"] is True
   and capture["issues"]==[] and export["original_capture_complete"] is True
   and captureterminal["capture_result_sha256"]==PINS[stem+"CAPTURE-RESULT.json"]
   and c["source_capture_sha256"]==capture["capture_sha256"]
   and capture["selected_scope"]==q["scope"],"business original capture complete")
  require(q["case_id"]==case and q["task_classification"]=="failed"
   and q["complete_business_success"] is False and q["proof_complete"] is False
   and process["task_classification"]=="failed" and process["proof_complete"] is False
   and c["native_status"]=="provider_failed" and c["task_classification"]=="failed","preserve failed business outcome")
  require(q["checks"]["all_named_action_projections_verified"] is True
   and q["checks"]["provider_native_terminal_text_agree"] is False
   and q["checks"]["no_unresolved_mutating_effects"] is True
   and q["observed_tool_dispatch_count"]==1 and len(q["tools"])==1,"one mapped action and original proof limits")
  tool=q["tools"][0];receipt=tool["sidecar_terminal"]
  require(tool["safe_original_execution_terminal"] is True and tool["successful_original_execution"] is False
   and tool["unresolved_effect"] is False and tool["r6_terminal_identity_and_cleanup_verified"] is True
   and receipt["state"]=="timed_out" and receipt["dispatch_count"]==1
   and receipt["effect_started"] is True and receipt["waitpid_joined"] is True and receipt["process_group_absent"] is True
   and receipt["waitpid_identity_lost"] is False and receipt["can_redispatch"] is False
   and c["original_action_terminal_independently_inspected"] is True,"real action terminal; no effect-success inference")
  require(q["business_outcome"]["verified_facts"]==[],"no verified partial business completion")
  action_item=[x for x in q["inputs"] if x["source"].endswith("/local-01.model-action.json")]
  require(len(action_item)==1,"original named model action")
  model_action=R.json(action_item[0]["source"],action_item[0]["sha256"])
  expected_alias={"visual":"视觉挑战","unicode":"Unicode验证"}[label]
  require(model_action["name"]=="mobile_use" and model_action["arguments"]["action"]=="open"
   and model_action["arguments"]["text"]==expected_alias,"correct exact registered alias")
  stderr_item=[x for x in q["inputs"] if x["source"].endswith("/stderr.bin")]
  require(len(stderr_item)==1,"original sidecar stderr")
  stderr=R.read(stderr_item[0]["source"],receipt["stderr_sha256"]).decode("utf-8")
  denied={prop:stderr.count('Access denied finding property "'+prop+'"') for prop in ("servicemanager.installed","servicemanager.ready")}
  require(all(n>0 for n in denied.values()),"observed property-access errors")
  row={"case_id":case,"attempt_id":case+"-r7-original-attempt-01","layer":"model_e2e",
   "candidate_manifest_sha256":SOURCE,"combination_manifest_sha256":COMBO,"combination_sha256":CANON,
   "protocol_result":"FAIL","task_outcome":"failed","task_outcome_scope":"Original bounded phone-local model business task.",
   "fresh_nonce_original_bound":q["fresh_nonce_supplied_and_exact"],
   "collector_report":ref(base,reportname),
   "evidence":[ref(base,n) for n in (reportname,closurename,stem+"CAPTURE-RESULT.json",
     stem+"CAPTURE-TERMINAL.json",stem+"COLLECTOR-RESULT.json",stem+"EXPORT-RESULT.json")],
   "observed_latency_interval_seconds":c["native_persistence_interval_seconds"],
   "original_task_terminal_unchanged":True,"automatic_replay":False,
   "hardware_energy_joules":None,"monetary_cost":None}
  rows.append(row)
  business.append({"case_id":case,"protocol_result":"FAIL","task_outcome":"failed","native_status":"provider_failed",
   "complete_business_success":False,"verified_partial_completion":False,"proof_complete":False,
   "model_requests":1,"model_usage":c["model_usage"],"http_elapsed_seconds":q["http_elapsed_seconds_sum"],
   "native_persistence_interval_seconds":c["native_persistence_interval_seconds"],
   "native_terminal_observed_upper_seconds":c["native_terminal_observed_upper_seconds"],
   "observation_interval_width_seconds":c["native_persistence_interval_seconds"][1]-c["native_persistence_interval_seconds"][0],
   "model_action":{"action":"open","exact_registered_alias":expected_alias,"projection_verified":True},
   "phone_tool_dispatches":1,"sidecar_elapsed_ms":receipt["elapsed_ms"],"native_tool_elapsed_ms":tool["native_terminal"]["elapsed_ms"],
   "sidecar_state":"timed_out","effect_started":True,"no_effect_claim":False,
   "successful_open_verified":False,"image_input_count":0,"screenshot_or_input_or_tap_reached":False,
   "missing_postconditions":q["business_outcome"]["missing_postconditions"],
   "stderr_property_access_denial_counts":denied,
   "original_action_cleanup":{"waitpid_joined":True,"process_group_absent":True,"ledger_inspection_closed":True,
    "unresolved_effect":False,"business_effect_success":False,"automatic_replay":False},
   "model_cleanup":{"http_worker_joined":True,"slot_after_idle":True},
   "owner_draft_restored_exact":True,"owner_draft_submitted":False,"draft_restore_counts_as_business_return":False,
   "collector_process_exit_code":0,"capture_actor_exit_code":0,"capture_phone_exit_code":0,
   "collector_workflow_exit_code":c["collector_workflow_exit_code"],
   "original_provider_native_text_mismatch_preserved":True,
   "failure_reason":"The first mapped phone.open_app exceeded the original 60-second executor bound; raw stderr repeatedly denied servicemanager properties.",
   "uncertainty":"No per-command stage receipt: the exact blocked subprocess and whether any app launch effect occurred are not proven. Worker entry and safe cleanup are proven, never zero effect."})
 resource_rows=[];resource_values={}
 for phase in ("before-health","after-health","before-visual","after-visual","before-unicode","after-unicode"):
  name="resource-sampler-r7-r1/"+phase+"/REPORT.json";r=values[name];resource_values[phase]=r
  operation=R.json(base/("resource-sampler-r7-r1/"+phase+"/sample-r7-r1-resources-"+phase+"-01.original-operation.json"))
  require(operation["actor_rc"]==0 and operation["wrapper"]["phone"]["rc"]==0,"actual resource read terminals")
  require(sha(operation["wrapper"]["phone"]["stdout"].encode())==r["capture_sha256"],"resource original bytes binding")
  require(r["phase"]==phase and r["identity_verified"] is True and r["input_bindings_verified"] is True
   and r["frozen_combination_sha256"]==CANON and r["boot_id_matches"] is True,"resource role/full combination binding")
  require(r["clock_ticks_per_second"]["error"] is None and r["clock_ticks_per_second"]["value"]==100,"observed HZ")
  clean_roles={}
  for role,v in r["roles"].items():
   require(v["identity_verified"] is True and v["errors"]==[],"resource exact role identity")
   clean_roles[role]={"rss_kB":v["rss"]["value"],"hwm_kB":v["hwm"]["value"],
    "cpu_user_ticks":v["cpu_end"]["utime_ticks"],"cpu_system_ticks":v["cpu_end"]["stime_ticks"],
    "rss_error":v["rss"]["error"],"hwm_error":v["hwm"]["error"]}
  resource_rows.append({"phase":phase,"identity_verified":True,"full_combination_verified":True,"observed_clock_ticks_per_second":100,
   "roles":clean_roles,"system_mem_available_kB":r["system"]["mem_available"]["value"],
   "battery_vendor_raw":r["battery"],"uptime_observation_interval_seconds":[float(r["uptime.begin"]["value"].split()[0]),float(r["uptime.end"]["value"].split()[0])],
   "hardware_energy_joules":None,"monetary_cost":None})
 windows=[]
 for label in ("health","visual","unicode"):
  before=resource_values["before-"+label];after=resource_values["after-"+label];delta={}
  for role in ("model","provider","sidecar"):
   b=before["roles"][role];e=after["roles"][role]
   require(b["claim_identity"]==e["claim_identity"] and b["context"]==e["context"] and b["executable"]==e["executable"],"same resource process identity")
   du=e["cpu_begin"]["utime_ticks"]-b["cpu_end"]["utime_ticks"];ds=e["cpu_begin"]["stime_ticks"]-b["cpu_end"]["stime_ticks"]
   require(du>=0 and ds>=0,"monotonic process CPU counter")
   delta[role]={"user_seconds":du/100,"system_seconds":ds/100,"total_seconds":(du+ds)/100}
  window={"label":label,"cpu_deltas_seconds":delta,
   "observation_window_seconds":[float(after["uptime.begin"]["value"].split()[0])-float(before["uptime.end"]["value"].split()[0]),
     float(after["uptime.end"]["value"].split()[0])-float(before["uptime.begin"]["value"].split()[0])],
   "scope":"Whole interval between two non-atomic observations; includes idle/control/collection overhead, not per-request CPU attribution. Sidecar parent only, not its exited workers."}
  windows.append(window)
  if label!="health":
   row=next(x for x in rows if x["case_id"]=={"visual":"E2E-01","unicode":"E2E-02"}[label])
   row["resources"]={"read_only_phone_phases":["before-"+label,"after-"+label],"measurements":[x for x in resource_rows if x["phase"].endswith(label)],
    "window":window,"hardware_energy_joules":None,"monetary_cost":None}
   row["evidence"] += [ref(base,"resource-sampler-r7-r1/"+p+"/REPORT.json") for p in ("before-"+label,"after-"+label)]
 R.stable()
 attempts=write_new(out/"ATTEMPTS.private.json",jbytes(rows))
 auxiliary=[{"kind":"health","path":str(base/"health-r7-closure-r1/ROOT-CLOSURE.json"),
   "sha256":PINS["health-r7-closure-r1/ROOT-CLOSURE.json"],"observed_status":"PASS; exact new nonce, native completed, zero tools, original HTTP cleanup and slot idle; separate from business."}]
 aux=write_new(out/"AUXILIARY.private.json",jbytes(auxiliary))
 cmd=[sys.executable,"-B",str(base/"acceptance-r7/aggregate_protocol_r7.py"),
  "--combination",str(base/"acceptance-r7-host-negative-r1/inputs-r1/combination.json"),"--combination-sha256",COMBO,
  "--attempts",str(out/"ATTEMPTS.private.json"),"--auxiliary",str(out/"AUXILIARY.private.json"),"--out",str(out/"AGGREGATE.private.json")]
 t=time.monotonic();cp=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
 write_new(out/"AGGREGATOR.stdout",cp.stdout);write_new(out/"AGGREGATOR.stderr",cp.stderr)
 process={"schema":"hepta.quality-aggregation-process.v150.r7.1","exit_code":cp.returncode,"elapsed_seconds":time.monotonic()-t,
  "stdout_bytes":len(cp.stdout),"stdout_sha256":sha(cp.stdout),"stderr_bytes":len(cp.stderr),"stderr_sha256":sha(cp.stderr),
  "original_aggregator_sha256":AGG,"wait_returned":True,"phone_calls":0,"model_requests":0}
 write_new(out/"AGGREGATOR-PROCESS.json",jbytes(process));require(cp.returncode==0,"actual frozen aggregator failed")
 aggregate=R.json(out/"AGGREGATE.private.json")
 require(aggregate["case_status_counts"]=={"PASS":7,"FAIL":2,"BLOCKED":10}
  and aggregate["model_task_sample_count"]==2 and aggregate["model_complete_success_count"]==0
  and aggregate["current_attempt_record_count"]==14 and aggregate["combination_excluded"]==[]
  and aggregate["unbound_executed_current_source_attempts"]==0,"actual frozen aggregation result")
 require(aggregate["by_layer"]["model_e2e"]["outcomes"]["failed"]==2
  and aggregate["by_layer"]["host_isolated"]["attempts"]==11
  and aggregate["by_layer"]["component_direct"]["attempts"]==1
  and aggregate["by_layer"]["physical_native_task"]["attempts"]==0,"exact sample denominators")
 for case in aggregate["cases"]:
  if case["id"] in ("NEG-04","NEG-05","NEG-07","NEG-08","NEG-09"):
   require(case["status"]=="BLOCKED" and
    {x["layer"]:x["status"] for x in case["required_layers"]}=={"host_isolated":"PASS","physical_native_task":"BLOCKED"},"do not close physical gate by host")
 h=closures["health"];health={"samples":1,"passed":1,"failed":0,"native_status":"completed","exact_new_nonce_verified":True,
  "nonce_forced_by_output_grammar":False,"phone_tools":0,"http_elapsed_seconds":h["http_elapsed_seconds"],"model_usage":h["model_usage"],
  "native_persistence_interval_seconds":h["native_persistence_interval_seconds"],
  "native_terminal_observed_upper_seconds":h["native_terminal_observed_upper_seconds"],
  "http_worker_joined":True,"slot_after_idle":True,"proof_complete":True,
  "counts_as_business_or_fixed19":False,"owner_draft_restored_exact":True,"owner_draft_submitted":False}
 usage_total={k:sum(c["model_usage"][k] for c in closures.values()) for k in ("prompt_tokens","completion_tokens","total_tokens")}
 public={"schema":"hepta.quality-checkpoint-public.v150.r7.1","created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
  "state":"R7_R1_FROZEN_COMBINATION_MEASURED_NOT_DAILY_QUALIFIED","combination":combo,
  "combination_manifest_sha256":COMBO,"combination_canonical_sha256":CANON,"protocol_sha256":PROTOCOL,
  "case_status_counts":aggregate["case_status_counts"],"fixed_case_count":19,"all_19_cases_preserved":True,
  "required_19_protocol_closed":False,"daily_use_qualification_established":False,"qualification":aggregate["daily_use_reason"],
  "sample_counts":{"fixed19_executed_samples":14,"real_model_business_tasks":2,"separate_real_health_tasks":1,
    "host_isolated_samples":11,"component_direct_geometry_fixture_samples":1,"physical_negative_samples":0,
    "runtime_assertions":462,"additional_original_export_and_process_closure_assertions":14,
    "assertions_are_not_sample_count":True},
  "business_outcomes":{"complete_success":0,"verified_partial":0,"failed":2,"cancelled":0,"unconfirmed":0,"sample_count":2,"complete_fraction":0},
  "by_layer":aggregate["by_layer"],"cases":aggregate["cases"],"health":health,"model_business":business,
  "model_usage":{"business":aggregate["usage"],"health":h["model_usage"],"all_three_real_requests":usage_total,
   "all_three_real_requests_count":3,"host_fixtures_are_not_model_usage":True,
   "source":"Original phone-local HTTP receipts only. Health is outside the business denominator."},
  "business_http_timings":aggregate["timings"]["http_elapsed_seconds"],
  "native_latency_note":"Original collector native_end_to_end scalar is unavailable and remains null. Separate observer intervals and upper bounds are reported per task; they are not exact persisted event-time latency.",
  "resources":{"phases":resource_rows,"windows":windows,
   "limits":"Non-atomic file reads. RSS/HWM are snapshots and lifetime high-water marks. CPU deltas span wider observation windows and omit exited worker descendants. Battery values are vendor raw values; current_now=0 does not prove zero power.",
   "model_rss_min_kB":min(r["roles"]["model"]["rss_kB"] for r in resource_rows),
   "model_rss_max_kB":max(r["roles"]["model"]["rss_kB"] for r in resource_rows),
   "model_hwm_max_kB":max(r["roles"]["model"]["hwm_kB"] for r in resource_rows),
   "system_mem_available_min_kB":min(r["system_mem_available_kB"] for r in resource_rows)},
  "monetary_cost":None,"hardware_energy_joules":None,
  "recovery":{"business_recovery_attempts":0,"business_recovery_successes":0,
   "timed_out_original_actions_independently_closed":2,"original_action_replay":False,
   "draft_cleanup_attempts":3,"exact_original_drafts_restored":3,"original_draft_submissions":0,
   "cleanup_is_not_business_return_or_business_recovery_success":True},
  "negative_layers":{"host_pass_cases":[r["case_id"] for r in host_rows],
   "physical_followup_still_required":["NEG-04","NEG-05","NEG-07","NEG-08","NEG-09"],
   "synthetic_geometry_rejection_is_not_outer_screen_or_rotation_support":True},
  "native_integrity":{label:{k:v for k,v in n.items() if k not in ("unobserved_global_sequence_gaps",)} for label,n in native_summaries.items()},
  "failure_analysis":{"observed":"Both named model actions selected the correct registered app. Each first executor call timed out after repeated denial of servicemanager.installed/servicemanager.ready property reads.",
   "inference":"A worker-domain Android service/property access problem is supported by the raw stderr. The precise policy/type defect and blocked subprocess require separate evidence; this report does not infer them.",
   "not_demonstrated":["No successful app launch postcondition","No visual screenshot/grounding/click qualification","No Unicode exact input or public original-text readback","No business return to HEPTA"],
   "provider_native_error_text_difference_preserved":True,"both_original_proof_complete_remain_false":True},
  "instrumentation_notes":["Visual capture/export originals were complete; a later duplicate host export attempt was rejected by O_EXCL before another phone read. The original host collector completed separately with process exit0.",
   "Business collector child process exit0 means the evidence program completed; its workflow exit2 and failed/proof_complete=false remain unchanged.",
   "Failed and cancelled synthetic negative tasks may satisfy their guard protocol, but they are not successful real model business tasks."],
  "history_boundary":{"r6_r2_results_not_relabelled":True,"r6_r2_physical_cancel_slot_busy_failure_not_a_r7_sample":True,
   "future_r7_r2_policy_or_module_not_in_this_combination":True,"original_failures_and_claims_preserved":True},
  "remaining_work":["Qualify a separately versioned minimal Android property-access correction using exact compiled policy evidence, then a new bounded health request.",
   "Run fresh visual and Unicode tasks only after the new combination is ready; never replay these original requests, text or effects.",
   "E2E-03/E2E-04 and independent COMP-01/NEG-01/NEG-02 lack current-combination evidence; preserve their original protocol and tool budgets.",
   "Obtain separate physical samples for NEG-04/05/07/08/09 through the authorized native chain; host passes cannot close those gates.",
   "Use repeated representative business samples and measured resource/latency limits before daily-use qualification. Outer display, rotation and folding remain unqualified."],
  "publication_privacy":{"full_requests":False,"nonces":False,"draft_text_or_digest":False,"keys_or_key_digests":False,
   "claims_or_native_records":False,"actual_scope_action_or_process_identifiers":False},
  "provenance":{"original_host_five_attempts_sha256":PINS["acceptance-r7-host-cancel-faults-r1/ATTEMPTS.json"],
   "original_host_seven_attempts_sha256":PINS["acceptance-r7-host-negative-r1/ATTEMPTS.json"],
   "health_report_sha256":PINS["health-r7-originals-01/health-audit-01/REPORT.json"],
   "visual_report_sha256":PINS["visual-r7-originals-01/business-audit-01/REPORT.json"],
   "unicode_report_sha256":PINS["unicode-r7-originals-01/business-audit-01/REPORT.json"],
   "root_closure_sha256":{x:PINS[x+"-r7-closure-r1/ROOT-CLOSURE.json"] for x in ("health","visual","unicode")},
   "frozen_aggregator_sha256":AGG,"native_auditor_sha256":AUDITOR,"aggregation_process_exit_code":0},
  "report_operation":{"host_only":True,"phone_calls":0,"real_model_requests":0,"task_execution":False,"production_changes":0,"git_operations":0}}
 # Explicit allowlist projection above; no original scope/owner/action/nonce/claim is copied.
 pubraw=jbytes(public)
 private_values=[]
 for c in closures.values():
  for k in ("owner_utf8_sha256","native_request_sha256","sidecar_action_id","draft_cleanup_host_readback_sha256"):
   if c.get(k):private_values.append(c[k])
  private_values+=list(c["scope"].values())
 for q in reports.values():
  for item in q.get("inputs",[]):
   if item["source"].endswith("/task-contract.json"):
    contract=R.json(item["source"],item["sha256"])
    if isinstance(contract.get("nonce"),str):private_values.append(contract["nonce"])
 for value in private_values:
  if isinstance(value,str) and len(value)>=16:require(value.encode() not in pubraw,"public projection includes private identity")
 R.stable()
 public_ref=write_new(out/"QUALITY-PUBLIC.json",pubraw)
 # Immutable private evidence chain includes only named files actually read, not a recursive upload list.
 manifest={"schema":"hepta.quality-private-input-manifest.v150.r7.1","input_count":len(R.rows),"inputs":list(R.rows.values()),
  "all_inputs_stable_after_aggregation":True,"phone_calls":0,"real_model_requests":0,"source_operation":"read exported originals"}
 write_new(out/"INPUT-MANIFEST.private.json",jbytes(manifest))
 write_new(out/"RESULT.json",jbytes({"schema":"hepta.quality-checkpoint-result.v150.r7.1","state":"COMPLETED",
  "case_status_counts":aggregate["case_status_counts"],"executed_fixed19_samples":14,"separate_health_samples":1,
  "business_complete":0,"business_failed":2,"runtime_assertions":462,"closure_assertions":14,
  "aggregator_process_exit_code":0,"input_count":len(R.rows),"inputs_stable":True,"public_report":public_ref,
  "phone_calls":0,"real_model_requests":0,"production_changes":0,"new_test_cases_executed":0}))
 print(json.dumps({"state":"COMPLETED","case_status_counts":aggregate["case_status_counts"],"fixed19_samples":14,"health_samples":1,
  "public_report":public_ref,"input_count":len(R.rows),"phone_calls":0,"model_calls":0},ensure_ascii=False,sort_keys=True))
if __name__=="__main__":main()
