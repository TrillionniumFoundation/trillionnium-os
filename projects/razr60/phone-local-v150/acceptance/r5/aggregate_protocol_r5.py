#!/usr/bin/env python3
"""Host-only r5 fixed19 binding. No service, phone, socket, model or task call."""
import argparse,collections,hashlib,json,os,re,stat,types
from pathlib import Path
BASE=Path(__file__).resolve().parent
SOURCE_SHA="f3685aadb004882a3f087e42d43d374bd24564ad56eb472cb638b2f88e96935f"
SERVICE_SHA="ccb7cacf0dd9e4e12daba09515a56633363dd9f04607b44546df1e493d15bfd2"
CONFIG_SHA="0eb740aea8591a0377bc9ceecafb4b848a9dcdd7dc2cb75ffc3f0892abe5c755"
ORIGINAL_PROTOCOL_SHA="c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0"
AGGREGATOR_SHA="9f0d0088eea2bd9962180bbe710266228717905a3f1c695b0192b867f4e73772"
MATERIALIZER_SHA="f2b2416cd895e9235fc36cbad07cc32f763420410fc48829c99ac9c566a3fb81"
DYNAMIC_PINS=("module_manifest_sha256","policy_rules_manifest_sha256",
 "live_policy_snapshot_sha256","live_policy_semantic_audit_sha256",
 "native_and_apps_manifest_sha256")
FIXED={"schema":"hepta.acceptance-combination.v150.r5.1","release":"v150-r5",
 "provider_source_seal_sha256":SOURCE_SHA,"service_inputs_sha256":SERVICE_SHA,
 "provider_config_sha256":CONFIG_SHA,"model_route":"phone_local_cpu","cloud_fallback":False}
IDS=["E2E-"+str(i).zfill(2) for i in range(1,5)]+["COMP-01"]+["NEG-"+str(i).zfill(2) for i in range(1,15)]
AUXILIARY_KINDS={"health","native_component","recovery_event","host_validation"}
def require(ok,label):
 if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):
 return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def strict(raw):
 def pairs(items):
  out={}
  for key,value in items:
   require(key not in out,"duplicate_json_key");out[key]=value
  return out
 return json.loads(raw,object_pairs_hook=pairs,
  parse_constant=lambda _:(_ for _ in ()).throw(ValueError("nonfinite_json")))
def read(path,limit=8*1024*1024):
 path=Path(path).absolute()
 require(path.parent.resolve()==path.parent,"noncanonical_parent")
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit,"regular_file_bound")
  with os.fdopen(fd,"rb",closefd=False) as f:raw=f.read(limit+1)
  after,named=os.fstat(fd),path.lstat()
  require(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k)
   for k in ("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")),"input_changed_or_incomplete")
 finally:os.close(fd)
 return raw
def write_new(path,raw):
 path=Path(path).absolute();require(path.parent.resolve()==path.parent,"noncanonical_output_parent")
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
 d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(d)
 finally:os.close(d)
 return {"path":str(path),"bytes":len(raw),"sha256":sha(raw)}
def frozen_module(name,expected):
 path=BASE/"references"/name;raw=read(path)
 require(sha(raw)==expected,"frozen_reference_sha256")
 m=types.ModuleType("frozen_"+name.replace(".","_"));m.__file__=str(path)
 exec(compile(raw,str(path),"exec"),m.__dict__)
 return m
def validate_protocol():
 old_raw=read(BASE/"references/fixed-acceptance-set-r4.original.json")
 require(sha(old_raw)==ORIGINAL_PROTOCOL_SHA,"original_fixed19_sha256")
 old=strict(old_raw);new_raw=read(BASE/"fixed-acceptance-set-r5.json");new=strict(new_raw)
 require([c["id"] for c in old["cases"]]==IDS,"original_fixed19_ids")
 require([c["id"] for c in new["cases"]]==IDS and new["case_count"]==19,"r5_fixed19_ids")
 allowed={"candidate_manifest_sha256","set_id","current_global_blocker"}
 require(set(new)==set(old)|{"r5_binding"},"protocol_fields_added_or_removed")
 for key in old:
  if key not in allowed:require(new[key]==old[key],"protocol_semantics_changed:"+key)
 require(new["cases"]==old["cases"] and new["limits"]==old["limits"]
  and new["qualified_geometry"]==old["qualified_geometry"],"fixed19_cases_limits_geometry_changed")
 require(new["candidate_manifest_sha256"]==SOURCE_SHA and new["set_id"]=="stock16-phone-local-fixed-set-r5","r5_source_metadata")
 b=new["r5_binding"]
 require(b["original_protocol_sha256"]==ORIGINAL_PROTOCOL_SHA and
  b["provider_source_seal_sha256"]==SOURCE_SHA and b["service_inputs_sha256"]==SERVICE_SHA and
  b["provider_config_sha256"]==CONFIG_SHA and b["full_production_combination_required"] is True,"r5_binding")
 return new,sha(new_raw),old["candidate_manifest_sha256"]
def validate_combination(value):
 require(isinstance(value,dict) and set(value)==set(FIXED)|{"state"}|set(DYNAMIC_PINS),"combination_fields")
 require(all(value[k]==v and type(value[k]) is type(v) for k,v in FIXED.items()),"combination_fixed_inputs")
 require(value["state"] in ("pending","frozen"),"combination_state")
 missing=[]
 for key in DYNAMIC_PINS:
  v=value[key]
  if v is None:missing.append(key)
  else:require(isinstance(v,str) and re.fullmatch("[0-9a-f]{64}",v) is not None,"combination_pin_shape:"+key)
 require(value["state"]!="frozen" or not missing,"frozen_combination_missing_real_pins")
 return {"combination_sha256":sha(canonical(value)),"state":value["state"],
  "frozen":value["state"]=="frozen","missing_inputs":missing}
def load_combination(path,expected_raw_sha):
 raw=read(path,32768);require(sha(raw)==expected_raw_sha,"selected_combination_raw_sha256")
 value=strict(raw);meta=validate_combination(value);meta["manifest_sha256"]=sha(raw)
 meta["manifest_path"]=str(Path(path).absolute());meta["value"]=value
 return meta
def partition_attempts(attempts,selected,attempt_base=None):
 require(isinstance(attempts,list),"attempts_array")
 current,excluded,ids=[],[],set();unbound_current=0
 for row in attempts:
  require(isinstance(row,dict) and row.get("case_id") in IDS,"fixed19_only_auxiliary_goes_separately")
  ident=row.get("attempt_id");require(isinstance(ident,str) and ident and ident not in ids,"attempt_id_unique")
  ids.add(ident);source=row.get("candidate_manifest_sha256")
  require(isinstance(source,str) and re.fullmatch("[0-9a-f]{64}",source) is not None,"attempt_source_pin")
  key=row.get("combination_sha256")
  if key==selected["combination_sha256"]:
   require(source==SOURCE_SHA,"same_combo_different_provider_source")
   require(row.get("combination_manifest_sha256")==selected["manifest_sha256"],"current_combo_manifest_raw_sha")
   if not selected["frozen"]:
    require(row.get("task_outcome")=="not_run" and row.get("protocol_result") in ("BLOCKED","NOT_RUN"),
      "pending_combination_cannot_admit_executed_sample")
   current.append(dict(row))
  else:
   if key is None:
    reason="No complete combination binding; excluded and retained, never silently assigned by source."
    if source==SOURCE_SHA and row.get("task_outcome")!="not_run":unbound_current+=1
   else:
    require(isinstance(key,str) and re.fullmatch("[0-9a-f]{64}",key) is not None,"foreign_combo_shape")
    ref=row.get("combination_manifest")
    if source==SOURCE_SHA and ref is not None:
     require(isinstance(ref,dict) and set(ref)=={"path","sha256"},"foreign_combination_reference")
     path=Path(ref["path"])
     if not path.is_absolute():
      require(attempt_base is not None,"foreign_combination_base_required");path=Path(attempt_base)/path
     foreign=load_combination(path,ref["sha256"])
     require(foreign["combination_sha256"]==key and foreign["frozen"]
      and row.get("combination_manifest_sha256")==foreign["manifest_sha256"],"foreign_combination_binding")
     reason="Verified different full frozen r5 combination; retained separately even though source matches."
    else:
     reason="Different declared combination; full foreign-combination provenance is not verified here."
     if source==SOURCE_SHA and row.get("task_outcome")!="not_run":unbound_current+=1
   excluded.append({"attempt_id":ident,"case_id":row["case_id"],"candidate_manifest_sha256":source,
    "combination_sha256":key,"task_outcome":row.get("task_outcome"),
    "protocol_result":row.get("protocol_result"),"attempt_record_sha256":sha(canonical(row)),"excluded_reason":reason})
 return current,excluded,unbound_current
def read_auxiliary(path):
 if path is None:return [],None
 raw=read(path);items=strict(raw);require(isinstance(items,list),"auxiliary_array")
 out=[]
 for item in items:
  require(isinstance(item,dict) and set(item)=={"kind","path","sha256","observed_status"},"auxiliary_fields")
  require(item["kind"] in AUXILIARY_KINDS and isinstance(item["observed_status"],str),"auxiliary_kind")
  p=Path(item["path"]);p=p if p.is_absolute() else Path(path).absolute().parent/p
  evidence=read(p,64*1024*1024);require(sha(evidence)==item["sha256"],"auxiliary_original_sha256")
  out.append({**item,"path":str(p),"bytes":len(evidence),"counts_as_fixed19_case":False,
   "counts_as_model_business_sample":False,"qualification":"Retained separately; observed_status is operator classification, not automatic PASS verification."})
 return out,sha(raw)
def aggregate_bound(protocol,selected,attempts,attempt_base,auxiliary):
 current,excluded,unbound=partition_attempts(attempts,selected,attempt_base)
 m=frozen_module("aggregate_protocol_r4.py",AGGREGATOR_SHA)
 result=m.aggregate(protocol,current,Path(attempt_base))
 result["schema"]="hepta.fixed19-quality-report.v150.r5.1"
 result["selected_combination"]={k:v for k,v in selected.items() if k!="value"}
 result["selected_combination_inputs"]=selected["value"]
 result["combination_excluded"]=excluded
 result["unbound_executed_current_source_attempts"]=unbound
 result["input_attempt_record_count"]=len(attempts)
 result["current_attempt_record_count"]=len(current)
 result["auxiliary_evidence"]=auxiliary
 result["auxiliary_record_counts"]=dict(collections.Counter(r["kind"] for r in auxiliary))
 if not selected["frozen"] or unbound:
  result["required_19_protocol_closed"]=False
 result["combination_qualification_gate"]={"frozen_inputs":selected["frozen"],
  "unbound_current_source_attempts_clear":unbound==0,
  "pending_is_not_a_frozen_production_release":True,
  "module_policy_and_native_app_hashes_must_be_bound_before_samples":True}
 result["historical_outcomes_rewritten"]=False
 result["component_health_recovery_in_business_denominator"]=False
 result["source_only_grouping_forbidden"]=True
 result["aggregation_operation"]={"host_only":True,"phone_calls":0,"model_calls":0,"service_changes":0,"task_execution":False}
 return result
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--combination",type=Path,required=True)
 p.add_argument("--combination-sha256",required=True)
 p.add_argument("--attempts",type=Path,required=True)
 p.add_argument("--auxiliary",type=Path)
 p.add_argument("--out",type=Path,required=True)
 a=p.parse_args();protocol,protocol_sha,old_source=validate_protocol()
 selected=load_combination(a.combination,a.combination_sha256)
 raw=read(a.attempts);attempts=strict(raw)
 auxiliary,auxsha=read_auxiliary(a.auxiliary)
 result=aggregate_bound(protocol,selected,attempts,a.attempts.absolute().parent,auxiliary)
 result.update(protocol_sha256=protocol_sha,original_protocol_sha256=ORIGINAL_PROTOCOL_SHA,
  original_protocol_candidate_source_sha256=old_source,attempts_sha256=sha(raw),auxiliary_input_sha256=auxsha,
  source_binding="Provider r5 f368..., service-inputs-r3 ccb7..., and exact full combination; no source-only mixing.")
 record=write_new(a.out,(json.dumps(result,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode())
 print(json.dumps({"report":record,"cases":len(result["cases"]),"case_status_counts":result["case_status_counts"],
  "model_task_sample_count":result["model_task_sample_count"],"complete_fraction":result["model_complete_success_fraction"],
  "full_combination_frozen":selected["frozen"],"required19_closed":result["required_19_protocol_closed"],
  "phone_calls":0,"model_calls":0},sort_keys=True))
if __name__=="__main__":main()
