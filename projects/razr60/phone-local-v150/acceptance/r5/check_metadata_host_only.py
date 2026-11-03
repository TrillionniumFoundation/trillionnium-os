#!/usr/bin/env python3
"""Host-only metadata assertions. All constructed nonempty rows are explicitly synthetic."""
import copy,hashlib,json,tempfile
from pathlib import Path
import aggregate_protocol_r5 as b
BASE=Path(__file__).resolve().parent
checks=[]
def check(name,condition):
 if not condition:raise AssertionError(name)
 checks.append({"name":name,"passed":True})
def rejects(name,fn):
 try:fn()
 except (ValueError,KeyError,TypeError):check(name,True)
 else:raise AssertionError(name)
protocol,protocol_sha,_=b.validate_protocol()
pending_raw=b.read(BASE/"COMBINATION-PENDING.json")
pending=b.load_combination(BASE/"COMBINATION-PENDING.json",b.sha(pending_raw))
check("all_original19_case_objects_limits_geometry_unchanged",len(protocol["cases"])==19)
check("actual_inputs_remain_empty",b.strict(b.read(BASE/"EMPTY-ACTUAL-ATTEMPTS.json"))==[])
check("pending_has_actual_known_pins_and_null_future_pins",not pending["frozen"] and len(pending["missing_inputs"])==5)
current,excluded,unbound=b.partition_attempts([],pending,BASE)
check("actual_zero_partition",current==excluded==[] and unbound==0)
zero=b.strict(b.read(BASE/"validation/EMPTY-CURRENT-REPORT.json"))
check("actual_report_19_preserved_all_blocked",len(zero["cases"])==19 and zero["case_status_counts"]=={"BLOCKED":19})
check("actual_report_model_denominator_zero_and_fraction_null",zero["model_task_sample_count"]==0 and zero["model_complete_success_fraction"] is None)
check("actual_report_not_qualified",not zero["required_19_protocol_closed"] and not zero["daily_use_qualification_established"])
check("actual_report_auxiliary_zero",zero["auxiliary_evidence"]==[] and zero["input_attempt_record_count"]==0)
check("actual_report_all_layer_counts_zero",all(v["attempts"]==0 for v in zero["by_layer"].values()))
# Synthetic fixtures below do not enter EMPTY-ACTUAL-ATTEMPTS or any quality denominator.
a=copy.deepcopy(pending["value"]);a["state"]="frozen"
for name in b.DYNAMIC_PINS:a[name]=b.sha(("SYNTHETIC_HOST_TEST_NOT_A_PRODUCTION_ARTIFACT:"+name+":A").encode())
def metadata(value):
 raw=(json.dumps(value,sort_keys=True,indent=2)+"\n").encode();m=b.validate_combination(value)
 m.update(manifest_sha256=b.sha(raw),manifest_path="synthetic-fixture-only",value=value)
 return m,raw
ma,ra=metadata(a)
changed=copy.deepcopy(a);changed["policy_rules_manifest_sha256"]=b.sha(b"SYNTHETIC_HOST_TEST_POLICY_B")
mb,rb=metadata(changed)
check("same_source_different_policy_has_different_full_combo_id",ma["combination_sha256"]!=mb["combination_sha256"])
other_module=copy.deepcopy(a);other_module["module_manifest_sha256"]=b.sha(b"SYNTHETIC_HOST_TEST_MODULE_B")
mc,_=metadata(other_module)
check("same_source_different_module_has_different_full_combo_id",ma["combination_sha256"]!=mc["combination_sha256"])
row={"case_id":"E2E-01","attempt_id":"SYNTHETIC-NOT-A-PHONE-ATTEMPT",
 "candidate_manifest_sha256":b.SOURCE_SHA,"combination_sha256":pending["combination_sha256"],
 "combination_manifest_sha256":pending["manifest_sha256"],"protocol_result":"FAIL","task_outcome":"failed"}
rejects("pending_cannot_admit_executed_sample",lambda:b.partition_attempts([row],pending,BASE))
wrong=dict(row,case_id="R6-IPC-COMPONENT")
rejects("component_probe_cannot_be_a_fixed19_attempt",lambda:b.partition_attempts([wrong],pending,BASE))
with tempfile.TemporaryDirectory(prefix="group-fixture-",dir=BASE/"validation") as directory:
 p=Path(directory)/"SYNTHETIC-COMBINATION-B.json";p.write_bytes(rb)
 foreign=dict(row,combination_sha256=mb["combination_sha256"],
  combination_manifest_sha256=mb["manifest_sha256"],
  combination_manifest={"path":str(p),"sha256":b.sha(rb)})
 c,e,q=b.partition_attempts([foreign],ma,BASE)
 check("foreign_same_source_verified_combo_is_separate_not_current",c==[] and len(e)==1 and q==0)
 check("foreign_original_failure_retained",e[0]["task_outcome"]=="failed" and e[0]["protocol_result"]=="FAIL")
 unverified=dict(foreign);del unverified["combination_manifest"]
 c,e,q=b.partition_attempts([unverified],ma,BASE)
 check("unverified_foreign_current_source_blocks_qualification",c==[] and len(e)==1 and q==1)
bad=copy.deepcopy(a);bad["module_manifest_sha256"]=None
rejects("frozen_cannot_contain_null_module_pin",lambda:b.validate_combination(bad))
bad=copy.deepcopy(a);bad["provider_source_seal_sha256"]="0"*64
rejects("other_provider_cannot_be_relabelled_r5",lambda:b.validate_combination(bad))
result={"schema":"hepta.acceptance-r5.host-metadata-validation.v150.1","state":"PASS",
 "checks":checks,"check_count":len(checks),"actual_business_attempts":0,"actual_phone_calls":0,
 "actual_model_requests":0,"synthetic_grouping_fixtures_are_not_samples":True,
 "selected_combination_frozen":False,"production_module_policy_native_app_pins_pending":True,
 "actual_zero_report_sha256":b.sha(b.read(BASE/"validation/EMPTY-CURRENT-REPORT.json")),
 "unchanged_original_protocol_sha256":b.ORIGINAL_PROTOCOL_SHA,"r5_protocol_sha256":protocol_sha}
artifact=b.write_new(BASE/"validation/HOST-METADATA-CHECKS.json",(json.dumps(result,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps({"result":artifact,"checks":len(checks),"actual_business_attempts":0,"actual_phone_calls":0},sort_keys=True))
