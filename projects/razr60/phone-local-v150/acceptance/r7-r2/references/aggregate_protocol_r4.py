#!/usr/bin/env python3
"""Aggregate the unchanged fixed 19 cases from explicitly supplied evidence.

Never executes a case. Missing cases/layers remain BLOCKED. Model E2E PASS
requires a matching collector report with complete_business_success=true.
Recovery counts are separate from original task outcomes; no old result changes.
"""
import argparse
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

IDS=["E2E-"+str(i).zfill(2) for i in range(1,5)]+["COMP-01"]+[
    "NEG-"+str(i).zfill(2) for i in range(1,15)]
OUTCOMES=("complete_success","partial","failed","cancelled","unconfirmed","not_run")

def sha(raw): return hashlib.sha256(raw).hexdigest()
def require(ok,message):
    if not ok: raise ValueError(message)
def read(path,maximum=8*1024*1024):
    path=Path(path).absolute()
    require(path.parent.resolve()==path.parent,"noncanonical input parent")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1
                and 0<=before.st_size<=maximum,"input identity/size differs")
        with os.fdopen(fd,"rb",closefd=False) as stream: raw=stream.read(maximum+1)
        after,named=os.fstat(fd),path.lstat()
        require(len(raw)==before.st_size and all(
            getattr(before,k)==getattr(after,k)==getattr(named,k)
            for k in ("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")),
            "input changed during read")
    finally: os.close(fd)
    return raw

def described(values):
    if not values:
        return {"samples":0,"min":None,"p50":None,"p95":None,"max":None,"mean":None}
    values=sorted(values)
    def quantile(q):
        point=(len(values)-1)*q
        low=math.floor(point);high=math.ceil(point)
        return values[low]+(values[high]-values[low])*(point-low)
    return {"samples":len(values),"min":values[0],"p50":quantile(.5),"p95":quantile(.95),
            "max":values[-1],"mean":sum(values)/len(values),
            "quantile_method":"linear interpolation; descriptive only"}

def aggregate(protocol,attempts,base):
    require([item["id"] for item in protocol["cases"]]==IDS and protocol["case_count"]==19,
            "the fixed 19 case identities/order differ")
    candidate=protocol["candidate_manifest_sha256"]
    require(re.fullmatch("[0-9a-f]{64}",candidate or ""),"protocol lacks final candidate seal")
    current,historical=[],[]
    seen_ids,seen_nonces=set(),set()
    source_rows=[]
    for original in attempts:
        row=dict(original)
        require(row.get("case_id") in IDS,"attempt names a case outside fixed 19")
        require(row.get("layer") in {"model_e2e","component_direct","host_isolated","physical_native_task"},
                "attempt layer unknown")
        require(row.get("protocol_result") in {"PASS","FAIL","BLOCKED","NOT_RUN"},"protocol_result unknown")
        require(row.get("task_outcome") in OUTCOMES,"task outcome unknown")
        attempt_id=row.get("attempt_id")
        require(isinstance(attempt_id,str) and attempt_id and attempt_id not in seen_ids,
                "attempt ID absent or duplicated")
        seen_ids.add(attempt_id)
        if row.get("candidate_manifest_sha256")!=candidate:
            historical.append({"attempt_id":attempt_id,"case_id":row["case_id"],
                "candidate_manifest_sha256":row.get("candidate_manifest_sha256"),
                "excluded_reason":"different frozen combination; not in current denominators"})
            continue
        nonce=row.get("nonce")
        if nonce is not None:
            require(isinstance(nonce,str) and re.fullmatch("[A-Za-z0-9_-]{16,64}",nonce)
                    and nonce not in seen_nonces,"fresh nonce absent/malformed/reused across current attempts")
            seen_nonces.add(nonce)
        evidence=[]
        for item in row.get("evidence",[]):
            require(set(item)=={"path","sha256"},"evidence reference fields differ")
            path=Path(item["path"])
            if not path.is_absolute(): path=base/path
            raw=read(path,64*1024*1024)
            require(sha(raw)==item["sha256"],"evidence byte hash differs")
            evidence.append({"path":str(path),"sha256":sha(raw),"bytes":len(raw)})
        row["verified_evidence"]=evidence
        report=None
        if row.get("collector_report"):
            item=row["collector_report"]
            path=Path(item["path"])
            if not path.is_absolute(): path=base/path
            raw=read(path,64*1024*1024)
            require(sha(raw)==item["sha256"],"collector report byte hash differs")
            report=json.loads(raw)
            require(report.get("case_id")==row["case_id"] and
                    report.get("candidate_source_seal_sha256")==candidate,
                    "collector case/candidate differs")
            evidence.append({"path":str(path),"sha256":sha(raw),"bytes":len(raw)})
            row["model_usage"]={field:report.get(field+"_sum")
                               for field in ("prompt_tokens","completion_tokens","total_tokens")}
            row["http_elapsed_seconds"]=report.get("http_elapsed_seconds_sum")
            row["native_end_to_end_latency_seconds"]=report.get("native_end_to_end_latency_seconds")
            row["model_request_count"]=report.get("observed_model_request_count")
            if report.get("complete_business_success") is True:
                require(row["task_outcome"]=="complete_success","verified business outcome mislabeled")
            elif row["task_outcome"]=="complete_success":
                raise ValueError("task claimed complete without independent complete_business_success")
        if row["protocol_result"]=="PASS":
            require(evidence,"PASS lacks retained evidence")
            if row["layer"]=="model_e2e":
                require(nonce and report and report.get("complete_business_success") is True,
                        "model E2E PASS requires fresh fully verified collector evidence")
            else:
                checks=row.get("assertions")
                require(isinstance(checks,list) and checks and all(
                    isinstance(check,dict) and set(check)=={"name","passed"}
                    and isinstance(check["name"],str) and check["name"]
                    and check["passed"] is True for check in checks),
                    "non-model PASS requires explicit evidence-backed assertions")
        if row["protocol_result"] in {"BLOCKED","NOT_RUN"}:
            require(row.get("reason"),"blocked/unrun case needs its real reason")
            require(row["task_outcome"]=="not_run","unrun attempt cannot carry an executed task outcome")
        if row.get("recovery"):
            require(isinstance(row["recovery"],dict)
                    and row["recovery"].get("status") in {"complete","partial","failed","unconfirmed"}
                    and row["recovery"].get("original_action_receipt_read") is True
                    and row["recovery"].get("old_action_replayed") is False,
                    "recovery must first read original receipt and never replay the old action")
        source_rows.extend(evidence)
        current.append(row)
    cases=[]
    for case in protocol["cases"]:
        rows=[row for row in current if row["case_id"]==case["id"]]
        required=case.get("required_qualification_layers",[case["layer"]])
        layers=[]
        for layer in required:
            matching=[row for row in rows if row["layer"]==layer]
            outcomes=[row["protocol_result"] for row in matching]
            status=("FAIL" if "FAIL" in outcomes else "PASS" if "PASS" in outcomes
                    else "BLOCKED")
            layers.append({"layer":layer,"status":status,
                "attempts":len(matching),"reason":None if status!="BLOCKED" else
                    ("; ".join(str(row.get("reason","")) for row in matching)
                     or "No current-combination evidence was supplied for this required layer.")})
        status="FAIL" if any(x["status"]=="FAIL" for x in layers) else (
            "PASS" if all(x["status"]=="PASS" for x in layers) else "BLOCKED")
        cases.append({"id":case["id"],"title":case["title"],"status":status,
                      "required_layers":layers,"attempt_count":len(rows),
                      "original_task_outcomes":dict(collections.Counter(
                          row["task_outcome"] for row in rows if row["task_outcome"]!="not_run")),
                      "recovery_attempts":sum(bool(row.get("recovery")) for row in rows)})
    model=[row for row in current if row["layer"]=="model_e2e" and row["task_outcome"]!="not_run"]
    by_layer={}
    for layer in ("model_e2e","component_direct","host_isolated","physical_native_task"):
        rows=[row for row in current if row["layer"]==layer and row["task_outcome"]!="not_run"]
        by_layer[layer]={"attempts":len(rows),"outcomes":{
            name:sum(row["task_outcome"]==name for row in rows) for name in OUTCOMES[:-1]},
            "recovery_attempts":sum(bool(row.get("recovery")) for row in rows)}
    usage={}
    for field in ("prompt_tokens","completion_tokens","total_tokens"):
        values=[row.get("model_usage",{}).get(field) for row in model]
        known=[value for value in values if type(value) is int and value>=0]
        usage[field]={"known_sum":sum(known) if known else None,"known_samples":len(known),
                      "missing_samples":len(values)-len(known),"complete_total":sum(known) if values and len(known)==len(values) else None}
    timings={}
    for field in ("http_elapsed_seconds","native_end_to_end_latency_seconds"):
        values=[row.get(field) for row in model]
        timings[field]=described([value for value in values if type(value) in (int,float)
                                 and math.isfinite(value) and value>=0])
        timings[field]["missing_samples"]=len(values)-timings[field]["samples"]
    recovery=collections.Counter(row["recovery"]["status"] for row in current if row.get("recovery"))
    passed=sum(row["status"]=="PASS" for row in cases)
    full=sum(row["task_outcome"]=="complete_success" for row in model)
    return {"schema":"hepta.fixed19-quality-report.v150.1",
        "candidate_manifest_sha256":candidate,"fixed_case_count":19,"cases":cases,
        "case_status_counts":dict(collections.Counter(row["status"] for row in cases)),
        "required_19_protocol_closed":passed==19,"all_cases_preserved":True,
        "by_layer":by_layer,"model_task_sample_count":len(model),
        "model_complete_success_count":full,"model_complete_success_fraction":full/len(model) if model else None,
        "usage":usage,"timings":timings,"recovery_status_counts":dict(recovery),
        "recovery_counting":"Separate cross-cutting events. Original task terminals remain unchanged.",
        "monetary_cost":None,"hardware_energy_joules":None,
        "resource_measurements":[{"attempt_id":row["attempt_id"],"measurements":row["resources"]}
                                 for row in current if row.get("resources") is not None],
        "resource_missing_samples":sum(row.get("resources") is None for row in model),
        "daily_use_qualification_established":False,
        "daily_use_reason":"The fixed protocol forbids a general daily reliability claim from one suite; repeated representative samples and measured limits are still required.",
        "model_e2e_denominator":"Only executed model_e2e tasks of this exact frozen combination; excludes health, direct components, isolated fixtures, blocked cases and historical runs.",
        "historical_excluded":historical,"source_evidence":source_rows,
        "automatic_task_execution":False,"actual_phone_actions":0,"actual_model_requests":0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--protocol",type=Path,required=True)
    p.add_argument("--attempts",type=Path,required=True,help="Root-owned JSON array with evidence hashes and actual outcomes")
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    protocol_raw,attempts_raw=read(args.protocol),read(args.attempts)
    protocol,attempts=json.loads(protocol_raw),json.loads(attempts_raw)
    require(isinstance(attempts,list),"attempts must be an array")
    result=aggregate(protocol,attempts,args.attempts.absolute().parent)
    result["protocol_sha256"]=sha(protocol_raw)
    result["attempts_sha256"]=sha(attempts_raw)
    out=args.out.absolute()
    require(out.parent.resolve()==out.parent,"noncanonical output parent")
    raw=(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
    print(json.dumps({"report":str(out),"sha256":sha(raw),"case_status_counts":result["case_status_counts"],
        "model_task_sample_count":result["model_task_sample_count"],
        "daily_use_qualification_established":False,"automatic_task_execution":False},separators=(",",":")))

if __name__=="__main__": main()
