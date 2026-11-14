#!/usr/bin/env python3
"""Bounded mixed-UID regression on production parser/exclusion; no real signals."""
import argparse,copy,hashlib,importlib.util,json,os,shutil,subprocess,sys,time
from pathlib import Path

def need(value,message):
    if not value:raise AssertionError(message)
def sha(data):return hashlib.sha256(data).hexdigest()
def pin(path):
    data=path.read_bytes();return {"path":str(path),"bytes":len(data),"sha256":sha(data)}
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module
def save(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as stream:stream.write(data)
def enc(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","cc"):parser.add_argument("--"+name,type=Path,required=True)
    a=parser.parse_args()
    need(all(p.is_absolute() for p in vars(a).values()),"absolute paths required")
    a.cc=a.cc.resolve(strict=True)
    a.output.mkdir(parents=True,exist_ok=False)
    result={"schema":"hepta.owned-generation-mixed-uid-gate.v1","all_pass":False,
            "phone_operations":0,"sdk_executed":False,"real_process_signals":False,
            "proc_boundary":"synthetic status/stat files, real held-directory openat reads; no complete live proc visibility claim"}
    inputs={};steps=[];records=[];assertions=0
    def capture(path):
        need(path.is_file() and not path.is_symlink(),"ordinary input "+str(path))
        raw=path.read_bytes();inputs[path]=raw;return raw
    def check(value,message):
        nonlocal assertions
        assertions+=1;need(value,message)
    def run(name,argv,timeout=60):
        began=time.monotonic()
        c=subprocess.run(list(map(str,argv)),capture_output=True,timeout=timeout)
        save(a.output/(name+".stdout"),c.stdout);save(a.output/(name+".stderr"),c.stderr)
        steps.append({"name":name,"argv":list(map(str,argv)),"exit_code":c.returncode,
                      "elapsed_seconds":time.monotonic()-began,"stdout":pin(a.output/(name+".stdout")),
                      "stderr":pin(a.output/(name+".stderr"))})
        need(c.returncode==0,name+": "+c.stderr.decode(errors="replace"))
        return c
    try:
        for p in sorted(a.source.rglob("*")):
            if p.is_file():capture(p)
        capture(a.cc);cxx=Path(shutil.which("c++") or "").resolve(strict=True);capture(cxx)
        test=a.source/"tests/owned-generation-mixed-uid";native=a.source/"native"
        fixture=test/"fixtures"
        case=json.loads(capture(fixture/"ci-b316-empty-RESULT.json"))
        traces=capture(fixture/"ci-b316-helper.stderr").decode().splitlines()
        first=json.loads(next(x[len("HEPTA_HOST_PROC_REJECTION "):] for x in traces
                            if x.startswith("HEPTA_HOST_PROC_REJECTION ")))
        need(first["reason"]=="uid_unresolved" and first["kind"]=="uid_values_differ"
             and first["stat_valid"] and first["uid_parse_valid"],"actual trace shape")
        observed={"pid":first["pid"],"ppid":1,"pgid":first["pgid"],"start":first["start_ticks"],
                  "uids":first["uid_values"],"state":"S"}
        leader=case["native"]
        need(observed["start"]<leader["leader_start_ticks"] and observed["pgid"]!=leader["pgid"],
             "actual trace older and different group")
        result["actual_fixture"]={"result":pin(fixture/"ci-b316-empty-RESULT.json"),
                                 "stderr":pin(fixture/"ci-b316-helper.stderr"),
                                 "observed_scalars":first,"synthetic_fields":["PPID=1","state=S","other stat/status columns"],
                                 "old_strict_uniform_uid_rejects":True}
        # The retained compiler composes the real generator and prior harness.
        # Its source and assertions remain byte-for-byte; no retained case is replaced.
        retained=load("mixed_uid_retained_native",a.source/"tests/owned-generation-cleanup/native_cases.py")
        compiled=a.output/"compile";compiled.mkdir()
        retained.compile_fixture(a.source,compiled,str(a.cc))
        original=(compiled/"normal.c").read_text()
        needle="int main(int argc,char **argv){return hepta_scope_fixture(argc,argv);}"
        need(original.count(needle)==1,"retained main exact anchor")
        code=original.replace(needle,"int hepta_retained_scope_main(int argc,char **argv){return hepta_scope_fixture(argc,argv);}")
        code+=capture(test/"mixed_uid_main.c").decode()
        generated=a.output/"mixed-uid.c";save(generated,code.encode())
        inc=["-I"+str(compiled/"generated"),"-I"+str(native),"-I"+str(native/"vendor"),
             "-I"+str(native/"vendor/llama")]
        obj=a.output/"mixed-uid.o";binary=a.output/"mixed-uid"
        run("mixed-uid-compile",[a.cc,"-std=c11","-Wall","-Wextra","-Werror","-O1","-fexceptions",
            "-DHEPTA_SDK_EXCEPTION_BOUNDARY=1","-DHEPTA_OWNED_GENERATION_HOST_TRACE=1",
            *inc,"-c",generated,"-o",obj])
        run("mixed-uid-link",[cxx,obj,compiled/"boundary.o","-o",binary])
        result["retained_compile_receipt"]=pin(compiled/"COMPILE.json")
        def stat_bytes(v):
            fields=[v["state"],str(v["ppid"]),str(v["pgid"])]+["0"]*16+[str(v["start"])]+["0"]*30
            return (str(v["pid"])+" (synthetic mixed uid fixture) "+" ".join(fields)+"\n").encode()
        def status_bytes(v):return ("Name:\tmixed_uid_fixture\nUid:\t"+"\t".join(map(str,v["uids"]))+"\n").encode()
        specs=[]
        def add(name,before=None,after=None,excluded=False,stat_ok=True,kind=2,strict=False,
                before_stat="auto",before_uid="auto",after_stat="auto",after_uid="auto",pid=None):
            specs.append(dict(name=name,before=before or copy.deepcopy(observed),
                  after=after or copy.deepcopy(observed),excluded=excluded,stat_ok=stat_ok,kind=kind,strict=strict,
                  before_stat=before_stat,before_uid=before_uid,after_stat=after_stat,after_uid=after_uid,pid=pid))
        def changed(**kw):
            v=copy.deepcopy(observed);v.update(kw);return v
        add("ci_trace_mixed_older_stable",excluded=True)
        add("same_group_old_refused",before=changed(pgid=leader["pgid"]),after=changed(pgid=leader["pgid"]))
        add("equal_start_tick_refused",before=changed(start=leader["leader_start_ticks"]),after=changed(start=leader["leader_start_ticks"]))
        add("newer_start_refused",before=changed(start=leader["leader_start_ticks"]+1),after=changed(start=leader["leader_start_ticks"]+1))
        add("leader_pid_alias_refused",before=changed(pid=leader["leader_pid"]),after=changed(pid=leader["leader_pid"]),pid=leader["leader_pid"])
        add("before_stat_missing_refused",before_stat=None,stat_ok=False)
        add("before_stat_malformed_refused",before_stat=b"broken\n",stat_ok=False)
        add("before_uid_missing_refused",before_uid=None,kind=0)
        add("before_uid_malformed_refused",before_uid=b"Uid:\t1001\t0\t0\n",kind=0)
        add("before_uid_duplicate_refused",before_uid=b"Uid:\t1001 0 0 0\nUid:\t1001 0 0 0\n",kind=0)
        add("uniform_uid_stays_strict_only",before=changed(uids=[1001]*4),after=changed(uids=[1001]*4),kind=1,strict=True)
        add("after_pid_changed_refused",after=changed(pid=observed["pid"]+1))
        add("after_start_changed_refused",after=changed(start=observed["start"]+1))
        add("after_pgid_changed_refused",after=changed(pgid=observed["pgid"]+1))
        add("after_ppid_changed_refused",after=changed(ppid=2))
        for index,name in enumerate(("real","effective","saved","filesystem")):
            uids=list(observed["uids"]);uids[index]+=1
            add("after_"+name+"_uid_changed_refused",after=changed(uids=uids))
        add("after_uniform_tuple_refused",after=changed(uids=[1001]*4))
        add("after_stat_missing_refused",after_stat=None)
        add("after_uid_missing_refused",after_uid=None)
        add("after_uid_malformed_refused",after_uid=b"Uid:\t1001\t0\t0\n")
        add("after_uid_duplicate_refused",after_uid=b"Uid:\t1001 0 0 0\nUid:\t1001 0 0 0\n")
        add("after_uid_nul_refused",after_uid=b"Uid:\t1001 0 0 0\n\0")
        add("after_stat_truncated_refused",after_stat=b"2119 (fixture) S 1 2103\n")
        add("before_uid_nul_refused",before_uid=b"Uid:\t1001 0 0 0\n\0",kind=0)
        add("before_status_over_budget_refused",before_uid=b"x"*16385,kind=0)
        add("before_status_no_uid_refused",before_uid=b"Name:\tfixture\n",kind=0)
        for spec in specs:
            folder=a.output/"cases"/spec["name"];folder.mkdir(parents=True)
            for stage,prefix in (("before",""),("after","after-")):
                for field,leaf,make in (("stat","stat",stat_bytes),("uid","status",status_bytes)):
                    raw=spec[stage+"_"+field]
                    if raw=="auto":raw=make(spec[stage])
                    if raw is not None:save(folder/(prefix+leaf),raw)
            cmd=[binary,folder,spec["pid"] or observed["pid"],leader["leader_pid"],
                 leader["leader_start_ticks"],leader["pgid"]]
            c=run("case-"+spec["name"],cmd,timeout=5);actual=json.loads(c.stdout)
            check(actual["stat_ok"] is spec["stat_ok"],spec["name"]+" initial stat")
            check(actual["uid_kind"]==spec["kind"],spec["name"]+" UID type")
            check(actual["strict_uid"] is spec["strict"],spec["name"]+" original strict authority")
            check(actual["excluded"] is spec["excluded"],spec["name"]+" exclusion")
            check(actual["same_held_fd"] is True,spec["name"]+" same held FD")
            check(actual["sdk_calls"]==0,spec["name"]+" no SDK")
            if spec["kind"]==2:check(actual["first_uid_values"]==spec["before"]["uids"],spec["name"]+" complete first tuple")
            records.append({"name":spec["name"],"actual":actual,"expected_excluded":spec["excluded"]})
        cases={"schema":"hepta.owned-generation-mixed-uid-host.v1","all_pass":True,
               "cases":len(records),"assertions":assertions,"case_names":[r["name"] for r in records],"records":records,
               "complete_live_proc_scanner_tested":False,"actual_mixed_uid_process_created":False,"phone_tested":False}
        save(a.output/"CASES.json",enc(cases))
        result["cases"]=cases;result["cases_file"]=pin(a.output/"CASES.json");result["all_pass"]=True
    except Exception as error:result["error"]=type(error).__name__+": "+str(error)
    finally:
        result["steps"]=steps
        result["inputs_unchanged"]=all(p.read_bytes()==b for p,b in inputs.items())
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"]
        result["source_inputs"]=[{"path":str(p),"bytes":len(b),"sha256":sha(b)} for p,b in inputs.items()]
        save(a.output/"RESULT.json",enc(result))
        print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),
             "cases":result.get("cases",{}).get("cases"),"assertions":result.get("cases",{}).get("assertions"),
             "result":pin(a.output/"RESULT.json")}))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
