#!/usr/bin/env python3
"""Repeat the actual transaction and full Engine admission tests with explicit host ports.
No Android SDK, phone, native model, network or dependency download is used.
"""
import argparse,hashlib,json,os,stat,subprocess,time
from pathlib import Path

def need(value,message):
    if not value: raise RuntimeError(message)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return (json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","java-home","json-jar"):
        parser.add_argument("--"+name,type=Path,required=True)
    a=parser.parse_args()
    need(all(p.is_absolute() for p in vars(a).values()),"absolute paths required")
    source=a.source.resolve(strict=True);out=a.output.absolute()
    try: out.relative_to(source)
    except ValueError: pass
    else: raise RuntimeError("test output must be outside source")
    need(os.name=="posix" and hasattr(os,"getuid") and os.getuid()!=0,
         "non-root POSIX host required for real file permission refusal tests")
    out.mkdir(parents=True,exist_ok=False)
    inputs={};result={"schema":"hepta.local-model-settings-host-gate.v1","all_pass":False,"steps":[],
        "phone_operations":0,"native_model_executed":False,"external_model_used":False,
        "full_production_engine_and_transaction":True,"java_release_api_check":False,
        "android_sdk_api_compilation":False,"android_runtime":False,
        "directory_fsync_and_android_uid_fd_are_surrogates":True,
        "hardware_or_positive_model_qualification":False}
    def take(path):
        st=path.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,"regular single-link input required: "+str(path))
        raw=path.read_bytes()
        if path in inputs: need(inputs[path]==raw,"input changed: "+str(path))
        inputs[path]=raw;return raw
    def put(path,raw):
        with path.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
        return {"path":str(path),"bytes":len(raw),"sha256":sha(raw)}
    def run(name,argv,timeout=180):
        argv=list(map(str,argv));start=time.monotonic()
        row={"name":name,"argv":argv,"started_host_wall_ms":int(time.time()*1000)}
        result["steps"].append(row)
        try:
            child=subprocess.run(argv,cwd=out,capture_output=True,timeout=timeout)
            row.update(exit_code=child.returncode,elapsed_seconds=time.monotonic()-start)
            row["stdout"]=put(out/(name+".stdout"),child.stdout)
            row["stderr"]=put(out/(name+".stderr"),child.stderr)
            return child.returncode
        except subprocess.TimeoutExpired as error:
            row.update(exit_code=None,timed_out=True,elapsed_seconds=time.monotonic()-start)
            row["stdout"]=put(out/(name+".stdout"),error.stdout or b"")
            row["stderr"]=put(out/(name+".stderr"),error.stderr or b"")
            raise
    try:
        test=source/"tests/local-model-settings"
        take(Path(__file__).resolve());take(test/"README.md")
        contracts=json.loads(take(test/"CASE-CONTRACT.json"))
        production=json.loads(take(test/"PRODUCTION-SOURCES.json"))
        need(contracts["schema"]=="hepta.local-model-settings-case-contract.v1","case contract schema")
        need(production["schema"]=="hepta.local-model-settings-production-sources.v1","source list schema")
        names=production["sources"]
        need(type(names)is list and len(names)==39 and len(set(names))==39,"complete 39 production inputs required")
        actual=[]
        for name in names:
            need(type(name)is str and name.startswith("src/org/trillionnium/hepta/") and name.endswith(".java")
                 and ".." not in Path(name).parts and not Path(name).is_absolute(),"production path")
            path=source/name;take(path);actual.append(path)
        fixture_root=test/"fixtures"
        fixture_paths=sorted(fixture_root.rglob("*"))
        need(not any(p.is_symlink() for p in fixture_paths),"fixture symlink")
        fixture=[p for p in fixture_paths if p.is_file()]
        need(len(fixture)==13 and all(p.suffix==".java" for p in fixture),"exact 13 explicit boundary source files")
        tests=[test/"RuntimeConfigTransactionHostTest.java",test/"RuntimeGenerationHostTest.java",
               test/"RuntimeContextFilesHostTest.java"]
        for path in fixture+tests:take(path)
        jar=take(a.json_jar)
        need(len(jar)==78332 and sha(jar)=="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed",
             "existing pinned org.json 20240303 required; no download is attempted")
        java=(a.java_home/"bin/java").resolve(strict=True);javac=(a.java_home/"bin/javac").resolve(strict=True)
        take(java);take(javac)
        need(run("javac-version",[javac,"-version"])==0,"javac version failed")
        classes=out/"classes";classes.mkdir();empty=out/"empty-sourcepath";empty.mkdir()
        command=[javac,"--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-proc:none",
                 "-sourcepath",empty,"-cp",a.json_jar,"-d",classes,*actual,*fixture,*tests]
        need(run("compile",command)==0,"strict Java 8 compilation failed")
        result["java_release_api_check"]=True
        result["cases"]={};result["case_receipts"]={}
        for label,main,expected_count,expected_assertions in (
                ("transaction","RuntimeConfigTransactionHostTest",43,196),
                ("generation","RuntimeGenerationHostTest",15,100),
                ("context_files","RuntimeContextFilesHostTest",8,36)):
            case_dir=out/(label+"-cases")
            contract=contracts[label]
            need(type(contract["cases"])is int and contract["cases"]==expected_count
                 and type(contract["assertions"])is int and contract["assertions"]==expected_assertions,
                 "fixed original case/assertion contract changed")
            expected_names=contract["names"]
            need(type(expected_names)is list and len(expected_names)==expected_count
                 and all(type(n)is str for n in expected_names) and len(set(expected_names))==expected_count,
                 "missing or duplicate original case names")
            rc=run(label,[java,"-Dhepta.fixture.host_uid="+str(os.getuid()),"-cp",
                str(classes)+os.pathsep+str(a.json_jar),
                "org.trillionnium.hepta.local."+main,case_dir])
            case_path=case_dir/"RESULT.json"
            raw=case_path.read_bytes();cases=json.loads(raw)
            result["cases"][label]=cases
            result["case_receipts"][label]={"path":str(case_path),"bytes":len(raw),"sha256":sha(raw)}
            need(rc==0 and cases.get("passed") is True and cases.get("schema")==contract["schema"],
                 label+" cases failed")
            need(type(cases.get("cases"))is int and cases["cases"]==expected_count
                 and type(cases.get("assertions"))is int and cases["assertions"]==expected_assertions,
                 label+" original cases/assertions changed")
            rows=cases.get("case_results")
            need(type(rows)is list and [r.get("name") for r in rows]==expected_names
                 and all(r.get("passed")is True and type(r.get("assertions"))is int for r in rows),
                 label+" original case names/results changed")
            need(type(cases.get("phone_operations"))is int and cases["phone_operations"]==0
                 and cases.get("native_model_executed")is False,label+" scope differs")
        result["all_pass"]=True
    except Exception as error:
        result["error"]=type(error).__name__+": "+str(error)
    finally:
        result["source_inputs"]=[{"path":str(p),"bytes":len(b),"sha256":sha(b)} for p,b in sorted(inputs.items(),key=lambda item:str(item[0]))]
        try: result["inputs_unchanged"]=all(p.read_bytes()==b for p,b in inputs.items())
        except OSError: result["inputs_unchanged"]=False
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"]
        ref=put(out/"RESULT.json",encoded(result))
        print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),
            "result":ref,"phone_operations":0,"native_model_executed":False}),flush=True)
    return 0 if result["all_pass"] else 1

if __name__=="__main__":raise SystemExit(main())
