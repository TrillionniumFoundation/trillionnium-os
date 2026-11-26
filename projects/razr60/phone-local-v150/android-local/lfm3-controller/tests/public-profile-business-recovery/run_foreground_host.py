#!/usr/bin/env python3
"""Focused current-absence concurrency tests; archived business originals are read-only."""
import argparse, hashlib, json, os
from pathlib import Path
import subprocess, time

def main():
    p=argparse.ArgumentParser()
    for key in ("source","output","java-home","json-jar","manifest","original-paths"):
        p.add_argument("--"+key, required=True, type=Path)
    a=p.parse_args(); s=a.source.resolve(); o=a.output.absolute(); o.mkdir(mode=0o700)
    classes=o/"classes"; classes.mkdir()
    java=a.java_home/"bin/java"; javac=a.java_home/"bin/javac"
    test=s/"tests/public-profile-business-recovery"
    inputs={str(a.manifest):hashlib.sha256(a.manifest.read_bytes()).hexdigest(),
        str(a.original_paths):hashlib.sha256(a.original_paths.read_bytes()).hexdigest()}
    for path in json.loads(a.original_paths.read_bytes()).values():
        inputs[path]=hashlib.sha256(Path(path).read_bytes()).hexdigest()
    names=["PublicProfileBusinessRecoveryHostTest","PublicProfileBusinessIncompleteHostTest",
        "PublicProfileReleasedCloseHostTest","PublicProfileRecoveryForegroundHostTest"]
    jobs=[("compile",[str(javac),"--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-proc:none",
        "-cp",str(a.json_jar),"-sourcepath",str(s/"src"),"-d",str(classes)]+[str(test/(n+".java")) for n in names])]
    for name in ("PublicProfileRecoveryForegroundHostTest","PublicProfileReleasedCloseHostTest"):
        jobs.append((name,[str(java),"-Xmx512m","-cp",str(classes)+os.pathsep+str(a.json_jar),
            "org.trillionnium.hepta.background."+name,str(a.manifest),str(a.original_paths)]))
    stages=[]
    for name,cmd in jobs:
        at=time.monotonic()
        r=subprocess.run(cmd,cwd=s,capture_output=True,timeout=120)
        (o/(name+".stdout")).write_bytes(r.stdout);(o/(name+".stderr")).write_bytes(r.stderr)
        row={"name":name,"argv":cmd,"exit_code":r.returncode,"seconds":time.monotonic()-at}
        if name!="compile" and r.returncode==0: row["report"]=json.loads(r.stdout)
        stages.append(row)
        if r.returncode: break
    unchanged=all(hashlib.sha256(Path(path).read_bytes()).hexdigest()==h for path,h in inputs.items())
    result={"all_pass":len(stages)==3 and all(x["exit_code"]==0 for x in stages) and unchanged,
        "stages":stages,"original_inputs_unchanged":unchanged,"phone_operations":0,
        "boundary":"real archived 02d originals; synthetic current framework samples; actual production policies executed"}
    (o/"RESULT.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({"all_pass":result["all_pass"],"result":str(o/"RESULT.json"),
        "stages":[{"name":r["name"],"exit_code":r["exit_code"],"counts":{k:r.get("report",{}).get(k) for k in ("cases","assertions")}} for r in stages]}))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
