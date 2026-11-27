#!/usr/bin/env python3
"""Whole-production normal cleanup read-order gate; explicit framework ports, no phone."""
import argparse,hashlib,importlib.util,json,os,stat,subprocess,sys,time,traceback
from pathlib import Path

BG="src/org/trillionnium/hepta/background"
NAMES=("ProfileIdentity","ProfileTarget","WindowOwnership","BrokerProtocol","PublicPermissionControllerUi",
"PublicOwnGroupPolicy","FixedIntentTools","BackgroundOwnedTaskPolicy","BackgroundOwnedSingleTask","ProfileTaskPolicy",
"ProfileOwnedTask","ProfilePermissionTransient","ProfileDisplayCustody","PublicOwnGroupPhysicalFence","PublicProfileRecentHistory")
PARENT="fd3e6f275c1082ce2197ad5629c4228d39780109"
OLD="fe0b6a67deefea03d7fb7f7881e42e08b73c5c978f7808374865ef62bb4c395c"
NEW="4ccfa1934331f17274b6f0d6ab911d7dd986a2cce852d9f65e64aea96c907a80"
JAR="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
FIX="b3a758e849b621bac4b21c508fa330dce03df38329b82ea260f01b635d44b0c9"
BIN="41dc7715aa7e7516a56bac7737dbb6c9a4a2ef621bfc5414e00c57c311d14b9f"
CLEANUP="9a05d359861df1c4aff5ced95d42f9e7543bcc2056278d76636fc8b5a3b4f7f1"
PKG="org.trillionnium.hepta.background."
TEST="tests/profile-cleanup-recents-first/ProfileCleanupRecentsFirstHostTest.java"
OLDTESTS=("tests/profile-broker/ProfileBrokerHostTest.java","tests/profile-cleanup-sampling/ProfileCleanupSamplingHostTest.java",
          "tests/profile-cleanup-settle/ProfileCleanupSettleFixtures.java")
def need(ok,msg):
    if not ok:raise AssertionError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def ref(p):
    p=Path(p).absolute();s=p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,"regular single-link input: "+str(p))
    b=p.read_bytes();t=p.lstat()
    need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns),"changed read")
    return dict(path=str(p),bytes=len(b),sha256=sha(b),mode=stat.S_IMODE(s.st_mode))
def write(p,x):
    with Path(p).open("x",encoding="utf-8") as f:f.write(json.dumps(x,indent=2,ensure_ascii=False)+"\n")
def actual(broker,cleanup):
    need(ref(broker)["sha256"]==BIN and ref(cleanup)["sha256"]==CLEANUP,"actual ce5 originals differ")
    rows=[json.loads(x) for x in Path(broker).read_bytes().splitlines()]
    need(len(rows)==2 and all(x["state"]=="CLEANUP_UNKNOWN" for x in rows),"actual terminals")
    text=json.dumps([rows,json.loads(Path(cleanup).read_bytes())],sort_keys=True)
    for n in (1117035229,1117035270,1117035272,1117036229,1117036258,1117038371,1117036629,1117038229):
        need(str(n) in text,"actual archived clock absent: "+str(n))
    return dict(originals=[ref(broker),ref(cleanup)],actual_phone_result="CLEANUP_UNKNOWN",
        original_failed_history_rewritten=False,per_subcall_latencies_unknown=True,
        host_projection_not_actual_complete_global_census=True,fixture_target_profile="existing synthetic Ctrip profile",
        actual_target_package="com.xiaomi.shop",phone_success_claimed=False)
def prepare(a):
    src,base,out=a.source.absolute(),a.baseline.absolute(),a.output.absolute()
    need(not out.exists() and src!=base and src not in out.parents and base not in out.parents,"isolated fresh output")
    need(ref(base/BG/"ProfileOwnedTask.java")["sha256"]==OLD and ref(src/BG/"ProfileOwnedTask.java")["sha256"]==NEW,"whole production pin")
    need(ref(a.json_jar)["sha256"]==JAR,"JSON pin")
    fixture=src/"tests/profile-cleanup-sampling/fixtures-synthetic/before-recents.txt"
    need(ref(fixture)["sha256"]==FIX,"synthetic complete raw fixture")
    for rel in OLDTESTS:need((src/rel).read_bytes()==(base/rel).read_bytes(),"old fixture changed: "+rel)
    actual_shape=actual(a.broker_bin,a.cleanup)
    helper=src/"tests/profile-cleanup-settle/run_host.py"
    spec=importlib.util.spec_from_file_location("original_cleanup_source_parser",helper)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    old=(base/BG/"ProfileOwnedTask.java").read_text();new=(src/BG/"ProfileOwnedTask.java").read_text()
    inv=json.loads((Path(__file__).absolute().parent/"WHOLE-INVERSE-r1.json").read_bytes())
    need(len(inv["spans"])==1,"one source span")
    x=inv["spans"][0]
    need(new.count(x["new"])==1 and new.replace(x["new"],x["old"])==old,"whole source inverse")
    unchanged=[]
    for anchor in ("    static final class CleanupPhase {","    private void normalCleanupFinalPair(",
        "    synchronized void prepareNormalDisplayRelease(","    public synchronized boolean absent(",
        "    synchronized RetainedCleanupProof cleanupRetained(","    private RetainedSample retainedCleanupSample(",
        "    private void retainedCleanupFinalPair(","    private ProfileTaskPolicy.Recents readRecents("):
        b=mod.extract(old,anchor)[0];c=mod.extract(new,anchor)[0]
        need(b==c,"protected full member changed: "+anchor)
        unchanged.append(dict(anchor=anchor,bytes=len(b.encode()),sha256=sha(b.encode()),whole_equal=True))
    paths={Path(__file__).absolute(),a.java_home/"bin/java",a.java_home/"bin/javac",a.java_home/"lib/modules",
        a.json_jar,fixture,a.broker_bin,a.cleanup,helper,Path(__file__).absolute().parent/"WHOLE-INVERSE-r1.json",
        Path(__file__).absolute().parent/"PRODUCTION-r1.patch",src/TEST}
    pure={}
    for kind,root in (("current",src),("old",base)):
        pure[kind]=[root/BG/(n+".java") for n in NAMES]
        paths.update(pure[kind])
    for n in NAMES:
        if n!="ProfileOwnedTask":need((src/BG/(n+".java")).read_bytes()==(base/BG/(n+".java")).read_bytes(),"unrelated production changed")
    fixtures=[src/rel for rel in OLDTESTS]+[src/TEST]
    paths.update(fixtures);paths.update(base/rel for rel in OLDTESTS)
    inputs=[ref(p) for p in sorted(paths)]
    out.mkdir(parents=True);(out/"current-classes").mkdir();(out/"old-classes").mkdir()
    flags=["--release","8","-proc:none","-Xlint:all,-options","-Werror","-encoding","UTF-8"]
    jdk=a.java_home/"bin";jar=str(a.json_jar);stages=[]
    for kind in ("current","old"):
        classes=out/(kind+"-classes");cp=str(classes)+os.pathsep+jar
        stages.append(dict(name=kind+"-strict",expected_exit=0,argv=[str(jdk/"javac"),"-J-Xmx512m",*flags,
            "-cp",jar,"-d",str(classes),*map(str,pure[kind]+fixtures)]))
        if kind=="current":
            groups=[("current-focused","ProfileCleanupRecentsFirstHostTest",[str(fixture)]),
                ("current-private-original","ProfileBrokerHostTest",[]),
                ("current-public-original","ProfileCleanupSamplingHostTest",[str(fixture.parent),"candidate"])]
            for name,cls,args in groups:stages.append(dict(name=name,expected_exit=0,
                argv=[str(jdk/"java"),"-Xmx512m","-cp",cp,PKG+cls,*args]))
        else:stages.append(dict(name="old-whole-counterfactual",expected_exit=1,argv=[str(jdk/"java"),"-Xmx512m",
            "-cp",cp,PKG+"ProfileCleanupRecentsFirstHostTest",str(fixture),"old-first"]))
    plan=dict(schema="hepta.ce5-cleanup-recents-first.prepared.v1",source_head=None,parent_head=PARENT,
        source=str(src),baseline=str(base),output=str(out),whole_production_current_sha=NEW,whole_production_old_sha=OLD,
        exact_source_inverse=True,unchanged_full_members=unchanged,inputs=inputs,stages=stages,
        actual_original=actual_shape,phone_operations=0,android_runtime=False,model_runs=0,
        framework_clock_effect_ports_synthetic=True,minimum_memavailable_bytes=1073741824)
    write(out/"PREPARED.json",plan);print(json.dumps(dict(prepared=True,receipt=ref(out/"PREPARED.json"),stages=len(stages))))
def execute(a):
    pre=a.prepared.absolute();need(ref(pre)["sha256"]==a.expected_sha,"prepared receipt changed")
    plan=json.loads(pre.read_bytes());out=Path(plan["output"])
    need(not (out/"RESULT.json").exists(),"once result destination")
    before=[ref(x["path"]) for x in plan["inputs"]];need(before==plan["inputs"],"input changed before execution")
    available=int(next(l.split()[1] for l in Path("/proc/meminfo").read_text().splitlines() if l.startswith("MemAvailable:")))*1024
    need(available>=plan["minimum_memavailable_bytes"],"memory precondition, no Java started")
    report=dict(schema="hepta.ce5-cleanup-recents-first.actual.v1",all_pass=False,prepared=ref(pre),inputs_before=before,
        stages=[],actual_original=plan["actual_original"],unchanged_full_members=plan["unchanged_full_members"],
        parent_head=PARENT,source_head=None,phone_operations=0,android_runtime=False,model_runs=0,
        framework_clock_effect_ports_synthetic=True,device_qualified=False,memavailable_before_bytes=available)
    env=dict(os.environ)
    for name in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH","PYTHONPATH"):env.pop(name,None)
    error=None
    try:
        for stage in plan["stages"]:
            start=time.monotonic()
            p=subprocess.run(stage["argv"],cwd=out,env=env,capture_output=True,timeout=120)
            stdout=out/(stage["name"]+".stdout");stderr=out/(stage["name"]+".stderr")
            with stdout.open("xb") as f:f.write(p.stdout)
            with stderr.open("xb") as f:f.write(p.stderr)
            row=dict(stage,exit_code=p.returncode,seconds=time.monotonic()-start,stdout=ref(stdout),stderr=ref(stderr))
            report["stages"].append(row)
            need(p.returncode==stage["expected_exit"],"unexpected stage: "+stage["name"]+" "+p.stderr.decode("utf-8","replace")[-3000:])
            if not stage["name"].endswith("-strict"):
                lines=p.stdout.decode().splitlines();data=json.loads(lines[0]);row["cases"]=data
                if stage["name"]=="current-focused":
                    need(data["all_pass"] is True and data["case_count"]==18,"new focused contract")
                elif stage["name"]=="current-private-original":
                    need(data["schema"]=="hepta.profile-broker-host-tests.v1" and data["passed"] is True,"private original")
                elif stage["name"]=="current-public-original":
                    need(data["passed"] is True and len(data["cases"])==9 and data["assertions"]==55
                        and data["original_cleanup_read_budget_ms"]==1400,"public original")
                else:
                    need(data["all_pass"] is False and data["case_count"]==1,"old whole behavior must fail first case")
                    c=data["cases"][0];trace=c["actual_host_trace"]
                    need(c["error"]=="java.lang.AssertionError: required normal cleanup did not complete","counterfactual failed for unrelated reason")
                    need(trace["leaf_calls"]==1 and trace["root_calls"]==0 and trace["pause_after_first_history"] is True
                        and trace["clock"]==1117038371,"old whole did not reach intended mixed sample projection")
            print(json.dumps(dict(stage=stage["name"],exit=p.returncode)),flush=True)
        report["all_pass"]=True
    except Exception as e:
        error=e;report["error"]=str(e);report["traceback"]=traceback.format_exc()
    finally:
        report["inputs_after"]=[ref(x["path"]) for x in plan["inputs"]]
        report["source_and_tools_unchanged"]=report["inputs_after"]==before
        report["all_pass"]=report["all_pass"] and report["source_and_tools_unchanged"]
        write(out/"RESULT.json",report)
        print(json.dumps(dict(all_pass=report["all_pass"],result=ref(out/"RESULT.json"),phone_operations=0)),flush=True)
    if error is not None:raise error
    return 0 if report["all_pass"] else 1
def main():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest="mode",required=True)
    a=s.add_parser("prepare")
    for k in ("source","baseline","output","java-home","json-jar","broker-bin","cleanup"):a.add_argument("--"+k,type=Path,required=True)
    a=s.add_parser("execute");a.add_argument("--prepared",type=Path,required=True);a.add_argument("--expected-sha",required=True)
    a=p.parse_args();return prepare(a) if a.mode=="prepare" else execute(a)
if __name__=="__main__":sys.exit(main())
