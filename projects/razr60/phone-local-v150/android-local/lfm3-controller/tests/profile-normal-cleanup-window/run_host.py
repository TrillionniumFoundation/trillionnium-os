#!/usr/bin/env python3
"""Focused normal public-profile cleanup timing gate. Synthetic Android IO, actual policy/members, no phone."""
import argparse, hashlib, json, os, stat, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode=True
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
CORE=["ProfileIdentity","ProfileTarget","WindowOwnership","BrokerProtocol","PublicPermissionControllerUi",
      "PublicOwnGroupPolicy","FixedIntentTools","BackgroundOwnedTaskPolicy","BackgroundOwnedSingleTask",
      "ProfileTaskPolicy","ProfileOwnedTask","ProfilePermissionTransient","ProfileDisplayCustody",
      "PublicOwnGroupPhysicalFence","PublicProfileRecentHistory","ProfileTaskPlatform"]
BROKER_MARKERS=[
 "private static final class NormalProfileCleanupWindow",
 "private boolean normalPublicProfileCleanup()",
 "private long cleanupWaitMillis(long originalRequestDeadline)",
 "private boolean cleanupDeadlineReached(long now)",
 "private long profileCleanupWorkDeadline()",
 "private void requireNormalProfileCleanupFresh()",
 "private long profileDeadline()",
 "private boolean profileCloseReplyPending(long now)",
 "private boolean releasedProfileReplyMayFlush(long now)",
 "private void beginCleanup(String reason)",
 "private void beginProfileCleanup()",
 "private void refreshProfileTaskEvidence()",
 "private java.util.Map<String,Object> emptyProfileCleanup(boolean known)",
 "private void quarantineProfile(String reason)",
 "private String releasedState()",
 "private static String code(Throwable error)",
 "private void recheckProfile(boolean ready,long deadline)",
 "private void requireUnlaunchedProfileEmpty()",
 "static final class ProfileCleanupFailureAudit"
]
ORGANIZER_MARKERS=["public void removeOwnedLeaf(Object token)","public boolean deleteOwnedContainer(Object token)","private Object wrapper(Object binder)"]
STUBS={
 "android/app/ActivityOptions.java":"package android.app; public final class ActivityOptions {}\n",
 "android/content/Context.java":"package android.content; public class Context {}\n",
 "android/os/Binder.java":"package android.os; public class Binder {}\n",
 "android/os/SystemClock.java":"package android.os; public final class SystemClock { public static java.util.function.LongSupplier clock; public static long elapsedRealtime(){if(clock==null)throw new AssertionError(\"unbound synthetic clock\");return clock.getAsLong();} private SystemClock(){} }\n"
}
def require(ok,why):
    if not ok:raise AssertionError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ref(p):
    raw=p.read_bytes()
    return {"path":str(p),"bytes":len(raw),"sha256":sha(raw),"mode":format(stat.S_IMODE(p.stat().st_mode),"04o")}
def write_new(p,raw):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open("xb") as f:f.write(raw)
def method(text,marker):
    require(text.count(marker)==1,"unique full-member marker required: "+marker)
    start=text.index(marker);first=text.index("{",start);depth,index,state=0,first,"code"
    while index<len(text):
        char=text[index];pair=text[index:index+2]
        if state=="line":
            if char=="\n":state="code"
        elif state=="block":
            if pair=="*/":state="code";index+=1
        elif state in ("string","char"):
            if char=="\\":index+=1
            elif char==('"' if state=="string" else "'"):state="code"
        elif pair=="//":state="line";index+=1
        elif pair=="/*":state="block";index+=1
        elif char=='"':state="string"
        elif char=="'":state="char"
        elif char=="{":depth+=1
        elif char=="}":
            depth-=1
            if depth==0:return text[start:index+1]
        index+=1
    raise AssertionError("incomplete member: "+marker)
def prepare(source,out):
    here=source/"tests/profile-normal-cleanup-window";pins=json.loads((here/"SOURCE-PINS.json").read_text())
    inputs=[]
    for relative,expected in pins["source_inputs"].items():
        p=source/relative;r=ref(p)
        require({k:r[k] for k in ("bytes","sha256","mode")}==expected,"frozen input differs: "+relative);inputs.append(r)
    bg=source/"src/org/trillionnium/hepta/background"
    broker=(bg/"BackgroundDisplayBroker.java").read_text()
    organizer=(bg/"BackgroundTaskOrganizer.java").read_text()
    extracted=[]
    def take(text,markers,file):
        blocks=[]
        for marker in markers:
            b=method(text,marker);expected=pins["extracted_members"][file][marker]
            require(sha(b.encode())==expected,"actual member differs: "+marker)
            blocks.append(b);extracted.append({"source_path":str(bg/file),"marker":marker,"bytes":len(b.encode()),"sha256":expected,"whole_member":True})
        return "\n\n".join(blocks)
    host=(here/"ProfileNormalCleanupHost.template").read_text()
    require(host.count("/*__BROKER_MEMBERS__*/")==1,"host slot")
    host=host.replace("/*__BROKER_MEMBERS__*/",take(broker,BROKER_MARKERS,"BackgroundDisplayBroker.java"))
    io=(here/"NormalCleanupIO.template").read_text()
    require(io.count("/*__ORGANIZER_MEMBERS__*/")==1,"organizer slot")
    io=io.replace("/*__ORGANIZER_MEMBERS__*/",take(organizer,ORGANIZER_MARKERS,"BackgroundTaskOrganizer.java"))
    root=out/"generated";root.mkdir()
    pkg=root/"org/trillionnium/hepta/background"
    write_new(pkg/"ProfileNormalCleanupHostTest.java",host.encode())
    common=io[:io.index("/** Explicit synthetic")]
    for name in ("NormalCleanupIO","ProfilePackages","BackgroundTaskOrganizer"):
        write_new(pkg/(name+".java"),(common+method(io,"final class "+name)+"\n").encode())
    for relative,value in STUBS.items():write_new(root/relative,value.encode())
    files=[bg/(n+".java") for n in CORE]
    files += [source/"tests/profile-broker/ProfileBrokerHostTest.java",source/"tests/profile-broker/ProfileRootRefusalHostTest.java"]
    files += sorted(root.rglob("*.java"))
    return files,inputs,extracted,[ref(p) for p in sorted(root.rglob("*.java"))],pins["case_names"]
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ("source","java-home","json-jar","output"):ap.add_argument("--"+name,type=Path,required=True)
    a=ap.parse_args();source=a.source.resolve(strict=True);out=a.output.resolve()
    require(source not in out.parents and not out.exists(),"new output outside source")
    require(Path(__file__).resolve()==source/"tests/profile-normal-cleanup-window/run_host.py","runner/source mismatch")
    require(sha(a.json_jar.read_bytes())==JSON_SHA,"fixed org.json input")
    out.mkdir(parents=True)
    report={"schema":"hepta.profile-normal-cleanup-window-host.v1","all_pass":False,"stages":[],
        "phone_actions":0,"apk_builds":0,"synthetic_android_io_and_time":True,"full_android_broker_compiled":False,
        "actual_whole_profile_platform_compiled":True,"historical_277631_replayed_or_success_claimed":False,
        "actual_binder_or_virtual_display_effects":0,"strict_javac":True}
    tracked=[]
    def run(name,argv):
        start=time.monotonic()
        p=subprocess.run(list(map(str,argv)),cwd=out,capture_output=True,timeout=90)
        stdout=out/(name+".stdout");stderr=out/(name+".stderr");write_new(stdout,p.stdout);write_new(stderr,p.stderr)
        report["stages"].append({"name":name,"argv":list(map(str,argv)),"exit_code":p.returncode,"seconds":time.monotonic()-start,
                                "stdout":ref(stdout),"stderr":ref(stderr)})
        require(p.returncode==0 and not p.stderr,name+" failed; original outputs retained")
        return p.stdout
    try:
        files,inputs,members,generated,expected=prepare(source,out)
        tools=[a.java_home/"bin/javac",a.java_home/"bin/java",a.java_home/"release",a.java_home/"lib/modules",
               a.java_home/"lib/server/libjvm.so",a.json_jar,Path(__file__).resolve(),Path(__file__).with_name("SOURCE-PINS.json"),
               Path(__file__).with_name("README.md")]
        tracked=inputs+[ref(p.resolve()) for p in tools]+generated
        report.update(source_root=str(source),inputs_before=tracked,actual_extracted_members=members,generated_sources=generated,
                      expected_focused_names=expected,legacy_bodies_changed=False)
        classes=out/"classes";classes.mkdir()
        jdk=a.java_home/"bin";cp=str(classes)+os.pathsep+str(a.json_jar.resolve())
        run("compile",[jdk/"javac","--release","8","-Xlint:all,-options","-Werror","-proc:none","-encoding","UTF-8",
                       "-cp",a.json_jar,"-d",classes,*files])
        casepath=out/"FOCUSED-CASES.json"
        raw=run("normal-cleanup",[jdk/"java","-cp",cp,"org.trillionnium.hepta.background.ProfileNormalCleanupHostTest",
            source/"tests/profile-cleanup-sampling/fixtures-synthetic/before-recents.txt",casepath])
        cases=json.loads(casepath.read_bytes());rows=cases["cases"]
        require(cases["passed"] is True and len(rows)==34 and [r["name"] for r in rows]==expected
                and all(r["passed"] is True for r in rows),"focused full name/count/predicate contract")
        report["focused"]={"result":ref(casepath),"cases":len(rows),"assertions":cases["assertions"],"all_pass":True}
        for label,name in (("legacy-profile","ProfileBrokerHostTest"),("legacy-root","ProfileRootRefusalHostTest")):
            raw=run(label,[jdk/"java","-cp",cp,"org.trillionnium.hepta.background."+name])
            legacy=json.loads(raw.decode().splitlines()[0]);require(legacy["passed"] is True,label+" false")
            report[label]=legacy
        report["all_pass"]=True
    except Exception as error:
        report["error"]=str(error)
    finally:
        report["inputs_after"]=[ref(Path(r["path"])) for r in tracked]
        report["inputs_unchanged"]=report.get("inputs_before",[])==report["inputs_after"]
        report["all_pass"]=report["all_pass"] and report["inputs_unchanged"]
        write_new(out/"RESULT.json",(json.dumps(report,ensure_ascii=False,indent=2)+"\n").encode())
        print(json.dumps({"all_pass":report["all_pass"],"result":ref(out/"RESULT.json"),"stages":[[x["name"],x["exit_code"]] for x in report["stages"]]}))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":sys.exit(main())
