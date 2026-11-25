#!/usr/bin/env python3
"""Run actual native live-verifier routing with explicit host Android/broker I/O ports."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.dont_write_bytecode = True
PKG = Path("src/org/trillionnium/hepta/local")

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def ref(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}

def body(text, anchor):
    if text.count(anchor) != 1:
        raise RuntimeError("exact unique actual member required: " + anchor)
    start = text.index(anchor)
    i = text.index("{", start)
    depth, state, quote = 0, "code", ""
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""
        if state == "line":
            if c == "\n":
                state = "code"
        elif state == "comment":
            if c == "*" and n == "/":
                state = "code"
                i += 1
        elif state == "string":
            if c == "\\":
                i += 1
            elif c == quote:
                state = "code"
        elif c == "/" and n == "/":
            state = "line"
            i += 1
        elif c == "/" and n == "*":
            state = "comment"
            i += 1
        elif c in ('"', "'"):
            state, quote = "string", c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1
    raise RuntimeError("unterminated actual member: " + anchor)

def between(text, start, end, after=0):
    begin = text.index(start, after)
    finish = text.index(end, begin)
    return text[begin:finish]

def prepare(source, controller, test, out):
    out.mkdir()
    inputs = [controller, source / PKG / "QualificationScopeConfig.java",
              source / PKG / "BackgroundSession.java",
              source / "src/org/trillionnium/hepta/background/ProfileIdentity.java",
              source / "src/org/trillionnium/hepta/background/ProfileTarget.java", test, Path(__file__).resolve()]
    controller_text = controller.read_text()
    qualification = inputs[1].read_text()
    background = inputs[2].read_text()
    members = []
    def actual(owner, label, text):
        members.append({"source": str(owner), "member": label, "bytes": len(text.encode()),
                        "sha256": sha(text.encode()), "verbatim": True})
        return text
    callback = actual(controller, "native InstalledVerifier expression",
                      body(controller_text, "new NativeAppSession.InstalledVerifier(){"))
    bindings = between(controller_text, "                final File nativeEvidence=evidence;\n",
                       "                NativeAppSession nativeTask=new NativeAppSession")
    bindings = bindings.split("\n", 1)[1]
    actual(controller, "native callback final bindings", bindings)
    after_record = controller_text.index('                history.put(row);record(evidence,String.format(java.util.Locale.ROOT,"step-%02d-after.json"')
    post = actual(controller, "complete post-observation installation branch",
                  between(controller_text, "                if(completionInstalled!=null)try",
                          "                completion.action(", after_record))
    terminal = actual(controller, "complete original post-cleanup installation branch",
                      between(controller_text, "            if(completionInstalled!=null)try{completionInstalled.verify(service);nativeInstalledRechecked=",
                              "            // Installed identity IO may outlive"))
    identity = actual(inputs[1], "complete CompletionInstalledIdentity class",
                      body(qualification, "    static final class CompletionInstalledIdentity {"))
    installation = actual(inputs[2], "verifyProfileInstallation",
                          body(background, "    void verifyProfileInstallation()throws Exception{"))
    remote = actual(inputs[2], "verifyRemote",
                    body(background, "    void verifyRemote()throws Exception{"))
    files = []
    def generated(rel, text):
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        files.append(p)
    generated("android/content/Context.java", "package android.content;public final class Context {}\n")
    generated("org/trillionnium/hepta/local/QualificationScope.java",
              'package org.trillionnium.hepta.local;final class QualificationScope {static void require(boolean ok,String why){if(!ok)throw new IllegalStateException(why);}}\n')
    generated("org/trillionnium/hepta/local/NativeAppGoal.java", """package org.trillionnium.hepta.local;
final class NativeAppGoal {
 static final String CTRIP_PACKAGE="ctrip.android.view",XIAOMI_PACKAGE="com.xiaomi.shop";
 final String packageName,ownerSha256;
 NativeAppGoal(String pkg,String owner){packageName=pkg;ownerSha256=owner;}
}\n""")
    generated("org/trillionnium/hepta/local/CalculatorGoalContract.java",
              'package org.trillionnium.hepta.local;final class CalculatorGoalContract {static final String PACKAGE="host.calculator";}\n')
    generated("org/trillionnium/hepta/local/TaskAuthorization.java",
              "package org.trillionnium.hepta.local;final class TaskAuthorization {static final class Gate {}}\n")
    generated("org/trillionnium/hepta/local/TaskCompletionGate.java", """package org.trillionnium.hepta.local;
final class TaskCompletionGate {
 final NativeAppGoal goal;boolean invalid;String reason;
 TaskCompletionGate(NativeAppGoal value){goal=value;}
 NativeAppGoal nativeGoal(){return goal;}
 void invalidateInstalled(String why){invalid=true;reason=why;}
}\n""")
    generated("org/trillionnium/hepta/local/NativeAppSession.java", """package org.trillionnium.hepta.local;
final class NativeAppSession {
 interface InstalledVerifier {void verify()throws Exception;}
 final String taskId;final TaskAuthorization.Gate authorization;final InstalledVerifier verifier;
 NativeAppSession(String task,TaskAuthorization.Gate auth,InstalledVerifier check){taskId=task;authorization=auth;verifier=check;}
 void verifyInstalled()throws Exception{verifier.verify();}
}\n""")
    generated("org/trillionnium/hepta/local/ProfileCatalogueClient.java", """package org.trillionnium.hepta.local;
import android.content.Context;import org.trillionnium.hepta.background.ProfileTarget;
final class ProfileCatalogueClient {
 static int calls;static ProfileTarget actual;static RuntimeException failure;
 static void requireCurrent(Context ignored,ProfileTarget expected){calls++;if(failure!=null)throw failure;
  if(actual==null||!expected.same(actual))throw new IllegalStateException("host catalogue changed installation");}
}\n""")
    generated("org/trillionnium/hepta/local/QualificationScopeConfig.java",
              "package org.trillionnium.hepta.local;\nimport android.content.Context;import java.util.*;\nfinal class QualificationScopeConfig {\n"
              + identity + """
 // Host-only ordinary PackageManager/APK endpoint. No Android installation is read.
 static final class Installed {
  static int verifyCalls;static RuntimeException failure;
  final String packageName,apkSetSha256="host-apk-set";final int uid=12000;final long version=1;
  final Map<String,Apk> apks=new TreeMap<String,Apk>();
  Installed(String pkg){packageName=pkg;apks.put("base",new Apk());}
  static Installed capture(Context ignored,String pkg){return new Installed(pkg);}
  void verify(Context ignored){verifyCalls++;if(failure!=null)throw failure;}
 }
 static final class Apk {final String sha256="host-apk";}
}\n""")
    generated("org/trillionnium/hepta/local/BackgroundSession.java", """package org.trillionnium.hepta.local;
import org.trillionnium.hepta.background.ProfileTarget;
final class BackgroundSession {
 final String taskId,ownerSha256;final ProfileTarget target;
 Object publicOwnGroupScope;boolean permissionPreparing,retired,retireOnAccept;
 int calls,accepts,activeChecks,lastTimeout;String lastOperation;
 Exception callFailure,acceptFailure;
 BackgroundSession(String task,String owner,ProfileTarget selected){taskId=task;ownerSha256=owner;target=selected;}
 ProfileTarget profileTarget(){return target;}
 void reset(){calls=0;accepts=0;activeChecks=0;lastTimeout=0;lastOperation=null;callFailure=null;acceptFailure=null;retireOnAccept=false;}
 // Explicit external RPC and active-session ports. Authentication is not simulated as device proof.
 void requireActive(){activeChecks++;if(retired)throw new IllegalStateException("host session retired");}
 Object call(String operation,Object none,int timeout)throws Exception {
  calls++;lastOperation=operation;lastTimeout=timeout;if(callFailure!=null)throw callFailure;return new Object();}
 void accept(Object response,boolean active)throws Exception{
  accepts++;if(acceptFailure!=null)throw acceptFailure;if(retireOnAccept)retired=true;
 }
""" + installation + "\n" + remote + "\n}\n")
    generated("org/trillionnium/hepta/local/NativeProfileVerifierHostFixture.java",
              """package org.trillionnium.hepta.local;
import android.content.Context;
final class NativeProfileVerifierHostFixture {
 static NativeAppSession.InstalledVerifier bind(final Context service,final String taskId,final TaskCompletionGate completion,
         final BackgroundSession background,final QualificationScopeConfig.CompletionInstalledIdentity nativeInstalled){
""" + bindings + "  return " + callback + ";\n }\n"
              + """ static void post(Context service,String taskId,TaskAuthorization.Gate authorization,BackgroundSession background,
         BackgroundSession activeNativeBackground,NativeAppSession activeNativeTask,
         QualificationScopeConfig.CompletionInstalledIdentity completionInstalled,TaskCompletionGate completion){
""" + post + " }\n"
              + """ static boolean terminal(Context service,QualificationScopeConfig.CompletionInstalledIdentity completionInstalled,
         TaskCompletionGate completion){
  boolean nativeInstalledRechecked=false,modelSuccess=true,controllerSuccess=true;
  String finalStatus="host-done",summary="";
""" + terminal + "  return nativeInstalledRechecked;\n }\n}\n")
    files.extend(inputs[3:5])
    files.append(test)
    return files, inputs, members

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "output", "java-home"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--controller", type=Path, help="Explicit isolated controller draft; otherwise use --source file")
    a = parser.parse_args()
    source, out, java = a.source.resolve(), a.output.resolve(), a.java_home.resolve()
    controller = a.controller.resolve() if a.controller else source / PKG / "LocalTaskController.java"
    test = Path(__file__).with_name("NativeProfileLiveVerifierHostTest.java").resolve()
    if out.exists() or source in out.parents:
        raise RuntimeError("fresh independent host output required")
    out.mkdir(parents=True, mode=0o700)
    report = {"schema": "hepta.native-profile-live-verifier-host.v1", "all_pass": False,
              "source": str(source), "controller": str(controller), "phone_operations": 0,
              "android_runtime": False, "actual_broker_authentication_executed": False,
              "physical_two_second_latency_proved": False, "stages": [],
              "scope": "actual controller callback/final bindings/post-observation/terminal blocks; complete actual CompletionInstalledIdentity, ProfileTarget and ProfileIdentity; actual verifyProfileInstallation and verifyRemote; explicit external I/O ports",
              "started_host_wall_ms": int(time.time()*1000)}
    inputs = []
    try:
        files, inputs, members = prepare(source, controller, test, out / "fixture")
        tools = [java / "bin/java", java / "bin/javac", java / "lib/modules", java / "lib/ct.sym", Path(sys.executable).resolve()]
        report["source_inputs_before"] = [ref(p) for p in inputs]
        report["tools_before"] = [ref(p) for p in tools]
        report["actual_members"] = members
        report["compile_inputs"] = [ref(p) for p in files]
        (out / "ACTUAL-MEMBERS.json").write_text(json.dumps(members, indent=2) + "\n")
        classes = out / "classes"
        classes.mkdir()
        env = dict(os.environ)
        env["PATH"] = str(java / "bin") + ":/usr/bin:/bin"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
            env.pop(key, None)
        stages = [
            ("compile", [java / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none",
                         "-Xlint:all,-options", "-Werror", "-d", classes, *files]),
            ("cases", [java / "bin/java", "-Djava.awt.headless=true", "-cp", classes,
                       "org.trillionnium.hepta.local.NativeProfileLiveVerifierHostTest"])]
        for name, argv in stages:
            start = time.monotonic()
            p = subprocess.run(list(map(str, argv)), cwd=out, env=env, capture_output=True, timeout=120)
            for suffix, raw in (("stdout", p.stdout), ("stderr", p.stderr)):
                (out / (name + "." + suffix)).write_bytes(raw)
            report["stages"].append({"name": name, "argv": list(map(str, argv)), "exit_code": p.returncode,
                                     "elapsed_seconds": time.monotonic() - start,
                                     "stdout": ref(out / (name + ".stdout")), "stderr": ref(out / (name + ".stderr"))})
            if name == "cases":
                lines = p.stdout.decode().splitlines()
                rows = [line.split("\t", 3) for line in lines if line.startswith("CASE\t")]
                totals = [line.split("\t") for line in lines if line.startswith("TOTAL\t")]
                if len(totals) != 1:
                    raise RuntimeError("complete actual case count missing")
                _, count, assertions, failures = totals[0]
                result = {"all_pass": int(failures) == 0, "cases": int(count), "assertions": int(assertions),
                          "failed": int(failures), "rows": [{"name": r[1], "pass": r[2] == "PASS",
                                                          "detail": r[3] if len(r) == 4 else None} for r in rows]}
                if result["cases"] != 22 or len(rows) != 22:
                    raise RuntimeError("exact finite case count differs")
                report["cases"] = result
                (out / "CASES.json").write_text(json.dumps(result, indent=2) + "\n")
            if p.returncode:
                raise RuntimeError("actual stage failed: " + name)
        report["all_pass"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        if inputs and "source_inputs_before" in report:
            report["source_inputs_after"] = [ref(p) for p in inputs]
            report["tools_after"] = [ref(p) for p in tools]
            report["source_inputs_unchanged"] = report["source_inputs_before"] == report["source_inputs_after"]
            report["tools_unchanged"] = report["tools_before"] == report["tools_after"]
            report["all_pass"] &= report["source_inputs_unchanged"] and report["tools_unchanged"]
        report["finished_host_wall_ms"] = int(time.time()*1000)
        (out / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"all_pass": report["all_pass"], "error": report.get("error"),
                      "cases": report.get("cases", {}).get("cases"),
                      "assertions": report.get("cases", {}).get("assertions"),
                      "failed": report.get("cases", {}).get("failed"), "result": str(out / "RESULT.json")}))
    return 0 if report["all_pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
