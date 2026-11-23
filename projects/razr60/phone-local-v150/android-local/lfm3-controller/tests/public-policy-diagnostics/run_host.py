#!/usr/bin/env python3
"""Execute production requireUnlocked and its first-failure audit against host-only ports."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

def identity(p):
    data=p.read_bytes()
    return {"path":str(p),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for k in ("source","output","java-home","json-jar"):
        parser.add_argument("--"+k,type=Path,required=True)
    a=parser.parse_args()
    source,output=a.source.resolve(),a.output.resolve()
    jdk,jar=a.java_home.resolve(),a.json_jar.resolve()
    assert not output.exists() and source not in output.parents
    output.mkdir(mode=0o700)
    broker=source/"src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java"
    template=source/"tests/public-policy-diagnostics/PublicPolicyDiagnosticsHostTest.java"
    before={str(p):identity(p) for p in (broker,template,Path(__file__).resolve(),jar,jdk/"bin/java",jdk/"bin/javac")}
    text=broker.read_text()
    guard=text[text.index("    private void requireUnlocked() throws BrokerProtocol.Refusal {"):text.index("    private void verifyDisplay() throws Exception {")]
    audit=text[text.index("    static final class PublicPolicyFailureAudit {"):text.index("    private static String code(Throwable error) {")]
    assert text.count('.put("public_policy_diagnostics",new JSONObject(publicPolicyFailures.evidence()))')==2
    assert text.count("publicPolicyFailures.record(phase,unavailable,SystemClock.elapsedRealtime())")==1
    assert text.count('if(!explanation.isEmpty())value.put("message",explanation);')==1
    assert 'catch(BrokerProtocol.Refusal refusal){throw refusal;}' in guard
    test=template.read_text()
    assert test.count("/* INSERT_PRODUCTION_AUDIT */")==test.count("/* INSERT_PRODUCTION_GUARD */")==1
    generated=output/"PublicPolicyDiagnosticsHostTest.java"
    generated.write_text(test.replace("/* INSERT_PRODUCTION_AUDIT */",audit).replace("/* INSERT_PRODUCTION_GUARD */",guard))
    classes=output/"classes";classes.mkdir()
    env=dict(os.environ)
    for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
    env["PATH"]=str(jdk/"bin")+":/usr/bin:/bin"
    env["PYTHONDONTWRITEBYTECODE"]="1"
    report={"schema":"hepta.public-policy-diagnostics-host-gate.v1","all_pass":False,
            "source":str(source),"phone_operations":0,"phone_runtime_qualified":False,
            "stages":[],"production_guard_sha256":hashlib.sha256(guard.encode()).hexdigest(),
            "production_audit_sha256":hashlib.sha256(audit.encode()).hexdigest(),"inputs":before}
    def run(name,argv):
        started=time.monotonic()
        with (output/(name+".stdout")).open("xb") as stdout,(output/(name+".stderr")).open("xb") as stderr:
            result=subprocess.run([str(x) for x in argv],env=env,stdout=stdout,stderr=stderr,timeout=120,cwd=source)
        report["stages"].append({"name":name,"exit_code":result.returncode,"seconds":time.monotonic()-started,
                                "stdout":identity(output/(name+".stdout")),"stderr":identity(output/(name+".stderr"))})
        assert result.returncode==0,name+" failed; original output retained"
    try:
        assert identity(jar)["sha256"]=="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
        run("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror","-cp",jar,"-d",classes,generated])
        run("cases",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.background.PublicPolicyDiagnosticsHostTest",output/"CASES.json"])
        cases=json.loads((output/"CASES.json").read_text())
        assert cases["all_pass"] is True and cases["extracted_production_guard_executed"] is True
        assert cases["cases"]==len(cases["case_names"])==len(set(cases["case_names"]))
        report["cases"]=cases;report["all_pass"]=True
    except Exception as error:report["failure"]={"type":type(error).__name__,"message":str(error)}
    finally:
        report["source_and_tools_unchanged"]=before=={p:identity(Path(p)) for p in before}
        report["all_pass"]=report["all_pass"] and report["source_and_tools_unchanged"]
        (output/"RESULT.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
        print(json.dumps({"all_pass":report["all_pass"],"cases":report.get("cases",{}).get("cases"),
                          "assertions":report.get("cases",{}).get("assertions"),"failure":report.get("failure"),
                          "result":str(output/"RESULT.json")},ensure_ascii=False))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":
    sys.dont_write_bytecode=True
    raise SystemExit(main())
