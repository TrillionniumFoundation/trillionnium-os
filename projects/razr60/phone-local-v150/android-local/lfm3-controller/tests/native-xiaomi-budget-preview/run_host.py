#!/usr/bin/env python3
"""Run the public native shopping price-review path using original App XML."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "java-home", "json-jar"):
        parser.add_argument("--"+name, type=Path, required=True)
    args = parser.parse_args()
    source, out, jdk, jar = [p.resolve() for p in (args.source,args.output,args.java_home,args.json_jar)]
    if out.exists() or source in out.parents:
        raise RuntimeError("fresh separate output required")
    out.mkdir(parents=True)
    closure = load(source/"tests/native-search-planning/host_closure.py","preview_real_session")
    query = load(source/"tests/web-flight/run_query_host_tests.py","preview_java_extractor")
    result = {"all_pass":False,"hardware_operations":0,"fixture_scope":"Recorded native public XML with synthetic profile transport, model outcomes and cleanup."}
    try:
        if digest(jar)!=closure.JSON_SHA:
            raise RuntimeError("original JSON library required")
        case = source/"tests/native-xiaomi-budget-preview/NativeXiaomiBudgetPreviewHostTest.java"
        xml = source/"tests/native-app-fixtures/NativeXmlFixture.java"
        login = load(source/"tests/native-xiaomi-login/run_host.py","preview_login_fixture")
        utility = load(source/"tests/native-xiaomi-home-loading/run_host.py","preview_login_fixture_io")
        portable = out/"login-fixture"
        login.fixture(source,portable,utility)
        paths, provenance = closure.prepare(source,out/"closure",(case,xml,portable/"SyntheticXiaomiNativeLoginFixture.java"))
        actual = source/"src/org/trillionnium/hepta/local/LocalTaskController.java"
        port = next(p for p in paths if p.name=="LocalTaskController.java")
        body = query.java_block(actual.read_bytes(),"static final class OutcomeExplanation")
        presentation = out/"presentation/LocalTaskController.java"
        presentation.parent.mkdir()
        original = port.read_text().rstrip()
        if not original.endswith("}") or original.count("final class LocalTaskController")!=1:
            raise RuntimeError("unrecognized legacy controller port")
        presentation.write_text(original[:-1].replace("final class LocalTaskController","import org.json.JSONObject;\nfinal class LocalTaskController")+"\n"+body+"\n}\n")
        paths=[presentation if p==port else p for p in paths]
        fixtures=source/"tests/native-xiaomi-product/fixtures"
        original_files=json.loads((fixtures/"PROVENANCE.json").read_bytes())["files"]
        fixtures_used=[r for r in original_files if r["name"] in ("suggestions","results","detail")]
        if len(fixtures_used)!=3 or any(digest(source/r["fixture_path"])!=r["sha256"] for r in fixtures_used):
            raise RuntimeError("original public native Xiaomi XML differs")
        originals=[actual,*paths,jar,*[source/r["fixture_path"] for r in fixtures_used]]
        pins={str(p):digest(p) for p in originals}
        classes=out/"classes";classes.mkdir()
        environment={**os.environ,"PATH":str(jdk/"bin")+":/usr/bin:/bin"}
        for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):
            environment.pop(k,None)
        stages=[("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror","-cp",jar,"-d",classes,*paths]),
                ("review",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeXiaomiBudgetPreviewHostTest",
                        fixtures,out/"work",out/"CASES.json"])]
        for name,argv in stages:
            process=subprocess.run(list(map(str,argv)),capture_output=True,cwd=out,env=environment,timeout=120,check=False)
            (out/(name+".stdout")).write_bytes(process.stdout);(out/(name+".stderr")).write_bytes(process.stderr)
            if process.returncode:raise RuntimeError(name+" failed")
        cases=json.loads((out/"CASES.json").read_bytes())
        if not cases["all_pass"] or cases["cases"]!=8 or not all(digest(Path(p))==v for p,v in pins.items()):
            raise RuntimeError("case count, judgment or source binding differs")
        result.update(all_pass=True,cases=cases["cases"],assertions=cases["assertions"],source_sha256=pins)
    except Exception as e:
        result["error"]=str(e)
    (out/"RESULT.json").write_text(json.dumps(result,sort_keys=True,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("source_sha256",)},ensure_ascii=False))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":
    raise SystemExit(main())
