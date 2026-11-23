#!/usr/bin/env python3
"""Offline import contract, real file publication and actual Engine slot checks; no phone or model."""
import argparse,hashlib,importlib.util,json,os,shutil,subprocess,time
from pathlib import Path
def sha(raw): return hashlib.sha256(raw).hexdigest()
def need(value,message):
    if not value: raise RuntimeError(message)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ("source","output","java-home","json-jar"): parser.add_argument("--"+key,type=Path,required=True)
    args=parser.parse_args();source=args.source.resolve(strict=True);out=args.output.absolute()
    need(os.getuid()!=0,"non-root POSIX host required")
    need(all(path.is_absolute() for path in vars(args).values()),"absolute paths required")
    need(source not in out.parents and source!=out,"output outside source required")
    out.mkdir(parents=True,exist_ok=False)
    inputs={};steps=[];result={"schema":"hepta.offline-model-import-host-gate.v1","all_pass":False,
        "phone_operations":0,"native_model_executed":False,"external_model_used":False,
        "android_sdk_api_compilation":False,"android_runtime":False,"steps":steps}
    def take(path):
        raw=path.read_bytes();inputs[str(path)]={"bytes":len(raw),"sha256":sha(raw)};return raw
    def run(name,argv,timeout=120):
        start=time.monotonic();child=subprocess.run(list(map(str,argv)),cwd=out,capture_output=True,timeout=timeout)
        (out/(name+".stdout")).write_bytes(child.stdout);(out/(name+".stderr")).write_bytes(child.stderr)
        steps.append({"name":name,"argv":list(map(str,argv)),"exit_code":child.returncode,"seconds":time.monotonic()-start})
        need(child.returncode==0,name+" failed; inspect "+str(out/(name+".stderr")))
    try:
        test=source/"tests/offline-model-import";take(test/"README.md");take(Path(__file__).resolve())
        registry=json.loads(take(source/"tests/local-model-settings/PRODUCTION-SOURCES.json"))
        names=registry["sources"]+[f"src/org/trillionnium/hepta/local/{name}.java" for name in
                ("ModelImportStream","LocalModelImportFile","LocalModelImportAsset","LocalModelImport")]
        need(len(names)==43 and len(set(names))==43,"exact production dependency list differs")
        actual=[source/name for name in names]
        for path in actual: take(path)
        # Keep the exact original 43-source contract; append only explicit new
        # parser/type dependencies with nonconstructible legacy-only search ports.
        search_helper=source/"tests/native-app/legacy-boundary/prepare_search_pure.py";take(search_helper)
        search_spec=importlib.util.spec_from_file_location("offline_import_search_pure",search_helper)
        search_pure=importlib.util.module_from_spec(search_spec);search_spec.loader.exec_module(search_pure)
        compile_sources=search_pure.add(source,actual)
        for path in compile_sources[len(actual):]: take(path)

        # Actual DecisionGrammar now names a calendar Offer. This old offline
        # import gate gets only unreachable private/all-throw type shapes.
        constant_source=source/"src/org/trillionnium/hepta/local/NativeCalendarDateIntent.java"
        constant_raw=take(constant_source)
        constants=b'    static final String SCHEMA="hepta.native-calendar-select-date.v1",ACTION="calendar.select_date";'
        need(constant_raw.splitlines().count(constants)==1,"actual calendar schema/action constants changed")
        names_in_compile={p.name for p in compile_sources}
        need(not names_in_compile.intersection({"NativeAppSession.java","NativeCalendarDateEnvelope.java","NativeCalendarDateIntent.java"}),
             "calendar boundary must not shadow any original compiler source")
        ports=out/"calendar-legacy-types";ports.mkdir()
        port_values=[
          ("NativeAppSession.java",b"""package org.trillionnium.hepta.local;
final class NativeAppSession {
    private NativeAppSession(){throw unavailable();}
    private static UnsupportedOperationException unavailable(){return new UnsupportedOperationException("No calendar Session in offline import gate");}
    static final class CalendarOffer {
        final NativeCalendarDateEnvelope source=null;
        final CalendarGrammar protocol=null;
        private CalendarOffer(){throw unavailable();}
        void claimGrammar(TaskAuthorization.Frame owner)throws Exception{throw unavailable();}
        void close(){throw unavailable();}
    }
    static final class CalendarGrammar {
        final String grammar=null,grammarSha256=null;
        private CalendarGrammar(){throw unavailable();}
    }
}
"""),
          ("NativeCalendarDateEnvelope.java",b"""package org.trillionnium.hepta.local;
final class NativeCalendarDateEnvelope {
    final Facts facts=null;
    static final class Facts {
        final String observationId=null,packageName=null;
        private Facts(){throw new UnsupportedOperationException("No calendar frame in offline import gate");}
    }
    private NativeCalendarDateEnvelope(){throw new UnsupportedOperationException("No calendar envelope in offline import gate");}
}
"""),
          ("NativeCalendarDateIntent.java",b"""package org.trillionnium.hepta.local;
final class NativeCalendarDateIntent {
"""+constants+b"""
    private NativeCalendarDateIntent(){throw new UnsupportedOperationException("No calendar intent in offline import gate");}
}
""")]
        generated_calendar=[]
        for name,value in port_values:
            p=ports/name
            with p.open("xb") as stream:stream.write(value)
            generated_calendar.append(p)
        compile_sources += generated_calendar
        result["calendar_type_boundary"]={"constant_source":str(constant_source),
            "constant_source_sha256":sha(constant_raw),
            "generated":[{"path":str(p),"bytes":p.stat().st_size,"sha256":sha(p.read_bytes())} for p in generated_calendar],
            "private_constructors_and_all_calendar_methods_throw":True,
            "calendar_authority_created":False,"calendar_behavior_executed":False}
        fixtures=out/"fixtures";shutil.copytree(source/"tests/local-model-settings/fixtures",fixtures)
        for path in sorted((source/"tests/local-model-settings/fixtures").rglob("*.java")): take(path)
        for path in sorted((test/"fixtures").rglob("*.java")):
            take(path);target=fixtures/path.relative_to(test/"fixtures");target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(path.read_bytes())
        osfile=fixtures/"android/system/Os.java"
        old=osfile.read_text();need(old.rstrip().endswith("}"),"original Os boundary differs")
        extra="""
 public static void link(String from,String to)throws ErrnoException{
  try{hit("BEFORE_LINK",to);Files.createLink(Paths.get(to),Paths.get(from));hit("AFTER_LINK",to);}
  catch(Exception e){throw failure("link",e);}
 }
 public static void remove(String path)throws ErrnoException{
  try{hit("BEFORE_UNLINK",path);Files.delete(Paths.get(path));hit("AFTER_UNLINK",path);}
  catch(Exception e){throw failure("remove",e);}
 }
"""
        osfile.write_text(old.rstrip()[:-1]+extra+"}\n")
        generated=sorted(fixtures.rglob("*.java"));need(len(generated)==19,"explicit host boundary count differs")
        host=test/"OfflineModelImportHostTest.java";take(host)
        jar=take(args.json_jar)
        need(len(jar)==78332 and sha(jar)=="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed","existing pinned org.json 20240303 required")
        java=args.java_home/"bin/java";javac=args.java_home/"bin/javac"
        classes=out/"classes";classes.mkdir();empty=out/"empty-sourcepath";empty.mkdir()
        run("compile",[javac,"--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-proc:none",
            "-sourcepath",empty,"-cp",args.json_jar,"-d",classes,*compile_sources,*generated,host])
        run("cases",[java,"-Dhepta.fixture.host_uid="+str(os.getuid()),"-cp",str(classes)+os.pathsep+str(args.json_jar),
            "org.trillionnium.hepta.local.OfflineModelImportHostTest",out/"cases"])
        cases=json.loads((out/"cases/RESULT.json").read_text())
        need(cases["passed"] and cases["cases"]==31 and len(cases["case_results"])==31,"case count or outcomes differ")
        need(all(row["passed"] for row in cases["case_results"]),"one case failed")
        result.update(all_pass=True,cases=cases,java_release_api_check=True)
    except Exception as error: result["error"]=str(error)
    result["source_inputs"]=inputs
    result["inputs_unchanged"]=all(sha(Path(path).read_bytes())==record["sha256"] for path,record in inputs.items())
    result["all_pass"]=result["all_pass"] and result["inputs_unchanged"]
    (out/"RESULT.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"result":str(out/"RESULT.json")}))
    return 0 if result["all_pass"] else 1
if __name__=="__main__": raise SystemExit(main())

