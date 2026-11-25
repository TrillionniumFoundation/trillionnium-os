#!/usr/bin/env python3
"""Actual diagnostic class/consumer with the previously successful, unchanged
retirement gate's complete source and Android IO fixture closure. No phone.
The closure is freshly compiled; previous .class files are never consumed.
"""
import argparse,hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
BROKER_PARENT="a4f8e3ea65e4ac70f0239b14426496af5fb80bb21ac6e793debf4062393dfc4a"
NEAREST=[
 (7043,"e8f46cb6dcf452e06ec660f0ad308355de5537ae2c95817c270a58b4709a3d86"),
 (7044,"357b4fe308797eb321a94a6df1e366449f5ab38bd6ba9798bfc7d4e2c80259c2"),
 (5389,"373bbedbc2b5dfa6c2c2b44059322f971c4039455b436300e8da36dfe2b00c31"),
 (5389,"1287981d962c6f98a5fd445392dbf526784d5a3e24abdc3bea20e54277184654")]
EXPECTED=[
 "unchanged complete history retains original acceptance",
 "all owned tasks remain excluded from foreign comparison",
 "preamble refusal preserves exact class code and byte pair",
 "absolute foreign activity time remains a refusal",
 "relative age allowed by original budget remains accepted",
 "relative age excess keeps original distinct refusal",
 "visible foreign field remains protected",
 "foreign membership remains protected",
 "UTF8 content and missing final newline round trip exactly",
 "raw pair exact fixed byte cap is included",
 "raw pair one byte beyond cap is explicitly omitted",
 "UTF8 byte bound is not a character bound",
 "null current retains original refusal and no invented raw",
 "unrelated errors do not emit a diagnostic",
 "typed cause cannot be used under a different error",
 "actual broker formatter preserves terminal fields and bounded repeated output",
 "broker diagnostic bound omits pair without changing originals",
 "whole-terminal bound leaves original fields and limits intact",
 "actual coordinator pre-effect refusal does not dispatch",
 "actual post-returned refusal retains single attempted effect"]
def need(ok,message):
    if not ok:raise ValueError(message)
def ref(path):
    p=Path(path).absolute();s=p.lstat()
    need(stat.S_ISREG(s.st_mode) and not p.is_symlink(),"regular file required")
    raw=p.read_bytes();after=p.lstat()
    need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),"input changed while read")
    return dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def same_ref(value):
    current=ref(value["path"])
    need(current=={k:value[k] for k in ("path","bytes","sha256")},"actual input differs: "+value["path"])
def unique(text,old,new):
    need(text.count(old)==1,"unique exact source hunk required")
    return text.replace(old,new)
def put(path,value):
    with path.open("x",encoding="utf-8") as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write("\n")
def close_reply_proof_copy(text):
    # Only this exact admitted-close source may be reversed for the historical proof.
    # Extraction and compilation below continue to use the unmodified actual text.
    if hashlib.sha256(text.encode()).hexdigest()=="abccc17b66df24056a75bb44d8b0f9c6c790727cf0ac2abd4067a0d27d60ea7c":
        text=unique(text,
            "    // Only an authenticated, already admitted profile or personal Notes close RPC owns this peer.\n",
            "    // Only the authenticated, already admitted work-profile close RPC can own this peer.\n")
        text=unique(text,
            '                        if(config.publicOwnGroupScope!=null&&(config.profileTarget!=null||publicNotesCustody!=null)&&"close".equals(request.operation))\n',
            '                        if(config.publicOwnGroupScope!=null&&config.profileTarget!=null&&"close".equals(request.operation))\n')
        need(hashlib.sha256(text.encode()).hexdigest()=="a74cd6c88a4468631c8e3d2f70fab7e1a6e7d66a6749cfc0c98742456a3f6f44",
             "exact authenticated Notes close inverse must restore the entire diagnostic broker")
    return text
def extract_broker(source,out):
    path=source/"src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java";text=path.read_text()
    begin="    /** Diagnostic-only augmentation of the original single terminal object.\n"
    end="    private static int fields(Class<?> type, String... names) throws Exception {"
    need(text.count(begin)==1 and text.count(end)==1,"exact broker diagnostic method boundaries")
    first,last=text.index(begin),text.index(end)
    helper=text[first:last]
    methods=helper[helper.index("    static void appendNotesHistoryDiagnostic("):]
    restored=unique(close_reply_proof_copy(text),helper,"")
    call='            if(config.publicOwnGroupScope!=null)appendNotesHistoryDiagnostic(terminal,publicNotesCleanupFailure,\n                    config.publicOwnGroupScope.taskId,config.generation,config.publicOwnGroupScope.sha256,displayId);\n'
    restored=unique(restored,call,"")
    restored=unique(restored,"    private volatile Throwable publicNotesCleanupFailure;\n","")
    restored=unique(restored,"                if(publicNotesCleanupFailure==null)publicNotesCleanupFailure=error;\n","")
    need(hashlib.sha256(restored.encode()).hexdigest()==BROKER_PARENT,"unchanged original broker whole-file proof")
    need(text.count("            System.out.println(terminal); }")==1
         and text.index(call)<text.index("            System.out.println(terminal); }"),"same single terminal output must follow augmentation")
    body="""package org.trillionnium.hepta.background;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;
/** Exact production diagnostic method; host caller supplies original JSON. */
final class NotesHistoryBrokerOutputHost {
    static final String TASK="22222222222242228222222222222222";
    static final String GEN="11111111-1111-4111-8111-111111111111";
"""+methods+"}\n"
    target=out/"NotesHistoryBrokerOutputHost.java";target.write_text(body)
    return target,dict(source=ref(path),methods_sha256=hashlib.sha256(methods.encode()).hexdigest(),
                       actual_methods_byte_exact=True,original_broker_whole_sha256=BROKER_PARENT,
                       original_broker_restored=True,full_android_broker_compiled=False,generated=ref(target))
def decode_pair(value):
    import base64,zlib
    need(value.get("raw_pair_complete") is True,"complete pair required")
    pair=value["raw_pair"]
    need(set(pair)=={"encoding","decoded_bytes","decoded_sha256","compressed_bytes","compressed_sha256","data"}
         and pair["encoding"]=="gzip-base64-concatenated-original-utf8","closed gzip pair schema")
    left=value["baseline"];right=value["current"]
    for row in (left,right):
        need(type(row["bytes"]) is int and 0<row["bytes"]<=32768,"raw part length")
        need(isinstance(row["sha256"],str) and len(row["sha256"])==64,"raw part hash")
    size=left["bytes"]+right["bytes"]
    need(size<=32768 and type(pair["decoded_bytes"]) is int and pair["decoded_bytes"]==size,"fixed decoded pair bound")
    need(type(pair["compressed_bytes"]) is int and 0<pair["compressed_bytes"]<=65536
         and isinstance(pair["data"],str) and len(pair["data"])<=87384,"encoded pair bound")
    compressed=base64.b64decode(pair["data"],validate=True)
    need(base64.b64encode(compressed).decode()==pair["data"] and len(compressed)==pair["compressed_bytes"]
         and hashlib.sha256(compressed).hexdigest()==pair["compressed_sha256"],"canonical compressed bytes")
    inflater=zlib.decompressobj(31);raw=inflater.decompress(compressed,size+1)
    need(len(raw)==size and inflater.eof and not inflater.unconsumed_tail and not inflater.unused_data
         and inflater.flush(1)==b"","exact single gzip end and output bound")
    need(hashlib.sha256(raw).hexdigest()==pair["decoded_sha256"],"complete raw SHA")
    a,b=raw[:left["bytes"]],raw[left["bytes"]:]
    need(hashlib.sha256(a).hexdigest()==left["sha256"] and hashlib.sha256(b).hexdigest()==right["sha256"],"raw part SHA")
    a.decode("utf-8",errors="strict");b.decode("utf-8",errors="strict")
    return a,b
def decoder_negatives(original):
    import base64,copy,gzip
    names=[]
    def rejected(name,change):
        value=copy.deepcopy(original);change(value)
        try:decode_pair(value)
        except Exception:names.append(name);return
        raise AssertionError("diagnostic decoder accepted "+name)
    def compressed(value,change):
        pair=value["raw_pair"];raw=change(base64.b64decode(pair["data"]))
        pair.update(data=base64.b64encode(raw).decode(),compressed_bytes=len(raw),compressed_sha256=hashlib.sha256(raw).hexdigest())
    rejected("truncated gzip",lambda v:compressed(v,lambda b:b[:-1]))
    rejected("trailing byte",lambda v:compressed(v,lambda b:b+b"x"))
    rejected("second gzip member",lambda v:compressed(v,lambda b:b+b))
    rejected("gzip CRC mutation",lambda v:compressed(v,lambda b:b[:-8]+bytes([b[-8]^1])+b[-7:]))
    rejected("noncanonical Base64",lambda v:v["raw_pair"].update(data=v["raw_pair"]["data"]+"\n"))
    rejected("decoded length substitution",lambda v:v["raw_pair"].update(decoded_bytes=v["raw_pair"]["decoded_bytes"]+1))
    rejected("combined SHA substitution",lambda v:v["raw_pair"].update(decoded_sha256="0"*64))
    rejected("part SHA substitution",lambda v:v["baseline"].update(sha256="0"*64))
    rejected("expanded output bomb",lambda v:compressed(v,lambda b:gzip.compress(b"x"*32769,mtime=0)))
    rejected("unknown codec field",lambda v:v["raw_pair"].update(extra=True))
    def invalid_utf8(value):
        a,b=decode_pair(value);a=b"\xff"+a[1:];raw=a+b;zipped=gzip.compress(raw,mtime=0)
        value["baseline"]["sha256"]=hashlib.sha256(a).hexdigest()
        value["raw_pair"].update(data=base64.b64encode(zipped).decode(),compressed_bytes=len(zipped),
            compressed_sha256=hashlib.sha256(zipped).hexdigest(),decoded_sha256=hashlib.sha256(raw).hexdigest())
    rejected("invalid UTF8 with corrected hashes",invalid_utf8)
    need(len(names)==11,"complete decoder negative set")
    return names
def main():
    p=argparse.ArgumentParser()
    for key in ("source","retirement-result","java-home","json-jar","output"):p.add_argument("--"+key,type=Path,required=True)
    for key in ("nearest-before","nearest-preclear","nearest-after","nearest-after2"):p.add_argument("--"+key,type=Path)
    p.add_argument("--actual-terminal",type=Path)
    a=p.parse_args();s=a.source.resolve(strict=True);out=a.output.absolute()
    need(not out.exists() and out!=s and s not in out.parents,"new outside-source output required")
    nearest=[a.nearest_before,a.nearest_preclear,a.nearest_after,a.nearest_after2]
    need(all(x is None for x in nearest) or all(x is not None for x in nearest),"complete nearest four required")
    nearest=[] if nearest[0] is None else [x.resolve(strict=True) for x in nearest]
    need(bool(nearest)==bool(a.actual_terminal),"complete nearest records and actual terminal required together")
    if a.actual_terminal:
        term=ref(a.actual_terminal);need((term["bytes"],term["sha256"])==(4814,"95dd8a66b4e1358ea1bbe2afb120789741339fe36a43402330ff331ab2dc5c7a"),"actual terminal pin differs")
    for path,(size,sha) in zip(nearest,NEAREST):
        value=ref(path);need((value["bytes"],value["sha256"])==(size,sha),"nearest original pin differs")
    need(ref(a.json_jar)["sha256"]==JSON_SHA,"fixed actual JSON jar required")
    prior=json.loads(a.retirement_result.read_text())
    need(prior.get("all_pass") is True and prior.get("inputs_unchanged") is True
         and prior["inputs_before"]==prior["inputs_after"],"complete actual retirement gate required")
    for value in prior["inputs_after"]:same_ref(value)
    production=prior["actual_production_inputs"]
    need(len(production)==17 and len({v["path"] for v in production})==17,"complete real retirement closure required")
    for value in production:
        need(Path(value["path"]).parent==s/"src/org/trillionnium/hepta/background","same current source production required")
    stages=prior["stages"];compile_stage=stages[0]
    need(compile_stage["name"]=="compile" and compile_stage["exit_code"]==0
         and len(stages)==6 and all(x["exit_code"]==0 for x in stages),"original gate complete stage set required")
    argv=compile_stage["argv"][:]
    need(Path(argv[0])==a.java_home.resolve()/"bin/javac" and "--release" in argv and argv[argv.index("--release")+1]=="8"
         and argv[argv.index("-cp")+1]==str(a.json_jar.resolve()),"exact release8 compiler and JSON closure")
    out.mkdir(mode=0o700);classes=out/"classes";classes.mkdir()
    generated,derivation=extract_broker(s,out)
    test=s/"tests/notes-history-diagnostics/NotesHistoryDiagnosticsHostTest.java"
    argv[argv.index("-d")+1]=str(classes);argv += [str(test),str(generated)]
    java_inputs=[Path(x) for x in argv if str(x).endswith(".java")]
    need(len(java_inputs)==len(set(java_inputs)),"no shadowed production class inputs")
    tracked=list(dict.fromkeys(java_inputs+[s/"src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java",
        Path(__file__).resolve(),a.retirement_result.resolve(),a.json_jar.resolve(),a.java_home.resolve()/"bin/javac",
        a.java_home.resolve()/"bin/java",a.java_home.resolve()/"lib/ct.sym"]+nearest+([a.actual_terminal.resolve()] if a.actual_terminal else [])))
    before=[ref(path) for path in tracked]
    result=dict(schema="hepta.notes-history-diagnostics-host.v1",all_pass=False,phone_operations=0,
                source=str(s),retirement_result=ref(a.retirement_result),actual_production_inputs=production,
                compile_inputs=[ref(path) for path in java_inputs],broker_derivation=derivation,
                inputs_before=before,stages=[],exact_failed_pair_available=False,phone_cleanup_claimed=False)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
    for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH","PYTHONPATH"):env.pop(k,None)
    commands=[("compile",argv),("cases",[str(a.java_home.resolve()/"bin/java"),"-ea","-cp",
        str(classes)+os.pathsep+str(a.json_jar.resolve()),"org.trillionnium.hepta.background.NotesHistoryDiagnosticsHostTest",
        str(out/"pairs")]+[str(x) for x in nearest]+([str(a.actual_terminal.resolve())] if a.actual_terminal else []))]
    try:
        for name,cmd in commands:
            began=time.monotonic()
            with (out/(name+".stdout")).open("xb") as so,(out/(name+".stderr")).open("xb") as se:
                done=subprocess.run(cmd,cwd=s,stdin=subprocess.DEVNULL,stdout=so,stderr=se,env=env,timeout=120)
            result["stages"].append(dict(name=name,argv=cmd,exit_code=done.returncode,seconds=time.monotonic()-began,
                stdout=ref(out/(name+".stdout")),stderr=ref(out/(name+".stderr"))))
            need(done.returncode==0,"actual "+name+" failed; originals retained")
        cases=json.loads((out/"cases.stdout").read_text().splitlines()[-1])
        need(cases["all_pass"] is True and cases["case_names"]==EXPECTED and cases["case_count"]==len(EXPECTED)
             and cases["phone_operations"]==0 and cases["original_cleanup_gate_relaxed"] is False,"exact named diagnostic cases")
        result["cases"]=cases
        need(len(cases["nearest_actual_comparisons"])==len(nearest)-1 if nearest else not cases["nearest_actual_comparisons"],"nearest comparison count")
        for comparison in cases["nearest_actual_comparisons"]:
            need(comparison["exact_failure_pair"] is False and comparison["cleanup_qualification"] is False
                 and comparison["causal_attribution_to_original_failure"] is False,"nearest evidence scope")
        result["pair_artifacts"]=[ref(out/"pairs"/name) for name in ("preamble-pair.json","broker-record.json","post-returned-pair.json")]
        for value in result["pair_artifacts"]:decode_pair(json.loads(Path(value["path"]).read_text()))
        packet=json.loads((out/"pairs/broker-record.json").read_text())
        result["decoder_negative_cases"]=decoder_negatives(packet)
        result["consumer_terminal_artifacts"]=[]
        if nearest:
            need(cases["consumer_transport_fixtures"]["host_derived_fixtures"] is True
                 and cases["consumer_transport_fixtures"]["not_original_phone_evidence"] is True,"consumer fixture scope")
            original=json.loads(a.actual_terminal.read_text())
            for label in ("normal","max","omitted"):
                value=cases["consumer_transport_fixtures"][label];same_ref(value)
                terminal=json.loads(Path(value["path"]).read_text());detail=terminal.pop("personal_notes_history_diagnostic")
                need(terminal==original,"original terminal fields changed")
                if label=="omitted":need(detail["raw_pair_complete"] is False and "raw_pair" not in detail,"omitted packet differs")
                else:decode_pair(detail)
                result["consumer_terminal_artifacts"].append(value)
        result["compiled_artifacts"]=[ref(path) for path in sorted(classes.rglob("*.class"))]
        result["all_pass"]=True
    except BaseException as e:result["error"]={"type":type(e).__name__,"message":str(e)}
    finally:
        result["inputs_after"]=[ref(path) for path in tracked]
        result["inputs_unchanged"]=result["inputs_before"]==result["inputs_after"]
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"]
        put(out/"RESULT.json",result)
    print(json.dumps(dict(all_pass=result["all_pass"],error=result.get("error"),result=ref(out/"RESULT.json"),
                         cases=result.get("cases",{}).get("case_count"),assertions=result.get("cases",{}).get("assertions"))))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
