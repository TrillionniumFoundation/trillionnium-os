#!/usr/bin/env python3
"""Execute the production terminal journal paths on real host files; no phone operations."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output",required=True)
parser.add_argument("--actual-manifest",type=Path,help="Optional private host-only record/owner paths; never required by CI.")
parser.add_argument("--java-home",type=Path,help="Existing full JDK; defaults to java selected by PATH.")
args=parser.parse_args()
java_home=args.java_home.resolve() if args.java_home else Path(shutil.which("java") or "").resolve().parent.parent
java=java_home/"bin/java"
if not java.is_file() or not (java_home/"bin/javac").is_file():raise RuntimeError("Existing full JDK required; no download or installation.")
root=Path(__file__).resolve().parents[2]
out=Path(args.output).resolve()
out.mkdir(mode=0o700)
src=root/"src/org/trillionnium/hepta/local"
here=Path(__file__).resolve().parent
session=src/"LocalTaskSession.java"
helper=src/"SessionTerminalEvidence.java"
queue=src/"SessionJournalQueue.java"
policy=src/"SessionRecovery.java"
scope=src/"QualificationScopeConfig.java"
template=here/"SessionTerminalHost.template"
legacy=here/"legacy-r13-session.java.inc"
json_fixture=root/"tests/qualification-scope/fixtures/org/json"

def body(source,signature):
    assert source.count(signature)==1,signature
    start=source.index(signature);opening=source.index("{",start)
    depth=0;state="code";i=opening
    while i<len(source):
        c=source[i];n=source[i:i+2]
        if state=="line":
            if c=="\n":state="code"
        elif state=="block":
            if n=="*/":state="code";i+=1
        elif state in ("string","char"):
            if c=="\\":i+=1
            elif (state=="string" and c=='"') or (state=="char" and c=="'"):state="code"
        elif n=="//":state="line";i+=1
        elif n=="/*":state="block";i+=1
        elif c=='"':state="string"
        elif c=="'":state="char"
        elif c=="{":depth+=1
        elif c=="}":
            depth-=1
            if depth==0:return source[start:i+1]
        i+=1
    raise ValueError("unterminated source block")

signatures=[
 "private void receiveFinished(LocalTaskController.TaskResult result) {",
 "private void setState(String value) {",
 "private void persist(String status,boolean cleanupKnown) {",
 "private SessionJournalQueue.Failure journalFailureHook(){",
 "private static String journalFailureDetails(String stage,Exception error){",
 "private static void logJournalFailure(String details){",
 "private void failSessionWrite(long expectedEpoch,Exception error){",
 "private byte[] snapshotSession(String status,boolean cleanupKnown)throws Exception {",
 "private void writeSessionSnapshot(byte[] snapshot)throws Exception {",
 "private void writeSessionSnapshot(byte[] snapshot,LeaseState leases)throws Exception {",
 "private void bindTerminalEvidence(JSONObject value)throws Exception {",
 "private void verifyTerminalEvidence(JSONObject value)throws Exception {",
 "private static JSONObject parseSessionJson(byte[] original)throws Exception{",
 "private static Map<String,Object> fieldsOf(JSONObject prior)throws Exception{",
 "private void recoverPreviousSession() {",
 "private static boolean recordExists(File file)throws Exception{",
 "private static void createInterruptionLatch(File latch,JSONObject reason)throws Exception{",
 "private static byte[] readSessionRecord(File file)throws Exception{",
 "private JSONArray archivePriorRecords(File[] records)throws Exception{",
 "private void persistStartupRecord(String status,boolean cleanupKnown){",
]
source=session.read_text();methods=[body(source,s) for s in signatures]
legacy_text=legacy.read_text()
legacy_methods=[
 body(legacy_text,signatures[7]).replace("snapshotSession(","legacySnapshotSession(",1),
 body(legacy_text,signatures[9]).replace("writeSessionSnapshot(","legacyWriteSessionSnapshot(",1),
]
files_root=body(scope.read_text(),"static final class FilesRoot {")
generated=out/"src";generated.mkdir()
def emit(name,text):
    path=generated/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text);return path
harness=emit("org/trillionnium/hepta/local/SessionTerminalHost.java",
             template.read_text().replace("{{SESSION_METHODS}}","\n".join(methods)).replace("{{LEGACY_METHODS}}","\n".join(legacy_methods)))
for path in sorted(json_fixture.glob("*.java")):
    text=path.read_text()
    if path.name=="JSONArray.java":
        old="public Object get(int i){return values.get(i);}"
        assert text.count(old)==1
        text=text.replace(old,"public Object get(int i){Object v=values.get(i);return v==null?JSONObject.NULL:v instanceof java.util.Map<?,?>?new JSONObject((java.util.Map<?,?>)v):v instanceof java.util.Collection<?>?new JSONArray((java.util.Collection<?>)v):v;}")
    emit("org/json/"+path.name,text)
emit("android/content/Context.java",'package android.content; public final class Context {private final java.io.File files;public Context(java.io.File f){files=f;}public java.io.File getFilesDir(){return files;}}')
emit("android/os/Process.java",'package android.os; public final class Process {public static int myUid(){return 10000;}}')
emit("android/util/Log.java",'package android.util; public final class Log {public static int e(String tag,String text){return 0;}}')
for name in ["OsConstants.java","StructStat.java","ErrnoException.java"]:
    p=root/"tests/qualification-scope/fixtures/android/system"/name
    emit("android/system/"+name,p.read_text())
emit("org/trillionnium/hepta/local/QualificationScopeConfig.java",
     "package org.trillionnium.hepta.local; import android.content.Context; import android.system.*; import java.io.File; import org.json.JSONObject;\n"
     +"final class QualificationScopeConfig {static Object nullable(String v){return v==null?JSONObject.NULL:v;}\n"+files_root
     +"\n}\nfinal class QualificationScope {static void require(boolean v,String why){if(!v)throw new IllegalStateException(why);}}\n")

os_source=(root/"tests/qualification-scope/fixtures/android/system/Os.java").read_text()
def one(text,old,new):
    assert text.count(old)==1,old
    return text.replace(old,new)
os_source=one(os_source,"import java.io.*;import java.nio.file.*;import java.util.*;","import java.io.*;import java.nio.file.*;import java.util.*;import java.nio.channels.FileChannel;")
os_source=one(os_source,"public static String failFsyncPath;","public static String failFsyncPath,failClosePath,failInputClosePath;")
os_source=one(os_source,"final Path path;final RandomAccessFile file;Open(","final Path path;final RandomAccessFile file;FileChannel directory;Open(")
os_source=one(os_source,"r.st_uid=((Number)a.get(\"uid\")).intValue();",
 "int realUid=((Number)a.get(\"uid\")).intValue();r.st_uid=realUid==Integer.getInteger(\"hepta.fixture.host_uid\").intValue()?10000:realUid;")
os_source=one(os_source,"OPEN.put(fd,new Open(p,null));return fd;",
 "Open opened=new Open(p,null);opened.directory=FileChannel.open(p,StandardOpenOption.READ);OPEN.put(fd,opened);return fd;")
os_source=one(os_source,"if(o!=null&&o.file!=null)o.file.close();",
 "if(o==null)throw new IOException(\"untracked close\");if(o.directory!=null)o.directory.close();else if(o.file!=null)o.file.close();if(o.path.toString().equals(failClosePath))throw new IOException(\"injected descriptor close\");")
os_source=one(os_source,"String path=OPEN.get(fd).path.toString();syncLog.add(path);",
 "Open opened=OPEN.get(fd);String path=opened.path.toString();syncLog.add(path);")
os_source=one(os_source,"if(fd.valid())fd.sync();",
 "if(opened.directory!=null)opened.directory.force(true);else fd.sync();")
i=os_source.rfind("}")
os_source=os_source[:i]+r'''
 public static void reset(){failFsyncPath=null;failClosePath=null;failInputClosePath=null;syncLog.clear();}
 public static String pathOf(FileDescriptor fd){Open o=OPEN.get(fd);return o==null?null:o.path.toString();}
 public static int liveDescriptors(){Iterator<Map.Entry<FileDescriptor,Open>> it=OPEN.entrySet().iterator();while(it.hasNext()){Map.Entry<FileDescriptor,Open> e=it.next();if(e.getValue().directory==null&&!e.getKey().valid())it.remove();}return OPEN.size();}
'''+os_source[i:]
os_source=os_source.replace("Directory fsync/Android UID authorization are not simulated claims.",
 "Directory fsync uses real FileChannel.force; Android UID numbering remains an explicit host adapter.")
emit("android/system/Os.java",os_source)

emit("host/android/FileInputStream.java",r'''package host.android;
import java.io.FileDescriptor;import java.io.IOException;
/** Android-equivalent supplied-descriptor ownership: close does not close our caller's FD. */
public final class FileInputStream extends java.io.FileInputStream {
 public FileInputStream(FileDescriptor fd){super(fd);}
 @Override public void close()throws IOException {
  String path=android.system.Os.pathOf(getFD());
  if(path!=null&&path.equals(android.system.Os.failInputClosePath))throw new IOException("injected input close");
 }
}
''')
emit("android/util/AtomicFile.java",r'''package android.util;
import java.io.*;import java.nio.file.*;
/** Real .new output and atomic replacement; failures never fabricate a successful write. */
public final class AtomicFile {
 public static boolean rejectRename;public static Runnable afterCommit;
 private final File file,next;
 public AtomicFile(File f){file=f;next=new File(f.getPath()+".new");}
 public File getBaseFile(){return file;}
 public FileOutputStream startWrite()throws IOException {FileOutputStream out=new FileOutputStream(next);android.system.Os.trackOutput(out.getFD(),next.getPath());return out;}
 public void finishWrite(FileOutputStream out)throws IOException {
  android.system.Os.forgetOutput(out.getFD());out.close();if(rejectRename)throw new IOException("injected atomic rename failure");
  Files.move(next.toPath(),file.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
  Runnable r=afterCommit;afterCommit=null;if(r!=null)r.run();
 }
 public void failWrite(FileOutputStream out){try{android.system.Os.forgetOutput(out.getFD());out.close();Files.deleteIfExists(next.toPath());}catch(IOException ignored){}}
 public static void reset(){rejectRename=false;afterCommit=null;}
}
''')
text=harness.read_text();a=text.index("\nclass RecoveryJournalTransaction");b=text.index("\nclass RecoveryJournalStore",a)
harness.write_text(text[:a]+"\n")
emit("org/trillionnium/hepta/local/RecoveryJournalTransaction.java",
 "package org.trillionnium.hepta.local;import java.io.IOException;import java.util.Map;\n"+text[a:b])
emit("org/trillionnium/hepta/local/RecoveryJournalStore.java",
 "package org.trillionnium.hepta.local;import android.content.Context;import java.util.*;\n"+text[b:])

def identity(path):
    raw=path.read_bytes()
    return {"path":str(path.relative_to(root)),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
source_inputs=[session,helper,queue,policy,scope,template,legacy,here/"legacy-r13-source.json",Path(__file__).resolve()]
source_inputs+=sorted(json_fixture.glob("*.java"))
source_inputs += [root/"tests/qualification-scope/fixtures/android/system"/n for n in ["Os.java","OsConstants.java","StructStat.java","ErrnoException.java"]]
pins=json.loads((here/"legacy-r13-source.json").read_text())
assert pins["parent_commit"]=="c8a1f0f9d2b3de3d75758a661ca5efc85a582e4f"
assert pins["parent_source_sha256"]=="a18389449b2c737233004dfab8bcbd70d5e079752b6c414e0435967d82ac20f5"
assert pins["fixture_sha256"]==hashlib.sha256(legacy.read_bytes()).hexdigest()
record={"schema":"hepta.session-terminal-host-run.v1","all_pass":False,
 "source_inputs":[identity(p) for p in source_inputs],
 "extracted_methods":[{"signature":s,"body_sha256":hashlib.sha256(b.encode()).hexdigest()} for s,b in zip(signatures,methods)],
 "legacy_parent":pins,"java8_bytecode_target":True,"java8_api_cross_compile":False,
 "java_home":str(java_home),"android_compilation":False,"host_uid_numbering_and_fstat_path_lookup_are_adapters":True,
 "real_host_file_sync_directory_force_and_atomic_move":True,"owner_acknowledgement_proof_is_not_stubbed_as_passing":True,
 "private_replay_requested":args.actual_manifest is not None,"phone_operations":0,"modes":[]}
if args.actual_manifest:
    args.actual_manifest=args.actual_manifest.resolve()
    assert root not in out.parents and root!=out
    assert root not in args.actual_manifest.parents
    requests=json.loads(args.actual_manifest.read_text())
    record["private_inputs"]=[]
    for row in requests["records"]:
        for key in ["result_path","owner_path"]:
            path=Path(row[key]).resolve();assert path.is_file() and root not in path.parents
            raw=path.read_bytes();record["private_inputs"].append({"kind":key,"path":str(path),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
common_sources=sorted(generated.rglob("*.java"))+[queue,policy]
for mode in ["host_owning_stream","android_nonowning_stream"]:
    mode_dir=out/mode;mode_dir.mkdir();classes=mode_dir/"classes";classes.mkdir()
    text=helper.read_text()
    if mode=="android_nonowning_stream":
        text=one(text,"import java.io.FileInputStream;","import host.android.FileInputStream;")
    actual_helper=mode_dir/"SessionTerminalEvidence.java";actual_helper.write_text(text)
    row={"mode":mode,"helper_source_sha256":hashlib.sha256(text.encode()).hexdigest(),
         "helper_adaptation":"one FileInputStream import replacement only" if mode=="android_nonowning_stream" else "exact production source",
         "all_pass":False}
    command=[str(java),"-m","jdk.compiler/com.sun.tools.javac.Main","-encoding","UTF-8","-source","8","-target","8","-Xlint:all,-options","-Werror","-d",str(classes)]+[str(p) for p in common_sources]+[str(actual_helper)]
    row["compile_command"]=command;p=subprocess.run(command,capture_output=True,timeout=90)
    (mode_dir/"compiler.stdout").write_bytes(p.stdout);(mode_dir/"compiler.stderr").write_bytes(p.stderr);row["compiler_returncode"]=p.returncode
    if p.returncode==0:
        command=[str(java),"-Dhepta.fixture.host_uid="+str(os.getuid()),"-Dhepta.fixture.nonowning="+str(mode=="android_nonowning_stream").lower(),
                 "-cp",str(classes),"org.trillionnium.hepta.local.SessionTerminalHost",str(mode_dir/"files")]
        if args.actual_manifest:command.append(str(args.actual_manifest))
        row["run_command"]=command;p=subprocess.run(command,capture_output=True,timeout=90)
        (mode_dir/"runtime.stdout").write_bytes(p.stdout);(mode_dir/"runtime.stderr").write_bytes(p.stderr);row["runtime_returncode"]=p.returncode
        if p.returncode==0:
            row["runtime"]=json.loads(p.stdout);row["all_pass"]=row["runtime"]["all_pass"] is True
    record["modes"].append(row)
    if not row["all_pass"]:break
record["source_inputs_unchanged"]=record["source_inputs"]==[identity(p) for p in source_inputs]
record["generated_fixture_sources"]=[{"path":str(p.relative_to(out)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(generated.rglob("*.java"))]
record["all_pass"]=len(record["modes"])==2 and all(m["all_pass"] for m in record["modes"]) and record["source_inputs_unchanged"]
record["cases"]=sum(m.get("runtime",{}).get("cases",0) for m in record["modes"])
record["assertions"]=sum(m.get("runtime",{}).get("assertions",0) for m in record["modes"])
record["runtime"]={"schema":"hepta.session-terminal-host-cases.v1","all_pass":record["all_pass"],
 "cases":record["cases"],"assertions":record["assertions"],
 "case_names":[m["mode"]+"/"+n for m in record["modes"] for n in m.get("runtime",{}).get("case_names",[])]}
assert len(record["runtime"]["case_names"])==record["cases"]
assert len(set(record["runtime"]["case_names"]))==record["cases"]
(out/"CASES.json").write_text(json.dumps(record["runtime"],ensure_ascii=False,indent=2)+"\n")
(out/"RESULT.json").write_text(json.dumps(record,ensure_ascii=False,indent=2)+"\n")
print(json.dumps({"all_pass":record["all_pass"],"cases":record["cases"],"assertions":record["assertions"],"modes":[{"mode":m["mode"],"compile":m["compiler_returncode"],"run":m.get("runtime_returncode")} for m in record["modes"]],"result":str(out/"RESULT.json")}))
raise SystemExit(0 if record["all_pass"] else 1)
