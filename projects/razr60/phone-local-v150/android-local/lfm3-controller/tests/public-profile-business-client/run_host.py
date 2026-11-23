#!/usr/bin/env python3
"""Actual positive-step client and lease CAS; explicit Android/stat/PM/root-process IO."""
import argparse, hashlib, importlib.util, json, os, re, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True

def ref(path):
    p=Path(path).resolve(strict=True);b=p.read_bytes()
    return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),mode=p.stat().st_mode&0o777)

def write(path,obj):
    with path.open('xb') as f:f.write((json.dumps(obj,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode())

def inventory(source):
    result={}
    for p in sorted(source.rglob('*')):
        if any(x in ('.git','__pycache__') for x in p.relative_to(source).parts):continue
        if p.is_symlink():raise RuntimeError('source symlink')
        if p.is_file():
            row=ref(p);row.pop('path');result[p.relative_to(source).as_posix()]=row
    return result

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def replace(path,old,new):
    text=path.read_text()
    if text.count(old)!=1:raise RuntimeError('explicit fixture seam changed: '+str(path)+' '+old[:100])
    path.write_text(text.replace(old,new))

def stage(name,argv,out,cwd):
    started=time.monotonic();error=None
    try:
        p=subprocess.run(argv,cwd=cwd,capture_output=True,timeout=120);code,so,se=p.returncode,p.stdout,p.stderr
    except Exception as ex:code,so,se,error=None,b'',str(ex).encode(),repr(ex)
    (out/(name+'.stdout')).write_bytes(so);(out/(name+'.stderr')).write_bytes(se)
    return dict(name=name,argv=argv,cwd=str(cwd),exit_code=code,error=error,elapsed_seconds=time.monotonic()-started,
                stdout=ref(out/(name+'.stdout')),stderr=ref(out/(name+'.stderr')))

def main():
    ap=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar','original-paths'):ap.add_argument('--'+name,required=True,type=Path)
    a=ap.parse_args();src=a.source.resolve();out=a.output.absolute();out.mkdir(mode=0o700)
    bg=src/'src/org/trillionnium/hepta/background';local=src/'src/org/trillionnium/hepta/local'
    test=src/'tests/public-profile-business-client';helper=src/'tests/background-session/prepare_fixture.py'
    before=inventory(src);write(out/'SOURCE-BEFORE.json',before)
    original_paths=json.loads(a.original_paths.read_bytes());originals_before={k:ref(v) for k,v in original_paths.items()};originals_before['path_map']=ref(a.original_paths)
    jar=a.json_jar.resolve();jdk=a.java_home.resolve()
    if ref(jar)['sha256']!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('actual org.json changed')
    toolpaths=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar,Path(sys.executable),Path(__file__)];tools_before=[ref(p) for p in toolpaths]
    fixture=out/'fixture';files,derivation=load('business_client_bg_fixture',helper).prepare(src,fixture,include_terminal=False)
    pure_helper=src/'tests/native-app/legacy-boundary/prepare_search_pure.py';files=load('business_client_search_pure',pure_helper).add(src,files)
    files=[p for p in files if '/org/json/' not in str(p)]
    replace(fixture/'android/os/Looper.java','public static Looper myLooper(){return L;}','public static boolean worker;public static Looper myLooper(){return worker?null:L;}')
    (fixture/'android/os/Process.java').write_text('package android.os;public final class Process {public static int myUid(){return 10481;}public static int myPid(){return 123;}}\n')
    replace(fixture/'android/content/Context.java','a.sourceDir=new java.io.File(files,"fake.apk").getPath();','a.sourceDir="/data/app/host-fixture/base.apk";')
    constants=fixture/'android/system/OsConstants.java'
    constants_text=constants.read_text()
    for name,value in (('O_RDWR',2),('EEXIST',17)):
        values=re.findall(r'\b'+name+r'\s*=\s*(-?\d+)\b',constants_text)
        if values:
            if values!=[str(value)]:raise RuntimeError('explicit OsConstants value or uniqueness changed: '+name)
        else:
            anchor='public final class OsConstants {'
            if constants_text.count(anchor)!=1:raise RuntimeError('explicit OsConstants carrier changed')
            constants_text=constants_text.replace(anchor,anchor+'public static final int '+name+'='+str(value)+';')
    constants.write_text(constants_text)
    replace(fixture/'android/system/StructStat.java','public int st_uid,st_mode;',
            'public int st_uid,st_mode;public StructTimespec st_mtim,st_ctim;public static final class StructTimespec {public long tv_sec,tv_nsec;public StructTimespec(long s,long n){tv_sec=s;tv_nsec=n;}}')
    osjava=fixture/'android/system/Os.java'
    replace(osjava,'public static String failFsyncPath;', '''public static String failFsyncPath;
 public static boolean corruptBusinessArchiveOnSync;public static Runnable afterBusinessCommitSync;
 public static String resultPath;public static long resultHostInode,resultOriginalInode,resultOriginalDevice;''')
    replace(osjava,'r.st_uid=((Number)a.get("uid")).intValue();','r.st_uid=((Number)a.get("uid")).intValue();if(r.st_uid=='+str(os.getuid())+')r.st_uid=10481;')
    replace(osjava,'return r;}','''java.time.Instant mt=((java.nio.file.attribute.FileTime)a.get("lastModifiedTime")).toInstant(),ct=((java.nio.file.attribute.FileTime)a.get("ctime")).toInstant();
 r.st_mtim=new StructStat.StructTimespec(mt.getEpochSecond(),mt.getNano());r.st_ctim=new StructStat.StructTimespec(ct.getEpochSecond(),ct.getNano());
 // Explicit Android stat boundary for the unchanged old terminal-reference inode.
 // A host inode replacement loses this mapping, preserving the ABA negative.
 if(s.equals(resultPath)&&r.st_ino==resultHostInode){r.st_ino=resultOriginalInode;r.st_dev=resultOriginalDevice;}
 return r;}''')
    replace(osjava,'if(fd.valid())fd.sync();','''if(fd.valid())fd.sync();
 if(corruptBusinessArchiveOnSync&&path.endsWith("/originals.bin")){corruptBusinessArchiveOnSync=false;Files.write(Paths.get(path),new byte[]{1});}
 if(afterBusinessCommitSync!=null&&path.endsWith("/receipt.json")&&path.contains("/business-absence-")){
  Runnable callback=afterBusinessCommitSync;afterBusinessCommitSync=null;callback.run();}''')
    identity=fixture/'org/trillionnium/hepta/background/RecoveryControllerIdentity.java'
    identity.write_text('''package org.trillionnium.hepta.background;
import org.json.*;
/** Explicit current-PM synthetic boundary; historical model/controller bytes remain real originals. */
public final class RecoveryControllerIdentity {
 public static boolean changed;
 public static JSONObject read(android.content.Context c,int uid,long deadline)throws Exception{
  if(android.os.SystemClock.elapsedRealtime()>=deadline)throw new java.io.IOException("synthetic identity expired");
  String hash=String.join("",java.util.Collections.nCopies(64,changed?"b":"a"));
  return new JSONObject().put("schema","hepta.recovery-controller-installation.v1").put("package",PublicProfileBusinessAbsenceRecovery.CONTROLLER)
   .put("user_id",0).put("uid",uid).put("source_path","/data/app/host-fixture/base.apk").put("source_bytes",22000000)
   .put("source_sha256",hash).put("version_code",70).put("signer_sha256",new JSONArray().put(hash));
 }
}
''')
    client=local/'PublicProfileBusinessRecoveryClient.java';raw=client.read_text();seam='new ProcessBuilder("su","-c",command).redirectErrorStream(true).start()'
    if raw.count(seam)!=1:raise RuntimeError('actual owned Process factory seam changed')
    projected=fixture/'org/trillionnium/hepta/local/PublicProfileBusinessRecoveryClient.java';projected.write_text(raw.replace(seam,'FakeBusinessRecoveryProcess.start(command)'))
    files += [projected,bg/'PublicProfileBusinessAbsenceRecovery.java',bg/'ProfileRecoveryProcesses.java',local/'RecoveryJournalStore.java',
        local/'RecoveryJournalTransaction.java',local/'SessionRecovery.java',src/'tests/public-profile-business-recovery/PublicProfileBusinessRecoveryHostTest.java',
        test/'FakeBusinessRecoveryProcess.java',test/'PublicProfileBusinessClientHostTest.java']
    files=list(dict.fromkeys(files));classes=out/'classes';classes.mkdir(mode=0o700)
    inputs=[ref(p) for p in files];generators=[ref(p) for p in [helper,pure_helper,Path(__file__),client]]
    original_fixture_inputs=[ref(p) for p in sorted((src/'tests/qualification-scope/fixtures').rglob('*.java'))]
    javac=[str(jdk/'bin/javac'),'--release','8','-Xlint:all,-options','-Werror','-encoding','UTF-8','-proc:none',
        '-cp',str(jar),'-sourcepath',str(src/'src'),'-d',str(classes)]+list(map(str,files))
    stages=[stage('compile',javac,out,src)]
    if stages[0]['exit_code']==0:
        stages.append(stage('client',[str(jdk/'bin/java'),'-Xmx768m','-cp',str(classes)+os.pathsep+str(jar),
            'org.trillionnium.hepta.local.PublicProfileBusinessClientHostTest',str(a.original_paths.resolve()),str(out/'CASES.json')],out,src))
    after=inventory(src);write(out/'SOURCE-AFTER.json',after);tools_after=[ref(p) for p in toolpaths]
    originals_after={k:ref(v) for k,v in original_paths.items()};originals_after['path_map']=ref(a.original_paths)
    counts=json.loads((out/'CASES.json').read_bytes()) if (out/'CASES.json').is_file() else None
    result=dict(schema='hepta.public-profile-business-client-host.v1',all_pass=len(stages)==2 and all(x['exit_code']==0 for x in stages)
        and counts is not None and counts['status']=='PASS' and before==after and tools_before==tools_after and originals_before==originals_after,
        source=str(src),source_before=ref(out/'SOURCE-BEFORE.json'),source_after=ref(out/'SOURCE-AFTER.json'),source_unchanged=before==after,
        tools_before=tools_before,tools_after=tools_after,tools_unchanged=tools_before==tools_after,external_originals_before=originals_before,
        external_originals_after=originals_after,external_originals_unchanged=originals_before==originals_after,
        inputs=inputs,generators=generators,original_fixture_inputs=original_fixture_inputs,fixture_derivation=derivation,
        client_source=ref(client),client_projection=ref(projected),client_factory_single_replacement=True,
        compiled_business_projection_overrides_shared_refusing_projection='business_client_projection' in derivation,stages=stages,
        cases=ref(out/'CASES.json') if counts else None,counts={k:counts[k] for k in ('cases','assertions')} if counts else None,
        actual_full_client_inputs_workerproof_receipt_and_background_cas=True,
        android_stat_uid_clock_pm_and_root_process_are_explicit_synthetic_boundaries=True,android_runtime_tested=False,phone_operations=0)
    write(out/'RESULT.json',result)
    print(json.dumps({'all_pass':result['all_pass'],'counts':result['counts'],'stages':[{'name':r['name'],'exit_code':r['exit_code']}for r in stages],'result':ref(out/'RESULT.json')}))
    return 0 if result['all_pass'] else 1

if __name__=='__main__':raise SystemExit(main())
