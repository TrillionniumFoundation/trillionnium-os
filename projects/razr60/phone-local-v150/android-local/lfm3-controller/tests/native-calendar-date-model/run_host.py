#!/usr/bin/env python3
"""Actual Adapter private calendar provenance; explicit native/Android ports, no model/phone."""
import argparse, hashlib, importlib.util, json, os, re, stat, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode=True
def sha(b): return hashlib.sha256(b).hexdigest()
def ref(p):
 p=Path(p).resolve();b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b),'mode':stat.S_IMODE(p.stat().st_mode)}
def module(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def classname(p):
 t=p.read_text();m=re.search(r'\bpackage\s+([a-zA-Z0-9_.]+)\s*;',t)
 if not m: raise RuntimeError('missing Java package '+str(p))
 return m.group(1)+'.'+p.stem
def prepare(S,O):
 session_path=S/'tests/native-search-planning/host_closure.py'
 adapter_path=S/'tests/vlm-adapter/run_host.py'
 session=module(session_path,'calendar_model_session_closure');adapter=module(adapter_path,'calendar_model_adapter_closure')
 tests=[S/'tests/native-calendar-date-session/NativeCalendarDateSessionHostTest.java',S/'tests/native-calendar-date-model/NativeCalendarDateModelHostTest.java']
 paths,session_provenance=session.prepare(S,O/'session',tests)
 va=O/'adapter';va.mkdir();vpaths=adapter.prepare(S,va)
 extras=[S/('src/org/trillionnium/hepta/local/'+n+'.java') for n in ['NativeCalendarDateEnvelope','NativeCalendarDateIntent','NativeCalendarDateProtocol','UiVenusInputContract']]
 selected={};replacements=[]
 for p in paths+extras+vpaths:
  p=p.resolve();key=classname(p)
  if key in ['org.trillionnium.hepta.local.ObservationModeHostTest','org.trillionnium.hepta.local.VlmAdapterLifecycleHostTest']: continue
  if key=='org.trillionnium.hepta.local.DecisionGrammar' and S not in p.parents:continue
  old=selected.get(key)
  if old is not None and old!=p:
   # Complete production is retained over same-name platform ports.
   if S in old.parents and S not in p.parents:continue
   replacements.append({'class':key,'previous':ref(old),'selected':ref(p),'reason':'merged explicit Android/engine fixture, actual production class preferred'})
  selected[key]=p
 ports=O/'merged';ports.mkdir()
 def generated(rel,text):
  p=ports/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);selected[classname(p)]=p;return p
 context='''package android.content;
public final class Context {
 public static final String DISPLAY_SERVICE="display",KEYGUARD_SERVICE="keyguard",ACTIVITY_SERVICE="activity";
 public final android.hardware.display.DisplayManager displays=new android.hardware.display.DisplayManager();
 public android.app.KeyguardManager keyguard=new android.app.KeyguardManager();
 public final android.content.pm.PackageManager manager=new android.content.pm.PackageManager();
 private final java.io.File files;public java.io.File cacheDirectory;public String packageName="org.trillionnium.hepta.local";
 public Context(java.io.File f){files=f;cacheDirectory=new java.io.File(f.getParentFile(),"cache");}
 public Context getApplicationContext(){return this;}public java.io.File getFilesDir(){return files;}
 public java.io.File getCacheDir(){return cacheDirectory;}public String getPackageName(){return packageName;}
 public android.content.pm.PackageManager getPackageManager(){return manager;}
 public Object getSystemService(String s){return DISPLAY_SERVICE.equals(s)?displays:ACTIVITY_SERVICE.equals(s)?new android.app.ActivityManager():keyguard;}
 public Object getContentResolver(){return this;}
 public android.content.pm.ApplicationInfo getApplicationInfo(){android.content.pm.ApplicationInfo a=new android.content.pm.ApplicationInfo();a.sourceDir=new java.io.File(files,"fake.apk").getPath();return a;}
}'''
 generated('android/content/Context.java',context)
 nativeports=O/'session/ports'
 code=(nativeports/'android/content/pm/ApplicationInfo.java').read_text();assert code.count('public String packageName,sourceDir;')==1
 generated('android/content/pm/ApplicationInfo.java',code.replace('public String packageName,sourceDir;','public String packageName,sourceDir;public String nativeLibraryDir="/host-fixture-no-installed-runtime";'))
 code=(nativeports/'android/system/Os.java').read_text()
 assert code.count('public static String failFsyncPath;')==1 and code.count('r.st_uid=((Number)a.get("uid")).intValue();')==1
 code=code.replace('public static String failFsyncPath;','public static String failFsyncPath;public static String foreignOwnerPath;')
 code=code.replace('r.st_uid=((Number)a.get("uid")).intValue();','r.st_uid=s.equals(foreignOwnerPath)?10482:android.os.Process.myUid();')
 generated('android/system/Os.java',code)
 selected['android.system.OsConstants']=(nativeports/'android/system/OsConstants.java').resolve()
 expected=S/'src/org/trillionnium/hepta/local/DecisionGrammar.java'
 if selected.get('org.trillionnium.hepta.local.DecisionGrammar')!=expected:raise RuntimeError('actual calendar grammar required')
 originals=[Path(r['path']) for r in session_provenance['production_inputs']]
 originals += [p for p in vpaths if S in p.parents]+extras+tests+[Path(__file__).resolve(),adapter_path,
   S/'tests/vlm-adapter/GenerationScopeFixture.java.inc',S/'tests/vlm-adapter/ObservationModeFixture.java.inc',
   S/'tests/vlm-contract/fixtures/gui-owl-chat-template.jinja',S/'tests/vlm-contract/fixtures/PROVENANCE.json',
   S/'src/org/trillionnium/hepta/local/LocalModelEngine.java',S/'src/org/trillionnium/hepta/local/LocalTaskController.java']
 originals += [S/'tests/qualification-scope/fixtures/android/system'/n for n in ['Os.java','OsConstants.java','StructStat.java','ErrnoException.java']]
 return list(selected.values()),list(dict.fromkeys(originals)),{'session':session_provenance,'adapter':json.loads((va/'EXTRACTION.json').read_text()),'fixture_replacements':replacements,
  'real_calendar_grammar':ref(expected),'boundary':'Only Android/context/UID and returned native worker/kernel-generation ports are synthetic; whole Adapter, private producer, real Session/Offer/grammar, native receipt verifier, private file checks and actual engine reservation members execute.'}
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for k in ('source','output','java-home','json-jar'):ap.add_argument('--'+k,type=Path,required=True)
 a=ap.parse_args();S=a.source.resolve();O=a.output.resolve();J=a.java_home.resolve();jar=a.json_jar.resolve()
 if O.exists() or S in O.parents:raise RuntimeError('fresh independent output')
 O.mkdir(mode=0o700,parents=True)
 if sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('pinned real JSON jar required')
 tools=[J/'bin/java',J/'bin/javac',J/'lib/modules',J/'lib/ct.sym',jar,Path(sys.executable).resolve()]
 report={'schema':'hepta.calendar-private-model-producer-focus.v1','all_pass':False,'source':str(S),'phone_actions':0,'model_runs':0,'stages':[],'started_host_wall_ms':int(time.time()*1000)}
 originals=[]
 try:
  paths,originals,provenance=prepare(S,O);report['closure']=provenance;report['source_inputs_before']=[ref(p) for p in originals];report['compile_inputs']=[ref(p) for p in paths];report['tools_before']=[ref(p) for p in tools]
  C=O/'classes';C.mkdir();env={**os.environ,'PATH':str(J/'bin')+':/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'}
  for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
  for name,argv in [('compile',[J/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar,'-d',C,*paths]),
    ('adapter',[J/'bin/java','-Djava.awt.headless=true','-cp',str(C)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeCalendarDateModelHostTest',O,O/'work',S/'tests/vlm-contract/fixtures/gui-owl-chat-template.jinja'])]:
   start=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=O,env=env,capture_output=True,timeout=120)
   (O/(name+'.stdout')).write_bytes(p.stdout);(O/(name+'.stderr')).write_bytes(p.stderr)
   report['stages'].append({'name':name,'argv':list(map(str,argv)),'cwd':str(O),'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-start,'stdout':ref(O/(name+'.stdout')),'stderr':ref(O/(name+'.stderr'))})
   if p.returncode:raise RuntimeError('actual stage failed: '+name)
  report['cases']=json.loads((O/'CASES.json').read_text())
  if not report['cases']['all_pass'] or report['cases']['cases']!=14:raise RuntimeError('exact necessary cases')
  report['all_pass']=True
 except Exception as e:report['error']=type(e).__name__+': '+str(e)
 finally:
  if originals:
   report['source_inputs_after']=[ref(p) for p in originals];report['tools_after']=[ref(p) for p in tools]
   report['source_inputs_unchanged']=report['source_inputs_before']==report['source_inputs_after'];report['tools_unchanged']=report['tools_before']==report['tools_after']
   report['all_pass'] &= report['source_inputs_unchanged'] and report['tools_unchanged']
  if (O/'CASES.json').exists():report['cases']=json.loads((O/'CASES.json').read_text())
  report['finished_host_wall_ms']=int(time.time()*1000);report['artifacts']=[ref(p) for p in O.rglob('*') if p.is_file() and p.name!='RESULT.json']
  (O/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'all_pass':report['all_pass'],'error':report.get('error'),'cases':report.get('cases',{}).get('cases'),'assertions':report.get('cases',{}).get('assertions'),'result':str(O/'RESULT.json')}))
 return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
