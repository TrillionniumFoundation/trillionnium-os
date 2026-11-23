#!/usr/bin/env python3
"""Actual finite LTC probe, full BG/auth/selection, explicit Android/socket ports."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import traceback


def ref(path):
    path=Path(path).resolve(); a=path.stat(); data=path.read_bytes(); b=path.stat()
    if (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_mode)!=(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_mode):
        raise RuntimeError('unstable input '+str(path))
    return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),mode=stat.S_IMODE(a.st_mode))


def put(path,value):
    data=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode();path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(data)
    return ref(path)


def inventory(root):
    return [dict(relative_path=str(p.relative_to(root)),**ref(p)) for p in sorted(root.rglob('*')) if p.is_file()]


def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def block(raw,signature):
    if raw.count(signature)!=1:raise RuntimeError('nonunique extraction '+signature)
    start=raw.index(signature);pos=raw.index('{',start);depth=0;mode='code';escaped=False;i=pos
    while i<len(raw):
        ch=raw[i];nxt=raw[i:i+2]
        if mode=='line':
            if ch=='\n':mode='code'
        elif mode=='comment':
            if nxt=='*/':mode='code';i+=1
        elif mode in ('string','char'):
            if escaped:escaped=False
            elif ch=='\\':escaped=True
            elif ch==('"' if mode=='string' else "'"):mode='code'
        elif nxt=='//':mode='line';i+=1
        elif nxt=='/*':mode='comment';i+=1
        elif ch=='"':mode='string'
        elif ch=="'":mode='char'
        elif ch=='{':depth+=1
        elif ch=='}':
            depth-=1
            if depth==0:return raw[start:i+1]
        i+=1
    raise RuntimeError('unterminated extraction '+signature)


def prepare(source,fixture,here):
    pkg=source/'src/org/trillionnium/hepta/local'; records=[]
    files,base=module('probe_actual_background',source/'tests/background-session/prepare_fixture.py').prepare(source,fixture,include_terminal=False)
    # Use the real JSON library for diagnostic and private receipt serialization.
    files=[Path(x) for x in files if '/org/json/' not in str(x)]
    actual_names=('PhoneObservation','ObservedChildText','ObservedWindowMetadata','ObservationState','ImeVisibility',
                  'ObservationCaptureEvidence','NativeCtripFormObservation','NativeActionSnapshotCheck','NativeAppEvidence')
    files += [pkg/(x+'.java') for x in actual_names]
    files=module('probe_legacy_unused_grammar',source/'tests/native-app/legacy-boundary/prepare_search_pure.py').add(source,files)
    def extract(path,signature):
        raw=path.read_text();part=block(raw,signature)
        records.append(dict(source=ref(path),signature=signature,bytes=len(part.encode()),sha256=hashlib.sha256(part.encode()).hexdigest(),verbatim=True))
        return part
    def write(name,text):
        path=fixture/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
        if path not in files:files.append(path)
        return path
    raw=(pkg/'LocalTaskController.java').read_text()
    owner=next(x for x in raw.splitlines() if x.startswith('    static final String CALENDAR_WINDOW_PROBE_OWNER='))
    early='            if(CALENDAR_WINDOW_PROBE_OWNER.equals(instruction))\n                requireCalendarWindowProbeSelection(taskId,instruction,authorization,backgroundSelection,deadline);'
    if raw.count(early)!=1:raise RuntimeError('scope-ready diagnostic admission must be unique')
    branch=extract(pkg/'LocalTaskController.java','            if(CALENDAR_WINDOW_PROBE_OWNER.equals(instruction)){')
    if not raw.index(early)<raw.index(branch)<raw.index('inference.beginTask(',raw.index(branch)):
        raise RuntimeError('diagnostic must precede beginTask')
    parts={'OWNER_CONSTANT':owner,'EARLY_BRANCH':early,'PROBE_BRANCH':branch,
           'SELECTION_METHOD':extract(pkg/'LocalTaskController.java','    private void requireCalendarWindowProbeSelection('),
           'PROBE_METHOD':extract(pkg/'LocalTaskController.java','    private PhoneObservation runCalendarWindowProbeOnly('),
           'CHECK_ACTIVE':extract(pkg/'LocalTaskController.java','    private void checkActive('),
           'STOPPED':extract(pkg/'LocalTaskController.java','    private static final class Stopped '),
           'RECORD':extract(pkg/'LocalTaskController.java','    private static void record(')}
    for name in ('OWNER_CONSTANT','EARLY_BRANCH'):
        part=parts[name];records.append(dict(source=ref(pkg/'LocalTaskController.java'),signature=name,bytes=len(part.encode()),sha256=hashlib.sha256(part.encode()).hexdigest(),verbatim=True))
    template=(here/'ProbeDiagnosticHost.template').read_text()
    for key,value in parts.items():
        marker='@@'+key+'@@'
        if template.count(marker)!=1:raise RuntimeError('template insertion '+marker)
        template=template.replace(marker,value)
    if '@@' in template:raise RuntimeError('unfilled controller marker')
    generated=write('org/trillionnium/hepta/local/ProbeDiagnosticHost.java',template)
    # Actual FilesRoot/Bound and unrestricted file checks. Restricted package/HOME
    # IO remains unavailable; a restricted configuration never reaches the probe.
    scope_parts=[extract(pkg/'QualificationScopeConfig.java',sig) for sig in (
        '    static final class FilesRoot {','    static final class Bound {',
        '    private static JSONObject pathDiagnostics(','    private static void diagnosticPath(',
        '    private static String boundedPath(','    static Object nullable(')]
    write('org/trillionnium/hepta/local/QualificationScopeConfig.java',
          'package org.trillionnium.hepta.local;import android.content.Context;import android.system.*;import java.io.*;import java.util.*;import org.json.*;\n'
          +'final class QualificationScopeConfig {\n'+'\n'.join(scope_parts)
          +'\nstatic final class Installed {void verify(Context c){throw new UnsupportedOperationException("restricted installed-package IO unavailable");}}'
          +'\nstatic String home(Context c){throw new UnsupportedOperationException("restricted HOME IO unavailable");}\n}\n')
    ha=pkg/'HeptaAccessibilityService.java'
    service_parts=[extract(ha,sig) for sig in (
        '    private synchronized boolean owns(','    private synchronized boolean ownsAuthorization(',
        '    void requireTaskAuthorization(','    void requireAuthorizationObservation(',
        '    private synchronized BackgroundSession backgroundFor(','    void requireBackgroundObservation(',
        '    private static void requireHistoricalProfileWindow(','    private static final class ProfileOwnershipViolation ',
        '    private synchronized QualificationScopeConfig.Bound scopeFor(','    void requireScopeObservation(')]
    service='''package org.trillionnium.hepta.local;
import org.json.*;import android.view.Display;import android.view.accessibility.AccessibilityWindowInfo;
/** Actual identity/observation guards. Scheduling booleans are explicit Android ports. */
final class HeptaAccessibilityService {
 interface Cancellation{boolean isCancelled();}
 static String sha(byte[] b){return QualificationScope.hash(b);}
 static String message(Throwable t){return t.getMessage()==null?t.getClass().getSimpleName():t.getMessage();}
 static HeptaAccessibilityService live;String lease;TaskAuthorization.Gate taskAuthorization;
 BackgroundSession taskBackground;QualificationScopeConfig.Bound taskScope;
 boolean readPending,actionPending,cancellationPending;
 boolean observationReadWorkPending(){return readPending;}
 boolean actionWorkPending(){return actionPending;}
 boolean nativeCancellationWorkPending(){return cancellationPending;}
 /** The date-effect path is out of scope and can never acquire a test permit. */
 static final class CalendarInputAttempt {
  private CalendarInputAttempt(){throw new UnsupportedOperationException("no calendar effect in readonly gate");}
  java.util.Map<String,Object> beginBrokerCall(BackgroundSession b,Cancellation c){throw new UnsupportedOperationException("no calendar effect in readonly gate");}
  void requireBeforeSend(BackgroundSession b,Cancellation c){throw new UnsupportedOperationException("no calendar effect in readonly gate");}
 }
'''
    write('org/trillionnium/hepta/local/HeptaAccessibilityService.java',service+'\n'.join(service_parts)+'\n}\n')
    canonical=extract(source/'src/org/trillionnium/hepta/webprotocol/WebEvidenceBinding.java','    public static String canonical(')
    same=extract(pkg/'WebEvidenceReceipt.java','    static boolean same(')
    write('org/trillionnium/hepta/webprotocol/WebEvidenceBinding.java','package org.trillionnium.hepta.webprotocol;import org.json.*;import java.util.*;public final class WebEvidenceBinding {\n'+canonical+'\n}\n')
    write('org/trillionnium/hepta/local/WebEvidenceReceipt.java','package org.trillionnium.hepta.local;import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;final class WebEvidenceReceipt {\n'+same+'\n}\n')
    ports={
      'android/app/KeyguardManager.java':'package android.app;public final class KeyguardManager {public boolean locked,secure,deviceSecure,deviceLocked;public boolean isKeyguardLocked(){return locked;}public boolean isKeyguardSecure(){return secure;}public boolean isDeviceSecure(){return deviceSecure;}public boolean isDeviceLocked(){return deviceLocked;}}',
      'android/os/Looper.java':'package android.os;public final class Looper {public static boolean worker=true;private static final Looper MAIN=new Looper();public static Looper myLooper(){return worker?null:MAIN;}public static Looper getMainLooper(){return MAIN;}}',
      'android/os/Process.java':'package android.os;public final class Process {public static int myUid(){return 10123;}public static int myPid(){return 123;}}',
      'android/graphics/Rect.java':'package android.graphics;public final class Rect {public int left,top,right,bottom;public Rect(int l,int t,int r,int b){left=l;top=t;right=r;bottom=b;}public Rect(Rect r){this(r.left,r.top,r.right,r.bottom);}public int width(){return right-left;}public int height(){return bottom-top;}public boolean isEmpty(){return width()<=0||height()<=0;}public boolean contains(int x,int y){return left<=x&&x<right&&top<=y&&y<bottom;}public String flattenToString(){return left+" "+top+" "+right+" "+bottom;}}',
      'android/view/accessibility/AccessibilityWindowInfo.java':'package android.view.accessibility;public final class AccessibilityWindowInfo{public static final int TYPE_APPLICATION=1;}'
    }
    for name,value in ports.items():write(name,value+'\n')
    osp=fixture/'android/system/Os.java';osraw=osp.read_text()
    if osraw.count('r.st_uid=((Number)a.get("uid")).intValue();')!=1:raise RuntimeError('stat UID port not unique')
    osraw=osraw.replace('r.st_uid=((Number)a.get("uid")).intValue();','r.st_uid=10123;')
    seam='public static void chmod(String s,int mode)'
    # Record's real chmod call can report a platform failure after actual fsync.
    if seam not in osraw:raise RuntimeError('chmod port signature unavailable')
    start=osraw.index('{',osraw.index(seam));osraw=osraw[:start+1]+'if(failChmod)throw new java.io.IOException("synthetic final chmod failure");'+osraw[start+1:]
    osraw=osraw.replace('public final class Os {','public final class Os {public static boolean failChmod;')
    osp.write_text(osraw)
    files += [here/'ProbeDiagnosticHostTest.java']
    files=list(dict.fromkeys(Path(x).resolve() for x in files))
    return files,dict(schema='hepta.calendar-probe-diagnostic-extraction.v1',shared_background=base,verbatim=records,
                     controller=ref(generated),actual_full_classes=['BackgroundSession','TaskAuthorization','BackgroundTaskTarget','PhoneObservation',*actual_names[1:]],
                     generated_android_ports=sorted(ports),scope='actual unrestricted FilesRoot/Bound; restricted Installed/HOME IO always throws',
                     first_observation='explicit host callback; no Android accessibility traversal',
                     socket='explicit LocalSocket peer and response; no real root broker or ROM qualification',
                     date_effect='private unconstructible always-throw attempt type; no date inputs',
                     model_and_input_boundaries='no model, Android input, process or device execution',
                     original_task_finally='not executed by this extracted consumer gate; full-source inverse checked independently')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--java-home',type=Path,required=True);p.add_argument('--json-jar',type=Path,required=True);a=p.parse_args()
    source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);here=Path(__file__).resolve().parent
    before=inventory(source)
    tools=[Path(sys.executable).resolve(),a.java_home/'bin/javac',a.java_home/'bin/java',a.java_home/'lib/modules',a.java_home/'lib/ct.sym',a.json_jar,
           Path(__file__).resolve(),here/'ProbeDiagnosticHost.template',here/'ProbeDiagnosticHostTest.java',source/'tests/background-session/prepare_fixture.py',source/'tests/native-app/legacy-boundary/prepare_search_pure.py']
    tool_before=[ref(x) for x in tools]
    result=dict(schema='hepta.calendar-probe-diagnostic-host-validation.v1',all_pass=False,source=str(source),source_before=put(out/'SOURCE-BEFORE.json',before),
                tools_before=tool_before,stages=[],phone_operations=0,model_processes=0,broker_processes=0,android_input_calls=0,actual_android_or_rom_qualification=False)
    files=[];pins=[]
    try:
        files,record=prepare(source,out/'fixture',here);result['extraction']=put(out/'EXTRACTION.json',record)
        pins=[ref(x) for x in files];result['compile_inputs_before']=pins
        classes=out/'classes';classes.mkdir()
        env=os.environ.copy();cleared=['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH']
        for name in cleared:env.pop(name,None)
        env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',JAVA_HOME=str(a.java_home),PATH=str(a.java_home/'bin')+':/usr/bin:/bin')
        result['cleared_environment']=cleared
        commands=[('compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',a.json_jar,'-d',classes,*files]),
                  ('probe-cases',[a.java_home/'bin/java','-ea','-cp',str(classes)+':'+str(a.json_jar),'org.trillionnium.hepta.local.ProbeDiagnosticHostTest',out/'CASES.json'])]
        for name,argv in commands:
            argv=list(map(str,argv));start=time.monotonic();r=subprocess.run(argv,cwd=out,env=env,capture_output=True,timeout=90)
            for kind,value in [('stdout',r.stdout),('stderr',r.stderr)]:(out/(name+'.'+kind)).write_bytes(value)
            result['stages'].append(dict(name=name,argv=argv,cwd=str(out),exit_code=r.returncode,elapsed_seconds=time.monotonic()-start,
                                         stdout=ref(out/(name+'.stdout')),stderr=ref(out/(name+'.stderr'))))
            if r.returncode:raise RuntimeError(name+' failed with exit '+str(r.returncode))
        case=json.loads((out/'CASES.json').read_bytes());result.update(case_report=ref(out/'CASES.json'),cases=case['cases'],assertions=case['assertions'],all_pass=case['all_pass'])
    except BaseException as error:result.update(error=str(error),traceback=traceback.format_exc())
    result['compile_inputs_after']=[ref(x) for x in files];result['compile_inputs_unchanged']=pins==result['compile_inputs_after']
    result['tools_after']=[ref(x) for x in tools];result['tools_unchanged']=tool_before==result['tools_after']
    after=inventory(source);result['source_after']=put(out/'SOURCE-AFTER.json',after);result['source_inputs_unchanged']=before==after
    result['all_pass'] &= result['compile_inputs_unchanged'] and result['tools_unchanged'] and result['source_inputs_unchanged']
    rr=put(out/'RESULT.json',result);print(json.dumps(dict(all_pass=result['all_pass'],cases=result.get('cases'),assertions=result.get('assertions'),result=rr)))
    return 0 if result['all_pass'] else 1


if __name__=='__main__':raise SystemExit(main())
