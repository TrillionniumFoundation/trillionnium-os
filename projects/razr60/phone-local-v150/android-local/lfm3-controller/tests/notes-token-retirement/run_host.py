#!/usr/bin/env python3
"""Strict actual production closure with inert Android IO; no device operation."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,subprocess,sys,time
sys.dont_write_bytecode=True
JSON_SHA='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
def need(ok,message):
    if not ok:raise RuntimeError(message)
def ref(path):
    path=Path(path).resolve(strict=True);raw=path.read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def main():
    ap=argparse.ArgumentParser()
    for key in ('source','output','java-home','json-jar'):ap.add_argument('--'+key,type=Path,required=True)
    ap.add_argument('--actual-detached-recents',type=Path)
    a=ap.parse_args();s=a.source.resolve(strict=True);out=a.output.absolute();jdk=a.java_home.resolve(strict=True);jar=a.json_jar.resolve(strict=True)
    need(s!=out and s not in out.parents,'output outside source');out.mkdir(parents=True,exist_ok=False)
    need(ref(jar)['sha256']==JSON_SHA,'fixed JSON dependency')
    shared=s/'tests/notes-task-info-reader/prepare_fixture.py'
    spec=importlib.util.spec_from_file_location('notes_read_ports',shared);ports=importlib.util.module_from_spec(spec);spec.loader.exec_module(ports)
    # These are IO ports only. The complete new coordinator/adapter/custody,
    # existing TaskInfo reader, organizer row parser, and physical parser compile unchanged.
    ports.STUBS['android/app/IActivityTaskManager.java']='package android.app; public interface IActivityTaskManager {Object getAllRootTaskInfos();Object getTasks(int max,boolean visible,boolean extras,int display);android.window.IWindowOrganizerController getWindowOrganizerController();}'
    ports.STUBS['android/window/WindowContainerTransaction.java']='package android.window; public final class WindowContainerTransaction {public WindowContainerToken selected;public WindowContainerTransaction removeTask(WindowContainerToken token){if(selected!=null)throw new AssertionError("second WCT effect");selected=token;return this;}public WindowContainerTransaction reparent(WindowContainerToken a,WindowContainerToken b,boolean top){throw new AssertionError("reparent forbidden");}}'
    ports.STUBS['android/os/Process.java']='package android.os; public final class Process {private Process(){}public static int myUid(){return 0;}}'
    ports.STUBS['android/content/pm/PackageManager.java']=ports.STUBS['android/content/pm/PackageManager.java'].replace('public ApplicationInfo installed;',
        'public ApplicationInfo installed;public String[] aliases;public String[] getPackagesForUid(int uid){return aliases==null?new String[]{installed.packageName}:aliases;}')
    ports.STUBS['android/hardware/display/DisplayManager.java']='package android.hardware.display;public final class DisplayManager {}'
    ports.STUBS['org/trillionnium/hepta/background/PublicOwnGroupFramework.java']='package org.trillionnium.hepta.background;final class PublicOwnGroupFramework {void requireRetiredDestroyHandle(int id,String name){if(id!=7||!"fixture-owned".equals(name))throw new AssertionError("exact synthetic handle");}}'
    ports.STUBS['org/trillionnium/hepta/background/PublicOwnGroupPhysicalReader.java']='''package org.trillionnium.hepta.background;
import java.util.Map;import java.util.function.LongSupplier;import android.hardware.display.DisplayManager;
final class PublicOwnGroupPhysicalReader {private PublicOwnGroupPhysicalReader(){}
private static Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> displayFacts(DisplayManager displays){return NotesTokenRetirementHostTest.facts();}
private static String dump(Object service,String[] args,LongSupplier deadline){return NotesTokenRetirementHostTest.dump(args);}}
'''
    ports.STUBS['android/view/DisplayInfo.java']='package android.view; public final class DisplayInfo {public int displayId;public String name;public DisplayInfo(int id){displayId=id;name=id==7?"fixture-owned":"physical-"+id;}}'
    ports.STUBS['android/hardware/display/IDisplayManager.java']='''package android.hardware.display;
public class IDisplayManager {public static int[] currentIds=new int[]{0,1};public int[] getDisplayIds(boolean disabled){if(!disabled)throw new AssertionError("disabled required");return currentIds.clone();}public android.view.DisplayInfo getDisplayInfo(int id){for(int found:currentIds)if(found==id)return new android.view.DisplayInfo(id);return null;}public static final class Stub {public static IDisplayManager asInterface(android.os.IBinder binder){return new IDisplayManager();}}}
'''
    ports.STUBS['android/os/ServiceManager.java']='package android.os;public final class ServiceManager {private ServiceManager(){}public static IBinder getService(String name){if(!"display".equals(name))throw new AssertionError("fixed service");return new Binder();}}'
    stubs=ports.prepare(out/'android-io-ports')
    bg=s/'src/org/trillionnium/hepta/background';own=s/'tests/notes-token-retirement'
    production=['BrokerProtocol','PublicPermissionControllerUi','FixedIntentTools','FixedIntentTarget','ProfileIdentity','ProfileTarget','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','PublicOwnGroupTaskFence','PublicOwnGroupPolicy','PublicOwnGroupPhysicalFence','PublicPersonalNotesCustody','BackgroundTaskOrganizer','PublicPersonalNotesReader','PublicPersonalNotesRetirement','PublicPersonalNotesRetirementAdapter']
    files=[bg/(name+'.java') for name in production]+[own/'NotesTaskInfoSemanticsHostTest.java',own/'NotesTokenRetirementHostTest.java',s/'tests/public-own-group-policy/PublicPhysicalAuditHostTest.java',s/'tests/public-own-group-policy/PersonalNotesCustodyHostTest.java']+stubs
    tracked=list(dict.fromkeys(files+[own/'actual-c672-taskinfo-fields.json',shared,Path(__file__).resolve(),jar,jdk/'bin/javac',jdk/'bin/java',jdk/'lib/ct.sym']))
    if a.actual_detached_recents:tracked.append(a.actual_detached_recents.resolve(strict=True))
    before=[ref(path) for path in tracked];classes=out/'classes';classes.mkdir()
    env=dict(os.environ)
    for name in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH'):env.pop(name,None)
    env.update(JAVA_HOME=str(jdk),PATH=str(jdk/'bin')+':/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    cp=str(classes)+os.pathsep+str(jar)
    commands=[('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-proc:none','-cp',jar,'-d',classes,*files]),
        ('token-cases',[jdk/'bin/java','-ea','-cp',cp,'org.trillionnium.hepta.background.NotesTokenRetirementHostTest',*([a.actual_detached_recents] if a.actual_detached_recents else [])]),
        ('taskinfo-semantics',[jdk/'bin/java','-ea','-cp',cp,'org.trillionnium.hepta.background.NotesTaskInfoSemanticsHostTest',own/'actual-c672-taskinfo-fields.json']),
        ('original-custody',[jdk/'bin/java','-ea','-cp',cp,'org.trillionnium.hepta.background.PersonalNotesCustodyHostTest']),
        ('original-physical-parser',[jdk/'bin/java','-ea','-cp',cp,'org.trillionnium.hepta.background.PublicPhysicalAuditHostTest'])]
    report={'schema':'hepta.notes-token-retirement-host-gate.v1','all_pass':False,'phone_operations':0,'android_runtime':False,
        'actual_production_inputs':[ref(bg/(name+'.java')) for name in production],'physical_dump_io_and_display_handle_ports_synthetic':True,
        'old_cases_or_expectations_changed':False,'inputs_before':before,'stages':[]}
    try:
        for name,argv in commands:
            argv=list(map(str,argv));start=time.monotonic()
            with (out/(name+'.stdout')).open('xb') as stdout,(out/(name+'.stderr')).open('xb') as stderr:
                p=subprocess.run(argv,cwd=s,env=env,stdout=stdout,stderr=stderr,timeout=120)
            row={'name':name,'argv':argv,'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-start,
                'stdout':ref(out/(name+'.stdout')),'stderr':ref(out/(name+'.stderr'))};report['stages'].append(row)
            print(json.dumps({'stage':name,'exit_code':p.returncode}),flush=True);need(p.returncode==0,name+' failed')
            if name!='compile':report[name]=json.loads((out/(name+'.stdout')).read_text().splitlines()[-1])
        report['all_pass']=True
    except BaseException as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['inputs_after']=[ref(path) for path in tracked];report['inputs_unchanged']=report['inputs_before']==report['inputs_after']
        report['all_pass']=report['all_pass'] and report['inputs_unchanged']
        with (out/'RESULT.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({'all_pass':report['all_pass'],'error':report.get('error'),'result':ref(out/'RESULT.json')}),flush=True)
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
