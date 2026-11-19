#!/usr/bin/env python3
"""Exact controller-locator/policy/read-only adapters and physical parsers; inert Android IO only."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,re,subprocess,time

def need(ok,message):
    if not ok:raise RuntimeError(message)
def pin(path):
    raw=path.read_bytes();return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def main():
    ap=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar'):ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args();source=a.source.resolve();out=a.output.absolute();own=Path(__file__).resolve().parent
    out.mkdir(parents=True,exist_ok=False);classes=out/'classes';classes.mkdir()
    jdk=a.java_home.resolve();jar=a.json_jar.resolve()
    need(pin(jar)['sha256']=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed','pinned JSON dependency')
    prepare=source/'tests/notes-task-info-reader/prepare_fixture.py'
    spec=importlib.util.spec_from_file_location('main_ui_inert_android',prepare);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    ports=out/'ports';files=module.prepare(ports)
    component=ports/'android/content/ComponentName.java';text=component.read_text()
    need(text.count('public String getPackageName()')==1,'component fixture boundary')
    component.write_text(text.replace('public String getPackageName()', 'public String flattenToString(){return pkg+"/"+cls;}public String getPackageName()',1))
    extras={
        'android/view/Display.java':'package android.view;public final class Display {public int id;public boolean valid=true;public Display(int id){this.id=id;}public int getDisplayId(){return id;}public boolean isValid(){return valid;}}',
        'android/view/View.java':'package android.view;public final class View {public boolean shown=true;public boolean isShown(){return shown;}}',
        'android/view/Window.java':'package android.view;public final class Window {public final View decor=new View();public View getDecorView(){return decor;}}',
        'android/os/Looper.java':'package android.os;public final class Looper {private static final Looper MAIN=new Looper();public static boolean main=true;public static Looper myLooper(){return main?MAIN:null;}public static Looper getMainLooper(){return MAIN;}}',
        'android/os/Process.java':'package android.os;public final class Process {public static int myUid(){return 10481;}public static int myPid(){return 2020;}}',
        'android/app/Activity.java':'''package android.app;public class Activity {
public android.view.Display display=new android.view.Display(0);public boolean focus=true,finishing,destroyed;public int task=100;
public android.view.Window window=new android.view.Window();public android.content.ComponentName component=new android.content.ComponentName("org.trillionnium.hepta.local","org.trillionnium.hepta.local.MainActivity");
public android.content.pm.ApplicationInfo application=new android.content.pm.ApplicationInfo();public Activity(){application.uid=10481;}
public android.view.Display getDisplay(){return display;}public boolean isFinishing(){return finishing;}public boolean isDestroyed(){return destroyed;}
public boolean hasWindowFocus(){return focus;}public android.view.Window getWindow(){return window;}public android.content.ComponentName getComponentName(){return component;}
public android.content.pm.ApplicationInfo getApplicationInfo(){return application;}public int getTaskId(){return task;}}
'''
    }
    for name,body in extras.items():
        path=ports/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body+'\n');files.append(path)
    main_source=source/'src/org/trillionnium/hepta/local/MainActivity.java';main_text=main_source.read_text()
    begin='    private org.trillionnium.hepta.background.PublicPermissionControllerUi.Locator controllerUiFromOwnerButton(String owner){'
    end='    private boolean beginTask('
    need(main_text.count(begin)==main_text.count(end)==1,'exact UI capture anchors')
    method=main_text[main_text.index(begin):main_text.index(end)]
    fixture=out/'MainActivity.java';fixture.write_text('package org.trillionnium.hepta.local;\npublic class MainActivity extends android.app.Activity {\n'+method+
        'org.trillionnium.hepta.background.PublicPermissionControllerUi.Locator capture(String owner){return controllerUiFromOwnerButton(owner);}\n}\n')
    # The source check is explicit, separate from runtime UI fixture coverage.
    dispatch=main_text[main_text.index(end):main_text.index('    private void runProbe(',main_text.index(end))]
    need(dispatch.count('controllerUiFromOwnerButton(owner)')==1 and
         dispatch.index('if(!"user_button".equals(source))')<dispatch.index('controllerUiFromOwnerButton(owner)'),
         'actual background Start checks user_button before the sole capture call')
    service_source=source/'src/org/trillionnium/hepta/local/HeptaAccessibilityService.java'
    service_text=service_source.read_text()
    digest_signature=re.findall(r'(?m)^    (?:public )?static String sha\(byte\[\] [^)]+\)[^{]*\{',service_text)
    need(len(digest_signature)==1,'actual service SHA helper anchor')
    extractor=source/'tests/action-worker/run_host_tests.py'
    es=importlib.util.spec_from_file_location('main_ui_exact_method',extractor);em=importlib.util.module_from_spec(es);es.loader.exec_module(em)
    digest_method=em.body(service_text,digest_signature[0].strip())
    digest_fixture=out/'HeptaAccessibilityService.java'
    digest_fixture.write_text('package org.trillionnium.hepta.local;\nimport java.security.*;import java.util.*;\nfinal class HeptaAccessibilityService {\n'+digest_method+'\n}\n')
    files.append(digest_fixture)
    bg=source/'src/org/trillionnium/hepta/background'
    names=['BrokerProtocol','FixedIntentTools','FixedIntentTarget','ProfileIdentity','ProfileTarget','BackgroundOwnedTaskPolicy',
           'BackgroundOwnedSingleTask','ProfileTaskPolicy','PublicOwnGroupTaskFence','PublicOwnGroupPolicy','PublicOwnGroupPhysicalFence',
           'BackgroundTaskOrganizer','PublicPermissionControllerUi']
    files += [bg/(name+'.java') for name in names]+[fixture,source/'tests/public-own-group-policy/PublicPhysicalAuditHostTest.java',
        own/'PublicPermissionControllerUiHostTest.java',own/'MainActivityLocatorHostTest.java']
    tracked=list(dict.fromkeys(files+[prepare,main_source,service_source,extractor,Path(__file__).resolve(),jar,jdk/'bin/javac',jdk/'bin/java']))
    before=[pin(path) for path in tracked]
    result={'schema':'hepta.main-ui-permission-gate.v1','all_pass':False,'phone_operations':0,'android_runtime':False,
        'framework_and_binder_fixtures_synthetic':True,'android_main_screen_executed':False,'source_inputs_before':before,
        'capture_method_sha256':hashlib.sha256(method.encode()).hexdigest(),'capture_source_user_button_check':True,'stages':[]}
    env=dict(os.environ)
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH'):env.pop(key,None)
    env.update(JAVA_HOME=str(jdk),PATH=str(jdk/'bin')+':/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1')
    commands=[('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-proc:none','-cp',jar,'-d',classes,*files])]
    for stage,cls in [('original-physical','org.trillionnium.hepta.background.PublicPhysicalAuditHostTest'),
                      ('controller-policy','org.trillionnium.hepta.background.PublicPermissionControllerUiHostTest'),
                      ('main-activity-capture','org.trillionnium.hepta.local.MainActivityLocatorHostTest')]:
        commands.append((stage,[jdk/'bin/java','-ea','-cp',str(classes)+os.pathsep+str(jar),cls]))
    try:
        for name,argv in commands:
            argv=list(map(str,argv));start=time.monotonic()
            with (out/(name+'.stdout')).open('xb') as so,(out/(name+'.stderr')).open('xb') as se:
                p=subprocess.run(argv,cwd=source,env=env,stdout=so,stderr=se,timeout=120)
            row={'name':name,'argv':argv,'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-start,
                 'stdout':pin(out/(name+'.stdout')),'stderr':pin(out/(name+'.stderr'))}
            result['stages'].append(row);print(json.dumps({'stage':name,'exit_code':p.returncode}),flush=True)
            need(p.returncode==0,name+' failed; preserved actual stdout/stderr')
            if name!='compile':
                cases=json.loads((out/(name+'.stdout')).read_text().splitlines()[-1]);row['cases']=cases
                if name=='original-physical':need(cases['cases']==29 and cases['assertions']==35,'original physical cases unchanged')
                elif name=='controller-policy':need(cases['cases']==19 and cases['mutation_calls']==cases['phone_operations']==0,'controller contract')
                else:need(cases['cases']==8 and cases['actual_production_method_executed'] is True and cases['phone_operations']==0,'capture contract')
        result['all_pass']=True
    except BaseException as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        result['source_inputs_after']=[pin(path) for path in tracked]
        result['inputs_unchanged']=before==result['source_inputs_after'];result['all_pass']=result['all_pass'] and result['inputs_unchanged']
        with (out/'RESULT.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'all_pass':result['all_pass'],'error':result.get('error'),'result':pin(out/'RESULT.json')}),flush=True)
    return 0 if result['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
