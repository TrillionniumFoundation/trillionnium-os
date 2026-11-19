#!/usr/bin/env python3
"""Actual pure protocol/policy and full app session, explicit Android transport fakes."""
import argparse,hashlib,importlib.util,json,pathlib,shutil,subprocess

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=pathlib.Path);parser.add_argument('--output',type=pathlib.Path,required=True);parser.add_argument('--java-home',type=pathlib.Path);parser.add_argument('--release8',action='store_true');args=parser.parse_args()
    root=pathlib.Path(__file__).resolve().parent;source=(args.source or root.parent).resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    helper=source/'tests/background-session/prepare_fixture.py';spec=importlib.util.spec_from_file_location('scope_fixture',helper)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);files,record=module.prepare(source,out/'fixture')
    fixture=out/'fixture'
    (fixture/'android/app/KeyguardManager.java').write_text('package android.app;public final class KeyguardManager {public boolean locked,secure,deviceSecure,deviceLocked;public boolean isKeyguardLocked(){return locked;}public boolean isKeyguardSecure(){return secure;}public boolean isDeviceSecure(){return deviceSecure;}public boolean isDeviceLocked(){return deviceLocked;}}\n')
    (fixture/'android/os/Looper.java').write_text('package android.os;public final class Looper {public static boolean worker;private static final Looper MAIN=new Looper();public static Looper myLooper(){return worker?null:MAIN;}public static Looper getMainLooper(){return MAIN;}}\n')
    (fixture/'android/os/Process.java').write_text('package android.os;public final class Process {public static int myUid(){return 10123;}public static int myPid(){return 123;}}\n')
    os=fixture/'android/system/Os.java';text=os.read_text();assert text.count('r.st_uid=((Number)a.get("uid")).intValue();')==1
    os.write_text(text.replace('r.st_uid=((Number)a.get("uid")).intValue();','r.st_uid=10123;'))
    files.append(source/'src/org/trillionnium/hepta/background/PublicOwnGroupPolicy.java')
    raw=(source/'src/org/trillionnium/hepta/local/HeptaAccessibilityService.java').read_text()
    def section(start,end):
        assert raw.count(start)==1 and raw.count(end)==1
        begin=raw.index(start);return raw[begin:raw.index(end,begin)]
    pieces={'locked':section('    private boolean locked(BackgroundSession background) {','    private int rotation(int displayId) {'),
            'model_admission':section('    void requireExperimentalModelScope(', '    void requireVisualFrameOwnership('),
            'final_effect':section('    private void enterActionEffect(ActionWork work){','    private static void actionEffectReturned(')}
    service_fixture=fixture/'org/trillionnium/hepta/local/ServicePolicyFixture.java'
    service_fixture.write_text('''package org.trillionnium.hepta.local;
import android.os.Looper;import android.os.SystemClock;
final class ServicePolicyFixture {
 interface Cancellation extends HeptaAccessibilityService.Cancellation {}
 static ServicePolicyFixture live;LocalTaskController controller,ownedController;
 TaskAuthorization.Gate authorization;BackgroundSession taskBackground;boolean foregroundLocked;int profileChecks,modelAdmissions;
 void bind(BackgroundSession background){live=this;controller=new LocalTaskController();ownedController=controller;taskBackground=background;
  authorization=TaskAuthorization.parse(PublicOwnGroupSessionHostTest.OWNER).bind(background.taskId);}
 boolean ownsAuthorization(String id,TaskAuthorization.Gate auth){return auth==authorization&&id.equals(authorization.taskId);}
 boolean ownsBackground(String id,BackgroundSession background){return live==this&&background==taskBackground&&id.equals(background.taskId);}
 boolean locked(){return foregroundLocked;}
 void requireTaskAuthorization(String id,TaskAuthorization.Gate auth){TaskAuthorization.require(ownsAuthorization(id,auth),"fixture captured auth retired");}
 static final class State {long deadlineElapsed;}
 static final class ActionWork {BackgroundSession background;HeptaAccessibilityService.Cancellation cancel;State state=new State();int effects;
  void check(){if(cancel.isCancelled()||SystemClock.elapsedRealtime()>=state.deadlineElapsed)throw new IllegalStateException("fixture cancelled");}
  void enterEffect(){check();effects++;}}
 void requireLiveProfileBeforeEffect(ActionWork work){profileChecks++;work.check();}
 static void actionCheck(ActionWork work){work.check();}
 HeptaAccessibilityService.Cancellation actionCancellation(ActionWork work,HeptaAccessibilityService.Cancellation cancel){return cancel;}
 ActionWork work(BackgroundSession background,HeptaAccessibilityService.Cancellation cancel){ActionWork value=new ActionWork();value.background=background;value.cancel=cancel;value.state.deadlineElapsed=SystemClock.elapsedRealtime()+3000;return value;}
 boolean backgroundLocked(BackgroundSession background){return locked(background);}
 void effect(ActionWork work){enterActionEffect(work);}
 void model(LocalTaskController controller,BackgroundSession background,TaskAuthorization.Gate auth,Cancellation cancel){requireExperimentalModelScope(controller,background.taskId,auth,background,cancel,SystemClock.elapsedRealtime()+3000);modelAdmissions++;}
'''+''.join(pieces.values())+'}\n')
    files.append(service_fixture)
    controller_stub=fixture/"org/trillionnium/hepta/local/LocalTaskController.java"
    controller_stub.write_text("package org.trillionnium.hepta.local;final class LocalTaskController {}\n");files.append(controller_stub)
    # New ordinary Start opt-in: exact preference/UI methods and exact factory
    # expression, with explicit inert widget/storage seams. No Activity or su runs.
    context_file=fixture/'android/content/Context.java';context_file.write_text(context_file.read_text().replace('public final class Context','public class Context'))
    preferences_raw=(source/'src/org/trillionnium/hepta/local/BackgroundUiPreferences.java').read_text()
    def exact(text,start,end):
        assert text.count(start)==1 and text.count(end)==1
        begin=text.index(start);return text[begin:text.index(end,begin)]
    preference_parts={'constants':exact(preferences_raw,'    private static final String MODE=','    private static final int MAX_BYTES='),
        'independent_reader_writer':exact(preferences_raw,'    static boolean independentProfileDisplay(Context context){','    static Selection load(Context context)throws Exception{')}
    preference_fixture=fixture/'org/trillionnium/hepta/local/BackgroundUiPreferences.java'
    preference_fixture.write_text('''package org.trillionnium.hepta.local;
import android.content.Context;import android.content.SharedPreferences;import java.util.*;
final class BackgroundUiPreferences {
 static final Map<String,Object> saved=new LinkedHashMap<String,Object>();static boolean commitAllowed=true;static int writes;
 static final class Preferences {Map<String,?> getAll(){return saved;}Editor edit(){return new Editor();}}
 static final class Editor implements SharedPreferences.Editor {final Map<String,Object> pending=new LinkedHashMap<String,Object>();public Editor putBoolean(String key,boolean value){pending.put(key,value);return this;}
  public boolean commit(){writes++;saved.putAll(pending);return commitAllowed;}}
 static Preferences preferences(Context context){return new Preferences();}
'''+''.join(preference_parts.values())+'}\n');files.append(preference_fixture)
    shared_preferences=fixture/'android/content/SharedPreferences.java';shared_preferences.write_text('package android.content;public interface SharedPreferences {interface Editor {Editor putBoolean(String key,boolean value);boolean commit();}}\n');files.append(shared_preferences)
    ui_raw=(source/'src/org/trillionnium/hepta/local/MainActivity.java').read_text()
    ui_mode_parts={'mode_read_restore':exact(ui_raw,'    private boolean selectedIndependentProfileDisplay(){','    private org.trillionnium.hepta.background.ProfileTarget selectedProfileTarget(){'),
        'visible_choice_listener':exact(ui_raw,'    private void installBackgroundPreferenceListeners(){','        backgroundMode.setOnClickListener(view -> {')+'    }\n'}
    ui_fixture=fixture/'org/trillionnium/hepta/local/ModeUiFixture.java'
    ui_fixture.write_text('''package org.trillionnium.hepta.local;
import android.content.Context;import org.trillionnium.hepta.background.ProfileTarget;
final class ModeUiFixture extends Context {
 interface Click {void click(Object view);}
 static final class Check {boolean checked,shown=true;Click listener;boolean isChecked(){return checked;}void setChecked(boolean value){checked=value;}boolean isShown(){return shown;}
  void setOnClickListener(Click value){listener=value;}void click(){checked=!checked;listener.click(this);}}
 static final class Busy {boolean running,busy,blocked,recovering,lease;boolean isRunning(){return running;}boolean isBusy(){return busy;}boolean isBlocked(){return blocked;}
  boolean isRecovering(){return recovering;}boolean hasBackgroundLease(){return lease;}boolean blocksOtherWork(){return busy;}}
 final Check independentProfileDisplay=new Check(),independentPersonalDisplay=new Check();String backgroundDisplayPreferenceError;ProfileTarget target;String personalPackage="com.motorola.stylus";
 final Busy tasks=new Busy(),engine=new Busy(),backgroundPermission=new Busy();boolean focus=true,finishing,destroyed;int refreshes;
 ModeUiFixture(java.io.File root){super(root);}boolean hasWindowFocus(){return focus;}boolean isFinishing(){return finishing;}boolean isDestroyed(){return destroyed;}
 ProfileTarget selectedProfileTarget(){return target;}String selectedBackgroundPackage(){return target==null?personalPackage:target.packageName;}void refresh(){refreshes++;}
 void restore(){restoreIndependentProfileDisplay();}void install(){installBackgroundPreferenceListeners();}boolean selected(){return selectedIndependentProfileDisplay();}boolean personalSelected(){return selectedIndependentPersonalDisplay();}
'''+''.join(ui_mode_parts.values())+'}\n');files.append(ui_fixture)
    controller_raw=(source/'src/org/trillionnium/hepta/local/LocalTaskController.java').read_text()
    factory=exact(controller_raw,'                background=backgroundSelection.independentProfileDisplay','                service.bindBackgroundSession(taskId,background);')
    factory_fixture=fixture/'org/trillionnium/hepta/local/ModeFactoryFixture.java'
    factory_fixture.write_text('''package org.trillionnium.hepta.local;
final class ModeFactoryFixture {
 static BackgroundSession create(android.content.Context service,String taskId,String instruction,BackgroundSession.Selection backgroundSelection,
  QualificationScopeConfig.FilesRoot filesRoot)throws Exception {BackgroundSession background;
'''+factory+'return background;}\n}\n');files.append(factory_fixture)
    record['exact_mode_preference_hunks']={name:hashlib.sha256(text.encode()).hexdigest() for name,text in preference_parts.items()}
    record['exact_mode_ui_hunks']={name:hashlib.sha256(text.encode()).hexdigest() for name,text in ui_mode_parts.items()}
    record['exact_normal_start_factory_hunk_sha256']=hashlib.sha256(factory.encode()).hexdigest()
    record['exact_service_hunks']={name:hashlib.sha256(text.encode()).hexdigest() for name,text in pieces.items()}
    record['service_boundary']='Only captured task identity helpers and existing native-profile checker are inert explicit stubs; actual new locked/model/final-effect methods call full production BackgroundSession against fake Android IO'
    tests=[('org.trillionnium.hepta.background.PublicOwnGroupPolicyHostTest','policy'),('org.trillionnium.hepta.local.PublicOwnGroupSessionHostTest','public-session'),
           ('org.trillionnium.hepta.local.ServiceScopeHostTest','service-scope'),
           ('org.trillionnium.hepta.local.ModeActivationHostTest','mode-activation'),
           ('org.trillionnium.hepta.local.PersonalModeHostTest','personal-mode'),
           ('org.trillionnium.hepta.local.BackgroundSessionHostTest','legacy-session'),('org.trillionnium.hepta.local.ProfileSessionHostTest','legacy-profile'),
           ('org.trillionnium.hepta.local.BackgroundTaskTargetHostTest','legacy-target')]
    for cls,name in tests:
        where='public-own-group-policy' if name in ('policy','public-session','service-scope','mode-activation','personal-mode') else 'background-session'
        files.append(source/'tests'/where/(cls.rsplit('.',1)[1]+'.java'))
    files=list(dict.fromkeys(pathlib.Path(p).resolve() for p in files))
    classes=out/'classes';classes.mkdir();pins={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    if args.java_home:
        java=str(args.java_home.resolve()/'bin/java');javac=str(args.java_home.resolve()/'bin/javac')
        if not pathlib.Path(java).is_file() or not pathlib.Path(javac).is_file():raise SystemExit('Specified Java home must provide both java and javac')
        compiler=[javac]
    else:
        java=shutil.which('java') or 'java';compiler=[shutil.which('javac')] if shutil.which('javac') else [java,'-m','jdk.compiler/com.sun.tools.javac.Main']
    flags=['--release','8','-Xlint:all'] if args.release8 else ['-source','8','-target','8','-Xlint:all,-options']
    stages=[('compile',compiler+flags+['-Werror','-encoding','UTF-8','-d',str(classes),*map(str,files)])]
    stages.extend((name,[java,'-cp',str(classes),cls,str(out/(name+'-CASES.json'))]) for cls,name in tests)
    report={'schema':'hepta.public-own-group.scope-host.v1','status':'NOT_DEPLOYED','phone_contacted':False,'default_policy':'legacy_public_unchanged',
            'full_production_session':True,'compiler_contract':'Java8 API release' if args.release8 else 'supplemental Java8 syntax/class target','android_transport_and_clock_fake':True,'actual_broker_model_or_ui_executed':False,'source_sha256':pins,'fixture_extraction':record,'stages':[]}
    for name,argv in stages:
        run=subprocess.run(argv,capture_output=True,text=True,timeout=60)
        (out/(name+'.stdout')).write_text(run.stdout);(out/(name+'.stderr')).write_text(run.stderr)
        report['stages'].append({'name':name,'exit_code':run.returncode});print(name,run.returncode,run.stdout[-600:].strip())
        if run.returncode:print(run.stderr[-7000:]);break
    report['source_unchanged']=all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==sha for p,sha in pins.items())
    report['passed']=len(report['stages'])==len(stages) and all(s['exit_code']==0 for s in report['stages']) and report['source_unchanged']
    (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':report['passed'],'phone_contacted':False,'status':'NOT_DEPLOYED'}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
