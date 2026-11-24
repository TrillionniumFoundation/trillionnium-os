#!/usr/bin/env python3
"""Run actual target preferences and exact owner UI choice/restore bodies with declared Android IO."""
import argparse,hashlib,importlib.util,json,os,subprocess,sys
from pathlib import Path

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    for name in ("source","output","java-home","json-jar"):parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();source=args.source.resolve();out=args.output.resolve();jdk=args.java_home.resolve();jar=args.json_jar.resolve()
    if out.exists() or out==source or source in out.parents:raise RuntimeError("fresh output outside source required")
    if sha(jar)!="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed":raise RuntimeError("fixed JSON jar differs")
    out.mkdir(parents=True);generated=out/"generated";classes=out/"classes";classes.mkdir()
    ports_path=source/"tests/native-auto-target/host_ports.py"
    extract_path=source/"tests/runtime-config-ui/run_host_tests.py"
    ports=module(ports_path,"choice_ports");extract=module(extract_path,"choice_extract")
    local=source/"src/org/trillionnium/hepta/local";background=source/"src/org/trillionnium/hepta/background"
    ui_path=local/"MainActivity.java";ui=ui_path.read_text()
    actual=[local/"BackgroundUiPreferences.java",background/"ProfileIdentity.java",background/"ProfileTarget.java"]
    test=Path(__file__).resolve().with_name("BackgroundUiChoiceHostTest.java")
    tracked=actual+[ui_path,test,Path(__file__).resolve(),ports_path,extract_path]
    pins={str(p):sha(p) for p in tracked};files=[]
    def emit(relative,text):
        p=generated/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);files.append(p)
    for name in ("android/content/SharedPreferences.java","android/content/pm/PackageManager.java",
                 "android/content/pm/ApplicationInfo.java","android/content/pm/PackageInfo.java",
                 "android/content/pm/SigningInfo.java","android/content/pm/Signature.java","android/content/Intent.java"):
        emit(name,ports.PORTS[name])
    emit("android/content/Context.java","""package android.content;
public class Context {
 public static final int MODE_PRIVATE=0;
 private final java.util.Map<String,SharedPreferences.Memory> preferences=new java.util.HashMap<String,SharedPreferences.Memory>();
 private final android.content.pm.PackageManager packages=new android.content.pm.PackageManager();
 public SharedPreferences.Memory getSharedPreferences(String name,int mode){SharedPreferences.Memory p=preferences.get(name);if(p==null){p=new SharedPreferences.Memory();preferences.put(name,p);}return p;}
 public android.content.pm.PackageManager getPackageManager(){return packages;}
}
""")
    emit("android/view/View.java","package android.view;public class View {}\n")
    emit("android/widget/AdapterView.java","package android.widget;public class AdapterView<T> {}\n")
    mode_begin=ui.index("    private boolean selectedIndependentProfileDisplay(){")
    mode_end=ui.index("    private org.trillionnium.hepta.background.ProfileTarget selectedProfileTarget(){",mode_begin)
    mode=ui[mode_begin:mode_end]
    remember=extract.method(ui,"private void rememberExplicitBackgroundChoice()")
    spinner=extract.method(ui,"public void onItemSelected(AdapterView<?> parent,View view,int position,long id)")
    callback=extract.method(ui,".setItems(labels,(dialog,index) -> {")
    callback_body=callback[callback.index("{")+1:-1]
    ui_fixture="""package org.trillionnium.hepta.local;
import android.content.Context;import android.content.SharedPreferences;import android.view.View;import android.widget.AdapterView;
import java.util.*;import org.trillionnium.hepta.background.ProfileTarget;
final class MainActivity extends Context {
 final Context store;final Widget independentProfileDisplay=new Widget(),independentPersonalDisplay=new Widget(),backgroundMode=new Widget(),taskState=new Widget();
 final Busy tasks=new Busy(),engine=new Busy();boolean backgroundInitialChoicePending;
 String backgroundDisplayPreferenceError,backgroundSelectionPreferenceError,backgroundModePreferenceError,initial;
 final Set<String> backgroundPackages=new TreeSet<String>();final Map<String,String> backgroundAppLabels=new TreeMap<String,String>();
 BackgroundUiPreferences.Selection rememberedBackgroundSelection;
 static final class Widget {boolean checked;String text="";boolean isChecked(){return checked;}void setChecked(boolean b){checked=b;}void setText(String s){text=s;}}
 static final class Busy {boolean isRunning(){return false;}boolean isBusy(){return false;}boolean isBlocked(){return false;}boolean isRecovering(){return false;}boolean hasBackgroundLease(){return false;}}
 MainActivity(Context store){this.store=store;restoreIndependentProfileDisplay();}
 @Override public SharedPreferences.Memory getSharedPreferences(String name,int mode){return store.getSharedPreferences(name,mode);}
 @Override public android.content.pm.PackageManager getPackageManager(){return store.getPackageManager();}
 private ProfileTarget selectedProfileTarget(){return rememberedBackgroundSelection==null?null:rememberedBackgroundSelection.profileTarget;}
 private String selectedBackgroundPackage(){return initial;}
 private void reloadBackgroundApps(){backgroundAppLabels.clear();for(String p:getPackageManager().installed.keySet())backgroundAppLabels.put(p,p);if(selectedProfileTarget()!=null)backgroundAppLabels.put(selectedProfileTarget().packageName,selectedProfileTarget().appLabel());}
 private void updateBackgroundSelection(String value){initial=value;}
 private void refresh(){}
 void restore(){restoreIndependentProfileDisplay();}
 boolean profileSelected(){return selectedIndependentProfileDisplay();}
 boolean personalSelected(){return selectedIndependentPersonalDisplay();}
 void choosePersonal(String pkg){choosePersonalRange(Collections.singleton(pkg),pkg);}
 void choosePersonalRange(Set<String> packages,String initial){rememberedBackgroundSelection=null;backgroundPackages.clear();backgroundPackages.addAll(packages);this.initial=initial;rememberExplicitBackgroundChoice();}
 void chooseInitial(String initial){this.initial=initial;backgroundInitialChoicePending=true;onItemSelected(null,null,0,0);}
 void chooseProfile(ProfileTarget target){java.util.List<ProfileTarget> targets=Collections.singletonList(target);int index=0;
"""+callback_body+"\n}\n"+mode+"\n"+remember+"\n"+spinner+"\n}\nfinal class HeptaAccessibilityService {static String message(Exception e){return e.getMessage();}}\n"
    emit("org/trillionnium/hepta/local/MainActivity.java",ui_fixture)
    files+=actual+[test]
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
    for key in ("CLASSPATH","JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS"):env.pop(key,None)
    stages=[("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror","-cp",jar,"-d",classes,*files]),
            ("cases",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.BackgroundUiChoiceHostTest"])]
    report={"schema":"hepta.background-ui-choice-host.v1","passed":False,"source_sha256":pins,"stages":[],
            "exact_ui_bodies_sha256":{name:hashlib.sha256(text.encode()).hexdigest() for name,text in (("mode",mode),("remember",remember),("spinner",spinner),("profile_callback",callback_body))},
            "whole_production_preferences":True,"android_preferences_and_package_manager_are_host_ports":True,
            "android_runtime":False,"phone_operations":0,"rendered_ui_tested":False}
    for name,command in stages:
        run=subprocess.run(list(map(str,command)),capture_output=True,text=True,env=env,timeout=60)
        (out/(name+".stdout")).write_text(run.stdout);(out/(name+".stderr")).write_text(run.stderr)
        report["stages"].append({"name":name,"exit_code":run.returncode,"argv":list(map(str,command))})
        if run.returncode:print(run.stdout[-4000:]);print(run.stderr[-6000:]);break
        if name=="cases":report["cases"]=json.loads(run.stdout)
    report["sources_unchanged"]=all(sha(Path(p))==digest for p,digest in pins.items())
    report["passed"]=len(report["stages"])==2 and all(row["exit_code"]==0 for row in report["stages"]) and report["sources_unchanged"] and report.get("cases",{}).get("passed") is True and report["cases"].get("cases")==8
    (out/"RESULT.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"passed":report["passed"],"result":str(out/"RESULT.json"),"phone_operations":0}))
    return 0 if report["passed"] else 1

if __name__=="__main__":sys.exit(main())
