"""Declared Android/asset/process/schedule IO for the automatic UI gate.
No preference, resolver, transaction, UI Start or settings-reservation algorithm is rewritten.
"""
import hashlib
from pathlib import Path

PORTS = {
'android/content/SharedPreferences.java':'''package android.content;
import java.util.*;
public interface SharedPreferences {
 Map<String,?> getAll(); Editor edit();
 interface Editor {Editor putString(String key,String value);Editor putBoolean(String key,boolean value);Editor remove(String key);boolean commit();}
 final class Memory implements SharedPreferences {
  public final Map<String,Object> values=new TreeMap<String,Object>();public int commits;public boolean fail;public Runnable beforeRead;
  public Map<String,?> getAll(){if(beforeRead!=null){Runnable r=beforeRead;beforeRead=null;r.run();}return new TreeMap<String,Object>(values);}
  public Editor edit(){return new Editor(){final Map<String,Object> updates=new TreeMap<String,Object>();
   public Editor putString(String k,String v){updates.put(k,v);return this;}public Editor putBoolean(String k,boolean v){updates.put(k,v);return this;}
   public Editor remove(String k){updates.put(k,null);return this;}public boolean commit(){commits++;if(fail)return false;for(Map.Entry<String,Object> e:updates.entrySet())if(e.getValue()==null)values.remove(e.getKey());else values.put(e.getKey(),e.getValue());return true;}};
  }
 }
}''',
'android/content/Context.java':'''package android.content;
public class Context {
 public static final int MODE_PRIVATE=0;public static final String DISPLAY_SERVICE="display",KEYGUARD_SERVICE="keyguard",INPUT_METHOD_SERVICE="input_method";
 public final android.hardware.display.DisplayManager displays=new android.hardware.display.DisplayManager();public final android.app.KeyguardManager keyguard=new android.app.KeyguardManager();
 public final java.util.Map<String,SharedPreferences.Memory> preferences=new java.util.TreeMap<String,SharedPreferences.Memory>();
 public final android.content.pm.PackageManager packages=new android.content.pm.PackageManager();private final java.io.File files;
 public Context(java.io.File f){files=f;}public Context getApplicationContext(){return this;}public java.io.File getFilesDir(){return files;}
 public Object getSystemService(String n){return DISPLAY_SERVICE.equals(n)?displays:INPUT_METHOD_SERVICE.equals(n)?new android.view.inputmethod.InputMethodManager():keyguard;}
 public Object getContentResolver(){return this;}public android.content.pm.ApplicationInfo getApplicationInfo(){android.content.pm.ApplicationInfo a=new android.content.pm.ApplicationInfo();a.sourceDir=new java.io.File(files,"fake.apk").getPath();a.uid=10481;return a;}
 public android.content.pm.PackageManager getPackageManager(){return packages;}public String getPackageName(){return "org.trillionnium.hepta.local";}
 public SharedPreferences.Memory getSharedPreferences(String n,int mode){SharedPreferences.Memory p=preferences.get(n);if(p==null){p=new SharedPreferences.Memory();preferences.put(n,p);}return p;}
}''',
'android/content/Intent.java':'''package android.content;public final class Intent {}''',
'android/content/pm/PackageManager.java':'''package android.content.pm;
public class PackageManager {public static final int GET_SIGNING_CERTIFICATES=134217728;public final java.util.Map<String,PackageInfo> installed=new java.util.TreeMap<String,PackageInfo>();
 public PackageInfo getPackageInfo(String p,int flags)throws Exception {PackageInfo i=installed.get(p);if(i==null)throw new Exception("synthetic package absent");return i;}
 public android.content.Intent getLaunchIntentForPackage(String p){return installed.containsKey(p)?new android.content.Intent():null;}
 public void install(String name,int uid,byte[] certificate){PackageInfo p=new PackageInfo();p.packageName=name;p.applicationInfo=new ApplicationInfo();p.applicationInfo.packageName=name;p.applicationInfo.uid=uid;p.applicationInfo.enabled=true;p.signingInfo=new SigningInfo(certificate);installed.put(name,p);}
}''',
'android/content/pm/ApplicationInfo.java':'''package android.content.pm;public final class ApplicationInfo {public String packageName,sourceDir;public String[] splitSourceDirs;public int uid;public boolean enabled=true;}''',
'android/content/pm/PackageInfo.java':'''package android.content.pm;public final class PackageInfo {public String packageName;public ApplicationInfo applicationInfo;public SigningInfo signingInfo;}''',
'android/content/pm/SigningInfo.java':'''package android.content.pm;public final class SigningInfo {private final byte[] raw;public SigningInfo(byte[] b){raw=b.clone();}public Signature[] getApkContentsSigners(){return new Signature[]{new Signature(raw)};}}''',
'android/content/pm/Signature.java':'''package android.content.pm;public final class Signature {private final byte[] raw;public Signature(byte[] b){raw=b.clone();}public byte[] toByteArray(){return raw.clone();}}''',
'android/os/Looper.java':'''package android.os;public final class Looper {private static final Thread OWNER=Thread.currentThread();private static final Looper MAIN=new Looper();public static Looper getMainLooper(){return MAIN;}public static Looper myLooper(){return Thread.currentThread()==OWNER?MAIN:null;}}''',
'android/os/Handler.java':'''package android.os;public final class Handler {private static final java.util.concurrent.LinkedBlockingQueue<Runnable> QUEUE=new java.util.concurrent.LinkedBlockingQueue<Runnable>();public Handler(Looper l){}public boolean post(Runnable r){QUEUE.add(r);return true;}public static boolean pump()throws Exception{Runnable r=QUEUE.poll(20,java.util.concurrent.TimeUnit.MILLISECONDS);if(r==null)return false;r.run();return true;}public static int size(){return QUEUE.size();}}''',
'android/view/View.java':'''package android.view;public class View {public static final int VISIBLE=0,GONE=8;public boolean shown=true,enabled=true;public boolean isShown(){return shown;}public boolean isEnabled(){return enabled;}public void setEnabled(boolean b){enabled=b;}public void setVisibility(int v){shown=v==VISIBLE;}public Object getWindowToken(){return this;}}''',
'android/view/inputmethod/InputMethodManager.java':'''package android.view.inputmethod;public final class InputMethodManager {public boolean hideSoftInputFromWindow(Object token,int flags){return true;}}''',
'android/app/Activity.java':'''package android.app;public class Activity extends android.content.Context {
 public final android.content.Context app;public boolean focused=true,finishing,destroyed;private final Window window=new Window();
 public Activity(android.content.Context app){super(app.getFilesDir());this.app=app;}
 public Object getApplication(){return app;}@Override public android.content.Context getApplicationContext(){return app;}
 @Override public android.content.pm.PackageManager getPackageManager(){return app.getPackageManager();}
 @Override public android.content.SharedPreferences.Memory getSharedPreferences(String n,int mode){return app.getSharedPreferences(n,mode);}
 public boolean hasWindowFocus(){return focused;}public boolean isFinishing(){return finishing;}public boolean isDestroyed(){return destroyed;}public Window getWindow(){return window;}
 public void runOnUiThread(Runnable r){if(android.os.Looper.myLooper()==android.os.Looper.getMainLooper())r.run();else new android.os.Handler(android.os.Looper.getMainLooper()).post(r);}
 public boolean moveTaskToBack(boolean b){return true;}public void onWindowFocusChanged(boolean f){focused=f;}protected void onStop(){}protected void onStart(){}
 public static final class Window {private final android.view.View decor=new android.view.View();public android.view.View getDecorView(){return decor;}}
}''',
'android/app/AlertDialog.java':'''package android.app;public final class AlertDialog {
 public interface Click {void selected(Object dialog,int which);}public interface Multi {void selected(Object dialog,int which,boolean checked);}
 public static final class Builder {public Builder(Activity a){}public Builder setTitle(String s){return this;}public Builder setItems(String[] s,Click c){return this;}public Builder setMultiChoiceItems(String[] s,boolean[] b,Multi m){return this;}public Builder setNegativeButton(String s,Click c){return this;}public Builder setPositiveButton(String s,Click c){return this;}public AlertDialog show(){return new AlertDialog();}}
}''',
'org/trillionnium/hepta/local/RecoveryProcessInventory.java':'''package org.trillionnium.hepta.local;final class RecoveryProcessInventory {static boolean fail;private static long clock;static java.util.List<RecoveryQuiescence.Sample> awaitInitial(LocalProbeApplication app){return new java.util.ArrayList<RecoveryQuiescence.Sample>(java.util.Arrays.asList(capture(app),capture(app),capture(app)));}static RecoveryQuiescence.Sample capture(LocalProbeApplication app){if(fail)throw new IllegalStateException("inventory unavailable port");return new RecoveryQuiescence.Sample(android.os.Process.myUid(),android.os.Process.myPid(),321,clock+=1000,0,true);}}''',
'org/trillionnium/hepta/local/LocalTaskSession.java':'''package org.trillionnium.hepta.local;
final class LocalTaskSession {boolean running,blocked,recovering,lease,failSchedule;int schedules;BackgroundSession.Selection selection;TaskAuthorization authorization;String owner;
 boolean isRunning(){return running;}boolean isBlocked(){return blocked;}boolean isRecovering(){return recovering;}boolean hasBackgroundLease(){return lease;}
 void requireModelSettingsJournalIdle(){if(running||blocked||recovering||lease)throw new IllegalStateException("task journal not idle");}
 boolean schedule(String o,String source,String nonce,String scope,TaskAuthorization a,BackgroundSession.Selection s,int delay){schedules++;owner=o;selection=s;authorization=a;if(s!=null)s.requireTaskTarget(o,a);if(failSchedule)return false;running=true;return true;}
 void stop(){running=false;}void bind(Object o){}void unbind(Object o){}
}''',
}


ENGINE_HEADER='''package org.trillionnium.hepta.local;
import java.io.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
/** Exact settings methods; native assets, cancellation inventory and unrelated inference are ports. */
final class LocalModelEngine {
 private final File files;private volatile RuntimeGeneration runtime;private volatile boolean settingsBlocked;private SettingsReservation settingsReservation;
 private static final Object PROCESS_ADMISSION=new Object();private static final AtomicReference<RunHandle> PROCESS_ACTIVE=new AtomicReference<RunHandle>();
 private final AtomicReference<RunHandle> active=new AtomicReference<RunHandle>();private final AtomicReference<Object> warmActive=new AtomicReference<Object>();private final AtomicBoolean closed=new AtomicBoolean();
 private final ThreadPoolExecutor executor=new ThreadPoolExecutor(1,1,0L,TimeUnit.MILLISECONDS,new LinkedBlockingQueue<Runnable>());
 private static final CancellationPort ACTIVE_CANCELLATION=new CancellationPort();private static final class CancellationPort {boolean pending(){return false;}}
 private static final class RunHandle {final AtomicReference<Process> child=new AtomicReference<Process>();}
 int verificationCalls;boolean failVerification,externalBusy;CountDownLatch verificationEntered,verificationRelease;
 LocalModelEngine(File files)throws Exception{this.files=files;runtime=generation(RuntimeConfigTransaction.current(files),new ModelFileVerifier());}
 boolean isBusy(){return settingsReservation!=null||externalBusy;}void cancelActive(){}
 ModelFileVerifier verifySettingsModel(SettingsReservation lease,LocalRuntimeConfig target)throws Exception {
  requireSettingsOwner(lease);RuntimeConfigTransaction.requireSupported(target);verificationCalls++;
  if(verificationEntered!=null)verificationEntered.countDown();if(verificationRelease!=null&&!verificationRelease.await(10,TimeUnit.SECONDS))throw new IOException("asset port timeout");
  if(failVerification)throw new IOException("declared unavailable model asset port");requireSettingsOwner(lease);return new ModelFileVerifier();
 }
 void hostGeneration(RuntimeGeneration next){runtime=next;}
 void hostError(){runtime=new RuntimeGeneration(null,runtime.source,new ModelFileVerifier(),"declared invalid current config port");}
 void close(){closed.set(true);executor.shutdown();}
'''

APP_HEADER='''package org.trillionnium.hepta.local;
final class LocalProbeApplication extends android.content.Context {
 final LocalModelEngine model;final LocalTaskSession tasks=new LocalTaskSession();LocalModelSettings modelSettings;
 Object recoveryBarrier,controlRecoveryAttempt;boolean controlRecoveryCallbackFailed,diagnosticsClean=true;
 static boolean permissionBusy;static void requirePermissionPreparationIdle(android.content.Context c){if(permissionBusy)throw new IllegalStateException("permission active port");}
 LocalProbeApplication(java.io.File files)throws Exception{super(files);model=new LocalModelEngine(files);modelSettings=new LocalModelSettings(this,model);}
 private void initializeSessions(){}private boolean otherDiagnosticsClean(){return diagnosticsClean;}LocalTaskSession taskSession(){return tasks;}
'''

UI_HEADER='''package org.trillionnium.hepta.local;
import android.app.Activity;import android.app.AlertDialog;import android.view.View;import android.view.inputmethod.InputMethodManager;import java.io.File;
/** Actual automatic UI and ordinary beginTask. View/package/process/schedule ports are declared. */
final class MainActivity extends Activity implements LocalModelSettings.Listener {
 final LocalModelEngine engine;final LocalTaskSession tasks;final LocalModelSettings modelSettings;
 final Port backgroundPermission=new Port(),modelImport=new Port();boolean profileCatalogueLoading,accessibilityUiStarted=true;
 Widget taskInput=new Widget(),taskState=new Widget(),backgroundMode=new Widget(),automaticTargetMode=new Widget(),startTask=new Widget(),pickAutomaticTargets=new Widget(),pickAutomaticInstance=new Widget(),backgroundChoiceState=new Widget(),backgroundInitialLabel=new Widget(),initialBackgroundApp=new Widget();
 BackgroundAutoTargetPreferences.Snapshot automaticTargets;BackgroundAutoTargetResolver.Resolution automaticResolution;
 String automaticTargetsError,automaticInstanceChoice,automaticStartFeedback,backgroundModePreferenceError;long automaticUiEpoch;AutomaticStart automaticStartPending,automaticReadyStart;
 QualificationScope.Launch scopeLaunch=QualificationScope.Launch.normal();String scopeLaunchError;
 java.util.Set<String> backgroundPackages=new java.util.TreeSet<String>();BackgroundUiPreferences.Selection manual;boolean manualProfile,manualPersonal;
 HeptaAccessibilityService profilePermissionService;final Runnable accessibilityConnectionChanged=()->{};final Object profilePermissionChanged=new Object();
 static final class Port {boolean busy;boolean isBusy(){return busy;}boolean blocksOtherWork(){return busy;}void bind(Object a){}void unbind(Object a){}}
 static final class Widget extends View {String text="";boolean checked;java.util.function.Consumer<Widget> listener;Runnable edit;
  String getText(){return text;}void setText(String s){text=s;if(edit!=null)edit.run();}boolean isChecked(){return checked;}void setChecked(boolean b){checked=b;}void setOnClickListener(java.util.function.Consumer<Widget> c){listener=c;}}
 MainActivity(LocalProbeApplication app,BackgroundAutoTargetPreferences.Snapshot saved,String owner)throws Exception {
  super(app);engine=app.model;tasks=app.tasks;modelSettings=app.modelSettings;backgroundMode.setChecked(true);BackgroundUiPreferences.saveMode(this,true);
  automaticTargets=saved;BackgroundAutoTargetPreferences.save(this,saved);automaticTargetMode.setChecked(saved.automatic);taskInput.text=owner;
  taskInput.edit=()->{automaticInputChanged();previewTaskAuthorization();};modelSettings.bind(this);
 }
 private void previewTaskAuthorization(){if(automaticMode())currentAutomaticResolution();}
 private void refresh(){}private void refreshProfilePermission(){}
 private void requireCurrentBackgroundChoice()throws Exception{if(manual==null)throw new IllegalStateException("manual choice missing");BackgroundUiPreferences.requireCurrent(this,manual,backgroundPackages,manual.initial,backgroundPackages);}
 private String selectedBackgroundPackage(){return manual==null?null:manual.initial;}private org.trillionnium.hepta.background.ProfileTarget selectedProfileTarget(){return manual==null?null:manual.profileTarget;}
 private boolean selectedIndependentProfileDisplay(){return manualProfile;}private boolean selectedIndependentPersonalDisplay(){return manualPersonal;}
 private org.trillionnium.hepta.background.PublicPermissionControllerUi.Locator controllerUiFromOwnerButton(String owner){return null;}
 boolean start(){return beginTask(taskInput.getText(),"user_button",null);}boolean startForeign(){return beginTask(taskInput.getText(),"other",null);}
 void edit(String text){taskInput.setText(text);}void cancel(){cancelAutomaticStart();}
 void choose(String key){automaticInputChanged();automaticInstanceChoice=key;currentAutomaticResolution();automaticInstanceChoice=key;}
 void mode(boolean value){automaticTargetMode.setChecked(value);automaticInputChanged();}
 boolean pending(){return automaticStartPending!=null||automaticReadyStart!=null;}
 void stopActivity(){onStop();}void resumeActivity(){focused=true;onStart();}
}
'''


def prepare(source, fixture, java_block):
    pkg=source/'src/org/trillionnium/hepta/local';files=[];replaced=[];extraction=[];portrefs=[]
    def emit(rel,text):
        p=fixture/rel;p.parent.mkdir(parents=True,exist_ok=True)
        if p.exists():replaced.append(p)
        p.write_text(text);files.append(p);portrefs.append({'path':str(p),'bytes':len(text.encode()),'sha256':hashlib.sha256(text.encode()).hexdigest()});return p
    for path,text in PORTS.items():emit(path,text)
    # Preserve the entire old refusing service/calendar shapes; add only idle/visibility IO.
    service=fixture/'org/trillionnium/hepta/local/HeptaAccessibilityService.java';raw=service.read_text()
    extension='''
 static final HeptaAccessibilityService LIVE=new HeptaAccessibilityService();static boolean idle=true;
 static HeptaAccessibilityService connected(){return LIVE;}boolean modelSettingsIdle(){return idle;}
 static void addConnectionListener(Runnable r){}static void removeConnectionListener(Runnable r){}
 static final class PermissionUi {void ownerVisibility(Object a,Object b,boolean c){}void bind(Object a){}void unbind(Object a){}}
 PermissionUi permissionUi(){return new PermissionUi();}
'''
    emit('org/trillionnium/hepta/local/HeptaAccessibilityService.java',raw[:raw.rfind('}')]+extension+'}\n')
    catalogue=fixture/'org/trillionnium/hepta/local/ProfileCatalogueClient.java';text=catalogue.read_text();end=text.rfind('}')
    emit('org/trillionnium/hepta/local/ProfileCatalogueClient.java',text[:end]+'static java.util.List<ProfileTarget> load(android.content.Context c){return actual==null?java.util.Collections.<ProfileTarget>emptyList():java.util.Collections.singletonList(actual);}'+'}\n')
    def blocks(path,signatures):
        raw=path.read_bytes();parts=[]
        for signature in signatures:
            value=java_block(raw,signature);parts.append(value);extraction.append({'source':str(path),'source_sha256':hashlib.sha256(raw).hexdigest(),'signature':signature,'bytes':len(value.encode()),'sha256':hashlib.sha256(value.encode()).hexdigest(),'method_body_verbatim':True})
        return '\n'.join(parts)
    eng=blocks(pkg/'LocalModelEngine.java',[
        'static final class RuntimeGeneration {','public LocalRuntimeConfig configuration()',
        'RuntimeGeneration runtimeGeneration()','static RuntimeGeneration generation(', 'boolean settingsBlocked()',
        'private boolean executorIdle()', 'boolean settingsAdmissionAvailable(', 'final class SettingsReservation {',
        'SettingsReservation reserveSettings(', 'private void requireSettingsOwner(', 'void publishSettings(', 'void finishSettings(',
        'public File modelDirectory()', 'public File modelFile()', 'private File modelDirectory(', 'private File modelFile('])
    emit('org/trillionnium/hepta/local/LocalModelEngine.java',ENGINE_HEADER+eng+'\n}\n')
    app=blocks(pkg/'LocalProbeApplication.java',['boolean canChangeLocalModelSettings(', 'void requireModelSettingsIdle(', 'private static void recoveryMainThread()'])
    emit('org/trillionnium/hepta/local/LocalProbeApplication.java',APP_HEADER+app+'\n}\n')
    raw=(pkg/'MainActivity.java').read_bytes();text=raw.decode();start=text.index('    /** One visible Start, never restored');end=text.index('    private void renderProbe(',start)
    fragment=text[start:end];extraction.append({'source':str(pkg/'MainActivity.java'),'source_sha256':hashlib.sha256(raw).hexdigest(),'signature':'complete AutomaticStart through cancelAutomaticStart region','bytes':len(fragment.encode()),'sha256':hashlib.sha256(fragment.encode()).hexdigest(),'method_body_verbatim':True})
    ui=blocks(pkg/'MainActivity.java',['private boolean beginTask(', '@Override public void onLocalModelSettingsChanged()', '@Override public void onWindowFocusChanged(', '@Override protected void onStop()', '@Override protected void onStart()'])
    emit('org/trillionnium/hepta/local/MainActivity.java',UI_HEADER[:UI_HEADER.rfind('}')]+fragment+ui+'\n}\n')
    return {'files':files,'replaced':replaced,'extraction':extraction,'ports':portrefs}
