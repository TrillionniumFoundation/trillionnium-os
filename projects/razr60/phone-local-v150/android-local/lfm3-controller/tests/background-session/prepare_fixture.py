"""Compile actual BackgroundSession and FilesRoot with explicit Android transport/display IO fakes."""
from pathlib import Path
import hashlib,json,importlib.util

def prepare(source,output,*,include_terminal=True):
 source,output=Path(source),Path(output);output.mkdir(parents=True,exist_ok=True)
 pkg=source/'src/org/trillionnium/hepta/local';fixtures=source/'tests/qualification-scope/fixtures'
 copies=['org/json/JSONException.java','org/json/FixtureJson.java','org/json/JSONObject.java','org/json/JSONArray.java',
 'android/system/Os.java','android/system/OsConstants.java','android/system/StructStat.java','android/system/ErrnoException.java','android/os/Process.java','android/os/Looper.java','android/content/pm/ApplicationInfo.java']
 files=[]
 for name in copies:
  dst=output/name;dst.parent.mkdir(parents=True,exist_ok=True);text=(fixtures/name).read_text()
  if name=='org/json/JSONObject.java':
   one_arg_signature='public String optString(String key)'
   one_arg_method='    public String optString(String key){return optString(key,"");}\n'
   if one_arg_signature in text:
    if text.count(one_arg_signature)!=1 or text.count(one_arg_method)!=1:
     raise RuntimeError('nonunique or changed JSON optString single-argument fixture')
   else:
    anchor='    public boolean has(String key)'
    if text.count(anchor)!=1:raise RuntimeError('nonunique JSON optString compatibility insertion point')
    text=text.replace(anchor,one_arg_method+anchor)
   text=text.replace('    private static String quote(', '    public static String quote(')
  if name=='android/system/Os.java':
   text=text.replace(' public static void close(', ' public static boolean failUnlink;\n public static void remove(String s)throws Exception{if(failUnlink)throw new IOException("synthetic remove failure");Files.delete(Paths.get(s));}\n public static void rename(String a,String b)throws Exception{Files.move(Paths.get(a),Paths.get(b),StandardCopyOption.REPLACE_EXISTING);}\n public static void close(')
  dst.write_text(text);files.append(dst)
 code={
 'org/json/JSONTokener.java':'''package org.json; public final class JSONTokener {private final String raw;public JSONTokener(String raw){this.raw=raw;}public Object nextValue()throws JSONException{return new JSONObject(raw);}public char nextClean(){return 0;}}''',
 'android/os/SystemClock.java':'''package android.os;public final class SystemClock {public static long now=1000000;public static long elapsedRealtime(){return now;}public static void sleep(long ms){now+=ms;}}''',
 'android/provider/Settings.java':'''package android.provider;public final class Settings {public static final class Global {public static final String BOOT_COUNT="boot_count";public static int boot=10;public static int getInt(Object resolver,String key){return boot;}public static int getInt(Object resolver,String key,int fallback){return boot;}}}''',
 'android/app/KeyguardManager.java':'''package android.app;public final class KeyguardManager {public boolean locked;public boolean isKeyguardLocked(){return locked;}public boolean isKeyguardSecure(){throw new AssertionError("legacy client fixture has no credential or experimental-display proof");}public boolean isDeviceSecure(){throw new AssertionError("legacy client fixture has no credential or experimental-display proof");}public boolean isDeviceLocked(){throw new AssertionError("legacy client fixture has no credential or experimental-display proof");}}''',
 'android/view/Display.java':'''package android.view;public final class Display {public static final int DEFAULT_DISPLAY=0;public final int id;public final String name;public boolean valid=true;public int flags=6272;public Display(int id,String name){this.id=id;this.name=name;}public String getName(){return name;}public int getDisplayId(){return id;}public int getFlags(){return flags;}public boolean isValid(){return valid;}}''',
 'android/hardware/display/DisplayManager.java':'''package android.hardware.display;public final class DisplayManager {public final java.util.Map<Integer,android.view.Display> displays=new java.util.LinkedHashMap<Integer,android.view.Display>();public android.view.Display getDisplay(int id){return displays.get(id);}public android.view.Display[] getDisplays(){return displays.values().toArray(new android.view.Display[0]);}}''',
 'android/content/Context.java':'''package android.content;public final class Context {public static final String DISPLAY_SERVICE="display",KEYGUARD_SERVICE="keyguard";public final android.hardware.display.DisplayManager displays=new android.hardware.display.DisplayManager();public android.app.KeyguardManager keyguard=new android.app.KeyguardManager();private final java.io.File files;public Context(java.io.File f){files=f;}public Context getApplicationContext(){return this;}public java.io.File getFilesDir(){return files;}public Object getSystemService(String s){return DISPLAY_SERVICE.equals(s)?displays:keyguard;}public Object getContentResolver(){return this;}public android.content.pm.ApplicationInfo getApplicationInfo(){android.content.pm.ApplicationInfo a=new android.content.pm.ApplicationInfo();a.sourceDir=new java.io.File(files,"fake.apk").getPath();return a;}}''',
 'android/net/Credentials.java':'''package android.net;public final class Credentials {private final int uid;public Credentials(int value){uid=value;}public int getUid(){return uid;}}''',
 'android/net/LocalSocketAddress.java':'''package android.net;public final class LocalSocketAddress {public enum Namespace {ABSTRACT}public final String name;public final Namespace namespace;public LocalSocketAddress(String name,Namespace namespace){this.name=name;this.namespace=namespace;}}''',
 'android/net/LocalSocket.java':'''package android.net;import java.io.*;import java.util.*;
public final class LocalSocket implements Closeable {
 public interface Reply {byte[] reply(byte[] request)throws Exception;}
 public static Reply responder;public static int peerUid=0,connections,timeout;
 public static boolean missing;public static byte[] sent=new byte[0];
 public static final List<String> events=new ArrayList<String>();
 private boolean connected;private final ByteArrayOutputStream output=new ByteArrayOutputStream();
 public static void reset(){responder=null;peerUid=0;connections=0;timeout=0;missing=false;sent=new byte[0];events.clear();}
 public void setSoTimeout(int ms)throws IOException{if(!connected)throw new IOException("socket not created");events.add("timeout");timeout=ms;}
 public void connect(LocalSocketAddress a)throws IOException{events.add("connect");connections++;if(missing)throw new IOException("synthetic absent endpoint");if(a.namespace!=LocalSocketAddress.Namespace.ABSTRACT)throw new IOException("wrong namespace");connected=true;}
 public Credentials getPeerCredentials(){events.add("peer");return new Credentials(peerUid);}
 public OutputStream getOutputStream(){events.add("output");return output;}
 public InputStream getInputStream()throws IOException{events.add("input");sent=output.toByteArray();try{return new ByteArrayInputStream(responder.reply(sent));}catch(IOException e){throw e;}catch(Exception e){throw new IOException(e);}}
 public void close(){events.add("close");connected=false;}
}''',
 'org/trillionnium/hepta/background/RecoveryControllerIdentity.java':'''package org.trillionnium.hepta.background;
/** Explicit unavailable PackageManager/APK IO for generic legacy tests. */
public final class RecoveryControllerIdentity {public static org.json.JSONObject read(android.content.Context context,int uid,long deadline)throws Exception{throw new java.io.IOException("host fixture cannot certify a current installed APK");}}''',
 'org/trillionnium/hepta/local/HostRecoveryProcessBoundary.java':'''package org.trillionnium.hepta.local;
/** Root-process IO is unavailable in this generic host fixture; never returns synthetic authority. */
final class HostRecoveryProcessBoundary {static Process start(String command)throws java.io.IOException{throw new java.io.IOException("host fixture cannot launch a recovery root process");}}''',
 'org/trillionnium/hepta/local/ProfileCatalogueClient.java':'''package org.trillionnium.hepta.local;import org.trillionnium.hepta.background.ProfileTarget;final class ProfileCatalogueClient {static ProfileTarget actual;static void requireCurrent(android.content.Context c,ProfileTarget expected){if(actual==null||!expected.same(actual))throw new IllegalStateException("synthetic privileged catalogue identity unavailable");}}''',
 'org/trillionnium/hepta/local/LocalProbeApplication.java':'package org.trillionnium.hepta.local;final class LocalProbeApplication {static boolean permissionBusy;static void requirePermissionPreparationIdle(android.content.Context c){if(permissionBusy)throw new IllegalStateException("permission preparation active");}}',
 'org/trillionnium/hepta/local/HeptaAccessibilityService.java':'''package org.trillionnium.hepta.local;final class HeptaAccessibilityService {interface Cancellation{boolean isCancelled();}static String sha(byte[] bytes){return QualificationScope.hash(bytes);}static String message(Throwable t){return t.getMessage()==null?t.getClass().getSimpleName():t.getMessage();}}'''
 }
 raw=(pkg/'QualificationScopeConfig.java').read_text();a=raw.index('    static final class FilesRoot {');b=raw.index('    static final class Bound {',a);part=raw[a:b]
 code['org/trillionnium/hepta/local/QualificationScopeConfig.java']='package org.trillionnium.hepta.local;\nimport android.content.Context;import android.system.*;import java.io.File;\nfinal class QualificationScopeConfig {\n'+part+'}\n'
 for name,text in code.items():
  dst=output/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(text);files.append(dst)
 files += [pkg/(name+'.java') for name in ('BackgroundSession','MobiMindPrivateFiles','QualificationScope',
 'BackgroundTaskTarget','NativeAppGoal','NotesOwnerIntent','TaskAuthorization','ActionDecision','DecisionGrammar',
 'ObservedTargetLabels','ObservedAppLabels','ObservedScrollActions','ObservedImeEnter','AppCatalogueRanker','WorkerGenerationProof')]
 files += [pkg/'web/WebFlightGoal.java',pkg/'web/WebShoppingGoal.java']
 files += [source/'src/org/trillionnium/hepta/background'/(name+'.java') for name in ('BrokerProtocol','PublicPermissionControllerUi','PublicOwnGroupPolicy','PublicOwnGroupPhysicalFence','PublicProfileRecentHistory')]
 files += [source/'src/org/trillionnium/hepta/background'/(name+'.java') for name in ('FixedIntentTools','FixedIntentTarget','ProfileIdentity','ProfileTarget','WindowOwnership','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','ProfilePrelaunchRecovery','ProfilePostlaunchRecovery','PublicProfileAbsenceRecovery','PublicPersonalNotesAbsenceRecovery','PublicPersonalNotesHistory','PermissionWindowObservation','ProfileOwnedTask','ProfilePermissionTransient','ProfileDisplayCustody')]
 # Keep the actual recovery client, projecting only the root process factory to a refusing IO boundary.
 # The dedicated recovery gate replaces the same factory with its explicit owned-process fixture.
 recovery_source=pkg/'ProfileRecoveryClient.java';recovery_raw=recovery_source.read_text()
 recovery_seam='new ProcessBuilder("su","-c",command).redirectErrorStream(true).start()'
 if recovery_raw.count(recovery_seam)!=1:raise RuntimeError('nonunique recovery process factory seam')
 recovery_projection=output/'org/trillionnium/hepta/local/ProfileRecoveryClient.java'
 recovery_projection.write_text(recovery_raw.replace(recovery_seam,'HostRecoveryProcessBoundary.start(command)'))
 files.append(recovery_projection)
 post_source=pkg/'ProfilePostlaunchRecoveryClient.java';post_raw=post_source.read_text()
 if post_raw.count(recovery_seam)!=1:raise RuntimeError('nonunique postlaunch recovery process factory seam')
 post_projection=output/'org/trillionnium/hepta/local/ProfilePostlaunchRecoveryClient.java'
 post_projection.write_text(post_raw.replace(recovery_seam,'HostRecoveryProcessBoundary.start(command)'))
 files.append(post_projection)
 public_source=pkg/'PublicProfileRecoveryClient.java';public_raw=public_source.read_text()
 if public_raw.count(recovery_seam)!=1:raise RuntimeError('nonunique public recovery process factory seam')
 public_projection=output/'org/trillionnium/hepta/local/PublicProfileRecoveryClient.java'
 public_projection.write_text(public_raw.replace(recovery_seam,'HostRecoveryProcessBoundary.start(command)'))
 files.append(public_projection)
 # The Notes branch also compiles its complete production client. Generic tests
 # preserve the same refusing process boundary and cannot manufacture a receipt.
 notes_source=pkg/'PublicPersonalNotesRecoveryClient.java';notes_raw=notes_source.read_text()
 if notes_raw.count(recovery_seam)!=1:raise RuntimeError('nonunique Notes recovery process factory seam')
 notes_projection=output/'org/trillionnium/hepta/local/PublicPersonalNotesRecoveryClient.java'
 notes_projection.write_text(notes_raw.replace(recovery_seam,'HostRecoveryProcessBoundary.start(command)'))
 files.append(notes_projection)
 # The exact finalization block is shared with the existing warm-finalization harness.
 # Android/model IO remains fake; the status policy itself is not reimplemented here.
 terminal_record={'included':False,'reason':'dedicated recovery gate does not exercise controller finalization'}
 if include_terminal:
  warm_helper=source/'tests/warm-finalization/prepare_fixture.py'
  warm_spec=importlib.util.spec_from_file_location('background_terminal_fixture',warm_helper)
  warm=importlib.util.module_from_spec(warm_spec);warm_spec.loader.exec_module(warm)
  terminal_files,terminal_record=warm.prepare(source,output/'terminal')
  files += [p for p in terminal_files if p.name in ('LocalInference.java','ControllerFinalizationFixture.java','TaskCancellationQueue.java')]

 records={'schema':'hepta.background-client-host-extraction.v1','actual_full_classes':['BackgroundSession','MobiMindPrivateFiles','QualificationScope','BrokerProtocol','PublicPermissionControllerUi','ProfilePrelaunchRecovery','ProfilePostlaunchRecovery','ProfileTaskPolicy','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask'],'actual_files_root_sha256':hashlib.sha256(part.encode()).hexdigest(),'boundary':'Android LocalSocket/DisplayManager/Keyguard/clock IO are explicit fakes; no broker process, Android runtime, root, model or phone actions','source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.parent==pkg},'controller_finalization':terminal_record,'recovery_client_projection':{'source_sha256':hashlib.sha256(recovery_raw.encode()).hexdigest(),'projected_sha256':hashlib.sha256(recovery_projection.read_bytes()).hexdigest(),'single_replacement':'root ProcessBuilder factory -> always-throwing host IO boundary','recovery_success_or_phone_qualification_claimed':False},'postlaunch_client_projection':{'source_sha256':hashlib.sha256(post_raw.encode()).hexdigest(),'projected_sha256':hashlib.sha256(post_projection.read_bytes()).hexdigest(),'single_replacement':'root ProcessBuilder factory -> always-throwing host IO boundary','recovery_success_or_phone_qualification_claimed':False}}
 records['public_profile_client_projection']={'source_sha256':hashlib.sha256(public_raw.encode()).hexdigest(),'projected_sha256':hashlib.sha256(public_projection.read_bytes()).hexdigest(),'single_replacement':'root ProcessBuilder factory -> always-throwing host IO boundary','installed_identity_boundary':'explicit always-unavailable PackageManager/APK test double','recovery_success_or_phone_qualification_claimed':False}
 records['personal_notes_client_projection']={'source_sha256':hashlib.sha256(notes_raw.encode()).hexdigest(),'projected_sha256':hashlib.sha256(notes_projection.read_bytes()).hexdigest(),'single_replacement':'root ProcessBuilder factory -> always-throwing host IO boundary','recovery_success_or_phone_qualification_claimed':False}
 (output/'EXTRACTION.json').write_text(json.dumps(records,indent=2)+'\n')
 return files,records
