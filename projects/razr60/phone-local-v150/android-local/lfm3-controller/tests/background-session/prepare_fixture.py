"""Compile actual BackgroundSession and FilesRoot with explicit Android transport/display IO fakes."""
from pathlib import Path
import hashlib,json

def prepare(source,output):
 source,output=Path(source),Path(output);output.mkdir(parents=True,exist_ok=True)
 pkg=source/'src/org/trillionnium/hepta/local';fixtures=source/'tests/qualification-scope/fixtures'
 copies=['org/json/JSONException.java','org/json/FixtureJson.java','org/json/JSONObject.java','org/json/JSONArray.java',
 'android/system/Os.java','android/system/OsConstants.java','android/system/StructStat.java','android/system/ErrnoException.java','android/os/Process.java','android/os/Looper.java','android/content/pm/ApplicationInfo.java']
 files=[]
 for name in copies:
  dst=output/name;dst.parent.mkdir(parents=True,exist_ok=True);text=(fixtures/name).read_text()
  if name=='org/json/JSONObject.java':
   text=text.replace('    public boolean has(String key)', '    public String optString(String key){return optString(key,"");}\n    public String optString(String key,String fallback){Object value=fields.get(key);return value instanceof String?(String)value:fallback;}\n    public boolean has(String key)')
  if name=='android/system/Os.java':
   text=text.replace(' public static void close(', ' public static boolean failUnlink;\n public static void unlink(String s)throws Exception{if(failUnlink)throw new IOException("synthetic unlink failure");Files.delete(Paths.get(s));}\n public static void rename(String a,String b)throws Exception{Files.move(Paths.get(a),Paths.get(b),StandardCopyOption.REPLACE_EXISTING);}\n public static void close(')
  dst.write_text(text);files.append(dst)
 code={
 'org/json/JSONTokener.java':'''package org.json; public final class JSONTokener {private final String raw;public JSONTokener(String raw){this.raw=raw;}public Object nextValue()throws JSONException{return new JSONObject(raw);}public char nextClean(){return 0;}}''',
 'android/os/SystemClock.java':'''package android.os;public final class SystemClock {public static long now=1000000;public static long elapsedRealtime(){return now;}public static void sleep(long ms){now+=ms;}}''',
 'android/provider/Settings.java':'''package android.provider;public final class Settings {public static final class Global {public static final String BOOT_COUNT="boot_count";public static int boot=10;public static int getInt(Object resolver,String key){return boot;}}}''',
 'android/app/KeyguardManager.java':'''package android.app;public final class KeyguardManager {public boolean locked;public boolean isKeyguardLocked(){return locked;}}''',
 'android/view/Display.java':'''package android.view;public final class Display {public static final int DEFAULT_DISPLAY=0;public final int id;public final String name;public boolean valid=true;public Display(int id,String name){this.id=id;this.name=name;}public String getName(){return name;}public boolean isValid(){return valid;}}''',
 'android/hardware/display/DisplayManager.java':'''package android.hardware.display;public final class DisplayManager {public final java.util.Map<Integer,android.view.Display> displays=new java.util.LinkedHashMap<Integer,android.view.Display>();public android.view.Display getDisplay(int id){return displays.get(id);}public android.view.Display[] getDisplays(){return displays.values().toArray(new android.view.Display[0]);}}''',
 'android/content/Context.java':'''package android.content;public final class Context {public static final String DISPLAY_SERVICE="display",KEYGUARD_SERVICE="keyguard";public final android.hardware.display.DisplayManager displays=new android.hardware.display.DisplayManager();public android.app.KeyguardManager keyguard=new android.app.KeyguardManager();private final java.io.File files;public Context(java.io.File f){files=f;}public Context getApplicationContext(){return this;}public java.io.File getFilesDir(){return files;}public Object getSystemService(String s){return DISPLAY_SERVICE.equals(s)?displays:keyguard;}public Object getContentResolver(){return this;}public android.content.pm.ApplicationInfo getApplicationInfo(){android.content.pm.ApplicationInfo a=new android.content.pm.ApplicationInfo();a.sourceDir=new java.io.File(files,"fake.apk").getPath();return a;}}''',
 'android/net/Credentials.java':'''package android.net;public final class Credentials {private final int uid;public Credentials(int value){uid=value;}public int getUid(){return uid;}}''',
 'android/net/LocalSocketAddress.java':'''package android.net;public final class LocalSocketAddress {public enum Namespace {ABSTRACT}public final String name;public final Namespace namespace;public LocalSocketAddress(String name,Namespace namespace){this.name=name;this.namespace=namespace;}}''',
 'android/net/LocalSocket.java':'''package android.net;import java.io.*;public final class LocalSocket implements Closeable {public interface Reply {byte[] reply(byte[] request)throws Exception;}public static Reply responder;public static int peerUid=0,connections,timeout;public static boolean missing;public static byte[] sent=new byte[0];private final ByteArrayOutputStream output=new ByteArrayOutputStream();public static void reset(){responder=null;peerUid=0;connections=0;timeout=0;missing=false;sent=new byte[0];}public void setSoTimeout(int ms){timeout=ms;}public void connect(LocalSocketAddress a)throws IOException{connections++;if(missing)throw new IOException("synthetic absent endpoint");if(a.namespace!=LocalSocketAddress.Namespace.ABSTRACT)throw new IOException("wrong namespace");}public Credentials getPeerCredentials(){return new Credentials(peerUid);}public OutputStream getOutputStream(){return output;}public InputStream getInputStream()throws IOException{sent=output.toByteArray();try{return new ByteArrayInputStream(responder.reply(sent));}catch(IOException e){throw e;}catch(Exception e){throw new IOException(e);}}public void close(){}}''',
 'org/trillionnium/hepta/local/HeptaAccessibilityService.java':'''package org.trillionnium.hepta.local;final class HeptaAccessibilityService {interface Cancellation{boolean isCancelled();}static String sha(byte[] bytes){return QualificationScope.hash(bytes);}static String message(Throwable t){return t.getMessage()==null?t.getClass().getSimpleName():t.getMessage();}}'''
 }
 raw=(pkg/'QualificationScopeConfig.java').read_text();a=raw.index('    static final class FilesRoot {');b=raw.index('    static final class Bound {',a);part=raw[a:b]
 code['org/trillionnium/hepta/local/QualificationScopeConfig.java']='package org.trillionnium.hepta.local;\nimport android.content.Context;import android.system.*;import java.io.File;\nfinal class QualificationScopeConfig {\n'+part+'}\n'
 for name,text in code.items():
  dst=output/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(text);files.append(dst)
 files += [pkg/(name+'.java') for name in ('BackgroundSession','MobiMindPrivateFiles','QualificationScope')]
 records={'schema':'hepta.background-client-host-extraction.v1','actual_full_classes':['BackgroundSession','MobiMindPrivateFiles','QualificationScope'],'actual_files_root_sha256':hashlib.sha256(part.encode()).hexdigest(),'boundary':'Android LocalSocket/DisplayManager/Keyguard/clock IO are explicit fakes; no broker process, Android runtime, root, model or phone actions','source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.parent==pkg}}
 (output/'EXTRACTION.json').write_text(json.dumps(records,indent=2)+'\n')
 return files,records
