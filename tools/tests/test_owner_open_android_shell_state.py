from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ACTIVITY = ROOT / 'android-integration/working-tree/vendor/trillionnium/owner-open/client/src/org/trillionnium/owneropen/OwnerOpenShellActivity.java'

STUBS = {
 'android/os/Bundle.java': '''package android.os; import java.util.*; public class Bundle { private final Map<String,Object> values=new HashMap<>(); public void putString(String k,String v){values.put(k,v);} public String getString(String k){return (String)values.get(k);} public String getString(String k,String fallback){String v=getString(k);return v==null?fallback:v;} public void putInt(String k,int v){values.put(k,v);} public int getInt(String k,int fallback){Object v=values.get(k);return v==null?fallback:(Integer)v;} public Set<String> keySet(){return values.keySet();}}''',
 'android/app/Activity.java': '''package android.app; import android.os.Bundle; import android.view.View; import android.content.res.Resources; public class Activity { protected void onCreate(Bundle b){} protected void onSaveInstanceState(Bundle b){} protected void onDestroy(){} public void setContentView(View v){} public Resources getResources(){return new Resources();} public void runOnUiThread(Runnable r){r.run();}}''',
 'android/content/res/Resources.java': '''package android.content.res; public class Resources { public static class DisplayMetrics { public float density=1; } public DisplayMetrics getDisplayMetrics(){return new DisplayMetrics();}}''',
 'android/view/View.java': '''package android.view; public class View { public interface OnClickListener { void onClick(View v); } public void setLayoutParams(Object p){} public void setOnClickListener(OnClickListener c){} public boolean post(Runnable r){r.run();return true;}}''',
 'android/view/ViewGroup.java': '''package android.view; public class ViewGroup extends View { public static class LayoutParams { public static final int MATCH_PARENT=-1,WRAP_CONTENT=-2; public LayoutParams(int w,int h){} }}''',
 'android/text/InputType.java': '''package android.text; public class InputType { public static final int TYPE_CLASS_TEXT=1,TYPE_TEXT_FLAG_MULTI_LINE=2;}''',
 'android/text/InputFilter.java': '''package android.text; public interface InputFilter { public static class LengthFilter implements InputFilter { public LengthFilter(int n){} }}''',
 'android/widget/TextView.java': '''package android.widget; import android.view.View; import android.app.Activity; public class TextView extends View { protected String text=""; public TextView(Activity a){} public synchronized CharSequence getText(){return text;} public synchronized void setText(CharSequence s){text=s.toString();} public synchronized void append(CharSequence s){text+=s.toString();} public void setTextIsSelectable(boolean b){} }''',
 'android/widget/EditText.java': '''package android.widget; import android.app.Activity; import android.text.InputFilter; public class EditText extends TextView { public EditText(Activity a){super(a);} public void setHint(int h){} public void setMinLines(int n){} public void setInputType(int n){} public void setFilters(InputFilter[] f){} }''',
 'android/widget/Button.java': '''package android.widget; import android.app.Activity; public class Button extends TextView { public Button(Activity a){super(a);} public void setText(int n){} public void setAllCaps(boolean b){} }''',
 'android/widget/LinearLayout.java': '''package android.widget; import android.view.*; import android.app.Activity; public class LinearLayout extends ViewGroup { public static final int VERTICAL=1,HORIZONTAL=0; public LinearLayout(Activity a){} public void setOrientation(int o){} public void setPadding(int l,int t,int r,int b){} public void addView(View v){} public void addView(View v,LayoutParams p){} public static class LayoutParams extends ViewGroup.LayoutParams { public LayoutParams(int w,int h){super(w,h);} public LayoutParams(int w,int h,int weight){super(w,h);} } }''',
 'android/widget/ScrollView.java': '''package android.widget; import android.view.*; import android.app.Activity; public class ScrollView extends ViewGroup { private int y; public ScrollView(Activity a){} public void addView(View v,LayoutParams p){} public int getScrollY(){return y;} public void scrollTo(int x,int y){this.y=y;} public static class LayoutParams extends ViewGroup.LayoutParams { public LayoutParams(int w,int h){super(w,h);} }}''',
 'org/trillionnium/owneropen/R.java': '''package org.trillionnium.owneropen; public final class R { public static final class string { public static final int prompt_hint=1,send=2,cancel=3,inspect=4,reconnect=5; }}''',
 'org/trillionnium/owneropen/OwnerOpenClient.java': '''package org.trillionnium.owneropen; import java.util.*; public class OwnerOpenClient { public interface Listener { void onFrame(String r); void onDisconnected(String r); } public static final List<String> events=Collections.synchronizedList(new ArrayList<>()); private boolean connected; public OwnerOpenClient(Listener l){} public void connect(){connected=true;events.add("connect");} public boolean isConnected(){return connected;} public String startTurn(String s,String t,String u,String p){events.add("start:"+s+":"+t+":"+u);return "request-start";} public String cancelTurn(String s,String u){events.add("cancel:"+s+":"+u);return "request-cancel";} public String inspectTurn(String s,String t,String u,long c){events.add("inspect:"+s+":"+t+":"+u);return "request-inspect";} public void shutdown(){connected=false;events.add("shutdown");}}''',
}

# Android mechanics are stubs; the actual Activity methods below are compiled.
STUBS['android/R.java'] = "package android; public final class R { public static final class string { public static final int cancel=1; }}"
STUBS['android/content/SharedPreferences.java'] = r'''package android.content; import java.util.*;
public final class SharedPreferences {
 private static final Map<String,String> values=new HashMap<>();
 static {values.put("owneropen.emergency","armed");}
 public static boolean readFail,missing,commitFail,blockCommit;
 public static final java.util.concurrent.CountDownLatch commitEntered=new java.util.concurrent.CountDownLatch(1),commitRelease=new java.util.concurrent.CountDownLatch(1);
 public String getString(String k,String fallback){if(readFail)throw new IllegalStateException("unreadable storage");return missing?fallback:values.getOrDefault(k,fallback);}
 public Editor edit(){return new Editor();}
 public static final class Editor { private String key,value; public Editor putString(String k,String v){key=k;value=v;return this;} public boolean commit(){if(blockCommit){commitEntered.countDown();try{commitRelease.await();}catch(InterruptedException e){throw new IllegalStateException(e);}}if(commitFail)return false;values.put(key,value);missing=false;return true;} }
}'''
STUBS['android/app/Activity.java'] = STUBS['android/app/Activity.java'].replace('public class Activity {', 'public class Activity { public static final int MODE_PRIVATE=0; private boolean destroyed; public boolean isDestroyed(){return destroyed;} public android.content.SharedPreferences getSharedPreferences(String name,int mode){return new android.content.SharedPreferences();}')
STUBS['android/app/Activity.java'] = STUBS['android/app/Activity.java'].replace('protected void onDestroy(){}','protected void onDestroy(){destroyed=true;}')
STUBS['android/app/Activity.java'] = STUBS['android/app/Activity.java'].replace('public void runOnUiThread(Runnable r){r.run();}', 'public static boolean gateUi; public static final java.util.concurrent.ConcurrentLinkedQueue<Runnable> uiPosts=new java.util.concurrent.ConcurrentLinkedQueue<>(); public void runOnUiThread(Runnable r){if(gateUi)uiPosts.add(r);else r.run();}')
STUBS['android/app/AlertDialog.java'] = r'''package android.app;
public final class AlertDialog { public static Click positive; public interface Click { void onClick(Object d,int w); }
 public static final class Builder { public Builder(Activity a){} public Builder setTitle(int n){return this;} public Builder setMessage(int n){return this;} public Builder setNegativeButton(int n,Click c){return this;} public Builder setPositiveButton(int n,Click c){positive=c;return this;} public void show(){} }
}'''
STUBS['org/trillionnium/owneropen/R.java'] = STUBS['org/trillionnium/owneropen/R.java'].replace('reconnect=5;', 'reconnect=5,emergency_stop=6,emergency_status=7,emergency_confirm=8,initialize_control=9,initialize_confirm=10,emergency_retry_confirm=11;')
STUBS['org/trillionnium/owneropen/OwnerOpenClient.java'] = r'''package org.trillionnium.owneropen;
import java.util.*; import java.util.concurrent.*; import java.io.IOException;
public class OwnerOpenClient {
 public interface Listener { void onFrame(String r); void onDisconnected(String r); }
 public static final List<String> events=Collections.synchronizedList(new ArrayList<>());
 public static volatile boolean blockConnect; public static final CountDownLatch connectEntered=new CountDownLatch(1),connectRelease=new CountDownLatch(1);
 private boolean connected; private volatile boolean inhibited;
 public OwnerOpenClient(Listener l){}
 public void connect() throws IOException { if(blockConnect){connectEntered.countDown();try{connectRelease.await();}catch(InterruptedException e){throw new IOException(e);}}connected=true;events.add("connect"); }
 public boolean isConnected(){return connected;}
 public void inhibitLocally(){inhibited=true;}
 public String emergencyControl(String operation,boolean stop){events.add((stop?"stop:":"status:")+operation);if(stop)return "emergency.result outcome unknown";return "{\"automatic_redispatch\":false,\"dispatch_inhibited\":false,\"durable_inhibit_confirmed\":false,\"inhibit_observation\":\"absent\",\"kind\":\"emergency.result\",\"operation_id\":\""+operation+"\",\"prior_effect_outcome\":\"unknown\",\"process_quiescence\":\"unknown\",\"request_attempt\":\"status_only\",\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\",\"stop_requested\":false,\"version\":1}";}
 public String startTurn(String s,String t,String u,String p)throws IOException{if(inhibited)throw new IOException("inhibited");events.add("start:"+s+":"+t+":"+u);return "request-start";}
 public String cancelTurn(String s,String u){events.add("cancel:"+s+":"+u);return "request-cancel";}
 public String inspectTurn(String s,String t,String u,long c){events.add("inspect:"+s+":"+t+":"+u);return "request-inspect";}
 public void shutdown(){connected=false;events.add("shutdown");}
}'''

# Actual app-private file operations use a per-scenario temporary directory.
STUBS['android/app/Activity.java'] = STUBS['android/app/Activity.java'].replace('public static final int MODE_PRIVATE=0;', 'public static final int MODE_PRIVATE=0; public static boolean blockIdentityDirectory; public static final java.util.concurrent.CountDownLatch identityEntered=new java.util.concurrent.CountDownLatch(1),identityRelease=new java.util.concurrent.CountDownLatch(1); public java.io.File getFilesDir(){if(blockIdentityDirectory){identityEntered.countDown();boolean ready=false;while(!ready){try{identityRelease.await();ready=true;}catch(InterruptedException ignored){}}}return new java.io.File(System.getProperty("owneropen.test.files"));}')
STUBS['org/trillionnium/owneropen/OwnerOpenClient.java'] = STUBS['org/trillionnium/owneropen/OwnerOpenClient.java'].replace('public OwnerOpenClient(Listener l){}', 'private final Listener listener; public static boolean wrongAccepted,moreInspection; public static String terminalStatus="completed"; public static boolean deferInspectResponse; public static volatile String deferredInspection; public OwnerOpenClient(Listener l){listener=l;}')
STUBS['org/trillionnium/owneropen/OwnerOpenClient.java'] = STUBS['org/trillionnium/owneropen/OwnerOpenClient.java'].replace('events.add("start:"+s+":"+t+":"+u);return "request-start";', r'''
  java.nio.file.Path dir=java.nio.file.Path.of(System.getProperty("owneropen.test.files"));
  OwnerOpenClientState actual=new OwnerOpenClientStateStore(dir).load().orElseThrow().state;
  String digest=OwnerOpenFrame.turnRequestSha256(s,t,u,p);
  if(!s.equals(actual.sessionId)||!t.equals(actual.taskId)||!u.equals(actual.turnId)||!digest.equals(actual.turnRequestSha256))throw new AssertionError("effect write preceded durable exact identity");
  java.nio.file.Files.writeString(dir.resolve("fixture-host-accepted-"+u),digest);
  events.add("start:"+s+":"+t+":"+u);
  listener.onFrame(envelope("turn.accepted",s,t,u,"{\"status\":\"accepted\",\"turn_request_sha256\":"+OwnerOpenFrame.quote(wrongAccepted?"b".repeat(64):digest)+"}"));
  return "request-start";
''')
STUBS['org/trillionnium/owneropen/OwnerOpenClient.java'] = STUBS['org/trillionnium/owneropen/OwnerOpenClient.java'].replace('public void shutdown(){', r'''
 public static String event(String kind,String s,String t,String u,String payload) {
  String stream=OwnerOpenFrame.turnStreamId(s,t,u);int sequence=kind.equals("turn.end")?1:0;
  return "{\"direction\":\"host_to_client\",\"stream_id\":"+OwnerOpenFrame.quote(stream)+",\"turn_stream_id\":"+OwnerOpenFrame.quote(stream)+",\"event_id\":"+OwnerOpenFrame.quote("fixture-event-"+sequence)+",\"seq\":"+sequence+",\"host_seq\":"+sequence+",\"broker_request_id\":\"request-inspect\",\"broker_request_sha256\":"+OwnerOpenFrame.quote("c".repeat(64))+",\"broker_request_upstream_seq\":7,\"kind\":"+OwnerOpenFrame.quote(kind)+",\"profile_id\":\"owner-open\",\"session_id\":"+OwnerOpenFrame.quote(s)+",\"task_id\":"+OwnerOpenFrame.quote(t)+",\"turn_id\":"+OwnerOpenFrame.quote(u)+",\"payload\":"+payload+"}";
 }
 public static String envelope(String kind,String s,String t,String u,String payload) {
  return "{\"schema\":\"org.trillionnium.owner-open.connection-broker-wire.v1\",\"kind\":\"result\",\"request_id\":\"request-inspect\",\"broker_request_id\":\"request-inspect\",\"automatic_redispatch\":false,\"broker_request_sha256\":"+OwnerOpenFrame.quote("c".repeat(64))+",\"broker_request_upstream_seq\":7,\"broker_request_kind\":"+OwnerOpenFrame.quote(kind.equals("turn.accepted")?"turn.start":"turn.inspect")+",\"frame\":"+event(kind,s,t,u,payload)+"}";
 }
 public String inspectTurn(String s,String t,String u,String digest,long c)throws IOException {
  if(c!=0)throw new AssertionError("invented cursor namespace");
  java.nio.file.Path marker=java.nio.file.Path.of(System.getProperty("owneropen.test.files")).resolve("fixture-host-accepted-"+u);
  boolean found=java.nio.file.Files.exists(marker);
  if(found&&!java.nio.file.Files.readString(marker).equals(digest))throw new AssertionError("Inspect changed original semantic request");
  String accepted=event("turn.accepted",s,t,u,"{\"status\":\"accepted\",\"turn_request_sha256\":"+OwnerOpenFrame.quote(digest)+"}");
  String terminal=event("turn.end",s,t,u,"{\"status\":"+OwnerOpenFrame.quote(terminalStatus)+",\"turn_request_sha256\":"+OwnerOpenFrame.quote(digest)+"}");
  String payload="{\"status\":"+OwnerOpenFrame.quote(found?"found":"not_found")+",\"source\":\"durable_event_store\",\"request_sha256\":"+OwnerOpenFrame.quote(digest)+",\"turn_request_sha256\":"+OwnerOpenFrame.quote(digest)+",\"inclusive_cursor\":0,\"next_cursor\":"+(found?2:0)+",\"total_events\":"+(found?(moreInspection?3:2):0)+",\"complete\":"+found+",\"has_more\":"+moreInspection+",\"frames\":["+(found?accepted+","+terminal:"")+"],\"side_effects\":false,\"automatic_redispatch\":false}";
  events.add("inspect:"+s+":"+t+":"+u);String response=envelope("turn.inspect.result",s,t,u,payload);if(deferInspectResponse)deferredInspection=response;else listener.onFrame(response);return "request-inspect";
 }
 public String inspectTurn(String s,String t,String u,String digest,long c,java.util.function.Consumer<String> beforeWrite)throws IOException {beforeWrite.accept("request-inspect");return inspectTurn(s,t,u,digest,c);}
 public void shutdown(){
''')
STUBS['org/trillionnium/owneropen/StoreFaultFactory.java'] = r'''package org.trillionnium.owneropen;
import java.nio.file.*; import java.io.IOException;
public final class StoreFaultFactory {
 public static OwnerOpenClientStateStore create(Path directory,String cut)throws IOException {
  return new OwnerOpenClientStateStore(directory,new OwnerOpenClientStateStore.CommitHook(){
   public void afterFileSync()throws IOException {if(cut.equals("pre-rename"))throw new IOException("injected before atomic move");}
   public void atomicMove(Path pending,Path committed)throws IOException {
    if(!cut.equals("move-before"))Files.move(pending,committed,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
    if(cut.startsWith("move-"))throw new IOException("injected unknown namespace outcome");
   }
   public void afterAtomicRename()throws IOException {if(cut.equals("post-rename"))throw new IOException("injected after atomic move");}
  });
 }
}'''

HARNESS = r'''
import android.os.Bundle;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.ScrollView;
import java.lang.reflect.*;
import java.util.*;
import org.trillionnium.owneropen.*;
public final class ShellStateHarness {
 static void require(boolean b,String m){if(!b)throw new AssertionError(m);}
 static Object field(Object a,String n)throws Exception{Field f=a.getClass().getDeclaredField(n);f.setAccessible(true);return f.get(a);}
 static void call(Object a,String n,Class<?>[] types,Object... args)throws Exception{Method m=a.getClass().getDeclaredMethod(n,types);m.setAccessible(true);m.invoke(a,args);}
 static void call(Object a,String n)throws Exception{call(a,n,new Class<?>[0]);}
 static void waitFor(String prefix)throws Exception{long end=System.nanoTime()+3000000000L;while(System.nanoTime()<end){synchronized(OwnerOpenClient.events){for(String e:OwnerOpenClient.events)if(e.startsWith(prefix))return;}Thread.sleep(5);}throw new AssertionError("missing "+prefix+": "+OwnerOpenClient.events);}
 public static void main(String[] args)throws Exception {
  if(args[0].startsWith("unavailable-")) {
   android.content.SharedPreferences.missing=args[0].equals("unavailable-missing")||args[0].equals("unavailable-post-race")||args[0].equals("unavailable-init-rotation");
   android.content.SharedPreferences.readFail=args[0].equals("unavailable-read-failure");
   OwnerOpenShellActivity unavailable=new OwnerOpenShellActivity();
   try {
    call(unavailable,"onCreate",new Class<?>[]{Bundle.class},(Object)null);Thread.sleep(100);
    require(OwnerOpenClient.events.isEmpty(),"unavailable state auto-connected");
    ((EditText)field(unavailable,"prompt")).setText("effect");call(unavailable,"sendPrompt");call(unavailable,"reconnect");Thread.sleep(100);
    require(OwnerOpenClient.events.isEmpty(),"unavailable state admitted dispatch");
    android.content.SharedPreferences.readFail=false;
    call(unavailable,"confirmInitializeControl");Thread.sleep(50);
    require(OwnerOpenClient.events.isEmpty(),"opening initialization had side effects");
    if(args[0].equals("unavailable-init-rotation"))android.content.SharedPreferences.blockCommit=true;
    if(args[0].equals("unavailable-post-race"))android.app.Activity.gateUi=true;
    android.app.AlertDialog.positive.onClick(null,1);waitFor("status:");
    if(args[0].equals("unavailable-init-rotation")) {
     require(android.content.SharedPreferences.commitEntered.await(2,java.util.concurrent.TimeUnit.SECONDS),"initialization commit not pending");
     call(unavailable,"onDestroy");OwnerOpenClient.events.clear();
     OwnerOpenShellActivity folded=new OwnerOpenShellActivity();
     try {
      call(folded,"onCreate",new Class<?>[]{Bundle.class},(Object)null);
      Bundle foldingState=new Bundle();call(folded,"onSaveInstanceState",new Class<?>[]{Bundle.class},foldingState);
      require(!foldingState.getString("owneropen.emergency").startsWith("state-initializing-"),"temporary initialization token persisted as Stop");
      android.content.SharedPreferences.commitRelease.countDown();
      long until=System.nanoTime()+3_000_000_000L;while(!"armed".equals(new android.content.SharedPreferences().getString("owneropen.emergency",null))&&System.nanoTime()<until)Thread.sleep(5);
      Thread.sleep(100);require(OwnerOpenClient.events.isEmpty(),"rotation automatically connected or sent");
      call(folded,"confirmInitializeControl");
      require(field(folded,"emergencyOperationId")==null,"explicit refresh of committed initialization failed");
      require(OwnerOpenClient.events.stream().noneMatch(e->e.equals("connect")||e.startsWith("start:")),"refresh auto-dispatched");
      call(folded,"reconnect");waitFor("connect");
     } finally {call(folded,"onDestroy");}
     System.out.println(args[0]+" PASS");return;
    }
    if(args[0].equals("unavailable-post-race")) {
     long until=System.nanoTime()+3_000_000_000L;while((!"armed".equals(new android.content.SharedPreferences().getString("owneropen.emergency",null))||android.app.Activity.uiPosts.isEmpty())&&System.nanoTime()<until)Thread.sleep(5);
     require(!android.app.Activity.uiPosts.isEmpty(),"initialization callback not pending");
     call(unavailable,"confirmEmergencyStop");android.app.AlertDialog.positive.onClick(null,1);waitFor("stop:");
     String operation=(String)field(unavailable,"emergencyOperationId");Object stoppedClient=field(unavailable,"client");
     android.app.Activity.gateUi=false;Runnable post;while((post=android.app.Activity.uiPosts.poll())!=null)post.run();
     require(operation.equals(field(unavailable,"emergencyOperationId")),"old initialization erased stop identity");
     require(stoppedClient==field(unavailable,"client"),"old initialization replaced fenced client");
     require(!((TextView)field(unavailable,"transcript")).getText().toString().contains("new turns allowed"),"old initialization published success after stop");
     call(unavailable,"emergencyStatus");waitFor("status:"+operation);
     System.out.println(args[0]+" PASS");return;
    }
    long until=System.nanoTime()+3_000_000_000L;while(field(unavailable,"emergencyOperationId")!=null&&System.nanoTime()<until)Thread.sleep(5);
    require(field(unavailable,"emergencyOperationId")==null,"explicit verified initialization failed");
    require(OwnerOpenClient.events.stream().noneMatch(e->e.startsWith("connect")||e.startsWith("start:")||e.startsWith("stop:")),"initialization automatically dispatched");
   } finally {call(unavailable,"onDestroy");}
   System.out.println(args[0]+" PASS");return;
  }
  OwnerOpenShellActivity a=new OwnerOpenShellActivity();
  call(a,"onCreate",new Class<?>[]{Bundle.class},(Object)null);
  long identityUntil=System.nanoTime()+3_000_000_000L;while(!(Boolean)field(a,"identityReady")&&System.nanoTime()<identityUntil)Thread.sleep(5);
  require((Boolean)field(a,"identityReady"),"actual identity worker did not finish");
  require(OwnerOpenClient.events.isEmpty(),"identity initialization connected automatically");
  call(a,"reconnect");waitFor("connect");
  String session=(String)field(a,"sessionId"),task=(String)field(a,"taskId");
  ((EditText)field(a,"prompt")).setText("one reversible effect");call(a,"sendPrompt");waitFor("start:");
  String turn=(String)field(a,"turnId");
  ((EditText)field(a,"prompt")).setText("unsent draft survives folding");
  a.onDisconnected("result delivery lost; outcome unknown");
  ((ScrollView)field(a,"scroll")).scrollTo(0,17);
  if(args[0].equals("bounded-history"))((TextView)field(a,"transcript")).setText("x".repeat(30000)+"tail evidence");
  Bundle saved=new Bundle();call(a,"onSaveInstanceState",new Class<?>[]{Bundle.class},saved);call(a,"onDestroy");
  Set<String> allowed=new HashSet<>(Arrays.asList("owneropen.session","owneropen.task","owneropen.turn","owneropen.prompt","owneropen.transcript","owneropen.scroll"));
  require(saved.keySet().equals(allowed),"saved credential or transport object: "+saved.keySet());
  require(saved.getString("owneropen.transcript").length()<17000,"saved history is not bounded");
  OwnerOpenClient.events.clear();
  OwnerOpenShellActivity restored=new OwnerOpenShellActivity();
  try {
   call(restored,"onCreate",new Class<?>[]{Bundle.class},saved);Thread.sleep(100);
   require(OwnerOpenClient.events.isEmpty(),"recreation silently reconnected or re-dispatched: "+OwnerOpenClient.events);
   require(session.equals(field(restored,"sessionId"))&&task.equals(field(restored,"taskId"))&&turn.equals(field(restored,"turnId")),"semantic identity changed");
   require(((EditText)field(restored,"prompt")).getText().toString().equals("unsent draft survives folding"),"draft lost");
   require(((ScrollView)field(restored,"scroll")).getScrollY()==17,"display scroll lost");
   String text=((TextView)field(restored,"transcript")).getText().toString();
   require(text.contains("explicit Inspect or Reconnect")&&text.contains("No saved turn was sent again"),"uncertainty coordination notice lost");
   if(args[0].equals("bounded-history")){require(text.contains("tail evidence"),"recent history lost");}
   else {require(text.contains("outcome unknown"),"unknown history lost");}
   if(args[0].startsWith("emergency-")) {
    if(args[0].equals("emergency-priority-fence")) {
     OwnerOpenClient.blockConnect=true;
     call(restored,"inspectTurn");
     ((EditText)field(restored,"prompt")).setText("queued effect");call(restored,"sendPrompt");
     require(OwnerOpenClient.connectEntered.await(2,java.util.concurrent.TimeUnit.SECONDS),"normal connect did not block");
    }
    java.util.concurrent.CountDownLatch controlRelease=new java.util.concurrent.CountDownLatch(1);
    if(args[0].equals("emergency-confirm-destroy")) {
     java.util.concurrent.ExecutorService queue=(java.util.concurrent.ExecutorService)field(restored,"STOP_OPERATIONS");
     queue.execute(()->{try{controlRelease.await();}catch(InterruptedException error){throw new RuntimeException(error);}});
    }
    if(args[0].equals("emergency-control-priority")) {
     java.util.concurrent.ExecutorService statusQueue=(java.util.concurrent.ExecutorService)field(restored,"EMERGENCY_OPERATIONS");
     statusQueue.execute(()->{try{controlRelease.await();}catch(InterruptedException e){throw new RuntimeException(e);}});
     statusQueue.execute(()->{}); // Status channel is full, not the stop channel.
    }
    if(args[0].equals("emergency-slow-persistence")) android.content.SharedPreferences.blockCommit=true;
    if(args[0].equals("emergency-persistence-failure-restart")) android.content.SharedPreferences.commitFail=true;
    call(restored,"confirmEmergencyStop");Thread.sleep(50);
    require(OwnerOpenClient.events.stream().noneMatch(e->e.startsWith("stop:")),"opening confirmation already stopped");
    android.app.AlertDialog.positive.onClick(null,1);
    if(args[0].equals("emergency-confirm-destroy")){call(restored,"onDestroy");controlRelease.countDown();}
    waitFor("stop:");
    if(args[0].equals("emergency-control-priority")) controlRelease.countDown();
    if(args[0].equals("emergency-slow-persistence")) {
     require(android.content.SharedPreferences.commitEntered.await(2,java.util.concurrent.TimeUnit.SECONDS),"prefs were not slow");
     require(OwnerOpenClient.events.stream().filter(e->e.startsWith("stop:")).count()==1,"storage delayed or repeated stop");
     android.content.SharedPreferences.commitRelease.countDown();
    }
    String operation=(String)field(restored,"emergencyOperationId");
    if(args[0].equals("emergency-priority-fence")) {
     OwnerOpenClient.connectRelease.countDown();Thread.sleep(100);
     require(OwnerOpenClient.events.stream().noneMatch(e->e.startsWith("start:")),"queued effect crossed local emergency fence");
    }
    call(restored,"emergencyStatus");waitFor("status:");
    require(OwnerOpenClient.events.stream().filter(e->e.startsWith("stop:")).count()==1,"second press retried stop");
    if(args[0].equals("emergency-manual-retry")) {
     call(restored,"confirmEmergencyStop");Thread.sleep(50);
     require(OwnerOpenClient.events.stream().filter(e->e.startsWith("stop:")).count()==1,"retry started before confirmation");
     android.app.AlertDialog.positive.onClick(null,1);
     long until=System.nanoTime()+3_000_000_000L;while(OwnerOpenClient.events.stream().filter(e->e.startsWith("stop:")).count()!=2&&System.nanoTime()<until)Thread.sleep(5);
     String second=(String)field(restored,"emergencyOperationId");require(!operation.equals(second),"manual stop reused prior operation");operation=second;
    }
    Bundle afterStop=new Bundle();call(restored,"onSaveInstanceState",new Class<?>[]{Bundle.class},afterStop);
    require(afterStop.getString("owneropen.emergency").equals(operation),"emergency identity lost on folding");
    require(afterStop.keySet().size()==7,"secret or socket persisted with emergency intent");
    call(restored,"onDestroy");OwnerOpenClient.events.clear();
    if(args[0].equals("emergency-persistence-failure-restart")) {
     long until=System.nanoTime()+3_000_000_000L;
     while(!((TextView)field(restored,"transcript")).getText().toString().contains("durable local emergency intent=false")&&System.nanoTime()<until)Thread.sleep(5);
     require(((TextView)field(restored,"transcript")).getText().toString().contains("durable local emergency intent=false"),"commit failure evidence absent");
     require("armed".equals(new android.content.SharedPreferences().getString("owneropen.emergency",null)),"failed commit changed old durable state");
     java.lang.reflect.Field process=OwnerOpenShellActivity.class.getDeclaredField("processIntent");process.setAccessible(true);process.set(null,null);
     OwnerOpenShellActivity relaunched=new OwnerOpenShellActivity();
     try {
      call(relaunched,"onCreate",new Class<?>[]{Bundle.class},(Object)null);Thread.sleep(100);
      require(OwnerOpenClient.events.isEmpty(),"durable identity restoration automatically connected");
      call(relaunched,"reconnect");waitFor("connect");
      require(field(relaunched,"emergencyOperationId")==null,"fixture hid old armed preference");
      require(OwnerOpenClient.events.stream().noneMatch(e->e.startsWith("stop:")||e.startsWith("start:")),"failed commit caused saved request replay");
     } finally {call(relaunched,"onDestroy");}
     System.out.println(args[0]+" PASS; demonstrated limitation: old armed prefs can survive failed Stop commit and process death; no cross-process local inhibit guarantee");return;
    }
    long persistUntil=System.nanoTime()+3_000_000_000L;
    while(!operation.equals(new android.content.SharedPreferences().getString("owneropen.emergency",null))&&System.nanoTime()<persistUntil)Thread.sleep(5);
    require(operation.equals(new android.content.SharedPreferences().getString("owneropen.emergency",null)),"local intent not durably saved");
    java.lang.reflect.Field process=OwnerOpenShellActivity.class.getDeclaredField("processIntent");process.setAccessible(true);process.set(null,null);
    OwnerOpenShellActivity relaunched=new OwnerOpenShellActivity();
    try {
     call(relaunched,"onCreate",new Class<?>[]{Bundle.class},(Object)null);Thread.sleep(100);
     require(OwnerOpenClient.events.isEmpty(),"new process launch reconnected or retried stop");
     require(operation.equals(field(relaunched,"emergencyOperationId")),"persisted intent lost on process restart");
     ((EditText)field(relaunched,"prompt")).setText("new effect");call(relaunched,"sendPrompt");call(relaunched,"reconnect");call(relaunched,"inspectTurn");call(relaunched,"cancelTurn");Thread.sleep(100);
     require(OwnerOpenClient.events.isEmpty(),"latched UI admitted a normal operation");
     call(relaunched,"emergencyStatus");waitFor("status:"+operation);
     require(OwnerOpenClient.events.stream().noneMatch(e->e.startsWith("stop:")),"status retried stop");
    } finally {call(relaunched,"onDestroy");}
   } else if(args[0].equals("inspect-cancel")) {
    call(restored,"inspectTurn");waitFor("inspect:"+session+":"+task+":"+turn);
    call(restored,"cancelTurn");waitFor("cancel:"+session+":"+turn);
    require(OwnerOpenClient.events.stream().noneMatch(e->e.startsWith("start:")),"inspect/cancel replays an effect");
   } else if(args[0].equals("explicit-new-turn")) {
    call(restored,"reconnect");waitFor("connect");
    call(restored,"inspectTurn");waitFor("inspect:"+session+":"+task+":"+turn);
    require(OwnerOpenClient.events.stream().noneMatch(e->e.startsWith("start:")),"reconnect replays saved turn");
    ((EditText)field(restored,"prompt")).setText("new user message");call(restored,"sendPrompt");waitFor("start:");
    require(!turn.equals(field(restored,"turnId")),"new Send reused old semantic turn");
    require(session.equals(field(restored,"sessionId"))&&task.equals(field(restored,"taskId")),"new Send abandoned restored session/task");
   }
  } finally {call(restored,"onDestroy");}
  System.out.println(args[0]+" PASS; host Activity fixture only, phone untested");
 }
}'''

class OwnerOpenAndroidShellStateTest(unittest.TestCase):
 def test_actual_activity_recreation_and_explicit_coordination(self):
  javac,java=shutil.which('javac'),shutil.which('java')
  if not javac or not java:self.skipTest('JDK required for actual Activity host fixture')
  with tempfile.TemporaryDirectory() as tmp:
   folder=Path(tmp)
   for name,content in STUBS.items():
    p=folder/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content)
   (folder/'ShellStateHarness.java').write_text(HARNESS)
   classes=folder/'classes';classes.mkdir()
   run=subprocess.run([javac,'-d',str(classes),str(ACTIVITY),*[str(ACTIVITY.with_name(name+'.java')) for name in ('OwnerOpenFrame','OwnerOpenTurnEvidence','OwnerOpenClientState','OwnerOpenClientStateCodec','OwnerOpenClientStateStore')],*map(str,folder.rglob('*.java'))],capture_output=True,text=True,timeout=30)
   self.assertEqual(run.returncode,0,run.stderr)
   for scenario in ['inspect-cancel','explicit-new-turn','bounded-history','emergency-intent-restart','emergency-priority-fence','emergency-confirm-destroy','emergency-slow-persistence','emergency-persistence-failure-restart','emergency-manual-retry','emergency-control-priority','unavailable-missing','unavailable-read-failure','unavailable-post-race','unavailable-init-rotation']:
    with self.subTest(scenario=scenario):
     files=folder/('files-'+scenario);files.mkdir()
     result=subprocess.run([java,'-Downeropen.test.files='+str(files),'-cp',str(classes),'ShellStateHarness',scenario],capture_output=True,text=True,timeout=10)
     self.assertEqual(result.returncode,0,result.stderr)
     self.assertIn(scenario+' PASS',result.stdout)
     print(result.stdout,end="",flush=True)

if __name__=='__main__':unittest.main()
