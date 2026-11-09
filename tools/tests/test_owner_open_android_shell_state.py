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
  OwnerOpenShellActivity a=new OwnerOpenShellActivity();
  call(a,"onCreate",new Class<?>[]{Bundle.class},(Object)null);waitFor("connect");
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
   if(args[0].equals("inspect-cancel")) {
    call(restored,"inspectTurn");waitFor("inspect:"+session+":"+task+":"+turn);
    call(restored,"cancelTurn");waitFor("cancel:"+session+":"+turn);
    require(OwnerOpenClient.events.stream().noneMatch(e->e.startsWith("start:")),"inspect/cancel replays an effect");
   } else if(args[0].equals("explicit-new-turn")) {
    call(restored,"reconnect");waitFor("connect");
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
   run=subprocess.run([javac,'-d',str(classes),str(ACTIVITY),*map(str,folder.rglob('*.java'))],capture_output=True,text=True,timeout=30)
   self.assertEqual(run.returncode,0,run.stderr)
   for scenario in ['inspect-cancel','explicit-new-turn','bounded-history']:
    with self.subTest(scenario=scenario):
     result=subprocess.run([java,'-cp',str(classes),'ShellStateHarness',scenario],capture_output=True,text=True,timeout=10)
     self.assertEqual(result.returncode,0,result.stderr)
     self.assertIn(scenario+' PASS',result.stdout)

if __name__=='__main__':unittest.main()
