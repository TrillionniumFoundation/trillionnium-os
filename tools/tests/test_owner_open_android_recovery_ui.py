from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/client/src/org/trillionnium/owneropen"


class AndroidRecoveryUiTest(unittest.TestCase):
    def test_activity_recovery_display_bounds_and_connection_generation(self):
        compiler, java = shutil.which("javac"), shutil.which("java")
        if not compiler or not java:
            self.skipTest("JDK required for source UI recovery harness")
        # These stubs exercise app state and asynchronous ownership only. They
        # are not Android target, rendering, SELinux, or installation evidence.
        stubs = {
            "android/os/Bundle.java": "package android.os; public class Bundle {}",
            "android/text/InputType.java": "package android.text; public class InputType {public static final int TYPE_CLASS_TEXT=1, TYPE_TEXT_FLAG_MULTI_LINE=2;}",
            "android/view/View.java": "package android.view; public class View {public interface OnClickListener {void onClick(View v);}}",
            "android/view/ViewGroup.java": "package android.view; public class ViewGroup extends View {public static class LayoutParams {public static final int MATCH_PARENT=-1,WRAP_CONTENT=-2; public LayoutParams(int a,int b){}}}",
            "android/app/Activity.java": """package android.app; import java.util.*; public class Activity {
                public final Queue<Runnable> ui=new ArrayDeque<>();
                public void runOnUiThread(Runnable r){synchronized(ui){ui.add(r);}}
                public void flushUi(){while(true){Runnable r;synchronized(ui){r=ui.poll();}if(r==null)return;r.run();}}
                protected void onCreate(android.os.Bundle b){} protected void onDestroy(){} public void setContentView(Object v){}
                public Resources getResources(){return new Resources();} public static class Resources {public Metrics getDisplayMetrics(){return new Metrics();}}
                public static class Metrics {public float density=1;}}
            """,
            "android/widget/TextView.java": "package android.widget; public class TextView extends android.view.View {String text=\"\";public TextView(Object a){} public void setTextIsSelectable(boolean b){} public void setText(CharSequence s){text=s.toString();}public CharSequence getText(){return text;}}",
            "android/widget/EditText.java": "package android.widget;public class EditText extends TextView {public EditText(Object a){super(a);}public void setHint(int s){}public void setMinLines(int n){}public void setInputType(int t){}}",
            "android/widget/Button.java": "package android.widget;public class Button extends TextView {public Button(Object a){super(a);}public void setText(int s){}public void setOnClickListener(android.view.View.OnClickListener l){}public void setAllCaps(boolean b){}public void setLayoutParams(Object o){}}",
            "android/widget/LinearLayout.java": "package android.widget;public class LinearLayout extends android.view.ViewGroup {public static final int VERTICAL=1,HORIZONTAL=2;public LinearLayout(Object a){}public void setOrientation(int n){}public void setPadding(int a,int b,int c,int d){}public void addView(Object v){}public void addView(Object v,Object p){}public static class LayoutParams extends android.view.ViewGroup.LayoutParams {public LayoutParams(int a,int b){super(a,b);}public LayoutParams(int a,int b,int c){super(a,b);}}}",
            "android/widget/ScrollView.java": "package android.widget;public class ScrollView extends android.view.ViewGroup {public ScrollView(Object a){}public void addView(Object v,Object p){} public static class LayoutParams extends android.view.ViewGroup.LayoutParams {public LayoutParams(int a,int b){super(a,b);}}}",
            "android/net/LocalSocketAddress.java": "package android.net;public class LocalSocketAddress {public enum Namespace {ABSTRACT}public LocalSocketAddress(String s,Namespace n){}}",
            "android/net/LocalSocket.java": "package android.net;import java.io.*;public class LocalSocket {public void connect(LocalSocketAddress a)throws IOException{}public InputStream getInputStream()throws IOException{return new ByteArrayInputStream(new byte[0]);}public OutputStream getOutputStream()throws IOException{return new ByteArrayOutputStream();}public void close()throws IOException{}}",
            "org/json/JSONObject.java": """package org.json;import java.util.*;public class JSONObject {
                public static final Object NULL=new Object();public static final Map<String,Map<String,Object>> fixtures=new HashMap<>();
                final Map<String,Object> values;public JSONObject(String s){values=fixtures.get(s);if(values==null)throw new IllegalArgumentException();}
                public JSONObject(Map<String,Object> m){values=m;} public String optString(String k){return String.valueOf(values.get(k));}
                public Object get(String k){Object v=values.get(k);if(v==null)return NULL;if(v instanceof Map)return new JSONObject((Map)v);if(v instanceof List)return new JSONArray((List)v);return v;}
                public JSONObject getJSONObject(String k){return (JSONObject)get(k);}public Iterator<String> keys(){return values.keySet().iterator();}}
            """,
            "org/json/JSONArray.java": "package org.json;import java.util.*;public class JSONArray {final List<?> values;public JSONArray(List<?> v){values=v;}public int length(){return values.size();}public Object get(int i){Object v=values.get(i);if(v instanceof Map)return new JSONObject((Map)v);if(v instanceof List)return new JSONArray((List)v);return v==null?JSONObject.NULL:v;}}",
            "org/trillionnium/owneropen/R.java": "package org.trillionnium.owneropen;public class R {public static class string {public static final int prompt_hint=1,send=2,cancel=3,inspect=4,reconnect=5,recover_output=6;}}",
        }
        harness = textwrap.dedent(r'''
            import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
            import java.io.*;import java.lang.reflect.*;import org.trillionnium.owneropen.*;
            import android.widget.TextView;import org.json.JSONObject;
            public class UiHarness {
                static void put(Object o,String n,Object v)throws Exception {Field f=o.getClass().getDeclaredField(n);f.setAccessible(true);f.set(o,v);}
                static Object get(Object o,String n)throws Exception {Field f=o.getClass().getDeclaredField(n);f.setAccessible(true);return f.get(o);}
                static Object call(Object o,String n,Class<?>[] types,Object... args)throws Exception {Method m=o.getClass().getDeclaredMethod(n,types);m.setAccessible(true);return m.invoke(o,args);}
                static void check(boolean b){if(!b)throw new AssertionError("UI recovery assertion failed");}
                static ExecutorService executor(OwnerOpenShellActivity a)throws Exception{return (ExecutorService)get(a,"operations");}
                static void barrier(OwnerOpenShellActivity a)throws Exception {long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(true){try{executor(a).submit(()->{}).get(2,TimeUnit.SECONDS);return;}catch(RejectedExecutionException full){if(System.nanoTime()>end)throw full;Thread.sleep(5);}}}
                static void await(ByteArrayOutputStream out,String value)throws Exception {long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(!out.toString("UTF-8").contains(value)){if(System.nanoTime()>end)throw new AssertionError(out.toString());Thread.sleep(5);}}
                static Map<String,Object> scope(OwnerOpenShellActivity a)throws Exception{return new LinkedHashMap<>(Map.of("session_id",get(a,"sessionId"),"profile_id","owner-open","task_id",get(a,"taskId"),"turn_id","turn","turn_stream_id","stream"));}
                static OwnerOpenShellActivity activity()throws Exception {OwnerOpenShellActivity a=new OwnerOpenShellActivity();put(a,"transcript",new TextView(a));put(a,"turnId","turn");put(a,"acceptedScope",scope(a));put(a,"acceptedDigest","a".repeat(64));return a;}
                static Map<String,Object> frame(OwnerOpenShellActivity a,String kind,Map<String,Object> p)throws Exception{Map<String,Object> f=scope(a);f.put("kind",kind);f.put("payload",p);return f;}
                static void close(OwnerOpenShellActivity a)throws Exception {call(a,"onDestroy",new Class[]{});}
                public static void main(String[] ignored)throws Exception {try {
                    OwnerOpenShellActivity a=activity();OwnerOpenClient client=new OwnerOpenClient(a);
                    ByteArrayOutputStream out=new ByteArrayOutputStream();put(client,"output",out);((AtomicBoolean)get(client,"closed")).set(false);put(a,"client",client);
                    put(a,"helloPayload",Map.of("resync_protocols",List.of("scoped_cursor_v1")));
                    Map<String,Object> gap=frame(a,"stream.resync_required",Map.of("resync_protocol","scoped_cursor_v1","cursor_scopes_complete",true,"next_control_seq",0,
                        "required_resumes",List.of(Map.of("cursor_domain","transport_event","cursor_scope",scope(a),"first_missing_cursor",0,"last_missing_cursor",0,"required_resume_cursor",1))));
                    put(a,"lastGap",gap);call(a,"recoverOutput",new Class[]{});await(out,"turn.inspect");
                    Map<String,Object> saved=frame(a,"model.delta",Map.of("text","saved output"));saved.put("event_id","stream-event-0");
                    Map<String,Object> page=frame(a,"turn.inspect.result",Map.of("status","found","source","durable_event_store","inclusive_cursor",0,"next_cursor",1,
                        "frames",List.of(saved),"side_effects",false,"automatic_redispatch",false));
                    executor(a).submit(()->{try{call(a,"handleHostFrame",new Class[]{Map.class,long.class},page,0L);}catch(Exception e){throw new RuntimeException(e);}}).get(2,TimeUnit.SECONDS);
                    check(!out.toString("UTF-8").contains("stream.resume"));a.flushUi();await(out,"stream.resume");
                    check(((TextView)get(a,"transcript")).getText().toString().contains("saved output"));
                    check(!out.toString("UTF-8").contains("turn.start"));check(!out.toString("UTF-8").contains("job.start"));
                    for(int i=0;i<50;i++)call(a,"append",new Class[]{String.class},"x".repeat(100000));
                    check(a.ui.size()<=1);check(((StringBuilder)get(a,"pendingDisplay")).length()<=65536);a.flushUi();
                    check(((TextView)get(a,"transcript")).getText().length()<=65536);
                    CountDownLatch block=new CountDownLatch(1);executor(a).execute(()->{try{block.await();}catch(Exception e){throw new RuntimeException(e);}});
                    JSONObject.fixtures.put("stale",frame(a,"model.delta",Map.of("text","OLD_CALLBACK")));
                    JSONObject.fixtures.put("fresh",frame(a,"model.delta",Map.of("text","NEW_CALLBACK")));
                    a.onFrame(1,"stale");a.onFrame(2,"fresh");block.countDown();barrier(a);a.flushUi();
                    String display=((TextView)get(a,"transcript")).getText().toString();check(!display.contains("OLD_CALLBACK"));check(display.contains("NEW_CALLBACK"));
                    close(a);a.onFrame(3,"fresh");check(a.ui.isEmpty());
                    OwnerOpenShellActivity full=activity();OwnerOpenClient owned=new OwnerOpenClient(full);put(full,"client",owned);
                    CountDownLatch stuck=new CountDownLatch(1);executor(full).execute(()->{try{stuck.await();}catch(Exception e){throw new RuntimeException(e);}});
                    for(int i=0;i<20;i++)full.onFrame(1,"stale");
                    check(((ThreadPoolExecutor)executor(full)).getQueue().size()<=16);check(((Long)get(full,"rejectedGeneration"))==1);
                    check(!owned.isConnected());stuck.countDown();barrier(full);full.flushUi();close(full);
                    System.out.println("UI recovery, bounded histories, queue overflow and stale generation PASS");
                }catch(Throwable failure){failure.printStackTrace();System.exit(1);}}
            }
        ''')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = []
            for relative, source in stubs.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
                sources.append(str(path))
            main = root / "UiHarness.java"
            main.write_text(harness)
            compiled = subprocess.run([compiler, "-d", str(root), *sources, *[str(CLIENT / name) for name in ("OwnerOpenFrame.java", "OwnerOpenClient.java", "OwnerOpenShellActivity.java")], str(main)], capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([java, "-cp", str(root), "UiHarness"], capture_output=True, text=True, timeout=15)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            self.assertIn("PASS", executed.stdout)


if __name__ == "__main__":
    unittest.main()
