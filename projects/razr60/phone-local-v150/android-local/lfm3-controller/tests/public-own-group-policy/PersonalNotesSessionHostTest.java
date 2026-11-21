package org.trillionnium.hepta.local;

import android.content.Context;
import android.net.LocalSocket;
import android.os.SystemClock;
import android.view.Display;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.json.*;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;

/** Full production close/reconcile paths with inert socket/process/display ports.
 * These host objects do not claim actual Android task or display ownership. */
public final class PersonalNotesSessionHostTest {
    static final String TASK="11111111111111111111111111111111",OWNER="打开应用",PKG="com.motorola.stylus";
    static int cases,checks;
    interface Work{void run()throws Exception;}
    static void yes(boolean value){checks++;if(!value)throw new AssertionError("Notes session boundary");}
    static void refuse(Work work)throws Exception{try{work.run();}catch(Exception expected){checks++;return;}throw new AssertionError("invalid Notes journal accepted");}
    static void test(String name,Work work)throws Exception{
        LocalSocket.reset();SystemClock.now=1000000;android.provider.Settings.Global.boot=10;
        work.run();cases++;System.out.println("PASS "+name);
    }
    static Object field(BackgroundSession session,String name,Object... value)throws Exception{
        Field field=BackgroundSession.class.getDeclaredField(name);field.setAccessible(true);
        if(value.length>0)field.set(session,value[0]);return field.get(session);
    }
    static Object call(BackgroundSession session,String name,Class<?>[] signature,Object... value)throws Exception{
        Method method=BackgroundSession.class.getDeclaredMethod(name,signature);method.setAccessible(true);return method.invoke(session,value);
    }
    static byte[] frame(JSONObject value)throws Exception{
        byte[] json=value.toString().getBytes(StandardCharsets.UTF_8);ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        DataOutputStream output=new DataOutputStream(bytes);output.writeInt(json.length);output.write(json);return bytes.toByteArray();
    }
    static JSONObject decode(byte[] bytes)throws Exception{
        DataInputStream input=new DataInputStream(new ByteArrayInputStream(bytes));int length=input.readInt();byte[] json=new byte[length];input.readFully(json);return new JSONObject(new String(json,StandardCharsets.UTF_8));
    }
    static final class Custodian extends Process {
        int destroyed;boolean exited;
        public InputStream getInputStream(){return new ByteArrayInputStream(new byte[0]);}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public int waitFor(){return 70;}
        public boolean waitFor(long timeout,TimeUnit unit){return exited;}
        public int exitValue(){if(!exited)throw new IllegalThreadStateException();return 70;}
        public void destroy(){destroyed++;}
    }
    static final class Env implements AutoCloseable {
        final Path root;final Context context;final BackgroundSession session;final PublicOwnGroupPolicy.Scope scope;
        final Custodian process=new Custodian();
        Env()throws Exception{
            root=Files.createTempDirectory("hepta-personal-notes-session-").toRealPath();context=new Context(root.toFile());
            BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(OWNER,PKG,Collections.singleton(PKG),null);
            session=BackgroundSession.experimentalPublicOwnGroup(context,TASK,OWNER,new BackgroundSession.Selection(target,false,true),new QualificationScopeConfig.FilesRoot(context));
            scope=(PublicOwnGroupPolicy.Scope)field(session,"publicOwnGroupScope");
            Display owned=new Display(7,session.displayName);owned.flags=7040;context.displays.displays.put(7,owned);
            context.displays.displays.put(0,new Display(0,"user-main"));context.displays.displays.put(1,new Display(1,"user-cover"));
            field(session,"state","ACTIVE");field(session,"displayId",7);field(session,"spawnAttempted",true);field(session,"brokerProcess",process);
            JSONObject journal=(JSONObject)call(session,"baseJournal",new Class<?>[]{});
            MobiMindPrivateFiles.writeNew(root.resolve(BackgroundSession.JOURNAL).toFile(),journal.toString().getBytes(StandardCharsets.UTF_8));
        }
        boolean journal(){return Files.exists(root.resolve(BackgroundSession.JOURNAL));}
        JSONObject reply(byte[] bytes,String state,boolean ok)throws Exception{
            JSONObject request=decode(bytes);
            return new JSONObject().put("version",3).put("request_id",request.getString("request_id"))
                    .put("generation",session.generation).put("operation",request.getString("op"))
                    .put("display_scope_sha256",scope.sha256).put("public_scope_admission_retired",true)
                    .put("public_scope_closing",true).put("ok",ok).put("state",state).put("display_id",7)
                    .put("display_name",session.displayName).put("expires_elapsed_ms",session.expiresElapsed).put("dispatched",false);
        }
        void intact(){yes(context.displays.getDisplay(0)!=null&&context.displays.getDisplay(1)!=null);}
        public void close()throws IOException{
            try(java.util.stream.Stream<Path> paths=Files.walk(root)){for(Path path:paths.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(path);}
        }
    }
    public static void main(String[] args)throws Exception{
        test("actual Notes close retains unknown custodian and journal",()->{try(Env e=new Env()){
            LocalSocket.responder=bytes->frame(e.reply(bytes,"CLEANUP_UNKNOWN",false));
            yes(!e.session.close().known&&!e.session.released());yes(e.process.destroyed==0&&e.journal());e.intact();
        }});
        test("RELEASED label and absent display alone do not retire Notes",()->{try(Env e=new Env()){
            LocalSocket.responder=bytes->{e.context.displays.displays.remove(7);return frame(e.reply(bytes,"RELEASED",true));};
            yes(!e.session.close().known);yes(e.process.destroyed==0&&e.journal());e.intact();
        }});
        test("expired missing broker and a new boot do not imply Notes recents absence",()->{try(Env e=new Env()){
            e.context.displays.displays.remove(7);LocalSocket.missing=true;e.process.exited=true;
            yes(!e.session.close().known);SystemClock.now=e.session.expiresElapsed+3000;android.provider.Settings.Global.boot=11;
            yes(!BackgroundSession.reconcile(e.context).known);yes(e.journal()&&e.process.destroyed==0);e.intact();
        }});
        for(final String mutation:new String[]{"missing","false","wrong-package"})test("actual journal parser refuses Notes scope "+mutation,()->{try(Env e=new Env()){
            JSONObject journal=new JSONObject(new String(Files.readAllBytes(e.root.resolve(BackgroundSession.JOURNAL)),StandardCharsets.UTF_8));
            if("missing".equals(mutation))journal.remove("personal_notes_retirement_required");
            else if("false".equals(mutation))journal.put("personal_notes_retirement_required",false);
            else{JSONObject selection=journal.getJSONObject("selection");selection.put("bootstrap_package","com.xiaomi.shop");journal.put("selection",selection);}
            Files.write(e.root.resolve(BackgroundSession.JOURNAL),journal.toString().getBytes(StandardCharsets.UTF_8));
            refuse(()->BackgroundSession.reconcile(e.context));yes(LocalSocket.connections==0&&e.journal());e.intact();
        }});
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+checks+",\"passed\":true,\"phone_contacted\":false}");
    }
}
