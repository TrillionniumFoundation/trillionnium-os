package org.trillionnium.hepta.local;

import android.content.Context;
import android.system.Os;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Real session + durable file helper + actual engine lease; only Android/process endpoints are fakes. */
public final class BackgroundPermissionSessionHostTest {
    static final List<String> passed=new ArrayList<String>();
    interface Case {void run()throws Exception;}
    static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    static void test(String name,Case body)throws Exception{body.run();passed.add(name);System.out.println("PASS "+name);}
    static void rejects(Case body)throws Exception{try{body.run();}catch(Exception expected){return;}throw new AssertionError("must refuse");}
    static final class Child extends Process {
        final CountDownLatch terminal=new CountDownLatch(1);final AtomicLong clock;final boolean delayed;
        volatile boolean alive=true;int destroys;final byte[] stdout;
        Child(AtomicLong clock,boolean delayed,byte[] stdout){this.clock=clock;this.delayed=delayed;this.stdout=stdout;}
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public InputStream getInputStream(){return new ByteArrayInputStream(stdout);}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public int waitFor()throws InterruptedException{terminal.await();return 0;}
        public boolean waitFor(long timeout,TimeUnit unit){if(!delayed)finish();else clock.addAndGet(61000);return !alive;}
        public int exitValue(){if(alive)throw new IllegalThreadStateException();return 0;}
        public void destroy(){destroys++;if(!delayed)finish();}
        public Process destroyForcibly(){destroy();return this;}
        public boolean isAlive(){return alive;}
        void finish(){alive=false;terminal.countDown();}
    }
    static final class Env implements AutoCloseable {
        final Path root;final Context context;final LocalModelEngine model;final AtomicLong clock=new AtomicLong(1000);final AtomicInteger launches=new AtomicInteger();
        ExecutorService executor;BackgroundPermissionSession session;Child child;boolean delayed,failResultFsync,failResultDirectory;byte[] stdout="0\n".getBytes(StandardCharsets.US_ASCII);
        Env()throws Exception{LocalModelEngine.fixtureReset();LocalProbeApplication.permission=null;Os.failFsyncPath=null;android.os.Process.uid=10123;
            root=Files.createTempDirectory("hepta-permission-session-");context=new Context(root.toFile());model=new LocalModelEngine(context);}
        void make(){executor=Executors.newSingleThreadExecutor();session=new BackgroundPermissionSession(context,model,()->{launches.incrementAndGet();child=new Child(clock,delayed,stdout);if(failResultFsync||failResultDirectory){File directory=root.resolve("background-permission-runs").toFile().listFiles()[0];Os.failFsyncPath=failResultFsync?new File(directory,"result.json").getPath():directory.getPath();}return child;},clock::get,executor);LocalProbeApplication.permission=session;}
        void await(boolean blocked)throws Exception{long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);while(System.nanoTime()<end){if(blocked?session.isBlocked():!session.isRunning())return;Thread.sleep(5);}throw new AssertionError("session did not reach expected terminal");}
        void awaitExecution(boolean blocked)throws Exception{
            long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);await(blocked);
            long remaining=end-System.nanoTime();check(remaining>0,"original terminal wait bound exceeded");
            executor.submit(()->{}).get(remaining,TimeUnit.NANOSECONDS);
        }
        Map<String,Object> marker()throws Exception{return MobiMindContract.jsonObject(Files.readAllBytes(root.resolve("background-permission-session.json")));}
        void write(String name,byte[] value)throws Exception{MobiMindPrivateFiles.writeNew(root.resolve(name).toFile(),value);}
        public void close(){if(child!=null)child.finish();if(session!=null)session.close();model.close();LocalProbeApplication.permission=null;LocalModelEngine.fixtureReset();Os.failFsyncPath=null;android.os.Process.uid=10123;}
    }
    static Map<String,Object> pending(){Map<String,Object> value=new BackgroundPermissionPreparation.Request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","org.trillionnium.hepta.local",10123,10123,123,-1).evidence(1000);value.put("phase","pending");value.put("status","pending");value.put("process_started",false);value.put("process_exit_observed",false);value.put("cleanup_known",false);return value;}
    static byte[] bytes(Map<String,Object> value){return new org.json.JSONObject(value).toString().getBytes(StandardCharsets.UTF_8);}
    public static void main(String[] args)throws Exception{
        test("actual_session_reserves_shared_slot_and_durable_terminal_before_release",()->{try(Env e=new Env()){
            e.make();e.session.startFromOwnerButton();e.await(false);Map<String,Object> m=e.marker();
            check(e.launches.get()==1&&!e.model.isBusy()&&!e.session.isBlocked(),"one child, actual shared lease released");
            check(Boolean.TRUE.equals(m.get("permission_verified"))&&BackgroundPermissionPreparation.cleanTerminal(m,10123),"strict durable result");
            Path run=e.root.resolve("background-permission-runs").resolve((String)m.get("request_id"));
            check(Files.isRegularFile(run.resolve("request.json"))&&Files.isRegularFile(run.resolve("result.json")),"independent request/result files");
        }});
        test("unfinished_same_process_blocks_second_preparation_and_external_diagnostics",()->{try(Env e=new Env()){
            e.delayed=true;e.make();e.session.startFromOwnerButton();e.await(true);check(e.model.isBusy()&&e.session.isRunning(),"unknown exact Process retains slot");
            rejects(()->e.session.startFromOwnerButton());rejects(()->e.model.reserveExternal("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
            check(e.launches.get()==1,"no replay");e.child.finish();e.await(false);Map<String,Object> m=e.marker();
            check("late_process_exit".equals(m.get("status"))&&Boolean.FALSE.equals(m.get("permission_verified"))&&!e.model.isBusy(),"late actual exit releases only process, never upgrades authorization");
            check(Files.exists(e.root.resolve("background-permission-runs").resolve((String)m.get("request_id")).resolve("late-exit.json")),"late exit separately retained");
        }});
        test("historical_pending_is_unknown_not_replayed_and_explicit_retry_archives_original",()->{try(Env e=new Env()){
            byte[] prior=bytes(pending());e.write("background-permission-session.json",prior);e.write("control-session.interrupted.json","control-latch".getBytes(StandardCharsets.UTF_8));e.write("qualification-scope.json","scope".getBytes(StandardCharsets.UTF_8));
            e.make();check(e.launches.get()==0&&!e.session.isBlocked()&&e.session.state().contains("未知"),"readonly historical unknown is not resumed or called clean");
            e.session.startFromOwnerButton();e.await(false);Map<String,Object> m=e.marker();Path run=e.root.resolve("background-permission-runs").resolve((String)m.get("request_id"));
            check(Arrays.equals(prior,Files.readAllBytes(run.resolve("previous-interrupted-record.json"))),"original bytes archived before new request");
            check(new String(Files.readAllBytes(e.root.resolve("control-session.interrupted.json")),StandardCharsets.UTF_8).equals("control-latch"),"original control latch untouched");
            check(new String(Files.readAllBytes(e.root.resolve("qualification-scope.json")),StandardCharsets.UTF_8).equals("scope"),"original scope untouched");
        }});
        test("historical_success_does_not_claim_current_or_permanent_permission",()->{try(Env e=new Env()){
            e.make();e.session.startFromOwnerButton();e.await(false);e.session.close();e.make();
            check(e.launches.get()==1&&e.session.state().contains("当前授权尚未核验")&&!e.session.isRunning(),"no cached ready or automatic probe");
        }});
        for(String corrupt:new String[]{"malformed","sidecar","latch"})test("storage_ambiguity_"+corrupt,()->{try(Env e=new Env()){
            e.write("malformed".equals(corrupt)?"background-permission-session.json":"sidecar".equals(corrupt)?"background-permission-session.json.new":"background-permission-interrupted.json","{}".getBytes(StandardCharsets.UTF_8));
            e.make();check(e.session.isBlocked()&&e.model.isBusy(),"specific storage ambiguity blocks new work");rejects(()->e.session.startFromOwnerButton());check(e.launches.get()==0,"no probe");
        }});
        test("directory_fsync_failure_prevents_launch_and_retains_lease",()->{try(Env e=new Env()){
            e.make();Os.failFsyncPath=e.root.toString();e.session.startFromOwnerButton();e.await(true);
            check(e.launches.get()==0&&e.model.isBusy(),"failure before durable reservation cannot launch or fabricate release");
        }});
        for(boolean directory:new boolean[]{false,true})test("terminal_"+(directory?"directory":"file")+"_fsync_failure_cannot_release_or_claim_permission",()->{try(Env e=new Env()){
            e.failResultDirectory=directory;e.failResultFsync=!directory;e.make();e.session.startFromOwnerButton();e.awaitExecution(true);
            check(e.launches.get()==1&&!e.child.isAlive()&&e.model.isBusy()&&e.session.isBlocked(),"owned exit is known but durable terminal failed, retain lease");
            check(e.session.state().contains("未认定已授权"),"no false success UI");
        }});
        test("ordinary_application_identity_rechecked_before_slot_or_launch",()->{try(Env e=new Env()){
            e.make();e.context.installedUid=10124;rejects(()->e.session.startFromOwnerButton());check(e.launches.get()==0&&!e.model.isBusy(),"wrong installed UID cannot occupy or launch");
        }});
        test("listener_rebind_does_not_replace_process_ownership",()->{try(Env e=new Env()){
            e.delayed=true;e.make();AtomicInteger old=new AtomicInteger(),fresh=new AtomicInteger();BackgroundPermissionSession.Listener a=old::incrementAndGet,b=fresh::incrementAndGet;
            e.session.bind(a);e.session.startFromOwnerButton();e.session.bind(b);e.session.unbind(a);e.await(true);int previous=old.get();
            e.child.finish();e.await(false);check(old.get()==previous&&fresh.get()>0&&e.launches.get()==1,"new UI observes same session without re-launch");
        }});
        String result="{\"passed\":"+passed.size()+",\"failed\":0,\"actual_session_and_external_lease\":true,\"android_process_io_fake\":true,\"su_executed\":false,\"phone_tested\":false}";
        Files.write(Paths.get(args[0]),result.getBytes(StandardCharsets.UTF_8));System.out.println(result);
    }
}
