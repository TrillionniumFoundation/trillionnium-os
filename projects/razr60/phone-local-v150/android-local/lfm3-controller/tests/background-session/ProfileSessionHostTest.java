package org.trillionnium.hepta.local;

import android.content.Context;
import android.net.LocalSocket;
import android.os.SystemClock;
import android.view.Display;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Full production client; explicit fake root transport, displays, clock and process. */
public final class ProfileSessionHostTest {
    private static final String TASK="11111111111111111111111111111111",OWNER="打开携程";
    private static final String TOKEN="33333333-3333-4333-8333-333333333333";
    private static int assertions;
    private static final List<String> cases=new ArrayList<String>();
    interface Check {void run()throws Exception;}
    static void need(boolean v){assertions++;if(!v)throw new AssertionError("profile client boundary failed");}
    static void reject(Check c)throws Exception{try{c.run();}catch(Exception expected){assertions++;return;}throw new AssertionError("invalid profile evidence admitted");}
    static void test(String name,Check c)throws Exception{LocalSocket.reset();SystemClock.now=1000000;android.provider.Settings.Global.boot=10;android.system.Os.failUnlink=false;c.run();cases.add(name);}
    static ProfileTarget target(long serial){Map<String,String> a=new LinkedHashMap<String,String>();a.put("base",String.join("",Collections.nCopies(64,"a")));return new ProfileTarget(new ProfileIdentity(10,serial,0,ProfileIdentity.MANAGED),1010367,ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.android.view.SplashActivity",1779,a,Collections.singleton(String.join("",Collections.nCopies(64,"b"))));}
    static final class Env implements AutoCloseable {
        final Path directory;final Context context;final ProfileTarget target;final BackgroundSession session;
        Env()throws Exception{
            directory=Files.createTempDirectory("hepta-profile-client-").toRealPath();context=new Context(directory.toFile());target=target(20);
            BackgroundTaskTarget chosen=BackgroundTaskTarget.resolveExplicitSelection(OWNER,target.packageName,Collections.singleton(target.packageName),target);
            session=new BackgroundSession(context,TASK,OWNER,new BackgroundSession.Selection(chosen),new QualificationScopeConfig.FilesRoot(context));
        }
        void active()throws Exception{
            context.displays.displays.put(7,new Display(7,session.displayName));
            JSONObject req=(JSONObject)BackgroundSessionHostTest.invoke(session,"request",new Class<?>[]{String.class,String.class,long.class},"state",null,SystemClock.now+3000);
            JSONObject reply=response(BackgroundSessionHostTest.frame(req.toString().getBytes(StandardCharsets.UTF_8)),"ACTIVE",true);
            BackgroundSessionHostTest.invoke(session,"accept",new Class<?>[]{JSONObject.class,boolean.class},reply,true);
        }
        JSONObject response(byte[] bytes,String state,boolean ok)throws Exception{
            JSONObject r=BackgroundSessionHostTest.decode(BackgroundSessionHostTest.response(bytes,state,7,ok,false));
            r.put("version",2).put("profile_target_wire",target.wire()).put("profile_current_identity_verified",true)
                .put("expires_elapsed_ms",session.expiresElapsed);return r;
        }
        void journal(boolean launched)throws Exception{
            BackgroundSessionHostTest.field(session,"profileLaunchAttempted",launched);
            JSONObject value=(JSONObject)BackgroundSessionHostTest.invoke(session,"baseJournal",new Class<?>[]{});
            MobiMindPrivateFiles.writeNew(directory.resolve(BackgroundSession.JOURNAL).toFile(),value.toString().getBytes(StandardCharsets.UTF_8));
            BackgroundSessionHostTest.field(session,"spawnAttempted",true);
        }
        boolean journalPresent(){return Files.exists(directory.resolve(BackgroundSession.JOURNAL));}
        JSONObject cleanup()throws Exception{
            JSONObject row=new JSONObject().put("task_id",1234).put("parent_task_id",1200).put("task_token_id",TOKEN)
                .put("user_id",10).put("user_serial",20L).put("full_uid",1010367).put("live_absent",true).put("recents_absent",true);
            return new JSONObject().put("schema","hepta.profile-task-cleanup.v1").put("generation",session.generation)
                .put("display_id",7).put("target_sha256",target.sha256).put("user_id",10).put("user_serial",20L).put("full_uid",1010367)
                .put("cleanup_known",true).put("live_tasks_absent",true).put("recents_tasks_absent",true)
                .put("foreign_tasks_present",false).put("identity_unknown",false).put("owned_tasks",new JSONArray().put(row));
        }
        byte[] window(byte[] bytes,ProfileTarget actual,int actualTask,long at)throws Exception{
            JSONObject req=BackgroundSessionHostTest.decode(bytes);WindowOwnership w=new WindowOwnership(actual,session.generation,7,17,actualTask,1200,TOKEN,UUID.randomUUID().toString(),actual.profile.userId,actual.profile.serial,actual.fullUid,at,Math.min(at+1000,req.getLong("deadline_elapsed_ms")));
            return BackgroundSessionHostTest.frame(response(bytes,"ACTIVE",true).put("window_ownership_wire",w.wire()).toString().getBytes(StandardCharsets.UTF_8));
        }
        public void close()throws IOException{android.system.Os.failUnlink=false;try(java.util.stream.Stream<Path> stream=Files.walk(directory)){for(Path p:stream.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(p);}}
    }
    static final HeptaAccessibilityService.Cancellation LIVE=new HeptaAccessibilityService.Cancellation(){public boolean isCancelled(){return false;}};
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
    public static void main(String[] args)throws Exception{
        test("selection_digest_binds_actual_profile",()->{try(Env e=new Env()){need(e.session.selection.profileTarget.same(e.target));need(e.session.selection.json().getString("profile_target_wire").equals(e.target.wire()));BackgroundTaskTarget other=BackgroundTaskTarget.resolveExplicitSelection(OWNER,e.target.packageName,Collections.singleton(e.target.packageName),target(21));need(!other.targetSha256.equals(e.session.selection.taskTarget.targetSha256));}});
        test("live_reply_registers_exact_proof_object",()->{try(Env e=new Env()){e.active();LocalSocket.responder=b->e.window(b,e.target,1234,SystemClock.now);WindowOwnership w=e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now+3000);e.session.requireProfileWindow(w,17,1234,SystemClock.now);need(LocalSocket.connections==1);WindowOwnership deserialized=WindowOwnership.fromWire(w.wire(),e.target);reject(()->e.session.requireProfileWindow(deserialized,17,1234,SystemClock.now));}});
        test("historical_proof_does_not_grant_current_authority",()->{try(Env e=new Env()){e.active();LocalSocket.responder=b->e.window(b,e.target,1234,SystemClock.now);WindowOwnership w=e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now+3000);long captured=SystemClock.now;SystemClock.now+=1200;WindowOwnership fresh=e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now+3000);e.session.requireHistoricalProfileWindow(w,17,1234,captured);WindowOwnership copied=WindowOwnership.fromWire(w.wire(),e.target);reject(()->e.session.requireHistoricalProfileWindow(copied,17,1234,captured));reject(()->e.session.requireProfileWindow(w,17,1234,SystemClock.now));e.session.requireProfileWindow(fresh,17,1234,SystemClock.now);need(LocalSocket.connections==2);}});
        test("historical_registry_uses_same_bounded_profile_quota_without_eviction",()->{try(Env e=new Env()){
            e.active();LocalSocket.responder=b->e.window(b,e.target,1234,SystemClock.now);
            WindowOwnership first=e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now+3000);long captured=SystemClock.now;
            for(int i=1;i<BrokerProtocol.MAX_PROFILE_REQUEST_IDS;i++)e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now+3000);
            need(BrokerProtocol.MAX_PROFILE_REQUEST_IDS==512);
            need(LocalSocket.connections==512);
            reject(()->e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now+3000));
            need(LocalSocket.connections==513);
            SystemClock.now+=1200;e.session.requireHistoricalProfileWindow(first,17,1234,captured);
            reject(()->e.session.requireProfileWindow(first,17,1234,SystemClock.now));
        }});
        test("cancel_before_window_rpc_sends_nothing",()->{try(Env e=new Env()){e.active();reject(()->e.session.verifyProfileWindow(17,1234,()->true,SystemClock.now+3000));need(LocalSocket.connections==0);}});
        test("expired_original_deadline_sends_nothing",()->{try(Env e=new Env()){e.active();reject(()->e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now));need(LocalSocket.connections==0);}});
        test("late_cancel_cannot_register_reply",()->{try(Env e=new Env()){e.active();final boolean[] cancelled={false};LocalSocket.responder=b->{byte[] r=e.window(b,e.target,1234,SystemClock.now);cancelled[0]=true;return r;};reject(()->e.session.verifyProfileWindow(17,1234,()->cancelled[0],SystemClock.now+3000));}});
        test("different_user_serial_refused",()->{try(Env e=new Env()){e.active();LocalSocket.responder=b->e.window(b,target(21),1234,SystemClock.now);reject(()->e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now+3000));}});
        test("different_observed_task_refused",()->{try(Env e=new Env()){e.active();LocalSocket.responder=b->e.window(b,e.target,1235,SystemClock.now);reject(()->e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now+3000));}});
        test("proof_predating_request_refused",()->{try(Env e=new Env()){e.active();LocalSocket.responder=b->e.window(b,e.target,1234,SystemClock.now-1);reject(()->e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now+3000));}});
        test("active_reply_requires_fresh_profile_identity",()->{try(Env e=new Env()){e.active();LocalSocket.responder=b->{JSONObject r=BackgroundSessionHostTest.decode(e.window(b,e.target,1234,SystemClock.now));r.put("profile_current_identity_verified",false);return BackgroundSessionHostTest.frame(r.toString().getBytes(StandardCharsets.UTF_8));};reject(()->e.session.verifyProfileWindow(17,1234,LIVE,SystemClock.now+3000));}});
        test("profile_cleanup_requires_real_retirement_and_display_absence",()->{try(Env e=new Env()){e.active();e.journal(true);LocalSocket.responder=b->{e.context.displays.displays.clear();return BackgroundSessionHostTest.frame(e.response(b,"RELEASED",true).put("profile_cleanup_known",true).put("profile_cleanup",e.cleanup()).toString().getBytes(StandardCharsets.UTF_8));};BackgroundSession.Cleanup c=e.session.close();need(c.known&&e.session.released());need(!e.journalPresent());need(c.evidence.getJSONObject("profile_cleanup").getBoolean("display_absence_observed"));}});
        for(final String bad:Arrays.asList("wrong_serial","parent_uid","empty_owned","extra_field","false_recents"))test("cleanup_"+bad+"_stays_unknown",()->{try(Env e=new Env()){e.active();e.journal(true);LocalSocket.responder=b->{JSONObject p=e.cleanup();if("wrong_serial".equals(bad))p.put("user_serial",21L);if("parent_uid".equals(bad))p.put("full_uid",10367);if("empty_owned".equals(bad))p.put("owned_tasks",new JSONArray());if("extra_field".equals(bad))p.put("display_absence_observed",true);if("false_recents".equals(bad))p.put("recents_tasks_absent",false);e.context.displays.displays.clear();return BackgroundSessionHostTest.frame(e.response(b,"RELEASED",true).put("profile_cleanup_known",true).put("profile_cleanup",p).toString().getBytes(StandardCharsets.UTF_8));};BackgroundSession.Cleanup c=e.session.close();need(!c.known&&!e.session.released());need(e.journalPresent());}});
        test("unknown_profile_retirement_retains_custodian_process",()->{try(Env e=new Env()){e.active();e.journal(true);Custodian process=new Custodian();BackgroundSessionHostTest.field(e.session,"brokerProcess",process);LocalSocket.responder=b->BackgroundSessionHostTest.frame(e.response(b,"CLEANUP_UNKNOWN",false).put("profile_cleanup_known",false).put("profile_custody_retained",true).toString().getBytes(StandardCharsets.UTF_8));need(!e.session.close().known);need(process.destroyed==0);need(e.journalPresent()&&e.context.displays.getDisplay(7)!=null);}});
        test("broker_death_and_expired_display_do_not_prove_task_cleanup",()->{try(Env e=new Env()){e.active();e.journal(true);Custodian process=new Custodian();process.exited=true;BackgroundSessionHostTest.field(e.session,"brokerProcess",process);LocalSocket.missing=true;e.context.displays.displays.clear();need(!e.session.close().known);SystemClock.now=e.session.expiresElapsed+3000;need(!BackgroundSession.reconcile(e.context).known);need(e.journalPresent());need(process.destroyed==0);}});
        test("known_reconcile_consumes_profile_release_projection",()->{try(Env e=new Env()){e.active();e.journal(true);LocalSocket.responder=b->{e.context.displays.displays.clear();return BackgroundSessionHostTest.frame(e.response(b,"RELEASED",true).put("profile_cleanup_known",true).put("profile_cleanup",e.cleanup()).toString().getBytes(StandardCharsets.UTF_8));};BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context);need(c.known);e.session.acceptReconciliation(c.evidence);need(e.session.released());need(e.session.evidence().getJSONObject("profile_cleanup").getBoolean("display_absence_observed"));}});
        JSONObject result=new JSONObject().put("schema","hepta.profile-client-host-tests.v1").put("all_pass",true).put("cases",cases.size()).put("assertions",assertions).put("case_names",new JSONArray(cases)).put("phone_actions",0).put("root_transport_and_android_io_mocked",true).put("framework_window_uid_corroboration_proved",false);
        Files.write(Paths.get(args[0]),(result.toString()+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(result.toString());
    }
}
