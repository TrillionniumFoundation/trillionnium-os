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
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Full production BackgroundSession. Only Android/clock/root transport are fake.
 * No real broker process, display, node, model or phone operation is executed. */
public final class PublicOwnGroupSessionHostTest {
    static final String TASK="11111111111111111111111111111111",OWNER="查看当前应用内容",PKG="com.example.app";
    static final HeptaAccessibilityService.Cancellation LIVE=()->false;
    static int cases,checks;
    interface Work{void run()throws Exception;}
    static void yes(boolean v){checks++;if(!v)throw new AssertionError("session boundary check failed");}
    static void no(Work w)throws Exception{try{w.run();}catch(Exception expected){checks++;return;}throw new AssertionError("invalid request admitted");}
    static void test(String name,Work w)throws Exception{LocalSocket.reset();SystemClock.now=1000000;android.provider.Settings.Global.boot=10;android.os.Looper.worker=true;w.run();cases++;System.out.println("PASS "+name);}
    static Object field(Object instance,String name)throws Exception{Field f=BackgroundSession.class.getDeclaredField(name);f.setAccessible(true);return f.get(instance);}
    static String hash(char c){char[] v=new char[64];Arrays.fill(v,c);return new String(v);}
    static final class Env implements AutoCloseable {
        final Path root;final Context context;final BackgroundSession session;final PublicOwnGroupPolicy.Scope scope;final ProfileTarget target;
        String unique="virtual:host-only";int group=2,replyFlags=7040;boolean showing=true;String physical0=hash('a'),physical1=hash('b');
        String staleWire,wrongScope,wrongOperation;String physicalFacts0="{\"state\":1,\"rotation\":0}",physicalFacts1="{\"state\":1,\"rotation\":0}";int overrideVersion=-1;boolean retireDuringReply,reportedRetired,reportedClosing;
        String permissionVariant="v2",permissionAudit0=hash('d');
        Env(boolean profile)throws Exception{
            root=Files.createTempDirectory("hepta-public-scope-host-").toRealPath();context=new Context(root.toFile());context.keyguard.locked=true;
            target=profile?ProfileSessionHostTest.target(20):null;String pkg=target==null?PKG:target.packageName;
            BackgroundTaskTarget chosen=BackgroundTaskTarget.resolveExplicitSelection(OWNER,pkg,Collections.singleton(pkg),target);
            session=BackgroundSession.experimentalPublicOwnGroup(context,TASK,OWNER,new BackgroundSession.Selection(chosen),new QualificationScopeConfig.FilesRoot(context));
            scope=(PublicOwnGroupPolicy.Scope)field(session,"publicOwnGroupScope");
            Display display=new Display(7,session.displayName);display.flags=7040;context.displays.displays.put(7,display);
            // Host surrogates for the untouched physical screens; actual phone proof is external.
            Display main=new Display(0,"physical-main"),cover=new Display(1,"physical-cover");main.flags=0;cover.flags=0;
            context.displays.displays.put(0,main);context.displays.displays.put(1,cover);
            LocalSocket.responder=this::reply;
        }
        byte[] reply(byte[] bytes)throws Exception{
            JSONObject req=BackgroundSessionHostTest.decode(bytes);
            JSONObject result=new JSONObject().put("version",overrideVersion<0?req.getInt("version"):overrideVersion)
                    .put("request_id",req.getString("request_id")).put("generation",session.generation)
                    .put("operation",wrongOperation==null?req.getString("op"):wrongOperation)
                    .put("display_scope_sha256",wrongScope==null?scope.sha256:wrongScope)
                    .put("public_scope_admission_retired",reportedRetired).put("public_scope_closing",reportedClosing)
                    .put("ok",true).put("state","ACTIVE").put("display_id",7).put("display_name",session.displayName)
                    .put("flags",replyFlags).put("expires_elapsed_ms",session.expiresElapsed).put("dispatched",false);
            if(target!=null)result.put("profile_target_wire",target.wire()).put("profile_current_identity_verified",true);
            PublicOwnGroupPolicy.Privileges privileges=new PublicOwnGroupPolicy.Privileges(0,0,0,0);
            PublicOwnGroupPolicy.Credentials credentials=new PublicOwnGroupPolicy.Credentials(0,showing,
                    new PublicOwnGroupPolicy.UserState(0,0,false,false,false),new PublicOwnGroupPolicy.UserState(scope.targetUserId,0,false,false,false));
            PublicOwnGroupPolicy.DisplayState display=new PublicOwnGroupPolicy.DisplayState(7,session.displayName,unique,0,"com.android.shell",7040,group,0,0,1,1,2,2);
            Map<Integer,String> physical=new LinkedHashMap<Integer,String>();physical.put(0,physical0);physical.put(1,physical1);
            Map<Integer,String> facts=new LinkedHashMap<Integer,String>();facts.put(0,physicalFacts0);facts.put(1,physicalFacts1);
            PublicOwnGroupPolicy.Readback proof=new PublicOwnGroupPolicy.Readback(scope,req.getString("request_id"),SystemClock.now,SystemClock.now,privileges,credentials,display,new PublicOwnGroupPolicy.PhysicalDisplays(physical,facts));
            result.put("public_own_group_readback_wire",staleWire==null?proof.wire():staleWire);
            if("permission_window".equals(req.getString("op")))result.put("profile_permission_preparing",true)
                    .put("permission_window_wire",permissionWire(proof,req));
            if(retireDuringReply)BackgroundSessionHostTest.field(session,"retired",true);
            return BackgroundSessionHostTest.frame(result.toString().getBytes(StandardCharsets.UTF_8));
        }
        /** Synthetic root-transport payload only. The immutable wire value is
         * made by the production constructor; actual registration/lease/mode
         * checks below execute the complete production BackgroundSession.
         * The core initialization gate separately exercises private issuance. */
        String permissionWire(PublicOwnGroupPolicy.Readback actual,JSONObject request)throws Exception{
            PublicOwnGroupPolicy.Scope projected=scope;
            if("foreign-scope".equals(permissionVariant))projected=new PublicOwnGroupPolicy.Scope("22222222222222222222222222222222",
                    scope.ownerSha256,scope.generation,scope.appUid,target,scope.createdElapsedMs,scope.expiresElapsedMs,scope.bootCount);
            if("foreign-generation".equals(permissionVariant))projected=new PublicOwnGroupPolicy.Scope(scope.taskId,
                    scope.ownerSha256,UUID.randomUUID().toString(),scope.appUid,target,scope.createdElapsedMs,scope.expiresElapsedMs,scope.bootCount);
            PublicOwnGroupPolicy.DisplayState display=new PublicOwnGroupPolicy.DisplayState(7,"hepta-bg-"+projected.generation,unique,0,"com.android.shell",7040,
                    "foreign-group".equals(permissionVariant)?3:group,0,0,1,1,2,2);
            PublicOwnGroupPolicy.Readback row=new PublicOwnGroupPolicy.Readback(projected,actual.requestId,SystemClock.now,SystemClock.now,
                    actual.privileges,actual.credentials,display,actual.physical);
            PermissionWindowObservation.PublicInitialization projection="v1".equals(permissionVariant)||"missing-projection".equals(permissionVariant)
                    ?null:PermissionWindowObservation.PublicInitialization.fromReadback(projected,target,row,SystemClock.now);
            Constructor<PermissionWindowObservation> constructor=PermissionWindowObservation.class.getDeclaredConstructor(ProfileTarget.class,String.class,String.class,String.class,
                    int.class,int.class,int.class,int.class,int.class,String.class,String.class,String.class,String.class,String.class,
                    long.class,long.class,Map.class,PermissionWindowObservation.PublicInitialization.class);
            constructor.setAccessible(true);Map<Integer,String> audit=new LinkedHashMap<Integer,String>();audit.put(0,permissionAudit0);audit.put(1,hash('e'));
            PermissionWindowObservation evidence=constructor.newInstance(target,projected.generation,UUID.randomUUID().toString(),"33333333-3333-4333-8333-333333333333",
                    7,17,1200,1234,1010335,"permission_activity","target_activity",hash('a'),hash('b'),hash('c'),SystemClock.now,
                    Math.min(SystemClock.now+1000,request.getLong("deadline_elapsed_ms")),audit,projection);
            if(!"missing-projection".equals(permissionVariant))return evidence.wire();
            DataInputStream in=new DataInputStream(new ByteArrayInputStream(Base64.getUrlDecoder().decode(evidence.wire())));
            in.readUTF();ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF(PermissionWindowObservation.PUBLIC_SCHEMA);while(in.available()>0)out.writeByte(in.readByte());out.flush();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes.toByteArray());
        }
        void preparing()throws Exception{active();BackgroundSessionHostTest.field(session,"permissionPreparing",true);
            BackgroundSessionHostTest.field(session,"profileLaunchAttempted",true);}
        void active()throws Exception{
            JSONObject reply=(JSONObject)BackgroundSessionHostTest.invoke(session,"call",new Class<?>[]{String.class,String.class,int.class},"create",null,3000);
            BackgroundSessionHostTest.invoke(session,"accept",new Class<?>[]{JSONObject.class,boolean.class},reply,true);session.requireActive();
        }
        void journal()throws Exception{
            JSONObject j=(JSONObject)BackgroundSessionHostTest.invoke(session,"baseJournal",new Class<?>[]{});
            MobiMindPrivateFiles.writeNew(root.resolve(BackgroundSession.JOURNAL).toFile(),j.toString().getBytes(StandardCharsets.UTF_8));
            BackgroundSessionHostTest.field(session,"spawnAttempted",true);
        }
        void physicalUnchanged(){yes(context.displays.getDisplay(0)!=null&&"physical-main".equals(context.displays.getDisplay(0).getName()));yes(context.displays.getDisplay(1)!=null&&"physical-cover".equals(context.displays.getDisplay(1).getName()));}
        public void close()throws IOException{try(java.util.stream.Stream<Path> p=Files.walk(root)){for(Path row:p.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(row);}}
    }
    public static void main(String[] args)throws Exception{
        test("ordinary constructor keeps legacy scope and protocol",()->{Path root=Files.createTempDirectory("hepta-legacy-scope-");Context c=new Context(root.toFile());BackgroundSession s=new BackgroundSession(c,TASK,OWNER,new BackgroundSession.Selection(PKG,Collections.singleton(PKG)),new QualificationScopeConfig.FilesRoot(c));
            yes(!s.usesExperimentalPublicOwnGroup());JSONObject q=(JSONObject)BackgroundSessionHostTest.invoke(s,"request",new Class<?>[]{String.class,String.class,long.class},"state",null,SystemClock.now+1000);yes(q.getInt("version")==1&&!q.has("display_scope_sha256"));Files.delete(root);});
        test("experimental factory refuses missing immutable explicit owner target",()->{Path root=Files.createTempDirectory("hepta-refused-scope-");Context c=new Context(root.toFile());no(()->BackgroundSession.experimentalPublicOwnGroup(c,TASK,OWNER,new BackgroundSession.Selection(PKG,Collections.singleton(PKG)),new QualificationScopeConfig.FilesRoot(c)));Files.delete(root);});
        for(boolean profile:new boolean[]{false,true})test("actual full client registers root RPC for "+(profile?"profile10":"target0"),()->{try(Env e=new Env(profile)){
            e.active();yes(e.session.displayId()==7&&e.context.keyguard.locked);yes(e.scope.targetUserId==(profile?10:0));
            JSONObject req=BackgroundSessionHostTest.decode(LocalSocket.sent);yes(req.getInt("version")== (profile?4:3));yes(req.getString("display_scope_sha256").equals(e.scope.sha256));e.physicalUnchanged();
        }});
        test("serialized plausible receipt alone cannot activate a session",()->{try(Env e=new Env(false)){
            JSONObject q=(JSONObject)BackgroundSessionHostTest.invoke(e.session,"request",new Class<?>[]{String.class,String.class,long.class},"create",null,SystemClock.now+1000);
            JSONObject r=BackgroundSessionHostTest.decode(e.reply(BackgroundSessionHostTest.frame(q.toString().getBytes(StandardCharsets.UTF_8))));
            no(()->BackgroundSessionHostTest.invoke(e.session,"accept",new Class<?>[]{JSONObject.class,boolean.class},r,true));yes(LocalSocket.connections==0);
        }});
        for(int peer:new int[]{2000,1000,10123})test("kernel peer UID "+peer+" rejected before writing even when JSON claims root",()->{try(Env e=new Env(false)){
            LocalSocket.peerUid=peer;no(e::active);yes(!LocalSocket.events.contains("output")&&LocalSocket.sent.length==0);LocalSocket.peerUid=0;no(e::active);e.physicalUnchanged();
        }});
        test("only absent create connection can retry before bytes",()->{try(Env e=new Env(false)){
            LocalSocket.missing=true;no(e::active);yes(LocalSocket.sent.length==0);LocalSocket.missing=false;e.active();yes(e.session.displayId()==7);
        }});
        test("readonly scheduling admission does not renew stale proof or send RPC",()->{try(Env e=new Env(false)){
            e.active();int prior=LocalSocket.connections;SystemClock.now+=2000;android.os.Looper.worker=false;e.session.requireAdmissionActive();yes(LocalSocket.connections==prior);
            no(()->e.session.requirePolicyBeforeEffect(LIVE,SystemClock.now+3000));yes(LocalSocket.connections==prior);
            android.os.Looper.worker=true;e.session.requirePolicyBeforeEffect(LIVE,SystemClock.now+3000);yes(LocalSocket.connections==prior+1);
            yes("display_policy".equals(BackgroundSessionHostTest.decode(LocalSocket.sent).getString("op")));e.physicalUnchanged();
        }});
        test("permission preparation refresh uses dedicated readonly op",()->{try(Env e=new Env(true)){
            e.active();BackgroundSessionHostTest.field(e.session,"permissionPreparing",true);BackgroundSessionHostTest.field(e.session,"profileLaunchAttempted",true);
            SystemClock.now+=600;e.session.requirePermissionPreparationActive();yes("display_policy".equals(BackgroundSessionHostTest.decode(LocalSocket.sent).getString("op")));
        }});
        test("full client binds v2 permission RPC to its current registered public readback",()->{try(Env e=new Env(true)){
            e.preparing();PermissionWindowObservation first=e.session.verifyPermissionWindow(17,1234,LIVE,SystemClock.now+3000);
            e.session.requirePermissionWindow(first,SystemClock.now);yes(PermissionWindowObservation.PUBLIC_SCHEMA.equals(first.schema));
            PublicOwnGroupPolicy.Readback before=(PublicOwnGroupPolicy.Readback)field(e.session,"publicScopeReadback");
            e.permissionAudit0=hash('f');e.physicalFacts0="{\"state\":2,\"rotation\":1,\"focus\":\"user0-other-task\"}";
            PermissionWindowObservation second=e.session.verifyPermissionWindow(17,1234,LIVE,SystemClock.now+3000);
            PublicOwnGroupPolicy.Readback after=(PublicOwnGroupPolicy.Readback)field(e.session,"publicScopeReadback");
            yes(before!=after&&!before.requestId.equals(after.requestId));yes(after.physicalObservedFacts.get(0).equals(e.physicalFacts0));
            yes(!first.physicalIdentities.equals(second.physicalIdentities)&&first.samePhysicalScope(second));
            e.session.requirePermissionWindow(second,SystemClock.now);
            no(()->e.session.requirePermissionWindow(PermissionWindowObservation.fromWire(second.wire(),e.target),SystemClock.now));
            e.physicalUnchanged();
        }});
        for(String variant:new String[]{"v1","missing-projection","foreign-scope","foreign-generation","foreign-group"})test("full public client rejects permission "+variant+" at actual RPC consumption",()->{try(Env e=new Env(true)){
            e.preparing();e.permissionVariant=variant;int before=LocalSocket.connections;
            no(()->e.session.verifyPermissionWindow(17,1234,LIVE,SystemClock.now+3000));yes(LocalSocket.connections==before+1);
            yes(((Map<?,?>)field(e.session,"permissionProofs")).isEmpty());e.physicalUnchanged();
        }});
        test("registered permission remains bound to current readback and cancellation",()->{try(Env e=new Env(true)){
            e.preparing();PermissionWindowObservation proof=e.session.verifyPermissionWindow(17,1234,LIVE,SystemClock.now+3000);
            int before=LocalSocket.connections;no(()->e.session.verifyPermissionWindow(17,1234,()->true,SystemClock.now+3000));yes(LocalSocket.connections==before);
            no(()->e.session.requirePermissionWindow(proof,proof.expiresElapsedMs));
            e.group=3;no(()->e.session.verifyPermissionWindow(17,1234,LIVE,SystemClock.now+3000));
            no(()->e.session.requirePermissionWindow(proof,SystemClock.now));e.physicalUnchanged();
        }});
        for(String change:new String[]{"unique","group","physical0","physical1","response_flags","scope","operation","version","retired","reported_retired","reported_closing"})test("changed fresh response irreversibly retires client "+change,()->{try(Env e=new Env(false)){
            e.active();if("unique".equals(change))e.unique="virtual:changed";if("group".equals(change))e.group=3;
            if("physical0".equals(change))e.physical0=hash('c');if("physical1".equals(change))e.physical1=hash('c');
            if("showing".equals(change))e.showing=false;if("response_flags".equals(change))e.replyFlags=6272;
            if("scope".equals(change))e.wrongScope=hash('c');if("operation".equals(change))e.wrongOperation="state";
            if("version".equals(change))e.overrideVersion=1;if("retired".equals(change))e.retireDuringReply=true;
            if("reported_retired".equals(change))e.reportedRetired=true;if("reported_closing".equals(change))e.reportedClosing=true;
            no(()->e.session.requirePolicyBeforeEffect(LIVE,SystemClock.now+3000));no(e.session::requireAdmissionActive);
            int attempts=LocalSocket.connections;no(()->e.session.requirePolicyBeforeEffect(LIVE,SystemClock.now+3000));yes(LocalSocket.connections==attempts);e.physicalUnchanged();
        }});
        test("natural user physical runtime and insecure keyguard showing changes retain owned scope",()->{try(Env e=new Env(false)){
            e.active();e.showing=false;e.context.keyguard.locked=false;e.physicalFacts0="{\"state\":2,\"rotation\":1}";
            e.session.requirePolicyBeforeEffect(LIVE,SystemClock.now+3000);e.session.requireActive();
            PublicOwnGroupPolicy.Readback proof=(PublicOwnGroupPolicy.Readback)field(e.session,"publicScopeReadback");
            yes(!proof.credentials.keyguardShowing&&proof.physicalObservedFacts.get(0).equals(e.physicalFacts0));e.physicalUnchanged();
        }});
        test("old wire cannot renew a new request",()->{try(Env e=new Env(false)){
            e.active();e.staleWire=((PublicOwnGroupPolicy.Readback)field(e.session,"publicScopeReadback")).wire();no(()->e.session.requirePolicyBeforeEffect(LIVE,SystemClock.now+3000));no(e.session::requireAdmissionActive);
        }});
        for(String positive:new String[]{"secure","device_secure","device_locked","boot"})test("positive ordinary app guard blocks "+positive,()->{try(Env e=new Env(false)){
            e.active();if("secure".equals(positive))e.context.keyguard.secure=true;if("device_secure".equals(positive))e.context.keyguard.deviceSecure=true;if("device_locked".equals(positive))e.context.keyguard.deviceLocked=true;
            if("boot".equals(positive))android.provider.Settings.Global.boot++;int prior=LocalSocket.connections;no(e.session::requireAdmissionActive);yes(LocalSocket.connections==prior);no(e.session::requireActive);
        }});
        test("cancellation sends no policy request bytes and keeps scope retired",()->{try(Env e=new Env(false)){
            e.active();LocalSocket.sent=new byte[0];no(()->e.session.requirePolicyBeforeEffect(()->true,SystemClock.now+3000));yes(LocalSocket.sent.length==0);no(e.session::requireAdmissionActive);
        }});
        test("original elapsed deadline is not replaced by fresh budget",()->{try(Env e=new Env(false)){
            e.active();int prior=LocalSocket.connections;no(()->e.session.requirePolicyBeforeEffect(LIVE,SystemClock.now));yes(LocalSocket.connections==prior);no(e.session::requireAdmissionActive);
        }});
        test("unavailable root policy read retires without retry",()->{try(Env e=new Env(false)){
            e.active();int prior=LocalSocket.connections;LocalSocket.missing=true;no(()->e.session.requirePolicyBeforeEffect(LIVE,SystemClock.now+3000));yes(LocalSocket.connections==prior+1);LocalSocket.missing=false;no(e.session::requireActive);yes(LocalSocket.connections==prior+1);
        }});
        test("late reply cannot reactivate after close began",()->{try(Env e=new Env(false)){
            e.active();e.retireDuringReply=true;no(()->e.session.requirePolicyBeforeEffect(LIVE,SystemClock.now+3000));yes(Boolean.TRUE.equals(field(e.session,"retired")));no(e.session::requireAdmissionActive);
        }});
        test("journal records scope only for exact cleanup not resume",()->{try(Env e=new Env(false)){
            e.active();e.journal();JSONObject j=new JSONObject(new String(Files.readAllBytes(e.root.resolve(BackgroundSession.JOURNAL)),StandardCharsets.UTF_8));
            yes(j.getBoolean("owned_task_retirement_required")&&!j.getBoolean("public_scope_serialization_grants_authority"));
            yes(j.getString("public_own_group_scope_wire").equals(e.scope.wire()));yes(!e.session.prelaunchRecoveryEligible()&&!e.session.postlaunchRecoveryEligible());
            JSONObject tampered=new JSONObject(j.toString()).put("owner_sha256",hash('c'));
            no(()->BackgroundSessionHostTest.invoke(null,"parseJournal",new Class<?>[]{byte[].class},tampered.toString().getBytes(StandardCharsets.UTF_8)));
        }});
        test("close keeps exact scope hash and requires actual display absence",()->{try(Env e=new Env(false)){
            e.active();e.journal();LocalSocket.responder=bytes->{JSONObject q=BackgroundSessionHostTest.decode(bytes);yes(q.getInt("version")==3&&q.getString("display_scope_sha256").equals(e.scope.sha256)&&"close".equals(q.getString("op")));
                JSONObject r=BackgroundSessionHostTest.decode(e.reply(bytes));r.put("state","RELEASED");return BackgroundSessionHostTest.frame(r.toString().getBytes(StandardCharsets.UTF_8));};
            BackgroundSession.Cleanup c=e.session.close();yes(!c.known&&!e.session.released());yes(Files.exists(e.root.resolve(BackgroundSession.JOURNAL)));no(e.session::requireActive);e.physicalUnchanged();
        }});
        test("closing refusal preserves unknown state and original live profile custody",()->{try(Env e=new Env(true)){
            e.active();BackgroundSessionHostTest.field(e.session,"profileLaunchAttempted",true);
            BackgroundSessionHostTest.field(e.session,"bootstrapDispatched",true);e.journal();
            ProfileSessionHostTest.Custodian process=new ProfileSessionHostTest.Custodian();
            BackgroundSessionHostTest.field(e.session,"brokerProcess",process);final JSONObject[] original={null};
            LocalSocket.responder=bytes->{JSONObject q=BackgroundSessionHostTest.decode(bytes);
                yes(q.getInt("version")==4&&q.getString("display_scope_sha256").equals(e.scope.sha256)&&"close".equals(q.getString("op")));
                original[0]=BackgroundSessionHostTest.decode(e.reply(bytes)).put("state","CLOSING").put("ok",false)
                        .put("error","CLEANUP_NOT_CONFIRMED").put("profile_cleanup_known",false).put("profile_custody_retained",true)
                        .put("public_scope_admission_retired",true).put("public_scope_closing",true);
                return BackgroundSessionHostTest.frame(original[0].toString().getBytes(StandardCharsets.UTF_8));};
            int before=LocalSocket.connections;BackgroundSession.Cleanup c=e.session.close();
            JSONObject journal=new JSONObject(new String(Files.readAllBytes(e.root.resolve(BackgroundSession.JOURNAL)),StandardCharsets.UTF_8));
            yes(!c.known&&!e.session.released()&&"CLEANUP_UNKNOWN".equals(c.evidence.getString("state")));
            yes("CLEANUP_UNKNOWN".equals(journal.getString("state"))&&journal.getString("generation").equals(e.session.generation));
            yes(c.evidence.getJSONObject("last_broker_response").toString().equals(original[0].toString()));
            yes(process.isAlive()&&process.destroyed==0&&!c.evidence.getBoolean("broker_process_exit_observed"));
            yes(e.context.displays.getDisplay(7)!=null&&LocalSocket.connections==before+1);
            yes(e.session.publicProfileBusinessCleanupEntryEligible()&&!e.session.publicProfileBusinessRecoveryEligible());
            no(e.session::requireActive);no(e.session::requireAdmissionActive);
            no(()->e.session.awaitRetainedBrokerExit("22222222222222222222222222222222",e.session.generation,e.session.ownerSha256,SystemClock.now+1000));
            no(()->e.session.awaitRetainedBrokerExit(e.session.taskId,e.session.generation,e.session.ownerSha256,SystemClock.now+1000));
            yes(process.isAlive()&&process.destroyed==0&&!e.session.publicProfileBusinessRecoveryEligible());
            yes(LocalSocket.connections==before+1&&Files.exists(e.root.resolve(BackgroundSession.JOURNAL)));e.physicalUnchanged();
        }});
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+checks+",\"passed\":true,\"phone_contacted\":false,\"actual_full_session\":true,\"android_transport_fake\":true}");
    }
}
