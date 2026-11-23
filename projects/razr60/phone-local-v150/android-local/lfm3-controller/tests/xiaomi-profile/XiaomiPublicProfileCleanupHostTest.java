/* Independent Xiaomi fixture derived from the original PublicProfileCleanupHostTest (06538000c0deebc4d39be8317974eff6cd1abfc9e3493ff10d3ef2912882f546).
 * The historical Ctrip/private fixture is retained byte-for-byte and still runs separately.
 * Only synthetic package/component parameters and explicit Xiaomi cases differ. */
package org.trillionnium.hepta.local;

import android.content.Context;
import android.net.LocalSocket;
import android.os.SystemClock;
import android.view.Display;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Full production client. Android, time and root transport are explicit IO
 * fixtures; an archived broker JSON is not made into a new device authority. */
public final class XiaomiPublicProfileCleanupHostTest {
    private static final String TASK="11111111111111111111111111111111";
    private static String OWNER="打开携程",PACKAGE=ProfileTarget.CTRIP;
    private static final String TOKEN="33333333-3333-4333-8333-333333333333";
    private static final String HASH=String.join("",Collections.nCopies(64,"a"));
    private static final List<String> cases=new ArrayList<String>();
    private static int assertions;
    interface Check {void run()throws Exception;}
    interface Change {void apply(JSONObject response)throws Exception;}
    static void need(boolean ok){assertions++;if(!ok)throw new AssertionError("public cleanup contract failed");}
    static void reject(Check check)throws Exception{
        try{check.run();}catch(Exception refused){assertions++;return;}
        throw new AssertionError("invalid public cleanup was accepted");
    }
    static void test(String name,Check check)throws Exception{
        LocalSocket.reset();SystemClock.now=1000000;android.provider.Settings.Global.boot=10;
        android.system.Os.failUnlink=false;check.run();cases.add(name);
    }
    static Object invoke(Object instance,String name,Class<?>[] types,Object...args)throws Exception{
        Method method=BackgroundSession.class.getDeclaredMethod(name,types);method.setAccessible(true);
        try{return method.invoke(instance,args);}catch(InvocationTargetException error){
            Throwable cause=error.getCause();if(cause instanceof Exception)throw (Exception)cause;throw new AssertionError(cause);
        }
    }
    static void field(Object instance,String name,Object value)throws Exception{
        Field field=BackgroundSession.class.getDeclaredField(name);field.setAccessible(true);field.set(instance,value);
    }
    static Object field(Object instance,String name)throws Exception{
        Field field=BackgroundSession.class.getDeclaredField(name);field.setAccessible(true);return field.get(instance);
    }
    static JSONObject checked(JSONObject response,ProfileTarget target,PublicOwnGroupPolicy.Scope scope,String generation,int display,boolean launched)throws Exception{
        return (JSONObject)invoke(null,"checkedProfileCleanup",new Class<?>[]{JSONObject.class,ProfileTarget.class,
                PublicOwnGroupPolicy.Scope.class,String.class,int.class,boolean.class},response,target,scope,generation,display,launched);
    }
    static byte[] frame(JSONObject value)throws Exception{
        byte[] raw=value.toString().getBytes(StandardCharsets.UTF_8);ByteArrayOutputStream out=new ByteArrayOutputStream();
        DataOutputStream data=new DataOutputStream(out);data.writeInt(raw.length);data.write(raw);return out.toByteArray();
    }
    static JSONObject decode(byte[] frame)throws Exception{
        DataInputStream in=new DataInputStream(new ByteArrayInputStream(frame));int count=in.readInt();byte[] raw=new byte[count];in.readFully(raw);
        need(in.read()==-1);return new JSONObject(new String(raw,StandardCharsets.UTF_8));
    }
    static ProfileTarget target(){
        Map<String,String> apks=new LinkedHashMap<String,String>();apks.put("base",HASH);
        return new ProfileTarget(new ProfileIdentity(10,20,0,ProfileIdentity.MANAGED),1010367,PACKAGE,
                ProfileTarget.XIAOMI.equals(PACKAGE)?BackgroundOwnedSingleTask.COMPONENT:ProfileTarget.CTRIP+"/ctrip.android.view.SplashActivity",
                ProfileTarget.XIAOMI.equals(PACKAGE)?20261010:1779,apks,Collections.singleton(HASH));
    }
    static final class Env implements AutoCloseable {
        final Path directory;final Context context;final ProfileTarget target=target();
        final BackgroundSession session;final PublicOwnGroupPolicy.Scope scope;
        Env()throws Exception{
            directory=Files.createTempDirectory("hepta-public-cleanup-").toRealPath();context=new Context(directory.toFile());
            BackgroundTaskTarget selection=BackgroundTaskTarget.resolveExplicitSelection(OWNER,target.packageName,Collections.singleton(target.packageName),target);
            session=BackgroundSession.experimentalPublicOwnGroup(context,TASK,OWNER,new BackgroundSession.Selection(selection,true),new QualificationScopeConfig.FilesRoot(context));
            scope=(PublicOwnGroupPolicy.Scope)field(session,"publicOwnGroupScope");SystemClock.now+=10;
        }
        JSONObject history()throws Exception{
            return new JSONObject().put("schema","hepta.public-profile-history-custody.v1").put("target_sha256",target.sha256)
                .put("foreign_dormant_history_preserved",true).put("history_refusal_latched",false).put("history_refusal_reason",JSONObject.NULL)
                .put("baseline_elapsed_ms",scope.createdElapsedMs+1).put("current_elapsed_ms",scope.createdElapsedMs+2)
                .put("baseline_raw_sha256",HASH).put("current_raw_sha256",HASH).put("nonowned_history_sha256",HASH)
                .put("baseline_task_ids",new JSONArray().put(1430).put(2)).put("owned_task_ids",new JSONArray().put(1200).put(1234))
                .put("owned_target_absent",true).put("serialized_task_ids_grant_authority",false);
        }
        JSONObject response()throws Exception{
            JSONObject row=new JSONObject().put("task_id",1234).put("parent_task_id",1200).put("task_token_id",TOKEN)
                .put("user_id",10).put("user_serial",20L).put("full_uid",1010367).put("live_absent",true).put("recents_absent",true);
            JSONObject proof=new JSONObject().put("schema","hepta.profile-task-cleanup.v1").put("generation",session.generation)
                .put("display_id",7).put("target_sha256",target.sha256).put("user_id",10).put("user_serial",20L).put("full_uid",1010367)
                .put("cleanup_known",true).put("live_tasks_absent",true).put("recents_tasks_absent",true).put("foreign_tasks_present",false)
                .put("identity_unknown",false).put("owned_tasks",new JSONArray().put(row)).put("public_foreign_recent_history",history())
                .put("recents_absence_scope","owned_target_only_with_foreign_history_preserved");
            return new JSONObject().put("version",BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION).put("generation",session.generation)
                .put("request_id",UUID.randomUUID().toString()).put("state","RELEASED").put("ok",false).put("operation","prepare_done")
                .put("display_id",7).put("display_name",session.displayName).put("expires_elapsed_ms",session.expiresElapsed)
                .put("display_scope_sha256",scope.sha256).put("public_scope_admission_retired",true).put("public_scope_closing",true)
                .put("profile_target_wire",target.wire()).put("profile_cleanup_known",true).put("profile_custody_retained",false)
                .put("profile_cleanup",proof).put("terminal_reason","PROFILE_ROOT_FOREIGN_ACTIVITY");
        }
        JSONObject checked(JSONObject response)throws Exception{return XiaomiPublicProfileCleanupHostTest.checked(response,target,scope,session.generation,7,true);}
        void journal(boolean launched)throws Exception{
            field(session,"displayId",7);field(session,"profileLaunchAttempted",launched);field(session,"spawnAttempted",true);
            JSONObject journal=(JSONObject)invoke(session,"baseJournal",new Class<?>[]{});
            MobiMindPrivateFiles.writeNew(directory.resolve(BackgroundSession.JOURNAL).toFile(),journal.toString().getBytes(StandardCharsets.UTF_8));
        }
        void terminal(JSONObject response,boolean launched)throws Exception{
            journal(launched);invoke(session,"accept",new Class<?>[]{JSONObject.class,boolean.class},response,false);LocalSocket.missing=true;
        }
        void live()throws Exception{journal(true);field(session,"state","ACTIVE");context.displays.displays.put(7,new Display(7,session.displayName));}
        byte[] closeResponse(byte[] request,Change change)throws Exception{
            JSONObject q=decode(request);need("close".equals(q.getString("op")));need(scope.sha256.equals(q.getString("display_scope_sha256")));
            JSONObject response=response().put("request_id",q.getString("request_id")).put("operation","close").put("ok",true);
            change.apply(response);context.displays.displays.clear();return frame(response);
        }
        boolean journalPresent(){return Files.exists(directory.resolve(BackgroundSession.JOURNAL));}
        public void close()throws IOException{
            android.system.Os.failUnlink=false;try(java.util.stream.Stream<Path> paths=Files.walk(directory)){
                for(Path p:paths.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(p);
            }
        }
    }
    static JSONObject history(JSONObject response)throws Exception{return response.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history");}
    static void mutation(String name,Change change)throws Exception{
        test(name,()->{try(Env env=new Env()){JSONObject response=env.response();change.apply(response);reject(()->env.checked(response));}});
    }
    static String sha(byte[] bytes)throws Exception{
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder hex=new StringBuilder();
        for(byte value:digest)hex.append(String.format(Locale.ROOT,"%02x",value&255));return hex.toString();
    }
    static JSONObject original(Path directory,String name,String expected)throws Exception{
        byte[] bytes=Files.readAllBytes(directory.resolve(name));need(expected.equals(sha(bytes)));
        return new JSONObject(new String(bytes,StandardCharsets.UTF_8));
    }
    static void actual(Path directory,boolean legacy)throws Exception{
        JSONObject cleanup=original(directory,"background-cleanup.json","e3105339081661e29ef10a22d2dd027c1702b7ed09a5393166d3202342a8c60f");
        JSONObject bootstrap=original(directory,"background-bootstrap.json","b132008f6e51d3aa3cf03eb1425545d7b9edce66e0e46825e358325f788e2392");
        JSONObject result=original(directory,"result.json","7f174b86d99f7dc8dd6f6af55e524e556f7bd73a322de234d7f0464f63667e8a");
        JSONObject response=cleanup.getJSONObject("last_broker_response");
        ProfileTarget target=ProfileTarget.fromWire(cleanup.getString("profile_target_wire"));
        PublicOwnGroupPolicy.Scope scope=PublicOwnGroupPolicy.Scope.fromWire(cleanup.getString("public_own_group_scope_wire"));
        SystemClock.now=history(response).getLong("current_elapsed_ms")+100;
        need(!cleanup.getBoolean("cleanup_known")&&"profile evidence fields differ".equals(cleanup.getString("cleanup_error")));
        need(response.getBoolean("profile_cleanup_known")&&!response.getBoolean("ok")&&"RELEASED".equals(response.getString("state")));
        need(bootstrap.getBoolean("profile_launch_attempted"));need(!result.getBoolean("cleanup_known"));
        if(legacy){
            try{invoke(null,"checkedProfileCleanup",new Class<?>[]{JSONObject.class,ProfileTarget.class,String.class,int.class,boolean.class},
                    response,target,scope.generation,196,true);throw new AssertionError("old consumer unexpectedly accepted");}
            catch(IOException error){need("profile evidence fields differ".equals(error.getMessage()));}
            cases.add("actual_a4_original_reproduces_exact_field_contract_refusal");
        }else{
            JSONObject proof=checked(response,target,scope,scope.generation,196,true);
            need(proof.getBoolean("cleanup_known"));need(proof.getJSONObject("public_foreign_recent_history").getJSONArray("baseline_task_ids").length()==8);
            need(!cleanup.getBoolean("cleanup_known"));need(!result.getBoolean("cleanup_known"));
            cases.add("actual_a4_terminal_projection_accepted_without_rewriting_failure");
        }
    }
    public static void main(String[] args)throws Exception{
        if(args.length>3&&"xiaomi".equals(args[3])){PACKAGE=ProfileTarget.XIAOMI;OWNER="打开小米商城";}
        boolean legacy=args.length>2&&"legacy".equals(args[2]);
        if(legacy){actual(Paths.get(args[1]),true);}
        else{
            test("public_failed_operation_terminal_cleanup_is_valid",()->{try(Env e=new Env()){
                JSONObject response=e.response(),proof=e.checked(response);need(proof.getBoolean("cleanup_known"));
                need(!response.getBoolean("ok"));need("PROFILE_ROOT_FOREIGN_ACTIVITY".equals(response.getString("terminal_reason")));
                need(history(response).getJSONArray("baseline_task_ids").length()==2);
            }});
            test("private_original_thirteen_fields_are_unchanged",()->{try(Env e=new Env()){
                JSONObject response=e.response();JSONObject proof=response.getJSONObject("profile_cleanup");
                proof.remove("public_foreign_recent_history");proof.remove("recents_absence_scope");
                need(checked(response,e.target,null,e.session.generation,7,true).length()==13);
            }});
            test("public_extensions_cannot_enter_private_contract",()->{try(Env e=new Env()){
                reject(()->checked(e.response(),e.target,null,e.session.generation,7,true));
            }});
            mutation("public_requires_explicit_history",r->r.getJSONObject("profile_cleanup").remove("public_foreign_recent_history"));
            mutation("public_requires_owned_absence_scope",r->r.getJSONObject("profile_cleanup").put("recents_absence_scope","whole_profile_empty"));
            mutation("public_unknown_cleanup_field_refused",r->r.getJSONObject("profile_cleanup").put("display_absence_observed",true));
            mutation("public_unknown_history_field_refused",r->history(r).put("profile_empty",true));
            mutation("public_wrong_history_schema_refused",r->history(r).put("schema","hepta.private-history.v1"));
            mutation("public_wrong_scope_hash_refused",r->r.put("display_scope_sha256",HASH));
            mutation("public_wrong_generation_refused",r->r.put("generation",UUID.randomUUID().toString()));
            mutation("public_wrong_display_refused",r->r.put("display_id",8));
            mutation("public_private_protocol_refused",r->r.put("version",BrokerProtocol.PROFILE_VERSION));
            mutation("public_active_not_terminal_refused",r->r.put("state","ACTIVE"));
            mutation("public_custodian_retained_refused",r->r.put("profile_custody_retained",true));
            mutation("public_scope_not_retired_refused",r->r.put("public_scope_admission_retired",false));
            mutation("public_scope_not_closing_refused",r->r.put("public_scope_closing",false));
            mutation("public_preservation_false_refused",r->history(r).put("foreign_dormant_history_preserved",false));
            mutation("public_preservation_string_refused",r->history(r).put("foreign_dormant_history_preserved","true"));
            mutation("public_refusal_latched_refused",r->history(r).put("history_refusal_latched",true));
            mutation("public_refusal_reason_refused",r->history(r).put("history_refusal_reason","PUBLIC_HISTORY_CHANGED"));
            mutation("public_missing_reason_refused",r->history(r).remove("history_refusal_reason"));
            mutation("public_target_absence_false_refused",r->history(r).put("owned_target_absent",false));
            mutation("public_task_ids_cannot_grant_authority",r->history(r).put("serialized_task_ids_grant_authority",true));
            mutation("public_history_wrong_target_refused",r->history(r).put("target_sha256",HASH));
            mutation("public_clock_before_lease_refused",r->history(r).put("baseline_elapsed_ms",999999L));
            mutation("public_clock_reversed_refused",r->history(r).put("current_elapsed_ms",1000000L));
            mutation("public_clock_future_refused",r->history(r).put("current_elapsed_ms",SystemClock.now+1));
            mutation("public_clock_string_refused",r->history(r).put("current_elapsed_ms","1000002"));
            mutation("public_digest_malformed_refused",r->history(r).put("current_raw_sha256","truncated"));
            mutation("public_owned_root_missing_refused",r->history(r).put("owned_task_ids",new JSONArray().put(1234)));
            mutation("public_owned_leaf_missing_refused",r->history(r).put("owned_task_ids",new JSONArray().put(1200)));
            mutation("public_owned_extra_id_refused",r->history(r).put("owned_task_ids",new JSONArray().put(1200).put(1234).put(4321)));
            mutation("public_owned_duplicate_id_refused",r->history(r).put("owned_task_ids",new JSONArray().put(1200).put(1234).put(1234)));
            mutation("public_owned_string_id_refused",r->history(r).put("owned_task_ids",new JSONArray().put(1200).put("1234")));
            mutation("public_owned_fractional_id_refused",r->history(r).put("owned_task_ids",new JSONArray().put(1200).put(1234.0)));
            mutation("public_baseline_duplicate_refused",r->history(r).put("baseline_task_ids",new JSONArray().put(1430).put(1430)));
            mutation("public_baseline_overlap_refused",r->history(r).put("baseline_task_ids",new JSONArray().put(1430).put(1200)));
            mutation("public_baseline_invalid_id_refused",r->history(r).put("baseline_task_ids",new JSONArray().put(0)));
            mutation("public_owned_parent_mismatch_refused",r->r.getJSONObject("profile_cleanup").getJSONArray("owned_tasks").getJSONObject(0).put("parent_task_id",1201));
            mutation("public_foreign_uid_refused",r->r.getJSONObject("profile_cleanup").put("full_uid",1010368));
            test("different_lease_scope_cannot_consume_projection",()->{try(Env e=new Env()){
                PublicOwnGroupPolicy.Scope other=new PublicOwnGroupPolicy.Scope(TASK,HASH,e.session.generation,android.os.Process.myUid(),e.target,
                        e.session.createdElapsed,e.session.expiresElapsed,10);
                reject(()->checked(e.response(),e.target,other,e.session.generation,7,true));
            }});
            test("failed_prepare_done_close_consumes_terminal_projection_without_retry",()->{try(Env e=new Env()){
                e.terminal(e.response(),true);BackgroundSession.Cleanup cleanup=e.session.close();
                need(cleanup.known&&e.session.released());need(!e.journalPresent());need(LocalSocket.connections==0);
                need(cleanup.evidence.getJSONObject("profile_cleanup").getBoolean("display_absence_observed"));
                need(!cleanup.evidence.getJSONObject("last_broker_response").getBoolean("ok"));
            }});
            test("public_close_consumes_authenticated_root_transport_projection",()->{try(Env e=new Env()){
                e.live();LocalSocket.responder=b->e.closeResponse(b,r->{});BackgroundSession.Cleanup cleanup=e.session.close();
                need(cleanup.known&&e.session.released()&&!e.journalPresent());need(LocalSocket.connections==1);
            }});
            test("public_reconcile_and_accept_use_same_typed_scope_contract",()->{try(Env e=new Env()){
                e.live();LocalSocket.responder=b->e.closeResponse(b,r->{});BackgroundSession.Cleanup cleanup=BackgroundSession.reconcile(e.context);
                need(cleanup.known&&!e.journalPresent());e.session.acceptReconciliation(cleanup);need(e.session.released());
                need(e.session.evidence().getJSONObject("profile_cleanup").getBoolean("display_absence_observed"));
            }});
            test("bad_terminal_history_keeps_journal_and_unknown",()->{try(Env e=new Env()){
                JSONObject response=e.response();history(response).put("history_refusal_latched",true);e.terminal(response,true);
                need(!e.session.close().known);need(!e.session.released()&&e.journalPresent());need(LocalSocket.connections==0);
            }});
            test("display_presence_cannot_be_replaced_by_broker_boolean",()->{try(Env e=new Env()){
                e.terminal(e.response(),true);e.context.displays.displays.put(7,new Display(7,e.session.displayName));
                need(!e.session.close().known);need(e.journalPresent()&&!e.session.released());
            }});
            test("journal_unlink_failure_retains_unknown",()->{try(Env e=new Env()){
                e.terminal(e.response(),true);android.system.Os.failUnlink=true;need(!e.session.close().known);
                need(e.journalPresent()&&!e.session.released());
            }});
            test("unlaunched_no_owned_tasks_keeps_foreign_history",()->{try(Env e=new Env()){
                JSONObject response=e.response();response.getJSONObject("profile_cleanup").put("owned_tasks",new JSONArray());
                history(response).put("owned_task_ids",new JSONArray());e.terminal(response,false);
                need(e.session.close().known);need(!e.journalPresent());
            }});
            test("launch_attempt_without_owned_leaf_remains_unknown",()->{try(Env e=new Env()){
                JSONObject response=e.response();response.getJSONObject("profile_cleanup").put("owned_tasks",new JSONArray());
                history(response).put("owned_task_ids",new JSONArray().put(1200));e.terminal(response,true);
                need(!e.session.close().known);need(e.journalPresent());
            }});
            if(args.length>1&&!"-".equals(args[1]))actual(Paths.get(args[1]),false);
        }
        JSONObject report=new JSONObject().put("schema","hepta.public-profile-cleanup-host-tests.v1").put("all_pass",true)
                .put("cases",cases.size()).put("assertions",assertions).put("case_names",new JSONArray(cases)).put("phone_actions",0)
                .put("actual_full_background_session",true).put("android_clock_display_root_transport_are_fakes",true)
                .put("actual_archived_broker_projection_replayed",args.length>1&&!"-".equals(args[1]))
                .put("actual_device_cleanup_granted_by_this_test",false).put("legacy_reproduction",legacy);
        Files.write(Paths.get(args[0]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(report.toString());
    }
}
