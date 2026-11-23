package org.trillionnium.hepta.local;

import android.content.Context;
import android.net.LocalSocket;
import android.os.SystemClock;
import android.view.Display;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Actual ProfileOwnedTask producer, full BackgroundSession consumer, unchanged
 * controller bridge extraction and full NativeAppSession/TCG terminal. Android,
 * model, transport, installed and frame IO remain explicit existing host ports. */
public final class PublicProfileTerminalBridgeHostTest {
    static int checks,consumerRefusals,fullTerminals;
    static final List<String> names=new ArrayList<String>();
    static final List<Map<String,Object>> samples=new ArrayList<Map<String,Object>>();
    interface Test {void run()throws Exception;}
    interface Change {void apply(JSONObject value)throws Exception;}
    static void need(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    static void one(String name,Test test)throws Exception{
        if(names.contains(name))throw new AssertionError("duplicate case");
        LocalSocket.reset();SystemClock.now=1000000;android.provider.Settings.Global.boot=10;android.system.Os.failUnlink=false;
        test.run();names.add(name);System.out.println("PASS "+name);
    }
    static String hash(String text){return NativeAppEvidence.hash(text);}
    static String id(String text){return hash(text).substring(0,32);}
    static boolean yes(Map<String,Object> value,String name){return Boolean.TRUE.equals(value.get(name));}
    static ProfileTarget profile(){return new ProfileTarget(new ProfileIdentity(10,10,0,ProfileIdentity.MANAGED),1010367,
            ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.business.splash.CtripSplashActivity",1779,
            Collections.singletonMap("base",NativeCtripFlightPage.BASE_APK_SHA256),Collections.singleton(hash("synthetic-profile-signer")));}

    static final class Env implements AutoCloseable {
        final Path directory;final Context context;final ProfileTarget target=profile();
        final NativeAppProviderHostTest.Harness raw;final BackgroundSession background;
        final BackgroundSession.Selection selection;final PublicOwnGroupPolicy.Scope scope;
        final PublicProfileBridgeProducer producer;final TaskAuthorization authorization;final TaskAuthorization.Gate owner;
        final TaskCompletionGate gate;final NativeAppSession nativeSession;final String selectionSha;
        final boolean publicMode;final List<Map<String,Object>> journal=new ArrayList<Map<String,Object>>();
        NativeAppEvidence.Frame frame;NotesCompletionEvidence.Frame completion;WindowOwnership window;
        int step;String run;JSONObject produced,wireResponse;BackgroundSession.Cleanup cleanup;
        String actualConsumerRefusal;
        Env(String name,boolean publicMode)throws Exception{
            this.publicMode=publicMode;raw=new NativeAppProviderHostTest.Harness("bridge:"+name);
            directory=Files.createTempDirectory("hepta-native-profile-bridge-").toRealPath();context=new Context(directory.toFile());
            BackgroundTaskTarget execution=BackgroundTaskTarget.resolveExplicitSelection(NativeAppProviderHostTest.OWNER,
                    target.packageName,Collections.singleton(target.packageName),target);
            selection=new BackgroundSession.Selection(execution,publicMode);
            background=publicMode?BackgroundSession.experimentalPublicOwnGroup(context,raw.task,NativeAppProviderHostTest.OWNER,selection,new QualificationScopeConfig.FilesRoot(context))
                    :new BackgroundSession(context,raw.task,NativeAppProviderHostTest.OWNER,selection,new QualificationScopeConfig.FilesRoot(context));
            scope=(PublicOwnGroupPolicy.Scope)PublicProfileCleanupHostTest.field(background,"publicOwnGroupScope");
            raw.time=SystemClock.now+20;producer=new PublicProfileBridgeProducer(target,background.generation,raw.time,publicMode);
            window=producer.window(70,++raw.time);
            authorization=TaskAuthorization.parse(NativeAppProviderHostTest.OWNER).forExecutionSelection(selection);owner=authorization.bind(raw.task);
            selectionSha=hash("synthetic-bound-profile-selection:"+execution.targetSha256);
            nativeSession=new NativeAppSession(raw.task,owner,selection,new NativeAppEvidence.Installed(target),selectionSha,background.generation,7,
                    ()->{if(!raw.installedCurrent)throw new IllegalStateException("synthetic installed identity changed");},
                    (leaf,value)->{Map<String,Object> record=NativeAppEvidence.map();record.put("leaf",leaf);record.put("value",value);journal.add(record);});
            gate=new TaskCompletionGate(raw.task,NativeAppProviderHostTest.OWNER,authorization,selection);gate.bindNativeSession(nativeSession);
        }
        void observe(String fixture)throws Exception{
            NativeAppEvidence.Frame source=raw.frame(fixture);NotesCompletionEvidence.Frame prior=raw.completion;
            completion=new NotesCompletionEvidence.Frame(prior.observationId,prior.packageName,prior.windowId,prior.displayId,
                    background.generation,prior.windowType,prior.metadataObserved,prior.nodesTruncated,prior.nodes);
            window=producer.window(source.windowId,source.capturedElapsedMs);
            frame=new NativeAppEvidence.Frame(raw.task,authorization.instructionSha256,selection.executionTarget().targetSha256,
                    authorization.sha256,selectionSha,source.observationId,source.packageName,background.generation,
                    source.treeSha,source.stateSha,source.screenshotSha,source.sourceRecordSha,TaskCompletionGate.webFrameSha(completion),
                    source.displayId,source.windowId,source.rotation,source.width,source.height,source.left,source.top,source.right,source.bottom,
                    source.capturedElapsedMs,source.nodesTruncated,source.collectionComplete,source.nodes,source.windowType,source.metadataObserved,window);
            nativeSession.observed(frame);gate.observed(completion);
        }
        String purpose(String prefix){for(String value:nativeSession.domain().purposes.values())if(value.startsWith(prefix))return value;return null;}
        ActionDecision action(String purpose)throws Exception{
            String node=null;for(Map.Entry<String,String> row:nativeSession.domain().purposes.entrySet())if(purpose.equals(row.getValue()))node=row.getKey();
            need(node!=null,"real native purpose absent: "+purpose);
            JSONObject value=new JSONObject().put("action","back".equals(node)?"back":"click").put("package",target.packageName).put("observation_id",frame.observationId);
            if(!"back".equals(node))value.put("node_id",node).put("node_label",frame.byId.get(node).label);
            return ActionDecision.parse(value.toString(),ActionDecision.IME_ACTION_SCHEMA);
        }
        void issue(ActionDecision action,boolean dispatched)throws Exception{
            run=id(raw.task+":native-model:"+ ++step);raw.time+=10;owner.check(action,run);
            nativeSession.beforeModelAction(step,action,run,raw.time);
            nativeSession.modelActionOutcome(action,run,true,dispatched,false,hash("synthetic-dispatch-receipt:"+step),++raw.time);
        }
        void perform(String purpose,String fixture)throws Exception{issue(action(purpose),true);observe(fixture);}
        void completeQuery()throws Exception{
            observe("form14.xml");need(purpose("query_observed_form")==null,"owner date cannot invent observed year");
            perform("inspect_departure_year","calendar14.xml");perform("return_from_calendar","form14.xml");
            perform("query_observed_form","result14.xml");need(!gate.verified(completion),"non-target query cannot complete target");
            String next=purpose("navigate_departure_date:");need(next!=null,"actual date transition missing");
            if(next.endsWith("2026-11-16")){perform(next,"result16.xml");next="navigate_departure_date:2026-11-17";}
            perform(next,"result17.xml");need(!gate.verified(completion),"date strip alone cannot replace target form query");
            perform("verify_form_after_result_date","form17.xml");perform("query_observed_form","result17.xml");
            need(gate.verified(completion)&&nativeSession.domain().resultReady,"real full query chain not ready");
            ActionDecision done=ActionDecision.parse(new JSONObject().put("action","done").put("package",target.packageName)
                    .put("observation_id",frame.observationId).put("status","success").put("summary","Host-only native query claim").toString(),ActionDecision.IME_ACTION_SCHEMA);
            issue(done,false);observe("result17-second.xml");need(gate.successClaim(step,run,completion,true).verified,"actual final claim not accepted");
        }
        JSONObject response(JSONObject request,JSONObject proof)throws Exception{
            JSONObject value=new JSONObject().put("version",publicMode?BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION:BrokerProtocol.PROFILE_VERSION)
                    .put("generation",background.generation).put("request_id",request.getString("request_id")).put("state","RELEASED")
                    .put("ok",true).put("operation","close").put("display_id",7).put("display_name",background.displayName)
                    .put("expires_elapsed_ms",background.expiresElapsed).put("profile_target_wire",target.wire())
                    .put("profile_cleanup_known",true).put("profile_custody_retained",false).put("profile_cleanup",proof);
            if(publicMode)value.put("display_scope_sha256",scope.sha256).put("public_scope_admission_retired",true).put("public_scope_closing",true);
            return value;
        }
        BackgroundSession.Cleanup closeValidated(boolean physicalChange,Change change)throws Exception{
            nativeSession.retire();PublicProfileCleanupHostTest.field(background,"displayId",7);
            PublicProfileCleanupHostTest.field(background,"profileLaunchAttempted",true);PublicProfileCleanupHostTest.field(background,"spawnAttempted",true);
            JSONObject reservation=(JSONObject)PublicProfileCleanupHostTest.invoke(background,"baseJournal",new Class<?>[]{});
            MobiMindPrivateFiles.writeNew(directory.resolve(BackgroundSession.JOURNAL).toFile(),reservation.toString().getBytes(StandardCharsets.UTF_8));
            PublicProfileCleanupHostTest.field(background,"state","ACTIVE");context.displays.displays.put(7,new Display(7,background.displayName));
            LocalSocket.responder=bytes->{
                JSONObject request=PublicProfileCleanupHostTest.decode(bytes);need("close".equals(request.getString("op")),"actual client did not request close");
                produced=producer.retire(raw.time+10,physicalChange);need(produced.length()==(publicMode?15:13),"actual producer shape differs");
                SystemClock.now=producer.now()+1;wireResponse=response(request,new JSONObject(produced.toString()));
                if(change!=null){change.apply(wireResponse);
                    try{PublicProfileCleanupHostTest.checked(wireResponse,target,scope,background.generation,7,true);
                        throw new AssertionError("actual BackgroundSession consumer accepted invalid nested/raw proof");}
                    catch(IOException expected){actualConsumerRefusal=expected.getMessage();consumerRefusals++;}}
                context.displays.displays.remove(7);return PublicProfileCleanupHostTest.frame(wireResponse);
            };
            cleanup=background.close();need(LocalSocket.connections==1,"client must consume exactly one real fixture transport response");
            return cleanup;
        }
        Map<String,Object> terminal(Map<String,Object> projection,boolean cancelled,int exit,boolean receipt)throws Exception{
            nativeSession.retire();fullTerminals++;
            return gate.terminalNativeCheck(nativeSession,completion,owner.frame(),step,run,true,cleanup.known,background.released(),true,true,cancelled,
                    true,true,exit,receipt,raw.task,id("synthetic-worker:"+raw.task),hash("synthetic-normal0-parent-receipt"),projection).evidence;
        }
        public void close()throws IOException{
            android.system.Os.failUnlink=false;LocalSocket.reset();
            try(java.util.stream.Stream<Path> paths=Files.walk(directory)){
                for(Path path:paths.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(path);
            }
        }
    }
    static Map<String,Object> projected(BackgroundSession.Cleanup cleanup){return ControllerProfileCleanupFixture.current(cleanup);}
    static void readyAndClose(Env e,boolean changed)throws Exception{e.completeQuery();e.closeValidated(changed,null);need(e.cleanup.known&&e.background.released(),"validated cleanup required");}
    static void intact(BackgroundSession.Cleanup cleanup,String before){need(before.equals(cleanup.evidence.toString()),"bridge rewrote original full cleanup evidence");}
    static void projectionMutation(String label,Change change)throws Exception{
        one(label,()->{try(Env e=new Env(label,true)){
            e.closeValidated(false,null);need(e.cleanup.known,"actual full consumer must first validate the original proof");
            JSONObject record=new JSONObject(e.cleanup.evidence.toString());change.apply(record.getJSONObject("profile_cleanup"));
            need(projected(new BackgroundSession.Cleanup(true,record))==null,"bridge accepted unknown or incomplete shape/type");
        }});
    }
    static void consumerMutation(String label,Change change)throws Exception{
        one(label,()->{try(Env e=new Env(label,true)){
            e.completeQuery();e.closeValidated(true,change);
            need(e.actualConsumerRefusal!=null&&!e.actualConsumerRefusal.isEmpty(),"failure must be in actual nested BackgroundSession consumer");
            need(!e.cleanup.known&&!e.background.released(),"invalid history must keep actual cleanup unknown");
            need(projected(e.cleanup)==null,"unknown cleanup cannot project");
            Map<String,Object> end=e.terminal(projected(e.cleanup),false,0,true);
            need(!yes(end,"completion_verified")&&!yes(end,"profile_cleanup_bound_to_final_window"),"invalid history became terminal completion");
        }});
    }
    public static void main(String[] args)throws Exception{
        NativeAppProviderHostTest.fixtures=Paths.get(args[0]);Path output=Paths.get(args[1]);
        boolean legacy=args.length>2&&"legacy".equals(args[2]);
        if(legacy){
            one("r17_old_bridge_loses_valid_public_cleanup_and_full_terminal_refuses",()->{try(Env e=new Env("old",true)){
                readyAndClose(e,true);String untouched=e.cleanup.evidence.toString();
                need(e.produced.length()==15&&e.cleanup.evidence.getJSONObject("profile_cleanup").length()==16,"real producer/consumer 15/16 shape required");
                Map<String,Object> old=ControllerProfileCleanupFixture.legacy(e.cleanup);need(old==null,"exact old bridge failure absent");
                Map<String,Object> end=e.terminal(old,false,0,true);
                need(!yes(end,"completion_verified")&&!yes(end,"profile_cleanup_bound_to_final_window"),"old full terminal must refuse");
                for(String key:Arrays.asList("same_final_native_result_snapshot","model_success_claim_verified","all_cleanup_known","background_released",
                        "scope_rechecked_after_worker_exit","installed_app_rechecked_after_cleanup","owner_rechecked","native_normal0_parent_session_bound"))need(yes(end,key),"old counterexample has unrelated failure: "+key);
                intact(e.cleanup,untouched);samples.add(end);
            }});
        }else{
            for(final boolean changed:new boolean[]{false,true})one("v2_real_producer_full_native_terminal_"+(changed?"with_user_foreground_change":"with_static_foreground"),()->{try(Env e=new Env("v2:"+changed,true)){
                readyAndClose(e,changed);String untouched=e.cleanup.evidence.toString();JSONObject raw=e.cleanup.evidence.getJSONObject("profile_cleanup");
                need(e.produced.length()==15&&raw.length()==16,"real producer and app terminal extension required");
                need(raw.getJSONObject("public_foreign_recent_history").getBoolean("unrelated_physical_history_changes_observed")==changed,"actual producer activity audit differs");
                Map<String,Object> map=projected(e.cleanup);need(map!=null&&map.size()==14,"native terminal requires only its original fourteen fields");
                need(NativeAppSession.profileCleanupBound(e.target,e.window,map),"exact final profile window must bind");
                Map<String,Object> end=e.terminal(map,false,0,true);need(yes(end,"completion_verified")&&yes(end,"profile_cleanup_bound_to_final_window"),"full native terminal did not complete");
                intact(e.cleanup,untouched);need(e.producer.mutations().equals(Arrays.asList("create","bind","remove_leaf","delete_root")),"producer performed unrelated mutation");samples.add(end);
            }});
            one("private_real_producer_legacy_fourteen_field_terminal_unchanged",()->{try(Env e=new Env("private",false)){
                readyAndClose(e,false);String untouched=e.cleanup.evidence.toString();need(e.produced.length()==13,"original private producer required");
                Map<String,Object> map=projected(e.cleanup);need(map!=null&&map.size()==14,"private native terminal shape differs");
                need(yes(e.terminal(map,false,0,true),"completion_verified"),"private terminal regressed");intact(e.cleanup,untouched);
            }});
            one("public_v1_original_full_consumer_and_legacy_native_binding_remain_accepted",()->{try(PublicProfileCleanupHostTest.Env e=new PublicProfileCleanupHostTest.Env()){
                e.live();LocalSocket.responder=b->e.closeResponse(b,r->{});BackgroundSession.Cleanup cleanup=e.session.close();need(cleanup.known,"original v1 consumer rejected");
                JSONObject raw=cleanup.evidence.getJSONObject("profile_cleanup");String untouched=cleanup.evidence.toString();JSONObject row=raw.getJSONArray("owned_tasks").getJSONObject(0);
                WindowOwnership window=new WindowOwnership(e.target,e.session.generation,7,70,row.getInt("task_id"),row.getInt("parent_task_id"),row.getString("task_token_id"),
                        UUID.randomUUID().toString(),10,20,1010367,SystemClock.now,SystemClock.now+1000);
                Map<String,Object> map=projected(cleanup);need(raw.length()==16&&map!=null&&map.size()==14,"v1 retains full source but narrow projection");
                need(NativeAppSession.profileCleanupBound(e.target,window,map),"unchanged native contract rejected v1 projection");intact(cleanup,untouched);
            }});
            consumerMutation("consumer_refuses_missing_public_history",r->r.getJSONObject("profile_cleanup").remove("public_foreign_recent_history"));
            consumerMutation("consumer_refuses_unknown_top_level_cleanup_field",r->r.getJSONObject("profile_cleanup").put("unknown",true));
            consumerMutation("consumer_refuses_unknown_nested_history_field",r->r.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("unknown",true));
            consumerMutation("consumer_refuses_foreign_history_target",r->r.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("target_sha256",hash("foreign target")));
            consumerMutation("consumer_refuses_missing_owned_root",r->r.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("owned_task_ids",new JSONArray().put(300)));
            consumerMutation("consumer_refuses_changed_protected_history",r->r.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("current_protected_history_sha256",hash("changed protected history")));
            consumerMutation("consumer_refuses_nonphysical_preservation_false",r->r.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("nonphysical_history_preserved",false));
            consumerMutation("consumer_refuses_history_refusal_latched",r->r.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("history_refusal_latched",true));
            consumerMutation("consumer_refuses_physical_frozen_claim",r->r.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("physical_history_frozen",true));
            consumerMutation("consumer_refuses_untyped_user_activity_flag",r->r.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("unrelated_physical_history_changes_observed","true"));
            consumerMutation("consumer_refuses_mismatched_absence_scope",r->r.getJSONObject("profile_cleanup").put("recents_absence_scope","owned_target_only_with_foreign_history_preserved"));
            projectionMutation("bridge_refuses_unknown_seventeenth_field",p->p.put("unknown",true));
            projectionMutation("bridge_refuses_missing_core_field",p->p.remove("display_absence_observed"));
            projectionMutation("bridge_refuses_lone_history_extension",p->p.remove("recents_absence_scope"));
            projectionMutation("bridge_refuses_lone_scope_extension",p->p.remove("public_foreign_recent_history"));
            projectionMutation("bridge_refuses_string_history",p->p.put("public_foreign_recent_history",p.getJSONObject("public_foreign_recent_history").toString()));
            projectionMutation("bridge_refuses_object_scope",p->p.put("recents_absence_scope",new JSONObject()));
            projectionMutation("bridge_refuses_unknown_history_schema",p->p.getJSONObject("public_foreign_recent_history").put("schema","unknown"));
            projectionMutation("bridge_refuses_schema_scope_mismatch",p->p.put("recents_absence_scope","owned_target_only_with_foreign_history_preserved"));
            projectionMutation("bridge_refuses_object_in_scalar_field",p->p.put("generation",new JSONObject()));
            projectionMutation("bridge_refuses_fractional_display_id",p->p.put("display_id",7.0));
            projectionMutation("bridge_refuses_nonarray_owned_tasks",p->p.put("owned_tasks",new JSONObject()));
            projectionMutation("bridge_refuses_excess_owned_task_rows",p->{JSONObject row=p.getJSONArray("owned_tasks").getJSONObject(0);JSONArray rows=new JSONArray();for(int i=0;i<33;i++)rows.put(row);p.put("owned_tasks",rows);});
            one("projection_is_deeply_immutable_and_does_not_alias_full_evidence",()->{try(Env e=new Env("immutable",true)){
                e.closeValidated(false,null);Map<String,Object> map=projected(e.cleanup);need(map!=null,"valid projection missing");String original=e.cleanup.evidence.toString();
                try{map.clear();throw new AssertionError("mutable root");}catch(UnsupportedOperationException expected){checks++;}
                List<?> rows=(List<?>)map.get("owned_tasks");try{rows.clear();throw new AssertionError("mutable rows");}catch(UnsupportedOperationException expected){checks++;}
                Map<?,?> row=(Map<?,?>)rows.get(0);try{row.clear();throw new AssertionError("mutable row");}catch(UnsupportedOperationException expected){checks++;}
                intact(e.cleanup,original);e.cleanup.evidence.getJSONObject("profile_cleanup").getJSONArray("owned_tasks").getJSONObject(0).put("full_uid",10367);
                need(((Number)row.get("full_uid")).intValue()==1010367,"projection aliases original mutable JSON");
            }});
            one("unchanged_native_contract_rejects_foreign_uid_and_string_boolean",()->{try(Env e=new Env("native-types",true)){
                e.closeValidated(false,null);Map<String,Object> map=projected(e.cleanup);need(map!=null,"valid projection missing");
                Map<String,Object> changed=new LinkedHashMap<String,Object>(map);changed.put("full_uid",10367);need(!NativeAppSession.profileCleanupBound(e.target,e.window,changed),"foreign UID accepted");
                changed=new LinkedHashMap<String,Object>(map);changed.put("cleanup_known","true");need(!NativeAppSession.profileCleanupBound(e.target,e.window,changed),"string Boolean accepted");
                changed=new LinkedHashMap<String,Object>(map);changed.put("public_foreign_recent_history",Collections.emptyMap());need(!NativeAppSession.profileCleanupBound(e.target,e.window,changed),"native fourteen-field contract expanded");
            }});
            one("unknown_or_missing_cleanup_never_projects",()->{need(projected(null)==null,"null cleanup accepted");
                need(projected(new BackgroundSession.Cleanup(false,new JSONObject()))==null,"unknown cleanup accepted");
                need(projected(new BackgroundSession.Cleanup(true,new JSONObject()))==null,"missing profile cleanup accepted");});
            for(final String mode:Arrays.asList("cancelled","nonzero_exit","invalid_receipt"))one("valid_projection_does_not_override_"+mode,()->{try(Env e=new Env(mode,true)){
                readyAndClose(e,true);Map<String,Object> map=projected(e.cleanup);need(map!=null,"valid projection missing");
                Map<String,Object> end=e.terminal(map,"cancelled".equals(mode),"nonzero_exit".equals(mode)?70:0,!"invalid_receipt".equals(mode));
                need(yes(end,"profile_cleanup_bound_to_final_window")&&!yes(end,"completion_verified"),"projection overrode original terminal gate");
            }});
        }
        JSONObject result=new JSONObject().put("schema","hepta.public-profile-terminal-bridge-cases.v1").put("all_pass",true)
                .put("mode",legacy?"legacy_counterexample":"candidate").put("case_names",new JSONArray(names)).put("cases",names.size()).put("assertions",checks)
                .put("real_nested_consumer_refusals",consumerRefusals).put("full_native_terminal_calls",fullTerminals)
                .put("old_bridge_full_terminal_reproduced",legacy).put("terminal_samples",new JSONArray(samples))
                .put("actual_profile_owned_task_producer",true).put("actual_background_session_consumer",true).put("actual_native_session_terminal",true)
                .put("controller_bridge_verbatim_extraction",true).put("full_android_controller_compiled_or_executed",false)
                .put("framework_model_installed_and_worker_io_synthetic",true).put("phone_operations",0).put("native_model_executed",false).put("android_runtime",false);
        Files.write(output,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(result.toString());
    }
}
