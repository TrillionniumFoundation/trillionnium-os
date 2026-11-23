package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.SystemClock;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.PersonalNotesAbsenceHostTest;
import org.trillionnium.hepta.background.PublicPersonalNotesAbsenceRecovery;
import org.trillionnium.hepta.background.RecoveryControllerIdentity;

/** Authored one-step failure. Android/process/absence observations remain explicit
 * fixtures; real Request, generation validator, client and durable byte reads run. */
public final class PersonalNotesPostModelHostTest {
    private static int cases,assertions;private static final JSONArray names=new JSONArray();
    private interface Work {void run()throws Exception;}
    private interface Change {void run(JSONObject object)throws Exception;}
    private static void need(boolean value){assertions++;if(!value)throw new AssertionError("post-model recovery boundary");}
    private static void refuse(Work work)throws Exception{try{work.run();}catch(Exception expected){assertions++;return;}throw new AssertionError("unsafe recovery accepted");}
    private static void test(String name,Work work)throws Exception{work.run();cases++;names.put(name);}
    private static JSONObject obj(byte[] raw){return new JSONObject(new String(raw,StandardCharsets.UTF_8));}
    private static byte[] raw(Object value){return value.toString().getBytes(StandardCharsets.UTF_8);}
    private static String hash(byte[] raw){return HeptaAccessibilityService.sha(raw);}
    private static JSONObject copy(JSONObject value){return obj(raw(value));}
    private static void flags(JSONObject value,boolean flag,String... keys){for(String key:keys)value.put(key,flag);}
    private static void nulls(JSONObject value,String... keys){for(String key:keys)value.put(key,JSONObject.NULL);}
    static final class Fixture {
        final PersonalNotesAbsenceHostTest.Fixture base=new PersonalNotesAbsenceHostTest.Fixture();
        final Map<String,byte[]> inputs=new LinkedHashMap<String,byte[]>(base.inputs);
        final String worker="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",run="cccccccccccccccccccccccccccccccc",obs="dddddddddddddddddddddddddddddddd";
        final String scope="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",nonce="ffffffffffffffffffffffffffffffff",boot="22222222-3333-4444-8555-666666666666";
        final String earlyId="aaaaaaaa-1111-4111-8111-111111111111",lastId="bbbbbbbb-2222-4222-8222-222222222222";
        final String pkg=PublicPersonalNotesAbsenceRecovery.PACKAGE;
        Fixture()throws Exception {
            JSONObject bootstrap=get("bootstrap"),cleanup=get("cleanup"),last=cleanup.getJSONObject("last_broker_response");
            JSONObject early=copy(last);early.put("request_id",earlyId).put("operation","launch").put("state","ACTIVE").put("ok",true).put("dispatched",true);
            early.getJSONObject("task_launch_policy").put("request_id",earlyId);
            early.getJSONObject("public_task_location").put("observed_elapsed_ms",base.created+2);
            JSONObject row=new JSONObject().put("task_id",base.oldTask).put("user_id",0).put("actual_effective_uid",base.targetUid)
                    .put("display_id",base.display).put("parent_id",-1).put("token_identity_in_broker",700).put("serialized_token_grants_authority",false);
            early.getJSONObject("personal_notes_cleanup").put("actual_observed_tasks",new JSONArray().put(row));
            last.put("request_id",lastId).put("operation","notes.create").put("state","CLEANUP_UNKNOWN").put("ok",false).put("dispatched",true).put("public_scope_admission_retired",true);
            last.getJSONObject("task_launch_policy").put("request_id",lastId).put("component",pkg+"/.TextNote");
            last.getJSONObject("public_task_location").put("observed_elapsed_ms",base.created+50).put("observed_owned_task_ids",new JSONArray().put(base.oldTask).put(base.oldTask+1));
            last.getJSONObject("personal_notes_cleanup").put("actual_observed_tasks",new JSONArray().put(copy(row)).put(copy(row).put("task_id",base.oldTask+1).put("token_identity_in_broker",701)));
            JSONObject terminal=obj(inputs.get("broker_output")).put("personal_notes_cleanup",last.getJSONObject("personal_notes_cleanup"));
            inputs.put("broker_output",raw(terminal));JSONObject broker=get("broker_receipt");broker.put("stored_bytes",inputs.get("broker_output").length)
                    .put("observed_bytes",inputs.get("broker_output").length).put("stored_sha256",hash(inputs.get("broker_output")));put("broker_receipt",broker);
            bootstrap.put("last_broker_response",early).put("broker_output",copy(broker).put("stored_bytes",0).put("observed_bytes",0).put("stored_sha256",hash(new byte[0])).put("persisted",false));
            cleanup.put("broker_output",broker);put("bootstrap",bootstrap);
            String auth=get("owner").getString("task_authorization_sha256"),payload=hash(raw("synthetic draft text"));
            JSONObject target=new JSONObject().put("source","installed_package_manager").put("action","notes.create").put("package",pkg).put("component",pkg+"/.TextNote").put("target_uid",base.targetUid);
            flags(target,true,"exported","activity_enabled","application_enabled","declared_intent_filter_matched","ordinary_caller_permission_checked");nulls(target,"required_permission");
            JSONObject attempt=new JSONObject().put("schema","hepta.fixed-intent-attempt.v1").put("stage","consumed_before_call").put("task_id",base.task)
                    .put("model_run_id",run).put("observation_id",obs).put("source_package",pkg).put("source_window_id",900).put("display_id",base.display)
                    .put("background_generation",base.gen).put("target",target).put("action","notes.create").put("payload_sha256",payload)
                    .put("attempt_id",hash(raw("synthetic attempt"))).put("attempt_ordinal",1).put("attempt_consumed",true).put("automatic_retry_allowed",false);
            put("fixed_intent_attempt",attempt);JSONObject fixed=copy(attempt);fixed.remove("stage");fixed.put("schema","hepta.fixed-intent-result.v1").put("dispatch_attempted",true)
                    .put("api_accepted",JSONObject.NULL).put("result","unknown").put("requested_outcome","draft_opened").put("goal_independently_verified",false).put("saved_or_search_results_verified",false);
            last.put("fixed_intent",new JSONObject().put("schema","hepta.background-fixed-intent.v1").put("target",target).put("request_id",lastId).put("generation",base.gen)
                    .put("display_id",base.display).put("ordinary_caller_uid",base.uid).put("action","notes.create").put("attempt_id",attempt.get("attempt_id"))
                    .put("payload_sha256",payload).put("attempt_consumed",true).put("goal_independently_verified",false));
            JSONObject work=new JSONObject().put("schema","hepta.action-execution.v1").put("execution_kind","serial_action_worker")
                    .put("operation_id","11111111111111111111111111111111").put("task_id",base.task).put("model_run_id",run).put("observation_id",obs)
                    .put("authorization_sha256",auth).put("display_id",base.display).put("background_generation",base.gen).put("window_id",900)
                    .put("queued_elapsed_ms",base.created+50).put("worker_drained_elapsed_ms",base.created+60).put("deadline_elapsed_ms",base.created+8000);
            flags(work,true,"effect_entered","worker_drained","callback_published","callback_authority_current");flags(work,false,"effect_returned","retired","phases_truncated","automatic_redispatch");nulls(work,"api_accepted","retirement_reason");
            JSONObject issued=new JSONObject().put("action","notes.create").put("package",pkg).put("observation_id",obs).put("text","synthetic draft text");
            put("step_model",new JSONObject().put("run_id",run).put("observation_id",obs).put("original_instruction_sha256",base.ownerHash).put("raw_text",issued.toString()));
            JSONObject result=get("result"),gate=result.getJSONObject("task_authorization");gate.put("catalogue_sha256",hash(raw("synthetic catalogue")))
                    .put("last_check",new JSONObject().put("schema","hepta.owner-action-check.v1").put("task_id",base.task).put("authorization_sha256",auth)
                            .put("model_run_id",run).put("action","notes.create").put("target_package",pkg).put("allowed",true));
            JSONObject action=new JSONObject().put("model_run_id",run).put("action",issued).put("action_execution",work).put("fixed_intent",fixed)
                    .put("task_authorization",copy(gate).put("callback_lease_current",true).put("callback_cancelled",false)).put("task_authorization_sha256",auth);
            flags(action,true,"dispatched","model_issued");flags(action,false,"accepted","stale","done_success_eligible");put("step_action",action);
            result.put("steps",1).put("last_action_execution",work).put("fixed_intent_attempts",new JSONArray().put(fixed)).put("final_observation_id",obs).put("terminal_decided_elapsed_ms",base.created+1000);put("result",result);syncCleanup(cleanup);
            JSONObject nativeRequest=new JSONObject().put("schema","hepta.geniex-task-request.result.v1").put("worker_generation",worker).put("task_id",base.task)
                    .put("request_id",run).put("request_sequence",1).put("pid",500).put("request_status",0).put("raw_text_sha256",hash(raw(issued)));
            flags(nativeRequest,false,"process_exit_observed","automatic_retry");
            JSONObject request=new JSONObject().put("schema","hepta.local-model.task-request.v1").put("task_id",base.task).put("worker_generation",worker).put("run_id",run)
                    .put("app_uid",base.uid).put("app_pid",99).put("worker_pid",500).put("request_sequence",1).put("grammar_observation_id",obs).put("grammar_current_package",pkg)
                    .put("raw_text_sha256_read",hash(raw(issued))).put("exit_code",JSONObject.NULL).put("status","request_completed").put("native_receipt",nativeRequest);
            flags(request,true,"process_started","inference_completed","request_committed","native_result_binding_valid");
            flags(request,false,"process_exit_observed","caller_cancellation_requested","cancel_requested","timeout_observed","force_destroy_sent","automatic_retry");put("model_request_receipt",request);
            JSONObject n=new JSONObject().put("schema","hepta.geniex-task-session.result.v1").put("worker_generation",worker).put("task_id",base.task).put("pid",500)
                    .put("last_request_status",0).put("signal_observed",0).put("sdk_exception_boundary",new JSONObject().put("caught",false).put("automatic_retry",false));
            flags(n,false,"process_exit_observed","control_channel_write_failed");flags(n,true,"model_metadata_unchanged_before_close","close_requested","sdk_destroy_attempted","sdk_deinit_attempted");
            for(String k:new String[]{"requests_received","requests_completed","model_hash_count","sdk_init_count","model_create_count","model_reset_count","control_done_attempts","control_done_delivered"})n.put(k,1);
            for(String k:new String[]{"sdk_destroy_rc","sdk_deinit_rc","control_channel_last_errno","last_request_return_status"})n.put(k,0);put("native_session_receipt",n);
            JSONObject g=new JSONObject().put("schema","hepta.worker-generation.app-cleanup.v1").put("task_id",base.task).put("worker_generation",worker).put("scope_token",scope)
                    .put("app_uid",base.uid).put("app_pid",99).put("app_start_ticks",100).put("boot_id",boot).put("cleanup_nonce",nonce)
                    .put("finisher_submitted_monotonic_ns",1200000000L).put("finisher_deadline_monotonic_ns",45200000000L)
                    .put("submitted_monotonic_ns",1210000000L).put("deadline_monotonic_ns",5210000000L).put("helper_finalization_reserve_ns",1500000000L)
                    .put("helper_exit_code",0).put("error",JSONObject.NULL).put("scope","pinned_sdk_inheriting_process_group_and_generation_markers");
            flags(g,true,"direct_process_exit_observed","helper_started","helper_exit_observed","cleanup_known","descendant_force_known","generation_unforced");flags(g,false,"helper_force_destroy_sent","helper_currently_alive","descendant_force_used","automatic_retry");
            JSONObject nativeCleanup=new JSONObject().put("schema","hepta.worker-generation.cleanup.v1");
            for(String k:new String[]{"task_id","worker_generation","scope_token","app_uid","app_pid","app_start_ticks","boot_id","cleanup_nonce"})nativeCleanup.put(k,g.get(k));
            nativeCleanup.put("leader_pid",500).put("leader_start_ticks",200).put("pgid",500).put("helper_pid",501).put("helper_uid",base.uid).put("helper_parent_pid",99)
                    .put("helper_start_ticks",201).put("helper_pgid",999).put("started_monotonic_ns",1220000000L).put("ended_monotonic_ns",1330000000L)
                    .put("deadline_monotonic_ns",5210000000L).put("scans",2).put("empty_readbacks",2).put("failure","none").put("targets",new JSONArray());
            flags(nativeCleanup,true,"cleanup_known","scan_complete","pidfd_supported","group_presence_probe_used");flags(nativeCleanup,false,"numeric_pid_signal_used","group_signal_used","sdk_called","worker_started");
            for(String k:new String[]{"remaining_owned_count","unknown_count","escaped_generation_count","term_attempts","kill_attempts","group_presence_probe_signal"})nativeCleanup.put(k,0);
            JSONArray observations=new JSONArray();for(long t:new long[]{1220000000L,1330000000L})observations.put(new JSONObject().put("pgid",500).put("monotonic_ns",t).put("result",-1).put("errno",3));nativeCleanup.put("group_presence_observations",observations);
            StringBuilder identity=new StringBuilder("hepta.worker-generation.v1\n");for(String k:new String[]{"task_id","worker_generation","scope_token","app_uid","app_pid","app_start_ticks","leader_pid","leader_start_ticks","pgid","boot_id"})identity.append(k).append('=').append(nativeCleanup.get(k)).append('\n');
            inputs.put("generation_identity",raw(identity));g.put("identity_sha256",hash(raw(identity)));nativeCleanup.put("identity_sha256",hash(raw(identity)));
            JSONObject session=new JSONObject().put("schema","hepta.local-model.task-session.v1").put("task_id",base.task).put("worker_generation",worker).put("app_uid",base.uid).put("app_pid",99)
                    .put("exit_code",0).put("requests_sent",1).put("requests_accepted",1).put("cleanup_classification","normal_close_with_observed_sdk_cleanup")
                    .put("finisher_submitted_monotonic_ns",1200000000L).put("finisher_deadline_monotonic_ns",45200000000L).put("native_session_receipt",n).put("worker_generation_cleanup",g);
            flags(session,true,"process_started","process_exit_observed","cleanup_known","native_session_binding_valid","generation_cleanup_known","generation_unforced");
            flags(session,false,"caller_cancellation_requested","cancel_requested","force_destroy_sent","parent_force_destroy_sent","automatic_restart","cross_task_reuse");
            for(JSONObject receipt:new JSONObject[]{request,session}){boolean closed=receipt==session;
                JSONObject cancellation=new JSONObject().put("schema","hepta.owned-worker-cancellation.v1").put("task_id",base.task).put("worker_generation",worker)
                        .put("term_destroy_attempts",0).put("force_destroy_attempts",0).put("signal_error",JSONObject.NULL).put("process_exit_observed",closed).put("exit_code",closed?0:JSONObject.NULL);
                flags(cancellation,true,"process_bound");flags(cancellation,false,"requested","termination_started","term_destroy_returned","force_destroy_returned","sdk_cleanup_proven_by_this_object");
                receipt.put("owned_worker_cancellation",cancellation);
            }
            put("model_request_receipt",request);put("model_session_receipt",session);syncGeneration(nativeCleanup);bindRunPaths("/synthetic/files");
        }
        JSONObject get(String key){return obj(inputs.get(key));}void put(String key,JSONObject value){inputs.put(key,raw(value));}
        void mutate(String key,Change change)throws Exception{JSONObject v=get(key);change.run(v);put(key,v);}
        void syncCleanup(JSONObject cleanup){put("cleanup",cleanup);JSONObject result=get("result"),session=copy(cleanup);session.remove("cleanup_known");session.remove("cleanup_error");result.put("background_cleanup",cleanup).put("background_session",session);put("result",result);}
        void syncTerminal(JSONObject terminal){
            put("broker_output",terminal);JSONObject broker=get("broker_receipt");
            broker.put("stored_bytes",inputs.get("broker_output").length).put("observed_bytes",inputs.get("broker_output").length)
                    .put("stored_sha256",hash(inputs.get("broker_output")));put("broker_receipt",broker);
            JSONObject cleanup=get("cleanup");cleanup.put("broker_output",broker);syncCleanup(cleanup);
        }
        void releasedCustodies(Change change)throws Exception{
            JSONObject cleanup=get("cleanup"),terminal=get("broker_output");
            change.run(cleanup.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup"));
            change.run(terminal.getJSONObject("personal_notes_cleanup"));syncCleanup(cleanup);syncTerminal(terminal);
        }
        Fixture released()throws Exception{
            JSONObject cleanup=get("cleanup"),last=cleanup.getJSONObject("last_broker_response");
            JSONObject custody=copy(last.getJSONObject("personal_notes_cleanup")).put("schema","hepta.public-personal-notes-cleanup.v2")
                    .put("absence_reads",2).put("pending_owned_reads",8).put("failure","")
                    .put("history_preservation_scope","nonphysical_and_unresolved_recents")
                    .put("history_preservation_interval","pre_release_to_absence")
                    .put("hidden_history_preservation_interval","initial_to_absence");
            flags(custody,true,"cleanup_known","pre_release_tasks_verified","release_api_entered","release_api_returned",
                    "display_absence_verified","live_tasks_absent","all_recents_sections_absent","prior_hidden_history_preserved",
                    "nonphysical_history_preserved","nonphysical_hidden_history_preserved");
            flags(custody,false,"identity_unknown","custodian_retained","no_display_create_attempted","physical_history_frozen",
                    "unrelated_physical_history_changes_observed","recents_presentation_changes_observed");
            for(String key:new String[]{"initial_recents_sha256","pre_release_recents_sha256","final_recents_sha256"})
                custody.put(key,hash(raw("synthetic "+key)));
            last.put("state","RELEASED").put("public_scope_closing",true).put("personal_notes_cleanup",custody);
            cleanup.put("broker_process_exit_observed",true).put("broker_process_exit_code",0)
                    .put("cleanup_error","NOTES_CLEANUP_ROOT_SCOPE_UNBOUND");syncCleanup(cleanup);
            JSONObject broker=get("broker_receipt");broker.put("eof_seen",true);put("broker_receipt",broker);
            JSONObject terminal=get("broker_output").put("state","RELEASED").put("release_confirmed",true)
                    .put("personal_notes_cleanup",copy(custody));syncTerminal(terminal);return this;
        }
        void syncSession(JSONObject session){put("model_session_receipt",session);JSONObject result=get("result");result.put("model_session",new JSONObject().put("task_id",base.task).put("worker_generation",worker).put("process_started",true).put("process_exit_observed",true).put("exit_code",0).put("receipt_valid",true).put("app_receipt_sha256",hash(inputs.get("model_session_receipt"))));put("result",result);}
        void syncGeneration(JSONObject value){put("generation_cleanup_receipt",value);JSONObject session=get("model_session_receipt"),g=session.getJSONObject("worker_generation_cleanup");g.put("native_cleanup",value).put("native_receipt_sha256",hash(inputs.get("generation_cleanup_receipt")));syncSession(session);}
        void syncNative(JSONObject value){put("native_session_receipt",value);JSONObject session=get("model_session_receipt");session.put("native_session_receipt",value);syncSession(session);}
        void syncAction(JSONObject value){JSONObject result=get("result"),action=get("step_action");result.put("last_action_execution",value);action.put("action_execution",value);put("result",result);put("step_action",action);}
        void bindRunPaths(String root){JSONObject session=get("model_session_receipt"),g=session.getJSONObject("worker_generation_cleanup");g.put("identity_file",root+"/runs/"+worker+"/worker-generation.identity").put("native_receipt_file",root+"/runs/"+worker+"/generation-cleanup-"+nonce+".json");syncSession(session);}
        PublicPersonalNotesAbsenceRecovery.Request request()throws Exception{return PublicPersonalNotesAbsenceRecovery.request(inputs,raw(base.control),base.controller,base.uid,"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",base.now,base.boot);}
        void full()throws Exception{PublicPersonalNotesRecoveryClient.requireDrainedGeneration(request());}
    }
    static final class Env implements AutoCloseable {
        final Fixture fixture;final Path root,task,journal;final Context context;final Map<Path,byte[]> originals=new LinkedHashMap<Path,byte[]>();
        Env()throws Exception{this(false);}
        Env(boolean released)throws Exception{
            fixture=released?new Fixture().released():new Fixture();root=Files.createTempDirectory("notes-post-model-host-").toRealPath();context=new Context(root.toFile());fixture.bindRunPaths(root.toString());
            MobiMindPrivateFiles.directory(root.resolve("control-tasks").toFile(),true);task=root.resolve("control-tasks").resolve(fixture.base.task);MobiMindPrivateFiles.directory(task.toFile(),true);
            MobiMindPrivateFiles.directory(root.resolve("runs").toFile(),true);Path run=root.resolve("runs").resolve(fixture.run),worker=root.resolve("runs").resolve(fixture.worker);MobiMindPrivateFiles.directory(run.toFile(),true);MobiMindPrivateFiles.directory(worker.toFile(),true);
            journal=root.resolve(BackgroundSession.JOURNAL);write(journal,fixture.inputs.get("journal"));write(root.resolve("control-session.json"),raw(fixture.base.control));
            String[][] pairs={{"owner","owner.json"},{"bootstrap","background-bootstrap.json"},{"cleanup","background-cleanup.json"},{"result","result.json"},{"broker_receipt","background-broker-"+fixture.base.gen+".json"},{"broker_output","background-broker-"+fixture.base.gen+".bin"},{"step_model","step-01-model-0.json"},{"step_action","step-01-action.json"},{"fixed_intent_attempt","fixed-intent-01-attempt.json"}};
            for(String[] pair:pairs)write(task.resolve(pair[1]),fixture.inputs.get(pair[0]));
            write(run.resolve("app-receipt.json"),fixture.inputs.get("model_request_receipt"));write(worker.resolve("app-session-receipt.json"),fixture.inputs.get("model_session_receipt"));
            write(worker.resolve("native-session-result.json"),fixture.inputs.get("native_session_receipt"));write(worker.resolve("worker-generation.identity"),fixture.inputs.get("generation_identity"));write(worker.resolve("generation-cleanup-"+fixture.nonce+".json"),fixture.inputs.get("generation_cleanup_receipt"));
            android.os.Looper.worker=true;android.provider.Settings.Global.boot=fixture.base.boot;SystemClock.now=fixture.base.now;
            FakePersonalNotesRecoveryProcess.reset();RecoveryControllerIdentity.changed=false;android.system.Os.corruptPublicArchiveOnSync=false;android.system.Os.afterPublicCommitSync=null;android.system.Os.failFsyncPath=null;
        }
        void write(Path path,byte[] value)throws Exception{MobiMindPrivateFiles.writeNew(path.toFile(),value);originals.put(path,value);}
        PublicPersonalNotesRecoveryClient.Receipt collect()throws Exception{return PublicPersonalNotesRecoveryClient.collect(context,MobiMindPrivateFiles.read(journal.toFile(),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true),()->{});}
        void unchanged()throws Exception{for(Map.Entry<Path,byte[]> e:originals.entrySet())if(!Arrays.equals(e.getValue(),Files.readAllBytes(e.getKey())))throw new AssertionError("original changed");assertions++;}
        public void close()throws IOException{try(java.util.stream.Stream<Path> paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(p);}}
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=0)throw new IllegalArgumentException("authored synthetic fixture only");
        test("single_drained_unknown_effect_preserved",()->{Fixture f=new Fixture();f.full();need(f.request().postModelDrained&&f.request().recordedTaskIds.size()==2);need(f.get("result").getString("status").equals("blocked")&&!f.get("result").getBoolean("cleanup_known")&&f.get("step_action").getJSONObject("action_execution").isNull("api_accepted"));});
        test("versioned_full_input_wire_round_trip",()->{Fixture f=new Fixture();PublicPersonalNotesAbsenceRecovery.Request r=f.request(),decoded=PublicPersonalNotesAbsenceRecovery.fromWire(r.wire());need(decoded.postModelDrained&&decoded.inputHashes().length()==15&&decoded.originalsSha256.equals(r.originalsSha256));need(r.wire().length()<PublicPersonalNotesAbsenceRecovery.MAX_WIRE);});
        test("old_seven_input_branch_stays_premodel",()->{PublicPersonalNotesAbsenceRecovery.Request r=new PersonalNotesAbsenceHostTest.Fixture().request();need(!r.postModelDrained&&r.inputHashes().length()==7&&!PublicPersonalNotesAbsenceRecovery.fromWire(r.wire()).postModelDrained);});
        test("each_extra_original_required",()->{for(String name:new String[]{"step_model","step_action","fixed_intent_attempt","model_request_receipt","model_session_receipt","native_session_receipt","generation_identity","generation_cleanup_receipt"}){Fixture f=new Fixture();f.inputs.remove(name);refuse(f::request);}});
        test("unrecognized_original_rejected",()->{Fixture f=new Fixture();f.inputs.put("self_report",raw("proof"));refuse(f::request);});
        test("second_step_rejected",()->{Fixture f=new Fixture();f.mutate("result",v->v.put("steps",2));refuse(f::request);});
        test("pending_action_rejected",()->{Fixture f=new Fixture();f.mutate("result",v->v.put("action_worker_pending_at_terminal",true));refuse(f::request);});
        test("undrained_worker_rejected",()->{Fixture f=new Fixture();JSONObject w=f.get("result").getJSONObject("last_action_execution");w.put("worker_drained",false);f.syncAction(w);refuse(f::request);});
        test("drain_after_terminal_rejected",()->{Fixture f=new Fixture();JSONObject w=f.get("result").getJSONObject("last_action_execution");w.put("worker_drained_elapsed_ms",f.base.now);f.syncAction(w);refuse(f::request);});
        test("unknown_effect_never_promoted_to_accepted",()->{Fixture f=new Fixture();JSONObject w=f.get("result").getJSONObject("last_action_execution");w.put("api_accepted",true);f.syncAction(w);refuse(f::request);});
        test("fixed_attempt_mutation_rejected",()->{Fixture f=new Fixture();f.mutate("fixed_intent_attempt",v->v.put("payload_sha256",hash(raw("other"))));refuse(f::request);});
        test("model_action_mutation_rejected",()->{Fixture f=new Fixture();f.mutate("step_model",v->v.put("raw_text","{}"));refuse(f::request);});
        test("bootstrap_owned_task_not_discarded",()->{Fixture f=new Fixture();JSONObject c=f.get("cleanup");c.getJSONObject("last_broker_response").getJSONObject("public_task_location").put("observed_owned_task_ids",new JSONArray().put(f.base.oldTask+1));f.syncCleanup(c);refuse(f::request);});
        test("same_task_token_replacement_rejected",()->{Fixture f=new Fixture();JSONObject c=f.get("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").getJSONArray("actual_observed_tasks").getJSONObject(0).put("token_identity_in_broker",999);f.syncCleanup(c);refuse(f::request);});
        test("session_raw_hash_required",()->{Fixture f=new Fixture();f.mutate("model_session_receipt",v->v.put("diagnostic_extra",true));refuse(f::request);});
        test("request_cannot_claim_worker_exit",()->{Fixture f=new Fixture();f.mutate("model_request_receipt",v->v.put("process_exit_observed",true));refuse(f::request);});
        test("session_must_observe_worker_exit",()->{Fixture f=new Fixture();JSONObject s=f.get("model_session_receipt");s.put("process_exit_observed",false);f.syncSession(s);refuse(f::request);});
        test("native_cannot_self_attest_exit",()->{Fixture f=new Fixture();JSONObject n=f.get("native_session_receipt");n.put("process_exit_observed",true);f.syncNative(n);refuse(f::request);});
        test("sdk_destroy_failure_rejected",()->{Fixture f=new Fixture();JSONObject n=f.get("native_session_receipt");n.put("sdk_destroy_rc",-1);f.syncNative(n);refuse(f::request);});
        test("second_model_request_rejected",()->{Fixture f=new Fixture();JSONObject s=f.get("model_session_receipt");s.put("requests_sent",2);f.syncSession(s);refuse(f::request);});
        test("generation_raw_identity_changed_rejected",()->{Fixture f=new Fixture();f.inputs.put("generation_identity",raw("other generation"));refuse(f::request);});
        test("generation_signal_never_normal_close",()->{Fixture f=new Fixture();JSONObject n=f.get("generation_cleanup_receipt");n.put("term_attempts",1);f.syncGeneration(n);refuse(f::request);});
        test("original_generation_validator_rejects_one_empty_scan",()->{Fixture f=new Fixture();JSONObject n=f.get("generation_cleanup_receipt");n.put("empty_readbacks",1);f.syncGeneration(n);f.request();refuse(f::full);});
        test("original_generation_validator_rejects_nonabsence_group_probe",()->{Fixture f=new Fixture();JSONObject n=f.get("generation_cleanup_receipt");n.getJSONArray("group_presence_observations").getJSONObject(1).put("result",0).put("errno",0);f.syncGeneration(n);f.request();refuse(f::full);});
        test("original_generation_validator_rejects_new_deadline",()->{Fixture f=new Fixture();JSONObject s=f.get("model_session_receipt");s.getJSONObject("worker_generation_cleanup").put("deadline_monotonic_ns",5210000001L);f.syncSession(s);f.request();refuse(f::full);});
        test("old_app_pid_is_not_current_ui_pid",()->{Fixture f=new Fixture();need(f.get("model_session_receipt").getInt("app_pid")!=android.os.Process.myPid());f.full();});
        test("client_reads_and_archives_all_sixteen_originals",()->{try(Env e=new Env()){PublicPersonalNotesRecoveryClient.Receipt receipt=e.collect();receipt.persist(e.context);receipt.requirePersisted();receipt.requireOriginals(true);need(receipt.request.postModelDrained&&FakePersonalNotesRecoveryProcess.calls==1);try(java.util.stream.Stream<Path> p=Files.list(e.task)){need(p.filter(x->x.getFileName().toString().contains(".original-")).count()==16);}e.unchanged();}});
        test("client_rejects_later_step_before_checker",()->{try(Env e=new Env()){e.write(e.task.resolve("step-02-model-0.json"),raw("unexpected"));refuse(e::collect);need(FakePersonalNotesRecoveryProcess.calls==0);}});
        test("client_rejects_foreign_receipt_path",()->{try(Env e=new Env()){Path path=e.root.resolve("runs").resolve(e.fixture.worker).resolve("app-session-receipt.json");JSONObject value=obj(Files.readAllBytes(path));value.getJSONObject("worker_generation_cleanup").put("identity_file","/foreign/worker-generation.identity");Files.write(path,raw(value));refuse(e::collect);need(FakePersonalNotesRecoveryProcess.calls==0);}});
        test("client_rechecks_generation_bytes_after_sampling",()->{try(Env e=new Env()){Path path=e.root.resolve("runs").resolve(e.fixture.worker).resolve("worker-generation.identity");FakePersonalNotesRecoveryProcess.afterReply=()->{try{Files.write(path,raw("changed"));}catch(IOException failure){throw new RuntimeException(failure);}};refuse(e::collect);need(FakePersonalNotesRecoveryProcess.calls==1);}});
        test("client_rechecks_extra_bytes_before_durable_commit",()->{try(Env e=new Env()){PublicPersonalNotesRecoveryClient.Receipt receipt=e.collect();Path path=e.root.resolve("runs").resolve(e.fixture.run).resolve("app-receipt.json");Files.write(path,raw("changed"));refuse(()->receipt.persist(e.context));}});
        test("nested_cancellation_cannot_contradict_normal_close",()->{Fixture f=new Fixture();JSONObject s=f.get("model_session_receipt");s.getJSONObject("owned_worker_cancellation").put("term_destroy_attempts",1);f.syncSession(s);refuse(f::request);});
        test("retired_action_authority_rejected",()->{Fixture f=new Fixture();f.mutate("step_action",v->v.getJSONObject("task_authorization").put("callback_lease_current",false));refuse(f::request);});
        test("released_terminal_keeps_failed_business_and_full_wire",()->{Fixture f=new Fixture().released();f.full();PublicPersonalNotesAbsenceRecovery.Request r=f.request();
            need(r.postModelDrained&&r.recordedTaskIds.size()==2&&r.inputHashes().length()==15);
            need(PublicPersonalNotesAbsenceRecovery.fromWire(r.wire()).wire().equals(r.wire()));
            need(f.get("result").getString("status").equals("blocked")&&!f.get("result").getBoolean("cleanup_known")
                    &&f.get("broker_output").getBoolean("release_confirmed")&&!f.get("cleanup").getJSONObject("last_broker_response").getBoolean("ok"));});
        test("released_terminal_requires_all_drained_originals",()->{Fixture f=new Fixture().released();for(String key:new String[]{"step_model","step_action","fixed_intent_attempt","model_request_receipt","model_session_receipt","native_session_receipt","generation_identity","generation_cleanup_receipt"})f.inputs.remove(key);refuse(f::request);});
        test("released_terminal_requires_release_confirmed",()->{Fixture f=new Fixture().released();JSONObject t=f.get("broker_output").put("release_confirmed",false);f.syncTerminal(t);refuse(f::request);});
        test("released_terminal_requires_owned_process_exit",()->{Fixture f=new Fixture().released();JSONObject c=f.get("cleanup").put("broker_process_exit_observed",false).put("broker_process_exit_code",JSONObject.NULL);f.syncCleanup(c);refuse(f::request);});
        test("released_terminal_requires_zero_exit",()->{Fixture f=new Fixture().released();JSONObject c=f.get("cleanup").put("broker_process_exit_code",1);f.syncCleanup(c);refuse(f::request);});
        test("released_terminal_requires_complete_eof",()->{Fixture f=new Fixture().released();JSONObject b=f.get("broker_receipt").put("eof_seen",false);f.put("broker_receipt",b);f.syncTerminal(f.get("broker_output"));refuse(f::request);});
        test("released_terminal_last_response_state_must_agree",()->{Fixture f=new Fixture().released();JSONObject c=f.get("cleanup");c.getJSONObject("last_broker_response").put("state","CLEANUP_UNKNOWN");f.syncCleanup(c);refuse(f::request);});
        test("released_terminal_cannot_promote_business_ok",()->{Fixture f=new Fixture().released();JSONObject c=f.get("cleanup");c.getJSONObject("last_broker_response").put("ok",true);f.syncCleanup(c);refuse(f::request);});
        test("released_terminal_requires_same_custody_bytes",()->{Fixture f=new Fixture().released();JSONObject c=f.get("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").put("pending_owned_reads",9);f.syncCleanup(c);refuse(f::request);});
        test("released_custody_requires_complete_retirement_flags",()->{for(String key:new String[]{"cleanup_known","pre_release_tasks_verified","release_api_entered","release_api_returned","display_absence_verified","live_tasks_absent","all_recents_sections_absent","prior_hidden_history_preserved","nonphysical_history_preserved","nonphysical_hidden_history_preserved"}){Fixture f=new Fixture().released();f.releasedCustodies(c->c.put(key,false));refuse(f::request);}});
        test("released_custody_refuses_unknown_or_retained_identity",()->{for(String key:new String[]{"identity_unknown","custodian_retained","no_display_create_attempted"}){Fixture f=new Fixture().released();f.releasedCustodies(c->c.put(key,true));refuse(f::request);}});
        test("released_custody_requires_two_absence_reads",()->{Fixture f=new Fixture().released();f.releasedCustodies(c->c.put("absence_reads",1));refuse(f::request);});
        test("released_custody_refuses_failure",()->{Fixture f=new Fixture().released();f.releasedCustodies(c->c.put("failure","synthetic failure"));refuse(f::request);});
        test("released_custody_requires_all_history_hashes",()->{for(String key:new String[]{"initial_recents_sha256","pre_release_recents_sha256","final_recents_sha256"}){Fixture f=new Fixture().released();f.releasedCustodies(c->c.put(key,""));refuse(f::request);}});
        test("released_terminal_does_not_skip_native_drain_proof",()->{Fixture f=new Fixture().released();JSONObject n=f.get("generation_cleanup_receipt");n.put("empty_readbacks",1);f.syncGeneration(n);f.request();refuse(f::full);});
        test("released_terminal_still_requires_fresh_absence",()->{Fixture f=new Fixture().released();PublicPersonalNotesAbsenceRecovery.Request r=f.request();
            JSONObject valid=PersonalNotesAbsenceHostTest.proof(r);need(PublicPersonalNotesAbsenceRecovery.validate(valid,r,r.started+21,r.requestBoot).getBoolean("cleanup_known"));
            JSONObject process=copy(valid);process.getJSONObject("after").getJSONObject("process").put("old_creator_absent",false);refuse(()->PublicPersonalNotesAbsenceRecovery.validate(process,r,r.started+21,r.requestBoot));
            JSONObject physical=copy(valid);physical.getJSONObject("after").getJSONObject("physical").put("0",hash(raw("changed main")));refuse(()->PublicPersonalNotesAbsenceRecovery.validate(physical,r,r.started+21,r.requestBoot));
            JSONObject task=copy(valid);task.getJSONObject("after").getJSONObject("live").getJSONArray("roots").getJSONObject(0).put("top",f.pkg+"/.Main");refuse(()->PublicPersonalNotesAbsenceRecovery.validate(task,r,r.started+21,r.requestBoot));});
        test("client_archives_released_originals_without_rewriting_failure",()->{try(Env e=new Env(true)){PublicPersonalNotesRecoveryClient.Receipt receipt=e.collect();receipt.persist(e.context);receipt.requirePersisted();receipt.requireOriginals(true);
            need(receipt.request.postModelDrained&&FakePersonalNotesRecoveryProcess.calls==1);try(java.util.stream.Stream<Path> p=Files.list(e.task)){need(p.filter(x->x.getFileName().toString().contains(".original-")).count()==16);}e.unchanged();}});
        test("client_archives_current_interrupted_control_after_update",()->{try(Env e=new Env(true)){
            // Authored startup-shaped state only: this test does not claim an
            // actual package update or invoke the Android startup producer.
            Path control=e.root.resolve("control-session.json");byte[] previous=Files.readAllBytes(control);
            Path archiveDir=e.root.resolve("session-recovery");MobiMindPrivateFiles.directory(archiveDir.toFile(),true);
            Path archive=archiveDir.resolve("control-session.json."+hash(previous)+".json");e.write(archive,previous);
            JSONObject startup=new JSONObject().put("schema","hepta.session-recovery.v1").put("decision","blocked_interrupted")
                    .put("reason","synthetic preserved blocked session").put("previous_status","blocked")
                    .put("previous_session_sha256",hash(previous)).put("read_error",JSONObject.NULL)
                    .put("interruption_latch","control-session.interrupted.json").put("interruption_latch_observed",true)
                    .put("interruption_latch_synced",true).put("recovery_pending_barrier_observed",false)
                    .put("automatic_resume",false).put("native_cleanup_independently_observed",false)
                    .put("preserved_records",new JSONArray().put(new JSONObject().put("original_name","control-session.json")
                            .put("path",archive.toString()).put("sha256",hash(previous)).put("bytes",previous.length)));
            byte[] current=raw(obj(previous).put("status","interrupted").put("cleanup_known",false)
                    .put("background_lease_unreleased",true).put("web_helper_lease_unreleased",false).put("startup_recovery",startup));
            Files.write(control,current);e.originals.put(control,current);
            PublicPersonalNotesRecoveryClient.Receipt receipt=e.collect();receipt.persist(e.context);receipt.requirePersisted();receipt.requireOriginals(true);
            need(receipt.request.postModelDrained&&FakePersonalNotesRecoveryProcess.calls==1);
            need(receipt.request.currentControlSha256.equals(hash(current))&&!receipt.request.currentControlSha256.equals(hash(previous))
                    &&Arrays.equals(receipt.request.original("current_control"),current));
            need(obj(Files.readAllBytes(e.task.resolve("result.json"))).getString("status").equals("blocked"));
            try(java.util.stream.Stream<Path> p=Files.list(e.task)){need(p.filter(x->x.getFileName().toString().contains(".original-")).count()==16);}
            e.unchanged();}});
        System.out.println(new JSONObject().put("schema","hepta.personal-notes-post-model-host.v1").put("passed",true).put("cases",cases).put("assertions",assertions).put("case_names",names).put("phone_operations",0).put("current_absence_samples_synthetic",true).put("business_success_claimed",false));
    }
}
