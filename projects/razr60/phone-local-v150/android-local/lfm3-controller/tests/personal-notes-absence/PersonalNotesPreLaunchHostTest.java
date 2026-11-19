package org.trillionnium.hepta.background;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import org.json.*;

/** Authored pre-launch failure values and synthetic current framework samples.
 * No phone, installed APK, administrative retirement or opaque App receipt. */
public final class PersonalNotesPreLaunchHostTest {
    private static int cases,assertions;
    private static final List<String> names=new ArrayList<String>();
    interface Work{void run()throws Exception;}
    interface Change{void run(Fixture value)throws Exception;}
    interface ProofChange{void run(JSONObject value)throws Exception;}
    private static void yes(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(String name,Work work)throws Exception{work.run();cases++;names.add(name);}
    private static void refuse(Work work)throws Exception{try{work.run();throw new AssertionError("unsafe input accepted");}catch(Exception expected){assertions++;}}
    private static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    private static JSONObject object(byte[] value){return new JSONObject(new String(value,StandardCharsets.UTF_8));}
    private static byte[] raw(JSONObject value){return value.toString().getBytes(StandardCharsets.UTF_8);}
    public static final class Fixture {
        public final PersonalNotesAbsenceHostTest.Fixture base=new PersonalNotesAbsenceHostTest.Fixture();
        final JSONObject terminal,broker,bootstrap,cleanup,result,last,custody,lease,detach;
        Fixture()throws Exception{
            terminal=object(base.inputs.get("broker_output"));broker=object(base.inputs.get("broker_receipt"));
            bootstrap=object(base.inputs.get("bootstrap"));cleanup=object(base.inputs.get("cleanup"));result=object(base.inputs.get("result"));
            last=bootstrap.getJSONObject("last_broker_response");custody=terminal.getJSONObject("personal_notes_cleanup");
            custody.put("schema","hepta.public-personal-notes-cleanup.v2").put("display_id",-1).put("launch_dispatched",false)
                    .put("identity_unknown",true).put("custodian_retained",true).put("failure","NOTES_OWNED_DISPLAY_OR_READER_UNKNOWN")
                    .put("history_preservation_scope","nonphysical_and_unresolved_recents").put("history_preservation_interval","pre_release_to_absence")
                    .put("hidden_history_preservation_interval","initial_to_absence").put("initial_recents_sha256",ProfileIdentity.sha("synthetic initial recents"))
                    .put("pre_release_recents_sha256","").put("final_recents_sha256","").put("absence_reads",0).put("pending_owned_reads",0);
            for(String key:new String[]{"pre_release_tasks_verified","release_api_entered","release_api_returned","display_absence_verified",
                    "live_tasks_absent","all_recents_sections_absent","prior_hidden_history_preserved","physical_history_frozen",
                    "unrelated_physical_history_changes_observed","recents_presentation_changes_observed","nonphysical_history_preserved",
                    "nonphysical_hidden_history_preserved","no_display_create_attempted"})custody.put(key,false);
            lease=new JSONObject().put("schema","hepta.public-own-group.screen-lease.v1").put("generation",base.gen)
                    .put("display_id",-1).put("display_group_id",-1).put("wake_lock_flags",10).put("expires_elapsed_ms",base.expires)
                    .put("failure",JSONObject.NULL).put("admission_retired",true).put("initial_first_display_state",-1).put("initial_last_display_state",-1);
            for(String key:new String[]{"acquire_entered","acquire_returned","release_entered","release_returned","grants_cleanup_or_business_success"})lease.put(key,false);
            for(String key:new String[]{"acquired_elapsed_ms","released_elapsed_ms","initial_readiness_started_elapsed_ms",
                    "initial_readiness_deadline_elapsed_ms","initial_readiness_census_count","initial_on_observed_elapsed_ms"})lease.put(key,0);
            detach=new JSONObject().put("schema","hepta.public-own-group.surface-retirement.v1").put("state","API_RETURNED_UNVERIFIED")
                    .put("identity_source","CREATE_RETURNED_HANDLE_ONLY").put("began_elapsed_ms",base.created+30)
                    .put("ended_elapsed_ms",base.created+40).put("failure_type","");
            for(String key:new String[]{"admission_irrevocably_retired","worker_claimed","identity_read_completed","adapter_entered","api_attempted","api_returned","worker_finished"})detach.put(key,true);
            for(String key:new String[]{"late_create_worker_claimed","deadline_exceeded","surface_stopped_verified","provides_task_or_display_cleanup_proof",
                    "allows_input_or_model_resumption","shutdown_depends_on_fresh_display_binder_query"})detach.put(key,false);
            terminal.put("reason","PUBLIC_SCOPE_DISPLAY_INFORMATION_UNKNOWN").put("public_screen_lease",lease).put("public_surface_detach",detach)
                    .put("profile_custody_retained",false);
            for(String key:new String[]{"owned_single_task","profile_cleanup","profile_last_leaf_validation","profile_first_root_refusal","boot_count_read_retirement_failure"})terminal.put(key,JSONObject.NULL);
            last.remove("task_launch_policy");last.put("request_id","11111111-1111-4111-8111-111111111111")
                    .put("operation","create").put("state","CLEANUP_UNKNOWN").put("display_name",base.name).put("expires_elapsed_ms",base.expires)
                    .put("ok",false).put("dispatched",true).put("capture_secure",false).put("public_scope_admission_retired",true).put("public_scope_closing",true)
                    .put("error","PUBLIC_SCOPE_RETIRED").put("terminal_reason",terminal.get("reason")).put("personal_notes_cleanup",custody)
                    .put("public_surface_detach",detach);
            for(String key:new String[]{"display_policy_readback","public_own_group_readback_wire","public_profile_recent_history"})last.put(key,JSONObject.NULL);
            JSONObject location=last.getJSONObject("public_task_location");location.put("observed_owned_task_ids",new JSONArray()).put("observed_elapsed_ms",base.created+20).put("initial_task_count",3);
            for(String key:new String[]{"retired","physical_user_activity_frozen","recents_unchanged_claimed"})location.put(key,false);
            for(JSONObject value:new JSONObject[]{bootstrap,cleanup})value.put("bootstrap_dispatched",false).put("app_display_readback",JSONObject.NULL);
            sync();
        }
        void sync(){
            byte[] bytes=raw(terminal);broker.put("stored_bytes",bytes.length).put("observed_bytes",bytes.length).put("stored_sha256",ProfileIdentity.sha(bytes));
            bootstrap.put("broker_output",broker).put("last_broker_response",last);cleanup.put("broker_output",broker).put("last_broker_response",last);
            JSONObject session=copy(cleanup);session.remove("cleanup_known");session.remove("cleanup_error");
            result.put("background_cleanup",cleanup).put("background_session",session);
            base.inputs.put("broker_output",bytes);base.inputs.put("broker_receipt",raw(broker));base.inputs.put("bootstrap",raw(bootstrap));
            base.inputs.put("cleanup",raw(cleanup));base.inputs.put("result",raw(result));
        }
        PublicPersonalNotesAbsenceRecovery.Request request()throws Exception{sync();return base.request();}
    }
    private static void bad(String name,Change change)throws Exception{test(name,()->{Fixture f=new Fixture();change.run(f);refuse(()->f.request());});}
    private static void badProof(String name,ProofChange change)throws Exception{test(name,()->{PublicPersonalNotesAbsenceRecovery.Request r=new Fixture().request();
        JSONObject value=PersonalNotesAbsenceHostTest.proof(r);change.run(value);refuse(()->PublicPersonalNotesAbsenceRecovery.validate(value,r,r.started+21,r.oldBoot));});}
    private static String schema(String wire)throws Exception{try(DataInputStream in=new DataInputStream(new GZIPInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(wire))))){return in.readUTF();}}
    private static String replaceSchema(String wire,String replacement)throws Exception{
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(DataInputStream in=new DataInputStream(new GZIPInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(wire))))){
            in.readUTF();DataOutputStream out=new DataOutputStream(bytes);out.writeUTF(replacement);byte[] buffer=new byte[4096];int count;while((count=in.read(buffer))!=-1)out.write(buffer,0,count);out.flush();}
        ByteArrayOutputStream zipped=new ByteArrayOutputStream();try(GZIPOutputStream out=new GZIPOutputStream(zipped)){out.write(bytes.toByteArray());}return Base64.getEncoder().encodeToString(zipped.toByteArray());
    }
    public static void main(String[] args)throws Exception{
        test("pre-launch v3 retains unknown custody and real returned display",()->{Fixture f=new Fixture();PublicPersonalNotesAbsenceRecovery.Request r=f.request();
            yes(r.preLaunchFailure&&!r.postModelDrained&&r.displayId==f.base.display&&r.recordedTaskIds.isEmpty(),"typed failure binding");
            yes(object(r.original("broker_output")).getJSONObject("personal_notes_cleanup").getInt("display_id")==-1,"custody must not be repaired");
            yes(schema(r.wire()).equals(PublicPersonalNotesAbsenceRecovery.PRELAUNCH_REQUEST_SCHEMA),"v3 schema");
            yes(PublicPersonalNotesAbsenceRecovery.fromWire(r.wire()).wire().equals(r.wire()),"canonical roundtrip");});
        test("old launched seven-original branch remains v1",()->{PublicPersonalNotesAbsenceRecovery.Request r=new PersonalNotesAbsenceHostTest.Fixture().request();
            yes(!r.preLaunchFailure&&!r.postModelDrained&&schema(r.wire()).equals(PublicPersonalNotesAbsenceRecovery.REQUEST_SCHEMA),"old route changed");});
        test("pre-launch request cannot claim v1",()->{PublicPersonalNotesAbsenceRecovery.Request r=new Fixture().request();
            refuse(()->PublicPersonalNotesAbsenceRecovery.fromWire(replaceSchema(r.wire(),PublicPersonalNotesAbsenceRecovery.REQUEST_SCHEMA)));});
        test("new controller APK retains exact old originals",()->{Fixture f=new Fixture();PublicPersonalNotesAbsenceRecovery.Request old=f.request();
            f.base.controller.put("source_path","/data/app/synthetic-upgraded/base.apk").put("source_sha256",ProfileIdentity.sha("synthetic new recovery APK")).put("source_bytes",54321).put("version_code",2);
            PublicPersonalNotesAbsenceRecovery.Request r=f.request();yes(old.originalsSha256.equals(r.originalsSha256),"old originals rewritten");
            yes(!old.controller().getString("source_sha256").equals(r.controller().getString("source_sha256")),"current identity not upgraded");
            JSONObject proof=PersonalNotesAbsenceHostTest.proof(r);yes(PublicPersonalNotesAbsenceRecovery.validate(proof,r,r.started+21,r.oldBoot).getBoolean("cleanup_known"),"fresh synthetic proof");
            proof.put("current_controller",old.controller());refuse(()->PublicPersonalNotesAbsenceRecovery.validate(proof,r,r.started+21,r.oldBoot));});
        bad("contradictory last owned-single-task proof refuses",f->f.last.put("owned_single_task",new JSONObject()));
        bad("last launch policy refuses",f->f.last.put("task_launch_policy",new JSONObject()));
        bad("last fixed intent refuses",f->f.last.put("fixed_intent",new JSONObject()));
        bad("bootstrap dispatch cannot select new path",f->f.bootstrap.put("bootstrap_dispatched",true));
        bad("cleanup dispatch refuses",f->f.cleanup.put("bootstrap_dispatched",true));
        bad("custody bound display refuses",f->f.custody.put("display_id",f.base.display));
        bad("custody launch refuses",f->f.custody.put("launch_dispatched",true));
        bad("custody historical cleanup success refuses",f->f.custody.put("cleanup_known",true));
        bad("custody identity known contradicts this failure",f->f.custody.put("identity_unknown",false));
        bad("custody observed task refuses",f->f.custody.getJSONArray("actual_observed_tasks").put(new JSONObject()));
        bad("located task refuses",f->f.last.getJSONObject("public_task_location").getJSONArray("observed_owned_task_ids").put(400));
        bad("app display readback refuses",f->f.bootstrap.put("app_display_readback",new JSONObject()));
        bad("different create failure refuses",f->f.last.put("terminal_reason","other"));
        bad("successful create response refuses",f->f.last.put("ok",true));
        bad("display wire falsely grants prior admission refuses",f->f.last.put("public_own_group_readback_wire","synthetic"));
        bad("screen lease acquisition refuses",f->f.lease.put("acquire_entered",true));
        bad("screen readiness work refuses",f->f.lease.put("initial_readiness_census_count",1));
        bad("surface detach is not cleanup proof",f->f.detach.put("provides_task_or_display_cleanup_proof",true));
        bad("prelaunch model process refuses",f->f.result.getJSONObject("model_session").put("process_started",true));
        bad("prelaunch native reservation refuses",f->f.result.getJSONObject("native_cancellation").put("request_reserved",true));
        bad("prelaunch business step refuses",f->f.result.put("steps",1));
        bad("prelaunch fixed effect refuses",f->f.result.getJSONArray("fixed_intent_attempts").put(new JSONObject()));
        bad("prelaunch pending worker refuses",f->f.result.put("action_worker_pending_at_terminal",true));
        badProof("empty historical task IDs still reject Notes live root",p->p.getJSONObject("after").getJSONObject("live").getJSONArray("roots").getJSONObject(0).put("top",PublicPersonalNotesAbsenceRecovery.PACKAGE+"/.Main"));
        badProof("empty historical task IDs still reject Notes leaf",p->p.getJSONObject("after").getJSONObject("live").getJSONArray("leaves").getJSONObject(0).put("name",PublicPersonalNotesAbsenceRecovery.PACKAGE+"/.Main"));
        badProof("old returned display remains forbidden",p->p.getJSONObject("after").getJSONObject("displays").getJSONArray("rows").getJSONObject(1).put("id",77));
        badProof("old creator remains forbidden",p->p.getJSONObject("after").getJSONObject("process").put("old_creator_absent",false));
        badProof("main physical change refuses",p->p.getJSONObject("after").getJSONObject("physical").put("0",ProfileIdentity.sha("changed")));
        badProof("current control CAS remains strict",p->p.put("current_control_sha256",ProfileIdentity.sha("changed")));
        test("hidden Notes remain forbidden with empty recorded IDs",()->{PublicPersonalNotesAbsenceRecovery.Request r=new Fixture().request();
            String history=PersonalNotesAbsenceHostTest.recents(5).replace("  Recent tasks:\n","mHiddenTasks=[Task{abc #999 type=standard A=23456:com.motorola.stylus}]\n  Recent tasks:\n");
            refuse(()->PublicPersonalNotesHistory.absence(history,r));});
        test("same-boot expiry and original request deadline remain strict",()->{PublicPersonalNotesAbsenceRecovery.Request r=new Fixture().request();
            refuse(()->r.requireFence(r.deadline,r.oldBoot));refuse(()->r.requireFence(r.started,r.oldBoot+1));});
        System.out.println(new JSONObject().put("schema","hepta.personal-notes-prelaunch-host.v1").put("all_pass",true).put("cases",cases).put("assertions",assertions)
                .put("case_names",new JSONArray(names)).put("framework_fixtures_synthetic",true).put("current_controller_synthetic",true)
                .put("phone_operations",0).put("android_runtime",false).put("app_receipt_created",false).put("business_success_claimed",false));
    }
}
