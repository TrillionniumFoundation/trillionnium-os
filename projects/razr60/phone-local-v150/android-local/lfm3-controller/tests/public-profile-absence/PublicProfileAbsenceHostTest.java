package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Real 8311 producer files; framework/current-installation samples are explicit synthetic fixtures. */
public final class PublicProfileAbsenceHostTest {
    private static final String ID="88888888-4444-4444-8444-123456789abc";
    private static final String HASH="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static Map<String,byte[]> originals;
    private static String recentsBefore,recentsAfter;
    private static long now;
    private static int boot,passed;
    private static final JSONArray cases=new JSONArray();
    interface Check {void run()throws Exception;}
    interface Change {void change(JSONObject o)throws Exception;}
    private static void yes(String name,Check check)throws Exception{check.run();passed++;cases.put(name);}
    private static void no(String name,Check check)throws Exception{try{check.run();}catch(Exception refused){passed++;cases.put(name);return;}throw new AssertionError("accepted: "+name);}
    private static Map<String,byte[]> copy(){Map<String,byte[]> out=new LinkedHashMap<String,byte[]>();for(Map.Entry<String,byte[]> e:originals.entrySet())out.put(e.getKey(),e.getValue().clone());return out;}
    private static JSONObject obj(byte[] b)throws Exception{return PublicProfileAbsenceRecovery.object(b);}
    private static Map<String,byte[]> mutate(String key,Change change)throws Exception{Map<String,byte[]> out=copy();JSONObject o=obj(out.get(key));change.change(o);out.put(key,o.toString().getBytes(StandardCharsets.UTF_8));return out;}
    private static JSONObject controller()throws Exception{return new JSONObject().put("schema","hepta.recovery-controller-installation.v1")
            .put("package",PublicProfileAbsenceRecovery.CONTROLLER).put("user_id",0).put("uid",10481)
            .put("source_path","/data/app/synthetic-new-recovery/base.apk").put("source_bytes",22000000).put("source_sha256",HASH)
            .put("version_code",70).put("signer_sha256",new JSONArray().put(HASH));}
    private static PublicProfileAbsenceRecovery.Request request(Map<String,byte[]> data)throws Exception{return PublicProfileAbsenceRecovery.request(data,controller(),10481,ID,now,boot);}
    public static void loadArchivedRecents(Path directory)throws Exception{
        byte[] before=Files.readAllBytes(directory.resolve("before-recents.txt"));
        byte[] after=Files.readAllBytes(directory.resolve("after-recents.txt"));
        if(!ProfileIdentity.sha(before).equals("bb1335844af98cf8a2a435ab8b10a6bf9930ccd96bc162bff38150c9a7d1ee6a")
                ||!ProfileIdentity.sha(after).equals("5755f3c99126d9f093272b7b73cce47a74049d5398110a1c8d97465e1952c4f3"))
            throw new AssertionError("actual archived recents fixture changed");
        recentsBefore=new String(before,StandardCharsets.UTF_8);recentsAfter=new String(after,StandardCharsets.UTF_8);
    }
    private static JSONObject sample(PublicProfileAbsenceRecovery.Request r,long at,String rawRecents)throws Exception{
        return new JSONObject().put("started_elapsed_ms",at).put("finished_elapsed_ms",at+3).put("target_sha256",r.target.sha256)
                .put("process",new JSONObject().put("complete",true).put("old_creator_absent",true).put("started_elapsed_ms",at+1).put("finished_elapsed_ms",at+2)
                        .put("self_pid",43210).put("self_start_ticks",123456L).put("process_count",512).put("inspected_count",35).put("inventory_sha256",HASH))
                .put("live",new JSONObject().put("complete",true).put("root_count",5).put("leaf_count",12).put("snapshot_sha256",HASH).put("target_user_id",10).put("target_task_ids",new JSONArray()))
                .put("recents",new JSONObject(PublicProfileRecentHistory.absence(rawRecents,r.target).evidence()))
                .put("displays",new JSONObject().put("complete",true).put("count",2).put("snapshot_sha256",HASH).put("exact_name_absent",true))
                .put("physical",new JSONObject().put("0",HASH).put("1",HASH));
    }
    public static JSONObject proof(PublicProfileAbsenceRecovery.Request r)throws Exception{
        return proof(r,recentsBefore,recentsAfter);
    }
    private static JSONObject proof(PublicProfileAbsenceRecovery.Request r,String before,String after)throws Exception{
        if(before==null||after==null)throw new AssertionError("archived recents fixture not loaded");
        return new JSONObject().put("schema",PublicProfileAbsenceRecovery.SCHEMA).put("source",PublicProfileAbsenceRecovery.SOURCE)
                .put("request_id",r.requestId).put("task_id",r.taskId).put("generation",r.generation).put("owner_uid",r.ownerUid)
                .put("owner_sha256",r.ownerSha256).put("journal_sha256",r.journalSha256).put("originals_sha256",r.originalsSha256).put("original_inputs",r.inputHashes())
                .put("public_scope_wire",r.publicScope.wire()).put("public_scope_sha256",r.publicScope.sha256).put("profile_target_wire",r.target.wire()).put("target_sha256",r.target.sha256)
                .put("display_name",r.displayName).put("old_boot_count",r.oldBoot).put("current_boot_count",r.requestBoot).put("lease_expires_elapsed_ms",r.expires)
                .put("request_started_elapsed_ms",r.started).put("started_elapsed_ms",r.started+1).put("finished_elapsed_ms",r.started+4020).put("deadline_elapsed_ms",r.deadline)
                .put("current_controller",r.controller()).put("before",sample(r,r.started+5,before)).put("after",sample(r,r.started+4010,after))
                .put("current_absence_verified",true).put("recovery_interval_physical_unchanged",true).put("historical_creation_unknown",true)
                .put("business_dispatch_absent_in_original_receipts",true).put("foreign_dormant_history_preserved",true)
                .put("cleanup_known",true).put("automatic_resume",false).put("broker_release_response",false);
    }
    private static void invalidProof(String name,Change change)throws Exception{no(name,()->{PublicProfileAbsenceRecovery.Request r=request(copy());JSONObject p=proof(r);change.change(p);PublicProfileAbsenceRecovery.validate(p,r,now+4025,boot);});}
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("exact fixture directory");Path dir=Paths.get(args[0]);originals=new LinkedHashMap<String,byte[]>();loadArchivedRecents(dir);
        String gen="2a746961-06d0-4a8e-9f53-2d34cadbaa99";
        for(String[] row:new String[][]{{"journal","background-session.json"},{"owner","owner.json"},{"bootstrap","background-bootstrap.json"},{"cleanup","background-cleanup.json"},
                {"result","result.json"},{"broker_receipt","background-broker-"+gen+".json"},{"broker_output","background-broker-"+gen+".bin"}})originals.put(row[0],Files.readAllBytes(dir.resolve(row[1])));
        JSONObject journal=obj(originals.get("journal"));boot=journal.getInt("boot_count");now=journal.getLong("expires_elapsed_ms")+3000;
        yes("actual_8311_originals_no_business_exit70_valid",()->request(copy()));
        yes("unknown_historical_creation_complete_current_absence_accepts",()->{PublicProfileAbsenceRecovery.Request r=request(copy());PublicProfileAbsenceRecovery.validate(proof(r),r,now+4025,boot);});
        yes("gzip_roundtrip_original_byte_identity_and_bounded_cmdline",()->{PublicProfileAbsenceRecovery.Request r=request(copy());String wire=r.wire();
            if(wire.length()+600>=60000)throw new AssertionError("wire too large");PublicProfileAbsenceRecovery.Request again=PublicProfileAbsenceRecovery.fromWire(wire);
            if(!again.originalsSha256.equals(r.originalsSha256))throw new AssertionError("raw originals changed");});
        no("bootstrap_early_exit_false_cannot_replace_final_cleanup",()->request(mutate("cleanup",o->o.put("broker_process_exit_observed",false))));
        no("exit70_display_minus_one_alone_insufficient",()->{Map<String,byte[]> m=copy();m.remove("result");request(m);});
        no("business_launch_attempted_rejects",()->request(mutate("journal",o->o.put("profile_launch_attempted",true))));
        no("bootstrap_dispatch_rejects",()->request(mutate("cleanup",o->o.put("bootstrap_dispatched",true))));
        no("model_worker_started_rejects",()->request(mutate("result",o->o.getJSONObject("model_session").put("process_started",true))));
        no("model_step_rejects",()->request(mutate("result",o->o.put("steps",1))));
        no("action_pending_rejects",()->request(mutate("result",o->o.put("action_worker_pending_at_terminal",true))));
        no("native_pending_rejects",()->request(mutate("result",o->o.getJSONObject("native_cancellation").put("submission_unknown",true))));
        no("native_cleanup_unknown_rejects",()->request(mutate("result",o->o.getJSONObject("native_cancellation").put("native_cleanup_known",false))));
        no("submit_attempt_rejects",()->request(mutate("result",o->o.getJSONArray("submit_attempts").put(new JSONObject()))));
        no("fixed_intent_attempt_rejects",()->request(mutate("result",o->o.getJSONArray("fixed_intent_attempts").put(new JSONObject()))));
        no("authorization_open_effect_rejects",()->request(mutate("result",o->o.getJSONObject("task_authorization").put("open_run_id","some-run"))));
        no("owner_bytes_changed_rejects",()->request(mutate("owner",o->o.put("instruction","different instruction"))));
        no("scope_hash_changed_rejects",()->request(mutate("journal",o->o.put("public_own_group_scope_sha256",HASH))));
        no("target_hash_changed_rejects",()->request(mutate("journal",o->o.put("profile_target_sha256",HASH))));
        no("old_private_lease_is_not_public",()->request(mutate("journal",o->o.remove("public_own_group_scope_wire"))));
        no("broker_stdout_eof_unproved_rejects",()->request(mutate("broker_receipt",o->o.put("eof_seen",false))));
        no("broker_stdout_truncated_rejects",()->request(mutate("broker_receipt",o->o.put("overflow",true))));
        no("broker_stdout_byte_corruption_rejects",()->{Map<String,byte[]> m=copy();m.get("broker_output")[0]^=1;request(m);});
        no("producer_process_binding_swapped_rejects",()->request(mutate("broker_receipt",o->o.put("process_reference",42))));
        no("lease_boot_changed_rejects",()->PublicProfileAbsenceRecovery.request(copy(),controller(),10481,ID,now,boot+1));
        no("lease_not_expired_rejects",()->PublicProfileAbsenceRecovery.request(copy(),controller(),10481,ID,now-2000,boot));
        no("new_controller_uid_differs_rejects",()->PublicProfileAbsenceRecovery.request(copy(),controller().put("uid",10482),10481,ID,now,boot));
        no("new_controller_package_differs_rejects",()->PublicProfileAbsenceRecovery.request(copy(),controller().put("package","different.package"),10481,ID,now,boot));
        no("new_controller_path_traversal_rejects",()->PublicProfileAbsenceRecovery.request(copy(),controller().put("source_path","/data/app/../wrong/base.apk"),10481,ID,now,boot));
        invalidProof("private_proof_schema_cannot_be_relabelled",p->p.put("schema",ProfilePrelaunchRecovery.SCHEMA));
        invalidProof("old_request_id_rejects",p->p.put("request_id","99999999-4444-4444-8444-123456789abc"));
        invalidProof("old_generation_rejects",p->p.put("generation","99999999-4444-4444-8444-123456789abc"));
        invalidProof("proof_owner_changed_rejects",p->p.put("owner_sha256",HASH));
        invalidProof("proof_scope_changed_rejects",p->p.put("public_scope_sha256",HASH));
        invalidProof("proof_current_apk_changed_rejects",p->p.getJSONObject("current_controller").put("source_sha256","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        invalidProof("partial_live_query_cannot_be_empty",p->p.getJSONObject("after").getJSONObject("live").put("complete",false));
        invalidProof("empty_root_query_rejects",p->p.getJSONObject("after").getJSONObject("live").put("root_count",0));
        invalidProof("any_user10_live_task_rejects",p->p.getJSONObject("before").getJSONObject("live").getJSONArray("target_task_ids").put(55));
        no("owned_target_recent_task_rejects",()->{PublicProfileAbsenceRecovery.Request r=request(copy());
            PublicProfileAbsenceRecovery.validate(proof(r,recentsBefore,recentsAfter.replace("com.motorola.maxesetting",r.target.packageName)),r,now+4025,boot);});
        invalidProof("recent_truncation_cannot_be_empty",p->p.getJSONObject("before").getJSONObject("recents").put("raw_text","ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)"));
        invalidProof("same_name_display_any_id_rejects",p->p.getJSONObject("after").getJSONObject("displays").put("exact_name_absent",false));
        invalidProof("census_permission_failure_rejects",p->p.getJSONObject("before").getJSONObject("process").put("complete",false));
        invalidProof("broker_child_alive_rejects",p->p.getJSONObject("after").getJSONObject("process").put("old_creator_absent",false));
        invalidProof("checker_pid_aba_rejects",p->p.getJSONObject("after").getJSONObject("process").put("self_start_ticks",123457));
        invalidProof("physical0_change_rejects",p->p.getJSONObject("after").getJSONObject("physical").put("0","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        invalidProof("physical1_missing_rejects",p->p.getJSONObject("after").getJSONObject("physical").remove("1"));
        invalidProof("clock_order_reversed_rejects",p->p.getJSONObject("after").put("started_elapsed_ms",now+2));
        invalidProof("claims_historical_no_create_rejects",p->p.put("historical_creation_unknown",false));
        invalidProof("claims_broker_release_rejects",p->p.put("broker_release_response",true));
        invalidProof("resume_authority_rejects",p->p.put("automatic_resume",true));
        no("expired_proof_rejects",()->{PublicProfileAbsenceRecovery.Request r=request(copy());PublicProfileAbsenceRecovery.validate(proof(r),r,r.deadline,boot);});
        no("request_wire_trailing_data_rejects",()->{String wire=request(copy()).wire();PublicProfileAbsenceRecovery.fromWire(wire+"AAAA");});
        yes("actual_foreign_dormant_history_preserved_without_profile_empty_claim",()->{
            PublicProfileAbsenceRecovery.Request r=request(copy());JSONObject p=proof(r);
            PublicProfileAbsenceRecovery.validate(p,r,now+4025,boot);
            JSONObject a=p.getJSONObject("before").getJSONObject("recents"),b=p.getJSONObject("after").getJSONObject("recents");
            if(a.getBoolean("profile_empty")||b.getBoolean("profile_empty")||!recentsBefore.equals(a.getString("raw_text"))
                    ||!recentsAfter.equals(b.getString("raw_text")))throw new AssertionError("foreign history was removed or called empty");
            if(p.toString().getBytes(StandardCharsets.UTF_8).length+1>PublicProfileAbsenceRecovery.MAX_OUTPUT)
                throw new AssertionError("complete actual-history proof exceeds existing transport bound");
        });
        invalidProof("old_v1_whole_profile_empty_receipt_rejects",p->p.put("schema","hepta.public-profile-current-absence.v1"));
        invalidProof("history_preservation_flag_required",p->p.put("foreign_dormant_history_preserved",false));
        invalidProof("raw_history_tampering_cannot_keep_old_summary",p->p.getJSONObject("after").getJSONObject("recents")
                .put("raw_text",recentsAfter.replace("cc00009","cc0000a")));
        no("changed_foreign_token_rejects_even_with_freshly_parsed_evidence",()->{PublicProfileAbsenceRecovery.Request r=request(copy());
            PublicProfileAbsenceRecovery.validate(proof(r,recentsBefore,recentsAfter.replace("cc00009","cc0000a")),r,now+4025,boot);});
        no("changed_last_active_time_is_not_inactivity_growth",()->{PublicProfileAbsenceRecovery.Request r=request(copy());
            PublicProfileAbsenceRecovery.validate(proof(r,recentsBefore,recentsAfter.replace("lastActiveTime=288126118","lastActiveTime=288126119")),r,now+4025,boot);});
        no("foreign_profile_activity_rejects",()->{PublicProfileAbsenceRecovery.Request r=request(copy());
            String active=recentsAfter.replace("    Activities=[]\n    mRootProcess=ProcessRecord{8bf7cb", "    Activities=[ActivityRecord{123456 u10 com.motorola.maxesetting/.IntroActivity t1430}]\n    mRootProcess=ProcessRecord{8bf7cb");
            if(active.equals(recentsAfter))throw new AssertionError("actual foreign Activities seam changed");
            PublicProfileAbsenceRecovery.validate(proof(r,recentsBefore,active),r,now+4025,boot);});
        no("inactivity_age_cannot_move_backwards",()->{PublicProfileAbsenceRecovery.Request r=request(copy());
            PublicProfileAbsenceRecovery.validate(proof(r,recentsBefore,recentsAfter.replace("inactive for 67010s","inactive for 67005s")),r,now+4025,boot);});
        no("inactivity_growth_exceeding_actual_sample_interval_rejects",()->{PublicProfileAbsenceRecovery.Request r=request(copy());
            PublicProfileAbsenceRecovery.validate(proof(r,recentsBefore,recentsAfter.replace("inactive for 67010s","inactive for 67110s")),r,now+4025,boot);});
        JSONObject result=new JSONObject().put("schema","hepta.public-profile-absence-host-tests.v1").put("passed",true).put("checks",passed).put("cases",cases)
                .put("actual_original_inputs",request(copy()).inputHashes()).put("wire_bytes",request(copy()).wire().length())
                .put("actual_history_inputs",new JSONObject().put("before_sha256",ProfileIdentity.sha(recentsBefore)).put("after_sha256",ProfileIdentity.sha(recentsAfter)))
                .put("synthetic_sample_interval_ms",4008).put("actual_history_proof_bytes",proof(request(copy())).toString().getBytes(StandardCharsets.UTF_8).length+1)
                .put("original_failure_task_unmodified",true).put("framework_samples_synthetic",true).put("current_controller_identity_synthetic",true)
                .put("phone_contacted",false).put("android_runtime",false);
        System.out.println(result.toString());
    }
}
