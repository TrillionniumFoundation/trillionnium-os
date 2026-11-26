package org.trillionnium.hepta.background;
import java.util.*;
import java.lang.reflect.Modifier;
import org.json.*;

/** Production owner, custody, close worker, close wait and final Binder guards.
 * Android services/clock remain explicit synthetic ports; no phone qualification. */
public final class ProfileCleanupSettleHostTest {
    interface Work {void run()throws Exception;}
    interface Setup {void apply(ProfileTaskPlatform f,ProfileCleanupBrokerHost b)throws Exception;}
    static final JSONArray cases=new JSONArray();static int assertions,failedCases;
    static void yes(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static void test(String name,Work run)throws Exception{
        int before=assertions;
        try{run.run();cases.put(new JSONObject().put("name",name).put("assertions",assertions-before).put("passed",true));}
        catch(Throwable failure){
            failedCases++;cases.put(new JSONObject().put("name",name).put("assertions",assertions-before)
                .put("passed",false).put("error",failure.toString()));
        }
    }
    static String refuses(Work run)throws Exception{
        try{run.run();throw new AssertionError("expected explicit refusal");}
        catch(Exception e){Throwable cause=e;while(cause.getCause()!=null)cause=cause.getCause();
            assertions++;return cause.getMessage();}
    }
    static ProfileCleanupBrokerHost run(Setup setup)throws Exception{
        ProfileTaskPlatform f=new ProfileTaskPlatform();f.active(true);
        ProfileCleanupBrokerHost b=new ProfileCleanupBrokerHost(f);setup.apply(f,b);
        JSONObject reply=b.closeResult();
        yes(b.cleanupDone.getCount()==0,"actual cleanup worker not drained");
        yes(reply.getBoolean("ok")==("RELEASED".equals(b.state)),"reply/state mismatch");
        yes(b.requestDeadline<=f.started+3500,"original close request changed");
        return b;
    }
    static void failed(ProfileCleanupBrokerHost b,int leaf,int root,String reason)throws Exception{
        ProfileTaskPlatform f=b.io;
        yes("CLEANUP_UNKNOWN".equals(b.state),"failure accepted");
        yes(f.removeCalls==leaf&&f.deleteCalls==root,"unexpected effect count "+f.removeCalls+"/"+f.deleteCalls);
        yes(b.displayReleaseCalls==0,"failure released display");
        yes(b.profileCustody.retain()&&!b.profileCustody.known()&&!b.profileCustody.normalCleanupAllowed(),"quarantine revived");
        JSONObject first=new JSONObject(b.profileCleanupFailures.evidence()).getJSONObject("first_failure");
        String actual=first.getString("code");yes(reason.equals(actual),"wrong refusal "+actual+" != "+reason);
        if(b.normalProfileCleanup!=null){
            yes(Boolean.TRUE.equals(b.normalProfileCleanup.evidence().get("failed")),"phase not latched failed");
            yes("PROFILE_NORMAL_CLEANUP_RETIRED".equals(refuses(()->b.normalProfileCleanup.beginRead(f.owner))),
                "late read callback revived phase");
        }
    }
    public static void main(String[] args)throws Exception{
        ProfileCleanupSettleFixtures.load(args[0]);
        test("actual_close_worker_mixed_global_recents_survives_old_1400_with_one_leaf_root_and_display",()->{
            ProfileCleanupBrokerHost b=run((f,x)->{});ProfileTaskPlatform f=b.io;
            yes("RELEASED".equals(b.state)&&f.owner.cleanupKnown()&&b.profileCustody.known(),"new bounded phase did not settle");
            yes(f.f.now-f.started==1408,"same measured-boundary projection changed");
            yes(f.removeCalls==1&&f.deleteCalls==1&&b.displayReleaseCalls==1,"effect replay or missing effect");
            yes(b.normalProfileCleanup.originalDeadline==f.started+1400
                &&b.normalProfileCleanup.convergenceDeadline==f.started+3000,"original/total bounds changed");
            yes(((Number)b.normalProfileCleanup.evidence().get("root_effect_entered_elapsed_ms")).longValue()>f.originalDeadline,
                "test did not exercise independently fresh later root cleanup");
            yes(!b.watchdogWouldFire(f.started+1500),"old watchdog incorrectly killed qualified read convergence");
            yes(!b.displayPresent&&!b.profileCustody.retain(),"owned display still live");
            yes(f.f.mutations.equals(Arrays.asList("create","bind","remove_leaf","delete_root")),"cleanup widened effects");
        });
        test("actual_close_waits_second_bounded_interval_after_first_await_expires",()->{
            ProfileCleanupBrokerHost b=run((f,x)->{
                f.mixedReached=new java.util.concurrent.CountDownLatch(1);
                f.continueMixed=new java.util.concurrent.CountDownLatch(1);
                x.forceFirstAwaitExpiry=true;
            });
            yes("RELEASED".equals(b.state)&&b.awaitCalls==2,"qualified second wait not used");
            yes(b.io.f.now-b.io.started==1500,"deterministic wait projection changed");
            yes(b.io.removeCalls==1&&b.io.deleteCalls==1&&b.displayReleaseCalls==1,"second wait repeated effects");
            yes(b.requestDeadline==b.io.started+3500,"request deadline extended");
        });
        test("legacy_no_optional_phase_still_refuses_at_same_1408",()->{
            ProfileCleanupSettleFixtures.Platform f=new ProfileCleanupSettleFixtures.Platform();f.active(true);
            yes("PROFILE_LEAF_RETIRE_NOT_CONFIRMED".equals(refuses(()->f.owner.retire(f.originalDeadline))),"legacy deadline changed");
            yes(f.f.now-f.started==1408&&f.removeCalls==1&&f.deleteCalls==0&&!f.owner.cleanupKnown(),"legacy result changed");
        });
        test("private_owner_cannot_construct_public_convergence_phase",()->{
            ProfileTaskPlatform f=new ProfileTaskPlatform();f.active(false);
            yes(f.owner.beginNormalCleanup(f.started,f.started+3500,()->f.custody.normalCleanupAllowed())==null,"private upgraded");
        });
        test("request_deadline_binds_total_before_3500",()->{
            ProfileCleanupBrokerHost b=run((f,x)->x.requestDeadline=f.started+2500);
            yes("RELEASED".equals(b.state)&&b.normalProfileCleanup.convergenceDeadline==b.io.started+2350,"request bound not retained");
        });
        test("short_close_request_cannot_activate_continuation",()->{
            ProfileCleanupBrokerHost b=run((f,x)->x.requestDeadline=f.started+1500);
            failed(b,1,0,"PROFILE_LEAF_RETIRE_NOT_CONFIRMED");yes(b.normalProfileCleanup==null,"short request extended");
        });
        test("late_leaf_return_cannot_activate_read_phase_or_delete_root",()->{
            ProfileCleanupBrokerHost b=run((f,x)->f.leafReturnLate=true);
            failed(b,1,0,"PROFILE_NORMAL_CLEANUP_CENSUS_STALE_OR_DEADLINE");
            yes(Boolean.FALSE.equals(b.normalProfileCleanup.evidence().get("read_convergence_activated")),"late effect opened phase");
        });
        test("throwing_leaf_is_claimed_once_without_continuation",()->{
            ProfileCleanupBrokerHost b=run((f,x)->f.leafThrows=true);
            failed(b,1,0,"REMOVE_FAILED");
            yes(Boolean.FALSE.equals(b.normalProfileCleanup.evidence().get("read_convergence_activated")),"throwing leaf opened phase");
        });
        test("real_leaf_adapter_final_guard_after_location_preparation_refuses_stale",()->{
            ProfileCleanupBrokerHost b=run((f,x)->f.organizer.leafPreparationDelay=1500);
            failed(b,0,0,"PROFILE_NORMAL_CLEANUP_CENSUS_STALE_OR_DEADLINE");
        });
        test("real_leaf_adapter_final_guard_after_quarantine_refuses",()->{
            ProfileCleanupBrokerHost b=run((f,x)->f.organizer.quarantineAtLeafPreparation=true);
            failed(b,0,0,"PROFILE_NORMAL_CLEANUP_RETIRED");
        });
        test("root_actual_binder_replacement_after_old_deadline_refused",()->{
            failed(run((f,x)->f.rootReplacement=true),1,0,"PROFILE_ROOT_TOKEN_CHANGED");
        });
        test("root_uid_change_after_old_deadline_refused",()->{
            failed(run((f,x)->f.rootUidChanged=true),1,0,"PROFILE_ROOT_TOKEN_CHANGED");
        });
        test("root_cookie_disappearance_after_old_deadline_refused",()->{
            failed(run((f,x)->f.rootCookieMissing=true),1,0,"PROFILE_ROOT_IDENTITY_CHANGED");
        });
        test("new_child_after_leaf_remove_prevents_root_effect",()->{
            failed(run((f,x)->f.newChild=true),1,0,"PROFILE_ROOT_CHILDREN_REMAIN");
        });
        test("owned_leaf_id_on_other_display_never_becomes_absence",()->{
            failed(run((f,x)->f.moveLeaf=true),1,0,"PROFILE_FOREIGN_DISPLAY_LEAF");
        });
        test("protected_nonphysical_history_change_still_latches",()->{
            ProfileCleanupBrokerHost b=run((f,x)->f.changedHistory=true);
            yes("CLEANUP_UNKNOWN".equals(b.state)&&b.io.removeCalls==1&&b.io.deleteCalls==0&&b.displayReleaseCalls==0,"changed history removed root");
            yes(Boolean.TRUE.equals(b.io.history.evidence().get("history_refusal_latched")),"history change not latched");
        });
        test("installed_profile_identity_change_before_next_read_refused",()->{
            failed(run((f,x)->f.changedIdentity=true),1,0,"PROFILE_INSTALLATION_IDENTITY_CHANGED");
        });
        test("new_foreign_profile_task_during_wait_refused",()->{
            failed(run((f,x)->f.foreignAfterMixed=true),1,0,"PROFILE_ALREADY_HAS_LEAF_TASK");
        });
        test("single_full_read_beyond_fresh_sample_or_total_budget_refused",()->{
            failed(run((f,x)->f.readNeverEnds=true),1,0,"PROFILE_RECENTS_DEADLINE");
        });
        test("never_absent_leaf_not_replayed_and_fixed_phase_expires",()->{
            ProfileCleanupBrokerHost b=run((f,x)->f.neverAbsent=true);
            failed(b,1,0,"PROFILE_LEAF_RETIRE_NOT_CONFIRMED");
            yes(b.io.f.now>=b.io.started+3000&&b.io.f.now<b.io.started+3500,"unbounded convergence");
        });
        test("delete_root_false_never_replayed_or_promoted",()->{
            failed(run((f,x)->f.rootFalse=true),1,1,"PROFILE_ROOT_DELETE_NOT_ACCEPTED");
        });
        test("delete_root_throw_never_replayed_or_promoted",()->{
            failed(run((f,x)->f.rootThrows=true),1,1,"DELETE_FAILED");
        });
        test("actual_root_adapter_final_guard_after_location_preparation_refuses_stale",()->{
            failed(run((f,x)->f.organizer.rootPreparationDelay=1500),1,0,"PROFILE_NORMAL_CLEANUP_CENSUS_STALE_OR_DEADLINE");
        });
        test("actual_root_adapter_final_guard_after_quarantine_refuses",()->{
            failed(run((f,x)->f.organizer.quarantineAtRootPreparation=true),1,0,"PROFILE_NORMAL_CLEANUP_RETIRED");
        });
        test("late_root_return_does_not_release_display",()->{
            failed(run((f,x)->f.rootReturnLate=true),1,1,"PROFILE_NORMAL_CLEANUP_CENSUS_STALE_OR_DEADLINE");
        });
        test("original_display_fresh_identity_replacement_refused",()->{
            failed(run((f,x)->x.replaceDisplayIdentity=true),1,1,"DISPLAY_IDENTITY_CHANGED");
        });
        test("actual_display_release_guard_rejects_stale_framework_read",()->{
            failed(run((f,x)->x.displayPreparationDelay=1500),1,1,"PROFILE_NORMAL_CLEANUP_CENSUS_STALE_OR_DEADLINE");
        });
        test("actual_display_release_guard_rejects_quarantine_after_framework_read",()->{
            failed(run((f,x)->x.quarantineBeforeDisplay=true),1,1,"PROFILE_NORMAL_CLEANUP_RETIRED");
        });
        test("quarantined_before_worker_never_falls_back_to_old_effect_path",()->{
            ProfileCleanupBrokerHost b=run((f,x)->f.custody.unresolved());
            failed(b,0,0,"PROFILE_CUSTODY_QUARANTINED");
        });
        test("quarantine_during_read_discards_frame_and_never_resumes",()->{
            failed(run((f,x)->f.quarantineAfterMixed=true),1,0,"PROFILE_NORMAL_CLEANUP_RETIRED");
        });
        test("quarantine_after_display_return_cannot_be_rewritten_released",()->{
            ProfileCleanupBrokerHost b=run((f,x)->f.onRead=()->{if(x.displayReleaseCalls>0)f.custody.unresolved();});
            yes(b.displayReleaseCalls==1&&"CLEANUP_UNKNOWN".equals(b.state)&&!b.profileCustody.known(),"late proof revived quarantine");
            yes(b.io.removeCalls==1&&b.io.deleteCalls==1,"post-display effect repeated");
        });
        test("cancelled_business_may_retire_owned_resources_but_never_resume_actions",()->{
            ProfileCleanupBrokerHost b=run((f,x)->f.f.cancel=true);
            yes("RELEASED".equals(b.state)&&b.io.f.cancel,"cancellation reset or owned cleanup blocked");
            yes("PROFILE_WINDOW_REQUEST_INVALID".equals(refuses(()->b.io.owner.window(14,300,b.io.f.now+1000))),
                "retired business obtained window");
            yes(Boolean.FALSE.equals(b.normalProfileCleanup.evidence().get("business_admission_restored")),"business admission restored");
        });
        test("personal_main_task_close_and_reopen_remain_audit_only",()->{
            ProfileCleanupBrokerHost b=run((f,x)->f.personalChanges=true);
            yes("RELEASED".equals(b.state)&&b.io.f.snapshot().leaves.get(102).display==0,"main task affected");
            yes(((List<?>)b.io.owner.personalAudit().get("absent_task_ids")).contains(100)
                &&((List<?>)b.io.owner.personalAudit().get("new_task_ids")).contains(102),"main activity not audited");
        });
        test("phase_constructor_is_private_and_not_wire_deserializable",()->{
            yes(Modifier.isPrivate(ProfileOwnedTask.CleanupPhase.class.getDeclaredConstructors()[0].getModifiers()),"forgeable phase constructor");
            for(java.lang.reflect.Method m:ProfileOwnedTask.CleanupPhase.class.getDeclaredMethods())
                yes(!m.getName().equals("fromWire")&&!m.getName().equals("fromJson"),"serialized authority");
        });
        test("second_retire_call_never_repeats_effects",()->{
            ProfileCleanupBrokerHost b=run((f,x)->{});
            yes("PROFILE_RETIRE_ALREADY_ATTEMPTED".equals(refuses(()->b.io.owner.retire(b.io.originalDeadline))),"retire replay accepted");
            yes(b.io.removeCalls==1&&b.io.deleteCalls==1&&b.displayReleaseCalls==1,"retire replay effects");
        });
        System.out.println(new JSONObject().put("schema","hepta.profile-cleanup-settle-cases.v1").put("all_pass",failedCases==0)
            .put("cases",cases).put("case_count",cases.length()).put("assertions",assertions)
            .put("actual_changed_coordinator_and_close_worker_compiled",true).put("actual_adapter_effect_methods_extracted",true)
            .put("original_close_request_max_ms",3500).put("maximum_cleanup_convergence_from_start_ms",3000)
            .put("maximum_census_to_effect_age_ms",1500).put("synthetic_framework_clock_and_latency",true)
            .put("actual_277_per_read_census_available",false).put("phone_operations",0).put("device_qualified",false));
        if(failedCases!=0)System.exit(1);
    }
}
