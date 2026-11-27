package org.trillionnium.hepta.background;

import java.io.IOException;
import java.util.*;
import org.json.*;

/** Executes whole production ProfileOwnedTask. Android/framework latency ports are
 * synthetic. The ce5 timestamps constrain a projection; no unrecorded Binder
 * subcall duration or new phone cleanup success is asserted. */
public final class ProfileCleanupRecentsFirstHostTest {
    static final long START=1117035229L;
    static final JSONArray CASES=new JSONArray();
    static int assertions,failures;
    static Frame active;
    interface Work {void run()throws Exception;}
    static void yes(boolean v,String reason){assertions++;if(!v)throw new AssertionError(reason);}
    static void test(String name,Work work){
        int n=assertions;active=null;
        try {work.run();CASES.put(new JSONObject().put("name",name).put("passed",true)
            .put("assertions",assertions-n).put("actual_host_trace",active==null?JSONObject.NULL:active.evidence()));}
        catch(Throwable e){failures++;CASES.put(new JSONObject().put("name",name).put("passed",false)
            .put("assertions",assertions-n).put("error",e.toString())
            .put("actual_host_trace",active==null?JSONObject.NULL:active.evidence()));}
    }
    static final class Frame extends ProfileCleanupSettleFixtures.Platform {
        final String scenario;
        final List<Map<String,Object>> reads=new ArrayList<Map<String,Object>>();
        ProfileOwnedTask.CleanupPhase phase;
        String refusal;
        int leafGuards,rootGuards,postChildren,rawCalls;
        boolean replayOpaqueLateSample,retainedInterval,displayPresent=true;
        int releases,retainedBeforeReads,retainedAfterReads;
        Frame(String name){scenario=name;firstMixedReadOffset=1000;firstMixedPause=29;}
        void init(boolean normal)throws Exception{
            active= this;active(true);
            started=START;originalDeadline=START+1400;f.now=START;
            if(normal){
                phase=owner.beginNormalCleanup(started,started+3500,()->custody.normalCleanupAllowed());
                yes(phase!=null,"actual factory refused prepared public owner");
                ioDeadline=()->phase.ioDeadline();
            }else ioDeadline=()->originalDeadline;
            replayOpaqueLateSample="ce5".equals(scenario);
        }
        void row(String kind,Map<String,Object> details){
            Map<String,Object> v=new LinkedHashMap<String,Object>();
            v.put("kind",kind);v.put("elapsed_ms",f.now);v.putAll(details);reads.add(v);
        }
        @Override public ProfileTaskPolicy.Snapshot snapshot()throws Exception{
            ProfileTaskPolicy.Snapshot s=super.snapshot();
            if(removed)row("complete_global",Collections.<String,Object>singletonMap("all_ids",new ArrayList<Integer>(s.allIds)));
            return s;
        }
        @Override public String publicRecentsDump()throws Exception{
            // ce5 archives no per-Binder timing. This is one explicitly synthetic
            // opaque slow read after the observed 29 ms retry boundary, not a
            // claim that Android's recents Binder consumed the real 2,113 ms.
            subsequentReadCost=replayOpaqueLateSample&&!retainedInterval&&pausedAfterMixed&&!deleted?2113:0;
            String value=super.publicRecentsDump();
            if(removed){
                rawCalls++;
                if(!retainedInterval&&postReads==1){
                    if("sample_expiry".equals(scenario))f.now=START+43+1500;
                    if("total_expiry".equals(scenario))f.now=START+3000;
                    if("live_remains".equals(scenario)){f.app=true;f.recentsApp=false;value=raw;}
                    if("recent_remains".equals(scenario)){f.app=false;f.recentsApp=true;value=ProfileCleanupSettleFixtures.leafRecent(raw);}
                    if("foreign_recent".equals(scenario))value=ProfileCleanupSettleFixtures.leafRecent(raw).replace("#300","#301")
                        .replace("t300}","t301}").replace("taskId=300","taskId=301");
                    if("truncated".equals(scenario))value=value.substring(0,value.length()-80);
                }
                row("complete_raw_recents",Collections.<String,Object>singletonMap("sha256",ProfileIdentity.sha(value)));
            }
            return value;
        }
        @Override public List<BackgroundOwnedSingleTask.Task> children(Object token){
            List<BackgroundOwnedSingleTask.Task> v=super.children(token);
            if(removed&&transitioned&&!deleted&&!retainedInterval){
                postChildren++;
                if(postChildren==1){
                    if("foreign_after_sample_children".equals(scenario))f.foreign=true;
                    if("identity_after_sample_children".equals(scenario))f.actual=ProfileBrokerHostTest.target(11,1010367);
                    if("token_after_sample_children".equals(scenario))f.rootToken=new Object();
                }
            }
            return v;
        }
        @Override public void removeLeaf(Object token,ProfileOwnedTask.CleanupEffectCheck check)throws Exception{
            f.now=START+41;leafGuards++;check.check();super.removeLeaf(token);f.now=START+43;
        }
        @Override public boolean deleteRoot(Object token,ProfileOwnedTask.CleanupEffectCheck check)throws Exception{
            if("late_root_guard".equals(scenario))f.now+=1500;
            if("quarantined_root_guard".equals(scenario))custody.unresolved();
            rootGuards++;check.check();return super.deleteRoot(token);
        }
        void retire()throws Exception{
            try{owner.retire(originalDeadline);}
            catch(Exception e){refusal=e.getClass().getName()+": "+e.getMessage();custody.unresolved();}
        }
        JSONObject evidence(){
            JSONObject out=new JSONObject().put("refusal",refusal==null?JSONObject.NULL:refusal)
                .put("clock",f.now).put("leaf_calls",removeCalls).put("root_calls",deleteCalls)
                .put("leaf_guards",leafGuards).put("root_guards",rootGuards).put("raw_reads",rawCalls)
                .put("post_leaf_children_reads",postChildren).put("pause_after_first_history",pausedAfterMixed)
                .put("cleanup_known",owner!=null&&owner.cleanupKnown()).put("reads",reads).put("events",events);
            if(phase!=null)out.put("phase",phase.evidence());
            return out;
        }
        ProfileOwnedTask.RetiredDisplay retainedHandle(){
            return new ProfileOwnedTask.RetiredDisplay(){
                @Override public void beginFreshSample(long began,long deadline){
                    ioDeadline=()->deadline;
                }
                @Override public void requireState(boolean before)throws Exception{
                    if(before){retainedBeforeReads++;if(!displayPresent)throw new IOException("fixture display missing");}
                    else {retainedAfterReads++;if(displayPresent)throw new IOException("fixture display present");}
                }
                @Override public void releaseOriginalHandle()throws Exception{
                    if(!displayPresent)throw new IOException("fixture display replay");
                    releases++;displayPresent=false;
                }
                @Override public void awaitAbsent()throws Exception{
                    if(displayPresent)throw new IOException("fixture display remains");
                }
            };
        }
    }
    static Frame fresh(String scenario)throws Exception{Frame f=new Frame(scenario);f.init(true);return f;}
    static void rejected(Frame f,String messagePart)throws Exception{
        f.retire();
        yes(f.refusal!=null&&f.refusal.contains(messagePart),"wrong or missing refusal: "+f.refusal);
        yes(f.removeCalls==1&&f.deleteCalls==0,"unexpected leaf/root effects");
        yes(!f.owner.cleanupKnown()&&f.custody.retain(),"failure accepted or custody released");
        yes(f.phase!=null&&Boolean.TRUE.equals(f.phase.evidence().get("failed")),"phase failure did not latch");
        yes(((Number)f.phase.evidence().get("root_effect_entered_elapsed_ms")).longValue()<0,"root claim occurred");
        yes(f.rawCalls>0||f.readNeverEnds,"negative did not reach post-leaf raw sample");
        yes(f.phase.originalDeadline==START+1400&&f.phase.convergenceDeadline==START+3000,"budgets changed");
    }
    static void emit(){
        System.out.println(new JSONObject().put("schema","hepta.ce5-cleanup-recents-first.cases.v1")
            .put("all_pass",failures==0).put("case_count",CASES.length()).put("assertions",assertions)
            .put("cases",CASES).put("whole_profile_owned_task_compiled",true)
            .put("complete_public_history_parser_used",true)
            .put("original_task_ce5_timestamps",Arrays.asList(1117035229L,1117035270L,1117035272L,1117036229L,1117036258L,1117038371L))
            .put("per_binder_timing_unknown",true).put("framework_clock_effect_ports_synthetic",true)
            .put("same_target_package_as_ce5",false).put("fixture_profile_package","ctrip.android.view")
            .put("phone_operations",0).put("device_qualified",false));
    }
    public static void main(String[] args)throws Exception{
        ProfileCleanupSettleFixtures.load(args[0]);
        test("ce5_mixed_pair_projection_uses_new_live_census_before_one_root_effect",()->{
            Frame f=fresh("ce5");f.retire();
            yes(f.owner.cleanupKnown()&&f.refusal==null,"required normal cleanup did not complete");
            yes(f.removeCalls==1&&f.deleteCalls==1&&f.leafGuards==1&&f.rootGuards==1,"actual effect guards not exactly once");
            yes(!f.pausedAfterMixed,"history/live mixed pair forced avoidable full retry");
            yes(f.f.now==START+1000,"projection used a synthetic extra delay or advanced deadline");
            yes(f.phase.originalDeadline==START+1400&&f.phase.convergenceDeadline==START+3000,"budget changed");
            yes(((Number)f.phase.evidence().get("leaf_effect_entered_elapsed_ms")).longValue()==START+41
                &&((Number)f.phase.evidence().get("leaf_effect_returned_elapsed_ms")).longValue()==START+43,"known leaf timing changed");
            int raw=-1,global=-1;for(int i=0;i<f.reads.size();i++){
                String k=(String)f.reads.get(i).get("kind");
                if(raw<0&&"complete_raw_recents".equals(k))raw=i;
                if(global<0&&"complete_global".equals(k))global=i;
            }
            yes(raw>=0&&global>raw,"no actual full recents-before-global path");
            yes(f.postChildren>=2,"unchanged final complete live pair was skipped");
            yes(f.displayPresent&&f.releases==0,"task proof falsely released display");
        });
        if(args.length>1&&"old-first".equals(args[1])){emit();if(failures!=0)System.exit(1);return;}
        test("asynchronous_foreign_live_after_sample_children_refused_by_final_pair",()->{
            Frame f=fresh("foreign_after_sample_children");rejected(f,"PROFILE_ALREADY_HAS_LEAF_TASK");
            yes(f.postChildren>=2&&f.f.foreign,"final live-pair mutation was not reached");
        });
        test("actual_installation_identity_changes_after_history_are_not_cached",()->{
            Frame f=fresh("identity_after_sample_children");rejected(f,"PROFILE_INSTALLATION_IDENTITY_CHANGED");
            yes(f.postChildren==1,"identity change did not hit final recheck before child read");
        });
        test("actual_root_token_replacement_after_history_is_refused",()->{
            Frame f=fresh("token_after_sample_children");rejected(f,"PROFILE_ROOT_TOKEN_CHANGED");
        });
        test("root_cookie_disappearance_refused",()->{
            Frame f=fresh("root_cookie");f.rootCookieMissing=true;rejected(f,"PROFILE_ROOT_IDENTITY_CHANGED");
        });
        test("additional_child_after_full_raw_absence_refused",()->{
            Frame f=fresh("new_child");f.newChild=true;rejected(f,"PROFILE_ROOT_CHILDREN_REMAIN");
        });
        test("owned_leaf_moved_outside_display_refused",()->{
            Frame f=fresh("moved_leaf");f.moveLeaf=true;rejected(f,"PROFILE_FOREIGN_DISPLAY_LEAF");
        });
        test("complete_raw_foreign_profile_recent_refused",()->{
            Frame f=fresh("foreign_recent");f.retire();
            yes(f.rawCalls==1&&f.refusal!=null,"foreign raw sample not reached");
            yes(Boolean.TRUE.equals(f.history.evidence().get("history_refusal_latched")),"full history parser did not latch foreign refusal");
            yes(f.removeCalls==1&&f.deleteCalls==0&&!f.owner.cleanupKnown(),"foreign recent authorized root");
        });
        test("protected_nonphysical_history_change_still_refused",()->{
            Frame f=fresh("history_change");f.changedHistory=true;f.retire();
            yes(f.rawCalls==1&&Boolean.TRUE.equals(f.history.evidence().get("history_refusal_latched")),"history change not observed");
            yes(f.refusal!=null&&f.removeCalls==1&&f.deleteCalls==0&&!f.owner.cleanupKnown(),"history refusal ignored");
        });
        test("incomplete_raw_history_never_becomes_full_census",()->{
            Frame f=fresh("truncated");f.retire();
            yes(f.rawCalls==1&&f.refusal!=null&&f.deleteCalls==0&&!f.owner.cleanupKnown(),"truncated history promoted");
        });
        test("one_complete_sample_at_1500ms_refused",()->{
            Frame f=fresh("sample_expiry");rejected(f,"PROFILE_NORMAL_CLEANUP_CENSUS_STALE_OR_DEADLINE");
            yes(f.f.now==START+1543&&f.f.now<START+3000,"per-sample guard not independently tested");
        });
        test("total_convergence_at_3000ms_refused",()->{
            Frame f=fresh("total_expiry");rejected(f,"PROFILE_NORMAL_CLEANUP_CENSUS_STALE_OR_DEADLINE");
            yes(f.f.now==START+3000,"total deadline changed");
        });
        test("live_leaf_present_with_absent_recents_never_authorizes_root",()->{
            Frame f=fresh("live_remains");rejected(f,"PROFILE_LEAF_RETIRE_NOT_CONFIRMED");
            yes(f.f.app&&!f.f.recentsApp&&f.rawCalls>1,"live/recents disagreement not exercised");
        });
        test("live_leaf_absent_with_present_recents_never_authorizes_root",()->{
            Frame f=fresh("recent_remains");rejected(f,"PROFILE_LEAF_RETIRE_NOT_CONFIRMED");
            yes(!f.f.app&&f.f.recentsApp&&f.rawCalls>1,"recents/live disagreement not exercised");
        });
        test("real_root_effect_guard_rejects_expired_sample",()->{
            Frame f=fresh("late_root_guard");rejected(f,"PROFILE_NORMAL_CLEANUP_CENSUS_STALE_OR_DEADLINE");
            yes(f.rootGuards==1&&f.postChildren>=2,"actual callback was not reached");
        });
        test("real_root_effect_guard_rejects_quarantine",()->{
            Frame f=fresh("quarantined_root_guard");rejected(f,"PROFILE_NORMAL_CLEANUP_RETIRED");
            yes(f.rootGuards==1,"actual callback was not reached");
        });
        test("legacy_public_without_normal_phase_keeps_global_first_and_original_deadline",()->{
            Frame f=new Frame("legacy");f.init(false);f.replayOpaqueLateSample=true;f.retire();
            yes(f.phase==null&&f.refusal!=null&&f.removeCalls==1&&f.deleteCalls==0,"legacy path became normal success");
            yes("complete_global".equals(f.reads.get(0).get("kind"))&&f.pausedAfterMixed,"legacy order changed");
            yes(f.originalDeadline==START+1400&&!f.owner.cleanupKnown(),"legacy deadline changed");
        });
        test("retained_interval_keeps_old_failure_and_real_double_absence_without_leaf_replay",()->{
            Frame f=fresh("retained");f.readNeverEnds=true;f.retire();
            yes(f.refusal!=null&&f.removeCalls==1&&f.deleteCalls==0&&!f.owner.cleanupKnown(),"normal failure not reached");
            JSONObject oldCleanup=new JSONObject(f.owner.cleanupEvidence());
            Map<String,Object> oldHistory=new LinkedHashMap<String,Object>(f.history.evidence());
            f.readNeverEnds=false;f.retainedInterval=true;f.f.now=START+5000;
            f.ioDeadline=()->START+6000;
            ProfileOwnedTask.RetainedCleanupProof proof=f.owner.cleanupRetained(START+6000,f.retainedHandle());
            yes(proof!=null&&f.releases==1&&!f.displayPresent,"retained fresh interval did not prove original display");
            yes(f.removeCalls==1&&f.deleteCalls==1,"retained repeated old leaf or root");
            yes(f.retainedBeforeReads>=2&&f.retainedAfterReads==2,"retained fresh double absence omitted");
            yes(oldHistory.equals(f.history.evidence())&&oldCleanup.similar(new JSONObject(f.owner.cleanupEvidence())),"old failed evidence rewritten");
            yes(!f.owner.cleanupKnown(),"retained interval rewrote original cleanup");
            f.custody.retainedCleanupObservedAbsent(f.owner,proof);
            yes(f.custody.known()&&!f.custody.retain(),"actual retained proof not consumed");
            boolean refused=false;try{f.owner.cleanupRetained(START+6000,f.retainedHandle());}catch(Exception e){refused=true;}
            yes(refused&&f.releases==1&&f.deleteCalls==1,"retained cleanup replayed");
        });
        emit();if(failures!=0)System.exit(1);
    }
}
