package org.trillionnium.hepta.background;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;

/** Exact archived phone recents; TaskInfo/cookie/clock boundaries remain explicit host fixtures. */
public final class PublicProfileHistoryHostTest {
    private static String before,after;
    private static final ProfileTarget TARGET=ProfileBrokerHostTest.target(10,1010367);
    private static final String FOREIGN="Task{cc00009 #1430 type=standard A=1010285:com.motorola.maxesetting}";
    private static final JSONArray CASES=new JSONArray();
    private static int assertions;
    private interface Work {void run()throws Exception;}
    private static void yes(boolean good,String why){assertions++;if(!good)throw new AssertionError(why);}
    private static void pass(String name,Work body)throws Exception{body.run();CASES.put(name);}
    private static void reject(String name,Work body)throws Exception{
        try{body.run();}catch(Exception expected){assertions++;CASES.put(name);return;}
        throw new AssertionError("accepted: "+name);
    }
    private static String change(String raw,String old,String value){
        int at=raw.indexOf(old);yes(at>=0&&at==raw.lastIndexOf(old),"fixture seam is not unique: "+old);
        return raw.substring(0,at)+value+raw.substring(at+old.length());
    }
    private static String foreign(String raw,String old,String value){
        int a=raw.indexOf("  * Recent #2:"),b=raw.indexOf("  * Recent #3:");
        return raw.substring(0,a)+change(raw.substring(a,b),old,value)+raw.substring(b);
    }
    private static String hidden(String raw,String label){return change(raw,"mHiddenTasks=[","mHiddenTasks=["+label+", ");}
    private static PublicProfileRecentHistory.Snapshot snap(String raw)throws Exception{return PublicProfileRecentHistory.absence(raw,TARGET);}
    private static PublicProfileRecentHistory.Baseline baseline()throws Exception{return new PublicProfileRecentHistory.Baseline(snap(before),1000);}
    private static String reindex(String raw){Matcher m=Pattern.compile("(?m)^  \\* Recent #[0-9]+:").matcher(raw);StringBuffer out=new StringBuffer();int i=0;
        while(m.find())m.appendReplacement(out,Matcher.quoteReplacement("  * Recent #"+(i++)+":"));m.appendTail(out);return out.toString();}
    private static String leafRecord(){return "  * Recent #0: Task{aabb300 #300 type=standard A=1010367:ctrip.android.view}\n"
            +"    userId=10 effectiveUid=u10a367 mCallingUid=0\n    affinity=1010367:ctrip.android.view\n"
            +"    intent={flg=0x10000000 cmp="+ProfileBrokerHostTest.SPLASH+"}\n"
            +"    mActivityComponent="+ProfileBrokerHostTest.HOME+"\n"
            +"    Activities=[ActivityRecord{aabb u10 "+ProfileBrokerHostTest.HOME+" t300}]\n"
            +"    taskId=300 rootTaskId=200\n    lastActiveTime=355000000 (inactive for 0s)\n    lastDisplayId=7\n";}
    private static String withLeaf(String raw){return reindex(change(raw,"  Recent tasks:\n","  Recent tasks:\n"+leafRecord()));}
    private static BackgroundOwnedSingleTask.Task root(){return new BackgroundOwnedSingleTask.Task(200,7,0,-1,0,-1,0,new Object(),
            java.util.Collections.singletonList(new Object()),null,null,null,null,null,false,false);}
    private static BackgroundOwnedSingleTask.Task leaf(BackgroundOwnedSingleTask.Task root){return new BackgroundOwnedSingleTask.Task(300,7,10,root.id,1010367,1010367,1,new Object(),
            java.util.Collections.singletonList(new Object()),ProfileBrokerHostTest.SPLASH,ProfileBrokerHostTest.SPLASH,
            ProfileBrokerHostTest.HOME,ProfileBrokerHostTest.SPLASH,null,true,true);}
    private static final class Platform implements ProfileOwnedTask.Platform {
        final ProfileBrokerHostTest.Fake delegate=new ProfileBrokerHostTest.Fake();String raw=before;boolean corruptOnRemove;
        public ProfileTarget recheck(boolean ready){return delegate.recheck(ready);}
        public void guard()throws Exception{delegate.guard();}
        public long now(){return delegate.now();}
        public Object newCookie(){return delegate.newCookie();}
        public ProfileTaskPolicy.Snapshot snapshot()throws Exception{return delegate.snapshot();}
        public ProfileTaskPolicy.Recents recents()throws Exception{throw new AssertionError("public path used private empty recents policy");}
        public String publicRecentsDump(){return delegate.recentsApp?withLeaf(raw):raw;}
        public List<BackgroundOwnedSingleTask.Task> roots(){return delegate.roots();}
        public List<BackgroundOwnedSingleTask.Task> children(Object token){return delegate.children(token);}
        public void createRoot(Object cookie){delegate.createRoot(cookie);}
        public void bindRoot(Object root,Object launch){delegate.bindRoot(root,launch);}
        public void removeLeaf(Object token)throws Exception{delegate.removeLeaf(token);if(corruptOnRemove)raw=change(raw,"cc00009","cc00008");}
        public boolean deleteRoot(Object token)throws Exception{return delegate.deleteRoot(token);}
        public void pause(){delegate.pause();}
        ProfileOwnedTask prepare()throws Exception{ProfileOwnedTask p=new ProfileOwnedTask(this,TARGET,ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7,baseline());p.prepare();return p;}
        ProfileOwnedTask active()throws Exception{ProfileOwnedTask p=prepare();p.beforeDispatch();delegate.launch();p.accepted(0);yes(p.observe(),"actual coordinator failed to own new leaf");return p;}
    }
    private static final class Retained {
        final Platform platform=new Platform();
        final ProfileOwnedTask task;
        final ProfileDisplayCustody custody=new ProfileDisplayCustody();
        int releases,before,after;
        String mutation="";
        Retained() throws Exception {
            task=platform.active();custody.beforeCreate();custody.unresolved();
            try{task.retire(platform.now());throw new AssertionError("expected original incomplete retirement");}
            catch(ProfileTaskPolicy.Refusal expected){yes(!task.cleanupKnown(),"original unknown missing");}
        }
        void run()throws Exception{
            task.closeRetainedEmptyDisplay(platform.now()+1000,new ProfileOwnedTask.RetiredDisplay(){
                public void requireState(boolean prior)throws Exception{
                    if(prior){
                        before++;
                        if(before==1){
                            if("new_child".equals(mutation))platform.delegate.app=true;
                            if("root_token_changes".equals(mutation))platform.delegate.rootToken=new Object();
                            if("wrong_display".equals(mutation))throw new IOException("changed VD identity");
                            if("new_recent".equals(mutation))platform.delegate.recentsApp=true;
                            if("source_changes".equals(mutation))platform.delegate.actual=ProfileBrokerHostTest.target(10,1010369);
                            if("physical_changed".equals(mutation))platform.delegate.personalClosed=true;
                            if("late".equals(mutation))platform.delegate.now+=1300;
                        }
                    }else{
                        after++;
                        if("display_held".equals(mutation))throw new IOException("still present");
                        if("late_foreign".equals(mutation))platform.delegate.foreign=true;
                        if("late_history".equals(mutation))platform.raw=change(platform.raw,"cc00009","cc00008");
                    }
                }
                public void awaitAbsent(){}
                public void releaseOriginalHandle(){releases++;if(!"root_held".equals(mutation))platform.delegate.root=false;}
            });
            custody.retainedObservedAbsent(task);
        }
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("archived recents fixture directory required");
        before=new String(Files.readAllBytes(Paths.get(args[0],"before-recents.txt")),StandardCharsets.UTF_8);
        after=new String(Files.readAllBytes(Paths.get(args[0],"after-recents.txt")),StandardCharsets.UTF_8);
        yes(ProfileIdentity.sha(before).equals("bb1335844af98cf8a2a435ab8b10a6bf9930ccd96bc162bff38150c9a7d1ee6a"),"before changed");
        yes(ProfileIdentity.sha(after).equals("5755f3c99126d9f093272b7b73cce47a74049d5398110a1c8d97465e1952c4f3"),"after changed");
        pass("actual_foreign_1430_is_preserved_not_declared_profile_empty",()->{
            JSONObject e=new JSONObject(snap(before).evidence());yes(!e.getBoolean("profile_empty"),"false empty claim");
            yes(e.getJSONArray("foreign_dormant_records").getJSONObject(0).getInt("task_id")==1430,"foreign record lost");
            yes(e.getInt("raw_bytes")==9654&&e.getBoolean("target_absent"),"raw/target fact wrong");
        });
        pass("actual_four_second_age_progress_within_real_interval",()->snap(before).requireSame(snap(after),6));
        pass("evidence_reconstructed_from_complete_actual_raw",()->PublicProfileRecentHistory.requireSameEvidence(new JSONObject(snap(before).evidence()),new JSONObject(snap(after).evidence()),TARGET,6));
        reject("private_whole_profile_empty_gate_remains_strict",()->ProfileTaskPolicy.Recents.parse(before).requireDedicatedEmpty(TARGET));
        reject("age_delta_exceeds_real_interval",()->snap(before).requireSame(snap(after),3));
        reject("age_reverse",()->snap(after).requireSame(snap(before),6));
        reject("age_huge_jump",()->snap(before).requireSame(snap(change(after,"inactive for 67010s","inactive for 999999s")),6));
        reject("absolute_last_active_changed",()->snap(before).requireSame(snap(change(before,"lastActiveTime=288126118","lastActiveTime=288126119")),6));
        reject("debug_token_changed",()->snap(before).requireSame(snap(change(before,"cc00009","cc00008")),6));
        reject("foreign_activities_live",()->snap(foreign(before,"Activities=[]","Activities=[ActivityRecord{abc u10 com.motorola.maxesetting/.IntroActivity t1430}]")));
        reject("foreign_activities_missing",()->snap(foreign(before,"    Activities=[]\n","")));
        reject("foreign_affinity_missing",()->snap(foreign(before,"    affinity=1010285:com.motorola.maxesetting\n","")));
        reject("foreign_uid_inconsistent",()->snap(foreign(before,"effectiveUid=u10a285","effectiveUid=u0a285")));
        reject("target_package_hint_in_root_affinity",()->snap(foreign(before,"    affinity=1010285:com.motorola.maxesetting\n","    affinity=1010285:com.motorola.maxesetting\n    rootAffinity=1010367:ctrip.android.view\n")));
        reject("target_package_hint_in_activity",()->snap(foreign(before,"mActivityComponent=com.motorola.maxesetting/.IntroActivity","mActivityComponent=ctrip.android.view/.Home")));
        reject("target_uid_hint_in_calling_uid",()->snap(foreign(before,"mCallingUid=u10a285","mCallingUid=u10a367")));
        reject("duplicate_age_field",()->snap(foreign(before,"    lastActiveTime=288126118 (inactive for 67006s)","    lastActiveTime=288126118 (inactive for 67006s)\n    lastActiveTime=288126118 (inactive for 67006s)")));
        pass("matching_hidden_internal_full_label_is_observation_only",()->snap(hidden(before,FOREIGN)));
        reject("hidden_same_id_token_affinity_target_intent_hint",()->snap(hidden(before,FOREIGN.replace("}"," I=ctrip.android.view/.Home}"))));
        reject("hidden_same_id_token_affinity_other_user_hint",()->snap(hidden(before,FOREIGN.replace("}"," U=0}"))));
        reject("hidden_same_id_token_affinity_different_size",()->snap(hidden(before,FOREIGN.replace("}"," sz=1}"))));
        reject("detached_profile_hidden_not_proven_dormant",()->snap(hidden(before,"Task{cc00100 #1431 type=standard A=1010285:com.motorola.maxesetting}")));
        reject("hidden_detached_id_reused_in_internal",()->snap(change(before,"cc00009","2bbd66")));
        reject("hidden_order_changes",()->snap(before).requireSame(snap(change(before,"Task{ff58d13 #1422 type=standard A=10312:com.motorola.smarteye}, Task{2bbd66 #1182 type=standard A=10481:org.trillionnium.hepta.local}","Task{2bbd66 #1182 type=standard A=10481:org.trillionnium.hepta.local}, Task{ff58d13 #1422 type=standard A=10312:com.motorola.smarteye}")),6));
        reject("foreign_record_removed",()->{int a=before.indexOf("  * Recent #2:"),b=before.indexOf("  * Recent #3:");snap(before).requireSame(snap(reindex(before.substring(0,a)+before.substring(b))),6);});
        reject("unknown_stable_body_field_changed",()->snap(before).requireSame(snap(foreign(before,"isPerceptible=false","isPerceptible=true")),6));
        reject("truncated_recents_refused",()->snap(before.substring(0,before.length()-70)));
        reject("raw_evidence_target_absent_flag_forged",()->{JSONObject e=new JSONObject(snap(before).evidence());e.put("target_absent",false);PublicProfileRecentHistory.requireSameEvidence(e,e,TARGET,0);});
        reject("raw_evidence_hash_forged",()->{JSONObject e=new JSONObject(snap(before).evidence());e.put("raw_sha256",ProfileBrokerHostTest.repeat('a'));PublicProfileRecentHistory.requireSameEvidence(e,e,TARGET,0);});
        reject("raw_evidence_foreign_record_removed",()->{JSONObject e=new JSONObject(snap(before).evidence());e.put("foreign_dormant_records",new JSONArray());PublicProfileRecentHistory.requireSameEvidence(e,e,TARGET,0);});
        pass("custody_new_owned_leaf_retirement_preserves_foreign_history",()->{
            PublicProfileRecentHistory.Baseline b=baseline();BackgroundOwnedSingleTask.Task r=root(),l=leaf(r);
            b.observe(before,TARGET,r,null,7,1000);b.observe(withLeaf(before),TARGET,r,l,7,1000);
            yes(!b.ownedAbsent(),"owned leaf disappeared by filtering");b.observe(before,TARGET,r,l,7,1000);b.requireTargetAbsent(before,TARGET,1000);
            yes(b.ownedAbsent()&&b.originalIds().contains(1430)&&b.originalIds().contains(1182),"baseline/absence wrong");
        });
        reject("custody_cannot_claim_preexisting_internal_id",()->{BackgroundOwnedSingleTask.Task r=new BackgroundOwnedSingleTask.Task(1430,7,0,-1,0,-1,0,new Object(),java.util.Collections.emptyList(),null,null,null,null,null,false,false);baseline().observe(before,TARGET,r,null,7,1000);});
        reject("custody_cannot_claim_preexisting_hidden_id",()->{BackgroundOwnedSingleTask.Task r=new BackgroundOwnedSingleTask.Task(1182,7,0,-1,0,-1,0,new Object(),java.util.Collections.emptyList(),null,null,null,null,null,false,false);baseline().observe(before,TARGET,r,null,7,1000);});
        reject("custody_cannot_claim_preexisting_debug_token",()->{BackgroundOwnedSingleTask.Task r=root();baseline().observe(change(withLeaf(before),"aabb300","2bbd66"),TARGET,r,leaf(r),7,1000);});
        reject("custody_clock_reversed",()->baseline().requireTargetAbsent(before,TARGET,999));
        reject("custody_age_jump_monotonic_clock",()->baseline().requireTargetAbsent(after,TARGET,1000));
        pass("custody_refusal_latched_even_if_history_restored",()->{
            PublicProfileRecentHistory.Baseline b=baseline();boolean refused=false;try{b.requireTargetAbsent(change(before,"cc00009","cc00008"),TARGET,1000);}catch(Exception e){refused=true;}
            yes(refused&&!b.ownedAbsent()&&Boolean.TRUE.equals(b.evidence().get("history_refusal_latched")),"failure not latched");
            try{b.requireTargetAbsent(before,TARGET,1000);throw new AssertionError("latch cleared");}catch(IllegalArgumentException expected){yes("PUBLIC_HISTORY_PREVIOUS_REFUSAL".equals(expected.getMessage()),"wrong refusal");}
        });
        pass("actual_coordinator_public_full_create_launch_observe_retire",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();p.window(14,300,2000);p.retire(2400);
            yes(p.cleanupKnown(),"public cleanup unknown");yes(f.delegate.mutations.equals(Arrays.asList("create","bind","remove_leaf","delete_root")),"unexpected mutation");
            yes(before.equals(f.raw),"foreign history mutated");yes(Boolean.TRUE.equals(((Map<?,?>)p.cleanupEvidence().get("public_foreign_recent_history")).get("foreign_dormant_history_preserved")),"missing custody");
        });
        reject("actual_coordinator_public_live_profile_admission_still_refuses",()->{Platform f=new Platform();f.delegate.initialProfileLive=true;try{f.prepare();}finally{yes(f.delegate.mutations.isEmpty(),"mutation before live census");}});
        reject("actual_coordinator_foreign_history_change_before_create",()->{Platform f=new Platform();f.raw=change(before,"cc00009","cc00008");try{f.prepare();}finally{yes(f.delegate.mutations.isEmpty(),"mutation before history census");}});
        pass("actual_coordinator_history_change_blocks_remove_and_delete",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.raw=change(before,"cc00009","cc00008");try{p.retire(2400);}catch(Exception refused){yes(refused.getMessage()!=null,"missing refusal");}
            yes(!p.cleanupKnown(),"changed history claimed cleaned");yes(f.delegate.mutations.equals(Arrays.asList("create","bind")),"mutated after foreign history changed");
        });
        pass("actual_coordinator_late_history_change_blocks_root_delete",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.corruptOnRemove=true;try{p.retire(2400);}catch(Exception refused){yes(refused.getMessage()!=null,"missing refusal");}
            yes(!p.cleanupKnown(),"late change claimed cleaned");yes(f.delegate.mutations.equals(Arrays.asList("create","bind","remove_leaf")),"deleted root after history changed");
        });
        pass("retained_released_empty_original_without_replay",()->{
            Retained x=new Retained();List<String> prior=new java.util.ArrayList<String>(x.platform.delegate.mutations);
            x.run();yes(x.releases==1&&x.before==2&&x.after==2&&prior.equals(x.platform.delegate.mutations),
                    "expected one display release, two new samples at each end and no task calls");
            yes(x.custody.known()&&!x.custody.retain()&&!x.custody.mayRelease()&&x.task.retainedAbsenceVerified(),"missing retained final proof");
            try{x.run();throw new AssertionError("replayed release");}catch(Exception expected){yes(x.releases==1,"second release");}
        });
        for(String condition:new String[]{"new_child","root_token_changes","wrong_display","new_recent","source_changes","physical_changed","late",
                "root_held","display_held","late_foreign","late_history"}){
            pass("retained_quarantined_"+condition,()->{
                Retained x=new Retained();x.mutation=condition;
                try{x.run();throw new AssertionError("bad sample accepted");}catch(Exception refused){
                    yes(x.custody.retain()&&!x.task.retainedAbsenceVerified(),"failed original released");
                }
                int effects=x.releases;
                yes(effects==(condition.equals("root_held")||condition.equals("display_held")||condition.startsWith("late_")?1:0),"unexpected effect");
                try{x.run();throw new AssertionError("second check");}catch(Exception refused){yes(x.releases==effects,"replayed input");}
            });
        }
        pass("original_ambiguous_root_delete_never_replayed",()->{
            Platform f=new Platform();ProfileOwnedTask t=f.active();f.delegate.deleteThrows=true;
            try{t.retire(2400);throw new AssertionError("original failure");}catch(Exception refused){yes(!t.cleanupKnown(),"unknown claimed");}
            try{t.closeRetainedEmptyDisplay(2600,null);throw new AssertionError("replay");}
            catch(ProfileTaskPolicy.Refusal correct){yes("PROFILE_RETAINED_EMPTY_NOT_ELIGIBLE".equals(correct.code),"wrong replay rejection");}
        });
        System.out.println(new JSONObject().put("schema","hepta.public-profile-history-cases.v1").put("passed",true)
                .put("cases",CASES.length()).put("assertions",assertions).put("case_names",CASES)
                .put("actual_archived_recents",true).put("framework_and_clock_fixtures_synthetic",true).put("phone_contacted",false));
    }
}
