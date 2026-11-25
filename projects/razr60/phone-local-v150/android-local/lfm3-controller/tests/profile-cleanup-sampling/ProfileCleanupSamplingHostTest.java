package org.trillionnium.hepta.background;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;

/** Production ownership/history policy; Android TaskInfo and latency are explicit host fixtures. */
public final class ProfileCleanupSamplingHostTest {
    private static String before;
    private static int assertions;
    private static final JSONArray cases=new JSONArray();
    private static final ProfileTarget TARGET=ProfileBrokerHostTest.target(10,1010367);
    private interface Work {void run()throws Exception;}
    private static void yes(boolean good,String reason){assertions++;if(!good)throw new AssertionError(reason);}
    private static void pass(String name,Work work)throws Exception{work.run();cases.put(name);}
    private static String fail(Work work)throws Exception{
        try{work.run();throw new AssertionError("cleanup was accepted");}
        catch(Exception expected){assertions++;return expected.getMessage();}
    }
    private static String change(String raw,String old,String value){
        int at=raw.indexOf(old);yes(at>=0&&at==raw.lastIndexOf(old),"unique raw fixture seam required");
        return raw.substring(0,at)+value+raw.substring(at+old.length());
    }
    private static String withLeaf(String raw){
        String row="  * Recent #0: Task{aabb300 #300 type=standard A=1010367:ctrip.android.view}\n"
                +"    userId=10 effectiveUid=u10a367 mCallingUid=0\n    affinity=1010367:ctrip.android.view\n"
                +"    intent={flg=0x10000000 cmp="+ProfileBrokerHostTest.SPLASH+"}\n"
                +"    mActivityComponent="+ProfileBrokerHostTest.HOME+"\n"
                +"    Activities=[ActivityRecord{aabb u10 "+ProfileBrokerHostTest.HOME+" t300}]\n"
                +"    taskId=300 rootTaskId=200\n    lastActiveTime=355000000 (inactive for 0s)\n    lastDisplayId=7\n";
        Matcher m=Pattern.compile("(?m)^  \\* Recent #[0-9]+:").matcher(change(raw,"  Recent tasks:\n","  Recent tasks:\n"+row));
        StringBuffer out=new StringBuffer();int index=0;
        while(m.find())m.appendReplacement(out,Matcher.quoteReplacement("  * Recent #"+index+++":"));
        m.appendTail(out);return out.toString();
    }
    private static final class Platform implements ProfileOwnedTask.Platform {
        final ProfileBrokerHostTest.Fake f=new ProfileBrokerHostTest.Fake();
        final List<String> events=new ArrayList<String>();
        String raw=before;
        boolean retiring,removed,deleted,changeHistoryOnChildren,childReturns,rootTokenChanges;
        boolean changeIdentityAfterFinalHistory,foreignAfterRootDelete;
        long deadline=Long.MAX_VALUE;
        int dumpCost,identityCost,retirementDumps;
        public ProfileTarget recheck(boolean ready)throws Exception{
            if(retiring){f.now+=identityCost;events.add("identity");
                if(f.now>=deadline)throw new IOException("PROFILE_READ_DEADLINE");}
            ProfileTarget actual=f.recheck(ready);
            ProfileTaskPolicy.need(TARGET.same(actual),"PROFILE_INSTALLATION_IDENTITY_CHANGED");
            return actual;
        }
        public void guard()throws Exception{f.guard();}
        public long now(){return f.now();}
        public Object newCookie(){return f.newCookie();}
        public ProfileTaskPolicy.Snapshot snapshot()throws Exception{
            if(retiring)events.add("global");return f.snapshot();
        }
        public ProfileTaskPolicy.Recents recents(){throw new AssertionError("public path used private history");}
        public String publicRecentsDump()throws Exception{
            if(retiring){
                retirementDumps++;f.now+=dumpCost;events.add(f.recentsApp?"history_owned":"history_absent");
                if(f.now>=deadline)throw new IOException("PROFILE_RECENTS_DEADLINE");
                if(removed&&!deleted&&changeIdentityAfterFinalHistory)f.actual=ProfileBrokerHostTest.target(11,1010367);
            }
            return f.recentsApp?withLeaf(raw):raw;
        }
        public List<BackgroundOwnedSingleTask.Task> roots(){
            if(retiring)events.add("roots");
            if(removed&&!deleted&&rootTokenChanges)return Collections.singletonList(
                    new BackgroundOwnedSingleTask.Task(200,7,0,-1,0,-1,0,new Object(),
                        Collections.singletonList(f.rootCookie),null,null,null,null,null,false,false));
            return f.roots();
        }
        public List<BackgroundOwnedSingleTask.Task> children(Object token){
            if(retiring)events.add("children");
            if(removed&&!deleted){
                if(changeHistoryOnChildren)raw=change(raw,"cc00009","cc00008");
                if(childReturns)f.app=true;
            }
            return f.children(token);
        }
        public void createRoot(Object cookie){f.createRoot(cookie);}
        public void bindRoot(Object token,Object cookie){f.bindRoot(token,cookie);}
        public void removeLeaf(Object token)throws Exception{
            recheck(false);f.removeLeaf(token);removed=true;if(retiring)events.add("remove_leaf");
        }
        public boolean deleteRoot(Object token)throws Exception{
            // The real organizer rechecks the installed identity immediately before this effect.
            recheck(false);boolean accepted=f.deleteRoot(token);deleted=true;events.add("delete_root");
            if(foreignAfterRootDelete)f.foreign=true;return accepted;
        }
        public void pause(){f.pause();}
        ProfileOwnedTask active()throws Exception{
            PublicProfileRecentHistory.Baseline history=new PublicProfileRecentHistory.Baseline(
                    PublicProfileRecentHistory.absence(before,TARGET),f.now);
            ProfileOwnedTask p=new ProfileOwnedTask(this,TARGET,ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7,history);
            p.prepare();p.beforeDispatch();f.launch();p.accepted(0);yes(p.observe(),"new profile leaf not admitted");
            return p;
        }
        long budget(int milliseconds,int readCost,int identityReadCost){
            retiring=true;deadline=f.now+milliseconds;dumpCost=readCost;identityCost=identityReadCost;
            retirementDumps=0;events.clear();return deadline;
        }
    }
    public static void main(String[] args)throws Exception{
        before=new String(Files.readAllBytes(Paths.get(args[0],"before-recents.txt")),StandardCharsets.UTF_8);
        final boolean baseline="baseline".equals(args[1]);
        final Platform budget=new Platform();final ProfileOwnedTask task=budget.active();
        long end=budget.budget(1400,350,15);
        if(baseline){
            String refused=fail(()->task.retire(end));
            yes("PROFILE_RECENTS_DEADLINE".equals(refused),"baseline did not hit the redundant-read budget failure: "+refused);
            yes(budget.retirementDumps==4&&!task.cleanupKnown(),"baseline failure shape changed");
            System.out.println(new JSONObject().put("expected_baseline_red",true).put("failure",refused)
                    .put("synthetic_history_read_ms",350).put("synthetic_identity_read_ms",15)
                    .put("original_cleanup_read_budget_ms",1400).put("retirement_history_reads",budget.retirementDumps)
                    .put("elapsed_ms",budget.f.now-1000).put("phone_qualification",false));
            System.exit(3);return;
        }
        task.retire(end);
        yes(task.cleanupKnown()&&budget.f.now<end,"candidate failed the same unchanged budget");
        yes(budget.retirementDumps==3,"one complete repeated history read was not removed");
        yes(budget.f.mutations.equals(Arrays.asList("create","bind","remove_leaf","delete_root")),"effects changed");
        pass("same_original_budget_with_full_pre_leaf_pre_root_and_post_root_history",()->{});
        pass("protected_history_change_during_child_read_vetoes_root_delete",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.changeHistoryOnChildren=true;
            fail(()->p.retire(f.budget(1400,0,0)));
            yes(!p.cleanupKnown()&&!f.deleted,"stale earlier history authorized deletion");
            Map<?,?> history=(Map<?,?>)p.cleanupEvidence().get("public_foreign_recent_history");
            yes(Boolean.TRUE.equals(history.get("history_refusal_latched")),"changed history not latched");
        });
        pass("final_history_expiry_never_authorizes_root_delete",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();
            yes("PROFILE_RECENTS_DEADLINE".equals(fail(()->p.retire(f.budget(700,350,0)))),"wrong deadline refusal");
            yes(!f.deleted&&!p.cleanupKnown(),"expired history granted cleanup");
        });
        pass("fresh_identity_before_root_mutation_is_not_cached",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.changeIdentityAfterFinalHistory=true;
            yes("PROFILE_INSTALLATION_IDENTITY_CHANGED".equals(fail(()->p.retire(f.budget(1400,0,0)))),"identity change ignored");
            yes(!f.deleted&&!p.cleanupKnown(),"old installed identity authorized deletion");
        });
        pass("root_actual_token_change_still_refuses",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.rootTokenChanges=true;
            yes("PROFILE_ROOT_TOKEN_CHANGED".equals(fail(()->p.retire(f.budget(1400,0,0)))),"root token change ignored");
            yes(!f.deleted&&!p.cleanupKnown(),"foreign root was removed");
        });
        pass("returned_owned_child_blocks_root_delete",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.childReturns=true;
            yes("PROFILE_ROOT_CHILDREN_REMAIN".equals(fail(()->p.retire(f.budget(1400,0,0)))),"returned child ignored");
            yes(!f.deleted&&!p.cleanupKnown(),"nonempty root removed");
        });
        pass("owned_recents_remains_until_original_deadline",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.f.keepRecents=true;
            fail(()->p.retire(f.budget(1400,350,0)));
            yes(!f.deleted&&!p.cleanupKnown(),"owned recents bypassed");
        });
        pass("fresh_global_after_root_mutation_is_required",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.foreignAfterRootDelete=true;
            fail(()->p.retire(f.budget(1400,0,0)));
            yes(f.deleted&&!p.cleanupKnown(),"pre-delete snapshot reused as post-delete proof");
        });
        pass("root_absence_is_not_assumed_from_recents_absence",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.f.deleteThrows=true;
            yes("DELETE_FAILED".equals(fail(()->p.retire(f.budget(1400,0,0)))),"root deletion error ignored");
            yes(!p.cleanupKnown(),"history absence converted unknown to success");
        });
        System.out.println(new JSONObject().put("passed",true).put("cases",cases).put("assertions",assertions)
                .put("retirement_history_reads",budget.retirementDumps).put("synthetic_elapsed_ms",budget.f.now-1000)
                .put("original_cleanup_read_budget_ms",1400).put("synthetic_framework_and_latency",true)
                .put("phone_qualification",false));
    }
}
