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

/** Actual production coordinator/protocol/history. Archived recents stay exact;
 * task Binder, display, clock, socket peer and effect boundaries are synthetic. */
public final class RetainedProfileCleanupHostTest {
    private static String archived;
    private static final String TASK="11111111111111111111111111111111",NONCE=ProfileBrokerHostTest.repeat('c');
    private static final ProfileTarget TARGET=ProfileBrokerHostTest.target(10,1010367);
    private static final List<String> CASES=new ArrayList<String>();private static int assertions;
    interface Work {void run()throws Exception;}
    interface Mutation {void apply(Env e)throws Exception;}
    static void yes(boolean value){assertions++;if(!value)throw new AssertionError("retained cleanup assertion");}
    static void pass(String name,Work body)throws Exception{body.run();CASES.add(name);}
    static void refuses(Work body)throws Exception{try{body.run();}catch(Exception expected){assertions++;return;}throw new AssertionError("unsafe cleanup accepted");}
    private static String leafRecord(){return "  * Recent #0: Task{aabb300 #300 type=standard A=1010367:ctrip.android.view}\n"
            +"    userId=10 effectiveUid=u10a367 mCallingUid=0\n    affinity=1010367:ctrip.android.view\n"
            +"    intent={flg=0x10000000 cmp="+ProfileBrokerHostTest.SPLASH+"}\n"
            +"    mActivityComponent="+ProfileBrokerHostTest.HOME+"\n"
            +"    Activities=[ActivityRecord{aabb u10 "+ProfileBrokerHostTest.HOME+" t300}]\n"
            +"    taskId=300 rootTaskId=200\n    lastActiveTime=355000000 (inactive for 0s)\n    lastDisplayId=7\n";}
    private static String withLeaf(String raw){
        String value=raw.replace("  Recent tasks:\n","  Recent tasks:\n"+leafRecord());
        Matcher m=Pattern.compile("(?m)^  \\* Recent #[0-9]+:").matcher(value);StringBuffer out=new StringBuffer();int i=0;
        while(m.find())m.appendReplacement(out,Matcher.quoteReplacement("  * Recent #"+(i++)+":"));m.appendTail(out);return out.toString();
    }
    static final class Platform implements ProfileOwnedTask.Platform {
        final ProfileBrokerHostTest.Fake f=new ProfileBrokerHostTest.Fake();String raw=archived;
        boolean deleteFalse,removeAfterThrow,removeCorrupt,detached;String leafToken="aabb300";
        long nextSnapshotAdvance,nextDumpAdvance;
        @Override public ProfileTarget recheck(boolean ready){return f.recheck(ready);}
        @Override public void guard()throws Exception{f.guard();}
        @Override public long now(){return f.now();}
        @Override public Object newCookie(){return f.newCookie();}
        @Override public ProfileTaskPolicy.Snapshot snapshot()throws Exception{f.now+=nextSnapshotAdvance;nextSnapshotAdvance=0;return f.snapshot();}
        @Override public ProfileTaskPolicy.Recents recents(){throw new AssertionError("private recents path used");}
        @Override public String publicRecentsDump(){f.now+=nextDumpAdvance;nextDumpAdvance=0;
            String value=(f.recentsApp?withLeaf(raw):raw).replace("aabb300",leafToken);
            return detached?value.replace("taskId=300 rootTaskId=200","taskId=300 rootTaskId=300"):value;}
        @Override public List<BackgroundOwnedSingleTask.Task> roots(){return f.roots();}
        @Override public List<BackgroundOwnedSingleTask.Task> children(Object token){return f.children(token);}
        @Override public void createRoot(Object token){f.createRoot(token);}
        @Override public void bindRoot(Object root,Object cookie){f.bindRoot(root,cookie);}
        @Override public void removeLeaf(Object token)throws Exception{
            try{f.removeLeaf(token);}catch(Exception e){if(removeAfterThrow){f.app=false;f.recentsApp=false;}throw e;}
            if(removeCorrupt)raw=raw.replace("cc00008","cc00007");
        }
        @Override public boolean deleteRoot(Object token)throws Exception{
            if(deleteFalse){f.mutations.add("delete_root");return false;}return f.deleteRoot(token);
        }
        @Override public void pause(){f.pause();}
    }
    static final class Env {
        final Platform p=new Platform();final PublicProfileRecentHistory.Baseline history;
        final ProfileOwnedTask task;final ProfileDisplayCustody custody=new ProfileDisplayCustody();
        String beforeCleanup;int releases,before,after,emptyReads;boolean display=true;String mutate="";
        Env(String originalFailure)throws Exception{
            history=new PublicProfileRecentHistory.Baseline(PublicProfileRecentHistory.absence(archived,TARGET),p.now());
            task=new ProfileOwnedTask(p,TARGET,ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7,history);
            task.prepare();task.beforeDispatch();p.f.launch();task.accepted(0);yes(task.observe());
            if("leaf_unknown".equals(originalFailure))p.f.removeThrows=true;
            else if("root_unknown".equals(originalFailure))p.f.deleteThrows=true;
            else p.raw=archived.replace("cc00009","cc00008");
            refuses(()->task.retire(p.now()+1000));yes(!task.cleanupKnown());
            p.f.now=5000;beforeCleanup=new JSONObject(task.cleanupEvidence()).toString();
            custody.beforeCreate();custody.unresolved();
        }
        ProfileOwnedTask.RetiredDisplay handle(){return new ProfileOwnedTask.RetiredDisplay(){
            @Override public void requireState(boolean prior)throws Exception{
                if(prior){
                    before++;if(!display)throw new IOException("display disappeared");
                    if(before==1){
                        if("root_token".equals(mutate))p.f.rootToken=new Object();
                        if("leaf_token".equals(mutate))p.f.leafToken=new Object();
                        if("foreign_child".equals(mutate))p.f.extraChild=true;
                        if("main_changed".equals(mutate))p.f.personalAdded=true;
                        if("history_changed".equals(mutate))p.raw=p.raw.replace("cc00008","cc00007");
                        if("late".equals(mutate))p.f.now+=2500;
                        if("stale_physical".equals(mutate))p.f.now+=1500;
                        if("physical_changed".equals(mutate))throw new IOException("physical display facts changed");
                    }
                    if(before==2&&"late_foreign_top".equals(mutate))p.f.foreignTop=true;
                    if(before==2&&"stale_final_pair".equals(mutate))p.nextSnapshotAdvance=1500;
                    if(!p.f.root&&++emptyReads==3&&"stale_release_read".equals(mutate))p.f.now+=1500;
                }else{
                    after++;if(display)throw new IOException("display remained");
                    if("post_foreign".equals(mutate))p.f.foreign=true;
                    if("post_late".equals(mutate))p.f.now+=2500;
                    if("post_physical".equals(mutate))throw new IOException("physical changed after release");
                }
            }
            @Override public void releaseOriginalHandle()throws Exception{
                releases++;yes(p.f.root==false&&p.f.app==false&&p.f.recentsApp==false);
                if("release_throw".equals(mutate))throw new IOException("release result unknown");
                if(!"display_held".equals(mutate))display=false;
            }
            @Override public void awaitAbsent()throws Exception{if(display)throw new IOException("display absent unconfirmed");}
        };}
        ProfileOwnedTask.RetainedCleanupProof run()throws Exception{return task.cleanupRetained(p.now()+2000,handle());}
        int effects(){return p.f.mutations.size()+releases;}
        void oldUnchanged(){yes(beforeCleanup.equals(new JSONObject(task.cleanupEvidence()).toString()));}
    }
    static PublicOwnGroupPolicy.Scope scope(){return new PublicOwnGroupPolicy.Scope(TASK,ProfileBrokerHostTest.repeat('a'),
            ProfileBrokerHostTest.GEN,10481,TARGET,0,1000,10);}
    static BrokerProtocol.Config config()throws Exception{
        PublicOwnGroupPolicy.Scope s=scope();return BrokerProtocol.Config.parse(new String[]{"--socket","hepta-bg-"+s.generation,
                "--owner-uid","10481","--generation",s.generation,"--allowed-packages",TARGET.packageName,"--ttl-ms","1000",
                "--expires-elapsed-ms","1000","--profile-target",TARGET.wire(),"--public-own-group-scope",s.wire(),
                "--retained-cleanup-token-sha256",ProfileIdentity.sha(NONCE)});
    }
    static JSONObject request()throws Exception{
        PublicOwnGroupPolicy.Scope s=scope();return new JSONObject().put("version",1).put("op","cleanup_retained_profile")
                .put("request_id",ProfileBrokerHostTest.REQUEST).put("generation",s.generation).put("task_id",TASK)
                .put("display_scope_sha256",s.sha256).put("profile_target_sha256",TARGET.sha256).put("nonce",NONCE)
                .put("started_elapsed_ms",5000L).put("deadline_elapsed_ms",7000L);
    }
    static BrokerProtocol.RetainedCleanupRequest parsed(JSONObject v)throws Exception{return BrokerProtocol.RetainedCleanupRequest.parse(v.toString().getBytes(StandardCharsets.UTF_8));}
    public static void main(String[] args)throws Exception{
        archived=new String(Files.readAllBytes(Paths.get(args[0],"before-recents.txt")),StandardCharsets.UTF_8);
        yes(ProfileIdentity.sha(archived).equals("bb1335844af98cf8a2a435ab8b10a6bf9930ccd96bc162bff38150c9a7d1ee6a"));
        pass("new_cleanup_interval_removes_original_leaf_root_then_display_without_clearing_old_failure",()->{
            Env e=new Env("history");Map<String,Object> old=e.history.evidence();
            RetainedProfileCleanupAttempt a=new RetainedProfileCleanupAttempt(config(),()->e.p.now());
            a.claim(parsed(request()),10481);a.run(deadline->e.task.cleanupRetained(deadline,e.handle()));
            yes(a.completedProof()!=null);e.custody.retainedCleanupObservedAbsent(e.task,a.completedProof());
            yes(!e.custody.retain()&&e.custody.known()&&!e.custody.mayRelease());e.oldUnchanged();
            yes(old.equals(e.history.evidence())&&Boolean.TRUE.equals(old.get("history_refusal_latched")));
            yes(e.p.f.mutations.equals(Arrays.asList("create","bind","remove_leaf","delete_root"))&&e.releases==1);
            int n=e.effects();refuses(e::run);refuses(()->a.claim(parsed(request()),10481));refuses(()->a.run(d->e.run()));yes(e.effects()==n);
            yes(!new JSONObject(a.evidence()).toString().contains(NONCE));
        });
        pass("old_leaf_call_with_unknown_result_is_never_replayed",()->{
            Env e=new Env("leaf_unknown");e.p.f.removeThrows=false;int n=e.effects();refuses(e::run);yes(e.effects()==n);e.oldUnchanged();
        });
        pass("old_leaf_unknown_but_fresh_leaf_absent_skips_remove",()->{
            Env e=new Env("leaf_unknown");e.p.f.app=false;e.p.f.recentsApp=false;e.p.f.removeThrows=false;
            ProfileOwnedTask.RetainedCleanupProof proof=e.run();yes(proof!=null&&e.releases==1);
            yes(Collections.frequency(e.p.f.mutations,"remove_leaf")==1);e.oldUnchanged();
        });
        pass("old_root_call_with_unknown_result_is_never_replayed",()->{
            Env e=new Env("root_unknown");e.p.f.deleteThrows=false;int n=e.effects();refuses(e::run);yes(e.effects()==n);e.oldUnchanged();
        });
        pass("old_root_unknown_but_fresh_all_tasks_absent_only_releases_original_display",()->{
            Env e=new Env("root_unknown");e.p.f.root=false;e.p.f.deleteThrows=false;int n=e.p.f.mutations.size();e.run();
            yes(e.p.f.mutations.size()==n&&e.releases==1);e.oldUnchanged();
        });
        for(String condition:new String[]{"root_token","leaf_token","foreign_child","main_changed","history_changed","late","physical_changed","late_foreign_top","stale_physical","stale_final_pair"}){
            pass("before_effect_reject_"+condition,()->{
                Env e=new Env("history");e.mutate=condition;int n=e.effects();refuses(e::run);yes(e.effects()==n&&e.custody.retain());
                refuses(e::run);yes(e.effects()==n);e.oldUnchanged();
            });
        }
        pass("complete_initial_history_read_1500ms_old_never_reaches_effect",()->{
            Env e=new Env("history");e.p.nextDumpAdvance=1500;int n=e.effects();refuses(e::run);yes(e.effects()==n&&e.p.now()==6500);e.oldUnchanged();
        });
        pass("complete_task_snapshot_1500ms_old_never_reaches_effect",()->{
            Env e=new Env("history");e.p.nextSnapshotAdvance=1500;int n=e.effects();refuses(e::run);yes(e.effects()==n&&e.p.now()==6500);e.oldUnchanged();
        });
        pass("late_final_display_read_does_not_release_original_handle",()->{
            Env e=new Env("history");e.mutate="stale_release_read";refuses(e::run);
            yes(e.p.f.mutations.contains("delete_root")&&e.releases==0&&e.display);e.oldUnchanged();
        });
        pass("detached_recent_only_self_root_is_explicit_unsupported_no_numeric_fallback",()->{
            Env e=new Env("history");e.p.f.app=false;e.p.detached=true;int n=e.effects();long began=e.p.now();
            try{e.run();throw new AssertionError("detached WCT path invented");}
            catch(IllegalArgumentException correct){yes("PUBLIC_RETAINED_DETACHED_RECENT_REQUIRES_MAINTENANCE".equals(correct.getMessage()));}
            yes(e.effects()==n&&e.p.now()==began&&e.custody.retain());e.oldUnchanged();
        });
        pass("recent_only_with_stale_parent_is_early_unsupported_no_ten_second_wait",()->{
            Env e=new Env("history");e.p.f.app=false;int n=e.effects();long began=e.p.now();
            try{e.run();throw new AssertionError("recent-only task accepted");}
            catch(ProfileTaskPolicy.Refusal correct){yes("PROFILE_RETAINED_RECENT_ONLY_REQUIRES_MAINTENANCE".equals(correct.code));}
            yes(e.effects()==n&&e.p.now()-began<100&&e.custody.retain());e.oldUnchanged();
        });
        for(String condition:new String[]{"post_foreign","post_late","post_physical","release_throw","display_held"}){
            pass("post_effect_unknown_remains_retained_"+condition,()->{
                Env e=new Env("history");e.mutate=condition;refuses(e::run);yes(e.releases==1&&e.custody.retain());int n=e.effects();
                refuses(e::run);yes(e.effects()==n);e.oldUnchanged();
            });
        }
        pass("new_leaf_effect_throw_is_not_replayed",()->{
            Env e=new Env("history");e.p.f.removeThrows=true;refuses(e::run);int n=e.effects();refuses(e::run);
            yes(e.effects()==n&&Collections.frequency(e.p.f.mutations,"remove_leaf")==1&&e.releases==0);e.oldUnchanged();
        });
        pass("new_root_effect_false_stops_before_display_release",()->{
            Env e=new Env("history");e.p.deleteFalse=true;refuses(e::run);yes(Collections.frequency(e.p.f.mutations,"delete_root")==1&&e.releases==0);e.oldUnchanged();
        });
        pass("foreign_history_change_after_leaf_effect_vetoes_root_delete",()->{
            Env e=new Env("history");e.p.removeCorrupt=true;refuses(e::run);
            yes(Collections.frequency(e.p.f.mutations,"remove_leaf")==1&&!e.p.f.mutations.contains("delete_root")&&e.releases==0);e.oldUnchanged();
        });
        for(String field:new String[]{"request_id","generation","task_id","display_scope_sha256","profile_target_sha256","nonce","op","version"}){
            pass("strict_request_binding_"+field,()->{
                JSONObject v=request();v.put(field,"version".equals(field)?2:"nonce".equals(field)?ProfileBrokerHostTest.repeat('d'):"wrong");
                refuses(()->parsed(v).authenticate(config(),10481,5000));
            });
        }
        pass("wrong_peer_uid_cannot_claim_or_consume_rightful_request",()->{
            RetainedProfileCleanupAttempt a=new RetainedProfileCleanupAttempt(config(),()->5000L);
            refuses(()->a.claim(parsed(request()),10482));yes(!a.claimed());a.claim(parsed(request()),10481);yes(a.claimed());
        });
        pass("wrong_nonce_cannot_claim_or_consume_rightful_request",()->{
            RetainedProfileCleanupAttempt a=new RetainedProfileCleanupAttempt(config(),()->5000L);
            refuses(()->a.claim(parsed(request().put("nonce",ProfileBrokerHostTest.repeat('d'))),10481));yes(!a.claimed());a.claim(parsed(request()),10481);
        });
        pass("business_lease_must_already_be_expired_without_renewal",()->{
            JSONObject v=request().put("started_elapsed_ms",2500).put("deadline_elapsed_ms",4500);refuses(()->parsed(v).authenticate(config(),10481,2500));
        });
        pass("new_cleanup_deadline_is_bounded_and_not_reset",()->{
            refuses(()->parsed(request().put("deadline_elapsed_ms",15001)));refuses(()->parsed(request()).authenticate(config(),10481,7000));
            refuses(()->parsed(request()).authenticate(config(),10481,4999));
        });
        pass("unknown_and_duplicate_wire_fields_rejected",()->{
            refuses(()->parsed(request().put("launch",TARGET.packageName)));
            byte[] v=request().toString().replace("{","{\"version\":1,").getBytes(StandardCharsets.UTF_8);
            refuses(()->BrokerProtocol.RetainedCleanupRequest.parse(v));
        });
        pass("ordinary_business_parser_does_not_accept_cleanup_endpoint",()->{
            refuses(()->BrokerProtocol.Request.parse(request().toString().getBytes(StandardCharsets.UTF_8)));
        });
        pass("failed_attempt_retains_once_claim_even_when_no_effect_occurs",()->{
            RetainedProfileCleanupAttempt a=new RetainedProfileCleanupAttempt(config(),()->5000L);a.claim(parsed(request()),10481);
            refuses(()->a.run(d->{throw new IOException("fresh census refused");}));yes(a.completedProof()==null&&a.claimed());
            refuses(()->a.run(d->{throw new AssertionError("replayed");}));
        });
        pass("proof_from_another_original_task_cannot_end_custody",()->{
            Env a=new Env("history"),b=new Env("history");ProfileOwnedTask.RetainedCleanupProof proof=a.run();
            refuses(()->b.custody.retainedCleanupObservedAbsent(b.task,proof));yes(b.custody.retain());
        });
        for(String type:new String[]{"uid","user","display","parent","top","root_cookie","recent_token","truncated"}){
            pass("complete_fresh_identity_refuses_"+type,()->{
                Env e=new Env("history");
                if("uid".equals(type))e.p.f.wrongUid=true;if("user".equals(type))e.p.f.wrongUser=true;
                if("display".equals(type))e.p.f.wrongDisplay=true;if("parent".equals(type))e.p.f.wrongParent=true;
                if("top".equals(type))e.p.f.foreignTop=true;if("root_cookie".equals(type))e.p.f.missingRootCookie=true;
                if("recent_token".equals(type))e.p.leafToken="aabb301";if("truncated".equals(type))e.p.raw=e.p.raw.substring(0,e.p.raw.length()-80);
                int n=e.effects();refuses(e::run);yes(n==e.effects());e.oldUnchanged();
            });
        }
        System.out.println(new JSONObject().put("all_pass",true).put("cases",CASES.size()).put("assertions",assertions).put("case_names",new JSONArray(CASES))
                .put("actual_archived_recents",true).put("android_runtime",false).put("framework_and_effect_ports_synthetic",true).put("phone_operations",0));
    }
}
