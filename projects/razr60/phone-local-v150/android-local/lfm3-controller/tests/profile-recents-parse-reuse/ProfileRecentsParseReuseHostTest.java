package org.trillionnium.hepta.background;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONArray;
import org.json.JSONObject;

/** Pure production parser/coordinator tests. Android/Binder, task identities,
 * time and histories below are explicit synthetic fixtures, never phone proof. */
public final class ProfileRecentsParseReuseHostTest {
    private static final AtomicInteger PARSES=new AtomicInteger();
    private static final ProfileTarget TARGET=ProfileBrokerHostTest.target(10,1010367);
    private static final JSONArray CASES=new JSONArray(),COUNTS=new JSONArray();
    private static boolean counted;
    private static int assertions;
    private static String base;
    private interface Work {void run()throws Exception;}
    public static void countParse(){PARSES.incrementAndGet();}
    private static void closeFromOtherThread(ProfileTaskPolicy.Recents.Observation scope){scope.close();}
    private static void yes(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    private static void pass(String name,Work body)throws Exception{body.run();CASES.put(name);}
    private static Exception refused(Work body)throws Exception{
        try{body.run();}catch(Exception correct){assertions++;return correct;}
        throw new AssertionError("unexpected acceptance");
    }
    private static String describe(Object value)throws Exception{
        if(value==null||value==JSONObject.NULL)return "null";
        if(value instanceof String)return JSONObject.quote((String)value);
        if(value instanceof Number||value instanceof Boolean)return value.toString();
        if(value instanceof Map){
            Map<String,String> rows=new TreeMap<String,String>();
            for(Map.Entry<?,?> row:((Map<?,?>)value).entrySet())rows.put(describe(row.getKey()),describe(row.getValue()));
            return "map"+rows.toString();
        }
        if(value instanceof Set){List<String> rows=new ArrayList<String>();for(Object row:(Set<?>)value)rows.add(describe(row));
            Collections.sort(rows);return "set"+rows.toString();}
        if(value instanceof List){List<String> rows=new ArrayList<String>();for(Object row:(List<?>)value)rows.add(describe(row));
            return "list"+rows.toString();}
        Map<String,String> fields=new TreeMap<String,String>();
        for(Field f:value.getClass().getDeclaredFields())if(!Modifier.isStatic(f.getModifiers())){
            f.setAccessible(true);fields.put(f.getName(),describe(f.get(value)));
        }
        yes(value.getClass().getName().startsWith("org.trillionnium.hepta.background."),"unsupported value in complete projection");
        return value.getClass().getName()+fields.toString();
    }
    private static String outcome(String raw,boolean optimized)throws Exception{
        try{
            PublicOwnGroupPhysicalFence.RecentCensus c;
            if(optimized){try(ProfileTaskPolicy.Recents.Observation scope=ProfileTaskPolicy.Recents.parseObservation(raw)){
                c=PublicOwnGroupPhysicalFence.inspectRecents(raw,scope);
            }}else{ProfileTaskPolicy.Recents.parse(raw);c=PublicOwnGroupPhysicalFence.inspectRecents(raw);}
            return "OK:"+describe(c);
        }catch(Exception error){return "REFUSED:"+error.getClass().getName()+":"+error.getMessage();}
    }
    private static void parity(String name,String raw,boolean accepted)throws Exception{
        pass(name,()->{
            String old=outcome(raw,false),now=outcome(raw,true);
            yes(old.equals(now),"complete result/refusal differs: "+name+"\n"+old+"\n"+now);
            yes(old.startsWith(accepted?"OK:":"REFUSED:"),"fixture unexpectedly accepted/refused: "+name);
        });
    }
    private static String change(String raw,String old,String value){
        int at=raw.indexOf(old);yes(at>=0&&at==raw.lastIndexOf(old),"fixture seam is not unique");
        return raw.substring(0,at)+value+raw.substring(at+old.length());
    }
    private static String withLeaf(String raw){
        String row="  * Recent #0: Task{aabb300 #300 type=standard A=1010367:ctrip.android.view}\n"
                +"    userId=10 effectiveUid=u10a367 mCallingUid=0\n    affinity=1010367:ctrip.android.view\n"
                +"    intent={flg=0x10000000 cmp="+ProfileBrokerHostTest.SPLASH+"}\n"
                +"    mActivityComponent="+ProfileBrokerHostTest.HOME+"\n"
                +"    Activities=[ActivityRecord{aabb u10 "+ProfileBrokerHostTest.HOME+" t300}]\n"
                +"    taskId=300 rootTaskId=200\n    lastActiveTime=355000000 (inactive for 0s)\n    lastDisplayId=7\n";
        String current=change(raw,"  Recent tasks:\n","  Recent tasks:\n"+row);
        java.util.regex.Matcher m=java.util.regex.Pattern.compile("(?m)^  \\* Recent #[0-9]+:").matcher(current);
        StringBuffer out=new StringBuffer();int i=0;
        while(m.find())m.appendReplacement(out,java.util.regex.Matcher.quoteReplacement("  * Recent #"+i+++":"));
        m.appendTail(out);return out.toString();
    }
    private static String home(){
        return "ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\n"
            +"mRecentsUid=10100\nmRecentsComponent=ComponentInfo{com.example.launcher/com.example.launcher.Recents}\n"
            +"mFreezeTaskListReordering=false\nmFreezeTaskListReorderingPendingTimeout=false\n"
            +"mHiddenTasks=[Task{aaa77 #777 type=standard A=10481:org.trillionnium.hepta.local}]\n"
            +"  Recent tasks:\n  * Recent #0: Task{ab101 #101 type=home A=10100:com.example.launcher}\n"
            +"    userId=0 effectiveUid=u0a100 mCallingUid=0\n    affinity=10100:com.example.launcher\n"
            +"    intent={act=android.intent.action.MAIN cat=[android.intent.category.HOME] flg=0x10000100 cmp=com.example.launcher/.Home}\n"
            +"    mActivityComponent=com.example.launcher/.Home\n"
            +"    autoRemoveRecents=false isPersistable=true activityType=2\n"
            +"    Activities=[]\n    taskId=101 rootTaskId=101\n"
            +"    lastActiveTime=100 (inactive for 0s)\n    lastDisplayId=0\n";
    }
    private static PublicProfileRecentHistory.Baseline baseline()throws Exception{
        return new PublicProfileRecentHistory.Baseline(PublicProfileRecentHistory.absence(base,TARGET),1000);
    }
    private static final class RecordedHistory implements ProfileOwnedTask.PublicRecentHistory {
        final PublicProfileRecentHistory.Baseline actual;
        final boolean optimized;
        final List<ProfileTaskPolicy.Recents.Observation> seen=new ArrayList<ProfileTaskPolicy.Recents.Observation>();
        boolean failAfter;
        RecordedHistory(boolean optimized)throws Exception{this.optimized=optimized;actual=baseline();}
        public void observe(String raw,ProfileTarget target,BackgroundOwnedSingleTask.Task root,
                BackgroundOwnedSingleTask.Task leaf,int display,long elapsed)throws Exception{
            actual.observe(raw,target,root,leaf,display,elapsed);
        }
        public void observeParsed(String raw,ProfileTaskPolicy.Recents.Observation parsed,ProfileTarget target,
                BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf,int display,long elapsed)throws Exception{
            seen.add(parsed);
            if(optimized)actual.observeParsed(raw,parsed,target,root,leaf,display,elapsed);
            else ProfileOwnedTask.PublicRecentHistory.super.observeParsed(raw,parsed,target,root,leaf,display,elapsed);
            if(failAfter)throw new IllegalStateException("SYNTHETIC_OBSERVER_REFUSAL");
        }
        public Set<Integer> observedIds(){return actual.observedIds();}
        public Map<String,Object> evidence(){return actual.evidence();}
    }
    private static final class Platform implements ProfileOwnedTask.Platform {
        final ProfileBrokerHostTest.Fake f=new ProfileBrokerHostTest.Fake();
        final RecordedHistory history;
        final ProfileOwnedTask task;
        String raw=base;int dumps;boolean corruptAfterRemove;
        Platform(boolean optimized)throws Exception{
            history=new RecordedHistory(optimized);
            task=new ProfileOwnedTask(this,TARGET,ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7,history);
        }
        public ProfileTarget recheck(boolean ready){return f.recheck(ready);}
        public void guard()throws Exception{f.guard();}
        public long now(){return f.now();}
        public Object newCookie(){return f.newCookie();}
        public ProfileTaskPolicy.Snapshot snapshot()throws Exception{return f.snapshot();}
        public ProfileTaskPolicy.Recents recents(){throw new AssertionError("unexpected private-profile read");}
        public String publicRecentsDump(){dumps++;return new String(f.recentsApp?withLeaf(raw):raw);}
        public List<BackgroundOwnedSingleTask.Task> roots(){return f.roots();}
        public List<BackgroundOwnedSingleTask.Task> children(Object token){return f.children(token);}
        public void createRoot(Object cookie){f.createRoot(cookie);}
        public void bindRoot(Object root,Object cookie){f.bindRoot(root,cookie);}
        public void removeLeaf(Object token)throws Exception{f.removeLeaf(token);if(corruptAfterRemove)raw=change(raw,"cc00009","cc00008");}
        public boolean deleteRoot(Object token)throws Exception{return f.deleteRoot(token);}
        public void pause(){f.pause();}
        void active()throws Exception{task.prepare();task.beforeDispatch();f.launch();task.accepted(0);yes(task.observe(),"owned leaf not observed");}
        void scopesClosed()throws Exception{
            IdentityHashMap<ProfileTaskPolicy.Recents.Observation,Boolean> unique=new IdentityHashMap<ProfileTaskPolicy.Recents.Observation,Boolean>();
            for(ProfileTaskPolicy.Recents.Observation s:history.seen){yes(unique.put(s,true)==null,"scope reused across fresh reads");refused(()->s.result());}
            yes(history.seen.size()==dumps,"fresh dump/observation counts differ");
        }
    }
    private static void countCheck(String name,int legacy,int optimized,int legacyDumps,int optimizedDumps){
        yes(legacyDumps==optimizedDumps&&legacyDumps>0,"complete read cadence changed");
        if(counted){
            yes(legacy==2*legacyDumps&&optimized==optimizedDumps,"exact full membership parse count differs");
            COUNTS.put(new JSONObject().put("case",name).put("legacy_full_parses",legacy).put("candidate_full_parses",optimized)
                .put("fresh_dumps_each",legacyDumps).put("effect_cadence_changed",false));
        }
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("synthetic fixture and variant required");
        counted="counted".equals(args[1]);
        base=new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8);
        yes(ProfileIdentity.sha(base).equals("b3a758e849b621bac4b21c508fa330dce03df38329b82ea260f01b635d44b0c9"),"synthetic fixture pin changed");
        pass("opaque_private_constructor_and_thread_local_lifetime",()->{
            Class<?> c=ProfileTaskPolicy.Recents.Observation.class;
            yes(Modifier.isFinal(c.getModifiers())&&!Modifier.isPublic(c.getModifiers()),"proof must be opaque/package-local");
            int declared=0,bridges=0;
            for(Constructor<?> k:c.getDeclaredConstructors()){
                Class<?>[] types=k.getParameterTypes();
                if(k.isSynthetic()){
                    bridges++;
                    yes(!Modifier.isPublic(k.getModifiers())&&!Modifier.isProtected(k.getModifiers())
                        &&types.length==3&&types[0]==String.class&&types[1]==ProfileTaskPolicy.Recents.class
                        &&types[2].isSynthetic(),"unexpected Java8 access bridge");
                }else{
                    declared++;
                    yes(Modifier.isPrivate(k.getModifiers())&&types.length==2
                        &&types[0]==String.class&&types[1]==ProfileTaskPolicy.Recents.class,"constructor authority exposed");
                }
            }
            yes(declared==1&&bridges<=1,"unexpected source constructor or bridge");
            yes(!java.io.Serializable.class.isAssignableFrom(c),"proof must not be serializable");
        });
        parity("full_foreign_profile_raw_census_exact",base,true);
        parity("owned_leaf_full_raw_census_exact",withLeaf(base),true);
        parity("complete_utf8_non_ascii_body_preserved",change(base,"    Activities=[]","    diagnosticName=模型测试甲乙\n    Activities=[]"),true);
        parity("decimal_uid_same_complete_proof",change(base,"effectiveUid=u10a999","effectiveUid=1010999"),true);
        parity("omitted_visible_home_and_detached_hidden_preserved",home(),true);
        parity("unknown_hidden_identity_not_filtered",change(base,"mHiddenTasks=[]","mHiddenTasks=[Task{aaa77 #777 type=standard A=10481:org.trillionnium.hepta.local}]"),true);
        parity("null_raw_refused",null,false);
        parity("empty_raw_refused","",false);
        parity("truncated_record_refused",base.substring(0,base.indexOf("    lastDisplayId=-1")),false);
        parity("appended_dump_timeout_refused",base+"dump timed out\n",false);
        parity("duplicate_identity_refused",change(base,"    userId=10 effectiveUid=u10a999 mCallingUid=0","    userId=10 effectiveUid=u10a999 mCallingUid=0\n    userId=10 effectiveUid=u10a999 mCallingUid=0"),false);
        parity("duplicate_internal_task_refused",change(base,"  Visible recent tasks (most recent first):","  * Recent #1: Task{cc00009 #900 type=standard A=1010999:org.example.dormant}\n    userId=10 effectiveUid=u10a999 mCallingUid=0\n    taskId=900 rootTaskId=900\n    Activities=[]\n  Visible recent tasks (most recent first):"),false);
        parity("visible_identity_mismatch_refused",change(base,"    id=900 userId=10 hasTask=false","    id=901 userId=10 hasTask=false"),false);
        parity("uid_user_disagreement_refused",change(base,"effectiveUid=u10a999","effectiveUid=u0a999"),false);
        parity("rich_identity_component_invalid_refused",change(base,"    mActivityComponent=org.example.dormant/.Main","    mActivityComponent=invalid component"),false);
        parity("omitted_visible_foreign_nonhome_refused",home().replace("activityType=2","activityType=1"),false);
        pass("one_raw_two_full_parses_becomes_one_with_equal_complete_census",()->{
            PARSES.set(0);String old=outcome(base,false);int legacy=PARSES.get();
            PARSES.set(0);String now=outcome(base,true);int optimized=PARSES.get();
            yes(old.equals(now)&&old.startsWith("OK:"),"complete census differs");
            if(counted){yes(legacy==2&&optimized==1,"duplicate membership parse not removed");
                COUNTS.put(new JSONObject().put("case","one_raw").put("legacy_full_parses",legacy).put("candidate_full_parses",optimized).put("fresh_dumps_each",1));}
        });
        for(String kind:Arrays.asList("equal_bytes_new_read","changed_raw","truncated_raw","appended_raw","duplicate_rows")){
            pass("opaque_proof_rejects_"+kind,()->{
                String different="equal_bytes_new_read".equals(kind)?new String(base):
                    "changed_raw".equals(kind)?change(base,"cc00009","cc00008"):
                    "truncated_raw".equals(kind)?base.substring(0,base.length()-20):
                    "appended_raw".equals(kind)?base+"extra\n":base+base;
                try(ProfileTaskPolicy.Recents.Observation s=ProfileTaskPolicy.Recents.parseObservation(base)){
                    refused(()->PublicOwnGroupPhysicalFence.inspectRecents(different,s));
                    // checked(raw) may reject malformed inputs before claim; no scope
                    // survives its synchronous finally boundary in the production caller.
                }
            });
        }
        pass("one_scope_cannot_authorize_second_projection",()->{
            try(ProfileTaskPolicy.Recents.Observation s=ProfileTaskPolicy.Recents.parseObservation(base)){
                PublicOwnGroupPhysicalFence.inspectRecents(base,s);
                refused(()->PublicOwnGroupPhysicalFence.inspectRecents(base,s));
            }
        });
        pass("closed_scope_rejects_same_and_changed_next_phase",()->{
            ProfileTaskPolicy.Recents.Observation s=ProfileTaskPolicy.Recents.parseObservation(base);s.close();
            refused(()->s.result());refused(()->PublicOwnGroupPhysicalFence.inspectRecents(base,s));
            refused(()->PublicOwnGroupPhysicalFence.inspectRecents(new String(base),s));
        });
        pass("wrong_thread_cannot_consume_or_close_owner_scope",()->{
            try(ProfileTaskPolicy.Recents.Observation s=ProfileTaskPolicy.Recents.parseObservation(base)){
                final List<Throwable> errors=new ArrayList<Throwable>();
                Thread other=new Thread(()->{
                    try{PublicOwnGroupPhysicalFence.inspectRecents(base,s);}catch(Throwable t){errors.add(t);}
                    try{closeFromOtherThread(s);}catch(Throwable t){errors.add(t);}
                });
                other.start();other.join();yes(errors.size()==2,"other thread accepted");
                PublicOwnGroupPhysicalFence.inspectRecents(base,s);
            }
        });
        pass("null_scope_refused",()->refused(()->PublicOwnGroupPhysicalFence.inspectRecents(base,null)));
        pass("mismatch_claim_cannot_be_retried_with_original",()->{
            try(ProfileTaskPolicy.Recents.Observation s=ProfileTaskPolicy.Recents.parseObservation(base)){
                refused(()->PublicOwnGroupPhysicalFence.inspectRecents(new String(base),s));
                refused(()->PublicOwnGroupPhysicalFence.inspectRecents(base,s));
            }
        });
        pass("full_ownership_lifecycle_fresh_reads_effects_and_history_equal",()->{
            Platform old=new Platform(false),now=new Platform(true);
            PARSES.set(0);old.active();old.task.retire(old.now()+1400);int legacy=PARSES.get();
            PARSES.set(0);now.active();now.task.retire(now.now()+1400);int optimized=PARSES.get();
            yes(old.task.cleanupKnown()&&now.task.cleanupKnown(),"complete retirement rejected");
            yes(old.f.mutations.equals(Arrays.asList("create","bind","remove_leaf","delete_root"))&&old.f.mutations.equals(now.f.mutations),"task effects changed");
            yes(describe(old.history.evidence()).equals(describe(now.history.evidence())),"complete history evidence differs");
            countCheck("full_lifecycle",legacy,optimized,old.dumps,now.dumps);old.scopesClosed();now.scopesClosed();
        });
        pass("coordinator_finally_invalidates_scope_on_observer_exception",()->{
            Platform p=new Platform(true);p.history.failAfter=true;
            Exception failure=refused(()->p.task.verifyPublicRecentHistory());
            yes("SYNTHETIC_OBSERVER_REFUSAL".equals(failure.getMessage()),"wrong synthetic failure");
            p.scopesClosed();yes(p.f.mutations.isEmpty(),"failure produced task effect");
            p.history.failAfter=false;p.task.verifyPublicRecentHistory();p.scopesClosed();
            yes(p.history.seen.size()==2,"next phase did not acquire fresh read and proof");
        });
        pass("foreign_history_change_still_latches_before_any_retire_effect",()->{
            Platform old=new Platform(false),now=new Platform(true);old.active();now.active();
            old.raw=change(base,"cc00009","cc00008");now.raw=old.raw;
            String first=refused(()->old.task.retire(old.now()+1400)).getMessage();
            String second=refused(()->now.task.retire(now.now()+1400)).getMessage();
            yes(first.equals(second),"history refusal changed");
            yes(old.f.mutations.equals(Arrays.asList("create","bind"))&&old.f.mutations.equals(now.f.mutations),"effect after history refusal");
            yes(Boolean.TRUE.equals(old.history.evidence().get("history_refusal_latched"))&&Boolean.TRUE.equals(now.history.evidence().get("history_refusal_latched")),"history latch omitted");
            old.scopesClosed();now.scopesClosed();
        });
        pass("late_foreign_change_after_leaf_remove_still_blocks_root_delete",()->{
            Platform old=new Platform(false),now=new Platform(true);old.active();now.active();
            old.corruptAfterRemove=true;now.corruptAfterRemove=true;
            String first=refused(()->old.task.retire(old.now()+1400)).getMessage();
            String second=refused(()->now.task.retire(now.now()+1400)).getMessage();
            yes(first.equals(second),"late history refusal changed");
            yes(old.f.mutations.equals(Arrays.asList("create","bind","remove_leaf"))&&old.f.mutations.equals(now.f.mutations),"root deleted after foreign history change");
            yes(!old.task.cleanupKnown()&&!now.task.cleanupKnown(),"late history granted cleanup");
            old.scopesClosed();now.scopesClosed();
        });
        System.out.println(new JSONObject().put("schema","hepta.profile-recents-parse-reuse-cases.v1")
            .put("passed",true).put("cases",CASES).put("case_count",CASES.length()).put("assertions",assertions)
            .put("instrumented",counted).put("actual_counted_full_parse_calls",COUNTS)
            .put("synthetic_framework_and_clock",true).put("phone_operations",0).put("phone_latency_improvement_claimed",false)
            .put("original_cleanup_read_budget_ms",1400));
    }
}
