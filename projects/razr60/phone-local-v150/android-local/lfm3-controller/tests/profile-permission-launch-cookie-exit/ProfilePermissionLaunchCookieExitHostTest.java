package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Actual ProfileOwnedTask and permission-pair reader; framework rows/time are explicit synthetic ports. */
public final class ProfilePermissionLaunchCookieExitHostTest {
    private static int assertions;
    private static String fixture;
    private static final List<Map<String,Object>> RESULTS=new ArrayList<Map<String,Object>>();
    private static final List<Map<String,Object>> TRACES=new ArrayList<Map<String,Object>>();
    private interface Work {void run()throws Exception;}
    private interface Hook {void run(Rig rig)throws Exception;}
    private static final String HOME=ProfilePermissionTransientHostTest.HOME;
    private static void yes(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    private static void test(String name,Work work){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        try{work.run();row.put("passed",true);}
        catch(Throwable e){row.put("passed",false);row.put("failure",e.toString());
            if(e instanceof ProfileTaskPolicy.Refusal)row.put("refusal_code",((ProfileTaskPolicy.Refusal)e).code);}
        RESULTS.add(row);
    }
    private static void rejects(String code,Work work)throws Exception{
        try{work.run();throw new AssertionError("unproved launch-cookie continuation accepted");}
        catch(ProfileTaskPolicy.Refusal e){yes(code==null||code.equals(e.code),"wrong refusal "+e.code+" expected "+code);}
    }
    private static BackgroundOwnedSingleTask.Task stableBase(BackgroundOwnedSingleTask.Task t){
        return new BackgroundOwnedSingleTask.Task(t.id,t.display,t.user,t.parent,t.uid,t.topUid,t.activities,
                t.token,t.cookies,t.intentComponent,ProfileBrokerHostTest.SPLASH.equals(t.base)?HOME:t.base,
                t.top,t.real,t.orig,t.running,t.visible);
    }
    private static BackgroundOwnedSingleTask.Task alter(BackgroundOwnedSingleTask.Task t,String field){
        List<Object> cookies=t.cookies;
        if("cookie_remove".equals(field))cookies=Collections.emptyList();
        if("cookie_replace".equals(field))cookies=Collections.singletonList(new Object());
        if("cookie_add".equals(field)){cookies=new ArrayList<Object>(t.cookies);cookies.add(new Object());}
        return new BackgroundOwnedSingleTask.Task("id".equals(field)?t.id+1:t.id,
                "display".equals(field)?t.display+1:t.display,"user".equals(field)?t.user+1:t.user,
                "parent".equals(field)?t.parent+1:t.parent,"uid".equals(field)?t.uid+1:t.uid,
                "top_uid".equals(field)?10367:t.topUid,
                "count_zero".equals(field)?0:"count_two".equals(field)?2:"count_three".equals(field)?3:t.activities,
                "binder".equals(field)?new ProfileBrokerHostTest.TaskToken(new Object()):t.token,
                cookies,"intent".equals(field)?"example.foreign/.Main":t.intentComponent,
                "base".equals(field)?"example.foreign/.Main":t.base,
                "foreign_top".equals(field)?"example.foreign/.Main":"unknown_top".equals(field)?null:
                        "other_target_top".equals(field)?ProfileBrokerHostTest.SPLASH:t.top,
                "real".equals(field)?"example.foreign/.Main":t.real,
                "orig".equals(field)?"example.foreign/.Main":t.orig,
                !"not_running".equals(field)&&t.running,!"not_visible".equals(field)&&t.visible);
    }
    private static BackgroundOwnedSingleTask.Task withCookies(BackgroundOwnedSingleTask.Task t,List<Object> cookies){
        return new BackgroundOwnedSingleTask.Task(t.id,t.display,t.user,t.parent,t.uid,t.topUid,t.activities,
                t.token,cookies,t.intentComponent,t.base,t.top,t.real,t.orig,t.running,t.visible);
    }


    /** Explicit synthetic history port. Existing production recents policy still parses/checks every supplied row. */
    private static final class History implements ProfileOwnedTask.PublicRecentHistory {
        int calls;boolean fail;Set<Integer> ids=Collections.emptySet();
        @Override public void observe(String raw,ProfileTarget target,BackgroundOwnedSingleTask.Task root,
                BackgroundOwnedSingleTask.Task leaf,int display,long elapsed)throws Exception{
            calls++;ProfileTaskPolicy.Recents recent=ProfileTaskPolicy.Recents.parse(raw);
            if(leaf==null)recent.requireDedicatedEmpty(target);else recent.requireOnlyOwned(target,leaf.id);
            ids=new LinkedHashSet<Integer>(recent.ids);
            if(fail)throw new ProfileTaskPolicy.Refusal("TEST_RECENTS_CHANGED");
        }
        @Override public Set<Integer> observedIds(){return Collections.unmodifiableSet(ids);}
        @Override public Map<String,Object> evidence(){return Collections.emptyMap();}
    }

    private static final class Rig implements ProfileOwnedTask.Platform {
        final ProfilePermissionTransientHostTest.Adapter a=new ProfilePermissionTransientHostTest.Adapter(fixture);
        final ProfileBrokerHostTest.Fake f=a.f;final History history=new History();
        final Object unrelatedCookie=new Object();
        int snapshots,rootReads,leafReads,pauses,pairReads,returnedProofs,guards,rechecks;
        boolean transition,duplicateLaunch=true,wrongCopiedCookie,dropLaunch=true,foreignRecent;
        String phase="before_activity_dump",freshRootChange,freshLeafChange;
        Hook onPause;
        Map<String,Object> mismatch=Collections.emptyMap();
        ProfileOwnedTask start(boolean retain)throws Exception{
            ProfileOwnedTask task=new ProfileOwnedTask(this,ProfilePermissionTransientHostTest.target(),
                    ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7,history);
            task.prepare();task.beforeDispatch();f.launch();task.accepted(0);
            if(retain)yes(task.observe(),"actual initial owned leaf not retained");
            snapshots=0;rootReads=0;leafReads=0;pauses=0;pairReads=0;returnedProofs=0;guards=0;rechecks=0;history.calls=0;
            return task;
        }
        void transition(){a.permission=true;transition=true;}
        void noEffects(){yes(f.mutations.equals(Arrays.asList("create","bind")),"read-only continuation mutated a task or display");}
        BackgroundOwnedSingleTask.Task row(boolean root){
            BackgroundOwnedSingleTask.Task t=stableBase(root?a.rootRow():a.leafRow());
            if(root&&f.app&&duplicateLaunch)
                t=withCookies(t,Arrays.asList(f.rootCookie,wrongCopiedCookie?unrelatedCookie:f.launchCookie));
            if(pauses>0&&dropLaunch&&f.app)
                t=withCookies(t,root?Collections.singletonList(f.rootCookie):Collections.emptyList());
            String field=root?freshRootChange:freshLeafChange;
            if(pauses>0&&field!=null){
                if("drop_root_cookie".equals(field))t=withCookies(t,Collections.singletonList(f.launchCookie));
                else if("add_unrelated_cookie".equals(field)){
                    List<Object> cookies=new ArrayList<Object>(t.cookies);cookies.add(unrelatedCookie);t=withCookies(t,cookies);
                }else t=alter(t,field);
            }
            return t;
        }
        @Override public ProfileTarget recheck(boolean ready)throws Exception{rechecks++;return a.recheck(ready);}
        @Override public void guard()throws Exception{guards++;a.guard();}
        @Override public long now(){return a.now();}
        @Override public Object newCookie(){return a.newCookie();}
        @Override public ProfileTaskPolicy.Snapshot snapshot()throws Exception{snapshots++;return a.snapshot();}
        @Override public ProfileTaskPolicy.Recents recents()throws Exception{return a.recents();}
        @Override public String publicRecentsDump(){return f.app
                ?foreignRecent?ProfileBrokerHostTest.recent(100,0,10367,f.leafId,10,1010367,401,10,1010367)
                    :ProfileBrokerHostTest.recent(100,0,10367,f.leafId,10,1010367)
                :ProfileBrokerHostTest.recent(100,0,10367);}
        @Override public List<BackgroundOwnedSingleTask.Task> roots(){rootReads++;return f.root?Collections.singletonList(row(true)):Collections.emptyList();}
        @Override public List<BackgroundOwnedSingleTask.Task> children(Object token){
            leafReads++;yes(token.equals(f.rootToken),"wrong live root queried");
            if(f.extraChild)return f.children(token);
            return f.app?Collections.singletonList(row(false)):Collections.emptyList();
        }
        @Override public void createRoot(Object cookie){a.createRoot(cookie);}
        @Override public void bindRoot(Object token,Object cookie){a.bindRoot(token,cookie);}
        @Override public void removeLeaf(Object token)throws Exception{a.removeLeaf(token);}
        @Override public boolean deleteRoot(Object token)throws Exception{return a.deleteRoot(token);}
        @Override public void pause()throws Exception{pauses++;a.pause();if(onPause!=null)onPause.run(this);}
        @Override public Map<String,Object> permissionReadMismatchEvidence(){return mismatch;}
        @Override public ProfilePermissionTransient.Proof permissionTransient(BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf)throws Exception{
            if(transition){
                transition=false;pairReads++;a.permission=false;
                // The first complete after-pair retains both exact capabilities and all original cookies.
                BackgroundOwnedSingleTask.Task afterRoot=row(true),afterLeaf=row(false);
                PermissionPairReadHostAdapter pair=new PermissionPairReadHostAdapter(
                        Collections.singletonList(afterRoot),Collections.singletonList(afterLeaf));
                try{pair.read(root,leaf,phase);throw new AssertionError("mixed pair returned an authority");}
                finally{if(mismatch.isEmpty())mismatch=pair.permissionReadMismatchEvidence();}
            }
            returnedProofs++;return a.permissionTransient(root,leaf);
        }
    }
    private static String retained(ProfileOwnedTask p){return (String)p.evidence().get("leaf_token_id");}
    private static boolean invoke(String entry,ProfileOwnedTask p,long deadline)throws Exception{
        return "confirm".equals(entry)?p.confirmInitializationReady(deadline):"APP_READY".equals(p.initializationState(deadline));
    }
    private static void samePairDiagnostic(ProfileOwnedTask p){
        Map<?,?> d=p.firstPermissionReadMismatch();
        for(String key:new String[]{"root","leaf"}){
            Map<?,?> row=(Map<?,?>)d.get(key);yes(row!=null,"actual pair diagnostic missing");
            yes(Boolean.TRUE.equals(row.get("complete_identity_equal")),"initial pair changed a capability/cookie");
            yes(Boolean.FALSE.equals(row.get("complete_taskinfo_equal")),"permission-to-HOME presentation was not sampled");
        }
        yes(Boolean.FALSE.equals(d.get("allows_input_or_model_resumption")),"read diagnostic became authority");
    }
    private static void positive(String entry,String phase)throws Exception{
        Rig r=new Rig();ProfileOwnedTask p=r.start(true);String token=retained(p);r.transition();r.phase=phase;
        long before=r.f.now,deadline=before+1000;Map<String,Object> trace=new LinkedHashMap<String,Object>();
        trace.put("entry",entry);trace.put("phase",phase);trace.put("original_deadline",deadline);
        try{
            boolean passed=invoke(entry,p,deadline);trace.put("returned_ready",passed);
            yes(passed,"complete fresh HOME pair did not pass actual coordinator");
            yes(r.snapshots==2&&r.rootReads==2&&r.leafReads==2&&r.pauses==1&&r.pairReads==1,"exactly one fresh complete replacement pair required");
            yes(r.returnedProofs==0&&r.a.proofs==0,"mixed old permission pair was used as a proof");
            yes(r.f.now==before+20&&r.f.now<deadline,"original one pause and deadline changed");
            yes(token.equals(retained(p)),"retained actual task was replaced");
            yes(r.history.calls==1&&r.guards==4&&r.rechecks>=2,"fresh global/history/installation/cancel checks missing");
            samePairDiagnostic(p);
            Map<String,Object> last=p.lastLeafValidation();
            yes(Boolean.TRUE.equals(last.get("valid"))&&Boolean.TRUE.equals(last.get("retained_task_identity_matches")),"fresh actual retained-leaf validation missing");
            yes(Boolean.FALSE.equals(last.get("launch_cookie_present")),"launch cookie was not actually removed");
            yes(!last.containsKey("permission_transient_verified")&&!last.containsKey("retirement_only"),"permission proof used as business authority");
            yes(r.row(true).cookies.equals(Collections.singletonList(r.f.rootCookie))&&r.row(false).cookies.isEmpty(),"wrong cookie set after pause");
            int reads=r.snapshots;WindowOwnership window=p.window(22,r.f.leafId,deadline);
            yes(r.snapshots==reads+1&&token.equals(window.taskTokenId),"window proof did not require another complete current observation");
            r.noEffects();
        }finally{
            trace.put("snapshots",r.snapshots);trace.put("pair_reads",r.pairReads);trace.put("pauses",r.pauses);
            trace.put("root_cookie_count",r.row(true).cookies.size());trace.put("leaf_cookie_count",r.row(false).cookies.size());
            trace.put("retained_token_unchanged",token.equals(retained(p)));trace.put("mutations",new ArrayList<String>(r.f.mutations));
            trace.put("first_pair",p.firstPermissionReadMismatch());trace.put("last_leaf",p.lastLeafValidation());
            trace.put("clock_now",r.f.now);TRACES.add(trace);
        }
    }
    private static void negative(String entry,String scenario)throws Exception{
        Rig r=new Rig();
        if("generic_one_cookie_root".equals(scenario))r.duplicateLaunch=false;
        if("wrong_copied_launch_binder".equals(scenario))r.wrongCopiedCookie=true;
        ProfileOwnedTask p=r.start(!"first_claim".equals(scenario));String token=retained(p);r.transition();
        long deadline=r.f.now+1000;
        if("root_cookie".equals(scenario))r.freshRootChange="drop_root_cookie";
        else if("root_binder".equals(scenario))r.freshRootChange="binder";
        else if("leaf_binder".equals(scenario))r.freshLeafChange="binder";
        else if("leaf_full_uid".equals(scenario))r.freshLeafChange="uid";
        else if("leaf_parent".equals(scenario))r.freshLeafChange="parent";
        else if("leaf_display".equals(scenario))r.freshLeafChange="display";
        else if("root_extra_cookie".equals(scenario))r.freshRootChange="add_unrelated_cookie";
        else if("leaf_extra_cookie".equals(scenario))r.freshLeafChange="add_unrelated_cookie";
        else if("foreign_top".equals(scenario))r.freshLeafChange="foreign_top";
        else if("cancel".equals(scenario))r.onPause=x->x.f.cancel=true;
        else if("deadline".equals(scenario))r.onPause=x->x.f.now+=1000;
        else if("pause_margin".equals(scenario))deadline=r.f.now+20;
        else if("foreign_global".equals(scenario))r.onPause=x->x.f.foreign=true;
        else if("foreign_recents".equals(scenario))r.onPause=x->x.foreignRecent=true;
        else if("installed_identity".equals(scenario))r.onPause=x->x.f.actual=ProfileBrokerHostTest.target(11,1010367);
        else if("permission_reappears".equals(scenario))r.onPause=x->x.a.permission=true;
        final long limit=deadline;
        rejects(null,()->invoke(entry,p,limit));
        yes(r.pairReads==1&&r.snapshots<=2&&r.pauses<=1,"refusal bypassed original complete read limits");
        if(token==null)yes(retained(p)==null,"cookie loss made first claim");
        else yes(token.equals(retained(p)),"refusal replaced retained task");
        r.noEffects();
    }
    private static String json(Object value){
        if(value==null)return "null";
        if(value instanceof String){String s=(String)value;StringBuilder b=new StringBuilder("\"");for(char c:s.toCharArray()){
            if(c=='"'||c=='\\')b.append('\\').append(c);else if(c=='\n')b.append("\\n");else if(c=='\r')b.append("\\r");
            else if(c=='\t')b.append("\\t");else if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);
        }return b.append('"').toString();}
        if(value instanceof Number||value instanceof Boolean)return value.toString();
        if(value instanceof Map){List<String> rows=new ArrayList<String>();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())rows.add(json(e.getKey().toString())+":"+json(e.getValue()));return "{"+String.join(",",rows)+"}";}
        if(value instanceof Iterable){List<String> rows=new ArrayList<String>();for(Object e:(Iterable<?>)value)rows.add(json(e));return "["+String.join(",",rows)+"]";}
        throw new IllegalArgumentException("unsupported diagnostic value "+value.getClass());
    }
    public static void main(String[] args)throws Exception{
        if(args.length<2||args.length>3)throw new IllegalArgumentException("fixture, result, optional positive-only required");
        byte[] raw=Files.readAllBytes(Paths.get(args[0]));
        yes(raw.length==2306&&ProfileIdentity.sha(raw).equals("7f8adcb158486f74a1ebe342e54902b9fc7550ed7b0dd7bf11b36d1d97ab63f0"),"exact existing synthetic fixture required");
        fixture=new String(raw,StandardCharsets.UTF_8);ProfilePermissionTransientHostTest.fixtureShape(fixture);
        for(final String entry:new String[]{"confirm","initialization"})for(final String phase:new String[]{"before_activity_dump","after_activity_dump"})
            test(entry+" complete pair then launch-cookie exit "+phase,()->positive(entry,phase));
        if(args.length==2){
            for(final String entry:new String[]{"confirm","initialization"})for(final String scenario:new String[]{
                    "root_cookie","root_binder","leaf_binder","leaf_full_uid","leaf_parent","leaf_display",
                    "root_extra_cookie","leaf_extra_cookie","foreign_top","generic_one_cookie_root","wrong_copied_launch_binder",
                    "first_claim","cancel","deadline","pause_margin","foreign_global","foreign_recents","installed_identity","permission_reappears"})
                test(entry+" refuses "+scenario,()->negative(entry,scenario));
            for(final String operation:new String[]{"observe","window","permission-window"})test("ordinary "+operation+" cannot consume new read continuation",()->{
                Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();boolean refused=false;
                try{if("observe".equals(operation))p.observe();else if("window".equals(operation))p.window(22,r.f.leafId,r.f.now+1000);else p.permissionForInitialization(22,r.f.leafId,r.f.now+1000);}
                catch(ProfilePermissionTransient.ReadChanged expected){refused=true;}
                yes(refused&&r.pauses==0&&r.snapshots==1&&r.pairReads==1,"ordinary API gained read retry");r.noEffects();
            });
        }else if(!"positive-only".equals(args[2]))throw new IllegalArgumentException("exact positive-only mode required");
        boolean all=true;for(Map<String,Object> row:RESULTS)all&=Boolean.TRUE.equals(row.get("passed"));
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("schema","hepta.profile-permission-launch-cookie-exit-host.v1");
        report.put("all_pass",all);report.put("cases",RESULTS.size());report.put("assertions",assertions);report.put("results",RESULTS);report.put("positive_traces",TRACES);
        report.put("phone_operations",0);report.put("android_build",false);report.put("taskinfo_fixtures_synthetic",true);
        report.put("actual_coordinator_and_pair_reader",true);report.put("new_input_model_or_window_authority",false);
        Files.write(Paths.get(args[1]),(json(report)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(json(report));if(!all)System.exit(1);
    }
}
