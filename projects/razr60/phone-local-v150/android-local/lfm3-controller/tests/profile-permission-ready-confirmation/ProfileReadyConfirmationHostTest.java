package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Real ready-confirmation coordinator and real pair-read code; only framework data/time are synthetic. */
public final class ProfileReadyConfirmationHostTest {
    private static int assertions;
    private static final List<String> CASES=new ArrayList<String>();
    private static String fixture;
    private interface Work {void run()throws Exception;}
    private interface Hook {void run(Rig rig)throws Exception;}
    private static void yes(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(String name,Work work)throws Exception{work.run();CASES.add(name);System.out.println("PASS "+name);}
    private static void rejects(String code,Work work)throws Exception{
        try{work.run();throw new AssertionError("unproved ready confirmation accepted: "+code);}
        catch(ProfileTaskPolicy.Refusal error){yes(code.equals(error.code),"wrong refusal: "+error.code+" expected "+code);}
    }
    private static ProfilePermissionTransient.ReadChanged changed(Work work)throws Exception{
        try{work.run();throw new AssertionError("sampling change did not remain typed");}
        catch(ProfilePermissionTransient.ReadChanged error){assertions++;return error;}
    }
    private static final String ROOT_CHANGED="PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ";
    private static final String LEAF_CHANGED="PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ";
    private static final String DEADLINE="PROFILE_PERMISSION_READ_DEADLINE";
    private static final String HOME=ProfilePermissionTransientHostTest.HOME;

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
        int guards,rechecks,snapshots,rootReads,leafReads,pauses,pairReads,dumpReads,returnedProofs;
        long readCost,recheckCost,pairCost;boolean transition,cookieExit,onlyRoot,onlyLeaf;
        String phase="before_activity_dump",afterRootChange,afterLeafChange;
        String freshRootChange,freshLeafChange;Hook onPause,onGuard,onRecheck;
        Map<String,Object> mismatch=Collections.emptyMap();
        ProfileOwnedTask start(boolean retain)throws Exception{
            ProfileOwnedTask task=new ProfileOwnedTask(this,ProfilePermissionTransientHostTest.target(),
                    ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7,history);
            task.prepare();task.beforeDispatch();f.launch();task.accepted(0);
            if(retain)yes(task.observe(),"ordinary retained target missing");
            reset();return task;
        }
        void reset(){guards=0;rechecks=0;snapshots=0;rootReads=0;leafReads=0;pauses=0;
            pairReads=0;dumpReads=0;returnedProofs=0;history.calls=0;}
        void transition(){a.permission=true;transition=true;}
        void noEffects(){yes(f.mutations.equals(Arrays.asList("create","bind")),"read coordination mutated task or display");}
        BackgroundOwnedSingleTask.Task row(boolean root){
            BackgroundOwnedSingleTask.Task t=stableBase(root?a.rootRow():a.leafRow());
            if(cookieExit&&a.permission&&root&&f.app)t=withCookies(t,Arrays.asList(f.rootCookie,f.launchCookie));
            String field=root?freshRootChange:freshLeafChange;
            if(snapshots>=2&&field!=null)t=alter(t,field);
            return t;
        }
        @Override public ProfileTarget recheck(boolean ready)throws Exception{
            rechecks++;f.now+=recheckCost;if(onRecheck!=null)onRecheck.run(this);return a.recheck(ready);
        }
        @Override public void guard()throws Exception{guards++;if(onGuard!=null)onGuard.run(this);a.guard();}
        @Override public long now(){return a.now();}
        @Override public Object newCookie(){return a.newCookie();}
        @Override public ProfileTaskPolicy.Snapshot snapshot()throws Exception{
            snapshots++;ProfileTaskPolicy.Snapshot value=a.snapshot();f.now+=readCost;return value;
        }
        @Override public ProfileTaskPolicy.Recents recents()throws Exception{return a.recents();}
        @Override public String publicRecentsDump(){return f.app
                ?ProfileBrokerHostTest.recent(100,0,10367,f.leafId,10,1010367)
                :ProfileBrokerHostTest.recent(100,0,10367);}
        @Override public List<BackgroundOwnedSingleTask.Task> roots(){
            rootReads++;return f.root?Collections.singletonList(row(true)):Collections.emptyList();
        }
        @Override public List<BackgroundOwnedSingleTask.Task> children(Object token){
            leafReads++;yes(token.equals(f.rootToken),"fresh read queried another root");
            if(f.extraChild)return f.children(token);
            return f.app?Collections.singletonList(row(false)):Collections.emptyList();
        }
        @Override public void createRoot(Object cookie){a.createRoot(cookie);}
        @Override public void bindRoot(Object token,Object cookie){a.bindRoot(token,cookie);}
        @Override public void removeLeaf(Object token)throws Exception{a.removeLeaf(token);}
        @Override public boolean deleteRoot(Object token)throws Exception{return a.deleteRoot(token);}
        @Override public void pause()throws Exception{pauses++;a.pause();if(onPause!=null)onPause.run(this);}
        @Override public Map<String,Object> permissionReadMismatchEvidence(){return mismatch;}
        @Override public ProfilePermissionTransient.Proof permissionTransient(BackgroundOwnedSingleTask.Task root,
                BackgroundOwnedSingleTask.Task leaf)throws Exception{
            if(transition){
                transition=false;pairReads++;if("after_activity_dump".equals(phase))dumpReads++;
                a.permission=false;f.now+=pairCost;
                BackgroundOwnedSingleTask.Task afterRoot=onlyLeaf?root:row(true);
                BackgroundOwnedSingleTask.Task afterLeaf=onlyRoot?leaf:row(false);
                if(afterRootChange!=null)afterRoot=alter(afterRoot,afterRootChange);
                if(afterLeafChange!=null)afterLeaf=alter(afterLeaf,afterLeafChange);
                PermissionPairReadHostAdapter pair=new PermissionPairReadHostAdapter(
                        Collections.singletonList(afterRoot),Collections.singletonList(afterLeaf));
                try{pair.read(root,leaf,phase);throw new AssertionError("mixed pair returned a permission proof");}
                finally{if(mismatch.isEmpty())mismatch=pair.permissionReadMismatchEvidence();}
            }
            ProfilePermissionTransient.Proof proof=a.permissionTransient(root,leaf);
            returnedProofs++;return proof;
        }
    }
    private static String retained(ProfileOwnedTask task){return (String)task.evidence().get("leaf_token_id");}
    private static void ordinaryValidation(ProfileOwnedTask task){
        Map<String,Object> last=task.lastLeafValidation();
        yes(Boolean.TRUE.equals(last.get("valid")),"fresh ordinary leaf was not proved");
        yes(!last.containsKey("permission_transient_verified")&&!last.containsKey("retirement_only"),"permission proof became ordinary success");
        Map<?,?> checks=(Map<?,?>)last.get("checks");
        yes(Boolean.TRUE.equals(checks.get("top_package_matches")),"fresh target package not checked");
        yes(Boolean.TRUE.equals(checks.get("top_activity_info_uid_matches")),"fresh target top UID not checked");
    }
    private static void positive(String phase)throws Exception{
        Rig r=new Rig();ProfileOwnedTask p=r.start(true);String token=retained(p);
        r.transition();r.phase=phase;
        yes(p.confirmInitializationReady(r.f.now+1000),"same-capability permission exit did not become ready");
        yes(r.snapshots==2&&r.rootReads==2&&r.leafReads==2,"replacement graph was not re-read in full");
        yes(r.pauses==1&&r.pairReads==1&&r.returnedProofs==0&&r.a.proofs==0,"old permission proof was reused");
        yes(r.history.calls==1&&r.rechecks==4&&r.guards==4,"fresh recents/installation/guard checks missing");
        yes(r.dumpReads==("after_activity_dump".equals(phase)?1:0),"phase port changed");
        yes(token.equals(retained(p)),"retained task was replaced");
        Map<?,?> d=p.firstPermissionReadMismatch();
        yes(phase.equals(d.get("phase")),"first mismatch phase missing");
        for(String name:new String[]{"root","leaf"}){
            Map<?,?> row=(Map<?,?>)d.get(name);
            yes(Boolean.TRUE.equals(row.get("complete_identity_equal")),"capabilities were not identical");
            yes(Boolean.FALSE.equals(row.get("complete_taskinfo_equal")),"presentation mismatch erased");
        }
        yes(Boolean.FALSE.equals(d.get("allows_input_or_model_resumption")),"diagnostic became authority");
        ordinaryValidation(p);r.noEffects();
        // A subsequent business window is minted only by a separate complete current observation.
        int before=r.snapshots;WindowOwnership window=p.window(22,300,r.f.now+1000);
        yes(r.snapshots==before+1&&window.windowId==22&&token.equals(window.taskTokenId),"business window bypassed a fresh read");
        r.noEffects();
    }

    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("authored synthetic fixture required");
        byte[] raw=Files.readAllBytes(Paths.get(args[0]));
        yes(raw.length==2306&&ProfileIdentity.sha(raw).equals(
                "7f8adcb158486f74a1ebe342e54902b9fc7550ed7b0dd7bf11b36d1d97ab63f0"),"synthetic fixture changed");
        fixture=new String(raw,StandardCharsets.UTF_8);ProfilePermissionTransientHostTest.fixtureShape(fixture);
        test("stable target confirms once without retry",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);
            yes(p.confirmInitializationReady(r.f.now+1000),"stable target not ready");
            yes(r.snapshots==1&&r.pauses==0&&r.pairReads==0&&r.history.calls==1,"stable target was polled");
            ordinaryValidation(p);r.noEffects();
        });
        test("stable permission remains setup required",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.a.permission=true;
            rejects("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.snapshots==1&&r.pauses==0&&r.returnedProofs==1,"pending permission was retried");
            r.noEffects();
        });
        test("unobserved empty target remains waiting",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(false);r.f.app=false;r.f.recentsApp=false;
            yes(!p.confirmInitializationReady(r.f.now+1000),"empty target became ready");
            yes(r.snapshots==1&&r.pauses==0&&retained(p)==null,"empty target was claimed or polled");r.noEffects();
        });
        test("before dump exit discards mixed pair and fully re-observes",()->positive("before_activity_dump"));
        test("after dump exit discards mixed pair and fully re-observes",()->positive("after_activity_dump"));
        test("permission exit cannot make the first leaf claim",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(false);r.transition();
            rejects(LEAF_CHANGED,()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.pauses==0&&r.snapshots==1&&retained(p)==null,"first claim escaped strict ownership");r.noEffects();
        });
        for(final String side:new String[]{"root","leaf"}){
            for(final String field:new String[]{"id","display","user","parent","uid","binder",
                    "cookie_remove","cookie_replace","cookie_add","intent","base","real","orig",
                    "top_uid","count_zero","count_two","count_three","foreign_top","unknown_top","not_running","not_visible"}){
                test(side+" changed "+field+" cannot trigger ready retry",()->{
                    Rig r=new Rig();ProfileOwnedTask p=r.start(true);String token=retained(p);r.transition();
                    if("root".equals(side))r.afterRootChange=field;else r.afterLeafChange=field;
                    // A real root presentation change determines the original signal code even if
                    // the leaf presentation is also invalid. Immutable leaf changes fail earlier.
                    String code="root".equals(side)||Arrays.asList("top_uid","count_zero","count_two",
                            "count_three","foreign_top","unknown_top","not_running","not_visible").contains(field)
                            ?ROOT_CHANGED:LEAF_CHANGED;
                    rejects(code,()->p.confirmInitializationReady(r.f.now+1000));
                    yes(r.pauses==0&&r.snapshots==1&&token.equals(retained(p)),"invalid exit retried or reclaimed");
                    r.noEffects();
                });
            }
        }
        test("root-only presentation exit is not a complete pair",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.onlyRoot=true;
            rejects(ROOT_CHANGED,()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.pauses==0,"root-only exit retried");r.noEffects();
        });
        test("leaf-only presentation exit is not a complete pair",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.onlyLeaf=true;
            rejects(LEAF_CHANGED,()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.pauses==0,"leaf-only exit retried");r.noEffects();
        });
        test("legacy cookie-exit signal is not accepted by ready confirmation",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.cookieExit=true;
            rejects(ROOT_CHANGED,()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.pauses==0&&r.snapshots==1,"cookie-loss exception leaked into ready confirmation");r.noEffects();
        });
        for(final String side:new String[]{"root","leaf"}){
            for(final String field:new String[]{"id","display","user","parent","uid","binder","cookie_remove",
                    "cookie_replace","cookie_add","intent","base","real","orig","top_uid","count_zero",
                    "count_two","foreign_top","unknown_top","other_target_top","not_running","not_visible"}){
                test("fresh "+side+" changed "+field+" rejects without a third read",()->{
                    Rig r=new Rig();ProfileOwnedTask p=r.start(true);String token=retained(p);r.transition();
                    if("root".equals(side))r.freshRootChange=field;else r.freshLeafChange=field;
                    rejects("root".equals(side)?ROOT_CHANGED:LEAF_CHANGED,
                            ()->p.confirmInitializationReady(r.f.now+1000));
                    yes(r.pauses==1&&r.snapshots==2&&r.pairReads==1,"unstable replacement was retried");
                    yes(token.equals(retained(p)),"unstable replacement changed retained leaf");r.noEffects();
                });
            }
        }
        test("permission reappearing in the replacement read gets no second retry",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();
            r.onPause=x->{x.a.permission=true;x.transition=true;};
            rejects(ROOT_CHANGED,()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.snapshots==2&&r.pauses==1&&r.pairReads==1,"second permission change was consumed");r.noEffects();
        });
        test("retained leaf Binder cannot change before the permission sample",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);String token=retained(p);
            r.f.leafToken=new ProfileBrokerHostTest.TaskToken(new Object());r.transition();
            rejects("PROFILE_LEAF_TOKEN_CHANGED",()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.pauses==0&&r.pairReads==0&&token.equals(retained(p)),"replacement Binder was reclaimed");r.noEffects();
        });
        test("owned root cookie remains mandatory before a retry",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.f.missingRootCookie=true;r.transition();
            rejects("PROFILE_ROOT_IDENTITY_CHANGED",()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.pauses==0&&r.pairReads==0,"unowned root was sampled for retry");r.noEffects();
        });
        test("foreign global task appearing in the retry gap is rejected",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.onPause=x->x.f.foreign=true;
            rejects("PROFILE_FOREIGN_ROOT_ON_DISPLAY",()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.snapshots==2&&r.pauses==1,"foreign graph was polled");r.noEffects();
        });
        test("fresh public history is required after the complete replacement",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.onPause=x->x.history.fail=true;
            rejects("TEST_RECENTS_CHANGED",()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.snapshots==2&&r.pauses==1&&r.history.calls==1,"history check skipped");r.noEffects();
        });
        test("cancellation before the first read cannot retry",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.f.cancel=true;
            rejects("CANCELLED",()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.snapshots==0&&r.pauses==0,"cancelled first read proceeded");r.noEffects();
        });
        test("cancellation before pause cannot retry",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.onGuard=x->{if(x.guards==2)x.f.cancel=true;};
            rejects("CANCELLED",()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.snapshots==1&&r.pauses==0,"cancelled gap proceeded");r.noEffects();
        });
        test("cancellation during pause prevents replacement read",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.onPause=x->x.f.cancel=true;
            rejects("CANCELLED",()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.snapshots==1&&r.pauses==1,"cancelled replacement read proceeded");r.noEffects();
        });
        test("final guard remains required after replacement",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.onGuard=x->{if(x.guards==4)x.f.cancel=true;};
            rejects("CANCELLED",()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.snapshots==2&&r.pauses==1,"final cancellation skipped");r.noEffects();
        });
        for(final int at:new int[]{1,2,3,4})test("installation change at ready check "+at+" rejects",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();
            r.onRecheck=x->{if(x.rechecks==at)x.f.actual=ProfileBrokerHostTest.target(11,1010367);};
            rejects("PROFILE_INSTALLATION_IDENTITY_CHANGED",()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.pauses<=1&&r.snapshots<=2,"installation mismatch retried");r.noEffects();
        });
        test("expired original deadline prevents any graph read",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();
            rejects(DEADLINE,()->p.confirmInitializationReady(r.f.now));
            yes(r.snapshots==0&&r.pauses==0,"expired request read graph");r.noEffects();
        });
        test("exactly one pause worth of budget cannot be consumed",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();
            rejects(DEADLINE,()->p.confirmInitializationReady(r.f.now+20));
            yes(r.snapshots==1&&r.pauses==0,"deadline margin was reset");r.noEffects();
        });
        test("time spent reading the changed pair consumes original deadline",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.pairCost=980;
            long deadline=r.f.now+1000;rejects(DEADLINE,()->p.confirmInitializationReady(deadline));
            yes(r.snapshots==1&&r.pauses==0,"pair cost created a fresh deadline");r.noEffects();
        });
        test("deadline elapsed during pause prevents replacement graph",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.onPause=x->x.f.now+=1000;
            rejects(DEADLINE,()->p.confirmInitializationReady(2000));
            yes(r.snapshots==1&&r.pauses==1,"expired pause proceeded");r.noEffects();
        });
        test("final deadline is checked after a full replacement graph",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();r.readCost=500;
            rejects(DEADLINE,()->p.confirmInitializationReady(r.f.now+1000));
            yes(r.snapshots==2&&r.pauses==1,"replacement result escaped its deadline");r.noEffects();
        });
        for(final String operation:new String[]{"observe","window","permission-window"}){
            test("ordinary "+operation+" keeps its strict no-retry boundary",()->{
                Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.transition();
                ProfilePermissionTransient.ReadChanged signal=changed(()->{
                    if("observe".equals(operation))p.observe();
                    else if("window".equals(operation))p.window(22,300,r.f.now+1000);
                    else p.permissionForInitialization(22,300,r.f.now+1000);
                });
                yes(ROOT_CHANGED.equals(signal.code)&&r.pauses==0&&r.snapshots==1,"ordinary operation adopted ready retry");
                yes(r.returnedProofs==0,"mixed permission read returned authority");r.noEffects();
            });
        }
        List<String> names=new ArrayList<String>();for(String name:CASES)names.add("\""+name+"\"");
        System.out.println("{\"schema\":\"hepta.profile-ready-confirmation-host-tests.v1\",\"passed\":true,\"cases\":"+CASES.size()
                +",\"assertions\":"+assertions+",\"case_names\":["+String.join(",",names)+"],\"fixture_sha256\":\""+ProfileIdentity.sha(raw)
                +"\",\"real_ready_coordinator_executed\":true,\"real_pair_read_method_executed\":true,"
                +"\"framework_clock_and_history_port_synthetic\":true,\"phone_contacted\":false,\"android_build\":false}");
    }
}
