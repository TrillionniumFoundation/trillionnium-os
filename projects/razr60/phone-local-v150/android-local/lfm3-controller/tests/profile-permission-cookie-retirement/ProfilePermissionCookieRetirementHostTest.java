package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Real saved primitive rows; explicit synthetic Binder/cookie objects and after-leaf fixture.
 * The complete production coordinator and extracted platform pair method execute on the host. */
public final class ProfilePermissionCookieRetirementHostTest {
    private static int assertions;
    private static final List<String> CASES=new ArrayList<String>();
    private static final String HOME=ProfilePermissionTransientHostTest.HOME;
    private static final String PC=ProfilePermissionTransient.COMPONENT;
    private interface Work {void run()throws Exception;}
    private interface Hook {void run(Rig rig)throws Exception;}
    private static void yes(boolean value,String text){assertions++;if(!value)throw new AssertionError(text);}
    private static void test(String name,Work work)throws Exception{work.run();CASES.add(name);System.out.println("PASS "+name);}
    private static String refused(Work work)throws Exception{
        try{work.run();throw new AssertionError("unproved read accepted");}
        catch(ProfileTaskPolicy.Refusal error){assertions++;return error.code;}
    }
    private static void rejects(String code,Work work)throws Exception{yes(code.equals(refused(work)),"wrong refusal: "+code);}
    private static ProfilePermissionTransient.ReadChanged changed(Work work)throws Exception{
        try{work.run();throw new AssertionError("expected read-only retry signal");}
        catch(ProfilePermissionTransient.ReadChanged value){assertions++;return value;}
    }
    private static BackgroundOwnedSingleTask.Task presentation(BackgroundOwnedSingleTask.Task t,
            int topUid,int activities,String top,List<Object> cookies,boolean running,boolean visible){
        return new BackgroundOwnedSingleTask.Task(t.id,t.display,t.user,t.parent,t.uid,topUid,activities,
                t.token,cookies,t.intentComponent,t.base,top,t.real,t.orig,running,visible);
    }
    private static BackgroundOwnedSingleTask.Task after(BackgroundOwnedSingleTask.Task t,List<Object> cookies){
        return presentation(t,1010367,1,HOME,cookies,true,true);
    }
    private static BackgroundOwnedSingleTask.Task alter(BackgroundOwnedSingleTask.Task t,String field){
        List<Object> cookies=t.cookies;
        if("cookies".equals(field))cookies=Collections.singletonList(new Object());
        if("empty_cookies".equals(field))cookies=Collections.emptyList();
        return new BackgroundOwnedSingleTask.Task("id".equals(field)?t.id+1:t.id,
                "display".equals(field)?t.display+1:t.display,"user".equals(field)?t.user+1:t.user,
                "parent".equals(field)?t.parent+1:t.parent,"uid".equals(field)?t.uid+1:t.uid,
                "top_uid".equals(field)?10367:t.topUid,"activities".equals(field)?0:t.activities,
                "binder".equals(field)?new Object():t.token,cookies,
                "intent".equals(field)?"example.foreign/.Main":t.intentComponent,
                "base".equals(field)?"example.foreign/.Main":t.base,
                "top".equals(field)?"example.foreign/.Main":t.top,
                "real".equals(field)?"example.foreign/.Main":t.real,
                "orig".equals(field)?"example.foreign/.Main":t.orig,
                !"running".equals(field)&&t.running,!"visible".equals(field)&&t.visible);
    }
    private static final class Pair {
        final Object rootCookie=new Object(),launchCookie=new Object();
        final Object rootToken=new ProfileBrokerHostTest.TaskToken(new Object());
        final Object leafToken=new ProfileBrokerHostTest.TaskToken(new Object());
        final BackgroundOwnedSingleTask.Task root,leaf,currentRoot,currentLeaf,retainedRoot,retainedLeaf;
        Pair(){
            root=ObservedPermissionPairFixture.rootBefore(rootToken,Arrays.asList(rootCookie,launchCookie));
            leaf=ObservedPermissionPairFixture.leafBefore(leafToken,Collections.singletonList(launchCookie));
            currentRoot=ObservedPermissionPairFixture.rootAfter(rootToken,Collections.singletonList(rootCookie));
            // No same-read after-leaf was saved on the phone. This is deliberately synthetic.
            currentLeaf=after(leaf,Collections.emptyList());
            retainedRoot=presentation(root,-1,0,null,Collections.singletonList(rootCookie),false,false);
            retainedLeaf=after(leaf,Collections.singletonList(launchCookie));
        }
        PermissionPairReadHostAdapter adapter(BackgroundOwnedSingleTask.Task r,BackgroundOwnedSingleTask.Task l){
            return new PermissionPairReadHostAdapter(Collections.singletonList(r),Collections.singletonList(l));
        }
        ProfilePermissionTransient.ReadChanged signal()throws Exception{
            return changed(()->adapter(currentRoot,currentLeaf).read(root,leaf,"before_activity_dump"));
        }
        void owned(ProfilePermissionTransient.ReadChanged value)throws Exception{
            value.requireRetainedCookieRetirement(retainedRoot,retainedLeaf,rootCookie,launchCookie);
        }
    }
    private static final class Rig implements ProfileOwnedTask.Platform {
        final ProfileBrokerHostTest.Fake f=new ProfileBrokerHostTest.Fake();
        boolean permission,retired;int reads,pauses,pairReads;Hook onPause;
        Map<String,Object> mismatch=Collections.emptyMap();
        ProfileOwnedTask start(boolean retain)throws Exception{
            ProfileOwnedTask p=new ProfileOwnedTask(this,ProfilePermissionTransientHostTest.target(),
                    ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7);
            p.prepare();p.beforeDispatch();f.launch();p.accepted(0);
            if(retain)yes(p.observe(),"first ordinary leaf claim missing");
            reads=0;pauses=0;pairReads=0;return p;
        }
        void noEffects(){yes(f.mutations.equals(Arrays.asList("create","bind")),"read changed owned tasks");}
        @Override public ProfileTarget recheck(boolean ready){return f.recheck(ready);}
        @Override public void guard()throws Exception{f.guard();}
        @Override public long now(){return f.now();}
        @Override public Object newCookie(){return f.newCookie();}
        @Override public ProfileTaskPolicy.Snapshot snapshot()throws Exception{reads++;return f.snapshot();}
        @Override public ProfileTaskPolicy.Recents recents()throws Exception{return f.recents();}
        private BackgroundOwnedSingleTask.Task row(BackgroundOwnedSingleTask.Task t,boolean root){
            String base=ProfileBrokerHostTest.SPLASH.equals(t.base)?HOME:t.base;
            String top=ProfileBrokerHostTest.HOME.equals(t.top)?HOME:t.top;
            List<Object> cookies=new ArrayList<Object>(t.cookies);
            if(permission&&f.app&&root&&!retired)cookies.add(f.launchCookie);
            return new BackgroundOwnedSingleTask.Task(t.id,t.display,t.user,t.parent,t.uid,
                    permission&&f.app?1010335:t.topUid,permission&&f.app?2:t.activities,t.token,cookies,
                    t.intentComponent,base,permission&&f.app?PC:top,t.real,t.orig,t.running,t.visible);
        }
        @Override public List<BackgroundOwnedSingleTask.Task> roots(){
            List<BackgroundOwnedSingleTask.Task> out=new ArrayList<BackgroundOwnedSingleTask.Task>();
            for(BackgroundOwnedSingleTask.Task t:f.roots())out.add(row(t,true));return out;
        }
        @Override public List<BackgroundOwnedSingleTask.Task> children(Object token){
            List<BackgroundOwnedSingleTask.Task> out=new ArrayList<BackgroundOwnedSingleTask.Task>();
            for(BackgroundOwnedSingleTask.Task t:f.children(token))out.add(row(t,false));return out;
        }
        @Override public void createRoot(Object cookie){f.createRoot(cookie);}
        @Override public void bindRoot(Object token,Object cookie){f.bindRoot(token,cookie);}
        @Override public void removeLeaf(Object token)throws Exception{f.removeLeaf(token);}
        @Override public boolean deleteRoot(Object token)throws Exception{return f.deleteRoot(token);}
        @Override public void pause()throws Exception{pauses++;f.pause();if(onPause!=null)onPause.run(this);}
        @Override public Map<String,Object> permissionReadMismatchEvidence(){return mismatch;}
        @Override public ProfilePermissionTransient.Proof permissionTransient(BackgroundOwnedSingleTask.Task root,
                BackgroundOwnedSingleTask.Task leaf)throws Exception{
            pairReads++;permission=false;retired=true;f.wrongCookie=true;
            PermissionPairReadHostAdapter pair=new PermissionPairReadHostAdapter(roots(),children(root.token));
            try{pair.read(root,leaf,"before_activity_dump");}
            finally{if(mismatch.isEmpty())mismatch=pair.permissionReadMismatchEvidence();}
            throw new AssertionError("unstable pair was returned as a permission proof");
        }
    }
    private static String retained(ProfileOwnedTask p){return (String)p.evidence().get("leaf_token_id");}
    private static void ordinary(ProfileOwnedTask p){
        Map<String,Object> last=p.lastLeafValidation();
        yes(Boolean.TRUE.equals(last.get("valid"))&&"retained_leaf".equals(last.get("phase")),"new ordinary retained proof missing");
        yes(Boolean.FALSE.equals(last.get("launch_cookie_present")),"test accidentally preserved launch cookie");
        yes(Boolean.TRUE.equals(last.get("actual_task_token_equal_to_retained")),"retained Binder changed");
        yes(!last.containsKey("permission_transient_verified"),"read signal became permission proof");
        Map<?,?> checks=(Map<?,?>)last.get("checks");
        yes(Boolean.TRUE.equals(checks.get("top_activity_info_uid_matches"))&&Boolean.TRUE.equals(checks.get("top_package_matches")),
                "ordinary target UID/package was not re-proved");
    }
    private static void corrupt(Rig r,String field){
        switch(field){
            case "root_binder":r.f.rootToken=new Object();break;
            case "leaf_binder":r.f.leafToken=new Object();break;
            case "leaf_id":r.f.leafId=301;break;
            case "user":r.f.wrongUser=true;break;
            case "parent":r.f.wrongParent=true;break;
            case "display":r.f.wrongDisplay=true;break;
            case "uid":r.f.wrongUid=true;break;
            case "top_uid":r.f.wrongTopUid=true;break;
            case "top":r.f.foreignTop=true;break;
            case "base":r.f.wrongBase=true;break;
            case "intent":r.f.wrongIntent=true;break;
            case "real":r.f.wrongReal=true;break;
            case "orig":r.f.wrongOrig=true;break;
            case "root_cookie":r.f.missingRootCookie=true;break;
            case "extra_child":r.f.extraChild=true;break;
            case "missing_global":r.f.globalMissingLeaf=true;break;
            case "foreign_global":r.f.foreign=true;break;
            default:throw new AssertionError(field);
        }
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("exact saved primitive fixture required");
        byte[] raw=Files.readAllBytes(Paths.get(args[0]));
        yes(ObservedPermissionPairFixture.SHA.equals(ProfileIdentity.sha(raw)),"saved primitive fixture pin differs");
        test("saved root transition keeps strict equality false and requires a fresh after-leaf read",()->{
            Pair p=new Pair();
            yes(!ProfilePermissionTransient.sameReadIdentity(p.root,p.currentRoot),"full cookie identity relaxed");
            yes(!ProfilePermissionTransient.sameTaskInfo(p.root,p.currentRoot),"complete TaskInfo relaxed");
            PermissionPairReadHostAdapter a=p.adapter(p.currentRoot,p.currentLeaf);
            ProfilePermissionTransient.ReadChanged signal=changed(()->a.read(p.root,p.leaf,"before_activity_dump"));
            yes(a.organizer.childrenCalls==1,"root cookie transition skipped actual leaf read");p.owned(signal);
            Map<String,Object> d=a.permissionReadMismatchEvidence();
            yes(Integer.valueOf(1).equals(d.get("leaf_count")),"new current leaf not diagnosed");
            yes(Boolean.FALSE.equals(((Map<?,?>)d.get("root")).get("complete_identity_equal")),"diagnostic comparison forged");
            yes(Boolean.FALSE.equals(d.get("allows_input_or_model_resumption")),"diagnostic created authority");
        });
        test("retained pair resamples the whole graph after its launch cookie retires",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);String token=retained(p);r.permission=true;
            yes("APP_READY".equals(p.initializationState(r.f.now+1000)),"same owned pair did not settle");
            yes(r.pairReads==1&&r.pauses==1&&r.reads==2,"no fresh full graph or unexpected retries");
            yes(token.equals(retained(p)),"leaf capability was re-claimed");ordinary(p);r.noEffects();
            WindowOwnership window=p.window(22,300,r.f.now+1000);
            yes(token.equals(window.taskTokenId)&&window.fullUid==1010367,"fresh normal window not independently proved");
            yes(r.reads==3,"window reused unstable sample");r.noEffects();
        });
        test("unclaimed leaf cannot gain the retained cookie-retirement exception",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(false);r.permission=true;
            rejects("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->p.initializationState(r.f.now+1000));
            yes(r.pairReads==1&&r.pauses==0&&retained(p)==null,"unclaimed leaf retried or was retained");r.noEffects();
        });
        test("private retained Binder and both original cookie anchors are required",()->{
            Pair p=new Pair();ProfilePermissionTransient.ReadChanged s=p.signal();
            rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->s.requireRetainedCookieRetirement(null,p.retainedLeaf,p.rootCookie,p.launchCookie));
            rejects("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->s.requireRetainedCookieRetirement(p.retainedRoot,null,p.rootCookie,p.launchCookie));
            for(String field:new String[]{"id","display","user","parent","uid","binder"}){
                rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->s.requireRetainedCookieRetirement(alter(p.retainedRoot,field),p.retainedLeaf,p.rootCookie,p.launchCookie));
                rejects("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->s.requireRetainedCookieRetirement(p.retainedRoot,alter(p.retainedLeaf,field),p.rootCookie,p.launchCookie));
            }
            rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->s.requireRetainedCookieRetirement(p.retainedRoot,p.retainedLeaf,new Object(),p.launchCookie));
            rejects("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->s.requireRetainedCookieRetirement(p.retainedRoot,p.retainedLeaf,p.rootCookie,new Object()));
            rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->s.requireRetainedCookieRetirement(p.retainedRoot,p.retainedLeaf,p.rootCookie,p.rootCookie));
            BackgroundOwnedSingleTask.Task rootAfter=after(p.root,Collections.singletonList(p.launchCookie));
            BackgroundOwnedSingleTask.Task leafBefore=presentation(p.leaf,1010335,2,PC,Collections.singletonList(p.rootCookie),true,true);
            ProfilePermissionTransient.ReadChanged wrong=changed(()->p.adapter(rootAfter,p.currentLeaf).read(p.root,leafBefore,"before_activity_dump"));
            rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->p.owned(wrong));
        });
        test("root or leaf immutable identity and unknown presentation changes still refuse",()->{
            Pair p=new Pair();
            for(String field:new String[]{"id","display","user","parent","uid","binder","intent","base","real","orig",
                    "top_uid","activities","top","running","visible","cookies","empty_cookies"}){
                PermissionPairReadHostAdapter a=p.adapter(alter(p.currentRoot,field),p.currentLeaf);
                rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->a.read(p.root,p.leaf,"before_activity_dump"));
                yes(a.organizer.childrenCalls==0,"changed root queried leaf: "+field);
            }
            for(String field:new String[]{"id","display","user","parent","uid","binder","intent","base","real","orig",
                    "top_uid","activities","top","running","visible","cookies"}){
                PermissionPairReadHostAdapter a=p.adapter(p.currentRoot,alter(p.currentLeaf,field));
                rejects("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->a.read(p.root,p.leaf,"before_activity_dump"));
            }
        });
        test("unpaired different duplicate or reordered cookie changes cannot request retry",()->{
            Pair p=new Pair();Object other=new Object();
            BackgroundOwnedSingleTask.Task stillCookie=after(p.leaf,p.leaf.cookies);
            rejects("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->p.adapter(p.currentRoot,stillCookie).read(p.root,p.leaf,"before_activity_dump"));
            BackgroundOwnedSingleTask.Task otherLeaf=presentation(p.leaf,1010335,2,PC,Collections.singletonList(other),true,true);
            rejects("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->p.adapter(p.currentRoot,p.currentLeaf).read(p.root,otherLeaf,"before_activity_dump"));
            BackgroundOwnedSingleTask.Task duplicate=presentation(p.root,1010335,2,PC,Arrays.asList(p.rootCookie,p.launchCookie,p.launchCookie),true,true);
            rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->p.adapter(p.currentRoot,p.currentLeaf).read(duplicate,p.leaf,"before_activity_dump"));
            BackgroundOwnedSingleTask.Task more=presentation(p.root,1010335,2,PC,Arrays.asList(p.rootCookie,other,p.launchCookie),true,true);
            BackgroundOwnedSingleTask.Task reordered=after(p.root,Arrays.asList(other,p.rootCookie));
            rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->p.adapter(reordered,p.currentLeaf).read(more,p.leaf,"before_activity_dump"));
            BackgroundOwnedSingleTask.Task newCookie=after(p.root,Arrays.asList(p.rootCookie,other));
            rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->p.adapter(newCookie,p.currentLeaf).read(p.root,p.leaf,"before_activity_dump"));
            rejects("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->p.adapter(p.currentRoot,null).read(p.root,p.leaf,"before_activity_dump"));
        });
        test("retry pins the complete after-cookie sets and never accepts the earlier unstable pair",()->{
            Pair p=new Pair();ProfilePermissionTransient.ReadChanged s=p.signal();p.owned(s);
            s.requireRoot(p.currentRoot);s.requireLeaf(p.currentLeaf);
            rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->s.requireRoot(p.root));
            rejects("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->s.requireLeaf(p.leaf));
            for(String field:new String[]{"id","display","user","parent","uid","binder","intent","base","real","orig","cookies"}){
                rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->s.requireRoot(alter(p.currentRoot,field)));
                rejects("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->s.requireLeaf(alter(p.currentLeaf,field)));
            }
            BackgroundOwnedSingleTask.Task hidden=presentation(p.currentRoot,1010367,1,HOME,p.currentRoot.cookies,true,false);
            ProfilePermissionTransient.ReadChanged next=changed(()->p.adapter(hidden,p.currentLeaf).read(p.currentRoot,p.currentLeaf,"after_activity_dump"));
            s.requireAttempt(next);
            rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->s.requireAttempt(p.signal()));
        });
        test("fresh complete retry reruns task scope global membership and component guards",()->{
            for(String field:new String[]{"root_binder","leaf_binder","leaf_id","user","parent","display","uid","top_uid",
                    "top","base","intent","real","orig","root_cookie","extra_child","missing_global","foreign_global"}){
                Rig r=new Rig();ProfileOwnedTask p=r.start(true);String token=retained(p);r.permission=true;
                r.onPause=x->corrupt(x,field);
                refused(()->p.observeStateUntil(r.f.now+1000));
                yes(r.pairReads==1&&r.pauses==1&&token.equals(retained(p)),"changed pair was reclaimed: "+field);r.noEffects();
            }
        });
        test("original deadline cancellation and three-sample ceiling remain effective",()->{
            Rig shortBudget=new Rig();ProfileOwnedTask p=shortBudget.start(true);shortBudget.permission=true;
            rejects("PROFILE_PERMISSION_READ_DEADLINE",()->p.initializationState(shortBudget.f.now+20));
            yes(shortBudget.pauses==0&&shortBudget.reads==1,"insufficient budget began another read");shortBudget.noEffects();
            Rig cancelled=new Rig();ProfileOwnedTask c=cancelled.start(true);cancelled.permission=true;
            cancelled.onPause=x->x.f.cancel=true;
            rejects("CANCELLED",()->c.observeStateUntil(cancelled.f.now+1000));
            yes(cancelled.reads==1&&cancelled.pauses==1,"cancelled retry continued");cancelled.noEffects();
            Rig late=new Rig();ProfileOwnedTask l=late.start(true);late.permission=true;late.onPause=x->x.f.now+=1000;
            rejects("PROFILE_STATE_READ_DEADLINE",()->l.observeStateUntil(late.f.now+500));
            yes(late.reads==1&&late.pauses==1,"late retry renewed budget");late.noEffects();
            Rig endless=new Rig();ProfileOwnedTask e=endless.start(true);endless.permission=true;endless.onPause=x->x.permission=true;
            rejects("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ",()->e.initializationState(endless.f.now+1000));
            yes(endless.pairReads==3&&endless.reads==3&&endless.pauses==2,"three-read limit changed");endless.noEffects();
        });
        test("ordinary observe window permission input and cleanup never acquire cookie retry",()->{
            for(int api=0;api<4;api++){
                Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.permission=true;final int choice=api;
                changed(()->{if(choice==0)p.observe();else if(choice==1)p.window(14,300,r.f.now+1000);
                    else if(choice==2)p.permissionForInitialization(14,300,r.f.now+1000);else p.retire(r.f.now+1000);});
                yes(r.pauses==0&&r.pairReads==1,"non-state API retried");
                if(choice==3)yes(!p.cleanupKnown(),"unstable cleanup was marked known");r.noEffects();
            }
        });
        List<String> names=new ArrayList<String>();for(String name:CASES)names.add("\""+name+"\"");
        System.out.println("{\"schema\":\"hepta.profile-permission-cookie-retirement-host.v1\",\"passed\":true,"
                +"\"cases\":"+CASES.size()+",\"assertions\":"+assertions+",\"case_names\":["+String.join(",",names)+"],"
                +"\"fixture_sha256\":\""+ProfileIdentity.sha(raw)+"\",\"real_coordinator_executed\":true,"
                +"\"real_platform_pair_executed\":true,\"after_leaf_synthetic\":true,\"binders_and_cookies_synthetic\":true,"
                +"\"phone_contacted\":false,\"business_success_claimed\":false,\"android_build\":false}");
    }
}
