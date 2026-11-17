package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Executes the production state coordinator. Only framework data and time are synthetic. */
public final class ProfileStateSettleHostTest {
    private static int assertions;
    private static final List<String> CASES=new ArrayList<String>();
    private static String fixture;
    private interface Work {void run()throws Exception;}
    private interface Hook {void run(Rig rig)throws Exception;}
    private static void yes(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(String name,Work work)throws Exception{work.run();CASES.add(name);System.out.println("PASS "+name);}
    private static String refused(Work work)throws Exception{
        try{work.run();throw new AssertionError("unproved state accepted");}
        catch(ProfileTaskPolicy.Refusal error){assertions++;return error.code;}
    }
    private static void rejects(String code,Work work)throws Exception{yes(code.equals(refused(work)),"wrong refusal for "+code);}
    private static String swap(String raw,String before,String after){
        yes(raw.contains(before),"authored fixture replacement missing");return raw.replace(before,after);
    }
    private static BackgroundOwnedSingleTask.Task hidden(BackgroundOwnedSingleTask.Task t){
        return new BackgroundOwnedSingleTask.Task(t.id,t.display,t.user,t.parent,t.uid,t.topUid,t.activities,
                t.token,t.cookies,t.intentComponent,t.base,t.top,t.real,t.orig,t.running,false);
    }
    private static final class Rig implements ProfileOwnedTask.Platform {
        final ProfilePermissionTransientHostTest.Adapter a;
        final ProfileBrokerHostTest.Fake f;
        int guards,reads,rechecks,pauses;long readCost,proofCost,recheckCost;
        boolean hiddenApp,forgedSetup;Hook onPause,onGuard;
        Rig(){this(fixture);}
        Rig(String raw){a=new ProfilePermissionTransientHostTest.Adapter(raw);f=a.f;}
        ProfileOwnedTask start(boolean observe)throws Exception{
            ProfileOwnedTask task=new ProfileOwnedTask(this,ProfilePermissionTransientHostTest.target(),
                    ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7);
            task.prepare();task.beforeDispatch();f.launch();task.accepted(0);
            if(observe)yes(task.observe(),"initial ordinary target missing");
            guards=0;reads=0;rechecks=0;pauses=0;return task;
        }
        void noEffects(){yes(f.mutations.equals(Arrays.asList("create","bind")),"state coordination mutated task/display");}
        @Override public ProfileTarget recheck(boolean ready){rechecks++;f.now+=recheckCost;return a.recheck(ready);}
        @Override public void guard()throws Exception{guards++;if(onGuard!=null)onGuard.run(this);a.guard();}
        @Override public long now(){return a.now();}
        @Override public Object newCookie(){return a.newCookie();}
        @Override public ProfileTaskPolicy.Snapshot snapshot()throws Exception{
            reads++;ProfileTaskPolicy.Snapshot value=a.snapshot();f.now+=readCost;return value;
        }
        @Override public ProfileTaskPolicy.Recents recents()throws Exception{return a.recents();}
        @Override public List<BackgroundOwnedSingleTask.Task> roots(){return a.roots();}
        @Override public List<BackgroundOwnedSingleTask.Task> children(Object token){
            List<BackgroundOwnedSingleTask.Task> value=a.children(token);
            if(hiddenApp&&!a.permission&&value.size()==1)return Collections.singletonList(hidden(value.get(0)));
            return value;
        }
        @Override public void createRoot(Object cookie){a.createRoot(cookie);}
        @Override public void bindRoot(Object token,Object cookie){a.bindRoot(token,cookie);}
        @Override public void removeLeaf(Object token)throws Exception{a.removeLeaf(token);}
        @Override public boolean deleteRoot(Object token)throws Exception{return a.deleteRoot(token);}
        @Override public void pause()throws Exception{pauses++;a.pause();if(onPause!=null)onPause.run(this);}
        @Override public ProfilePermissionTransient.Proof permissionTransient(BackgroundOwnedSingleTask.Task root,
                BackgroundOwnedSingleTask.Task leaf)throws Exception{
            if(forgedSetup)throw new ProfileTaskPolicy.Refusal("PROFILE_PERMISSION_SETUP_REQUIRED");
            ProfilePermissionTransient.Proof proof=a.permissionTransient(root,leaf);f.now+=proofCost;return proof;
        }
    }
    private static String retained(ProfileOwnedTask task){return (String)task.evidence().get("leaf_token_id");}
    private static void ordinaryValidation(ProfileOwnedTask task){
        Map<String,Object> last=task.lastLeafValidation();
        yes(Boolean.TRUE.equals(last.get("valid")),"ordinary validation absent");
        yes(!last.containsKey("permission_transient_verified")&&!last.containsKey("retirement_only"),"permission proof became ordinary success");
        yes(Boolean.TRUE.equals(((Map<?,?>)last.get("checks")).get("top_package_matches")),"ordinary target top was not re-proved");
        yes(Boolean.TRUE.equals(((Map<?,?>)last.get("checks")).get("top_activity_info_uid_matches")),"ordinary target UID was not re-proved");
    }
    private static void corrupt(Rig r,String kind){
        switch(kind){
            case "root_binder":r.f.rootToken=new Object();break;
            case "leaf_binder":r.f.leafToken=new ProfileBrokerHostTest.TaskToken(new Object());break;
            case "leaf_id":r.f.leafId=301;break;
            case "user":r.f.wrongUser=true;break;
            case "parent":r.f.wrongParent=true;break;
            case "display":r.f.wrongDisplay=true;break;
            case "full_uid":r.f.wrongUid=true;break;
            case "top_uid":r.f.wrongTopUid=true;break;
            case "top_package":r.f.foreignTop=true;break;
            case "base":r.f.wrongBase=true;break;
            case "intent":r.f.wrongIntent=true;break;
            case "real":r.f.wrongReal=true;break;
            case "orig":r.f.wrongOrig=true;break;
            case "root_cookie":r.f.missingRootCookie=true;break;
            case "extra_child":r.f.extraChild=true;break;
            case "missing_global_leaf":r.f.globalMissingLeaf=true;break;
            case "foreign_global":r.f.foreign=true;break;
            default:throw new AssertionError("unknown fixture corruption");
        }
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("exact synthetic fixture required");
        byte[] raw=Files.readAllBytes(Paths.get(args[0]));fixture=new String(raw,StandardCharsets.UTF_8);
        ProfilePermissionTransientHostTest.fixtureShape(fixture);
        test("ordinary state returns without permission wait",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);long before=r.f.now;
            yes(p.observeStateUntil(before+1700),"ordinary state rejected");
            yes(r.pauses==0&&r.a.proofs==0&&r.reads==1&&r.f.now==before,"ordinary state unexpectedly waited");
            ordinaryValidation(p);r.noEffects();
        });
        test("verified PC returns to a fresh ordinary proof on the same Binder",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);String token=retained(p);r.a.permission=true;
            r.onPause=x->x.a.permission=false;
            yes(p.observeStateUntil(r.f.now+1700),"PC to App did not settle");
            yes(r.pauses==1&&r.a.proofs==1&&r.reads==2,"fresh ordinary read was skipped");
            yes(token.equals(retained(p)),"retained Binder was replaced");ordinaryValidation(p);r.noEffects();
        });
        test("retained Binder survives cookie loss between complete reads",()->{
            Rig r=new Rig();Object binder=new Object();r.f.leafToken=new ProfileBrokerHostTest.TaskToken(binder);
            ProfileOwnedTask p=r.start(true);String token=retained(p);r.a.permission=true;
            r.onPause=x->{x.a.permission=false;x.f.wrongCookie=true;x.f.leafToken=new ProfileBrokerHostTest.TaskToken(binder);};
            yes(p.observeStateUntil(r.f.now+1700),"durable Binder with expired Activity cookie rejected");
            yes(token.equals(retained(p)),"cookie loss re-claimed leaf");ordinaryValidation(p);r.noEffects();
        });
        test("first PC claim requires a cookie before any ordinary continuation",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(false);r.a.permission=true;
            final String[] token={null};r.onPause=x->{token[0]=retained(p);x.a.permission=false;x.f.wrongCookie=true;};
            yes(p.observeStateUntil(r.f.now+1700),"fresh cookie-bound PC could not return to App");
            yes(token[0]!=null&&token[0].equals(retained(p)),"first positive claim was not retained");
            ordinaryValidation(p);r.noEffects();
            Rig missing=new Rig();ProfileOwnedTask unclaimed=missing.start(false);missing.a.permission=true;missing.f.wrongCookie=true;
            rejects("PROFILE_NEW_LEAF_NOT_PROVEN",()->unclaimed.observeStateUntil(missing.f.now+1700));
            yes(missing.pauses==0&&retained(unclaimed)==null,"unproved first leaf waited or was claimed");missing.noEffects();
        });
        test("persistent PC exhausts the same 1800 ms request without renewal",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.a.permission=true;long begin=r.f.now,wireDeadline=begin+1800;
            rejects("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observeStateUntil(wireDeadline-100));
            yes(r.f.now<wireDeadline-100&&wireDeadline-100-r.f.now<=20,"original state deadline was extended");
            yes(r.pauses>0&&r.pauses<=85&&r.a.proofs==r.pauses+1,"pending PC did not use bounded complete reads");
            yes(Boolean.FALSE.equals(p.lastLeafValidation().get("business_observation_allowed")),"persistent PC became business authority");r.noEffects();
        });
        test("partly consumed request uses only its original remaining budget",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);long wireDeadline=r.f.now+1800;r.f.now+=1600;r.a.permission=true;
            long begin=r.f.now;rejects("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observeStateUntil(wireDeadline-100));
            yes(r.f.now-begin<=100&&r.pauses<=4,"state reset a partially consumed request");r.noEffects();
        });
        test("expired and sub-pause budgets cannot start another sample",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);int before=r.reads;
            rejects("PROFILE_STATE_READ_DEADLINE",()->p.observeStateUntil(r.f.now));
            yes(r.reads==before&&r.pauses==0,"expired state read began work");r.a.permission=true;
            rejects("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observeStateUntil(r.f.now+20));
            yes(r.pauses==0&&r.a.proofs==1,"pause began without room");r.noEffects();
        });
        test("ordinary success after a stalled read is rejected as late",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.readCost=1800;long end=r.f.now+1700;
            rejects("PROFILE_STATE_READ_DEADLINE",()->p.observeStateUntil(end));
            yes(r.reads==1&&r.pauses==0&&r.f.now>end,"late ordinary fixture did not cross deadline");r.noEffects();
        });
        test("installation read consuming the deadline does not begin a graph",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.recheckCost=1800;long end=r.f.now+1700;
            rejects("PROFILE_STATE_READ_DEADLINE",()->p.observeStateUntil(end));
            yes(r.reads==0&&r.pauses==0,"post-deadline graph was requested");r.noEffects();
        });
        test("full PC proof consuming the remaining budget cannot renew it",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.a.permission=true;r.proofCost=1000;long end=r.f.now+800;
            rejects("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observeStateUntil(end));
            yes(r.pauses==0&&r.a.proofs==1&&r.f.now>end,"proof cost reset original deadline");r.noEffects();
        });
        test("pause overshoot cannot accept an otherwise normal next top",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.a.permission=true;
            r.onPause=x->{x.a.permission=false;x.f.now+=1800;};long end=r.f.now+1700;
            rejects("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observeStateUntil(end));
            yes(r.reads==1&&r.pauses==1,"late pause caused another ordinary read");r.noEffects();
        });
        test("generic setup-required text cannot manufacture the private marker",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(false);r.a.permission=true;r.forgedSetup=true;
            rejects("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observeStateUntil(r.f.now+1700));
            yes(r.pauses==0&&r.a.proofs==0&&retained(p)==null,"matching exception text became verified pending");r.noEffects();
        });
        test("unavailable stale and invalid static PC proofs never wait",()->{
            List<String> bad=Arrays.asList(
                swap(fixture,"launchedFromUid=1010367","launchedFromUid=10367"),
                swap(fixture,"resultTo=ActivityRecord{target_record","resultTo=ActivityRecord{missing_record"),
                swap(fixture,"dataDir=/data/user_de/10/","dataDir=/data/user_de/0/"),
                swap(fixture,"taskAffinity=1010335:","taskAffinity=10335:"),
                swap(fixture,"act=android.content.pm.action.REQUEST_PERMISSIONS","act=android.intent.action.MAIN"),
                swap(fixture,"state=RESUMED delayedResume=false finishing=false","state=INITIALIZING delayedResume=false finishing=false"),
                swap(fixture,"app=ProcessRecord{permission_process 2000:com.android.permissioncontroller/u10a335}","app=null"));
            for(String dump:bad){Rig r=new Rig(dump);ProfileOwnedTask p=r.start(false);r.a.permission=true;
                yes(!"PROFILE_PERMISSION_SETUP_REQUIRED".equals(refused(()->p.observeStateUntil(r.f.now+1700))),"invalid PC entered pending branch");
                yes(r.pauses==0&&retained(p)==null,"invalid PC acquired a retained leaf");r.noEffects();}
            for(boolean stale:new boolean[]{false,true}){Rig r=new Rig();ProfileOwnedTask p=r.start(false);r.a.permission=true;r.a.stale=stale;r.a.unavailable=!stale;
                refused(()->p.observeStateUntil(r.f.now+1700));yes(r.pauses==0&&retained(p)==null,"missing/stale proof waited");r.noEffects();}
        });
        test("identity gates rerun while PC persists and after App returns",()->{
            String[] failures={"root_binder","leaf_binder","leaf_id","user","parent","display","full_uid","top_uid",
                "top_package","base","intent","real","orig","root_cookie","extra_child","missing_global_leaf","foreign_global"};
            for(boolean pcPersists:new boolean[]{false,true})for(String failure:failures){
                // These two switches concern the ordinary App top; the PC adapter
                // has its own exact system top UID/component and full-chain proof.
                if(pcPersists&&("top_uid".equals(failure)||"top_package".equals(failure)))continue;
                Rig r=new Rig();r.f.leafToken=new ProfileBrokerHostTest.TaskToken(new Object());
                ProfileOwnedTask p=r.start(true);String token=retained(p);r.a.permission=true;
                r.onPause=x->{x.a.permission=pcPersists;corrupt(x,failure);};
                refused(()->p.observeStateUntil(r.f.now+1700));
                yes(r.pauses==1&&token.equals(retained(p)),"changed identity was re-claimed: "+failure);r.noEffects();}
        });
        test("profile serial full UID and installed APK changes abort settle",()->{
            ProfileTarget[] changed={ProfileBrokerHostTest.target(11,1010367),ProfileBrokerHostTest.target(10,1010368),
                new ProfileTarget(new ProfileIdentity(10,10,0,"android.os.usertype.profile.MANAGED"),1010367,ProfileTarget.CTRIP,
                    ProfileBrokerHostTest.SPLASH,1779,Collections.singletonMap("base",ProfileBrokerHostTest.repeat('c')),
                    Collections.singleton(ProfileBrokerHostTest.repeat('b')))};
            for(ProfileTarget target:changed){Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.a.permission=true;
                r.onPause=x->{x.a.permission=false;x.f.actual=target;};
                rejects("PROFILE_INSTALLATION_IDENTITY_CHANGED",()->p.observeStateUntil(r.f.now+1700));
                yes(r.reads==1&&r.pauses==1,"changed installation reached a second tree read");r.noEffects();}
        });
        test("cancellation before pause during pause and after ordinary read aborts",()->{
            Rig before=new Rig();ProfileOwnedTask p=before.start(true);before.a.permission=true;
            before.onGuard=x->{if(x.guards==2)x.f.cancel=true;};
            rejects("CANCELLED",()->p.observeStateUntil(before.f.now+1700));yes(before.pauses==0,"cancelled PC paused");before.noEffects();
            Rig during=new Rig();ProfileOwnedTask q=during.start(true);during.a.permission=true;during.onPause=x->x.f.cancel=true;
            rejects("CANCELLED",()->q.observeStateUntil(during.f.now+1700));yes(during.reads==1&&during.pauses==1,"cancelled pause began another read");during.noEffects();
            Rig late=new Rig();ProfileOwnedTask z=late.start(true);late.onGuard=x->{if(x.guards==2)x.f.cancel=true;};
            rejects("CANCELLED",()->z.observeStateUntil(late.f.now+1700));yes(late.reads==1&&late.pauses==0,"late cancellation fixture invalid");late.noEffects();
        });
        test("ordinary non-visible result keeps the original false outcome",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.hiddenApp=true;
            yes(!p.observeStateUntil(r.f.now+1700)&&r.pauses==0,"ordinary null was broadened into wait/success");r.noEffects();
        });
        test("PC to non-visible ordinary result immediately returns false",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.a.permission=true;
            r.onPause=x->{x.a.permission=false;x.hiddenApp=true;};
            yes(!p.observeStateUntil(r.f.now+1700),"non-visible App became ready");
            yes(r.pauses==1&&r.reads==2,"ordinary null did not preserve immediate refusal boundary");r.noEffects();
        });
        test("owned leaf disappearance never turns into readiness polling",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.a.permission=true;
            r.onPause=x->{x.a.permission=false;x.f.app=false;};
            rejects("PROFILE_OWNED_LEAF_DISAPPEARED",()->p.observeStateUntil(r.f.now+1700));
            yes(r.pauses==1,"missing leaf was retried");r.noEffects();
        });
        test("ordinary observe and PC window retain their strict refusal",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.a.permission=true;String token=retained(p);
            rejects("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observe());
            rejects("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.window(14,300,r.f.now+1700));
            yes(r.pauses==0&&token.equals(retained(p)),"ordinary/window API used state settle");
            r.onPause=x->x.a.permission=false;yes(p.observeStateUntil(r.f.now+1700),"read-only state did not settle");
            WindowOwnership fresh=p.window(22,300,r.f.now+1000);
            yes(fresh.windowId==22&&fresh.fullUid==1010367&&fresh.taskTokenId.equals(token),"new ordinary window proof differs");r.noEffects();
        });
        test("timeout then cancelled retirement keeps the exact single cleanup chain",()->{
            Rig r=new Rig();ProfileOwnedTask p=r.start(true);r.a.permission=true;
            rejects("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observeStateUntil(r.f.now+60));r.noEffects();r.f.cancel=true;
            p.retire(r.f.now+1500);yes(p.cleanupKnown(),"read-only wait damaged independent retirement");
            List<String> one=Arrays.asList("create","bind","remove_leaf","delete_root");yes(r.f.mutations.equals(one),"retirement effect count changed");
            rejects("PROFILE_TASK_NOT_ACTIVE",()->p.observeStateUntil(r.f.now+1700));
            rejects("PROFILE_RETIRE_ALREADY_ATTEMPTED",()->p.retire(r.f.now+1500));yes(r.f.mutations.equals(one),"retired state replayed cleanup");
        });
        List<String> names=new ArrayList<String>();for(String name:CASES)names.add("\""+name+"\"");
        System.out.println("{\"schema\":\"hepta.profile-state-settle-host-tests.v1\",\"passed\":true,\"cases\":"+CASES.size()
                +",\"assertions\":"+assertions+",\"case_names\":["+String.join(",",names)+"],\"fixture_sha256\":\""+ProfileIdentity.sha(raw)
                +"\",\"real_coordinator_executed\":true,\"framework_and_clock_synthetic\":true,\"phone_contacted\":false,\"android_build\":false}");
    }
}
