package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/** Synthetic TaskInfo/binder/time adapters; real classifier, coordinator and pair-bracket method. */
public final class ProfilePermissionReadRetryHostTest {
    static final String PC=ProfilePermissionTransient.COMPONENT;
    static final String HOME=ProfilePermissionTransientHostTest.HOME;
    static final String ROOT_CHANGED="PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ";
    static int cases,checks;
    interface Work {void run()throws Exception;}
    static void yes(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    static void test(String name,Work work)throws Exception{work.run();cases++;System.out.println("PASS "+name);}
    static ProfileTaskPolicy.Refusal refusal(String code,Work work)throws Exception{
        try{work.run();throw new AssertionError("accepted "+code);}
        catch(ProfileTaskPolicy.Refusal result){yes(code.equals(result.code),"wrong refusal "+result.code+" expected "+code);return result;}
    }
    static ProfileTarget target(){return ProfilePermissionTransientHostTest.target();}
    static ProfilePermissionTransient.Authority authority()throws Exception{return ProfilePermissionTransientHostTest.authority();}
    static BackgroundOwnedSingleTask.Task presentation(BackgroundOwnedSingleTask.Task t,String top,int topUid,int activities){
        return new BackgroundOwnedSingleTask.Task(t.id,t.display,t.user,t.parent,t.uid,topUid,activities,
                t.token,t.cookies,t.intentComponent,t.base,top,t.real,t.orig,true,true);
    }
    static BackgroundOwnedSingleTask.Task alter(BackgroundOwnedSingleTask.Task t,String field){
        return new BackgroundOwnedSingleTask.Task(
                "id".equals(field)?t.id+1:t.id,"display".equals(field)?t.display+1:t.display,
                "user".equals(field)?t.user+1:t.user,"parent".equals(field)?t.parent+1:t.parent,
                "uid".equals(field)?t.uid+1:t.uid,"topUid".equals(field)?t.topUid+1:t.topUid,
                "activities0".equals(field)?0:"activities33".equals(field)?33:t.activities,
                "token".equals(field)?new Object():t.token,
                "cookies".equals(field)?Collections.singletonList(new Object()):t.cookies,
                "intent".equals(field)?HOME+"Changed":t.intentComponent,
                "base".equals(field)?HOME+"Changed":t.base,
                "foreign".equals(field)?"com.motorola.deviceguard/.permission.activity.ClipboardDialogActivity":t.top,
                "real".equals(field)?HOME+"Changed":t.real,"orig".equals(field)?HOME+"Changed":t.orig,
                !"running".equals(field)&&t.running,!"visible".equals(field)&&t.visible);
    }
    static ProfileTaskPolicy.Refusal classify(BackgroundOwnedSingleTask.Task r,BackgroundOwnedSingleTask.Task l,
            BackgroundOwnedSingleTask.Task nextR,BackgroundOwnedSingleTask.Task nextL)throws Exception{
        return ProfilePermissionTransient.changedRootRefusal(target(),r,l,
                Collections.singletonList(nextR),Collections.singletonList(nextL),authority(),1000,1100);
    }
    static ProfilePermissionTransient.ReadChange marker(ProfileTaskPolicy.Refusal failure){
        yes(ROOT_CHANGED.equals(failure.code),"original failure code changed");
        yes(failure.getCause() instanceof ProfilePermissionTransient.ReadChange,"missing structural marker");
        return (ProfilePermissionTransient.ReadChange)failure.getCause();
    }
    static void unmarked(ProfileTaskPolicy.Refusal failure){
        yes(ROOT_CHANGED.equals(failure.code),"original failure code changed");
        yes(failure.getCause()==null,"unproved change became retry classification");
    }
    static void onlySetupMutations(RetryAdapter a){
        yes(a.base.f.mutations.equals(Arrays.asList("create","bind")),"read retry mutated a task");
    }
    static final class RetryAdapter implements ProfileOwnedTask.Platform {
        final ProfilePermissionTransientHostTest.Adapter base;
        String mode="target";boolean afterFailure,inject=true;
        int proofs,readyReads,snapshots;long recheckDelay,snapshotDelay,afterFailureClock=-1;
        boolean cancelAfterFailure,installationAfterFailure,foreignAfterFailure,wrongCallerAfterFailure;
        String identityAfterFailure;boolean identityLeafOnly,foreignMarker;
        RetryAdapter(String dump){base=new ProfilePermissionTransientHostTest.Adapter(dump);}
        @Override public ProfileTarget recheck(boolean ready){
            if(ready)readyReads++;
            if(afterFailure){base.f.now+=recheckDelay;recheckDelay=0;}
            return afterFailure&&installationAfterFailure?ProfileBrokerHostTest.target(11,1010367):base.f.actual;
        }
        @Override public void guard()throws Exception{base.guard();}
        @Override public long now(){return base.now();}
        @Override public Object newCookie(){return base.newCookie();}
        @Override public ProfileTaskPolicy.Snapshot snapshot()throws Exception{
            snapshots++;
            if(afterFailure){base.f.now+=snapshotDelay;snapshotDelay=0;}
            return base.snapshot();
        }
        @Override public ProfileTaskPolicy.Recents recents()throws Exception{return base.recents();}
        BackgroundOwnedSingleTask.Task row(boolean root){
            BackgroundOwnedSingleTask.Task t=root?base.rootRow():base.leafRow();
            if(!base.permission||!base.f.app)return t;
            int count=!afterFailure&&("pc".equals(mode)||"repeat".equals(mode)||"caller".equals(mode))?3:2;
            String top=afterFailure&&"target".equals(mode)?HOME:PC;
            int topUid=HOME.equals(top)?1010367:1010335;
            t=presentation(t,top,topUid,HOME.equals(top)?1:count);
            if(afterFailure&&identityAfterFailure!=null&&(!root||!identityLeafOnly))t=alter(t,identityAfterFailure);
            return t;
        }
        @Override public List<BackgroundOwnedSingleTask.Task> roots(){
            return base.f.root?Collections.singletonList(row(true)):Collections.emptyList();
        }
        @Override public List<BackgroundOwnedSingleTask.Task> children(Object token){
            yes(token.equals(base.f.rootToken),"read used an unowned root");
            if(base.f.extraChild)return base.children(token);
            return base.f.app?Collections.singletonList(row(false)):Collections.emptyList();
        }
        @Override public void createRoot(Object cookie){base.createRoot(cookie);}
        @Override public void bindRoot(Object token,Object cookie){base.bindRoot(token,cookie);}
        @Override public void removeLeaf(Object token)throws Exception{base.removeLeaf(token);}
        @Override public boolean deleteRoot(Object token)throws Exception{return base.deleteRoot(token);}
        @Override public void pause(){base.pause();}
        @Override public ProfilePermissionTransient.Proof permissionTransient(BackgroundOwnedSingleTask.Task r,
                BackgroundOwnedSingleTask.Task l)throws Exception{
            proofs++;
            if(inject&&(!afterFailure||"repeat".equals(mode))){
                ProfileTaskPolicy.Refusal refused;
                if("plain".equals(mode)||"foreignCause".equals(mode)){
                    refused=new ProfileTaskPolicy.Refusal(ROOT_CHANGED);
                    if("foreignCause".equals(mode))refused.initCause(new Exception("same text is not typed evidence"));
                }else{
                    String nextTop="target".equals(mode)?HOME:PC;
                    int nextUid=HOME.equals(nextTop)?1010367:1010335;
                    int nextCount=HOME.equals(nextTop)?1:(afterFailure?3:2);
                    BackgroundOwnedSingleTask.Task nr=presentation(r,nextTop,nextUid,nextCount);
                    BackgroundOwnedSingleTask.Task nl=presentation(l,nextTop,nextUid,nextCount);
                    if(foreignMarker){
                        Object other=new Object();
                        l=new BackgroundOwnedSingleTask.Task(l.id,l.display,l.user,l.parent,l.uid,l.topUid,l.activities,
                                other,l.cookies,l.intentComponent,l.base,l.top,l.real,l.orig,l.running,l.visible);
                        nl=presentation(l,nextTop,nextUid,nextCount);
                    }
                    refused=ProfilePermissionTransient.changedRootRefusal(target(),r,l,
                            Collections.singletonList(nr),Collections.singletonList(nl),authority(),base.f.now,base.f.now);
                }
                afterFailure=true;
                if(afterFailureClock>=0)base.f.now=afterFailureClock;
                if(cancelAfterFailure)base.f.cancel=true;
                if(foreignAfterFailure)base.f.foreign=true;
                if(wrongCallerAfterFailure)base.wrongCaller=true;
                throw refused;
            }
            return base.permissionTransient(r,l);
        }
        ProfileOwnedTask start(boolean retain)throws Exception{
            ProfileOwnedTask task=new ProfileOwnedTask(this,target(),ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7);
            task.prepare();task.beforeDispatch();base.f.launch();task.accepted(0);
            if(retain)yes(task.observe(),"initial actual leaf not retained");
            base.permission=true;proofs=readyReads=snapshots=0;return task;
        }
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("synthetic fixture path required");
        byte[] bytes=Files.readAllBytes(Paths.get(args[0]));
        yes(bytes.length==2306&&ProfileIdentity.sha(bytes).equals("7f8adcb158486f74a1ebe342e54902b9fc7550ed7b0dd7bf11b36d1d97ab63f0"),"synthetic fixture pin");
        final String dump=new String(bytes,StandardCharsets.UTF_8);
        ProfilePermissionTransientHostTest.fixtureShape(dump);

        test("only known presentation change creates a non-authority marker",()->{
            BackgroundOwnedSingleTask.Task r=ProfilePermissionTransientHostTest.root(),l=ProfilePermissionTransientHostTest.leaf();
            BackgroundOwnedSingleTask.Task nr=presentation(r,HOME,1010367,1),nl=presentation(l,HOME,1010367,1);
            ProfilePermissionTransient.ReadChange change=marker(classify(r,l,nr,nl));
            yes(change.matchesRetained(target(),r,l,1100),"retained exact pair missing");
            yes(change.retryDeadline(9000)==3100&&change.retryDeadline(1500)==1500,"deadline extended");
            change.requireSameReadIdentity(nr,nl,1101);
            yes(!ProfilePermissionTransient.sameTaskInfo(r,nr)&&!ProfilePermissionTransient.sameTaskInfo(l,nl),"full equality was weakened");
            yes(ProfilePermissionTransient.ReadChange.class.getConstructors().length==0,"public marker reconstruction");
            marker(classify(r,l,presentation(r,PC,1010335,3),presentation(l,PC,1010335,3)));
        });
        test("failed-pair stable identity fields never become a retry marker",()->{
            for(String field:new String[]{"id","display","user","parent","uid","token","cookies","intent","base","real","orig"}){
                BackgroundOwnedSingleTask.Task r=ProfilePermissionTransientHostTest.root(),l=ProfilePermissionTransientHostTest.leaf();
                BackgroundOwnedSingleTask.Task nr=presentation(r,HOME,1010367,1),nl=presentation(l,HOME,1010367,1);
                unmarked(classify(r,l,alter(nr,field),nl));
                unmarked(classify(r,l,nr,alter(nl,field)));
            }
        });
        test("unknown foreign invisible mixed presentation is not retryable",()->{
            for(String field:new String[]{"topUid","activities0","activities33","foreign","running","visible"}){
                BackgroundOwnedSingleTask.Task r=ProfilePermissionTransientHostTest.root(),l=ProfilePermissionTransientHostTest.leaf();
                BackgroundOwnedSingleTask.Task nr=presentation(r,HOME,1010367,1),nl=presentation(l,HOME,1010367,1);
                unmarked(classify(r,l,alter(nr,field),nl));unmarked(classify(r,l,nr,alter(nl,field)));
            }
            BackgroundOwnedSingleTask.Task r=ProfilePermissionTransientHostTest.root(),l=ProfilePermissionTransientHostTest.leaf();
            unmarked(classify(r,l,r,l));
            unmarked(classify(r,l,presentation(r,HOME,1010367,1),presentation(l,PC,1010335,1)));
            unmarked(classify(r,l,presentation(r,HOME,1010367,1),presentation(l,HOME+"Different",1010367,1)));
        });

        test("incomplete pairs system authority and bad clocks do not classify",()->{
            BackgroundOwnedSingleTask.Task r=ProfilePermissionTransientHostTest.root(),l=ProfilePermissionTransientHostTest.leaf();
            List<BackgroundOwnedSingleTask.Task> rs=Collections.singletonList(presentation(r,HOME,1010367,1));
            List<BackgroundOwnedSingleTask.Task> ls=Collections.singletonList(presentation(l,HOME,1010367,1));
            for(List<BackgroundOwnedSingleTask.Task> bad:Arrays.<List<BackgroundOwnedSingleTask.Task>>asList(null,Collections.emptyList(),Arrays.asList(rs.get(0),rs.get(0)),Collections.singletonList(null))){
                unmarked(ProfilePermissionTransient.changedRootRefusal(target(),r,l,bad,ls,authority(),1000,1100));
                unmarked(ProfilePermissionTransient.changedRootRefusal(target(),r,l,rs,bad,authority(),1000,1100));
            }
            unmarked(ProfilePermissionTransient.changedRootRefusal(target(),r,l,rs,ls,null,1000,1100));
            ProfilePermissionTransient.Authority other=new ProfilePermissionTransient.Authority(11,1110335,
                    ProfilePermissionTransient.PACKAGE,ProfilePermissionTransient.APK,ProfilePermissionTransient.APK_SHA,
                    ProfilePermissionTransient.SIGNER,330000000,true,true,true,true);
            unmarked(ProfilePermissionTransient.changedRootRefusal(target(),r,l,rs,ls,other,1000,1100));
            unmarked(ProfilePermissionTransient.changedRootRefusal(target(),r,l,rs,ls,authority(),1000,999));
            unmarked(ProfilePermissionTransient.changedRootRefusal(target(),r,l,rs,ls,authority(),1000,3001));
        });
        test("marker freshness and retained binding are independent of serialized IDs",()->{
            BackgroundOwnedSingleTask.Task r=ProfilePermissionTransientHostTest.root(),l=ProfilePermissionTransientHostTest.leaf();
            ProfilePermissionTransient.ReadChange change=marker(classify(r,l,presentation(r,HOME,1010367,1),presentation(l,HOME,1010367,1)));
            yes(change.matchesRetained(target(),r,l,3099),"fresh classification rejected");
            yes(!change.matchesRetained(target(),r,l,3100)&&!change.matchesRetained(target(),r,l,1099),"age or clock rollback accepted");
            yes(!change.matchesRetained(target(),r,alter(l,"token"),1100),"different Binder accepted");
            yes(!change.matchesRetained(target(),r,alter(l,"id"),1100),"different task ID accepted");
            yes(!change.matchesRetained(ProfileBrokerHostTest.target(11,1010367),r,l,1100),"different profile accepted");
            refusal("PROFILE_PERMISSION_READ_RETRY_IDENTITY_CHANGED",()->change.requireSameReadIdentity(r,alter(l,"cookies"),1100));
            refusal("PROFILE_PERMISSION_READ_RETRY_DEADLINE",()->change.requireSameReadIdentity(r,l,3100));
        });
        test("actual platform bracket keeps refusal and avoids child read on changed identity",()->{
            for(String field:new String[]{"id","display","user","parent","uid","token","cookies","intent","base","real","orig"}){
                BackgroundOwnedSingleTask.Task r=ProfilePermissionTransientHostTest.root(),l=ProfilePermissionTransientHostTest.leaf();
                PermissionPairProbe p=new PermissionPairProbe(target(),Collections.singletonList(alter(presentation(r,HOME,1010367,1),field)),
                        Collections.singletonList(presentation(l,HOME,1010367,1)),r.token);
                unmarked(refusal(ROOT_CHANGED,()->p.check(r,l,authority(),1000)));
                yes(p.organizer.childReads==0,"changed stable root caused additional child read");
            }
        });
        test("actual platform bracket classifies only root presentation and retains leaf equality",()->{
            BackgroundOwnedSingleTask.Task r=ProfilePermissionTransientHostTest.root(),l=ProfilePermissionTransientHostTest.leaf();
            PermissionPairProbe p=new PermissionPairProbe(target(),Collections.singletonList(presentation(r,HOME,1010367,1)),
                    Collections.singletonList(presentation(l,HOME,1010367,1)),r.token);
            marker(refusal(ROOT_CHANGED,()->p.check(r,l,authority(),1000)));
            yes(p.organizer.rootReads==1&&p.organizer.childReads==1,"bracket read shape changed");
            PermissionPairProbe equal=new PermissionPairProbe(target(),Collections.singletonList(r),Collections.singletonList(l),r.token);
            equal.check(r,l,authority(),1000);checks++;
            PermissionPairProbe leaf=new PermissionPairProbe(target(),Collections.singletonList(r),Collections.singletonList(alter(l,"cookies")),r.token);
            ProfileTaskPolicy.Refusal failure=refusal("PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ",()->leaf.check(r,l,authority(),1000));
            yes(failure.getCause()==null,"leaf-only changed pair was reclassified");
            PermissionPairProbe slow=new PermissionPairProbe(target(),Collections.singletonList(presentation(r,HOME,1010367,1)),
                    Collections.singletonList(presentation(l,HOME,1010367,1)),r.token);
            slow.organizer.afterChildClock=3001;
            unmarked(refusal(ROOT_CHANGED,()->slow.check(r,l,authority(),1000)));
        });

        test("target return receives a fresh complete window proof without an effect",()->{
            RetryAdapter a=new RetryAdapter(dump);ProfileOwnedTask p=a.start(true);
            String retained=(String)p.evidence().get("leaf_token_id");
            WindowOwnership w=p.window(4,300,9000);
            yes(a.proofs==1&&a.readyReads==2&&a.snapshots==2,"fresh installed/global read missing");
            yes(w.taskId==300&&w.userId==10&&w.fullUid==1010367,"fresh target window identity");
            yes(retained.equals(w.taskTokenId)&&Boolean.TRUE.equals(p.evidence().get("permission_read_retry_used")),"retained authority replaced");
            onlySetupMutations(a);
        });
        test("still visible PC needs a new full caller proof and only yields setup required",()->{
            RetryAdapter a=new RetryAdapter(dump);a.mode="pc";ProfileOwnedTask p=a.start(true);
            refusal("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.window(4,300,9000));
            yes(a.proofs==2&&a.base.proofs==1&&a.readyReads==2&&a.snapshots==2,"new full PC proof missing");
            Map<?,?> proof=(Map<?,?>)p.evidence().get("permission_transient");
            yes(Boolean.FALSE.equals(proof.get("business_observation_allowed"))&&Boolean.FALSE.equals(proof.get("permission_input_allowed")),"PC granted action authority");
            onlySetupMutations(a);
        });
        test("fresh PC caller failure is not converted to setup or business success",()->{
            RetryAdapter a=new RetryAdapter(dump);a.mode="caller";a.wrongCallerAfterFailure=true;
            ProfileOwnedTask p=a.start(true);
            refusal("PROFILE_PERMISSION_CALLER_UNPROVEN",()->p.window(4,300,9000));
            yes(a.proofs==2&&a.base.proofs==1,"fresh full caller proof skipped");onlySetupMutations(a);
        });
        test("string-only foreign cause and foreign typed marker never retry",()->{
            for(String mode:new String[]{"plain","foreignCause","foreignMarker"}){
                RetryAdapter a=new RetryAdapter(dump);
                if("foreignMarker".equals(mode))a.foreignMarker=true;else a.mode=mode;
                ProfileOwnedTask p=a.start(true);
                refusal(ROOT_CHANGED,()->p.window(4,300,9000));
                yes(a.proofs==1&&a.readyReads==1&&a.snapshots==1,"untyped or unrelated failure retried");
                yes(Boolean.FALSE.equals(p.evidence().get("permission_read_retry_used")),"unrelated retry consumed");
                onlySetupMutations(a);
            }
        });
        test("first claim observe and retirement do not use the window-only retry",()->{
            RetryAdapter first=new RetryAdapter(dump);ProfileOwnedTask unclaimed=first.start(false);
            refusal(ROOT_CHANGED,()->unclaimed.window(4,300,9000));
            yes(unclaimed.evidence().get("leaf_task_id")==null&&first.readyReads==1,"failed first claim gained authority");
            onlySetupMutations(first);
            RetryAdapter observed=new RetryAdapter(dump);ProfileOwnedTask p=observed.start(true);
            refusal(ROOT_CHANGED,()->p.observe());
            yes(observed.proofs==1&&observed.readyReads==0,"ordinary observe retried");onlySetupMutations(observed);
            RetryAdapter retired=new RetryAdapter(dump);ProfileOwnedTask r=retired.start(true);
            refusal(ROOT_CHANGED,()->r.retire(9000));
            yes(retired.proofs==1&&!r.cleanupKnown(),"retirement reused a failed proof");onlySetupMutations(retired);
        });

        test("identity change during the fresh read is rejected before window publication",()->{
            for(String field:new String[]{"id","display","user","parent","uid","token","cookies","intent","base","real","orig"}){
                RetryAdapter a=new RetryAdapter(dump);a.identityAfterFailure=field;a.identityLeafOnly=true;
                ProfileOwnedTask p=a.start(true);
                refusal("PROFILE_PERMISSION_READ_RETRY_IDENTITY_CHANGED",()->p.window(4,300,9000));
                yes(a.readyReads==2&&a.snapshots==2,"expected complete fresh read not attempted");
                onlySetupMutations(a);
            }
        });
        test("fresh cancellation installation and complete-global failures remain terminal",()->{
            RetryAdapter cancelled=new RetryAdapter(dump);cancelled.cancelAfterFailure=true;
            ProfileOwnedTask c=cancelled.start(true);
            refusal("CANCELLED",()->c.window(4,300,9000));onlySetupMutations(cancelled);
            RetryAdapter installation=new RetryAdapter(dump);installation.installationAfterFailure=true;
            ProfileOwnedTask i=installation.start(true);
            refusal("PROFILE_INSTALLATION_IDENTITY_CHANGED",()->i.window(4,300,9000));
            yes(installation.snapshots==1,"changed installation continued to fresh tree");onlySetupMutations(installation);
            RetryAdapter foreign=new RetryAdapter(dump);foreign.foreignAfterFailure=true;
            ProfileOwnedTask f=foreign.start(true);
            refusal("PROFILE_FOREIGN_ROOT_ON_DISPLAY",()->f.window(4,300,9000));onlySetupMutations(foreign);
        });
        test("rollback and expired typed classification never initiate retry",()->{
            for(long now:new long[]{999,3000,3001}){
                RetryAdapter a=new RetryAdapter(dump);a.afterFailureClock=now;ProfileOwnedTask p=a.start(true);
                refusal(ROOT_CHANGED,()->p.window(4,300,9000));
                yes(a.readyReads==1&&a.snapshots==1&&!Boolean.TRUE.equals(p.evidence().get("permission_read_retry_used")),"stale/rollback marker retried");
                onlySetupMutations(a);
            }
        });
        test("two second acceptance cap covers installed check and fresh tree",()->{
            RetryAdapter boundary=new RetryAdapter(dump);boundary.recheckDelay=2000;ProfileOwnedTask b=boundary.start(true);
            refusal(ROOT_CHANGED,()->b.window(4,300,9000));
            yes(boundary.readyReads==2&&boundary.snapshots==1,"expired read continued");onlySetupMutations(boundary);
            RetryAdapter inside=new RetryAdapter(dump);inside.recheckDelay=1999;ProfileOwnedTask p=inside.start(true);
            WindowOwnership accepted=p.window(4,300,9000);
            yes(accepted.observedElapsedMs==2999,"new evidence timestamp not used");onlySetupMutations(inside);
            for(long delay:new long[]{2000,-1}){
                RetryAdapter during=new RetryAdapter(dump);during.snapshotDelay=delay;ProfileOwnedTask t=during.start(true);
                refusal("PROFILE_PERMISSION_READ_RETRY_DEADLINE",()->t.window(4,300,9000));onlySetupMutations(during);
            }
        });
        test("original request deadline is never extended by a fresh read",()->{
            RetryAdapter expired=new RetryAdapter(dump);ProfileOwnedTask e=expired.start(true);
            refusal(ROOT_CHANGED,()->e.window(4,300,1000));
            yes(expired.readyReads==1,"original expired request retried");onlySetupMutations(expired);
            RetryAdapter a=new RetryAdapter(dump);a.recheckDelay=500;ProfileOwnedTask p=a.start(true);
            refusal(ROOT_CHANGED,()->p.window(4,300,1500));
            yes(a.snapshots==1,"original deadline extended by 2 seconds");onlySetupMutations(a);
            RetryAdapter valid=new RetryAdapter(dump);valid.recheckDelay=499;ProfileOwnedTask v=valid.start(true);
            WindowOwnership w=v.window(4,300,1500);
            yes(w.observedElapsedMs==1499&&w.expiresElapsedMs==1500,"window outlived original deadline");onlySetupMutations(valid);
        });
        test("a second failed proof and later calls cannot obtain a second retry",()->{
            RetryAdapter repeat=new RetryAdapter(dump);repeat.mode="repeat";ProfileOwnedTask p=repeat.start(true);
            refusal(ROOT_CHANGED,()->p.window(4,300,9000));
            yes(repeat.proofs==2&&repeat.readyReads==2&&repeat.snapshots==2,"unbounded second retry");onlySetupMutations(repeat);
            RetryAdapter a=new RetryAdapter(dump);ProfileOwnedTask held=a.start(true);held.window(4,300,9000);
            a.afterFailure=false;
            refusal(ROOT_CHANGED,()->held.window(4,300,9000));
            yes(a.proofs==2&&a.readyReads==3&&a.snapshots==3,"retry counter reset across window calls");onlySetupMutations(a);
        });
        test("fresh target window still requires the actual observed task id",()->{
            RetryAdapter a=new RetryAdapter(dump);ProfileOwnedTask p=a.start(true);
            refusal("PROFILE_WINDOW_TASK_MISMATCH",()->p.window(4,301,9000));onlySetupMutations(a);
        });
        test("retained long-term cookie loss is distinct from short failed-pair changes",()->{
            RetryAdapter a=new RetryAdapter(dump);ProfileOwnedTask p=a.start(true);
            a.base.f.wrongCookie=true;
            WindowOwnership w=p.window(4,300,9000);
            yes(w.taskId==300&&Boolean.FALSE.equals(p.lastLeafValidation().get("launch_cookie_present")),"long-term cookie became authority again");
            onlySetupMutations(a);
        });
        test("unavailable fresh permission proof remains unavailable",()->{
            RetryAdapter a=new RetryAdapter(dump);a.mode="pc";a.base.unavailable=true;ProfileOwnedTask p=a.start(true);
            refusal("PROFILE_PERMISSION_PROOF_UNAVAILABLE",()->p.window(4,300,9000));
            yes(a.proofs==2&&a.base.proofs==1,"fresh permission proof bypassed");onlySetupMutations(a);
        });
        System.out.println("{\"schema\":\"hepta.profile-permission-read-retry-host-tests.v1\",\"passed\":true,\"cases\":"+cases
                +",\"assertions\":"+checks+",\"fixture_sha256\":\""+ProfileIdentity.sha(bytes)
                +"\",\"taskinfo_and_framework_fixtures_synthetic\":true,\"real_pair_bracket_method_extracted\":true"
                +",\"phone_contacted\":false,\"android_build\":false}");
    }
}
