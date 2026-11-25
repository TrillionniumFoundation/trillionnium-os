package org.trillionnium.hepta.local;

import android.content.Context;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;

/** Actual controller fragments and installation identity class, with explicit host I/O ports. */
public final class NativeProfileLiveVerifierHostTest {
    interface Checked { void run() throws Exception; }
    static int assertions,cases,failed;
    static final Context SERVICE=new Context();
    static final String TASK="host-task-a",OWNER=hex('a');
    static final class Env {
        final ProfileTarget target=target(0);
        final BackgroundSession background=new BackgroundSession(TASK,OWNER,target);
        final TaskAuthorization.Gate authorization=new TaskAuthorization.Gate();
        final TaskCompletionGate completion=new TaskCompletionGate(new NativeAppGoal(ProfileTarget.CTRIP,OWNER));
        final QualificationScopeConfig.CompletionInstalledIdentity installed;
        final NativeAppSession.InstalledVerifier verifier;
        final NativeAppSession nativeTask;
        Env() throws Exception {
            ProfileCatalogueClient.actual=target;
            installed=QualificationScopeConfig.CompletionInstalledIdentity.captureNativeApp(SERVICE,completion.nativeGoal(),background);
            verifier=NativeProfileVerifierHostFixture.bind(SERVICE,TASK,completion,background,installed);
            nativeTask=new NativeAppSession(TASK,authorization,verifier);
            reset();
        }
        void reset() {
            background.reset();ProfileCatalogueClient.calls=0;ProfileCatalogueClient.failure=null;
            QualificationScopeConfig.Installed.verifyCalls=0;QualificationScopeConfig.Installed.failure=null;
        }
        void post(BackgroundSession activeBackground,NativeAppSession current) throws Exception {
            NativeProfileVerifierHostFixture.post(SERVICE,TASK,authorization,background,activeBackground,current,installed,completion);
        }
    }
    static String hex(char c){StringBuilder b=new StringBuilder();for(int i=0;i<64;i++)b.append(c);return b.toString();}
    static ProfileTarget target(int variant){
        int user=variant==1?11:10;long serial=variant==2?101:100;
        int uid=user*100000+(variant==3?12001:12000);
        String pkg=variant==4?ProfileTarget.XIAOMI:ProfileTarget.CTRIP;
        String component=pkg+"/"+(variant==5?"ChangedActivity":"MainActivity");
        long version=variant==6?2:1;
        Map<String,String> apks=new TreeMap<String,String>();apks.put("base",hex(variant==7?'b':'a'));
        apks.put("split:config",hex(variant==8?'d':'c'));
        if(variant==9)apks.put("split:extra",hex('e'));
        Set<String> signers=new TreeSet<String>();signers.add(hex(variant==10?'f':'1'));
        return new ProfileTarget(new ProfileIdentity(user,serial,0,ProfileIdentity.MANAGED),uid,pkg,component,version,apks,signers);
    }
    static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    static void refuses(Checked body,String message) throws Exception {
        boolean refused=false;try{body.run();}catch(Exception expected){refused=true;}
        check(refused,message);
    }
    static void test(String name,Checked body){
        cases++;try{body.run();System.out.println("CASE\t"+name+"\tPASS");}
        catch(Throwable error){failed++;System.out.println("CASE\t"+name+"\tFAIL\t"+error.getClass().getSimpleName()+": "+error.getMessage());}
    }
    public static void main(String[] args){
        test("live_profile_uses_a_new_broker_state_each_time",()->{
            Env e=new Env();for(int i=0;i<3;i++)e.verifier.verify();
            check(e.background.calls==3,"three actual state calls required");
            check(e.background.activeChecks==6,"each actual verifyRemote brackets RPC with requireActive");
            check(ProfileCatalogueClient.calls==0,"live verification must not restart whole catalogue");
            check(e.background.lastOperation.equals("state"),"ordinary native state operation");
            check(e.background.lastTimeout==1800,"original broker timeout unchanged");
        });
        test("live_broker_failure_never_falls_back_to_catalogue",()->{
            Env e=new Env();e.background.callFailure=new java.io.IOException("host transport refusal");
            refuses(()->e.verifier.verify(),"transport failure must propagate");
            check(e.background.calls==1,"one RPC attempted");check(ProfileCatalogueClient.calls==0,"no catalogue fallback");
        });
        test("authenticated_response_refusal_propagates_without_fallback",()->{
            Env e=new Env();e.background.acceptFailure=new java.io.IOException("host response validation refusal");
            refuses(()->e.verifier.verify(),"response failure must propagate");
            check(e.background.calls==1&&e.background.accepts==1,"actual verifyRemote reaches accepting port once");
            check(ProfileCatalogueClient.calls==0,"no catalogue fallback");
        });
        test("retired_bound_session_refuses_before_rpc",()->{
            Env e=new Env();e.background.retired=true;
            refuses(()->e.verifier.verify(),"retired live verifier must refuse");
            check(e.background.calls==0&&ProfileCatalogueClient.calls==0,"retirement cannot select another route");
        });
        test("retirement_during_state_refuses_on_original_final_guard",()->{
            Env e=new Env();e.background.retireOnAccept=true;
            refuses(()->e.verifier.verify(),"final requireActive must refuse retirement");
            check(e.background.calls==1&&e.background.activeChecks==2,"original post-RPC guard executed");
            check(ProfileCatalogueClient.calls==0,"no fallback");
        });
        test("callback_rejects_different_task",()->{
            Env e=new Env();BackgroundSession wrong=new BackgroundSession("host-task-b",OWNER,e.target);
            NativeAppSession.InstalledVerifier v=NativeProfileVerifierHostFixture.bind(SERVICE,TASK,e.completion,wrong,e.installed);
            refuses(()->v.verify(),"different task rejected");check(wrong.calls==0&&ProfileCatalogueClient.calls==0,"no IO after task mismatch");
        });
        test("callback_rejects_different_owner",()->{
            Env e=new Env();BackgroundSession wrong=new BackgroundSession(TASK,hex('b'),e.target);
            NativeAppSession.InstalledVerifier v=NativeProfileVerifierHostFixture.bind(SERVICE,TASK,e.completion,wrong,e.installed);
            refuses(()->v.verify(),"different owner rejected");check(wrong.calls==0&&ProfileCatalogueClient.calls==0,"no IO after owner mismatch");
        });
        test("all_selected_profile_identity_fields_remain_exact",()->{
            for(int i=1;i<=10;i++){
                Env e=new Env();BackgroundSession wrong=new BackgroundSession(TASK,OWNER,target(i));
                NativeAppSession.InstalledVerifier v=NativeProfileVerifierHostFixture.bind(SERVICE,TASK,e.completion,wrong,e.installed);
                refuses(()->v.verify(),"selected identity variant "+i+" rejected");
                check(wrong.calls==0&&ProfileCatalogueClient.calls==0,"identity mismatch must not trigger any alternative read");
            }
        });
        test("equal_complete_target_value_is_accepted",()->{
            Env e=new Env();ProfileTarget equivalent=ProfileTarget.fromWire(e.target.wire());
            BackgroundSession same=new BackgroundSession(TASK,OWNER,equivalent);
            NativeProfileVerifierHostFixture.bind(SERVICE,TASK,e.completion,same,e.installed).verify();
            check(same.calls==1&&ProfileCatalogueClient.calls==0,"exact value equality uses bound live session");
        });
        test("closure_keeps_the_original_background_object",()->{
            Env e=new Env();BackgroundSession other=new BackgroundSession(TASK,OWNER,e.target);
            BackgroundSession callerReference=e.background;NativeAppSession.InstalledVerifier saved=
                    NativeProfileVerifierHostFixture.bind(SERVICE,TASK,e.completion,callerReference,e.installed);
            callerReference=other;saved.verify();
            check(e.background.calls==1&&callerReference.calls==0,"caller replacement cannot replace captured session");
        });
        test("native_step_after_uses_its_live_verifier",()->{
            Env e=new Env();e.post(e.background,e.nativeTask);
            check(!e.completion.invalid,"valid same-task post observation remains valid");
            check(e.background.calls==1&&ProfileCatalogueClient.calls==0,"post observation cannot reintroduce full catalogue");
        });
        test("native_step_after_missing_session_refuses_without_fallback",()->{
            Env e=new Env();e.post(e.background,null);
            check(e.completion.invalid,"missing native session invalidates installation");
            check(e.background.calls==0&&ProfileCatalogueClient.calls==0,"missing native task never falls back");
        });
        test("native_step_after_task_mismatch_refuses",()->{
            Env e=new Env();e.post(e.background,new NativeAppSession("other",e.authorization,e.verifier));
            check(e.completion.invalid,"task mismatch invalidates");check(e.background.calls==0&&ProfileCatalogueClient.calls==0,"no fallback");
        });
        test("native_step_after_authorization_mismatch_refuses",()->{
            Env e=new Env();e.post(e.background,new NativeAppSession(TASK,new TaskAuthorization.Gate(),e.verifier));
            check(e.completion.invalid,"authorization mismatch invalidates");check(e.background.calls==0&&ProfileCatalogueClient.calls==0,"no fallback");
        });
        test("native_step_after_foreign_session_object_refuses",()->{
            Env e=new Env();e.post(new BackgroundSession(TASK,OWNER,e.target),e.nativeTask);
            check(e.completion.invalid,"same-target different background object invalidates");
            check(e.background.calls==0&&ProfileCatalogueClient.calls==0,"no replacement session fallback");
        });
        test("native_step_after_broker_failure_keeps_original_invalidation",()->{
            Env e=new Env();e.background.callFailure=new java.io.IOException("host transport failure");e.post(e.background,e.nativeTask);
            check(e.completion.invalid,"broker failure invalidates");check("installed_notes_identity_changed".equals(e.completion.reason),"old invalidation label retained");
            check(e.background.calls==1&&ProfileCatalogueClient.calls==0,"no fallback");
        });
        test("nonprofile_callback_keeps_original_installed_check",()->{
            Env e=new Env();QualificationScopeConfig.CompletionInstalledIdentity local=
                    QualificationScopeConfig.CompletionInstalledIdentity.captureNativeApp(SERVICE,e.completion.nativeGoal());
            NativeAppSession.InstalledVerifier v=NativeProfileVerifierHostFixture.bind(SERVICE,TASK,e.completion,e.background,local);
            v.verify();check(QualificationScopeConfig.Installed.verifyCalls==1,"ordinary installed verifier retained");
            check(e.background.calls==0&&ProfileCatalogueClient.calls==0,"no profile path used");
            QualificationScopeConfig.Installed.failure=new IllegalStateException("host ordinary installation changed");
            refuses(()->v.verify(),"ordinary failure retained");check(e.background.calls==0,"no profile fallback");
        });
        test("nonnative_step_after_keeps_original_installed_check",()->{
            Env e=new Env();TaskCompletionGate notes=new TaskCompletionGate(null);
            QualificationScopeConfig.CompletionInstalledIdentity local=QualificationScopeConfig.CompletionInstalledIdentity.captureNotes(SERVICE);
            NativeProfileVerifierHostFixture.post(SERVICE,TASK,e.authorization,e.background,null,null,local,notes);
            check(!notes.invalid&&QualificationScopeConfig.Installed.verifyCalls==1,"ordinary Notes check retained");
            check(e.background.calls==0&&ProfileCatalogueClient.calls==0,"no native route");
        });
        test("no_installed_completion_remains_a_noop",()->{
            Env e=new Env();NativeProfileVerifierHostFixture.post(SERVICE,TASK,e.authorization,e.background,null,null,null,e.completion);
            check(!e.completion.invalid&&e.background.calls==0&&ProfileCatalogueClient.calls==0,"null optional completion unchanged");
        });
        test("post_cleanup_profile_check_uses_original_catalogue",()->{
            Env e=new Env();e.background.retired=true;
            boolean checked=NativeProfileVerifierHostFixture.terminal(SERVICE,e.installed,e.completion);
            check(checked&&!e.completion.invalid,"terminal check remains available after release");
            check(ProfileCatalogueClient.calls==1&&e.background.calls==0,"terminal must not call retired broker");
        });
        test("post_cleanup_changed_installation_still_invalidates",()->{
            Env e=new Env();e.background.retired=true;ProfileCatalogueClient.actual=target(6);
            boolean checked=NativeProfileVerifierHostFixture.terminal(SERVICE,e.installed,e.completion);
            check(!checked&&e.completion.invalid,"changed installation refused after cleanup");
            check("installed_native_app_identity_changed_after_cleanup".equals(e.completion.reason),"original terminal invalidation retained");
            check(ProfileCatalogueClient.calls==1&&e.background.calls==0,"no broker fallback");
        });
        test("post_cleanup_nonprofile_check_remains_original",()->{
            Env e=new Env();TaskCompletionGate notes=new TaskCompletionGate(null);
            QualificationScopeConfig.CompletionInstalledIdentity local=QualificationScopeConfig.CompletionInstalledIdentity.captureNotes(SERVICE);
            check(!NativeProfileVerifierHostFixture.terminal(SERVICE,local,notes),"native flag stays false for Notes");
            check(!notes.invalid&&QualificationScopeConfig.Installed.verifyCalls==1,"original ordinary terminal verification");
            check(e.background.calls==0&&ProfileCatalogueClient.calls==0,"no native state");
        });
        System.out.println("TOTAL\t"+cases+"\t"+assertions+"\t"+failed);
        if(failed!=0)System.exit(1);
    }
}
