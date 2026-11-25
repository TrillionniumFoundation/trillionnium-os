package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import android.os.SystemClock;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;

/** Full production installed-identity class and BackgroundSession. Only Android
 * display/socket/clock and terminal catalogue IO are the existing explicit ports. */
public final class LiveProfileIdentityHostTest {
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    interface Checked {void run()throws Exception;}
    interface Mutation {void change(NativeProfileIdentityHostTest.Env e,JSONObject reply)throws Exception;}
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void reject(Checked work)throws Exception{
        boolean refused=false;
        try{work.run();}catch(IllegalArgumentException|IllegalStateException|IOException expected){refused=true;}
        check(refused,"actual production fence must refuse");
    }
    private static void one(String name,Checked work)throws Exception{
        LocalSocket.reset();SystemClock.now=1000000;ProfileCatalogueClient.actual=null;work.run();names.add(name);
    }
    private static NativeProfileIdentityHostTest.Env flight()throws Exception{
        NativeProfileIdentityHostTest.Env e=new NativeProfileIdentityHostTest.Env(NativeProfileIdentityHostTest.ctrip(),NativeProfileIdentityHostTest.FLIGHT);
        e.active();return e;
    }
    private static QualificationScopeConfig.CompletionInstalledIdentity identity(NativeProfileIdentityHostTest.Env e)throws Exception{
        return e.capture(e.owner,e.target.packageName);
    }
    private static void replyMutation(String name,Mutation mutation)throws Exception{
        one(name,()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            QualificationScopeConfig.CompletionInstalledIdentity id=identity(e);
            ProfileCatalogueClient.actual=e.target; // An available fallback must never rescue this failure.
            LocalSocket.responder=raw->{
                JSONObject value=e.reply(raw,e.target,true);mutation.change(e,value);
                return ProfileClientPort.frame(value.toString().getBytes(StandardCharsets.UTF_8));
            };
            reject(()->id.verifyLive(e.context));check(LocalSocket.connections==2,"one actual live attempt, no replay");
        }});
    }
    private static ProfileTarget changed(ProfileTarget t,String key){
        ProfileIdentity profile=t.profile;int uid=t.fullUid;String pkg=t.packageName,component=t.component;
        long version=t.versionCode;
        Map<String,String> hashes=new TreeMap<String,String>(t.apkHashes);
        java.util.Set<String> signers=new java.util.TreeSet<String>(t.signerSha256);
        if("serial".equals(key))profile=new ProfileIdentity(profile.userId,profile.serial+1,0,ProfileIdentity.MANAGED);
        if("uid".equals(key))uid++;
        if("version".equals(key))version++;
        if("apk".equals(key))hashes.put("base",NativeAppEvidence.hash("changed-base"));
        if("split".equals(key))hashes.put("split:other",NativeAppEvidence.hash("additional-split"));
        if("signer".equals(key)){signers.clear();signers.add(NativeAppEvidence.hash("changed-signer"));}
        if("component".equals(key))component=pkg+"/"+pkg+".OtherActivity";
        if("package".equals(key)){pkg=ProfileTarget.XIAOMI;component=pkg+"/com.xiaomi.shop2.activity.MainActivity";}
        return new ProfileTarget(profile,uid,pkg,component,version,hashes,signers);
    }
    private static void released(NativeProfileIdentityHostTest.Env e)throws Exception{
        Field state=BackgroundSession.class.getDeclaredField("state");state.setAccessible(true);state.set(e.session,"RELEASED");
        Field retired=BackgroundSession.class.getDeclaredField("retired");retired.setAccessible(true);retired.setBoolean(e.session,true);
    }
    public static void main(String[] args)throws Exception{
        Path output=Paths.get(args[0]);NativeProfileIdentityHostTest.workspace=Paths.get(args[1]);
        Files.createDirectories(NativeProfileIdentityHostTest.workspace);
        one("ctrip_each_live_call_uses_original_state_rpc",()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            QualificationScopeConfig.CompletionInstalledIdentity id=identity(e);
            final List<JSONObject> requests=new ArrayList<JSONObject>();
            LocalSocket.responder=raw->{requests.add(ProfileClientPort.decode(raw));return ProfileClientPort.frame(e.reply(raw,e.target,true).toString().getBytes(StandardCharsets.UTF_8));};
            LiveIdentityControllerBridge.verifier(id,e.context).verify();
            LiveIdentityControllerBridge.after(id,e.context,null);
            check(LocalSocket.connections==3&&requests.size()==2,"capture plus both actual Controller live boundaries");
            check(ProfileCatalogueClient.actual==null,"no catalogue permission was introduced");
            String prior=null;
            for(JSONObject r:requests){
                check("state".equals(r.getString("op")),"read-only state operation");
                check(e.session.generation.equals(r.getString("generation")),"same captured generation");
                check(e.target.sha256.equals(r.getString("target_sha256")),"full exact target digest");
                check(r.getLong("deadline_elapsed_ms")==SystemClock.now+1800,"original 1800 ms budget");
                check(prior==null||!prior.equals(r.getString("request_id")),"each call has a new actual request");
                prior=r.getString("request_id");
            }
        }});
        one("xiaomi_each_live_call_uses_same_profile_channel",()->{try(NativeProfileIdentityHostTest.Env e=new NativeProfileIdentityHostTest.Env(NativeProfileIdentityHostTest.xiaomi(),NativeProfileIdentityHostTest.OWNER)){
            e.active();QualificationScopeConfig.CompletionInstalledIdentity id=identity(e);
            id.verifyLive(e.context);id.verifyLive(e.context);check(LocalSocket.connections==3,"each live check must read anew");
        }});
        one("identity_holds_exact_captured_session_object",()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            QualificationScopeConfig.CompletionInstalledIdentity id=identity(e);
            Field f=id.getClass().getDeclaredField("profileSession");f.setAccessible(true);
            check(f.get(id)==e.session,"no target-only lookup or replacement session");
        }});
        one("target_only_identity_cannot_use_live_path",()->{
            Constructor<QualificationScopeConfig.CompletionInstalledIdentity> c=QualificationScopeConfig.CompletionInstalledIdentity.class.getDeclaredConstructor(ProfileTarget.class);
            c.setAccessible(true);QualificationScopeConfig.CompletionInstalledIdentity id=c.newInstance(NativeProfileIdentityHostTest.ctrip());
            reject(()->id.verifyLive(null));check(LocalSocket.connections==0,"missing captured session must not touch transport");
        });
        one("constructor_rejects_different_captured_target",()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            Constructor<QualificationScopeConfig.CompletionInstalledIdentity> c=QualificationScopeConfig.CompletionInstalledIdentity.class.getDeclaredConstructor(ProfileTarget.class,BackgroundSession.class);
            c.setAccessible(true);boolean refused=false;
            try{c.newInstance(changed(e.target,"serial"),e.session);}catch(InvocationTargetException x){refused=x.getCause() instanceof IllegalArgumentException||x.getCause() instanceof IllegalStateException;}
            check(refused&&LocalSocket.connections==0,"mismatched binding cannot be constructed");
        }});
        one("released_session_refuses_without_catalogue_fallback",()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            QualificationScopeConfig.CompletionInstalledIdentity id=identity(e);released(e);ProfileCatalogueClient.actual=e.target;
            reject(()->id.verifyLive(e.context));check(LocalSocket.connections==1,"closed broker is not reopened");
        }});
        one("expired_session_refuses_before_transport",()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            QualificationScopeConfig.CompletionInstalledIdentity id=identity(e);SystemClock.now=e.session.expiresElapsed;ProfileCatalogueClient.actual=e.target;
            reject(()->id.verifyLive(e.context));check(LocalSocket.connections==1,"expiry is not extended");
        }});
        one("equal_target_new_session_cannot_replace_original_closed_session",()->{
            try(NativeProfileIdentityHostTest.Env a=flight();NativeProfileIdentityHostTest.Env b=flight()){
                QualificationScopeConfig.CompletionInstalledIdentity id=identity(a);released(a);b.active();ProfileCatalogueClient.actual=b.target;
                reject(()->id.verifyLive(a.context));check(LocalSocket.connections==1,"same target does not authorize a different generation");
            }
        });
        one("missing_socket_refuses_without_catalogue_fallback",()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            QualificationScopeConfig.CompletionInstalledIdentity id=identity(e);LocalSocket.missing=true;ProfileCatalogueClient.actual=e.target;
            reject(()->id.verifyLive(e.context));check(LocalSocket.connections==2,"one failed connection, no retry");
        }});
        one("unauthorized_peer_refuses_before_request_bytes",()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            QualificationScopeConfig.CompletionInstalledIdentity id=identity(e);LocalSocket.peerUid=10001;ProfileCatalogueClient.actual=e.target;
            reject(()->id.verifyLive(e.context));check(LocalSocket.connections==2,"one peer check");
            check(LocalSocket.events.get(LocalSocket.events.size()-1).equals("close"),"socket always closed");
        }});
        one("public_scope_shell_peer_refuses_before_request_bytes",()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            JSONObject request=(JSONObject)ProfileClientPort.invoke(e.session,"request",new Class<?>[]{String.class,String.class,long.class},"state",null,SystemClock.now+1800);
            request.put("version",org.trillionnium.hepta.background.BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION);
            LocalSocket.reset();LocalSocket.peerUid=2000;
            reject(()->ProfileClientPort.invoke(e.session,"exchange",new Class<?>[]{String.class,String.class,JSONObject.class,int.class},
                    e.session.socketName,e.session.generation,request,2300));
            check(LocalSocket.connections==1&&LocalSocket.sent.length==0&&!LocalSocket.events.contains("output"),"public scope rejects shell before request output");
        }});
        replyMutation("unverified_profile_identity_refuses", (e,r)->r.put("profile_current_identity_verified",false));
        replyMutation("wrong_request_id_refuses",(e,r)->r.put("request_id","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
        replyMutation("wrong_generation_refuses",(e,r)->r.put("generation","bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"));
        replyMutation("wrong_virtual_display_refuses",(e,r)->r.put("display_id",8));
        replyMutation("physical_display_refuses",(e,r)->r.put("display_id",0));
        replyMutation("released_during_live_rpc_refuses",(e,r)->r.put("state","RELEASED"));
        replyMutation("rpc_failure_refuses",(e,r)->r.put("ok",false).put("error","synthetic-refusal"));
        replyMutation("expiry_during_live_rpc_refuses",(e,r)->SystemClock.now=e.session.expiresElapsed);
        for(String key:Arrays.asList("serial","uid","version","apk","split","signer","component","package")){
            final String field=key;
            replyMutation("changed_"+key+"_refuses",(e,r)->r.put("profile_target_wire",changed(e.target,field).wire()));
        }
        one("terminal_verify_after_release_uses_original_catalogue_only",()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            QualificationScopeConfig.CompletionInstalledIdentity id=identity(e);released(e);ProfileCatalogueClient.actual=e.target;
            LocalSocket.missing=true;id.verify(e.context);check(LocalSocket.connections==1,"terminal check never needs the retired broker");
            ProfileCatalogueClient.actual=changed(e.target,"apk");reject(()->id.verify(e.context));
            check(LocalSocket.connections==1,"terminal identity change cannot use live success");
        }});
        one("terminal_verify_has_no_live_fallback_when_catalogue_unavailable",()->{try(NativeProfileIdentityHostTest.Env e=flight()){
            QualificationScopeConfig.CompletionInstalledIdentity id=identity(e);ProfileCatalogueClient.actual=null;
            reject(()->id.verify(e.context));check(LocalSocket.connections==1,"terminal catalogue failure is final");
        }});
        JSONObject report=new JSONObject().put("schema","hepta.native-profile-live-identity-host.v1").put("all_pass",true)
            .put("cases",names.size()).put("assertions",assertions).put("case_names",new JSONArray(names))
            .put("actual_completion_identity_and_background_session",true).put("controller_live_callsite_extracts_executed",true)
            .put("android_socket_display_clock_and_catalogue_io_are_host_ports",true)
            .put("phone_actions",0).put("model_runs",0).put("device_latency_measured",false).put("business_verified",false);
        Files.write(output,(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(report.toString());
    }
}
