package org.trillionnium.hepta.local;

import android.content.Context;
import android.net.LocalSocket;
import android.os.SystemClock;
import android.view.Display;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Actual NativeAppSession/BackgroundSession and exact CompletionInstalledIdentity.
 * Android displays, authenticated socket and installed verifier are explicit host
 * IO ports. No observed phone identity, Android launch or business result is claimed. */
public final class NativeProfileIdentityHostTest {
    static final String TASK="11111111111111111111111111111111";
    static final String GENERATION="22345678-1234-4234-8234-123456789012";
    static final String OWNER="在小米商城查询小米AX3000T价格";
    static final String FLIGHT="在携程查询2026年11月21日北京到上海的单程机票，1名成人";
    static final String APK="95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373";
    static final String HASH=NativeAppEvidence.hash("synthetic-selection");
    static final List<String> cases=new ArrayList<String>();
    static int assertions;static Path workspace;
    interface Case {void run()throws Exception;}
    static void check(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    static void reject(Case body)throws Exception{boolean refused=false;try{body.run();}catch(IllegalArgumentException|IllegalStateException|IOException expected){refused=true;}check(refused,"expected production identity fence");}
    static void one(String name,Case body)throws Exception{LocalSocket.reset();SystemClock.now=1000000;body.run();cases.add(name);}
    static ProfileTarget target(String pkg,int uid,long serial,long version,String apk){
        String component=pkg.equals(ProfileTarget.XIAOMI)?pkg+"/com.xiaomi.shop2.activity.MainActivity":pkg+"/ctrip.business.splash.CtripSplashActivity";
        return new ProfileTarget(new ProfileIdentity(10,serial,0,ProfileIdentity.MANAGED),uid,pkg,component,version,
                Collections.singletonMap("base",apk),Collections.singleton(NativeAppEvidence.hash("synthetic-signer")));
    }
    static ProfileTarget xiaomi(){return target(ProfileTarget.XIAOMI,1010111,20,20261010,APK);}
    static ProfileTarget ctrip(){return target(ProfileTarget.CTRIP,1010367,20,NativeCtripFlightPage.VERSION_CODE,NativeCtripFlightPage.BASE_APK_SHA256);}
    static BackgroundSession.Selection selection(String owner,ProfileTarget target){
        return new BackgroundSession.Selection(BackgroundTaskTarget.resolveExplicitSelection(owner,target.packageName,Collections.singleton(target.packageName),target));
    }
    static final class Env implements AutoCloseable {
        final Path directory;final Context context;final ProfileTarget target;final BackgroundSession session;final String owner;
        Env(ProfileTarget target,String owner)throws Exception{
            this.target=target;this.owner=owner;directory=Files.createTempDirectory(workspace,"profile-identity-").toRealPath();context=new Context(directory.toFile());
            session=new BackgroundSession(context,TASK,owner,selection(owner,target),new QualificationScopeConfig.FilesRoot(context));
        }
        JSONObject reply(byte[] request,ProfileTarget actual,boolean verified)throws Exception{
            return ProfileClientPort.decode(ProfileClientPort.response(request,"ACTIVE",7,true,false))
                    .put("version",2).put("profile_target_wire",actual.wire()).put("profile_current_identity_verified",verified)
                    .put("expires_elapsed_ms",session.expiresElapsed);
        }
        void active()throws Exception{
            context.displays.displays.put(7,new Display(7,session.displayName));
            JSONObject request=(JSONObject)ProfileClientPort.invoke(session,"request",new Class<?>[]{String.class,String.class,long.class},"state",null,SystemClock.now+3000);
            JSONObject response=reply(ProfileClientPort.frame(request.toString().getBytes(StandardCharsets.UTF_8)),target,true);
            ProfileClientPort.invoke(session,"accept",new Class<?>[]{JSONObject.class,boolean.class},response,true);
            LocalSocket.responder=raw->ProfileClientPort.frame(reply(raw,target,true).toString().getBytes(StandardCharsets.UTF_8));
        }
        QualificationScopeConfig.CompletionInstalledIdentity capture(String instruction,String pkg)throws Exception{
            return QualificationScopeConfig.CompletionInstalledIdentity.captureNativeApp(context,NativeAppGoal.parse(instruction,pkg),session);
        }
        public void close()throws IOException{
            try(java.util.stream.Stream<Path> paths=Files.walk(directory)){
                for(Path p:paths.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(p);
            }
        }
    }
    static final class NativeEnv {
        final ProfileTarget target;final BackgroundSession.Selection selection;final TaskAuthorization auth;
        final List<Map<String,Object>> journal=new ArrayList<Map<String,Object>>();
        int verifies;boolean verifierFail;
        NativeEnv(ProfileTarget target){this.target=target;selection=selection(OWNER,target);auth=TaskAuthorization.parse(OWNER).forExecutionSelection(selection);}
        NativeAppSession session(NativeAppEvidence.Installed installed)throws Exception{
            return new NativeAppSession(TASK,auth.bind(TASK),selection,installed,HASH,GENERATION,7,
                ()->{verifies++;if(verifierFail)throw new IOException("synthetic changed installation");},
                (name,value)->journal.add(new LinkedHashMap<String,Object>(value)));
        }
        WindowOwnership window(ProfileTarget actual){return new WindowOwnership(actual,GENERATION,7,17,1234,1200,
                "33333333-3333-4333-8333-333333333333",UUID.randomUUID().toString(),actual.profile.userId,actual.profile.serial,actual.fullUid,1000000,1001000);}
        NativeAppEvidence.Frame frame(WindowOwnership window){return frame(window,7,target.packageName);}
        NativeAppEvidence.Frame frame(WindowOwnership window,int display,String pkg){
            return new NativeAppEvidence.Frame(TASK,auth.instructionSha256,selection.taskTarget.targetSha256,auth.sha256,HASH,
                "44444444444444444444444444444444",pkg,GENERATION,HASH,HASH,HASH,HASH,HASH,display,17,0,720,1280,0,0,720,1280,
                1000000,false,true,Collections.<NativeAppEvidence.Node>emptyList(),1,true,window);
        }
    }
    public static void main(String[] args)throws Exception{
        workspace=Paths.get(args[1]);Files.createDirectories(workspace);
        one("Xiaomi capture uses actual live profile verification and retains full UID",()->{try(Env e=new Env(xiaomi(),OWNER)){
            e.active();QualificationScopeConfig.CompletionInstalledIdentity id=e.capture(OWNER,ProfileTarget.XIAOMI);
            check(LocalSocket.connections==1,"capture must perform one live state RPC");check(id.profileTarget.same(e.target)&&id.uid==1010111,"profile installation was replaced by user0");
            check(id.apkHashes.get("base").equals(APK)&&id.versionCode==20261010,"full installation identity lost");
            check(id.evidence().get("profile_target") instanceof Map,"profile evidence missing");
        }});
        one("Ctrip capture keeps original target-user identity path",()->{try(Env e=new Env(ctrip(),FLIGHT)){
            e.active();QualificationScopeConfig.CompletionInstalledIdentity id=e.capture(FLIGHT,ProfileTarget.CTRIP);
            check(LocalSocket.connections==1&&id.profileTarget.same(e.target)&&id.uid==1010367,"Ctrip capture changed");
        }});
        one("fresh verification false refuses capture",()->{try(Env e=new Env(xiaomi(),OWNER)){
            e.active();LocalSocket.responder=raw->ProfileClientPort.frame(e.reply(raw,e.target,false).toString().getBytes(StandardCharsets.UTF_8));
            reject(()->e.capture(OWNER,ProfileTarget.XIAOMI));check(LocalSocket.connections==1,"missing live recheck");
        }});
        one("different profile serial in authenticated reply refuses capture",()->{try(Env e=new Env(xiaomi(),OWNER)){
            e.active();ProfileTarget other=target(ProfileTarget.XIAOMI,1010111,21,20261010,APK);
            LocalSocket.responder=raw->ProfileClientPort.frame(e.reply(raw,other,true).toString().getBytes(StandardCharsets.UTF_8));
            reject(()->e.capture(OWNER,ProfileTarget.XIAOMI));
        }});
        one("selected Xiaomi profile cannot capture a Ctrip goal",()->{try(Env e=new Env(xiaomi(),OWNER)){e.active();reject(()->e.capture(FLIGHT,ProfileTarget.CTRIP));}});
        one("unrecognized goal cannot use selected profile",()->{try(Env e=new Env(xiaomi(),OWNER)){e.active();reject(()->e.capture("查询任意型号价格",ProfileTarget.XIAOMI));}});
        one("inactive profile never falls back to ordinary PackageManager",()->{try(Env e=new Env(xiaomi(),OWNER)){reject(()->e.capture(OWNER,ProfileTarget.XIAOMI));check(LocalSocket.connections==0,"inactive session touched transport");}});
        one("expired original profile lease refuses capture",()->{try(Env e=new Env(xiaomi(),OWNER)){e.active();SystemClock.now=e.session.expiresElapsed;reject(()->e.capture(OWNER,ProfileTarget.XIAOMI));check(LocalSocket.connections==0,"expired session touched transport");}});
        one("completion identity reverify rejects changed installation",()->{try(Env e=new Env(xiaomi(),OWNER)){
            e.active();QualificationScopeConfig.CompletionInstalledIdentity id=e.capture(OWNER,ProfileTarget.XIAOMI);
            ProfileCatalogueClient.actual=e.target;id.verify(e.context);
            ProfileCatalogueClient.actual=target(ProfileTarget.XIAOMI,1010111,21,20261010,APK);reject(()->id.verify(e.context));
        }});
        one("actual native Xiaomi session binds exact profile and query remains unverified",()->{
            NativeEnv e=new NativeEnv(xiaomi());NativeAppSession session=e.session(new NativeAppEvidence.Installed(e.target));
            check(session.installed.profileTarget.same(e.target)&&e.verifies==1&&e.journal.size()==1,"native binding did not verify identity");
            check(Boolean.FALSE.equals(e.journal.get(0).get("query_result_verified")),"identity capture claimed a product result");
        });
        one("personal same-package installation cannot replace selected profile",()->{
            NativeEnv e=new NativeEnv(xiaomi());reject(()->e.session(new NativeAppEvidence.Installed(ProfileTarget.XIAOMI,10111,20261010,Collections.singletonMap("base",APK))));
            check(e.verifies==0&&e.journal.isEmpty(),"foreign identity reached verifier/journal");
        });
        one("different full UID cannot replace selected profile",()->{
            NativeEnv e=new NativeEnv(xiaomi());ProfileTarget other=target(ProfileTarget.XIAOMI,1010112,20,20261010,APK);
            reject(()->e.session(new NativeAppEvidence.Installed(other)));check(e.verifies==0&&e.journal.isEmpty(),"foreign full UID reached binding");
        });
        one("different serial cannot replace selected profile",()->{
            NativeEnv e=new NativeEnv(xiaomi());reject(()->e.session(new NativeAppEvidence.Installed(target(ProfileTarget.XIAOMI,1010111,21,20261010,APK))));
        });
        one("unsupported Xiaomi APK remains unqualified",()->{
            ProfileTarget p=target(ProfileTarget.XIAOMI,1010111,20,20261010,HASH);NativeEnv e=new NativeEnv(p);
            reject(()->e.session(new NativeAppEvidence.Installed(p)));check(e.verifies==0&&e.journal.isEmpty(),"unsupported APK produced binding");
        });
        one("unsupported Xiaomi version remains unqualified",()->{
            ProfileTarget p=target(ProfileTarget.XIAOMI,1010111,20,20261011,APK);NativeEnv e=new NativeEnv(p);reject(()->e.session(new NativeAppEvidence.Installed(p)));
        });
        one("failed installation verifier cannot publish native binding",()->{
            NativeEnv e=new NativeEnv(xiaomi());e.verifierFail=true;reject(()->e.session(new NativeAppEvidence.Installed(e.target)));check(e.verifies==1&&e.journal.isEmpty(),"failed verification published binding");
        });
        one("actual native observation retains profile-window identity",()->{
            NativeEnv e=new NativeEnv(xiaomi());NativeAppSession s=e.session(new NativeAppEvidence.Installed(e.target));WindowOwnership w=e.window(e.target);s.observed(e.frame(w));
            check(s.domain().frame.profileWindow==w&&e.verifies==2&&e.journal.size()==2,"actual profile observation did not recheck installation");
        });
        one("profile observation without window proof is rejected",()->{
            NativeEnv e=new NativeEnv(xiaomi());NativeAppSession s=e.session(new NativeAppEvidence.Installed(e.target));reject(()->s.observed(e.frame(null)));check(e.journal.size()==1,"missing window proof published observation");
        });
        one("other profile serial window proof is rejected",()->{
            NativeEnv e=new NativeEnv(xiaomi());NativeAppSession s=e.session(new NativeAppEvidence.Installed(e.target));
            reject(()->s.observed(e.frame(e.window(target(ProfileTarget.XIAOMI,1010111,21,20261010,APK)))));check(e.journal.size()==1,"foreign window published observation");
        });
        one("physical display cannot become native profile frame",()->{
            NativeEnv e=new NativeEnv(xiaomi());reject(()->e.frame(null,0,ProfileTarget.XIAOMI));
        });
        one("same window with foreign package is rejected",()->{
            NativeEnv e=new NativeEnv(xiaomi());NativeAppSession s=e.session(new NativeAppEvidence.Installed(e.target));reject(()->s.observed(e.frame(e.window(e.target),7,ProfileTarget.CTRIP)));
        });
        one("changed installation cannot publish next native observation",()->{
            NativeEnv e=new NativeEnv(xiaomi());NativeAppSession s=e.session(new NativeAppEvidence.Installed(e.target));e.verifierFail=true;reject(()->s.observed(e.frame(e.window(e.target))));check(e.journal.size()==1,"failed fresh installed check published page");
        });
        JSONObject result=new JSONObject().put("schema","hepta.xiaomi-profile-native-identity-host.v1").put("all_pass",true)
            .put("cases",cases.size()).put("assertions",assertions).put("case_names",new JSONArray(cases)).put("phone_actions",0)
            .put("android_transport_and_installation_io_synthetic",true).put("device_qualified",false).put("business_verified",false);
        Files.write(Paths.get(args[0]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(result.toString());
    }
}
