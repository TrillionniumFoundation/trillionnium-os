package org.trillionnium.hepta.local;
import java.nio.file.Files;
import java.util.Collections;
import org.trillionnium.hepta.background.ProfileTarget;
public final class PersonalModeHostTest {
    static int cases,checks;
    interface Work{void run()throws Exception;}
    static void yes(boolean v){checks++;if(!v)throw new AssertionError("personal mode boundary");}
    static void no(Work w)throws Exception{try{w.run();}catch(Exception expected){checks++;return;}throw new AssertionError("unsupported mode accepted");}
    static void test(String name,Work w)throws Exception{BackgroundUiPreferences.saved.clear();BackgroundUiPreferences.writes=0;BackgroundUiPreferences.commitAllowed=true;android.os.SystemClock.now=1000000;android.provider.Settings.Global.boot=10;android.net.LocalSocket.reset();w.run();yes(android.net.LocalSocket.connections==0);cases++;System.out.println("PASS "+name);}
    static ModeUiFixture ui()throws Exception{ModeUiFixture u=new ModeUiFixture(Files.createTempDirectory("hepta-personal-mode-").toFile());u.restore();u.install();return u;}
    static BackgroundTaskTarget target(String pkg,ProfileTarget p){return BackgroundTaskTarget.resolveExplicitSelection("打开应用",pkg,Collections.singleton(pkg),p);}
    public static void main(String[] args)throws Exception{
        test("old absent choice remains legacy and does not enable personal mode",()->{ModeUiFixture u=ui();yes(!u.selected()&&!u.personalSelected()&&BackgroundUiPreferences.writes==0);});
        for(String pkg:new String[]{"com.motorola.stylus","com.xiaomi.shop"})test("explicit visible personal choice accepts only "+pkg,()->{ModeUiFixture u=ui();u.personalPackage=pkg;u.independentPersonalDisplay.click();yes(u.personalSelected()&&!u.selected());BackgroundSession.Selection s=new BackgroundSession.Selection(target(pkg,null),false,true);yes(s.independentPersonalDisplay&&!s.independentProfileDisplay);yes("public_own_group_personal_no_credentials_v1".equals(s.json().getString("display_scope_mode")));BackgroundSession b=ModeFactoryFixture.create(u,ModeActivationHostTest.TASK,"打开应用",s,new QualificationScopeConfig.FilesRoot(u));yes(b.usesExperimentalPublicOwnGroup()&&b.profileTarget()==null);});
        test("personal mode cannot silently select another app",()->{ModeUiFixture u=ui();u.personalPackage="ctrip.android.view";u.independentPersonalDisplay.click();no(u::personalSelected);no(()->new BackgroundSession.Selection(target(u.personalPackage,null),false,true));yes(BackgroundUiPreferences.writes==0);});
        test("profile target cannot enter personal mode",()->{ModeUiFixture u=ui();u.target=ProfileSessionHostTest.target(20);u.independentPersonalDisplay.click();no(u::personalSelected);no(()->new BackgroundSession.Selection(target(u.target.packageName,u.target),false,true));});
        test("explicit profile selection clears only personal display choice atomically",()->{ModeUiFixture u=ui();u.independentPersonalDisplay.click();u.target=ProfileSessionHostTest.target(20);u.independentProfileDisplay.click();yes(u.selected()&&!u.personalSelected()&&!u.independentPersonalDisplay.isChecked());});
        test("explicit personal choice does not reinterpret old stored profile true",()->{BackgroundUiPreferences.saved.put("independent_profile_display",true);ModeUiFixture u=ui();yes(u.independentProfileDisplay.isChecked()&&!u.personalSelected());no(u::selected);u.independentPersonalDisplay.click();yes(u.personalSelected()&&!u.selected());});
        for(String state:new String[]{"hidden","focus","busy","lease","permission"})test("personal mode cannot change while "+state,()->{ModeUiFixture u=ui();if("hidden".equals(state))u.independentPersonalDisplay.shown=false;if("focus".equals(state))u.focus=false;if("busy".equals(state))u.tasks.running=true;if("lease".equals(state))u.tasks.lease=true;if("permission".equals(state))u.backgroundPermission.busy=true;u.independentPersonalDisplay.click();yes(!u.personalSelected()&&BackgroundUiPreferences.writes==0);});
        test("conflicting persisted choices block Start",()->{ModeUiFixture u=ui();BackgroundUiPreferences.saved.put("independent_profile_display",true);BackgroundUiPreferences.saved.put("independent_personal_display",true);u.restore();no(u::selected);no(u::personalSelected);});
        test("malformed personal choice never falls back to legacy",()->{ModeUiFixture u=ui();BackgroundUiPreferences.saved.put("independent_personal_display","true");u.restore();no(u::personalSelected);no(u::selected);});
        test("UI and saved personal choice must still match at Start",()->{ModeUiFixture u=ui();u.independentPersonalDisplay.setChecked(true);no(u::personalSelected);});
        test("selection cannot carry both display modes",()->no(()->new BackgroundSession.Selection(target("com.motorola.stylus",null),true,true)));
        test("changing target after a personal opt-in blocks without task migration",()->{ModeUiFixture u=ui();u.independentPersonalDisplay.click();u.personalPackage="com.other.app";no(u::personalSelected);yes(Boolean.TRUE.equals(BackgroundUiPreferences.saved.get("independent_personal_display")));});
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+checks+",\"passed\":true,\"phone_contacted\":false}");
    }
}
