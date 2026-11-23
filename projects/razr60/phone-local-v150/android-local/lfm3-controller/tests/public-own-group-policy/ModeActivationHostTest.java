package org.trillionnium.hepta.local;

import android.content.Context;
import android.net.LocalSocket;
import java.nio.file.*;
import java.util.*;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;

/** Full actual Selection and Session constructors, exact new preference/UI mode
 * methods and exact normal-Start factory branch. IO/widgets are explicit fakes. */
public final class ModeActivationHostTest {
    static final String TASK="11111111111111111111111111111111",OWNER="打开携程";
    static int cases,assertions;
    interface Work{void run()throws Exception;}
    static void yes(boolean v){assertions++;if(!v)throw new AssertionError("mode activation boundary failed");}
    static void no(Work w)throws Exception{try{w.run();}catch(Exception expected){assertions++;return;}throw new AssertionError("invalid mode activated");}
    static void test(String name,Work w)throws Exception{BackgroundUiPreferences.saved.clear();BackgroundUiPreferences.commitAllowed=true;BackgroundUiPreferences.writes=0;LocalSocket.reset();android.os.SystemClock.now=1000000;android.provider.Settings.Global.boot=10;w.run();yes(LocalSocket.connections==0);cases++;System.out.println("PASS "+name);}
    static BackgroundTaskTarget target(ProfileTarget profile){String pkg=profile==null?"com.example.app":profile.packageName;return BackgroundTaskTarget.resolveExplicitSelection(OWNER,pkg,Collections.singleton(pkg),profile);}
    static ModeUiFixture ui()throws Exception{return new ModeUiFixture(Files.createTempDirectory("hepta-mode-ui-activation-").toFile());}
    public static void main(String[] args)throws Exception{
        test("missing display preference is explicit legacy default and performs no write",()->{ModeUiFixture u=ui();u.restore();yes(!u.selected()&&!u.independentProfileDisplay.isChecked()&&BackgroundUiPreferences.writes==0);});
        for(Object bad:new Object[]{"true",Integer.valueOf(1),null})test("malformed preference is blocked until a new visible choice",()->{ModeUiFixture u=ui();BackgroundUiPreferences.saved.put("independent_profile_display",bad);u.restore();no(u::selected);yes(u.backgroundDisplayPreferenceError!=null&&BackgroundUiPreferences.writes==0);});
        test("visible idle profile checkbox saves the actual choice",()->{ModeUiFixture u=ui();u.target=ProfileSessionHostTest.target(20);u.restore();u.install();u.independentProfileDisplay.click();yes(u.selected()&&BackgroundUiPreferences.writes==1);yes(u.refreshes==1);});
        test("no profile target cannot select independent mode or migrate personal app",()->{ModeUiFixture u=ui();u.restore();u.install();u.independentProfileDisplay.click();yes(BackgroundUiPreferences.writes==0);no(u::selected);no(()->new BackgroundSession.Selection(target(null),true));});
        for(String blocked:new String[]{"focus","hidden","running","model_busy","blocked","recovering","lease","permission"})test("mode change refused while "+blocked,()->{ModeUiFixture u=ui();u.target=ProfileSessionHostTest.target(20);u.restore();u.install();
            if("focus".equals(blocked))u.focus=false;if("hidden".equals(blocked))u.independentProfileDisplay.shown=false;
            if("running".equals(blocked))u.tasks.running=true;if("model_busy".equals(blocked))u.engine.busy=true;
            if("blocked".equals(blocked))u.tasks.blocked=true;if("recovering".equals(blocked))u.tasks.recovering=true;
            if("lease".equals(blocked))u.tasks.lease=true;if("permission".equals(blocked))u.backgroundPermission.busy=true;
            u.independentProfileDisplay.click();yes(!u.selected()&&BackgroundUiPreferences.writes==0);
        });
        test("commit failure cannot silently authorize a checked mode",()->{ModeUiFixture u=ui();u.target=ProfileSessionHostTest.target(20);u.restore();u.install();BackgroundUiPreferences.commitAllowed=false;u.independentProfileDisplay.click();no(u::selected);yes(u.backgroundDisplayPreferenceError!=null);});
        test("saved mode and visible checkbox must agree at Start",()->{ModeUiFixture u=ui();u.target=ProfileSessionHostTest.target(20);u.restore();u.independentProfileDisplay.setChecked(true);no(u::selected);yes(BackgroundUiPreferences.writes==0);});
        test("profile selection removal keeps mode blocked rather than falling back",()->{ModeUiFixture u=ui();u.target=ProfileSessionHostTest.target(20);u.restore();u.install();u.independentProfileDisplay.click();u.target=null;no(u::selected);yes(Boolean.TRUE.equals(BackgroundUiPreferences.saved.get("independent_profile_display")));});
        test("final Selection binds requested mode to same original authorization object",()->{ProfileTarget p=ProfileSessionHostTest.target(20);BackgroundTaskTarget t=target(p);BackgroundSession.Selection independent=new BackgroundSession.Selection(t,true),legacy=new BackgroundSession.Selection(t,false);
            TaskAuthorization original=TaskAuthorization.parse(OWNER),auth=original.forExecutionSelection(independent);
            independent.requireTaskTarget(OWNER,auth);yes(original.allowedTools.containsAll(auth.allowedTools));
            no(()->legacy.requireTaskTarget(OWNER,auth));no(()->new BackgroundSession.Selection(t,true).requireTaskTarget(OWNER,auth));
            no(()->independent.requireTaskTarget("查看其它应用",auth));
            JSONObject request=independent.json();yes(request.getString("display_scope_mode").equals("public_own_group_no_credentials_v1")&&!request.getBoolean("display_scope_mode_grants_authority"));
            yes(!legacy.json().has("display_scope_mode")&&!legacy.independentProfileDisplay);
        });
        test("exact ordinary Start branch picks root-scope factory only for captured explicit mode",()->{Path root=Files.createTempDirectory("hepta-mode-factory-");Context context=new Context(root.toFile());ProfileTarget profile=ProfileSessionHostTest.target(20);BackgroundTaskTarget t=target(profile);
            BackgroundSession.Selection independent=new BackgroundSession.Selection(t,true),legacy=new BackgroundSession.Selection(t,false);
            BackgroundSession a=ModeFactoryFixture.create(context,TASK,OWNER,independent,new QualificationScopeConfig.FilesRoot(context));
            BackgroundSession b=ModeFactoryFixture.create(context,TASK,OWNER,legacy,new QualificationScopeConfig.FilesRoot(context));
            yes(a.usesExperimentalPublicOwnGroup()&&!b.usesExperimentalPublicOwnGroup());yes(a.selection==independent&&b.selection==legacy);
            yes(a.profileTarget().same(profile)&&a.ownerSha256.equals(b.ownerSha256));yes(a.displayId()==-1&&b.displayId()==-1);
            Files.delete(root);
        });
        test("factory refusal does not retry legacy construction",()->{Path root=Files.createTempDirectory("hepta-mode-expired-boot-");Context context=new Context(root.toFile());BackgroundSession.Selection independent=new BackgroundSession.Selection(target(ProfileSessionHostTest.target(20)),true);
            android.provider.Settings.Global.boot=-1;no(()->ModeFactoryFixture.create(context,TASK,OWNER,independent,new QualificationScopeConfig.FilesRoot(context)));Files.delete(root);
        });
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+assertions+",\"passed\":true,\"normal_start_branch_exact\":true,\"mode_ui_methods_exact\":true,\"phone_contacted\":false}");
    }
}
