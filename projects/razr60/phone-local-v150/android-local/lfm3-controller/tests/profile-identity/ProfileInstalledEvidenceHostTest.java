package org.trillionnium.hepta.local;
import java.lang.reflect.Constructor;
import java.util.Collections;
import java.util.Map;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;
/** Actual constructor/evidence; no PM, Android or phone calls. */
public final class ProfileInstalledEvidenceHostTest {
    private static int assertions;
    private static void check(boolean v){assertions++;if(!v)throw new AssertionError("profile evidence mismatch");}
    public static void main(String[] args)throws Exception{
        String hash=String.join("",Collections.nCopies(64,"a"));
        ProfileTarget target=new ProfileTarget(new ProfileIdentity(10,20,0,ProfileIdentity.MANAGED),1010367,
                ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.android.view.SplashActivity",1779,
                Collections.singletonMap("base",hash),Collections.singleton(hash));
        Constructor<QualificationScopeConfig.CompletionInstalledIdentity> ctor=
                QualificationScopeConfig.CompletionInstalledIdentity.class.getDeclaredConstructor(ProfileTarget.class);
        ctor.setAccessible(true);
        QualificationScopeConfig.CompletionInstalledIdentity installed=ctor.newInstance(target);
        Map<String,Object> e=installed.evidence();
        check(Long.valueOf(1779).equals(e.get("version_code")));
        check(Integer.valueOf(1010367).equals(e.get("uid")));
        check(target.apkSetSha256.equals(e.get("apk_set_sha256")));
        check(target.evidence().equals(e.get("profile_target")));
        check("privileged_target_user_package_manager_and_full_apk_hash".equals(e.get("source")));
        System.out.println("{\"all_pass\":true,\"cases\":1,\"assertions\":"+assertions+",\"phone_actions\":0,\"actual_constructor_and_evidence\":true,\"package_manager_called\":false}");
    }
}
