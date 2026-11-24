package org.trillionnium.hepta.local;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.*;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;

/** Actual preference transactions and exact owner-choice UI bodies; Android IO is a host port. */
public final class BackgroundUiChoiceHostTest {
    private static int cases,checks;
    private interface Checked {void run()throws Exception;}
    private static void check(boolean yes,String message){checks++;if(!yes)throw new AssertionError(message);}
    private static void run(Checked test)throws Exception{test.run();cases++;}
    private static Context context(){
        Context c=new Context();
        c.getPackageManager().install("com.motorola.stylus",10101,new byte[]{1,2,3});
        c.getPackageManager().install("com.xiaomi.shop",10102,new byte[]{4,5,6});
        c.getPackageManager().install("com.example.browser",10103,new byte[]{7,8,9});
        return c;
    }
    private static ProfileTarget profile(String pkg){
        String hash="1111111111111111111111111111111111111111111111111111111111111111";
        return new ProfileTarget(new ProfileIdentity(10,10,0,ProfileIdentity.MANAGED),1010123,pkg,pkg+"/Main",
                1,Collections.singletonMap("base",hash),Collections.singleton(hash));
    }
    private static SharedPreferences.Memory memory(Context c){return c.getSharedPreferences("background-ui-choice-v1",Context.MODE_PRIVATE);}
    private static void clearModes(MainActivity ui)throws Exception{
        check(!BackgroundUiPreferences.independentProfileDisplay(ui)&&!BackgroundUiPreferences.independentPersonalDisplay(ui),"incompatible saved flags must be cleared");
        check(!ui.independentProfileDisplay.isChecked()&&!ui.independentPersonalDisplay.isChecked(),"visible checkboxes must match the committed flags");
        check(ui.backgroundDisplayPreferenceError==null&&ui.backgroundSelectionPreferenceError==null,"a successful explicit target choice must not leave a mode mismatch");
        check(!ui.profileSelected()&&!ui.personalSelected(),"Start readers must accept the synchronized choices without enabling a new mode");
    }
    public static void main(String[] args)throws Exception{
        run(()->{
            Context c=context();MainActivity ui=new MainActivity(c);ui.choosePersonal("com.motorola.stylus");
            clearModes(ui);
            check(BackgroundUiPreferences.load(c).initial.equals("com.motorola.stylus"),"actual preference reader must recover the selected target");
            check(memory(c).commits==1,"selection and compatibility cleanup use one Editor commit");
        });
        run(()->{
            Context c=context();MainActivity ui=new MainActivity(c);ui.choosePersonal("com.motorola.stylus");
            BackgroundUiPreferences.saveIndependentPersonalDisplay(c,true);ui.restore();
            ProfileTarget target=profile(ProfileTarget.CTRIP);ui.chooseProfile(target);
            clearModes(ui);
            check(BackgroundUiPreferences.load(c).profileTarget.same(target),"personal-to-profile choice retains the exact profile identity");
            check(ui.rememberedBackgroundSelection.profileTarget.same(target),"the visible profile selection matches persisted identity");
        });
        run(()->{
            Context c=context();MainActivity ui=new MainActivity(c);ui.chooseProfile(profile(ProfileTarget.CTRIP));
            BackgroundUiPreferences.saveIndependentProfileDisplay(c,true);ui.restore();
            ui.choosePersonal("com.motorola.stylus");clearModes(ui);
            check(BackgroundUiPreferences.load(c).profileTarget==null,"profile-to-personal selection does not retain a hidden profile target");
        });
        run(()->{
            Context c=context();MainActivity ui=new MainActivity(c);ui.choosePersonal("com.motorola.stylus");
            BackgroundUiPreferences.saveIndependentPersonalDisplay(c,true);ui.restore();ui.choosePersonal("com.xiaomi.shop");
            check(BackgroundUiPreferences.independentPersonalDisplay(c)&&ui.independentPersonalDisplay.isChecked()&&ui.personalSelected(),"compatible personal target preserves the owner's existing display choice");
            check(!BackgroundUiPreferences.independentProfileDisplay(c)&&!ui.independentProfileDisplay.isChecked(),"compatible personal choice cannot retain profile mode");
        });
        run(()->{
            Context c=context();MainActivity ui=new MainActivity(c);ui.choosePersonal("com.motorola.stylus");
            BackgroundUiPreferences.saveIndependentPersonalDisplay(c,true);ui.restore();ui.choosePersonal("com.example.browser");
            clearModes(ui);
            check(BackgroundUiPreferences.load(c).initial.equals("com.example.browser"),"incompatible display flag is cleared without replacing the selected app");
        });
        run(()->{
            Context c=context();MainActivity ui=new MainActivity(c);ui.chooseProfile(profile(ProfileTarget.CTRIP));
            BackgroundUiPreferences.saveIndependentProfileDisplay(c,true);ui.restore();ui.chooseProfile(profile(ProfileTarget.XIAOMI));
            check(BackgroundUiPreferences.independentProfileDisplay(c)&&ui.independentProfileDisplay.isChecked()&&ui.profileSelected(),"compatible profile target preserves profile mode");
            check(!BackgroundUiPreferences.independentPersonalDisplay(c)&&!ui.independentPersonalDisplay.isChecked(),"profile selection keeps personal mode off");
        });
        run(()->{
            Context c=context();MainActivity ui=new MainActivity(c);
            ui.choosePersonalRange(new TreeSet<String>(Arrays.asList("com.motorola.stylus","com.example.browser")),"com.motorola.stylus");
            BackgroundUiPreferences.saveIndependentPersonalDisplay(c,true);ui.restore();ui.chooseInitial("com.example.browser");
            clearModes(ui);
            check(BackgroundUiPreferences.load(c).initial.equals("com.example.browser"),"the exact spinner save path persists the new initial target");
            check(ui.rememberedBackgroundSelection.packages.size()==2,"changing the initial app preserves the explicitly chosen range");
        });
        run(()->{
            Context c=context();MainActivity ui=new MainActivity(c);ui.choosePersonal("com.motorola.stylus");
            BackgroundUiPreferences.saveIndependentPersonalDisplay(c,true);
            int before=memory(c).commits;ProfileTarget target=profile(ProfileTarget.CTRIP);
            BackgroundUiPreferences.save(c,BackgroundUiPreferences.captureProfile(target));
            check(memory(c).commits==before+1,"switching the target and clearing its incompatible flag must not use separate commits");
            check(BackgroundUiPreferences.load(c).profileTarget.same(target)&&!BackgroundUiPreferences.independentPersonalDisplay(c),"one committed selection contains compatible display state");
            check(!BackgroundUiPreferences.independentProfileDisplay(c),"selection save never automatically grants profile display mode");
        });
        System.out.println("{\"passed\":true,\"cases\":"+cases+",\"assertions\":"+checks+",\"phone_operations\":0}");
    }
}
