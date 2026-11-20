package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Actual Selection producer and full PhoneObservation constructor/parser.
 * Android frame/JSON IO is synthetic; no live window, RPC or action authority. */
public final class ObservationDisplayScopeHostTest {
    private static final String OWNER="打开应用",HASH=String.join("",Collections.nCopies(64,"a"));
    private static final String GENERATION="11111111-1111-4111-8111-111111111111";
    private static final String TOKEN="22222222-2222-4222-8222-222222222222";
    private static final String PROOF="33333333-3333-4333-8333-333333333333";
    private static final String PROFILE_MODE="public_own_group_no_credentials_v1";
    private static final String PERSONAL_MODE="public_own_group_personal_no_credentials_v1";
    private static int assertions;
    private static final List<String> cases=new ArrayList<String>();
    interface Work {void run()throws Exception;}
    static void yes(boolean condition){assertions++;if(!condition)throw new AssertionError("observation/display Selection boundary");}
    static void reject(Work work)throws Exception{
        try{work.run();}catch(IllegalArgumentException expected){assertions++;return;}
        throw new AssertionError("malformed/foreign display Selection admitted");
    }
    static void test(String name,Work work)throws Exception{
        android.net.LocalSocket.reset();work.run();yes(android.net.LocalSocket.connections==0);
        cases.add(name);System.out.println("PASS "+name);
    }
    static ProfileTarget profile(int user,long serial){
        Map<String,String> apks=new LinkedHashMap<String,String>();apks.put("base",HASH);
        return new ProfileTarget(new ProfileIdentity(user,serial,0,ProfileIdentity.MANAGED),user*100000+10367,
                ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.android.view.SplashActivity",1779,apks,
                Collections.singleton(String.join("",Collections.nCopies(64,"b"))));
    }
    static BackgroundSession.Selection selection(String pkg,ProfileTarget target,boolean profileMode,boolean personalMode){
        BackgroundTaskTarget actual=BackgroundTaskTarget.resolveExplicitSelection(OWNER,pkg,Collections.singleton(pkg),target);
        return new BackgroundSession.Selection(actual,profileMode,personalMode);
    }
    static WindowOwnership window(ProfileTarget target,String generation,int display,int window){
        return target==null?null:new WindowOwnership(target,generation,display,window,441,440,TOKEN,PROOF,
                target.profile.userId,target.profile.serial,target.fullUid,900,1900);
    }
    static PhoneObservation build(BackgroundSession.Selection selected,JSONObject json,WindowOwnership window,
            String generation,int display,int windowId,long now)throws Exception{
        return new PhoneObservation("44444444444444444444444444444444",selected.initialPackage,now,720,1280,0,windowId,
                new Rect(0,0,720,1280),new File("synthetic-never-read.png"),HASH,HASH,
                new ObservationState(HASH,ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,720,1280},"android.widget.FrameLayout",1,display,
                        new int[]{0,0,720,1280},"synthetic title"),false,Collections.<PhoneObservation.Node>emptyList(),
                generation,selected.initialPackage,selected.allowedPackages,null,json,
                selected.taskTarget.ownerSha256,null,window);
    }
    static PhoneObservation build(BackgroundSession.Selection selected,JSONObject json)throws Exception{
        return build(selected,json,window(selected.profileTarget,GENERATION,7,42),GENERATION,7,42,1000);
    }
    static void preserved(BackgroundSession.Selection selected)throws Exception{
        JSONObject original=selected.json();PhoneObservation observed=build(selected,original);
        yes(observed.backgroundSelectionEvidence().toString().equals(original.toString()));
        JSONObject evidence=observed.toEvidenceJson().getJSONObject("background_session");
        yes(evidence.getInt("display_id")==7&&GENERATION.equals(evidence.getString("generation")));
        if(original.has("display_scope_mode")){
            yes(original.getString("display_scope_mode").equals(evidence.getString("display_scope_mode")));
            yes(Boolean.FALSE.equals(evidence.get("display_scope_mode_grants_authority")));
        }else yes(!evidence.has("display_scope_mode"));
        if(selected.profileTarget!=null){
            yes(observed.profileTarget.same(selected.profileTarget)&&observed.profileWindow!=null);
            yes(Boolean.FALSE.equals(evidence.getJSONObject("actual_profile_window").get("grants_action_authority")));
        }else yes(observed.profileTarget==null&&observed.profileWindow==null);
        original.put("main_display_fallback",true);
        yes(Boolean.FALSE.equals(observed.backgroundSelectionEvidence().get("main_display_fallback")));
    }
    public static void main(String[] args)throws Exception{
        final ProfileTarget target=profile(10,10);
        final BackgroundSession.Selection scoped=selection(ProfileTarget.CTRIP,target,true,false);
        final BackgroundSession.Selection personal=selection("com.motorola.stylus",null,false,true);
        // First case is also the actual pre-fix regression trigger.
        test("actual profile Selection JSON reaches full ordinary observation unchanged",()->preserved(scoped));
        test("actual Notes personal Selection JSON reaches full ordinary observation",()->preserved(personal));
        test("actual MiShop personal Selection JSON reaches full ordinary observation",()->preserved(selection("com.xiaomi.shop",null,false,true)));
        test("legacy profile Selection remains unchanged",()->preserved(selection(ProfileTarget.CTRIP,target,false,false)));
        test("legacy user0 Selection remains unchanged",()->preserved(selection("com.motorola.stylus",null,false,false)));
        final List<String> modeKeys=Arrays.asList("display_scope_mode","display_scope_mode_source","display_scope_mode_grants_authority");
        for(int mask=1;mask<7;mask++){
            final int removed=mask;
            test("partial display provenance rejected mask "+mask,()->{
                JSONObject json=scoped.json();for(int i=0;i<3;i++)if((removed&(1<<i))!=0)json.remove(modeKeys.get(i));
                reject(()->build(scoped,json));
            });
        }
        for(Object mode:new Object[]{"future_mode",Boolean.TRUE,Integer.valueOf(1),JSONObject.NULL})
            test("unknown/non-string mode rejected "+mode,()->{JSONObject json=scoped.json().put("display_scope_mode",mode);reject(()->build(scoped,json));});
        for(Object source:new Object[]{"model_output","screen_text",Boolean.TRUE,JSONObject.NULL})
            test("non-immutable/non-string source rejected "+source,()->{JSONObject json=scoped.json().put("display_scope_mode_source",source);reject(()->build(scoped,json));});
        for(Object authority:new Object[]{Boolean.TRUE,"false",Integer.valueOf(0),JSONObject.NULL})
            test("authority must be Boolean false "+authority,()->{JSONObject json=scoped.json().put("display_scope_mode_grants_authority",authority);reject(()->build(scoped,json));});
        test("personal mode cannot carry profile target",()->{JSONObject json=scoped.json().put("display_scope_mode",PERSONAL_MODE);reject(()->build(scoped,json));});
        test("profile mode requires actual profile wire",()->{JSONObject json=personal.json().put("display_scope_mode",PROFILE_MODE);reject(()->build(personal,json));});
        test("personal Ctrip user0 unsupported",()->{
            BackgroundSession.Selection legacy=selection(ProfileTarget.CTRIP,null,false,false);
            JSONObject json=legacy.json().put("display_scope_mode",PERSONAL_MODE).put("display_scope_mode_source","immutable_start_selection")
                    .put("display_scope_mode_grants_authority",false);reject(()->build(legacy,json));
        });
        test("profile mode requires immutable owner derivation",()->{JSONObject json=scoped.json();json.remove("owner_task_selection");json.put("bootstrap_source","owner_selected_initial_app");reject(()->build(scoped,json));});
        test("new scope cannot reinterpret changed initial app",()->{
            JSONObject json=scoped.json(),owner=json.getJSONObject("owner_task_selection");
            owner.put("original_ui_initial_package","com.motorola.stylus").put("original_ui_allowed_packages",new org.json.JSONArray(Arrays.asList("com.motorola.stylus",ProfileTarget.CTRIP)))
                    .put("initial_app_changed",true).put("effective_scope_strictly_smaller",true);json.put("owner_task_selection",owner);
            reject(()->build(scoped,json));
        });
        test("mode does not permit unknown Selection key",()->{JSONObject json=scoped.json().put("trusted_scope",true);reject(()->build(scoped,json));});
        test("legacy unknown Selection key still rejected",()->{
            BackgroundSession.Selection legacy=selection("com.motorola.stylus",null,false,false);reject(()->build(legacy,legacy.json().put("trusted_scope",true)));
        });
        test("profile digest cannot differ from canonical wire",()->{JSONObject json=scoped.json().put("profile_target_sha256",String.join("",Collections.nCopies(64,"c")));reject(()->build(scoped,json));});
        test("profile wire without digest refused",()->{JSONObject json=scoped.json();json.remove("profile_target_sha256");reject(()->build(scoped,json));});
        test("profile wire has no implicit parse fallback",()->{JSONObject json=scoped.json().put("profile_target_wire","bad_wire");reject(()->build(scoped,json));});
        test("foreign target wire and digest cannot reuse original observed window",()->{
            ProfileTarget foreign=profile(11,11);JSONObject json=scoped.json().put("profile_target_wire",foreign.wire()).put("profile_target_sha256",foreign.sha256);
            reject(()->build(scoped,json));
        });
        test("foreign full UID/profile window rejected",()->reject(()->build(scoped,scoped.json(),window(profile(11,11),GENERATION,7,42),GENERATION,7,42,1000)));
        test("changed profile serial rejected",()->reject(()->build(scoped,scoped.json(),window(profile(10,20),GENERATION,7,42),GENERATION,7,42,1000)));
        test("stale actual profile window rejected",()->reject(()->build(scoped,scoped.json(),window(target,GENERATION,7,42),GENERATION,7,42,1900)));
        test("wrong generation actual profile window rejected",()->reject(()->build(scoped,scoped.json(),window(target,TOKEN,7,42),GENERATION,7,42,1000)));
        test("wrong display actual profile window rejected",()->reject(()->build(scoped,scoped.json(),window(target,GENERATION,8,42),GENERATION,7,42,1000)));
        test("wrong AX window rejected",()->reject(()->build(scoped,scoped.json(),window(target,GENERATION,7,43),GENERATION,7,42,1000)));
        test("missing live profile window not replaced by JSON mode",()->reject(()->build(scoped,scoped.json(),null,GENERATION,7,42,1000)));
        test("user0 mode cannot accept any profile window",()->reject(()->build(personal,personal.json(),window(target,GENERATION,7,42),GENERATION,7,42,1000)));
        test("main display remains refused by observed-window constructor",()->reject(()->build(personal,personal.json(),null,GENERATION,0,42,1000)));
        test("legacy-shaped projection cannot preserve actual scoped producer fingerprint",()->{
            JSONObject stripped=scoped.json();for(String key:modeKeys)stripped.remove(key);
            PhoneObservation legacy=build(scoped,stripped);
            yes(!legacy.backgroundSelectionEvidence().toString().equals(scoped.json().toString()));
        });
        test("wrong owner hash remains refused",()->{
            JSONObject json=scoped.json(),owner=json.getJSONObject("owner_task_selection");owner.put("owner_sha256",HASH);json.put("owner_task_selection",owner);reject(()->build(scoped,json));
        });
        JSONObject result=new JSONObject().put("schema","hepta.observation-display-scope.host.v1").put("all_pass",true)
                .put("cases",cases.size()).put("assertions",assertions).put("names",new org.json.JSONArray(cases))
                .put("full_phone_observation_class",true).put("actual_selection_producer",true)
                .put("android_runtime",false).put("phone_actions",0).put("host_fixture_is_live_window_proof",false);
        Files.write(Paths.get(args[0]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(result.toString());
    }
}
