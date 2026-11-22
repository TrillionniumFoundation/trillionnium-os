package org.trillionnium.hepta.background;

import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.Region;
import android.os.Binder;
import android.os.InputConfig;
import android.os.SystemClock;
import android.util.Pair;
import android.view.InputWindowHandle;
import android.view.accessibility.IAccessibilityManager;
import android.window.WindowInfosListener;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONObject;

/** Actual comparison, lifecycle, namespace, parser and extracted broker method, explicit IO ports. */
public final class CalendarWindowHostTest {
    interface Body {void run()throws Exception;}
    static final List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();
    static int assertions;
    static final String GEN="00000000-0000-4000-8000-000000000001";
    static final String RID="00000000-0000-4000-8000-000000000002";
    static final String HASH=repeat('a',64);
    static void check(boolean b,String why){assertions++;if(!b)throw new AssertionError(why);}
    static String repeat(char c,int n){char[] x=new char[n];Arrays.fill(x,c);return new String(x);}
    static void rejected(String expected,Body b)throws Exception{
        try{b.run();throw new AssertionError("expected rejection "+expected);}
        catch(InputChannelIsolation.Refusal e){check(expected.equals(e.code),"actual "+e.code+" expected "+expected);}
        catch(BrokerProtocol.Refusal e){check(expected.equals(e.getMessage()),"actual "+e.getMessage()+" expected "+expected);}
    }
    static void test(String name,Body body){
        int start=assertions;Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        try{body.run();row.put("passed",true);}catch(Throwable e){row.put("passed",false);row.put("failure",e.toString());e.printStackTrace(System.err);}
        row.put("assertions",assertions-start);rows.add(row);
    }
    static final class Fixture {
        final Binder window=new Binder(),input=new Binder(),service=new Binder();
        final ProfileIdentity profile=new ProfileIdentity(10,44,0,ProfileIdentity.MANAGED);
        final ProfileTarget target=new ProfileTarget(profile,1010123,ProfileTarget.CTRIP,"ctrip.android.view/Main",1,
                Collections.singletonMap("base",HASH),Collections.singleton(HASH));
        final ProfilePackages packages=new ProfilePackages(user->{if(user!=10)throw new AssertionError("wrong profile");return profile;});
        final List<Integer> namespaceReads=new ArrayList<Integer>();
        final BrokerProtocol.Config config;
        InputWindowHandle[] windows;
        WindowInfosListener.DisplayInfo[] displays;
        Fixture()throws Exception{
            WindowInfosListener.reset();SystemClock.now=1000;android.os.Process.uid=0;
            android.os.Build.VERSION.SDK_INT=36;android.app.ActivityManager.currentUser=0;
            android.os.ServiceManager.accessibility=service;
            IAccessibilityManager.Stub.service=(id,user)->{if(id!=96)throw new AssertionError("wrong AX window");namespaceReads.add(user);return user==0?window:null;};
            windows=new InputWindowHandle[]{raw(7,1010123,ProfileTarget.CTRIP,input,window,0),raw(0,10099,"fixture.physical",new Binder(),new Binder(),0)};
            displays=new WindowInfosListener.DisplayInfo[]{new WindowInfosListener.DisplayInfo(7,100,200),new WindowInfosListener.DisplayInfo(0,100,200),new WindowInfosListener.DisplayInfo(1,100,200),new WindowInfosListener.DisplayInfo(9,100,200)};
            PublicOwnGroupPolicy.Scope scope=new PublicOwnGroupPolicy.Scope(repeat('b',32),HASH,GEN,10001,target,1000,61000,1);
            config=BrokerProtocol.Config.parse(new String[]{"--socket","hepta-bg-"+GEN,"--owner-uid","10001","--generation",GEN,
                    "--allowed-packages",ProfileTarget.CTRIP,"--ttl-ms","60000","--expires-elapsed-ms","61000",
                    "--profile-target",target.wire(),"--public-own-group-scope",scope.wire()});
        }
        void emit(){WindowInfosListener.last.onWindowInfosChanged(windows,displays);}
        WindowInfosCapture capture()throws Exception{WindowInfosListener.onRegister=this::emit;WindowInfosCapture c=new WindowInfosCapture(5000);c.register();return c;}
        InputChannelIsolation.Expected expected()throws Exception{return new InputChannelIsolation.Expected(7,1010123,10,0,96,100,ProfileTarget.CTRIP,100,200,0,window);}
        InputChannelIsolation.Match inspect()throws Exception{WindowInfosCapture c=capture();try{return InputChannelIsolation.inspect(c.awaitCallback(),expected(),SystemClock.now,5000);}finally{c.unregisterAndDrain(5000);}}
        BrokerProtocol.Request request()throws Exception{return BrokerProtocol.Request.parse(requestObject().toString().getBytes(StandardCharsets.UTF_8));}
        JSONObject requestObject(){return new JSONObject().put("version",4).put("request_id",RID).put("generation",GEN)
                .put("deadline_elapsed_ms",5000).put("op","calendar_probe").put("display_scope_sha256",config.publicOwnGroupScope.sha256)
                .put("target_sha256",target.sha256).put("package",ProfileTarget.CTRIP).put("window_id",96).put("task_id",100);}
        BrokerProbeHost broker(){WindowInfosListener.onRegister=this::emit;return new BrokerProbeHost(config,packages);}
    }
    static InputWindowHandle raw(int display,int uid,String pkg,Binder input,Binder window,int flags){
        InputWindowHandle w=new InputWindowHandle();w.token=input;w.windowToken=window;w.displayId=display;w.ownerUid=uid;w.ownerPid=123;
        w.packageName=pkg;w.inputConfig=flags;w.frame=new Rect(0,0,100,200);w.touchableRegion=new Region(w.frame);w.transform=new Matrix();w.alpha=1;return w;
    }
    static void append(Fixture f,InputWindowHandle extra){List<InputWindowHandle> v=new ArrayList<InputWindowHandle>(Arrays.asList(f.windows));v.add(extra);f.windows=v.toArray(new InputWindowHandle[0]);}
    static BrokerProtocol.Request parse(JSONObject v)throws Exception{return BrokerProtocol.Request.parse(v.toString().getBytes(StandardCharsets.UTF_8));}
    static void joined(Thread t,AtomicReference<Throwable> error)throws Exception{t.join(2000);check(!t.isAlive(),"fixture callback joined");if(error.get()!=null)throw new AssertionError(error.get());}
    static Thread callbackThread(Fixture f,AtomicReference<Throwable> error){Thread t=new Thread(()->{try{f.emit();}catch(Throwable e){error.set(e);}});t.start();return t;}
    static void waitLatch(CountDownLatch l){try{if(!l.await(2,TimeUnit.SECONDS))throw new AssertionError("fixture latch timeout");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new AssertionError(e);}}

    // The observed row came from a separate zero-input callback with all VDs closed.
    // These host cases add that exact row to an explicitly synthetic owned-window fixture.
    static final int[] OBSERVED_BLANKED_BITS={1065353216,0,-2147483648,0,1065353216,-2147483648,0,0,1065353216};
    static void addObservedBlankedDisplay(Fixture f){
        WindowInfosListener.DisplayInfo blanked=new WindowInfosListener.DisplayInfo(-1,1224,2992);
        float[] matrix=new float[9];for(int i=0;i<matrix.length;i++)matrix[i]=Float.intBitsToFloat(OBSERVED_BLANKED_BITS[i]);
        blanked.mTransform.setValues(matrix);
        List<WindowInfosListener.DisplayInfo> all=new ArrayList<WindowInfosListener.DisplayInfo>(Arrays.asList(f.displays));
        all.add(blanked);f.displays=all.toArray(new WindowInfosListener.DisplayInfo[0]);
    }
    static BrokerProtocol.Request calendarDateRequest(Fixture f)throws Exception{
        return parse(f.requestObject().put("op","calendar_date").put("owner_task_id",repeat('c',32))
                .put("goal_sha256",HASH).put("date","2026-11-25").put("observation_id",repeat('d',32))
                .put("screen_sha256",HASH).put("permit_sha256",HASH).put("attempt_record_sha256",HASH)
                .put("display_width",100).put("display_height",200).put("display_rotation",0)
                .put("left",1).put("top",2).put("right",3).put("bottom",4));
    }
    static byte[] reply(boolean ok,String error,boolean dispatched){
        return new JSONObject().put("ok",ok).put("error",error).put("dispatched",dispatched)
                .put("state","ACTIVE").put("public_own_group_readback_wire","host historical wire")
                .toString().getBytes(StandardCharsets.UTF_8);
    }


    // The second phone callback recorded only these raw fields, with all owned VDs closed.
    // All remaining window geometry, identities and Binder instances below are explicit host ports.
    static final int[] OBSERVED_PHYSICAL_IDS={1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static final int[] OBSERVED_PHYSICAL_CONFIGS={16652,16652,16652,270,11,78,9,16652,16652,16652,1804,2824,268,266,15,11,11,15,9,76};
    static final boolean[] OBSERVED_PHYSICAL_NULL={false,false,false,false,true,false,true,false,false,false,false,false,false,false,true,true,true,true,true,false};
    static void physicalShape(Fixture f,boolean actualNumericConfigs){
        List<InputWindowHandle> rows=new ArrayList<InputWindowHandle>();rows.add(f.windows[0]);
        for(int i=0;i<OBSERVED_PHYSICAL_IDS.length;i++){
            Binder input=OBSERVED_PHYSICAL_NULL[i]?null:new Binder();
            int config=actualNumericConfigs?OBSERVED_PHYSICAL_CONFIGS[i]:(input==null?InputConfig.NO_INPUT_CHANNEL:0);
            rows.add(raw(OBSERVED_PHYSICAL_IDS[i],10099,"fixture.physical",input,new Binder(),config));
        }
        f.windows=rows.toArray(new InputWindowHandle[0]);
        f.displays=new WindowInfosListener.DisplayInfo[]{new WindowInfosListener.DisplayInfo(7,100,200)};
        addObservedBlankedDisplay(f);
    }
    static InputChannelIsolation.Census physicalNumericCensus(Fixture f)throws Exception{
        Map<String,Integer> flags=new LinkedHashMap<String,Integer>();
        for(java.lang.reflect.Field field:InputConfig.class.getFields())flags.put(field.getName(),field.getInt(null));
        // Preserve the recorded numeric vectors without claiming these host names are ROM enum names.
        for(int bit=9;bit<=14;bit++)flags.put("HOST_RAW_FLAG_"+bit,1<<bit);
        List<InputChannelIsolation.WindowFacts> windows=new ArrayList<InputChannelIsolation.WindowFacts>();
        for(InputWindowHandle w:f.windows)windows.add(new InputChannelIsolation.WindowFacts(w.token,w.windowToken,
                w.displayId,w.ownerUid,w.ownerPid,w.packageName,w.inputConfig,w.layoutParamsType,w.layoutParamsFlags,
                new int[]{0,0,100,200},new int[][]{{0,0,100,200}},new float[]{1,0,0,0,1,0,0,0,1},1));
        List<InputChannelIsolation.DisplayFacts> displays=new ArrayList<InputChannelIsolation.DisplayFacts>();
        for(WindowInfosListener.DisplayInfo d:f.displays){
            float[] matrix=new float[9];d.mTransform.getValues(matrix);
            displays.add(new InputChannelIsolation.DisplayFacts(d.mDisplayId,d.mLogicalSize.getWidth(),d.mLogicalSize.getHeight(),matrix));
        }
        return new InputChannelIsolation.Census(1,1000,1000,windows,displays,new InputChannelIsolation.Flags(flags));
    }
    static void missingPhysical(Fixture f,int id){
        f.windows[1].displayId=id;
        f.displays=new WindowInfosListener.DisplayInfo[]{new WindowInfosListener.DisplayInfo(7,100,200)};
        addObservedBlankedDisplay(f);
    }

    public static void main(String[] args)throws Exception{
        if(args.length==2&&"same-loader".equals(args[1])){
            new Fixture();rejected("INPUT_CAPTURE_NOT_BOOT_FRAMEWORK",()->new WindowInfosCapture(5000));
            Files.write(Paths.get(args[0]),new JSONObject().put("all_pass",true).put("cases",1).put("assertions",assertions).toString(2).getBytes(StandardCharsets.UTF_8));return;
        }
        test("actual_callback_complete_raw_census_and_no_authority",()->{
            Fixture f=new Fixture();InputChannelIsolation.Match m=f.inspect();check(m.census.windows.size()==2,"both displays retained");
            check(m.target.inputToken==f.input&&m.target.windowToken==f.window,"live independent tokens");
            check(Boolean.FALSE.equals(m.evidence().get("grants_dispatch")),"no dispatch");check(m.census.regionRects==2,"full region count");
            check(WindowInfosListener.unregistrations==1,"real close call");
        });
        test("cached_register_pair_is_not_a_callback",()->{
            Fixture f=new Fixture();WindowInfosListener.cache=new Pair<InputWindowHandle[],WindowInfosListener.DisplayInfo[]>(f.windows,f.displays);
            WindowInfosCapture c=new WindowInfosCapture(5000);c.register();SystemClock.now=5000;
            rejected("INPUT_CALLBACK_DEADLINE",c::awaitCallback);c.unregisterAndDrain(5100);
            check(((Number)c.evidence().get("callback_arrivals")).intValue()==0,"no invented callback");check(c.locallyDrained(),"closed");
        });
        test("callback_snapshot_is_immutable_after_raw_mutation",()->{
            Fixture f=new Fixture();WindowInfosCapture c=f.capture();InputChannelIsolation.Census s=c.awaitCallback();
            f.windows[0].frame.right=1;f.windows[0].touchableRegion.rects.clear();f.windows[0].token=new Binder();
            check(s.windows.get(0).frame()[2]==100&&s.windows.get(0).region().length==1&&s.windows.get(0).inputToken==f.input,"immutable raw copy");
            c.requireCurrent(s);c.unregisterAndDrain(5000);
        });
        test("new_callback_invalidates_previous_object",()->{
            Fixture f=new Fixture();WindowInfosCapture c=f.capture();InputChannelIsolation.Census s=c.awaitCallback();f.emit();
            rejected("INPUT_CALLBACK_CHANGED_DURING_READ",()->c.requireCurrent(s));check(c.awaitCallback().ordinal==2,"new ordinal");c.unregisterAndDrain(5000);
        });
        test("late_callback_cannot_republish_after_retirement",()->{
            Fixture f=new Fixture();WindowInfosCapture c=f.capture();c.unregisterAndDrain(5000);f.emit();
            check(c.locallyDrained(),"remains drained");check(Boolean.FALSE.equals(c.evidence().get("retains_current_census")),"no token retained");
            check(((Number)c.evidence().get("late_callbacks_ignored")).intValue()==1,"late callback observed");rejected("INPUT_LISTENER_NOT_LIVE",c::awaitCallback);
        });
        test("inflight_callback_retired_before_actual_drain",()->{
            Fixture f=new Fixture();WindowInfosCapture c=f.capture();CountDownLatch entered=new CountDownLatch(1),resume=new CountDownLatch(1);
            f.windows[0].beforeToken=()->{entered.countDown();waitLatch(resume);};AtomicReference<Throwable> error=new AtomicReference<Throwable>();
            Thread t=callbackThread(f,error);waitLatch(entered);c.retire();check(!c.locallyDrained(),"actual callback still running");
            rejected("INPUT_LISTENER_DRAIN_DEADLINE",()->c.unregisterAndDrain(SystemClock.now));resume.countDown();joined(t,error);
            c.unregisterAndDrain(5000);check(c.locallyDrained()&&WindowInfosListener.unregistrations==1,"one unregister and true drain");
            check(Boolean.FALSE.equals(c.evidence().get("surfaceflinger_removal_queue_drain_observed")),"no remote queue claim");
        });
        test("older_callback_finishing_late_cannot_replace_newer",()->{
            Fixture f=new Fixture();WindowInfosCapture c=f.capture();CountDownLatch entered=new CountDownLatch(1),resume=new CountDownLatch(1);
            InputWindowHandle older=f.windows[0];older.beforeToken=()->{entered.countDown();waitLatch(resume);};AtomicReference<Throwable> error=new AtomicReference<Throwable>();
            Thread t=callbackThread(f,error);waitLatch(entered);f.windows=new InputWindowHandle[]{raw(7,1010123,ProfileTarget.CTRIP,f.input,f.window,0)};f.emit();
            resume.countDown();joined(t,error);check(c.awaitCallback().ordinal==3,"latest callback wins");
            check(((Number)c.evidence().get("superseded_callbacks")).intValue()==1,"old completion recorded");c.unregisterAndDrain(5000);
        });
        test("callback_error_remains_latched_after_later_good_data",()->{
            Fixture f=new Fixture();WindowInfosCapture c=f.capture();WindowInfosListener.last.onWindowInfosChanged(null,f.displays);f.emit();
            rejected("INPUT_CALLBACK_ARRAYS_INCOMPLETE",c::awaitCallback);c.unregisterAndDrain(5000);check(c.locallyDrained(),"failed callback drained");
        });
        test("register_failure_still_gets_one_unregister",()->{
            new Fixture();WindowInfosListener.registerFails=true;WindowInfosCapture c=new WindowInfosCapture(5000);
            rejected("INPUT_LISTENER_REGISTRATION_FAILED",c::register);c.unregisterAndDrain(5000);check(WindowInfosListener.unregistrations==1&&c.locallyDrained(),"close after attempted register");
        });
        test("unregister_failure_is_unknown_and_never_retried",()->{
            Fixture f=new Fixture();WindowInfosCapture c=f.capture();WindowInfosListener.unregisterFails=true;
            rejected("INPUT_LISTENER_UNREGISTER_UNKNOWN",()->c.unregisterAndDrain(5000));rejected("INPUT_LISTENER_UNREGISTER_UNKNOWN",()->c.unregisterAndDrain(5000));
            check(!c.locallyDrained()&&WindowInfosListener.unregistrations==1,"unknown remains and no second native unregister");
        });
        test("late_register_return_rejected_without_refreshing_deadline",()->{
            new Fixture();WindowInfosListener.onRegister=()->SystemClock.now=5000;WindowInfosCapture c=new WindowInfosCapture(5000);
            rejected("INPUT_LISTENER_REGISTRATION_LATE",c::register);c.unregisterAndDrain(5100);check(c.locallyDrained(),"late IO closed");
        });
        test("callback_age_and_original_deadline_both_enforced",()->{
            Fixture f=new Fixture();WindowInfosCapture c=f.capture();InputChannelIsolation.Census s=c.awaitCallback();SystemClock.now=3001;
            rejected("INPUT_CENSUS_STALE",()->c.requireCurrent(s));SystemClock.now=5000;rejected("INPUT_CENSUS_STALE",()->InputChannelIsolation.inspect(s,f.expected(),SystemClock.now,5000));c.unregisterAndDrain(5100);
        });
        test("root_uid_and_platform_are_real_entry_requirements",()->{
            new Fixture();android.os.Process.uid=2000;rejected("INPUT_CAPTURE_ROOT_REQUIRED",()->new WindowInfosCapture(5000));android.os.Process.uid=0;android.os.Build.VERSION.SDK_INT=35;
            rejected("INPUT_CAPTURE_PLATFORM_UNSUPPORTED",()->new WindowInfosCapture(5000));
        });
        test("cross_display_channel_alias_main_cover_and_other_vd_rejected",()->{
            for(int display:new int[]{0,1,9}){Fixture f=new Fixture();f.windows[1]=raw(display,10099,"fixture.other",f.input,new Binder(),InputConfig.NOT_TOUCHABLE);
                rejected("INPUT_CHANNEL_CROSS_DISPLAY_ALIAS",f::inspect);}
        });
        test("window_token_alias_is_rejected_even_with_distinct_input_tokens",()->{
            Fixture f=new Fixture();f.windows[1].windowToken=f.window;rejected("INPUT_WINDOW_TOKEN_MATCH_NOT_UNIQUE",f::inspect);
        });
        test("owned_non_target_window_token_alias_on_other_display_rejected",()->{
            Fixture f=new Fixture();Binder other=new Binder();append(f,raw(7,10099,"fixture.hidden",new Binder(),other,InputConfig.NOT_VISIBLE));f.windows[1].windowToken=other;
            rejected("INPUT_WINDOW_CROSS_DISPLAY_ALIAS",f::inspect);
        });
        test("same_display_duplicate_channel_rejected",()->{
            Fixture f=new Fixture();append(f,raw(7,1010123,ProfileTarget.CTRIP,f.input,new Binder(),InputConfig.NOT_TOUCHABLE));rejected("INPUT_OWNED_CHANNEL_AMBIGUOUS",f::inspect);
        });
        test("spy_clone_foreign_overlay_and_same_uid_additional_touch_refused",()->{
            for(int flag:new int[]{InputConfig.SPY,InputConfig.CLONE}){Fixture f=new Fixture();append(f,raw(7,1010123,ProfileTarget.CTRIP,new Binder(),new Binder(),flag));rejected("INPUT_OWNED_SPY_OR_CLONE",f::inspect);}
            Fixture foreign=new Fixture();append(foreign,raw(7,1000,"android.permission",new Binder(),new Binder(),0));rejected("INPUT_FOREIGN_TOUCH_RECIPIENT",foreign::inspect);
            Fixture same=new Fixture();append(same,raw(7,1010123,ProfileTarget.CTRIP,new Binder(),new Binder(),0));rejected("INPUT_ADDITIONAL_OWNED_TOUCH_RECIPIENT",same::inspect);
        });
        test("unknown_flags_display_and_missing_channel_rejected",()->{
            Fixture unknown=new Fixture();unknown.windows[0].inputConfig=1<<24;rejected("INPUT_WINDOW_CONFIG_UNKNOWN",unknown::inspect);
            Fixture display=new Fixture();display.windows[1].displayId=10;rejected("INPUT_WINDOW_DISPLAY_UNKNOWN",display::inspect);
            Fixture channel=new Fixture();channel.windows[0].token=null;rejected("INPUT_CHANNEL_UNKNOWN",channel::inspect);
        });
        test("actual_window_must_match_full_uid_package_and_independent_token",()->{
            Fixture uid=new Fixture();uid.windows[0].ownerUid=1010124;rejected("INPUT_FOREIGN_TOUCH_RECIPIENT",uid::inspect);
            Fixture pkg=new Fixture();pkg.windows[0].packageName="com.xiaomi.shop";rejected("INPUT_FOREIGN_TOUCH_RECIPIENT",pkg::inspect);
            Fixture same=new Fixture();same.windows[0].token=same.window;rejected("INPUT_TOKEN_NAMESPACES_COLLIDE",same::inspect);
            Fixture missing=new Fixture();missing.windows[0].windowToken=new Binder();rejected("INPUT_ADDITIONAL_OWNED_TOUCH_RECIPIENT",missing::inspect);
        });
        test("target_transform_and_owned_geometry_cannot_be_approximated",()->{
            Fixture perspective=new Fixture();perspective.windows[0].transform.setValues(new float[]{1,0,0,0,1,0,.1f,0,1});rejected("INPUT_TRANSFORM_PERSPECTIVE",perspective::inspect);
            Fixture overflow=new Fixture();overflow.windows[0].frame.right=101;rejected("INPUT_TARGET_OUTSIDE_OWNED_DISPLAY",overflow::inspect);
            Fixture region=new Fixture();region.windows[0].touchableRegion.rects.clear();rejected("INPUT_TARGET_GEOMETRY_UNAVAILABLE",region::inspect);
            Fixture rotate=new Fixture();rotate.displays[0].mTransform.setValues(new float[]{0,-1,200,1,0,0,0,0,1});rejected("INPUT_TARGET_OUTSIDE_OWNED_DISPLAY",rotate::inspect);
        });
        test("all_display_duplicates_null_rows_and_region_budget_rejected",()->{
            Fixture duplicate=new Fixture();duplicate.displays[1]=duplicate.displays[0];rejected("INPUT_DISPLAY_DUPLICATE",duplicate::inspect);
            Fixture nul=new Fixture();nul.windows[1]=null;rejected("INPUT_WINDOW_RUNTIME_TYPE",nul::inspect);
            Fixture many=new Fixture();for(int i=0;i<8192;i++)many.windows[0].touchableRegion.rects.add(new Rect(0,0,1,1));rejected("INPUT_CENSUS_REGION_LIMIT",many::inspect);
        });
        test("namespace_is_derived_before_lookup_and_target_profile_is_unchanged",()->{
            Fixture f=new Fixture();AccessibilityWindowTokens.Read r=AccessibilityWindowTokens.read(f.packages,f.target,96,5000);
            check(r.profile.userId==10&&r.namespaceUserId==0&&r.token==f.window,"actual parent namespace plus original profile");
            check(f.namespaceReads.equals(Arrays.asList(10,0,10,0)),"both exact reads and repeat");
            check(Boolean.FALSE.equals(r.evidence().get("null_result_fallback_used")),"no null-driven fallback");
        });
        test("namespace_direct_token_if_present_must_be_same_binder",()->{
            Fixture f=new Fixture();IAccessibilityManager.Stub.service=(w,u)->u==0?f.window:new Binder();rejected("INPUT_ACCESSIBILITY_NAMESPACE_AMBIGUOUS",()->AccessibilityWindowTokens.read(f.packages,f.target,96,5000));
        });
        test("namespace_null_parent_and_changed_serial_or_current_user_rejected",()->{
            Fixture nil=new Fixture();IAccessibilityManager.Stub.service=(w,u)->null;rejected("INPUT_ACCESSIBILITY_WINDOW_TOKEN_NULL",()->AccessibilityWindowTokens.read(nil.packages,nil.target,96,5000));
            Fixture serial=new Fixture();serial.packages.source=u->new ProfileIdentity(10,45,0,ProfileIdentity.MANAGED);rejected("INPUT_ACCESSIBILITY_PROFILE_CHANGED",()->AccessibilityWindowTokens.read(serial.packages,serial.target,96,5000));
            Fixture current=new Fixture();android.app.ActivityManager.currentUser=10;rejected("INPUT_ACCESSIBILITY_PARENT_NOT_CURRENT",()->AccessibilityWindowTokens.read(current.packages,current.target,96,5000));check(current.namespaceReads.isEmpty(),"reject before Binder lookup");
        });
        test("namespace_final_token_service_liveness_and_deadline_are_rechecked",()->{
            Fixture changed=new Fixture();int[] n={0};IAccessibilityManager.Stub.service=(w,u)->u==10?null:(++n[0]==1?changed.window:new Binder());
            rejected("INPUT_ACCESSIBILITY_WINDOW_CHANGED",()->AccessibilityWindowTokens.read(changed.packages,changed.target,96,5000));
            Fixture expired=new Fixture();IAccessibilityManager.Stub.service=(w,u)->{SystemClock.now=5000;return null;};
            rejected("INPUT_ACCESSIBILITY_LOOKUP_DEADLINE",()->AccessibilityWindowTokens.read(expired.packages,expired.target,96,5000));
            Fixture dead=new Fixture();dead.service.alive=false;rejected("INPUT_ACCESSIBILITY_SERVICE_UNAVAILABLE",()->AccessibilityWindowTokens.read(dead.packages,dead.target,96,5000));
        });
        test("protocol_only_exact_readonly_version4_ctrip_window_shape",()->{
            Fixture f=new Fixture();BrokerProtocol.Request r=f.request();r.authenticate(f.config,10001);r.checkDeadline(SystemClock.now,61000);
            check(r.operation.equals("calendar_probe")&&r.windowId==96&&r.observedTaskId==100,"actual parse");
            rejected("REQUEST_FIELDS",()->parse(f.requestObject().put("left",1)));
            rejected("CALENDAR_PROBE_SCOPE_REQUIRED",()->parse(f.requestObject().put("version",2)));
            rejected("CALENDAR_PROBE_PACKAGE_REQUIRED",()->parse(f.requestObject().put("package",ProfileTarget.XIAOMI)));
            rejected("CALLER_UID_MISMATCH",()->r.authenticate(f.config,0));
        });
        test("protocol_date_and_coordinate_effects_remain_unavailable",()->{
            Fixture f=new Fixture();for(String action:new String[]{"calendar_tap","calendar_select","coordinate_click","native.select_calendar_date"}){
                JSONObject v=f.requestObject().put("op",action);v.remove("package");v.remove("window_id");v.remove("task_id");rejected("OPERATION_NOT_ALLOWED",()->parse(v));}
            JSONObject back=f.requestObject().put("op","back");back.remove("window_id");back.remove("task_id");check("back".equals(parse(back).operation),"legacy back parser preserved");
        });
        test("actual_broker_probe_success_is_readonly_and_closes_listener",()->{
            Fixture f=new Fixture();BrokerProbeHost b=f.broker();b.run(f.request());JSONObject p=b.calendarProbeEvidence;
            check(p.getBoolean("qualified")&&!p.getBoolean("grants_dispatch")&&!p.getBoolean("dispatched"),"read-only qualification");
            check(p.getInt("input_attempts")==0&&b.calendarWindowCapture==null,"zero input and no active capture");
            check(b.profileOwnedTask.reads==2&&b.guards==4,"full before/fresh real method sequence");check(WindowInfosListener.unregistrations==1,"one actual close");
        });
        test("actual_broker_rejects_owned_task_change_and_drains",()->{
            Fixture f=new Fixture();BrokerProbeHost b=f.broker();b.profileOwnedTask.beforeRead=()->{if(b.profileOwnedTask.reads==2)b.profileOwnedTask.taskToken="00000000-0000-4000-8000-000000000009";};
            rejected("INPUT_OWNED_TASK_CHANGED",()->b.run(f.request()));check(b.calendarWindowCapture==null&&!b.calendarProbeEvidence.getBoolean("qualified"),"failed and drained");
        });
        test("actual_broker_rejects_callback_change_at_final_gate",()->{
            Fixture f=new Fixture();BrokerProbeHost b=f.broker();b.beforeGuard=()->{if(b.guards==4)f.emit();};
            rejected("INPUT_CALLBACK_CHANGED_DURING_READ",()->b.run(f.request()));check(b.calendarWindowCapture==null,"drained after event");
        });
        test("actual_broker_final_cancel_and_dead_input_token_refused",()->{
            Fixture cancel=new Fixture();BrokerProbeHost b=cancel.broker();b.beforeGuard=()->{if(b.guards==4)b.cancelled=true;};
            rejected("BROKER_CANCELLED",()->b.run(cancel.request()));check(b.calendarWindowCapture==null,"cancel drains");
            Fixture dead=new Fixture();BrokerProbeHost d=dead.broker();dead.input.alive=false;rejected("INPUT_CHANNEL_TOKEN_NOT_LIVE",()->d.run(dead.request()));
        });
        test("actual_broker_unregister_unknown_retains_capture_and_rejects_qualification",()->{
            Fixture f=new Fixture();BrokerProbeHost b=f.broker();WindowInfosListener.unregisterFails=true;
            rejected("INPUT_LISTENER_UNREGISTER_UNKNOWN",()->b.run(f.request()));check(b.calendarWindowCapture!=null&&!b.calendarWindowCapture.locallyDrained(),"unknown retained");
            check(!b.calendarProbeEvidence.getBoolean("qualified")&&b.calendarProbeEvidence.getInt("input_attempts")==0,"no authority on close failure");
        });
        test("actual_broker_four_second_return_check_is_not_native_cancellation",()->{
            Fixture f=new Fixture();BrokerProbeHost b=f.broker();WindowInfosListener.onUnregister=()->SystemClock.now=5000;
            rejected("INPUT_PROBE_DEADLINE",()->b.run(f.request()));check(WindowInfosListener.unregistrations==1&&b.calendarWindowCapture==null,"actual IO returned and drained");
            check(!b.calendarProbeEvidence.getBoolean("qualified"),"expired result not accepted");
        });
        test("observed_blanked_display_preserves_signed_id_size_and_float_bits",()->{
            Fixture f=new Fixture();addObservedBlankedDisplay(f);WindowInfosCapture c=f.capture();
            try{InputChannelIsolation.Census census=c.awaitCallback();check(census.displays.size()==5,"all raw display rows retained");
                InputChannelIsolation.DisplayFacts d=census.displays.get(4);
                check(d.id==-1&&d.blankedLayerStack&&d.width==1224&&d.height==2992,"exact non-target metadata");
                float[] matrix=d.transform();for(int i=0;i<matrix.length;i++)check(Float.floatToRawIntBits(matrix[i])==OBSERVED_BLANKED_BITS[i],"original matrix bits "+i);
                InputChannelIsolation.Match match=InputChannelIsolation.inspect(census,f.expected(),SystemClock.now,5000);
                check(match.expected.displayId==7&&match.target==census.windows.get(0),"target never remapped to blanked or physical display");
                Map<String,Object> evidence=match.evidence();check(((Number)evidence.get("blanked_layer_stack_display_count")).intValue()==1,"explicit blanked count");
                Object rows=evidence.get("blanked_layer_stack_displays");check(rows instanceof List<?> && ((List<?>)rows).size()==1,"retained metadata evidence");
                Map<?,?> row=(Map<?,?>)((List<?>)rows).get(0);
                check(Boolean.FALSE.equals(row.get("can_be_input_target"))&&((Number)row.get("display_id")).intValue()==-1,"metadata grants no target");
                List<?> bits=(List<?>)row.get("transform_float32_bits");for(int i=0;i<bits.size();i++)check(((Number)bits.get(i)).intValue()==OBSERVED_BLANKED_BITS[i],"evidence raw bit "+i);
                check(Boolean.FALSE.equals(evidence.get("grants_dispatch"))&&census.windows.size()==2,"no input authority or omitted windows");
            }finally{c.unregisterAndDrain(5000);}check(c.locallyDrained(),"real listener lifecycle drained");
        });
        test("actual_probe_accepts_metadata_sentinel_and_still_closes_once",()->{
            Fixture f=new Fixture();addObservedBlankedDisplay(f);BrokerProbeHost b=f.broker();b.run(f.request());
            JSONObject p=b.calendarProbeEvidence;
            check(p.getBoolean("qualified")&&!p.getBoolean("grants_dispatch")&&p.getInt("input_attempts")==0,"only read-only qualification");
            check(p.getJSONObject("isolation").getInt("blanked_layer_stack_display_count")==1,"actual probe publishes sentinel metadata");
            check(WindowInfosListener.unregistrations==1&&b.calendarWindowCapture==null,"actual probe unregister and drain");
        });
        test("other_negative_ids_bad_sizes_and_nonfinite_transforms_still_refused",()->{
            for(int id:new int[]{-2,Integer.MIN_VALUE}){Fixture f=new Fixture();f.displays[1]=new WindowInfosListener.DisplayInfo(id,1224,2992);rejected("INPUT_DISPLAY_FACTS_INVALID",f::inspect);}
            for(int[] size:new int[][]{{-1,2992},{1224,-1},{16385,2992},{1224,16385}}){Fixture f=new Fixture();f.displays[1]=new WindowInfosListener.DisplayInfo(-1,size[0],size[1]);rejected("INPUT_DISPLAY_FACTS_INVALID",f::inspect);}
            Fixture nonfinite=new Fixture();addObservedBlankedDisplay(nonfinite);nonfinite.displays[4].mTransform.setValues(new float[]{1,0,Float.NaN,0,1,0,0,0,1});rejected("INPUT_TRANSFORM_NONFINITE",nonfinite::inspect);
        });
        test("blanked_metadata_cannot_be_expected_target_or_replace_missing_display",()->{
            Fixture expected=new Fixture();rejected("INPUT_EXPECTED_OWNER_INVALID",()->new InputChannelIsolation.Expected(-1,1010123,10,0,96,100,ProfileTarget.CTRIP,1224,2992,0,expected.window));
            Fixture missing=new Fixture();missing.displays[0]=new WindowInfosListener.DisplayInfo(-1,1224,2992);rejected("INPUT_WINDOW_DISPLAY_UNKNOWN",missing::inspect);
            Fixture window=new Fixture();addObservedBlankedDisplay(window);window.windows[1].displayId=-1;rejected("INPUT_WINDOW_IDENTITY_INVALID",window::inspect);
        });
        test("blanked_row_does_not_remove_foreign_aliases_or_weaken_target_geometry",()->{
            for(int display:new int[]{0,1,9}){Fixture f=new Fixture();addObservedBlankedDisplay(f);f.windows[1]=raw(display,10099,"fixture.other",f.input,new Binder(),InputConfig.NOT_TOUCHABLE);rejected("INPUT_CHANNEL_CROSS_DISPLAY_ALIAS",f::inspect);}
            Fixture size=new Fixture();addObservedBlankedDisplay(size);size.displays[0]=new WindowInfosListener.DisplayInfo(7,101,200);rejected("INPUT_DISPLAY_GEOMETRY_MISMATCH",size::inspect);
            Fixture token=new Fixture();addObservedBlankedDisplay(token);token.windows[1].windowToken=token.window;rejected("INPUT_WINDOW_TOKEN_MATCH_NOT_UNIQUE",token::inspect);
        });
        test("duplicate_blanked_rows_remain_a_complete_census_refusal",()->{
            Fixture f=new Fixture();addObservedBlankedDisplay(f);addObservedBlankedDisplay(f);rejected("INPUT_DISPLAY_DUPLICATE",f::inspect);
        });
        test("actual_retirement_block_preserves_calendar_probe_first_error",()->{
            Fixture f=new Fixture();BrokerProbeHost b=f.broker();b.publicAdmissionRetired.set(true);
            JSONObject r=new JSONObject(new String(b.retirement(f.request(),reply(false,"INPUT_DISPLAY_FACTS_INVALID",false)),StandardCharsets.UTF_8));
            check(!r.getBoolean("ok")&&"INPUT_DISPLAY_FACTS_INVALID".equals(r.getString("error")),"primary failure propagated");
            check("PUBLIC_SCOPE_RETIRED".equals(r.getString("public_scope_retirement_error")),"retirement retained separately");
            check(r.getBoolean("public_scope_admission_retired")&&r.getBoolean("public_scope_closing")&&r.isNull("public_own_group_readback_wire"),"retirement still removes authority");
            check(!r.getBoolean("dispatched")&&"CLOSING".equals(r.getString("state")),"historical zero dispatch and actual closing state");
        });
        test("actual_retirement_block_preserves_calendar_date_effect_history",()->{
            Fixture f=new Fixture();BrokerProbeHost b=f.broker();b.closing.set(true);
            JSONObject r=new JSONObject(new String(b.retirement(calendarDateRequest(f),reply(false,"CALENDAR_UP_UNKNOWN",true)),StandardCharsets.UTF_8));
            check(!r.getBoolean("ok")&&"CALENDAR_UP_UNKNOWN".equals(r.getString("error")),"date failure is not replaced");
            check(r.getBoolean("dispatched")&&r.isNull("public_own_group_readback_wire"),"recorded effect truth retained without authority");
            check("PUBLIC_SCOPE_RETIRED".equals(r.getString("public_scope_retirement_error")),"separate retirement reason");
        });
        test("retired_success_and_legacy_failure_keep_existing_retirement_result",()->{
            Fixture f=new Fixture();BrokerProbeHost b=f.broker();b.closing.set(true);
            JSONObject success=new JSONObject(new String(b.retirement(f.request(),reply(true,"",false)),StandardCharsets.UTF_8));
            check(!success.getBoolean("ok")&&"PUBLIC_SCOPE_RETIRED".equals(success.getString("error")),"successful stale result remains rejected");
            JSONObject back=f.requestObject().put("op","back");back.remove("window_id");back.remove("task_id");
            JSONObject legacy=new JSONObject(new String(b.retirement(parse(back),reply(false,"OLD_FAILURE",true)),StandardCharsets.UTF_8));
            check("PUBLIC_SCOPE_RETIRED".equals(legacy.getString("error"))&&legacy.getBoolean("dispatched"),"legacy branch and effect history unchanged");
            check(!legacy.has("public_scope_retirement_error"),"new field restricted to original calendar failure");
        });
        test("retirement_block_does_not_change_live_close_or_null_request_receipts",()->{
            Fixture f=new Fixture();BrokerProbeHost b=f.broker();byte[] original=reply(false,"INPUT_DISPLAY_FACTS_INVALID",false);
            check(b.retirement(f.request(),original)==original,"live response unchanged");b.closing.set(true);
            JSONObject close=f.requestObject().put("op","close");close.remove("package");close.remove("window_id");close.remove("task_id");
            check(b.retirement(parse(close),original)==original,"authenticated close retains original response");
            check(b.retirement(null,original)==original,"null request original behavior");
        });
        test("observed_physical_ids_null_tokens_and_numeric_configs_remain_in_full_census",()->{
            Fixture f=new Fixture();physicalShape(f,true);
            InputChannelIsolation.Census census=physicalNumericCensus(f);
            check(census.windows.size()==21&&census.displays.size()==2,"all recorded rows plus explicit synthetic target retained");
            check(census.unresolvedPhysicalDisplayIds.equals(Arrays.asList(1,0)),"only observed physical IDs unresolved, first-seen order");
            for(int i=0;i<20;i++){
                InputChannelIsolation.WindowFacts w=census.windows.get(i+1);
                check(w.displayId==OBSERVED_PHYSICAL_IDS[i]&&w.inputConfig==OBSERVED_PHYSICAL_CONFIGS[i]
                        &&(w.inputToken==null)==OBSERVED_PHYSICAL_NULL[i],"raw minimal field vector retained "+i);
            }
            InputChannelIsolation.Match match=InputChannelIsolation.inspect(census,f.expected(),1000,5000);
            Map<String,Object> evidence=match.evidence();
            check(match.target==census.windows.get(0)&&match.expected.displayId==7,"only actual synthetic owned target matched");
            check(((Number)evidence.get("unresolved_physical_display_count")).intValue()==2
                    &&((Number)evidence.get("unresolved_physical_window_count")).intValue()==20,"explicit unresolved count");
            List<?> rows=(List<?>)evidence.get("unresolved_physical_display_windows");
            for(Object value:rows){
                Map<?,?> row=(Map<?,?>)value;int id=((Number)row.get("display_id")).intValue();
                check(Boolean.FALSE.equals(row.get("display_facts_present"))&&Boolean.FALSE.equals(row.get("geometry_known"))
                        &&Boolean.FALSE.equals(row.get("can_be_input_target")),"no invented geometry or authority");
                check(((Number)row.get("window_count")).intValue()==(id==1?6:14)
                        &&((Number)row.get("input_token_present_count")).intValue()==(id==1?5:8)
                        &&((Number)row.get("input_token_null_count")).intValue()==(id==1?1:6),"exact per-display observed counts");
            }
            check(match.foreignDisplayWindows==20&&((Number)evidence.get("omitted_window_count")).intValue()==0,"all foreign rows take part");
            try{census.unresolvedPhysicalDisplayIds.add(2);throw new AssertionError("mutable unresolved IDs");}
            catch(UnsupportedOperationException expected){check(true,"derived unresolved ID list immutable");}
            String before=census.sha256;f.windows[1].inputConfig^=InputConfig.NOT_VISIBLE;
            check(!before.equals(physicalNumericCensus(f).sha256),"unresolved raw config remains hashed");
        });
        test("actual_probe_keeps_unresolved_physical_rows_and_closes_listener",()->{
            Fixture f=new Fixture();physicalShape(f,false);BrokerProbeHost b=f.broker();b.run(f.request());
            JSONObject proof=b.calendarProbeEvidence,iso=proof.getJSONObject("isolation");
            check(proof.getBoolean("qualified")&&!proof.getBoolean("grants_dispatch")&&proof.getInt("input_attempts")==0,"read-only probe only");
            check(iso.getInt("window_count")==21&&iso.getInt("other_display_window_count")==20&&iso.getInt("omitted_window_count")==0,"complete rows through actual callback and probe");
            check(iso.getInt("unresolved_physical_display_count")==2&&iso.getInt("unresolved_physical_window_count")==20,"actual probe publishes unresolved metadata");
            check(WindowInfosListener.unregistrations==1&&b.calendarWindowCapture==null,"actual listener closed once and drained");
        });
        test("missing_physical_display_still_requires_valid_blanked_metadata",()->{
            for(int id:new int[]{0,1}){
                Fixture f=new Fixture();f.windows[1].displayId=id;
                f.displays=new WindowInfosListener.DisplayInfo[]{new WindowInfosListener.DisplayInfo(7,100,200)};
                rejected("INPUT_WINDOW_DISPLAY_UNKNOWN",f::inspect);
            }
        });
        test("blanked_exception_never_covers_unknown_vd_or_missing_expected_display",()->{
            for(int id:new int[]{2,8,99}){
                Fixture f=new Fixture();missingPhysical(f,id);
                rejected("INPUT_WINDOW_DISPLAY_UNKNOWN",f::inspect);
            }
            Fixture missing=new Fixture();physicalShape(missing,false);
            missing.displays=new WindowInfosListener.DisplayInfo[]{missing.displays[1]};
            rejected("INPUT_WINDOW_DISPLAY_UNKNOWN",missing::inspect);
            Fixture noTarget=new Fixture();physicalShape(noTarget,false);
            noTarget.displays=new WindowInfosListener.DisplayInfo[]{noTarget.displays[1]};
            noTarget.windows=Arrays.copyOfRange(noTarget.windows,1,noTarget.windows.length);
            rejected("INPUT_DISPLAY_GEOMETRY_MISMATCH",noTarget::inspect);
            for(int id:new int[]{0,1}){
                Fixture f=new Fixture();rejected("INPUT_EXPECTED_OWNER_INVALID",()->new InputChannelIsolation.Expected(
                        id,1010123,10,0,96,100,ProfileTarget.CTRIP,100,200,0,f.window));
            }
        });
        test("unresolved_physical_windows_still_participate_in_input_and_window_alias_checks",()->{
            for(int id:new int[]{0,1}){
                Fixture input=new Fixture();missingPhysical(input,id);input.windows[1].token=input.input;
                rejected("INPUT_CHANNEL_CROSS_DISPLAY_ALIAS",input::inspect);
                Fixture window=new Fixture();missingPhysical(window,id);window.windows[1].windowToken=window.window;
                rejected("INPUT_WINDOW_TOKEN_MATCH_NOT_UNIQUE",window::inspect);
                Fixture other=new Fixture();missingPhysical(other,id);Binder extraWindow=new Binder();
                append(other,raw(7,1010123,ProfileTarget.CTRIP,new Binder(),extraWindow,InputConfig.NOT_TOUCHABLE));
                other.windows[1].windowToken=extraWindow;
                rejected("INPUT_WINDOW_CROSS_DISPLAY_ALIAS",other::inspect);
            }
        });
        test("unresolved_rows_keep_channel_config_target_geometry_and_spy_refusals",()->{
            Fixture channel=new Fixture();missingPhysical(channel,0);channel.windows[1].token=null;
            rejected("INPUT_CHANNEL_UNKNOWN",channel::inspect);
            Fixture config=new Fixture();missingPhysical(config,1);config.windows[1].inputConfig=1<<20;
            rejected("INPUT_WINDOW_CONFIG_UNKNOWN",config::inspect);
            Fixture geometry=new Fixture();physicalShape(geometry,false);
            geometry.displays[0]=new WindowInfosListener.DisplayInfo(7,101,200);
            rejected("INPUT_DISPLAY_GEOMETRY_MISMATCH",geometry::inspect);
            Fixture spy=new Fixture();physicalShape(spy,false);spy.windows[0].inputConfig=InputConfig.SPY;
            rejected("INPUT_OWNED_SPY_OR_CLONE",spy::inspect);
        });
        test("resolved_physical_geometry_is_not_reported_as_missing",()->{
            Fixture f=new Fixture();physicalShape(f,false);
            f.displays=new WindowInfosListener.DisplayInfo[]{f.displays[0],f.displays[1],
                    new WindowInfosListener.DisplayInfo(0,100,200),new WindowInfosListener.DisplayInfo(1,100,200)};
            InputChannelIsolation.Match all=f.inspect();
            check(all.census.unresolvedPhysicalDisplayIds.isEmpty()&&all.census.windows.size()==21,"present physical rows need no exception");
            check(((Number)all.evidence().get("unresolved_physical_display_count")).intValue()==0,"no false unresolved metadata");
            Fixture partial=new Fixture();physicalShape(partial,false);
            partial.displays=new WindowInfosListener.DisplayInfo[]{partial.displays[0],partial.displays[1],
                    new WindowInfosListener.DisplayInfo(0,100,200)};
            InputChannelIsolation.Match one=partial.inspect();
            check(one.census.unresolvedPhysicalDisplayIds.equals(Collections.singletonList(1)),"only missing cover display retained as unresolved");
            check(((Number)one.evidence().get("unresolved_physical_window_count")).intValue()==6,"only missing cover windows counted");
        });
        boolean pass=true;for(Map<String,Object> r:rows)pass&=Boolean.TRUE.equals(r.get("passed"));
        JSONObject result=new JSONObject().put("schema","hepta.calendar-window-host-cases.v1").put("all_pass",pass)
                .put("cases",rows.size()).put("assertions",assertions).put("rows",rows).put("phone_actions",0)
                .put("android_runtime",false).put("explicit_android_io_ports",true).put("boot_loader_boundary_simulated",true)
                .put("input_dispatch_calls",0).put("native_register_unregister_hard_cancel_claimed",false);
        Files.write(Paths.get(args[0]),result.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println(new JSONObject().put("all_pass",pass).put("cases",rows.size()).put("assertions",assertions));
        if(!pass)throw new AssertionError("calendar window host cases failed");
    }
}
