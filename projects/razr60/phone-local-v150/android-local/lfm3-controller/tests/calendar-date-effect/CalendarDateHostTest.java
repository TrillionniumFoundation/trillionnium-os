package org.trillionnium.hepta.background;
import android.graphics.Rect;
import android.graphics.Region;
import android.os.Binder;
import android.os.InputConfig;
import android.os.SystemClock;
import android.view.MotionEvent;
import android.window.WindowInfosListener;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

/** Exact broker date methods and full guards/helpers with explicit Android IPC/input ports. No App authority fixture. */
public final class CalendarDateHostTest {
 interface Body {void run()throws Exception;}
 static final List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();
 static int assertions;
 static void check(boolean b,String why){assertions++;if(!b)throw new AssertionError(why);}
 static void test(String name,Body body){int a=assertions;Map<String,Object> r=new LinkedHashMap<String,Object>();r.put("name",name);try{body.run();r.put("passed",true);}catch(Throwable e){r.put("passed",false);r.put("failure",e.toString());e.printStackTrace(System.err);}r.put("assertions",assertions-a);rows.add(r);}
 static Throwable rejected(String code,Body body)throws Exception {
  try{body.run();throw new AssertionError("expected refusal "+code);}
  catch(AssertionError e){throw e;}
  catch(Exception e){Throwable x=e;while(x instanceof InvocationTargetException&&x.getCause()!=null)x=x.getCause();String actual=x instanceof InputChannelIsolation.Refusal?((InputChannelIsolation.Refusal)x).code:x.getMessage();check(code==null||code.equals(actual),"actual "+actual+" expected "+code);return x;}
 }
 static final class F {
  final CalendarWindowHostTest.Fixture base=new CalendarWindowHostTest.Fixture();
  final BrokerDateHost broker;
  F()throws Exception{MotionEvent.reset();WindowInfosListener.onRegister=base::emit;broker=new BrokerDateHost(base.config,base.packages);}
  JSONObject value(){return base.requestObject().put("op","calendar_date")
   .put("owner_task_id",base.config.publicOwnGroupScope.taskId).put("goal_sha256",CalendarWindowHostTest.HASH)
   .put("date","2026-11-25").put("observation_id",CalendarWindowHostTest.repeat('c',32))
   .put("screen_sha256",CalendarWindowHostTest.repeat('d',64)).put("permit_sha256",CalendarWindowHostTest.repeat('e',64))
   .put("attempt_record_sha256",CalendarWindowHostTest.repeat('f',64)).put("display_width",100).put("display_height",200)
   .put("display_rotation",0).put("left",20).put("top",30).put("right",40).put("bottom",50);}
  BrokerProtocol.Request request()throws Exception{return parse(value());}
  boolean run()throws Exception{return broker.run(request());}
  List<Map<String,Object>> calls(){return broker.inputManager.calls;}
  JSONObject proof(){return broker.calendarDateEvidence;}
 }
 static BrokerProtocol.Request parse(JSONObject v)throws Exception{return BrokerProtocol.Request.parse(v.toString().getBytes(StandardCharsets.UTF_8));}
 static void calls(F f,int down,int up){
  int d=0,u=0;for(Map<String,Object> r:f.calls()){int a=((Number)r.get("action")).intValue();if(a==MotionEvent.ACTION_DOWN)d++;if(a==MotionEvent.ACTION_UP)u++;check(a!=MotionEvent.ACTION_CANCEL,"no CANCEL");check(((Number)r.get("display")).intValue()==7,"only owned display");check(((Number)r.get("uid")).intValue()==1010123,"actual full UID");}
  check(d==down&&u==up&&f.calls().size()==down+up,"exact DOWN/UP/no other count");
 }
 static void drained(F f){check(f.broker.calendarWindowCapture==null,"capture actually cleared after drain");check(!f.broker.effectInFlight,"effect flag left");check(MotionEvent.created==MotionEvent.recycled,"all constructed motion recycled");}
 static void noCompletion(F f){check(!f.proof().getBoolean("date_independently_verified")&&!f.proof().getBoolean("business_completion_verified"),"transport not date/business success");}
 public static final class MutableConstant {public static int VALUE=1;}
 public static final class WrongConstant {public static final String VALUE="1";}
 public static final class ExactConstant {public static final int VALUE=536870912;}

 public static void main(String[] args)throws Exception {
  test("strict_calendar_wire_valid_exact_fields_but_data_only",()->{
   F f=new F();BrokerProtocol.Request r=f.request();r.authenticate(f.base.config,10001);
   check(r.version==4&&r.targetUid==-1&&r.calendarDate!=null,"no client numeric UID");
   check(r.calendarDate.ownerTaskId.equals(f.base.config.publicOwnGroupScope.taskId)&&r.calendarDate.date.equals("2026-11-25"),"exact binding values");calls(f,0,0);
  });
  test("strict_calendar_wire_rejects_missing_extra_and_wrong_type",()->{
   F f=new F();JSONObject miss=f.value();miss.remove("attempt_record_sha256");rejected("REQUEST_FIELDS",()->parse(miss));
   rejected("REQUEST_FIELDS",()->parse(f.value().put("target_uid",1010123)));
   rejected("REQUEST_FIELDS",()->parse(f.value().put("op","back")));
   rejected("FIELD_TYPE",()->parse(f.value().put("left","20")));
   rejected("CALENDAR_DATE_BINDING_INVALID",()->parse(f.value().put("permit_sha256","abcd")));calls(f,0,0);
  });
  test("strict_calendar_wire_rejects_scope_package_iso_and_rectangle",()->{
   F f=new F();rejected("CALENDAR_DATE_SCOPE_REQUIRED",()->parse(f.value().put("version",2)));
   rejected("CALENDAR_DATE_PACKAGE_REQUIRED",()->parse(f.value().put("package",ProfileTarget.XIAOMI)));
   for(String date:new String[]{"2026-02-30","1969-12-31","2026-11-25x"})rejected("CALENDAR_ISO_DATE_INVALID",()->parse(f.value().put("date",date)));
   rejected("CALENDAR_DATE_RECT_INVALID",()->parse(f.value().put("left",40)));
   rejected("CALENDAR_DATE_INTEGER_INVALID",()->parse(f.value().put("right",101)));
   check(parse(f.value().put("date","2028-02-29")).calendarDate!=null,"valid Gregorian leap day");calls(f,0,0);
  });
  test("actual_complete_dispatch_success_has_exact_targeted_pointer_pair",()->{
   F f=new F();f.broker.inputManager.beforeDownReturn=()->SystemClock.uptime=82;
   check(f.run(),"actual method transport accepted");calls(f,1,1);
   Map<String,Object> d=f.calls().get(0),u=f.calls().get(1);
   for(Map<String,Object> r:f.calls()){
    check(((Number)r.get("mode")).intValue()==1,"actual WAIT_FOR_RESULT port constant");
    check(((Number)r.get("flags")).intValue()==MotionEvent.FLAG_NO_FOCUS_CHANGE,"actual NO_FOCUS_CHANGE port field");
    check(((Number)r.get("device")).intValue()==-1&&((Number)r.get("source")).intValue()==4098,"virtual injected device and touch source");
    check(((Number)r.get("pointer")).intValue()==0&&((Number)r.get("tool")).intValue()==1,"same single finger");
    check(((Number)r.get("x")).doubleValue()==30&&((Number)r.get("y")).doubleValue()==40,"logical centroid");
   }
   check(d.get("down").equals(u.get("down"))&&((Number)d.get("down")).longValue()==71,"original uptime downTime");
   check(((Number)u.get("time")).longValue()==82,"UP actual uptime not elapsed clock");
   check(f.proof().getBoolean("attempt_consumed")&&f.proof().getBoolean("input_pair_accepted"),"actual one-use receipt");
   check(f.broker.profileOwnedTask.reads==2&&f.broker.guards==5,"complete owner/guard sequence");
   check(WindowInfosListener.registrations==1&&WindowInfosListener.unregistrations==1,"fresh capture and exact removal");
   check(f.broker.profileRequestDispatched,"effect attempted flag");noCompletion(f);drained(f);
  });
  test("down_false_never_sends_up_cancel_or_second_down",()->{
   F f=new F();f.broker.inputManager.downResult=false;rejected("CALENDAR_DOWN_NOT_CONFIRMED",f::run);calls(f,1,0);
   check(f.proof().getBoolean("attempt_consumed")&&!f.proof().getBoolean("down_returned_true")&&!f.proof().getBoolean("up_attempted"),"unknown down recorded");noCompletion(f);drained(f);
  });
  test("down_exception_never_sends_up_cancel_or_second_down",()->{
   F f=new F();f.broker.inputManager.downError=new IllegalStateException("synthetic Binder outcome unknown");rejected("synthetic Binder outcome unknown",f::run);calls(f,1,0);
   check(f.proof().getString("phase").equals("down_outcome_unknown_owned_cleanup_only"),"unknown retained");drained(f);
  });
  test("accepted_down_then_original_deadline_no_up",()->{
   F f=new F();f.broker.inputManager.beforeDownReturn=()->SystemClock.now=1500;
   rejected("REQUEST_EXPIRED",()->f.broker.run(parse(f.value().put("deadline_elapsed_ms",1500))));calls(f,1,0);
   check(f.proof().getBoolean("down_returned_true")&&!f.proof().getBoolean("up_attempted"),"known down cannot renew");drained(f);
  });
  test("accepted_down_then_four_second_clip_no_up",()->{
   F f=new F();f.broker.inputManager.beforeDownReturn=()->SystemClock.now=5000;
   rejected(null,()->f.broker.run(parse(f.value().put("deadline_elapsed_ms",7000))));calls(f,1,0);
   check(f.proof().getLong("original_request_deadline_elapsed_ms")==7000&&f.proof().getLong("effect_deadline_elapsed_ms")==5000,"4s clip no extension");drained(f);
  });
  test("accepted_down_then_retirement_or_cancel_no_up",()->{
   F closed=new F();closed.broker.inputManager.beforeDownReturn=()->closed.broker.closing.set(true);
   rejected("SESSION_CLOSING",closed::run);calls(closed,1,0);drained(closed);
   F cancel=new F();cancel.broker.inputManager.beforeDownReturn=()->cancel.broker.cancelled=true;
   rejected("BROKER_CANCELLED",cancel::run);calls(cancel,1,0);drained(cancel);
  });
  test("accepted_down_then_new_callback_no_up",()->{
   F f=new F();f.broker.inputManager.beforeDownReturn=f.base::emit;
   rejected("INPUT_CALLBACK_CHANGED_DURING_READ",f::run);calls(f,1,0);check(f.proof().getBoolean("down_returned_true"),"known down retained");drained(f);
  });
  test("accepted_down_then_owned_window_proof_expiry_no_up",()->{
   F f=new F();f.broker.inputManager.beforeDownReturn=()->SystemClock.now=2000;
   rejected(null,f::run);calls(f,1,0);check(f.proof().getBoolean("down_returned_true"),"no false preeffect classification");drained(f);
  });
  test("up_false_is_unknown_and_never_replayed",()->{
   F f=new F();f.broker.inputManager.upResult=false;rejected("CALENDAR_UP_NOT_CONFIRMED",f::run);calls(f,1,1);
   check(f.proof().getBoolean("down_returned_true")&&f.proof().getBoolean("up_attempted")&&!f.proof().getBoolean("up_returned_true"),"partial pair retained");noCompletion(f);drained(f);
  });
  test("up_exception_is_unknown_and_never_cancelled_or_replayed",()->{
   F f=new F();f.broker.inputManager.upError=new IllegalStateException("synthetic UP unknown");
   rejected("synthetic UP unknown",f::run);calls(f,1,1);drained(f);
  });
  test("late_up_return_is_not_success_or_new_budget",()->{
   F f=new F();f.broker.inputManager.beforeUpReturn=()->SystemClock.now=5000;
   rejected("CALENDAR_DATE_DEADLINE",f::run);calls(f,1,1);check(f.proof().getBoolean("input_pair_accepted"),"actual accepted pair preserved despite late result");noCompletion(f);drained(f);
  });
  test("same_lease_second_date_is_consumed_once",()->{
   F f=new F();check(f.run(),"first actual run");rejected("CALENDAR_DATE_ALREADY_CONSUMED",()->f.broker.run(parse(f.value().put("request_id","00000000-0000-4000-8000-000000000003"))));calls(f,1,1);
   check(f.broker.calendarDateConsumed.get(),"not resurrected");check(WindowInfosListener.registrations==2&&WindowInfosListener.unregistrations==2,"second refusal also drains");drained(f);
  });
  test("owner_task_wrong_refused_before_platform_read_or_input",()->{
   F f=new F();rejected("CALENDAR_DATE_SCOPE_REQUIRED",()->f.broker.run(parse(f.value().put("owner_task_id",CalendarWindowHostTest.repeat('9',32)))));calls(f,0,0);
   check(f.broker.profileOwnedTask.reads==0&&WindowInfosListener.registrations==0&&!f.broker.calendarDateConsumed.get(),"no admission or effect");
  });
  test("actual_guard_rechecks_installed_full_identity",()->{
   F f=new F();f.base.packages.installedTarget=new ProfileTarget(f.base.profile,1010124,ProfileTarget.CTRIP,"ctrip.android.view/Main",1,
    java.util.Collections.singletonMap("base",CalendarWindowHostTest.HASH),java.util.Collections.singleton(CalendarWindowHostTest.HASH));
   rejected("PROFILE_INSTALLATION_IDENTITY_CHANGED",f::run);calls(f,0,0);check(WindowInfosListener.registrations==0,"actual guard before capture");
  });
  test("display_rotation_and_dimensions_must_match_actual_image",()->{
   F f=new F();rejected("CALENDAR_DISPLAY_GEOMETRY_CHANGED",()->f.broker.run(parse(f.value().put("display_rotation",1))));calls(f,0,0);
   F g=new F();rejected("CALENDAR_DISPLAY_GEOMETRY_CHANGED",()->g.broker.run(parse(g.value().put("display_width",101))));calls(g,0,0);
  });
  test("fresh_task_identity_change_refused_and_drained",()->{
   F f=new F();f.broker.profileOwnedTask.beforeRead=()->{if(f.broker.profileOwnedTask.reads==2)f.broker.profileOwnedTask.taskToken="00000000-0000-4000-8000-000000000009";};
   rejected("INPUT_OWNED_TASK_CHANGED",f::run);calls(f,0,0);drained(f);
  });
  test("final_guard_callback_and_cancellation_refused_before_down",()->{
   F f=new F();f.broker.beforeGuard=()->{if(f.broker.guards==4)f.base.emit();};
   rejected("INPUT_CALLBACK_CHANGED_DURING_READ",f::run);calls(f,0,0);drained(f);
   F g=new F();g.broker.beforeGuard=()->{if(g.broker.guards==4)g.broker.cancelled=true;};
   rejected("BROKER_CANCELLED",g::run);calls(g,0,0);drained(g);
  });
  test("last_motion_construction_deadline_fence_precedes_down_claim",()->{
   F f=new F();MotionEvent.afterSetDisplay=()->SystemClock.now=5000;
   rejected(null,f::run);calls(f,0,0);check(MotionEvent.created==1,"reached actual motion construction before refusing");check(!f.broker.calendarDateConsumed.get(),"expiry before CAS");drained(f);
  });
  test("actual_cross_display_input_and_window_aliases_refused",()->{
   for(int display:new int[]{0,1,9}){
    F f=new F();f.base.windows[1]=CalendarWindowHostTest.raw(display,10099,"fixture.other",f.base.input,new Binder(),InputConfig.NOT_TOUCHABLE);
    rejected("INPUT_CHANNEL_CROSS_DISPLAY_ALIAS",f::run);calls(f,0,0);drained(f);
   }
   F f=new F();f.base.windows[1].windowToken=f.base.window;rejected("INPUT_WINDOW_TOKEN_MATCH_NOT_UNIQUE",f::run);calls(f,0,0);drained(f);
  });
  test("actual_spy_clone_foreign_receiver_and_dead_token_refused",()->{
   for(int flag:new int[]{InputConfig.SPY,InputConfig.CLONE}){
    F f=new F();CalendarWindowHostTest.append(f.base,CalendarWindowHostTest.raw(7,1010123,ProfileTarget.CTRIP,new Binder(),new Binder(),flag));
    rejected("INPUT_OWNED_SPY_OR_CLONE",f::run);calls(f,0,0);drained(f);
   }
   F f=new F();CalendarWindowHostTest.append(f.base,CalendarWindowHostTest.raw(7,1000,"android.permission",new Binder(),new Binder(),0));
   rejected("INPUT_FOREIGN_TOUCH_RECIPIENT",f::run);calls(f,0,0);drained(f);
   F dead=new F();dead.base.input.alive=false;rejected("INPUT_CHANNEL_TOKEN_NOT_LIVE",dead::run);calls(dead,0,0);drained(dead);
  });
  test("rect_must_fit_matched_window_and_point_real_touchable_region",()->{
   F f=new F();f.base.windows[0].frame=new Rect(30,0,100,200);rejected("CALENDAR_RECT_OUTSIDE_MATCHED_WINDOW",f::run);calls(f,0,0);drained(f);
   F g=new F();g.base.windows[0].touchableRegion=new Region(new Rect(0,0,10,10));rejected("CALENDAR_POINT_OUTSIDE_TOUCHABLE_REGION",g::run);calls(g,0,0);drained(g);
  });
  test("point_is_logical_not_transformed_twice_to_target_local",()->{
   F f=new F();f.base.windows[0].transform.setValues(new float[]{.5f,0,0,0,.5f,0,0,0,1});check(f.run(),"valid target local transform");
   calls(f,1,1);check(((Number)f.calls().get(0).get("x")).doubleValue()==30,"logical coordinate kept");drained(f);
  });
  test("listener_unregister_unknown_retains_unknown_after_input",()->{
   F f=new F();WindowInfosListener.unregisterFails=true;rejected("INPUT_LISTENER_UNREGISTER_UNKNOWN",f::run);calls(f,1,1);
   check(f.broker.calendarWindowCapture!=null&&!f.broker.calendarWindowCapture.locallyDrained(),"active unknown retained");
   check(WindowInfosListener.unregistrations==1&&!f.broker.effectInFlight,"no second unregister or false in-flight");
   check(f.proof().getBoolean("input_pair_accepted"),"input history not erased");noCompletion(f);
  });
  test("historical_readonly_probe_is_not_reused_for_effect_census",()->{
   F f=new F();BrokerProbeHost old=f.base.broker();old.run(f.base.request());check(old.calendarProbeEvidence.getBoolean("qualified"),"actual old read-only probe");
   check(WindowInfosListener.unregistrations==1&&old.calendarWindowCapture==null,"old capture closed");
   check(f.run(),"new actual broker date method");calls(f,1,1);check(WindowInfosListener.registrations==2&&WindowInfosListener.unregistrations==2,"fresh new registration mandatory");drained(f);
  });
  test("platform_constant_helper_rejects_mutable_or_wrong_type_no_fallback",()->{
   check(BrokerDateHost.constant(ExactConstant.class,"VALUE")==ExactConstant.VALUE,"actual field read");
   rejected("CALENDAR_PLATFORM_CONSTANT_UNAVAILABLE",()->BrokerDateHost.constant(MutableConstant.class,"VALUE"));
   rejected("CALENDAR_PLATFORM_CONSTANT_UNAVAILABLE",()->BrokerDateHost.constant(WrongConstant.class,"VALUE"));
   Throwable e=rejected(null,()->BrokerDateHost.constant(ExactConstant.class,"MISSING"));check(e instanceof NoSuchFieldException,"missing actual field refusal");
  });
  boolean pass=true;for(Map<String,Object> r:rows)pass&=Boolean.TRUE.equals(r.get("passed"));
  JSONObject out=new JSONObject().put("schema","hepta.calendar-date-broker-host-cases.v1").put("all_pass",pass).put("cases",rows.size()).put("assertions",assertions).put("rows",rows)
   .put("phone_actions",0).put("android_runtime",false).put("actual_broker_methods_extracted",true).put("platform_effects_are_host_ports",true)
   .put("actual_app_attempt_or_slot_authority_tested",false).put("vendor_rom_qualified",false).put("actual_handler_enabled",false);
  Files.write(Paths.get(args[0]),out.toString(2).getBytes(StandardCharsets.UTF_8));
  System.out.println(new JSONObject().put("all_pass",pass).put("cases",rows.size()).put("assertions",assertions));
  if(!pass)throw new AssertionError("calendar date host failures");
 }
}
