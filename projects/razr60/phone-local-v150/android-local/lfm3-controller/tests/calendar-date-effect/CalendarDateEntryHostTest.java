package org.trillionnium.hepta.background;
import android.os.SystemClock;
import android.view.MotionEvent;
import android.window.WindowInfosListener;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

/** Actual complete perform and date methods. Socket/authentication use the real parser; Android IO is explicit. */
public final class CalendarDateEntryHostTest {
 interface Body {void run()throws Exception;}
 static final List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();
 static int assertions;
 static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
 static void test(String name,Body body){int n=assertions;Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);try{body.run();row.put("passed",true);}catch(Throwable e){row.put("passed",false);row.put("failure",e.toString());e.printStackTrace(System.err);}row.put("assertions",assertions-n);rows.add(row);}
 static JSONObject run(CalendarDateHostTest.F f,JSONObject request)throws Exception{return new JSONObject(new String(f.broker.runHandler(request.toString().getBytes(StandardCharsets.UTF_8),10001),StandardCharsets.UTF_8));}
 static void calls(CalendarDateHostTest.F f,int down,int up){
  int d=0,u=0;for(Map<String,Object> call:f.calls()){
   int action=((Number)call.get("action")).intValue();if(action==0)d++;if(action==1)u++;
   check(action==0||action==1,"no CANCEL or other operation");
   check(((Number)call.get("uid")).intValue()==1010123,"actual target full UID");
   check(((Number)call.get("display")).intValue()==7,"only owned VD");
  }
  check(d==down&&u==up&&f.calls().size()==down+up,"exact targeted pair count");
 }
 static void finalState(CalendarDateHostTest.F f){
  check(f.broker.activeProfileRequest==null,"real perform finally cleared active request");
  check(f.broker.calendarWindowCapture==null,"actual listener drained and cleared");
  check(!f.broker.effectInFlight,"actual effect finally returned");
  check(MotionEvent.created==MotionEvent.recycled,"constructed motions actually recycled");
 }
 static void refused(CalendarDateHostTest.F f,JSONObject result,String error,boolean dispatched){
  check(!result.getBoolean("ok")&&error.equals(result.getString("error")),"real perform catch preserved "+error);
  check(result.getBoolean("dispatched")==dispatched,"real catch preserves attempted effect");
  check(f.broker.cleanupCalls==1&&f.broker.cleanupWaits==1,"actual catch invoked cleanup exactly once");
  check(!f.broker.serve&&f.broker.responseCalls==1,"no serving retry after catch");
  check(f.broker.cleanupWaitBudget>0&&f.broker.cleanupWaitBudget<=1500,"original cleanup budget clipping");
  check("CLOSING".equals(result.getString("state")),"cleanup port does not pretend released");
  finalState(f);
 }
 public static void main(String[] args)throws Exception{
  test("complete_perform_dedicated_handler_dispatches_one_actual_pair",()->{
   CalendarDateHostTest.F f=new CalendarDateHostTest.F();JSONObject result=run(f,f.value());
   check(result.getBoolean("ok")&&result.getBoolean("dispatched"),"actual entry selected date branch");
   check(result.getBoolean("host_response_port"),"explicit serialization port");
   calls(f,1,1);JSONObject proof=f.proof();
   check(proof.getBoolean("effect_route_integrated")&&proof.getBoolean("input_pair_accepted"),"actual route truth and pair evidence");
   check(!proof.getBoolean("date_independently_verified")&&!proof.getBoolean("business_completion_verified"),"pair is not date/business proof");
   check(f.broker.cleanupCalls==0&&f.broker.responseCalls==1&&f.broker.serve,"success did not cleanup or retry");
   check(WindowInfosListener.registrations==1&&WindowInfosListener.unregistrations==1,"new live census and removal");
   finalState(f);
  });
  test("complete_perform_permission_preparation_refuses_before_motion",()->{
   CalendarDateHostTest.F f=new CalendarDateHostTest.F();f.broker.profilePreparing=true;
   JSONObject result=run(f,f.value());calls(f,0,0);check(MotionEvent.created==0,"permission barrier before motion construction");
   refused(f,result,"PROFILE_PERMISSION_PREPARATION_ACTIVE",false);
  });
  test("complete_perform_original_deadline_refuses_before_motion",()->{
   CalendarDateHostTest.F f=new CalendarDateHostTest.F();SystemClock.now=1500;
   JSONObject result=run(f,f.value().put("deadline_elapsed_ms",1500));calls(f,0,0);
   refused(f,result,"REQUEST_EXPIRED",false);
  });
  test("complete_perform_current_full_identity_refusal_is_terminal",()->{
   CalendarDateHostTest.F f=new CalendarDateHostTest.F();
   f.base.packages.installedTarget=new ProfileTarget(f.base.profile,1010124,ProfileTarget.CTRIP,"ctrip.android.view/Main",1,
    java.util.Collections.singletonMap("base",CalendarWindowHostTest.HASH),java.util.Collections.singleton(CalendarWindowHostTest.HASH));
   JSONObject result=run(f,f.value());calls(f,0,0);refused(f,result,"PROFILE_INSTALLATION_IDENTITY_CHANGED",false);
  });
  test("complete_perform_unknown_down_no_up_cancel_or_replay",()->{
   CalendarDateHostTest.F f=new CalendarDateHostTest.F();f.broker.inputManager.downResult=false;
   JSONObject result=run(f,f.value());calls(f,1,0);refused(f,result,"CALENDAR_DOWN_NOT_CONFIRMED",true);
   check(f.proof().getBoolean("attempt_consumed")&&!f.proof().getBoolean("up_attempted"),"unknown down preserved and slot remains spent");
  });
  test("complete_perform_unknown_up_preserves_dispatched_and_closes",()->{
   CalendarDateHostTest.F f=new CalendarDateHostTest.F();f.broker.inputManager.upResult=false;
   JSONObject result=run(f,f.value());calls(f,1,1);refused(f,result,"CALENDAR_UP_NOT_CONFIRMED",true);
   check(f.proof().getBoolean("down_returned_true")&&f.proof().getBoolean("up_attempted"),"actual partial pair retained");
  });
  test("complete_perform_success_does_not_restore_second_date_claim",()->{
   CalendarDateHostTest.F f=new CalendarDateHostTest.F();check(run(f,f.value()).getBoolean("ok"),"first actual handler");
   JSONObject result=run(f,f.value().put("request_id","00000000-0000-4000-8000-000000000003"));
   calls(f,1,1);check(!result.getBoolean("ok")&&"CALENDAR_DATE_ALREADY_CONSUMED".equals(result.getString("error")),"same lease cannot dispatch twice");
   check(!result.getBoolean("dispatched")&&f.broker.calendarDateConsumed.get(),"second request no effect and original claim retained");
   check(f.broker.cleanupCalls==1&&f.broker.responseCalls==2&&!f.broker.serve,"single cleanup after second refusal");
   finalState(f);
  });
  test("complete_perform_last_callback_change_prevents_down",()->{
   CalendarDateHostTest.F f=new CalendarDateHostTest.F();MotionEvent.afterSetDisplay=f.base::emit;
   JSONObject result=run(f,f.value());calls(f,0,0);
   check(MotionEvent.created==1&&!f.broker.calendarDateConsumed.get(),"actual motion reached but callback invalidated before CAS");
   refused(f,result,"INPUT_CALLBACK_CHANGED_DURING_READ",false);
  });
  test("actual_request_authentication_refuses_foreign_peer_before_entry",()->{
   CalendarDateHostTest.F f=new CalendarDateHostTest.F();boolean rejected=false;
   try{f.broker.runHandler(f.value().toString().getBytes(StandardCharsets.UTF_8),10002);}
   catch(BrokerProtocol.Refusal e){rejected=true;check(e.getMessage()!=null,"actual authentication refusal reason");}
   check(rejected,"foreign peer rejected");calls(f,0,0);
   check(f.broker.responseCalls==0&&f.broker.cleanupCalls==0&&f.broker.activeProfileRequest==null,"never entered perform");
  });
  boolean pass=true;for(Map<String,Object> row:rows)pass&=Boolean.TRUE.equals(row.get("passed"));
  JSONObject result=new JSONObject().put("schema","hepta.calendar-date-handler-host-cases.v1").put("all_pass",pass)
   .put("cases",rows.size()).put("assertions",assertions).put("rows",rows).put("complete_actual_perform_extracted",true)
   .put("actual_app_attempt_or_slot_authority_tested",false).put("platform_effects_are_host_ports",true)
   .put("platform_cleanup_executed",false).put("whole_socket_loop_executed",false).put("vendor_rom_qualified",false).put("phone_actions",0);
  Files.write(Paths.get(args[0]),result.toString(2).getBytes(StandardCharsets.UTF_8));
  System.out.println(new JSONObject().put("all_pass",pass).put("cases",rows.size()).put("assertions",assertions));
  if(!pass)throw new AssertionError("calendar handler host failures");
 }
}
