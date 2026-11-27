package org.trillionnium.hepta.local;
import android.net.LocalSocket;
import android.os.SystemClock;
import android.provider.Settings;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;
/** Actual full BackgroundSession.close, journal writer and entry guards.
 * Reuses unchanged explicit Android socket/display/clock/OS test ports. */
public final class ClosingBackgroundSessionHostTest {
 interface Work {void run()throws Exception;}
 private static final List<JSONObject> rows=new ArrayList<JSONObject>();
 private static int assertions;
 private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
 private static Object field(BackgroundSession s,String name)throws Exception{Field f=BackgroundSession.class.getDeclaredField(name);f.setAccessible(true);return f.get(s);}
 private static void pass(String name,Work w)throws Exception{
  LocalSocket.reset();SystemClock.now=1000000;Settings.Global.boot=10;android.system.Os.failUnlink=false;
  int before=assertions;
  try{w.run();rows.add(new JSONObject().put("name",name).put("status","PASS").put("assertions",assertions-before));}
  catch(Exception|AssertionError e){rows.add(new JSONObject().put("name",name).put("status","FAIL").put("error",e.toString()));throw e;}
 }
 private static JSONObject journal(BackgroundSessionHostTest.Env e)throws Exception{
  return new JSONObject(new String(Files.readAllBytes(e.directory.resolve(BackgroundSession.JOURNAL)),StandardCharsets.UTF_8));
 }
 private static void tests()throws Exception{
  pass("actual_failed_close_normalizes_local_UNKNOWN_but_keeps_raw_CLOSING",()->{
   try(BackgroundSessionHostTest.Env e=new BackgroundSessionHostTest.Env()){
    e.active();e.journal();final byte[][] sent={null};
    LocalSocket.responder=req->{
     JSONObject v=BackgroundSessionHostTest.decode(BackgroundSessionHostTest.response(req,"CLOSING",7,false,false));
     v.put("error","CLEANUP_NOT_CONFIRMED");sent[0]=v.toString().getBytes(StandardCharsets.UTF_8);
     return BackgroundSessionHostTest.frame(sent[0]);
    };
    BackgroundSession.Cleanup result=e.session.close();
    check(!result.known&&e.journalPresent()&&!e.session.released(),"failed close cannot release");
    check("CLEANUP_UNKNOWN".equals(journal(e).getString("state")),"actual_nonexception_CLOSING_close_must_save_UNKNOWN");
    JSONObject raw=(JSONObject)field(e.session,"lastResponse");
    check("CLOSING".equals(raw.getString("state"))&&"CLEANUP_NOT_CONFIRMED".equals(raw.getString("error")),"actual raw response is preserved");
    check(new String(sent[0],StandardCharsets.UTF_8).equals(raw.toString()),"whole raw response unchanged by local state normalization");
    check(LocalSocket.connections==1,"exactly one close request");
   }
  });
  pass("successful_release_keeps_original_absence_and_journal_removal",()->{
   try(BackgroundSessionHostTest.Env e=new BackgroundSessionHostTest.Env()){
    e.active();e.journal();
    LocalSocket.responder=req->{e.context.displays.displays.clear();return BackgroundSessionHostTest.response(req,"RELEASED",7,true,false);};
    BackgroundSession.Cleanup result=e.session.close();
    check(result.known&&!e.journalPresent()&&e.session.released(),"only actual complete release removes lease");
    check(LocalSocket.connections==1,"single original close");
   }
  });
  pass("exceptional_close_still_keeps_unknown_barrier",()->{
   try(BackgroundSessionHostTest.Env e=new BackgroundSessionHostTest.Env()){
    e.active();e.journal();LocalSocket.responder=req->{throw new java.net.SocketTimeoutException("explicit host transport timeout");};
    check(!e.session.close().known&&e.journalPresent()&&!e.session.released(),"timeout cannot release");
    check("CLEANUP_UNKNOWN".equals(journal(e).getString("state")),"existing exceptional UNKNOWN behavior preserved");
   }
  });
  pass("unconfirmed_RELEASED_response_with_live_display_is_UNKNOWN",()->{
   try(BackgroundSessionHostTest.Env e=new BackgroundSessionHostTest.Env()){
    e.active();e.journal();LocalSocket.responder=req->BackgroundSessionHostTest.response(req,"RELEASED",7,true,false);
    check(!e.session.close().known&&e.journalPresent(),"live display not absence");
    check("CLEANUP_UNKNOWN".equals(journal(e).getString("state")),"completed unproved release remains unknown");
    check("RELEASED".equals(((JSONObject)field(e.session,"lastResponse")).getString("state")),"actual RELEASED response remains raw, not a local proof");
   }
  });
  pass("bare_CLOSING_string_without_exact_retained_origin_does_not_admit",()->{
   try(BackgroundSessionHostTest.Env e=new BackgroundSessionHostTest.Env()){
    e.active();e.journal();BackgroundSessionHostTest.field(e.session,"state","CLOSING");
    BackgroundSessionHostTest.field(e.session,"retired",true);
    Object value=BackgroundSessionHostTest.invoke(e.session,"businessCleanupFailureState",new Class<?>[]{});
    check(Boolean.FALSE.equals(value),"missing original retained config/failed close must refuse");
    check(!e.session.publicProfileBusinessCleanupEntryEligible(),"full business entry still refuses");
   }
  });
 }
 public static void main(String[] args)throws Exception{
  if(args.length!=1)throw new IllegalArgumentException("output");Throwable error=null;
  try{tests();}catch(Throwable e){error=e;}
  JSONObject result=new JSONObject().put("schema","hepta.ce5.actual-close-host.v1").put("status",error==null?"PASS":"FAIL")
    .put("cases",rows.size()).put("assertions",assertions).put("rows",rows).put("actual_full_BackgroundSession",true)
    .put("android_io_is_host_boundary",true).put("retained_effect_performed",false).put("phone_operations",0);
  Files.write(Paths.get(args[0]),result.toString().getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
  System.out.println(new JSONObject().put("status",result.get("status")).put("cases",rows.size()).put("assertions",assertions));
  if(error!=null){error.printStackTrace(System.err);System.exit(1);}
 }
}
