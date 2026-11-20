package org.trillionnium.hepta.background;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.*;
import org.json.*;
/** Host-only synthetic Proc boundary; actual production census and validator. */
public final class ProfileRecoveryCensusHostTest {
 static final ProfilePrelaunchRecovery.Request R;
 static {try{R=ProfileRecoveryHostTest.request(ProfileRecoveryHostTest.journal());}catch(Exception e){throw new ExceptionInInitializerError(e);}}
 static int cases,assertions;static final JSONArray names=new JSONArray();
 interface Work{void run()throws Exception;}
 static void check(boolean value){assertions++;if(!value)throw new AssertionError();}
 static void ok(String name,Work work)throws Exception{work.run();names.put(name);cases++;}
 static Exception gone(int pid,boolean causeSuppressed,boolean directSuppressed)throws Exception{
  IOException cause=new IOException("fixture native ENOENT");
  if(causeSuppressed)cause.addSuppressed(new IOException("fixture close failed"));
  Exception out;
  try{
   Class<?> type=Class.forName("org.trillionnium.hepta.background.ProfileRecoveryProcesses$ProcessGone");
   Constructor<?> ctor=type.getDeclaredConstructor(int.class,Throwable.class);ctor.setAccessible(true);
   out=(Exception)ctor.newInstance(pid,cause);
  }catch(ClassNotFoundException old){out=new IOException("fixture native ENOENT before retry support",cause);}
  if(directSuppressed)out.addSuppressed(new IOException("fixture unresolved close"));
  return out;
 }
 static boolean typedAvailable(){
  try{Class.forName("org.trillionnium.hepta.background.ProfileRecoveryProcesses$ProcessGone");return true;}
  catch(ClassNotFoundException old){return false;}
 }
 static final class Proc implements ProfileRecoveryProcesses.Proc {
  final String mode;int enumerations;long time=R.started+1;
  final Map<String,Integer> round=new HashMap<String,Integer>(),total=new HashMap<String,Integer>();
  Proc(String mode){this.mode=mode;}
  int call(String key){int n=round.containsKey(key)?round.get(key)+1:1;round.put(key,n);total.put(key,total.containsKey(key)?total.get(key)+1:1);return n;}
  int total(String key){return total.containsKey(key)?total.get(key):0;}
  boolean unstable(){return "twice".equals(mode)?enumerations<=2:"always".equals(mode)||enumerations==1;}
  public String[] entries(){
   enumerations++;round.clear();
   if("second_expired".equals(mode)&&enumerations==2)time=R.deadline;
   if("stable".equals(mode))return new String[]{"50","80","100"};
   if(enumerations>1&&!unstable()){
    if("no_self_after_retry".equals(mode))return new String[]{"80","100"};
    return new String[]{"50","80","100"};
   }
   return new String[]{"50","80","90"};
  }
  public ProfileRecoveryProcesses.Directory directory(int pid)throws Exception{
   int n=call("dir"+pid);
   if(pid==50&&"self_gone".equals(mode))throw gone(pid,false,false);
   if(pid==80&&"permission".equals(mode))throw new IOException("fixture EACCES");
   if(pid==80&&("identity_then_gone".equals(mode)||"uid_then_gone".equals(mode))&&n==2)throw gone(pid,false,false);
   if(pid==90&&unstable()&&(!"late_gone".equals(mode)||n==2)){
    if("deadline_after_gone".equals(mode))time=R.deadline;
    throw gone(pid,"cause_suppressed".equals(mode),"direct_suppressed".equals(mode));
   }
   long inode=pid+100;
   if(pid==80&&"directory_changed".equals(mode)&&n==2)inode++;
   if(pid==50&&"self_directory".equals(mode)&&enumerations>1)inode++;
   return new ProfileRecoveryProcesses.Directory(0,1,inode);
  }
  public byte[] read(int pid,String leaf,int maximum)throws Exception{
   int n=call(leaf+pid);
   if(pid==80&&"non_typed_enoent".equals(mode))throw new IOException("ENOENT");
   if(pid==100&&"fresh_unknown".equals(mode))throw new IOException("fixture fresh row unreadable");
   if("stat".equals(leaf)){
    if(pid==80&&"malformed".equals(mode))return ProfileRecoveryHostTest.bytes("bad stat");
    long ticks=pid==50?100:200+pid;
    if(pid==50&&"self_ticks".equals(mode)&&enumerations>1)ticks++;
    if(pid==80&&"identity_then_gone".equals(mode)&&n==2)ticks++;
    return ProfileRecoveryHostTest.stat(pid,ticks,0);
   }
   if("status".equals(leaf)){
    int uid=pid==80&&"uid_then_gone".equals(mode)&&n==2?1:0;
    return ProfileRecoveryHostTest.status(pid,uid,uid,uid,uid);
   }
   if(!"cmdline".equals(leaf))throw new AssertionError("unexpected leaf");
   if(pid==80&&"broker".equals(mode))return ProfileRecoveryHostTest.bytes("app_process64\0/\0"+ProfileRecoveryProcesses.BROKER+"\0");
   if(pid==80&&"generation".equals(mode))return ProfileRecoveryHostTest.bytes("/system/bin/sh\0-c\0pending "+R.generation+"\0");
   return ProfileRecoveryHostTest.bytes(pid==50?"checker\0":"ordinary\0");
  }
  public long now(){return time;}
 }
 static JSONObject capture(Proc p)throws Exception{return ProfileRecoveryProcesses.capture(p,50,R);}
 static void rejected(String name,String mode,String reason,int attempts)throws Exception{
  ok(name,()->{
   Proc p=new Proc(mode);boolean refused=false;
   try{capture(p);}catch(Exception e){refused=true;check(String.valueOf(e.getMessage()).contains(reason));}
   check(refused);check(p.enumerations==attempts);
   if("identity_then_gone".equals(mode)||"uid_then_gone".equals(mode))check(p.total("dir80")==1);
   if("broker".equals(mode)||"generation".equals(mode))check(p.total("dir90")==0);
  });
 }
 public static void main(String[] args)throws Exception{
  if(args.length==1&&"one-vanished".equals(args[0])){
   Proc p=new Proc("restart");JSONObject out=new JSONObject().put("schema","hepta.census-one-vanished-host.v1")
    .put("phone_contacted",false).put("android_runtime",false).put("native_provider","synthetic Proc boundary")
    .put("typed_process_gone_available",typedAvailable());boolean pass=false;
   try{
    JSONObject result=capture(p);check(p.enumerations==2);check(result.getInt("process_count")==3);
    check(p.total("dir50")==4);check(p.total("stat80")==4);pass=true;
    out.put("observed_recovery",true).put("complete",result.getBoolean("complete"));
   }catch(Exception failure){out.put("observed_recovery",false).put("error_type",failure.getClass().getName()).put("error",String.valueOf(failure.getMessage()));}
   out.put("passed",pass).put("enumerations",p.enumerations).put("assertions",assertions);
   System.out.println(out.toString());if(!pass)System.exit(1);return;
  }
  ok("stable_schema_and_original_request_bracket",()->{
   Proc p=new Proc("stable");JSONObject first=capture(p);
   ProfilePrelaunchRecovery.keys(first,"complete","old_creator_absent","started_elapsed_ms","finished_elapsed_ms","self_pid","self_start_ticks","process_count","inspected_count","inventory_sha256");
   check(p.enumerations==1);check(first.getInt("process_count")==3);check(first.getInt("inspected_count")==3);
   Proc q=new Proc("stable");q.time=R.started+6;JSONObject last=capture(q);
   JSONObject proof=ProfileRecoveryHostTest.proof(R).put("process_before",first).put("process_after",last);
   ProfileRecoveryHostTest.valid(proof,R);check(first.getLong("self_start_ticks")==last.getLong("self_start_ticks"));
  });
  for(String mode:new String[]{"restart","late_gone","twice"})ok("whole_census_"+mode,()->{
   Proc p=new Proc(mode);JSONObject got=capture(p),fresh=capture(new Proc("stable"));int attempts="twice".equals(mode)?3:2;
   check(p.enumerations==attempts);check(got.getInt("process_count")==3);check(got.getInt("inspected_count")==3);
   check(got.getString("inventory_sha256").equals(fresh.getString("inventory_sha256")));
   check(p.total("dir50")==2*attempts);check(p.total("stat80")==2*attempts);
   check(got.getLong("started_elapsed_ms")==R.started+1);
  });
  rejected("third_disappearance_is_terminal","always","RECOVERY_PROC_CENSUS_UNSTABLE",3);
  rejected("original_deadline_at_retry_boundary","deadline_after_gone","RECOVERY_PROC_DEADLINE",1);
  rejected("original_deadline_during_fresh_census","second_expired","RECOVERY_PROC_DEADLINE",2);
  rejected("checker_disappearance_is_terminal","self_gone","RECOVERY_PROC_GONE",1);
  rejected("self_start_ticks_pinned_across_attempts","self_ticks","RECOVERY_PROC_SELF_IDENTITY_CHANGED",2);
  rejected("self_directory_pinned_across_attempts","self_directory","RECOVERY_PROC_SELF_IDENTITY_CHANGED",2);
  rejected("known_broker_not_hidden_by_later_gone","broker","RECOVERY_BROKER_OR_CREATOR_STILL_VISIBLE",1);
  rejected("known_generation_not_hidden_by_later_gone","generation","RECOVERY_OLD_GENERATION_STILL_VISIBLE",1);
  rejected("known_ticks_change_before_last_directory_gone","identity_then_gone","RECOVERY_PROC_IDENTITY_CHANGED",1);
  rejected("known_uid_change_before_last_directory_gone","uid_then_gone","RECOVERY_PROC_IDENTITY_CHANGED",1);
  rejected("directory_identity_change_is_terminal","directory_changed","RECOVERY_PROC_IDENTITY_CHANGED",1);
  rejected("permission_failure_not_retried","permission","fixture EACCES",1);
  rejected("untyped_enoent_message_not_retried","non_typed_enoent","ENOENT",1);
  rejected("malformed_identity_not_retried","malformed","RECOVERY_PROC_STAT_FORMAT",1);
  rejected("typed_cause_suppressed_failure_is_terminal","cause_suppressed","RECOVERY_PROC_GONE",1);
  rejected("typed_suppressed_failure_is_terminal","direct_suppressed","RECOVERY_PROC_GONE",1);
  rejected("old_self_row_cannot_fill_new_census","no_self_after_retry","RECOVERY_PROC_SELF_MISSING",2);
  rejected("new_census_unknown_row_cannot_be_skipped","fresh_unknown","fixture fresh row unreadable",2);
  System.out.println(new JSONObject().put("schema","hepta.census-retry-host.v1").put("passed",true)
   .put("cases",cases).put("assertions",assertions).put("case_names",names)
   .put("phone_contacted",false).put("android_runtime",false).put("native_provider","synthetic Proc boundary; actual production census and proof validator").toString());
 }
}
