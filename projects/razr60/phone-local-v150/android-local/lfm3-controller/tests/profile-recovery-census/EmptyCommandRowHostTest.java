package org.trillionnium.hepta.background;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
/** Host-only scripted Proc boundary; invokes the unmodified production census entry points. */
public final class EmptyCommandRowHostTest {
 private static final String G="11111111-1111-1111-1111-111111111111";
 private static final long START=543001L,END=START+ProfilePrelaunchRecovery.LIMIT_MS;
 private static final JSONArray CASES=new JSONArray();private static int checks;
 private static final class Proc implements ProfileRecoveryProcesses.Proc {
  final String mode;final Map<String,Integer> reads=new HashMap<String,Integer>();int lists;long time=START+1;
  Proc(String mode){this.mode=mode;}
  int mark(String key){Integer old=reads.get(key);int n=old==null?1:old+1;reads.put(key,n);return n;}
  int count(String key){Integer n=reads.get(key);return n==null?0:n;}
  int target(){return mode.startsWith("self_")?50:80;}
  public String[] entries(){
   lists++;
   if(mode.equals("only_self")||(mode.equals("empty_gone")&&lists>1))return new String[]{"50"};
   return new String[]{"50","80"};
  }
  void gone(int pid)throws IOException{
   IOException cause=new IOException("fixture positive native ENOENT");
   ProfileRecoveryProcesses.ProcessGone gone=new ProfileRecoveryProcesses.ProcessGone(pid,cause);
   if(mode.equals("empty_gone_suppressed"))cause.addSuppressed(new IOException("close failure"));
   throw gone;
  }
  public ProfileRecoveryProcesses.Directory directory(int pid)throws Exception{
   int n=mark("dir"+pid);
   if(pid==target()){
    if(n==3&&(mode.equals("empty_gone")||mode.equals("empty_gone_reappears")||mode.equals("empty_gone_suppressed")||mode.equals("self_empty_gone")))gone(pid);
    if(n==3&&mode.equals("empty_permission"))throw new IOException("fixture EACCES");
    if(n==3&&mode.equals("empty_untyped_gone"))throw new IOException("ENOENT");
    if(n==2&&mode.equals("deadline"))time=END;
   }
   long inode=100+pid;
   if(pid==target()&&((mode.equals("directory_changed")&&n==3)||(mode.equals("directory_changed_first_row")&&n==2)))inode++;
   return new ProfileRecoveryProcesses.Directory(0,1,inode);
  }
  public byte[] read(int pid,String leaf,int maximum)throws Exception{
   int n=mark(leaf+pid);boolean target=pid==target();
   if(leaf.equals("stat")){
    long ticks=pid+50,flags=0;
    if(target&&((mode.equals("ticks_changed")&&n>=3)||(mode.equals("ticks_changed_first_row")&&n==2)))ticks++;
    if(target&&mode.equals("flags_changed")&&n>=3)flags=ProfileRecoveryProcesses.PF_KTHREAD;
    byte[] stat=ProfileRecoveryHostTest.stat(pid,ticks,flags);
    if(target&&(mode.equals("persistent_z")||mode.equals("persistent_x")))
     stat=new String(stat,StandardCharsets.UTF_8).replace(") S ",mode.equals("persistent_z")?") Z ":") X ").getBytes(StandardCharsets.UTF_8);
    return stat;
   }
   if(leaf.equals("status")){
    int uid=target&&mode.equals("uid_changed")&&n>=3?2000:0;
    return ProfileRecoveryHostTest.status(pid,uid,uid,uid,uid);
   }
   if(!leaf.equals("cmdline"))throw new AssertionError("unrequested leaf");
   if(!target)return ProfileRecoveryHostTest.bytes("ordinary\0");
   if(mode.equals("broker_first")||(mode.equals("empty_broker")&&n==2))
    return ProfileRecoveryHostTest.bytes("sh\0-c\0"+ProfileRecoveryProcesses.BROKER+"\0");
   if(mode.equals("generation_first")||(mode.equals("empty_generation")&&n==2))
    return ProfileRecoveryHostTest.bytes("sh\0-c\0"+G+"\0");
   if(mode.equals("bare_first"))return ProfileRecoveryHostTest.bytes("app_process64\0");
   if(mode.equals("incomplete_first"))return ProfileRecoveryHostTest.bytes("ordinary");
   if(mode.equals("null_first"))return null;
   if(mode.equals("stable")||mode.equals("only_self"))return ProfileRecoveryHostTest.bytes("ordinary\0");
   if(mode.equals("empty_once")||mode.equals("self_empty_once"))return n==1?new byte[0]:ProfileRecoveryHostTest.bytes("ordinary\0");
   if(mode.equals("empty_twice"))return n<=2?new byte[0]:ProfileRecoveryHostTest.bytes("ordinary\0");
   return new byte[0];
  }
  public long now(){return time;}
 }
 private static void check(boolean v){checks++;if(!v)throw new AssertionError();}
 private static JSONObject capture(Proc p)throws Exception{return ProfileRecoveryProcesses.captureBusiness(p,50,10481,G,START,END);}
 private static Proc rejected(String mode,String expected)throws Exception{
  Proc p=new Proc(mode);
  try{capture(p);}catch(IOException e){
   if(!expected.equals(e.getMessage()))throw new AssertionError(mode+": "+e.getMessage(),e);
   CASES.put(mode);check(true);return p;
  }
  throw new AssertionError("accepted "+mode);
 }
 public static void main(String[] args)throws Exception{
  if(args.length==1&&args[0].equals("one-empty")){
   Proc p=new Proc("empty_once");JSONObject out=new JSONObject().put("synthetic_proc_boundary",true).put("phone_operations",0);boolean pass=false;
   try{JSONObject got=capture(p);pass=got.getBoolean("complete");out.put("observed_recovery",pass);}
   catch(IOException e){out.put("observed_recovery",false).put("error",e.getMessage());}
   out.put("passed",pass).put("command_reads",p.count("cmdline80")).put("stat_reads",p.count("stat80")).put("status_reads",p.count("status80")).put("directory_reads",p.count("dir80"));
   System.out.println(out);if(!pass)System.exit(1);return;
  }
  JSONObject stable=capture(new Proc("stable"));CASES.put("stable_original_inventory");
  for(String mode:new String[]{"empty_once","empty_twice"}){
   Proc p=new Proc(mode);JSONObject got=capture(p);int count=mode.equals("empty_once")?2:3;
   check(stable.getString("inventory_sha256").equals(got.getString("inventory_sha256")));
   check(p.count("cmdline80")==count&&p.count("stat80")==2*count&&p.count("status80")==2*count&&p.count("dir80")==2*count+1);
   check(p.lists==2);CASES.put(mode);
  }
  Proc self=new Proc("self_empty_once");check(capture(self).getBoolean("complete"));check(self.count("cmdline50")==3);CASES.put("self_pin_kept_after_complete_retry");
  Proc oldStyle=new Proc("empty_once");check(ProfileRecoveryProcesses.capture(oldStyle,50,10481,G,START,END).getBoolean("complete"));CASES.put("original_capture_entry_uses_same_bounded_row");
  for(String mode:new String[]{"persistent","persistent_z","persistent_x"}){
   Proc p=rejected(mode,"RECOVERY_PROC_CMDLINE_UNKNOWN");check(p.count("cmdline80")==3&&p.count("stat80")==6&&p.count("status80")==6);
   check(p.lists==1);
  }
  Proc gone=new Proc("empty_gone");JSONObject observed=capture(gone),alone=capture(new Proc("only_self"));
  check(observed.getInt("process_count")==1&&observed.getString("inventory_sha256").equals(alone.getString("inventory_sha256")));
  check(gone.lists==2&&gone.count("cmdline80")==1);CASES.put("empty_then_native_gone_and_independent_closing_absent");
  rejected("empty_gone_reappears","RECOVERY_PROC_IDENTITY_CHANGED");
  rejected("empty_gone_suppressed","RECOVERY_PROC_GONE");rejected("self_empty_gone","RECOVERY_PROC_GONE");
  for(String mode:new String[]{"ticks_changed","uid_changed","flags_changed","directory_changed","directory_changed_first_row","ticks_changed_first_row"}){
   Proc p=rejected(mode,"RECOVERY_PROC_IDENTITY_CHANGED");check(p.count("cmdline80")==1);
  }
  for(String mode:new String[]{"broker_first","empty_broker","generation_first","empty_generation"}){
   Proc p=rejected(mode,mode.contains("broker")?"RECOVERY_BROKER_OR_CREATOR_STILL_VISIBLE":"RECOVERY_OLD_GENERATION_STILL_VISIBLE");
   check(p.count("cmdline80")==(mode.startsWith("empty_")?2:1));check(p.lists==1);
  }
  Proc deadline=rejected("deadline","RECOVERY_PROC_DEADLINE");check(deadline.count("cmdline80")==1);
  Proc nullCommand=rejected("null_first","RECOVERY_PROC_CMDLINE_BOUND");check(nullCommand.count("cmdline80")==1);
  Proc incomplete=rejected("incomplete_first","RECOVERY_PROC_CMDLINE_INCOMPLETE");check(incomplete.count("cmdline80")==1);
  Proc bare=rejected("bare_first","RECOVERY_PROC_BARE_APP_PROCESS_UNKNOWN");check(bare.count("cmdline80")==1);
  rejected("empty_permission","fixture EACCES");rejected("empty_untyped_gone","ENOENT");
  System.out.println(new JSONObject().put("schema","hepta.empty-command-complete-row-host.v1").put("passed",true)
   .put("cases",CASES.length()).put("assertions",checks).put("case_names",CASES).put("phone_operations",0)
   .put("android_runtime",false).put("proc_boundary","synthetic; actual unmodified census entry points"));
 }
}
