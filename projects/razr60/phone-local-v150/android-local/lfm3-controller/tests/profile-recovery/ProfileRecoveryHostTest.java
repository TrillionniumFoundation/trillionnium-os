package org.trillionnium.hepta.background;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
public final class ProfileRecoveryHostTest {
 static int cases,assertions;
 interface Work{void run()throws Exception;}
 static void check(boolean b){assertions++;if(!b)throw new AssertionError();}
 static void ok(Work w)throws Exception{w.run();cases++;}
 static void no(String reason,Work w)throws Exception{try{w.run();}catch(Exception e){check(reason==null||String.valueOf(e.getMessage()).contains(reason));cases++;return;}throw new AssertionError("accepted "+reason);}
 static String repeat(char c,int n){char[] a=new char[n];Arrays.fill(a,c);return new String(a);}
 static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static JSONObject journal()throws Exception{
  Map<String,String> hashes=new TreeMap<String,String>();hashes.put("base",repeat('c',64));
  ProfileTarget t=new ProfileTarget(new ProfileIdentity(10,10,0,ProfileIdentity.MANAGED),1010367,ProfileTarget.CTRIP,"ctrip.android.view/ctrip.business.splash.CtripSplashActivity",1,hashes,new TreeSet<String>(Arrays.asList(repeat('d',64))));
  String g="11111111-1111-1111-1111-111111111111";
  return new JSONObject().put("schema","hepta.background-session.v1").put("app_uid",10481).put("task_id",repeat('a',32)).put("owner_sha256",repeat('b',64)).put("generation",g)
   .put("socket","hepta-bg-"+g).put("display_name","hepta-bg-"+g).put("display_id",-1).put("state","CLEANUP_UNKNOWN").put("created_elapsed_ms",1000L).put("expires_elapsed_ms",541000L).put("boot_count",83)
   .put("profile_launch_attempted",false).put("profile_isolation_required",true).put("owned_task_retirement_required",true).put("profile_target_wire",t.wire()).put("profile_target_sha256",t.sha256)
   .put("selection",new JSONObject().put("profile_target_wire",t.wire()).put("profile_target_sha256",t.sha256));
 }
 static ProfilePrelaunchRecovery.Request request(JSONObject j)throws Exception{return ProfilePrelaunchRecovery.request(bytes(j.toString()),10481,"22222222-2222-2222-2222-222222222222",543001,83);}
 static JSONObject sample(long a,long b)throws Exception{return new JSONObject().put("complete",true).put("old_creator_absent",true).put("started_elapsed_ms",a).put("finished_elapsed_ms",b).put("self_pid",50).put("self_start_ticks",100L).put("process_count",4).put("inspected_count",3).put("inventory_sha256",repeat('e',64));}
 static JSONObject proof(ProfilePrelaunchRecovery.Request r)throws Exception{
  return new JSONObject().put("schema",ProfilePrelaunchRecovery.SCHEMA).put("source",ProfilePrelaunchRecovery.SOURCE).put("request_id",r.requestId).put("owner_uid",r.ownerUid).put("task_id",r.taskId).put("generation",r.generation).put("owner_sha256",r.ownerSha256).put("journal_sha256",r.journalSha256)
   .put("profile_target_wire",r.target.wire()).put("target_sha256",r.target.sha256).put("display_id",-1).put("display_name",r.displayName).put("old_boot_count",r.oldBoot).put("current_boot_count",r.requestBoot).put("lease_expires_elapsed_ms",r.expires).put("request_started_elapsed_ms",r.started)
   .put("started_elapsed_ms",r.started).put("finished_elapsed_ms",r.started+8).put("deadline_elapsed_ms",r.deadline).put("boot_changed",r.oldBoot!=r.requestBoot).put("no_late_create",true).put("profile_launch_attempted",false).put("identity_rechecked",true).put("cleanup_known",true).put("automatic_resume",false)
   .put("live",new JSONObject().put("complete",true).put("root_count",2).put("leaf_count",3).put("snapshot_sha256",repeat('f',64)).put("target_user_id",10).put("target_task_ids",new JSONArray()))
   .put("recents",new JSONObject().put("complete",true).put("count",22).put("bytes",50030).put("snapshot_sha256",repeat('f',64)).put("target_user_id",10).put("target_task_ids",new JSONArray()))
   .put("displays",new JSONObject().put("complete",true).put("count",2).put("snapshot_sha256",repeat('f',64)).put("exact_name_absent",true).put("recorded_id_absent",true))
   .put("process_before",sample(r.started+1,r.started+2)).put("process_after",sample(r.started+6,r.started+7));
 }
 static void valid(JSONObject p,ProfilePrelaunchRecovery.Request r)throws Exception{ProfilePrelaunchRecovery.validate(p,r,r.started+9,r.requestBoot);}
 static byte[] stat(int pid,long ticks,long flags){String[] f=new String[22];Arrays.fill(f,"0");f[0]="S";f[6]=""+flags;f[19]=""+ticks;return bytes(pid+" (system worker) "+String.join(" ",f)+"\n");}
 static byte[] status(int pid,int... u){return bytes("Name:\tworker\nTgid:\t"+pid+"\nPid:\t"+pid+"\nUid:\t"+u[0]+"\t"+u[1]+"\t"+u[2]+"\t"+u[3]+"\n");}
 static final class Proc implements ProfileRecoveryProcesses.Proc{
  final Map<Integer,byte[]> stats=new HashMap<Integer,byte[]>(),statuses=new HashMap<Integer,byte[]>(),commands=new HashMap<Integer,byte[]>();
  final Map<Integer,Integer> reads=new HashMap<Integer,Integer>();int race=-1,dirReads;boolean dirRace;long time=543002;
  Proc(){row(50,100,0,0,bytes("app_process64\0/\0org.trillionnium.hepta.background.ProfileRecoveryMain\0--request\0YmFzZTY0\0"));row(1,0,0,0,bytes("/system/bin/init\0second_stage\0"));row(2,0,ProfileRecoveryProcesses.PF_KTHREAD,0,new byte[0]);row(80,200,0,10123,bytes("ordinary.personal.app\0"));}
  void row(int p,long t,long f,int u,byte[] c){stats.put(p,stat(p,t,f));statuses.put(p,status(p,u,u,u,u));commands.put(p,c);}
  public String[] entries(){return stats.keySet().stream().map(String::valueOf).toArray(String[]::new);}
  public ProfileRecoveryProcesses.Directory directory(int p){return new ProfileRecoveryProcesses.Directory(0,1,dirRace?++dirReads:p+100);}
  public byte[] read(int p,String leaf,int max)throws Exception{
   byte[] b;if("stat".equals(leaf)){int n=reads.containsKey(p)?reads.get(p):0;reads.put(p,n+1);b=p==race&&n>0?stat(p,999,0):stats.get(p);}
   else b="status".equals(leaf)?statuses.get(p):commands.get(p);
   if(b==null)throw new IOException("fixture unreadable");if(b.length>max)throw new IOException("fixture bounded");return b;
  }
  public long now(){return time;}
 }
 public static void main(String[] args)throws Exception{
  final ProfilePrelaunchRecovery.Request r=request(journal());
  ok(()->{check(r.target.profile.userId==10);check(ProfilePrelaunchRecovery.fromWire(r.wire()).journalSha256.equals(r.journalSha256));});
  ok(()->{ProfilePrelaunchRecovery.Request q=ProfilePrelaunchRecovery.request(bytes(journal().toString()),10481,r.requestId,10,84);check(q.requestBoot!=q.oldBoot);});
  no("profile_launch_attempted",()->{JSONObject j=journal();j.remove("profile_launch_attempted");request(j);});
  no("RECOVERY_NOT_PRELAUNCH",()->request(journal().put("profile_launch_attempted","false")));
  no("RECOVERY_NOT_PRELAUNCH",()->request(journal().put("profile_launch_attempted",true)));
  for(int display:new int[]{0,128,-2})no("RECOVERY_NOT_PRELAUNCH",()->request(journal().put("display_id",display)));
  no("RECOVERY_LEASE_NOT_EXPIRED",()->ProfilePrelaunchRecovery.request(bytes(journal().toString()),10481,r.requestId,543000,83));
  no("RECOVERY_LEASE_CLOCK",()->request(journal().put("boot_count",-1)));
  no("RECOVERY_SELECTION_BINDING",()->{JSONObject j=journal();j.getJSONObject("selection").put("profile_target_sha256",repeat('0',64));request(j);});
  no("RECOVERY_BOOTSTRAP_ATTEMPTED",()->request(journal().put("bootstrap_dispatched",true)));
  ok(()->{valid(proof(r),r);check(true);});
  no("RECOVERY_FIELDS_DIFFER",()->valid(new JSONObject().put("state","RELEASED").put("cleanup_known",true),r));
  no("RECOVERY_PROOF_BINDING",()->valid(proof(r).put("request_id","33333333-3333-3333-3333-333333333333"),r));
  no("RECOVERY_PROOF_BINDING",()->valid(proof(r).put("journal_sha256",repeat('0',64)),r));
  no("RECOVERY_PROCESS_ABSENCE_INCOMPLETE",()->{JSONObject p=proof(r);p.getJSONObject("process_after").put("complete",false);valid(p,r);});
  no("RECOVERY_PROCESS_BRACKET",()->{JSONObject p=proof(r);p.getJSONObject("process_after").put("self_start_ticks",101);valid(p,r);});
  no("RECOVERY_LIVE_ABSENCE_INCOMPLETE",()->{JSONObject p=proof(r);p.getJSONObject("live").getJSONArray("target_task_ids").put(100);valid(p,r);});
  no("RECOVERY_RECENTS_ABSENCE_INCOMPLETE",()->{JSONObject p=proof(r);p.getJSONObject("recents").getJSONArray("target_task_ids").put(100);valid(p,r);});
  no("RECOVERY_RECENTS_ABSENCE_INCOMPLETE",()->{JSONObject p=proof(r);p.getJSONObject("recents").put("complete",false);valid(p,r);});
  no("RECOVERY_DISPLAY_ABSENCE_INCOMPLETE",()->{JSONObject p=proof(r);p.getJSONObject("displays").put("exact_name_absent",false);valid(p,r);});
  no("RECOVERY_PROOF_FLAGS",()->valid(proof(r).put("identity_rechecked",false),r));
  no("RECOVERY_PROOF_FLAGS",()->valid(proof(r).put("automatic_resume",true),r));
  no("RECOVERY_REQUEST_EXPIRED_OR_BOOT_CHANGED",()->ProfilePrelaunchRecovery.validate(proof(r),r,r.deadline,83));
  ok(()->{JSONObject p=ProfileRecoveryProcesses.capture(new Proc(),50,r);check(p.getInt("process_count")==4);check(p.getInt("inspected_count")==3);check(p.getLong("self_start_ticks")==100);});
  no("RECOVERY_BROKER_OR_CREATOR_STILL_VISIBLE",()->{Proc p=new Proc();p.row(99,22,0,0,bytes("app_process\0/\0"+ProfileRecoveryProcesses.BROKER+"\0--generation\0"+r.generation+"\0"));ProfileRecoveryProcesses.capture(p,50,r);});
  no("RECOVERY_BROKER_OR_CREATOR_STILL_VISIBLE",()->{Proc p=new Proc();p.row(99,22,0,10481,bytes("su\0-c\0CLASSPATH=/installed.apk /system/bin/app_process / "+ProfileRecoveryProcesses.BROKER+" --generation "+r.generation+"\0"));p.statuses.put(99,status(99,10481,0,0,0));ProfileRecoveryProcesses.capture(p,50,r);});
  no("RECOVERY_OLD_GENERATION_STILL_VISIBLE",()->{Proc p=new Proc();p.row(99,22,0,2000,bytes("/system/bin/sh\0-c\0pending "+r.generation+"\0"));ProfileRecoveryProcesses.capture(p,50,r);});
  no("RECOVERY_PROC_CMDLINE_INCOMPLETE",()->ProfileRecoveryProcesses.checkCommand(bytes("app_process"),0,r.generation));
  no("RECOVERY_PROC_BARE_APP_PROCESS_UNKNOWN",()->ProfileRecoveryProcesses.checkCommand(bytes("app_process64\0\0"),0,r.generation));
  no("RECOVERY_PROC_CMDLINE_UNKNOWN",()->ProfileRecoveryProcesses.checkCommand(new byte[0],0,r.generation));
  no("RECOVERY_PROC_SELF_MISSING",()->{Proc p=new Proc();p.stats.put(50,stat(50,0,0));ProfileRecoveryProcesses.capture(p,50,r);});
  no("RECOVERY_PROC_IDENTITY_CHANGED",()->{Proc p=new Proc();p.race=50;ProfileRecoveryProcesses.capture(p,50,r);});
  no("RECOVERY_PROC_IDENTITY_CHANGED",()->{Proc p=new Proc();p.dirRace=true;ProfileRecoveryProcesses.capture(p,50,r);});
  no("fixture unreadable",()->{Proc p=new Proc();p.commands.remove(50);ProfileRecoveryProcesses.capture(p,50,r);});
  no("RECOVERY_PROC_SELF_MISSING",()->{Proc p=new Proc();p.stats.remove(50);ProfileRecoveryProcesses.capture(p,50,r);});
  no("RECOVERY_PROC_DEADLINE",()->{Proc p=new Proc();p.time=r.deadline;ProfileRecoveryProcesses.capture(p,50,r);});
  JSONObject out=new JSONObject().put("schema","hepta.profile-recovery-host-tests.v1").put("passed",true).put("cases",cases).put("assertions",assertions)
   .put("phone_contacted",false).put("android_runtime",false).put("process_framework_fixtures","synthetic; actual production parser and policy");
  if(args.length>=1){byte[] raw=Files.readAllBytes(Paths.get(args[0]));JSONObject j=ProfilePrelaunchRecovery.object(raw);ProfilePrelaunchRecovery.Request actual=ProfilePrelaunchRecovery.request(raw,j.getInt("app_uid"),r.requestId,j.getLong("expires_elapsed_ms")+2001,j.getInt("boot_count"));
   out.put("actual_lease_parse_only",new JSONObject().put("sha256",ProfileIdentity.sha(raw)).put("bytes",raw.length).put("original_bytes_preserved",Arrays.equals(raw,actual.journalBytes())).put("phone_absence_proved",false).put("host_clock_simulated",true));}
  if(args.length>=2){String[] lines=new String(Files.readAllBytes(Paths.get(args[1])),StandardCharsets.UTF_8).split("\\n");int count=0;
   for(String line:lines){if(!line.matches("[12] \\(.*"))continue;int pid=Integer.parseInt(line.substring(0,line.indexOf(' ')));ProfileRecoveryProcesses.Identity i=ProfileRecoveryProcesses.identity(bytes(line),status(pid,0,0,0,0),pid);check(i.ticks==0);check(((i.flags&ProfileRecoveryProcesses.PF_KTHREAD)!=0)==(pid==2));count++;}
   check(count==2);out.put("actual_pid1_pid2_stat_replay",new JSONObject().put("count",count).put("status_boundary","synthetic UID tuple, exact actual stat bytes")).put("assertions",assertions);}
  System.out.println(out.toString());
 }
}
