package org.trillionnium.hepta.background;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;
/** Original raw /proc fixture port with the real unchanged census algorithm. */
public final class NotesAbortedProcessesHost {
static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
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
 public static JSONObject capture(PublicPersonalNotesAbsenceRecovery.Request request,String kind)throws Exception{
  Proc p=new Proc();p.time=request.started+2;
  if("creator".equals(kind))p.row(99,22,0,0,bytes("app_process\0/\0"+ProfileRecoveryProcesses.BROKER+"\0--generation\0"+request.generation+"\0"));
  else if("generation".equals(kind))p.row(99,22,0,request.ownerUid,bytes("/system/bin/sh\0-c\0pending "+request.generation+"\0"));
  else if(!"empty".equals(kind))throw new IllegalArgumentException("closed fixture kind");
  return ProfileRecoveryProcesses.capture(p,50,request.ownerUid,request.generation,request.started,request.deadline);
 }
}
