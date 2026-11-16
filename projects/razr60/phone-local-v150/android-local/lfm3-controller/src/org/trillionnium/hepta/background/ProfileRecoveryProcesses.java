package org.trillionnium.hepta.background;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeMap;
import org.json.JSONObject;

/** Bounded root-side census. It sends no signal and never infers exit from a remembered PID. */
final class ProfileRecoveryProcesses {
    static final String BROKER="org.trillionnium.hepta.background.BackgroundDisplayBroker";
    static final int STAT_MAX=16384,STATUS_MAX=65536,CMDLINE_MAX=65536,MAX_PROCESSES=65536;
    static final long PF_KTHREAD=0x00200000L;
    static final int MAX_CENSUS_ATTEMPTS=3;
    private ProfileRecoveryProcesses(){}
    interface Proc {
        String[] entries()throws Exception;
        Directory directory(int pid)throws Exception;
        byte[] read(int pid,String leaf,int maximum)throws Exception;
        long now();
    }
    static final class Directory {
        final int uid;final long device,inode;
        Directory(int uid,long device,long inode){this.uid=uid;this.device=device;this.inode=inode;}
        boolean same(Directory d){return d!=null&&uid==d.uid&&device==d.device&&inode==d.inode;}
    }
    static final class Identity {
        final int pid;final long ticks,flags;final int[] uids;
        Identity(int pid,long ticks,long flags,int[] uids){this.pid=pid;this.ticks=ticks;this.flags=flags;this.uids=uids;}
        boolean same(Identity other){return other!=null&&pid==other.pid&&ticks==other.ticks
                &&(flags&PF_KTHREAD)==(other.flags&PF_KTHREAD)&&Arrays.equals(uids,other.uids);}
        boolean inspect(int owner){for(int uid:uids)if(uid==0||uid==2000||uid==owner)return true;return false;}
        String canonical(){return pid+":"+ticks+":"+flags+":"+Arrays.toString(uids);}
    }
    static final class ProcessGone extends IOException {
        private static final long serialVersionUID=1L;
        final int pid;
        ProcessGone(int pid,Throwable cause){super("RECOVERY_PROC_GONE",cause);this.pid=pid;}
    }
    private static final class SelfPin {
        Directory directory;Identity identity;
        void observe(Directory currentDirectory,Identity currentIdentity)throws IOException{
            if(identity==null){directory=currentDirectory;identity=currentIdentity;}
            else need(directory.same(currentDirectory)&&identity.same(currentIdentity),
                    "RECOVERY_PROC_SELF_IDENTITY_CHANGED");
        }
    }
    static JSONObject capture(Proc proc,int self,ProfilePrelaunchRecovery.Request request)throws Exception{
        need(request!=null,"RECOVERY_REQUEST_MISSING");
        return capture(proc,self,request.ownerUid,request.generation,request.started,request.deadline);
    }
    static JSONObject capture(Proc proc,int self,int owner,String generation,long started,long deadline)throws Exception{
        return capture(proc,self,new CensusScope(owner,generation,started,deadline));
    }
    private static final class CensusScope {
        final int ownerUid;final String generation;final long started,deadline;
        CensusScope(int owner,String generation,long started,long deadline)throws IOException{
            need(owner>=10000&&owner<90000&&ProfileIdentity.uuid(generation)&&started>=0
                    &&started<=Long.MAX_VALUE-ProfilePrelaunchRecovery.LIMIT_MS
                    &&deadline==started+ProfilePrelaunchRecovery.LIMIT_MS,"RECOVERY_CENSUS_SCOPE");
            ownerUid=owner;this.generation=generation;this.started=started;this.deadline=deadline;
        }
    }
    private static JSONObject capture(Proc proc,int self,CensusScope request)throws Exception{
        long begun=proc.now();SelfPin selfPin=new SelfPin();
        for(int attempt=0;attempt<MAX_CENSUS_ATTEMPTS;attempt++){
            try{return captureAttempt(proc,self,request,begun,selfPin);}
            catch(ProcessGone gone){
                // Only the native adapter's positive disappearance signal may discard this whole census.
                // A failed close or a disappearing checker is never a retryable process absence.
                if(gone.pid<=0||gone.pid==self||gone.getSuppressed().length!=0
                        ||(gone.getCause()!=null&&gone.getCause().getSuppressed().length!=0))throw gone;
                check(proc,request);
                if(attempt+1==MAX_CENSUS_ATTEMPTS)
                    throw new IOException("RECOVERY_PROC_CENSUS_UNSTABLE",gone);
            }
        }
        throw new IOException("RECOVERY_PROC_CENSUS_UNSTABLE");
    }
    private static JSONObject captureAttempt(Proc proc,int self,CensusScope request,
            long begun,SelfPin selfPin)throws Exception{
        check(proc,request);
        String[] entries=proc.entries();
        need(entries!=null&&entries.length>0&&entries.length<=MAX_PROCESSES,"RECOVERY_PROC_ENUMERATION");
        Set<Integer> seen=new HashSet<Integer>();TreeMap<Integer,String> rows=new TreeMap<Integer,String>();
        int inspected=0;long ownTicks=-1;
        for(String name:entries){
            check(proc,request);if(!name.matches("[0-9]+"))continue;
            int pid=positive(name);need(seen.add(pid),"RECOVERY_PROC_DUPLICATE");
            Directory first=proc.directory(pid);need(first!=null&&first.uid>=0,"RECOVERY_PROC_DIRECTORY_UNKNOWN");
            Identity before=identity(proc.read(pid,"stat",STAT_MAX),proc.read(pid,"status",STATUS_MAX),pid);
            String cmdSha="-";
            if(before.inspect(request.ownerUid)){
                byte[] command=proc.read(pid,"cmdline",CMDLINE_MAX);inspected++;
                checkCommand(command,before.flags,request.generation);cmdSha=ProfileIdentity.sha(command);
            }
            Identity after=identity(proc.read(pid,"stat",STAT_MAX),proc.read(pid,"status",STATUS_MAX),pid);
            // A known identity change must reject before any later directory disappearance.
            need(before.same(after),"RECOVERY_PROC_IDENTITY_CHANGED");
            Directory last=proc.directory(pid);
            need(first.same(last),"RECOVERY_PROC_IDENTITY_CHANGED");
            rows.put(pid,before.canonical()+":"+first.uid+":"+first.device+":"+first.inode+":"+cmdSha);
            if(pid==self){need(before.uids[0]==0&&before.uids[1]==0&&before.uids[2]==0&&before.uids[3]==0,
                    "RECOVERY_PROC_SELF_UID");selfPin.observe(first,before);ownTicks=before.ticks;}
        }
        check(proc,request);need(ownTicks>0&&inspected>0,"RECOVERY_PROC_SELF_MISSING");
        StringBuilder canonical=new StringBuilder();for(String row:rows.values())canonical.append(row).append('\n');
        return new JSONObject().put("complete",true).put("old_creator_absent",true)
                .put("started_elapsed_ms",begun).put("finished_elapsed_ms",proc.now())
                .put("self_pid",self).put("self_start_ticks",ownTicks).put("process_count",rows.size())
                .put("inspected_count",inspected).put("inventory_sha256",ProfileIdentity.sha(canonical.toString()));
    }
    static void checkCommand(byte[] bytes,long flags,String generation)throws Exception{
        need(bytes!=null&&bytes.length<=CMDLINE_MAX,"RECOVERY_PROC_CMDLINE_BOUND");
        if(bytes.length==0){need((flags&PF_KTHREAD)!=0,"RECOVERY_PROC_CMDLINE_UNKNOWN");return;}
        need((flags&PF_KTHREAD)==0&&bytes[bytes.length-1]==0,"RECOVERY_PROC_CMDLINE_INCOMPLETE");
        String command=decode(bytes);
        String[] arguments=command.split("\\u0000",-1);int used=arguments.length;
        while(used>0&&arguments[used-1].isEmpty())used--;
        if(used==1&&arguments[0].matches("(?:.*/)?app_process(?:32|64)?"))
            throw new IOException("RECOVERY_PROC_BARE_APP_PROCESS_UNKNOWN");
        // Both exec'd app_process and a pending su -c / shell command retain these bytes.
        // Ambiguous broker identity also rejects; absence is never inferred from a truncated name.
        need(!command.contains(BROKER),"RECOVERY_BROKER_OR_CREATOR_STILL_VISIBLE");
        need(!command.contains(generation),"RECOVERY_OLD_GENERATION_STILL_VISIBLE");
    }
    static Identity identity(byte[] statBytes,byte[] statusBytes,int expected)throws Exception{
        need(statBytes!=null&&statBytes.length>0&&statBytes.length<=STAT_MAX
                &&statusBytes!=null&&statusBytes.length>0&&statusBytes.length<=STATUS_MAX,"RECOVERY_PROC_IDENTITY_BOUND");
        String stat=decode(statBytes),status=decode(statusBytes);
        need(stat.indexOf('\0')<0&&status.indexOf('\0')<0,"RECOVERY_PROC_IDENTITY_NUL");
        int open=stat.indexOf('('),close=stat.lastIndexOf(')');
        need(open>0&&close>open&&close+2<stat.length()&&stat.charAt(close+1)==' ',"RECOVERY_PROC_STAT_FORMAT");
        need(positive(stat.substring(0,open).trim())==expected,"RECOVERY_PROC_STAT_PID");
        String[] fields=stat.substring(close+2).trim().split("\\s+");
        need(fields.length>=20&&fields[0].length()==1,"RECOVERY_PROC_STAT_INCOMPLETE");
        // PID 1 / early kernel tasks may legitimately start at tick zero; the new checker still requires >0.
        long ticks=decimal(fields[19]),flags=decimal(fields[6]);
        int[] uids=null;boolean pid=false,tgid=false;
        for(String line:status.split("\\n",-1)){
            if(line.startsWith("Uid:")){
                need(uids==null,"RECOVERY_PROC_UID_DUPLICATE");String[] values=line.substring(4).trim().split("\\s+");
                need(values.length==4,"RECOVERY_PROC_UID_INCOMPLETE");uids=new int[4];
                for(int i=0;i<4;i++){long uid=decimal(values[i]);need(uid<=Integer.MAX_VALUE,"RECOVERY_PROC_UID_RANGE");uids[i]=(int)uid;}
            }else if(line.startsWith("Pid:")){
                need(!pid&&positive(line.substring(4).trim())==expected,"RECOVERY_PROC_STATUS_PID");pid=true;
            }else if(line.startsWith("Tgid:")){
                need(!tgid&&positive(line.substring(5).trim())==expected,"RECOVERY_PROC_STATUS_TGID");tgid=true;
            }
        }
        need(uids!=null&&pid&&tgid,"RECOVERY_PROC_IDENTITY_INCOMPLETE");
        return new Identity(expected,ticks,flags,uids);
    }
    private static long decimal(String value)throws IOException{
        try{need(value!=null&&value.matches("[0-9]{1,19}"),"RECOVERY_PROC_INTEGER");return Long.parseLong(value);}
        catch(NumberFormatException invalid){throw new IOException("RECOVERY_PROC_INTEGER_RANGE",invalid);}
    }
    private static int positive(String value)throws IOException{
        long result=decimal(value);need(result>0&&result<=Integer.MAX_VALUE,"RECOVERY_PROC_PID_RANGE");return (int)result;
    }
    private static String decode(byte[] bytes)throws Exception{
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
    }
    private static void check(Proc proc,CensusScope request)throws IOException{
        need(proc.now()>=request.started&&proc.now()<request.deadline,"RECOVERY_PROC_DEADLINE");
    }
    private static void need(boolean value,String reason)throws IOException{if(!value)throw new IOException(reason);}
}
