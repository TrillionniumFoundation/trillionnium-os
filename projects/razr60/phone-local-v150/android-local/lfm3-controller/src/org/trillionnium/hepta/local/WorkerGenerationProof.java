package org.trillionnium.hepta.local;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

/** A separate generation-absence proof. SDK request/close success cannot create it. */
final class WorkerGenerationProof {
    static final String[] ENVIRONMENT = {
        "HEPTA_WORKER_SCOPE_REQUIRED","HEPTA_WORKER_SCOPE_TASK",
        "HEPTA_WORKER_SCOPE_GENERATION","HEPTA_WORKER_SCOPE_TOKEN",
        "HEPTA_WORKER_SCOPE_PARENT_START","HEPTA_WORKER_SCOPE_BOOT"
    };
    static final long BUDGET_NANOS=4000000000L;
    static final long FINALIZATION_RESERVE_NANOS=1500000000L,MINIMUM_BUDGET_NANOS=200000000L;
    static long cleanupDeadline(long submitted,long finisherSubmitted,long finisherDeadline)throws IOException{
        need(finisherSubmitted>0&&submitted>=finisherSubmitted&&finisherDeadline>finisherSubmitted
                &&finisherDeadline-finisherSubmitted<=44000000000L,"invalid original finisher deadline");
        long remaining=finisherDeadline-submitted;
        need(remaining>=FINALIZATION_RESERVE_NANOS+MINIMUM_BUDGET_NANOS,"original finisher budget exhausted");
        remaining-=FINALIZATION_RESERVE_NANOS;
        return submitted+Math.min(BUDGET_NANOS,remaining);
    }
    static final int IDENTITY_LIMIT=2047,RECEIPT_LIMIT=65536;
    static final class Expected {
        final String task,generation,token,boot;
        final long uid,appPid,appStart;
        Expected(String task,String generation,String token,String boot,long uid,long appPid,long appStart)throws IOException{
            need(id(task)&&id(generation)&&id(token)&&uuid(boot)&&uid>0&&uid<=Integer.MAX_VALUE
                    &&appPid>1&&appPid<=Integer.MAX_VALUE&&appStart>0,"invalid immutable generation owner");
            this.task=task;this.generation=generation;this.token=token;this.boot=boot;
            this.uid=uid;this.appPid=appPid;this.appStart=appStart;
        }
    }
    static final class Identity {
        final Expected expected;
        final long leaderPid,leaderStart,pgid;
        final String sha256;
        private Identity(Expected expected,long leaderPid,long leaderStart,long pgid,String sha256){
            this.expected=expected;this.leaderPid=leaderPid;this.leaderStart=leaderStart;this.pgid=pgid;this.sha256=sha256;
        }
    }
    static Identity identity(byte[] raw,Expected e)throws IOException{
        need(raw!=null&&raw.length>0&&raw.length<=IDENTITY_LIMIT&&e!=null,"missing early identity");
        for(byte b:raw)need(b==10||b>=32&&b<=126,"non-ASCII scope identity");
        String text=new String(raw,StandardCharsets.US_ASCII);
        String[] lines=text.split("\n",-1);
        need(lines.length==12&&lines[11].isEmpty()&&"hepta.worker-generation.v1".equals(lines[0]),"identity shape");
        String[] names={"task_id","worker_generation","scope_token","app_uid","app_pid","app_start_ticks",
                "leader_pid","leader_start_ticks","pgid","boot_id"};
        String[] values=new String[10];
        for(int i=0;i<10;i++){
            need(lines[i+1].startsWith(names[i]+"="),"identity field order");
            values[i]=lines[i+1].substring(names[i].length()+1);
        }
        need(e.task.equals(values[0])&&e.generation.equals(values[1])&&e.token.equals(values[2])
                &&e.uid==decimal(values[3])&&e.appPid==decimal(values[4])&&e.appStart==decimal(values[5])
                &&e.boot.equals(values[9]),"identity owner differs");
        long pid=decimal(values[6]),start=decimal(values[7]),group=decimal(values[8]);
        need(pid>1&&pid<=Integer.MAX_VALUE&&pid!=e.appPid&&group==pid&&start>=e.appStart,"identity leader differs");
        return new Identity(e,pid,start,group,sha256(raw));
    }
    static JSONObject bindCleanup(Identity id,String nonce,long submitted,long deadline,
            long finisherSubmitted,long finisherDeadline,JSONObject r,
            boolean helperExitObserved,Integer helperExit,boolean helperForced)throws IOException{
        need(id!=null&&id(nonce)&&submitted>0&&deadline>submitted&&deadline-submitted<=BUDGET_NANOS,"cleanup invocation");
        need(deadline==cleanupDeadline(submitted,finisherSubmitted,finisherDeadline),"cleanup must use remaining original finisher budget");
        need(helperExitObserved&&Integer.valueOf(0).equals(helperExit)&&!helperForced,"helper exit is not cleanup proof");
        need(r!=null&&"hepta.worker-generation.cleanup.v1".equals(r.opt("schema")),"cleanup schema");
        Expected e=id.expected;
        string(r,"task_id",e.task);string(r,"worker_generation",e.generation);string(r,"scope_token",e.token);
        string(r,"boot_id",e.boot);string(r,"identity_sha256",id.sha256);string(r,"cleanup_nonce",nonce);
        equal(r,"app_uid",e.uid);equal(r,"app_pid",e.appPid);equal(r,"app_start_ticks",e.appStart);
        equal(r,"leader_pid",id.leaderPid);equal(r,"leader_start_ticks",id.leaderStart);equal(r,"pgid",id.pgid);
        equal(r,"helper_uid",e.uid);equal(r,"helper_parent_pid",e.appPid);
        long helper=integer(r,"helper_pid"),helperStart=integer(r,"helper_start_ticks"),helperGroup=integer(r,"helper_pgid");
        need(helper>1&&helper<=Integer.MAX_VALUE&&helper!=id.leaderPid&&helper!=e.appPid
                &&helperStart>=id.leaderStart&&helperGroup>1&&helperGroup!=id.pgid,"helper must be outside worker group");
        long start=integer(r,"started_monotonic_ns"),end=integer(r,"ended_monotonic_ns");
        need(start>=submitted&&start<deadline&&end>=start&&end<=deadline,"cleanup observation outside absolute budget");
        equal(r,"deadline_monotonic_ns",deadline);
        truth(r,"scan_complete",true);truth(r,"cleanup_known",true);truth(r,"pidfd_supported",true);
        truth(r,"numeric_pid_signal_used",false);truth(r,"group_signal_used",false);
        truth(r,"sdk_called",false);truth(r,"worker_started",false);string(r,"failure","none");
        equal(r,"remaining_owned_count",0);equal(r,"unknown_count",0);equal(r,"escaped_generation_count",0);
        long scans=integer(r,"scans"),empty=integer(r,"empty_readbacks");
        need(scans>=2&&scans<=1024&&empty>=2&&empty<=scans&&end-start>=100000000L,"complete independent empty observations required");
        bindGroupAbsence(r,id.pgid,start,end,scans,empty);
        Object rawTargets=r.opt("targets");need(rawTargets instanceof JSONArray,"cleanup target audit missing");
        JSONArray targets=(JSONArray)rawTargets;need(targets.length()<=64,"cleanup target bound");
        long terms=0,kills=0;Set<String> seen=new HashSet<>();
        for(int i=0;i<targets.length();i++){
            Object value=targets.opt(i);need(value instanceof JSONObject,"target shape");
            JSONObject t=(JSONObject)value;long pid=integer(t,"pid"),ticks=integer(t,"start_ticks");
            need(pid>1&&pid<=Integer.MAX_VALUE&&pid!=id.leaderPid&&pid!=e.appPid&&pid!=helper
                    &&ticks>=id.leaderStart&&seen.add(pid+":"+ticks),"target identity");
            Object term=t.opt("term_attempted"),kill=t.opt("kill_attempted");
            need(term instanceof Boolean&&kill instanceof Boolean,"target attempt types");
            long te=integer(t,"term_errno"),ke=integer(t,"kill_errno");
            need(te==0||te==3,"TERM did not complete or observe exact original exit");
            need(ke==0||ke==3,"KILL did not complete or observe exact original exit");
            if(Boolean.TRUE.equals(term))terms++;else need(te==0,"TERM errno without attempt");
            if(Boolean.TRUE.equals(kill))kills++;else need(ke==0,"KILL errno without attempt");
            need(Boolean.TRUE.equals(term)||Boolean.TRUE.equals(kill),"target without actual signal attempt");
        }
        equal(r,"term_attempts",terms);equal(r,"kill_attempts",kills);
        try{return new JSONObject(r.toString());}catch(Exception error){throw new IOException("cleanup audit copy",error);}
    }
    private static void bindGroupAbsence(JSONObject r,long pgid,long start,long end,long scans,long empty)throws IOException{
        truth(r,"group_presence_probe_used",true);equal(r,"group_presence_probe_signal",0);
        Object value=r.opt("group_presence_observations");
        need(value instanceof JSONArray,"kernel group observations missing");
        JSONArray rows=(JSONArray)value;
        need(rows.length()>=2&&rows.length()<=128&&rows.length()<=scans&&empty<=rows.length(),"kernel group observation count");
        long previous=0,firstFinal=0,last=0;
        for(int i=0;i<rows.length();i++){
            Object item=rows.opt(i);need(item instanceof JSONObject,"kernel group observation shape");
            JSONObject row=(JSONObject)item;equal(row,"pgid",pgid);
            long when=integer(row,"monotonic_ns"),result=integer(row,"result"),error=integer(row,"errno");
            need(when>=start&&when<=end&&(i==0||when>=previous),"kernel group observation clock");
            need(result==0&&error==0||result==-1&&error>0&&error<=4095,"kernel group result");
            if(i>=rows.length()-empty){
                need(result==-1&&error==3,"kernel group is not proven absent");
                if(i==rows.length()-empty)firstFinal=when;
                last=when;
            }
            previous=when;
        }
        need(last-firstFinal>=100000000L,"kernel group absence must span two independent observations");
    }
    /** Signal audit is independently bound even when the same helper reports an
     * incomplete cleanup. An unknown audit never establishes cooperative exit. */
    static int boundForceAttempts(Identity id,String nonce,JSONObject r)throws IOException{
        need(id!=null&&id(nonce)&&r!=null,"signal audit unavailable");Expected e=id.expected;
        string(r,"schema","hepta.worker-generation.cleanup.v1");
        string(r,"task_id",e.task);string(r,"worker_generation",e.generation);string(r,"scope_token",e.token);
        string(r,"boot_id",e.boot);string(r,"identity_sha256",id.sha256);string(r,"cleanup_nonce",nonce);
        equal(r,"app_uid",e.uid);equal(r,"app_pid",e.appPid);equal(r,"app_start_ticks",e.appStart);
        equal(r,"leader_pid",id.leaderPid);equal(r,"leader_start_ticks",id.leaderStart);equal(r,"pgid",id.pgid);
        equal(r,"helper_uid",e.uid);equal(r,"helper_parent_pid",e.appPid);
        long helper=integer(r,"helper_pid");
        need(helper>1&&helper!=id.leaderPid&&helper!=e.appPid&&integer(r,"helper_pgid")!=id.pgid
                &&integer(r,"helper_start_ticks")>=id.leaderStart,"signal audit helper identity");
        truth(r,"numeric_pid_signal_used",false);truth(r,"group_signal_used",false);
        truth(r,"sdk_called",false);truth(r,"worker_started",false);
        Object raw=r.opt("targets");need(raw instanceof JSONArray,"signal target audit");
        JSONArray targets=(JSONArray)raw;need(targets.length()<=64,"signal target limit");
        int terms=0,kills=0;Set<String> seen=new HashSet<>();
        for(int i=0;i<targets.length();i++){
            Object item=targets.opt(i);need(item instanceof JSONObject,"signal target object");
            JSONObject target=(JSONObject)item;long pid=integer(target,"pid"),start=integer(target,"start_ticks");
            need(pid>1&&pid<=Integer.MAX_VALUE&&pid!=id.leaderPid&&pid!=e.appPid&&pid!=helper
                    &&start>=id.leaderStart&&seen.add(pid+":"+start),"signal target identity");
            Object term=target.opt("term_attempted"),kill=target.opt("kill_attempted");
            need(term instanceof Boolean&&kill instanceof Boolean,"signal attempt type");
            long te=integer(target,"term_errno"),ke=integer(target,"kill_errno");
            need(te>=0&&te<=4095&&ke>=0&&ke<=4095,"signal errno range");
            if(Boolean.TRUE.equals(term))terms++;else need(te==0,"signal TERM errno without attempt");
            if(Boolean.TRUE.equals(kill))kills++;else need(ke==0,"signal KILL errno without attempt");
        }
        equal(r,"term_attempts",terms);equal(r,"kill_attempts",kills);return kills;
    }
    static long procStart(byte[] raw,long expectedPid)throws IOException{
        need(raw!=null&&raw.length>0&&raw.length<=8192,"process stat unavailable");
        String s=new String(raw,StandardCharsets.US_ASCII);
        int left=s.indexOf(' '),end=s.lastIndexOf(')');
        need(left>0&&end>left&&s.substring(0,left).equals(Long.toString(expectedPid))
                &&end+2<s.length()&&s.charAt(end+1)==' ',"process stat identity");
        String[] fields=s.substring(end+2).trim().split("\\s+");
        need(fields.length>=20&&fields[0].length()==1,"process stat fields");
        long start=decimal(fields[19]);need(start>0,"process start ticks");return start;
    }
    static String sha256(byte[] raw)throws IOException{
        try{StringBuilder out=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(raw))
            out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();}
        catch(Exception error){throw new IOException("SHA-256 unavailable",error);}
    }
    private static long decimal(String s)throws IOException{
        need(s!=null&&s.matches("0|[1-9][0-9]{0,18}"),"noncanonical integer");
        try{return Long.parseLong(s);}catch(NumberFormatException error){throw new IOException("integer range",error);}
    }
    private static long integer(JSONObject r,String key)throws IOException{
        Object v=r.opt(key);need(v instanceof Integer||v instanceof Long,"typed integer missing: "+key);
        return ((Number)v).longValue();
    }
    private static void equal(JSONObject r,String key,long value)throws IOException{need(integer(r,key)==value,"integer binding: "+key);}
    private static void truth(JSONObject r,String key,boolean value)throws IOException{need(r.opt(key)==(value?Boolean.TRUE:Boolean.FALSE),"boolean binding: "+key);}
    private static void string(JSONObject r,String key,String value)throws IOException{need(value.equals(r.opt(key)),"string binding: "+key);}
    static boolean id(String s){return s!=null&&s.matches("[0-9a-f]{32}");}
    private static boolean uuid(String s){return s!=null&&s.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");}
    static void need(boolean condition,String reason)throws IOException{if(!condition)throw new IOException(reason);}
}
