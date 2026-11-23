package org.trillionnium.hepta.local;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** The only preparation command is a bounded identity probe; it cannot create a display. */
public final class BackgroundPermissionPreparation {
    public static final long TIMEOUT_MS=60000,TERMINATE_MS=2000,DRAIN_MS=1000;
    public static final int OUTPUT_LIMIT=4096;
    public static final String SCHEMA="hepta.background-permission-preparation.v1";
    public interface Clock {long elapsed();}
    public interface Launcher {Process start()throws IOException;}
    public interface Lease {boolean cancelled();void attach(Process process);}
    public interface Journal {void beforeLaunch(Map<String,Object> value)throws Exception;void terminal(Map<String,Object> value)throws Exception;}
    public static String[] command(){return new String[]{"su","-c","/system/bin/id -u"};}
    private BackgroundPermissionPreparation(){}
    public static boolean ordinaryIdentity(String pkg,int uid,int installedUid){
        int appId=uid%100000;
        return "org.trillionnium.hepta.local".equals(pkg)&&uid>=10000&&appId>=10000&&appId<=19999&&uid==installedUid;
    }
    public static boolean exactRootOutput(byte[] value){
        return Arrays.equals(value,new byte[]{'0'})||Arrays.equals(value,new byte[]{'0','\n'});
    }
    static boolean integer(Object value){return value instanceof Integer||value instanceof Long;}
    static long number(Object value){return integer(value)?((Number)value).longValue():Long.MIN_VALUE;}
    static boolean digest(Object value){return value instanceof String&&((String)value).matches("[0-9a-f]{64}");}
    /** Recognizes a prior fixed read-only request without pretending it completed or authorizing replay. */
    public static boolean validReservation(Map<String,Object> value,int uid){
        return value!=null&&SCHEMA.equals(value.get("schema"))&&"visible_owner_button".equals(value.get("source"))
            &&value.get("request_id") instanceof String&&((String)value.get("request_id")).matches("[0-9a-f]{32}")
            &&number(value.get("installed_uid"))==uid&&ordinaryIdentity(String.valueOf(value.get("package_name")),uid,uid)
            &&number(value.get("app_uid"))==uid&&number(value.get("app_pid"))>0&&number(value.get("app_pid"))<=Integer.MAX_VALUE
            &&number(value.get("boot_count"))>=-1&&number(value.get("boot_count"))<=Integer.MAX_VALUE
            &&number(value.get("started_elapsed_ms"))>=0&&number(value.get("started_elapsed_ms"))<=Long.MAX_VALUE-TIMEOUT_MS&&number(value.get("timeout_ms"))==TIMEOUT_MS
            &&number(value.get("deadline_elapsed_ms"))==number(value.get("started_elapsed_ms"))+TIMEOUT_MS
            &&Arrays.asList(command()).equals(value.get("command"))
            &&Boolean.FALSE.equals(value.get("automatic_retry"))&&Boolean.FALSE.equals(value.get("automatic_resume"))
            &&Boolean.FALSE.equals(value.get("permanent_authorization_proven"))&&Boolean.FALSE.equals(value.get("display_created"))
            &&Boolean.FALSE.equals(value.get("broker_started"))&&Boolean.FALSE.equals(value.get("task_started"))
            &&Boolean.FALSE.equals(value.get("model_started"))&&Boolean.FALSE.equals(value.get("policy_database_modified"));
    }
    public static boolean cleanTerminal(Map<String,Object> value,int uid){
        if(!validReservation(value,uid)||!"terminal".equals(value.get("phase"))||!Boolean.TRUE.equals(value.get("cleanup_known"))
                ||!Boolean.TRUE.equals(value.get("terminal_receipt_published"))||!digest(value.get("result_sha256")))return false;
        boolean started=Boolean.TRUE.equals(value.get("process_started")),observed=Boolean.TRUE.equals(value.get("process_exit_observed"));
        if(!started)return Boolean.FALSE.equals(value.get("process_started"))&&!observed&&value.get("exit_code")==null
                &&Boolean.FALSE.equals(value.get("permission_verified"))&&Arrays.asList("not_started","cancelled_before_start","timed_out_before_start").contains(value.get("status"));
        if(!observed||!integer(value.get("exit_code")))return false;
        if(Boolean.TRUE.equals(value.get("permission_verified")))return "verified".equals(value.get("status"))&&number(value.get("exit_code"))==0
                &&Boolean.FALSE.equals(value.get("cancel_requested"))&&Boolean.FALSE.equals(value.get("timed_out"))
                &&Boolean.FALSE.equals(value.get("termination_requested"))&&Boolean.FALSE.equals(value.get("forced_termination"))
                &&Boolean.TRUE.equals(value.get("stdout_complete"))&&Boolean.TRUE.equals(value.get("stderr_complete"))
                &&Boolean.FALSE.equals(value.get("stdout_read_failed"))&&Boolean.FALSE.equals(value.get("stderr_read_failed"))
                &&digest(value.get("stdout_sha256"))&&digest(value.get("stderr_sha256"))
                &&Boolean.FALSE.equals(value.get("stdout_overflow"))&&Boolean.FALSE.equals(value.get("stderr_overflow"))
                &&((number(value.get("stdout_bytes"))==1&&sha(new byte[]{'0'}).equals(value.get("stdout_sha256")))
                    ||(number(value.get("stdout_bytes"))==2&&sha(new byte[]{'0','\n'}).equals(value.get("stdout_sha256"))));
        return Boolean.FALSE.equals(value.get("permission_verified"))&&Arrays.asList("cancelled","timed_out","output_unverified","not_authorized","cleanup_unknown","late_process_exit").contains(value.get("status"));
    }
    static String sha(byte[] value){
        try{StringBuilder out=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(value))out.append(String.format(Locale.ROOT,"%02x",b&255));return out.toString();}
        catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    public static final class Request {
        public final String id,packageName;public final int uid,installedUid,pid,bootCount;
        public Request(String id,String pkg,int uid,int installedUid,int pid,int boot){
            if(id==null||!id.matches("[0-9a-f]{32}")||!ordinaryIdentity(pkg,uid,installedUid)||pid<=0||boot< -1)
                throw new IllegalArgumentException("ordinary application identity required");
            this.id=id;packageName=pkg;this.uid=uid;this.installedUid=installedUid;this.pid=pid;bootCount=boot;
        }
        Map<String,Object> evidence(long started){
            Map<String,Object> value=new LinkedHashMap<String,Object>();value.put("schema",SCHEMA);value.put("request_id",id);
            value.put("source","visible_owner_button");value.put("command",Arrays.asList(command()));
            value.put("package_name",packageName);value.put("app_uid",uid);value.put("installed_uid",installedUid);value.put("app_pid",pid);
            value.put("boot_count",bootCount);value.put("started_elapsed_ms",started);value.put("deadline_elapsed_ms",started+TIMEOUT_MS);
            value.put("timeout_ms",TIMEOUT_MS);value.put("permission_verified",false);value.put("permanent_authorization_proven",false);
            value.put("display_created",false);value.put("broker_started",false);value.put("task_started",false);value.put("model_started",false);
            value.put("policy_database_modified",false);value.put("automatic_retry",false);value.put("automatic_resume",false);return value;
        }
    }
    public static final class Result {
        public final Map<String,Object> receipt;
        public final boolean verified,cleanupKnown;
        public final String status;
        final Process process;
        Result(Map<String,Object> value,Process process){this.process=process;receipt=java.util.Collections.unmodifiableMap(new LinkedHashMap<String,Object>(value));
            verified=Boolean.TRUE.equals(value.get("permission_verified"));cleanupKnown=Boolean.TRUE.equals(value.get("cleanup_known"));status=String.valueOf(value.get("status"));}
    }
    private static final class Output implements Runnable {
        private final InputStream input;private final ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        volatile boolean complete,overflow,failed,closeRequested;volatile long count;
        Output(InputStream input){this.input=input;}
        public void run(){
            try(InputStream stream=input){byte[] buffer=new byte[512];int n;
                while((n=stream.read(buffer))!=-1){count+=n;synchronized(bytes){int keep=Math.min(n,OUTPUT_LIMIT-bytes.size());if(keep>0)bytes.write(buffer,0,keep);}if(count>OUTPUT_LIMIT)overflow=true;}
                complete=!closeRequested;
            }catch(IOException failure){failed=true;}
        }
        byte[] bytes(){synchronized(bytes){return bytes.toByteArray();}}
        void closeOwnedStream(){closeRequested=true;Thread closer=new Thread(()->{try{input.close();}catch(IOException ignored){}} ,"hepta-permission-stream-close");closer.setDaemon(true);closer.start();}
        void fields(Map<String,Object> value,String prefix){value.put(prefix+"_bytes",count);value.put(prefix+"_sha256",sha(bytes()));
            value.put(prefix+"_complete",complete);value.put(prefix+"_overflow",overflow);value.put(prefix+"_read_failed",failed);}
    }
    /** Terminal publication precedes caller release; unknown exit or publication failure never grants permission. */
    public static Result execute(Request request,Lease lease,Launcher launcher,Clock clock,Journal journal){
        if(request==null||lease==null||launcher==null||clock==null||journal==null)throw new IllegalArgumentException("owned preparation inputs required");
        long started=clock.elapsed();Map<String,Object> value=request.evidence(started);
        Process process=null;Output stdout=null,stderr=null;Thread outThread=null,errThread=null;
        boolean exited=false,launched=false,timedOut=false,cancelled=false,forced=false,terminated=false,publication=false;
        Integer exit=null;String status="not_started",error=null;
        try{
            if(started<0||started>Long.MAX_VALUE-TIMEOUT_MS)throw new IOException("invalid elapsed time");
            value.put("status","pending");value.put("process_started",false);value.put("process_exit_observed",false);value.put("cleanup_known",false);
            journal.beforeLaunch(new LinkedHashMap<String,Object>(value));
            if(lease.cancelled()){cancelled=true;status="cancelled_before_start";}
            else if(clock.elapsed()>=started+TIMEOUT_MS){timedOut=true;status="timed_out_before_start";}
            else{
                process=launcher.start();launched=true;lease.attach(process);
                stdout=new Output(process.getInputStream());stderr=new Output(process.getErrorStream());
                outThread=new Thread(stdout,"hepta-permission-stdout");errThread=new Thread(stderr,"hepta-permission-stderr");
                outThread.setDaemon(true);errThread.setDaemon(true);outThread.start();errThread.start();
                while(true){
                    cancelled=lease.cancelled();timedOut=clock.elapsed()>=started+TIMEOUT_MS;
                    if(cancelled||timedOut||stdout.overflow||stderr.overflow||stdout.failed||stderr.failed)break;
                    if(process.waitFor(100,TimeUnit.MILLISECONDS)){exited=true;exit=process.exitValue();break;}
                }
                if(!exited){
                    terminated=true;process.destroy();exited=process.waitFor(TERMINATE_MS,TimeUnit.MILLISECONDS);
                    if(!exited){forced=true;process.destroyForcibly();exited=process.waitFor(TERMINATE_MS,TimeUnit.MILLISECONDS);}
                    if(exited)exit=process.exitValue();
                }
                outThread.join(DRAIN_MS);errThread.join(DRAIN_MS);
                if(!stdout.complete)stdout.closeOwnedStream();if(!stderr.complete)stderr.closeOwnedStream();
                cancelled|=lease.cancelled();timedOut|=clock.elapsed()>=started+TIMEOUT_MS;
                boolean outputComplete=stdout.complete&&stderr.complete&&!stdout.failed&&!stderr.failed&&!stdout.overflow&&!stderr.overflow;
                status=!exited?"cleanup_unknown":cancelled?"cancelled":timedOut?"timed_out":!outputComplete?"output_unverified":exit!=null&&exit==0&&exactRootOutput(stdout.bytes())?"verified":"not_authorized";
                value.put("permission_verified","verified".equals(status));
            }
        }catch(Exception failure){
            error=failure.getClass().getSimpleName()+": "+String.valueOf(failure.getMessage());
            status=launched?"cleanup_unknown":"not_started";
            if(failure instanceof InterruptedException)Thread.currentThread().interrupt();
            if(process!=null&&!exited){try{terminated=true;process.destroy();exited=process.waitFor(TERMINATE_MS,TimeUnit.MILLISECONDS);if(exited)exit=process.exitValue();}catch(Exception ignored){/* Retain unknown. */}}
        }
        cancelled|=lease.cancelled();
        // Cleanup here is only the owned Process, not a claim about Magisk's authorization decision.
        boolean cleanup=!launched||exited;
        if(cancelled){value.put("permission_verified",false);if(cleanup)status=launched?"cancelled":"cancelled_before_start";}
        if(!cleanup){status="cleanup_unknown";value.put("permission_verified",false);}
        value.put("status",status);value.put("process_started",launched);value.put("process_exit_observed",exited);value.put("exit_code",exit);
        value.put("cleanup_known",cleanup);value.put("cancel_requested",cancelled||lease.cancelled());value.put("timed_out",timedOut);value.put("forced_termination",forced);
        value.put("termination_requested",terminated);value.put("authorization_request_outcome_unknown",launched&&(!cleanup||cancelled||timedOut||terminated));
        value.put("ended_elapsed_ms",clock.elapsed());value.put("error",error);
        if(stdout!=null)stdout.fields(value,"stdout");if(stderr!=null)stderr.fields(value,"stderr");
        try{journal.terminal(new LinkedHashMap<String,Object>(value));publication=true;}
        catch(Exception failure){value.put("publication_error",failure.toString());value.put("cleanup_known",false);value.put("permission_verified",false);value.put("status","receipt_unknown");}
        value.put("terminal_receipt_published",publication);
        return new Result(value,process);
    }
}
