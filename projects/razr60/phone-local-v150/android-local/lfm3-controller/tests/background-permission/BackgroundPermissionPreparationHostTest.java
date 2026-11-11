package org.trillionnium.hepta.local;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Runs the real production worker with fake Process/Clock/Lease/Journal only. */
public final class BackgroundPermissionPreparationHostTest {
    static final String PACKAGE="org.trillionnium.hepta.local",ID="1234567890abcdef1234567890abcdef";
    static final int UID=10481;
    static final List<String> passed=new ArrayList<String>(),failures=new ArrayList<String>();
    interface Case {void run()throws Exception;}
    interface Mutation {void change(Map<String,Object> value);}
    static void check(boolean value,String why){if(!value)throw new AssertionError(why);}
    static void test(String name,Case body){
        try{body.run();passed.add(name);System.out.println("PASS "+name);}
        catch(Throwable error){failures.add(name+": "+error);System.out.println("FAIL "+name+": "+error);}
    }
    static void rejects(Case body){try{body.run();throw new AssertionError("expected rejection");}
        catch(IllegalArgumentException expected){/* Required refusal. */}catch(Exception other){throw new AssertionError(other);}}
    static byte[] bytes(String value){return value.getBytes(StandardCharsets.UTF_8);}
    static BackgroundPermissionPreparation.Request request(){return new BackgroundPermissionPreparation.Request(ID,PACKAGE,UID,UID,2345,41);}
    static final class Clock implements BackgroundPermissionPreparation.Clock {
        volatile long now=1000;public long elapsed(){return now;}void advance(long value){now+=value;}
    }
    static final class Lease implements BackgroundPermissionPreparation.Lease {
        volatile boolean cancel;boolean failAttach;Process attached;final List<String> events;
        Lease(List<String> events){this.events=events;}
        public boolean cancelled(){return cancel;}
        public void attach(Process child){events.add("attach");if(failAttach)throw new IllegalStateException("injected attachment failure");
            check(child!=null&&attached==null,"exactly one non-null owned child");attached=child;}
    }
    static final class Journal implements BackgroundPermissionPreparation.Journal {
        final List<String> events;Map<String,Object> before,terminal;boolean failBefore,failTerminal;Runnable beforeHook;
        Journal(List<String> events){this.events=events;}
        public void beforeLaunch(Map<String,Object> value)throws IOException {
            events.add("before_journal");before=new LinkedHashMap<String,Object>(value);
            if(beforeHook!=null)beforeHook.run();if(failBefore)throw new IOException("injected prelaunch publication failure");
        }
        public void terminal(Map<String,Object> value)throws IOException {
            events.add("terminal_journal");terminal=new LinkedHashMap<String,Object>(value);
            if(failTerminal)throw new IOException("injected terminal publication failure");
        }
    }
    static final class FakeProcess extends Process {
        final Clock clock;final List<String> events;InputStream stdout=new ByteArrayInputStream(bytes("0\n")),stderr=new ByteArrayInputStream(new byte[0]);
        boolean alive=true,destroyed,forced,exitOnDestroy=true,exitOnForce=true;int code,waits,exitAtWait=1;long waitAdvance=100;Runnable firstWait;
        FakeProcess(Clock clock,List<String> events){this.clock=clock;this.events=events;}
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public InputStream getInputStream(){check(events.contains("attach"),"attach precedes output handling");return stdout;}
        public InputStream getErrorStream(){check(events.contains("attach"),"attach precedes stderr handling");return stderr;}
        public boolean waitFor(long timeout,TimeUnit unit)throws InterruptedException {
            waits++;if(waits==1&&firstWait!=null)firstWait.run();clock.advance(waitAdvance);Thread.yield();
            if(alive&&exitAtWait>0&&waits>=exitAtWait)alive=false;
            return !alive;
        }
        public int waitFor()throws InterruptedException {while(!waitFor(100,TimeUnit.MILLISECONDS)){/* Controlled fake time only. */}return exitValue();}
        public int exitValue(){if(alive)throw new IllegalThreadStateException("fake child still alive");return code;}
        public void destroy(){events.add("destroy");destroyed=true;if(exitOnDestroy){alive=false;code=143;}}
        public Process destroyForcibly(){events.add("force_destroy");forced=true;if(exitOnForce){alive=false;code=137;}return this;}
        public boolean isAlive(){return alive;}
    }
    static final class Rig {
        final List<String> events=new ArrayList<String>();final Clock clock=new Clock();
        final Lease lease=new Lease(events);final Journal journal=new Journal(events);final FakeProcess child=new FakeProcess(clock,events);
        int launches;boolean launchFails;
        BackgroundPermissionPreparation.Result run(){return BackgroundPermissionPreparation.execute(request(),lease,()->{
            check(journal.before!=null,"durable reservation precedes every launch attempt");
            events.add("spawn");launches++;if(launchFails)throw new IOException("injected launcher failure");return child;
        },clock,journal);}
    }
    static final class BrokenStream extends InputStream {
        public int read()throws IOException {throw new IOException("injected stream failure");}
    }
    static final class HeldStream extends InputStream {
        final CountDownLatch release=new CountDownLatch(1);
        public int read()throws IOException {try{release.await();return -1;}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new IOException(failure);}}
        public void close(){release.countDown();}
    }
    static Map<String,Object> terminal(BackgroundPermissionPreparation.Result result){
        Map<String,Object> value=new LinkedHashMap<String,Object>(result.receipt);
        value.put("phase","terminal");value.put("result_sha256",BackgroundPermissionPreparation.sha(bytes("terminal receipt bytes fixture")));return value;
    }
    static void refusedWithoutStart(Rig rig,BackgroundPermissionPreparation.Result result){
        check(!result.verified&&rig.launches==0&&rig.lease.attached==null,"no command launch or ready state");
        check(Boolean.FALSE.equals(result.receipt.get("process_started")),"no-start fact recorded");
    }
    static void authorizationUnknownAfterInterruption(Rig rig,BackgroundPermissionPreparation.Result result){
        check(!result.verified,"interrupted su request cannot grant permission");
        check(rig.launches==1&&Boolean.TRUE.equals(result.receipt.get("authorization_request_outcome_unknown")),"one ambiguous authorization request is retained");
    }
    static void cases(){
        test("ordinary_uid_and_exact_package_only",()->{
            check(BackgroundPermissionPreparation.ordinaryIdentity(PACKAGE,UID,UID),"ordinary app");
            check(BackgroundPermissionPreparation.ordinaryIdentity(PACKAGE,110481,110481),"ordinary secondary-user app ID");
            for(int uid:new int[]{0,1000,2000,9999,20000,90000,99000})check(!BackgroundPermissionPreparation.ordinaryIdentity(PACKAGE,uid,uid),"reject nonordinary UID "+uid);
            check(!BackgroundPermissionPreparation.ordinaryIdentity(PACKAGE+"probe",UID,UID),"foreign package");
            check(!BackgroundPermissionPreparation.ordinaryIdentity(PACKAGE,UID,UID+1),"installed UID mismatch");
        });
        test("request_rejects_invalid_identity_without_requiring_boot_observation",()->{
            rejects(()->new BackgroundPermissionPreparation.Request("bad",PACKAGE,UID,UID,2345,41));
            rejects(()->new BackgroundPermissionPreparation.Request(ID,PACKAGE,UID,UID+1,2345,41));
            rejects(()->new BackgroundPermissionPreparation.Request(ID,PACKAGE,UID,UID,0,41));
            check(new BackgroundPermissionPreparation.Request(ID,PACKAGE,UID,UID,2345,-1)!=null,"unavailable boot metadata is not a preparation blocker");
        });
        test("fixed_command_is_fresh_and_not_model_parameterized",()->{
            check(Arrays.equals(BackgroundPermissionPreparation.command(),new String[]{"su","-c","/system/bin/id -u"}),"exact fixed argv");
            String[] changed=BackgroundPermissionPreparation.command();changed[2]="untrusted";
            check("/system/bin/id -u".equals(BackgroundPermissionPreparation.command()[2]),"caller cannot mutate future command");
        });
        for(String accepted:new String[]{"0","0\n"})test("exact_root_stdout_"+accepted.length(),()->{
            Rig rig=new Rig();rig.child.stdout=new ByteArrayInputStream(bytes(accepted));BackgroundPermissionPreparation.Result result=rig.run();
            check(result.verified&&result.cleanupKnown&&"verified".equals(result.status),"natural complete exact root output");
            check(rig.launches==1&&rig.lease.attached==rig.child&&!rig.child.destroyed,"one leased natural child");
            check(Boolean.TRUE.equals(result.receipt.get("terminal_receipt_published")),"terminal publication reported");
            check(Long.valueOf(accepted.length()).equals(result.receipt.get("stdout_bytes")),"complete stdout count");
            check(BackgroundPermissionPreparation.sha(bytes(accepted)).equals(result.receipt.get("stdout_sha256")),"exact full stdout hash");
            check(BackgroundPermissionPreparation.cleanTerminal(terminal(result),UID),"current valid terminal accepted for historical cleanup only");
        });
        for(String bad:new String[]{"","00"," 0","0 ","0\r\n","0\nextra","0\n0\n","0\u0000","10481\n"})test("wrong_stdout_"+Integer.toHexString(bad.hashCode()),()->{
            Rig rig=new Rig();rig.child.stdout=new ByteArrayInputStream(bytes(bad));BackgroundPermissionPreparation.Result result=rig.run();
            check(!result.verified&&result.cleanupKnown&&"not_authorized".equals(result.status),"full wrong output never grants ready");
        });
        test("nonzero_exit_with_root_stdout_is_not_authorization",()->{
            Rig rig=new Rig();rig.child.code=1;BackgroundPermissionPreparation.Result result=rig.run();
            check(!result.verified&&result.cleanupKnown&&Integer.valueOf(1).equals(result.receipt.get("exit_code")),"exit 0 independently required");
        });
        test("durable_reservation_and_attachment_precede_output_and_terminal",()->{
            Rig rig=new Rig();BackgroundPermissionPreparation.Result result=rig.run();
            check(rig.events.indexOf("before_journal")<rig.events.indexOf("spawn")&&rig.events.indexOf("spawn")<rig.events.indexOf("attach")
                &&rig.events.indexOf("attach")<rig.events.indexOf("terminal_journal"),"required event ordering");
            check(Boolean.FALSE.equals(rig.journal.before.get("permission_verified"))&&Boolean.FALSE.equals(rig.journal.before.get("process_started"))
                &&Boolean.FALSE.equals(rig.journal.before.get("cleanup_known")),"before journal cannot claim future success");
            for(String field:new String[]{"automatic_retry","automatic_resume","display_created","broker_started","task_started","model_started","policy_database_modified","permanent_authorization_proven"})
                check(Boolean.FALSE.equals(result.receipt.get(field)),"bounded preparation statement "+field);
        });
        test("cancel_before_launch_records_no_process",()->{
            Rig rig=new Rig();rig.lease.cancel=true;BackgroundPermissionPreparation.Result result=rig.run();refusedWithoutStart(rig,result);
            check(result.cleanupKnown&&"cancelled_before_start".equals(result.status),"known no-spawn cancellation");
        });
        test("cancel_during_prelaunch_publication_never_spawns",()->{
            Rig rig=new Rig();rig.journal.beforeHook=()->rig.lease.cancel=true;BackgroundPermissionPreparation.Result result=rig.run();
            refusedWithoutStart(rig,result);check(result.cleanupKnown,"no root request exists");
        });
        test("prelaunch_journal_consumes_deadline_without_spawning",()->{
            Rig rig=new Rig();rig.journal.beforeHook=()->rig.clock.advance(BackgroundPermissionPreparation.TIMEOUT_MS);
            BackgroundPermissionPreparation.Result result=rig.run();refusedWithoutStart(rig,result);
            check(result.cleanupKnown&&"timed_out_before_start".equals(result.status),"deadline checked after journal");
        });
        test("natural_exit_after_deadline_cannot_grant_permission",()->{
            Rig rig=new Rig();rig.child.waitAdvance=BackgroundPermissionPreparation.TIMEOUT_MS;BackgroundPermissionPreparation.Result result=rig.run();
            authorizationUnknownAfterInterruption(rig,result);check(Boolean.TRUE.equals(result.receipt.get("timed_out")),"fresh deadline after wait");
            check(result.cleanupKnown&&Boolean.TRUE.equals(result.receipt.get("process_exit_observed")),"natural child exit and complete streams can be clean while authorization remains unknown");
        });
        test("timeout_then_reaped_su_still_retains_unknown_authorization",()->{
            Rig rig=new Rig();rig.child.exitAtWait=-1;rig.child.waitAdvance=30000;BackgroundPermissionPreparation.Result result=rig.run();
            authorizationUnknownAfterInterruption(rig,result);check(rig.child.destroyed&&Boolean.TRUE.equals(result.receipt.get("process_exit_observed")),"client waitFor is retained independently from authorization");
            check(result.cleanupKnown,"owned child exit plus complete output permits process-slot release");
        });
        test("cancellation_after_launch_keeps_unknown_even_after_exit",()->{
            Rig rig=new Rig();rig.child.firstWait=()->rig.lease.cancel=true;BackgroundPermissionPreparation.Result result=rig.run();
            authorizationUnknownAfterInterruption(rig,result);check(Boolean.TRUE.equals(result.receipt.get("cancel_requested")),"cancel retained");
            check(result.cleanupKnown,"reaped cancelled child is not a false live-process blocker");
        });
        test("unreaped_child_after_soft_and_forced_stop_is_unknown",()->{
            Rig rig=new Rig();rig.child.exitAtWait=-1;rig.child.waitAdvance=30000;rig.child.exitOnDestroy=false;rig.child.exitOnForce=false;
            BackgroundPermissionPreparation.Result result=rig.run();authorizationUnknownAfterInterruption(rig,result);
            check(!result.cleanupKnown&&"cleanup_unknown".equals(result.status),"unreaped process keeps lease");
            check(rig.child.destroyed&&rig.child.forced&&Boolean.FALSE.equals(result.receipt.get("process_exit_observed"))&&result.receipt.get("exit_code")==null,"no invented waitFor/exit code");
        });
        for(boolean stderr:new boolean[]{false,true})test((stderr?"stderr":"stdout")+"_overflow_never_verifies",()->{
            Rig rig=new Rig();byte[] overflow=new byte[BackgroundPermissionPreparation.OUTPUT_LIMIT+1];Arrays.fill(overflow,(byte)'0');
            if(stderr)rig.child.stderr=new ByteArrayInputStream(overflow);else rig.child.stdout=new ByteArrayInputStream(overflow);
            BackgroundPermissionPreparation.Result result=rig.run();check(!result.verified,"overflow never grants ready");
            check(Boolean.TRUE.equals(result.receipt.get((stderr?"stderr":"stdout")+"_overflow")),"overflow explicitly retained");
            check(Long.valueOf(overflow.length).equals(result.receipt.get((stderr?"stderr":"stdout")+"_bytes")),"full observed byte count retained");
        });
        for(boolean stderr:new boolean[]{false,true})test((stderr?"stderr":"stdout")+"_read_error_never_verifies",()->{
            Rig rig=new Rig();if(stderr)rig.child.stderr=new BrokenStream();else rig.child.stdout=new BrokenStream();
            BackgroundPermissionPreparation.Result result=rig.run();check(!result.verified,"failed stream cannot prove authorization");
            check(result.cleanupKnown&&Boolean.TRUE.equals(result.receipt.get("process_exit_observed")),"known owned child exit is independent of output validity");
            check(Boolean.TRUE.equals(result.receipt.get((stderr?"stderr":"stdout")+"_read_failed")),"stream error explicit");
        });
        test("exit_without_stdout_eof_is_not_complete_authorization",()->{
            Rig rig=new Rig();HeldStream held=new HeldStream();rig.child.stdout=held;
            try{BackgroundPermissionPreparation.Result result=rig.run();check(!result.verified&&result.cleanupKnown&&Boolean.FALSE.equals(result.receipt.get("stdout_complete")),"waitFor proves process exit but cannot prove output EOF or authorization");}
            finally{held.close();}
        });
        test("prelaunch_write_failure_never_spawns_and_publishes_failure",()->{
            Rig rig=new Rig();rig.journal.failBefore=true;BackgroundPermissionPreparation.Result result=rig.run();refusedWithoutStart(rig,result);
            check(rig.journal.terminal!=null&&result.receipt.get("error")!=null,"terminal diagnostics retained");
        });
        test("launcher_failure_retains_no_start_fact",()->{
            Rig rig=new Rig();rig.launchFails=true;BackgroundPermissionPreparation.Result result=rig.run();
            check(!result.verified&&result.cleanupKnown&&rig.launches==1&&rig.lease.attached==null&&Boolean.FALSE.equals(result.receipt.get("process_started")),"failed launch is not claimed started");
        });
        test("attachment_failure_records_actual_started_child_and_waited_exit",()->{
            Rig rig=new Rig();rig.lease.failAttach=true;BackgroundPermissionPreparation.Result result=rig.run();
            check(!result.verified&&result.cleanupKnown&&rig.launches==1&&rig.child.destroyed,"attachment error followed by owned waitFor is clean only for the process");
            check(Boolean.TRUE.equals(result.receipt.get("process_started"))&&Boolean.TRUE.equals(result.receipt.get("process_exit_observed")),"started child cannot be relabelled never started");
        });
        test("terminal_write_failure_cannot_publish_ready_or_cleanup",()->{
            Rig rig=new Rig();rig.journal.failTerminal=true;BackgroundPermissionPreparation.Result result=rig.run();
            check(!result.verified&&!result.cleanupKnown&&"receipt_unknown".equals(result.status),"receipt failure retains lease eligibility barrier");
            check(Boolean.FALSE.equals(result.receipt.get("terminal_receipt_published"))&&result.receipt.get("publication_error")!=null,"write failure explicit");
        });
        test("invalid_elapsed_time_cannot_launch",()->{
            for(long clock:new long[]{-1,Long.MAX_VALUE}){Rig rig=new Rig();rig.clock.now=clock;refusedWithoutStart(rig,rig.run());}
        });
        test("valid_reservation_requires_original_ordinary_identity_and_fixed_command",()->{
            Rig rig=new Rig();rig.run();check(BackgroundPermissionPreparation.validReservation(rig.journal.before,UID),"original reservation valid");
            Map<String,Object> changed=new LinkedHashMap<String,Object>(rig.journal.before);changed.put("command",Arrays.asList("su","-c","arbitrary"));
            check(!BackgroundPermissionPreparation.validReservation(changed,UID),"changed command rejected");
        });
        test("reservation_rejects_installed_uid_narrowing_overflow",()->{
            Rig rig=new Rig();rig.run();Map<String,Object> changed=new LinkedHashMap<String,Object>(rig.journal.before);
            changed.put("installed_uid",Long.valueOf(UID+(1L<<32)));check(!BackgroundPermissionPreparation.validReservation(changed,UID),"long UID cannot narrow to ordinary identity");
        });
        test("reservation_rejects_elapsed_deadline_overflow",()->{
            Rig rig=new Rig();rig.run();Map<String,Object> changed=new LinkedHashMap<String,Object>(rig.journal.before);
            changed.put("started_elapsed_ms",Long.MAX_VALUE);changed.put("deadline_elapsed_ms",Long.valueOf(Long.MAX_VALUE+BackgroundPermissionPreparation.TIMEOUT_MS));
            check(!BackgroundPermissionPreparation.validReservation(changed,UID),"overflowed deadline is not valid reservation");
        });
        test("unobserved_exit_cannot_be_relabelled_clean_terminal",()->{
            Rig rig=new Rig();Map<String,Object> changed=terminal(rig.run());changed.put("permission_verified",false);changed.put("status","cleanup_unknown");changed.put("process_exit_observed",false);
            check(!BackgroundPermissionPreparation.cleanTerminal(changed,UID),"unknown process exit cannot become historical clean exit");
        });
        for(String field:new String[]{"cancel_requested","timed_out","termination_requested","forced_termination"})test("verified_terminal_rejects_interrupted_"+field,()->{
            Rig rig=new Rig();Map<String,Object> changed=terminal(rig.run());changed.put(field,true);
            check(!BackgroundPermissionPreparation.cleanTerminal(changed,UID),"interrupted su request cannot remain authorization verified");
        });
        test("reaped_cancel_and_timeout_can_be_clean_but_not_verified",()->{
            for(boolean cancel:new boolean[]{false,true}){
                Rig rig=new Rig();if(cancel)rig.child.firstWait=()->rig.lease.cancel=true;else rig.child.waitAdvance=BackgroundPermissionPreparation.TIMEOUT_MS;
                BackgroundPermissionPreparation.Result result=rig.run();
                check(!result.verified&&result.cleanupKnown&&BackgroundPermissionPreparation.cleanTerminal(terminal(result),UID),"historical process cleanup does not confer authorization");
            }
        });
        test("clean_terminal_requires_published_receipt_digest",()->{
            Rig rig=new Rig();Map<String,Object> good=terminal(rig.run());
            for(String field:new String[]{"result_sha256","terminal_receipt_published","phase"}){
                Map<String,Object> changed=new LinkedHashMap<String,Object>(good);changed.remove(field);check(!BackgroundPermissionPreparation.cleanTerminal(changed,UID),"missing terminal identity "+field);}
        });
        test("verified_terminal_requires_full_exact_stdout_digest",()->{
            Rig rig=new Rig();Map<String,Object> good=terminal(rig.run());
            for(Mutation mutate:Arrays.<Mutation>asList(v->v.put("stdout_sha256",BackgroundPermissionPreparation.sha(bytes("00"))),v->v.put("stdout_bytes",3),
                    v->v.put("stdout_overflow",true),v->v.put("stdout_complete",false),v->v.put("exit_code",1))){
                Map<String,Object> changed=new LinkedHashMap<String,Object>(good);mutate.change(changed);check(!BackgroundPermissionPreparation.cleanTerminal(changed,UID),"incomplete/mismatched root output refused");}
        });
    }
    static String json(String value){return "\""+value.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r")+"\"";}
    static String array(List<String> values){StringBuilder out=new StringBuilder("[");for(String value:values){if(out.length()>1)out.append(',');out.append(json(value));}return out.append(']').toString();}
    public static void main(String[] args)throws Exception {
        cases();String report="{\"passed\":"+passed.size()+",\"failed\":"+failures.size()+",\"cases\":"+array(passed)+",\"failures\":"+array(failures)
            +",\"production_worker_executed\":true,\"process_clock_lease_journal_fakes\":true,\"su_executed\":false,\"android_runtime\":false,\"phone_tested\":false}";
        Path path=Paths.get(args[0]);Files.write(path,report.getBytes(StandardCharsets.UTF_8));System.out.println(report);
        if(!failures.isEmpty())throw new AssertionError(failures.size()+" host cases failed");
    }
}
