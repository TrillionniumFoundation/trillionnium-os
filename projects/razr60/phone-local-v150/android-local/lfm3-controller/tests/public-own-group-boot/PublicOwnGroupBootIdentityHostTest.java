package org.trillionnium.hepta.background;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Executes the actual boot comparison and existing owned-process reader on the host. */
public final class PublicOwnGroupBootIdentityHostTest {
    private static final List<String> names=new ArrayList<String>();
    private static int checks;
    private interface Work { void run() throws Exception; }
    private static long now(){return System.nanoTime()/1000000L;}
    private static void yes(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    private static void test(String name,Work work)throws Exception{work.run();names.add(name);}
    private static void fails(Work work,String code)throws Exception{
        try{work.run();}catch(Exception failure){yes(code.equals(failure.getMessage()),"wrong failure: "+failure);return;}
        throw new AssertionError("expected "+code);
    }
    private static final class Child extends Process {
        final InputStream input;final int status;boolean alive,timeout,throwOnDestroy;int kills;long waited;
        CountDownLatch stdinEntered,stdinRelease;
        Child(String text,int status){this.input=new ByteArrayInputStream(text.getBytes(StandardCharsets.US_ASCII));this.status=status;}
        public InputStream getInputStream(){return input;}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public OutputStream getOutputStream(){return new ByteArrayOutputStream(){public void close()throws IOException{
            if(stdinEntered!=null){stdinEntered.countDown();try{stdinRelease.await();}catch(InterruptedException error){Thread.currentThread().interrupt();throw new IOException(error);}}
            super.close();
        }};}
        public boolean isAlive(){return alive;}
        public int exitValue(){if(alive)throw new IllegalThreadStateException();return status;}
        public int waitFor(){return exitValue();}
        public boolean waitFor(long value,TimeUnit unit){waited=unit.toMillis(value);return !timeout;}
        public void destroy(){kills++;if(throwOnDestroy)throw new UnsupportedOperationException("HOST_ABORT_FAILURE");alive=false;}
        public Process destroyForcibly(){destroy();return this;}
    }
    private static ProfileRecoveryBootCount reader(Child child){
        return new ProfileRecoveryBootCount(PublicOwnGroupBootIdentityHostTest::now,()->child);
    }
    private static void require(ProfileRecoveryBootCount value,int expected)throws Exception{
        long current=now();PublicOwnGroupBootIdentity.requireCurrent(value,expected,current,current+10000);
    }
    public static void main(String[] args)throws Exception{
        test("actual_observation_matches_expected_boot",()->{
            Child child=new Child("83\n",0);require(reader(child),83);yes(!child.isAlive(),"child exit");
        });
        test("different_actual_boot_cannot_use_scope_claim",()->{
            fails(()->require(reader(new Child("84\n",0)),83),"PUBLIC_SCOPE_BOOT_CHANGED");
            fails(()->require(reader(new Child("0\n",0)),83),"PUBLIC_SCOPE_BOOT_CHANGED");
        });
        test("missing_reader_or_invalid_expected_value_never_spawns",()->{
            AtomicInteger starts=new AtomicInteger();ProfileRecoveryBootCount r=new ProfileRecoveryBootCount(
                PublicOwnGroupBootIdentityHostTest::now,()->{starts.incrementAndGet();return new Child("83\n",0);});
            fails(()->require(null,83),"PUBLIC_SCOPE_BOOT_READER_REQUIRED");
            fails(()->require(r,-1),"PUBLIC_SCOPE_BOOT_CHANGED");yes(starts.get()==0,"invalid expected boot started process");
        });
        test("no_default_for_null_empty_partial_or_ambiguous_output",()->{
            for(String text:new String[]{"null\n","","83","-1\n","+83\n","083\n","83\n84\n","83\r\n"," 83\n"})
                fails(()->require(reader(new Child(text,0)),83),"RECOVERY_BOOT_INTEGER");
        });
        test("integer_overflow_and_output_bound_are_refusals",()->{
            fails(()->require(reader(new Child("2147483648\n",0)),83),"RECOVERY_BOOT_INTEGER_RANGE");
            fails(()->require(reader(new Child("12345678901234567890123456789012345",0)),83),"RECOVERY_BOOT_OUTPUT_FAILED");
        });
        test("nonzero_exit_cannot_supply_an_apparently_correct_number",()->
            fails(()->require(reader(new Child("83\n",7)),83),"RECOVERY_BOOT_EXIT"));
        test("expired_and_overflowing_deadlines_never_spawn",()->{
            AtomicInteger starts=new AtomicInteger();ProfileRecoveryBootCount r=new ProfileRecoveryBootCount(
                PublicOwnGroupBootIdentityHostTest::now,()->{starts.incrementAndGet();return new Child("83\n",0);});
            long current=now();
            fails(()->PublicOwnGroupBootIdentity.requireCurrent(r,83,current,current),"PUBLIC_SCOPE_BOOT_DEADLINE");
            fails(()->PublicOwnGroupBootIdentity.requireCurrent(r,83,-1,current),"PUBLIC_SCOPE_BOOT_DEADLINE");
            fails(()->PublicOwnGroupBootIdentity.requireCurrent(r,83,Long.MAX_VALUE-1,Long.MAX_VALUE),"PUBLIC_SCOPE_BOOT_DEADLINE");
            fails(()->PublicOwnGroupBootIdentity.requireCurrent(r,83,current,current+499),"RECOVERY_BOOT_DEADLINE");
            yes(starts.get()==0,"deadline failure started child");
        });
        test("two_second_budget_cannot_be_widened_by_caller",()->{
            Child child=new Child("83\n",0);child.alive=true;child.timeout=true;
            fails(()->require(reader(child),83),"RECOVERY_BOOT_DEADLINE");
            yes(child.waited>0&&child.waited<=1500,"read budget exceeds cap minus cleanup reserve");
            yes(child.kills==1&&!child.isAlive(),"only owned child must retire");
        });
        test("retired_owner_cannot_restart_read",()->{
            AtomicInteger starts=new AtomicInteger();ProfileRecoveryBootCount r=new ProfileRecoveryBootCount(
                PublicOwnGroupBootIdentityHostTest::now,()->{starts.incrementAndGet();return new Child("83\n",0);});
            r.abortForDeadline();fails(()->require(r,83),"RECOVERY_BOOT_OWNER_UNAVAILABLE");
            yes(starts.get()==0,"retired owner restarted");
        });
        test("actual_host_process_output_is_checked",()->{
            List<Process> children=new ArrayList<Process>();
            ProfileRecoveryBootCount r=new ProfileRecoveryBootCount(PublicOwnGroupBootIdentityHostTest::now,()->{
                Process child=new ProcessBuilder("/usr/bin/python3","-c","print(83)").start();children.add(child);return child;});
            try{require(r,83);fails(()->require(r,84),"PUBLIC_SCOPE_BOOT_CHANGED");
                yes(children.size()==2,"comparison silently reused expected value");
                for(Process child:children)yes(!child.isAlive()&&child.exitValue()==0,"real process exit missing");
            }finally{for(Process child:children)if(child.isAlive()){child.destroyForcibly();child.waitFor(2,TimeUnit.SECONDS);}}
        });
        test("exact_broker_cleanup_entry_retires_reader_before_later_start",()->{
            AtomicInteger starts=new AtomicInteger();ProfileRecoveryBootCount r=new ProfileRecoveryBootCount(
                PublicOwnGroupBootIdentityHostTest::now,()->{starts.incrementAndGet();return new Child("83\n",0);});
            BrokerBootLifecycleFixture fixture=new BrokerBootLifecycleFixture(r);fixture.cleanup();
            yes(fixture.closing.get(),"cleanup did not close admission");
            fails(()->require(r,83),"RECOVERY_BOOT_OWNER_UNAVAILABLE");yes(starts.get()==0,"cleanup allowed later child");
        });
        test("exact_broker_hard_halt_aborts_actual_owned_child",()->{
            AtomicReference<Process> child=new AtomicReference<Process>();AtomicReference<Throwable> outcome=new AtomicReference<Throwable>();
            CountDownLatch started=new CountDownLatch(1);
            ProfileRecoveryBootCount r=new ProfileRecoveryBootCount(PublicOwnGroupBootIdentityHostTest::now,()->{
                Process p=new ProcessBuilder("/usr/bin/python3","-c","import time; time.sleep(5)").start();child.set(p);started.countDown();return p;});
            Thread worker=new Thread(()->{try{require(r,83);outcome.set(new AssertionError("cancelled read returned"));}catch(Throwable e){outcome.set(e);}});
            worker.start();
            try{
                yes(started.await(1,TimeUnit.SECONDS),"owned child not started");
                BrokerBootLifecycleFixture fixture=new BrokerBootLifecycleFixture(r);
                try{fixture.halt(70);throw new AssertionError("halt fixture returned");}
                catch(BrokerBootLifecycleFixture.Halted halted){yes(halted.exit==70,"halt result changed");}
                worker.join(2500);yes(!worker.isAlive(),"owned worker retained");
                yes(outcome.get() instanceof IOException,"cancelled read not refused");
                yes(child.get()!=null&&!child.get().isAlive(),"signal was mistaken for observed exit");
            }finally{Process p=child.get();if(p!=null&&p.isAlive()){p.destroyForcibly();p.waitFor(2,TimeUnit.SECONDS);}worker.join(1000);}
        });
        test("abort_exception_cannot_skip_cleanup_or_promote_release",()->{
            Child child=new Child("83\n",0);child.alive=true;child.throwOnDestroy=true;
            child.stdinEntered=new CountDownLatch(1);child.stdinRelease=new CountDownLatch(1);
            ProfileRecoveryBootCount r=reader(child);AtomicReference<Throwable> outcome=new AtomicReference<Throwable>();
            Thread worker=new Thread(()->{try{require(r,83);}catch(Throwable e){outcome.set(e);}});worker.start();
            try{
                yes(child.stdinEntered.await(1,TimeUnit.SECONDS),"owned child not published");
                BrokerBootLifecycleFixture fixture=new BrokerBootLifecycleFixture(r);fixture.cleanup();
                yes(fixture.cleanupEntryReturned&&fixture.closing.get(),"abort failure skipped cleanup entry");
                yes("java.lang.UnsupportedOperationException".equals(fixture.bootReadRetirementFailure),"abort failure not retained");
                yes("CLEANUP_UNKNOWN".equals(fixture.released()),"abort failure promoted RELEASED");
                try{fixture.halt(0);throw new AssertionError("halt fixture returned");}
                catch(BrokerBootLifecycleFixture.Halted halted){yes(halted.exit==70,"abort failure produced successful halt");}
                child.throwOnDestroy=false;child.alive=false;child.stdinRelease.countDown();worker.join(2500);
                yes(!worker.isAlive(),"synthetic worker retained");
                yes("CLEANUP_UNKNOWN".equals(fixture.released()),"late observation erased previous abort failure");
            }finally{child.throwOnDestroy=false;child.alive=false;child.stdinRelease.countDown();worker.join(1000);}
        });
        test("late_halt_abort_failure_precedes_the_only_terminal_record",()->{
            Child child=new Child("83\n",0);child.alive=true;child.throwOnDestroy=true;
            child.stdinEntered=new CountDownLatch(1);child.stdinRelease=new CountDownLatch(1);
            ProfileRecoveryBootCount r=reader(child);
            Thread worker=new Thread(()->{try{require(r,83);}catch(Exception expected){}});worker.start();
            try{
                yes(child.stdinEntered.await(1,TimeUnit.SECONDS),"owned child not published");
                BrokerBootLifecycleFixture fixture=new BrokerBootLifecycleFixture(r);
                yes("RELEASED".equals(fixture.released())&&fixture.terminalStates.isEmpty(),"fixture must begin without an earlier failure");
                try{fixture.watchdogKnown();throw new AssertionError("halt fixture returned");}
                catch(BrokerBootLifecycleFixture.Halted halted){yes(halted.exit==70,"late abort failure exited successfully");}
                yes(fixture.terminalStates.size()==1,"terminal was missing or an earlier statement was already emitted");
                yes("CLEANUP_UNKNOWN".equals(fixture.terminalStates.get(0)),"irreversible false RELEASED terminal emitted");
                yes("CLEANUP_UNKNOWN".equals(fixture.state),"late failure not latched before terminal output");
            }finally{child.throwOnDestroy=false;child.alive=false;child.stdinRelease.countDown();worker.join(1000);yes(!worker.isAlive(),"synthetic worker retained");}
        });
        StringBuilder list=new StringBuilder("[");for(String name:names){if(list.length()>1)list.append(',');list.append('"').append(name).append('"');}
        System.out.println("{\"schema\":\"hepta.public-scope-boot-host.v1\",\"passed\":true,\"cases\":"+names.size()
            +",\"assertions\":"+checks+",\"case_names\":"+list+"],\"phone_contacted\":false,\"android_runtime\":false}");
    }
}
