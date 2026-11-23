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

public final class ProfileRecoveryBootCountHostTest {
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private interface Checked { void run() throws Exception; }
    private static long now(){return System.nanoTime()/1000000L;}
    private static byte[] bytes(String value){return value.getBytes(StandardCharsets.US_ASCII);}
    private static void need(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static Exception fails(Checked work,String message)throws Exception{
        try{work.run();}catch(Exception failure){need(message.equals(failure.getMessage()),"expected "+message+" got "+failure);return failure;}
        throw new AssertionError("expected "+message);
    }
    private static void test(String name,Checked work)throws Exception{work.run();names.add(name);}
    private static final class FakeProcess extends Process {
        final InputStream input;final ByteArrayOutputStream stdin=new ByteArrayOutputStream();
        boolean alive;final int code;int destroys;boolean waitTimeout;
        FakeProcess(InputStream input,boolean alive,int code){this.input=input;this.alive=alive;this.code=code;}
        public OutputStream getOutputStream(){return stdin;}
        public InputStream getInputStream(){return input;}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public int waitFor(){if(alive)throw new IllegalStateException("fixture blocking wait");return code;}
        public boolean waitFor(long amount,TimeUnit unit){return !alive||!waitTimeout;}
        public int exitValue(){if(alive)throw new IllegalThreadStateException();return code;}
        public void destroy(){destroys++;alive=false;}
        public Process destroyForcibly(){destroy();return this;}
        public boolean isAlive(){return alive;}
    }
    private static final class HeldInput extends InputStream {
        final CountDownLatch release=new CountDownLatch(1),closed=new CountDownLatch(1);
        public int read()throws IOException{
            try{release.await();return -1;}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}
        }
        public void close(){release.countDown();closed.countDown();}
    }
    private static ProfileRecoveryBootCount owner(FakeProcess child){
        return new ProfileRecoveryBootCount(ProfileRecoveryBootCountHostTest::now,()->child);
    }
    public static void main(String[] args)throws Exception{
        test("canonical_nonnegative_integer",()->{
            need(ProfileRecoveryBootCount.parse(bytes("0\n"))==0,"zero");
            need(ProfileRecoveryBootCount.parse(bytes("83\n"))==83,"actual form");
            need(ProfileRecoveryBootCount.parse(bytes("2147483647\n"))==Integer.MAX_VALUE,"max");
        });
        test("malformed_extra_overflow_output",()->{
            for(String value:new String[]{"","83","-1\n","+83\n"," 83\n","083\n","83\n84\n","null\n","83\r\n"})
                fails(()->ProfileRecoveryBootCount.parse(bytes(value)),"RECOVERY_BOOT_INTEGER");
            fails(()->ProfileRecoveryBootCount.parse(bytes("2147483648\n")),"RECOVERY_BOOT_INTEGER_RANGE");
        });
        test("expired_before_spawn",()->{
            AtomicInteger starts=new AtomicInteger();
            ProfileRecoveryBootCount reader=new ProfileRecoveryBootCount(ProfileRecoveryBootCountHostTest::now,()->{
                starts.incrementAndGet();throw new IOException("must not start");
            });
            fails(()->reader.read(now()+499),"RECOVERY_BOOT_DEADLINE");
            need(starts.get()==0,"no child at expired reserved deadline");
        });
        test("real_host_child_success_and_sequential_owner",()->{
            List<Process> children=new ArrayList<Process>();
            ProfileRecoveryBootCount reader=new ProfileRecoveryBootCount(ProfileRecoveryBootCountHostTest::now,()->{
                Process p=new ProcessBuilder("/usr/bin/python3","-c","print(83)").start();children.add(p);return p;
            });
            try{
                need(reader.read(now()+2000)==83,"first real value");
                need(reader.read(now()+2000)==83,"owner reused after exact retire");
                need(children.size()==2,"two owned children");
                for(Process p:children)need(!p.isAlive()&&p.exitValue()==0,"exit observed");
            }finally{for(Process p:children)if(p.isAlive()){p.destroyForcibly();p.waitFor(2,TimeUnit.SECONDS);}}
        });
        test("nonzero_exit_cannot_supply_integer",()->{
            FakeProcess p=new FakeProcess(new ByteArrayInputStream(bytes("83\n")),false,7);
            fails(()->owner(p).read(now()+1000),"RECOVERY_BOOT_EXIT");
            need(!p.isAlive(),"fixture exited");
        });
        test("output_bound_preserves_capture_cause",()->{
            FakeProcess p=new FakeProcess(new ByteArrayInputStream(new byte[33]),false,0);
            Exception e=fails(()->owner(p).read(now()+1000),"RECOVERY_BOOT_OUTPUT_FAILED");
            need(e.getCause()!=null&&"RECOVERY_BOOT_OUTPUT_BOUND".equals(e.getCause().getMessage()),"bound cause");
        });
        test("exit_without_eof_is_not_success",()->{
            HeldInput input=new HeldInput();FakeProcess p=new FakeProcess(input,false,0);
            try{
                Exception e=fails(()->owner(p).read(now()+650),"RECOVERY_BOOT_OUTPUT_INCOMPLETE");
                need(e.getSuppressed().length==1,"retire also records incomplete output");
            }finally{input.release.countDown();need(input.closed.await(1,TimeUnit.SECONDS),"fixture reader drained after explicit release");}
        });
        test("timeout_signals_only_owned_child",()->{
            FakeProcess p=new FakeProcess(new ByteArrayInputStream(bytes("83\n")),true,0);p.waitTimeout=true;
            FakeProcess other=new FakeProcess(new ByteArrayInputStream(new byte[0]),true,0);
            fails(()->owner(p).read(now()+1000),"RECOVERY_BOOT_DEADLINE");
            need(p.destroys==1&&!p.isAlive(),"owned retire exit observed");
            need(other.destroys==0&&other.isAlive(),"unrelated process untouched");
        });
        test("watchdog_cancel_before_start",()->{
            AtomicInteger starts=new AtomicInteger();
            ProfileRecoveryBootCount reader=new ProfileRecoveryBootCount(ProfileRecoveryBootCountHostTest::now,()->{
                starts.incrementAndGet();return new FakeProcess(new ByteArrayInputStream(bytes("83\n")),false,0);
            });
            reader.abortForDeadline();
            fails(()->reader.read(now()+1000),"RECOVERY_BOOT_OWNER_UNAVAILABLE");
            need(starts.get()==0,"cancelled owner cannot launch");
        });
        test("watchdog_terminates_actual_owned_host_child",()->{
            AtomicReference<Process> process=new AtomicReference<Process>();AtomicReference<Throwable> outcome=new AtomicReference<Throwable>();
            CountDownLatch started=new CountDownLatch(1);
            ProfileRecoveryBootCount reader=new ProfileRecoveryBootCount(ProfileRecoveryBootCountHostTest::now,()->{
                Process p=new ProcessBuilder("/usr/bin/python3","-c","import time; time.sleep(5)").start();
                process.set(p);started.countDown();return p;
            });
            Thread worker=new Thread(()->{try{reader.read(now()+2000);outcome.set(new AssertionError("cancelled child returned success"));}catch(Throwable e){outcome.set(e);}},"HostBootOwnerTest");
            worker.start();
            try{
                need(started.await(1,TimeUnit.SECONDS),"actual start observed");
                reader.abortForDeadline();worker.join(2500);
                need(!worker.isAlive(),"reader joined");
                need(outcome.get() instanceof IOException,"cancel remains failure");
                Process p=process.get();need(p!=null&&!p.isAlive(),"real exit observed independently of signal request");
            }finally{
                Process p=process.get();if(p!=null&&p.isAlive()){p.destroyForcibly();p.waitFor(2,TimeUnit.SECONDS);}
                worker.join(1000);
            }
        });
        test("read_error_cause_preserved",()->{
            IOException original=new IOException("HOST_SYNTHETIC_READ");
            InputStream bad=new InputStream(){public int read()throws IOException{throw original;}};
            Exception e=fails(()->owner(new FakeProcess(bad,false,0)).read(now()+1000),"RECOVERY_BOOT_OUTPUT_FAILED");
            need(e.getCause()==original,"original read exception");
        });
        StringBuilder list=new StringBuilder("[");
        for(String name:names){if(list.length()>1)list.append(',');list.append('"').append(name).append('"');}
        System.out.println("{\"schema\":\"hepta.boot-count-owner-host.v1\",\"cases\":"+names.size()
                +",\"assertions\":"+assertions+",\"case_names\":"+list+"],\"phone_contacted\":false,\"android_runtime\":false}");
    }
}
