import org.trillionnium.hepta.local.WarmProcessSession;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Real child-process lifecycle tests. The protocol peer is synthetic, not a model. */
public final class WarmProcessSessionHostTest {
    private static final String G="11111111111111111111111111111111",T="22222222222222222222222222222222";
    private static final String A="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",B="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static Process child(String mode)throws Exception{
        return new ProcessBuilder(System.getProperty("java.home")+"/bin/java","-cp",System.getProperty("java.class.path"),
                WarmProcessSessionHostTest.class.getName(),"child",mode).redirectError(ProcessBuilder.Redirect.INHERIT).start();
    }
    private static void peer(String mode)throws Exception{
        if("late".equals(mode))Runtime.getRuntime().addShutdownHook(new Thread(new Runnable(){public void run(){
            try{Thread.sleep(20000);}catch(InterruptedException ignored){Thread.currentThread().interrupt();}
        }}));
        String pid=ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
        System.out.println("HEPTA_WARM_READY "+G+" "+T+" "+pid);System.out.flush();
        BufferedReader input=new BufferedReader(new InputStreamReader(System.in,"US-ASCII"));
        for(String line;(line=input.readLine())!=null;){
            String[] p=line.split(" ");
            if("CLOSE".equals(p[0])){if("close-hang".equals(mode))Thread.sleep(20000);return;}
            if("slow".equals(mode)||"late".equals(mode))Thread.sleep(600);
            if("stall".equals(mode)){Thread.sleep(20000);return;}
            String generation="stale".equals(mode)?"33333333333333333333333333333333":G;
            System.out.println("HEPTA_WARM_DONE "+generation+" "+T+" "+p[3]+" "+p[4]+" 0");System.out.flush();
        }
    }
    private static void serialReuse()throws Exception{
        Process p=child("good");WarmProcessSession s=new WarmProcessSession(p,G,T);
        WarmProcessSession.Reply a=s.exchange(A,32,1000),b=s.exchange(B,32,1000);
        check(a.sequence==1&&b.sequence==2&&s.requestsSent()==2,"request sequence");
        check(p.isAlive()&&s.observedExitCode()==null,"request completion must not invent process exit");
        WarmProcessSession.Cleanup end=s.finish();
        check(end.exitObserved&&end.exitCode!=null&&end.exitCode==0&&!p.isAlive(),"owned terminal exit");
        try{s.exchange(A,32,1000);throw new AssertionError("retired generation reused");}
        catch(WarmProcessSession.Failure expected){check(expected.cleanup.exitObserved,"retired exit proof");}
    }
    private static void staleReply()throws Exception{
        Process p=child("stale");WarmProcessSession s=new WarmProcessSession(p,G,T);
        try{s.exchange(A,32,1000);throw new AssertionError("wrong generation accepted");}
        catch(WarmProcessSession.Failure expected){check(expected.cleanup.exitObserved&&!p.isAlive(),"stale peer retired");}
    }
    private static void overlap()throws Exception{
        Process p=child("slow");final WarmProcessSession s=new WarmProcessSession(p,G,T);
        final AtomicReference<Throwable> failure=new AtomicReference<Throwable>();
        Thread first=new Thread(new Runnable(){public void run(){try{s.exchange(A,32,2000);}catch(Throwable e){failure.set(e);}}});
        first.start();long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        while(s.requestsSent()==0&&System.nanoTime()<until)Thread.sleep(5);
        try{s.exchange(B,32,2000);throw new AssertionError("overlapping request accepted");}
        catch(IllegalStateException expected){check(s.requestsSent()==1,"overlap did not send a second request");}
        first.join(4000);check(!first.isAlive()&&failure.get()==null,"original serial owner finishes");
        check(s.finish().exitObserved&&!p.isAlive(),"overlap test cleanup");
    }
    private static void cancelLate()throws Exception{
        Process p=child("late");final WarmProcessSession s=new WarmProcessSession(p,G,T);
        final AtomicReference<Object> result=new AtomicReference<Object>();
        Thread generation=new Thread(new Runnable(){public void run(){try{result.set(s.exchange(A,32,5000));}catch(Exception e){result.set(e);}}});
        generation.start();long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        while(s.requestsSent()==0&&System.nanoTime()<until)Thread.sleep(5);
        s.cancel();generation.join(12000);
        check(!generation.isAlive()&&result.get() instanceof WarmProcessSession.Failure,"cancel rejects a late complete frame");
        WarmProcessSession.Failure failure=(WarmProcessSession.Failure)result.get();
        check(failure.cleanup.exitObserved&&!p.isAlive(),"cancel observes actual child exit");
        check(failure.cleanup.forceSent,"noncooperative peer requires force termination");
        WarmProcessSession.Cleanup terminal=s.finish();
        check(terminal.exitObserved&&terminal.forceSent,"terminal exit and force evidence retained");
    }
    private static void deadline()throws Exception{
        Process p=child("stall");WarmProcessSession s=new WarmProcessSession(p,G,T);
        try{s.exchange(A,32,1000);throw new AssertionError("stalled request accepted");}
        catch(WarmProcessSession.Failure expected){check(expected.timedOut&&expected.cleanup.exitObserved&&!p.isAlive(),"deadline retires actual worker");}
    }
    private static void unprovenExit(){
        Process stubborn=new Process(){
            public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
            public InputStream getInputStream(){return new ByteArrayInputStream(new byte[0]);}
            public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
            public int waitFor(){throw new IllegalStateException("not an observed exit");}
            public boolean waitFor(long timeout,TimeUnit unit){return false;}
            public int exitValue(){throw new IllegalThreadStateException("still alive");}
            public void destroy(){ }
            public Process destroyForcibly(){return this;}
            public boolean isAlive(){return true;}
        };
        WarmProcessSession.Cleanup end=new WarmProcessSession(stubborn,G,T).finish();
        check(!end.exitObserved&&end.exitCode==null,"failed termination must remain unknown");
    }
    public static void main(String[] args)throws Exception{
        if(args.length==2&&"child".equals(args[0])){peer(args[1]);return;}
        serialReuse();staleReply();overlap();cancelLate();deadline();unprovenExit();
        System.out.println("WarmProcessSession: real reuse/exit, stale/overlap/cancel/deadline rejection and unknown cleanup PASS; synthetic peer only");
    }
}
