package org.trillionnium.hepta.local;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Candidate lifecycle tests. Real OS child tests use a synthetic protocol peer, never a model or SDK. */
public final class OwnedWorkerCancellationHostTest {
    private static final String G="11111111111111111111111111111111",T="22222222222222222222222222222222",R="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static int assertions,cases;
    private static void check(boolean ok,String message){assertions++;if(!ok)throw new AssertionError(message);}
    private static long ns(long ms){return TimeUnit.MILLISECONDS.toNanos(ms);}
    private static final class ManualClock implements OwnedWorkerCancellation.Clock {
        private long value;
        public synchronized long nanoTime(){return value;}
        synchronized void advance(long n){if(n<0)throw new AssertionError("negative fake clock advance");value+=n;}
        synchronized void set(long n){if(n<value)throw new AssertionError("clock moved backwards");value=n;}
    }
    private static final class FakeProcess extends Process {
        final ManualClock clock;final AtomicInteger terms=new AtomicInteger(),forces=new AtomicInteger();
        volatile boolean alive=true,earlyFalse,interruptOnce,termThrows,forceThrows,forceWorks=true;
        long normalExitAt=Long.MAX_VALUE,termExitDelay=Long.MAX_VALUE,forceExitDelay;
        int exit=143;
        FakeProcess(ManualClock c){clock=c;}
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public InputStream getInputStream(){return new ByteArrayInputStream(new byte[0]);}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public int waitFor(){throw new AssertionError("unbounded wait forbidden");}
        public synchronized boolean waitFor(long amount,TimeUnit unit)throws InterruptedException{
            check(amount>=0,"wait duration nonnegative");
            if(interruptOnce){interruptOnce=false;throw new InterruptedException("synthetic interrupt");}
            if(!alive)return true;
            if(earlyFalse)return false;
            long now=clock.nanoTime(),duration=unit.toNanos(amount);
            long until=duration>Long.MAX_VALUE-now?Long.MAX_VALUE:now+duration;
            if(normalExitAt<=until){clock.set(Math.max(now,normalExitAt));alive=false;return true;}
            clock.set(until);return false;
        }
        public int exitValue(){if(alive)throw new IllegalThreadStateException("alive");return exit;}
        public synchronized void destroy(){
            terms.incrementAndGet();
            if(termThrows)throw new IllegalStateException("term transport failure");
            if(termExitDelay!=Long.MAX_VALUE)normalExitAt=Math.min(normalExitAt,clock.nanoTime()+termExitDelay);
        }
        public synchronized Process destroyForcibly(){
            forces.incrementAndGet();
            if(forceThrows)throw new IllegalStateException("force transport failure");
            if(forceWorks){exit=137;normalExitAt=Math.min(normalExitAt,clock.nanoTime()+forceExitDelay);}
            return this;
        }
        public boolean isAlive(){return alive;}
    }
    private static OwnedWorkerCancellation bound(ManualClock clock,FakeProcess process){
        OwnedWorkerCancellation c=new OwnedWorkerCancellation(G,T,clock);c.attach(process,G,T);return c;
    }
    private static void identityAndPending()throws Exception{
        ManualClock clock=new ManualClock();OwnedWorkerCancellation c=new OwnedWorkerCancellation(G,T,clock);
        c.cancel();check(c.isCancellationRequested()&&!c.snapshot().processBound&&c.snapshot().termAttempts==0,"pending cancellation immediately latched");
        FakeProcess p=new FakeProcess(clock);p.termExitDelay=ns(1);c.attach(p,G,T);c.attach(p,G,T);
        check(p.terms.get()==1,"first actual attachment signals once");
        try{c.attach(new FakeProcess(clock),G,T);throw new AssertionError("different actual Process accepted");}catch(IllegalArgumentException expected){}
        try{c.attach(p,G,R);throw new AssertionError("different task accepted");}catch(IllegalArgumentException expected){}
        try{c.attach(p,R,T);throw new AssertionError("different generation accepted");}catch(IllegalArgumentException expected){}
        check(c.awaitCancellation().observed,"pending cancellation actual wait result");cases++;
    }
    private static void duplicateConcurrentSignals()throws Exception{
        ManualClock clock=new ManualClock();FakeProcess p=new FakeProcess(clock);p.termExitDelay=ns(4300);OwnedWorkerCancellation c=bound(clock,p);
        CountDownLatch ready=new CountDownLatch(16),go=new CountDownLatch(1);List<Thread> all=new ArrayList<Thread>();
        for(int i=0;i<16;i++){Thread t=new Thread(()->{ready.countDown();try{go.await();}catch(InterruptedException e){throw new RuntimeException(e);}c.cancel();});all.add(t);t.start();}
        check(ready.await(2,TimeUnit.SECONDS),"cancellation callers ready");go.countDown();
        for(Thread t:all){t.join(2000);check(!t.isAlive(),"cancellation caller completed");}
        check(p.terms.get()==1&&c.snapshot().termAttempts==1,"one signal across duplicate callers");
        OwnedWorkerCancellation.Exit end=c.awaitCancellation();
        check(end.observed&&end.code==143&&!end.forceSent&&p.forces.get()==0,"4.3-second cooperative exit retained as 143 without force");
        check(clock.nanoTime()==ns(4300),"grace did not preempt observed delayed exit");cases++;
    }
    private static void deadlineIsNotRenewed(){
        ManualClock clock=new ManualClock();FakeProcess p=new FakeProcess(clock);p.forceExitDelay=ns(1000);OwnedWorkerCancellation c=bound(clock,p);
        c.cancel();clock.advance(ns(6000));c.cancel();clock.advance(ns(500));
        OwnedWorkerCancellation.Exit end=c.awaitCancellation();
        check(end.observed&&end.code==137&&end.forceSent,"actual forced exit is 137, not healthy close");
        check(clock.nanoTime()==ns(9000)&&p.terms.get()==1&&p.forces.get()==1,"force at first eight-second deadline, no renewal");
        c.cancel();c.awaitCancellation();check(clock.nanoTime()==ns(9000)&&p.terms.get()==1&&p.forces.get()==1,"observed exit and single attempts retained");cases++;
    }
    private static void unknownBounded(){
        ManualClock clock=new ManualClock();FakeProcess p=new FakeProcess(clock);p.forceWorks=false;OwnedWorkerCancellation c=bound(clock,p);
        OwnedWorkerCancellation.Exit a=c.awaitCancellation();
        check(!a.observed&&a.code==null&&a.forceSent,"unobserved force outcome remains unknown");
        check(clock.nanoTime()==ns(16000),"unknown total observation bounded");
        c.awaitCancellation();check(clock.nanoTime()==ns(16000)&&p.terms.get()==1&&p.forces.get()==1,"duplicate unknown wait cannot restart budget");cases++;
    }
    private static void earlyFalseDoesNotForce(){
        ManualClock clock=new ManualClock();FakeProcess p=new FakeProcess(clock);p.earlyFalse=true;OwnedWorkerCancellation c=bound(clock,p);
        OwnedWorkerCancellation.Exit a=c.awaitCancellation();
        check(!a.observed&&a.code==null&&!a.forceSent&&p.forces.get()==0&&clock.nanoTime()==0,"invalid early false must not abbreviate grace");cases++;
    }
    private static void signalFailureNoRetry(){
        ManualClock clock=new ManualClock();FakeProcess p=new FakeProcess(clock);p.termThrows=true;OwnedWorkerCancellation c=bound(clock,p);
        c.cancel();c.cancel();check(p.terms.get()==1&&!c.snapshot().termReturned&&c.snapshot().signalError!=null,"failed term attempt is recorded and not repeated");
        c.awaitCancellation();check(p.forces.get()==1&&c.snapshot().forceReturned,"separate force attempt after actual deadline");cases++;
    }
    private static void forceFailureUnknown(){
        ManualClock clock=new ManualClock();FakeProcess p=new FakeProcess(clock);p.forceThrows=true;OwnedWorkerCancellation c=bound(clock,p);
        OwnedWorkerCancellation.Exit a=c.awaitCancellation();
        check(!a.observed&&a.code==null&&!a.forceSent&&c.snapshot().forceAttempts==1&&!c.snapshot().forceReturned,"failed force return is not a sent/observed exit");
        c.awaitCancellation();check(p.forces.get()==1&&clock.nanoTime()==ns(16000),"failed force cannot be retried or extended");cases++;
    }
    private static void interruptedUnknown(){
        ManualClock clock=new ManualClock();FakeProcess p=new FakeProcess(clock);p.interruptOnce=true;OwnedWorkerCancellation c=bound(clock,p);
        OwnedWorkerCancellation.Exit a=c.awaitCancellation();
        check(!a.observed&&a.code==null&&Thread.currentThread().isInterrupted()&&p.forces.get()==0,"interruption preserves unknown and interrupt state");
        Thread.interrupted();cases++;
    }
    private static void normalCloseAndHungClose(){
        ManualClock a=new ManualClock();FakeProcess good=new FakeProcess(a);good.normalExitAt=ns(1000);good.exit=0;OwnedWorkerCancellation c=bound(a,good);
        OwnedWorkerCancellation.Exit clean=c.awaitGracefulClose();
        check(clean.observed&&clean.code==0&&!clean.forceSent&&good.terms.get()==0,"normal observed close has no cancellation signal");
        ManualClock b=new ManualClock();FakeProcess hung=new FakeProcess(b);OwnedWorkerCancellation d=bound(b,hung);
        OwnedWorkerCancellation.Exit forced=d.awaitGracefulClose();
        check(forced.observed&&forced.code==137&&forced.forceSent&&b.nanoTime()==ns(10000),"hung CLOSE gets two seconds then shared eight-second termination grace");
        check(hung.terms.get()==1&&hung.forces.get()==1,"hung close uses same authority");cases++;
    }
    private static void abnormalIsNotNormalized(){
        ManualClock clock=new ManualClock();FakeProcess p=new FakeProcess(clock);p.normalExitAt=0;p.exit=134;p.alive=false;OwnedWorkerCancellation c=bound(clock,p);
        OwnedWorkerCancellation.Exit a=c.awaitCancellation();
        check(a.observed&&a.code==134&&!a.forceSent&&p.terms.get()==0,"already-aborted worker retains 134 without invented graceful result");cases++;
    }
    private static final class CountingProcess extends Process {
        final Process actual;final AtomicInteger terms=new AtomicInteger(),forces=new AtomicInteger();
        CountingProcess(Process p){actual=p;}
        public OutputStream getOutputStream(){return actual.getOutputStream();}
        public InputStream getInputStream(){return actual.getInputStream();}
        public InputStream getErrorStream(){return actual.getErrorStream();}
        public int waitFor()throws InterruptedException{return actual.waitFor();}
        public boolean waitFor(long t,TimeUnit u)throws InterruptedException{return actual.waitFor(t,u);}
        public int exitValue(){return actual.exitValue();}
        public void destroy(){terms.incrementAndGet();actual.destroy();}
        public Process destroyForcibly(){forces.incrementAndGet();actual.destroyForcibly();return this;}
        public boolean isAlive(){return actual.isAlive();}
    }
    private static void child()throws Exception{
        Runtime.getRuntime().addShutdownHook(new Thread(()->{try{Thread.sleep(4300);}catch(InterruptedException ignored){Thread.currentThread().interrupt();}}));
        String pid=ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
        System.out.println("HEPTA_WARM_READY "+G+" "+T+" "+pid);System.out.flush();
        BufferedReader r=new BufferedReader(new InputStreamReader(System.in,"US-ASCII"));
        String line=r.readLine();if(line==null||!line.startsWith("RUN "))throw new AssertionError("actual RUN expected");
        System.err.println("REAL_TEST_RUN_ENTERED");System.err.flush();
        Thread.sleep(30000);
    }
    private static void actualDelayedProcess()throws Exception{
        Process real=new ProcessBuilder(System.getProperty("java.home")+"/bin/java","-cp",System.getProperty("java.class.path"),
                OwnedWorkerCancellationHostTest.class.getName(),"child").start();
        CountingProcess p=new CountingProcess(real);OwnedWorkerCancellation authority=new OwnedWorkerCancellation(G,T);
        authority.attach(p,G,T);WarmProcessSession session=new WarmProcessSession(p,G,T,authority);
        AtomicReference<Object> outcome=new AtomicReference<Object>();
        Thread request=new Thread(()->{try{outcome.set(session.exchange(R,32,30000));}catch(Throwable failure){outcome.set(failure);}});
        request.start();
        BufferedReader err=new BufferedReader(new InputStreamReader(real.getErrorStream(),"UTF-8"));
        check("REAL_TEST_RUN_ENTERED".equals(err.readLine()),"actual child entered first RUN");
        long start=System.nanoTime();
        authority.cancel();session.cancel();authority.cancel();session.cancel();
        check(authority.isCancellationRequested()&&session.isCancelled(),"all task request gates latched immediately");
        request.join(12000);
        check(!request.isAlive()&&outcome.get() instanceof WarmProcessSession.Failure,"cancelled actual exchange never accepts a result");
        WarmProcessSession.Cleanup cleanup=session.finish();long elapsed=System.nanoTime()-start;
        check(cleanup.exitObserved&&cleanup.exitCode==143&&!cleanup.forceSent&&!p.isAlive(),"real delayed SIGTERM exit observed as 143");
        check(p.terms.get()==1&&p.forces.get()==0,"real shared Process got exactly one destroy API call");
        check(elapsed>=ns(4000)&&elapsed<ns(11000),"actual delayed shutdown allowed but bounded");
        check(authority.snapshot().termAttempts==1&&authority.snapshot().exitCode==143,"single actual authority owns final observation");
        System.out.println("REAL_DELAYED_CHILD elapsed_ms="+TimeUnit.NANOSECONDS.toMillis(elapsed)+" exit="+cleanup.exitCode+" term_calls="+p.terms.get()+" force_calls="+p.forces.get()+" sdk_health_verified=false");
        cases++;
    }
    public static void main(String[] args)throws Exception{
        if(args.length==1&&"child".equals(args[0])){child();return;}
        identityAndPending();duplicateConcurrentSignals();deadlineIsNotRenewed();unknownBounded();
        earlyFalseDoesNotForce();signalFailureNoRetry();forceFailureUnknown();interruptedUnknown();
        normalCloseAndHungClose();abnormalIsNotNormalized();actualDelayedProcess();
        System.out.println("OwnedWorkerCancellation PASS cases="+cases+" assertions="+assertions+" native_sdk_executed=false phone_tested=false");
    }
}
