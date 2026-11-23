package org.trillionnium.hepta.local;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** A real child runs the generated production worker against an explicitly fake SDK. */
public final class NativeCancellationPipeHostTest {
    private static final String G="11111111111111111111111111111111",T="22222222222222222222222222222222",R="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    private static final class Counted extends Process {
        final Process p;int terms,forces;
        Counted(Process value){p=value;}
        public OutputStream getOutputStream(){return p.getOutputStream();}
        public InputStream getInputStream(){return p.getInputStream();}
        public InputStream getErrorStream(){return p.getErrorStream();}
        public int waitFor()throws InterruptedException{return p.waitFor();}
        public boolean waitFor(long n,TimeUnit u)throws InterruptedException{return p.waitFor(n,u);}
        public int exitValue(){return p.exitValue();}
        public synchronized void destroy(){terms++;p.destroy();}
        public synchronized Process destroyForcibly(){forces++;p.destroyForcibly();return this;}
        public boolean isAlive(){return p.isAlive();}
    }
    private static void awaitFile(Path path,Process child)throws Exception{
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);
        while(!Files.isRegularFile(path)){
            check(child.isAlive(),"native exited before actual generate marker");
            check(System.nanoTime()<deadline,"actual generate marker deadline");Thread.sleep(5);
        }
        check(Arrays.equals(Files.readAllBytes(path),"generate_entered\n".getBytes(StandardCharsets.US_ASCII)),"exact fake-SDK marker");
    }
    private static long ready(BufferedReader reader)throws Exception{
        String line=reader.readLine();check(line!=null,"real READY absent");
        String[] fields=line.split(" ");
        check(fields.length==4&&"HEPTA_WARM_READY".equals(fields[0])&&G.equals(fields[1])&&T.equals(fields[2]),"actual READY identity");
        return Long.parseLong(fields[3]);
    }
    public static void main(String[] args)throws Exception{
        check(args.length>5,"mode, marker, release, stderr, native argv required");
        String mode=args[0];Path marker=Paths.get(args[1]),release=Paths.get(args[2]);File stderr=new File(args[3]);
        check(!Files.exists(marker)&&!Files.exists(release)&&!stderr.exists(),"new host case paths");
        List<String> command=Arrays.asList(Arrays.copyOfRange(args,4,args.length));
        ProcessBuilder builder=new ProcessBuilder(command).redirectError(stderr);
        builder.environment().put("HEPTA_CANCEL_TEST_ENTER",marker.toString());
        builder.environment().put("HEPTA_CANCEL_TEST_RELEASE",release.toString());
        builder.environment().put("HEPTA_CANCEL_TEST_DELAY_MS","shared_cancel".equals(mode)?"4300":"0");
        Counted p=new Counted(builder.start());OwnedWorkerCancellation owner=new OwnedWorkerCancellation(G,T);owner.attach(p,G,T);
        long workerPid=-1,started=System.nanoTime();Integer exit=null;boolean observed=false,force=false;
        try{
            if("shared_cancel".equals(mode)){
                WarmProcessSession session=new WarmProcessSession(p,G,T,owner);AtomicReference<Object> outcome=new AtomicReference<Object>();
                Thread request=new Thread(()->{try{outcome.set(session.exchange(R,32,30000));}catch(Throwable e){outcome.set(e);}});
                request.start();awaitFile(marker,p);workerPid=session.workerPid();check(workerPid>0,"actual worker PID observed");
                started=System.nanoTime();owner.cancel();session.cancel();owner.cancel();
                // Separate filesystem gate is released only after destroy() returned.
                // A concurrent warm reader may still deliver DONE; its actual native receipt decides transport state.
                Files.write(release,"released_after_destroy\n".getBytes(StandardCharsets.US_ASCII),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
                request.join(13000);
                check(!request.isAlive()&&outcome.get() instanceof WarmProcessSession.Failure,"actual cancelled RUN not accepted");
                WarmProcessSession.Cleanup end=session.finish();observed=end.exitObserved;exit=end.exitCode;force=end.forceSent;
                check(observed&&exit==143&&!force&&p.terms==1&&p.forces==0,"generated worker real cancellation must retain143 and shared one signal");
                check(session.requestsSent()==1,"no second RUN or fabricated CLOSE");
            }else{
                BufferedReader control=new BufferedReader(new InputStreamReader(p.getInputStream(),StandardCharsets.US_ASCII));
                workerPid=ready(control);
                if("idle_cancel".equals(mode)||"partial_cancel".equals(mode)){
                    if("partial_cancel".equals(mode)){p.getOutputStream().write(("RUN "+G).getBytes(StandardCharsets.US_ASCII));p.getOutputStream().flush();}
                    owner.cancel();OwnedWorkerCancellation.Exit end=owner.awaitCancellation();observed=end.observed;exit=end.code;force=end.forceSent;
                    check(observed&&exit==143&&!force&&p.terms==1,"idle or partial control read must exit within shared grace");
                }else{
                    p.getOutputStream().write(("RUN "+G+" "+T+" "+R+" 1 32 30000\n").getBytes(StandardCharsets.US_ASCII));p.getOutputStream().flush();
                    awaitFile(marker,p);started=System.nanoTime();
                    if("baseline_destroy".equals(mode)||"raw_cancel".equals(mode))owner.cancel();
                    else if("normal_broken".equals(mode))p.getInputStream().close();
                    else throw new AssertionError("unknown mode");
                    Files.write(release,"released_after_pipe_close\n".getBytes(StandardCharsets.US_ASCII),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
                    if("baseline_destroy".equals(mode)||"raw_cancel".equals(mode)){
                        OwnedWorkerCancellation.Exit end=owner.awaitCancellation();observed=end.observed;exit=end.code;force=end.forceSent;
                        if("baseline_destroy".equals(mode))check(observed&&(exit==141||exit==74)&&!force&&p.terms==1,"baseline must expose unclassified broken-control failure");
                        else check(observed&&exit==143&&!force&&p.terms==1&&p.forces==0,"raw cancellation retains143 after the actual pipe closes");
                    }else{
                        observed=p.waitFor(8,TimeUnit.SECONDS);exit=observed?p.exitValue():null;
                        check(observed&&exit==74&&p.terms==0&&p.forces==0,"normal broken control remains failure74 without inventing cancellation");
                    }
                }
            }
            check(observed&&!p.isAlive(),"actual child wait observed");
            long elapsed=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started);
            if("shared_cancel".equals(mode))check(elapsed>=4000&&elapsed<12000,"4.3s synthetic SDK drain allowed, bounded below force deadline");
            System.out.println("NATIVE_PIPE_RESULT mode="+mode+" exit="+exit+" observed="+observed+" force="+force
                    +" term_calls="+p.terms+" force_calls="+p.forces+" worker_pid="+workerPid+" elapsed_ms="+elapsed+" proprietary_sdk_executed=false");
        }finally{
            if(p.isAlive()){p.destroyForcibly();check(p.waitFor(8,TimeUnit.SECONDS),"test-owned child cleanup unknown");}
        }
    }
}
