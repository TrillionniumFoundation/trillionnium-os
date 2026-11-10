package org.trillionnium.hepta.local;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** One owned process for one task. A completed request is not a process exit. */
public final class WarmProcessSession {
    public final String generation, taskId;
    private final Process process;
    private final OutputStream input;
    private final ArrayBlockingQueue<String> frames = new ArrayBlockingQueue<String>(4);
    private final AtomicReference<String> readerFailure = new AtomicReference<String>();
    private final AtomicBoolean cancelled = new AtomicBoolean(), closing = new AtomicBoolean();
    private final AtomicBoolean inFlight = new AtomicBoolean();
    private final AtomicBoolean forceEver = new AtomicBoolean();
    private volatile Integer observedExit;
    private volatile long workerPid;
    private volatile int sequence;
    private boolean ready;

    public static final class Reply {
        public final String generation, taskId, requestId;
        public final int sequence, status;
        Reply(String generation, String taskId, String requestId, int sequence, int status) {
            this.generation=generation; this.taskId=taskId; this.requestId=requestId;
            this.sequence=sequence; this.status=status;
        }
    }
    public static final class Cleanup {
        public final boolean exitObserved, forceSent;
        public final Integer exitCode;
        Cleanup(boolean exitObserved, Integer exitCode, boolean forceSent) {
            this.exitObserved=exitObserved; this.exitCode=exitCode; this.forceSent=forceSent;
        }
    }
    public static final class Failure extends IOException {
        private static final long serialVersionUID=1L;
        public final boolean timedOut;
        public final Cleanup cleanup;
        Failure(String message, boolean timedOut, Cleanup cleanup) {
            super(message); this.timedOut=timedOut; this.cleanup=cleanup;
        }
    }
    private static final class Deadline extends IOException {
        private static final long serialVersionUID=1L;
        Deadline(String message){super(message);}
    }
    public WarmProcessSession(Process process, String generation, String taskId) {
        if(process==null||!validId(generation)||!validId(taskId))
            throw new IllegalArgumentException("owned process and exact task/generation required");
        this.process=process; this.generation=generation; this.taskId=taskId;
        input=process.getOutputStream();
        Thread reader=new Thread(new Runnable(){public void run(){readFrames();}},"hepta-warm-control-reader");
        reader.setDaemon(true); reader.start();
    }
    public static boolean validId(String value) { return value!=null&&value.matches("[0-9a-f]{32}"); }
    public long workerPid() { return workerPid; }
    public int requestsSent() { return sequence; }
    public Integer observedExitCode() { return observedExit; }
    public boolean isAlive() { return process.isAlive(); }
    public boolean isCancelled() { return cancelled.get()||closing.get(); }
    public void cancel() {
        cancelled.set(true);
        if(process.isAlive())process.destroy();
    }
    private void readFrames() {
        try(InputStream output=process.getInputStream()) {
            ByteArrayOutputStream line=new ByteArrayOutputStream();
            for(int value;(value=output.read())!=-1;) {
                if(value=='\n') {
                    if(line.size()==0||!frames.offer(new String(line.toByteArray(),StandardCharsets.US_ASCII)))
                        throw new IOException("empty control frame or full control queue");
                    line.reset();
                } else {
                    if(value<32||value>126||line.size()>=256)throw new IOException("invalid or oversized control frame");
                    line.write(value);
                }
            }
            if(line.size()!=0)throw new IOException("truncated control frame");
            readerFailure.compareAndSet(null,"worker control channel ended");
        } catch(Exception error) {
            readerFailure.compareAndSet(null,error.getClass().getSimpleName()+": "+error.getMessage());
        }
    }
    private void send(String frame) throws IOException {
        input.write(frame.getBytes(StandardCharsets.US_ASCII)); input.flush();
    }
    private String awaitFrame(long deadline) throws IOException, InterruptedException {
        while(true) {
            if(cancelled.get()||closing.get())throw new IOException("task worker retired");
            if(System.nanoTime()>=deadline)throw new Deadline("task worker request deadline");
            String frame=frames.poll(100,TimeUnit.MILLISECONDS);
            if(frame!=null)return frame;
            String failure=readerFailure.get();
            if(failure!=null)throw new IOException(failure);
            if(process.waitFor(1,TimeUnit.MILLISECONDS)) {
                observedExit=process.exitValue(); throw new IOException("task worker exited before request completion");
            }
        }
    }
    /** The caller still must validate the create-only native receipt and output hashes. */
    public Reply exchange(String requestId, int maxTokens, long timeoutMillis) throws Failure {
        if(!validId(requestId)||maxTokens<1||maxTokens>1024||timeoutMillis<1000||timeoutMillis>300000)
            throw new IllegalArgumentException("invalid bounded request");
        if(!inFlight.compareAndSet(false,true))throw new IllegalStateException("overlapping task requests");
        final long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeoutMillis+2000);
        try {
            if(isCancelled())throw new IOException("task worker already retired");
            if(!ready) {
                String[] frame=awaitFrame(deadline).split(" ",-1);
                if(frame.length!=4||!"HEPTA_WARM_READY".equals(frame[0])||!generation.equals(frame[1])
                        ||!taskId.equals(frame[2])||!frame[3].matches("[1-9][0-9]{0,9}"))
                    throw new IOException("task worker ready identity differs");
                workerPid=Long.parseLong(frame[3]); ready=true;
            }
            if(isCancelled())throw new IOException("task worker retired before request");
            int expected=++sequence;
            send("RUN "+generation+" "+taskId+" "+requestId+" "+expected+" "+maxTokens+" "+timeoutMillis+"\n");
            String[] frame=awaitFrame(deadline).split(" ",-1);
            if(frame.length!=6||!"HEPTA_WARM_DONE".equals(frame[0])||!generation.equals(frame[1])
                    ||!taskId.equals(frame[2])||!requestId.equals(frame[3])||!Integer.toString(expected).equals(frame[4])
                    ||!frame[5].matches("[0-9]{1,3}"))throw new IOException("stale or mismatched task worker result");
            int status=Integer.parseInt(frame[5]);
            if(status==124)throw new Deadline("native task worker deadline");
            if(status!=0)throw new IOException("task worker request failed: "+status);
            if(isCancelled()||!process.isAlive())throw new IOException("worker retired before result acceptance");
            return new Reply(generation,taskId,requestId,expected,status);
        } catch(Exception error) {
            boolean timeout=error instanceof Deadline;
            cancel(); Cleanup cleanup=terminate(false);
            if(error instanceof InterruptedException)Thread.currentThread().interrupt();
            throw new Failure(error.getClass().getSimpleName()+": "+error.getMessage(),timeout,cleanup);
        } finally { inFlight.set(false); }
    }
    /** A task terminal is allowed only after this real Process has returned from waitFor. */
    public Cleanup finish() {
        closing.set(true);
        boolean graceful=!cancelled.get()&&!inFlight.get();
        if(graceful) {
            try { send("CLOSE "+generation+" "+taskId+"\n"); input.close(); }
            catch(IOException error) { graceful=false; cancel(); }
        } else cancel();
        return terminate(graceful);
    }
    private Cleanup terminate(boolean graceful) {
        boolean force=false;
        try {
            if(observedExit!=null)return new Cleanup(true,observedExit,forceEver.get());
            if(graceful&&process.waitFor(2000,TimeUnit.MILLISECONDS)) {
                observedExit=process.exitValue(); return new Cleanup(true,observedExit,forceEver.get());
            }
            process.destroy();
            if(!process.waitFor(2000,TimeUnit.MILLISECONDS)) {
                process.destroyForcibly(); force=true;forceEver.set(true);
                if(!process.waitFor(8000,TimeUnit.MILLISECONDS))return new Cleanup(false,null,true);
            }
            observedExit=process.exitValue(); return new Cleanup(true,observedExit,forceEver.get());
        } catch(InterruptedException interrupted) {
            Thread.currentThread().interrupt(); return new Cleanup(false,null,force||forceEver.get());
        }
    }
}
