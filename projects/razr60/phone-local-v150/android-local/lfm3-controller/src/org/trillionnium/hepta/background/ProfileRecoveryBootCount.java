package org.trillionnium.hepta.background;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Owns only a fixed, read-only boot-count command. Its output is data, never cleanup authority. */
final class ProfileRecoveryBootCount {
    interface Clock { long now(); }
    interface Starter { Process start() throws IOException; }
    private static final long CLEANUP_RESERVE_MS=500;
    private final Clock clock;
    private final Starter starter;
    private Process active;
    private boolean cancelled;
    ProfileRecoveryBootCount(Clock clock){
        this(clock,()->new ProcessBuilder("/system/bin/cmd","settings","get","global","boot_count")
                .redirectErrorStream(true).start());
    }
    // Package-private deterministic process boundary for host tests; production uses only the fixed argv above.
    ProfileRecoveryBootCount(Clock clock,Starter starter){this.clock=clock;this.starter=starter;}
    private long remaining(long deadline)throws IOException{
        long now=clock.now();
        if(now<0||now>=deadline)throw new IOException("RECOVERY_BOOT_DEADLINE");
        return deadline-now;
    }
    private synchronized Process start(long deadline)throws Exception{
        remaining(deadline);
        if(cancelled||active!=null)throw new IOException("RECOVERY_BOOT_OWNER_UNAVAILABLE");
        // Publish ownership before the watchdog can pass this monitor and halt the parent.
        active=starter.start();
        if(active==null)throw new IOException("RECOVERY_BOOT_PROCESS_MISSING");
        return active;
    }
    /** Called by the existing request watchdog before its halt; never signals a discovered PID. */
    synchronized void abortForDeadline(){
        cancelled=true;
        if(active!=null&&active.isAlive())active.destroyForcibly();
    }
    int read(long deadline)throws Exception{
        // Reserve within the original request deadline; never add a timeout grace.
        long readDeadline=deadline-CLEANUP_RESERVE_MS;
        Process child=start(readDeadline);
        Capture capture=null;Thread reader=null;Throwable primary=null;
        try{
            child.getOutputStream().close();
            capture=new Capture(child.getInputStream());
            reader=new Thread(capture,"HeptaProfileBootCountRead");reader.setDaemon(true);reader.start();
            if(!child.waitFor(remaining(readDeadline),TimeUnit.MILLISECONDS))
                throw new IOException("RECOVERY_BOOT_DEADLINE");
            if(child.exitValue()!=0)throw new IOException("RECOVERY_BOOT_EXIT");
            reader.join(remaining(readDeadline));
            if(reader.isAlive())throw new IOException("RECOVERY_BOOT_OUTPUT_INCOMPLETE");
            if(capture.error!=null)throw new IOException("RECOVERY_BOOT_OUTPUT_FAILED",capture.error);
            if(!capture.eof)throw new IOException("RECOVERY_BOOT_OUTPUT_INCOMPLETE");
            int value=parse(capture.bytes);
            remaining(deadline);
            return value;
        }catch(Exception|Error failure){primary=failure;throw failure;}
        finally{
            try{retire(child,reader,deadline);}
            catch(Exception|Error closeFailure){
                if(primary==null)throw closeFailure;
                if(closeFailure!=primary)primary.addSuppressed(closeFailure);
            }
        }
    }
    private void retire(Process child,Thread reader,long deadline)throws Exception{
        if(child.isAlive())child.destroyForcibly();
        long left=deadline-clock.now();
        if(child.isAlive()&&left>0)child.waitFor(left,TimeUnit.MILLISECONDS);
        if(child.isAlive())throw new IOException("RECOVERY_BOOT_CHILD_EXIT_UNKNOWN");
        left=deadline-clock.now();
        if(reader!=null&&reader.isAlive()&&left>0)reader.join(left);
        // A descendant retaining the pipe is not treated as EOF or as proven tree cleanup.
        if(reader!=null&&reader.isAlive())throw new IOException("RECOVERY_BOOT_OUTPUT_INCOMPLETE");
        child.getInputStream().close();child.getErrorStream().close();child.getOutputStream().close();
        synchronized(this){
            if(active!=child)throw new IOException("RECOVERY_BOOT_OWNER_CHANGED");
            active=null;
        }
        remaining(deadline);
    }
    static int parse(byte[] bytes)throws IOException{
        if(bytes==null||bytes.length<2||bytes.length>11||bytes[bytes.length-1]!='\n')
            throw new IOException("RECOVERY_BOOT_INTEGER");
        for(int i=0;i<bytes.length-1;i++)if(bytes[i]<'0'||bytes[i]>'9')
            throw new IOException("RECOVERY_BOOT_INTEGER");
        if(bytes.length>2&&bytes[0]=='0')throw new IOException("RECOVERY_BOOT_INTEGER");
        try{return Integer.parseInt(new String(bytes,0,bytes.length-1,StandardCharsets.US_ASCII));}
        catch(NumberFormatException invalid){throw new IOException("RECOVERY_BOOT_INTEGER_RANGE",invalid);}
    }
    private static final class Capture implements Runnable{
        final InputStream input;volatile byte[] bytes;volatile Throwable error;volatile boolean eof;
        Capture(InputStream input){this.input=input;}
        public void run(){
            try(InputStream owned=input;ByteArrayOutputStream output=new ByteArrayOutputStream()){
                byte[] buffer=new byte[32];int count;
                while((count=owned.read(buffer))!=-1){
                    if(output.size()+count>32)throw new IOException("RECOVERY_BOOT_OUTPUT_BOUND");
                    output.write(buffer,0,count);
                }
                bytes=output.toByteArray();eof=true;
            }catch(Throwable failure){error=failure;}
        }
    }
}
