package org.trillionnium.hepta.local;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;
import org.trillionnium.hepta.background.PublicProfileBusinessAbsenceRecovery;
import org.trillionnium.hepta.background.PublicProfileBusinessRecoveryHostTest;

/** Explicit owned-process/PM boundary. No su, Android, root census or phone is executed. */
final class FakeBusinessRecoveryProcess extends Process {
    static Path root;
    static int calls,exit,destroyed;
    static boolean badNonce,timeout,readFailure,delayedDrain,cancelled;
    static String suffix;
    static Runnable afterReply;
    static CountDownLatch drainRelease;
    static PublicProfileBusinessAbsenceRecovery.Request lastRequest;
    final byte[] output;
    volatile boolean alive;
    static void reset(){calls=exit=destroyed=0;badNonce=timeout=readFailure=delayedDrain=cancelled=false;
        suffix="";afterReply=null;lastRequest=null;root=null;drainRelease=new CountDownLatch(1);}
    static Process start(String command)throws Exception{
        calls++;String marker=" --request '";int at=command.indexOf(marker);
        if(at<0||!command.endsWith("'")||root==null)throw new IOException("synthetic transport framing");
        PublicProfileBusinessAbsenceRecovery.Manifest m=PublicProfileBusinessAbsenceRecovery.fromWire(command.substring(at+marker.length(),command.length()-1));
        Map<String,byte[]> inputs=new TreeMap<String,byte[]>();for(String p:m.paths())inputs.put(p,Files.readAllBytes(root.resolve(p)));
        PublicProfileBusinessAbsenceRecovery.Request r=PublicProfileBusinessAbsenceRecovery.request(m,inputs);lastRequest=r;
        JSONObject proof=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);
        if(badNonce)proof.put("request_id","99999999-9999-4999-8999-999999999999");
        if(exit!=0)proof=new JSONObject().put("schema",r.proofSchema()).put("request_id",r.requestId).put("cleanup_known",false).put("error","SYNTHETIC_CHECKER_FAILURE");
        android.os.SystemClock.now=r.started+31;if(afterReply!=null)afterReply.run();
        return new FakeBusinessRecoveryProcess((proof.toString()+"\n"+suffix).getBytes(StandardCharsets.UTF_8));
    }
    FakeBusinessRecoveryProcess(byte[] output){this.output=output;alive=delayedDrain;}
    public InputStream getInputStream(){
        if(readFailure)return new InputStream(){public int read()throws IOException{throw new IOException("synthetic incomplete EOF");}};
        if(delayedDrain)return new InputStream(){boolean released;final ByteArrayInputStream bytes=new ByteArrayInputStream(output);
            public int read()throws IOException{await();return bytes.read();}
            public int read(byte[] b,int o,int n)throws IOException{await();return bytes.read(b,o,n);}
            private void await()throws IOException{if(!released)try{drainRelease.await();released=true;}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}}};
        return new ByteArrayInputStream(output);
    }
    public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
    public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
    public int waitFor()throws InterruptedException{if(delayedDrain){drainRelease.await();alive=false;}return exit;}
    public boolean waitFor(long value,TimeUnit unit){return !timeout&&!delayedDrain;}
    public int exitValue(){if(alive)throw new IllegalThreadStateException("synthetic child still running");return exit;}
    public boolean isAlive(){return alive;}
    public void destroy(){destroyed++;}
}
