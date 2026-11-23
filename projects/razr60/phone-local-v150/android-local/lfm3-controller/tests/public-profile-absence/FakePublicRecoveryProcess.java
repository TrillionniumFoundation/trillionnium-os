package org.trillionnium.hepta.local;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;
import org.trillionnium.hepta.background.PublicProfileAbsenceRecovery;
import org.trillionnium.hepta.background.PublicProfileAbsenceHostTest;

/** Explicit host transport only; no su, Android process, Binder call or device connection. */
final class FakePublicRecoveryProcess extends Process {
    static int calls,exit,destroyed;
    static boolean badNonce,timeout,readFailure,cancelled;
    static String suffix;
    static Runnable afterReply;
    static PublicProfileAbsenceRecovery.Request lastRequest;
    final byte[] output;
    static void reset(){calls=exit=destroyed=0;badNonce=timeout=readFailure=cancelled=false;suffix="";afterReply=null;lastRequest=null;}
    static Process start(String command)throws Exception{
        calls++;String marker=" --request '";int at=command.indexOf(marker);
        if(at<0||!command.endsWith("'"))throw new IOException("synthetic command framing");
        PublicProfileAbsenceRecovery.Request r=PublicProfileAbsenceRecovery.fromWire(command.substring(at+marker.length(),command.length()-1));lastRequest=r;
        JSONObject proof=PublicProfileAbsenceHostTest.proof(r);
        if(badNonce)proof.put("request_id","99999999-9999-9999-9999-999999999999");
        if(exit!=0)proof=new JSONObject().put("schema",PublicProfileAbsenceRecovery.SCHEMA).put("request_id",r.requestId)
                .put("cleanup_known",false).put("error","PUBLIC_RECOVERY_SYNTHETIC_FAILURE");
        android.os.SystemClock.now=r.started+4025;if(afterReply!=null)afterReply.run();
        return new FakePublicRecoveryProcess((proof.toString()+"\n"+suffix).getBytes(StandardCharsets.UTF_8));
    }
    FakePublicRecoveryProcess(byte[] output){this.output=output;}
    public InputStream getInputStream(){if(readFailure)return new InputStream(){public int read()throws IOException{throw new IOException("synthetic EOF unavailable");}};return new ByteArrayInputStream(output);}
    public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
    public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
    public int waitFor(){return exit;}
    public boolean waitFor(long time,TimeUnit unit){return !timeout;}
    public int exitValue(){return exit;}
    public void destroy(){destroyed++;}
}
