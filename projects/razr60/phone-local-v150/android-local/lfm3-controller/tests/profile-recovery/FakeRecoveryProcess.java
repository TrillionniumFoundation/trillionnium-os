package org.trillionnium.hepta.local;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.json.*;
import org.trillionnium.hepta.background.*;
/** Host fixture only. No ProcessBuilder, Android, root command or device operation is executed. */
final class FakeRecoveryProcess extends Process {
 static int calls,exit;static boolean badNonce,cancelAfterReply,cancelled;static String suffix;static Path changeJournal;static Runnable afterReply;
 final byte[] output;
 static void reset(){calls=0;exit=0;badNonce=false;cancelAfterReply=false;cancelled=false;suffix="";changeJournal=null;afterReply=null;android.system.Os.failFsyncPath=null;android.system.Os.corruptRecoveryArchiveOnSync=false;}
 static Process start(String command)throws Exception{
  calls++;String marker=" --request '";int at=command.indexOf(marker);
  if(at<0||!command.endsWith("'"))throw new IOException("fixture command framing");
  ProfilePrelaunchRecovery.Request r=ProfilePrelaunchRecovery.fromWire(command.substring(at+marker.length(),command.length()-1));
  JSONObject value=RecoveryProofFixture.reply(r);
  if(badNonce)value.put("request_id","99999999-9999-9999-9999-999999999999");
  android.os.SystemClock.now=r.started+9;
  if(changeJournal!=null){JSONObject changed=new JSONObject(new String(Files.readAllBytes(changeJournal),StandardCharsets.UTF_8));changed.put("owner_sha256",String.join("",java.util.Collections.nCopies(64,"f")));Files.write(changeJournal,changed.toString().getBytes(StandardCharsets.UTF_8));}
  if(cancelAfterReply)cancelled=true;
  if(afterReply!=null)afterReply.run();
  return new FakeRecoveryProcess((value.toString()+"\n"+suffix).getBytes(StandardCharsets.UTF_8));
 }
 FakeRecoveryProcess(byte[] output){this.output=output;}
 public InputStream getInputStream(){return new ByteArrayInputStream(output);}
 public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
 public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
 public int waitFor(){return exit;}
 public boolean waitFor(long t,TimeUnit u){return true;}
 public int exitValue(){return exit;}
 public void destroy(){throw new AssertionError("unexpected fixture checker destroy");}
}
