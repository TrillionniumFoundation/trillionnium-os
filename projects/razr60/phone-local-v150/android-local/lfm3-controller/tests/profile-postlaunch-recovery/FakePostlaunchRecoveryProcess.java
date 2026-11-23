package org.trillionnium.hepta.local;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.json.*;
import org.trillionnium.hepta.background.*;
/** Host fixture only. No ProcessBuilder, Android, root command or device operation is executed. */
final class FakePostlaunchRecoveryProcess extends Process {
 static boolean outputReadFailure,timeout,bootChange,expire;static int destroyed;
 static int calls,exit;static boolean badNonce,cancelAfterReply,cancelled;static String suffix;static Path changeJournal;static Runnable afterReply;
 final byte[] output;
 static void reset(){outputReadFailure=false;timeout=false;bootChange=false;expire=false;destroyed=0;calls=0;exit=0;badNonce=false;cancelAfterReply=false;cancelled=false;suffix="";changeJournal=null;afterReply=null;android.system.Os.failFsyncPath=null;android.system.Os.corruptRecoveryArchiveOnSync=false;}
 static Process start(String command)throws Exception{
  calls++;String marker=" --request '";int at=command.indexOf(marker);
  if(at<0||!command.endsWith("'"))throw new IOException("fixture command framing");
  ProfilePostlaunchRecovery.Request r=ProfilePostlaunchRecovery.fromWire(command.substring(at+marker.length(),command.length()-1));
  JSONObject value=PostlaunchRecoveryProofFixture.reply(r);
  if(badNonce)value.put("request_id","99999999-9999-9999-9999-999999999999");
  android.os.SystemClock.now=expire?r.deadline:r.started+9;if(bootChange)android.provider.Settings.Global.boot++;
  if(changeJournal!=null){JSONObject changed=new JSONObject(new String(Files.readAllBytes(changeJournal),StandardCharsets.UTF_8));changed.put("owner_sha256",String.join("",java.util.Collections.nCopies(64,"f")));Files.write(changeJournal,changed.toString().getBytes(StandardCharsets.UTF_8));}
  if(cancelAfterReply)cancelled=true;
  if(afterReply!=null)afterReply.run();
  return new FakePostlaunchRecoveryProcess((value.toString()+"\n"+suffix).getBytes(StandardCharsets.UTF_8));
 }
 FakePostlaunchRecoveryProcess(byte[] output){this.output=output;}
 public InputStream getInputStream(){if(!outputReadFailure)return new ByteArrayInputStream(output);return new InputStream(){int at;public int read()throws IOException{if(at==output.length)throw new IOException("synthetic missing EOF after complete bytes");return output[at++]&255;}};}
 public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
 public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
 public int waitFor(){return exit;}
 public boolean waitFor(long t,TimeUnit u){return !timeout;}
 public int exitValue(){return exit;}
 public void destroy(){destroyed++;}
}
