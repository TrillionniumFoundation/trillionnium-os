package org.trillionnium.hepta.local;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import android.net.LocalSocket;
import android.os.SystemClock;
import org.json.*;
public final class ProfilePostlaunchRecoverySessionHostTest {
 static int cases,assertions;
 interface Work{void run()throws Exception;}
 static void check(boolean b){assertions++;if(!b)throw new AssertionError();}
 static void reject(Work w)throws Exception{try{w.run();}catch(Exception expected){assertions++;return;}throw new AssertionError("unexpected recovery");}
 static void test(Work w)throws Exception{
  LocalSocket.reset();LocalSocket.missing=true;SystemClock.now=1000000;android.provider.Settings.Global.boot=10;android.system.Os.failUnlink=false;
  FakePostlaunchRecoveryProcess.reset();w.run();cases++;
 }
 static void ready(ProfileSessionHostTest.Env e)throws Exception{
  e.active();BackgroundSessionHostTest.field(e.session,"retired",true);BackgroundSessionHostTest.field(e.session,"state","CLEANUP_UNKNOWN");
  e.context.displays.displays.clear();e.journal(true);
  MobiMindPrivateFiles.directory(e.directory.resolve("control-tasks").toFile(),true);
  MobiMindPrivateFiles.directory(e.directory.resolve("control-tasks").resolve(e.session.taskId).toFile(),true);
  MobiMindPrivateFiles.writeNew(e.directory.resolve("fake.apk").toFile(),new byte[]{1});
  SystemClock.now=e.session.expiresElapsed+2001;
 }
 static BackgroundSession.ReconciliationCheck idle(){return ()->{if(FakePostlaunchRecoveryProcess.cancelled)throw new java.io.IOException("original owner changed");};}
 static long commits(ProfileSessionHostTest.Env e)throws Exception{try(java.util.stream.Stream<Path> p=Files.walk(e.directory)){return p.filter(x->x.getFileName().toString().startsWith("background-postlaunch-recovery-")&&x.toString().endsWith(".json")&&!x.toString().endsWith(".journal.json")).count();}}
 public static void main(String[] args)throws Exception{
  android.os.Looper.worker=true; // Explicit worker-thread Android boundary fixture.
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);byte[] old=Files.readAllBytes(e.directory.resolve(BackgroundSession.JOURNAL));
   BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context,idle());
   check(c.known&&!e.journalPresent()&&FakePostlaunchRecoveryProcess.calls==1);check(!c.evidence.getBoolean("broker_released"));
   check(c.evidence.isNull("broker_response"));check(commits(e)==1);
   Path saved=Paths.get(c.evidence.getString("postlaunch_receipt_path"));JSONObject commit=new JSONObject(new String(Files.readAllBytes(saved),StandardCharsets.UTF_8));
   check(Arrays.equals(old,Files.readAllBytes(saved.resolveSibling(commit.getString("journal_archive")))));
   check(commit.getJSONObject("transport").getBoolean("owned_process_exit_observed"));
   reject(()->e.session.acceptReconciliation(new JSONObject(c.evidence.toString())));
   reject(()->e.session.acceptReconciliation(new BackgroundSession.Cleanup(true,c.evidence)));
   e.session.acceptReconciliation(c);check(e.session.released());
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);FakePostlaunchRecoveryProcess.exit=70;reject(()->BackgroundSession.reconcile(e.context,idle()));check(e.journalPresent()&&commits(e)==0);
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);FakePostlaunchRecoveryProcess.suffix="{}";reject(()->BackgroundSession.reconcile(e.context,idle()));check(e.journalPresent()&&commits(e)==0);
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);FakePostlaunchRecoveryProcess.badNonce=true;reject(()->BackgroundSession.reconcile(e.context,idle()));check(e.journalPresent()&&commits(e)==0);
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);FakePostlaunchRecoveryProcess.cancelAfterReply=true;reject(()->BackgroundSession.reconcile(e.context,idle()));check(e.journalPresent()&&commits(e)==0);
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);FakePostlaunchRecoveryProcess.changeJournal=e.directory.resolve(BackgroundSession.JOURNAL);reject(()->BackgroundSession.reconcile(e.context,idle()));
   check(e.journalPresent()&&!e.session.released());check(commits(e)==1);
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);android.system.Os.failUnlink=true;reject(()->BackgroundSession.reconcile(e.context,idle()));
   check(e.journalPresent()&&!e.session.released());check(commits(e)==1);
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);Files.delete(e.directory.resolve("control-tasks").resolve(e.session.taskId));
   reject(()->BackgroundSession.reconcile(e.context,idle()));check(e.journalPresent()&&!e.session.released());
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);BackgroundSession.Cleanup c=BackgroundSession.reconcile(e.context,idle());
   Files.write(Paths.get(c.evidence.getString("postlaunch_receipt_path")),new byte[]{1});
   reject(()->e.session.acceptReconciliation(c));check(!e.session.released());
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);check(!BackgroundSession.reconcile(e.context).known);check(FakePostlaunchRecoveryProcess.calls==0&&e.journalPresent());
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   e.active();e.journal(true);e.context.displays.displays.clear();SystemClock.now=e.session.expiresElapsed+3000;
   check(!BackgroundSession.reconcile(e.context,idle()).known);check(FakePostlaunchRecoveryProcess.calls==0&&e.journalPresent());
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);android.system.Os.failFsyncPath=e.directory.resolve("control-tasks").resolve(e.session.taskId).toString();
   reject(()->BackgroundSession.reconcile(e.context,idle()));check(e.journalPresent()&&!e.session.released());
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);android.system.Os.corruptRecoveryArchiveOnSync=true;
   reject(()->BackgroundSession.reconcile(e.context,idle()));check(e.journalPresent()&&!e.session.released());
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);FakePostlaunchRecoveryProcess.afterReply=()->e.context.displays.displays.put(9,new android.view.Display(9,e.session.displayName));
   reject(()->BackgroundSession.reconcile(e.context,idle()));check(e.journalPresent()&&!e.session.released());check(e.context.displays.getDisplay(9)!=null);
  }});
  for(final String bad:Arrays.asList("missing_eof","timeout","boot_changed","deadline"))test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);FakePostlaunchRecoveryProcess.outputReadFailure=bad.equals("missing_eof");FakePostlaunchRecoveryProcess.timeout=bad.equals("timeout");
   FakePostlaunchRecoveryProcess.bootChange=bad.equals("boot_changed");FakePostlaunchRecoveryProcess.expire=bad.equals("deadline");
   reject(()->BackgroundSession.reconcile(e.context,idle()));check(e.journalPresent()&&commits(e)==0&&!e.session.released());
   check(FakePostlaunchRecoveryProcess.destroyed==(bad.equals("timeout")?1:0));
  }});
  test(()->{try(ProfileSessionHostTest.Env e=new ProfileSessionHostTest.Env()){
   ready(e);FakePostlaunchRecoveryProcess.afterReply=()->e.context.displays.displays.put(7,new android.view.Display(7,"other-display"));
   reject(()->BackgroundSession.reconcile(e.context,idle()));check(e.journalPresent()&&!e.session.released());check(e.context.displays.getDisplay(7)!=null);
  }});
  System.out.println(new JSONObject().put("schema","hepta.profile-recovery-client-host-tests.v1").put("passed",true)
   .put("cases",cases).put("assertions",assertions).put("phone_contacted",false)
   .put("actual_background_session",true).put("actual_client_except_owned_process_factory",true)
   .put("root_process_android_io_synthetic",true).toString());
 }
}
