"""Actual Activity+State/Codec/Store, real files and separate JVM restarts; Android/socket are fixtures."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from tools.tests.test_owner_open_android_shell_state import STUBS, ACTIVITY

HARNESS = r'''
import android.os.Bundle;
import android.widget.EditText;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import java.security.MessageDigest;
import org.trillionnium.owneropen.*;
public final class DurableActivityHarness {
 static void require(boolean b,String m){if(!b)throw new AssertionError(m);}
 static Object field(Object a,String n)throws Exception{Field f=a.getClass().getDeclaredField(n);f.setAccessible(true);return f.get(a);}
 static void set(Object a,String n,Object v)throws Exception{Field f=a.getClass().getDeclaredField(n);f.setAccessible(true);f.set(a,v);}
 static void call(Object a,String n)throws Exception{Method m=a.getClass().getDeclaredMethod(n);m.setAccessible(true);m.invoke(a);}
 static void create(Object a,Bundle b)throws Exception{Method m=a.getClass().getDeclaredMethod("onCreate",Bundle.class);m.setAccessible(true);m.invoke(a,b);
  waitFor(()->{try{return (Boolean)field(a,"identityReady")||field(a,"storageFailure")!=null;}catch(Exception e){throw new RuntimeException(e);}},"identity worker did not settle");}
 static void waitFor(java.util.function.BooleanSupplier condition,String failure)throws Exception {
  long until=System.nanoTime()+3_000_000_000L;while(!condition.getAsBoolean()&&System.nanoTime()<until)Thread.sleep(5);
  require(condition.getAsBoolean(),failure+": "+OwnerOpenClient.events);
 }
 static boolean event(String prefix){synchronized(OwnerOpenClient.events){return OwnerOpenClient.events.stream().anyMatch(s->s.startsWith(prefix));}}
 static void send(OwnerOpenShellActivity a)throws Exception{((EditText)field(a,"prompt")).setText("private prompt must not be persisted");call(a,"sendPrompt");}
 static OwnerOpenClientState disk(Path directory)throws Exception{return new OwnerOpenClientStateStore(directory).load().orElseThrow().state;}
 static String receipt(OwnerOpenClientState state) {
  return OwnerOpenClient.envelope("turn.accepted",state.sessionId,state.taskId,state.turnId,
   "{\"status\":\"accepted\",\"turn_request_sha256\":"+OwnerOpenFrame.quote(state.turnRequestSha256)+"}");
 }
 public static void main(String[] args)throws Exception {
  String scenario=args[0];Path directory=Path.of(System.getProperty("owneropen.test.files"));
  Path bin=directory.resolve("owner-client-session-v1.bin");
  OwnerOpenShellActivity a=new OwnerOpenShellActivity();
  try {
   if(scenario.startsWith("identity-stall")) {
    android.app.Activity.blockIdentityDirectory=true;
    Method initialize=a.getClass().getDeclaredMethod("onCreate",Bundle.class);initialize.setAccessible(true);
    long start=System.nanoTime();initialize.invoke(a,(Object)null);
    require(System.nanoTime()-start<1_000_000_000L,"identity storage blocked UI construction");
    require(field(a,"prompt")!=null&&field(a,"transcript")!=null&&field(a,"client")!=null,"emergency UI/client not constructed");
    require(android.app.Activity.identityEntered.await(2,java.util.concurrent.TimeUnit.SECONDS),"normal worker not held in directory lookup");
    // A stale cached/Bundle-like turn cannot queue Cancel while identity initialization is withheld.
    set(a,"turnId","turn-33333333-3333-4333-8333-333333333333");
    send(a);call(a,"reconnect");call(a,"cancelTurn");call(a,"inspectTurn");Thread.sleep(100);
    require(OwnerOpenClient.events.isEmpty(),"loading identity admitted normal dispatch or stale control");
    call(a,"confirmEmergencyStop");require(android.app.AlertDialog.positive!=null,"stop confirmation unavailable during identity stall");
    android.app.AlertDialog.positive.onClick(null,1);waitFor(()->event("stop:"),"stop queued behind identity storage");
    if(scenario.equals("identity-stall-destroy"))call(a,"onDestroy");
    android.app.Activity.identityRelease.countDown();Thread.sleep(150);
    require(!event("connect")&&!event("start:"),"late identity completion connected or dispatched");
    if(scenario.equals("identity-stall-destroy"))require(!(Boolean)field(a,"identityReady"),"destroyed Activity published late identity readiness");
    return;
   }
   if(scenario.equals("bundle-without-disk")) {
    Bundle state=new Bundle();state.putString("owneropen.session","session-11111111-1111-4111-8111-111111111111");
    create(a,state);send(a);Thread.sleep(100);
    require(field(a,"storageFailure")!=null&&!Files.exists(bin)&&OwnerOpenClient.events.isEmpty(),"absent disk replaced saved semantic identity");return;
   }
   create(a,null);
   if(scenario.equals("commit-restart")) {
    Thread.sleep(100);require(OwnerOpenClient.events.isEmpty(),"unknown commit restart automatically connected");
    byte[] before=Files.readAllBytes(bin);send(a);call(a,"inspectTurn");Thread.sleep(100);send(a);Thread.sleep(100);
    require(!event("start:")&&Arrays.equals(before,Files.readAllBytes(bin)),"unknown commit recreation dispatched or reset identity");return;
   }
   if(scenario.equals("restart-inspect")) {
    Thread.sleep(100);require(OwnerOpenClient.events.isEmpty(),"actual process restart automatically connected");
    OwnerOpenClientState original=disk(directory);String saved=Files.readString(directory.resolve("fixture-expected-identity"));
    require(saved.equals(original.sessionId+"\n"+original.taskId+"\n"+original.turnId+"\n"+original.turnRequestSha256),"process restart changed durable identity");
    require(original.sessionId.equals(field(a,"sessionId"))&&original.taskId.equals(field(a,"taskId"))&&original.turnId.equals(field(a,"turnId")),"Activity did not restore actual files");
    byte[] before=Files.readAllBytes(bin);send(a);a.onFrame(receipt(original));send(a);Thread.sleep(100);
    require(!event("start:")&&Arrays.equals(before,Files.readAllBytes(bin)),"late acceptance or restart reselected live turn");
    // A mechanically valid unsolicited readback cannot release the explicit-request gate.
    ((OwnerOpenClient)field(a,"client")).inspectTurn(original.sessionId,original.taskId,original.turnId,original.turnRequestSha256,0);
    send(a);Thread.sleep(100);require(!event("start:"),"unsolicited inspection released Send");
    OwnerOpenClient.events.clear();call(a,"inspectTurn");waitFor(()->event("inspect:"),"explicit same-turn inspect missing");
    waitFor(()->{try{return !(Boolean)field(a,"readbackRequired");}catch(Exception e){throw new RuntimeException(e);}},"full terminal readback did not reconcile identity");
    require(!event("start:"),"readback automatically submitted a new effect");
    send(a);waitFor(()->event("start:"),"new explicit Send after terminal evidence missing");
    require(!original.turnId.equals(disk(directory).turnId),"new explicit Send reused original semantic turn");return;
   }
   require(OwnerOpenClient.events.isEmpty(),"identity initialization auto-connected");
   call(a,"reconnect");waitFor(()->event("connect"),"explicit fixture reconnect missing");OwnerOpenClient.events.clear();
   if(scenario.startsWith("commit-")) {
    set(a,"identityStore",StoreFaultFactory.create(directory,scenario.substring(7)));
    send(a);waitFor(()->{try{return field(a,"storageFailure")!=null;}catch(Exception e){throw new RuntimeException(e);}},"commit failure was not fenced");
    send(a);call(a,"inspectTurn");Thread.sleep(100);require(!event("start:"),"ambiguous commit authorized effect write");
    require(Files.exists(bin),"commit fixture erased last identity");return;
   }
   if(scenario.equals("record-disappears")) {
    Files.delete(bin);send(a);Thread.sleep(100);
    require(field(a,"storageFailure")!=null&&!Files.exists(bin)&&!event("start:"),"missing committed identity silently recreated");return;
   }
   if(scenario.equals("bad-accepted"))OwnerOpenClient.wrongAccepted=true;
   send(a);waitFor(()->event("start:"),"first explicit dispatch missing");
   OwnerOpenClientState original=disk(directory);byte[] before=Files.readAllBytes(bin);
   require(!new String(before,java.nio.charset.StandardCharsets.ISO_8859_1).contains("private prompt"),"state retained user input");
   if(scenario.equals("create-start")) {
    Files.writeString(directory.resolve("fixture-expected-identity"),original.sessionId+"\n"+original.taskId+"\n"+original.turnId+"\n"+original.turnRequestSha256);return;
   }
   if(scenario.equals("late-reader-publication")) {
    call(a,"inspectTurn");waitFor(()->{try{return !(Boolean)field(a,"readbackRequired");}catch(Exception e){throw new RuntimeException(e);}},"first terminal inspection did not complete");
    OwnerOpenClient.deferInspectResponse=true;OwnerOpenClient.events.clear();
    call(a,"inspectTurn");waitFor(()->OwnerOpenClient.deferredInspection!=null,"I0 explicit request missing");
    String oldReply=OwnerOpenClient.deferredInspection;
    java.util.concurrent.CountDownLatch parsed=new java.util.concurrent.CountDownLatch(1),release=new java.util.concurrent.CountDownLatch(1);
    java.util.concurrent.atomic.AtomicReference<Throwable> readerFailure=new java.util.concurrent.atomic.AtomicReference<>();
    set(a,"evidencePublicationProbe",(Runnable)()->{
      if(!Thread.currentThread().getName().equals("fixture-single-reader"))return;
      parsed.countDown();try{release.await();}catch(InterruptedException e){throw new RuntimeException(e);}
    });
    Thread reader=new Thread(()->{try{a.onFrame(oldReply);}catch(Throwable e){readerFailure.set(e);}},"fixture-single-reader");reader.start();
    try {
      require(parsed.await(2,java.util.concurrent.TimeUnit.SECONDS),"old reader never parsed I0");
      send(a);waitFor(()->event("start:"),"S1 normal worker did not dispatch after S0 terminal");
      OwnerOpenClientState newer=disk(directory);byte[] newerBytes=Files.readAllBytes(bin);
      require(!original.turnId.equals(newer.turnId)&&(Boolean)field(a,"readbackRequired"),"S1 did not own a held durable identity");
      release.countDown();reader.join(3000);
      require(!reader.isAlive()&&readerFailure.get()==null,"old reader failed or blocked");
      require((Boolean)field(a,"readbackRequired"),"old matched I0 cleared new S1 hold");
      send(a);Thread.sleep(150);
      require(OwnerOpenClient.events.stream().filter(e->e.startsWith("start:")).count()==1
        &&Arrays.equals(newerBytes,Files.readAllBytes(bin)),"late reader admitted S2 or replaced S1 identity");
    } finally {release.countDown();reader.join(3000);set(a,"evidencePublicationProbe",null);}
    return;
   }
   if(scenario.equals("queued-cancel-drift")||scenario.equals("queued-inspect-drift")) {
    java.util.concurrent.CountDownLatch entered=new java.util.concurrent.CountDownLatch(1),release=new java.util.concurrent.CountDownLatch(1);
    java.util.concurrent.ExecutorService worker=(java.util.concurrent.ExecutorService)field(a,"operations");
    worker.execute(()->{entered.countDown();try{release.await();}catch(InterruptedException e){throw new RuntimeException(e);}});
    require(entered.await(2,java.util.concurrent.TimeUnit.SECONDS),"queue gate did not enter");
    OwnerOpenClient.events.clear();call(a,scenario.equals("queued-cancel-drift")?"cancelTurn":"inspectTurn");
    OwnerOpenClientStateCodec.Snapshot current=new OwnerOpenClientStateStore(directory).load().orElseThrow();
    OwnerOpenClientStateCodec.Snapshot changed=new OwnerOpenClientStateStore(directory).compareAndSet(current.revision,
      current.state.selectBoundTurnForExplicitSend("turn-44444444-4444-4444-8444-444444444444","b".repeat(64)));
    set(a,"identitySnapshot",changed);set(a,"turnId",changed.state.turnId);
    release.countDown();Thread.sleep(150);
    require(!event("cancel:")&&!event("inspect:")&&!event("start:"),"queued control silently substituted changed target");
    require(disk(directory).turnId.equals(changed.state.turnId),"rejected control reverted newer durable identity");return;
   }
   if(scenario.equals("accepted-still-active")||scenario.equals("bad-accepted")) {
    Thread.sleep(100);OwnerOpenClient.events.clear();send(a);Thread.sleep(100);
    require(!event("start:")&&Arrays.equals(before,Files.readAllBytes(bin)),"acceptance admitted second effect or replaced original turn");
    if(scenario.equals("bad-accepted"))require(field(a,"evidenceFailure")!=null,"conflicting digest was not held");
    else require((Boolean)field(a,"readbackRequired"),"admission was mistaken for terminal outcome");return;
   }
   if(scenario.equals("paginated-inspect")||scenario.equals("not-found-inspect")||scenario.startsWith("unknown-terminal-")) {
    if(scenario.equals("paginated-inspect"))OwnerOpenClient.moreInspection=true;
    else if(scenario.equals("not-found-inspect"))Files.delete(directory.resolve("fixture-host-accepted-"+original.turnId));
    else OwnerOpenClient.terminalStatus=scenario.substring("unknown-terminal-".length());
    OwnerOpenClient.events.clear();call(a,"inspectTurn");waitFor(()->event("inspect:"),"inspect missing");Thread.sleep(100);send(a);Thread.sleep(100);
    require(!event("start:")&&(Boolean)field(a,"readbackRequired")&&Arrays.equals(before,Files.readAllBytes(bin)),"incomplete/notfound evidence authorized a new effect");return;
   }
   Bundle saved=new Bundle();Method save=a.getClass().getDeclaredMethod("onSaveInstanceState",Bundle.class);save.setAccessible(true);save.invoke(a,saved);
   call(a,"onDestroy");OwnerOpenClient.events.clear();
   if(scenario.equals("stale-bundle"))saved.putString("owneropen.turn","turn-44444444-4444-4444-8444-444444444444");
   if(scenario.equals("corrupt")){byte[] value=before.clone();value[22]^=1;Files.write(bin,value);}
   if(scenario.equals("pending"))Files.write(directory.resolve("owner-client-session-v1.pending"),new byte[]{7});
   if(scenario.equals("schema1")) {
    byte[] value=before.clone();value[11]=1;byte[] checksum=MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(value,value.length-32));
    System.arraycopy(checksum,0,value,value.length-32,32);Files.write(bin,value);
   }
   byte[] damaged=Files.readAllBytes(bin);
   OwnerOpenShellActivity recovered=new OwnerOpenShellActivity();
   try {
    create(recovered,scenario.equals("stale-bundle")?saved:null);Thread.sleep(100);
    require(OwnerOpenClient.events.isEmpty(),"recreation automatically connected or retried");
    if(scenario.equals("stale-bundle"))require(original.turnId.equals(field(recovered,"turnId")),"stale Bundle replaced committed identity");
    else require(field(recovered,"storageFailure")!=null,"damaged/pending/unknown version became empty state");
    send(recovered);Thread.sleep(100);require(!event("start:")&&Arrays.equals(damaged,Files.readAllBytes(bin)),"HOLD state admitted effect or repaired evidence");
    if(scenario.equals("pending"))require(Files.readAllBytes(directory.resolve("owner-client-session-v1.pending"))[0]==7,"pending residue silently repaired");
   } finally {call(recovered,"onDestroy");}
  } finally {call(a,"onDestroy");}
  System.out.println(scenario+" PASS; host Activity mechanics and real files only");
 }
}
'''


class AndroidDurableIdentityBehaviorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('javac') or not shutil.which('java'):
            raise AssertionError('JDK required for real Activity behavior tests')
        cls.temporary = tempfile.TemporaryDirectory()
        cls.folder = Path(cls.temporary.name)
        for name, content in STUBS.items():
            path = cls.folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (cls.folder / 'DurableActivityHarness.java').write_text(HARNESS)
        cls.classes = cls.folder / 'classes'
        sources = [str(ACTIVITY), *[str(ACTIVITY.with_name(name + '.java')) for name in
            ('OwnerOpenFrame', 'OwnerOpenTurnEvidence', 'OwnerOpenClientState', 'OwnerOpenClientStateCodec', 'OwnerOpenClientStateStore')],
            *map(str, cls.folder.rglob('*.java'))]
        result = subprocess.run(['javac', '-Xlint:all', '-Werror', '-d', str(cls.classes), *sources],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def scenario(self, scenario, directory):
        result = subprocess.run(['java', '-Downeropen.test.files=' + str(directory), '-cp', str(self.classes),
                                 'DurableActivityHarness', scenario], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_identity_storage_stall_does_not_delay_ui_stop_or_late_destroy_fence(self):
        for scenario in ('identity-stall', 'identity-stall-destroy'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                self.scenario(scenario, directory)

    def test_actual_separate_process_restore_and_explicit_same_turn_inspect(self):
        with tempfile.TemporaryDirectory() as directory:
            self.scenario('create-start', directory)
            self.scenario('restart-inspect', directory)

    def test_accepted_running_or_conflicting_receipt_cannot_replace_original_turn(self):
        for scenario in ('accepted-still-active', 'bad-accepted'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                self.scenario(scenario, directory)

    def test_incomplete_or_absent_inspection_keeps_send_held(self):
        for scenario in ('paginated-inspect', 'not-found-inspect', 'unknown-terminal-unknown_after_disconnect', 'unknown-terminal-unknown_after_journal_failure'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                self.scenario(scenario, directory)

    def test_real_pre_post_rename_and_unknown_namespace_outcomes_never_start(self):
        for cut in ('pre-rename', 'move-before', 'move-after', 'post-rename'):
            with self.subTest(cut=cut), tempfile.TemporaryDirectory() as directory:
                self.scenario('commit-' + cut, directory)
                self.scenario('commit-restart', directory)

    def test_corruption_pending_and_prior_schema_survive_without_new_identity(self):
        for scenario in ('corrupt', 'pending', 'schema1'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                self.scenario(scenario, directory)

    def test_stale_bundle_cannot_replace_committed_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            self.scenario('stale-bundle', directory)

    def test_one_old_reader_cannot_release_new_turn_hold_after_normal_worker_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            self.scenario('late-reader-publication', directory)

    def test_queued_cancel_and_inspect_reject_changed_durable_targets(self):
        for scenario in ('queued-cancel-drift', 'queued-inspect-drift'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                self.scenario(scenario, directory)

    def test_missing_committed_identity_is_not_reinitialized(self):
        for scenario in ('record-disappears', 'bundle-without-disk'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                self.scenario(scenario, directory)


if __name__ == '__main__':
    unittest.main()
