"""Execute the production Java state/codec/store against real host private files.

These are source behavior tests, not Android filesystem, phone or power-loss evidence.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'android-integration/working-tree/vendor/trillionnium/owner-open/client/src/org/trillionnium/owneropen'

HARNESS = r'''
package org.trillionnium.owneropen;
import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import org.trillionnium.owneropen.OwnerOpenClientState.Cursor;
import org.trillionnium.owneropen.OwnerOpenClientState.CursorDomain;
import org.trillionnium.owneropen.OwnerOpenClientStateCodec.Snapshot;
import org.trillionnium.owneropen.OwnerOpenClientStateStore.Failure;

public final class ClientStateStoreHarness {
 static final String SESSION="session-11111111-1111-4111-8111-111111111111";
 static final String TASK="task-22222222-2222-4222-8222-222222222222";
 static final String TURN="turn-33333333-3333-4333-8333-333333333333";
 static final String TURN2="turn-44444444-4444-4444-8444-444444444444";
 static final String EPOCH="a".repeat(64), EPOCH2="b".repeat(64);
 static final String BIN="owner-client-session-v1.bin", PENDING="owner-client-session-v1.pending", LOCK="owner-client-session-v1.lock";
 interface Action { void run() throws Exception; }
 static void require(boolean value,String message) { if(!value) throw new AssertionError(message); }
 static void rejectIllegal(Action action) throws Exception {
  try {action.run();throw new AssertionError("accepted invalid state");}
  catch(IllegalArgumentException expected){}
 }
 static void corrupt(Action action) throws Exception {
  try {action.run();throw new AssertionError("accepted corrupt record");}
  catch(OwnerOpenClientStateCodec.CorruptStateException expected){}
 }
 static OwnerOpenClientStateStore.StoreException failure(Failure expected,Action action) throws Exception {
  try {action.run();throw new AssertionError("accepted unsafe store operation");}
  catch(OwnerOpenClientStateStore.StoreException error) {
   require(error.failure==expected,"wrong failure: "+error.failure+" expected "+expected);return error;
  }
 }
 static OwnerOpenClientState identity() { return OwnerOpenClientState.identity(SESSION,TASK,TURN); }
 static OwnerOpenClientState cursored() {
  OwnerOpenClientState state=identity();
  long[] cursors={27,13,4};int index=0;
  for(CursorDomain domain:CursorDomain.values()) state=state.withObservedCursor(new Cursor(domain,EPOCH,cursors[index++]));
  return state;
 }
 static byte[] encoded() throws Exception {return OwnerOpenClientStateCodec.encode(new Snapshot(2,cursored()));}
 static byte[] rehash(byte[] value) throws Exception {
  int size=value.length-32;byte[] digest=MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(value,size));
  System.arraycopy(digest,0,value,size,32);return value;
 }
 static void same(OwnerOpenClientState expected,OwnerOpenClientState actual) {
  require(expected.sessionId.equals(actual.sessionId)&&expected.taskId.equals(actual.taskId)
    && Objects.equals(expected.turnId,actual.turnId)
    && Objects.equals(expected.turnRequestSha256,actual.turnRequestSha256),"semantic identity changed");
  require(expected.cursors.size()==actual.cursors.size(),"cursor count changed");
  for(CursorDomain domain:expected.cursors.keySet()) {
   Cursor a=expected.cursors.get(domain),b=actual.cursors.get(domain);
   require(a.inclusiveCursor==b.inclusiveCursor&&a.producerEpochSha256.equals(b.producerEpochSha256),"cursor identity changed");
  }
 }
 static int countOffset(byte[] value) {
  int offset=20;offset+=1+Byte.toUnsignedInt(value[offset]);offset+=1+Byte.toUnsignedInt(value[offset]);
  int selected=Byte.toUnsignedInt(value[offset++]);if(selected==1)offset+=1+Byte.toUnsignedInt(value[offset]);
  int bound=Byte.toUnsignedInt(value[offset++]);if(bound==1)offset+=1+Byte.toUnsignedInt(value[offset]);
  return offset;
 }
 static void roundtrip() throws Exception {
  byte[] value=encoded();require(value.length<=512,"unbounded encoding");
  Snapshot restored=OwnerOpenClientStateCodec.decode(value);require(restored.revision==2,"revision lost");same(cursored(),restored.state);
  require(Arrays.equals(value,OwnerOpenClientStateCodec.encode(restored)),"noncanonical encoding");
  same(OwnerOpenClientState.identity(SESSION,TASK,null),OwnerOpenClientStateCodec.decode(
    OwnerOpenClientStateCodec.encode(new Snapshot(1,OwnerOpenClientState.identity(SESSION,TASK,null)))).state);
 }
 static void boundDigest() throws Exception {
  OwnerOpenClientState base=OwnerOpenClientState.identity(SESSION,TASK,null);
  OwnerOpenClientState bound=base.selectBoundTurnForExplicitSend(TURN,EPOCH);
  for(CursorDomain domain:CursorDomain.values())bound=bound.withObservedCursor(new Cursor(domain,EPOCH,Long.MAX_VALUE));
  byte[] encoded=OwnerOpenClientStateCodec.encode(new Snapshot(1,bound));
  require(encoded.length<=512,"digest plus all cursors exceeded record bound");
  same(bound,OwnerOpenClientStateCodec.decode(encoded).state);
  rejectIllegal(()->base.selectBoundTurnForExplicitSend(TURN,null));
  rejectIllegal(()->new OwnerOpenClientState(SESSION,TASK,null,EPOCH,Collections.emptyMap()));
  rejectIllegal(()->new OwnerOpenClientState(SESSION,TASK,TURN,"X".repeat(64),Collections.emptyMap()));
  byte[] old=encoded.clone();old[11]=1;corrupt(()->OwnerOpenClientStateCodec.decode(rehash(old)));
 }
 static void codecNegative() throws Exception {
  byte[] good=encoded();
  for(int length=0;length<good.length;length++) {
   final byte[] shortRecord=Arrays.copyOf(good,length);corrupt(()->OwnerOpenClientStateCodec.decode(shortRecord));
  }
  for(int offset=0;offset<good.length;offset++) {
   byte[] changed=good.clone();changed[offset]^=1;corrupt(()->OwnerOpenClientStateCodec.decode(changed));
  }
  corrupt(()->OwnerOpenClientStateCodec.decode(new byte[513]));
  for(int offset:new int[]{0,11,12,20,21,countOffset(good)}) {
   byte[] changed=good.clone();changed[offset]=(byte)0xff;
   corrupt(()->OwnerOpenClientStateCodec.decode(rehash(changed)));
  }
  byte[] badRevision=good.clone();Arrays.fill(badRevision,12,20,(byte)0);corrupt(()->OwnerOpenClientStateCodec.decode(rehash(badRevision)));
  int flag=20;flag+=1+Byte.toUnsignedInt(good[flag]);flag+=1+Byte.toUnsignedInt(good[flag]);
  byte[] badPresence=good.clone();badPresence[flag]=2;corrupt(()->OwnerOpenClientStateCodec.decode(rehash(badPresence)));
  int count=countOffset(good),first=count+1,second=first+1+1+64+8;
  byte[] unknownDomain=good.clone();unknownDomain[first]=3;corrupt(()->OwnerOpenClientStateCodec.decode(rehash(unknownDomain)));
  byte[] duplicate=good.clone();duplicate[second]=duplicate[first];corrupt(()->OwnerOpenClientStateCodec.decode(rehash(duplicate)));
  byte[] negativeCursor=good.clone();negativeCursor[first+1+1+64]=(byte)0x80;corrupt(()->OwnerOpenClientStateCodec.decode(rehash(negativeCursor)));
  byte[] truncatedField=Arrays.copyOf(good,good.length-1);corrupt(()->OwnerOpenClientStateCodec.decode(rehash(truncatedField)));
  byte[] unknownField=new byte[good.length+1];System.arraycopy(good,0,unknownField,0,good.length-32);
  unknownField[good.length-32]=1;corrupt(()->OwnerOpenClientStateCodec.decode(rehash(unknownField)));
 }
 static void identityNegative() throws Exception {
  rejectIllegal(()->OwnerOpenClientState.identity(null,TASK,TURN));
  rejectIllegal(()->OwnerOpenClientState.identity("session-"+"x".repeat(300),TASK,TURN));
  rejectIllegal(()->OwnerOpenClientState.identity(SESSION.toUpperCase(),TASK,TURN));
  rejectIllegal(()->OwnerOpenClientState.identity(SESSION,TASK,"turn-secret-token"));
  rejectIllegal(()->new Cursor(CursorDomain.JOB_RUNTIME_EVENT,EPOCH,-1));
  rejectIllegal(()->new Cursor(CursorDomain.JOB_RUNTIME_EVENT,"not-an-epoch-digest",1));
  Map<CursorDomain,Cursor> mismatch=new EnumMap<>(CursorDomain.class);
  mismatch.put(CursorDomain.JOB_RUNTIME_EVENT,new Cursor(CursorDomain.JOB_JOURNAL_RECORD,EPOCH,0));
  rejectIllegal(()->new OwnerOpenClientState(SESSION,TASK,TURN,mismatch));
  rejectIllegal(()->new OwnerOpenClientState(SESSION,TASK,null,cursored().cursors));
  try {cursored().cursors.clear();throw new AssertionError("mutable read model");}catch(UnsupportedOperationException expected){}
 }
 static void cursorSemantics() throws Exception {
  OwnerOpenClientState state=cursored();
  require(state.cursorForExplicitInspect(CursorDomain.JOB_RUNTIME_EVENT,EPOCH)==13,"runtime/journal mixed");
  require(state.cursorForExplicitInspect(CursorDomain.JOB_JOURNAL_RECORD,EPOCH)==4,"journal/runtime mixed");
  require(state.cursorForExplicitInspect(CursorDomain.TRANSPORT_EVENT,EPOCH)==27,"transport mixed");
  rejectIllegal(()->state.cursorForExplicitInspect(CursorDomain.JOB_RUNTIME_EVENT,EPOCH2));
  rejectIllegal(()->state.withObservedCursor(new Cursor(CursorDomain.JOB_RUNTIME_EVENT,EPOCH,12)));
  rejectIllegal(()->state.withObservedCursor(new Cursor(CursorDomain.JOB_RUNTIME_EVENT,EPOCH2,14)));
  rejectIllegal(()->state.selectTurnForExplicitSend(TURN));
  OwnerOpenClientState selected=state.selectTurnForExplicitSend(TURN2);
  require(selected.cursors.isEmpty(),"new turn reused old cursor namespace");
  require(selected.sessionId.equals(SESSION)&&selected.taskId.equals(TASK),"explicit turn abandoned task");
  OwnerOpenClientState huge=identity().withObservedCursor(new Cursor(CursorDomain.JOB_RUNTIME_EVENT,EPOCH,Long.MAX_VALUE));
  same(huge,OwnerOpenClientStateCodec.decode(OwnerOpenClientStateCodec.encode(new Snapshot(1,huge))).state);
  rejectIllegal(()->huge.withObservedCursor(new Cursor(CursorDomain.JOB_RUNTIME_EVENT,EPOCH,Long.MAX_VALUE+1)));
 }
 static void storeRoundtrip(Path directory) throws Exception {
  OwnerOpenClientStateStore store=new OwnerOpenClientStateStore(directory);require(store.load().isEmpty(),"missing became fabricated state");
  Snapshot initial=store.compareAndSet(0,identity());require(initial.revision==1,"initial revision");
  Snapshot updated=store.compareAndSet(1,cursored());require(updated.revision==2,"commit revision");
  same(cursored(),new OwnerOpenClientStateStore(directory).load().orElseThrow().state);
  require(Files.getPosixFilePermissions(directory.resolve(BIN)).equals(PosixFilePermissions.fromString("rw-------")),"state mode wider than0600");
  require(Files.getPosixFilePermissions(directory.resolve(LOCK)).equals(PosixFilePermissions.fromString("rw-------")),"lock mode wider than0600");
  require(!Files.exists(directory.resolve(PENDING)),"successful commit left ambiguous residue");
 }
 static void staleAndConflict(Path directory) throws Exception {
  OwnerOpenClientStateStore a=new OwnerOpenClientStateStore(directory),b=new OwnerOpenClientStateStore(directory);
  a.compareAndSet(0,identity());a.compareAndSet(1,cursored());byte[] before=Files.readAllBytes(directory.resolve(BIN));
  failure(Failure.STALE_REVISION,()->b.compareAndSet(1,identity()));
  failure(Failure.STATE_CONFLICT,()->a.compareAndSet(2,identity()));
  failure(Failure.STATE_CONFLICT,()->a.compareAndSet(2,OwnerOpenClientState.identity(SESSION,"task-55555555-5555-4555-8555-555555555555",TURN)));
  failure(Failure.STATE_CONFLICT,()->a.compareAndSet(2,new OwnerOpenClientState(SESSION,TASK,TURN,
    Map.of(CursorDomain.JOB_RUNTIME_EVENT,new Cursor(CursorDomain.JOB_RUNTIME_EVENT,EPOCH2,90)))));
  require(Arrays.equals(before,Files.readAllBytes(directory.resolve(BIN))),"conflict mutated committed identity");
  Snapshot selected=a.compareAndSet(2,cursored().selectTurnForExplicitSend(TURN2));require(selected.revision==3,"explicit selected turn revision");
 }
 static void fault(Path directory,boolean afterRename) throws Exception {
  OwnerOpenClientStateStore first=new OwnerOpenClientStateStore(directory);first.compareAndSet(0,identity());
  byte[] before=Files.readAllBytes(directory.resolve(BIN));
  OwnerOpenClientStateStore store=new OwnerOpenClientStateStore(directory,new OwnerOpenClientStateStore.CommitHook(){
   public void afterFileSync() throws IOException {if(!afterRename)throw new IOException("injected post-file-sync failure");}
   public void afterAtomicRename() throws IOException {if(afterRename)throw new IOException("injected post-rename failure");}
  });
  OwnerOpenClientStateStore.StoreException error=failure(Failure.IO_FAILURE,()->store.compareAndSet(1,cursored()));
  require(error.commitMayHaveOccurred==afterRename,"write uncertainty erased");
  if(afterRename) {
   Snapshot readback=new OwnerOpenClientStateStore(directory).load().orElseThrow();same(cursored(),readback.state);require(readback.revision==2,"renamed state lost");
  } else {
   require(Arrays.equals(before,Files.readAllBytes(directory.resolve(BIN))),"pre-rename fault mutated previous commit");
   require(Files.exists(directory.resolve(PENDING)),"ambiguous residue auto-repaired");
   byte[] pending=Files.readAllBytes(directory.resolve(PENDING));
   failure(Failure.PENDING_WRITE,()->new OwnerOpenClientStateStore(directory).load());
   failure(Failure.PENDING_WRITE,()->new OwnerOpenClientStateStore(directory).compareAndSet(1,identity()));
   require(Arrays.equals(pending,Files.readAllBytes(directory.resolve(PENDING))),"blocked load/write deleted or repaired residue");
  }
 }
 static void renameError(Path directory,boolean performed) throws Exception {
  OwnerOpenClientStateStore first=new OwnerOpenClientStateStore(directory);first.compareAndSet(0,identity());
  byte[] before=Files.readAllBytes(directory.resolve(BIN));
  OwnerOpenClientStateStore store=new OwnerOpenClientStateStore(directory,new OwnerOpenClientStateStore.CommitHook(){
   public void afterFileSync(){}
   public void atomicMove(Path pending,Path committed) throws IOException {
    if(performed)Files.move(pending,committed,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
    throw new IOException("injected unknown atomic move outcome");
   }
   public void afterAtomicRename(){throw new AssertionError("move error cannot return success");}
  });
  OwnerOpenClientStateStore.StoreException error=failure(Failure.IO_FAILURE,()->store.compareAndSet(1,cursored()));
  require(error.commitMayHaveOccurred,"rename attempt error claimed no commit");
  if(performed) {
   same(cursored(),new OwnerOpenClientStateStore(directory).load().orElseThrow().state);
  } else {
   require(Arrays.equals(before,Files.readAllBytes(directory.resolve(BIN))),"nonperformed fixture changed commit");
   failure(Failure.PENDING_WRITE,()->new OwnerOpenClientStateStore(directory).load());
  }
 }
 static void corruptFile(Path directory) throws Exception {
  OwnerOpenClientStateStore store=new OwnerOpenClientStateStore(directory);store.compareAndSet(0,identity());
  byte[] bad=Files.readAllBytes(directory.resolve(BIN));bad[22]^=1;Files.write(directory.resolve(BIN),bad);
  failure(Failure.CORRUPT_RECORD,()->store.load());failure(Failure.CORRUPT_RECORD,()->store.compareAndSet(0,identity()));
  require(Arrays.equals(bad,Files.readAllBytes(directory.resolve(BIN))),"corruption was silently reset");
  Files.write(directory.resolve(BIN),new byte[513]);failure(Failure.CORRUPT_RECORD,()->store.load());
 }
 static void symlink(Path directory,String name) throws Exception {
  Path outside=directory.resolve("sentinel");Files.writeString(outside,"untouched");Files.createSymbolicLink(directory.resolve(name),outside);
  OwnerOpenClientStateStore store=new OwnerOpenClientStateStore(directory);
  failure(name.equals(PENDING)?Failure.PENDING_WRITE:Failure.INVALID_FILE,()->store.load());
  require(Files.isSymbolicLink(directory.resolve(name)),"repaired a symlink");
  require(Files.readString(outside).equals("untouched"),"followed a symlink write");
 }
 static void overflow(Path directory) throws Exception {
  Files.write(directory.resolve(BIN),OwnerOpenClientStateCodec.encode(new Snapshot(Long.MAX_VALUE,identity())));
  byte[] before=Files.readAllBytes(directory.resolve(BIN));
  failure(Failure.STATE_CONFLICT,()->new OwnerOpenClientStateStore(directory).compareAndSet(Long.MAX_VALUE,identity()));
  require(Arrays.equals(before,Files.readAllBytes(directory.resolve(BIN))),"revision overflow mutated state");
 }
 static void explicitReadback(Path directory) throws Exception {
  storeRoundtrip(directory);Snapshot restored=new OwnerOpenClientStateStore(directory).load().orElseThrow();
  // turn.inspect is a different durable frame domain; these cached job/transport cursors cannot select it.
  long cursor=0;
  String frame=OwnerOpenFrame.turnInspect(restored.state.sessionId,restored.state.taskId,restored.state.turnId,cursor,256);
  require(OwnerOpenFrame.hasKind(frame,"turn.inspect"),"readback changed operation kind");
  require(frame.contains("\"inclusive_cursor\":0")&&frame.contains(TURN),"explicit readback lost same identity/explicit zero cursor");
  require(!OwnerOpenFrame.hasKind(frame,"turn.start"),"readback submitted an effect");
  byte[] before=Files.readAllBytes(directory.resolve(BIN));
  for(int i=0;i<10;i++)new OwnerOpenClientStateStore(directory).load();
  require(Arrays.equals(before,Files.readAllBytes(directory.resolve(BIN))),"restore performed hidden state transition");
 }
 static void lockHeld(Path directory) throws Exception {
  long start=System.nanoTime();failure(Failure.LOCK_BUSY,()->new OwnerOpenClientStateStore(directory).load());
  require(System.nanoTime()-start<1000000000L,"lock contention blocked instead of rejecting");
 }
 static void holdLock(Path directory) throws Exception {
  try(FileChannel c=FileChannel.open(directory.resolve(LOCK),StandardOpenOption.CREATE,StandardOpenOption.WRITE);
      FileLock lock=c.lock()) {
   require(lock.isValid(),"holder lock invalid");System.out.println("READY");System.out.flush();
   require(System.in.read()!=-1,"holder lost coordination");
  }
 }
 static void probeOsLock(Path directory) throws Exception {
  try(FileChannel channel=FileChannel.open(directory.resolve(LOCK),StandardOpenOption.WRITE);
      FileLock probe=channel.tryLock()) {
   require(probe==null,"external independent process entered while original Store transaction was active");
  }
 }
 static void sameJvmLockSafety(Path directory,boolean recursive) throws Exception {
  new OwnerOpenClientStateStore(directory).compareAndSet(0,identity());
  CountDownLatch synced=new CountDownLatch(1),release=new CountDownLatch(1);
  AtomicReference<Throwable> failed=new AtomicReference<>();
  OwnerOpenClientStateStore store=new OwnerOpenClientStateStore(directory,new OwnerOpenClientStateStore.CommitHook(){
   public void afterFileSync() throws IOException {
    try {
     if(recursive)failure(Failure.LOCK_BUSY,()->new OwnerOpenClientStateStore(directory).load());
     synced.countDown();require(release.await(5,TimeUnit.SECONDS),"writer lost coordination");
    }catch(Exception error){throw new IOException(error);}
   }
   public void afterAtomicRename(){}
  });
  Thread writer=new Thread(()->{try{store.compareAndSet(1,cursored());}catch(Throwable error){failed.set(error);}});
  writer.start();
  try {
   require(synced.await(5,TimeUnit.SECONDS),"writer never reached actual file fsync");
   failure(Failure.LOCK_BUSY,()->new OwnerOpenClientStateStore(directory).load());
   Process child=new ProcessBuilder(System.getProperty("java.home")+"/bin/java","-cp",System.getProperty("java.class.path"),
    "org.trillionnium.owneropen.ClientStateStoreHarness","probe-os-lock",directory.toString()).redirectErrorStream(true).start();
   require(child.waitFor(3,TimeUnit.SECONDS),"external independent process probe timed out");
   String output=new String(child.getInputStream().readAllBytes());
   require(child.exitValue()==0,"failed Store contender released original POSIX lock: "+output);
  } finally {release.countDown();writer.join(3000);}
  require(!writer.isAlive()&&failed.get()==null,"original writer failed: "+failed.get());
  same(cursored(),new OwnerOpenClientStateStore(directory).load().orElseThrow().state);
 }
 public static void main(String[] args) throws Exception {
  String scenario=args[0];Path directory=args.length>1?Path.of(args[1]):null;
  switch(scenario) {
   case "roundtrip":roundtrip();break;
   case "bound-digest":boundDigest();break;
   case "codec-negative":codecNegative();break;
   case "identity-negative":identityNegative();break;
   case "cursor-domains":cursorSemantics();break;
   case "store-roundtrip":storeRoundtrip(directory);break;
   case "reopen-process":same(cursored(),new OwnerOpenClientStateStore(directory).load().orElseThrow().state);break;
   case "stale-conflict":staleAndConflict(directory);break;
   case "pre-rename-fault":fault(directory,false);break;
   case "post-rename-fault":fault(directory,true);break;
   case "rename-error-before":renameError(directory,false);break;
   case "rename-error-after":renameError(directory,true);break;
   case "corrupt-file":corruptFile(directory);break;
   case "state-symlink":symlink(directory,BIN);break;
   case "pending-symlink":symlink(directory,PENDING);break;
   case "lock-symlink":symlink(directory,LOCK);break;
   case "overflow":overflow(directory);break;
   case "explicit-readback":explicitReadback(directory);break;
   case "lock-held":lockHeld(directory);break;
   case "hold-lock":holdLock(directory);break;
   case "probe-os-lock":probeOsLock(directory);break;
   case "same-jvm-lock-safety":sameJvmLockSafety(directory,false);break;
   case "same-thread-lock-safety":sameJvmLockSafety(directory,true);break;
   default:throw new AssertionError("unknown behavior test");
  }
  System.out.println(scenario+" PASS; actual Java/host filesystem only, Android/phone unqualified");
 }
}'''


class ClientStateStoreBehaviorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java = shutil.which('java')
        javac = shutil.which('javac')
        if not cls.java or not javac:
            raise RuntimeError('JDK required for production client state/store behavior tests')
        cls.tmp = tempfile.TemporaryDirectory()
        cls.classes = Path(cls.tmp.name) / 'classes'
        cls.classes.mkdir()
        harness = Path(cls.tmp.name) / 'ClientStateStoreHarness.java'
        harness.write_text(HARNESS)
        sources = [SOURCE / (name+'.java') for name in (
            'OwnerOpenClientState', 'OwnerOpenClientStateCodec', 'OwnerOpenClientStateStore', 'OwnerOpenFrame')]
        result = subprocess.run([javac, '-Xlint:all', '-Werror', '-d', str(cls.classes),
                                 *map(str, sources), str(harness)], capture_output=True,
                                text=True, timeout=30)
        if result.returncode:
            cls.tmp.cleanup()
            raise AssertionError(result.stdout+result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def command(self, scenario, directory):
        return [self.java, '-cp', str(self.classes),
                'org.trillionnium.owneropen.ClientStateStoreHarness', scenario, str(directory)]

    def run_scenario(self, scenario, directory):
        result = subprocess.run(self.command(scenario, directory), capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn(scenario+' PASS', result.stdout)

    def test_codec_state_and_domains(self):
        for scenario in ('roundtrip', 'bound-digest', 'codec-negative', 'identity-negative', 'cursor-domains'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder:
                self.run_scenario(scenario, Path(folder))

    def test_real_store_and_cross_process_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            self.run_scenario('store-roundtrip', Path(folder))
            self.run_scenario('reopen-process', Path(folder))

    def test_conflicts_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            self.run_scenario('stale-conflict', Path(folder))

    def test_real_pre_and_post_rename_failure_cuts(self):
        for scenario in ('pre-rename-fault', 'post-rename-fault'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder:
                self.run_scenario(scenario, Path(folder))

    def test_atomic_move_error_is_unknown_for_both_namespace_outcomes(self):
        for scenario in ('rename-error-before', 'rename-error-after'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder:
                self.run_scenario(scenario, Path(folder))

    def test_corrupt_record_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            self.run_scenario('corrupt-file', Path(folder))

    def test_symlinks_are_rejected_without_repair(self):
        for scenario in ('state-symlink', 'pending-symlink', 'lock-symlink'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder:
                self.run_scenario(scenario, Path(folder))

    def test_revision_overflow_before_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            self.run_scenario('overflow', Path(folder))

    def test_explicit_turn_inspect_uses_identity_and_zero_cursor_without_mixing_job_domains(self):
        with tempfile.TemporaryDirectory() as folder:
            self.run_scenario('explicit-readback', Path(folder))

    def test_real_cross_process_lock_rejects_without_wait(self):
        with tempfile.TemporaryDirectory() as folder:
            holder = subprocess.Popen(self.command('hold-lock', Path(folder)),
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(holder.stdout.readline().strip(), 'READY')
                self.run_scenario('lock-held', Path(folder))
                stdout, stderr = holder.communicate('\n', timeout=5)
                self.assertEqual(holder.returncode, 0, stdout+stderr)
            finally:
                if holder.poll() is None:
                    holder.kill()
                    holder.communicate()

    def test_failed_same_jvm_or_recursive_contender_cannot_release_writer_posix_lock(self):
        for scenario in ('same-jvm-lock-safety', 'same-thread-lock-safety'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder:
                self.run_scenario(scenario, Path(folder))


if __name__ == '__main__':
    unittest.main()
