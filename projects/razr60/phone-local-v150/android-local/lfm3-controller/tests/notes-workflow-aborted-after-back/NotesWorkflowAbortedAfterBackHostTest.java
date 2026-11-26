package org.trillionnium.hepta.local;

import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Exact private historical inputs plus bounded, authored host mutations.
 * Framework/PM/clock/UID/file-descriptor ports are inherited from the original
 * personal-notes-absence fixture. No sample here proves current phone absence. */
public final class NotesWorkflowAbortedAfterBackHostTest {
 private static int cases,assertions;
 private static final List<String> names=new ArrayList<String>(),rejections=new ArrayList<String>();
 private static final String SCHEMA="hepta.personal-notes-absence-request.v13-workflow-aborted-after-back";
 private static Inputs captured;
 private static Path scratch;
 interface Work {void run()throws Exception;}
 interface Change {void run(Inputs x)throws Exception;}
 private static void check(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
 private static void test(String name,Work work)throws Exception{work.run();cases++;names.add(name);}
 private static byte[] raw(JSONObject value){return value.toString().getBytes(StandardCharsets.UTF_8);}
 private static String sha(byte[] value){return HeptaAccessibilityService.sha(value);}
 private static JSONObject object(byte[] value)throws Exception{return PublicPersonalNotesAbsenceRecovery.object(value);}
 private static Exception unwrap(Exception e){
  if(e instanceof InvocationTargetException){Throwable t=((InvocationTargetException)e).getCause();if(t instanceof Exception)return (Exception)t;if(t instanceof Error)throw (Error)t;}
  return e;
 }
 private static void refused(String label,Work work)throws Exception{
  try{work.run();throw new AssertionError("accepted: "+label);}
  catch(Exception e){e=unwrap(e);check(true,label);rejections.add(label+":"+e.getClass().getName()+":"+String.valueOf(e.getMessage()));}
 }
 private static void reject(String label,Change change)throws Exception{
  Inputs x=captured.copy();change.run(x);refused(label,()->x.request());
 }
 private static void putAt(JSONObject value,String path,Object replacement)throws Exception{
  String[] parts=path.split("/");JSONObject cursor=value;
  for(int i=0;i<parts.length-1;i++)cursor=cursor.getJSONObject(parts[i]);cursor.put(parts[parts.length-1],replacement);
 }
 private static void field(Inputs x,String role,String path,Object value)throws Exception{
  JSONObject o=x.json(role);putAt(o,path,value);x.set(role,o);
 }
 private static boolean aborted(PublicPersonalNotesAbsenceRecovery.Request r)throws Exception{
  return r.getClass().getField("workflowAbortedAfterBack").getBoolean(r);
 }
 private static byte[] referenced(JSONObject ref)throws Exception{
  Path path=Paths.get(ref.getString("path"));byte[] bytes=Files.readAllBytes(path);
  check(bytes.length==ref.getLong("bytes")&&sha(bytes).equals(ref.getString("sha256")),"fixed original ref "+path.getFileName());return bytes;
 }
 private static final class Inputs {
  final Map<String,byte[]> input=new LinkedHashMap<String,byte[]>(),taskFiles=new TreeMap<String,byte[]>();
  final Map<String,Path> paths=new LinkedHashMap<String,Path>(),taskPaths=new TreeMap<String,Path>();
  byte[] control;JSONObject controller;int uid,boot;long now;
  Inputs copy()throws Exception{
   Inputs x=new Inputs();for(Map.Entry<String,byte[]> e:input.entrySet())x.input.put(e.getKey(),e.getValue().clone());
   for(Map.Entry<String,byte[]> e:taskFiles.entrySet())x.taskFiles.put(e.getKey(),e.getValue().clone());
   x.paths.putAll(paths);x.taskPaths.putAll(taskPaths);x.control=control.clone();x.controller=new JSONObject(controller.toString());x.uid=uid;x.boot=boot;x.now=now;return x;
  }
  JSONObject json(String role)throws Exception{return object(input.get(role));}
  void set(String role,JSONObject value)throws Exception{
   byte[] bytes=raw(value);input.put(role,bytes);Path p=paths.get(role);
   if(p!=null&&taskPaths.containsKey(p.getFileName().toString())){taskFiles.put(p.getFileName().toString(),bytes);refreshManifest();}
  }
  void refreshManifest()throws Exception{
   JSONObject old=json("aborted_history");JSONArray rows=new JSONArray();
   for(Map.Entry<String,byte[]> e:taskFiles.entrySet())rows.put(new JSONArray().put(e.getKey()).put(e.getValue().length).put(sha(e.getValue())));
   input.put("aborted_history",raw(new JSONObject().put("schema",old.getString("schema"))
    .put("startup_archive",old.getBoolean("startup_archive")).put("task_files",rows)));
  }
  PublicPersonalNotesAbsenceRecovery.Request request()throws Exception{
   return PublicPersonalNotesAbsenceRecovery.request(input,control,controller,uid,"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",now,boot);
  }
 }
 private static Inputs read(Path map)throws Exception{
  JSONObject m=object(Files.readAllBytes(map));Inputs x=new Inputs();JSONArray rows=m.getJSONArray("rows");
  check(rows.length()==24,"exact 24 historical roles");
  for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i),r=row.getJSONObject("ref");String role=row.getString("role");
   check(!x.input.containsKey(role),"unique original role");x.input.put(role,referenced(r));x.paths.put(role,Paths.get(r.getString("path")));}
  JSONObject control=m.getJSONObject("historical_current_control");x.control=referenced(control);x.paths.put("current_control",Paths.get(control.getString("path")));
  JSONArray task=m.getJSONArray("complete_task_files");check(task.length()==29,"exact 29 original task members");
  for(int i=0;i<task.length();i++){JSONObject row=task.getJSONObject(i),r=row.getJSONObject("ref");Path p=Paths.get(r.getString("path"));
   String name=p.getFileName().toString();check(!x.taskFiles.containsKey(name)&&row.getInt("archive_mode")==0600,"unique private task member");
   x.taskFiles.put(name,referenced(r));x.taskPaths.put(name,p);}
  JSONObject journal=x.json("journal");x.uid=journal.getInt("app_uid");x.boot=journal.getInt("boot_count");x.now=journal.getLong("expires_elapsed_ms")+3000;
  x.controller=new PersonalNotesAbsenceHostTest.Fixture().controller;
  x.controller.put("uid",x.uid).put("source_path","/data/app/~~explicit-host-controller-fixture==/org.trillionnium.hepta.local-source-fixture==/base.apk");
  return x;
 }
 private static void verifyOriginals()throws Exception{
  for(Map.Entry<String,Path> e:captured.paths.entrySet())check(Arrays.equals("current_control".equals(e.getKey())?captured.control:captured.input.get(e.getKey()),Files.readAllBytes(e.getValue())),"input unchanged "+e.getKey());
  for(Map.Entry<String,Path> e:captured.taskPaths.entrySet())check(Arrays.equals(captured.taskFiles.get(e.getKey()),Files.readAllBytes(e.getValue())),"complete task unchanged "+e.getKey());
 }
 private static void syncCleanup(Inputs x)throws Exception{
  JSONObject cleanup=x.json("cleanup"),result=x.json("result");result.put("background_cleanup",cleanup);
  JSONObject session=new JSONObject(cleanup.toString());session.remove("cleanup_known");session.remove("cleanup_error");
  result.put("background_session",session);x.set("result",result);
 }
 private static void syncTerminal(Inputs x)throws Exception{
  byte[] bytes=x.input.get("broker_output");JSONObject receipt=x.json("broker_receipt");
  receipt.put("observed_bytes",bytes.length).put("stored_bytes",bytes.length).put("stored_sha256",sha(bytes));x.set("broker_receipt",receipt);
  JSONObject cleanup=x.json("cleanup");cleanup.put("broker_output",receipt);x.set("cleanup",cleanup);syncCleanup(x);
 }
 private static void nativeSessionProjection(Inputs x)throws Exception{
  JSONObject result=x.json("result");result.getJSONObject("model_session").put("app_receipt_sha256",sha(x.input.get("model_session_receipt")));x.set("result",result);
 }
 private static void manifestRow(Inputs x,String mode)throws Exception{
  JSONObject h=x.json("aborted_history");JSONArray old=h.getJSONArray("task_files"),rows=new JSONArray();
  for(int i=0;i<old.length();i++)if(!"missing".equals(mode)||i!=0)rows.put(old.get(i));
  if("duplicate".equals(mode))rows.put(old.get(0));
  if("extra".equals(mode))rows.put(new JSONArray().put("step-02-model-0.json").put(1).put(sha(new byte[]{0})));
  h.put("task_files",rows);x.input.put("aborted_history",raw(h));
 }
 private static String changedWire(String wire,String schema,boolean duplicate,boolean trailing)throws Exception{
  ByteArrayOutputStream plain=new ByteArrayOutputStream();
  try(GZIPInputStream in=new GZIPInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(wire)))){
   byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1)plain.write(b,0,n);}
  if(!duplicate){
   DataInputStream in=new DataInputStream(new ByteArrayInputStream(plain.toByteArray()));in.readUTF();
   ByteArrayOutputStream changed=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(changed);out.writeUTF(schema);
   byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1)out.write(b,0,n);if(trailing)out.writeByte(1);out.flush();
   ByteArrayOutputStream zipped=new ByteArrayOutputStream();try(GZIPOutputStream zip=new GZIPOutputStream(zipped)){zip.write(changed.toByteArray());}
   return Base64.getEncoder().encodeToString(zipped.toByteArray());
  }
  // Real v13 framing, changing only the second role name to duplicate the first.
  // The following caller checks exact schema and count before this mutation.
  DataInputStream in=new DataInputStream(new ByteArrayInputStream(plain.toByteArray()));
  ByteArrayOutputStream changed=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(changed);
  out.writeUTF(in.readUTF());out.writeInt(in.readInt());out.writeUTF(in.readUTF());out.writeLong(in.readLong());out.writeInt(in.readInt());
  for(int i=0;i<2;i++){int length=in.readInt();check(length>0&&length<=131072,"bounded controller/control wire");out.writeInt(length);byte[] part=new byte[length];in.readFully(part);out.write(part);}
  int count=in.readInt();check(count==24,"v13 wire original count");out.writeInt(count);String first=null;
  for(int i=0;i<count;i++){String role=in.readUTF();if(i==0)first=role;out.writeUTF(i==1?first:role);
   int length=in.readInt();out.writeInt(length);byte[] b=new byte[length];in.readFully(b);out.write(b);}
  byte[] tail=new byte[4096];int n;while((n=in.read(tail))!=-1)out.write(tail,0,n);out.flush();
  ByteArrayOutputStream zipped=new ByteArrayOutputStream();try(GZIPOutputStream zip=new GZIPOutputStream(zipped)){zip.write(changed.toByteArray());}
  return Base64.getEncoder().encodeToString(zipped.toByteArray());
 }
 interface ProofChange {void run(JSONObject p,PublicPersonalNotesAbsenceRecovery.Request r)throws Exception;}
 private static void proofRefusal(String label,ProofChange change)throws Exception{
  PublicPersonalNotesAbsenceRecovery.Request r=captured.request();JSONObject p=PersonalNotesAbsenceHostTest.proof(r);change.run(p,r);
  refused(label,()->PublicPersonalNotesAbsenceRecovery.validate(p,r,r.started+21,r.requestBoot));
 }
 private static void sessionField(BackgroundSession s,String name,Object value)throws Exception{
  Field f=BackgroundSession.class.getDeclaredField(name);f.setAccessible(true);f.set(s,value);
 }
 private static BackgroundSession.Cleanup typed(PublicPersonalNotesRecoveryClient.Receipt receipt,JSONObject evidence)throws Exception{
  Constructor<BackgroundSession.Cleanup> c=BackgroundSession.Cleanup.class.getDeclaredConstructor(boolean.class,JSONObject.class,
   ProfileRecoveryClient.Receipt.class,ProfilePostlaunchRecoveryClient.Receipt.class,PublicProfileRecoveryClient.Receipt.class,PublicPersonalNotesRecoveryClient.Receipt.class);
  c.setAccessible(true);return c.newInstance(true,evidence,null,null,null,receipt);
 }
 private static final class ClientFixture {
  final Inputs x;final PublicPersonalNotesAbsenceRecovery.Request request;
  final Path root,task;final android.content.Context context;final BackgroundSession session;
  final Map<String,MobiMindPrivateFiles.Read> reads=new LinkedHashMap<String,MobiMindPrivateFiles.Read>();
  final Object archive;final PublicPersonalNotesRecoveryClient.Receipt receipt;
  ClientFixture(Inputs input)throws Exception{
   x=input;request=x.request();
   android.os.Process.uid=x.uid;android.os.SystemClock.now=request.started+21;android.provider.Settings.Global.boot=request.oldBoot;android.os.Looper.worker=true;
   android.net.LocalSocket.reset();android.net.LocalSocket.missing=true;android.system.Os.failUnlink=false;android.system.Os.failFsyncPath=null;
   android.system.Os.corruptPublicArchiveOnSync=false;android.system.Os.afterPublicCommitSync=null;
   root=Files.createTempDirectory(scratch,"consumer-private-").toRealPath();MobiMindPrivateFiles.directory(root.toFile(),false);
   context=new android.content.Context(root.toFile());
   String instruction=x.json("owner").getString("instruction"),pkg=PublicPersonalNotesAbsenceRecovery.PACKAGE;
   BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(instruction,pkg,Collections.singleton(pkg));
   session=BackgroundSession.experimentalPublicOwnGroup(context,request.taskId,instruction,new BackgroundSession.Selection(target,false,true),new QualificationScopeConfig.FilesRoot(context));
   MobiMindPrivateFiles.directory(root.resolve("control-tasks").toFile(),true);
   task=root.resolve("control-tasks").resolve(request.taskId);MobiMindPrivateFiles.directory(task.toFile(),true);
   Path nativeDir=root.resolve("native-fixture");MobiMindPrivateFiles.directory(nativeDir.toFile(),true);
   for(Map.Entry<String,byte[]> e:x.taskFiles.entrySet())MobiMindPrivateFiles.writeNew(task.resolve(e.getKey()).toFile(),e.getValue());
   for(String role:x.input.keySet()){
    if("aborted_history".equals(role))continue;Path dst;
    if("journal".equals(role))dst=root.resolve(BackgroundSession.JOURNAL);
    else if("origin_control".equals(role)){
     MobiMindPrivateFiles.directory(root.resolve("session-recovery").toFile(),false);
     dst=root.resolve("session-recovery").resolve("control-session.json."+sha(x.input.get(role))+".json");
    }else if("interruption_latch".equals(role))dst=root.resolve("control-session.interrupted.json");
    else if(x.paths.containsKey(role)&&x.taskFiles.containsKey(x.paths.get(role).getFileName().toString()))dst=task.resolve(x.paths.get(role).getFileName());
    else dst=nativeDir.resolve(role+".bin");
    if(!Files.exists(dst))MobiMindPrivateFiles.writeNew(dst.toFile(),x.input.get(role));
    reads.put(role,MobiMindPrivateFiles.read(dst.toFile(),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
   }
   Path control=root.resolve("control-session.json");MobiMindPrivateFiles.writeNew(control.toFile(),x.control);
   reads.put("current_control",MobiMindPrivateFiles.read(control.toFile(),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
   Class<?> kind=Class.forName("org.trillionnium.hepta.local.PublicPersonalNotesRecoveryClient$AbortedWorkflowArchive");
   Constructor<?> factory=kind.getDeclaredConstructor(File.class,Map.class);factory.setAccessible(true);archive=factory.newInstance(task.toFile(),reads);
   Field startup=kind.getDeclaredField("startupArchive");startup.setAccessible(true);startup.setBoolean(archive,x.input.containsKey("origin_control"));
   Method original=kind.getDeclaredMethod("requireUnchanged",PublicPersonalNotesAbsenceRecovery.Request.class);original.setAccessible(true);original.invoke(archive,request);
   JSONObject proof=PersonalNotesAbsenceHostTest.proof(request);PublicPersonalNotesAbsenceRecovery.validate(proof,request,request.started+21,request.requestBoot);
   Class<?> cancelled=Class.forName("org.trillionnium.hepta.local.PublicPersonalNotesRecoveryClient$CancelledArchive");
   Constructor<PublicPersonalNotesRecoveryClient.Receipt> c=PublicPersonalNotesRecoveryClient.Receipt.class.getDeclaredConstructor(
    PublicPersonalNotesAbsenceRecovery.Request.class,JSONObject.class,byte[].class,String.class,long.class,Map.class,cancelled,kind);
   c.setAccessible(true);receipt=c.newInstance(request,proof,raw(proof),"explicit host absence-process fixture",request.started+21,reads,null,archive);
  }
  void requireTaskExact()throws Exception{
   try(java.util.stream.Stream<Path> files=Files.list(task)){
    Set<String> names=new TreeSet<String>();for(Path p:files.toArray(Path[]::new))names.add(p.getFileName().toString());
    check(names.equals(x.taskFiles.keySet()),"receipt never adds to original 29-member task");}
   for(Map.Entry<String,byte[]> e:x.taskFiles.entrySet())check(Arrays.equals(e.getValue(),Files.readAllBytes(task.resolve(e.getKey()))),"29-member byte preservation "+e.getKey());
  }
  void consume()throws Exception{
   refused("unpersisted receipt",()->receipt.evidence());receipt.persist(context);receipt.requirePersisted();receipt.requireOriginals(true);requireTaskExact();
   JSONObject evidence=receipt.evidence();
   check(request.source().equals(evidence.getString("reconciliation_source"))&&request.proofSchema().equals(evidence.getJSONObject("personal_notes_absence").getString("schema")),"v13 dynamic source through actual client");
   check(!evidence.getBoolean("broker_released")&&!evidence.getBoolean("historical_broker_release_observed")&&evidence.get("broker_response")==JSONObject.NULL,"historical unknown remains unknown");
   Path directory=root.resolve("session-recovery").resolve("notes-aborted-absence-"+request.requestId);
   check(Files.isDirectory(directory)&&Arrays.equals(request.original("aborted_history"),Files.readAllBytes(directory.resolve("aborted-workflow-history.json"))),"new private receipt namespace and exact manifest");
   sessionField(session,"generation",request.generation);sessionField(session,"socketName",request.displayName);sessionField(session,"displayName",request.displayName);
   sessionField(session,"createdElapsed",request.created);sessionField(session,"expiresElapsed",request.expires);sessionField(session,"bootCount",request.oldBoot);
   sessionField(session,"publicOwnGroupScope",request.publicScope);
   Field owner=BackgroundSession.class.getDeclaredField("publicScopeOwner");owner.setAccessible(true);Object key=owner.get(session);
   PublicOwnGroupPolicy.LiveLease lease=new PublicOwnGroupPolicy.LiveLease(key,request.publicScope);lease.retire(key);sessionField(session,"publicScopeLease",lease);
   sessionField(session,"retired",true);sessionField(session,"spawnAttempted",true);sessionField(session,"bootstrapDispatched",true);
   sessionField(session,"displayId",request.displayId);sessionField(session,"brokerExitObserved",false);sessionField(session,"state","CLEANUP_UNKNOWN");
   refused("opaque receipt cannot bypass present lease",()->session.acceptReconciliation(typed(receipt,evidence)));
   // The old suite separately executes the unchanged production CAS/unlink.
   // This is its existing, explicit post-CAS consumer port, not a phone effect.
   Files.delete(root.resolve(BackgroundSession.JOURNAL));
   refused("JSON alone not typed authority",()->session.acceptReconciliation(new BackgroundSession.Cleanup(true,evidence)));
   JSONObject wrong=new JSONObject(evidence.toString()).put("reconciliation_source",PublicPersonalNotesAbsenceRecovery.SOURCE);
   refused("v13 cannot alias original source",()->session.acceptReconciliation(typed(receipt,wrong)));
   session.acceptReconciliation(typed(receipt,evidence));check(session.released(),"actual typed consumer");
   receipt.requireOriginals(false);requireTaskExact();check(android.net.LocalSocket.connections==0,"no broker/socket operations");
  }
 }
private static final class AckStore implements RecoveryJournalTransaction.Store{
  final Map<String,byte[]> files=new LinkedHashMap<String,byte[]>();
  public byte[] read(String n){byte[] b=files.get(n);return b==null?null:b.clone();}
  public List<String> pendingBarriers(){List<String> a=new ArrayList<String>();for(String n:files.keySet())if(n.startsWith(RecoveryJournalTransaction.PENDING_PREFIX))a.add(n);return a;}
  public void create(String n,byte[] b)throws Exception{if(files.containsKey(n))throw new IOException("already exists");files.put(n,b.clone());}
  public void replaceActive(byte[] old,byte[] b,String tx)throws Exception{if(!Arrays.equals(old,files.get(RecoveryJournalTransaction.ACTIVE)))throw new IOException("compare");files.put(RecoveryJournalTransaction.ACTIVE,b.clone());}
  public void removeIfEqual(String n,byte[] old)throws Exception{if(!Arrays.equals(old,files.get(n)))throw new IOException("compare");files.remove(n);}
  public void sync(){}
 }
 private static Map<String,Object> idleFields(RecoveryJournalTransaction.Proof p,int uid){
  RecoveryJournalTransaction.Acknowledgement a=p.acknowledgement;Map<String,Object> m=new LinkedHashMap<String,Object>();
  m.put("schema","hepta.local-session.v1");m.put("status",RecoveryJournalTransaction.IDLE_STATUS);m.put("state","host fixture new idle; original failure unchanged");
  m.put("app_uid",uid);m.put("updated_wall_ms",a.wallMs);m.put("task_id",null);m.put("instruction_sha256",null);m.put("debug_nonce_sha256",null);
  m.put("origin","user_recovery_confirmation");m.put("pending",false);m.put("running",false);m.put("blocked",false);m.put("cleanup_known",true);
  m.put("external_model",false);m.put("automatic_resume",false);m.put("session_id",a.sessionId);m.put("recovery_transaction_id",a.transactionId);
  m.put("recovery_prepare_sha256",a.prepareSha256);m.put("recovery_ack_sha256",a.ackSha256);m.put("recovery_quiescence_sha256",a.quiescenceSha256);
  m.put("old_native_cleanup","unknown");m.put("old_session_disposition","interrupted_not_resumed");m.put("process_inventory_scope",RecoveryJournalTransaction.SCOPE);return m;
 }
 private static void acknowledgementContract()throws Exception{
  AckStore store=new AckStore();store.files.put(RecoveryJournalTransaction.ACTIVE,captured.control.clone());
  for(Map.Entry<String,byte[]> e:captured.input.entrySet())store.files.put("historical-task/"+e.getKey(),e.getValue().clone());
  final int uid=captured.uid,pid=4321;final long[] next={2400};
  List<RecoveryQuiescence.Sample> first=Arrays.asList(new RecoveryQuiescence.Sample(uid,pid,99,100,0,true),
   new RecoveryQuiescence.Sample(uid,pid,99,850,0,true),new RecoveryQuiescence.Sample(uid,pid,99,1600,0,true));
  RecoveryJournalTransaction.Proof proof=RecoveryJournalTransaction.acknowledge(store,uid,pid,new String(new char[32]).replace('\0','c'),
    new String(new char[32]).replace('\0','d'),123456L,first,()->{},
    ()->{RecoveryQuiescence.Sample s=new RecoveryQuiescence.Sample(uid,pid,99,next[0],0,true);next[0]+=800;return s;},
    a->("host idle "+a.transactionId+" "+a.sessionId).getBytes(StandardCharsets.UTF_8));
  Map<String,Object> idle=idleFields(proof,uid);
  check(SessionRecovery.evaluate(idle,uid,false,proof).allowNewTask,"actual ACK proof may authorize only new idle");
  check(!SessionRecovery.evaluate(idle,uid).allowNewTask&&!SessionRecovery.evaluate(idle,uid,true,proof).allowNewTask,"JSON-only ACK and retained latch reject");
  for(Map.Entry<String,byte[]> e:captured.input.entrySet())check(Arrays.equals(e.getValue(),store.files.get("historical-task/"+e.getKey())),"ACK cannot rewrite original "+e.getKey());
  check(!captured.json("result").getBoolean("cleanup_known")&&!captured.json("cleanup").getBoolean("broker_process_exit_observed"),"ACK does not promote historical cleanup or exit");
 }
 
 private static Inputs startup(Path report)throws Exception{
  JSONObject produced=object(Files.readAllBytes(report));check(produced.getBoolean("all_pass")&&produced.getBoolean("host_only")&&!produced.getBoolean("phone_startup_proven"),"actual host producer completed");
  Inputs x=captured.copy();x.control=referenced(produced.getJSONObject("current_control"));
  byte[] original=referenced(produced.getJSONObject("origin_control")),latch=referenced(produced.getJSONObject("interruption_latch"));
  check(Arrays.equals(original,captured.control),"producer archived exact original control");
  x.input.put("origin_control",original);x.input.put("interruption_latch",latch);
  JSONObject history=x.json("aborted_history");history.put("startup_archive",true);x.input.put("aborted_history",raw(history));
  JSONObject current=object(x.control);check("interrupted".equals(current.getString("status"))&&current.getBoolean("blocked")
   &&!current.getBoolean("cleanup_known")&&!current.getBoolean("automatic_resume"),"producer retains blocked interrupted state");
  check(!current.has("completion_evidence")&&!current.has("steps")&&!current.has("task_result_reference"),"producer does not restore business result");
  check(!object(latch).getBoolean("cleanup_known"),"real producer latch does not grant cleanup");return x;
 }
 public static void main(String[] args)throws Exception{
  if(args.length!=4)throw new IllegalArgumentException("actual map, new scratch, baseline|candidate, startup producer report");
  scratch=Paths.get(args[1]);Files.createDirectory(scratch);
  check(Paths.get(JSONObject.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().toString().equals(System.getProperty("hepta.android.json.path")),"actual pinned Android JSON");
  captured=read(Paths.get(args[0]));
  if("baseline".equals(args[2])){
   try{captured.request();throw new AssertionError("old request accepted new aborted kind");}
   catch(IOException expected){check("NOTES_INPUT_SET".equals(expected.getMessage()),"exact old input-set rejection");}
   verifyOriginals();System.out.println(new JSONObject().put("schema","hepta.notes-workflow-aborted-after-back-host.v1").put("mode","baseline").put("all_pass",true).put("cases",1).put("assertions",assertions).put("exact_refusal","NOTES_INPUT_SET").put("phone_operations",0));return;
  }
  check("candidate".equals(args[2]),"closed mode");final PublicPersonalNotesAbsenceRecovery.Request r=captured.request();
  final Inputs[] restarted={null};
  test("actual_569_history_new_kind_and_roundtrip",()->{
   check(aborted(r)&&r.postModelDrained&&!r.workflowCloseFailed&&!r.workflowReleasedReplyLost&&!r.cancelledAfterActions,"distinct v13 no old-kind alias");
   PublicPersonalNotesAbsenceRecovery.Request round=PublicPersonalNotesAbsenceRecovery.fromWire(r.wire());check(aborted(round)&&r.originalsSha256.equals(round.originalsSha256),"exact wire kind");
   for(String role:captured.input.keySet())check(Arrays.equals(r.original(role),round.original(role)),"raw role roundtrip "+role);
   for(Map.Entry<String,byte[]> e:captured.taskFiles.entrySet())r.getClass().getMethod("requireAbortedTaskWitness",String.class,byte[].class).invoke(r,e.getKey(),e.getValue());
   int bytes=0;for(byte[] b:captured.input.values())bytes+=b.length;
   check(bytes<=262144&&r.wire().length()<=65536,"unchanged original bundle and wire bounds");
   String command="CLASSPATH='"+r.controller().getString("source_path")+"' /system/bin/app_process / org.trillionnium.hepta.background.PublicPersonalNotesAbsenceMain --request '"+r.wire()+"'";
   check(command.getBytes(StandardCharsets.UTF_8).length<60000,"unchanged complete command bound");
   check("CLEANUP_UNKNOWN".equals(captured.json("broker_output").getString("state"))&&!captured.json("broker_receipt").getBoolean("eof_seen")
    &&!captured.json("cleanup").getBoolean("broker_process_exit_observed")&&captured.json("cleanup").get("broker_process_exit_code")==JSONObject.NULL,"original UNKNOWN/EOFfalse/exitunknown");
  });
  test("ordinary_startup_from_exact_original_control",()->{
   Inputs x=startup(Paths.get(args[3]));restarted[0]=x;PublicPersonalNotesAbsenceRecovery.Request current=x.request();
   check(aborted(current)&&x.input.size()==26&&!r.currentControlSha256.equals(current.currentControlSha256),"actual producer current control is separately bound");
   PublicPersonalNotesAbsenceRecovery.Request round=PublicPersonalNotesAbsenceRecovery.fromWire(current.wire());
   check(aborted(round)&&Arrays.equals(x.input.get("origin_control"),round.original("origin_control")),"26-role roundtrip");
   Inputs bad=x.copy();JSONObject latch=bad.json("interruption_latch");latch.put("app_uid",bad.uid+1);bad.set("interruption_latch",latch);
   refused("startup foreign latch",()->bad.request());
  });
  test("wire_kind_and_input_set",()->{
   reject("missing historical role",x->x.input.remove("workflow_aborted"));
   reject("mixed cancelled kind",x->x.input.put("cancelled_history",raw(new JSONObject())));
   reject("startup flag without origin roles",x->{JSONObject h=x.json("aborted_history");h.put("startup_archive",true);x.input.put("aborted_history",raw(h));});
   refused("wrong wire kind",()->PublicPersonalNotesAbsenceRecovery.fromWire(changedWire(r.wire(),"hepta.personal-notes-absence-request.v12-workflow-released-reply-lost",false,false)));
   refused("duplicate wire role",()->PublicPersonalNotesAbsenceRecovery.fromWire(changedWire(r.wire(),SCHEMA,true,false)));
   refused("wire trailing byte",()->PublicPersonalNotesAbsenceRecovery.fromWire(changedWire(r.wire(),SCHEMA,false,true)));
  });
  test("complete_task_directory_membership",()->{
   for(String mode:new String[]{"missing","extra","duplicate"})reject("manifest "+mode,x->manifestRow(x,mode));
   ClientFixture f=new ClientFixture(captured);Path extra=f.task.resolve("step-02-action.json");MobiMindPrivateFiles.writeNew(extra.toFile(),new byte[]{0});
   refused("actual directory added second step",()->f.receipt.requireOriginals(true));Files.delete(extra);
   Path p=f.task.resolve(captured.taskFiles.keySet().iterator().next());byte[] before=Files.readAllBytes(p);Files.delete(p);
   refused("actual directory member missing",()->f.receipt.requireOriginals(true));MobiMindPrivateFiles.writeNew(p.toFile(),before);
  });
  test("original_byte_witness",()->{
   reject("selected role changed without manifest",x->{byte[] b=x.input.get("readiness");byte[] changed=Arrays.copyOf(b,b.length+1);changed[changed.length-1]=' ';x.input.put("readiness",changed);});
   String name=captured.taskFiles.keySet().iterator().next();byte[] b=captured.taskFiles.get(name).clone();b[0]^=1;
   refused("unselected full archive witness changed",()->r.getClass().getMethod("requireAbortedTaskWitness",String.class,byte[].class).invoke(r,name,b));
  });
  test("one_back_not_completed_workflow",()->{
   reject("not Back",x->field(x,"child_1_action","action/action","tap"));
   reject("Back not drained",x->field(x,"child_1_action","action_execution/worker_drained",false));
   reject("Back callback not current",x->field(x,"child_1_action","action_execution/callback_authority_current",false));
   reject("plan incorrectly entered",x->field(x,"child_1_planned","service_entered",true));
   reject("workflow completion claimed",x->field(x,"workflow_aborted","workflow_verified",true));
   reject("saved list claimed",x->field(x,"readiness","saved_or_reopened_verified",true));
  });
  test("historical_broker_kind_is_not_release",()->{
   reject("UNKNOWN cannot become RELEASED",x->{field(x,"broker_output","state","RELEASED");syncTerminal(x);});
   reject("EOF cannot become true",x->{field(x,"broker_receipt","eof_seen",true);JSONObject c=x.json("cleanup");c.put("broker_output",x.json("broker_receipt"));x.set("cleanup",c);syncCleanup(x);});
   reject("old App exit cannot become known",x->{JSONObject c=x.json("cleanup");c.put("broker_process_exit_observed",true).put("broker_process_exit_code",0);x.set("cleanup",c);syncCleanup(x);});
   reject("historical retained custody changed",x->{field(x,"broker_output","personal_notes_cleanup/custodian_retained",false);syncTerminal(x);});
  });
  test("normal_model_and_native_close",()->{
   PublicPersonalNotesRecoveryClient.requireDrainedGeneration(r);check(true,"real normal-close and WorkerGenerationProof");
   reject("abnormal native exit",x->field(x,"native_session_receipt","signal_observed",9));
   reject("forced generation cleanup",x->field(x,"generation_cleanup_receipt","kill_attempts",1));
   reject("normal model force destroy",x->field(x,"model_request_receipt","force_destroy_sent",true));
  });
  test("owner_uid_boot_generation_and_time",()->{
   reject("foreign owner",x->field(x,"owner","instruction_utf8_sha256",new String(new char[64]).replace('\0','b')));
   reject("foreign UID",x->x.uid++);
   reject("foreign boot",x->x.boot++);
   reject("foreign generation",x->field(x,"cleanup","generation","bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"));
   reject("expiry grace equality",x->x.now=r.expires+2000);
   refused("exact request deadline",()->r.requireFence(r.deadline,r.requestBoot));
   refused("request before start",()->r.requireFence(r.started-1,r.requestBoot));
   r.requireFence(r.deadline-1,r.requestBoot);check(r.deadline-r.started==12000,"original request budget remains 12 seconds");
  });
  test("full_fresh_absence_proof_binding",()->{
   JSONObject p=PersonalNotesAbsenceHostTest.proof(r);
   JSONObject verified=PublicPersonalNotesAbsenceRecovery.validate(p,r,r.started+21,r.requestBoot);
   check(verified.getBoolean("current_absence_verified")&&!verified.getBoolean("historical_broker_release_observed"),"fixture full proof, never historical release");
   refused("terminal not current proof",()->PublicPersonalNotesAbsenceRecovery.validate(captured.json("broker_output"),r,r.started+21,r.requestBoot));
   proofRefusal("missing second sample",(a,b)->a.remove("after"));
   proofRefusal("incomplete process census",(a,b)->a.getJSONObject("before").getJSONObject("process").put("complete",false));
   proofRefusal("different request source",(a,b)->a.put("source",PublicPersonalNotesAbsenceRecovery.SOURCE));
   proofRefusal("mixed original hash",(a,b)->a.put("originals_sha256",sha(new byte[]{1})));
   proofRefusal("changed current controller UID",(a,b)->a.getJSONObject("current_controller").put("uid",b.ownerUid+1));
  });
  test("recorded_task_migrated_to_main_or_cover",()->{
   for(final int display:new int[]{0,1})proofRefusal("recorded task on physical "+display,(p,q)->{
    JSONObject row=p.getJSONObject("after").getJSONObject("live").getJSONArray("roots").getJSONObject(0);
    row.put("id",q.recordedTaskIds.iterator().next()).put("display",display);
   });
   proofRefusal("other Notes task",(p,q)->p.getJSONObject("after").getJSONObject("live").getJSONArray("roots").getJSONObject(0).put("base","com.motorola.stylus/.Other"));
  });
  test("creator_or_native_generation_still_live",()->{
   proofRefusal("old creator present",(p,q)->p.getJSONObject("after").getJSONObject("process").put("old_creator_absent",false));
   check(NotesAbortedProcessesHost.capture(r,"empty").getBoolean("complete"),"actual complete proc algorithm on inherited raw port");
   refused("actual retained creator scan",()->NotesAbortedProcessesHost.capture(r,"creator"));
   refused("actual old lease generation scan",()->NotesAbortedProcessesHost.capture(r,"generation"));
   refused("current same-UID native or other worker blocks ACK",()->RecoveryQuiescence.confirm(Arrays.asList(
    new RecoveryQuiescence.Sample(r.ownerUid,4321,99,100,0,true),new RecoveryQuiescence.Sample(r.ownerUid,4321,99,850,1,true),
    new RecoveryQuiescence.Sample(r.ownerUid,4321,99,1600,0,true)),r.ownerUid,4321));
   proofRefusal("empty process inventory",(p,q)->p.getJSONObject("after").getJSONObject("process").put("process_count",0));
  });
  test("typed_client_commit_and_ack_consumer",()->{
   new ClientFixture(captured).consume();new ClientFixture(restarted[0]).consume();acknowledgementContract();verifyOriginals();
  });
  test("postproof_cas_and_archive_change",()->{
   ClientFixture controlFixture=new ClientFixture(captured);controlFixture.receipt.persist(controlFixture.context);
   controlFixture.receipt.requireOriginals(true);controlFixture.receipt.requirePersisted();controlFixture.requireTaskExact();
   Path control=controlFixture.root.resolve("control-session.json");byte[] old=Files.readAllBytes(control);byte[] changed=Arrays.copyOf(old,old.length+1);changed[changed.length-1]=' ';
   Files.write(control,changed);refused("actual pre-CAS current-control re-read",()->controlFixture.receipt.requireOriginals(true));
   ClientFixture archiveFixture=new ClientFixture(captured);archiveFixture.receipt.persist(archiveFixture.context);
   String name=captured.taskFiles.keySet().iterator().next();Path archive=archiveFixture.task.resolve(name);byte[] bad=Files.readAllBytes(archive);bad[0]^=1;Files.write(archive,bad);
   refused("actual pre-CAS complete task re-read",()->archiveFixture.receipt.requireOriginals(true));
   // These are independent negative fixture copies: no timestamp/inode is reset
   // to revive the first receipt after its unchanged-path guard has rejected it.
   verifyOriginals();
  });
  check(cases==14&&new HashSet<String>(names).size()==14,"exact 14 required groups");
  System.out.println(new JSONObject().put("schema","hepta.notes-workflow-aborted-after-back-host.v1").put("mode","candidate").put("all_pass",true)
   .put("cases",cases).put("assertions",assertions).put("case_names",new JSONArray(names)).put("refusals",new JSONArray(rejections))
   .put("actual_historical_roles",24).put("startup_roles",26).put("complete_task_members",29)
   .put("startup_control_producer_executed",true).put("startup_android_path_is_explicit_host_projection",true)
   .put("current_absence_is_fixture",true).put("controller_identity_is_fixture",true).put("clock_is_fixture",true)
   .put("post_cas_consumer_port_inherited",true).put("actual_pre_cas_originals_gate_executed",true)
   .put("phone_operations",0).put("current_phone_absence_proven",false).put("phone_startup_proven",false)
   .put("app_recovery_completed",false).put("business_success_claimed",false).toString());
 }
}
