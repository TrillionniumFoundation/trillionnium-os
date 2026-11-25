package org.trillionnium.hepta.local;

import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Captured private input admission plus authored in-memory negative mutations.
 * The 23 historical originals stay outside this repository. Controller identity
 * and clock are explicit host fixtures. This cannot prove current absence. */
public final class NotesWorkflowReleasedReplyLostHostTest {
 private static int cases, assertions;
 private static final List<String> names=new ArrayList<String>();
 private static final List<String> rejections=new ArrayList<String>();
 private static Inputs captured;
 private static Path scratch;
 interface Work {void run() throws Exception;}
 interface Change {void run(Inputs value) throws Exception;}
 private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
 private static void test(String name,Work work)throws Exception{work.run();cases++;names.add(name);}
 private static byte[] raw(JSONObject value){return value.toString().getBytes(StandardCharsets.UTF_8);}
 private static String sha(byte[] value){return HeptaAccessibilityService.sha(value);}
 private static void putAt(JSONObject value,String path,Object replacement)throws Exception{
  String[] parts=path.split("/");JSONObject current=value;
  for(int i=0;i<parts.length-1;i++)current=current.getJSONObject(parts[i]);
  current.put(parts[parts.length-1],replacement);
 }
 private static JSONObject objectAt(JSONObject value,String path)throws Exception{
  JSONObject current=value;for(String part:path.split("/"))current=current.getJSONObject(part);return current;
 }
 private static void reject(String name,Change change)throws Exception{
  test(name,()->{Inputs value=captured.copy();change.run(value);try{
   value.request();throw new AssertionError("unsafe historical input accepted: "+name);
  }catch(Exception expected){check(true,name);rejections.add(name+":"+expected.getClass().getSimpleName()+":"+safeReason(expected));}});
 }
 private static String safeReason(Exception error){
  String value=error.getMessage();return value!=null&&value.matches("NOTES_[A-Z0-9_]+")?value:"typed_exception";
 }
 private static void rejectField(String name,String role,String path,Object value)throws Exception{
  reject(name,x->{JSONObject o=x.json(role);putAt(o,path,value);x.set(role,o);});
 }
 private static final class Inputs {
  final Map<String,byte[]> input=new LinkedHashMap<String,byte[]>();
  final Map<String,Path> paths=new LinkedHashMap<String,Path>();
  byte[] control;JSONObject controller;int uid,boot;long now;
  Inputs copy()throws Exception{
   Inputs r=new Inputs();for(Map.Entry<String,byte[]> e:input.entrySet())r.input.put(e.getKey(),e.getValue().clone());
   r.paths.putAll(paths);r.control=control.clone();r.controller=new JSONObject(controller.toString());r.uid=uid;r.boot=boot;r.now=now;return r;
  }
  JSONObject json(String role)throws Exception{return PublicPersonalNotesAbsenceRecovery.object(input.get(role));}
  void set(String role,JSONObject value){input.put(role,raw(value));}
  PublicPersonalNotesAbsenceRecovery.Request request()throws Exception{
   return PublicPersonalNotesAbsenceRecovery.request(input,control,controller,uid,
     "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",now,boot);
  }
  void refreshSessionProjection()throws Exception{
   JSONObject result=json("result");result.getJSONObject("model_session").put("app_receipt_sha256",sha(input.get("model_session_receipt")));set("result",result);
  }
 }
 private static Inputs read(Path mapping)throws Exception{
  JSONObject manifest=new JSONObject(new String(Files.readAllBytes(mapping),StandardCharsets.UTF_8));
  Inputs value=new Inputs();Set<String> roles=new HashSet<String>();JSONArray rows=manifest.getJSONArray("rows");
  for(int i=0;i<rows.length();i++){
   JSONObject row=rows.getJSONObject(i);String role=row.getString("role");check(roles.add(role),"duplicate captured role");
   Path path=Paths.get(row.getString("host_path"));byte[] bytes=Files.readAllBytes(path);
   check(bytes.length==row.getInt("bytes")&&sha(bytes).equals(row.getString("sha256")),"captured hash differs");
   value.paths.put(role,path);
   if("current_control".equals(role))value.control=bytes;else value.input.put(role,bytes);
  }
  check(value.input.size()==23&&value.control!=null,"exact 23 originals and current control required");
  JSONObject journal=value.json("journal");value.uid=journal.getInt("app_uid");value.boot=journal.getInt("boot_count");
  value.now=journal.getLong("expires_elapsed_ms")+3000;
  value.controller=new PersonalNotesAbsenceHostTest.Fixture().controller;
  value.controller.put("uid",value.uid).put("source_path",
   "/data/app/~~explicit-host-controller-fixture==/org.trillionnium.hepta.local-source-fixture==/base.apk");
  return value;
 }
 private static void verifyOriginals()throws Exception{
  for(Map.Entry<String,Path> entry:captured.paths.entrySet()){
   byte[] original="current_control".equals(entry.getKey())?captured.control:captured.input.get(entry.getKey());
   check(Arrays.equals(original,Files.readAllBytes(entry.getValue())),"private original changed");
  }
 }
 private static String quote(String value){return "'"+value.replace("'","'\\''")+"'";}
 private static String changedWire(String wire,String schema,boolean trailing)throws Exception{
  ByteArrayOutputStream plain=new ByteArrayOutputStream();
  try(GZIPInputStream in=new GZIPInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(wire)))){
   byte[] buffer=new byte[4096];int n;while((n=in.read(buffer))!=-1)plain.write(buffer,0,n);
  }
  DataInputStream old=new DataInputStream(new ByteArrayInputStream(plain.toByteArray()));old.readUTF();
  ByteArrayOutputStream changed=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(changed);
  out.writeUTF(schema);byte[] buffer=new byte[4096];int n;while((n=old.read(buffer))!=-1)out.write(buffer,0,n);
  if(trailing)out.writeByte(1);out.flush();
  ByteArrayOutputStream zipped=new ByteArrayOutputStream();
  try(GZIPOutputStream zip=new GZIPOutputStream(zipped)){zip.write(changed.toByteArray());}
  return Base64.getEncoder().encodeToString(zipped.toByteArray());
 }
 private static void rejectWire(String name,String schema,boolean trailing)throws Exception{
  test(name,()->{String wire=changedWire(captured.request().wire(),schema,trailing);
   try{PublicPersonalNotesAbsenceRecovery.fromWire(wire);throw new AssertionError("unsafe wire accepted");}
   catch(Exception expected){check(true,name);}});
 }
 private static void taskEntries(File directory,boolean postModel,boolean workflow)throws Exception{
  Method method=PublicPersonalNotesRecoveryClient.class.getDeclaredMethod("requireTaskEntries",File.class,boolean.class,boolean.class);
  method.setAccessible(true);
  try{method.invoke(null,directory,postModel,workflow);}
  catch(InvocationTargetException error){Throwable cause=error.getCause();if(cause instanceof Exception)throw (Exception)cause;throw error;}
 }
 private static boolean lost(PublicPersonalNotesAbsenceRecovery.Request r)throws Exception{
  return r.getClass().getField("workflowReleasedReplyLost").getBoolean(r);
 }
 private static void syncCleanup(Inputs x)throws Exception{
  JSONObject cleanup=x.json("cleanup"),result=x.json("result");
  result.put("background_cleanup",cleanup);JSONObject session=new JSONObject(cleanup.toString());
  session.remove("cleanup_known");session.remove("cleanup_error");result.put("background_session",session);x.set("result",result);
 }
 private static void syncTerminal(Inputs x)throws Exception{
  byte[] output=x.input.get("broker_output");JSONObject broker=x.json("broker_receipt");
  broker.put("observed_bytes",output.length).put("stored_bytes",output.length).put("stored_sha256",sha(output));x.set("broker_receipt",broker);
  JSONObject cleanup=x.json("cleanup");cleanup.put("broker_output",broker);x.set("cleanup",cleanup);syncCleanup(x);
 }
 private static void rejectTerminal(String name,String path,Object replacement)throws Exception{
  reject(name,x->{JSONObject t=x.json("broker_output");putAt(t,path,replacement);x.set("broker_output",t);syncTerminal(x);});
 }
 private static void rejectLast(String name,String path,Object replacement)throws Exception{
  reject(name,x->{JSONObject c=x.json("cleanup");putAt(c.getJSONObject("last_broker_response"),path,replacement);x.set("cleanup",c);syncCleanup(x);});
 }
 interface ProofChange {void run(JSONObject p,PublicPersonalNotesAbsenceRecovery.Request r)throws Exception;}
 private static void rejectProof(String name,ProofChange change)throws Exception{
  test(name,()->{PublicPersonalNotesAbsenceRecovery.Request r=captured.request();
   JSONObject p=PersonalNotesAbsenceHostTest.proof(r);change.run(p,r);
   try{PublicPersonalNotesAbsenceRecovery.validate(p,r,r.started+21,r.requestBoot);throw new AssertionError("unsafe current proof accepted: "+name);}
   catch(Exception expected){check(true,name);}
  });
 }
 private static void refused(Work work,String name)throws Exception{
  try{work.run();throw new AssertionError("unsafe consumer accepted: "+name);}catch(Exception expected){check(true,name);}
 }
 private static void sessionField(BackgroundSession s,String name,Object value)throws Exception{
  Field f=BackgroundSession.class.getDeclaredField(name);f.setAccessible(true);f.set(s,value);
 }
 private static BackgroundSession.Cleanup typed(PublicPersonalNotesRecoveryClient.Receipt receipt,JSONObject evidence)throws Exception{
  Constructor<BackgroundSession.Cleanup> c=BackgroundSession.Cleanup.class.getDeclaredConstructor(boolean.class,JSONObject.class,
   ProfileRecoveryClient.Receipt.class,ProfilePostlaunchRecoveryClient.Receipt.class,PublicProfileRecoveryClient.Receipt.class,PublicPersonalNotesRecoveryClient.Receipt.class);
  c.setAccessible(true);return c.newInstance(true,evidence,null,null,null,receipt);
 }
 private static void consumerRoundtrip(PublicPersonalNotesAbsenceRecovery.Request r)throws Exception{
  // Only the existing Android private-file/clock/display adapters are synthetic.
  // Every historical byte below is copied into a new host-only fixture directory.
  android.os.SystemClock.now=r.started+21;android.provider.Settings.Global.boot=r.oldBoot;android.os.Looper.worker=true;
  android.net.LocalSocket.reset();android.net.LocalSocket.missing=true;
  android.system.Os.failUnlink=false;android.system.Os.failFsyncPath=null;
  android.system.Os.corruptPublicArchiveOnSync=false;android.system.Os.afterPublicCommitSync=null;
  Path root=Files.createTempDirectory(scratch,"consumer-private-fixture-").toRealPath();
  MobiMindPrivateFiles.directory(root.toFile(),false);
  android.content.Context context=new android.content.Context(root.toFile());
  String instruction=captured.json("owner").getString("instruction"),pkg=PublicPersonalNotesAbsenceRecovery.PACKAGE;
  BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(instruction,pkg,Collections.singleton(pkg));
  BackgroundSession session=BackgroundSession.experimentalPublicOwnGroup(context,r.taskId,instruction,new BackgroundSession.Selection(target,false,true),new QualificationScopeConfig.FilesRoot(context));
  MobiMindPrivateFiles.directory(root.resolve("control-tasks").toFile(),true);
  Path task=root.resolve("control-tasks").resolve(r.taskId);MobiMindPrivateFiles.directory(task.toFile(),true);
  Path nativeDir=root.resolve("native-fixture");MobiMindPrivateFiles.directory(nativeDir.toFile(),true);
  Path oldTask=captured.paths.get("result").getParent();
  try(java.util.stream.Stream<Path> files=Files.list(oldTask)){
   for(Path file:files.sorted().toArray(Path[]::new))MobiMindPrivateFiles.writeNew(task.resolve(file.getFileName()).toFile(),Files.readAllBytes(file));
  }
  Map<String,MobiMindPrivateFiles.Read> originalReads=new LinkedHashMap<String,MobiMindPrivateFiles.Read>();
  for(String role:captured.paths.keySet()){
   Path destination;
   if("journal".equals(role))destination=root.resolve(BackgroundSession.JOURNAL);
   else if("current_control".equals(role))destination=root.resolve("control-session.json");
   else if(captured.paths.get(role).getParent().equals(oldTask))destination=task.resolve(captured.paths.get(role).getFileName());
   else destination=nativeDir.resolve(role+".bin");
   byte[] bytes=r.original(role);
   if(!Files.exists(destination))MobiMindPrivateFiles.writeNew(destination.toFile(),bytes);
   originalReads.put(role,MobiMindPrivateFiles.read(destination.toFile(),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
  }
  JSONObject proof=PersonalNotesAbsenceHostTest.proof(r);
  PublicPersonalNotesAbsenceRecovery.validate(proof,r,r.started+21,r.requestBoot);
  Constructor<PublicPersonalNotesRecoveryClient.Receipt> c=PublicPersonalNotesRecoveryClient.Receipt.class.getDeclaredConstructor(
    PublicPersonalNotesAbsenceRecovery.Request.class,JSONObject.class,byte[].class,String.class,long.class,Map.class);
  c.setAccessible(true);
  PublicPersonalNotesRecoveryClient.Receipt receipt=c.newInstance(r,proof,raw(proof),"explicit host checker fixture",r.started+21,originalReads);
  refused(()->receipt.evidence(),"unpersisted opaque receipt");
  receipt.persist(context);receipt.requirePersisted();receipt.requireOriginals(true);
  JSONObject evidence=receipt.evidence();
  check(r.source().equals(evidence.getString("reconciliation_source"))&&r.proofSchema().equals(evidence.getJSONObject("personal_notes_absence").getString("schema")),"dynamic v12 source/proof through actual client");
  check(!evidence.getBoolean("historical_broker_release_observed")&&!evidence.getBoolean("broker_released")&&evidence.get("broker_response")==JSONObject.NULL,"terminal text is not a close reply");
  refused(()->receipt.requireLease(r.taskId,"bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",r.ownerSha256,r.created,r.expires,r.oldBoot,r.publicScope,r.displayId),"wrong lease receipt");
  sessionField(session,"generation",r.generation);sessionField(session,"socketName",r.displayName);sessionField(session,"displayName",r.displayName);
  sessionField(session,"createdElapsed",r.created);sessionField(session,"expiresElapsed",r.expires);sessionField(session,"bootCount",r.oldBoot);
  sessionField(session,"publicOwnGroupScope",r.publicScope);
  Field owner=BackgroundSession.class.getDeclaredField("publicScopeOwner");owner.setAccessible(true);Object key=owner.get(session);
  PublicOwnGroupPolicy.LiveLease lease=new PublicOwnGroupPolicy.LiveLease(key,r.publicScope);lease.retire(key);sessionField(session,"publicScopeLease",lease);
  sessionField(session,"retired",true);sessionField(session,"spawnAttempted",true);sessionField(session,"bootstrapDispatched",true);
  sessionField(session,"displayId",r.displayId);sessionField(session,"brokerExitObserved",false);sessionField(session,"state","CLEANUP_UNKNOWN");
  check(session.personalNotesRecoveryEligible(),"same failed personal scope eligible");
  refused(()->session.acceptReconciliation(typed(receipt,evidence)),"journal still present rejects");
  // Explicit host fixture transition to the already-CAS-retired input of this
  // consumer. Production unlink/CAS is unchanged and tested by the original suite.
  Files.delete(root.resolve(BackgroundSession.JOURNAL));
  refused(()->session.acceptReconciliation(new BackgroundSession.Cleanup(true,evidence)),"JSON alone cannot substitute opaque receipt");
  JSONObject wrong=new JSONObject(evidence.toString()).put("reconciliation_source",PublicPersonalNotesAbsenceRecovery.SOURCE);
  refused(()->session.acceptReconciliation(typed(receipt,wrong)),"old source cannot stand for v12");
  JSONObject wrongHash=new JSONObject(evidence.toString()).put("personal_notes_receipt_sha256",new String(new char[64]).replace('\0','a'));
  refused(()->session.acceptReconciliation(typed(receipt,wrongHash)),"wrong receipt hash rejects");
  session.acceptReconciliation(typed(receipt,evidence));check(session.released(),"actual BackgroundSession typed consumer accepts v12");
  receipt.requireOriginals(false);check(Arrays.equals(captured.input.get("result"),Files.readAllBytes(task.resolve("result.json"))),"old blocked result retained by actual consumer");
  check(!new JSONObject(new String(Files.readAllBytes(task.resolve("background-cleanup.json")),StandardCharsets.UTF_8)).getBoolean("broker_process_exit_observed"),"old exit unknown retained");
  check(android.net.LocalSocket.connections==0,"no socket or phone call");
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
 public static void main(String[] args)throws Exception{
  if(args.length!=3)throw new IllegalArgumentException("private input map, new host scratch and baseline|candidate required");
  scratch=Paths.get(args[1]);Files.createDirectory(scratch);
  check(Paths.get(JSONObject.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().toString().equals(System.getProperty("hepta.android.json.path")),"actual Android JSON loaded");captured=read(Paths.get(args[0]));
  if("baseline".equals(args[2])){
   try{captured.request();throw new AssertionError("old source unexpectedly accepted lost close");}
   catch(IOException expected){check("NOTES_EXPECTED_TRUE".equals(expected.getMessage()),"exact original exit requirement refusal");}
   verifyOriginals();
   System.out.println(new JSONObject().put("schema","hepta.notes-workflow-released-reply-lost-host.v1").put("mode","baseline").put("all_pass",true)
    .put("cases",1).put("assertions",assertions).put("exact_refusal","NOTES_EXPECTED_TRUE").put("phone_operations",0).put("current_absence_proven",false));return;
  }
  check("candidate".equals(args[2]),"closed mode");
  final PublicPersonalNotesAbsenceRecovery.Request request=captured.request();
  test("actual_23_originals_distinct_v12_and_exact_wire_roundtrip",()->{
   check(lost(request)&&request.workflowCloseFailed&&request.postModelDrained&&!request.workflowForeignHistoryRetirement
    &&!request.workflowPartialRetirement&&!request.workflowRetirementRefused&&!request.cancelledAfterActions,"distinct closed classification");
   PublicPersonalNotesAbsenceRecovery.Request decoded=PublicPersonalNotesAbsenceRecovery.fromWire(request.wire());
   check(lost(decoded)&&request.originalsSha256.equals(decoded.originalsSha256)&&request.currentControlSha256.equals(decoded.currentControlSha256),"wire binding");
   for(String role:captured.paths.keySet())check(Arrays.equals(request.original(role),decoded.original(role)),"exact original in wire "+role);
  });
  test("actual_model_unforced_generation_proof",()->{PublicPersonalNotesRecoveryClient.requireDrainedGeneration(request);check(true,"real original WorkerGenerationProof");});
  test("historical_release_log_never_promotes_app_exit_or_task",()->{
   JSONObject c=captured.json("cleanup"),result=captured.json("result"),i=request.recordedOwnedIdentity();
   check(!c.getBoolean("broker_process_exit_observed")&&c.get("broker_process_exit_code")==JSONObject.NULL,"old exit false/null");
   check("ACTIVE".equals(c.getJSONObject("last_broker_response").getString("state"))&&"state".equals(c.getJSONObject("last_broker_response").getString("operation")),"last actual response remains ACTIVE");
   check("blocked".equals(result.getString("status"))&&!result.getBoolean("cleanup_known")&&!result.getBoolean("completion_verified")
    &&!result.getBoolean("goal_independently_verified"),"task remains blocked");
   check(!i.getBoolean("historical_output_is_cleanup_proof")&&!i.getBoolean("historical_app_close_response_observed")
    &&!i.getBoolean("historical_background_cleanup_known")&&!i.getBoolean("historical_business_success"),"history grants no proof");
  });
  final int[] total={0},commandBytes={0};
  test("original_bundle_wire_complete_command_limits",()->{
   for(byte[] b:captured.input.values())total[0]+=b.length;
   String command="CLASSPATH="+quote(captured.controller.getString("source_path"))
     +" /system/bin/app_process / org.trillionnium.hepta.background.PublicPersonalNotesAbsenceMain --request "+quote(request.wire());
   commandBytes[0]=command.getBytes(StandardCharsets.UTF_8).length;
   check(total[0]<=262144&&request.wire().length()<=65536&&commandBytes[0]<60000,"original limits unchanged");
  });
  test("fresh_independent_two_sample_fixture_passes_actual_validator",()->{
   JSONObject p=PersonalNotesAbsenceHostTest.proof(request);
   JSONObject verified=PublicPersonalNotesAbsenceRecovery.validate(p,request,request.started+21,request.requestBoot);
   check(verified.getBoolean("current_absence_verified")&&!verified.getBoolean("historical_broker_release_observed"),"fresh fixture only");
   check(!captured.json("cleanup").getBoolean("cleanup_known"),"fixture never rewrites originals");
  });
  test("historical_terminal_alone_rejected_as_current_proof",()->{
   refused(()->PublicPersonalNotesAbsenceRecovery.validate(captured.json("broker_output"),request,request.started+21,request.requestBoot),"terminal is not absence");
  });
  test("current_startup_blocked_control_same_task_is_accepted_without_history_rewrite",()->{
   Inputs x=captured.copy();JSONObject oldControl=PublicPersonalNotesAbsenceRecovery.object(x.control);
   Map<String,Object> fields=new LinkedHashMap<String,Object>();java.util.Iterator<String> keys=oldControl.keys();
   while(keys.hasNext()){String key=keys.next();Object value=oldControl.get(key);fields.put(key,value==JSONObject.NULL?null:value);}
   SessionRecovery.Decision decision=SessionRecovery.evaluate(fields,captured.uid);
   check(!decision.allowNewTask&&decision.priorRecordValid&&request.taskId.equals(decision.taskId)
     &&request.ownerSha256.equals(decision.instructionSha256),"actual startup policy retains failed identity");
   // Explicit host-derived form of unchanged LocalTaskSession.snapshotSession:
   // lastResult is null at restart, no completion/result projection is restored.
   JSONObject control=new JSONObject().put("schema","hepta.local-session.v1").put("status","interrupted")
     .put("task_id",decision.taskId).put("origin",decision.origin).put("instruction_sha256",decision.instructionSha256)
     .put("debug_nonce_sha256",decision.nonceSha256==null?JSONObject.NULL:decision.nonceSha256)
     .put("task_authorization_sha256",JSONObject.NULL).put("task_authorization",JSONObject.NULL)
     .put("background_request",JSONObject.NULL).put("expected_scope_sha256",JSONObject.NULL).put("actual_scope_sha256",JSONObject.NULL)
     .put("state","上次会话中断且退出状态未确认；应用重启后已暂停新任务，不会自动恢复或重做。")
     .put("pending",false).put("running",false).put("blocked",true).put("cleanup_known",false)
     .put("app_uid",captured.uid).put("updated_wall_ms",1L).put("external_model",false).put("automatic_resume",false)
     .put("goal_independently_verified",false)
     .put("startup_recovery",new JSONObject().put("schema","hepta.session-recovery.v1").put("decision","blocked_interrupted")
       .put("reason",decision.reason).put("previous_status",decision.priorStatus)
       .put("previous_session_sha256",sha(captured.control)).put("read_error",JSONObject.NULL)
       .put("interruption_latch","control-session.interrupted.json").put("interruption_latch_observed",true)
       .put("interruption_latch_synced",true).put("recovery_pending_barrier_observed",false)
       .put("automatic_resume",false).put("native_cleanup_independently_observed",false));
   check(!control.has("completion_evidence")&&!control.has("task_result_reference"),"startup omits old result rather than rewriting it");
   x.control=raw(control);PublicPersonalNotesAbsenceRecovery.Request startup=x.request();
   check(lost(startup)&&startup.originalsSha256.equals(request.originalsSha256),"same old failure with separately bound current-control");
   check(!startup.currentControlSha256.equals(request.currentControlSha256),"current control separately hashed");
  });
  for(String role:new ArrayList<String>(captured.input.keySet()))reject("missing_original_"+role,x->x.input.remove(role));
  reject("extra_untyped_absence_receipt",x->x.input.put("host_absence",raw(new JSONObject().put("absent",true))));
  reject("oversized_original",x->x.input.put("workflow_result",new byte[PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL+1]));
  reject("wrong_terminal_sha",x->{byte[] b=x.input.get("broker_output");b[b.length-2]^=1;});
  reject("old_exit_claim_changed_to_success",x->{JSONObject c=x.json("cleanup");c.put("broker_process_exit_observed",true).put("broker_process_exit_code",0);x.set("cleanup",c);syncCleanup(x);});
  reject("old_exit_null_required",x->{JSONObject c=x.json("cleanup");c.put("broker_process_exit_code",0);x.set("cleanup",c);syncCleanup(x);});
  reject("different_close_error_not_classified",x->{JSONObject c=x.json("cleanup");c.put("cleanup_error","other transport failure");x.set("cleanup",c);syncCleanup(x);});
  reject("old_eof_not_complete",x->{JSONObject b=x.json("broker_receipt");b.put("eof_seen",false);x.set("broker_receipt",b);JSONObject c=x.json("cleanup");c.put("broker_output",b);x.set("cleanup",c);syncCleanup(x);});
  reject("broker_receipt_cannot_grant_release",x->{JSONObject b=x.json("broker_receipt");b.put("release_evidence",true);x.set("broker_receipt",b);JSONObject c=x.json("cleanup");c.put("broker_output",b);x.set("cleanup",c);syncCleanup(x);});
  rejectTerminal("terminal_not_released","state","CLEANUP_UNKNOWN");
  rejectTerminal("terminal_no_release_claim","release_confirmed",false);
  rejectTerminal("terminal_reason_not_client_close","reason","lease_expired");
  rejectTerminal("terminal_mixed_generation","generation","bbbbbbbb-cccc-4ddd-8eee-ffffffffffff");
  rejectTerminal("terminal_profile_state_forbidden","profile_cleanup",new JSONObject());
  rejectTerminal("terminal_profile_custody_forbidden","profile_custody_retained",true);
  rejectTerminal("terminal_unverified_task_absence","personal_notes_cleanup/live_tasks_absent",false);
  rejectTerminal("terminal_unverified_hidden_history","personal_notes_cleanup/nonphysical_hidden_history_preserved",false);
  rejectTerminal("terminal_extra_absence_shape","personal_notes_cleanup/absence_reads",3);
  rejectTerminal("terminal_pending_read","personal_notes_cleanup/pending_owned_reads",1);
  rejectTerminal("terminal_force_stop_forbidden","personal_notes_cleanup/force_stop_used",true);
  rejectTerminal("terminal_arbitrary_removal_forbidden","personal_notes_cleanup/arbitrary_task_removal_used",true);
  rejectTerminal("terminal_numeric_task_authority_forbidden","personal_notes_cleanup/token_retirement/numeric_task_id_authority",true);
  rejectTerminal("terminal_missing_retirement_return","personal_notes_cleanup/token_retirement/returned_task_ids",new JSONArray());
  rejectTerminal("terminal_duplicate_retirement","personal_notes_cleanup/token_retirement/attempted_task_ids",new JSONArray().put(1).put(1));
  reject("retirement_of_editor_instead_of_original_launch_refused",x->{JSONObject t=x.json("broker_output"),c=t.getJSONObject("personal_notes_cleanup");
   long id=c.getJSONArray("actual_observed_tasks").getJSONObject(1).getLong("task_id");
   c.getJSONObject("token_retirement").put("attempted_task_ids",new JSONArray().put(id)).put("returned_task_ids",new JSONArray().put(id));x.set("broker_output",t);syncTerminal(x);});
  reject("terminal_missing_one_owned_task",x->{JSONObject t=x.json("broker_output"),c=t.getJSONObject("personal_notes_cleanup");
   c.put("actual_observed_tasks",new JSONArray().put(c.getJSONArray("actual_observed_tasks").getJSONObject(0)));x.set("broker_output",t);syncTerminal(x);});
  reject("terminal_owned_token_changed",x->{JSONObject t=x.json("broker_output"),c=t.getJSONObject("personal_notes_cleanup");c.getJSONArray("actual_observed_tasks").getJSONObject(1).put("token_identity_in_broker",123);x.set("broker_output",t);syncTerminal(x);});
  rejectTerminal("terminal_retirement_after_expiry","personal_notes_cleanup/token_retirement/deadline_elapsed_ms",request.expires+1);
  rejectTerminal("terminal_old_last_after_retirement","personal_notes_cleanup/token_retirement/deadline_elapsed_ms",request.created);
  rejectTerminal("surface_is_not_verified_proof","public_surface_detach/provides_task_or_display_cleanup_proof",true);
  rejectTerminal("surface_cannot_resume","public_surface_detach/allows_input_or_model_resumption",true);
  rejectTerminal("surface_identity_unavailable","public_surface_detach/identity_source","NONE");
  rejectTerminal("surface_not_returned","public_surface_detach/api_returned",false);
  rejectTerminal("screen_wrong_display","public_screen_lease/display_id",0);
  rejectTerminal("screen_not_retired","public_screen_lease/admission_retired",false);
  rejectTerminal("screen_wrong_failure","public_screen_lease/failure","OTHER");
  rejectTerminal("screen_cannot_grant_cleanup","public_screen_lease/grants_cleanup_or_business_success",true);
  rejectTerminal("policy_wrong_phase","public_policy_diagnostics/first_failure/phase","FRAMEWORK");
  rejectTerminal("policy_wrong_exception","public_policy_diagnostics/first_failure/exception_class","java.lang.IllegalStateException");
  rejectTerminal("policy_unknown_cause","public_policy_diagnostics/first_failure/cause_class","unknown");
  rejectTerminal("policy_wrapped_failure","public_policy_diagnostics/first_failure/reflection_wrapper_count",1);
  rejectTerminal("policy_wrong_category","public_policy_diagnostics/first_failure/category","OTHER");
  rejectTerminal("policy_before_close","public_policy_diagnostics/first_failure/observed_elapsed_ms",request.created);
  rejectTerminal("runtime_wrong_phase","personal_notes_task_info_diagnostics/first_runtime_failure/phase","cleanup");
  rejectTerminal("runtime_wrong_reason","personal_notes_task_info_diagnostics/first_runtime_failure/reason","OTHER");
  rejectTerminal("runtime_root_failure","personal_notes_task_info_diagnostics/first_runtime_failure/actual_root_read_failure",new JSONObject());
  rejectTerminal("cleanup_failure_not_this_shape","personal_notes_task_info_diagnostics/first_cleanup_failure",new JSONObject());
  rejectLast("last_cannot_be_close","operation","close");
  rejectLast("last_cannot_claim_released","state","RELEASED");
  rejectLast("last_cannot_be_dispatched","dispatched",true);
  rejectLast("last_cannot_be_error","ok",false);
  rejectLast("last_cannot_be_closing","public_scope_closing",true);
  rejectLast("last_scope_must_be_active","public_scope_admission_retired",true);
  rejectLast("last_no_old_release_return","personal_notes_cleanup/release_api_returned",true);
  rejectLast("last_no_old_absence","personal_notes_cleanup/absence_reads",1);
  rejectLast("last_no_old_cleanup","personal_notes_cleanup/cleanup_known",true);
  rejectLast("last_custody_required","personal_notes_cleanup/custodian_retained",false);
  rejectLast("last_no_previous_diagnostic","public_policy_diagnostics/first_failure",new JSONObject());
  rejectField("launch_target_uid_changed","bootstrap","last_broker_response/personal_notes_cleanup/target_uid",1);
  rejectField("created_response_not_active","step_action","background_session/last_broker_response/state","RELEASED");
  for(String field:new String[]{"cleanup_known","completion_verified","goal_independently_verified","model_reported_success"})
   rejectField("old_business_cannot_be_promoted_"+field,"result",field,true);
  rejectField("additional_model_round_not_covered","result","steps",2);
  rejectField("completion_not_requested","result","controller_completion_requested",false);
  rejectField("pending_native_worker","result","native_cancel_worker_pending_at_terminal",true);
  rejectField("pending_action_worker","result","action_worker_pending_at_terminal",true);
  rejectField("native_cleanup_unknown","result","native_cancellation/native_cleanup_known",false);
  rejectField("model_not_complete","model_request_receipt","inference_completed",false);
  rejectField("model_forced","model_request_receipt","force_destroy_sent",true);
  rejectField("native_session_signalled","native_session_receipt","signal_observed",9);
  rejectField("generation_unknown","generation_cleanup_receipt","unknown_count",1);
  rejectField("generation_forced_kill","generation_cleanup_receipt","kill_attempts",1);
  reject("generation_identity_raw_changed",x->{byte[] b=x.input.get("generation_identity");b[b.length-2]^=1;});
  reject("session_restart_not_allowed",x->{JSONObject o=x.json("model_session_receipt");o.put("automatic_restart",true);x.set("model_session_receipt",o);x.refreshSessionProjection();});
  rejectField("workflow_not_verified","workflow_result","workflow_verified",false);
  rejectField("workflow_grant_not_retired","workflow_result","grant_retired",false);
  rejectField("child_two_not_drained","child_2_action","action_execution/worker_drained",false);
  rejectField("child_one_force_replay","child_1_action","action_execution/automatic_redispatch",true);
  rejectField("completion_no_pending_cleanup","completion_candidate","terminal_pending_native_identity_and_cleanup",false);
  reject("lease_not_expired",x->x.now=request.expires);
  reject("grace_boundary_not_passed",x->x.now=request.expires+2000);
  reject("wrong_boot",x->x.boot=request.oldBoot+1);
  test("new_request_deadline_cannot_be_extended",()->{refused(()->request.requireFence(request.deadline,request.requestBoot),"exact deadline");});
  test("new_request_started_lower_bound",()->{refused(()->request.requireFence(request.started-1,request.requestBoot),"before started");});
  reject("current_control_other_task",x->{JSONObject o=PublicPersonalNotesAbsenceRecovery.object(x.control);o.put("task_id",new String(new char[32]).replace('\0','b'));x.control=raw(o);});
  reject("current_control_running",x->{JSONObject o=PublicPersonalNotesAbsenceRecovery.object(x.control);o.put("running",true);x.control=raw(o);});
  rejectWire("cannot_downgrade_v11","hepta.personal-notes-absence-request.v11-workflow-foreign-history",false);
  rejectWire("cannot_downgrade_v3",PublicPersonalNotesAbsenceRecovery.WORKFLOW_CLOSE_REQUEST_SCHEMA,false);
  rejectWire("cannot_downgrade_v1",PublicPersonalNotesAbsenceRecovery.REQUEST_SCHEMA,false);
  rejectWire("cannot_append_wire","hepta.personal-notes-absence-request.v12-workflow-released-reply-lost",true);
  for(String key:new String[]{"automatic_resume","broker_release_response","historical_broker_release_observed","business_success","rewrites_original_task_result"})
   rejectProof("fresh_proof_no_"+key,(p,r)->p.put(key,true));
  rejectProof("missing_after_sample",(p,r)->p.remove("after"));
  rejectProof("before_process_incomplete",(p,r)->p.getJSONObject("before").getJSONObject("process").put("complete",false));
  rejectProof("after_creator_present",(p,r)->p.getJSONObject("after").getJSONObject("process").put("old_creator_absent",false));
  rejectProof("after_proc_inventory_empty",(p,r)->p.getJSONObject("after").getJSONObject("process").put("process_count",0));
  rejectProof("old_display_present",(p,r)->p.getJSONObject("after").getJSONObject("displays").getJSONArray("rows").put(new JSONObject().put("id",r.displayId).put("name",r.displayName).put("unique_id","virtual:old").put("flags",0).put("state",1)));
  rejectProof("old_task_present",(p,r)->p.getJSONObject("after").getJSONObject("live").getJSONArray("roots").getJSONObject(0).put("id",r.recordedTaskIds.iterator().next()));
  rejectProof("another_notes_task_present",(p,r)->p.getJSONObject("after").getJSONObject("live").getJSONArray("roots").getJSONObject(0).put("base","com.motorola.stylus/.Other"));
  rejectProof("target_uid_changed",(p,r)->p.getJSONObject("after").getJSONObject("target_installation").put("uid",r.targetUid+1));
  rejectProof("main_changed",(p,r)->p.getJSONObject("after").getJSONObject("physical").put("0",sha(new byte[]{1})));
  rejectProof("cover_changed",(p,r)->p.getJSONObject("after").getJSONObject("physical").put("1",sha(new byte[]{2})));
  rejectProof("stale_before_sample",(p,r)->p.getJSONObject("before").put("started_elapsed_ms",r.started-1));
  rejectProof("reordered_samples",(p,r)->p.getJSONObject("after").put("started_elapsed_ms",r.started+2));
  rejectProof("changed_deadline",(p,r)->p.put("deadline_elapsed_ms",r.deadline+1));
  rejectProof("changed_boot",(p,r)->p.put("current_boot_count",r.requestBoot+1));
  rejectProof("unknown_proof_schema",(p,r)->p.put("schema",PublicPersonalNotesAbsenceRecovery.SCHEMA));
  rejectProof("unrelated_proof_source",(p,r)->p.put("source",PublicPersonalNotesAbsenceRecovery.SOURCE));
  rejectProof("original_hash_mixed",(p,r)->p.put("originals_sha256",sha(new byte[]{3})));
  test("actual_task_entries_are_covered",()->{taskEntries(captured.paths.get("result").getParent().toFile(),true,true);check(true,"full original directory");});
  test("typed_client_archive_and_background_consumer",()->consumerRoundtrip(request));
  test("actual_ack_transaction_and_new_idle_consumer",NotesWorkflowReleasedReplyLostHostTest::acknowledgementContract);
  test("all_private_original_bytes_preserved",NotesWorkflowReleasedReplyLostHostTest::verifyOriginals);
  System.out.println(new JSONObject().put("schema","hepta.notes-workflow-released-reply-lost-host.v1").put("mode","candidate").put("all_pass",true)
   .put("cases",cases).put("assertions",assertions).put("case_names",new JSONArray(names)).put("rejected_mutations",new JSONArray(rejections))
   .put("actual_private_original_roles",23).put("actual_current_control_additional",true).put("raw_bundle_bytes",total[0])
   .put("wire_chars",request.wire().length()).put("complete_command_bytes",commandBytes[0]).put("complete_command_limit",60000)
   .put("request_roundtrip_exact",true).put("normal_model_generation_validator_passed",true).put("original_byte_preservation",true)
   .put("client_and_background_dynamic_source_passed",true).put("actual_ack_new_idle_consumer_passed",true)
   .put("controller_fixture",true).put("clock_fixture",true).put("current_absence_fixture",true).put("consumer_private_files_fixture",true)
   .put("negative_inputs_authored_in_memory",true).put("portable_without_private_inputs",false).put("phone_operations",0)
   .put("current_absence_proven",false).put("app_recovery_completed",false).put("business_success_claimed",false).toString());
 }
}
