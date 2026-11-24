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
public final class NotesWorkflowPartialRetirementHostTest {
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
 private static void refreshClose(Inputs x)throws Exception{
  // Coherent authored mutations update every linked close projection. They never touch actual files.
  JSONObject cleanup=x.json("cleanup"),last=cleanup.getJSONObject("last_broker_response"),terminal=x.json("broker_output");
  terminal.put("personal_notes_cleanup",last.getJSONObject("personal_notes_cleanup"));
  terminal.put("personal_notes_task_info_diagnostics",last.getJSONObject("personal_notes_task_info_diagnostics"));
  x.set("broker_output",terminal);byte[] output=x.input.get("broker_output");
  JSONObject broker=x.json("broker_receipt");broker.put("observed_bytes",output.length).put("stored_bytes",output.length).put("stored_sha256",sha(output));
  x.set("broker_receipt",broker);cleanup.put("broker_output",broker);x.set("cleanup",cleanup);
  JSONObject result=x.json("result");result.put("background_cleanup",cleanup);
  JSONObject session=new JSONObject(cleanup.toString());session.remove("cleanup_known");session.remove("cleanup_error");
  result.put("background_session",session);x.set("result",result);
 }
 public static void main(String[] args)throws Exception{
  if(args.length!=2)throw new IllegalArgumentException("private input map and empty host scratch are required");
  scratch=Paths.get(args[1]);Files.createDirectory(scratch);captured=read(Paths.get(args[0]));
  final PublicPersonalNotesAbsenceRecovery.Request request=captured.request();
  test("actual_23_originals_v8_roundtrip",()->{
   check(request.workflowPartialRetirement&&request.workflowCloseFailed&&request.postModelDrained&&request.inputHashes().length()==23,"typed v8 request");
   PublicPersonalNotesAbsenceRecovery.Request decoded=PublicPersonalNotesAbsenceRecovery.fromWire(request.wire());
   check(decoded.workflowPartialRetirement&&decoded.workflowCloseFailed&&decoded.postModelDrained,"decoded v8 flags");
   check(request.originalsSha256.equals(decoded.originalsSha256)&&request.currentControlSha256.equals(decoded.currentControlSha256),"decoded hashes");
   for(String role:captured.paths.keySet())check(Arrays.equals(request.original(role),decoded.original(role)),"decoded bytes");
  });
  test("actual_broker_eof_successor_keeps_original_cleanup_result_and_bin",()->{
   Inputs value=captured.copy();JSONObject broker=value.json("broker_receipt");broker.put("eof_seen",true);value.set("broker_receipt",broker);
   PublicPersonalNotesAbsenceRecovery.Request after=value.request();
   check(after.workflowPartialRetirement&&after.workflowCloseFailed&&after.postModelDrained&&!after.cancelledAfterActions,"same normal v8 kind after actual EOF");
   for(String role:new String[]{"cleanup","result","broker_output"})check(Arrays.equals(after.original(role),captured.input.get(role)),"historical bytes preserved after EOF: "+role);
   check(!PublicPersonalNotesAbsenceRecovery.object(after.original("cleanup")).getBoolean("broker_process_exit_observed"),"historical broker exit remains unknown");
   check(!after.recordedOwnedIdentity().getBoolean("historical_business_success"),"EOF is not business success");
   check(after.wire().equals(PublicPersonalNotesAbsenceRecovery.fromWire(after.wire()).wire()),"EOF successor exact wire roundtrip");
  });
  reject("eof_successor_changed_process_reference",value->{JSONObject broker=value.json("broker_receipt");broker.put("eof_seen",true).put("process_reference",broker.getLong("process_reference")+1);value.set("broker_receipt",broker);});
  reject("eof_successor_changed_command_hash",value->{JSONObject broker=value.json("broker_receipt");broker.put("eof_seen",true).put("command_sha256",new String(new char[64]).replace('\0','a'));value.set("broker_receipt",broker);});
  reject("eof_successor_changed_stored_bytes",value->{JSONObject broker=value.json("broker_receipt");broker.put("eof_seen",true).put("stored_bytes",broker.getLong("stored_bytes")+1);value.set("broker_receipt",broker);});
  reject("eof_successor_changed_numeric_type",value->{JSONObject broker=value.json("broker_receipt");broker.put("eof_seen",true).put("process_reference",broker.getString("process_reference"));value.set("broker_receipt",broker);});
  reject("eof_successor_boolean_type_required",value->{JSONObject broker=value.json("broker_receipt");broker.put("eof_seen",1);value.set("broker_receipt",broker);});
  test("actual_history_remains_failed_and_exit_unknown",()->{
   JSONObject result=captured.json("result"),cleanup=captured.json("cleanup"),broker=captured.json("broker_receipt");
   check("blocked".equals(result.getString("status"))&&!result.getBoolean("cleanup_known")&&!result.getBoolean("completion_verified")
    &&!result.getBoolean("goal_independently_verified"),"business failure must remain");
   check(result.getBoolean("controller_completion_requested")&&result.getInt("steps")==1,"preserved one-step workflow history");
   check(!cleanup.getBoolean("broker_process_exit_observed")&&cleanup.get("broker_process_exit_code")==JSONObject.NULL
    &&!broker.getBoolean("eof_seen"),"old exit is not fabricated");
  });
  test("normal_worker_generation_validator",()->{PublicPersonalNotesRecoveryClient.requireDrainedGeneration(request);check(true,"normal generation");});
  final int[] commandBytes={0};final int[] totalBytes={0};
  test("unchanged_wire_and_complete_command_limits",()->{
   for(byte[] bytes:captured.input.values())totalBytes[0]+=bytes.length;
   String command="CLASSPATH="+quote(captured.controller.getString("source_path"))
     +" /system/bin/app_process / org.trillionnium.hepta.background.PublicPersonalNotesAbsenceMain --request "+quote(request.wire());
   commandBytes[0]=command.getBytes(StandardCharsets.UTF_8).length;
   check(totalBytes[0]<=262144&&request.wire().length()<=65536&&commandBytes[0]<60000,"original hard limits");
  });
  test("request_input_bytes_defensively_copied",()->{
   Inputs copy=captured.copy();PublicPersonalNotesAbsenceRecovery.Request r=copy.request();
   byte[] expected=r.original("workflow_result");copy.input.get("workflow_result")[0]^=1;copy.control[0]^=1;
   check(Arrays.equals(expected,r.original("workflow_result")),"input clone");
   byte[] exposed=r.original("workflow_result");exposed[0]^=1;check(Arrays.equals(expected,r.original("workflow_result")),"returned clone");
   check(Arrays.equals(captured.control,r.original("current_control")),"control clone");
  });
  test("historical_request_cannot_supply_current_absence",()->{
   try{PublicPersonalNotesAbsenceRecovery.validate(new JSONObject(),request,request.started+1,request.requestBoot);
    throw new AssertionError("empty current absence accepted");}catch(Exception expected){check(true,"fresh proof required");}
  });
  for(String role:new ArrayList<String>(captured.input.keySet()))
   reject("missing_original_"+role,x->x.input.remove(role));
  reject("operator_retirement_receipt_is_not_an_original",x->x.input.put("operator_retirement",raw(new JSONObject().put("retired",true))));
  reject("empty_workflow_original",x->x.input.put("workflow_result",new byte[0]));
  reject("oversized_original",x->x.input.put("workflow_result",new byte[PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL+1]));
  rejectField("controller_completion_flag_cannot_be_removed","result","controller_completion_requested",false);
  for(String field:new String[]{"cleanup_known","completion_verified","model_reported_success","goal_independently_verified","model_done_synthesized"})
   rejectField("cannot_promote_result_"+field,"result",field,true);
  for(String field:new String[]{"observation_read_worker_pending_at_terminal","action_worker_pending_at_terminal","native_cancel_worker_pending_at_terminal"})
   rejectField("pending_worker_"+field,"result",field,true);
  rejectField("additional_model_step","result","steps",2);
  rejectField("native_cleanup_unknown","result","native_cancellation/native_cleanup_known",false);
  rejectField("native_signal_requested","result","native_cancellation/signal_entered",true);
  rejectField("wrong_close_operation","cleanup","last_broker_response/operation","notes.create");
  rejectField("wrong_close_reason","cleanup","last_broker_response/terminal_reason","lease_expired");
  rejectField("release_attempt_forbidden","cleanup","last_broker_response/personal_notes_cleanup/release_api_returned",true);
  rejectField("close_admission_not_retired","cleanup","last_broker_response/public_scope_admission_retired",false);
  for(String key:new String[]{"release_api_entered","release_api_returned","arbitrary_task_removal_used","force_stop_used"})
   reject("coherent_refusal_cannot_claim_"+key,x->{JSONObject cleanup=x.json("cleanup");cleanup.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").put(key,true);x.set("cleanup",cleanup);refreshClose(x);});
  reject("coherent_partial_requires_pre_release_verified",x->{JSONObject c=x.json("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").put("pre_release_tasks_verified",false);x.set("cleanup",c);refreshClose(x);});
  for(String key:new String[]{"numeric_task_id_authority","detached_recent_removal_supported"}){
   reject("partial_cannot_claim_"+key,x->{JSONObject c=x.json("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement").put(key,true);x.set("cleanup",c);refreshClose(x);});
  }
  reject("partial_cannot_claim_prior_absence",x->{JSONObject c=x.json("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement").put("pre_release_absence_reads",1);x.set("cleanup",c);refreshClose(x);});
  reject("partial_framework_cleanup_flag_required",x->{JSONObject c=x.json("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement").put("framework_process_cleanup_possible",false);x.set("cleanup",c);refreshClose(x);});
  for(String key:new String[]{"attempted_task_ids","returned_task_ids"}){
   reject("partial_empty_"+key,x->{JSONObject c=x.json("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement").put(key,new JSONArray());x.set("cleanup",c);refreshClose(x);});
   reject("partial_duplicate_"+key,x->{JSONObject c=x.json("cleanup");JSONObject r=c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement");long id=r.getJSONArray(key).getLong(0);r.put(key,new JSONArray().put(id).put(id));x.set("cleanup",c);refreshClose(x);});
   reject("partial_foreign_"+key,x->{JSONObject c=x.json("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement").put(key,new JSONArray().put(999999));x.set("cleanup",c);refreshClose(x);});
   reject("partial_string_"+key,x->{JSONObject c=x.json("cleanup");JSONObject r=c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement");r.put(key,new JSONArray().put(String.valueOf(r.getJSONArray(key).getLong(0))));x.set("cleanup",c);refreshClose(x);});
  }
  reject("partial_deadline_after_original_expiry",x->{JSONObject c=x.json("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement").put("deadline_elapsed_ms",x.json("journal").getLong("expires_elapsed_ms")+1);x.set("cleanup",c);refreshClose(x);});
  reject("partial_failure_after_retirement_deadline",x->{JSONObject c=x.json("cleanup");JSONObject last=c.getJSONObject("last_broker_response");last.getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement").put("deadline_elapsed_ms",last.getJSONObject("personal_notes_task_info_diagnostics").getJSONObject("first_cleanup_failure").getLong("observed_elapsed_ms"));x.set("cleanup",c);refreshClose(x);});
  test("partial_identity_preserves_effect_without_cleanup_claim",()->{
   JSONObject i=request.recordedOwnedIdentity();JSONObject c=captured.json("cleanup").getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement");
   check(!request.workflowRetirementRefused&&request.workflowPartialRetirement,"distinct v8 flag");
   check(i.getBoolean("historical_partial_task_retirement_observed")&&i.getBoolean("historical_pre_release_tasks_verified"),"original partial effect preserved");
   check(!i.getBoolean("historical_retirement_release_entered")&&!i.getBoolean("historical_background_cleanup_known")&&!i.getBoolean("historical_business_success"),"no historical promotion");
   check(PublicPersonalNotesAbsenceRecovery.same(i.getJSONArray("historical_attempted_task_ids"),c.getJSONArray("attempted_task_ids"))&&PublicPersonalNotesAbsenceRecovery.same(i.getJSONArray("historical_returned_task_ids"),c.getJSONArray("returned_task_ids")),"exact partial arrays");
   check("fresh_workflow_partial_retirement_personal_notes_absence_with_preserved_failure".equals(request.source())&&"hepta.personal-notes-workflow-partial-retirement-current-absence.v1".equals(request.proofSchema()),"distinct v8 source and proof");
  });
  reject("coherent_unrelated_failure_not_admitted",x->{JSONObject c=x.json("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup").put("failure","ANOTHER_FAILURE");x.set("cleanup",c);refreshClose(x);});
  reject("coherent_diagnostic_reason_mismatch",x->{JSONObject c=x.json("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_task_info_diagnostics").getJSONObject("first_cleanup_failure").put("reason","ANOTHER_FAILURE");x.set("cleanup",c);refreshClose(x);});
  reject("coherent_root_read_failure_not_admitted",x->{JSONObject c=x.json("cleanup");c.getJSONObject("last_broker_response").getJSONObject("personal_notes_task_info_diagnostics").getJSONObject("first_cleanup_failure").put("actual_root_read_failure",new JSONObject().put("phase","failed"));x.set("cleanup",c);refreshClose(x);});

  rejectField("early_response_not_active","bootstrap","last_broker_response/state","CLEANUP_UNKNOWN");
  rejectField("early_wrong_owned_uid","bootstrap","last_broker_response/personal_notes_cleanup/target_uid",1);
  rejectField("parent_not_active","step_action","background_session/last_broker_response/state","CLEANUP_UNKNOWN");
  rejectField("parent_nested_broker_mixed","step_action","fixed_intent/broker_response/generation","11111111-2222-4333-8444-555555555555");
  rejectField("parent_projection_unexpected_key","step_action","fixed_intent/unexpected_key",true);
  rejectField("parent_projection_result_changed","step_action","fixed_intent/result","completed");
  for(String field:new String[]{"accepted","dispatched","model_issued"})
   rejectField("parent_not_"+field,"step_action",field,false);
  rejectField("parent_stale","step_action","stale",true);
  for(String field:new String[]{"effect_entered","effect_returned","api_accepted","worker_drained","callback_published","callback_authority_current"})
   rejectField("parent_action_not_"+field,"step_action","action_execution/"+field,false);
  rejectField("parent_action_redispatch","step_action","action_execution/automatic_redispatch",true);
  rejectField("parent_action_late_drain","step_action","action_execution/worker_drained_elapsed_ms",Long.MAX_VALUE);
  rejectField("parent_wrong_action_uid_scope","step_action","action_execution/display_id",0);
  rejectField("parent_authorization_cancelled","step_action","task_authorization/callback_cancelled",true);
  rejectField("parent_authorization_disallowed","step_action","task_authorization/last_check/allowed",false);
  rejectField("fixed_attempt_replay_allowed","fixed_intent_attempt","automatic_retry_allowed",true);
  for(String field:new String[]{"grant_consumed","grant_retired","workflow_verified","accepted_as_completion_proof"})
   rejectField("workflow_not_"+field,"workflow_result",field,false);
  for(String field:new String[]{"grants_tool_authority","model_issued","model_done_synthesized","native_model_done_synthesized","persistent_storage_bytes_verified"})
   rejectField("workflow_cannot_claim_"+field,"workflow_result",field,true);
  rejectField("workflow_display_mixed","workflow_result","display_id",0);
  rejectField("workflow_stable_tree_mixed","workflow_result","stable_readback/tree_sha256",String.join("",Collections.nCopies(64,"0")));
  rejectField("grant_not_consumed","workflow_grant","grant_consumed",false);
  rejectField("grant_live_record_cannot_claim_retired","workflow_grant","grant_retired",true);
  for(String key:new String[]{"workflow_id","task_id","parent_step","parent_model_run_id","parent_observation_id","created_observation_id",
    "parent_create_after_observation_id","workflow_initial_observation_id","parent_fixed_intent_attempt_id","owner_sha256","contract_sha256",
    "task_authorization_sha256","body_sha256","target_package","target_uid","target_apk_sha256","display_id","background_generation"}){
   reject("grant_missing_"+key,x->{JSONObject o=x.json("workflow_grant");check(o.has(key),"expected grant scope key");o.remove(key);x.set("workflow_grant",o);});
  }
  rejectField("final_authorization_check_mixed","result","task_authorization/last_check/action","back");
  for(int i=1;i<=2;i++){
   final String action="child_"+i+"_action",proof="child_"+i+"_proof";final int index=i;
   rejectField("child_"+i+"_not_accepted",action,"accepted",false);
   rejectField("child_"+i+"_stale",action,"stale",true);
   rejectField("child_"+i+"_model_issued",action,"model_issued",true);
   rejectField("child_"+i+"_wrong_ordinal",action,"child_ordinal",3);
   rejectField("child_"+i+"_wrong_display",action,"action_execution/display_id",0);
   for(String field:new String[]{"worker_drained","effect_returned","callback_published","callback_authority_current"})
    rejectField("child_"+i+"_not_"+field,action,"action_execution/"+field,false);
   rejectField("child_"+i+"_late_drain",action,"action_execution/worker_drained_elapsed_ms",Long.MAX_VALUE);
   rejectField("child_"+i+"_authorization_cancelled",action,"task_authorization/callback_cancelled",true);
   rejectField("child_"+i+"_authorization_disallowed",action,"task_authorization/last_check/allowed",false);
   rejectField("child_"+i+"_receipt_mixed",proof,"child/display_id",0);
   rejectField("child_"+i+"_proof_live_lease_false",proof,"live_lease_verified",false);
   reject("child_"+i+"_operation_reused",x->{JSONObject o=x.json(action),prior=x.json(index==1?"step_action":"child_1_action");
    o.getJSONObject("action_execution").put("operation_id",prior.getJSONObject("action_execution").getString("operation_id"));x.set(action,o);});
  }
  reject("child_records_swapped",x->{byte[] first=x.input.get("child_1_action");x.input.put("child_1_action",x.input.get("child_2_action"));x.input.put("child_2_action",first);});
  rejectField("completion_candidate_claims_model_done","completion_candidate","model_done_synthesized",true);
  rejectField("completion_candidate_no_pending_cleanup","completion_candidate","terminal_pending_native_identity_and_cleanup",false);
  rejectField("completion_identity_wrong_uid","completion_identity","uid",1);
  rejectField("completion_history_claims_cleanup","result","completion_evidence/terminal_binding_and_cleanup_verified",true);
  rejectField("completion_history_grants_authority","result","completion_evidence/grants_tool_authority",true);
  for(String field:new String[]{"worker_drained","callback_authority_current"})
   rejectField("final_action_"+field,"result","last_action_execution/"+field,false);
  rejectField("model_request_forced","model_request_receipt","force_destroy_sent",true);
  rejectField("model_request_incomplete","model_request_receipt","inference_completed",false);
  for(String field:new String[]{"force_destroy_sent","parent_force_destroy_sent","automatic_restart","cross_task_reuse"}){
   reject("normal_session_"+field,x->{JSONObject o=x.json("model_session_receipt");o.put(field,true);x.set("model_session_receipt",o);x.refreshSessionProjection();});
  }
  reject("normal_session_generation_not_unforced",x->{JSONObject o=x.json("model_session_receipt");o.put("generation_unforced",false);x.set("model_session_receipt",o);x.refreshSessionProjection();});
  rejectField("native_session_force_signal","native_session_receipt","signal_observed",9);
  rejectField("generation_unknown","generation_cleanup_receipt","unknown_count",1);
  rejectField("generation_forced_kill","generation_cleanup_receipt","kill_attempts",1);
  reject("generation_identity_raw_changed",x->{byte[] b=x.input.get("generation_identity");b[b.length-2]^=1;});
  reject("current_controller_old_task_mixed",x->{JSONObject o=PublicPersonalNotesAbsenceRecovery.object(x.control);o.put("task_id","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");x.control=raw(o);});
  reject("current_session_running",x->{JSONObject o=PublicPersonalNotesAbsenceRecovery.object(x.control);o.put("running",true);x.control=raw(o);});
  reject("unexpired_original_lease",x->x.now=x.json("journal").getLong("expires_elapsed_ms"));
  reject("request_boot_before_original",x->x.boot=Math.max(0,x.boot-1));
  rejectWire("v8_cannot_impersonate_v7","hepta.personal-notes-absence-request.v7-workflow-retirement-refused",false);
  rejectWire("v8_cannot_downgrade_v3",PublicPersonalNotesAbsenceRecovery.WORKFLOW_CLOSE_REQUEST_SCHEMA,false);
  rejectWire("v8_cannot_downgrade_v2",PublicPersonalNotesAbsenceRecovery.DRAINED_REQUEST_SCHEMA,false);
  rejectWire("v8_cannot_downgrade_v1",PublicPersonalNotesAbsenceRecovery.REQUEST_SCHEMA,false);
  rejectWire("wire_cannot_add_bytes",PublicPersonalNotesAbsenceRecovery.WORKFLOW_CLOSE_REQUEST_SCHEMA,true);
  final File actualTask=captured.paths.get("result").getParent().toFile();
  test("actual_task_entry_allowlist",()->{taskEntries(actualTask,true,true);check(true,"actual entries");});
  for(String addition:new String[]{"step-02-model-0.json","step-01-tool-child-03-action.json","native-app-uncovered.json",
      "controller-completion-extra.json","fixed-intent-02-attempt.json","ime-submit-01.json"}){
   test("task_entry_rejects_"+addition,()->{
    Path d=Files.createDirectory(scratch.resolve("entries-"+cases));String[] leaves=actualTask.list();check(leaves!=null,"actual entries available");
    for(String leaf:leaves)Files.createFile(d.resolve(leaf));Files.createFile(d.resolve(addition));
    try{taskEntries(d.toFile(),true,true);throw new AssertionError("uncovered task entry admitted");}catch(Exception expected){check(true,"extra entry rejected");}
   });
  }
  test("workflow_branch_requires_post_model",()->{try{taskEntries(actualTask,false,true);throw new AssertionError("workflow without model admitted");}catch(Exception expected){check(true,"post model required");}});
  test("all_private_input_bytes_preserved",NotesWorkflowPartialRetirementHostTest::verifyOriginals);
  System.out.println(new JSONObject().put("schema","hepta.notes-workflow-partial-retirement-host.v1").put("all_pass",true)
   .put("cases",cases).put("assertions",assertions).put("case_names",new JSONArray(names)).put("rejected_mutations",new JSONArray(rejections))
   .put("actual_private_original_roles",23).put("actual_current_control_additional",true).put("raw_bundle_bytes",totalBytes[0])
   .put("wire_chars",request.wire().length()).put("complete_command_bytes",commandBytes[0]).put("complete_command_limit",60000)
   .put("request_roundtrip_exact",true).put("normal_model_generation_validator_passed",true).put("original_byte_preservation",true)
   .put("controller_fixture",true).put("clock_fixture",true).put("negative_inputs_authored_in_memory",true)
   .put("portable_without_private_inputs",false).put("phone_operations",0).put("current_absence_proven",false)
   .put("business_success_claimed",false).toString());
 }
}
