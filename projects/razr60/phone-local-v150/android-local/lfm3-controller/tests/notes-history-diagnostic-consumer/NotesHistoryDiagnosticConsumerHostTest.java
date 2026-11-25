package org.trillionnium.hepta.local;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Host-only compatibility of exact producer terminals with private archived inputs.
 * Private maps and derived current-control fixtures are never repository fixtures. */
public final class NotesHistoryDiagnosticConsumerHostTest {
 private static int cases, assertions;
 private static final List<String> names=new ArrayList<String>();
 private static final JSONArray metrics=new JSONArray();
 private static final JSONArray diagnosticMetrics=new JSONArray();
 private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
 private static String sha(byte[] b){return HeptaAccessibilityService.sha(b);}
 private static byte[] raw(JSONObject o){return o.toString().getBytes(StandardCharsets.UTF_8);}
 private static boolean equal(Object a,Object b)throws Exception{
  if(a==JSONObject.NULL||b==JSONObject.NULL)return a==JSONObject.NULL&&b==JSONObject.NULL;
  if(a instanceof JSONObject&&b instanceof JSONObject){
   JSONObject l=(JSONObject)a,r=(JSONObject)b;if(l.length()!=r.length())return false;
   Iterator<String> keys=l.keys();while(keys.hasNext()){String k=keys.next();if(!r.has(k)||!equal(l.get(k),r.get(k)))return false;}return true;
  }
  if(a instanceof JSONArray&&b instanceof JSONArray){
   JSONArray l=(JSONArray)a,r=(JSONArray)b;if(l.length()!=r.length())return false;
   for(int i=0;i<l.length();i++)if(!equal(l.get(i),r.get(i)))return false;return true;
  }
  return a!=null&&b!=null&&a.getClass()==b.getClass()&&a.equals(b);
 }
 private static final class Inputs{
  final Map<String,byte[]> input=new LinkedHashMap<String,byte[]>();
  final Map<String,Path> paths=new LinkedHashMap<String,Path>();
  byte[] control;JSONObject controller;int uid,boot;long now;
  Inputs copy()throws Exception{
   Inputs r=new Inputs();for(Map.Entry<String,byte[]>e:input.entrySet())r.input.put(e.getKey(),e.getValue().clone());
   r.paths.putAll(paths);r.control=control.clone();r.controller=new JSONObject(controller.toString());r.uid=uid;r.boot=boot;r.now=now;return r;
  }
  JSONObject json(String role)throws Exception{return PublicPersonalNotesAbsenceRecovery.object(input.get(role));}
  PublicPersonalNotesAbsenceRecovery.Request request()throws Exception{
   return PublicPersonalNotesAbsenceRecovery.request(input,control,controller,uid,"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",now,boot);
  }
 }
 private static Inputs read(Path map)throws Exception{
  JSONObject m=new JSONObject(new String(Files.readAllBytes(map),StandardCharsets.UTF_8));
  check("hepta.actual-private-original-input-map.v1".equals(m.getString("schema")),"actual input map schema");
  Inputs x=new Inputs();JSONArray rows=m.getJSONArray("rows");Set<String>seen=new HashSet<String>();
  for(int i=0;i<rows.length();i++){
   JSONObject row=rows.getJSONObject(i);String role=row.getString("role");Path p=Paths.get(row.getString("host_path"));byte[] b=Files.readAllBytes(p);
   check(seen.add(role)&&b.length==row.getInt("bytes")&&sha(b).equals(row.getString("sha256")),"actual role hash");
   x.paths.put(role,p);if("current_control".equals(role))x.control=b;else x.input.put(role,b);
  }
  check(x.input.size()==23&&x.control!=null,"23 historical roles plus current control");
  JSONObject j=x.json("journal");x.uid=j.getInt("app_uid");x.boot=j.getInt("boot_count");x.now=j.getLong("expires_elapsed_ms")+3000;
  x.controller=new PersonalNotesAbsenceHostTest.Fixture().controller;
  x.controller.put("uid",x.uid).put("source_path","/data/app/~~explicit-host-controller-fixture==/org.trillionnium.hepta.local-source-fixture==/base.apk");
  return x;
 }
 private static byte[] formatLike(byte[] original,JSONObject changed)throws Exception{
  JSONObject before=PublicPersonalNotesAbsenceRecovery.object(original);
  for(int indent:new int[]{-1,2})for(String tail:new String[]{"","\n"}){
   byte[] formatted=((indent<0?before.toString():before.toString(indent))+tail).getBytes(StandardCharsets.UTF_8);
   if(Arrays.equals(original,formatted))return ((indent<0?changed.toString():changed.toString(indent))+tail).getBytes(StandardCharsets.UTF_8);
  }
  throw new IllegalStateException("actual serializer format could not be preserved");
 }
 private static byte[] startupControl(Inputs x)throws Exception{
  JSONObject old=PublicPersonalNotesAbsenceRecovery.object(x.control);
  String archive="control-session.json."+sha(x.control)+".json";
  JSONObject row=new JSONObject().put("original_name","control-session.json")
   .put("path","/data/user/0/org.trillionnium.hepta.local/files/session-recovery/"+archive)
   .put("sha256",sha(x.control)).put("bytes",x.control.length);
  JSONObject recovery=new JSONObject().put("schema","hepta.session-recovery.v1").put("decision","blocked_interrupted")
   .put("reason","prior_activity_or_cleanup_unresolved").put("previous_status","blocked")
   .put("previous_session_sha256",sha(x.control)).put("read_error",JSONObject.NULL)
   .put("interruption_latch","control-session.interrupted.json").put("interruption_latch_observed",true)
   .put("recovery_pending_barrier_observed",false).put("automatic_resume",false)
   .put("native_cleanup_independently_observed",false).put("interruption_latch_synced",true)
   .put("preserved_records",new JSONArray().put(row));
  return raw(new JSONObject().put("schema","hepta.local-session.v1").put("status","interrupted")
   .put("task_id",old.get("task_id")).put("origin",old.get("origin")).put("instruction_sha256",old.get("instruction_sha256"))
   .put("task_authorization_sha256",JSONObject.NULL).put("task_authorization",JSONObject.NULL).put("background_request",JSONObject.NULL)
   .put("debug_nonce_sha256",old.get("debug_nonce_sha256")).put("expected_scope_sha256",JSONObject.NULL).put("actual_scope_sha256",JSONObject.NULL)
   .put("state","上次会话中断且退出状态未确认；应用重启后已暂停新任务，不会自动恢复或重做。")
   .put("pending",false).put("running",false).put("blocked",true).put("cleanup_known",false).put("app_uid",10481)
   .put("updated_wall_ms",old.getLong("updated_wall_ms")+1).put("external_model",false).put("automatic_resume",false)
   .put("goal_independently_verified",false).put("startup_recovery",recovery)
   .put("background_lease_unreleased",true).put("web_helper_lease_unreleased",false));
 }
 private static int bundle(Inputs x){int n=0;for(byte[]b:x.input.values())n+=b.length;return n;}
 private static String quote(String x){return "'"+x.replace("'","'\\''")+"'";}
 private static void checkRequest(String label,Inputs x)throws Exception{
  PublicPersonalNotesAbsenceRecovery.Request r=x.request();
  check(r.workflowForeignHistoryRetirement&&r.workflowCloseFailed&&r.postModelDrained&&r.inputHashes().length()==23,"v11 history classification");
  PublicPersonalNotesRecoveryClient.requireDrainedGeneration(r);
  PublicPersonalNotesAbsenceRecovery.Request decoded=PublicPersonalNotesAbsenceRecovery.fromWire(r.wire());
  check(r.wire().equals(decoded.wire()),"wire exact roundtrip");
  for(String role:x.input.keySet())check(Arrays.equals(x.input.get(role),decoded.original(role)),"wire role bytes");
  check(Arrays.equals(x.control,decoded.original("current_control")),"current-control bytes");
  JSONObject identity=r.recordedOwnedIdentity();
  check(!identity.getBoolean("historical_business_success"),"failure history retained");
  String command="CLASSPATH="+quote(x.controller.getString("source_path"))+" /system/bin/app_process / org.trillionnium.hepta.background.PublicPersonalNotesAbsenceMain --request "+quote(r.wire());
  int commandBytes=command.getBytes(StandardCharsets.UTF_8).length;
  check(bundle(x)<=262144&&r.wire().length()<=65536&&commandBytes<60000,"unchanged size limits");
  try{PublicPersonalNotesAbsenceRecovery.validate(new JSONObject(),r,r.started+1,r.requestBoot);throw new AssertionError("empty current absence accepted");}
  catch(Exception expected){check(true,"historical input cannot supply fresh absence");}
  metrics.put(new JSONObject().put("case",label).put("raw_bundle_bytes",bundle(x)).put("raw_bundle_limit",262144)
   .put("wire_chars",r.wire().length()).put("wire_limit",65536).put("complete_command_bytes",commandBytes)
   .put("complete_command_limit_exclusive",60000).put("historical_business_success",false)
   .put("current_absence_proven",false).put("current_control_host_fixture","interrupted".equals(PublicPersonalNotesAbsenceRecovery.object(x.control).getString("status"))));
  names.add(label);cases++;
 }
 private static int serializedDiagnosticBytes(byte[] terminal)throws Exception{
  String text=new String(terminal,StandardCharsets.UTF_8),key="\"personal_notes_history_diagnostic\":";
  int at=text.indexOf(key);check(at>=0&&at==text.lastIndexOf(key),"exactly one serialized private field");
  int start=at+key.length();while(start<text.length()&&Character.isWhitespace(text.charAt(start)))start++;
  check(start<text.length()&&text.charAt(start)=='{',"private field is an object");
  int depth=0;boolean string=false,escape=false;
  for(int i=start;i<text.length();i++){
   char c=text.charAt(i);
   if(string){if(escape)escape=false;else if(c=='\\')escape=true;else if(c=='"')string=false;}
   else if(c=='"')string=true;
   else if(c=='{'||c=='[')depth++;
   else if(c=='}'||c==']'){depth--;if(depth==0)return text.substring(start,i+1).getBytes(StandardCharsets.UTF_8).length;}
  }
  throw new IllegalStateException("private field is incomplete");
 }
 private static Inputs withTerminal(Inputs original,byte[] terminal,String variant)throws Exception{
  Inputs x=original.copy();JSONObject next=PublicPersonalNotesAbsenceRecovery.object(terminal),old=x.json("broker_output");
  check(next.has("personal_notes_history_diagnostic")&&!old.has("personal_notes_history_diagnostic"),"one new private diagnostic");
  JSONObject diagnostic=next.getJSONObject("personal_notes_history_diagnostic");next.remove("personal_notes_history_diagnostic");
  check(equal(next,old),"producer changes no existing terminal field");
  int diag=serializedDiagnosticBytes(terminal);diagnosticMetrics.put(new JSONObject().put("variant",variant).put("actual_producer_diagnostic_bytes",diag).put("android_reserialized_diagnostic_bytes",raw(diagnostic).length).put("actual_terminal_bytes",terminal.length));check(diag<=4608&&terminal.length<=32767,"unchanged actual producer caps");
  check(diagnostic.getInt("diagnostic_limit_bytes")==4608,"actual narrowed producer limit");
  check(!diagnostic.getBoolean("diagnostics_grant_authority")&&!diagnostic.getBoolean("release_evidence")&&!diagnostic.getBoolean("model_input"),"diagnostic is not authority");
  if("max".equals(variant))check(diag==4608,"exact max diagnostic fixture");
  check(diagnostic.getBoolean("raw_pair_complete")==!"omitted".equals(variant),"explicit omission form");
  if("omitted".equals(variant))check(!diagnostic.has("raw_pair")&&"serialized_diagnostic_bound".equals(diagnostic.getString("raw_pair_omission_reason")),"omit reason");
  JSONObject receipt=x.json("broker_receipt");
  receipt.put("observed_bytes",terminal.length).put("stored_bytes",terminal.length).put("stored_sha256",sha(terminal));
  x.input.put("broker_output",terminal);x.input.put("broker_receipt",formatLike(x.input.get("broker_receipt"),receipt));
  JSONObject cleanup=x.json("cleanup");cleanup.put("broker_output",receipt);
  x.input.put("cleanup",formatLike(x.input.get("cleanup"),cleanup));
  JSONObject result=x.json("result");
  result.getJSONObject("background_cleanup").put("broker_output",receipt);
  result.getJSONObject("background_session").put("broker_output",receipt);
  x.input.put("result",formatLike(x.input.get("result"),result));
  Set<String> changed=new HashSet<String>(Arrays.asList("broker_output","broker_receipt","cleanup","result"));
  for(String role:original.input.keySet())if(!changed.contains(role))check(Arrays.equals(original.input.get(role),x.input.get(role)),"unchanged unrelated original role");
  check(bundle(x)>bundle(original),"diagnostic cannot manufacture margin by compacting originals");
  JSONObject oldReceipt=original.json("broker_receipt");
  JSONObject reset=new JSONObject(receipt.toString());for(String k:new String[]{"observed_bytes","stored_bytes","stored_sha256"})reset.put(k,oldReceipt.get(k));
  check(equal(reset,oldReceipt),"only byte/hash receipt metadata changed");
  JSONObject resetCleanup=x.json("cleanup");resetCleanup.put("broker_output",oldReceipt);check(equal(resetCleanup,original.json("cleanup")),"cleanup only linked metadata changed");
  JSONObject resetResult=x.json("result");resetResult.getJSONObject("background_cleanup").put("broker_output",oldReceipt);resetResult.getJSONObject("background_session").put("broker_output",oldReceipt);
  check(equal(resetResult,original.json("result")),"result only linked metadata changed");
  return x;
 }
 public static void main(String[]args)throws Exception{
  if(args.length!=2)throw new IllegalArgumentException("explicit input map and three producer files manifest required");
  Inputs original=read(Paths.get(args[0]));
  check(bundle(original)==253774,"actual baseline bundle size must not change");
  JSONObject manifest=new JSONObject(new String(Files.readAllBytes(Paths.get(args[1])),StandardCharsets.UTF_8));
  check("hepta.notes-diagnostic-consumer-inputs.v1".equals(manifest.getString("schema")),"producer manifest schema");
  checkRequest("actual_original_control",original);
  Inputs interrupted=original.copy();interrupted.control=startupControl(original);checkRequest("exact_normal_startup_current_control_host_fixture",interrupted);
  for(String variant:new String[]{"normal","max","omitted"}){
   JSONObject row=manifest.getJSONObject(variant);byte[] terminal=Files.readAllBytes(Paths.get(row.getString("path")));
   check(terminal.length==row.getInt("bytes")&&sha(terminal).equals(row.getString("sha256")),"exact producer output");
   Inputs x=withTerminal(original,terminal,variant);
   checkRequest("producer_"+variant+"_original_control",x);
   Inputs startup=x.copy();startup.control=startupControl(original);checkRequest("producer_"+variant+"_normal_startup_control_host_fixture",startup);
   Inputs eof=startup.copy();JSONObject receipt=eof.json("broker_receipt");receipt.put("eof_seen",true);
   eof.input.put("broker_receipt",formatLike(eof.input.get("broker_receipt"),receipt));
   checkRequest("producer_"+variant+"_startup_and_eof_successor_host_fixture",eof);
   check(Arrays.equals(x.input.get("cleanup"),eof.input.get("cleanup"))&&Arrays.equals(x.input.get("result"),eof.input.get("result")),"EOF never rewrites historical cleanup");
   Inputs tooLarge=x.copy();byte[] pad=new byte[262145-bundle(x)+x.input.get("broker_output").length];Arrays.fill(pad,(byte)' ');System.arraycopy(terminal,0,pad,0,terminal.length);tooLarge.input.put("broker_output",pad);
   try{tooLarge.request();throw new AssertionError("oversized raw bundle accepted");}catch(Exception expected){check(true,"original bundle cap enforced");}
   names.add("producer_"+variant+"_oversized_bundle_rejected");cases++;
  }
  for(Map.Entry<String,Path> e:original.paths.entrySet()){
   byte[] captured="current_control".equals(e.getKey())?original.control:original.input.get(e.getKey());
   check(Arrays.equals(captured,Files.readAllBytes(e.getValue())),"original unchanged after test");
  }
  System.out.println(new JSONObject().put("schema","hepta.notes-history-diagnostic-consumer-host.v1").put("all_pass",true)
   .put("cases",cases).put("assertions",assertions).put("case_names",new JSONArray(names)).put("metrics",metrics)
   .put("diagnostic_metrics",diagnosticMetrics).put("actual_original_roles",23).put("original_byte_preservation",true).put("producer_terminals_host_derived",true)
   .put("startup_current_control_host_derived",true).put("startup_archive_validation_boundary","separate existing typed installer readback")
   .put("normal_worker_generation_validator",true).put("phone_operations",0).put("app_recovery_completed",false)
   .put("current_absence_proven",false).put("business_success_claimed",false).toString());
 }
}
