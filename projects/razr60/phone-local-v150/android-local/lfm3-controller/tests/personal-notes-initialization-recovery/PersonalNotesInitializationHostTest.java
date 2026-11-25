package org.trillionnium.hepta.background;
import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.util.*;import org.json.*;
/** Pure actual policy. Portable authored fixture; private original replay is an optional explicit input.
 * The current controller, clock and framework samples are synthetic in every host case. */
public final class PersonalNotesInitializationHostTest {
 private static int cases,assertions;private static final JSONArray checks=new JSONArray();
 interface Work{void run()throws Exception;}interface Change{void run(JSONObject value)throws Exception;}interface Alter{void run(Setup s)throws Exception;}
 private static void yes(boolean b,String reason){assertions++;if(!b)throw new AssertionError(reason);}
 private static JSONObject copy(JSONObject o){return new JSONObject(o.toString());}
 private static byte[] bytes(JSONObject o){return o.toString().getBytes(StandardCharsets.UTF_8);}
 private static void pass(String name,Work w)throws Exception{w.run();cases++;checks.put(new JSONObject().put("name",name).put("passed",true));}
 private static void reject(String name,Work w)throws Exception{
  try{w.run();}catch(Exception e){cases++;assertions++;checks.put(new JSONObject().put("name",name).put("rejection",e.getClass().getSimpleName()+": "+e.getMessage()));return;}
  throw new AssertionError("unsafe input accepted: "+name);
 }
 public static final class Setup {
  public final Map<String,byte[]> inputs=new LinkedHashMap<String,byte[]>();
  public byte[] control;public final JSONObject controller;public final int uid,boot;public final long now;
  Setup(Map<String,byte[]> data,byte[] control,JSONObject controller)throws Exception{
   for(Map.Entry<String,byte[]> e:data.entrySet())inputs.put(e.getKey(),e.getValue().clone());
   this.control=control.clone();this.controller=copy(controller);JSONObject j=get("journal");
   uid=j.getInt("app_uid");boot=j.getInt("boot_count");now=j.getLong("expires_elapsed_ms")+3000;
  }
  public Setup duplicate()throws Exception{return new Setup(inputs,control,controller);}
  public JSONObject get(String key)throws Exception{return PublicPersonalNotesAbsenceRecovery.object(inputs.get(key));}
  public void set(String key,JSONObject value){inputs.put(key,bytes(value));}
  public void mutate(String key,Change change)throws Exception{JSONObject value=get(key);change.run(value);set(key,value);}
  public PublicPersonalNotesAbsenceRecovery.Request request()throws Exception{return request(now,boot);}
  public PublicPersonalNotesAbsenceRecovery.Request request(long clock,int bootCount)throws Exception{
   return PublicPersonalNotesAbsenceRecovery.request(inputs,control,controller,uid,"aabbccdd-1122-4333-8444-556677889900",clock,bootCount);
  }
  void syncResult()throws Exception{
   JSONObject cleanup=get("cleanup"),background=copy(cleanup);background.remove("cleanup_known");background.remove("cleanup_error");
   mutate("result",r->r.put("background_cleanup",cleanup).put("background_session",background));
  }
  void syncBroker()throws Exception{
   byte[] output=inputs.get("broker_output");JSONObject broker=get("broker_receipt");
   broker.put("stored_bytes",output.length).put("observed_bytes",output.length).put("stored_sha256",ProfileIdentity.sha(output));set("broker_receipt",broker);
   mutate("bootstrap",b->b.put("broker_output",copy(broker)));mutate("cleanup",b->b.put("broker_output",copy(broker)));syncResult();
  }
  void terminal(Change change)throws Exception{
   String[] lines=new String(inputs.get("broker_output"),StandardCharsets.UTF_8).split("\n",-1);JSONObject t=new JSONObject(lines[1]);change.run(t);
   inputs.put("broker_output",(lines[0]+"\n"+t.toString()+"\n").getBytes(StandardCharsets.UTF_8));syncBroker();
  }
  public Setup startup()throws Exception{
   byte[] original=control.clone();String sha=ProfileIdentity.sha(original),relative="session-recovery/control-session.json."+sha+".json";
   JSONObject recovery=new JSONObject().put("schema","hepta.session-recovery.v1").put("decision","blocked_interrupted")
     .put("previous_status","blocked").put("previous_session_sha256",sha).put("read_error",JSONObject.NULL)
     .put("interruption_latch","control-session.interrupted.json").put("recovery_pending_barrier_observed",false)
     .put("automatic_resume",false).put("native_cleanup_independently_observed",false);
   JSONObject latch=new JSONObject().put("schema","hepta.session-interruption-latch.v1").put("app_uid",uid).put("blocked",true)
     .put("cleanup_known",false).put("automatic_resume",false).put("recovery_reason",copy(recovery));
   recovery.put("interruption_latch_observed",true).put("interruption_latch_synced",true)
     .put("preserved_records",new JSONArray().put(new JSONObject().put("original_name","control-session.json").put("bytes",original.length)
     .put("sha256",sha).put("path","/data/user/0/org.trillionnium.hepta.local/files/"+relative)));
   JSONObject current=PublicPersonalNotesAbsenceRecovery.object(original).put("status","interrupted").put("startup_recovery",recovery);
   current.remove("steps");current.remove("completion_evidence");current.put("task_authorization",JSONObject.NULL).put("background_request",JSONObject.NULL);
   control=bytes(current);inputs.put("origin_control",original);inputs.put("interruption_latch",bytes(latch));return this;
  }
 }
 public static Setup synthetic()throws Exception{
  PersonalNotesAbsenceHostTest.Fixture f=new PersonalNotesAbsenceHostTest.Fixture();
  Map<String,byte[]> in=new LinkedHashMap<String,byte[]>();for(Map.Entry<String,byte[]> e:f.inputs.entrySet())in.put(e.getKey(),e.getValue().clone());
  JSONObject journal=new JSONObject(new String(in.get("journal"),StandardCharsets.UTF_8)).put("display_id",-1);
  JSONObject owner=new JSONObject(new String(in.get("owner"),StandardCharsets.UTF_8)),selection=journal.getJSONObject("selection");
  JSONObject target=new JSONObject().put("owner_sha256",f.ownerHash).put("effective_initial_package",PublicPersonalNotesAbsenceRecovery.PACKAGE)
    .put("effective_allowed_packages",selection.getJSONArray("allowed_packages"));
  for(String k:new String[]{"owner_rewritten","package_from_model_or_screen","grants_tool_authority","business_verified"})target.put(k,false);
  owner.getJSONObject("task_authorization").put("execution_target",target);
  JSONObject scope=new JSONObject().put("task_id",f.task).put("expected_scope_sha256",JSONObject.NULL).put("actual_scope_sha256",JSONObject.NULL)
    .put("restricted",false).put("scope_refused",false).put("scope_loaded",false);
  JSONObject contract=new JSONObject().put("schema","synthetic-initialization-host-contract");
  owner.put("qualification_scope",scope).put("completion_contract",contract);
  JSONObject evidence=new JSONObject().put("contract",contract).put("task_id",f.task).put("owner_sha256",f.ownerHash)
    .put("proofs",new JSONArray()).put("model_success_claims",new JSONArray());
  for(String k:new String[]{"notes_launch_observed","completion_verified","model_done_synthesized","controller_completion_requested","grants_tool_authority"})evidence.put(k,false);
  JSONObject terminal=new JSONObject("{\"schema\":\"hepta.background-broker-terminal.v1\",\"generation\":\"synthetic\",\"state\":\"RELEASED\",\"display_id\":-1,\"reason\":\"process_finally\",\"release_confirmed\":true,\"boot_count_read_retirement_failure\":null,\"owned_single_task\":null,\"profile_cleanup\":null,\"profile_cleanup_diagnostics\":{\"schema\":\"hepta.profile-cleanup-diagnostics.v1\",\"first_failure\":null,\"diagnostics_grant_authority\":false,\"provides_cleanup_proof\":false,\"allows_input_or_model_resumption\":false},\"profile_last_leaf_validation\":null,\"profile_first_root_refusal\":null,\"profile_permission_first_read_mismatch\":null,\"profile_custody_retained\":false,\"display_scope_sha256\":\"synthetic\",\"public_scope_admission_retired\":true,\"public_surface_detach\":{\"schema\":\"hepta.public-own-group.surface-retirement.v1\",\"admission_irrevocably_retired\":true,\"state\":\"IDENTITY_UNAVAILABLE_UNVERIFIED\",\"worker_claimed\":true,\"late_create_worker_claimed\":false,\"identity_read_completed\":false,\"adapter_entered\":false,\"identity_source\":\"NONE\",\"api_attempted\":false,\"api_returned\":false,\"began_elapsed_ms\":0,\"ended_elapsed_ms\":0,\"worker_finished\":true,\"deadline_exceeded\":false,\"failure_type\":\"java.io.IOException\",\"surface_stopped_verified\":false,\"provides_task_or_display_cleanup_proof\":false,\"allows_input_or_model_resumption\":false,\"shutdown_depends_on_fresh_display_binder_query\":false},\"public_screen_lease\":{\"schema\":\"hepta.public-own-group.screen-lease.v1\",\"generation\":\"synthetic\",\"display_id\":-1,\"display_group_id\":-1,\"wake_lock_flags\":10,\"expires_elapsed_ms\":0,\"acquire_entered\":false,\"acquire_returned\":false,\"acquired_elapsed_ms\":0,\"admission_retired\":true,\"release_entered\":false,\"release_returned\":false,\"released_elapsed_ms\":0,\"failure\":null,\"initial_readiness_started_elapsed_ms\":0,\"initial_readiness_deadline_elapsed_ms\":0,\"initial_readiness_census_count\":0,\"initial_first_display_state\":-1,\"initial_last_display_state\":-1,\"initial_on_observed_elapsed_ms\":0,\"grants_cleanup_or_business_success\":false},\"public_policy_diagnostics\":{\"schema\":\"hepta.public-policy-diagnostics.v1\",\"first_failure\":null,\"diagnostics_grant_authority\":false,\"provides_cleanup_proof\":false}}").put("generation",f.gen).put("display_scope_sha256",f.scope.sha256);
  terminal.getJSONObject("public_surface_detach").put("began_elapsed_ms",f.created+20).put("ended_elapsed_ms",f.created+20);
  terminal.getJSONObject("public_screen_lease").put("generation",f.gen).put("expires_elapsed_ms",f.expires);
  String first=new JSONObject().put("schema","hepta.background-broker-terminal.v1").put("error","FRAMEWORK_OPERATION_FAILED").put("state","INITIAL").toString();
  byte[] output=(first+"\n"+terminal.toString()+"\n").getBytes(StandardCharsets.UTF_8);
  JSONObject broker=new JSONObject(new String(in.get("broker_receipt"),StandardCharsets.UTF_8)).put("capture_reason","stream_terminal").put("eof_seen",true)
    .put("stored_bytes",output.length).put("observed_bytes",output.length).put("stored_sha256",ProfileIdentity.sha(output));
  JSONObject initial=copy(journal).put("state","INITIAL").put("broker_output",JSONObject.NULL).put("broker_process_exit_code",JSONObject.NULL)
    .put("app_display_readback",JSONObject.NULL).put("last_broker_response",JSONObject.NULL).put("execution_target",target);
  for(String k:new String[]{"retired","spawn_attempted","bootstrap_dispatched","bootstrap_model_issued","broker_process_exit_observed"})initial.put(k,false);
  JSONObject bootstrap=copy(initial).put("spawn_attempted",true).put("broker_output",broker);
  JSONObject cleanup=copy(bootstrap).put("state","CLEANUP_UNKNOWN").put("retired",true).put("broker_process_exit_observed",true)
    .put("broker_process_exit_code",70).put("cleanup_known",false).put("cleanup_error","synthetic initialization failure");
  JSONObject result=new JSONObject(new String(in.get("result"),StandardCharsets.UTF_8)).put("qualification_scope",scope).put("completion_evidence",evidence)
    .put("background_cleanup",cleanup);
  JSONObject background=copy(cleanup);background.remove("cleanup_known");background.remove("cleanup_error");result.put("background_session",background);
  result.getJSONObject("task_authorization").put("execution_target",target);
  JSONObject control=copy(f.control).put("status","blocked").put("steps",0).put("task_authorization_sha256",owner.get("task_authorization_sha256"))
    .put("task_authorization",owner.getJSONObject("task_authorization")).put("background_request",selection).put("completion_evidence",evidence)
    .put("background_lease_unreleased",true);
  for(String k:new String[]{"cleanup_known","external_model","web_helper_lease_unreleased","completion_verified","model_reported_success"})control.put(k,false);
  String apk=ProfileIdentity.sha("synthetic Notes APK");
  JSONObject identity=new JSONObject().put("source","ordinary_package_manager_and_full_apk_hash").put("package",PublicPersonalNotesAbsenceRecovery.PACKAGE)
    .put("uid",f.targetUid).put("version_code",1).put("apk_hashes",new JSONObject().put("base",apk))
    .put("apk_set_sha256",ProfileIdentity.sha("base\t"+apk+"\n"));
  in.put("journal",bytes(journal));in.put("owner",bytes(owner));in.put("bootstrap",bytes(bootstrap));in.put("cleanup",bytes(cleanup));
  in.put("result",bytes(result));in.put("broker_receipt",bytes(broker));in.put("broker_output",output);
  in.put("initial_binding",bytes(initial));in.put("scope_binding",bytes(scope));in.put("completion_identity",bytes(identity));
  return new Setup(in,bytes(control),f.controller);
 }
 public static Setup actual(Path indexPath)throws Exception{
  JSONObject index=new JSONObject(new String(Files.readAllBytes(indexPath),StandardCharsets.UTF_8));
  if(index.has("records"))index=index.getJSONObject("records");
  Map<String,byte[]> data=new LinkedHashMap<String,byte[]>();byte[] control=null;
  for(String key:new String[]{"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output","initial_binding","scope_binding","completion_identity","current_control"}){
   JSONObject ref=index.getJSONObject(key);byte[] raw=Files.readAllBytes(Paths.get(ref.getString("path")));
   yes(raw.length==ref.getLong("bytes")&&ProfileIdentity.sha(raw).equals(ref.getString("sha256")),"exact original "+key);
   if("current_control".equals(key))control=raw;else data.put(key,raw);
  }
  int uid=PublicPersonalNotesAbsenceRecovery.object(data.get("journal")).getInt("app_uid");
  return new Setup(data,control,new PersonalNotesAbsenceHostTest.Fixture().controller.put("uid",uid));
 }
 private static void bad(Setup base,String name,Alter mutation)throws Exception{
  Setup s=base.duplicate();mutation.run(s);reject(name,()->s.request());
 }
 private static void proofBad(Setup base,String name,Change mutation)throws Exception{
  PublicPersonalNotesAbsenceRecovery.Request r=base.request();JSONObject p=PersonalNotesAbsenceHostTest.proof(r);mutation.run(p);
  reject(name,()->PublicPersonalNotesAbsenceRecovery.validate(p,r,r.started+21,r.oldBoot));
 }
 private static Path writePortable(Setup s,Path dir)throws Exception{
  Files.createDirectory(dir);JSONObject refs=new JSONObject();JSONObject j=s.get("journal");String gen=j.getString("generation");
  Map<String,String> filenames=new LinkedHashMap<String,String>();
  filenames.put("journal","background-session.active.json");filenames.put("owner","owner.json");filenames.put("bootstrap","background-bootstrap.json");
  filenames.put("cleanup","background-cleanup.json");filenames.put("result","result.json");filenames.put("broker_receipt","background-broker-"+gen+".json");
  filenames.put("broker_output","background-broker-"+gen+".bin");filenames.put("initial_binding","background-binding.json");
  filenames.put("scope_binding","scope-binding.json");filenames.put("completion_identity","completion-installed-identity.json");filenames.put("current_control","control-session.json");
  for(Map.Entry<String,String> e:filenames.entrySet()){
   byte[] raw="current_control".equals(e.getKey())?s.control:s.inputs.get(e.getKey());Path file=dir.resolve(e.getValue());Files.write(file,raw);
   refs.put(e.getKey(),new JSONObject().put("path",file.toString()).put("bytes",raw.length).put("sha256",ProfileIdentity.sha(raw)));
  }
  Path index=dir.resolve("INDEX.json");Files.write(index,bytes(new JSONObject().put("records",refs).put("controller",s.controller)
    .put("all_input_values_authored_synthetic",true)));return index;
 }
 public static void main(String[] args)throws Exception{
  boolean actual=args.length==2&&"--actual".equals(args[0]);Setup base=actual?actual(Paths.get(args[1])):synthetic();
  String portable=null;if(!actual&&args.length==2&&"--synthetic-output".equals(args[0]))portable=writePortable(base,Paths.get(args[1])).toString();
  pass("new initialization request with exact originals",()->{PublicPersonalNotesAbsenceRecovery.Request r=base.request();
   yes(r.initializationFailed&&r.displayId==-1&&r.recordedTaskIds.isEmpty()&&!r.releasedBeforeModel,"narrow mode");
   yes(r.wire().equals(PublicPersonalNotesAbsenceRecovery.fromWire(r.wire()).wire()),"wire roundtrip");
   for(Map.Entry<String,byte[]> e:base.inputs.entrySet())yes(Arrays.equals(e.getValue(),r.original(e.getKey())),"unchanged "+e.getKey());
   JSONObject p=PersonalNotesAbsenceHostTest.proof(r);yes(PublicPersonalNotesAbsenceRecovery.validate(p,r,r.started+21,r.oldBoot).getBoolean("cleanup_known"),"new proof");
   yes(!p.getBoolean("historical_broker_release_observed"),"no historical promotion");
  });
  pass("restart preserves exact original control and latch",()->{Setup s=base.duplicate().startup();PublicPersonalNotesAbsenceRecovery.Request r=s.request();
   yes(r.initializationFailed&&!r.releasedBeforeModel,"startup mode");yes(r.wire().equals(PublicPersonalNotesAbsenceRecovery.fromWire(r.wire()).wire()),"startup wire");
   yes(Arrays.equals(base.control,r.original("origin_control")),"startup preserves old bytes");
  });
  reject("new boot refused",()->base.request(base.now,base.boot+1));
  reject("original expiry grace boundary refused",()->base.request(base.now-1000,base.boot));
  for(int id:new int[]{-2,0,1,77})bad(base,"invalid or unbound recorded display "+id,s->s.mutate("journal",j->j.put("display_id",id)));
  bad(base,"missing initial binding",s->s.inputs.remove("initial_binding"));
  bad(base,"missing scope binding",s->s.inputs.remove("scope_binding"));
  bad(base,"extra original role",s->s.inputs.put("extra",new byte[]{1}));
  bad(base,"initial spawn cannot be true",s->s.mutate("initial_binding",j->j.put("spawn_attempted",true)));
  bad(base,"initial response cannot exist",s->s.mutate("initial_binding",j->j.put("last_broker_response",new JSONObject())));
  bad(base,"cleanup launch dispatched forbidden",s->{s.mutate("cleanup",j->j.put("bootstrap_dispatched",true));s.syncResult();});
  bad(base,"bootstrap launch dispatched forbidden",s->s.mutate("bootstrap",j->j.put("bootstrap_dispatched",true)));
  bad(base,"cleanup broker exit must remain 70",s->{s.mutate("cleanup",j->j.put("broker_process_exit_code",0));s.syncResult();});
  bad(base,"cleanup broker exit must be observed",s->{s.mutate("cleanup",j->j.put("broker_process_exit_observed",false).put("broker_process_exit_code",JSONObject.NULL));s.syncResult();});
  bad(base,"transport EOF required",s->{s.mutate("broker_receipt",j->j.put("eof_seen",false));s.syncBroker();});
  bad(base,"transport overflow refused",s->{s.mutate("broker_receipt",j->j.put("overflow",true));s.syncBroker();});
  bad(base,"historical release evidence cannot be promoted",s->{s.mutate("broker_receipt",j->j.put("release_evidence",true));s.syncBroker();});
  bad(base,"two line framing rejects third line",s->{s.inputs.put("broker_output",(new String(s.inputs.get("broker_output"),StandardCharsets.UTF_8)+"{}\n").getBytes(StandardCharsets.UTF_8));s.syncBroker();});
  bad(base,"two line framing rejects missing LF",s->{byte[] raw=s.inputs.get("broker_output");s.inputs.put("broker_output",Arrays.copyOf(raw,raw.length-1));s.syncBroker();});
  bad(base,"INITIAL first line required",s->{String text=new String(s.inputs.get("broker_output"),StandardCharsets.UTF_8);s.inputs.put("broker_output",text.replace("\"INITIAL\"","\"ACTIVE\"").getBytes(StandardCharsets.UTF_8));s.syncBroker();});
  bad(base,"terminal unknown transition key refused",s->s.terminal(t->t.put("creation_attempted",false)));
  bad(base,"terminal display identity remains minus one",s->s.terminal(t->t.put("display_id",9)));
  bad(base,"terminal generation cannot differ",s->s.terminal(t->t.put("generation","11111111-1111-4111-8111-111111111111")));
  bad(base,"terminal release diagnostic cannot be false",s->s.terminal(t->t.put("release_confirmed",false)));
  bad(base,"terminal custody cannot appear",s->s.terminal(t->t.put("owned_single_task",new JSONObject())));
  bad(base,"screen acquisition forbidden",s->s.terminal(t->t.getJSONObject("public_screen_lease").put("acquire_entered",true)));
  bad(base,"screen generation cannot differ",s->s.terminal(t->t.getJSONObject("public_screen_lease").put("generation","11111111-1111-4111-8111-111111111111")));
  bad(base,"detach late worker unknown refused",s->s.terminal(t->t.getJSONObject("public_surface_detach").put("late_create_worker_claimed",true)));
  bad(base,"detach diagnostics are strictly typed",s->s.terminal(t->t.getJSONObject("public_surface_detach").put("api_attempted","false")));
  bad(base,"wrong Notes installation UID refused",s->s.mutate("completion_identity",j->j.put("uid",s.uid)));
  bad(base,"wrong Notes APK set digest refused",s->s.mutate("completion_identity",j->j.put("apk_set_sha256",ProfileIdentity.sha("wrong"))));
  bad(base,"scope source cannot change",s->s.mutate("scope_binding",j->j.put("restricted",true)));
  bad(base,"model dispatch forbidden",s->s.mutate("result",j->j.getJSONObject("model_session").put("process_started",true)));
  bad(base,"native work forbidden",s->s.mutate("result",j->j.getJSONObject("native_cancellation").put("worker_started",true)));
  bad(base,"business action forbidden",s->s.mutate("result",j->j.getJSONArray("fixed_intent_attempts").put(new JSONObject())));
  bad(base,"pending observation worker forbidden",s->s.mutate("result",j->j.put("observation_read_worker_pending_at_terminal",true)));
  bad(base,"current control replacement forbidden",s->{JSONObject c=PublicPersonalNotesAbsenceRecovery.object(s.control).put("task_id","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");s.control=bytes(c);});
  Setup startup=base.duplicate().startup();
  bad(startup,"startup latch different predecessor refused",s->s.mutate("interruption_latch",j->j.getJSONObject("recovery_reason").put("previous_session_sha256",ProfileIdentity.sha("different"))));
  bad(startup,"startup original control cannot report done",s->s.mutate("origin_control",j->j.put("status","done")));
  proofBad(base,"new proof cannot claim old release",p->p.put("historical_broker_release_observed",true));
  proofBad(base,"wrong proof request refused",p->p.put("request_id","11111111-1111-4111-8111-111111111111"));
  proofBad(base,"new proof cannot grant business",p->p.put("business_success",true));
  proofBad(base,"new proof rejects unknown old creator",p->p.getJSONObject("before").getJSONObject("process").put("old_creator_absent",false));
  proofBad(base,"new proof rejects named display",p->p.getJSONObject("before").getJSONObject("displays").getJSONArray("rows").getJSONObject(0).put("name",base.get("journal").getString("display_name")));
  proofBad(base,"new proof rejects live Notes target",p->p.getJSONObject("before").getJSONObject("live").getJSONArray("roots").getJSONObject(0).put("top","com.motorola.stylus/.NotesManager"));
  proofBad(base,"new proof rejects physical change",p->p.getJSONObject("after").getJSONObject("physical").put("0",ProfileIdentity.sha("changed")));
  proofBad(base,"new proof rejects incomplete recents",p->p.getJSONObject("after").getJSONObject("recents").put("complete",false));
  PublicPersonalNotesAbsenceRecovery.Request r=base.request();JSONObject proof=PersonalNotesAbsenceHostTest.proof(r);
  reject("new proof cannot extend twelve second deadline",()->PublicPersonalNotesAbsenceRecovery.validate(proof,r,r.deadline,r.oldBoot));
  reject("new proof cannot cross reboot",()->PublicPersonalNotesAbsenceRecovery.validate(proof,r,r.started+21,r.oldBoot+1));
  System.out.println(new JSONObject().put("all_pass",true).put("cases",cases).put("assertions",assertions).put("checks",checks)
    .put("phone_operations",0).put("actual_private_originals",actual).put("framework_controller_clock_synthetic",true)
    .put("portable_index",portable==null?JSONObject.NULL:portable));
 }
}
