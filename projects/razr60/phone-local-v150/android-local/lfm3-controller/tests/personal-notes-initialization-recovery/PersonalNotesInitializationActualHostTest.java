package org.trillionnium.hepta.background;
import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.util.*;import org.json.*;
/** Host-private exact-original replay. Only fresh framework/controller/clock values are synthetic. */
public final class PersonalNotesInitializationActualHostTest {
 static void need(boolean b,String message){if(!b)throw new AssertionError(message);}
 static byte[] read(JSONObject index,String role)throws Exception{
  JSONObject ref=index.getJSONObject(role);byte[] raw=Files.readAllBytes(Paths.get(ref.getString("path")));
  need(raw.length==ref.getLong("bytes")&&ProfileIdentity.sha(raw).equals(ref.getString("sha256")),"original digest "+role);return raw;
 }
 public static void main(String[] args)throws Exception{
  JSONObject index=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
  Map<String,byte[]> inputs=new LinkedHashMap<String,byte[]>();
  for(String name:new String[]{"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output","initial_binding","scope_binding","completion_identity"})inputs.put(name,read(index,name));
  byte[] control=read(index,"current_control");JSONObject journal=PublicPersonalNotesAbsenceRecovery.object(inputs.get("journal"));
  int uid=journal.getInt("app_uid"),boot=journal.getInt("boot_count");long now=journal.getLong("expires_elapsed_ms")+3000;
  JSONObject controller=new PersonalNotesAbsenceHostTest.Fixture().controller.put("uid",uid);
  boolean expectReject=args.length>1&&"--expect-reject".equals(args[1]);
  PublicPersonalNotesAbsenceRecovery.Request r;
  try{r=PublicPersonalNotesAbsenceRecovery.request(inputs,control,controller,uid,"aabbccdd-1122-4333-8444-556677889900",now,boot);}
  catch(Exception failure){if(!expectReject)throw failure;System.out.println(new JSONObject().put("expected_baseline_rejection",true).put("error",failure.getMessage()).put("originals_exact",true));return;}
  need(!expectReject,"old baseline unexpectedly accepted");
  need(r.displayId==-1&&r.recordedTaskIds.isEmpty()&&!r.releasedBeforeModel,"new mode identity");
  need("hepta.personal-notes-initialization-current-absence.v1".equals(r.proofSchema()),"new schema");
  need("fresh_initialization_failure_personal_notes_absence_with_preserved_failure".equals(r.source()),"new source");
  for(Map.Entry<String,byte[]> e:inputs.entrySet())need(Arrays.equals(e.getValue(),r.original(e.getKey())),"preserved "+e.getKey());
  need(Arrays.equals(control,r.original("current_control")),"preserved control");
  String wire=r.wire();PublicPersonalNotesAbsenceRecovery.Request replay=PublicPersonalNotesAbsenceRecovery.fromWire(wire);
  need(wire.equals(replay.wire()),"canonical wire roundtrip");
  JSONObject proof=PersonalNotesAbsenceHostTest.proof(r);
  JSONObject verified=PublicPersonalNotesAbsenceRecovery.validate(proof,r,now+21,boot);
  need(verified.getBoolean("cleanup_known")&&!verified.getBoolean("historical_broker_release_observed"),"independent current proof only");
  need(!PublicPersonalNotesAbsenceRecovery.object(r.original("result")).getBoolean("cleanup_known"),"old result unchanged");
  need(!PublicPersonalNotesAbsenceRecovery.object(r.original("broker_receipt")).getBoolean("release_evidence"),"raw not promoted");
  System.out.println(new JSONObject().put("all_pass",true).put("originals_exact",true).put("original_roles",inputs.size()+1)
   .put("input_hashes",r.inputHashes()).put("controller_and_framework_values_synthetic",true).put("phone_operations",0)
   .put("wire_chars",wire.length()).put("new_proof_schema",r.proofSchema()).put("new_source",r.source())
   .put("journal_sha256",r.journalSha256).put("target_uid",r.targetUid).put("historical_broker_release_observed",false));
 }
}
