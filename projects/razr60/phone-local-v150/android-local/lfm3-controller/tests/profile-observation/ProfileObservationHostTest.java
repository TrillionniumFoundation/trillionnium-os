package org.trillionnium.hepta.local;
import java.util.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import org.trillionnium.hepta.background.*;
/** Exact production values/predicate plus extracted cleanup method. Synthetic only. */
public final class ProfileObservationHostTest {
 static final String H=NativeActionSnapshotCheckHostTest.H,G="11111111-2222-3333-4444-555555555555";
 static final String TOKEN="22222222-2222-3333-4444-555555555555",OTHER="33333333-2222-3333-4444-555555555555";
 static final List<String> cases=new ArrayList<String>();static int assertions;
 interface Check{void run()throws Exception;}
 static void yes(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
 static void check(String name,Check body)throws Exception{body.run();cases.add(name);}
 static void refuse(Check body)throws Exception{boolean failed=false;try{body.run();}catch(IllegalArgumentException expected){failed=true;}yes(failed,"must fail closed");}
 static ProfileTarget target(int user,long serial){
  return new ProfileTarget(new ProfileIdentity(user,serial,0,ProfileIdentity.MANAGED),user*100000+10050,
   ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.android.view.splash.SplashActivity",123L,Collections.singletonMap("base",H),Collections.singleton(H));
 }
 static WindowOwnership proof(ProfileTarget target,int task,String token,long at,String id){
  return new WindowOwnership(target,G,15,96,task,400,token,id,target.profile.userId,target.profile.serial,target.fullUid,at,at+1000);
 }
 static NativeAppEvidence.Frame frame(WindowOwnership p,int window,long at){
  String id=NativeActionSnapshotCheckHostTest.ID;
  return new NativeAppEvidence.Frame(id,H,H,H,H,id,ProfileTarget.CTRIP,G,H,H,H,H,H,15,window,0,1224,2992,0,0,1224,2992,at,false,true,
   Collections.<NativeAppEvidence.Node>emptyList(),1,true,p);
 }
 static NativeActionSnapshotCheck.Intent intent(NativeActionSnapshotCheckHostTest.Fixture f){
  NativeActionSnapshotCheck.Intent old=f.intent();Map<String,Object> fields=new TreeMap<String,Object>(old.identity);
  for(String key:NativeActionSnapshotCheck.PROFILE_IDENTITY)fields.put(key,f.env.get(key));
  return new NativeActionSnapshotCheck.Intent(old.purpose,old.pkg,old.path,old.label,old.refSha256,old.run,old.node,old.actionSha,old.historySha,fields,old.started,old.deadline);
 }
 static Map<String,Object> cleanup(WindowOwnership p){
  Map<String,Object> c=new LinkedHashMap<String,Object>(),r=new LinkedHashMap<String,Object>();
  c.put("schema","hepta.profile-task-cleanup.v1");c.put("generation",p.generation);c.put("display_id",p.displayId);
  c.put("target_sha256",p.targetSha256);c.put("user_id",p.userId);c.put("user_serial",p.userSerial);c.put("full_uid",p.fullUid);
  c.put("cleanup_known",true);c.put("live_tasks_absent",true);c.put("recents_tasks_absent",true);
  c.put("foreign_tasks_present",false);c.put("identity_unknown",false);c.put("display_absence_observed",true);
  r.put("task_id",p.taskId);r.put("parent_task_id",p.parentTaskId);r.put("task_token_id",p.taskTokenId);
  r.put("user_id",p.userId);r.put("user_serial",p.userSerial);r.put("full_uid",p.fullUid);r.put("live_absent",true);r.put("recents_absent",true);
  c.put("owned_tasks",new ArrayList<Object>(Collections.singletonList(r)));return c;
 }
 @SuppressWarnings("unchecked") static Map<String,Object> onlyRow(Map<String,Object> c){return (Map<String,Object>)((List<?>)c.get("owned_tasks")).get(0);}
 static NativeActionSnapshotCheckHostTest.Fixture withProfile(WindowOwnership p){
  NativeActionSnapshotCheckHostTest.Fixture f=NativeActionSnapshotCheckHostTest.home();
  f.env.putAll(NativeAppEvidence.profileActionIdentity(p));return f;
 }
 public static void main(String[] args)throws Exception{
  final ProfileTarget t=target(10,77),other=target(11,88);
  final WindowOwnership p=proof(t,500,TOKEN,50,OTHER),fresh=proof(t,500,TOKEN,250,G);
  check("legacy_user0_uid_gate_is_preserved",()->{yes(new NativeAppEvidence.Installed(ProfileTarget.CTRIP,10050,123,Collections.singletonMap("base",H)).profileTarget==null,"legacy branch");
   refuse(()->new NativeAppEvidence.Installed(ProfileTarget.CTRIP,t.fullUid,123,Collections.singletonMap("base",H)));});
  check("explicit_profile_installed_keeps_full_uid_and_serial",()->{NativeAppEvidence.Installed i=new NativeAppEvidence.Installed(t);
   yes(i.uid==1010050&&i.profileTarget.profile.serial==77&&i.apkSetSha256.equals(t.apkSetSha256),"no user0 remap");});
  check("same_package_other_profile_is_not_same_owner",()->{WindowOwnership wrong=proof(other,500,TOKEN,50,OTHER);
   yes(!NativeAppEvidence.sameProfileOwner(p,wrong),"package alone cannot bind");refuse(()->NativeAppEvidence.requireProfileTarget(t,wrong));});
  check("copied_expected_profile_cannot_substitute_missing_actual_proof",()->refuse(()->NativeAppEvidence.requireProfileTarget(t,null)));
  check("parent_remapped_uid_cannot_construct_profile_proof",()->refuse(()->new WindowOwnership(t,G,15,96,500,400,TOKEN,OTHER,10,77,10050,50,1050)));
  check("recreated_user_serial_is_not_the_original_profile",()->{ProfileTarget recreated=target(10,78);WindowOwnership wrong=proof(recreated,500,TOKEN,50,OTHER);
   yes(!NativeAppEvidence.sameProfileOwner(p,wrong),"serial is identity");refuse(()->NativeAppEvidence.requireProfileTarget(t,wrong));});
  check("fresh_rpc_nonce_and_time_do_not_change_stable_leaf_identity",()->{yes(!p.sha256.equals(fresh.sha256),"distinct readback");yes(NativeAppEvidence.sameProfileWindow(p,fresh),"same actual leaf");yes(frame(p,96,100).capturedElapsedMs==100,"old capture remains old");});
  check("task_id_reuse_with_new_real_token_is_rejected",()->yes(!NativeAppEvidence.sameProfileOwner(p,proof(t,500,OTHER,50,G)),"token changes identity"));
  check("historical_frame_requires_capture_time_inside_its_own_proof",()->{yes(frame(p,96,100).profileWindow==p,"actual proof retained");refuse(()->frame(p,96,1050));refuse(()->frame(p,96,49));});
  check("historical_frame_wrong_window_is_rejected",()->refuse(()->frame(p,97,100)));
  check("user0_frame_cannot_consume_profile_proof",()->refuse(()->NativeAppEvidence.requireProfileTarget(null,p)));
  check("full_census_comparison_accepts_same_profile_without_granting_dispatch",()->{
   NativeActionSnapshotCheckHostTest.Fixture a=withProfile(p),z=NativeActionSnapshotCheckHostTest.fresh(a);
   z.env.putAll(NativeAppEvidence.profileActionIdentity(fresh));Map<String,Object> result=NativeActionSnapshotCheck.compare(intent(a),a.snapshot(),z.snapshot(),400);
   yes(Boolean.FALSE.equals(result.get("grants_dispatch")),"still only a predicate");});
  for(final String key:Arrays.asList("profile_user_serial","profile_task_id","profile_parent_task_id","profile_task_token_id","profile_target_sha256")){
   check("snapshot_identity_change_"+key+"_is_hard_refusal",()->{
    NativeActionSnapshotCheckHostTest.Fixture a=withProfile(p),z=NativeActionSnapshotCheckHostTest.fresh(a);
    Object old=z.env.get(key);z.env.put(key,key.endsWith("token_id")?OTHER:key.endsWith("sha256")?NativeActionSnapshotCheck.hash("different target"):
     old instanceof Long?Long.valueOf(((Long)old)+1):Integer.valueOf(((Integer)old)+1));
    boolean hard=false;try{NativeActionSnapshotCheck.compare(intent(a),a.snapshot(),z.snapshot(),400);}
    catch(IllegalArgumentException e){yes(!(e instanceof NativeActionSnapshotCheck.CurrentnessChanged),"identity is not stale content");hard=true;}
    yes(hard,"changed identity rejected");
   });
  }
  check("profile_snapshot_cannot_fallback_to_legacy_envelope",()->{
   NativeActionSnapshotCheckHostTest.Fixture a=withProfile(p),z=NativeActionSnapshotCheckHostTest.fresh(a);for(String key:NativeActionSnapshotCheck.PROFILE_IDENTITY)z.env.remove(key);
   refuse(()->NativeActionSnapshotCheck.compare(intent(a),a.snapshot(),z.snapshot(),400));});
  check("partial_profile_envelope_and_parent_uid_are_rejected",()->{
   NativeActionSnapshotCheckHostTest.Fixture a=withProfile(p);a.env.remove("profile_user_serial");refuse(()->a.snapshot());
   NativeActionSnapshotCheckHostTest.Fixture b=withProfile(p);b.env.put("profile_full_uid",10050);refuse(()->b.snapshot());});
  check("terminal_cleanup_matches_exact_actual_final_leaf",()->yes(ProfileCleanupProjection.profileCleanupBound(t,p,cleanup(p)),"valid bounded projection"));
  check("old_terminal_signature_has_no_profile_cleanup_authority",()->yes(!ProfileCleanupProjection.profileCleanupBound(t,p,null),"missing real cleanup"));
  for(final String key:Arrays.asList("cleanup_known","live_tasks_absent","recents_tasks_absent","display_absence_observed","foreign_tasks_present","identity_unknown")){
   check("terminal_rejects_"+key,()->{Map<String,Object> c=cleanup(p);c.put(key,!((Boolean)c.get(key)));
    yes(!ProfileCleanupProjection.profileCleanupBound(t,p,c),"not complete cleanup");});
  }
  check("terminal_other_user_same_package_cannot_complete",()->yes(!ProfileCleanupProjection.profileCleanupBound(t,p,cleanup(proof(other,500,TOKEN,50,OTHER))),"other full UID/serial"));
  check("terminal_reused_user_or_task_token_cannot_complete",()->{Map<String,Object> c=cleanup(p);c.put("user_serial",78L);yes(!ProfileCleanupProjection.profileCleanupBound(t,p,c),"recreated profile");
   c=cleanup(p);onlyRow(c).put("task_token_id",OTHER);yes(!ProfileCleanupProjection.profileCleanupBound(t,p,c),"new task with same id");});
  check("terminal_duplicate_or_missing_owned_leaf_refuses",()->{Map<String,Object> c=cleanup(p);List<Object> rows=new ArrayList<Object>();rows.add(onlyRow(c));rows.add(new LinkedHashMap<String,Object>(onlyRow(c)));c.put("owned_tasks",rows);
   yes(!ProfileCleanupProjection.profileCleanupBound(t,p,c),"duplicate actual leaf");
   c=cleanup(p);c.put("owned_tasks",Collections.emptyList());yes(!ProfileCleanupProjection.profileCleanupBound(t,p,c),"no retired final leaf");});
  check("terminal_unknown_or_nonintegral_identity_fields_refuse",()->{Map<String,Object> c=cleanup(p);c.put("fallback_user",0);yes(!ProfileCleanupProjection.profileCleanupBound(t,p,c),"unknown authority field");
   c=cleanup(p);onlyRow(c).put("user_serial",77.0);yes(!ProfileCleanupProjection.profileCleanupBound(t,p,c),"lossy numeric coercion");});
  StringBuilder out=new StringBuilder("{\"schema\":\"hepta.profile-observation-host.v1\",\"all_pass\":true,\"phone_operations\":0,\"android_runtime\":false,\"actual_framework_parcel_tested\":false,\"business_verified\":false,\"cases\":"+cases.size()+",\"assertions\":"+assertions+",\"names\":[");
  for(int i=0;i<cases.size();i++){if(i>0)out.append(',');out.append('"').append(cases.get(i)).append('"');}
  out.append("]}\n");Files.write(Paths.get(args[0]),out.toString().getBytes(StandardCharsets.UTF_8));System.out.print(out);
 }
}
