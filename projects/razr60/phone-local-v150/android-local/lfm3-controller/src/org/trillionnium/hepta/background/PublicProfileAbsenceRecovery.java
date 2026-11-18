package org.trillionnium.hepta.background;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import org.json.JSONArray;
import org.json.JSONObject;

/** Current absence for an expired public user-10 lease whose original producer
 * stopped before business dispatch. Historical display creation remains unknown.
 * This data policy grants neither input authority nor authority to delete a lease.
 * The app additionally requires its own completed checker Process and durable receipt. */
public final class PublicProfileAbsenceRecovery {
    public static final String REQUEST_SCHEMA="hepta.public-profile-absence-request.v2";
    public static final String SCHEMA="hepta.public-profile-current-absence.v2";
    public static final String SOURCE="fresh_public_profile_current_absence_with_preserved_history";
    public static final String POST_REQUEST_SCHEMA="hepta.public-profile-postlaunch-absence-request.v1";
    public static final String POST_SCHEMA="hepta.public-profile-postlaunch-current-absence.v1";
    public static final String POST_SOURCE="fresh_public_profile_postlaunch_absence_with_preserved_history";
    public static final String CONTROLLER="org.trillionnium.hepta.local";
    // The actual bounded proc census uses this same interval. No grace is added at acceptance.
    public static final long LIMIT_MS=12000, TTL_MS=540000, EXPIRY_GRACE_MS=2000;
    public static final int MAX_ORIGINAL=131072, MAX_BUNDLE=262144, MAX_WIRE=65536, MAX_OUTPUT=65536;
    private static final String[] INPUTS={"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output"};
    private PublicProfileAbsenceRecovery(){}

    public static final class Request {
        public final int ownerUid,oldBoot,requestBoot;
        public final long created,expires,started,deadline;
        public final String requestId,taskId,generation,ownerSha256,displayName,journalSha256,originalsSha256;
        public final ProfileTarget target;
        public final PublicOwnGroupPolicy.Scope publicScope;
        public final boolean postlaunch;
        public final int displayId,ownedRootTaskId,ownedLeafTaskId;
        public final String ownedLeafTaskToken;
        private final Map<String,byte[]> originals;
        private final String controllerText;
        private Request(Map<String,byte[]> inputs,JSONObject controller,int uid,String id,long now,int boot,boolean launched)throws Exception{
            postlaunch=launched;
            need(uid>=10000&&uid<90000&&ProfileIdentity.uuid(id)&&now>=0&&boot>=0,"PUBLIC_RECOVERY_REQUEST_IDENTITY");
            need(inputs!=null&&inputs.keySet().equals(new TreeSet<String>(Arrays.asList(INPUTS))),"PUBLIC_RECOVERY_INPUT_SET");
            LinkedHashMap<String,byte[]> captured=new LinkedHashMap<String,byte[]>();int bytes=0;
            for(String name:INPUTS){byte[] raw=inputs.get(name);need(raw!=null&&raw.length>0&&raw.length<=MAX_ORIGINAL,"PUBLIC_RECOVERY_INPUT_BOUND");
                bytes+=raw.length;need(bytes<=MAX_BUNDLE,"PUBLIC_RECOVERY_INPUT_BOUND");captured.put(name,raw.clone());}
            originals=Collections.unmodifiableMap(captured);
            JSONObject journal=object(originals.get("journal"));
            need("hepta.background-session.v1".equals(string(journal,"schema"))&&number(journal,"app_uid")==uid,
                    "PUBLIC_RECOVERY_JOURNAL_OWNER");
            taskId=string(journal,"task_id");generation=string(journal,"generation");ownerSha256=string(journal,"owner_sha256");
            displayName=string(journal,"display_name");
            need(taskId.matches("[0-9a-f]{32}")&&ProfileIdentity.uuid(generation)&&ProfileIdentity.hash(ownerSha256)
                    &&("hepta-bg-"+generation).equals(displayName)&&displayName.equals(string(journal,"socket")),"PUBLIC_RECOVERY_JOURNAL_IDENTITY");
            long recordedDisplay=number(journal,"display_id");
            need(recordedDisplay>=-1&&recordedDisplay<=Integer.MAX_VALUE,"PUBLIC_RECOVERY_DISPLAY_BOUND");displayId=(int)recordedDisplay;
            need("CLEANUP_UNKNOWN".equals(string(journal,"state"))&&(postlaunch?displayId>1:displayId==-1)
                    &&Boolean.valueOf(postlaunch).equals(journal.get("profile_launch_attempted"))
                    &&Boolean.TRUE.equals(journal.get("profile_isolation_required"))
                    &&Boolean.TRUE.equals(journal.get("owned_task_retirement_required")),"PUBLIC_RECOVERY_NOT_UNDISPATCHED_PROFILE");
            target=ProfileTarget.fromWire(string(journal,"profile_target_wire"));
            need(target.profile.userId==10&&target.profile.parentUserId==0&&target.profile.serial>0
                    &&ProfileIdentity.MANAGED.equals(target.profile.type)&&ProfileTarget.CTRIP.equals(target.packageName)
                    &&target.sha256.equals(string(journal,"profile_target_sha256")),"PUBLIC_RECOVERY_PROFILE_SCOPE");
            created=number(journal,"created_elapsed_ms");expires=number(journal,"expires_elapsed_ms");
            long previousBoot=number(journal,"boot_count");
            need(created>=0&&expires>created&&expires-created==TTL_MS&&expires<Long.MAX_VALUE-EXPIRY_GRACE_MS
                    &&previousBoot>=0&&previousBoot<=Integer.MAX_VALUE,"PUBLIC_RECOVERY_LEASE_CLOCK");
            oldBoot=(int)previousBoot;ownerUid=uid;requestId=id;started=now;requestBoot=boot;
            need(started<=Long.MAX_VALUE-LIMIT_MS,"PUBLIC_RECOVERY_REQUEST_CLOCK");deadline=started+LIMIT_MS;
            publicScope=PublicOwnGroupPolicy.Scope.fromWire(string(journal,"public_own_group_scope_wire"));
            publicScope.requireConfig(uid,generation,expires,target);
            need(publicScope.sha256.equals(string(journal,"public_own_group_scope_sha256"))&&publicScope.taskId.equals(taskId)
                    &&publicScope.ownerSha256.equals(ownerSha256)&&publicScope.createdElapsedMs==created&&publicScope.bootCount==oldBoot
                    &&Boolean.TRUE.equals(journal.get("public_own_group_experimental"))
                    &&Boolean.FALSE.equals(journal.get("public_scope_serialization_grants_authority")),"PUBLIC_RECOVERY_PUBLIC_SCOPE_BINDING");
            JSONObject selection=journal.getJSONObject("selection");requireSelection(selection);
            JSONObject owner=object(originals.get("owner"));
            need("hepta.local-owner.v1".equals(string(owner,"schema"))&&taskId.equals(string(owner,"task_id"))
                    &&ownerSha256.equals(string(owner,"instruction_utf8_sha256"))
                    &&ownerSha256.equals(ProfileIdentity.sha(string(owner,"instruction")))
                    &&Boolean.FALSE.equals(owner.get("external_model"))&&Boolean.FALSE.equals(owner.get("automatic_resume")),"PUBLIC_RECOVERY_OWNER_BINDING");
            need(same(selection,owner.getJSONObject("background_request")),"PUBLIC_RECOVERY_OWNER_SELECTION");
            JSONObject bootstrap=object(originals.get("bootstrap")),cleanup=object(originals.get("cleanup")),result=object(originals.get("result"));
            bindBackground(bootstrap);bindBackground(cleanup);
            need((postlaunch?"RELEASED":"INITIAL").equals(string(bootstrap,"state"))&&Boolean.valueOf(postlaunch).equals(bootstrap.get("retired"))
                    &&Boolean.TRUE.equals(bootstrap.get("spawn_attempted")),"PUBLIC_RECOVERY_BOOTSTRAP_STATE");
            need("CLEANUP_UNKNOWN".equals(string(cleanup,"state"))&&Boolean.TRUE.equals(cleanup.get("retired"))
                    &&Boolean.TRUE.equals(cleanup.get("spawn_attempted"))&&Boolean.FALSE.equals(cleanup.get("cleanup_known"))
                    &&Boolean.TRUE.equals(cleanup.get("broker_process_exit_observed")),"PUBLIC_RECOVERY_BROKER_EXIT_UNPROVED");
            long exit=number(cleanup,"broker_process_exit_code");need(exit>=0&&exit<=255,"PUBLIC_RECOVERY_BROKER_EXIT_INVALID");
            JSONObject broker=object(originals.get("broker_receipt")),finalBroker=cleanup.getJSONObject("broker_output");
            requireBroker(broker);requireBroker(finalBroker);
            if(!postlaunch)requireBroker(bootstrap.getJSONObject("broker_output"));
            need(same(broker,finalBroker)&& (postlaunch||same(broker,bootstrap.getJSONObject("broker_output")))
                    &&Boolean.TRUE.equals(broker.get("persisted")),
                    "PUBLIC_RECOVERY_BROKER_RECEIPT_CHANGED");
            byte[] output=originals.get("broker_output");
            need(number(broker,"stored_bytes")==output.length&&number(broker,"observed_bytes")==output.length
                    &&ProfileIdentity.sha(output).equals(string(broker,"stored_sha256")),"PUBLIC_RECOVERY_BROKER_OUTPUT_BYTES");
            if(postlaunch){
                need(exit==0,"PUBLIC_POSTLAUNCH_BROKER_EXIT");
                requireBootstrapPrefix(bootstrap.getJSONObject("broker_output"),broker,output);
                JSONObject owned=postlaunchOrigin(bootstrap,cleanup,output);
                ownedRootTaskId=(int)number(owned,"root_task_id");ownedLeafTaskId=(int)number(owned,"leaf_task_id");
                ownedLeafTaskToken=string(owned,"leaf_task_token");
            }else{ownedRootTaskId=-1;ownedLeafTaskId=-1;ownedLeafTaskToken=null;}
            need(taskId.equals(string(result,"task_id"))&&"blocked".equals(string(result,"status"))&&number(result,"steps")==0
                    &&Boolean.FALSE.equals(result.get("cleanup_known"))&&Boolean.FALSE.equals(result.get("completion_verified"))
                    &&Boolean.FALSE.equals(result.get("model_reported_success"))&&Boolean.FALSE.equals(result.get("external_model"))
                    &&Boolean.FALSE.equals(result.get("automatic_replay"))&&Boolean.FALSE.equals(result.get("controller_completion_requested"))
                    &&result.get("last_action_execution")==JSONObject.NULL&&result.get("final_observation_id")==JSONObject.NULL
                    &&result.get("model_done_status")==JSONObject.NULL&&result.get("completion_actor")==JSONObject.NULL,
                    "PUBLIC_RECOVERY_BUSINESS_OR_MODEL_DISPATCH");
            for(String key:new String[]{"observation_read_worker_pending_at_terminal","action_worker_pending_at_terminal","native_cancel_worker_pending_at_terminal"})
                need(Boolean.FALSE.equals(result.get(key)),"PUBLIC_RECOVERY_WORKER_PENDING");
            need(result.getJSONArray("submit_attempts").length()==0&&result.getJSONArray("fixed_intent_attempts").length()==0
                    &&result.get("profile_permission_preparation")==JSONObject.NULL,"PUBLIC_RECOVERY_EFFECT_ATTEMPT");
            JSONObject nativeWork=result.getJSONObject("native_cancellation"),model=result.getJSONObject("model_session");
            need(taskId.equals(string(nativeWork,"task_id"))&&Boolean.TRUE.equals(nativeWork.get("native_cleanup_known"))
                    &&nativeWork.get("run_id")==JSONObject.NULL,"PUBLIC_RECOVERY_NATIVE_UNKNOWN");
            for(String key:new String[]{"request_reserved","executor_accepted","worker_started","signal_entered","submission_unknown"})
                need(Boolean.FALSE.equals(nativeWork.get(key)),"PUBLIC_RECOVERY_NATIVE_DISPATCH");
            need(taskId.equals(string(model,"task_id"))&&Boolean.FALSE.equals(model.get("process_started"))&&Boolean.FALSE.equals(model.get("process_exit_observed"))
                    &&model.get("worker_generation")==JSONObject.NULL&&model.get("exit_code")==JSONObject.NULL
                    &&Boolean.TRUE.equals(model.get("receipt_valid"))&&model.get("app_receipt_sha256")==JSONObject.NULL,
                    "PUBLIC_RECOVERY_MODEL_SESSION");
            need(same(cleanup,result.getJSONObject("background_cleanup"))
                    &&same(without(cleanup,"cleanup_known","cleanup_error"),result.getJSONObject("background_session")),"PUBLIC_RECOVERY_RESULT_CROSS_BINDING");
            JSONObject authorization=owner.getJSONObject("task_authorization"),gate=result.getJSONObject("task_authorization");
            need(ownerSha256.equals(string(gate,"instruction_sha256"))
                    &&string(owner,"task_authorization_sha256").equals(string(result,"task_authorization_sha256"))
                    &&string(owner,"task_authorization_sha256").equals(string(authorization,"authorization_sha256"))
                    &&taskId.equals(string(gate,"task_id")),"PUBLIC_RECOVERY_AUTHORIZATION_BINDING");
            // The result is a Gate projection with additional state; the owner is immutable authorization.
            Iterator<String> authorizationKeys=authorization.keys();while(authorizationKeys.hasNext()){
                String key=authorizationKeys.next();need(same(authorization.get(key),gate.get(key)),"PUBLIC_RECOVERY_AUTHORIZATION_CHANGED");}
            for(String key:new String[]{"discovery_run_id","opened_package","catalogue_sha256","discovery_observation_id",
                    "open_run_id","opened_observation_id","pending_open_package"})
                need(gate.get(key)==JSONObject.NULL,"PUBLIC_RECOVERY_AUTHORIZATION_EFFECT");
            need(gate.getJSONArray("found_packages").length()==0&&gate.getJSONObject("last_check").length()==0,
                    "PUBLIC_RECOVERY_AUTHORIZATION_EFFECT");
            long terminal=number(result,"terminal_decided_elapsed_ms");need(terminal>=created&&terminal<=started,"PUBLIC_RECOVERY_TERMINAL_CLOCK");
            requireController(controller,uid);controllerText=canonical(controller);
            journalSha256=ProfileIdentity.sha(originals.get("journal"));originalsSha256=ProfileIdentity.sha(canonical(inputHashes()));
            requireFence(now,boot);
        }
        private void requireSelection(JSONObject s)throws Exception{
            need("background".equals(string(s,"mode"))&&target.packageName.equals(string(s,"bootstrap_package"))
                    &&s.getJSONArray("allowed_packages").length()==1&&target.packageName.equals(s.getJSONArray("allowed_packages").get(0))
                    &&target.wire().equals(string(s,"profile_target_wire"))&&target.sha256.equals(string(s,"profile_target_sha256"))
                    &&"public_own_group_no_credentials_v1".equals(string(s,"display_scope_mode"))
                    &&"immutable_start_selection".equals(string(s,"display_scope_mode_source"))
                    &&Boolean.FALSE.equals(s.get("bootstrap_model_issued"))&&Boolean.FALSE.equals(s.get("main_display_fallback"))
                    &&Boolean.FALSE.equals(s.get("home_allowed"))&&Boolean.FALSE.equals(s.get("display_scope_mode_grants_authority")),"PUBLIC_RECOVERY_SELECTION");
        }
        private void bindBackground(JSONObject b)throws Exception{
            JSONObject j=object(originals.get("journal"));
            for(String key:new String[]{"schema","task_id","app_uid","owner_sha256","generation","socket","display_name","display_id",
                    "created_elapsed_ms","expires_elapsed_ms","boot_count","selection","owned_task_retirement_required","public_own_group_scope_wire",
                    "public_own_group_scope_sha256","public_own_group_experimental","public_scope_serialization_grants_authority","profile_target_wire",
                    "profile_target_sha256","profile_isolation_required","profile_launch_attempted"})need(same(j.get(key),b.get(key)),"PUBLIC_RECOVERY_ORIGINAL_IDENTITY");
            need(Boolean.valueOf(postlaunch).equals(b.get("bootstrap_dispatched"))&&Boolean.FALSE.equals(b.get("bootstrap_model_issued")),"PUBLIC_RECOVERY_BOOTSTRAP_DISPATCH");
            if(!postlaunch)need(b.get("last_broker_response")==JSONObject.NULL&&b.get("app_display_readback")==JSONObject.NULL,"PUBLIC_RECOVERY_BOOTSTRAP_DISPATCH");
        }
        private void requireBroker(JSONObject b)throws Exception{
            need("hepta.background-broker-output.v1".equals(string(b,"schema"))&&taskId.equals(string(b,"task_id"))
                    &&generation.equals(string(b,"generation"))&&number(b,"app_uid")==ownerUid&&number(b,"app_pid")>0
                    &&"owned_java_process_merged_stream".equals(string(b,"process_binding"))&&number(b,"process_reference")>0
                    &&ProfileIdentity.hash(string(b,"command_sha256"))&&number(b,"started_elapsed_ms")>=created
                    &&number(b,"started_elapsed_ms")<=started&&number(b,"output_limit_bytes")==65536
                    &&("background-broker-"+generation+".bin").equals(string(b,"output_file"))
                    &&("background-broker-"+generation+".json").equals(string(b,"receipt_file"))
                    &&Boolean.TRUE.equals(b.get("eof_seen"))&&Boolean.FALSE.equals(b.get("read_failed"))&&Boolean.FALSE.equals(b.get("overflow"))
                    &&Boolean.TRUE.equals(b.get("merged_stdout_stderr"))&&Boolean.FALSE.equals(b.get("model_input"))
                    &&Boolean.FALSE.equals(b.get("release_evidence")),"PUBLIC_RECOVERY_BROKER_TRANSPORT");
        }
        private void requireBootstrapPrefix(JSONObject early,JSONObject complete,byte[] output)throws Exception{
            // The bootstrap finally block can precede owned-stream EOF. Its exact
            // prefix is historical evidence; only the final owned Process record proves exit.
            for(String key:new String[]{"schema","task_id","generation","app_uid","app_pid","process_binding","process_reference",
                    "command_sha256","started_elapsed_ms","output_file","receipt_file","output_limit_bytes","overflow","read_failed",
                    "merged_stdout_stderr","model_input","release_evidence"})
                need(same(early.get(key),complete.get(key)),"PUBLIC_POSTLAUNCH_BOOTSTRAP_PRODUCER_CHANGED");
            need(early.get("eof_seen") instanceof Boolean&&early.get("persisted") instanceof Boolean,
                    "PUBLIC_POSTLAUNCH_BOOTSTRAP_TRANSPORT_TYPE");
            long size=number(early,"stored_bytes");
            need(size>=0&&size<=output.length&&number(early,"observed_bytes")==size
                    &&ProfileIdentity.sha(Arrays.copyOf(output,(int)size)).equals(string(early,"stored_sha256")),
                    "PUBLIC_POSTLAUNCH_BOOTSTRAP_PREFIX_CHANGED");
            if(Boolean.TRUE.equals(early.get("eof_seen")))need(size==output.length,"PUBLIC_POSTLAUNCH_EARLY_EOF_DIFFERS");
            if(Boolean.TRUE.equals(early.get("persisted")))need(same(early,complete),"PUBLIC_POSTLAUNCH_PERSISTED_RECEIPT_CHANGED");
        }
        private JSONObject postlaunchOrigin(JSONObject bootstrap,JSONObject cleanup,byte[] output)throws Exception{
            JSONObject terminal=object(output),response=cleanup.getJSONObject("last_broker_response");
            need("hepta.background-broker-terminal.v1".equals(string(terminal,"schema"))
                    &&generation.equals(string(terminal,"generation"))&&number(terminal,"display_id")==displayId
                    &&"RELEASED".equals(string(terminal,"state"))&&Boolean.TRUE.equals(terminal.get("release_confirmed"))
                    &&terminal.get("boot_count_read_retirement_failure")==JSONObject.NULL
                    &&terminal.get("owned_single_task")==JSONObject.NULL
                    &&publicScope.sha256.equals(string(terminal,"display_scope_sha256"))
                    &&Boolean.TRUE.equals(terminal.get("public_scope_admission_retired"))
                    &&Boolean.FALSE.equals(terminal.get("profile_custody_retained")),"PUBLIC_POSTLAUNCH_ORIGINAL_TERMINAL");
            String reason=string(terminal,"reason");need(reason.matches("[A-Z0-9_]{1,96}"),"PUBLIC_POSTLAUNCH_TERMINAL_REASON");
            need(same(response,bootstrap.getJSONObject("last_broker_response"))
                    &&number(response,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION
                    &&ProfileIdentity.uuid(string(response,"request_id"))&&generation.equals(string(response,"generation"))
                    &&number(response,"display_id")==displayId&&displayName.equals(string(response,"display_name"))
                    &&publicScope.sha256.equals(string(response,"display_scope_sha256"))
                    &&"RELEASED".equals(string(response,"state"))&&Boolean.FALSE.equals(response.get("ok"))
                    &&Boolean.FALSE.equals(response.get("dispatched"))&&"prepare_done".equals(string(response,"operation"))
                    &&reason.equals(string(response,"terminal_reason"))&&"PUBLIC_SCOPE_RETIRED".equals(string(response,"error"))
                    &&Boolean.TRUE.equals(response.get("public_scope_admission_retired")),"PUBLIC_POSTLAUNCH_ORIGINAL_RESPONSE");
            JSONObject readback=cleanup.getJSONObject("app_display_readback");
            need(same(readback,bootstrap.getJSONObject("app_display_readback"))
                    &&"hepta.public-own-group.app-readback.v1".equals(string(readback,"schema"))
                    &&taskId.equals(string(readback,"task_id"))&&generation.equals(string(readback,"generation"))
                    &&number(readback,"app_uid")==ownerUid&&number(readback,"app_pid")>0&&number(readback,"boot_count")==oldBoot
                    &&number(readback,"display_id")==displayId&&displayName.equals(string(readback,"display_name"))
                    &&publicScope.sha256.equals(string(readback,"scope_sha256"))&&Boolean.TRUE.equals(readback.get("valid"))
                    &&Boolean.TRUE.equals(readback.get("root_rpc_registered"))
                    &&Boolean.FALSE.equals(readback.get("serialization_grants_authority")),"PUBLIC_POSTLAUNCH_APP_READBACK");
            JSONObject cleaned=terminal.getJSONObject("profile_cleanup");
            ProfilePrelaunchRecovery.keys(cleaned,"schema","generation","display_id","target_sha256","user_id","user_serial","full_uid",
                    "cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown","owned_tasks",
                    "public_foreign_recent_history","recents_absence_scope");
            need(same(cleaned,response.getJSONObject("profile_cleanup"))
                    &&"hepta.profile-task-cleanup.v1".equals(string(cleaned,"schema"))&&generation.equals(string(cleaned,"generation"))
                    &&number(cleaned,"display_id")==displayId&&target.sha256.equals(string(cleaned,"target_sha256"))
                    &&number(cleaned,"user_id")==target.profile.userId&&number(cleaned,"user_serial")==target.profile.serial
                    &&number(cleaned,"full_uid")==target.fullUid&&Boolean.TRUE.equals(cleaned.get("cleanup_known"))
                    &&Boolean.TRUE.equals(cleaned.get("live_tasks_absent"))&&Boolean.TRUE.equals(cleaned.get("recents_tasks_absent"))
                    &&Boolean.FALSE.equals(cleaned.get("foreign_tasks_present"))&&Boolean.FALSE.equals(cleaned.get("identity_unknown"))
                    &&"owned_target_only_with_foreign_history_preserved".equals(string(cleaned,"recents_absence_scope")),
                    "PUBLIC_POSTLAUNCH_ORIGINAL_PROFILE_CLEANUP");
            JSONArray tasks=cleaned.getJSONArray("owned_tasks");need(tasks.length()==1,"PUBLIC_POSTLAUNCH_BOOTSTRAP_OWNED_COUNT");
            JSONObject task=tasks.getJSONObject(0);ProfilePrelaunchRecovery.keys(task,"task_id","parent_task_id","task_token_id","user_id",
                    "user_serial","full_uid","live_absent","recents_absent");
            long root=number(task,"parent_task_id"),leaf=number(task,"task_id");String token=string(task,"task_token_id");
            need(root>0&&root<=Integer.MAX_VALUE&&leaf>0&&leaf<=Integer.MAX_VALUE&&root!=leaf&&ProfileIdentity.uuid(token)
                    &&number(task,"user_id")==target.profile.userId&&number(task,"user_serial")==target.profile.serial
                    &&number(task,"full_uid")==target.fullUid&&Boolean.TRUE.equals(task.get("live_absent"))
                    &&Boolean.TRUE.equals(task.get("recents_absent")),"PUBLIC_POSTLAUNCH_ORIGINAL_OWNED_IDENTITY");
            JSONObject validation=terminal.getJSONObject("profile_last_leaf_validation");
            need(same(validation,response.getJSONObject("profile_last_leaf_validation"))
                    &&"hepta.profile-leaf-validation.v1".equals(string(validation,"schema"))
                    &&"retained_leaf".equals(string(validation,"phase"))&&validation.get("refusal_code")==JSONObject.NULL
                    &&number(validation,"retained_task_id")==leaf&&number(validation,"observed_task_id")==leaf
                    &&number(validation,"observed_parent_id")==root&&number(validation,"observed_display_id")==displayId
                    &&number(validation,"observed_user_id")==target.profile.userId&&number(validation,"observed_full_uid")==target.fullUid
                    &&number(validation,"observed_top_activity_info_uid")==target.fullUid
                    &&Boolean.FALSE.equals(validation.get("serialized_token_is_authority")),"PUBLIC_POSTLAUNCH_ORIGINAL_LEAF_VALIDATION");
            for(String key:new String[]{"valid","launch_cookie_present","actual_task_token_equal_to_retained",
                    "retained_task_identity_matches","complete_global_leaf_matches"})
                need(Boolean.TRUE.equals(validation.get(key)),"PUBLIC_POSTLAUNCH_ORIGINAL_LEAF_CHECK");
            JSONObject checks=validation.getJSONObject("checks");
            String[] required={"dispatch_marked","task_info_present","task_id_positive","task_id_differs_from_root","task_id_absent_before_launch",
                    "actual_task_token_present","actual_task_token_differs_from_root","display_matches","user_matches","parent_matches","full_uid_matches",
                    "top_activity_info_uid_matches","first_claim_launch_cookie","intent_package_matches","base_package_matches","top_package_matches",
                    "real_package_matches","orig_package_matches"};
            ProfilePrelaunchRecovery.keys(checks,required);for(String key:required)need(Boolean.TRUE.equals(checks.get(key)),"PUBLIC_POSTLAUNCH_ORIGINAL_LEAF_CHECK");
            JSONObject history=cleaned.getJSONObject("public_foreign_recent_history");
            need("hepta.public-profile-history-custody.v1".equals(string(history,"schema"))&&target.sha256.equals(string(history,"target_sha256"))
                    &&Boolean.TRUE.equals(history.get("foreign_dormant_history_preserved"))&&Boolean.FALSE.equals(history.get("history_refusal_latched"))
                    &&history.get("history_refusal_reason")==JSONObject.NULL&&Boolean.TRUE.equals(history.get("owned_target_absent"))
                    &&Boolean.FALSE.equals(history.get("serialized_task_ids_grant_authority")),"PUBLIC_POSTLAUNCH_ORIGINAL_HISTORY");
            JSONArray retained=history.getJSONArray("owned_task_ids"),baseline=history.getJSONArray("baseline_task_ids");
            need(retained.length()==2&&numberAt(retained,0)==root&&numberAt(retained,1)==leaf,"PUBLIC_POSTLAUNCH_ORIGINAL_OWNED_SET");
            TreeSet<Long> ids=new TreeSet<Long>();for(int i=0;i<baseline.length();i++){long n=numberAt(baseline,i);
                need(n>0&&n<=Integer.MAX_VALUE&&n!=root&&n!=leaf&&ids.add(n),"PUBLIC_POSTLAUNCH_OWNED_ID_WAS_FOREIGN");}
            return new JSONObject().put("root_task_id",root).put("leaf_task_id",leaf).put("leaf_task_token",token);
        }
        public void requireFence(long now,int boot)throws IOException{
            need(boot==requestBoot&&boot==oldBoot&&now>=started&&now<deadline&&now>expires+EXPIRY_GRACE_MS,
                    "PUBLIC_RECOVERY_BOOT_TTL_OR_DEADLINE");
        }
        public byte[] original(String name)throws IOException{byte[] b=originals.get(name);need(b!=null,"PUBLIC_RECOVERY_INPUT_NAME");return b.clone();}
        public String requestSchema(){return postlaunch?POST_REQUEST_SCHEMA:REQUEST_SCHEMA;}
        public String proofSchema(){return postlaunch?POST_SCHEMA:SCHEMA;}
        public String source(){return postlaunch?POST_SOURCE:SOURCE;}
        public JSONObject recordedOwnedIdentity()throws Exception{return new JSONObject().put("display_id",displayId)
                .put("root_task_id",ownedRootTaskId).put("leaf_task_id",ownedLeafTaskId).put("leaf_task_token",ownedLeafTaskToken)
                .put("user_id",target.profile.userId).put("user_serial",target.profile.serial).put("full_uid",target.fullUid)
                .put("target_sha256",target.sha256).put("public_scope_sha256",publicScope.sha256)
                .put("serialized_identity_grants_mutation_authority",false);}
        public void requireRecordedLiveAbsent(ProfileTaskPolicy.Snapshot live)throws Exception{
            if(!postlaunch)return;
            need(!live.allIds.contains(ownedRootTaskId)&&!live.allIds.contains(ownedLeafTaskId),"PUBLIC_POSTLAUNCH_OWNED_ID_REUSED");
            for(ProfileTaskPolicy.Root root:live.roots)need(root.display!=displayId,"PUBLIC_POSTLAUNCH_RECORDED_DISPLAY_TASK_PRESENT");
            for(ProfileTaskPolicy.Leaf leaf:live.leaves.values())need(leaf.display!=displayId,"PUBLIC_POSTLAUNCH_RECORDED_DISPLAY_TASK_PRESENT");
        }
        public void requireRecordedRecentsAbsent(String raw)throws Exception{
            if(!postlaunch)return;
            PublicOwnGroupPhysicalFence.RecentCensus census=PublicOwnGroupPhysicalFence.inspectRecents(raw);
            need(!census.allIds.contains(ownedRootTaskId)&&!census.allIds.contains(ownedLeafTaskId),"PUBLIC_POSTLAUNCH_RECENT_OWNED_ID_REUSED");
            for(PublicOwnGroupPhysicalFence.RecentRecord row:census.records.values())
                need(row.root!=ownedRootTaskId&&row.root!=ownedLeafTaskId&&row.display!=displayId,"PUBLIC_POSTLAUNCH_RECENT_OWNED_LOCATION_PRESENT");
        }
        public JSONObject controller()throws Exception{return object(controllerText.getBytes(StandardCharsets.UTF_8));}
        public JSONObject inputHashes()throws Exception{JSONObject out=new JSONObject();for(String key:INPUTS){byte[] b=originals.get(key);
            out.put(key,new JSONObject().put("bytes",b.length).put("sha256",ProfileIdentity.sha(b)));}return out;}
        public String wire()throws Exception{
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF(requestSchema());out.writeInt(ownerUid);out.writeUTF(requestId);out.writeLong(started);out.writeInt(requestBoot);
            put(out,controllerText.getBytes(StandardCharsets.UTF_8));for(String name:INPUTS)put(out,originals.get(name));out.flush();
            byte[] raw=bytes.toByteArray();need(raw.length<=MAX_BUNDLE+8192,"PUBLIC_RECOVERY_WIRE_BOUND");
            ByteArrayOutputStream compressed=new ByteArrayOutputStream();try(GZIPOutputStream zip=new GZIPOutputStream(compressed)){zip.write(raw);}
            String value=Base64.getEncoder().encodeToString(compressed.toByteArray());need(value.length()<=MAX_WIRE,"PUBLIC_RECOVERY_WIRE_BOUND");return value;
        }
    }
    public static Request request(Map<String,byte[]> originals,JSONObject currentController,int uid,String id,long now,int boot)throws Exception{
        return new Request(originals,currentController,uid,id,now,boot,false);
    }
    public static Request postlaunchRequest(Map<String,byte[]> originals,JSONObject currentController,int uid,String id,long now,int boot)throws Exception{
        return new Request(originals,currentController,uid,id,now,boot,true);
    }
    public static Request fromWire(String wire)throws Exception{
        need(wire!=null&&wire.length()>0&&wire.length()<=MAX_WIRE,"PUBLIC_RECOVERY_WIRE_BOUND");byte[] zipped=Base64.getDecoder().decode(wire);
        need(Base64.getEncoder().encodeToString(zipped).equals(wire),"PUBLIC_RECOVERY_WIRE_NONCANONICAL");
        ByteArrayOutputStream decoded=new ByteArrayOutputStream();try(GZIPInputStream in=new GZIPInputStream(new ByteArrayInputStream(zipped))){
            byte[] block=new byte[4096];int count;while((count=in.read(block))!=-1){need(decoded.size()+count<=MAX_BUNDLE+8192,"PUBLIC_RECOVERY_WIRE_BOUND");decoded.write(block,0,count);}}
        DataInputStream in=new DataInputStream(new ByteArrayInputStream(decoded.toByteArray()));String schema=in.readUTF();
        need(REQUEST_SCHEMA.equals(schema)||POST_REQUEST_SCHEMA.equals(schema),"PUBLIC_RECOVERY_REQUEST_SCHEMA");
        int uid=in.readInt();String id=in.readUTF();long now=in.readLong();int boot=in.readInt();JSONObject controller=object(take(in,8192));
        Map<String,byte[]> originals=new LinkedHashMap<String,byte[]>();for(String name:INPUTS)originals.put(name,take(in,MAX_ORIGINAL));
        need(in.read()==-1,"PUBLIC_RECOVERY_WIRE_TRAILING");Request request=new Request(originals,controller,uid,id,now,boot,POST_REQUEST_SCHEMA.equals(schema));
        need(request.wire().equals(wire),"PUBLIC_RECOVERY_WIRE_NONCANONICAL");return request;
    }
    public static void requireController(JSONObject c,int uid)throws Exception{
        ProfilePrelaunchRecovery.keys(c,"schema","package","user_id","uid","source_path","source_bytes","source_sha256","version_code","signer_sha256");
        need("hepta.recovery-controller-installation.v1".equals(string(c,"schema"))&&CONTROLLER.equals(string(c,"package"))
                &&number(c,"user_id")==0&&number(c,"uid")==uid&&number(c,"source_bytes")>0&&number(c,"source_bytes")<=134217728
                &&ProfileIdentity.hash(string(c,"source_sha256"))&&number(c,"version_code")>0,"PUBLIC_RECOVERY_CONTROLLER_IDENTITY");
        String path=string(c,"source_path");need(path.startsWith("/data/app/")&&path.endsWith("/base.apk")&&path.length()<=4096
                &&path.indexOf('\0')<0&&path.indexOf('\n')<0&&path.indexOf('\r')<0&&!path.contains("/../")&&!path.contains("/./"),"PUBLIC_RECOVERY_CONTROLLER_PATH");
        JSONArray signers=c.getJSONArray("signer_sha256");need(signers.length()>0&&signers.length()<=4,"PUBLIC_RECOVERY_CONTROLLER_SIGNER");
        String previous="";for(int i=0;i<signers.length();i++){Object s=signers.get(i);need(s instanceof String&&ProfileIdentity.hash((String)s)
                &&previous.compareTo((String)s)<0,"PUBLIC_RECOVERY_CONTROLLER_SIGNER");previous=(String)s;}
    }
    public static JSONObject validate(JSONObject value,Request r,long now,int boot)throws Exception{
        need(r!=null,"PUBLIC_RECOVERY_REQUEST_MISSING");r.requireFence(now,boot);
        JSONObject shaped=value;
        if(r.postlaunch){
            need(Boolean.TRUE.equals(value.get("profile_bootstrap_dispatched"))&&Boolean.TRUE.equals(value.get("historical_broker_release_observed"))
                    &&Boolean.TRUE.equals(value.get("model_action_dispatch_absent_in_original_receipts"))
                    &&same(r.recordedOwnedIdentity(),value.getJSONObject("recorded_owned_identity")),"PUBLIC_POSTLAUNCH_PROOF_ORIGIN");
            shaped=without(value,"profile_bootstrap_dispatched","historical_broker_release_observed","model_action_dispatch_absent_in_original_receipts","recorded_owned_identity");
        }
        ProfilePrelaunchRecovery.keys(shaped,"schema","source","request_id","task_id","generation","owner_uid","owner_sha256","journal_sha256",
                "originals_sha256","original_inputs","public_scope_wire","public_scope_sha256","profile_target_wire","target_sha256","display_name",
                "old_boot_count","current_boot_count","lease_expires_elapsed_ms","request_started_elapsed_ms","started_elapsed_ms","finished_elapsed_ms",
                "deadline_elapsed_ms","current_controller","before","after","current_absence_verified","recovery_interval_physical_unchanged",
                "historical_creation_unknown","business_dispatch_absent_in_original_receipts","foreign_dormant_history_preserved",
                "cleanup_known","automatic_resume","broker_release_response");
        need(r.proofSchema().equals(string(value,"schema"))&&r.source().equals(string(value,"source"))&&r.requestId.equals(string(value,"request_id"))
                &&r.taskId.equals(string(value,"task_id"))&&r.generation.equals(string(value,"generation"))&&number(value,"owner_uid")==r.ownerUid
                &&r.ownerSha256.equals(string(value,"owner_sha256"))&&r.journalSha256.equals(string(value,"journal_sha256"))
                &&r.originalsSha256.equals(string(value,"originals_sha256"))&&same(r.inputHashes(),value.getJSONObject("original_inputs"))
                &&r.publicScope.wire().equals(string(value,"public_scope_wire"))&&r.publicScope.sha256.equals(string(value,"public_scope_sha256"))
                &&r.target.wire().equals(string(value,"profile_target_wire"))&&r.target.sha256.equals(string(value,"target_sha256"))
                &&r.displayName.equals(string(value,"display_name"))&&same(r.controller(),value.getJSONObject("current_controller")),"PUBLIC_RECOVERY_PROOF_BINDING");
        need(number(value,"old_boot_count")==r.oldBoot&&number(value,"current_boot_count")==boot&&number(value,"lease_expires_elapsed_ms")==r.expires
                &&number(value,"request_started_elapsed_ms")==r.started&&number(value,"deadline_elapsed_ms")==r.deadline,"PUBLIC_RECOVERY_PROOF_CLOCK");
        long begin=number(value,"started_elapsed_ms"),end=number(value,"finished_elapsed_ms");
        need(begin>=r.started&&end>=begin&&end<=now&&end<r.deadline,"PUBLIC_RECOVERY_PROOF_CLOCK");
        for(String key:new String[]{"current_absence_verified","recovery_interval_physical_unchanged","foreign_dormant_history_preserved","cleanup_known"})
            need(Boolean.TRUE.equals(value.get(key)),"PUBLIC_RECOVERY_PROOF_FLAGS");
        need(Boolean.valueOf(!r.postlaunch).equals(value.get("historical_creation_unknown"))
                &&Boolean.valueOf(!r.postlaunch).equals(value.get("business_dispatch_absent_in_original_receipts")),"PUBLIC_RECOVERY_PROOF_PHASE_FLAGS");
        need(Boolean.FALSE.equals(value.get("automatic_resume"))&&Boolean.FALSE.equals(value.get("broker_release_response")),"PUBLIC_RECOVERY_PROOF_FLAGS");
        JSONObject first=value.getJSONObject("before"),last=value.getJSONObject("after");sample(first,r,begin,end);sample(last,r,begin,end);
        need(number(first,"finished_elapsed_ms")<=number(last,"started_elapsed_ms")&&same(first.getJSONObject("physical"),last.getJSONObject("physical"))
                &&number(first.getJSONObject("process"),"self_pid")==number(last.getJSONObject("process"),"self_pid")
                &&number(first.getJSONObject("process"),"self_start_ticks")==number(last.getJSONObject("process"),"self_start_ticks"),"PUBLIC_RECOVERY_DOUBLE_SAMPLE_CHANGED");
        // Current owned-resource absence is distinct from an empty profile history.
        // Rebuild both complete public history proofs, preserving all unrelated
        // records and their order; only naturally increasing inactivity may differ.
        long ageAdvanceSeconds=(number(last,"finished_elapsed_ms")-number(first,"started_elapsed_ms"))/1000+2;
        PublicProfileRecentHistory.requireSameEvidence(first.getJSONObject("recents"),last.getJSONObject("recents"),r.target,ageAdvanceSeconds);
        return object(value.toString().getBytes(StandardCharsets.UTF_8));
    }
    private static void sample(JSONObject s,Request r,long begin,long end)throws Exception{
        ProfilePrelaunchRecovery.keys(s,"started_elapsed_ms","finished_elapsed_ms","process","live","recents","displays","physical","target_sha256");
        long a=number(s,"started_elapsed_ms"),b=number(s,"finished_elapsed_ms");need(a>=begin&&b>=a&&b<=end&&r.target.sha256.equals(string(s,"target_sha256")),"PUBLIC_RECOVERY_SAMPLE_CLOCK");
        JSONObject p=s.getJSONObject("process");ProfilePrelaunchRecovery.keys(p,"complete","old_creator_absent","started_elapsed_ms","finished_elapsed_ms","self_pid","self_start_ticks","process_count","inspected_count","inventory_sha256");
        need(Boolean.TRUE.equals(p.get("complete"))&&Boolean.TRUE.equals(p.get("old_creator_absent"))&&number(p,"started_elapsed_ms")>=a
                &&number(p,"finished_elapsed_ms")>=number(p,"started_elapsed_ms")&&number(p,"finished_elapsed_ms")<=b
                &&number(p,"self_pid")>0&&number(p,"self_start_ticks")>0&&number(p,"process_count")>0&&number(p,"process_count")<=65536
                &&number(p,"inspected_count")>0&&number(p,"inspected_count")<=number(p,"process_count")
                &&ProfileIdentity.hash(string(p,"inventory_sha256")),"PUBLIC_RECOVERY_PROCESS_SAMPLE");
        JSONObject live=s.getJSONObject("live"),recent=s.getJSONObject("recents"),displays=s.getJSONObject("displays");
        if(r.postlaunch){
            ProfilePrelaunchRecovery.keys(live,"complete","root_count","leaf_count","snapshot_sha256","target_user_id","target_task_ids",
                    "all_task_ids","recorded_owned_ids_absent","recorded_display_empty");
            need(Boolean.TRUE.equals(live.get("recorded_owned_ids_absent"))&&Boolean.TRUE.equals(live.get("recorded_display_empty")),"PUBLIC_POSTLAUNCH_LIVE_ABSENCE");
            JSONArray ids=live.getJSONArray("all_task_ids");TreeSet<Long> seen=new TreeSet<Long>();
            need(ids.length()>=number(live,"root_count")&&ids.length()<=number(live,"root_count")+number(live,"leaf_count"),"PUBLIC_POSTLAUNCH_LIVE_MEMBERSHIP");
            for(int i=0;i<ids.length();i++){long id=numberAt(ids,i);need(id>0&&id<=Integer.MAX_VALUE&&seen.add(id)
                    &&id!=r.ownedRootTaskId&&id!=r.ownedLeafTaskId,"PUBLIC_POSTLAUNCH_OWNED_ID_REUSED");}
            ProfilePrelaunchRecovery.keys(displays,"complete","count","snapshot_sha256","exact_name_absent","recorded_id_absent");
            need(Boolean.TRUE.equals(displays.get("recorded_id_absent")),"PUBLIC_POSTLAUNCH_DISPLAY_ID_REUSED");
        }else{
            ProfilePrelaunchRecovery.keys(live,"complete","root_count","leaf_count","snapshot_sha256","target_user_id","target_task_ids");
            ProfilePrelaunchRecovery.keys(displays,"complete","count","snapshot_sha256","exact_name_absent");
        }
        need(Boolean.TRUE.equals(live.get("complete"))&&number(live,"root_count")>0&&number(live,"root_count")<=ProfileTaskPolicy.MAX_ROOTS
                &&number(live,"leaf_count")>=0&&number(live,"leaf_count")<=ProfileTaskPolicy.MAX_LEAVES&&ProfileIdentity.hash(string(live,"snapshot_sha256"))
                &&number(live,"target_user_id")==10&&live.getJSONArray("target_task_ids").length()==0,"PUBLIC_RECOVERY_LIVE_SAMPLE");
        PublicProfileRecentHistory.requireSameEvidence(recent,recent,r.target);
        r.requireRecordedRecentsAbsent(string(recent,"raw_text"));
        need(Boolean.TRUE.equals(displays.get("complete"))&&number(displays,"count")>=2&&number(displays,"count")<=256
                &&ProfileIdentity.hash(string(displays,"snapshot_sha256"))&&Boolean.TRUE.equals(displays.get("exact_name_absent")),"PUBLIC_RECOVERY_DISPLAY_SAMPLE");
        JSONObject physical=s.getJSONObject("physical");ProfilePrelaunchRecovery.keys(physical,"0","1");
        need(ProfileIdentity.hash(string(physical,"0"))&&ProfileIdentity.hash(string(physical,"1")),"PUBLIC_RECOVERY_PHYSICAL_SAMPLE");
    }
    public static JSONObject object(byte[] b)throws Exception{return ProfilePrelaunchRecovery.object(b);}
    public static String string(JSONObject o,String k)throws Exception{return ProfilePrelaunchRecovery.string(o,k);}
    public static long number(JSONObject o,String k)throws Exception{return ProfilePrelaunchRecovery.number(o,k);}
    private static long numberAt(JSONArray a,int i)throws Exception{Object value=a.get(i);need(value instanceof Integer||value instanceof Long,"PUBLIC_RECOVERY_ARRAY_INTEGER");return ((Number)value).longValue();}
    public static void need(boolean b,String error)throws IOException{if(!b)throw new IOException(error);}
    public static boolean same(Object a,Object b)throws Exception{return canonical(a).equals(canonical(b));}
    public static String canonical(Object value)throws Exception{
        if(value==JSONObject.NULL)return "null";
        if(value instanceof JSONObject){JSONObject o=(JSONObject)value;TreeSet<String> names=new TreeSet<String>();Iterator<String> i=o.keys();while(i.hasNext())names.add(i.next());
            StringBuilder out=new StringBuilder("{");for(String key:names){if(out.length()>1)out.append(',');out.append(JSONObject.quote(key)).append(':').append(canonical(o.get(key)));}return out.append('}').toString();}
        if(value instanceof JSONArray){JSONArray a=(JSONArray)value;StringBuilder out=new StringBuilder("[");for(int i=0;i<a.length();i++){if(i>0)out.append(',');out.append(canonical(a.get(i)));}return out.append(']').toString();}
        if(value instanceof String)return JSONObject.quote((String)value);
        need(value instanceof Boolean||value instanceof Integer||value instanceof Long,"PUBLIC_RECOVERY_UNSUPPORTED_JSON_VALUE");return value.toString();
    }
    private static JSONObject without(JSONObject in,String... keys)throws Exception{JSONObject out=object(in.toString().getBytes(StandardCharsets.UTF_8));for(String key:keys)out.remove(key);return out;}
    private static void put(DataOutputStream out,byte[] raw)throws Exception{out.writeInt(raw.length);out.write(raw);}
    private static byte[] take(DataInputStream in,int max)throws Exception{int n=in.readInt();need(n>0&&n<=max,"PUBLIC_RECOVERY_WIRE_LENGTH");byte[] b=new byte[n];in.readFully(b);return b;}
}
