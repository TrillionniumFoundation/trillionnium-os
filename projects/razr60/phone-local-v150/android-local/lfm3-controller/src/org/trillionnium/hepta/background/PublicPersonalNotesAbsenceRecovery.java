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

/** Independent current absence for an expired personal Notes lease. The failed
 * task and its historical broker records stay unchanged. These current absence
 * observations cannot create an App receipt or authorize any business effect. */
public final class PublicPersonalNotesAbsenceRecovery {
    public static final String REQUEST_SCHEMA="hepta.personal-notes-absence-request.v1";
    public static final String DRAINED_REQUEST_SCHEMA="hepta.personal-notes-absence-request.v2";
    public static final String WORKFLOW_CLOSE_REQUEST_SCHEMA="hepta.personal-notes-absence-request.v3";
    private static final String WORKFLOW_ABORTED_REQUEST_SCHEMA="hepta.personal-notes-absence-request.v13-workflow-aborted-after-back";
    private static final String WORKFLOW_ABORTED_SOURCE="fresh_workflow_aborted_after_back_personal_notes_absence_with_preserved_failure";
    private static final String WORKFLOW_ABORTED_PROOF_SCHEMA="hepta.personal-notes-workflow-aborted-after-back-current-absence.v1";
    private static final String[] WORKFLOW_ABORTED_INPUTS={"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output",
            "step_model","step_action","fixed_intent_attempt","model_request_receipt","model_session_receipt",
            "native_session_receipt","generation_identity","generation_cleanup_receipt","workflow_grant","child_1_action",
            "workflow_aborted","child_1_planned","readiness","completion_identity","created_after","child_1_before","aborted_history"};
    private static final String WORKFLOW_RELEASED_REPLY_LOST_REQUEST_SCHEMA="hepta.personal-notes-absence-request.v12-workflow-released-reply-lost";
    private static final String WORKFLOW_RELEASED_REPLY_LOST_SOURCE="fresh_workflow_released_reply_lost_personal_notes_absence_with_preserved_failure";
    private static final String WORKFLOW_RELEASED_REPLY_LOST_PROOF_SCHEMA="hepta.personal-notes-workflow-released-reply-lost-current-absence.v1";
    private static final String WORKFLOW_FOREIGN_HISTORY_REQUEST_SCHEMA="hepta.personal-notes-absence-request.v11-workflow-foreign-history";
    private static final String WORKFLOW_FOREIGN_HISTORY_SOURCE="fresh_workflow_foreign_history_personal_notes_absence_with_preserved_failure";
    private static final String WORKFLOW_FOREIGN_HISTORY_PROOF_SCHEMA="hepta.personal-notes-workflow-foreign-history-current-absence.v1";
    private static final String WORKFLOW_PARTIAL_RETIREMENT_REQUEST_SCHEMA="hepta.personal-notes-absence-request.v8-workflow-partial-retirement";
    private static final String WORKFLOW_PARTIAL_RETIREMENT_SOURCE="fresh_workflow_partial_retirement_personal_notes_absence_with_preserved_failure";
    private static final String WORKFLOW_PARTIAL_RETIREMENT_PROOF_SCHEMA="hepta.personal-notes-workflow-partial-retirement-current-absence.v1";
    private static final String WORKFLOW_RETIREMENT_REFUSED_REQUEST_SCHEMA="hepta.personal-notes-absence-request.v7-workflow-retirement-refused";
    private static final String WORKFLOW_RETIREMENT_REFUSED_SOURCE="fresh_workflow_retirement_refused_personal_notes_absence_with_preserved_failure";
    private static final String WORKFLOW_RETIREMENT_REFUSED_PROOF_SCHEMA="hepta.personal-notes-workflow-retirement-refused-current-absence.v1";
    private static final String INITIALIZATION_REQUEST_SCHEMA="hepta.personal-notes-absence-request.v9-initialization";
    private static final String INITIALIZATION_STARTUP_SCHEMA="hepta.personal-notes-absence-request.v10-initialization-startup";
    private static final String INITIALIZATION_PROOF_SCHEMA="hepta.personal-notes-initialization-current-absence.v1";
    private static final String INITIALIZATION_SOURCE="fresh_initialization_failure_personal_notes_absence_with_preserved_failure";
    private static final String RELEASED_BEFORE_MODEL_SCHEMA="hepta.personal-notes-absence-request.v4";
    private static final String[] RELEASED_BEFORE_MODEL_INPUTS={"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output",
            "initial_binding","scope_binding","completion_identity"};
    private static final String LOST_LAUNCH_STARTUP_SCHEMA="hepta.personal-notes-absence-request.v5";
    private static final String[] LOST_LAUNCH_STARTUP_INPUTS={"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output",
            "initial_binding","scope_binding","completion_identity","origin_control","interruption_latch"};
    private static final String CANCELLED_REQUEST_SCHEMA="hepta.personal-notes-absence-request.v6-cancelled";
    private static final String CANCELLED_SOURCE="fresh_cancelled_personal_notes_absence_with_preserved_failure";
    private static final String CANCELLED_PROOF_SCHEMA="hepta.personal-notes-cancelled-current-absence.v1";
    private static final String[] CANCELLED_BASE_INPUTS={"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output",
            "model_session_receipt","native_session_receipt","generation_identity","generation_cleanup_receipt","cancelled_history"};
    public static final String SCHEMA="hepta.personal-notes-current-absence.v2";
    public static final String SOURCE="fresh_personal_notes_absence_with_preserved_failure";
    public static final String PACKAGE="com.motorola.stylus";
    public static final long LIMIT_MS=12000,TTL_MS=540000,EXPIRY_GRACE_MS=2000;
    public static final int MAX_ORIGINAL=131072,MAX_BUNDLE=262144,MAX_WIRE=65536,MAX_OUTPUT=524288,MAX_RECEIPT=786432;
    private static final String[] INPUTS={"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output"};
    private static final String[] DRAINED_INPUTS={"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output",
            "step_model","step_action","fixed_intent_attempt","model_request_receipt","model_session_receipt",
            "native_session_receipt","generation_identity","generation_cleanup_receipt"};
    private static final String[] WORKFLOW_CLOSE_INPUTS={"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output",
            "step_model","step_action","fixed_intent_attempt","model_request_receipt","model_session_receipt",
            "native_session_receipt","generation_identity","generation_cleanup_receipt","workflow_result","workflow_grant",
            "child_1_action","child_2_action","child_1_proof","child_2_proof","completion_candidate","completion_identity"};
    private PublicPersonalNotesAbsenceRecovery(){}
    public static final class Request {
        public final int ownerUid,oldBoot,requestBoot,displayId,targetUid;
        public final long created,expires,started,deadline;
        public final String requestId,taskId,generation,ownerSha256,displayName,journalSha256,originalsSha256,currentControlSha256;
        public final PublicOwnGroupPolicy.Scope publicScope;
        public final java.util.Set<Integer> recordedTaskIds;
        public final boolean postModelDrained,workflowCloseFailed,workflowRetirementRefused,workflowPartialRetirement,workflowForeignHistoryRetirement,workflowReleasedReplyLost,cancelledAfterActions;
        public final boolean workflowAbortedAfterBack;
        private final boolean abortedStartup;
        private final boolean prelaunchCreateFailure;
        private final boolean releasedTerminal;
        public final boolean releasedBeforeModel,initializationFailed;
        private final boolean interruptedLostLaunch;
        private final Map<String,byte[]> originals;
        private final byte[] currentControl;
        private final String controllerText;
        private Request(Map<String,byte[]> input,byte[] control,JSONObject controller,int uid,String id,long now,int boot)throws Exception{
            need(uid>=10000&&uid<90000&&ProfileIdentity.uuid(id)&&now>=0&&boot>=0,"NOTES_REQUEST_IDENTITY");
            need(input!=null,"NOTES_INPUT_SET");
            cancelledAfterActions=input.containsKey("cancelled_history");
            workflowAbortedAfterBack=input.containsKey("aborted_history");
            abortedStartup=workflowAbortedAfterBack&&Boolean.TRUE.equals(object(input.get("aborted_history")).get("startup_archive"));
            need(!workflowAbortedAfterBack||!cancelledAfterActions,"NOTES_ABORTED_INPUT_KIND");
            boolean startupInputs=input.keySet().equals(new TreeSet<String>(Arrays.asList(LOST_LAUNCH_STARTUP_INPUTS)));
            boolean beforeModelInputs=startupInputs||input.keySet().equals(new TreeSet<String>(Arrays.asList(RELEASED_BEFORE_MODEL_INPUTS)));
            workflowCloseFailed=input.keySet().equals(new TreeSet<String>(Arrays.asList(WORKFLOW_CLOSE_INPUTS)));
            postModelDrained=workflowAbortedAfterBack||workflowCloseFailed||input.keySet().equals(new TreeSet<String>(Arrays.asList(DRAINED_INPUTS)));
            need(cancelledAfterActions||beforeModelInputs||postModelDrained||input.keySet().equals(new TreeSet<String>(Arrays.asList(INPUTS))),"NOTES_INPUT_SET");
            LinkedHashMap<String,byte[]> copy=new LinkedHashMap<String,byte[]>();int total=0;
            String[] names=workflowAbortedAfterBack?abortedNames(abortedStartup):cancelledAfterActions?cancelledNames(object(input.get("cancelled_history"))):startupInputs?LOST_LAUNCH_STARTUP_INPUTS:beforeModelInputs?RELEASED_BEFORE_MODEL_INPUTS:workflowCloseFailed?WORKFLOW_CLOSE_INPUTS:postModelDrained?DRAINED_INPUTS:INPUTS;
            need(input.keySet().equals(new TreeSet<String>(Arrays.asList(names))),"NOTES_INPUT_SET");
            for(String name:names){byte[] raw=input.get(name);need(raw!=null&&raw.length>0&&raw.length<=MAX_ORIGINAL,"NOTES_INPUT_BOUND");
                total+=raw.length;need(total<=MAX_BUNDLE,"NOTES_INPUT_BOUND");copy.put(name,raw.clone());}
            originals=Collections.unmodifiableMap(copy);
            JSONObject j=object(originals.get("journal"));
            need("hepta.background-session.v1".equals(string(j,"schema"))&&number(j,"app_uid")==uid,"NOTES_JOURNAL_OWNER");
            taskId=string(j,"task_id");generation=string(j,"generation");ownerSha256=string(j,"owner_sha256");displayName=string(j,"display_name");
            need(taskId.matches("[0-9a-f]{32}")&&ProfileIdentity.uuid(generation)&&ProfileIdentity.hash(ownerSha256)
                    &&("hepta-bg-"+generation).equals(displayName)&&displayName.equals(string(j,"socket")),"NOTES_JOURNAL_IDENTITY");
            long d=number(j,"display_id");
            initializationFailed=beforeModelInputs&&d==-1;interruptedLostLaunch=startupInputs;
            releasedBeforeModel=beforeModelInputs&&!initializationFailed;
            need(initializationFailed||(d>1&&d<=Integer.MAX_VALUE),"NOTES_RECORDED_DISPLAY");displayId=(int)d;
            need("CLEANUP_UNKNOWN".equals(string(j,"state")),"NOTES_JOURNAL_PHASE");
            yes(j,"owned_task_retirement_required","personal_notes_retirement_required","public_own_group_experimental");
            no(j,"public_scope_serialization_grants_authority");
            for(String key:new String[]{"profile_target_wire","profile_target_sha256","profile_isolation_required","profile_launch_attempted"})
                need(!j.has(key),"NOTES_PROFILE_SCOPE_FORBIDDEN");
            created=number(j,"created_elapsed_ms");expires=number(j,"expires_elapsed_ms");long old=number(j,"boot_count");
            need(created>=0&&expires>created&&expires-created==TTL_MS&&expires<Long.MAX_VALUE-EXPIRY_GRACE_MS
                    &&old>=0&&old<=Integer.MAX_VALUE&&now<=Long.MAX_VALUE-LIMIT_MS,"NOTES_REQUEST_CLOCK");
            oldBoot=(int)old;ownerUid=uid;requestId=id;started=now;deadline=now+LIMIT_MS;requestBoot=boot;
            publicScope=PublicOwnGroupPolicy.Scope.fromWire(string(j,"public_own_group_scope_wire"));
            publicScope.requireConfig(uid,generation,expires,null);
            need(publicScope.targetUserId==0&&publicScope.targetSha256.isEmpty()&&publicScope.sha256.equals(string(j,"public_own_group_scope_sha256"))
                    &&publicScope.taskId.equals(taskId)&&publicScope.ownerSha256.equals(ownerSha256)
                    &&publicScope.createdElapsedMs==created&&publicScope.bootCount==oldBoot,"NOTES_PUBLIC_SCOPE_BINDING");
            JSONObject selection=j.getJSONObject("selection");requireSelection(selection);
            JSONObject owner=object(originals.get("owner")),bootstrap=object(originals.get("bootstrap")),cleanup=object(originals.get("cleanup")),result=object(originals.get("result"));
            // Derived only from the immutable original close failure, never a caller mode.
            workflowRetirementRefused=workflowCloseFailed&&"NOTES_RETIREMENT_TOP_IDENTITY".equals(
                    string(cleanup.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup"),"failure"));
            workflowPartialRetirement=workflowCloseFailed&&"NOTES_RETIREMENT_GLOBAL_CHANGED_DURING_READ".equals(
                    string(cleanup.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup"),"failure"));
            workflowForeignHistoryRetirement=workflowCloseFailed&&"NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED".equals(
                    string(cleanup.getJSONObject("last_broker_response").getJSONObject("personal_notes_cleanup"),"failure"));
            // Derive the prelaunch shape from the original records, never from a
            // caller's recovery flag. A create response may be dispatched even
            // though the application launch and every model request were not.
            prelaunchCreateFailure=!releasedBeforeModel&&Boolean.FALSE.equals(cleanup.get("bootstrap_dispatched"));
            need(!prelaunchCreateFailure||(!postModelDrained&&!cancelledAfterActions),"NOTES_PRELAUNCH_MODEL_INPUTS");
            need("hepta.local-owner.v1".equals(string(owner,"schema"))&&taskId.equals(string(owner,"task_id"))
                    &&ownerSha256.equals(string(owner,"instruction_utf8_sha256"))&&ownerSha256.equals(ProfileIdentity.sha(string(owner,"instruction")))
                    &&same(selection,owner.getJSONObject("background_request")),"NOTES_OWNER_BINDING");
            no(owner,"external_model","automatic_resume");bindBackground(bootstrap);bindBackground(cleanup);
            need("CLEANUP_UNKNOWN".equals(string(cleanup,"state")),"NOTES_ORIGINAL_FAILURE_PHASE");
            yes(cleanup,"retired","spawn_attempted");no(cleanup,"cleanup_known","bootstrap_model_issued");
            Object exited=cleanup.get("broker_process_exit_observed"),exit=cleanup.get("broker_process_exit_code");
            need(exited instanceof Boolean&&((Boolean.FALSE.equals(exited)&&exit==JSONObject.NULL)
                    ||(Boolean.TRUE.equals(exited)&&(exit instanceof Integer||exit instanceof Long)&&((Number)exit).longValue()>=0&&((Number)exit).longValue()<=255)),"NOTES_OLD_EXIT_TYPE");
            JSONObject broker=object(originals.get("broker_receipt"));requireBroker(broker);
            if(cancelledAfterActions)requireCancelledBrokerReceipt(cleanup.getJSONObject("broker_output"),broker);
            else if(workflowForeignHistoryRetirement)requireWorkflowRetirementBrokerReceipt(cleanup.getJSONObject("broker_output"),broker);
            else if(workflowPartialRetirement)requireWorkflowRetirementBrokerReceipt(cleanup.getJSONObject("broker_output"),broker);
            else if(workflowRetirementRefused)requireWorkflowRetirementBrokerReceipt(cleanup.getJSONObject("broker_output"),broker);
            else need(same(broker,cleanup.getJSONObject("broker_output"))&&Boolean.TRUE.equals(broker.get("persisted")),"NOTES_BROKER_RECEIPT_CHANGED");
            byte[] output=originals.get("broker_output");
            need(number(broker,"stored_bytes")==output.length&&number(broker,"observed_bytes")==output.length
                    &&ProfileIdentity.sha(output).equals(string(broker,"stored_sha256")),"NOTES_BROKER_OUTPUT_BYTES");
            requireBootstrapPrefix(bootstrap.getJSONObject("broker_output"),broker,output);
            JSONObject terminal=initializationFailed?initializationTerminal(output):cancelledAfterActions?cancelledTerminal(output):object(output);
            // A failed action can complete its owned retirement before returning
            // ok=false. Derive this shape from the preserved terminal bytes; it
            // still requires the complete one-step drained model proof and fresh
            // independent absence. It never promotes the failed business result.
            releasedTerminal="RELEASED".equals(string(terminal,"state"));
            workflowReleasedReplyLost=workflowCloseFailed&&releasedTerminal
                    &&"后台响应提前结束".equals(cleanup.opt("cleanup_error"))
                    &&Boolean.FALSE.equals(cleanup.get("broker_process_exit_observed"))&&cleanup.get("broker_process_exit_code")==JSONObject.NULL
                    &&"ACTIVE".equals(cleanup.getJSONObject("last_broker_response").opt("state"))
                    &&"state".equals(cleanup.getJSONObject("last_broker_response").opt("operation"));
            need((!releasedTerminal||postModelDrained||releasedBeforeModel||initializationFailed)&&(!releasedBeforeModel||releasedTerminal),"NOTES_RELEASED_MODEL_STATE");
            need("hepta.background-broker-terminal.v1".equals(string(terminal,"schema"))&&generation.equals(string(terminal,"generation"))
                    &&number(terminal,"display_id")==displayId&&(releasedTerminal||"CLEANUP_UNKNOWN".equals(string(terminal,"state")))
                    &&publicScope.sha256.equals(string(terminal,"display_scope_sha256")),"NOTES_BROKER_TERMINAL_BINDING");
            if(workflowReleasedReplyLost){
                yes(terminal,"release_confirmed");yes(broker,"eof_seen");
                no(cleanup,"broker_process_exit_observed");
                need(cleanup.get("broker_process_exit_code")==JSONObject.NULL,"NOTES_WORKFLOW_LOST_CLOSE_OLD_EXIT");
            }else if(releasedTerminal){
                yes(terminal,"release_confirmed");yes(cleanup,"broker_process_exit_observed");yes(broker,"eof_seen");
                need(number(cleanup,"broker_process_exit_code")== (initializationFailed?70:0),"NOTES_RELEASED_BROKER_EXIT");
            }else no(terminal,"release_confirmed");
            yes(terminal,"public_scope_admission_retired");
            java.util.Set<Integer> ids=new TreeSet<Integer>();JSONObject last=null;
            if(initializationFailed){
                targetUid=initializationTargetUid();
                requireInitializationRecords(bootstrap,cleanup,broker,terminal,owner,result);
            }else{
            JSONObject custody=terminal.getJSONObject("personal_notes_cleanup");
            targetUid=notesCustody(custody,releasedTerminal);
            last=cleanup.getJSONObject("last_broker_response");
            need(generation.equals(string(last,"generation"))&&number(last,"display_id")==displayId
                    &&publicScope.sha256.equals(string(last,"display_scope_sha256"))&&number(last,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_VERSION,
                    "NOTES_LAST_RESPONSE_BINDING");
            need(notesCustody(last.getJSONObject("personal_notes_cleanup"),releasedTerminal&&!releasedBeforeModel&&!workflowReleasedReplyLost)==targetUid,"NOTES_TARGET_UID_CHANGED");
            if(releasedTerminal&&!releasedBeforeModel&&!workflowReleasedReplyLost){
                need(same(custody,last.getJSONObject("personal_notes_cleanup")),"NOTES_RELEASED_CUSTODY_CHANGED");
                yes(last,"public_scope_closing");
            }
            for(JSONObject c:new JSONObject[]{custody,last.getJSONObject("personal_notes_cleanup")}){
                JSONArray observed=c.getJSONArray("actual_observed_tasks");need(observed.length()<=32,"NOTES_RECORDED_TASK_BOUND");
                for(int i=0;i<observed.length();i++){JSONObject row=observed.getJSONObject(i);long task=number(row,"task_id");
                    need(task>0&&task<=Integer.MAX_VALUE&&number(row,"user_id")==0&&number(row,"actual_effective_uid")==targetUid
                            &&number(row,"display_id")==displayId&&number(row,"parent_id")<0
                            &&Boolean.FALSE.equals(row.get("serialized_token_grants_authority")),"NOTES_RECORDED_TASK_IDENTITY");ids.add((int)task);}
            }
            JSONObject location=last.getJSONObject("public_task_location");
            need("hepta.public-own-group.task-location.v1".equals(string(location,"schema"))&&generation.equals(string(location,"generation"))
                    &&number(location,"display_id")==displayId&&number(location,"target_user_id")==0
                    &&Boolean.FALSE.equals(location.get("task_mutation_authority")),"NOTES_ORIGINAL_TASK_LOCATION");
            JSONArray located=location.getJSONArray("observed_owned_task_ids");need(((prelaunchCreateFailure||releasedBeforeModel)?located.length()==0:located.length()>0)&&located.length()<=32,"NOTES_RECORDED_TASK_BOUND");
            for(int i=0;i<located.length();i++){long task=numberAt(located,i);need(task>0&&task<=Integer.MAX_VALUE,"NOTES_RECORDED_TASK_ID");ids.add((int)task);}
            if(releasedBeforeModel){
                requireLostLaunchReply(bootstrap,cleanup,last,location,custody,terminal,ids,owner,result);
            }else if(prelaunchCreateFailure){
                need("CLEANUP_UNKNOWN".equals(string(bootstrap,"state"))&&"create".equals(string(last,"operation"))
                        &&"CLEANUP_UNKNOWN".equals(string(last,"state"))&&ProfileIdentity.uuid(string(last,"request_id"))
                        &&!last.has("task_launch_policy")&&ids.isEmpty(),"NOTES_PRELAUNCH_CREATE_RESPONSE");
                no(last,"ok");yes(last,"dispatched","public_scope_admission_retired","public_scope_closing");
                long observed=number(location,"observed_elapsed_ms");
                need(observed>=created&&observed<=number(result,"terminal_decided_elapsed_ms")
                        &&number(location,"initial_task_count")>=0,"NOTES_PRELAUNCH_LOCATION_CLOCK");
                no(location,"retired","physical_user_activity_frozen","recents_unchanged_claimed");
            }else{
                JSONObject launched=cancelledAfterActions?bootstrap.getJSONObject("last_broker_response"):(workflowCloseFailed||workflowAbortedAfterBack)?object(originals.get("step_action")).getJSONObject("background_session").getJSONObject("last_broker_response"):last;
                JSONObject launch=launched.getJSONObject("task_launch_policy");
                need("hepta.background-task-launch-policy.v1".equals(string(launch,"schema"))&&generation.equals(string(launch,"generation"))
                        &&number(launch,"display_id")==displayId&&PACKAGE.equals(string(launch,"package"))&&number(launch,"target_uid")==targetUid
                        &&string(launch,"component").startsWith(PACKAGE+"/")&&string(launch,"request_id").equals(string(launched,"request_id"))
                        &&Boolean.TRUE.equals(launch.get("activity_info_rechecked_before_dispatch")),"NOTES_ORIGINAL_LAUNCH_TARGET");
            }
            if(cancelledAfterActions)requireCancelledBootstrap(bootstrap.getJSONObject("last_broker_response"),last,terminal,ids);
            else if(workflowAbortedAfterBack)requireAbortedBootstrap(bootstrap.getJSONObject("last_broker_response"),
                    object(originals.get("step_action")).getJSONObject("background_session").getJSONObject("last_broker_response"),last,terminal,ids);
            else if(workflowReleasedReplyLost)requireWorkflowReleasedReplyLostBootstrap(bootstrap.getJSONObject("last_broker_response"),
                    object(originals.get("step_action")).getJSONObject("background_session").getJSONObject("last_broker_response"),last,terminal,ids);
            else if(workflowForeignHistoryRetirement)requireWorkflowForeignHistoryBootstrap(bootstrap.getJSONObject("last_broker_response"),
                    object(originals.get("step_action")).getJSONObject("background_session").getJSONObject("last_broker_response"),last,terminal,ids);
            else if(workflowPartialRetirement)requireWorkflowPartialRetirementBootstrap(bootstrap.getJSONObject("last_broker_response"),
                    object(originals.get("step_action")).getJSONObject("background_session").getJSONObject("last_broker_response"),last,terminal,ids);
            else if(workflowRetirementRefused)requireWorkflowRetirementRefusalBootstrap(bootstrap.getJSONObject("last_broker_response"),
                    object(originals.get("step_action")).getJSONObject("background_session").getJSONObject("last_broker_response"),last,terminal,ids);
            else if(workflowCloseFailed)requireWorkflowBootstrap(bootstrap.getJSONObject("last_broker_response"),
                    object(originals.get("step_action")).getJSONObject("background_session").getJSONObject("last_broker_response"),last,terminal,ids);
            else if(postModelDrained)requireDrainedBootstrap(bootstrap.getJSONObject("last_broker_response"),last,ids);
            else need(same(bootstrap.getJSONObject("last_broker_response"),last),"NOTES_ORIGINAL_RESPONSE_CHANGED");
            }
            recordedTaskIds=Collections.unmodifiableSet(ids);
            if(cancelledAfterActions)requireCancelledResult(result,owner,last);
            else {
            need(taskId.equals(string(result,"task_id"))&&"blocked".equals(string(result,"status"))&&number(result,"steps")== (postModelDrained?1:0)
                    &&Boolean.FALSE.equals(result.get("cleanup_known"))&&Boolean.FALSE.equals(result.get("completion_verified"))
                    &&Boolean.FALSE.equals(result.get("model_reported_success"))&&Boolean.FALSE.equals(result.get("external_model"))
                    &&Boolean.FALSE.equals(result.get("automatic_replay"))&&Boolean.valueOf(workflowCloseFailed).equals(result.get("controller_completion_requested"))
                    &&(postModelDrained||(result.get("last_action_execution")==JSONObject.NULL&&result.get("final_observation_id")==JSONObject.NULL))
                    &&result.get("model_done_status")==JSONObject.NULL&&result.get("completion_actor")==JSONObject.NULL,
                    "NOTES_RECOVERY_BUSINESS_OR_MODEL_DISPATCH");
            for(String key:new String[]{"observation_read_worker_pending_at_terminal","action_worker_pending_at_terminal","native_cancel_worker_pending_at_terminal"})
                need(Boolean.FALSE.equals(result.get(key)),"NOTES_RECOVERY_WORKER_PENDING");
            need(result.getJSONArray("submit_attempts").length()==0&&result.getJSONArray("fixed_intent_attempts").length()==(postModelDrained?1:0)
                    &&(!result.has("profile_permission_preparation")||result.get("profile_permission_preparation")==JSONObject.NULL),"NOTES_RECOVERY_EFFECT_ATTEMPT");
            JSONObject nativeWork=result.getJSONObject("native_cancellation"),model=result.getJSONObject("model_session");
            need(taskId.equals(string(nativeWork,"task_id"))&&Boolean.TRUE.equals(nativeWork.get("native_cleanup_known"))
                    &&nativeWork.get("run_id")==JSONObject.NULL,"NOTES_RECOVERY_NATIVE_UNKNOWN");
            for(String key:new String[]{"request_reserved","executor_accepted","worker_started","signal_entered","submission_unknown"})
                need(Boolean.FALSE.equals(nativeWork.get(key)),"NOTES_RECOVERY_NATIVE_DISPATCH");
            if(workflowAbortedAfterBack)requireAbortedModel(result,owner,model,
                    object(originals.get("step_action")).getJSONObject("background_session").getJSONObject("last_broker_response"));
            else if(workflowCloseFailed)requireWorkflowModel(result,owner,model,
                    object(originals.get("step_action")).getJSONObject("background_session").getJSONObject("last_broker_response"));
            else if(postModelDrained)requireDrainedModel(result,owner,model,last);
            else need(taskId.equals(string(model,"task_id"))&&Boolean.FALSE.equals(model.get("process_started"))&&Boolean.FALSE.equals(model.get("process_exit_observed"))
                    &&model.get("worker_generation")==JSONObject.NULL&&model.get("exit_code")==JSONObject.NULL
                    &&Boolean.TRUE.equals(model.get("receipt_valid"))&&model.get("app_receipt_sha256")==JSONObject.NULL,
                    "NOTES_RECOVERY_MODEL_SESSION");
            }
            need(same(cleanup,result.getJSONObject("background_cleanup"))
                    &&same(without(cleanup,"cleanup_known","cleanup_error"),result.getJSONObject("background_session")),"NOTES_RECOVERY_RESULT_CROSS_BINDING");
            JSONObject authorization=owner.getJSONObject("task_authorization"),gate=result.getJSONObject("task_authorization");
            need(ownerSha256.equals(string(gate,"instruction_sha256"))
                    &&string(owner,"task_authorization_sha256").equals(string(result,"task_authorization_sha256"))
                    &&string(owner,"task_authorization_sha256").equals(string(authorization,"authorization_sha256"))
                    &&taskId.equals(string(gate,"task_id")),"NOTES_RECOVERY_AUTHORIZATION_BINDING");
            // The result is a Gate projection with additional state; the owner is immutable authorization.
            Iterator<String> authorizationKeys=authorization.keys();while(authorizationKeys.hasNext()){
                String key=authorizationKeys.next();need(same(authorization.get(key),gate.get(key)),"NOTES_RECOVERY_AUTHORIZATION_CHANGED");}
            for(String key:new String[]{"discovery_run_id","opened_package","catalogue_sha256","discovery_observation_id",
                    "open_run_id","opened_observation_id","pending_open_package"})
                need((postModelDrained||cancelledAfterActions)&&"catalogue_sha256".equals(key)?ProfileIdentity.hash(string(gate,key)):gate.get(key)==JSONObject.NULL,"NOTES_RECOVERY_AUTHORIZATION_EFFECT");
            need(gate.getJSONArray("found_packages").length()==0&&(postModelDrained||cancelledAfterActions||gate.getJSONObject("last_check").length()==0),
                    "NOTES_RECOVERY_AUTHORIZATION_EFFECT");
            long terminalAt=number(result,"terminal_decided_elapsed_ms");need(terminalAt>=created&&terminalAt<=started,"NOTES_RECOVERY_TERMINAL_CLOCK");
            PublicProfileAbsenceRecovery.requireController(controller,uid);controllerText=canonical(controller);
            need(control!=null&&control.length>0&&control.length<=MAX_ORIGINAL,"NOTES_CURRENT_CONTROL_BOUND");
            JSONObject current=object(control);need("hepta.local-session.v1".equals(string(current,"schema"))&&number(current,"app_uid")==uid,
                    "NOTES_CURRENT_CONTROL_OWNER");no(current,"pending","running","automatic_resume");yes(current,"blocked");
            need(taskId.equals(string(current,"task_id"))&&ownerSha256.equals(string(current,"instruction_sha256")),"NOTES_CURRENT_CONTROL_BINDING");
            if(releasedBeforeModel||initializationFailed)requireLostControl(current,owner,result);
            if(cancelledAfterActions)requireCancelledControl(current,owner,result);
            if(workflowAbortedAfterBack)requireAbortedControl(current,owner,result);
            currentControl=control.clone();currentControlSha256=ProfileIdentity.sha(control);
            journalSha256=ProfileIdentity.sha(originals.get("journal"));originalsSha256=ProfileIdentity.sha(canonical(inputHashes()));requireFence(now,boot);
        }


        /** A separate historical kind: one model-issued create and one drained
         * tool Back, followed by an unverified observation and retained custody.
         * The exact task-file manifest is a byte witness, never absence authority. */
        private JSONObject abortedHistory()throws Exception{
            JSONObject history=object(originals.get("aborted_history"));
            keys(history,"schema","startup_archive","task_files");
            need("hepta.personal-notes-aborted-after-back-history.v1".equals(string(history,"schema"))
                    &&history.get("startup_archive") instanceof Boolean
                    &&Boolean.valueOf(abortedStartup).equals(history.get("startup_archive")),"NOTES_ABORTED_HISTORY_SCHEMA");
            return history;
        }
        private JSONArray abortedTaskRow(String name)throws Exception{
            JSONArray rows=abortedHistory().getJSONArray("task_files");JSONArray found=null;
            for(int i=0;i<rows.length();i++){JSONArray row=rows.getJSONArray(i);
                if(name.equals(row.getString(0))){need(found==null,"NOTES_ABORTED_MANIFEST_DUPLICATE");found=row;}}
            need(found!=null,"NOTES_ABORTED_MANIFEST_MISSING");return found;
        }
        public void requireAbortedTaskWitness(String name,byte[] raw)throws Exception{
            need(workflowAbortedAfterBack&&raw!=null,"NOTES_NOT_ABORTED_KIND");JSONArray row=abortedTaskRow(name);
            need(row.length()==3&&numberAt(row,1)==raw.length&&ProfileIdentity.sha(raw).equals(row.getString(2)),
                    "NOTES_ABORTED_RAW_REFERENCE");
        }
        private void requireAbortedManifest(String before,String createdObservation,String childBefore)throws Exception{
            java.util.Set<String> observations=new TreeSet<String>();
            for(String id:new String[]{before,createdObservation,childBefore})
                need(id.matches("[0-9a-f]{32}")&&observations.add(id),"NOTES_ABORTED_CAPTURE_IDENTITY");
            java.util.Set<String> expected=new TreeSet<String>(Arrays.asList("owner.json","scope-binding.json",
                    "completion-installed-identity.json","background-binding.json","background-bootstrap.json","initial-app-catalogue.json",
                    "step-01-before.json","step-01-budget-0.json","step-01-model-0.json","fixed-intent-01-attempt.json","step-01-action.json",
                    "step-01-after.json","step-01-notes-readiness-result.json","step-01-notes-workflow-grant-consumed.json",
                    "step-01-notes-workflow-observation-1.json","step-01-notes-workflow-child-1-planned.json",
                    "step-01-tool-child-01-before.json","step-01-tool-child-01-action.json","step-01-notes-workflow-aborted.json",
                    "background-broker-"+generation+".bin","background-broker-"+generation+".json","background-cleanup.json","result.json"));
            for(String id:observations){expected.add(id+".png");expected.add("scope-observation-"+id+".json");}
            JSONArray rows=abortedHistory().getJSONArray("task_files");
            need(expected.size()==29&&rows.length()==29,"NOTES_ABORTED_MANIFEST_COUNT");String previous="";long total=0;
            for(int i=0;i<rows.length();i++){
                JSONArray row=rows.getJSONArray(i);need(row.length()==3&&row.get(0) instanceof String&&row.get(2) instanceof String,"NOTES_ABORTED_MANIFEST_ROW");
                String name=row.getString(0);long size=numberAt(row,1);
                need(name.compareTo(previous)>0&&expected.remove(name)&&size>0&&size<=MAX_RECEIPT
                        &&ProfileIdentity.hash(row.getString(2)),"NOTES_ABORTED_MANIFEST_ROW");
                previous=name;total+=size;need(total<=8388608,"NOTES_ABORTED_ARCHIVE_BOUND");
            }
            need(expected.isEmpty(),"NOTES_ABORTED_MANIFEST_MISSING");
            for(String[] item:new String[][]{{"owner","owner.json"},{"bootstrap","background-bootstrap.json"},{"cleanup","background-cleanup.json"},
                    {"result","result.json"},{"broker_receipt","background-broker-"+generation+".json"},{"broker_output","background-broker-"+generation+".bin"},
                    {"step_model","step-01-model-0.json"},{"step_action","step-01-action.json"},{"fixed_intent_attempt","fixed-intent-01-attempt.json"},
                    {"workflow_grant","step-01-notes-workflow-grant-consumed.json"},{"child_1_action","step-01-tool-child-01-action.json"},
                    {"workflow_aborted","step-01-notes-workflow-aborted.json"},{"child_1_planned","step-01-notes-workflow-child-1-planned.json"},
                    {"readiness","step-01-notes-readiness-result.json"},{"completion_identity","completion-installed-identity.json"},
                    {"created_after","step-01-after.json"},{"child_1_before","step-01-tool-child-01-before.json"}})
                requireAbortedTaskWitness(item[1],originals.get(item[0]));
            requireAbortedTaskWitness("step-01-notes-workflow-observation-1.json",originals.get("child_1_before"));
            for(String role:new String[]{"created_after","child_1_before"}){
                JSONObject observation=object(originals.get(role));String id=string(observation,"observation_id");
                need(string(observation,"screen_sha256").equals(abortedTaskRow(id+".png").getString(2)),"NOTES_ABORTED_CAPTURE_BYTES");
            }
        }
        private void requireAbortedControl(JSONObject current,JSONObject owner,JSONObject result)throws Exception{
            JSONObject origin=current;
            if(abortedStartup){
                String relative=lostLaunchOriginArchive(current);byte[] raw=originals.get("origin_control");origin=object(raw);String sha=ProfileIdentity.sha(raw);
                need(relative.equals("session-recovery/control-session.json."+sha+".json"),"NOTES_ABORTED_STARTUP_ARCHIVE");
                JSONObject reason=current.getJSONObject("startup_recovery"),ref=reason.getJSONArray("preserved_records").getJSONObject(0),latch=object(originals.get("interruption_latch"));
                need(number(ref,"bytes")==raw.length&&"hepta.session-recovery.v1".equals(string(reason,"schema"))&&"blocked_interrupted".equals(string(reason,"decision"))
                        &&reason.get("read_error")==JSONObject.NULL&&"control-session.interrupted.json".equals(string(reason,"interruption_latch")),"NOTES_ABORTED_STARTUP_RECORD");
                yes(reason,"interruption_latch_observed","interruption_latch_synced");no(reason,"recovery_pending_barrier_observed","automatic_resume","native_cleanup_independently_observed");
                need("hepta.session-interruption-latch.v1".equals(string(latch,"schema"))&&number(latch,"app_uid")==ownerUid
                        &&sha.equals(string(latch.getJSONObject("recovery_reason"),"previous_session_sha256")),"NOTES_ABORTED_STARTUP_LATCH");
                yes(latch,"blocked");no(latch,"cleanup_known","automatic_resume");
            }else need("blocked".equals(string(current,"status")),"NOTES_ABORTED_CURRENT_STATUS");
            need("hepta.local-session.v1".equals(string(origin,"schema"))&&"blocked".equals(string(origin,"status"))&&number(origin,"app_uid")==ownerUid
                    &&taskId.equals(string(origin,"task_id"))&&ownerSha256.equals(string(origin,"instruction_sha256"))&&number(origin,"steps")==1
                    &&string(owner,"task_authorization_sha256").equals(string(origin,"task_authorization_sha256"))
                    &&same(owner.getJSONObject("task_authorization"),origin.getJSONObject("task_authorization"))
                    &&same(owner.getJSONObject("background_request"),origin.getJSONObject("background_request"))
                    &&same(result.getJSONObject("completion_evidence"),origin.getJSONObject("completion_evidence")),"NOTES_ABORTED_ORIGIN_CONTROL");
            yes(origin,"blocked","background_lease_unreleased");
            no(origin,"pending","running","cleanup_known","automatic_resume","external_model","web_helper_lease_unreleased","completion_verified","model_reported_success");
            no(current,"cleanup_known","automatic_resume","external_model");
        }

        private void requireAbortedBootstrap(JSONObject early,JSONObject createdResponse,JSONObject last,JSONObject terminal,
                java.util.Set<Integer> ids)throws Exception{
            JSONObject cleanup=object(originals.get("cleanup")),broker=object(originals.get("broker_receipt"));
            need(!prelaunchCreateFailure&&!releasedTerminal&&!workflowCloseFailed&&postModelDrained&&ids.size()==2
                    &&"后台 socket 尚不可连接".equals(string(cleanup,"cleanup_error"))
                    &&"PUBLIC_SCOPE_POLICY_UNAVAILABLE".equals(string(terminal,"reason")),"NOTES_ABORTED_CUSTODY_KIND");
            no(cleanup,"broker_process_exit_observed");need(cleanup.get("broker_process_exit_code")==JSONObject.NULL,"NOTES_ABORTED_OLD_EXIT");
            no(broker,"eof_seen");yes(broker,"persisted");
            need("state".equals(string(last,"operation"))&&"ACTIVE".equals(string(last,"state"))&&!last.has("task_launch_policy"),"NOTES_ABORTED_LAST_RESPONSE");
            yes(last,"ok");no(last,"dispatched","public_scope_admission_retired","public_scope_closing");
            JSONObject finalCustody=terminal.getJSONObject("personal_notes_cleanup"),lastCustody=last.getJSONObject("personal_notes_cleanup");
            need("hepta.public-personal-notes-cleanup.v2".equals(string(finalCustody,"schema"))
                    &&same(finalCustody.getJSONArray("actual_observed_tasks"),lastCustody.getJSONArray("actual_observed_tasks"))
                    &&"NOTES_RETIREMENT_FINAL_TASKINFO_CHANGED".equals(string(finalCustody,"failure")),"NOTES_ABORTED_RETAINED_CUSTODY");
            yes(finalCustody,"identity_unknown","custodian_retained");
            for(JSONObject custody:new JSONObject[]{finalCustody,lastCustody}){
                no(custody,"pre_release_tasks_verified","release_api_entered","release_api_returned","cleanup_known",
                        "display_absence_verified","live_tasks_absent","all_recents_sections_absent","prior_hidden_history_preserved","no_display_create_attempted");
                need(number(custody,"absence_reads")==0&&number(custody,"pending_owned_reads")==0
                        &&ProfileIdentity.hash(string(custody,"initial_recents_sha256"))&&string(custody,"pre_release_recents_sha256").isEmpty()
                        &&string(custody,"final_recents_sha256").isEmpty(),"NOTES_ABORTED_NO_HISTORICAL_ABSENCE");
            }
            no(lastCustody,"identity_unknown");need(string(lastCustody,"failure").isEmpty(),"NOTES_ABORTED_LAST_CUSTODY");
            java.util.Set<String> requests=new TreeSet<String>();requests.add(string(last,"request_id"));long prior=created;
            for(int stage=0;stage<2;stage++){
                JSONObject response=stage==0?early:createdResponse;
                need(number(response,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_VERSION&&generation.equals(string(response,"generation"))
                        &&number(response,"display_id")==displayId&&publicScope.sha256.equals(string(response,"display_scope_sha256"))
                        &&"ACTIVE".equals(string(response,"state"))&&(stage==0?"launch":"notes.create").equals(string(response,"operation"))
                        &&ProfileIdentity.uuid(string(response,"request_id"))&&requests.add(string(response,"request_id")),"NOTES_ABORTED_RESPONSE");
                yes(response,"ok","dispatched");no(response,"public_scope_admission_retired","public_scope_closing");
                JSONObject custody=response.getJSONObject("personal_notes_cleanup"),location=response.getJSONObject("public_task_location");
                need(notesCustody(custody,false)==targetUid,"NOTES_TARGET_UID_CHANGED");
                no(custody,"identity_unknown","pre_release_tasks_verified","release_api_entered","release_api_returned");
                need(string(custody,"failure").isEmpty(),"NOTES_ABORTED_RESPONSE_CUSTODY");
                need("hepta.public-own-group.task-location.v1".equals(string(location,"schema"))&&generation.equals(string(location,"generation"))
                        &&number(location,"display_id")==displayId&&number(location,"target_user_id")==0
                        &&number(location,"observed_elapsed_ms")>=prior&&number(location,"observed_elapsed_ms")<=number(last.getJSONObject("public_task_location"),"observed_elapsed_ms"),
                        "NOTES_ABORTED_RESPONSE_LOCATION");
                no(location,"task_mutation_authority","retired","physical_user_activity_frozen","recents_unchanged_claimed");prior=number(location,"observed_elapsed_ms");
                JSONArray oldRows=custody.getJSONArray("actual_observed_tasks"),finalRows=finalCustody.getJSONArray("actual_observed_tasks");
                need(oldRows.length()==(stage==0?1:2)&&finalRows.length()==2,"NOTES_ABORTED_TASK_SET");java.util.Set<Integer> oldIds=new TreeSet<Integer>();
                for(int i=0;i<oldRows.length();i++){JSONObject row=oldRows.getJSONObject(i);long task=number(row,"task_id");boolean found=false;
                    need(task>0&&task<=Integer.MAX_VALUE&&oldIds.add((int)task),"NOTES_ABORTED_TASK_SET");
                    for(int n=0;n<finalRows.length();n++)if(task==number(finalRows.getJSONObject(n),"task_id")){
                        need(!found&&same(row,finalRows.getJSONObject(n)),"NOTES_ABORTED_OWNED_IDENTITY_CHANGED");found=true;}
                    need(found,"NOTES_ABORTED_OWNED_IDENTITY_LOST");}
                JSONArray located=location.getJSONArray("observed_owned_task_ids");java.util.Set<Integer> locations=new TreeSet<Integer>();
                for(int i=0;i<located.length();i++){long task=numberAt(located,i);need(task>0&&task<=Integer.MAX_VALUE&&locations.add((int)task),"NOTES_ABORTED_TASK_SET");}
                need(locations.equals(oldIds)&&ids.containsAll(oldIds)&&(stage==0||ids.equals(oldIds)),"NOTES_ABORTED_TASK_SET");
                JSONObject launch=response.getJSONObject("task_launch_policy");
                need("hepta.background-task-launch-policy.v1".equals(string(launch,"schema"))&&generation.equals(string(launch,"generation"))
                        &&number(launch,"display_id")==displayId&&PACKAGE.equals(string(launch,"package"))&&number(launch,"target_uid")==targetUid
                        &&string(launch,"component").startsWith(PACKAGE+"/")&&string(launch,"request_id").equals(string(response,"request_id")),
                        "NOTES_ABORTED_LAUNCH_TARGET");yes(launch,"activity_info_rechecked_before_dispatch");
            }
            JSONObject diagnostics=terminal.getJSONObject("personal_notes_task_info_diagnostics"),policy=terminal.getJSONObject("public_policy_diagnostics");
            need("hepta.notes-taskinfo-diagnostics.v1".equals(string(diagnostics,"schema"))&&"hepta.public-policy-diagnostics.v1".equals(string(policy,"schema")),"NOTES_ABORTED_DIAGNOSTIC_SCHEMA");
            no(diagnostics,"diagnostics_grant_authority","provides_cleanup_proof");no(policy,"diagnostics_grant_authority","provides_cleanup_proof");
            JSONObject runtime=diagnostics.getJSONObject("first_runtime_failure"),retirement=diagnostics.getJSONObject("first_cleanup_failure"),policyFailure=policy.getJSONObject("first_failure");
            need("runtime_policy_check".equals(string(runtime,"phase"))&&"org.trillionnium.hepta.background.PublicPersonalNotesReader$CensusChanged".equals(string(runtime,"exception_class"))
                    &&"NOTES_ROOT_CENSUS_CHANGED".equals(string(runtime,"reason"))&&"NOTES_FRAME_AND_CUSTODY".equals(string(policyFailure,"phase"))
                    &&same(runtime.get("exception_class"),policyFailure.get("exception_class"))&&same(runtime.get("exception_class"),policyFailure.get("cause_class"))
                    &&number(policyFailure,"reflection_wrapper_count")==0&&"IO_FAILURE".equals(string(policyFailure,"category"))
                    &&same(runtime.get("observed_elapsed_ms"),policyFailure.get("observed_elapsed_ms"))
                    &&"cleanup".equals(string(retirement,"phase"))&&"java.io.IOException".equals(string(retirement,"exception_class"))
                    &&"NOTES_RETIREMENT_FINAL_TASKINFO_CHANGED".equals(string(retirement,"reason"))&&retirement.get("actual_root_read_failure")==JSONObject.NULL,
                    "NOTES_ABORTED_ORIGINAL_REFUSAL");
            JSONObject refusal=runtime.getJSONObject("actual_root_read_failure");
            need("hepta.notes-root-census-refusal.v1".equals(string(refusal,"schema"))&&"within_sample".equals(string(refusal,"stage"))
                    &&"NOTES_ROOT_CENSUS_CHANGED".equals(string(refusal,"reason"))&&number(refusal,"sample_attempt")==1
                    &&number(refusal,"expected_display_id")==displayId&&refusal.get("previously_pinned_ids")==JSONObject.NULL,"NOTES_ABORTED_ROOT_REFUSAL");
            no(refusal,"diagnostics_grant_authority");
            JSONArray before=refusal.getJSONArray("before_all_roots"),middle=refusal.getJSONArray("owned_display_roots"),after=refusal.getJSONArray("after_all_roots");
            need(before.length()==2&&after.length()==1&&same(before,middle),"NOTES_ABORTED_ROOT_HISTORY");
            java.util.Set<Integer> seen=new TreeSet<Integer>();
            for(int i=0;i<before.length();i++){JSONObject row=before.getJSONObject(i);long task=number(row,"task_id");
                need(task>0&&task<=Integer.MAX_VALUE,"NOTES_ABORTED_ROOT_IDENTITY");int id=(int)task;boolean found=false;
                need(seen.add(id)&&ids.contains(id)&&number(row,"user_id")==0&&number(row,"display_id")==displayId
                        &&number(row,"effective_uid")==targetUid&&number(row,"launch_cookie_count")==0,"NOTES_ABORTED_ROOT_IDENTITY");
                JSONArray custody=finalCustody.getJSONArray("actual_observed_tasks");for(int j=0;j<custody.length();j++){JSONObject recorded=custody.getJSONObject(j);
                    if(id==number(recorded,"task_id")){need(number(row,"token_identity_in_reader")==number(recorded,"token_identity_in_broker"),"NOTES_ABORTED_ROOT_TOKEN");found=true;}}
                need(found,"NOTES_ABORTED_ROOT_IDENTITY");
            }
            need(seen.equals(ids)&&(same(before.getJSONObject(0),after.getJSONObject(0))||same(before.getJSONObject(1),after.getJSONObject(0))),"NOTES_ABORTED_ROOT_HISTORY");
            long lastAt=number(last.getJSONObject("public_task_location"),"observed_elapsed_ms"),failedAt=number(runtime,"observed_elapsed_ms");
            JSONObject backWork=object(originals.get("child_1_action")).getJSONObject("action_execution");
            JSONArray backPhases=backWork.getJSONArray("phases");need(backPhases.length()>0&&backPhases.length()<=32,"NOTES_ABORTED_ACTION_PHASES");
            JSONObject callback=backPhases.getJSONObject(backPhases.length()-1);
            need("callback_published".equals(string(callback,"phase")),"NOTES_ABORTED_ACTION_PHASES");long backAt=number(callback,"elapsed_ms");
            need(ProfileIdentity.uuid(string(last,"request_id"))&&lastAt>=prior&&lastAt<=failedAt&&failedAt>=backAt
                    &&number(retirement,"observed_elapsed_ms")>=failedAt&&number(retirement,"observed_elapsed_ms")<=number(object(originals.get("result")),"terminal_decided_elapsed_ms"),
                    "NOTES_ABORTED_FAILURE_CLOCK");
        }

        private void requireAbortedModel(JSONObject result,JSONObject owner,JSONObject projection,JSONObject response)throws Exception{
            JSONObject step=object(originals.get("step_model")),action=object(originals.get("step_action")),attempt=object(originals.get("fixed_intent_attempt"));
            JSONObject fixed=result.getJSONArray("fixed_intent_attempts").getJSONObject(0),work=action.getJSONObject("action_execution");
            String run=string(step,"run_id"),observation=string(step,"observation_id"),authorization=string(owner,"task_authorization_sha256");
            long terminal=number(result,"terminal_decided_elapsed_ms");
            need(run.matches("[0-9a-f]{32}")&&observation.matches("[0-9a-f]{32}")&&ownerSha256.equals(string(step,"original_instruction_sha256"))
                    &&run.equals(string(action,"model_run_id"))&&same(fixed,without(action.getJSONObject("fixed_intent"),"broker_response"))
                    &&same(response,action.getJSONObject("fixed_intent").getJSONObject("broker_response")),"NOTES_WORKFLOW_PARENT_BINDING");
            yes(action,"accepted","dispatched","model_issued");no(action,"stale","done_success_eligible");
            JSONObject issued=object(string(step,"raw_text").getBytes(StandardCharsets.UTF_8));
            need(same(issued,action.getJSONObject("action"))&&"notes.create".equals(string(issued,"action"))
                    &&PACKAGE.equals(string(issued,"package"))&&observation.equals(string(issued,"observation_id")),"NOTES_WORKFLOW_MODEL_ACTION");
            long drained=requireWorkflowDrainedAction(work,run,observation,authorization,created,terminal);
            bindBackground(action.getJSONObject("background_session"));
            requireWorkflowAuthorization(action.getJSONObject("task_authorization"),result.getJSONObject("task_authorization"),run,authorization,"notes.create",false);
            need(authorization.equals(string(action,"task_authorization_sha256")),"NOTES_WORKFLOW_PARENT_AUTHORIZATION");
            need("hepta.fixed-intent-attempt.v1".equals(string(attempt,"schema"))&&"consumed_before_call".equals(string(attempt,"stage"))
                    &&"hepta.fixed-intent-result.v1".equals(string(fixed,"schema")),"NOTES_WORKFLOW_ATTEMPT_SCHEMA");
            Iterator<String> attemptKeys=attempt.keys();while(attemptKeys.hasNext()){String key=attemptKeys.next();
                if(!"schema".equals(key)&&!"stage".equals(key))need(same(attempt.get(key),fixed.get(key)),"NOTES_WORKFLOW_ATTEMPT_CHANGED");}
            need(taskId.equals(string(attempt,"task_id"))&&run.equals(string(attempt,"model_run_id"))&&observation.equals(string(attempt,"observation_id"))
                    &&number(attempt,"source_window_id")==number(work,"window_id")&&PACKAGE.equals(string(attempt,"source_package"))
                    &&number(attempt,"display_id")==displayId&&generation.equals(string(attempt,"background_generation"))
                    &&"notes.create".equals(string(attempt,"action"))&&number(attempt,"attempt_ordinal")==1
                    &&ProfileIdentity.hash(string(attempt,"attempt_id"))&&ProfileIdentity.sha(string(issued,"text")).equals(string(attempt,"payload_sha256")),
                    "NOTES_WORKFLOW_ATTEMPT_IDENTITY");
            yes(attempt,"attempt_consumed");no(attempt,"automatic_retry_allowed");yes(fixed,"dispatch_attempted","api_accepted");
            no(fixed,"goal_independently_verified","saved_or_search_results_verified");
            need("launch_accepted".equals(string(fixed,"result"))&&"draft_opened".equals(string(fixed,"requested_outcome")),"NOTES_WORKFLOW_PARENT_RESULT");
            JSONObject target=attempt.getJSONObject("target"),brokerFixed=response.getJSONObject("fixed_intent"),launch=response.getJSONObject("task_launch_policy");
            need("installed_package_manager".equals(string(target,"source"))&&"notes.create".equals(string(target,"action"))
                    &&PACKAGE.equals(string(target,"package"))&&number(target,"target_uid")==targetUid&&string(target,"component").startsWith(PACKAGE+"/")
                    &&string(target,"component").equals(string(launch,"component"))&&target.get("required_permission")==JSONObject.NULL,"NOTES_WORKFLOW_TARGET");
            yes(target,"exported","activity_enabled","application_enabled","declared_intent_filter_matched","ordinary_caller_permission_checked");
            need("hepta.background-fixed-intent.v1".equals(string(brokerFixed,"schema"))&&same(target,brokerFixed.getJSONObject("target"))
                    &&string(response,"request_id").equals(string(brokerFixed,"request_id"))&&generation.equals(string(brokerFixed,"generation"))
                    &&number(brokerFixed,"display_id")==displayId&&number(brokerFixed,"ordinary_caller_uid")==ownerUid
                    &&"notes.create".equals(string(brokerFixed,"action"))&&string(attempt,"attempt_id").equals(string(brokerFixed,"attempt_id"))
                    &&string(attempt,"payload_sha256").equals(string(brokerFixed,"payload_sha256")),"NOTES_WORKFLOW_BROKER_ATTEMPT");
            yes(brokerFixed,"attempt_consumed");no(brokerFixed,"goal_independently_verified");

            JSONObject grant=object(originals.get("workflow_grant")),aborted=object(originals.get("workflow_aborted"));
            String[] bindingKeys={"workflow_id","task_id","parent_step","parent_model_run_id","parent_observation_id","created_observation_id",
                    "parent_create_after_observation_id","workflow_initial_observation_id","parent_fixed_intent_attempt_id","owner_sha256","contract_sha256",
                    "task_authorization_sha256","body_sha256","target_package","target_uid","target_apk_sha256","display_id","background_generation"};
            keys(grant,"schema","workflow_id","task_id","parent_step","parent_model_run_id","parent_observation_id","created_observation_id",
                    "parent_create_after_observation_id","workflow_initial_observation_id","parent_fixed_intent_attempt_id","owner_sha256","contract_sha256",
                    "task_authorization_sha256","body_sha256","target_package","target_uid","target_apk_sha256","display_id","background_generation",
                    "grant_consumed","grant_retired","grants_tool_authority");
            keys(aborted,"schema","workflow_id","task_id","parent_step","parent_model_run_id","parent_observation_id","created_observation_id",
                    "parent_create_after_observation_id","workflow_initial_observation_id","parent_fixed_intent_attempt_id","owner_sha256","contract_sha256",
                    "task_authorization_sha256","body_sha256","target_package","target_uid","target_apk_sha256","display_id","background_generation",
                    "grant_consumed","grant_retired","grants_tool_authority","actor_kind","model_issued","workflow_verified","model_done_synthesized",
                    "last_observation_id","error","automatic_retry_allowed");
            need("hepta.notes-create-workflow.v1".equals(string(grant,"schema"))&&same(grant.get("schema"),aborted.get("schema"))
                    &&ProfileIdentity.hash(string(grant,"workflow_id"))&&taskId.equals(string(grant,"task_id"))&&number(grant,"parent_step")==1
                    &&run.equals(string(grant,"parent_model_run_id"))&&observation.equals(string(grant,"parent_observation_id"))
                    &&string(attempt,"attempt_id").equals(string(grant,"parent_fixed_intent_attempt_id"))
                    &&ownerSha256.equals(string(grant,"owner_sha256"))&&authorization.equals(string(grant,"task_authorization_sha256"))
                    &&string(attempt,"payload_sha256").equals(string(grant,"body_sha256"))&&PACKAGE.equals(string(grant,"target_package"))
                    &&number(grant,"target_uid")==targetUid&&number(grant,"display_id")==displayId
                    &&generation.equals(string(grant,"background_generation")),"NOTES_ABORTED_GRANT_BINDING");
            for(String key:bindingKeys)need(same(grant.get(key),aborted.get(key)),"NOTES_ABORTED_GRANT_CHANGED");
            yes(grant,"grant_consumed");no(grant,"grant_retired","grants_tool_authority");
            yes(aborted,"grant_consumed","grant_retired");
            no(aborted,"grants_tool_authority","model_issued","workflow_verified","model_done_synthesized","automatic_retry_allowed");
            need("tool_workflow".equals(string(aborted,"actor_kind"))&&string(aborted,"error").matches(
                    "当前显示范围的锁状态或后台显示凭据不可用 \\[phase=sample_graph,elapsed_ms=[0-9]{1,9},phase_ms=[0-9]{1,9}\\]"),"NOTES_ABORTED_OBSERVATION_FAILURE");
            JSONObject childAction=object(originals.get("child_1_action")),planned=object(originals.get("child_1_planned")),child=childAction.getJSONObject("tool_child");
            keys(planned,"schema","workflow_id","task_id","parent_step","parent_model_run_id","parent_observation_id","created_observation_id",
                    "parent_create_after_observation_id","workflow_initial_observation_id","parent_fixed_intent_attempt_id","owner_sha256","contract_sha256",
                    "task_authorization_sha256","body_sha256","target_package","target_uid","target_apk_sha256","display_id","background_generation",
                    "grant_consumed","grant_retired","grants_tool_authority","child_id","child_ordinal","actor_kind","model_issued","action","observation_id",
                    "node_id","node_label","service_entered","automatic_retry_allowed");
            need(same(without(planned,"service_entered"),without(child,"service_entered")),"NOTES_ABORTED_CHILD_PLAN_CHANGED");
            for(String key:bindingKeys)need(same(grant.get(key),child.get(key)),"NOTES_ABORTED_CHILD_BINDING");
            String initial=string(grant,"created_observation_id"),before=string(child,"observation_id");
            need(initial.equals(string(grant,"parent_create_after_observation_id"))&&initial.equals(string(grant,"workflow_initial_observation_id"))
                    &&before.equals(string(aborted,"last_observation_id"))&&before.equals(string(result,"final_observation_id")),
                    "NOTES_ABORTED_OBSERVATION_CHAIN");
            requireAbortedManifest(observation,initial,before);
            need("hepta.tool-child.v1".equals(string(child,"schema"))&&"tool_child".equals(string(child,"actor_kind"))
                    &&ProfileIdentity.hash(string(child,"child_id"))&&number(child,"child_ordinal")==1&&"back".equals(string(child,"action"))
                    &&child.get("node_id")==JSONObject.NULL&&child.get("node_label")==JSONObject.NULL,"NOTES_ABORTED_ONLY_BACK_CHILD");
            yes(child,"grant_consumed","service_entered");no(child,"grant_retired","grants_tool_authority","model_issued","automatic_retry_allowed");
            no(planned,"service_entered");
            need("hepta.tool-child.v1".equals(string(childAction,"schema"))&&"hepta.internal-tool-child.v1".equals(string(childAction,"action_schema"))
                    &&"tool_child".equals(string(childAction,"actor_kind"))&&number(childAction,"child_ordinal")==1,"NOTES_ABORTED_CHILD_ACTION");
            for(String key:new String[]{"parent_model_run_id","parent_fixed_intent_attempt_id","workflow_id","child_id"})
                need(same(child.get(key),childAction.get(key)),"NOTES_ABORTED_CHILD_ACTION");
            yes(childAction,"accepted","dispatched");no(childAction,"model_issued","stale");
            JSONObject issuedChild=childAction.getJSONObject("action"),childWork=childAction.getJSONObject("action_execution");
            need("back".equals(string(issuedChild,"action"))&&PACKAGE.equals(string(issuedChild,"package"))
                    &&before.equals(string(issuedChild,"observation_id"))&&!issuedChild.has("node_id")&&number(issuedChild,"duration_ms")==0&&number(issuedChild,"offset")==0
                    &&!string(work,"operation_id").equals(string(childWork,"operation_id")),"NOTES_ABORTED_BACK_OPERATION");
            JSONObject afterObservation=object(originals.get("created_after")),childObservation=object(originals.get("child_1_before"));
            long afterPublished=requireAbortedObservation(afterObservation,initial,owner,drained,number(childWork,"queued_elapsed_ms"));
            long beforePublished=requireAbortedObservation(childObservation,before,owner,afterPublished,number(childWork,"queued_elapsed_ms"));
            need(number(afterObservation,"window_id")==number(childObservation,"window_id")
                    &&number(childWork,"window_id")==number(childObservation,"window_id"),"NOTES_ABORTED_EDITOR_WINDOW_CHANGED");
            requireAbortedActionPhases(work,terminal);
            drained=requireWorkflowDrainedAction(childWork,run,before,authorization,drained,terminal);requireAbortedActionPhases(childWork,terminal);
            need(beforePublished<=number(childWork,"queued_elapsed_ms"),"NOTES_ABORTED_BACK_CAPTURE_ORDER");
            requireWorkflowAuthorization(childAction.getJSONObject("task_authorization"),result.getJSONObject("task_authorization"),run,authorization,"back",true);
            bindBackground(childAction.getJSONObject("background_session"));
            need(same(childWork,result.getJSONObject("last_action_execution"))
                    &&same(without(childAction.getJSONObject("task_authorization"),"callback_lease_current","callback_cancelled"),result.getJSONObject("task_authorization"))
                    &&result.get("stop_requested_elapsed_ms")==JSONObject.NULL,"NOTES_ABORTED_FINAL_ACTION");
            requireAbortedReadiness(run,initial,afterObservation,afterPublished,number(childWork,"queued_elapsed_ms"));
            JSONObject identity=object(originals.get("completion_identity")),evidence=result.getJSONObject("completion_evidence"),contract=owner.getJSONObject("completion_contract");
            need("ordinary_package_manager_and_full_apk_hash".equals(string(identity,"source"))&&PACKAGE.equals(string(identity,"package"))
                    &&number(identity,"uid")==targetUid&&number(identity,"version_code")>0&&ProfileIdentity.hash(string(identity,"apk_set_sha256"))
                    &&same(identity.getJSONObject("apk_hashes"),grant.getJSONObject("target_apk_sha256")),"NOTES_ABORTED_TARGET_IDENTITY");
            JSONObject hashes=identity.getJSONObject("apk_hashes");need(hashes.length()>0&&hashes.length()<=32,"NOTES_ABORTED_TARGET_IDENTITY");
            Iterator<String> parts=hashes.keys();while(parts.hasNext())need(ProfileIdentity.hash(string(hashes,parts.next())),"NOTES_ABORTED_TARGET_IDENTITY");
            need("hepta.task-completion.v1".equals(string(contract,"schema"))&&"notes_save_list_reopen".equals(string(contract,"kind"))
                    &&ownerSha256.equals(string(contract,"owner_sha256"))&&string(grant,"contract_sha256").equals(string(contract,"contract_sha256"))
                    &&string(grant,"body_sha256").equals(string(contract,"expected_body_sha256"))
                    &&"save_list_reopen".equals(string(contract,"note_persistence_verification_policy")),"NOTES_ABORTED_COMPLETION_CONTRACT");
            no(contract,"body_rewritten","model_may_change_goal","grants_tool_authority");
            need("hepta.task-completion.v1".equals(string(evidence,"schema"))&&"notes_save_list_reopen".equals(string(evidence,"kind"))
                    &&taskId.equals(string(evidence,"task_id"))&&ownerSha256.equals(string(evidence,"owner_sha256"))
                    &&string(grant,"contract_sha256").equals(string(evidence,"contract_sha256"))&&same(contract,evidence.getJSONObject("contract"))
                    &&number(evidence,"display_id")==displayId&&generation.equals(string(evidence,"background_generation"))
                    &&evidence.getJSONArray("model_success_claims").length()==0&&evidence.get("completion_actor")==JSONObject.NULL
                    &&evidence.get("controller_native_parent_session_bound")==JSONObject.NULL,"NOTES_ABORTED_COMPLETION_HISTORY");
            yes(evidence,"notes_launch_observed","editor_body_observed","current_editor_body_matched");
            no(evidence,"completion_verified","list_observed","same_list_item_reopened","observation_chain_verified","terminal_binding_and_cleanup_verified",
                    "controller_completion_requested","model_done_synthesized","persistent_storage_bytes_verified","new_database_item_identity_verified","grants_tool_authority");
            need("verified_note_editor".equals(string(evidence,"current_surface"))&&evidence.get("current_list_item_node_id")==JSONObject.NULL
                    &&evidence.get("identity_failure")==JSONObject.NULL&&!evidence.has("notes_create_workflow"),"NOTES_ABORTED_NO_LIST_OR_REOPEN");
            JSONArray proofs=evidence.getJSONArray("proofs");need(proofs.length()==2,"NOTES_ABORTED_PROOF_COUNT");
            JSONObject launchProof=proofs.getJSONObject(0),bodyProof=proofs.getJSONObject(1);
            need("model_bound_notes_launch".equals(string(launchProof,"kind"))&&number(launchProof,"step")==1
                    &&run.equals(string(launchProof,"model_run_id"))&&observation.equals(string(launchProof,"before_observation_id"))
                    &&initial.equals(string(launchProof,"after_observation_id"))&&string(attempt,"attempt_id").equals(string(launchProof,"attempt_id"))
                    &&string(attempt,"payload_sha256").equals(string(launchProof,"payload_sha256"))
                    &&"editor_body_observed".equals(string(bodyProof,"kind"))&&number(bodyProof,"step")==0
                    &&bodyProof.get("model_run_id")==JSONObject.NULL&&initial.equals(string(bodyProof,"before_observation_id"))
                    &&initial.equals(string(bodyProof,"after_observation_id")),"NOTES_ABORTED_PROGRESS_ONLY");
            no(result,"goal_independently_verified","model_done_synthesized");
            requireNormalModelClose(projection,run,observation,step,drained,terminal);
        }
        private long requireAbortedObservation(JSONObject observation,String id,JSONObject owner,long lower,long upper)throws Exception{
            need(id.equals(string(observation,"observation_id"))&&PACKAGE.equals(string(observation,"package"))
                    &&number(observation,"window_id")>=0&&ProfileIdentity.hash(string(observation,"screen_sha256"))
                    &&ProfileIdentity.hash(string(observation,"app_tree_sha256"))&&ProfileIdentity.hash(string(observation,"observation_state_sha256"))
                    &&number(observation,"rotation")>=0&&number(observation,"rotation")<=3,"NOTES_ABORTED_OBSERVATION_IDENTITY");
            no(observation,"nodes_truncated");JSONObject background=observation.getJSONObject("background_session");
            need(generation.equals(string(background,"generation"))&&number(background,"display_id")==displayId
                    &&same(without(background,"generation","display_id"),owner.getJSONObject("background_request")),"NOTES_ABORTED_OBSERVATION_SCOPE");
            JSONObject window=observation.getJSONObject("window"),collection=observation.getJSONObject("collection"),capture=observation.getJSONObject("capture");
            need(number(window,"window_id")==number(observation,"window_id")&&number(window,"display_id")==displayId
                    &&"observed".equals(string(window,"metadata_status"))&&"hepta.observation-collection.v1".equals(string(collection,"schema"))
                    &&number(collection,"visited_nodes")>0&&number(collection,"retained_nodes")==observation.getJSONArray("nodes").length()
                    &&number(collection,"pending_nodes_at_stop")==0&&number(collection,"child_slots_omitted_by_traversal_limit")==0
                    &&number(collection,"nodes_omitted_by_node_limit")==0&&number(collection,"nodes_omitted_by_text_limit")==0
                    &&collection.getJSONArray("truncation_reasons").length()==0,"NOTES_ABORTED_OBSERVATION_COMPLETENESS");
            no(collection,"grants_action_capability");
            need("hepta.observation-capture.v1".equals(string(capture,"schema"))&&"post_encoding_whole_graph".equals(string(capture,"mode")),"NOTES_ABORTED_OBSERVATION_CAPTURE");
            yes(capture,"post_encoding_whole_graph_rechecked","fresh_action_validation_required");
            no(capture,"same_instant_pixels_and_ax_claimed","publication_refreshes_capture_age","grants_action_authority","business_completion_verified");
            long at=number(observation,"captured_elapsed_ms"),published=number(capture,"published_elapsed_ms");
            need(at>=lower&&published>=at&&published<=upper,"NOTES_ABORTED_OBSERVATION_CLOCK");return published;
        }
        private void requireAbortedActionPhases(JSONObject work,long terminal)throws Exception{
            JSONArray phases=work.getJSONArray("phases");need(phases.length()>0&&phases.length()<=32,"NOTES_ABORTED_ACTION_PHASES");
            String[] required={"effect_entered","effect_returned","worker_drained","callback_published"};int next=0;long previous=number(work,"queued_elapsed_ms");
            for(int i=0;i<phases.length();i++){JSONObject phase=phases.getJSONObject(i);String name=string(phase,"phase");long at=number(phase,"elapsed_ms");
                need(at>=previous&&at<=terminal&&at<=number(work,"deadline_elapsed_ms"),"NOTES_ABORTED_ACTION_PHASE_CLOCK");previous=at;
                if(Arrays.asList(required).contains(name)){
                    need(next<required.length&&required[next].equals(name),"NOTES_ABORTED_ACTION_PHASE_ORDER");
                    if("worker_drained".equals(name))need(at==number(work,"worker_drained_elapsed_ms"),"NOTES_ABORTED_ACTION_DRAIN_CLOCK");next++;}
            }
            need(next==required.length&&"queued".equals(string(phases.getJSONObject(0),"phase"))
                    &&number(phases.getJSONObject(0),"elapsed_ms")==number(work,"queued_elapsed_ms")
                    &&"callback_published".equals(string(phases.getJSONObject(phases.length()-1),"phase")),"NOTES_ABORTED_ACTION_PHASES");
            no(work,"complete_phase_coverage");
        }
        private void requireAbortedReadiness(String run,String observation,JSONObject after,long lower,long upper)throws Exception{
            JSONObject readiness=object(originals.get("readiness"));
            need("hepta.notes-created-editor-readiness.v1".equals(string(readiness,"schema"))&&taskId.equals(string(readiness,"task_id"))
                    &&run.equals(string(readiness,"model_run_id"))&&number(readiness,"parent_step")==1&&readiness.get("reopen_child_id")==JSONObject.NULL
                    &&readiness.get("workflow_id")==JSONObject.NULL&&observation.equals(string(readiness,"first_after_observation_id"))
                    &&observation.equals(string(readiness,"last_observation_id"))&&"step-01-after.json".equals(string(readiness,"last_observation_file"))
                    &&number(readiness,"first_after_window_id")==number(after,"window_id")&&number(readiness,"max_observations")==4
                    &&number(readiness,"max_elapsed_ms")==15000&&readiness.get("client_cache_reset")==JSONObject.NULL&&readiness.get("error")==JSONObject.NULL
                    &&number(readiness,"model_requests")==0&&number(readiness,"app_actions")==0,"NOTES_ABORTED_READINESS");
            yes(readiness,"first_after_preserved","body_verified");
            no(readiness,"after_verified_reopen_child","window_replacement_allowed","complete_opaque_editor_reads","automatic_create_retry","saved_or_reopened_verified");
            long began=number(readiness,"started_elapsed_ms"),finished=number(readiness,"finished_elapsed_ms");
            need(began>=lower&&finished>=began&&finished<=upper&&finished-began==number(readiness,"elapsed_ms")&&finished-began<=15000,"NOTES_ABORTED_READINESS_CLOCK");
            JSONArray samples=readiness.getJSONArray("samples");need(samples.length()==1,"NOTES_ABORTED_READINESS_SAMPLE_COUNT");JSONObject sample=samples.getJSONObject(0);
            need(observation.equals(string(sample,"observation_id"))&&number(sample,"window_id")==number(after,"window_id")&&number(sample,"display_id")==displayId
                    &&"step-01-after.json".equals(string(sample,"observation_file"))&&number(sample,"elapsed_ms")==0,"NOTES_ABORTED_READINESS_SAMPLE");
            yes(sample,"first_model_after","validation_accepted","current_body_matched","domain_valid");no(sample,"first_reopen_after");
        }

        /** A diagnostic INITIAL failure followed by a final terminal line is not
         * cleanup proof. Original expiry, an exited owned Process and the fresh
         * complete double census are still required before journal retirement. */
        private JSONObject initializationTerminal(byte[] raw)throws Exception{
            String text=new String(raw,StandardCharsets.UTF_8);
            need(Arrays.equals(raw,text.getBytes(StandardCharsets.UTF_8))&&text.endsWith("\n")
                    &&text.indexOf('\r')<0,"NOTES_INITIALIZATION_OUTPUT_FRAMING");
            String[] lines=text.split("\n",-1);
            need(lines.length==3&&!lines[0].isEmpty()&&!lines[1].isEmpty()&&lines[2].isEmpty(),"NOTES_INITIALIZATION_OUTPUT_FRAMING");
            JSONObject first=object(lines[0].getBytes(StandardCharsets.UTF_8)),last=object(lines[1].getBytes(StandardCharsets.UTF_8));
            keys(first,"schema","error","state");
            need("hepta.background-broker-terminal.v1".equals(string(first,"schema"))
                    &&"FRAMEWORK_OPERATION_FAILED".equals(string(first,"error"))&&"INITIAL".equals(string(first,"state")),
                    "NOTES_INITIALIZATION_FAILURE_SEQUENCE");
            keys(last,"schema","generation","state","display_id","reason","release_confirmed","boot_count_read_retirement_failure",
                    "owned_single_task","profile_cleanup","profile_cleanup_diagnostics","profile_last_leaf_validation",
                    "profile_first_root_refusal","profile_permission_first_read_mismatch","profile_custody_retained",
                    "display_scope_sha256","public_scope_admission_retired","public_surface_detach","public_screen_lease","public_policy_diagnostics");
            need("process_finally".equals(string(last,"reason"))&&"RELEASED".equals(string(last,"state"))
                    &&number(last,"display_id")==-1,"NOTES_INITIALIZATION_FINAL_SEQUENCE");
            for(String key:new String[]{"boot_count_read_retirement_failure","owned_single_task","profile_cleanup",
                    "profile_last_leaf_validation","profile_first_root_refusal","profile_permission_first_read_mismatch"})
                need(last.get(key)==JSONObject.NULL,"NOTES_INITIALIZATION_NO_CUSTODY");
            no(last,"profile_custody_retained");
            return last;
        }
        private int initializationTargetUid()throws Exception{
            JSONObject identity=object(originals.get("completion_identity"));
            long uid=number(identity,"uid");
            need(uid>=10000&&uid<90000&&uid!=ownerUid,"NOTES_INITIALIZATION_TARGET_UID");
            return (int)uid;
        }
        private void requireInitializationRecords(JSONObject bootstrap,JSONObject cleanup,JSONObject broker,
                JSONObject terminal,JSONObject owner,JSONObject result)throws Exception{
            need(displayId==-1&&!releasedBeforeModel&&!postModelDrained&&!cancelledAfterActions
                    &&number(result,"steps")==0,"NOTES_INITIALIZATION_SHAPE");
            JSONObject initial=object(originals.get("initial_binding")),scope=object(originals.get("scope_binding"));
            JSONObject journal=object(originals.get("journal"));
            Iterator<String> fields=journal.keys();
            while(fields.hasNext()){
                String key=fields.next();
                if(!"state".equals(key))need(same(journal.get(key),initial.get(key)),"NOTES_INITIALIZATION_BINDING_CHANGED");
            }
            need("INITIAL".equals(string(initial,"state"))&&"INITIAL".equals(string(bootstrap,"state"))
                    &&initial.get("broker_output")==JSONObject.NULL&&initial.get("broker_process_exit_code")==JSONObject.NULL
                    &&bootstrap.get("broker_process_exit_code")==JSONObject.NULL,"NOTES_INITIALIZATION_INITIAL_RECORD");
            no(initial,"retired","spawn_attempted","bootstrap_dispatched","bootstrap_model_issued","broker_process_exit_observed");
            no(bootstrap,"retired","bootstrap_dispatched","bootstrap_model_issued","broker_process_exit_observed");
            yes(bootstrap,"spawn_attempted");yes(cleanup,"retired","spawn_attempted","broker_process_exit_observed");
            no(cleanup,"bootstrap_dispatched","bootstrap_model_issued","cleanup_known");
            need(number(cleanup,"broker_process_exit_code")==70&&same(bootstrap.getJSONObject("broker_output"),broker),
                    "NOTES_INITIALIZATION_OWNED_EXIT");
            for(JSONObject record:new JSONObject[]{initial,bootstrap,cleanup})
                need(record.get("app_display_readback")==JSONObject.NULL&&record.get("last_broker_response")==JSONObject.NULL,
                        "NOTES_INITIALIZATION_RESPONSE_OBSERVED");
            keys(broker,"schema","task_id","generation","app_uid","app_pid","process_binding","process_reference",
                    "command_sha256","started_elapsed_ms","output_file","receipt_file","output_limit_bytes","observed_bytes",
                    "stored_bytes","stored_sha256","overflow","eof_seen","read_failed","merged_stdout_stderr","model_input",
                    "release_evidence","capture_reason","persisted");
            need("stream_terminal".equals(string(broker,"capture_reason")),"NOTES_INITIALIZATION_CAPTURE_REASON");
            yes(broker,"eof_seen","persisted");no(broker,"release_evidence");
            JSONObject target=owner.getJSONObject("task_authorization").getJSONObject("execution_target");
            for(JSONObject record:new JSONObject[]{initial,bootstrap,cleanup})
                need(same(target,record.getJSONObject("execution_target")),"NOTES_INITIALIZATION_TARGET_CHANGED");
            need(ownerSha256.equals(string(target,"owner_sha256"))&&PACKAGE.equals(string(target,"effective_initial_package"))
                    &&same(owner.getJSONObject("background_request").getJSONArray("allowed_packages"),target.getJSONArray("effective_allowed_packages")),
                    "NOTES_INITIALIZATION_TARGET");
            no(target,"owner_rewritten","package_from_model_or_screen","grants_tool_authority","business_verified");
            need(same(scope,owner.getJSONObject("qualification_scope"))&&same(scope,result.getJSONObject("qualification_scope"))
                    &&taskId.equals(string(scope,"task_id"))&&scope.get("expected_scope_sha256")==JSONObject.NULL
                    &&scope.get("actual_scope_sha256")==JSONObject.NULL,"NOTES_INITIALIZATION_ORDINARY_SCOPE");
            no(scope,"restricted","scope_refused","scope_loaded");
            JSONObject identity=object(originals.get("completion_identity"));
            need("ordinary_package_manager_and_full_apk_hash".equals(string(identity,"source"))&&PACKAGE.equals(string(identity,"package"))
                    &&number(identity,"uid")==targetUid&&number(identity,"version_code")>0,"NOTES_INITIALIZATION_TARGET_INSTALLATION");
            JSONObject hashes=identity.getJSONObject("apk_hashes");java.util.TreeMap<String,String> sorted=new java.util.TreeMap<String,String>();
            need(hashes.has("base")&&hashes.length()<=32,"NOTES_INITIALIZATION_TARGET_INSTALLATION");
            Iterator<String> parts=hashes.keys();while(parts.hasNext()){
                String part=parts.next(),hash=string(hashes,part);
                need(("base".equals(part)||part.matches("split:[A-Za-z0-9_.-]+"))&&ProfileIdentity.hash(hash),"NOTES_INITIALIZATION_TARGET_INSTALLATION");
                sorted.put(part,hash);
            }
            StringBuilder rows=new StringBuilder();
            for(Map.Entry<String,String> row:sorted.entrySet())rows.append(row.getKey()).append('\t').append(row.getValue()).append('\n');
            need(ProfileIdentity.sha(rows.toString()).equals(string(identity,"apk_set_sha256")),"NOTES_INITIALIZATION_APK_SET");
            JSONObject profile=terminal.getJSONObject("profile_cleanup_diagnostics"),policy=terminal.getJSONObject("public_policy_diagnostics");
            keys(profile,"schema","first_failure","diagnostics_grant_authority","provides_cleanup_proof","allows_input_or_model_resumption");
            keys(policy,"schema","first_failure","diagnostics_grant_authority","provides_cleanup_proof");
            need("hepta.profile-cleanup-diagnostics.v1".equals(string(profile,"schema"))&&profile.get("first_failure")==JSONObject.NULL
                    &&"hepta.public-policy-diagnostics.v1".equals(string(policy,"schema"))&&policy.get("first_failure")==JSONObject.NULL,
                    "NOTES_INITIALIZATION_DIAGNOSTICS");
            no(profile,"diagnostics_grant_authority","provides_cleanup_proof","allows_input_or_model_resumption");
            no(policy,"diagnostics_grant_authority","provides_cleanup_proof");
            JSONObject detach=terminal.getJSONObject("public_surface_detach");
            keys(detach,"schema","admission_irrevocably_retired","state","worker_claimed","late_create_worker_claimed",
                    "identity_read_completed","adapter_entered","identity_source","api_attempted","api_returned","began_elapsed_ms",
                    "ended_elapsed_ms","worker_finished","deadline_exceeded","failure_type","surface_stopped_verified",
                    "provides_task_or_display_cleanup_proof","allows_input_or_model_resumption","shutdown_depends_on_fresh_display_binder_query");
            long end=number(result,"terminal_decided_elapsed_ms"),begin=number(detach,"began_elapsed_ms"),finished=number(detach,"ended_elapsed_ms");
            need("hepta.public-own-group.surface-retirement.v1".equals(string(detach,"schema"))
                    &&"IDENTITY_UNAVAILABLE_UNVERIFIED".equals(string(detach,"state"))&&"NONE".equals(string(detach,"identity_source"))
                    &&"java.io.IOException".equals(string(detach,"failure_type"))&&created<=begin&&begin<=finished&&finished<=end,
                    "NOTES_INITIALIZATION_SURFACE_DIAGNOSTIC");
            yes(detach,"admission_irrevocably_retired","worker_claimed","worker_finished");
            // Detach-adapter diagnostics do not establish whether display creation
            // was attempted. Current absence requires the fresh complete census.
            no(detach,"late_create_worker_claimed","identity_read_completed","adapter_entered","api_attempted","api_returned",
                    "deadline_exceeded","surface_stopped_verified","provides_task_or_display_cleanup_proof",
                    "allows_input_or_model_resumption","shutdown_depends_on_fresh_display_binder_query");
            JSONObject screen=terminal.getJSONObject("public_screen_lease");
            keys(screen,"schema","generation","display_id","display_group_id","wake_lock_flags","expires_elapsed_ms",
                    "acquire_entered","acquire_returned","acquired_elapsed_ms","admission_retired","release_entered","release_returned",
                    "released_elapsed_ms","failure","initial_readiness_started_elapsed_ms","initial_readiness_deadline_elapsed_ms",
                    "initial_readiness_census_count","initial_first_display_state","initial_last_display_state","initial_on_observed_elapsed_ms",
                    "grants_cleanup_or_business_success");
            need("hepta.public-own-group.screen-lease.v1".equals(string(screen,"schema"))&&generation.equals(string(screen,"generation"))
                    &&number(screen,"display_id")==-1&&number(screen,"display_group_id")==-1&&number(screen,"wake_lock_flags")==10
                    &&number(screen,"expires_elapsed_ms")==expires&&screen.get("failure")==JSONObject.NULL
                    &&number(screen,"initial_first_display_state")==-1&&number(screen,"initial_last_display_state")==-1,
                    "NOTES_INITIALIZATION_SCREEN_IDENTITY");
            for(String key:new String[]{"acquired_elapsed_ms","released_elapsed_ms","initial_readiness_started_elapsed_ms",
                    "initial_readiness_deadline_elapsed_ms","initial_readiness_census_count","initial_on_observed_elapsed_ms"})
                need(number(screen,key)==0,"NOTES_INITIALIZATION_SCREEN_NOT_ACQUIRED");
            yes(screen,"admission_retired");
            no(screen,"acquire_entered","acquire_returned","release_entered","release_returned","grants_cleanup_or_business_success");
            JSONObject evidence=result.getJSONObject("completion_evidence");
            need(same(owner.getJSONObject("completion_contract"),evidence.getJSONObject("contract"))
                    &&taskId.equals(string(evidence,"task_id"))&&ownerSha256.equals(string(evidence,"owner_sha256"))
                    &&evidence.getJSONArray("proofs").length()==0&&evidence.getJSONArray("model_success_claims").length()==0,
                    "NOTES_INITIALIZATION_BUSINESS_STATE");
            no(evidence,"notes_launch_observed","completion_verified","model_done_synthesized","controller_completion_requested","grants_tool_authority");
        }

        private JSONObject cancelledHistory()throws Exception{return object(originals.get("cancelled_history"));}
        public int cancelledActionCount()throws Exception{need(cancelledAfterActions,"NOTES_NOT_CANCELLED_KIND");return (int)number(cancelledHistory(),"completed_actions");}
        private JSONArray cancelledTaskRow(String file)throws Exception{
            JSONArray rows=cancelledHistory().getJSONArray("task_files");JSONArray found=null;
            for(int i=0;i<rows.length();i++){JSONArray row=rows.getJSONArray(i);if(file.equals(row.getString(0))){need(found==null,"NOTES_CANCELLED_MANIFEST_DUPLICATE");found=row;}}
            need(found!=null,"NOTES_CANCELLED_MANIFEST_MISSING");return found;
        }
        private static void rawReference(JSONArray row,byte[] raw,int nameOffset)throws Exception{
            need(row.length()==nameOffset+3&&row.get(nameOffset) instanceof String&&numberAt(row,nameOffset+1)==raw.length
                    &&ProfileIdentity.sha(raw).equals(row.getString(nameOffset+2)),"NOTES_CANCELLED_RAW_REFERENCE");
        }
        public void requireOriginalBytes(String name,byte[] raw)throws Exception{
            if(!cancelledAfterActions){need(Arrays.equals(raw,original(name)),"NOTES_ORIGINAL_BYTES_CHANGED");return;}
            if(name.startsWith("cancelled_action_")||name.startsWith("cancelled_model_")){
                boolean action=name.startsWith("cancelled_action_");String prefix=action?"cancelled_action_":"cancelled_model_";
                need(name.substring(prefix.length()).matches("[0-9]{2}"),"NOTES_CANCELLED_INPUT_NAME");int index=Integer.parseInt(name.substring(prefix.length()));
                need(index>=1&&index<=cancelledActionCount(),"NOTES_CANCELLED_INPUT_INDEX");
                rawReference(cancelledTaskRow(cancelledStepName(index,action?"action":"model-0")),raw,0);
                need(Arrays.equals(action?compactCancelledAction(raw):raw,original(name)),"NOTES_CANCELLED_COMPLETE_VALUE_CHANGED");
            }else if(name.startsWith("cancelled_request_")){
                int index=Integer.parseInt(name.substring("cancelled_request_".length()));need(index>=1&&index<=cancelledActionCount(),"NOTES_CANCELLED_REQUEST_INDEX");
                JSONArray row=cancelledHistory().getJSONArray("request_receipts").getJSONArray(index-1);rawReference(row,raw,0);
                requireCompletedRequest(raw,index);
            }else need(Arrays.equals(raw,original(name)),"NOTES_ORIGINAL_BYTES_CHANGED");
        }
        public void requireTaskWitness(String name,byte[] raw)throws Exception{
            need(cancelledAfterActions,"NOTES_NOT_CANCELLED_KIND");rawReference(cancelledTaskRow(name),raw,0);
        }
        private void requireCancelledManifest(JSONObject result)throws Exception{
            JSONObject history=cancelledHistory();int count=cancelledActionCount();JSONArray rows=history.getJSONArray("task_files");
            need(rows.length()>=12&&rows.length()<=256,"NOTES_CANCELLED_MANIFEST_BOUND");
            java.util.Set<String> required=new TreeSet<String>(Arrays.asList("owner.json","background-bootstrap.json","background-cleanup.json","result.json",
                    "background-broker-"+generation+".json","background-broker-"+generation+".bin","background-binding.json","scope-binding.json","initial-app-catalogue.json"));
            for(int i=1;i<=count;i++)for(String suffix:new String[]{"before","budget-0","model-0","action","after"})required.add(cancelledStepName(i,suffix));
            required.add(cancelledStepName(count+1,"before"));required.add(cancelledStepName(count+1,"budget-0"));
            String previous="";long total=0;
            for(int i=0;i<rows.length();i++){
                JSONArray row=rows.getJSONArray(i);need(row.length()==3,"NOTES_CANCELLED_MANIFEST_ROW");String name=row.getString(0);long size=numberAt(row,1);
                need(name.compareTo(previous)>0&&size>0&&size<=MAX_RECEIPT&&ProfileIdentity.hash(row.getString(2)),"NOTES_CANCELLED_MANIFEST_ROW");previous=name;
                total+=size;need(total<=8388608,"NOTES_CANCELLED_ARCHIVE_BOUND");
                need(required.remove(name)||name.matches("[0-9a-f]{32}\\.png")||name.matches("scope-observation-[0-9a-f]{32}\\.json"),"NOTES_CANCELLED_UNCOVERED_TASK_ENTRY");
            }
            need(required.isEmpty(),"NOTES_CANCELLED_TASK_ENTRY_MISSING");
            for(String[] item:new String[][]{{"owner","owner.json"},{"bootstrap","background-bootstrap.json"},{"cleanup","background-cleanup.json"},
                    {"result","result.json"},{"broker_receipt","background-broker-"+generation+".json"},{"broker_output","background-broker-"+generation+".bin"}})
                rawReference(cancelledTaskRow(item[1]),originals.get(item[0]),0);
            JSONArray requests=history.getJSONArray("request_receipts");need(requests.length()==count,"NOTES_CANCELLED_REQUEST_COUNT");
            java.util.Set<String> runs=new TreeSet<String>();
            for(int i=1;i<=count;i++){
                JSONObject model=object(originals.get(cancelledKey(i,"model")));String run=string(model,"run_id");JSONArray row=requests.getJSONArray(i-1);
                need(row.length()==3&&run.matches("[0-9a-f]{32}")&&runs.add(run)&&run.equals(row.getString(0))
                        &&numberAt(row,1)>0&&numberAt(row,1)<=MAX_ORIGINAL&&ProfileIdentity.hash(row.getString(2)),"NOTES_CANCELLED_REQUEST_REFERENCE");
                rawReference(cancelledTaskRow(cancelledStepName(i,"model-0")),originals.get(cancelledKey(i,"model")),0);
            }
            need(number(result,"steps")==count+1,"NOTES_CANCELLED_STEP_COUNT");
        }
        private JSONObject cancelledTerminal(byte[] raw)throws Exception{
            String text=new String(raw,StandardCharsets.UTF_8);String[] lines=text.split("\n",-1);
            need(Arrays.equals(raw,text.getBytes(StandardCharsets.UTF_8))&&lines.length==3&&lines[2].isEmpty()
                    &&!lines[0].isEmpty()&&!lines[1].isEmpty(),"NOTES_CANCELLED_TERMINAL_FRAMING");
            JSONObject first=object(lines[0].getBytes(StandardCharsets.UTF_8)),last=object(lines[1].getBytes(StandardCharsets.UTF_8));
            JSONObject a=first.getJSONObject("personal_notes_cleanup"),b=last.getJSONObject("personal_notes_cleanup");
            need(same(without(first,"personal_notes_cleanup"),without(last,"personal_notes_cleanup"))
                    &&same(without(a,"failure"),without(b,"failure"))
                    &&"NOTES_CLEANUP_ABSENCE_DEADLINE".equals(string(a,"failure"))
                    &&"NOTES_CLEANUP_DEADLINE".equals(string(b,"failure")),"NOTES_CANCELLED_TERMINAL_SUCCESSOR");
            return last;
        }
        private void requireWorkflowRetirementBrokerReceipt(JSONObject historical,JSONObject current)throws Exception{
            requireBroker(historical);no(historical,"eof_seen");yes(historical,"persisted");yes(current,"persisted");
            // The recorded pre-release refusal remains immutable. A subsequently
            // observed stream EOF changes only this current producer metadata bit.
            need(same(without(historical,"eof_seen"),without(current,"eof_seen")),"NOTES_WORKFLOW_BROKER_SUCCESSOR");
        }
        private void requireCancelledBrokerReceipt(JSONObject historical,JSONObject current)throws Exception{
            requireBroker(historical);yes(historical,"persisted");yes(current,"persisted");
            // Observing EOF after an independently performed maintenance is not a
            // successful historical close. All producer identity/output bytes stay exact.
            need(same(without(historical,"eof_seen"),without(current,"eof_seen"))
                    &&(!Boolean.TRUE.equals(historical.get("eof_seen"))||Boolean.TRUE.equals(current.get("eof_seen"))),"NOTES_CANCELLED_BROKER_SUCCESSOR");
        }
        private void requireCancelledBootstrap(JSONObject early,JSONObject last,JSONObject terminal,java.util.Set<Integer> ids)throws Exception{
            need(!prelaunchCreateFailure&&!releasedTerminal&&!releasedBeforeModel&&!postModelDrained,"NOTES_CANCELLED_HISTORY_KIND");
            need("launch".equals(string(early,"operation"))&&"ACTIVE".equals(string(early,"state"))&&"close".equals(string(last,"operation"))
                    &&"CLEANUP_UNKNOWN".equals(string(last,"state"))&&"client_close".equals(string(last,"terminal_reason"))
                    &&"CLEANUP_NOT_CONFIRMED".equals(string(last,"error")),"NOTES_CANCELLED_CLOSE_PHASE");
            yes(early,"ok","dispatched");no(early,"public_scope_admission_retired","public_scope_closing");
            no(last,"ok","dispatched");yes(last,"public_scope_admission_retired","public_scope_closing");
            need(ProfileIdentity.uuid(string(early,"request_id"))&&ProfileIdentity.uuid(string(last,"request_id"))
                    &&!string(early,"request_id").equals(string(last,"request_id")),"NOTES_CANCELLED_RESPONSE_ID");
            JSONObject initial=early.getJSONObject("personal_notes_cleanup"),ending=last.getJSONObject("personal_notes_cleanup");
            need(notesCustody(initial,false)==targetUid&&same(without(ending,"failure"),without(terminal.getJSONObject("personal_notes_cleanup"),"failure")),"NOTES_CANCELLED_CUSTODY_CHAIN");
            no(initial,"pre_release_tasks_verified","release_api_entered","release_api_returned","identity_unknown");
            need(string(initial,"failure").isEmpty(),"NOTES_CANCELLED_INITIAL_CUSTODY");
            yes(ending,"pre_release_tasks_verified","release_api_entered","release_api_returned","identity_unknown","custodian_retained");
            need("NOTES_CLEANUP_ABSENCE_DEADLINE".equals(string(ending,"failure"))&&number(ending,"pending_owned_reads")>0&&number(ending,"absence_reads")==0,
                    "NOTES_CANCELLED_UNCONFIRMED_CLOSE");
            JSONArray oldRows=initial.getJSONArray("actual_observed_tasks"),finalRows=ending.getJSONArray("actual_observed_tasks");
            need(oldRows.length()>0&&finalRows.length()>=oldRows.length(),"NOTES_CANCELLED_OWNED_HISTORY");
            for(int i=0;i<oldRows.length();i++){JSONObject row=oldRows.getJSONObject(i);boolean seen=false;
                for(int n=0;n<finalRows.length();n++)if(number(row,"task_id")==number(finalRows.getJSONObject(n),"task_id")){
                    need(!seen&&same(row,finalRows.getJSONObject(n)),"NOTES_CANCELLED_OWNED_IDENTITY");seen=true;}
                need(seen&&ids.contains((int)number(row,"task_id")),"NOTES_CANCELLED_OWNED_IDENTITY");}
        }
        private void requireCancelledResult(JSONObject result,JSONObject owner,JSONObject last)throws Exception{
            requireCancelledManifest(result);int count=cancelledActionCount();
            need(taskId.equals(string(result,"task_id"))&&"blocked".equals(string(result,"status")),"NOTES_CANCELLED_RESULT_IDENTITY");
            no(result,"cleanup_known","completion_verified","model_reported_success","external_model","automatic_replay","controller_completion_requested",
                    "model_done_synthesized","goal_independently_verified","observation_read_worker_pending_at_terminal","action_worker_pending_at_terminal","native_cancel_worker_pending_at_terminal");
            need(result.get("model_done_status")==JSONObject.NULL&&result.get("completion_actor")==JSONObject.NULL
                    &&result.getJSONArray("submit_attempts").length()==0&&result.getJSONArray("fixed_intent_attempts").length()==0
                    &&result.get("profile_permission_preparation")==JSONObject.NULL,"NOTES_CANCELLED_BUSINESS_HISTORY");
            JSONObject cancellation=result.getJSONObject("native_cancellation");
            need("hepta.native-cancel-work.v1".equals(string(cancellation,"schema"))&&taskId.equals(string(cancellation,"task_id"))
                    &&"task".equals(string(cancellation,"identity_kind"))&&cancellation.get("run_id")==JSONObject.NULL&&cancellation.get("error_class")==JSONObject.NULL,"NOTES_CANCELLED_WORK_IDENTITY");
            yes(cancellation,"request_reserved","native_cleanup_known","executor_accepted","worker_started","signal_entered","signal_returned","worker_drained");
            no(cancellation,"automatic_requeue","native_exit_proved_by_this_record","queue_rejected","submission_unknown","skipped_after_cleanup","skipped_after_lease_retired");
            long stop=number(result,"stop_requested_elapsed_ms"),terminal=number(result,"terminal_decided_elapsed_ms"),prior=created;
            need(stop>=created&&terminal>=stop&&terminal<=started,"NOTES_CANCELLED_TERMINAL_CLOCK");
            String authorization=string(owner,"task_authorization_sha256");java.util.Set<String> operations=new TreeSet<String>();JSONObject finalWork=null;
            for(int i=1;i<=count;i++){
                JSONObject step=object(originals.get(cancelledKey(i,"model"))),action=object(originals.get(cancelledKey(i,"action"))),issued=object(string(step,"raw_text").getBytes(StandardCharsets.UTF_8));
                String run=string(step,"run_id"),observation=string(step,"observation_id"),tool=string(issued,"action");
                need(ownerSha256.equals(string(step,"original_instruction_sha256"))&&observation.matches("[0-9a-f]{32}")
                        &&same(issued,action.getJSONObject("action"))&&PACKAGE.equals(string(issued,"package"))&&observation.equals(string(issued,"observation_id"))
                        &&run.equals(string(action,"model_run_id"))&&Arrays.asList("click","back","type").contains(tool),"NOTES_CANCELLED_MODEL_ACTION");
                yes(action,"accepted","dispatched","model_issued");no(action,"stale","done_success_eligible");
                need(action.get("ime_submit")==JSONObject.NULL&&action.get("fixed_intent")==JSONObject.NULL
                        &&authorization.equals(string(action,"task_authorization_sha256")),"NOTES_CANCELLED_ACTION_SCOPE");
                JSONObject work=action.getJSONObject("action_execution");need(operations.add(string(work,"operation_id")),"NOTES_CANCELLED_OPERATION_REUSED");
                prior=requireWorkflowDrainedAction(work,run,observation,authorization,prior,stop);
                requireWorkflowAuthorization(action.getJSONObject("task_authorization"),result.getJSONObject("task_authorization"),run,authorization,tool,false);
                bindBackground(action.getJSONObject("background_session"));finalWork=work;
            }
            need(finalWork!=null&&same(finalWork,result.getJSONObject("last_action_execution")),"NOTES_CANCELLED_FINAL_ACTION");
            requireCancelledModel(result.getJSONObject("model_session"),count,prior,stop,terminal);
        }
        private void requireCancelledModel(JSONObject projection,int count,long drained,long stop,long terminal)throws Exception{
            JSONObject session=object(originals.get("model_session_receipt")),nativeSession=object(originals.get("native_session_receipt"));
            JSONObject g=session.getJSONObject("worker_generation_cleanup"),receipt=object(originals.get("generation_cleanup_receipt"));
            String worker=string(session,"worker_generation");long appPid=number(session,"app_pid"),leader=number(nativeSession,"pid");
            need(worker.matches("[0-9a-f]{32}")&&"hepta.local-model.task-session.v1".equals(string(session,"schema"))&&taskId.equals(string(session,"task_id"))
                    &&number(session,"app_uid")==ownerUid&&appPid>1&&appPid==number(object(originals.get("broker_receipt")),"app_pid"),"NOTES_CANCELLED_MODEL_IDENTITY");
            need(taskId.equals(string(projection,"task_id"))&&worker.equals(string(projection,"worker_generation"))&&number(projection,"exit_code")==143
                    &&ProfileIdentity.sha(originals.get("model_session_receipt")).equals(string(projection,"app_receipt_sha256")),"NOTES_CANCELLED_MODEL_PROJECTION");
            yes(projection,"process_started","process_exit_observed");no(projection,"receipt_valid");
            yes(session,"caller_cancellation_requested","process_started","process_exit_observed","cleanup_known","generation_cleanup_known","generation_unforced","cancel_requested","cancellation_sdk_cleanup_binding_valid");
            no(session,"native_session_binding_valid","force_destroy_sent","parent_force_destroy_sent","automatic_restart","cross_task_reuse","sdk_exception_failure_cleanup_binding_valid");
            need(number(session,"exit_code")==143&&number(session,"requests_sent")==count+1&&number(session,"requests_accepted")==count
                    &&"expected_cancelled_exit_143_with_observed_sdk_cleanup".equals(string(session,"cleanup_classification"))
                    &&session.get("sdk_exception_failure")==JSONObject.NULL&&same(nativeSession,session.getJSONObject("native_session_receipt")),"NOTES_CANCELLED_SESSION_CLOSE");
            JSONObject cancel=session.getJSONObject("owned_worker_cancellation");
            need("hepta.owned-worker-cancellation.v1".equals(string(cancel,"schema"))&&taskId.equals(string(cancel,"task_id"))&&worker.equals(string(cancel,"worker_generation"))
                    &&number(cancel,"term_destroy_attempts")==1&&number(cancel,"force_destroy_attempts")==0&&number(cancel,"exit_code")==143
                    &&cancel.get("signal_error")==JSONObject.NULL,"NOTES_CANCELLED_SIGNAL_AUDIT");
            yes(cancel,"requested","process_bound","termination_started","term_destroy_returned","process_exit_observed");
            no(cancel,"force_destroy_returned","sdk_cleanup_proven_by_this_object");
            need("hepta.geniex-task-session.result.v1".equals(string(nativeSession,"schema"))&&taskId.equals(string(nativeSession,"task_id"))&&worker.equals(string(nativeSession,"worker_generation"))
                    &&leader>1&&number(nativeSession,"signal_observed")==15&&number(nativeSession,"last_request_status")==143&&number(nativeSession,"last_request_return_status")==143,
                    "NOTES_CANCELLED_NATIVE_IDENTITY");
            no(nativeSession,"process_exit_observed","close_requested");yes(nativeSession,"model_metadata_unchanged_before_close","sdk_destroy_attempted","sdk_deinit_attempted","control_channel_write_failed");
            no(nativeSession.getJSONObject("sdk_exception_boundary"),"caught","automatic_retry");
            for(String key:new String[]{"model_hash_count","sdk_init_count","model_create_count"})need(number(nativeSession,key)==1,"NOTES_CANCELLED_NATIVE_COUNTS");
            for(String key:new String[]{"requests_received","model_reset_count","control_done_attempts"})need(number(nativeSession,key)==count+1,"NOTES_CANCELLED_NATIVE_COUNTS");
            for(String key:new String[]{"requests_completed","control_done_delivered"})need(number(nativeSession,key)==count,"NOTES_CANCELLED_NATIVE_COUNTS");
            need(number(nativeSession,"sdk_destroy_rc")==0&&number(nativeSession,"sdk_deinit_rc")==0&&number(nativeSession,"control_channel_last_errno")==32,"NOTES_CANCELLED_SDK_CLEANUP");
            need("hepta.worker-generation.app-cleanup.v1".equals(string(g,"schema"))&&taskId.equals(string(g,"task_id"))&&worker.equals(string(g,"worker_generation"))
                    &&number(g,"app_uid")==ownerUid&&number(g,"app_pid")==appPid&&ProfileIdentity.sha(originals.get("generation_identity")).equals(string(g,"identity_sha256"))
                    &&ProfileIdentity.sha(originals.get("generation_cleanup_receipt")).equals(string(g,"native_receipt_sha256"))&&same(receipt,g.getJSONObject("native_cleanup")),"NOTES_CANCELLED_GENERATION_BINDING");
            yes(g,"direct_process_exit_observed","helper_started","helper_exit_observed","cleanup_known","descendant_force_known","generation_unforced");
            no(g,"helper_force_destroy_sent","helper_currently_alive","descendant_force_used","automatic_retry");
            long finish=number(session,"finisher_submitted_monotonic_ns"),end=number(receipt,"ended_monotonic_ns");
            need(finish/1000000L>=stop&&finish/1000000L>=drained&&finish/1000000L<=terminal&&end/1000000L<=terminal
                    &&number(g,"helper_exit_code")==0&&g.get("error")==JSONObject.NULL&&"pinned_sdk_inheriting_process_group_and_generation_markers".equals(string(g,"scope"))
                    &&number(g,"finisher_submitted_monotonic_ns")==finish&&number(g,"finisher_deadline_monotonic_ns")==number(session,"finisher_deadline_monotonic_ns"),"NOTES_CANCELLED_GENERATION_CLOSE");
            for(String key:new String[]{"task_id","worker_generation","scope_token","app_uid","app_pid","app_start_ticks","boot_id","identity_sha256","cleanup_nonce"})
                need(same(g.get(key),receipt.get(key)),"NOTES_CANCELLED_GENERATION_IDENTITY");
            need("hepta.worker-generation.cleanup.v1".equals(string(receipt,"schema"))&&number(receipt,"leader_pid")==leader&&number(receipt,"pgid")==leader
                    &&number(receipt,"term_attempts")==0&&number(receipt,"kill_attempts")==0&&receipt.getJSONArray("targets").length()==0,"NOTES_CANCELLED_GENERATION_UNFORCED");
            yes(receipt,"cleanup_known","scan_complete","pidfd_supported");
            for(String key:new String[]{"remaining_owned_count","unknown_count","escaped_generation_count"})need(number(receipt,key)==0,"NOTES_CANCELLED_GENERATION_UNKNOWN");
            StringBuilder identity=new StringBuilder("hepta.worker-generation.v1\n");
            for(String key:new String[]{"task_id","worker_generation","scope_token","app_uid","app_pid","app_start_ticks","leader_pid","leader_start_ticks","pgid","boot_id"})identity.append(key).append('=').append(receipt.get(key)).append('\n');
            need(Arrays.equals(identity.toString().getBytes(StandardCharsets.US_ASCII),originals.get("generation_identity")),"NOTES_CANCELLED_IDENTITY_BYTES");
        }
        public void requireCompletedRequest(byte[] raw,int ordinal)throws Exception{
            need(cancelledAfterActions&&ordinal>=1&&ordinal<=cancelledActionCount(),"NOTES_CANCELLED_REQUEST_INDEX");
            JSONObject request=object(raw),step=object(originals.get(cancelledKey(ordinal,"model"))),session=object(originals.get("model_session_receipt"));
            String run=string(step,"run_id"),worker=string(session,"worker_generation");long leader=number(session.getJSONObject("native_session_receipt"),"pid");
            need("hepta.local-model.task-request.v1".equals(string(request,"schema"))&&taskId.equals(string(request,"task_id"))&&worker.equals(string(request,"worker_generation"))
                    &&run.equals(string(request,"run_id"))&&number(request,"request_sequence")==ordinal&&number(request,"app_uid")==ownerUid
                    &&number(request,"app_pid")==number(session,"app_pid")&&number(request,"worker_pid")==leader
                    &&string(step,"observation_id").equals(string(request,"grammar_observation_id"))&&PACKAGE.equals(string(request,"grammar_current_package"))
                    &&ProfileIdentity.sha(string(step,"raw_text")).equals(string(request,"raw_text_sha256_read")),"NOTES_CANCELLED_REQUEST_IDENTITY");
            yes(request,"process_started","inference_completed","request_committed","native_result_binding_valid");
            no(request,"process_exit_observed","caller_cancellation_requested","cancel_requested","timeout_observed","force_destroy_sent","automatic_retry");
            need(request.get("exit_code")==JSONObject.NULL&&"request_completed".equals(string(request,"status")),"NOTES_CANCELLED_REQUEST_STATUS");
            JSONObject nativeRequest=request.getJSONObject("native_receipt");
            need("hepta.geniex-task-request.result.v1".equals(string(nativeRequest,"schema"))&&taskId.equals(string(nativeRequest,"task_id"))&&worker.equals(string(nativeRequest,"worker_generation"))
                    &&run.equals(string(nativeRequest,"request_id"))&&number(nativeRequest,"request_sequence")==ordinal&&number(nativeRequest,"pid")==leader
                    &&number(nativeRequest,"request_status")==0&&string(request,"raw_text_sha256_read").equals(string(nativeRequest,"raw_text_sha256")),"NOTES_CANCELLED_NATIVE_REQUEST");
            no(nativeRequest,"process_exit_observed","automatic_retry");
        }
        private void requireCancelledControl(JSONObject current,JSONObject owner,JSONObject result)throws Exception{
            JSONObject origin=current;boolean archive=Boolean.TRUE.equals(cancelledHistory().get("startup_archive"));
            if(archive){
                String relative=lostLaunchOriginArchive(current);byte[] raw=originals.get("origin_control");origin=object(raw);String sha=ProfileIdentity.sha(raw);
                need(relative.equals("session-recovery/control-session.json."+sha+".json"),"NOTES_CANCELLED_STARTUP_ARCHIVE");
                JSONObject reason=current.getJSONObject("startup_recovery"),ref=reason.getJSONArray("preserved_records").getJSONObject(0),latch=object(originals.get("interruption_latch"));
                need(number(ref,"bytes")==raw.length&&"hepta.session-recovery.v1".equals(string(reason,"schema"))&&"blocked_interrupted".equals(string(reason,"decision"))
                        &&reason.get("read_error")==JSONObject.NULL&&"control-session.interrupted.json".equals(string(reason,"interruption_latch")),"NOTES_CANCELLED_STARTUP_RECORD");
                yes(reason,"interruption_latch_observed","interruption_latch_synced");no(reason,"recovery_pending_barrier_observed","automatic_resume","native_cleanup_independently_observed");
                need("hepta.session-interruption-latch.v1".equals(string(latch,"schema"))&&number(latch,"app_uid")==ownerUid
                        &&sha.equals(string(latch.getJSONObject("recovery_reason"),"previous_session_sha256")),"NOTES_CANCELLED_STARTUP_LATCH");
                yes(latch,"blocked");no(latch,"cleanup_known","automatic_resume");
            }else need("blocked".equals(string(current,"status")),"NOTES_CANCELLED_CURRENT_STATUS");
            need("hepta.local-session.v1".equals(string(origin,"schema"))&&"blocked".equals(string(origin,"status"))&&number(origin,"app_uid")==ownerUid
                    &&taskId.equals(string(origin,"task_id"))&&ownerSha256.equals(string(origin,"instruction_sha256"))&&number(origin,"steps")==number(result,"steps")
                    &&string(owner,"task_authorization_sha256").equals(string(origin,"task_authorization_sha256")),"NOTES_CANCELLED_ORIGIN_CONTROL");
            yes(origin,"blocked");no(origin,"pending","running","cleanup_known","automatic_resume");
        }

        private void requireLostControl(JSONObject current,JSONObject owner,JSONObject result)throws Exception{
            JSONObject origin=current;
            if(interruptedLostLaunch){
                String relative=lostLaunchOriginArchive(current);byte[] bytes=originals.get("origin_control");origin=object(bytes);
                String sha=ProfileIdentity.sha(bytes);
                need(relative.equals("session-recovery/control-session.json."+sha+".json"),"NOTES_STARTUP_ARCHIVE_DIGEST");
                JSONObject reason=current.getJSONObject("startup_recovery"),ref=reason.getJSONArray("preserved_records").getJSONObject(0);
                need(number(ref,"bytes")==bytes.length&&"hepta.session-recovery.v1".equals(string(reason,"schema"))
                        &&"blocked_interrupted".equals(string(reason,"decision"))&&reason.get("read_error")==JSONObject.NULL
                        &&"control-session.interrupted.json".equals(string(reason,"interruption_latch")),"NOTES_STARTUP_RECORD");
                yes(reason,"interruption_latch_observed","interruption_latch_synced");
                no(reason,"recovery_pending_barrier_observed","automatic_resume","native_cleanup_independently_observed");
                JSONObject latch=object(originals.get("interruption_latch"));
                need("hepta.session-interruption-latch.v1".equals(string(latch,"schema"))&&number(latch,"app_uid")==ownerUid
                        &&sha.equals(string(latch.getJSONObject("recovery_reason"),"previous_session_sha256")),"NOTES_STARTUP_LATCH");
                yes(latch,"blocked");no(latch,"cleanup_known","automatic_resume");
            }
            need("blocked".equals(string(origin,"status"))&&"hepta.local-session.v1".equals(string(origin,"schema"))
                    &&number(origin,"app_uid")==ownerUid&&taskId.equals(string(origin,"task_id"))&&ownerSha256.equals(string(origin,"instruction_sha256"))
                    &&number(origin,"steps")==0&&string(owner,"task_authorization_sha256").equals(string(origin,"task_authorization_sha256"))
                    &&same(owner.getJSONObject("task_authorization"),origin.getJSONObject("task_authorization"))
                    &&same(owner.getJSONObject("background_request"),origin.getJSONObject("background_request"))
                    &&same(result.getJSONObject("completion_evidence"),origin.getJSONObject("completion_evidence")),"NOTES_LOST_LAUNCH_ORIGIN");
            yes(origin,"blocked","background_lease_unreleased");
            no(origin,"pending","running","cleanup_known","automatic_resume","external_model","web_helper_lease_unreleased","completion_verified","model_reported_success");
            no(current,"cleanup_known","automatic_resume","external_model");
        }
        private void requireLostLaunchReply(JSONObject bootstrap,JSONObject cleanup,JSONObject last,JSONObject location,
                JSONObject finalCustody,JSONObject terminal,java.util.Set<Integer> ids,JSONObject owner,JSONObject result)throws Exception{
            JSONObject initial=object(originals.get("initial_binding")),scope=object(originals.get("scope_binding")),identity=object(originals.get("completion_identity"));
            JSONObject journal=object(originals.get("journal"));
            Iterator<String> fields=journal.keys();
            while(fields.hasNext()){
                String key=fields.next();
                if(!"state".equals(key)&&!"display_id".equals(key))need(same(journal.get(key),initial.get(key)),"NOTES_INITIAL_SCOPE_CHANGED");
            }
            need("INITIAL".equals(string(initial,"state"))&&number(initial,"display_id")==-1
                    &&initial.get("last_broker_response")==JSONObject.NULL&&initial.get("broker_output")==JSONObject.NULL,"NOTES_INITIAL_RECORD");
            no(initial,"retired","spawn_attempted","bootstrap_dispatched","bootstrap_model_issued","broker_process_exit_observed");
            JSONObject target=owner.getJSONObject("task_authorization").getJSONObject("execution_target");
            for(JSONObject source:new JSONObject[]{initial,bootstrap,cleanup})need(same(target,source.getJSONObject("execution_target")),"NOTES_RECORDED_TARGET");
            need(ownerSha256.equals(string(target,"owner_sha256"))&&PACKAGE.equals(string(target,"effective_initial_package"))
                    &&same(owner.getJSONObject("background_request").getJSONArray("allowed_packages"),target.getJSONArray("effective_allowed_packages")),"NOTES_RECORDED_TARGET");
            no(target,"owner_rewritten","package_from_model_or_screen","grants_tool_authority","business_verified");
            need(same(scope,owner.getJSONObject("qualification_scope"))&&same(scope,result.getJSONObject("qualification_scope"))
                    &&taskId.equals(string(scope,"task_id"))&&scope.get("expected_scope_sha256")==JSONObject.NULL&&scope.get("actual_scope_sha256")==JSONObject.NULL,
                    "NOTES_RECORDED_ORDINARY_SCOPE");
            no(scope,"restricted","scope_refused","scope_loaded");
            need("ordinary_package_manager_and_full_apk_hash".equals(string(identity,"source"))&&PACKAGE.equals(string(identity,"package"))
                    &&number(identity,"uid")==targetUid&&number(identity,"version_code")>0,"NOTES_RECORDED_TARGET_INSTALLATION");
            JSONObject hashes=identity.getJSONObject("apk_hashes");java.util.TreeMap<String,String> sorted=new java.util.TreeMap<String,String>();
            need(hashes.has("base")&&hashes.length()<=32,"NOTES_RECORDED_TARGET_INSTALLATION");
            Iterator<String> parts=hashes.keys();while(parts.hasNext()){String part=parts.next(),hash=string(hashes,part);
                need(("base".equals(part)||part.matches("split:[A-Za-z0-9_.-]+"))&&ProfileIdentity.hash(hash),"NOTES_RECORDED_TARGET_INSTALLATION");sorted.put(part,hash);}
            StringBuilder rows=new StringBuilder();for(Map.Entry<String,String> row:sorted.entrySet())rows.append(row.getKey()).append('\t').append(row.getValue()).append('\n');
            need(ProfileIdentity.sha(rows.toString()).equals(string(identity,"apk_set_sha256")),"NOTES_RECORDED_APK_SET");
            need("ACTIVE".equals(string(bootstrap,"state"))&&"create".equals(string(last,"operation"))
                    &&"ACTIVE".equals(string(last,"state"))&&ProfileIdentity.uuid(string(last,"request_id"))&&!last.has("task_launch_policy")
                    &&ids.size()==1&&finalCustody.getJSONArray("actual_observed_tasks").length()==1
                    &&string(last.getJSONObject("personal_notes_cleanup"),"initial_recents_sha256").equals(string(finalCustody,"initial_recents_sha256")),
                    "NOTES_LOST_LAUNCH_ORIGINAL_SEQUENCE");
            yes(last,"ok","dispatched");no(last,"public_scope_admission_retired","public_scope_closing");
            no(location,"retired","physical_user_activity_frozen","recents_unchanged_claimed");
            long observed=number(location,"observed_elapsed_ms"),end=number(result,"terminal_decided_elapsed_ms");
            JSONObject diagnostics=terminal.getJSONObject("public_policy_diagnostics"),failure=diagnostics.getJSONObject("first_failure");
            need("PUBLIC_SCOPE_POLICY_UNAVAILABLE".equals(string(terminal,"reason"))&&terminal.get("profile_cleanup")==JSONObject.NULL
                    &&terminal.get("owned_single_task")==JSONObject.NULL&&"NOTES_FRAME_AND_CUSTODY".equals(string(failure,"phase"))
                    &&created<=observed&&observed<=number(failure,"observed_elapsed_ms")&&number(failure,"observed_elapsed_ms")<=end,
                    "NOTES_LOST_LAUNCH_TERMINAL");
            no(terminal,"profile_custody_retained");no(diagnostics,"diagnostics_grant_authority","provides_cleanup_proof");
            JSONObject screen=terminal.getJSONObject("public_screen_lease");
            need(generation.equals(string(screen,"generation"))&&number(screen,"display_id")==displayId&&number(screen,"expires_elapsed_ms")==expires
                    &&number(screen,"acquired_elapsed_ms")>=created&&number(screen,"released_elapsed_ms")>=observed&&number(screen,"released_elapsed_ms")<=end,
                    "NOTES_LOST_LAUNCH_SCREEN_LEASE");
            yes(screen,"acquire_entered","acquire_returned","admission_retired","release_entered","release_returned");no(screen,"grants_cleanup_or_business_success");
            JSONObject evidence=result.getJSONObject("completion_evidence");
            need(same(owner.getJSONObject("completion_contract"),evidence.getJSONObject("contract"))
                    &&taskId.equals(string(evidence,"task_id"))&&ownerSha256.equals(string(evidence,"owner_sha256"))
                    &&evidence.getJSONArray("proofs").length()==0&&evidence.getJSONArray("model_success_claims").length()==0,"NOTES_LOST_LAUNCH_BUSINESS_STATE");
            no(evidence,"notes_launch_observed","completion_verified","model_done_synthesized","controller_completion_requested","grants_tool_authority");
        }
        /** A different terminal response is permitted only for the single recorded
         * Notes create below. Neither a drained worker nor an absent task proves
         * that the attempted note was not created. All failure bytes stay intact. */
        private void requireDrainedBootstrap(JSONObject early,JSONObject last,java.util.Set<Integer> ids)throws Exception{
            need(number(early,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_VERSION&&generation.equals(string(early,"generation"))
                    &&number(early,"display_id")==displayId&&publicScope.sha256.equals(string(early,"display_scope_sha256"))
                    &&"launch".equals(string(early,"operation"))&&"ACTIVE".equals(string(early,"state"))
                    &&"notes.create".equals(string(last,"operation"))
                    &&(releasedTerminal?"RELEASED":"CLEANUP_UNKNOWN").equals(string(last,"state"))
                    &&ProfileIdentity.uuid(string(early,"request_id"))&&ProfileIdentity.uuid(string(last,"request_id"))
                    &&!string(early,"request_id").equals(string(last,"request_id")),"NOTES_DRAINED_BOOTSTRAP_BINDING");
            yes(early,"ok","dispatched");no(last,"ok");yes(last,"dispatched","public_scope_admission_retired");
            need(notesCustody(early.getJSONObject("personal_notes_cleanup"),false)==targetUid,"NOTES_TARGET_UID_CHANGED");
            JSONObject location=early.getJSONObject("public_task_location"),later=last.getJSONObject("public_task_location"),launch=early.getJSONObject("task_launch_policy");
            need("hepta.public-own-group.task-location.v1".equals(string(location,"schema"))&&generation.equals(string(location,"generation"))
                    &&number(location,"display_id")==displayId&&number(location,"target_user_id")==0
                    &&number(location,"observed_elapsed_ms")>=created&&number(location,"observed_elapsed_ms")<=number(later,"observed_elapsed_ms")
                    &&number(later,"observed_elapsed_ms")<=started,"NOTES_DRAINED_BOOTSTRAP_LOCATION");
            no(location,"task_mutation_authority");
            JSONArray originalTasks=location.getJSONArray("observed_owned_task_ids"),finalTasks=later.getJSONArray("observed_owned_task_ids");
            need(originalTasks.length()>0&&originalTasks.length()<=32,"NOTES_RECORDED_TASK_BOUND");
            java.util.Set<Long> retained=new TreeSet<Long>();for(int i=0;i<finalTasks.length();i++)retained.add(numberAt(finalTasks,i));
            for(int i=0;i<originalTasks.length();i++){long task=numberAt(originalTasks,i);need(task>0&&task<=Integer.MAX_VALUE&&retained.contains(task),"NOTES_DRAINED_OWNED_TASK_LOST");ids.add((int)task);}
            JSONArray oldRows=early.getJSONObject("personal_notes_cleanup").getJSONArray("actual_observed_tasks");
            JSONArray finalRows=last.getJSONObject("personal_notes_cleanup").getJSONArray("actual_observed_tasks");
            need(oldRows.length()>0&&oldRows.length()<=32,"NOTES_RECORDED_TASK_BOUND");
            for(int i=0;i<oldRows.length();i++){JSONObject row=oldRows.getJSONObject(i);boolean found=false;
                for(int n=0;n<finalRows.length();n++)if(number(row,"task_id")==number(finalRows.getJSONObject(n),"task_id")){
                    need(!found&&same(row,finalRows.getJSONObject(n)),"NOTES_DRAINED_OWNED_IDENTITY_CHANGED");found=true;}
                need(found,"NOTES_DRAINED_OWNED_IDENTITY_LOST");}
            need("hepta.background-task-launch-policy.v1".equals(string(launch,"schema"))&&generation.equals(string(launch,"generation"))
                    &&number(launch,"display_id")==displayId&&PACKAGE.equals(string(launch,"package"))&&number(launch,"target_uid")==targetUid
                    &&string(launch,"component").startsWith(PACKAGE+"/")&&string(launch,"request_id").equals(string(early,"request_id")),"NOTES_DRAINED_BOOTSTRAP_TARGET");
            yes(launch,"activity_info_rechecked_before_dispatch");
        }
        private void requireDrainedModel(JSONObject result,JSONObject owner,JSONObject projection,JSONObject last)throws Exception{
            JSONObject step=object(originals.get("step_model")),action=object(originals.get("step_action")),attempt=object(originals.get("fixed_intent_attempt"));
            JSONObject work=result.getJSONObject("last_action_execution"),fixed=result.getJSONArray("fixed_intent_attempts").getJSONObject(0);
            String run=string(step,"run_id"),observation=string(step,"observation_id"),authorization=string(owner,"task_authorization_sha256");
            need(run.matches("[0-9a-f]{32}")&&observation.matches("[0-9a-f]{32}")&&ownerSha256.equals(string(step,"original_instruction_sha256"))
                    &&observation.equals(string(result,"final_observation_id"))&&run.equals(string(action,"model_run_id"))
                    &&same(work,action.getJSONObject("action_execution"))&&same(fixed,action.getJSONObject("fixed_intent")),"NOTES_DRAINED_ACTION_BINDING");
            no(action,"accepted","stale","done_success_eligible");yes(action,"dispatched","model_issued");
            JSONObject issued=object(string(step,"raw_text").getBytes(StandardCharsets.UTF_8));
            need(same(issued,action.getJSONObject("action"))&&"notes.create".equals(string(issued,"action"))
                    &&PACKAGE.equals(string(issued,"package"))&&observation.equals(string(issued,"observation_id")),"NOTES_DRAINED_MODEL_ACTION");
            need("hepta.action-execution.v1".equals(string(work,"schema"))&&"serial_action_worker".equals(string(work,"execution_kind"))
                    &&string(work,"operation_id").matches("[0-9a-f]{32}")&&taskId.equals(string(work,"task_id"))
                    &&run.equals(string(work,"model_run_id"))&&observation.equals(string(work,"observation_id"))
                    &&authorization.equals(string(work,"authorization_sha256"))&&number(work,"display_id")==displayId
                    &&generation.equals(string(work,"background_generation"))&&number(work,"window_id")>=0,"NOTES_DRAINED_ACTION_IDENTITY");
            yes(work,"effect_entered","worker_drained","callback_published","callback_authority_current");
            no(work,"effect_returned","retired","phases_truncated","automatic_redispatch");
            need(work.get("api_accepted")==JSONObject.NULL&&work.get("retirement_reason")==JSONObject.NULL,"NOTES_DRAINED_EFFECT_REMAINS_UNKNOWN");
            long terminal=number(result,"terminal_decided_elapsed_ms"),queued=number(work,"queued_elapsed_ms"),drained=number(work,"worker_drained_elapsed_ms");
            need(queued>=created&&drained>=queued&&drained<=terminal&&number(work,"deadline_elapsed_ms")>queued,"NOTES_DRAINED_ACTION_CLOCK");
            need("hepta.fixed-intent-attempt.v1".equals(string(attempt,"schema"))&&"consumed_before_call".equals(string(attempt,"stage"))
                    &&"hepta.fixed-intent-result.v1".equals(string(fixed,"schema")),"NOTES_DRAINED_ATTEMPT_SCHEMA");
            Iterator<String> attemptKeys=attempt.keys();while(attemptKeys.hasNext()){String key=attemptKeys.next();
                if(!"schema".equals(key)&&!"stage".equals(key))need(same(attempt.get(key),fixed.get(key)),"NOTES_DRAINED_ATTEMPT_CHANGED");}
            need(taskId.equals(string(attempt,"task_id"))&&run.equals(string(attempt,"model_run_id"))&&observation.equals(string(attempt,"observation_id"))
                    &&number(attempt,"source_window_id")==number(work,"window_id")&&PACKAGE.equals(string(attempt,"source_package"))
                    &&number(attempt,"display_id")==displayId&&generation.equals(string(attempt,"background_generation"))
                    &&"notes.create".equals(string(attempt,"action"))&&number(attempt,"attempt_ordinal")==1
                    &&ProfileIdentity.hash(string(attempt,"attempt_id"))&&ProfileIdentity.sha(string(issued,"text")).equals(string(attempt,"payload_sha256")),"NOTES_DRAINED_ATTEMPT_IDENTITY");
            yes(attempt,"attempt_consumed");no(attempt,"automatic_retry_allowed");yes(fixed,"dispatch_attempted");
            no(fixed,"goal_independently_verified","saved_or_search_results_verified");
            need(fixed.get("api_accepted")==JSONObject.NULL&&"unknown".equals(string(fixed,"result"))&&"draft_opened".equals(string(fixed,"requested_outcome")),"NOTES_DRAINED_EFFECT_REMAINS_UNKNOWN");
            JSONObject target=attempt.getJSONObject("target"),brokerFixed=last.getJSONObject("fixed_intent"),launch=last.getJSONObject("task_launch_policy");
            need("installed_package_manager".equals(string(target,"source"))&&"notes.create".equals(string(target,"action"))
                    &&PACKAGE.equals(string(target,"package"))&&number(target,"target_uid")==targetUid&&string(target,"component").startsWith(PACKAGE+"/")
                    &&string(target,"component").equals(string(launch,"component"))&&target.get("required_permission")==JSONObject.NULL,"NOTES_DRAINED_TARGET");
            yes(target,"exported","activity_enabled","application_enabled","declared_intent_filter_matched","ordinary_caller_permission_checked");
            need("hepta.background-fixed-intent.v1".equals(string(brokerFixed,"schema"))&&same(target,brokerFixed.getJSONObject("target"))
                    &&string(last,"request_id").equals(string(brokerFixed,"request_id"))&&generation.equals(string(brokerFixed,"generation"))
                    &&number(brokerFixed,"display_id")==displayId&&number(brokerFixed,"ordinary_caller_uid")==ownerUid
                    &&"notes.create".equals(string(brokerFixed,"action"))&&string(attempt,"attempt_id").equals(string(brokerFixed,"attempt_id"))
                    &&string(attempt,"payload_sha256").equals(string(brokerFixed,"payload_sha256")),"NOTES_DRAINED_BROKER_ATTEMPT");
            yes(brokerFixed,"attempt_consumed");no(brokerFixed,"goal_independently_verified");
            JSONObject gate=result.getJSONObject("task_authorization"),check=gate.getJSONObject("last_check");
            yes(action.getJSONObject("task_authorization"),"callback_lease_current");no(action.getJSONObject("task_authorization"),"callback_cancelled");
            need(same(gate,without(action.getJSONObject("task_authorization"),"callback_lease_current","callback_cancelled"))&&authorization.equals(string(action,"task_authorization_sha256"))
                    &&"hepta.owner-action-check.v1".equals(string(check,"schema"))&&taskId.equals(string(check,"task_id"))
                    &&authorization.equals(string(check,"authorization_sha256"))&&run.equals(string(check,"model_run_id"))
                    &&"notes.create".equals(string(check,"action"))&&PACKAGE.equals(string(check,"target_package")),"NOTES_DRAINED_AUTHORIZATION");yes(check,"allowed");
            requireNormalModelClose(projection,run,observation,step,drained,terminal);
        }
        /** A completed Notes workflow may still fail its final close. This binds
         * the already drained history only. No historical workflow or exit record
         * replaces the independent current absence observations below. */
        private void requireWorkflowBootstrap(JSONObject early,JSONObject createdResponse,JSONObject last,JSONObject terminal,
                java.util.Set<Integer> ids)throws Exception{
            need(!prelaunchCreateFailure&&!releasedTerminal&&"close".equals(string(last,"operation"))
                    &&"CLEANUP_UNKNOWN".equals(string(last,"state"))&&"client_close".equals(string(last,"terminal_reason"))
                    &&"CLEANUP_NOT_CONFIRMED".equals(string(last,"error")),"NOTES_WORKFLOW_CLOSE_PHASE");
            no(last,"ok","dispatched");yes(last,"public_scope_admission_retired","public_scope_closing");
            JSONObject finalCustody=last.getJSONObject("personal_notes_cleanup");
            need(same(finalCustody,terminal.getJSONObject("personal_notes_cleanup")),"NOTES_WORKFLOW_CLOSE_CUSTODY");
            yes(finalCustody,"pre_release_tasks_verified","release_api_entered","release_api_returned","identity_unknown","custodian_retained");
            need("NOTES_CLEANUP_UNKNOWN".equals(string(finalCustody,"failure")),"NOTES_WORKFLOW_CLOSE_FAILURE");
            java.util.Set<String> requests=new TreeSet<String>();requests.add(string(last,"request_id"));
            long prior=created;
            for(int stage=0;stage<2;stage++){
                JSONObject response=stage==0?early:createdResponse;
                need(number(response,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_VERSION&&generation.equals(string(response,"generation"))
                        &&number(response,"display_id")==displayId&&publicScope.sha256.equals(string(response,"display_scope_sha256"))
                        &&"ACTIVE".equals(string(response,"state"))&&(stage==0?"launch":"notes.create").equals(string(response,"operation"))
                        &&ProfileIdentity.uuid(string(response,"request_id"))&&requests.add(string(response,"request_id")),"NOTES_WORKFLOW_RESPONSE");
                yes(response,"ok","dispatched");no(response,"public_scope_admission_retired","public_scope_closing");
                JSONObject custody=response.getJSONObject("personal_notes_cleanup"),location=response.getJSONObject("public_task_location");
                need(notesCustody(custody,false)==targetUid,"NOTES_TARGET_UID_CHANGED");
                no(custody,"identity_unknown","pre_release_tasks_verified","release_api_entered","release_api_returned");
                need(string(custody,"failure").isEmpty(),"NOTES_WORKFLOW_RESPONSE_CUSTODY");
                need("hepta.public-own-group.task-location.v1".equals(string(location,"schema"))&&generation.equals(string(location,"generation"))
                        &&number(location,"display_id")==displayId&&number(location,"target_user_id")==0
                        &&number(location,"observed_elapsed_ms")>=prior&&number(location,"observed_elapsed_ms")<=number(last.getJSONObject("public_task_location"),"observed_elapsed_ms"),
                        "NOTES_WORKFLOW_RESPONSE_LOCATION");
                no(location,"task_mutation_authority","retired","physical_user_activity_frozen","recents_unchanged_claimed");
                prior=number(location,"observed_elapsed_ms");
                JSONArray oldRows=custody.getJSONArray("actual_observed_tasks"),finalRows=finalCustody.getJSONArray("actual_observed_tasks");
                need(oldRows.length()>0&&oldRows.length()<=32&&(stage==0||oldRows.length()==finalRows.length()),"NOTES_WORKFLOW_TASK_SET");
                java.util.Set<Integer> oldIds=new TreeSet<Integer>();
                for(int i=0;i<oldRows.length();i++){JSONObject row=oldRows.getJSONObject(i);long task=number(row,"task_id");boolean found=false;
                    need(task>0&&task<=Integer.MAX_VALUE&&oldIds.add((int)task),"NOTES_WORKFLOW_TASK_SET");
                    for(int n=0;n<finalRows.length();n++)if(task==number(finalRows.getJSONObject(n),"task_id")){
                        need(!found&&same(row,finalRows.getJSONObject(n)),"NOTES_WORKFLOW_OWNED_IDENTITY_CHANGED");found=true;}
                    need(found,"NOTES_WORKFLOW_OWNED_IDENTITY_LOST");}
                JSONArray located=location.getJSONArray("observed_owned_task_ids");java.util.Set<Integer> locations=new TreeSet<Integer>();
                for(int i=0;i<located.length();i++){long task=numberAt(located,i);
                    need(task>0&&task<=Integer.MAX_VALUE&&locations.add((int)task),"NOTES_WORKFLOW_TASK_SET");}
                need(locations.equals(oldIds)&&ids.containsAll(oldIds)&&(stage==0||ids.equals(oldIds)),"NOTES_WORKFLOW_TASK_SET");
                JSONObject launch=response.getJSONObject("task_launch_policy");
                need("hepta.background-task-launch-policy.v1".equals(string(launch,"schema"))&&generation.equals(string(launch,"generation"))
                        &&number(launch,"display_id")==displayId&&PACKAGE.equals(string(launch,"package"))&&number(launch,"target_uid")==targetUid
                        &&string(launch,"component").startsWith(PACKAGE+"/")&&string(launch,"request_id").equals(string(response,"request_id")),
                        "NOTES_WORKFLOW_LAUNCH_TARGET");yes(launch,"activity_info_rechecked_before_dispatch");
            }
            need(ProfileIdentity.uuid(string(last,"request_id"))&&number(last.getJSONObject("public_task_location"),"observed_elapsed_ms")<=started,
                    "NOTES_WORKFLOW_CLOSE_CLOCK");
        }
        /** Independent preserved-history branch for a workflow whose final close
         * refused task identity before any retirement/release call. */
        private void requireWorkflowRetirementRefusalBootstrap(JSONObject early,JSONObject createdResponse,JSONObject last,JSONObject terminal,
                java.util.Set<Integer> ids)throws Exception{
            need(!prelaunchCreateFailure&&!releasedTerminal&&"close".equals(string(last,"operation"))
                    &&"CLEANUP_UNKNOWN".equals(string(last,"state"))&&"client_close".equals(string(last,"terminal_reason"))
                    &&"CLEANUP_NOT_CONFIRMED".equals(string(last,"error")),"NOTES_WORKFLOW_CLOSE_PHASE");
            no(last,"ok","dispatched");yes(last,"public_scope_admission_retired","public_scope_closing");
            JSONObject finalCustody=last.getJSONObject("personal_notes_cleanup");
            need(same(finalCustody,terminal.getJSONObject("personal_notes_cleanup")),"NOTES_WORKFLOW_CLOSE_CUSTODY");
            // This is the exact pre-release identity refusal shape. It gives no
            // release proof: the same independent post-TTL absence remains mandatory.
            no(finalCustody,"pre_release_tasks_verified","release_api_entered","release_api_returned",
                    "cleanup_known","display_absence_verified","live_tasks_absent","all_recents_sections_absent",
                    "arbitrary_task_removal_used","force_stop_used","caller_flag_is_cleanup_proof");
            yes(finalCustody,"identity_unknown","custodian_retained");
            need("NOTES_RETIREMENT_TOP_IDENTITY".equals(string(finalCustody,"failure"))
                    &&number(finalCustody,"absence_reads")==0&&number(finalCustody,"pending_owned_reads")==0,
                    "NOTES_WORKFLOW_RETIREMENT_REFUSAL");
            JSONObject diagnostics=last.getJSONObject("personal_notes_task_info_diagnostics");
            need(same(diagnostics,terminal.getJSONObject("personal_notes_task_info_diagnostics"))
                    &&"hepta.notes-taskinfo-diagnostics.v1".equals(string(diagnostics,"schema"))
                    &&diagnostics.get("first_runtime_failure")==JSONObject.NULL,"NOTES_WORKFLOW_RETIREMENT_DIAGNOSTICS");
            no(diagnostics,"diagnostics_grant_authority","provides_cleanup_proof");
            JSONObject refusal=diagnostics.getJSONObject("first_cleanup_failure");
            need("cleanup".equals(string(refusal,"phase"))&&"java.io.IOException".equals(string(refusal,"exception_class"))
                    &&"NOTES_RETIREMENT_TOP_IDENTITY".equals(string(refusal,"reason"))
                    &&refusal.get("actual_root_read_failure")==JSONObject.NULL
                    &&number(refusal,"observed_elapsed_ms")>=number(last.getJSONObject("public_task_location"),"observed_elapsed_ms")
                    &&number(refusal,"observed_elapsed_ms")<=number(object(originals.get("result")),"terminal_decided_elapsed_ms"),
                    "NOTES_WORKFLOW_RETIREMENT_DIAGNOSTICS");
            java.util.Set<String> requests=new TreeSet<String>();requests.add(string(last,"request_id"));
            long prior=created;
            for(int stage=0;stage<2;stage++){
                JSONObject response=stage==0?early:createdResponse;
                need(number(response,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_VERSION&&generation.equals(string(response,"generation"))
                        &&number(response,"display_id")==displayId&&publicScope.sha256.equals(string(response,"display_scope_sha256"))
                        &&"ACTIVE".equals(string(response,"state"))&&(stage==0?"launch":"notes.create").equals(string(response,"operation"))
                        &&ProfileIdentity.uuid(string(response,"request_id"))&&requests.add(string(response,"request_id")),"NOTES_WORKFLOW_RESPONSE");
                yes(response,"ok","dispatched");no(response,"public_scope_admission_retired","public_scope_closing");
                JSONObject custody=response.getJSONObject("personal_notes_cleanup"),location=response.getJSONObject("public_task_location");
                need(notesCustody(custody,false)==targetUid,"NOTES_TARGET_UID_CHANGED");
                no(custody,"identity_unknown","pre_release_tasks_verified","release_api_entered","release_api_returned");
                need(string(custody,"failure").isEmpty(),"NOTES_WORKFLOW_RESPONSE_CUSTODY");
                need("hepta.public-own-group.task-location.v1".equals(string(location,"schema"))&&generation.equals(string(location,"generation"))
                        &&number(location,"display_id")==displayId&&number(location,"target_user_id")==0
                        &&number(location,"observed_elapsed_ms")>=prior&&number(location,"observed_elapsed_ms")<=number(last.getJSONObject("public_task_location"),"observed_elapsed_ms"),
                        "NOTES_WORKFLOW_RESPONSE_LOCATION");
                no(location,"task_mutation_authority","retired","physical_user_activity_frozen","recents_unchanged_claimed");
                prior=number(location,"observed_elapsed_ms");
                JSONArray oldRows=custody.getJSONArray("actual_observed_tasks"),finalRows=finalCustody.getJSONArray("actual_observed_tasks");
                need(oldRows.length()>0&&oldRows.length()<=32&&(stage==0||oldRows.length()==finalRows.length()),"NOTES_WORKFLOW_TASK_SET");
                java.util.Set<Integer> oldIds=new TreeSet<Integer>();
                for(int i=0;i<oldRows.length();i++){JSONObject row=oldRows.getJSONObject(i);long task=number(row,"task_id");boolean found=false;
                    need(task>0&&task<=Integer.MAX_VALUE&&oldIds.add((int)task),"NOTES_WORKFLOW_TASK_SET");
                    for(int n=0;n<finalRows.length();n++)if(task==number(finalRows.getJSONObject(n),"task_id")){
                        need(!found&&same(row,finalRows.getJSONObject(n)),"NOTES_WORKFLOW_OWNED_IDENTITY_CHANGED");found=true;}
                    need(found,"NOTES_WORKFLOW_OWNED_IDENTITY_LOST");}
                JSONArray located=location.getJSONArray("observed_owned_task_ids");java.util.Set<Integer> locations=new TreeSet<Integer>();
                for(int i=0;i<located.length();i++){long task=numberAt(located,i);
                    need(task>0&&task<=Integer.MAX_VALUE&&locations.add((int)task),"NOTES_WORKFLOW_TASK_SET");}
                need(locations.equals(oldIds)&&ids.containsAll(oldIds)&&(stage==0||ids.equals(oldIds)),"NOTES_WORKFLOW_TASK_SET");
                JSONObject launch=response.getJSONObject("task_launch_policy");
                need("hepta.background-task-launch-policy.v1".equals(string(launch,"schema"))&&generation.equals(string(launch,"generation"))
                        &&number(launch,"display_id")==displayId&&PACKAGE.equals(string(launch,"package"))&&number(launch,"target_uid")==targetUid
                        &&string(launch,"component").startsWith(PACKAGE+"/")&&string(launch,"request_id").equals(string(response,"request_id")),
                        "NOTES_WORKFLOW_LAUNCH_TARGET");yes(launch,"activity_info_rechecked_before_dispatch");
            }
            need(ProfileIdentity.uuid(string(last,"request_id"))&&number(last.getJSONObject("public_task_location"),"observed_elapsed_ms")<=started,
                    "NOTES_WORKFLOW_CLOSE_CLOCK");
        }
        /** Independent preserved-history branch for a workflow whose final close
         * submitted one token retirement before its following complete read failed. */
        private void requireWorkflowPartialRetirementBootstrap(JSONObject early,JSONObject createdResponse,JSONObject last,JSONObject terminal,
                java.util.Set<Integer> ids)throws Exception{
            need(!prelaunchCreateFailure&&!releasedTerminal&&"close".equals(string(last,"operation"))
                    &&"CLEANUP_UNKNOWN".equals(string(last,"state"))&&"client_close".equals(string(last,"terminal_reason"))
                    &&"CLEANUP_NOT_CONFIRMED".equals(string(last,"error")),"NOTES_WORKFLOW_CLOSE_PHASE");
            no(last,"ok","dispatched");yes(last,"public_scope_admission_retired","public_scope_closing");
            JSONObject finalCustody=last.getJSONObject("personal_notes_cleanup");
            need(same(finalCustody,terminal.getJSONObject("personal_notes_cleanup")),"NOTES_WORKFLOW_CLOSE_CUSTODY");
            // Preserve the actual partial effect. It neither grants another task
            // mutation nor proves any task, creator, recent or display absent.
            no(finalCustody,"release_api_entered","release_api_returned",
                    "cleanup_known","display_absence_verified","live_tasks_absent","all_recents_sections_absent",
                    "arbitrary_task_removal_used","force_stop_used","caller_flag_is_cleanup_proof");
            yes(finalCustody,"pre_release_tasks_verified","identity_unknown","custodian_retained");
            need("NOTES_RETIREMENT_GLOBAL_CHANGED_DURING_READ".equals(string(finalCustody,"failure"))
                    &&number(finalCustody,"absence_reads")==0&&number(finalCustody,"pending_owned_reads")==0,
                    "NOTES_WORKFLOW_PARTIAL_RETIREMENT");
            JSONObject diagnostics=last.getJSONObject("personal_notes_task_info_diagnostics");
            need(same(diagnostics,terminal.getJSONObject("personal_notes_task_info_diagnostics"))
                    &&"hepta.notes-taskinfo-diagnostics.v1".equals(string(diagnostics,"schema"))
                    &&diagnostics.get("first_runtime_failure")==JSONObject.NULL,"NOTES_WORKFLOW_RETIREMENT_DIAGNOSTICS");
            no(diagnostics,"diagnostics_grant_authority","provides_cleanup_proof");
            JSONObject refusal=diagnostics.getJSONObject("first_cleanup_failure");
            need("cleanup".equals(string(refusal,"phase"))&&"java.io.IOException".equals(string(refusal,"exception_class"))
                    &&"NOTES_RETIREMENT_GLOBAL_CHANGED_DURING_READ".equals(string(refusal,"reason"))
                    &&refusal.get("actual_root_read_failure")==JSONObject.NULL
                    &&number(refusal,"observed_elapsed_ms")>=number(last.getJSONObject("public_task_location"),"observed_elapsed_ms")
                    &&number(refusal,"observed_elapsed_ms")<=number(object(originals.get("result")),"terminal_decided_elapsed_ms"),
                    "NOTES_WORKFLOW_RETIREMENT_DIAGNOSTICS");
            need("hepta.public-personal-notes-cleanup.v2".equals(string(finalCustody,"schema"))
                    &&ProfileIdentity.hash(string(finalCustody,"initial_recents_sha256"))
                    &&ProfileIdentity.hash(string(finalCustody,"pre_release_recents_sha256"))
                    &&string(finalCustody,"final_recents_sha256").isEmpty(),"NOTES_WORKFLOW_PARTIAL_CUSTODY");
            no(finalCustody,"prior_hidden_history_preserved","no_display_create_attempted");
            JSONObject retirement=finalCustody.getJSONObject("token_retirement");
            need("hepta.personal-notes-token-retirement.v1".equals(string(retirement,"schema"))
                    &&number(retirement,"pre_release_absence_reads")==0,"NOTES_WORKFLOW_PARTIAL_RETIREMENT_RECORD");
            yes(retirement,"framework_process_cleanup_possible");
            no(retirement,"numeric_task_id_authority","detached_recent_removal_supported");
            JSONArray attempted=retirement.getJSONArray("attempted_task_ids"),returned=retirement.getJSONArray("returned_task_ids");
            need(attempted.length()==1&&returned.length()==1,"NOTES_WORKFLOW_PARTIAL_EFFECT_COUNT");
            long attemptedId=numberAt(attempted,0);
            need(attemptedId>0&&attemptedId<=Integer.MAX_VALUE&&ids.contains((int)attemptedId)
                    &&numberAt(returned,0)==attemptedId,"NOTES_WORKFLOW_PARTIAL_EFFECT_IDENTITY");
            long retirementDeadline=number(retirement,"deadline_elapsed_ms");
            need(retirementDeadline>number(last.getJSONObject("public_task_location"),"observed_elapsed_ms")
                    &&retirementDeadline<=expires&&number(refusal,"observed_elapsed_ms")<retirementDeadline,
                    "NOTES_WORKFLOW_PARTIAL_EFFECT_CLOCK");
            java.util.Set<String> requests=new TreeSet<String>();requests.add(string(last,"request_id"));
            long prior=created;
            for(int stage=0;stage<2;stage++){
                JSONObject response=stage==0?early:createdResponse;
                need(number(response,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_VERSION&&generation.equals(string(response,"generation"))
                        &&number(response,"display_id")==displayId&&publicScope.sha256.equals(string(response,"display_scope_sha256"))
                        &&"ACTIVE".equals(string(response,"state"))&&(stage==0?"launch":"notes.create").equals(string(response,"operation"))
                        &&ProfileIdentity.uuid(string(response,"request_id"))&&requests.add(string(response,"request_id")),"NOTES_WORKFLOW_RESPONSE");
                yes(response,"ok","dispatched");no(response,"public_scope_admission_retired","public_scope_closing");
                JSONObject custody=response.getJSONObject("personal_notes_cleanup"),location=response.getJSONObject("public_task_location");
                need(notesCustody(custody,false)==targetUid,"NOTES_TARGET_UID_CHANGED");
                no(custody,"identity_unknown","pre_release_tasks_verified","release_api_entered","release_api_returned");
                need(string(custody,"failure").isEmpty(),"NOTES_WORKFLOW_RESPONSE_CUSTODY");
                need("hepta.public-own-group.task-location.v1".equals(string(location,"schema"))&&generation.equals(string(location,"generation"))
                        &&number(location,"display_id")==displayId&&number(location,"target_user_id")==0
                        &&number(location,"observed_elapsed_ms")>=prior&&number(location,"observed_elapsed_ms")<=number(last.getJSONObject("public_task_location"),"observed_elapsed_ms"),
                        "NOTES_WORKFLOW_RESPONSE_LOCATION");
                no(location,"task_mutation_authority","retired","physical_user_activity_frozen","recents_unchanged_claimed");
                prior=number(location,"observed_elapsed_ms");
                JSONArray oldRows=custody.getJSONArray("actual_observed_tasks"),finalRows=finalCustody.getJSONArray("actual_observed_tasks");
                need(oldRows.length()>0&&oldRows.length()<=32&&(stage==0||oldRows.length()==finalRows.length()),"NOTES_WORKFLOW_TASK_SET");
                java.util.Set<Integer> oldIds=new TreeSet<Integer>();
                for(int i=0;i<oldRows.length();i++){JSONObject row=oldRows.getJSONObject(i);long task=number(row,"task_id");boolean found=false;
                    need(task>0&&task<=Integer.MAX_VALUE&&oldIds.add((int)task),"NOTES_WORKFLOW_TASK_SET");
                    for(int n=0;n<finalRows.length();n++)if(task==number(finalRows.getJSONObject(n),"task_id")){
                        need(!found&&same(row,finalRows.getJSONObject(n)),"NOTES_WORKFLOW_OWNED_IDENTITY_CHANGED");found=true;}
                    need(found,"NOTES_WORKFLOW_OWNED_IDENTITY_LOST");}
                JSONArray located=location.getJSONArray("observed_owned_task_ids");java.util.Set<Integer> locations=new TreeSet<Integer>();
                for(int i=0;i<located.length();i++){long task=numberAt(located,i);
                    need(task>0&&task<=Integer.MAX_VALUE&&locations.add((int)task),"NOTES_WORKFLOW_TASK_SET");}
                need(locations.equals(oldIds)&&ids.containsAll(oldIds)&&(stage==0||ids.equals(oldIds)),"NOTES_WORKFLOW_TASK_SET");
                JSONObject launch=response.getJSONObject("task_launch_policy");
                need("hepta.background-task-launch-policy.v1".equals(string(launch,"schema"))&&generation.equals(string(launch,"generation"))
                        &&number(launch,"display_id")==displayId&&PACKAGE.equals(string(launch,"package"))&&number(launch,"target_uid")==targetUid
                        &&string(launch,"component").startsWith(PACKAGE+"/")&&string(launch,"request_id").equals(string(response,"request_id")),
                        "NOTES_WORKFLOW_LAUNCH_TARGET");yes(launch,"activity_info_rechecked_before_dispatch");
            }
            need(ProfileIdentity.uuid(string(last,"request_id"))&&number(last.getJSONObject("public_task_location"),"observed_elapsed_ms")<=started,
                    "NOTES_WORKFLOW_CLOSE_CLOCK");
        }
        /** A successful one-step Notes workflow whose original close returned one
         * owned launch-token retirement, then rejected changed foreign history.
         * All failed original bytes stay failed. Only later independent complete
         * absence can retire the old lease; this branch cannot retry a task effect. */
        private void requireWorkflowForeignHistoryBootstrap(JSONObject early,JSONObject createdResponse,JSONObject last,JSONObject terminal,
                java.util.Set<Integer> ids)throws Exception{
            need(!prelaunchCreateFailure&&!releasedTerminal&&"close".equals(string(last,"operation"))
                    &&"CLEANUP_UNKNOWN".equals(string(last,"state"))&&"client_close".equals(string(last,"terminal_reason"))
                    &&"CLEANUP_NOT_CONFIRMED".equals(string(last,"error")),"NOTES_WORKFLOW_CLOSE_PHASE");
            no(last,"ok","dispatched");yes(last,"public_scope_admission_retired","public_scope_closing");
            JSONObject finalCustody=last.getJSONObject("personal_notes_cleanup");
            need(same(finalCustody,terminal.getJSONObject("personal_notes_cleanup")),"NOTES_WORKFLOW_CLOSE_CUSTODY");
            // Preserve the actual partial effect. It neither grants another task
            // mutation nor proves any task, creator, recent or display absent.
            no(finalCustody,"release_api_entered","release_api_returned",
                    "cleanup_known","display_absence_verified","live_tasks_absent","all_recents_sections_absent",
                    "arbitrary_task_removal_used","force_stop_used","caller_flag_is_cleanup_proof");
            yes(finalCustody,"pre_release_tasks_verified","identity_unknown","custodian_retained");
            need("NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED".equals(string(finalCustody,"failure"))
                    &&number(finalCustody,"absence_reads")==0&&number(finalCustody,"pending_owned_reads")==0,
                    "NOTES_WORKFLOW_FOREIGN_HISTORY_RETIREMENT");
            JSONObject diagnostics=last.getJSONObject("personal_notes_task_info_diagnostics");
            need(same(diagnostics,terminal.getJSONObject("personal_notes_task_info_diagnostics"))
                    &&"hepta.notes-taskinfo-diagnostics.v1".equals(string(diagnostics,"schema"))
                    &&diagnostics.get("first_runtime_failure")==JSONObject.NULL,"NOTES_WORKFLOW_RETIREMENT_DIAGNOSTICS");
            no(diagnostics,"diagnostics_grant_authority","provides_cleanup_proof");
            JSONObject refusal=diagnostics.getJSONObject("first_cleanup_failure");
            need("cleanup".equals(string(refusal,"phase"))&&"java.lang.IllegalStateException".equals(string(refusal,"exception_class"))
                    &&"NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED".equals(string(refusal,"reason"))
                    &&refusal.get("actual_root_read_failure")==JSONObject.NULL
                    &&number(refusal,"observed_elapsed_ms")>=number(last.getJSONObject("public_task_location"),"observed_elapsed_ms")
                    &&number(refusal,"observed_elapsed_ms")<=number(object(originals.get("result")),"terminal_decided_elapsed_ms"),
                    "NOTES_WORKFLOW_RETIREMENT_DIAGNOSTICS");
            need("hepta.public-personal-notes-cleanup.v2".equals(string(finalCustody,"schema"))
                    &&ProfileIdentity.hash(string(finalCustody,"initial_recents_sha256"))
                    &&ProfileIdentity.hash(string(finalCustody,"pre_release_recents_sha256"))
                    &&string(finalCustody,"final_recents_sha256").isEmpty(),"NOTES_WORKFLOW_FOREIGN_HISTORY_CUSTODY");
            no(finalCustody,"prior_hidden_history_preserved","no_display_create_attempted");
            JSONObject retirement=finalCustody.getJSONObject("token_retirement");
            need("hepta.personal-notes-token-retirement.v1".equals(string(retirement,"schema"))
                    &&number(retirement,"pre_release_absence_reads")==0,"NOTES_WORKFLOW_FOREIGN_HISTORY_RETIREMENT_RECORD");
            yes(retirement,"framework_process_cleanup_possible");
            no(retirement,"numeric_task_id_authority","detached_recent_removal_supported");
            JSONArray attempted=retirement.getJSONArray("attempted_task_ids"),returned=retirement.getJSONArray("returned_task_ids");
            need(attempted.length()==1&&returned.length()==1,"NOTES_WORKFLOW_FOREIGN_HISTORY_EFFECT_COUNT");
            long attemptedId=numberAt(attempted,0);
            need(attemptedId>0&&attemptedId<=Integer.MAX_VALUE&&ids.contains((int)attemptedId)
                    &&numberAt(returned,0)==attemptedId,"NOTES_WORKFLOW_FOREIGN_HISTORY_EFFECT_IDENTITY");
            // This closed shape is the one launch task plus its one Notes-created
            // editor. The single returned token must belong to that original launch.
            // It does not prove either task absent and grants no further retirement.
            JSONArray initialTasks=early.getJSONObject("personal_notes_cleanup").getJSONArray("actual_observed_tasks");
            need(ids.size()==2&&initialTasks.length()==1
                    &&number(initialTasks.getJSONObject(0),"task_id")==attemptedId,
                    "NOTES_WORKFLOW_FOREIGN_HISTORY_EFFECT_TARGET");
            long retirementDeadline=number(retirement,"deadline_elapsed_ms");
            need(retirementDeadline>number(last.getJSONObject("public_task_location"),"observed_elapsed_ms")
                    &&retirementDeadline<=expires&&number(refusal,"observed_elapsed_ms")<retirementDeadline,
                    "NOTES_WORKFLOW_FOREIGN_HISTORY_EFFECT_CLOCK");
            java.util.Set<String> requests=new TreeSet<String>();requests.add(string(last,"request_id"));
            long prior=created;
            for(int stage=0;stage<2;stage++){
                JSONObject response=stage==0?early:createdResponse;
                need(number(response,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_VERSION&&generation.equals(string(response,"generation"))
                        &&number(response,"display_id")==displayId&&publicScope.sha256.equals(string(response,"display_scope_sha256"))
                        &&"ACTIVE".equals(string(response,"state"))&&(stage==0?"launch":"notes.create").equals(string(response,"operation"))
                        &&ProfileIdentity.uuid(string(response,"request_id"))&&requests.add(string(response,"request_id")),"NOTES_WORKFLOW_RESPONSE");
                yes(response,"ok","dispatched");no(response,"public_scope_admission_retired","public_scope_closing");
                JSONObject custody=response.getJSONObject("personal_notes_cleanup"),location=response.getJSONObject("public_task_location");
                need(notesCustody(custody,false)==targetUid,"NOTES_TARGET_UID_CHANGED");
                no(custody,"identity_unknown","pre_release_tasks_verified","release_api_entered","release_api_returned");
                need(string(custody,"failure").isEmpty(),"NOTES_WORKFLOW_RESPONSE_CUSTODY");
                need("hepta.public-own-group.task-location.v1".equals(string(location,"schema"))&&generation.equals(string(location,"generation"))
                        &&number(location,"display_id")==displayId&&number(location,"target_user_id")==0
                        &&number(location,"observed_elapsed_ms")>=prior&&number(location,"observed_elapsed_ms")<=number(last.getJSONObject("public_task_location"),"observed_elapsed_ms"),
                        "NOTES_WORKFLOW_RESPONSE_LOCATION");
                no(location,"task_mutation_authority","retired","physical_user_activity_frozen","recents_unchanged_claimed");
                prior=number(location,"observed_elapsed_ms");
                JSONArray oldRows=custody.getJSONArray("actual_observed_tasks"),finalRows=finalCustody.getJSONArray("actual_observed_tasks");
                need(oldRows.length()>0&&oldRows.length()<=32&&(stage==0||oldRows.length()==finalRows.length()),"NOTES_WORKFLOW_TASK_SET");
                java.util.Set<Integer> oldIds=new TreeSet<Integer>();
                for(int i=0;i<oldRows.length();i++){JSONObject row=oldRows.getJSONObject(i);long task=number(row,"task_id");boolean found=false;
                    need(task>0&&task<=Integer.MAX_VALUE&&oldIds.add((int)task),"NOTES_WORKFLOW_TASK_SET");
                    for(int n=0;n<finalRows.length();n++)if(task==number(finalRows.getJSONObject(n),"task_id")){
                        need(!found&&same(row,finalRows.getJSONObject(n)),"NOTES_WORKFLOW_OWNED_IDENTITY_CHANGED");found=true;}
                    need(found,"NOTES_WORKFLOW_OWNED_IDENTITY_LOST");}
                JSONArray located=location.getJSONArray("observed_owned_task_ids");java.util.Set<Integer> locations=new TreeSet<Integer>();
                for(int i=0;i<located.length();i++){long task=numberAt(located,i);
                    need(task>0&&task<=Integer.MAX_VALUE&&locations.add((int)task),"NOTES_WORKFLOW_TASK_SET");}
                need(locations.equals(oldIds)&&ids.containsAll(oldIds)&&(stage==0||ids.equals(oldIds)),"NOTES_WORKFLOW_TASK_SET");
                JSONObject launch=response.getJSONObject("task_launch_policy");
                need("hepta.background-task-launch-policy.v1".equals(string(launch,"schema"))&&generation.equals(string(launch,"generation"))
                        &&number(launch,"display_id")==displayId&&PACKAGE.equals(string(launch,"package"))&&number(launch,"target_uid")==targetUid
                        &&string(launch,"component").startsWith(PACKAGE+"/")&&string(launch,"request_id").equals(string(response,"request_id")),
                        "NOTES_WORKFLOW_LAUNCH_TARGET");yes(launch,"activity_info_rechecked_before_dispatch");
            }
            need(ProfileIdentity.uuid(string(last,"request_id"))&&number(last.getJSONObject("public_task_location"),"observed_elapsed_ms")<=started,
                    "NOTES_WORKFLOW_CLOSE_CLOCK");
        }
        /** A released broker terminal is only historical output when the App lost
         * the authenticated close reply. Keep its old unknown exit and ACTIVE
         * response intact; only validate() can accept independent current absence. */
        private void requireWorkflowReleasedReplyLostBootstrap(JSONObject early,JSONObject createdResponse,JSONObject last,
                JSONObject terminal,java.util.Set<Integer> ids)throws Exception{
            JSONObject cleanup=object(originals.get("cleanup")),result=object(originals.get("result"));
            need(workflowReleasedReplyLost&&!prelaunchCreateFailure&&releasedTerminal
                    &&!workflowRetirementRefused&&!workflowPartialRetirement&&!workflowForeignHistoryRetirement
                    &&"后台响应提前结束".equals(string(cleanup,"cleanup_error"))
                    &&cleanup.get("broker_process_exit_code")==JSONObject.NULL,"NOTES_WORKFLOW_LOST_CLOSE_KIND");
            no(cleanup,"broker_process_exit_observed","cleanup_known");
            need("client_close".equals(string(terminal,"reason"))&&ids.size()==2,"NOTES_WORKFLOW_LOST_CLOSE_TERMINAL");
            for(String key:new String[]{"boot_count_read_retirement_failure","owned_single_task","profile_cleanup",
                    "profile_last_leaf_validation","profile_first_root_refusal","profile_permission_first_read_mismatch"})
                need(terminal.get(key)==JSONObject.NULL,"NOTES_WORKFLOW_LOST_CLOSE_PROFILE_STATE");
            no(terminal,"profile_custody_retained");
            JSONObject profileDiagnostics=terminal.getJSONObject("profile_cleanup_diagnostics");
            need("hepta.profile-cleanup-diagnostics.v1".equals(string(profileDiagnostics,"schema"))
                    &&profileDiagnostics.get("first_failure")==JSONObject.NULL,"NOTES_WORKFLOW_LOST_CLOSE_PROFILE_STATE");
            no(profileDiagnostics,"diagnostics_grant_authority","provides_cleanup_proof","allows_input_or_model_resumption");
            JSONObject finalCustody=terminal.getJSONObject("personal_notes_cleanup");
            need(number(finalCustody,"absence_reads")==2&&number(finalCustody,"pending_owned_reads")==0,
                    "NOTES_WORKFLOW_LOST_CLOSE_CUSTODY");
            JSONArray finalRows=finalCustody.getJSONArray("actual_observed_tasks");
            need(finalRows.length()==2,"NOTES_WORKFLOW_LOST_CLOSE_TASK_SET");
            JSONObject retirement=finalCustody.getJSONObject("token_retirement");
            need("hepta.personal-notes-token-retirement.v1".equals(string(retirement,"schema"))
                    &&number(retirement,"pre_release_absence_reads")==2,"NOTES_WORKFLOW_LOST_CLOSE_RETIREMENT");
            yes(retirement,"framework_process_cleanup_possible");
            no(retirement,"numeric_task_id_authority","detached_recent_removal_supported");
            JSONArray attempted=retirement.getJSONArray("attempted_task_ids"),returned=retirement.getJSONArray("returned_task_ids");
            JSONArray initialRows=early.getJSONObject("personal_notes_cleanup").getJSONArray("actual_observed_tasks");
            need(attempted.length()==1&&returned.length()==1&&initialRows.length()==1
                    &&numberAt(attempted,0)==numberAt(returned,0)&&numberAt(attempted,0)==number(initialRows.getJSONObject(0),"task_id"),
                    "NOTES_WORKFLOW_LOST_CLOSE_RETIREMENT_TARGET");
            long terminalAt=number(result,"terminal_decided_elapsed_ms"),lastAt=number(last.getJSONObject("public_task_location"),"observed_elapsed_ms");
            long retirementDeadline=number(retirement,"deadline_elapsed_ms");
            need(retirementDeadline>lastAt&&retirementDeadline<=expires&&terminalAt<=retirementDeadline,
                    "NOTES_WORKFLOW_LOST_CLOSE_RETIREMENT_CLOCK");
            JSONObject surface=terminal.getJSONObject("public_surface_detach");
            need("hepta.public-own-group.surface-retirement.v1".equals(string(surface,"schema"))
                    &&"API_RETURNED_UNVERIFIED".equals(string(surface,"state"))
                    &&"FROZEN_FRAMEWORK_IDENTITY".equals(string(surface,"identity_source"))
                    &&string(surface,"failure_type").isEmpty(),"NOTES_WORKFLOW_LOST_CLOSE_SURFACE");
            yes(surface,"admission_irrevocably_retired","worker_claimed","identity_read_completed","adapter_entered",
                    "api_attempted","api_returned","worker_finished");
            no(surface,"late_create_worker_claimed","deadline_exceeded","surface_stopped_verified",
                    "provides_task_or_display_cleanup_proof","allows_input_or_model_resumption","shutdown_depends_on_fresh_display_binder_query");
            long retiredAt=number(surface,"began_elapsed_ms"),surfaceEnd=number(surface,"ended_elapsed_ms");
            need(retiredAt>=lastAt&&surfaceEnd>=retiredAt&&surfaceEnd<=terminalAt,"NOTES_WORKFLOW_LOST_CLOSE_SURFACE_CLOCK");
            JSONObject screen=terminal.getJSONObject("public_screen_lease");
            need("hepta.public-own-group.screen-lease.v1".equals(string(screen,"schema"))
                    &&generation.equals(string(screen,"generation"))&&number(screen,"display_id")==displayId
                    &&number(screen,"expires_elapsed_ms")==expires&&number(screen,"display_group_id")>1
                    &&number(screen,"wake_lock_flags")==10&&"PUBLIC_SCREEN_LEASE_RETIRED".equals(string(screen,"failure")),
                    "NOTES_WORKFLOW_LOST_CLOSE_SCREEN");
            yes(screen,"acquire_entered","acquire_returned","admission_retired","release_entered","release_returned");
            no(screen,"grants_cleanup_or_business_success");
            need(number(screen,"acquired_elapsed_ms")>=created&&number(screen,"acquired_elapsed_ms")<=lastAt
                    &&number(screen,"released_elapsed_ms")>=retiredAt&&number(screen,"released_elapsed_ms")<=terminalAt,
                    "NOTES_WORKFLOW_LOST_CLOSE_SCREEN_CLOCK");
            JSONObject policy=terminal.getJSONObject("public_policy_diagnostics"),notes=terminal.getJSONObject("personal_notes_task_info_diagnostics");
            need("hepta.public-policy-diagnostics.v1".equals(string(policy,"schema"))
                    &&"hepta.notes-taskinfo-diagnostics.v1".equals(string(notes,"schema"))
                    &&notes.get("first_cleanup_failure")==JSONObject.NULL,"NOTES_WORKFLOW_LOST_CLOSE_DIAGNOSTICS");
            no(policy,"diagnostics_grant_authority","provides_cleanup_proof");no(notes,"diagnostics_grant_authority","provides_cleanup_proof");
            JSONObject policyFailure=policy.getJSONObject("first_failure"),runtimeFailure=notes.getJSONObject("first_runtime_failure");
            need("SCREEN_LEASE".equals(string(policyFailure,"phase"))
                    &&"java.io.IOException".equals(string(policyFailure,"exception_class"))
                    &&"java.io.IOException".equals(string(policyFailure,"cause_class"))
                    &&number(policyFailure,"reflection_wrapper_count")==0
                    &&"PUBLIC_SCREEN_LEASE_RETIRED".equals(string(policyFailure,"category"))
                    &&"runtime_policy_check".equals(string(runtimeFailure,"phase"))
                    &&"java.io.IOException".equals(string(runtimeFailure,"exception_class"))
                    &&"PUBLIC_SCREEN_LEASE_RETIRED".equals(string(runtimeFailure,"reason"))
                    &&runtimeFailure.get("actual_root_read_failure")==JSONObject.NULL,"NOTES_WORKFLOW_LOST_CLOSE_DIAGNOSTICS");
            need(number(policyFailure,"observed_elapsed_ms")>=retiredAt&&number(policyFailure,"observed_elapsed_ms")<=terminalAt
                    &&number(runtimeFailure,"observed_elapsed_ms")>=retiredAt&&number(runtimeFailure,"observed_elapsed_ms")<=terminalAt,
                    "NOTES_WORKFLOW_LOST_CLOSE_DIAGNOSTIC_CLOCK");
            java.util.Set<String> requests=new TreeSet<String>();long prior=created;
            for(int stage=0;stage<3;stage++){
                JSONObject response=stage==0?early:stage==1?createdResponse:last;
                need(number(response,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_VERSION&&generation.equals(string(response,"generation"))
                        &&number(response,"display_id")==displayId&&publicScope.sha256.equals(string(response,"display_scope_sha256"))
                        &&"ACTIVE".equals(string(response,"state"))&&(stage==0?"launch":stage==1?"notes.create":"state").equals(string(response,"operation"))
                        &&ProfileIdentity.uuid(string(response,"request_id"))&&requests.add(string(response,"request_id"))
                        &&!response.has("error")&&!response.has("terminal_reason"),"NOTES_WORKFLOW_LOST_CLOSE_RESPONSE");
                yes(response,"ok");if(stage<2)yes(response,"dispatched");else no(response,"dispatched");
                no(response,"public_scope_admission_retired","public_scope_closing");
                JSONObject custody=response.getJSONObject("personal_notes_cleanup"),location=response.getJSONObject("public_task_location");
                need(notesCustody(custody,false)==targetUid&&"hepta.public-personal-notes-cleanup.v2".equals(string(custody,"schema")),
                        "NOTES_WORKFLOW_LOST_CLOSE_ACTIVE_CUSTODY");
                yes(custody,"custodian_retained");
                no(custody,"identity_unknown","pre_release_tasks_verified","release_api_entered","release_api_returned",
                        "display_absence_verified","live_tasks_absent","all_recents_sections_absent","prior_hidden_history_preserved","no_display_create_attempted");
                need(number(custody,"absence_reads")==0&&number(custody,"pending_owned_reads")==0&&string(custody,"failure").isEmpty()
                        &&string(custody,"pre_release_recents_sha256").isEmpty()&&string(custody,"final_recents_sha256").isEmpty()
                        &&string(custody,"initial_recents_sha256").equals(string(finalCustody,"initial_recents_sha256")),
                        "NOTES_WORKFLOW_LOST_CLOSE_ACTIVE_CUSTODY");
                JSONObject oldPolicy=response.getJSONObject("public_policy_diagnostics"),oldNotes=response.getJSONObject("personal_notes_task_info_diagnostics");
                need("hepta.public-policy-diagnostics.v1".equals(string(oldPolicy,"schema"))&&oldPolicy.get("first_failure")==JSONObject.NULL
                        &&"hepta.notes-taskinfo-diagnostics.v1".equals(string(oldNotes,"schema"))
                        &&oldNotes.get("first_runtime_failure")==JSONObject.NULL&&oldNotes.get("first_cleanup_failure")==JSONObject.NULL,
                        "NOTES_WORKFLOW_LOST_CLOSE_ACTIVE_DIAGNOSTICS");
                no(oldPolicy,"diagnostics_grant_authority","provides_cleanup_proof");no(oldNotes,"diagnostics_grant_authority","provides_cleanup_proof");
                need("hepta.public-own-group.task-location.v1".equals(string(location,"schema"))&&generation.equals(string(location,"generation"))
                        &&number(location,"display_id")==displayId&&number(location,"target_user_id")==0
                        &&number(location,"observed_elapsed_ms")>=prior&&number(location,"observed_elapsed_ms")<=lastAt,
                        "NOTES_WORKFLOW_LOST_CLOSE_RESPONSE_CLOCK");
                no(location,"task_mutation_authority","retired","physical_user_activity_frozen","recents_unchanged_claimed");
                prior=number(location,"observed_elapsed_ms");JSONArray oldRows=custody.getJSONArray("actual_observed_tasks");
                need(oldRows.length()==(stage==0?1:2),"NOTES_WORKFLOW_LOST_CLOSE_TASK_SET");
                java.util.Set<Integer> oldIds=new TreeSet<Integer>();
                for(int i=0;i<oldRows.length();i++){JSONObject row=oldRows.getJSONObject(i);long task=number(row,"task_id");boolean found=false;
                    need(task>0&&task<=Integer.MAX_VALUE&&oldIds.add((int)task),"NOTES_WORKFLOW_LOST_CLOSE_TASK_SET");
                    for(int n=0;n<finalRows.length();n++)if(task==number(finalRows.getJSONObject(n),"task_id")){
                        need(!found&&same(row,finalRows.getJSONObject(n)),"NOTES_WORKFLOW_LOST_CLOSE_IDENTITY_CHANGED");found=true;}
                    need(found,"NOTES_WORKFLOW_LOST_CLOSE_IDENTITY_LOST");}
                JSONArray located=location.getJSONArray("observed_owned_task_ids");java.util.Set<Integer> locations=new TreeSet<Integer>();
                for(int i=0;i<located.length();i++){long task=numberAt(located,i);
                    need(task>0&&task<=Integer.MAX_VALUE&&locations.add((int)task),"NOTES_WORKFLOW_LOST_CLOSE_TASK_SET");}
                need(locations.equals(oldIds)&&ids.containsAll(oldIds)&&(stage==0||ids.equals(oldIds)),"NOTES_WORKFLOW_LOST_CLOSE_TASK_SET");
                if(stage<2){JSONObject launch=response.getJSONObject("task_launch_policy");
                    need("hepta.background-task-launch-policy.v1".equals(string(launch,"schema"))&&generation.equals(string(launch,"generation"))
                            &&number(launch,"display_id")==displayId&&PACKAGE.equals(string(launch,"package"))&&number(launch,"target_uid")==targetUid
                            &&string(launch,"component").startsWith(PACKAGE+"/")&&string(launch,"request_id").equals(string(response,"request_id")),
                            "NOTES_WORKFLOW_LOST_CLOSE_LAUNCH_TARGET");yes(launch,"activity_info_rechecked_before_dispatch");}
                else need(!response.has("task_launch_policy"),"NOTES_WORKFLOW_LOST_CLOSE_LAST_STATE");
            }
        }
        private void requireWorkflowModel(JSONObject result,JSONObject owner,JSONObject projection,JSONObject response)throws Exception{
            JSONObject step=object(originals.get("step_model")),action=object(originals.get("step_action")),attempt=object(originals.get("fixed_intent_attempt"));
            JSONObject fixed=result.getJSONArray("fixed_intent_attempts").getJSONObject(0),work=action.getJSONObject("action_execution");
            String run=string(step,"run_id"),observation=string(step,"observation_id"),authorization=string(owner,"task_authorization_sha256");
            long terminal=number(result,"terminal_decided_elapsed_ms");
            need(run.matches("[0-9a-f]{32}")&&observation.matches("[0-9a-f]{32}")&&ownerSha256.equals(string(step,"original_instruction_sha256"))
                    &&run.equals(string(action,"model_run_id"))&&same(fixed,without(action.getJSONObject("fixed_intent"),"broker_response"))
                    &&same(response,action.getJSONObject("fixed_intent").getJSONObject("broker_response")),"NOTES_WORKFLOW_PARENT_BINDING");
            yes(action,"accepted","dispatched","model_issued");no(action,"stale","done_success_eligible");
            JSONObject issued=object(string(step,"raw_text").getBytes(StandardCharsets.UTF_8));
            need(same(issued,action.getJSONObject("action"))&&"notes.create".equals(string(issued,"action"))
                    &&PACKAGE.equals(string(issued,"package"))&&observation.equals(string(issued,"observation_id")),"NOTES_WORKFLOW_MODEL_ACTION");
            long drained=requireWorkflowDrainedAction(work,run,observation,authorization,created,terminal);
            bindBackground(action.getJSONObject("background_session"));
            requireWorkflowAuthorization(action.getJSONObject("task_authorization"),result.getJSONObject("task_authorization"),run,authorization,"notes.create",false);
            need(authorization.equals(string(action,"task_authorization_sha256")),"NOTES_WORKFLOW_PARENT_AUTHORIZATION");
            need("hepta.fixed-intent-attempt.v1".equals(string(attempt,"schema"))&&"consumed_before_call".equals(string(attempt,"stage"))
                    &&"hepta.fixed-intent-result.v1".equals(string(fixed,"schema")),"NOTES_WORKFLOW_ATTEMPT_SCHEMA");
            Iterator<String> attemptKeys=attempt.keys();while(attemptKeys.hasNext()){String key=attemptKeys.next();
                if(!"schema".equals(key)&&!"stage".equals(key))need(same(attempt.get(key),fixed.get(key)),"NOTES_WORKFLOW_ATTEMPT_CHANGED");}
            need(taskId.equals(string(attempt,"task_id"))&&run.equals(string(attempt,"model_run_id"))&&observation.equals(string(attempt,"observation_id"))
                    &&number(attempt,"source_window_id")==number(work,"window_id")&&PACKAGE.equals(string(attempt,"source_package"))
                    &&number(attempt,"display_id")==displayId&&generation.equals(string(attempt,"background_generation"))
                    &&"notes.create".equals(string(attempt,"action"))&&number(attempt,"attempt_ordinal")==1
                    &&ProfileIdentity.hash(string(attempt,"attempt_id"))&&ProfileIdentity.sha(string(issued,"text")).equals(string(attempt,"payload_sha256")),
                    "NOTES_WORKFLOW_ATTEMPT_IDENTITY");
            yes(attempt,"attempt_consumed");no(attempt,"automatic_retry_allowed");yes(fixed,"dispatch_attempted","api_accepted");
            no(fixed,"goal_independently_verified","saved_or_search_results_verified");
            need("launch_accepted".equals(string(fixed,"result"))&&"draft_opened".equals(string(fixed,"requested_outcome")),"NOTES_WORKFLOW_PARENT_RESULT");
            JSONObject target=attempt.getJSONObject("target"),brokerFixed=response.getJSONObject("fixed_intent"),launch=response.getJSONObject("task_launch_policy");
            need("installed_package_manager".equals(string(target,"source"))&&"notes.create".equals(string(target,"action"))
                    &&PACKAGE.equals(string(target,"package"))&&number(target,"target_uid")==targetUid&&string(target,"component").startsWith(PACKAGE+"/")
                    &&string(target,"component").equals(string(launch,"component"))&&target.get("required_permission")==JSONObject.NULL,"NOTES_WORKFLOW_TARGET");
            yes(target,"exported","activity_enabled","application_enabled","declared_intent_filter_matched","ordinary_caller_permission_checked");
            need("hepta.background-fixed-intent.v1".equals(string(brokerFixed,"schema"))&&same(target,brokerFixed.getJSONObject("target"))
                    &&string(response,"request_id").equals(string(brokerFixed,"request_id"))&&generation.equals(string(brokerFixed,"generation"))
                    &&number(brokerFixed,"display_id")==displayId&&number(brokerFixed,"ordinary_caller_uid")==ownerUid
                    &&"notes.create".equals(string(brokerFixed,"action"))&&string(attempt,"attempt_id").equals(string(brokerFixed,"attempt_id"))
                    &&string(attempt,"payload_sha256").equals(string(brokerFixed,"payload_sha256")),"NOTES_WORKFLOW_BROKER_ATTEMPT");
            yes(brokerFixed,"attempt_consumed");no(brokerFixed,"goal_independently_verified");
            JSONObject workflow=object(originals.get("workflow_result")),grant=object(originals.get("workflow_grant"));
            need("hepta.notes-create-workflow.v1".equals(string(workflow,"schema"))&&ProfileIdentity.hash(string(workflow,"workflow_id"))
                    &&taskId.equals(string(workflow,"task_id"))&&number(workflow,"parent_step")==1
                    &&run.equals(string(workflow,"parent_model_run_id"))&&observation.equals(string(workflow,"parent_observation_id"))
                    &&string(attempt,"attempt_id").equals(string(workflow,"parent_fixed_intent_attempt_id"))
                    &&ownerSha256.equals(string(workflow,"owner_sha256"))&&authorization.equals(string(workflow,"task_authorization_sha256"))
                    &&ProfileIdentity.hash(string(workflow,"contract_sha256"))&&string(attempt,"payload_sha256").equals(string(workflow,"body_sha256"))
                    &&PACKAGE.equals(string(workflow,"target_package"))&&number(workflow,"target_uid")==targetUid
                    &&number(workflow,"display_id")==displayId&&generation.equals(string(workflow,"background_generation"))
                    &&"tool_workflow".equals(string(workflow,"actor_kind"))&&"draft_opened".equals(string(workflow,"fixed_intent_outcome_unchanged"))
                    &&workflow.get("stop_reason")==JSONObject.NULL,"NOTES_WORKFLOW_HISTORY_BINDING");
            yes(workflow,"grant_consumed","grant_retired","workflow_verified","accepted_as_completion_proof");
            no(workflow,"grants_tool_authority","model_issued","model_done_synthesized","native_model_done_synthesized","persistent_storage_bytes_verified");
            need("hepta.notes-create-workflow.v1".equals(string(grant,"schema")),"NOTES_WORKFLOW_GRANT_SCHEMA");
            yes(grant,"grant_consumed");no(grant,"grant_retired","grants_tool_authority");
            for(String key:new String[]{"workflow_id","task_id","parent_step","parent_model_run_id","parent_observation_id","created_observation_id",
                    "parent_create_after_observation_id","workflow_initial_observation_id","parent_fixed_intent_attempt_id","owner_sha256","contract_sha256",
                    "task_authorization_sha256","body_sha256","target_package","target_uid","target_apk_sha256","display_id","background_generation"})
                need(same(grant.get(key),workflow.get(key)),"NOTES_WORKFLOW_GRANT_BINDING");
            Iterator<String> grantKeys=grant.keys();while(grantKeys.hasNext()){String key=grantKeys.next();
                if(!"grant_retired".equals(key))need(same(grant.get(key),workflow.get(key)),"NOTES_WORKFLOW_GRANT_CHANGED");}
            JSONObject initial=workflow.getJSONObject("initial"),current=workflow.getJSONObject("current"),stable=workflow.getJSONObject("stable_readback");
            requireWorkflowObservation(initial);requireWorkflowObservation(current);requireWorkflowObservation(stable);
            need(string(initial,"observation_id").equals(string(workflow,"created_observation_id"))
                    &&string(initial,"observation_id").equals(string(workflow,"parent_create_after_observation_id"))
                    &&string(initial,"observation_id").equals(string(workflow,"workflow_initial_observation_id"))
                    &&same(without(current,"observation_id"),without(stable,"observation_id"))
                    &&string(stable,"observation_id").equals(string(workflow,"final_observation_id"))
                    &&string(stable,"observation_id").equals(string(result,"final_observation_id")),"NOTES_WORKFLOW_OBSERVATION_CHAIN");
            JSONArray children=workflow.getJSONArray("children");need(children.length()==2,"NOTES_WORKFLOW_CHILD_COUNT");
            java.util.Set<String> operations=new TreeSet<String>(),childIds=new TreeSet<String>();operations.add(string(work,"operation_id"));
            JSONObject previous=initial,lastAction=null;
            for(int i=1;i<=2;i++){
                JSONObject childAction=object(originals.get("child_"+i+"_action")),proof=object(originals.get("child_"+i+"_proof"));
                JSONObject recorded=children.getJSONObject(i-1),child=proof.getJSONObject("child"),retired=recorded.getJSONObject("child");
                need(same(without(proof,"child"),without(recorded,"child"))&&same(without(child,"grant_retired"),without(retired,"grant_retired"))
                        &&same(child,proof.getJSONObject("service_child_receipt"))&&same(child,childAction.getJSONObject("tool_child")),"NOTES_WORKFLOW_CHILD_RECEIPT");
                yes(retired,"grant_retired");no(child,"grant_retired");
                for(String key:new String[]{"workflow_id","task_id","parent_step","parent_model_run_id","parent_observation_id","created_observation_id",
                        "parent_create_after_observation_id","workflow_initial_observation_id","parent_fixed_intent_attempt_id","owner_sha256","contract_sha256",
                        "task_authorization_sha256","body_sha256","target_package","target_uid","target_apk_sha256","display_id","background_generation"})
                    need(same(child.get(key),workflow.get(key)),"NOTES_WORKFLOW_CHILD_BINDING");
                String tool=i==1?"back":"click",before=string(proof.getJSONObject("before"),"observation_id");
                need("hepta.tool-child.v1".equals(string(child,"schema"))&&"tool_child".equals(string(child,"actor_kind"))
                        &&ProfileIdentity.hash(string(child,"child_id"))&&childIds.add(string(child,"child_id"))&&number(child,"child_ordinal")==i
                        &&tool.equals(string(child,"action"))&&before.equals(string(child,"observation_id")),"NOTES_WORKFLOW_CHILD_IDENTITY");
                yes(child,"grant_consumed","service_entered");no(child,"grants_tool_authority","model_issued","automatic_retry_allowed");
                yes(proof,"accepted","dispatched","live_lease_verified");no(proof,"stale");
                requireWorkflowObservation(proof.getJSONObject("before"));requireWorkflowObservation(proof.getJSONObject("after"));
                need(i==1?same(without(previous,"observation_id"),without(proof.getJSONObject("before"),"observation_id"))
                        :same(previous,proof.getJSONObject("before")),"NOTES_WORKFLOW_CHILD_OBSERVATION_CHAIN");
                previous=proof.getJSONObject("after");
                need("hepta.tool-child.v1".equals(string(childAction,"schema"))&&"hepta.internal-tool-child.v1".equals(string(childAction,"action_schema"))
                        &&"tool_child".equals(string(childAction,"actor_kind"))&&number(childAction,"child_ordinal")==i,"NOTES_WORKFLOW_CHILD_ACTION");
                for(String key:new String[]{"parent_model_run_id","parent_fixed_intent_attempt_id","workflow_id","child_id"})
                    need(same(child.get(key),childAction.get(key)),"NOTES_WORKFLOW_CHILD_ACTION");
                yes(childAction,"accepted","dispatched");no(childAction,"model_issued","stale");
                JSONObject issuedChild=childAction.getJSONObject("action");
                need(tool.equals(string(issuedChild,"action"))&&PACKAGE.equals(string(issuedChild,"package"))
                        &&before.equals(string(issuedChild,"observation_id"))&&(i==1?child.get("node_id")==JSONObject.NULL
                        :string(child,"node_id").equals(string(issuedChild,"node_id"))),"NOTES_WORKFLOW_CHILD_ACTION");
                JSONObject childWork=childAction.getJSONObject("action_execution");
                need(number(childWork,"window_id")==number(proof.getJSONObject("before"),"window_id")&&operations.add(string(childWork,"operation_id")),
                        "NOTES_WORKFLOW_CHILD_OPERATION");
                drained=requireWorkflowDrainedAction(childWork,run,before,authorization,drained,terminal);
                requireWorkflowAuthorization(childAction.getJSONObject("task_authorization"),result.getJSONObject("task_authorization"),run,authorization,tool,true);
                bindBackground(childAction.getJSONObject("background_session"));lastAction=childWork;
            }
            need(same(previous,current)&&same(lastAction,result.getJSONObject("last_action_execution"))
                    &&same(without(object(originals.get("child_2_action")).getJSONObject("task_authorization"),"callback_lease_current","callback_cancelled"),
                            result.getJSONObject("task_authorization")),"NOTES_WORKFLOW_FINAL_ACTION");
            JSONObject candidate=object(originals.get("completion_candidate")),identity=object(originals.get("completion_identity")),evidence=result.getJSONObject("completion_evidence");
            need("hepta.controller-workflow-completion.v1".equals(string(candidate,"schema"))&&taskId.equals(string(candidate,"task_id"))
                    &&"controller/tool_workflow".equals(string(candidate,"completion_actor"))&&string(stable,"observation_id").equals(string(candidate,"observation_id")),
                    "NOTES_WORKFLOW_COMPLETION_CANDIDATE");
            for(String key:new String[]{"workflow_id","parent_model_run_id","parent_fixed_intent_attempt_id"})
                need(same(candidate.get(key),workflow.get(key)),"NOTES_WORKFLOW_COMPLETION_CANDIDATE");
            yes(candidate,"terminal_pending_native_identity_and_cleanup");no(candidate,"model_done_synthesized");
            need("ordinary_package_manager_and_full_apk_hash".equals(string(identity,"source"))&&PACKAGE.equals(string(identity,"package"))
                    &&number(identity,"uid")==targetUid&&number(identity,"version_code")>0&&ProfileIdentity.hash(string(identity,"apk_set_sha256"))
                    &&same(identity.getJSONObject("apk_hashes"),workflow.getJSONObject("target_apk_sha256")),"NOTES_WORKFLOW_TARGET_IDENTITY");
            JSONObject hashes=identity.getJSONObject("apk_hashes");need(hashes.length()>0&&hashes.length()<=32,"NOTES_WORKFLOW_TARGET_IDENTITY");
            Iterator<String> parts=hashes.keys();while(parts.hasNext())need(ProfileIdentity.hash(string(hashes,parts.next())),"NOTES_WORKFLOW_TARGET_IDENTITY");
            need("hepta.task-completion.v1".equals(string(evidence,"schema"))&&taskId.equals(string(evidence,"task_id"))
                    &&ownerSha256.equals(string(evidence,"owner_sha256"))&&string(workflow,"contract_sha256").equals(string(evidence,"contract_sha256"))
                    &&number(evidence,"display_id")==displayId&&generation.equals(string(evidence,"background_generation"))
                    &&same(without(workflow,"accepted_as_completion_proof","final_observation_id","native_model_done_synthesized"),evidence.getJSONObject("notes_create_workflow")),
                    "NOTES_WORKFLOW_COMPLETION_HISTORY");
            yes(evidence,"controller_completion_requested","controller_native_parent_session_bound","notes_create_workflow_verified","observation_chain_verified");
            no(evidence,"terminal_binding_and_cleanup_verified","model_done_synthesized","grants_tool_authority");
            no(result,"goal_independently_verified","model_done_synthesized");
            requireNormalModelClose(projection,run,observation,step,drained,terminal);
        }
        private long requireWorkflowDrainedAction(JSONObject work,String run,String observation,String authorization,long previous,long terminal)throws Exception{
            need("hepta.action-execution.v1".equals(string(work,"schema"))&&"serial_action_worker".equals(string(work,"execution_kind"))
                    &&string(work,"operation_id").matches("[0-9a-f]{32}")&&taskId.equals(string(work,"task_id"))
                    &&run.equals(string(work,"model_run_id"))&&observation.equals(string(work,"observation_id"))
                    &&authorization.equals(string(work,"authorization_sha256"))&&number(work,"display_id")==displayId
                    &&generation.equals(string(work,"background_generation"))&&number(work,"window_id")>=0,"NOTES_WORKFLOW_ACTION_IDENTITY");
            yes(work,"effect_entered","effect_returned","api_accepted","worker_drained","callback_published","callback_authority_current");
            no(work,"retired","phases_truncated","automatic_redispatch");
            need(work.get("retirement_reason")==JSONObject.NULL,"NOTES_WORKFLOW_ACTION_RETIRED");
            long queued=number(work,"queued_elapsed_ms"),drained=number(work,"worker_drained_elapsed_ms"),due=number(work,"deadline_elapsed_ms");
            need(queued>=previous&&drained>=queued&&drained<=terminal&&due>queued&&drained<=due,"NOTES_WORKFLOW_ACTION_CLOCK");return drained;
        }
        private void requireWorkflowAuthorization(JSONObject action,JSONObject gate,String run,String authorization,String tool,boolean child)throws Exception{
            yes(action,"callback_lease_current");no(action,"callback_cancelled");
            need(same(without(gate,"last_check"),without(action,"last_check","callback_lease_current","callback_cancelled")),"NOTES_WORKFLOW_AUTHORIZATION_CHANGED");
            JSONObject check=action.getJSONObject("last_check");
            need("hepta.owner-action-check.v1".equals(string(check,"schema"))&&taskId.equals(string(check,"task_id"))
                    &&authorization.equals(string(check,"authorization_sha256"))&&run.equals(string(check,"model_run_id"))
                    &&tool.equals(string(check,"action"))&&PACKAGE.equals(string(check,"target_package")),"NOTES_WORKFLOW_AUTHORIZATION");yes(check,"allowed");
            if(child){need("tool_child".equals(string(check,"actor_kind"))&&run.equals(string(check,"parent_model_run_id")),"NOTES_WORKFLOW_CHILD_AUTHORIZATION");no(check,"model_issued");}
        }
        private void requireWorkflowObservation(JSONObject observation)throws Exception{
            need(string(observation,"observation_id").matches("[0-9a-f]{32}")&&PACKAGE.equals(string(observation,"package"))
                    &&number(observation,"window_id")>=0&&number(observation,"display_id")==displayId
                    &&generation.equals(string(observation,"background_generation"))&&ProfileIdentity.hash(string(observation,"tree_sha256"))
                    &&number(observation,"rotation")>=0&&number(observation,"rotation")<=3,"NOTES_WORKFLOW_OBSERVATION_IDENTITY");
        }
        private void requireNormalModelClose(JSONObject projection,String run,String observation,JSONObject step,long drained,long terminal)throws Exception{
            JSONObject request=object(originals.get("model_request_receipt")),session=object(originals.get("model_session_receipt"));
            JSONObject nativeSession=object(originals.get("native_session_receipt")),generationReceipt=object(originals.get("generation_cleanup_receipt"));
            String worker=string(session,"worker_generation");long appPid=number(session,"app_pid");
            need(worker.matches("[0-9a-f]{32}")&&"hepta.local-model.task-session.v1".equals(string(session,"schema"))
                    &&taskId.equals(string(session,"task_id"))&&number(session,"app_uid")==ownerUid&&appPid>1&&appPid==number(object(originals.get("broker_receipt")),"app_pid")
                    &&"hepta.local-model.task-request.v1".equals(string(request,"schema"))&&taskId.equals(string(request,"task_id"))
                    &&worker.equals(string(request,"worker_generation"))&&run.equals(string(request,"run_id"))
                    &&number(request,"app_uid")==ownerUid&&number(request,"app_pid")==appPid&&number(request,"request_sequence")==1
                    &&observation.equals(string(request,"grammar_observation_id"))&&PACKAGE.equals(string(request,"grammar_current_package"))
                    &&ProfileIdentity.sha(string(step,"raw_text")).equals(string(request,"raw_text_sha256_read")),"NOTES_DRAINED_REQUEST_RECEIPT");
            yes(request,"process_started","inference_completed","request_committed","native_result_binding_valid");
            no(request,"process_exit_observed","caller_cancellation_requested","cancel_requested","timeout_observed","force_destroy_sent","automatic_retry");
            need(request.get("exit_code")==JSONObject.NULL&&"request_completed".equals(string(request,"status")),"NOTES_DRAINED_REQUEST_STATE");
            need(taskId.equals(string(projection,"task_id"))&&worker.equals(string(projection,"worker_generation"))
                    &&number(projection,"exit_code")==0&&ProfileIdentity.sha(originals.get("model_session_receipt")).equals(string(projection,"app_receipt_sha256")),"NOTES_DRAINED_SESSION_PROJECTION");
            yes(projection,"process_started","process_exit_observed","receipt_valid");
            yes(session,"process_started","process_exit_observed","cleanup_known","native_session_binding_valid","generation_cleanup_known","generation_unforced");
            no(session,"caller_cancellation_requested","cancel_requested","force_destroy_sent","parent_force_destroy_sent","automatic_restart","cross_task_reuse");
            need(number(session,"finisher_submitted_monotonic_ns")/1000000L>=drained
                    &&number(session,"finisher_submitted_monotonic_ns")/1000000L<=terminal
                    &&number(session,"exit_code")==0&&number(session,"requests_sent")==1&&number(session,"requests_accepted")==1
                    &&"normal_close_with_observed_sdk_cleanup".equals(string(session,"cleanup_classification"))
                    &&same(nativeSession,session.getJSONObject("native_session_receipt")),"NOTES_DRAINED_SESSION_CLOSE");
            for(JSONObject receipt:new JSONObject[]{request,session}){
                JSONObject cancellation=receipt.getJSONObject("owned_worker_cancellation");boolean closed=receipt==session;
                need("hepta.owned-worker-cancellation.v1".equals(string(cancellation,"schema"))&&taskId.equals(string(cancellation,"task_id"))
                        &&worker.equals(string(cancellation,"worker_generation"))&&number(cancellation,"term_destroy_attempts")==0
                        &&number(cancellation,"force_destroy_attempts")==0&&cancellation.get("signal_error")==JSONObject.NULL
                        &&Boolean.valueOf(closed).equals(cancellation.get("process_exit_observed"))
                        &&(closed?number(cancellation,"exit_code")==0:cancellation.get("exit_code")==JSONObject.NULL),"NOTES_DRAINED_CANCELLATION_AUDIT");
                yes(cancellation,"process_bound");no(cancellation,"requested","termination_started","term_destroy_returned","force_destroy_returned","sdk_cleanup_proven_by_this_object");
            }
            JSONObject nativeRequest=request.getJSONObject("native_receipt"),g=session.getJSONObject("worker_generation_cleanup");
            need("hepta.geniex-task-request.result.v1".equals(string(nativeRequest,"schema"))&&worker.equals(string(nativeRequest,"worker_generation"))
                    &&taskId.equals(string(nativeRequest,"task_id"))&&run.equals(string(nativeRequest,"request_id"))&&number(nativeRequest,"request_sequence")==1
                    &&number(nativeRequest,"pid")==number(request,"worker_pid")&&number(nativeRequest,"request_status")==0
                    &&string(request,"raw_text_sha256_read").equals(string(nativeRequest,"raw_text_sha256")),"NOTES_DRAINED_NATIVE_REQUEST");
            no(nativeRequest,"process_exit_observed","automatic_retry");
            need("hepta.geniex-task-session.result.v1".equals(string(nativeSession,"schema"))&&worker.equals(string(nativeSession,"worker_generation"))
                    &&taskId.equals(string(nativeSession,"task_id"))&&number(nativeSession,"pid")==number(request,"worker_pid")
                    &&number(nativeSession,"last_request_status")==0&&number(nativeSession,"signal_observed")==0,"NOTES_DRAINED_NATIVE_SESSION");
            no(nativeSession,"process_exit_observed","control_channel_write_failed");
            no(nativeSession.getJSONObject("sdk_exception_boundary"),"caught","automatic_retry");
            yes(nativeSession,"model_metadata_unchanged_before_close","close_requested","sdk_destroy_attempted","sdk_deinit_attempted");
            for(String key:new String[]{"requests_received","requests_completed","model_hash_count","sdk_init_count","model_create_count","model_reset_count","control_done_attempts","control_done_delivered"})
                need(number(nativeSession,key)==1,"NOTES_DRAINED_NATIVE_COUNTS");
            for(String key:new String[]{"sdk_destroy_rc","sdk_deinit_rc","control_channel_last_errno","last_request_return_status"})need(number(nativeSession,key)==0,"NOTES_DRAINED_NATIVE_CLOSE");
            need("hepta.worker-generation.app-cleanup.v1".equals(string(g,"schema"))&&taskId.equals(string(g,"task_id"))&&worker.equals(string(g,"worker_generation"))
                    &&number(g,"app_uid")==ownerUid&&number(g,"app_pid")==appPid&&ProfileIdentity.sha(originals.get("generation_identity")).equals(string(g,"identity_sha256"))
                    &&ProfileIdentity.sha(originals.get("generation_cleanup_receipt")).equals(string(g,"native_receipt_sha256"))
                    &&same(generationReceipt,g.getJSONObject("native_cleanup")),"NOTES_DRAINED_GENERATION_RAW_BINDING");
            yes(g,"direct_process_exit_observed","helper_started","helper_exit_observed","cleanup_known","descendant_force_known","generation_unforced");
            no(g,"helper_force_destroy_sent","helper_currently_alive","descendant_force_used","automatic_retry");
            need(number(g,"helper_exit_code")==0&&g.get("error")==JSONObject.NULL&&"pinned_sdk_inheriting_process_group_and_generation_markers".equals(string(g,"scope"))
                    &&number(g,"finisher_submitted_monotonic_ns")==number(session,"finisher_submitted_monotonic_ns")
                    &&number(g,"finisher_deadline_monotonic_ns")==number(session,"finisher_deadline_monotonic_ns"),"NOTES_DRAINED_GENERATION_CLOSE");
            for(String key:new String[]{"task_id","worker_generation","scope_token","app_uid","app_pid","app_start_ticks","boot_id","identity_sha256","cleanup_nonce"})
                need(same(g.get(key),generationReceipt.get(key)),"NOTES_DRAINED_GENERATION_IDENTITY");
            need("hepta.worker-generation.cleanup.v1".equals(string(generationReceipt,"schema"))&&number(generationReceipt,"leader_pid")==number(request,"worker_pid")
                    &&number(generationReceipt,"pgid")==number(request,"worker_pid")&&number(generationReceipt,"term_attempts")==0&&number(generationReceipt,"kill_attempts")==0
                    &&generationReceipt.getJSONArray("targets").length()==0&&number(generationReceipt,"ended_monotonic_ns")/1000000L<=terminal,"NOTES_DRAINED_GENERATION_UNFORCED");
            yes(generationReceipt,"cleanup_known","scan_complete","pidfd_supported");
            for(String key:new String[]{"remaining_owned_count","unknown_count","escaped_generation_count"})need(number(generationReceipt,key)==0,"NOTES_DRAINED_GENERATION_UNKNOWN");
            StringBuilder identity=new StringBuilder("hepta.worker-generation.v1\n");
            for(String key:new String[]{"task_id","worker_generation","scope_token","app_uid","app_pid","app_start_ticks","leader_pid","leader_start_ticks","pgid","boot_id"})
                identity.append(key).append('=').append(generationReceipt.get(key)).append('\n');
            need(Arrays.equals(identity.toString().getBytes(StandardCharsets.US_ASCII),originals.get("generation_identity")),"NOTES_DRAINED_IDENTITY_BYTES");
            // The App client additionally replays the unchanged WorkerGenerationProof
            // validator against these exact raw bytes before creating an opaque receipt.
        }
        private int notesCustody(JSONObject c,boolean released)throws Exception{
            boolean concurrent="hepta.public-personal-notes-cleanup.v2".equals(string(c,"schema"));
            need((concurrent||"hepta.public-personal-notes-cleanup.v1".equals(string(c,"schema")))&&generation.equals(string(c,"generation"))
                    &&publicScope.sha256.equals(string(c,"scope_sha256"))&&PACKAGE.equals(string(c,"package"))
                    &&(number(c,"display_id")==displayId||(prelaunchCreateFailure&&number(c,"display_id")==-1)),
                    "NOTES_CUSTODY_BINDING");
            long uid=number(c,"target_uid");need(uid>=10000&&uid<90000,"NOTES_TARGET_UID");
            yes(c,"create_attempted");no(c,"arbitrary_task_removal_used","force_stop_used","caller_flag_is_cleanup_proof");
            if(released){
                need(releasedTerminal&&(postModelDrained||releasedBeforeModel)&&!prelaunchCreateFailure&&concurrent,"NOTES_RELEASED_CUSTODY_KIND");
                yes(c,"cleanup_known","pre_release_tasks_verified","release_api_entered","release_api_returned",
                        "display_absence_verified","live_tasks_absent","all_recents_sections_absent","prior_hidden_history_preserved");
                no(c,"identity_unknown","custodian_retained","no_display_create_attempted");
                need(number(c,"absence_reads")>=2&&string(c,"failure").isEmpty()
                        &&ProfileIdentity.hash(string(c,"initial_recents_sha256"))
                        &&ProfileIdentity.hash(string(c,"pre_release_recents_sha256"))
                        &&ProfileIdentity.hash(string(c,"final_recents_sha256")),"NOTES_RELEASED_CUSTODY_INCOMPLETE");
            }else no(c,"cleanup_known");
            if(prelaunchCreateFailure){
                // An uninitialised custodian has no observed task to retire.
                // Recovery still requires independent current absence of the
                // journal's exact display, creator and every Notes task/history.
                need(concurrent&&c.getJSONArray("actual_observed_tasks").length()==0
                        &&number(c,"pending_owned_reads")==0&&number(c,"absence_reads")==0
                        &&ProfileIdentity.hash(string(c,"initial_recents_sha256"))
                        &&string(c,"pre_release_recents_sha256").isEmpty()&&string(c,"final_recents_sha256").isEmpty(),
                        "NOTES_PRELAUNCH_CUSTODY");
                no(c,"launch_dispatched","pre_release_tasks_verified","release_api_entered","release_api_returned",
                        "display_absence_verified","live_tasks_absent","all_recents_sections_absent","prior_hidden_history_preserved","no_display_create_attempted");
                yes(c,"identity_unknown","custodian_retained");
            }else if(releasedBeforeModel&&!released){
                need(concurrent&&c.getJSONArray("actual_observed_tasks").length()==0&&number(c,"pending_owned_reads")==0&&number(c,"absence_reads")==0
                        &&ProfileIdentity.hash(string(c,"initial_recents_sha256"))&&string(c,"pre_release_recents_sha256").isEmpty()
                        &&string(c,"final_recents_sha256").isEmpty()&&string(c,"failure").isEmpty(),"NOTES_CREATED_CUSTODY");
                yes(c,"custodian_retained");
                no(c,"launch_dispatched","identity_unknown","pre_release_tasks_verified","release_api_entered","release_api_returned",
                        "display_absence_verified","live_tasks_absent","all_recents_sections_absent","prior_hidden_history_preserved","no_display_create_attempted");
            }else yes(c,"launch_dispatched");
            if(concurrent){
                need("nonphysical_and_unresolved_recents".equals(string(c,"history_preservation_scope"))
                        &&"pre_release_to_absence".equals(string(c,"history_preservation_interval"))
                        &&"initial_to_absence".equals(string(c,"hidden_history_preservation_interval"))
                        &&Boolean.FALSE.equals(c.get("physical_history_frozen"))
                        &&c.get("unrelated_physical_history_changes_observed") instanceof Boolean
                        &&c.get("recents_presentation_changes_observed") instanceof Boolean
                        &&c.get("prior_hidden_history_preserved") instanceof Boolean,"NOTES_CUSTODY_HISTORY_SCOPE");
                if(released)yes(c,"nonphysical_history_preserved","nonphysical_hidden_history_preserved");
                else no(c,"nonphysical_history_preserved","nonphysical_hidden_history_preserved");
            }
            return (int)uid;
        }
        private void requireSelection(JSONObject s)throws Exception{
            need("background".equals(string(s,"mode"))&&PACKAGE.equals(string(s,"bootstrap_package"))&&s.getJSONArray("allowed_packages").length()==1
                    &&PACKAGE.equals(s.getJSONArray("allowed_packages").get(0))&&"public_own_group_personal_no_credentials_v1".equals(string(s,"display_scope_mode"))
                    &&"immutable_start_selection".equals(string(s,"display_scope_mode_source"))&&!s.has("profile_target_wire")&&!s.has("profile_target_sha256"),"NOTES_SELECTION");
            no(s,"bootstrap_model_issued","main_display_fallback","home_allowed","display_scope_mode_grants_authority");
        }
        private void bindBackground(JSONObject b)throws Exception{
            JSONObject j=object(originals.get("journal"));
            for(String key:new String[]{"schema","task_id","app_uid","owner_sha256","generation","socket","display_name","display_id",
                    "created_elapsed_ms","expires_elapsed_ms","boot_count","selection","owned_task_retirement_required","public_own_group_scope_wire",
                    "public_own_group_scope_sha256","public_own_group_experimental","public_scope_serialization_grants_authority","personal_notes_retirement_required"})
                need(same(j.get(key),b.get(key)),"NOTES_ORIGINAL_IDENTITY");
            yes(b,"spawn_attempted");no(b,"bootstrap_model_issued");
            if(prelaunchCreateFailure||releasedBeforeModel)no(b,"bootstrap_dispatched");else yes(b,"bootstrap_dispatched");
        }
        private void requireBroker(JSONObject b)throws Exception{
            need("hepta.background-broker-output.v1".equals(string(b,"schema"))&&taskId.equals(string(b,"task_id"))
                    &&generation.equals(string(b,"generation"))&&number(b,"app_uid")==ownerUid&&number(b,"app_pid")>0
                    &&"owned_java_process_merged_stream".equals(string(b,"process_binding"))&&number(b,"process_reference")>0
                    &&ProfileIdentity.hash(string(b,"command_sha256"))&&number(b,"started_elapsed_ms")>=created
                    &&number(b,"started_elapsed_ms")<=started&&number(b,"output_limit_bytes")==65536
                    &&("background-broker-"+generation+".bin").equals(string(b,"output_file"))
                    &&("background-broker-"+generation+".json").equals(string(b,"receipt_file"))
                    &&b.get("eof_seen") instanceof Boolean&&Boolean.FALSE.equals(b.get("read_failed"))&&Boolean.FALSE.equals(b.get("overflow"))
                    &&Boolean.TRUE.equals(b.get("merged_stdout_stderr"))&&Boolean.FALSE.equals(b.get("model_input"))
                    &&Boolean.FALSE.equals(b.get("release_evidence")),"NOTES_RECOVERY_BROKER_TRANSPORT");
        }
        private void requireBootstrapPrefix(JSONObject early,JSONObject complete,byte[] output)throws Exception{
            // The bootstrap finally block can precede owned-stream EOF. Its exact
            // prefix is historical evidence; only the final owned Process record proves exit.
            for(String key:new String[]{"schema","task_id","generation","app_uid","app_pid","process_binding","process_reference",
                    "command_sha256","started_elapsed_ms","output_file","receipt_file","output_limit_bytes","overflow","read_failed",
                    "merged_stdout_stderr","model_input","release_evidence"})
                need(same(early.get(key),complete.get(key)),"NOTES_RECOVERY_BOOTSTRAP_PRODUCER_CHANGED");
            need(early.get("eof_seen") instanceof Boolean&&early.get("persisted") instanceof Boolean,
                    "NOTES_RECOVERY_BOOTSTRAP_TRANSPORT_TYPE");
            long size=number(early,"stored_bytes");
            need(size>=0&&size<=output.length&&number(early,"observed_bytes")==size
                    &&ProfileIdentity.sha(Arrays.copyOf(output,(int)size)).equals(string(early,"stored_sha256")),
                    "NOTES_RECOVERY_BOOTSTRAP_PREFIX_CHANGED");
            if(Boolean.TRUE.equals(early.get("eof_seen")))need(size==output.length,"NOTES_RECOVERY_EARLY_EOF_DIFFERS");
            if(Boolean.TRUE.equals(early.get("persisted")))need(same(early,complete),"NOTES_RECOVERY_PERSISTED_RECEIPT_CHANGED");
        }
        public void requireFence(long now,int boot)throws IOException{
            need(boot==requestBoot&&boot==oldBoot&&now>=started&&now<deadline&&now>expires+EXPIRY_GRACE_MS,"NOTES_BOOT_TTL_OR_DEADLINE");
        }
        public byte[] original(String name)throws IOException{
            if("current_control".equals(name))return currentControl.clone();byte[] b=originals.get(name);need(b!=null,"NOTES_INPUT_NAME");return b.clone();
        }
        public String source(){return workflowAbortedAfterBack?WORKFLOW_ABORTED_SOURCE:initializationFailed?INITIALIZATION_SOURCE:cancelledAfterActions?CANCELLED_SOURCE:workflowReleasedReplyLost?WORKFLOW_RELEASED_REPLY_LOST_SOURCE:workflowForeignHistoryRetirement?WORKFLOW_FOREIGN_HISTORY_SOURCE:workflowPartialRetirement?WORKFLOW_PARTIAL_RETIREMENT_SOURCE:workflowRetirementRefused?WORKFLOW_RETIREMENT_REFUSED_SOURCE:SOURCE;}public String proofSchema(){return workflowAbortedAfterBack?WORKFLOW_ABORTED_PROOF_SCHEMA:initializationFailed?INITIALIZATION_PROOF_SCHEMA:cancelledAfterActions?CANCELLED_PROOF_SCHEMA:workflowReleasedReplyLost?WORKFLOW_RELEASED_REPLY_LOST_PROOF_SCHEMA:workflowForeignHistoryRetirement?WORKFLOW_FOREIGN_HISTORY_PROOF_SCHEMA:workflowPartialRetirement?WORKFLOW_PARTIAL_RETIREMENT_PROOF_SCHEMA:workflowRetirementRefused?WORKFLOW_RETIREMENT_REFUSED_PROOF_SCHEMA:SCHEMA;}
        public JSONObject recordedOwnedIdentity()throws Exception{
            JSONObject value=new JSONObject().put("display_id",displayId).put("display_name",displayName)
                .put("task_ids",new JSONArray(recordedTaskIds)).put("user_id",0).put("full_uid",targetUid).put("package",PACKAGE)
                .put("recorded_task_ids_complete",false).put("absence_requires_all_notes_tasks",true).put("serialized_identity_grants_authority",false);
            if(cancelledAfterActions)value.put("historical_model_exit_code",143).put("historical_model_receipt_valid",false)
                    .put("historical_business_success",false).put("historical_background_cleanup_known",false)
                    .put("model_cancellation_kind","expected_cancelled_exit_143_with_observed_sdk_cleanup");
            if(workflowRetirementRefused)value.put("historical_model_exit_code",0).put("historical_model_receipt_valid",true)
                    .put("historical_notes_workflow_verified",true).put("historical_business_success",false)
                    .put("historical_background_cleanup_known",false).put("historical_retirement_release_entered",false)
                    .put("historical_retirement_failure","NOTES_RETIREMENT_TOP_IDENTITY");
            if(workflowPartialRetirement){
                JSONObject retirement=object(originals.get("cleanup")).getJSONObject("last_broker_response")
                        .getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement");
                value.put("historical_model_exit_code",0).put("historical_model_receipt_valid",true)
                        .put("historical_notes_workflow_verified",true).put("historical_business_success",false)
                        .put("historical_background_cleanup_known",false).put("historical_retirement_release_entered",false)
                        .put("historical_pre_release_tasks_verified",true).put("historical_partial_task_retirement_observed",true)
                        .put("historical_attempted_task_ids",retirement.getJSONArray("attempted_task_ids"))
                        .put("historical_returned_task_ids",retirement.getJSONArray("returned_task_ids"))
                        .put("historical_retirement_failure","NOTES_RETIREMENT_GLOBAL_CHANGED_DURING_READ");
            }
            if(workflowForeignHistoryRetirement){
                JSONObject retirement=object(originals.get("cleanup")).getJSONObject("last_broker_response")
                        .getJSONObject("personal_notes_cleanup").getJSONObject("token_retirement");
                value.put("historical_model_exit_code",0).put("historical_model_receipt_valid",true)
                        .put("historical_notes_workflow_verified",true).put("historical_business_success",false)
                        .put("historical_background_cleanup_known",false).put("historical_retirement_release_entered",false)
                        .put("historical_pre_release_tasks_verified",true).put("historical_partial_task_retirement_observed",true)
                        .put("historical_attempted_task_ids",retirement.getJSONArray("attempted_task_ids"))
                        .put("historical_returned_task_ids",retirement.getJSONArray("returned_task_ids"))
                        .put("historical_retirement_failure","NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED");
            }
            if(workflowAbortedAfterBack)value.put("historical_model_exit_code",0).put("historical_model_receipt_valid",true)
                    .put("historical_notes_workflow_verified",false).put("historical_business_success",false)
                    .put("historical_background_cleanup_known",false).put("historical_broker_terminal_state","CLEANUP_UNKNOWN")
                    .put("historical_broker_eof_observed",false).put("historical_broker_process_exit_observed",false)
                    .put("historical_broker_exit_code",JSONObject.NULL).put("historical_custodian_retained",true)
                    .put("historical_only_back_child_drained",true).put("historical_list_reopen_verified",false)
                    .put("historical_output_is_cleanup_proof",false);
            if(workflowReleasedReplyLost)value.put("historical_model_exit_code",0).put("historical_model_receipt_valid",true)
                    .put("historical_notes_workflow_verified",true).put("historical_business_success",false)
                    .put("historical_background_cleanup_known",false).put("historical_broker_terminal_state","RELEASED")
                    .put("historical_broker_process_exit_observed",false).put("historical_broker_exit_code",JSONObject.NULL)
                    .put("historical_app_close_response_observed",false).put("historical_last_response_state","ACTIVE")
                    .put("historical_output_is_cleanup_proof",false).put("historical_cleanup_error","后台响应提前结束");
            if(initializationFailed)value.put("historical_broker_terminal_state","RELEASED").put("historical_broker_exit_code",70)
                    .put("historical_background_cleanup_known",false).put("historical_output_is_cleanup_proof",false)
                    .put("app_bootstrap_dispatched",false).put("model_process_started",false);
            if(releasedBeforeModel)value.put("historical_broker_terminal_state","RELEASED").put("broker_launch_dispatched",true)
                    .put("app_observed_launch_response",false).put("model_process_started",false);
            return value;
        }
        public boolean targetHint(String text){
            if(text==null)return false;
            return java.util.regex.Pattern.compile("(?<![A-Za-z0-9_.])"+java.util.regex.Pattern.quote(PACKAGE)+"(?=$|[^A-Za-z0-9_.])").matcher(text).find()
                    ||java.util.regex.Pattern.compile("(?<![0-9])"+targetUid+"(?![0-9])").matcher(text).find()
                    ||java.util.regex.Pattern.compile("(?<![A-Za-z0-9])u0a"+(targetUid-10000)+"(?=$|[^A-Za-z0-9])").matcher(text).find();
        }
        public JSONObject controller()throws Exception{return object(controllerText.getBytes(StandardCharsets.UTF_8));}
        public JSONObject inputHashes()throws Exception{JSONObject out=new JSONObject();for(String name:originals.keySet()){byte[] b=originals.get(name);
            out.put(name,new JSONObject().put("bytes",b.length).put("sha256",ProfileIdentity.sha(b)));}return out;}
        public String wire()throws Exception{
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF(workflowAbortedAfterBack?WORKFLOW_ABORTED_REQUEST_SCHEMA:initializationFailed?(interruptedLostLaunch?INITIALIZATION_STARTUP_SCHEMA:INITIALIZATION_REQUEST_SCHEMA):cancelledAfterActions?CANCELLED_REQUEST_SCHEMA:interruptedLostLaunch?LOST_LAUNCH_STARTUP_SCHEMA:releasedBeforeModel?RELEASED_BEFORE_MODEL_SCHEMA:workflowReleasedReplyLost?WORKFLOW_RELEASED_REPLY_LOST_REQUEST_SCHEMA:workflowForeignHistoryRetirement?WORKFLOW_FOREIGN_HISTORY_REQUEST_SCHEMA:workflowPartialRetirement?WORKFLOW_PARTIAL_RETIREMENT_REQUEST_SCHEMA:workflowRetirementRefused?WORKFLOW_RETIREMENT_REFUSED_REQUEST_SCHEMA:workflowCloseFailed?WORKFLOW_CLOSE_REQUEST_SCHEMA:postModelDrained?DRAINED_REQUEST_SCHEMA:REQUEST_SCHEMA);out.writeInt(ownerUid);out.writeUTF(requestId);out.writeLong(started);out.writeInt(requestBoot);
            put(out,controllerText.getBytes(StandardCharsets.UTF_8));put(out,currentControl);
            if(cancelledAfterActions||workflowAbortedAfterBack){out.writeInt(originals.size());for(String name:originals.keySet()){out.writeUTF(name);put(out,originals.get(name));}}
            else for(String name:originals.keySet())put(out,originals.get(name));out.flush();
            need(bytes.size()<=MAX_BUNDLE+MAX_ORIGINAL+8192,"NOTES_WIRE_BOUND");ByteArrayOutputStream compressed=new ByteArrayOutputStream();
            try(GZIPOutputStream zip=new GZIPOutputStream(compressed)){zip.write(bytes.toByteArray());}
            String value=Base64.getEncoder().encodeToString(compressed.toByteArray());need(value.length()<=MAX_WIRE,"NOTES_WIRE_BOUND");return value;
        }
    }
    /** Complete JSON values are retained; this removes indentation only. The App
     * separately binds and archives each original byte sequence through the manifest. */
    public static byte[] compactCancelledAction(byte[] raw)throws Exception{
        need(raw!=null&&raw.length>0&&raw.length<=MAX_ORIGINAL,"NOTES_CANCELLED_ACTION_BOUND");
        return object(raw).toString().getBytes(StandardCharsets.UTF_8);
    }
    public static String cancelledStepName(int step,String suffix)throws IOException{
        need(step>=1&&step<=24&&Arrays.asList("action","model-0","before","after","budget-0").contains(suffix),"NOTES_CANCELLED_STEP_NAME");
        return String.format(java.util.Locale.ROOT,"step-%02d-%s.json",step,suffix);
    }
    private static String cancelledKey(int step,String suffix){return String.format(java.util.Locale.ROOT,"cancelled_%s_%02d",suffix,step);}
    private static String[] cancelledNames(JSONObject history)throws Exception{
        keys(history,"schema","completed_actions","startup_archive","task_files","request_receipts");
        need("hepta.personal-notes-cancelled-history.v1".equals(string(history,"schema"))&&history.get("startup_archive") instanceof Boolean,"NOTES_CANCELLED_HISTORY_SCHEMA");
        long count=number(history,"completed_actions");need(count>=1&&count<=23,"NOTES_CANCELLED_ACTION_COUNT");
        java.util.List<String> names=new java.util.ArrayList<String>(Arrays.asList(CANCELLED_BASE_INPUTS));
        for(int i=1;i<=count;i++){names.add(cancelledKey(i,"action"));names.add(cancelledKey(i,"model"));}
        if(Boolean.TRUE.equals(history.get("startup_archive"))){names.add("origin_control");names.add("interruption_latch");}
        return names.toArray(new String[0]);
    }
    public static Map<String,byte[]> packCancelledInputs(Map<String,byte[]> raw,JSONObject history)throws Exception{
        need(raw!=null,"NOTES_CANCELLED_INPUTS_MISSING");Map<String,byte[]> result=new LinkedHashMap<String,byte[]>();
        for(String name:cancelledNames(history)){
            byte[] bytes="cancelled_history".equals(name)?canonical(history).getBytes(StandardCharsets.UTF_8):raw.get(name);
            need(bytes!=null,"NOTES_CANCELLED_INPUT_MISSING");
            result.put(name,name.startsWith("cancelled_action_")?compactCancelledAction(bytes):bytes.clone());
        }
        return result;
    }


    private static String[] abortedNames(boolean startup){
        java.util.List<String> names=new java.util.ArrayList<String>(Arrays.asList(WORKFLOW_ABORTED_INPUTS));
        if(startup){names.add("origin_control");names.add("interruption_latch");}
        return names.toArray(new String[0]);
    }
    /** No semantic value is compacted or synthesised. All selected files remain
     * the original bytes; the separate manifest binds the full 29-file archive. */
    public static Map<String,byte[]> packAbortedInputs(Map<String,byte[]> raw,JSONObject history)throws Exception{
        need(raw!=null&&history!=null,"NOTES_ABORTED_INPUTS_MISSING");
        keys(history,"schema","startup_archive","task_files");
        need("hepta.personal-notes-aborted-after-back-history.v1".equals(string(history,"schema"))
                &&history.get("startup_archive") instanceof Boolean,"NOTES_ABORTED_HISTORY_SCHEMA");
        Map<String,byte[]> result=new LinkedHashMap<String,byte[]>();
        for(String name:abortedNames(Boolean.TRUE.equals(history.get("startup_archive")))){
            byte[] bytes="aborted_history".equals(name)?canonical(history).getBytes(StandardCharsets.UTF_8):raw.get(name);
            need(bytes!=null,"NOTES_ABORTED_INPUT_MISSING");result.put(name,bytes.clone());
        }
        return result;
    }

    public static String lostLaunchOriginArchive(JSONObject current)throws Exception{
        need("interrupted".equals(string(current,"status")),"NOTES_STARTUP_STATUS");
        JSONObject reason=current.getJSONObject("startup_recovery");String sha=string(reason,"previous_session_sha256");
        need(ProfileIdentity.hash(sha)&&"blocked".equals(string(reason,"previous_status")),"NOTES_STARTUP_PREDECESSOR");
        JSONArray rows=reason.getJSONArray("preserved_records");need(rows.length()==1,"NOTES_STARTUP_ARCHIVE_SET");
        JSONObject row=rows.getJSONObject(0);String relative="session-recovery/control-session.json."+sha+".json",path=string(row,"path");
        need("control-session.json".equals(string(row,"original_name"))&&sha.equals(string(row,"sha256"))
                &&(("/data/data/org.trillionnium.hepta.local/files/"+relative).equals(path)||("/data/user/0/org.trillionnium.hepta.local/files/"+relative).equals(path)),
                "NOTES_STARTUP_ARCHIVE_REFERENCE");return relative;
    }
    public static Request request(Map<String,byte[]> originals,byte[] currentControl,JSONObject currentController,int uid,String id,long now,int boot)throws Exception{
        return new Request(originals,currentControl,currentController,uid,id,now,boot);
    }
    public static Request fromWire(String wire)throws Exception{
        need(wire!=null&&wire.length()>0&&wire.length()<=MAX_WIRE,"NOTES_WIRE_BOUND");byte[] zipped=Base64.getDecoder().decode(wire);
        need(Base64.getEncoder().encodeToString(zipped).equals(wire),"NOTES_WIRE_NONCANONICAL");
        ByteArrayOutputStream decoded=new ByteArrayOutputStream();try(GZIPInputStream in=new GZIPInputStream(new ByteArrayInputStream(zipped))){
            byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1){need(decoded.size()+n<=MAX_BUNDLE+MAX_ORIGINAL+8192,"NOTES_WIRE_BOUND");decoded.write(b,0,n);}}
        DataInputStream in=new DataInputStream(new ByteArrayInputStream(decoded.toByteArray()));String schema=in.readUTF();
        need(WORKFLOW_ABORTED_REQUEST_SCHEMA.equals(schema)||INITIALIZATION_REQUEST_SCHEMA.equals(schema)||INITIALIZATION_STARTUP_SCHEMA.equals(schema)||CANCELLED_REQUEST_SCHEMA.equals(schema)||REQUEST_SCHEMA.equals(schema)||DRAINED_REQUEST_SCHEMA.equals(schema)||WORKFLOW_CLOSE_REQUEST_SCHEMA.equals(schema)||WORKFLOW_RETIREMENT_REFUSED_REQUEST_SCHEMA.equals(schema)||WORKFLOW_PARTIAL_RETIREMENT_REQUEST_SCHEMA.equals(schema)||WORKFLOW_FOREIGN_HISTORY_REQUEST_SCHEMA.equals(schema)||WORKFLOW_RELEASED_REPLY_LOST_REQUEST_SCHEMA.equals(schema)||RELEASED_BEFORE_MODEL_SCHEMA.equals(schema)||LOST_LAUNCH_STARTUP_SCHEMA.equals(schema),"NOTES_REQUEST_SCHEMA");
        int uid=in.readInt();String id=in.readUTF();long now=in.readLong();int boot=in.readInt();JSONObject controller=object(take(in,8192));byte[] control=take(in,MAX_ORIGINAL);
        Map<String,byte[]> inputs=new LinkedHashMap<String,byte[]>();
        if(CANCELLED_REQUEST_SCHEMA.equals(schema)||WORKFLOW_ABORTED_REQUEST_SCHEMA.equals(schema)){
            int count=in.readInt();need(WORKFLOW_ABORTED_REQUEST_SCHEMA.equals(schema)?count==24||count==26:count>=14&&count<=60,"NOTES_CANCELLED_INPUT_COUNT");
            for(int i=0;i<count;i++){String name=in.readUTF();need(name.matches("[a-z_0-9]{1,48}")&&inputs.put(name,take(in,MAX_ORIGINAL))==null,"NOTES_CANCELLED_INPUT_NAME");}
        }else for(String name:(LOST_LAUNCH_STARTUP_SCHEMA.equals(schema)||INITIALIZATION_STARTUP_SCHEMA.equals(schema))?LOST_LAUNCH_STARTUP_INPUTS:(RELEASED_BEFORE_MODEL_SCHEMA.equals(schema)||INITIALIZATION_REQUEST_SCHEMA.equals(schema))?RELEASED_BEFORE_MODEL_INPUTS:(WORKFLOW_CLOSE_REQUEST_SCHEMA.equals(schema)||WORKFLOW_RETIREMENT_REFUSED_REQUEST_SCHEMA.equals(schema)||WORKFLOW_PARTIAL_RETIREMENT_REQUEST_SCHEMA.equals(schema)||WORKFLOW_FOREIGN_HISTORY_REQUEST_SCHEMA.equals(schema)||WORKFLOW_RELEASED_REPLY_LOST_REQUEST_SCHEMA.equals(schema))?WORKFLOW_CLOSE_INPUTS:DRAINED_REQUEST_SCHEMA.equals(schema)?DRAINED_INPUTS:INPUTS)inputs.put(name,take(in,MAX_ORIGINAL));need(in.read()==-1,"NOTES_WIRE_TRAILING");
        Request r=new Request(inputs,control,controller,uid,id,now,boot);need(r.wire().equals(wire),"NOTES_WIRE_NONCANONICAL");return r;
    }
    public static JSONObject validate(JSONObject value,Request r,long now,int boot)throws Exception{
        need(r!=null,"NOTES_REQUEST_MISSING");r.requireFence(now,boot);
        keys(value,"schema","source","request_id","task_id","generation","owner_uid","owner_sha256","journal_sha256","originals_sha256","original_inputs",
                "public_scope_wire","public_scope_sha256","display_name","recorded_owned_identity","current_control_sha256","current_controller",
                "old_boot_count","current_boot_count","lease_expires_elapsed_ms","request_started_elapsed_ms","started_elapsed_ms","finished_elapsed_ms","deadline_elapsed_ms",
                "before","after","current_absence_verified","recovery_interval_physical_unchanged","foreign_history_preserved","cleanup_known",
                "automatic_resume","broker_release_response","historical_broker_release_observed","business_success","rewrites_original_task_result");
        need(r.proofSchema().equals(string(value,"schema"))&&r.source().equals(string(value,"source"))&&r.requestId.equals(string(value,"request_id"))
                &&r.taskId.equals(string(value,"task_id"))&&r.generation.equals(string(value,"generation"))&&number(value,"owner_uid")==r.ownerUid
                &&r.ownerSha256.equals(string(value,"owner_sha256"))&&r.journalSha256.equals(string(value,"journal_sha256"))
                &&r.originalsSha256.equals(string(value,"originals_sha256"))&&same(r.inputHashes(),value.getJSONObject("original_inputs"))
                &&r.publicScope.wire().equals(string(value,"public_scope_wire"))&&r.publicScope.sha256.equals(string(value,"public_scope_sha256"))
                &&r.displayName.equals(string(value,"display_name"))&&same(r.recordedOwnedIdentity(),value.getJSONObject("recorded_owned_identity"))
                &&same(r.controller(),value.getJSONObject("current_controller"))&&r.currentControlSha256.equals(string(value,"current_control_sha256")),"NOTES_PROOF_BINDING");
        need(number(value,"old_boot_count")==r.oldBoot&&number(value,"current_boot_count")==boot&&number(value,"lease_expires_elapsed_ms")==r.expires
                &&number(value,"request_started_elapsed_ms")==r.started&&number(value,"deadline_elapsed_ms")==r.deadline,"NOTES_PROOF_CLOCK");
        long begin=number(value,"started_elapsed_ms"),end=number(value,"finished_elapsed_ms");
        need(begin>=r.started&&end>=begin&&end<=now&&end<r.deadline,"NOTES_PROOF_CLOCK");
        yes(value,"current_absence_verified","recovery_interval_physical_unchanged","foreign_history_preserved","cleanup_known");
        no(value,"automatic_resume","broker_release_response","business_success","rewrites_original_task_result");
        need(Boolean.valueOf(r.releasedBeforeModel).equals(value.get("historical_broker_release_observed")),"NOTES_HISTORICAL_TERMINAL_SOURCE");
        JSONObject first=value.getJSONObject("before"),last=value.getJSONObject("after");sample(first,r,begin,end);sample(last,r,begin,end);
        need(number(first,"finished_elapsed_ms")<=number(last,"started_elapsed_ms")&&same(first.getJSONObject("physical"),last.getJSONObject("physical"))
                &&same(first.getJSONObject("displays"),last.getJSONObject("displays"))&&same(first.getJSONObject("live"),last.getJSONObject("live"))
                &&same(first.getJSONObject("target_installation"),last.getJSONObject("target_installation"))
                &&number(first.getJSONObject("process"),"self_pid")==number(last.getJSONObject("process"),"self_pid")
                &&number(first.getJSONObject("process"),"self_start_ticks")==number(last.getJSONObject("process"),"self_start_ticks"),"NOTES_DOUBLE_SAMPLE_CHANGED");
        PublicPersonalNotesHistory.requireSameEvidence(first.getJSONObject("recents"),last.getJSONObject("recents"),r,(end-begin)/1000+2);
        return object(value.toString().getBytes(StandardCharsets.UTF_8));
    }
    private static void sample(JSONObject s,Request r,long begin,long end)throws Exception{
        keys(s,"started_elapsed_ms","finished_elapsed_ms","process","live","recents","displays","physical","target_installation");
        long a=number(s,"started_elapsed_ms"),b=number(s,"finished_elapsed_ms");need(a>=begin&&b>=a&&b<=end,"NOTES_SAMPLE_CLOCK");
        JSONObject p=s.getJSONObject("process");keys(p,"complete","old_creator_absent","started_elapsed_ms","finished_elapsed_ms","self_pid","self_start_ticks","process_count","inspected_count","inventory_sha256");
        yes(p,"complete","old_creator_absent");
        need(number(p,"started_elapsed_ms")>=a&&number(p,"finished_elapsed_ms")>=number(p,"started_elapsed_ms")&&number(p,"finished_elapsed_ms")<=b
                &&number(p,"self_pid")>0&&number(p,"self_start_ticks")>0&&number(p,"process_count")>0&&number(p,"process_count")<=65536
                &&number(p,"inspected_count")>0&&number(p,"inspected_count")<=number(p,"process_count")&&ProfileIdentity.hash(string(p,"inventory_sha256")),"NOTES_PROCESS_SAMPLE");
        requireLive(s.getJSONObject("live"),r);requireDisplays(s.getJSONObject("displays"),r);
        PublicPersonalNotesHistory.requireSameEvidence(s.getJSONObject("recents"),s.getJSONObject("recents"),r,0);
        JSONObject physical=s.getJSONObject("physical");keys(physical,"0","1");
        need(ProfileIdentity.hash(string(physical,"0"))&&ProfileIdentity.hash(string(physical,"1")),"NOTES_PHYSICAL_SAMPLE");
        JSONObject target=s.getJSONObject("target_installation");keys(target,"package","uid","source_path","enabled");
        need(PACKAGE.equals(string(target,"package"))&&number(target,"uid")==r.targetUid
                &&string(target,"source_path").startsWith("/")&&string(target,"source_path").length()<=4096,"NOTES_TARGET_INSTALLATION");yes(target,"enabled");
    }
    static void requireLive(JSONObject value,Request r)throws Exception{
        keys(value,"complete","roots","leaves");yes(value,"complete");JSONArray roots=value.getJSONArray("roots"),leaves=value.getJSONArray("leaves");
        need(roots.length()>0&&roots.length()<=ProfileTaskPolicy.MAX_ROOTS&&leaves.length()<=ProfileTaskPolicy.MAX_LEAVES,"NOTES_LIVE_BOUND");
        Map<Integer,JSONObject> rootIds=new LinkedHashMap<Integer,JSONObject>();TreeSet<Integer> leafIds=new TreeSet<Integer>();
        for(int i=0;i<roots.length();i++){JSONObject row=roots.getJSONObject(i);keys(row,"id","display","user","activities","visible","base","top");
            int id=integer(row,"id");need(id>0&&rootIds.put(id,row)==null&&!r.recordedTaskIds.contains(id)&&integer(row,"display")>=0
                    &&integer(row,"display")!=r.displayId&&integer(row,"user")>=0&&integer(row,"activities")>=0&&integer(row,"activities")<=ProfileTaskPolicy.MAX_LEAVES
                    &&row.get("visible") instanceof Boolean,"NOTES_LIVE_ROOT_IDENTITY");
            for(String key:new String[]{"base","top"}){Object c=row.get(key);need(c==JSONObject.NULL||c instanceof String,"NOTES_LIVE_COMPONENT_TYPE");
                if(c instanceof String)need(((String)c).matches("[A-Za-z][A-Za-z0-9_.]*/[A-Za-z_.$][A-Za-z0-9_.$]*")&&!r.targetHint((String)c),"NOTES_LIVE_TARGET_PRESENT");}
            need(integer(row,"activities")==0||row.get("base")!=JSONObject.NULL||row.get("top")!=JSONObject.NULL,"NOTES_LIVE_ACTIVE_IDENTITY_UNKNOWN");
        }
        for(int i=0;i<leaves.length();i++){JSONObject row=leaves.getJSONObject(i);keys(row,"id","parent","display","user","name");
            int id=integer(row,"id"),parent=integer(row,"parent");JSONObject root=rootIds.get(parent);
            need(id>0&&leafIds.add(id)&&root!=null&&!r.recordedTaskIds.contains(id)&&!r.recordedTaskIds.contains(parent)
                    &&integer(row,"display")>=0&&integer(row,"display")!=r.displayId&&integer(row,"display")==integer(root,"display")
                    &&integer(row,"user")>=0&&!r.targetHint(string(row,"name")),"NOTES_LIVE_LEAF_IDENTITY");
            need(!"unknown".equals(string(row,"name"))||integer(root,"activities")==0,"NOTES_LIVE_LEAF_UNKNOWN");
        }
    }
    static void requireDisplays(JSONObject value,Request r)throws Exception{
        keys(value,"complete","rows");yes(value,"complete");JSONArray rows=value.getJSONArray("rows");
        need(rows.length()>=2&&rows.length()<=256,"NOTES_DISPLAY_CENSUS_BOUND");TreeSet<Integer> ids=new TreeSet<Integer>();TreeSet<String> unique=new TreeSet<String>();
        for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);keys(row,"id","name","unique_id","flags","state");
            int id=integer(row,"id");String name=string(row,"name"),u=string(row,"unique_id");
            need(id>=0&&ids.add(id)&&id!=r.displayId&&!r.displayName.equals(name)&&!u.contains(r.displayName)
                    &&name.length()>0&&name.length()<=512&&name.indexOf('\0')<0&&u.length()>0&&u.length()<=1024&&unique.add(u),"NOTES_DISPLAY_PRESENT_OR_UNKNOWN");
            integer(row,"flags");integer(row,"state");
        }
        need(ids.contains(0)&&ids.contains(1),"NOTES_PHYSICAL_DISPLAY_MISSING");
    }
    public static JSONObject object(byte[] b)throws Exception{return PublicProfileAbsenceRecovery.object(b);}
    public static String string(JSONObject o,String k)throws Exception{return PublicProfileAbsenceRecovery.string(o,k);}
    public static long number(JSONObject o,String k)throws Exception{return PublicProfileAbsenceRecovery.number(o,k);}
    public static boolean same(Object a,Object b)throws Exception{return PublicProfileAbsenceRecovery.same(a,b);}
    public static String canonical(Object a)throws Exception{return PublicProfileAbsenceRecovery.canonical(a);}
    public static void need(boolean b,String code)throws IOException{if(!b)throw new IOException(code);}
    private static int integer(JSONObject o,String k)throws Exception{long n=number(o,k);need(n>=Integer.MIN_VALUE&&n<=Integer.MAX_VALUE,"NOTES_INTEGER_RANGE");return (int)n;}
    private static long numberAt(JSONArray a,int i)throws Exception{Object v=a.get(i);need(v instanceof Integer||v instanceof Long,"NOTES_INTEGER_TYPE");return ((Number)v).longValue();}
    private static void keys(JSONObject o,String... names)throws Exception{ProfilePrelaunchRecovery.keys(o,names);}
    private static void yes(JSONObject o,String... names)throws Exception{for(String name:names)need(Boolean.TRUE.equals(o.get(name)),"NOTES_EXPECTED_TRUE");}
    private static void no(JSONObject o,String... names)throws Exception{for(String name:names)need(Boolean.FALSE.equals(o.get(name)),"NOTES_EXPECTED_FALSE");}
    private static JSONObject without(JSONObject in,String... names)throws Exception{JSONObject out=object(in.toString().getBytes(StandardCharsets.UTF_8));for(String name:names)out.remove(name);return out;}
    private static void put(DataOutputStream out,byte[] b)throws Exception{out.writeInt(b.length);out.write(b);}
    private static byte[] take(DataInputStream in,int max)throws Exception{int n=in.readInt();need(n>0&&n<=max,"NOTES_WIRE_LENGTH");byte[] b=new byte[n];in.readFully(b);return b;}
}
