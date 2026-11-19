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
 * task remains failed and the historical broker release remains unknown. These
 * serialized observations cannot create an App receipt or authorize any effect. */
public final class PublicPersonalNotesAbsenceRecovery {
    public static final String REQUEST_SCHEMA="hepta.personal-notes-absence-request.v1";
    public static final String SCHEMA="hepta.personal-notes-current-absence.v2";
    public static final String SOURCE="fresh_personal_notes_absence_with_preserved_failure";
    public static final String PACKAGE="com.motorola.stylus";
    public static final long LIMIT_MS=12000,TTL_MS=540000,EXPIRY_GRACE_MS=2000;
    public static final int MAX_ORIGINAL=131072,MAX_BUNDLE=262144,MAX_WIRE=65536,MAX_OUTPUT=524288,MAX_RECEIPT=786432;
    private static final String[] INPUTS={"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output"};
    private PublicPersonalNotesAbsenceRecovery(){}
    public static final class Request {
        public final int ownerUid,oldBoot,requestBoot,displayId,targetUid;
        public final long created,expires,started,deadline;
        public final String requestId,taskId,generation,ownerSha256,displayName,journalSha256,originalsSha256,currentControlSha256;
        public final PublicOwnGroupPolicy.Scope publicScope;
        public final java.util.Set<Integer> recordedTaskIds;
        private final Map<String,byte[]> originals;
        private final byte[] currentControl;
        private final String controllerText;
        private Request(Map<String,byte[]> input,byte[] control,JSONObject controller,int uid,String id,long now,int boot)throws Exception{
            need(uid>=10000&&uid<90000&&ProfileIdentity.uuid(id)&&now>=0&&boot>=0,"NOTES_REQUEST_IDENTITY");
            need(input!=null&&input.keySet().equals(new TreeSet<String>(Arrays.asList(INPUTS))),"NOTES_INPUT_SET");
            LinkedHashMap<String,byte[]> copy=new LinkedHashMap<String,byte[]>();int total=0;
            for(String name:INPUTS){byte[] raw=input.get(name);need(raw!=null&&raw.length>0&&raw.length<=MAX_ORIGINAL,"NOTES_INPUT_BOUND");
                total+=raw.length;need(total<=MAX_BUNDLE,"NOTES_INPUT_BOUND");copy.put(name,raw.clone());}
            originals=Collections.unmodifiableMap(copy);
            JSONObject j=object(originals.get("journal"));
            need("hepta.background-session.v1".equals(string(j,"schema"))&&number(j,"app_uid")==uid,"NOTES_JOURNAL_OWNER");
            taskId=string(j,"task_id");generation=string(j,"generation");ownerSha256=string(j,"owner_sha256");displayName=string(j,"display_name");
            need(taskId.matches("[0-9a-f]{32}")&&ProfileIdentity.uuid(generation)&&ProfileIdentity.hash(ownerSha256)
                    &&("hepta-bg-"+generation).equals(displayName)&&displayName.equals(string(j,"socket")),"NOTES_JOURNAL_IDENTITY");
            long d=number(j,"display_id");need(d>1&&d<=Integer.MAX_VALUE,"NOTES_RECORDED_DISPLAY");displayId=(int)d;
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
            need("hepta.local-owner.v1".equals(string(owner,"schema"))&&taskId.equals(string(owner,"task_id"))
                    &&ownerSha256.equals(string(owner,"instruction_utf8_sha256"))&&ownerSha256.equals(ProfileIdentity.sha(string(owner,"instruction")))
                    &&same(selection,owner.getJSONObject("background_request")),"NOTES_OWNER_BINDING");
            no(owner,"external_model","automatic_resume");bindBackground(bootstrap);bindBackground(cleanup);
            need("CLEANUP_UNKNOWN".equals(string(cleanup,"state")),"NOTES_ORIGINAL_FAILURE_PHASE");
            yes(cleanup,"retired","spawn_attempted","bootstrap_dispatched");no(cleanup,"cleanup_known","bootstrap_model_issued");
            Object exited=cleanup.get("broker_process_exit_observed"),exit=cleanup.get("broker_process_exit_code");
            need(exited instanceof Boolean&&((Boolean.FALSE.equals(exited)&&exit==JSONObject.NULL)
                    ||(Boolean.TRUE.equals(exited)&&(exit instanceof Integer||exit instanceof Long)&&((Number)exit).longValue()>=0&&((Number)exit).longValue()<=255)),"NOTES_OLD_EXIT_TYPE");
            JSONObject broker=object(originals.get("broker_receipt"));requireBroker(broker);
            need(same(broker,cleanup.getJSONObject("broker_output"))&&Boolean.TRUE.equals(broker.get("persisted")),"NOTES_BROKER_RECEIPT_CHANGED");
            byte[] output=originals.get("broker_output");
            need(number(broker,"stored_bytes")==output.length&&number(broker,"observed_bytes")==output.length
                    &&ProfileIdentity.sha(output).equals(string(broker,"stored_sha256")),"NOTES_BROKER_OUTPUT_BYTES");
            requireBootstrapPrefix(bootstrap.getJSONObject("broker_output"),broker,output);
            JSONObject terminal=object(output);
            need("hepta.background-broker-terminal.v1".equals(string(terminal,"schema"))&&generation.equals(string(terminal,"generation"))
                    &&number(terminal,"display_id")==displayId&&"CLEANUP_UNKNOWN".equals(string(terminal,"state"))
                    &&publicScope.sha256.equals(string(terminal,"display_scope_sha256")),"NOTES_BROKER_TERMINAL_BINDING");
            no(terminal,"release_confirmed");yes(terminal,"public_scope_admission_retired");
            JSONObject custody=terminal.getJSONObject("personal_notes_cleanup");
            targetUid=notesCustody(custody);
            JSONObject last=cleanup.getJSONObject("last_broker_response");
            need(generation.equals(string(last,"generation"))&&number(last,"display_id")==displayId
                    &&publicScope.sha256.equals(string(last,"display_scope_sha256"))&&number(last,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_VERSION,
                    "NOTES_LAST_RESPONSE_BINDING");
            need(notesCustody(last.getJSONObject("personal_notes_cleanup"))==targetUid,"NOTES_TARGET_UID_CHANGED");
            java.util.Set<Integer> ids=new TreeSet<Integer>();
            for(JSONObject c:new JSONObject[]{custody,last.getJSONObject("personal_notes_cleanup")}){
                JSONArray observed=c.getJSONArray("actual_observed_tasks");need(observed.length()<=32,"NOTES_RECORDED_TASK_BOUND");
                for(int i=0;i<observed.length();i++){JSONObject row=observed.getJSONObject(i);long task=number(row,"task_id");
                    need(task>0&&task<=Integer.MAX_VALUE&&number(row,"user_id")==0&&number(row,"actual_effective_uid")==targetUid
                            &&number(row,"display_id")==displayId&&number(row,"parent_id")<0
                            &&Boolean.FALSE.equals(row.get("serialized_token_grants_authority")),"NOTES_RECORDED_TASK_IDENTITY");ids.add((int)task);}
            }
            JSONObject location=last.getJSONObject("public_task_location"),launch=last.getJSONObject("task_launch_policy");
            need("hepta.public-own-group.task-location.v1".equals(string(location,"schema"))&&generation.equals(string(location,"generation"))
                    &&number(location,"display_id")==displayId&&number(location,"target_user_id")==0
                    &&Boolean.FALSE.equals(location.get("task_mutation_authority")),"NOTES_ORIGINAL_TASK_LOCATION");
            JSONArray located=location.getJSONArray("observed_owned_task_ids");need(located.length()>0&&located.length()<=32,"NOTES_RECORDED_TASK_BOUND");
            for(int i=0;i<located.length();i++){long task=numberAt(located,i);need(task>0&&task<=Integer.MAX_VALUE,"NOTES_RECORDED_TASK_ID");ids.add((int)task);}
            need("hepta.background-task-launch-policy.v1".equals(string(launch,"schema"))&&generation.equals(string(launch,"generation"))
                    &&number(launch,"display_id")==displayId&&PACKAGE.equals(string(launch,"package"))&&number(launch,"target_uid")==targetUid
                    &&string(launch,"component").startsWith(PACKAGE+"/")&&string(launch,"request_id").equals(string(last,"request_id"))
                    &&Boolean.TRUE.equals(launch.get("activity_info_rechecked_before_dispatch")),"NOTES_ORIGINAL_LAUNCH_TARGET");
            need(same(bootstrap.getJSONObject("last_broker_response"),last),"NOTES_ORIGINAL_RESPONSE_CHANGED");
            recordedTaskIds=Collections.unmodifiableSet(ids);
            need(taskId.equals(string(result,"task_id"))&&"blocked".equals(string(result,"status"))&&number(result,"steps")==0
                    &&Boolean.FALSE.equals(result.get("cleanup_known"))&&Boolean.FALSE.equals(result.get("completion_verified"))
                    &&Boolean.FALSE.equals(result.get("model_reported_success"))&&Boolean.FALSE.equals(result.get("external_model"))
                    &&Boolean.FALSE.equals(result.get("automatic_replay"))&&Boolean.FALSE.equals(result.get("controller_completion_requested"))
                    &&result.get("last_action_execution")==JSONObject.NULL&&result.get("final_observation_id")==JSONObject.NULL
                    &&result.get("model_done_status")==JSONObject.NULL&&result.get("completion_actor")==JSONObject.NULL,
                    "NOTES_RECOVERY_BUSINESS_OR_MODEL_DISPATCH");
            for(String key:new String[]{"observation_read_worker_pending_at_terminal","action_worker_pending_at_terminal","native_cancel_worker_pending_at_terminal"})
                need(Boolean.FALSE.equals(result.get(key)),"NOTES_RECOVERY_WORKER_PENDING");
            need(result.getJSONArray("submit_attempts").length()==0&&result.getJSONArray("fixed_intent_attempts").length()==0
                    &&(!result.has("profile_permission_preparation")||result.get("profile_permission_preparation")==JSONObject.NULL),"NOTES_RECOVERY_EFFECT_ATTEMPT");
            JSONObject nativeWork=result.getJSONObject("native_cancellation"),model=result.getJSONObject("model_session");
            need(taskId.equals(string(nativeWork,"task_id"))&&Boolean.TRUE.equals(nativeWork.get("native_cleanup_known"))
                    &&nativeWork.get("run_id")==JSONObject.NULL,"NOTES_RECOVERY_NATIVE_UNKNOWN");
            for(String key:new String[]{"request_reserved","executor_accepted","worker_started","signal_entered","submission_unknown"})
                need(Boolean.FALSE.equals(nativeWork.get(key)),"NOTES_RECOVERY_NATIVE_DISPATCH");
            need(taskId.equals(string(model,"task_id"))&&Boolean.FALSE.equals(model.get("process_started"))&&Boolean.FALSE.equals(model.get("process_exit_observed"))
                    &&model.get("worker_generation")==JSONObject.NULL&&model.get("exit_code")==JSONObject.NULL
                    &&Boolean.TRUE.equals(model.get("receipt_valid"))&&model.get("app_receipt_sha256")==JSONObject.NULL,
                    "NOTES_RECOVERY_MODEL_SESSION");
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
                need(gate.get(key)==JSONObject.NULL,"NOTES_RECOVERY_AUTHORIZATION_EFFECT");
            need(gate.getJSONArray("found_packages").length()==0&&gate.getJSONObject("last_check").length()==0,
                    "NOTES_RECOVERY_AUTHORIZATION_EFFECT");
            long terminalAt=number(result,"terminal_decided_elapsed_ms");need(terminalAt>=created&&terminalAt<=started,"NOTES_RECOVERY_TERMINAL_CLOCK");
            PublicProfileAbsenceRecovery.requireController(controller,uid);controllerText=canonical(controller);
            need(control!=null&&control.length>0&&control.length<=MAX_ORIGINAL,"NOTES_CURRENT_CONTROL_BOUND");
            JSONObject current=object(control);need("hepta.local-session.v1".equals(string(current,"schema"))&&number(current,"app_uid")==uid,
                    "NOTES_CURRENT_CONTROL_OWNER");no(current,"pending","running","automatic_resume");yes(current,"blocked");
            need(taskId.equals(string(current,"task_id"))&&ownerSha256.equals(string(current,"instruction_sha256")),"NOTES_CURRENT_CONTROL_BINDING");
            currentControl=control.clone();currentControlSha256=ProfileIdentity.sha(control);
            journalSha256=ProfileIdentity.sha(originals.get("journal"));originalsSha256=ProfileIdentity.sha(canonical(inputHashes()));requireFence(now,boot);
        }
        private int notesCustody(JSONObject c)throws Exception{
            boolean concurrent="hepta.public-personal-notes-cleanup.v2".equals(string(c,"schema"));
            need((concurrent||"hepta.public-personal-notes-cleanup.v1".equals(string(c,"schema")))&&generation.equals(string(c,"generation"))
                    &&publicScope.sha256.equals(string(c,"scope_sha256"))&&PACKAGE.equals(string(c,"package"))&&number(c,"display_id")==displayId,
                    "NOTES_CUSTODY_BINDING");
            long uid=number(c,"target_uid");need(uid>=10000&&uid<90000,"NOTES_TARGET_UID");
            yes(c,"create_attempted","launch_dispatched");no(c,"cleanup_known","arbitrary_task_removal_used","force_stop_used","caller_flag_is_cleanup_proof");
            if(concurrent){
                need("nonphysical_and_unresolved_recents".equals(string(c,"history_preservation_scope"))
                        &&"pre_release_to_absence".equals(string(c,"history_preservation_interval"))
                        &&"initial_to_absence".equals(string(c,"hidden_history_preservation_interval"))
                        &&Boolean.FALSE.equals(c.get("physical_history_frozen"))
                        &&c.get("unrelated_physical_history_changes_observed") instanceof Boolean
                        &&c.get("recents_presentation_changes_observed") instanceof Boolean
                        &&c.get("prior_hidden_history_preserved") instanceof Boolean,"NOTES_CUSTODY_HISTORY_SCOPE");
                no(c,"nonphysical_history_preserved","nonphysical_hidden_history_preserved");
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
            yes(b,"spawn_attempted","bootstrap_dispatched");no(b,"bootstrap_model_issued");
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
        public String source(){return SOURCE;}public String proofSchema(){return SCHEMA;}
        public JSONObject recordedOwnedIdentity()throws Exception{return new JSONObject().put("display_id",displayId).put("display_name",displayName)
                .put("task_ids",new JSONArray(recordedTaskIds)).put("user_id",0).put("full_uid",targetUid).put("package",PACKAGE)
                .put("recorded_task_ids_complete",false).put("absence_requires_all_notes_tasks",true).put("serialized_identity_grants_authority",false);}
        public boolean targetHint(String text){
            if(text==null)return false;
            return java.util.regex.Pattern.compile("(?<![A-Za-z0-9_.])"+java.util.regex.Pattern.quote(PACKAGE)+"(?=$|[^A-Za-z0-9_.])").matcher(text).find()
                    ||java.util.regex.Pattern.compile("(?<![0-9])"+targetUid+"(?![0-9])").matcher(text).find()
                    ||java.util.regex.Pattern.compile("(?<![A-Za-z0-9])u0a"+(targetUid-10000)+"(?=$|[^A-Za-z0-9])").matcher(text).find();
        }
        public JSONObject controller()throws Exception{return object(controllerText.getBytes(StandardCharsets.UTF_8));}
        public JSONObject inputHashes()throws Exception{JSONObject out=new JSONObject();for(String name:INPUTS){byte[] b=originals.get(name);
            out.put(name,new JSONObject().put("bytes",b.length).put("sha256",ProfileIdentity.sha(b)));}return out;}
        public String wire()throws Exception{
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF(REQUEST_SCHEMA);out.writeInt(ownerUid);out.writeUTF(requestId);out.writeLong(started);out.writeInt(requestBoot);
            put(out,controllerText.getBytes(StandardCharsets.UTF_8));put(out,currentControl);for(String name:INPUTS)put(out,originals.get(name));out.flush();
            need(bytes.size()<=MAX_BUNDLE+MAX_ORIGINAL+8192,"NOTES_WIRE_BOUND");ByteArrayOutputStream compressed=new ByteArrayOutputStream();
            try(GZIPOutputStream zip=new GZIPOutputStream(compressed)){zip.write(bytes.toByteArray());}
            String value=Base64.getEncoder().encodeToString(compressed.toByteArray());need(value.length()<=MAX_WIRE,"NOTES_WIRE_BOUND");return value;
        }
    }
    public static Request request(Map<String,byte[]> originals,byte[] currentControl,JSONObject currentController,int uid,String id,long now,int boot)throws Exception{
        return new Request(originals,currentControl,currentController,uid,id,now,boot);
    }
    public static Request fromWire(String wire)throws Exception{
        need(wire!=null&&wire.length()>0&&wire.length()<=MAX_WIRE,"NOTES_WIRE_BOUND");byte[] zipped=Base64.getDecoder().decode(wire);
        need(Base64.getEncoder().encodeToString(zipped).equals(wire),"NOTES_WIRE_NONCANONICAL");
        ByteArrayOutputStream decoded=new ByteArrayOutputStream();try(GZIPInputStream in=new GZIPInputStream(new ByteArrayInputStream(zipped))){
            byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1){need(decoded.size()+n<=MAX_BUNDLE+MAX_ORIGINAL+8192,"NOTES_WIRE_BOUND");decoded.write(b,0,n);}}
        DataInputStream in=new DataInputStream(new ByteArrayInputStream(decoded.toByteArray()));need(REQUEST_SCHEMA.equals(in.readUTF()),"NOTES_REQUEST_SCHEMA");
        int uid=in.readInt();String id=in.readUTF();long now=in.readLong();int boot=in.readInt();JSONObject controller=object(take(in,8192));byte[] control=take(in,MAX_ORIGINAL);
        Map<String,byte[]> inputs=new LinkedHashMap<String,byte[]>();for(String name:INPUTS)inputs.put(name,take(in,MAX_ORIGINAL));need(in.read()==-1,"NOTES_WIRE_TRAILING");
        Request r=new Request(inputs,control,controller,uid,id,now,boot);need(r.wire().equals(wire),"NOTES_WIRE_NONCANONICAL");return r;
    }
    public static JSONObject validate(JSONObject value,Request r,long now,int boot)throws Exception{
        need(r!=null,"NOTES_REQUEST_MISSING");r.requireFence(now,boot);
        keys(value,"schema","source","request_id","task_id","generation","owner_uid","owner_sha256","journal_sha256","originals_sha256","original_inputs",
                "public_scope_wire","public_scope_sha256","display_name","recorded_owned_identity","current_control_sha256","current_controller",
                "old_boot_count","current_boot_count","lease_expires_elapsed_ms","request_started_elapsed_ms","started_elapsed_ms","finished_elapsed_ms","deadline_elapsed_ms",
                "before","after","current_absence_verified","recovery_interval_physical_unchanged","foreign_history_preserved","cleanup_known",
                "automatic_resume","broker_release_response","historical_broker_release_observed","business_success","rewrites_original_task_result");
        need(SCHEMA.equals(string(value,"schema"))&&SOURCE.equals(string(value,"source"))&&r.requestId.equals(string(value,"request_id"))
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
        no(value,"automatic_resume","broker_release_response","historical_broker_release_observed","business_success","rewrites_original_task_result");
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
