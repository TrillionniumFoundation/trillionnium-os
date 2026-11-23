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
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import org.json.JSONArray;
import org.json.JSONObject;

/** Absence-only recovery of an expired supported public-profile lease after business work.
 * Old business/model records retain their original identities and outcome. This pure
 * contract never grants an action, acknowledges an interruption, or removes a journal. */
public final class PublicProfileBusinessAbsenceRecovery {
    public static final String REQUEST_SCHEMA="hepta.public-profile-business-absence-request.v1";
    public static final String SCHEMA="hepta.public-profile-business-current-absence.v1";
    public static final String SOURCE="fresh_public_profile_post_business_absence_with_preserved_history";
    public static final String CONTROLLER="org.trillionnium.hepta.local";
    public static final String JOURNAL="background-session.active.json",CONTROL="control-session.json",LATCH="control-session.interrupted.json";
    public static final long LIMIT_MS=12000,TTL_MS=540000,EXPIRY_GRACE_MS=2000;
    public static final int MAX_ORIGINAL=2097152,MAX_BUNDLE=33554432,MAX_FILES=512,MAX_MANIFEST=262144,MAX_WIRE=65536,MAX_OUTPUT=65536;
    private PublicProfileBusinessAbsenceRecovery(){}

    /** A bounded hash/path manifest. The root reader derives its root from PackageManager,
     * not from this value; no caller-supplied absolute path is an input capability. */
    public static final class Manifest {
        public final int ownerUid,boot;
        public final long started,deadline;
        public final String requestId,taskId,originSummary,sha256;
        private final String text;
        private final Map<String,String> descriptors;
        private final java.util.Set<String> taskFiles;
        private Manifest(JSONObject value)throws Exception{
            keys(value,"schema","owner_uid","request_id","task_id","started_elapsed_ms","boot_count","current_controller","origin_summary","files","task_membership");
            need(REQUEST_SCHEMA.equals(string(value,"schema")),"BUSINESS_MANIFEST_SCHEMA");
            long uid=number(value,"owner_uid"),b=number(value,"boot_count");
            need(uid>=10000&&uid<90000&&b>=0&&b<=Integer.MAX_VALUE,"BUSINESS_MANIFEST_OWNER");ownerUid=(int)uid;boot=(int)b;
            requestId=string(value,"request_id");taskId=string(value,"task_id");started=number(value,"started_elapsed_ms");
            need(ProfileIdentity.uuid(requestId)&&taskId.matches("[0-9a-f]{32}")&&started>=0&&started<=Long.MAX_VALUE-LIMIT_MS,"BUSINESS_MANIFEST_IDENTITY");deadline=started+LIMIT_MS;
            requireController(value.getJSONObject("current_controller"),ownerUid);originSummary=string(value,"origin_summary");
            need(CONTROL.equals(originSummary)||originSummary.matches("session-recovery/control-session\\.json\\.[0-9a-f]{64}\\.json"),"BUSINESS_ORIGIN_PATH");
            JSONObject files=value.getJSONObject("files");need(files.length()>0&&files.length()<=MAX_FILES,"BUSINESS_FILE_COUNT");
            TreeMap<String,String> ds=new TreeMap<String,String>();long total=0;
            Iterator<String> names=files.keys();while(names.hasNext()){
                String path=names.next();requireRelative(path,taskId);JSONObject d=files.getJSONObject(path);requireDescriptor(d,ownerUid);
                if(JOURNAL.equals(path))need(number(d,"bytes")<=16384,"BUSINESS_JOURNAL_BOUND");
                if(CONTROL.equals(path)||LATCH.equals(path)||path.equals(originSummary))need(number(d,"bytes")<=65536,"BUSINESS_SUMMARY_BOUND");
                total+=number(d,"bytes");need(total<=MAX_BUNDLE,"BUSINESS_TOTAL_BOUND");ds.put(path,canonical(d));
            }
            need(ds.containsKey(JOURNAL)&&ds.containsKey(CONTROL)&&ds.containsKey(originSummary),"BUSINESS_CORE_FILES");
            TreeSet<String> members=new TreeSet<String>();JSONArray membership=value.getJSONArray("task_membership");
            for(int i=0;i<membership.length();i++){Object n=membership.get(i);need(n instanceof String&&leaf((String)n)&&members.add((String)n),"BUSINESS_TASK_MEMBERSHIP");}
            TreeSet<String> actual=new TreeSet<String>();String prefix="control-tasks/"+taskId+"/";
            for(String p:ds.keySet())if(p.startsWith(prefix))actual.add(p.substring(prefix.length()));
            need(members.equals(actual)&&members.containsAll(Arrays.asList("result.json","owner.json","background-bootstrap.json","background-cleanup.json")),"BUSINESS_TASK_MEMBERSHIP");
            descriptors=Collections.unmodifiableMap(ds);taskFiles=Collections.unmodifiableSet(members);text=canonical(value);
            need(text.getBytes(StandardCharsets.UTF_8).length<=MAX_MANIFEST,"BUSINESS_MANIFEST_BOUND");sha256=ProfileIdentity.sha(text);
        }
        public JSONObject json()throws Exception{return object(text.getBytes(StandardCharsets.UTF_8));}
        public java.util.Set<String> paths(){return descriptors.keySet();}
        public java.util.Set<String> taskFiles(){return taskFiles;}
        public JSONObject descriptor(String path)throws Exception{String d=descriptors.get(path);need(d!=null,"BUSINESS_FILE_NOT_BOUND");return object(d.getBytes(StandardCharsets.UTF_8));}
        public JSONObject controller()throws Exception{return json().getJSONObject("current_controller");}
        public void requireClock(long now)throws Exception{need(now>=started&&now<deadline,"BUSINESS_MANIFEST_DEADLINE");}
        public String wire()throws Exception{
            ByteArrayOutputStream out=new ByteArrayOutputStream();try(GZIPOutputStream zip=new GZIPOutputStream(out)){zip.write(text.getBytes(StandardCharsets.UTF_8));}
            String wire=Base64.getEncoder().encodeToString(out.toByteArray());need(wire.length()<=MAX_WIRE,"BUSINESS_WIRE_BOUND");return wire;
        }
    }
    public static Manifest manifest(JSONObject value)throws Exception{return new Manifest(value);}
    public static Manifest fromWire(String wire)throws Exception{
        need(wire!=null&&wire.length()>0&&wire.length()<=MAX_WIRE,"BUSINESS_WIRE_BOUND");byte[] zipped=Base64.getDecoder().decode(wire);
        need(Base64.getEncoder().encodeToString(zipped).equals(wire),"BUSINESS_WIRE_NONCANONICAL");
        ByteArrayOutputStream out=new ByteArrayOutputStream();try(GZIPInputStream in=new GZIPInputStream(new ByteArrayInputStream(zipped))){
            byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1){need(out.size()+n<=MAX_MANIFEST,"BUSINESS_MANIFEST_BOUND");out.write(b,0,n);}}
        Manifest m=new Manifest(object(out.toByteArray()));need(Arrays.equals(out.toByteArray(),canonical(m.json()).getBytes(StandardCharsets.UTF_8))&&m.wire().equals(wire),"BUSINESS_WIRE_NONCANONICAL");return m;
    }
    public static void requireRelative(String path,String task)throws Exception{
        need(path!=null&&path.length()<=256&&!path.contains("..")&&!path.startsWith("/")&&!path.endsWith("/"),"BUSINESS_PATH");
        boolean known=JOURNAL.equals(path)||CONTROL.equals(path)||LATCH.equals(path)||path.matches("session-recovery/control-session\\.json\\.[0-9a-f]{64}\\.json");
        String prefix="control-tasks/"+task+"/";if(path.startsWith(prefix))known=leaf(path.substring(prefix.length()));
        if(path.matches("runs/[0-9a-f]{32}/(?:app-session-receipt\\.json|native-session-result\\.json|worker-generation\\.identity|generation-cleanup-[0-9a-f]{32}\\.json|app-receipt\\.json|native-result\\.json|raw-text\\.txt)"))known=true;
        need(known,"BUSINESS_PATH_NOT_ALLOWLISTED");
    }
    public static boolean leaf(String name){return name!=null&&name.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,199}")&&!name.contains("..");}
    public static void requireDescriptor(JSONObject d,int uid)throws Exception{
        keys(d,"bytes","sha256","device","inode","uid","mode","nlink","mtime_seconds","mtime_nanos","ctime_seconds","ctime_nanos");
        need(number(d,"bytes")>=0&&number(d,"bytes")<=MAX_ORIGINAL&&ProfileIdentity.hash(string(d,"sha256"))
                &&number(d,"device")>=0&&number(d,"inode")>0&&number(d,"uid")==uid&&number(d,"mode")==0100600&&number(d,"nlink")==1,"BUSINESS_FILE_METADATA");
        for(String k:new String[]{"mtime_nanos","ctime_nanos"})need(number(d,k)>=0&&number(d,k)<1000000000L,"BUSINESS_FILE_CLOCK");
        need(number(d,"mtime_seconds")>=0&&number(d,"ctime_seconds")>=0,"BUSINESS_FILE_CLOCK");
    }

    public static final class Request {
        public final Manifest manifest;
        public final int ownerUid,oldBoot,requestBoot,displayId,ownedRootTaskId,ownedLeafTaskId,steps,modelRequests;
        public final long created,expires,started,deadline;
        public final String requestId,taskId,generation,ownerSha256,displayName,journalSha256,originalsSha256,ownedLeafTaskToken,modelGeneration;
        public final ProfileTarget target;
        public final PublicOwnGroupPolicy.Scope publicScope;
        public final boolean postlaunch=true;
        private final Map<String,byte[]> originals;
        private final String taskPrefix,modelPrefix;
        private Request(Manifest m,Map<String,byte[]> files)throws Exception{
            manifest=m;need(m!=null&&files!=null&&files.keySet().equals(m.paths()),"BUSINESS_INPUT_SET");
            LinkedHashMap<String,byte[]> copy=new LinkedHashMap<String,byte[]>();long total=0;
            for(String p:m.paths()){byte[] bytes=files.get(p);JSONObject d=m.descriptor(p);
                need(bytes!=null&&bytes.length==number(d,"bytes")&&ProfileIdentity.sha(bytes).equals(string(d,"sha256")),"BUSINESS_INPUT_HASH");
                total+=bytes.length;need(total<=MAX_BUNDLE,"BUSINESS_TOTAL_BOUND");copy.put(p,bytes.clone());}
            originals=Collections.unmodifiableMap(copy);ownerUid=m.ownerUid;requestId=m.requestId;taskId=m.taskId;started=m.started;deadline=m.deadline;requestBoot=m.boot;
            taskPrefix="control-tasks/"+taskId+"/";JSONObject journal=object(original(JOURNAL));
            need("hepta.background-session.v1".equals(string(journal,"schema"))&&taskId.equals(string(journal,"task_id"))&&number(journal,"app_uid")==ownerUid,"BUSINESS_JOURNAL_OWNER");
            generation=string(journal,"generation");ownerSha256=string(journal,"owner_sha256");displayName=string(journal,"display_name");
            need(ProfileIdentity.uuid(generation)&&ProfileIdentity.hash(ownerSha256)&&("hepta-bg-"+generation).equals(displayName)&&displayName.equals(string(journal,"socket")),"BUSINESS_JOURNAL_IDENTITY");
            long display=number(journal,"display_id");need(display>1&&display<=Integer.MAX_VALUE,"BUSINESS_DISPLAY");displayId=(int)display;
            need("CLEANUP_UNKNOWN".equals(string(journal,"state")),"BUSINESS_LEASE_STATE");yes(journal,"profile_launch_attempted","profile_isolation_required","owned_task_retirement_required");
            target=ProfileTarget.fromWire(string(journal,"profile_target_wire"));
            need(target.profile.userId==10&&target.profile.parentUserId==0&&target.profile.serial>0&&ProfileIdentity.MANAGED.equals(target.profile.type)
                    &&ProfileTarget.supportsPackage(target.packageName)&&target.sha256.equals(string(journal,"profile_target_sha256")),"BUSINESS_TARGET");
            created=number(journal,"created_elapsed_ms");expires=number(journal,"expires_elapsed_ms");long boot=number(journal,"boot_count");
            need(created>=0&&expires>created&&expires-created==TTL_MS&&expires<Long.MAX_VALUE-EXPIRY_GRACE_MS&&boot>=0&&boot<=Integer.MAX_VALUE,"BUSINESS_LEASE_CLOCK");oldBoot=(int)boot;
            publicScope=PublicOwnGroupPolicy.Scope.fromWire(string(journal,"public_own_group_scope_wire"));publicScope.requireConfig(ownerUid,generation,expires,target);
            need(publicScope.sha256.equals(string(journal,"public_own_group_scope_sha256"))&&publicScope.taskId.equals(taskId)&&publicScope.ownerSha256.equals(ownerSha256)
                    &&publicScope.createdElapsedMs==created&&publicScope.bootCount==oldBoot,"BUSINESS_SCOPE_BINDING");
            yes(journal,"public_own_group_experimental");no(journal,"public_scope_serialization_grants_authority");
            JSONObject selection=journal.getJSONObject("selection");requireSelection(selection);
            JSONObject owner=object(task("owner.json"));need("hepta.local-owner.v1".equals(string(owner,"schema"))&&taskId.equals(string(owner,"task_id"))
                    &&ownerSha256.equals(string(owner,"instruction_utf8_sha256"))&&ownerSha256.equals(ProfileIdentity.sha(string(owner,"instruction")))
                    &&same(selection,owner.getJSONObject("background_request")),"BUSINESS_OWNER");no(owner,"external_model","automatic_resume");
            JSONObject bootstrap=object(task("background-bootstrap.json")),cleanup=object(task("background-cleanup.json")),result=object(task("result.json"));
            bindBackground(bootstrap);bindBackground(cleanup);
            need("ACTIVE".equals(string(bootstrap,"state"))&&"CLEANUP_UNKNOWN".equals(string(cleanup,"state")),"BUSINESS_BACKGROUND_STATE");
            yes(bootstrap,"spawn_attempted");no(bootstrap,"retired");yes(cleanup,"retired","spawn_attempted","broker_process_exit_observed");no(cleanup,"cleanup_known");
            need(number(cleanup,"broker_process_exit_code")==0,"BUSINESS_BROKER_EXIT");
            JSONObject broker=object(task("background-broker-"+generation+".json")),finalBroker=cleanup.getJSONObject("broker_output");requireBroker(broker);requireBroker(finalBroker);
            need(same(broker,finalBroker)&&Boolean.TRUE.equals(broker.get("persisted")),"BUSINESS_BROKER_RECEIPT");byte[] output=task("background-broker-"+generation+".bin");
            need(number(broker,"stored_bytes")==output.length&&number(broker,"observed_bytes")==output.length&&ProfileIdentity.sha(output).equals(string(broker,"stored_sha256")),"BUSINESS_BROKER_BYTES");
            requireBootstrapPrefix(bootstrap.getJSONObject("broker_output"),broker,output);
            JSONObject owned=businessOrigin(bootstrap,cleanup,output);ownedRootTaskId=(int)number(owned,"root_task_id");ownedLeafTaskId=(int)number(owned,"leaf_task_id");ownedLeafTaskToken=string(owned,"leaf_task_token");
            long count=number(result,"steps");need(count>0&&count<=256&&taskId.equals(string(result,"task_id"))&&"blocked".equals(string(result,"status")),"BUSINESS_TERMINAL");steps=(int)count;
            no(result,"cleanup_known","completion_verified","model_reported_success","external_model","automatic_replay","controller_completion_requested");
            for(String k:new String[]{"observation_read_worker_pending_at_terminal","action_worker_pending_at_terminal","native_cancel_worker_pending_at_terminal"})no(result,k);
            need(result.get("model_done_status")==JSONObject.NULL&&result.get("completion_actor")==JSONObject.NULL&&result.get("profile_permission_preparation")==JSONObject.NULL
                    &&result.getJSONArray("submit_attempts").length()==0&&result.getJSONArray("fixed_intent_attempts").length()==0,"BUSINESS_UNSUPPORTED_PENDING_CONTRACT");
            JSONObject cancellation=result.getJSONObject("native_cancellation");need(taskId.equals(string(cancellation,"task_id"))&&cancellation.get("run_id")==JSONObject.NULL,"BUSINESS_NATIVE_IDENTITY");
            yes(cancellation,"native_cleanup_known");no(cancellation,"request_reserved","executor_accepted","worker_started","signal_entered","submission_unknown","automatic_requeue");
            need(same(cleanup,result.getJSONObject("background_cleanup"))&&same(without(cleanup,"cleanup_known","cleanup_error"),result.getJSONObject("background_session")),"BUSINESS_RESULT_BINDING");
            JSONObject authorization=owner.getJSONObject("task_authorization"),gate=result.getJSONObject("task_authorization");
            need(ownerSha256.equals(string(gate,"instruction_sha256"))&&taskId.equals(string(gate,"task_id"))&&string(owner,"task_authorization_sha256").equals(string(result,"task_authorization_sha256"))
                    &&string(owner,"task_authorization_sha256").equals(string(authorization,"authorization_sha256")),"BUSINESS_AUTHORIZATION");
            Iterator<String> ak=authorization.keys();while(ak.hasNext()){String k=ak.next();need(same(authorization.get(k),gate.get(k)),"BUSINESS_AUTHORIZATION_CHANGED");}
            long terminal=number(result,"terminal_decided_elapsed_ms");need(terminal>=created&&terminal<=started,"BUSINESS_TERMINAL_CLOCK");
            requireLastAction(result,terminal);
            modelGeneration=string(result.getJSONObject("model_session"),"worker_generation");need(modelGeneration.matches("[0-9a-f]{32}")&&!modelGeneration.equals(taskId),"BUSINESS_MODEL_GENERATION");modelPrefix="runs/"+modelGeneration+"/";
            modelRequests=requireNormalModelClose(result.getJSONObject("model_session"),broker);
            requireControl(result,owner);requireOnlyBoundModelPaths();
            journalSha256=ProfileIdentity.sha(original(JOURNAL));originalsSha256=ProfileIdentity.sha(canonical(inputHashes()));requireFence(started,requestBoot);
        }
        public byte[] task(String leaf)throws Exception{return original(taskPrefix+leaf);}
        public byte[] model(String leaf)throws Exception{return original(modelPrefix+leaf);}
        private long requireLastAction(JSONObject result,long terminal)throws Exception{
            if(result.get("last_action_execution")==JSONObject.NULL)return created;
            JSONObject a=result.getJSONObject("last_action_execution");need("hepta.action-execution.v1".equals(string(a,"schema"))&&taskId.equals(string(a,"task_id"))
                    &&generation.equals(string(a,"background_generation"))&&number(a,"display_id")==displayId,"BUSINESS_LAST_ACTION_IDENTITY");
            yes(a,"worker_drained","callback_published");no(a,"automatic_redispatch");
            long queued=number(a,"queued_elapsed_ms"),drained=number(a,"worker_drained_elapsed_ms");need(queued>=created&&drained>=queued&&drained<=terminal,"BUSINESS_LAST_ACTION_CLOCK");
            need(a.get("effect_entered") instanceof Boolean&&a.get("effect_returned") instanceof Boolean,"BUSINESS_LAST_ACTION_TYPE");
            if(Boolean.TRUE.equals(a.get("effect_entered")))yes(a,"effect_returned");return drained;
        }
        private JSONObject businessOrigin(JSONObject bootstrap,JSONObject cleanup,byte[] output)throws Exception{
            JSONObject terminal=object(output);
            need("hepta.background-broker-terminal.v1".equals(string(terminal,"schema"))&&generation.equals(string(terminal,"generation"))&&number(terminal,"display_id")==displayId
                    &&"RELEASED".equals(string(terminal,"state"))&&publicScope.sha256.equals(string(terminal,"display_scope_sha256"))
                    &&terminal.get("boot_count_read_retirement_failure")==JSONObject.NULL&&terminal.get("owned_single_task")==JSONObject.NULL,"BUSINESS_HISTORICAL_TERMINAL");
            yes(terminal,"release_confirmed","public_scope_admission_retired");no(terminal,"profile_custody_retained");
            need(string(terminal,"reason").matches("[A-Z0-9_]{1,96}"),"BUSINESS_TERMINAL_REASON");
            JSONObject first=bootstrap.getJSONObject("last_broker_response"),last=cleanup.getJSONObject("last_broker_response");
            requireHistoricalResponse(first,bootstrap.getJSONObject("app_display_readback"));requireHistoricalResponse(last,cleanup.getJSONObject("app_display_readback"));
            need(number(bootstrap.getJSONObject("app_display_readback"),"observed_ended_elapsed_ms")<=number(cleanup.getJSONObject("app_display_readback"),"observed_ended_elapsed_ms"),"BUSINESS_RESPONSE_CLOCK");
            JSONObject cleaned=terminal.getJSONObject("profile_cleanup"),history=cleaned.getJSONObject("public_foreign_recent_history");
            boolean concurrent="hepta.public-profile-history-custody.v2".equals(string(history,"schema"));
            String historyScope=concurrent?"owned_target_only_with_unrelated_physical_history_audited":"owned_target_only_with_foreign_history_preserved";
            keys(cleaned,"schema","generation","display_id","target_sha256","user_id","user_serial","full_uid","cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown","owned_tasks","public_foreign_recent_history","recents_absence_scope");
            need("hepta.profile-task-cleanup.v1".equals(string(cleaned,"schema"))&&generation.equals(string(cleaned,"generation"))&&number(cleaned,"display_id")==displayId
                    &&target.sha256.equals(string(cleaned,"target_sha256"))&&number(cleaned,"user_id")==target.profile.userId&&number(cleaned,"user_serial")==target.profile.serial
                    &&number(cleaned,"full_uid")==target.fullUid&&historyScope.equals(string(cleaned,"recents_absence_scope")),"BUSINESS_HISTORICAL_CLEANUP");
            yes(cleaned,"cleanup_known","live_tasks_absent","recents_tasks_absent");no(cleaned,"foreign_tasks_present","identity_unknown");
            JSONArray tasks=cleaned.getJSONArray("owned_tasks");need(tasks.length()==1,"BUSINESS_OWNED_COUNT");JSONObject task=tasks.getJSONObject(0);
            keys(task,"task_id","parent_task_id","task_token_id","user_id","user_serial","full_uid","live_absent","recents_absent");
            long root=number(task,"parent_task_id"),leaf=number(task,"task_id");String token=string(task,"task_token_id");
            need(root>0&&root<=Integer.MAX_VALUE&&leaf>0&&leaf<=Integer.MAX_VALUE&&root!=leaf&&ProfileIdentity.uuid(token)
                    &&number(task,"user_id")==target.profile.userId&&number(task,"user_serial")==target.profile.serial&&number(task,"full_uid")==target.fullUid,"BUSINESS_OWNED_IDENTITY");
            yes(task,"live_absent","recents_absent");requireHistoricalLeaf(terminal.getJSONObject("profile_last_leaf_validation"),root,leaf);
            requireHistoricalHistory(history,root,leaf,true);
            for(JSONObject response:new JSONObject[]{first,last}){
                JSONObject previous=response.getJSONObject("profile_cleanup");JSONArray rows=previous.getJSONArray("owned_tasks");
                need(rows.length()==1&&same(without(previous,"cleanup_known","live_tasks_absent","recents_tasks_absent","owned_tasks","public_foreign_recent_history"),
                        without(cleaned,"cleanup_known","live_tasks_absent","recents_tasks_absent","owned_tasks","public_foreign_recent_history")),"BUSINESS_CUSTODY_TRANSITION");
                no(previous,"cleanup_known","live_tasks_absent","recents_tasks_absent");JSONObject old=rows.getJSONObject(0);
                need(same(without(old,"live_absent","recents_absent"),without(task,"live_absent","recents_absent")),"BUSINESS_OWNED_IDENTITY_CHANGED");no(old,"live_absent","recents_absent");
                requireHistoricalLeaf(response.getJSONObject("profile_last_leaf_validation"),root,leaf);
                JSONObject priorHistory=previous.getJSONObject("public_foreign_recent_history");requireHistoricalHistory(priorHistory,root,leaf,false);
                for(String k:new String[]{"schema","target_sha256","baseline_elapsed_ms","baseline_raw_sha256","baseline_task_ids","owned_task_ids"})
                    need(same(priorHistory.get(k),history.get(k)),"BUSINESS_HISTORY_ORIGIN_CHANGED");
                if(concurrent)need(string(priorHistory,"protected_history_sha256").equals(string(history,"protected_history_sha256")),"BUSINESS_PROTECTED_HISTORY_CHANGED");
                else need(string(priorHistory,"nonowned_history_sha256").equals(string(history,"nonowned_history_sha256")),"BUSINESS_HISTORY_CHANGED");
            }
            return new JSONObject().put("root_task_id",root).put("leaf_task_id",leaf).put("leaf_task_token",token);
        }
        private void requireHistoricalResponse(JSONObject response,JSONObject readback)throws Exception{
            need(number(response,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION&&ProfileIdentity.uuid(string(response,"request_id"))
                    &&generation.equals(string(response,"generation"))&&number(response,"display_id")==displayId&&displayName.equals(string(response,"display_name"))
                    &&publicScope.sha256.equals(string(response,"display_scope_sha256"))&&"ACTIVE".equals(string(response,"state"))
                    &&string(response,"operation").matches("[a-z_]{1,64}")&&expires==number(response,"expires_elapsed_ms")&&target.wire().equals(string(response,"profile_target_wire")),"BUSINESS_HISTORICAL_RESPONSE");
            yes(response,"ok","profile_current_identity_verified","always_unlocked");no(response,"public_scope_admission_retired","public_scope_closing","capture_secure");
            need("hide".equals(string(response,"ime_policy"))&&response.get("dispatched") instanceof Boolean,"BUSINESS_HISTORICAL_RESPONSE_FLAGS");
            need("hepta.public-own-group.app-readback.v1".equals(string(readback,"schema"))&&taskId.equals(string(readback,"task_id"))&&generation.equals(string(readback,"generation"))
                    &&number(readback,"app_uid")==ownerUid&&number(readback,"app_pid")==number(object(task("background-broker-"+generation+".json")),"app_pid")
                    &&number(readback,"boot_count")==oldBoot&&number(readback,"display_id")==displayId&&displayName.equals(string(readback,"display_name"))
                    &&publicScope.sha256.equals(string(readback,"scope_sha256")),"BUSINESS_HISTORICAL_READBACK");
            yes(readback,"valid","root_rpc_registered");no(readback,"serialization_grants_authority");
            PublicOwnGroupPolicy.Readback observed=PublicOwnGroupPolicy.Readback.fromWire(string(response,"public_own_group_readback_wire"),publicScope);
            need(observed.requestId.equals(string(response,"request_id"))&&observed.display.displayId==displayId&&observed.display.flags==number(response,"flags")
                    &&observed.display.name.equals(displayName)&&observed.sha256.equals(string(readback,"broker_readback_sha256"))&&observed.requestId.equals(string(readback,"broker_request_id"))
                    &&number(readback,"flags")==observed.display.flags&&"ordinary_app_public_display_readback".equals(string(readback,"source"))
                    &&number(readback,"observed_started_elapsed_ms")>=observed.observedEndedElapsedMs&&number(readback,"observed_ended_elapsed_ms")>=number(readback,"observed_started_elapsed_ms")
                    &&number(readback,"observed_ended_elapsed_ms")<expires,"BUSINESS_READBACK_BINDING");
        }
        private void requireHistoricalLeaf(JSONObject v,long root,long leaf)throws Exception{
            need("hepta.profile-leaf-validation.v1".equals(string(v,"schema"))&&"retained_leaf".equals(string(v,"phase"))&&v.get("refusal_code")==JSONObject.NULL
                    &&number(v,"retained_task_id")==leaf&&number(v,"observed_task_id")==leaf&&number(v,"observed_parent_id")==root&&number(v,"observed_display_id")==displayId
                    &&number(v,"observed_user_id")==target.profile.userId&&number(v,"observed_full_uid")==target.fullUid&&number(v,"observed_top_activity_info_uid")==target.fullUid
                    &&number(v,"observed_elapsed_ms")>=created&&number(v,"observed_elapsed_ms")<=started&&v.get("launch_cookie_present") instanceof Boolean,"BUSINESS_LEAF_IDENTITY");
            yes(v,"valid","actual_task_token_equal_to_retained","retained_task_identity_matches","complete_global_leaf_matches");no(v,"serialized_token_is_authority");
            String[] required={"dispatch_marked","task_info_present","task_id_positive","task_id_differs_from_root","task_id_absent_before_launch","actual_task_token_present","actual_task_token_differs_from_root",
                    "display_matches","user_matches","parent_matches","full_uid_matches","top_activity_info_uid_matches","first_claim_launch_cookie","intent_package_matches","base_package_matches","top_package_matches","real_package_matches","orig_package_matches"};
            JSONObject checks=v.getJSONObject("checks");keys(checks,required);yes(checks,required);
        }
        private void requireHistoricalHistory(JSONObject h,long root,long leaf,boolean absent)throws Exception{
            boolean concurrent="hepta.public-profile-history-custody.v2".equals(string(h,"schema"));
            need((concurrent||"hepta.public-profile-history-custody.v1".equals(string(h,"schema")))&&target.sha256.equals(string(h,"target_sha256"))
                    &&h.get("history_refusal_reason")==JSONObject.NULL&&Boolean.valueOf(absent).equals(h.get("owned_target_absent"))
                    &&number(h,"baseline_elapsed_ms")>=created&&number(h,"current_elapsed_ms")>=number(h,"baseline_elapsed_ms")&&number(h,"current_elapsed_ms")<=started,"BUSINESS_HISTORICAL_HISTORY");
            yes(h,concurrent?"nonphysical_history_preserved":"foreign_dormant_history_preserved");no(h,"history_refusal_latched","serialized_task_ids_grant_authority");
            for(String k:new String[]{"baseline_raw_sha256","current_raw_sha256","nonowned_history_sha256"})need(ProfileIdentity.hash(string(h,k)),"BUSINESS_HISTORY_HASH");
            if(concurrent){
                need("nonphysical_and_unresolved_recents".equals(string(h,"history_preservation_scope"))&&h.get("unrelated_physical_history_changes_observed") instanceof Boolean
                        &&h.get("recents_presentation_changes_observed") instanceof Boolean&&ProfileIdentity.hash(string(h,"protected_history_sha256"))
                        &&string(h,"protected_history_sha256").equals(string(h,"current_protected_history_sha256"))
                        &&Boolean.valueOf(!h.getBoolean("unrelated_physical_history_changes_observed")&&!h.getBoolean("recents_presentation_changes_observed")).equals(h.get("foreign_dormant_history_preserved")),"BUSINESS_PROTECTED_HISTORY");no(h,"physical_history_frozen");
            }
            JSONArray owned=h.getJSONArray("owned_task_ids"),baseline=h.getJSONArray("baseline_task_ids");need(owned.length()==2&&numberAt(owned,0)==root&&numberAt(owned,1)==leaf,"BUSINESS_HISTORY_OWNED_SET");
            TreeSet<Long> ids=new TreeSet<Long>();for(int i=0;i<baseline.length();i++){long n=numberAt(baseline,i);need(n>0&&n<=Integer.MAX_VALUE&&n!=root&&n!=leaf&&ids.add(n),"BUSINESS_HISTORY_BASELINE");}
        }
        private int requireNormalModelClose(JSONObject projection,JSONObject broker)throws Exception{
            JSONObject session=object(model("app-session-receipt.json")),nativeSession=object(model("native-session-result.json"));
            long appPid=number(session,"app_pid"),count=number(session,"requests_sent");need(count>0&&count<=256,"BUSINESS_MODEL_COUNT");
            need("hepta.local-model.task-session.v1".equals(string(session,"schema"))&&taskId.equals(string(session,"task_id"))&&modelGeneration.equals(string(session,"worker_generation"))
                    &&number(session,"app_uid")==ownerUid&&appPid>1&&appPid==number(broker,"app_pid")&&number(session,"exit_code")==0&&number(session,"requests_accepted")==count
                    &&"normal_close_with_observed_sdk_cleanup".equals(string(session,"cleanup_classification"))&&same(nativeSession,session.getJSONObject("native_session_receipt")),"BUSINESS_MODEL_SESSION");
            // Model nanoTime budgets and task elapsedRealtime clocks are distinct.
            // Preserve each recorded clock in its own domain, without conversion.
            long submitted=number(session,"finisher_submitted_monotonic_ns"),deadline=number(session,"finisher_deadline_monotonic_ns");
            need(submitted>0&&deadline>submitted&&deadline-submitted<=44000000000L,"BUSINESS_FINISHER_CLOCK");
            yes(session,"process_started","process_exit_observed","cleanup_known","native_session_binding_valid","generation_cleanup_known","generation_unforced");
            no(session,"caller_cancellation_requested","cancel_requested","force_destroy_sent","parent_force_destroy_sent","automatic_restart","cross_task_reuse");
            need(taskId.equals(string(projection,"task_id"))&&modelGeneration.equals(string(projection,"worker_generation"))&&number(projection,"exit_code")==0
                    &&ProfileIdentity.sha(model("app-session-receipt.json")).equals(string(projection,"app_receipt_sha256")),"BUSINESS_MODEL_PROJECTION");yes(projection,"process_started","process_exit_observed","receipt_valid");
            requireCancellation(session.getJSONObject("owned_worker_cancellation"),true);
            need("hepta.geniex-task-session.result.v1".equals(string(nativeSession,"schema"))&&taskId.equals(string(nativeSession,"task_id"))&&modelGeneration.equals(string(nativeSession,"worker_generation"))
                    &&number(nativeSession,"pid")>1,"BUSINESS_NATIVE_SESSION");no(nativeSession,"process_exit_observed","control_channel_write_failed");no(nativeSession.getJSONObject("sdk_exception_boundary"),"caught","automatic_retry");
            yes(nativeSession,"model_metadata_unchanged_before_close","close_requested","sdk_destroy_attempted","sdk_deinit_attempted");
            for(String k:new String[]{"requests_received","requests_completed","model_reset_count","control_done_attempts","control_done_delivered"})need(number(nativeSession,k)==count,"BUSINESS_NATIVE_COUNTS");
            for(String k:new String[]{"model_hash_count","sdk_init_count","model_create_count"})need(number(nativeSession,k)==1,"BUSINESS_NATIVE_INITIALIZATION");
            for(String k:new String[]{"last_request_status","signal_observed","sdk_destroy_rc","sdk_deinit_rc","control_channel_last_errno","last_request_return_status"})need(number(nativeSession,k)==0,"BUSINESS_NATIVE_CLOSE");
            TreeSet<Integer> sequences=new TreeSet<Integer>();TreeSet<String> runIds=new TreeSet<String>();
            for(String leaf:manifest.taskFiles())if(leaf.matches("step-[0-9]+-model-[0-9]+\\.json")){
                int stepIndex=Integer.parseInt(leaf.split("-")[1]);need(stepIndex>=1&&stepIndex<=steps,"BUSINESS_STEP_INDEX");JSONObject step=object(task(leaf));
                String run=string(step,"run_id"),obs=string(step,"observation_id");need(run.matches("[0-9a-f]{32}")&&!run.equals(modelGeneration)&&runIds.add(run)
                        &&obs.matches("[0-9a-f]{32}")&&ownerSha256.equals(string(step,"original_instruction_sha256")),"BUSINESS_MODEL_STEP");
                String prefix="runs/"+run+"/";JSONObject request=object(original(prefix+"app-receipt.json")),nativeRequest=object(original(prefix+"native-result.json"));byte[] raw=original(prefix+"raw-text.txt");
                long sequence=number(request,"request_sequence");need(sequence>=1&&sequence<=count&&sequences.add((int)sequence),"BUSINESS_REQUEST_SEQUENCE");
                need("hepta.local-model.task-request.v1".equals(string(request,"schema"))&&taskId.equals(string(request,"task_id"))&&modelGeneration.equals(string(request,"worker_generation"))
                        &&run.equals(string(request,"run_id"))&&number(request,"app_uid")==ownerUid&&number(request,"app_pid")==appPid&&number(request,"worker_pid")==number(nativeSession,"pid")
                        &&obs.equals(string(request,"grammar_observation_id"))&&target.packageName.equals(string(request,"grammar_current_package"))
                        &&ProfileIdentity.sha(raw).equals(string(request,"raw_text_sha256_read"))&&Arrays.equals(raw,string(step,"raw_text").getBytes(StandardCharsets.UTF_8))
                        &&sameNativeRequestReceipt(nativeRequest,request.getJSONObject("native_receipt")),"BUSINESS_REQUEST_BINDING");
                yes(request,"process_started","inference_completed","request_committed","native_result_binding_valid");no(request,"process_exit_observed","caller_cancellation_requested","cancel_requested","timeout_observed","force_destroy_sent","automatic_retry");
                need(request.get("exit_code")==JSONObject.NULL&&"request_completed".equals(string(request,"status")),"BUSINESS_REQUEST_STATE");requireCancellation(request.getJSONObject("owned_worker_cancellation"),false);
                need("hepta.geniex-task-request.result.v1".equals(string(nativeRequest,"schema"))&&modelGeneration.equals(string(nativeRequest,"worker_generation"))&&taskId.equals(string(nativeRequest,"task_id"))
                        &&run.equals(string(nativeRequest,"request_id"))&&number(nativeRequest,"request_sequence")==sequence&&number(nativeRequest,"pid")==number(nativeSession,"pid")
                        &&number(nativeRequest,"request_status")==0&&number(nativeRequest,"raw_text_bytes")==raw.length&&ProfileIdentity.sha(raw).equals(string(nativeRequest,"raw_text_sha256")),"BUSINESS_NATIVE_REQUEST");
                yes(nativeRequest,"generation_complete","raw_text_present","raw_text_utf8");no(nativeRequest,"process_exit_observed","automatic_retry","raw_text_truncated");
            }
            need(sequences.size()==count&&runIds.size()==count,"BUSINESS_REQUEST_MEMBERSHIP");
            requireGeneration(session,nativeSession);return (int)count;
        }
        private void requireCancellation(JSONObject c,boolean closed)throws Exception{
            need("hepta.owned-worker-cancellation.v1".equals(string(c,"schema"))&&taskId.equals(string(c,"task_id"))&&modelGeneration.equals(string(c,"worker_generation"))
                    &&number(c,"term_destroy_attempts")==0&&number(c,"force_destroy_attempts")==0&&c.get("signal_error")==JSONObject.NULL
                    &&Boolean.valueOf(closed).equals(c.get("process_exit_observed"))&&(closed?number(c,"exit_code")==0:c.get("exit_code")==JSONObject.NULL),"BUSINESS_CANCELLATION_AUDIT");
            yes(c,"process_bound");no(c,"requested","termination_started","term_destroy_returned","force_destroy_returned","sdk_cleanup_proven_by_this_object");
        }
        private void requireGeneration(JSONObject session,JSONObject nativeSession)throws Exception{
            JSONObject g=session.getJSONObject("worker_generation_cleanup");String nonce=string(g,"cleanup_nonce");need(nonce.matches("[0-9a-f]{32}"),"BUSINESS_GENERATION_NONCE");
            byte[] identity=model("worker-generation.identity"),raw=model("generation-cleanup-"+nonce+".json");JSONObject receipt=object(raw);
            need("hepta.worker-generation.app-cleanup.v1".equals(string(g,"schema"))&&taskId.equals(string(g,"task_id"))&&modelGeneration.equals(string(g,"worker_generation"))
                    &&number(g,"app_uid")==ownerUid&&number(g,"app_pid")==number(session,"app_pid")&&ProfileIdentity.sha(identity).equals(string(g,"identity_sha256"))
                    &&ProfileIdentity.sha(raw).equals(string(g,"native_receipt_sha256"))&&same(receipt,g.getJSONObject("native_cleanup")),"BUSINESS_GENERATION_RAW_BINDING");
            yes(g,"direct_process_exit_observed","helper_started","helper_exit_observed","cleanup_known","descendant_force_known","generation_unforced");no(g,"helper_force_destroy_sent","helper_currently_alive","descendant_force_used","automatic_retry","escaped_sessions_proven_absent");
            need(number(g,"helper_exit_code")==0&&g.get("error")==JSONObject.NULL&&"pinned_sdk_inheriting_process_group_and_generation_markers".equals(string(g,"scope"))
                    &&number(g,"finisher_submitted_monotonic_ns")==number(session,"finisher_submitted_monotonic_ns")&&number(g,"finisher_deadline_monotonic_ns")==number(session,"finisher_deadline_monotonic_ns"),"BUSINESS_GENERATION_CLOSE");
            for(String k:new String[]{"task_id","worker_generation","scope_token","app_uid","app_pid","app_start_ticks","boot_id","identity_sha256","cleanup_nonce"})need(same(g.get(k),receipt.get(k)),"BUSINESS_GENERATION_IDENTITY");
            need("hepta.worker-generation.cleanup.v1".equals(string(receipt,"schema"))&&number(receipt,"leader_pid")==number(nativeSession,"pid")&&number(receipt,"pgid")==number(nativeSession,"pid")
                    &&number(receipt,"term_attempts")==0&&number(receipt,"kill_attempts")==0&&receipt.getJSONArray("targets").length()==0,"BUSINESS_GENERATION_UNFORCED");
            long submitted=number(g,"submitted_monotonic_ns"),deadline=number(g,"deadline_monotonic_ns"),begin=number(receipt,"started_monotonic_ns"),end=number(receipt,"ended_monotonic_ns");
            need(submitted>=number(session,"finisher_submitted_monotonic_ns")&&deadline>submitted&&deadline-submitted<=4000000000L
                    &&deadline<=number(session,"finisher_deadline_monotonic_ns")&&begin>=submitted&&begin<deadline&&end>=begin&&end<=deadline
                    &&number(receipt,"deadline_monotonic_ns")==deadline,"BUSINESS_GENERATION_MONOTONIC_CLOCK");
            yes(receipt,"cleanup_known","scan_complete","pidfd_supported");no(receipt,"numeric_pid_signal_used","group_signal_used","sdk_called","worker_started");
            for(String k:new String[]{"remaining_owned_count","unknown_count","escaped_generation_count"})need(number(receipt,k)==0,"BUSINESS_GENERATION_UNKNOWN");
            StringBuilder exact=new StringBuilder("hepta.worker-generation.v1\n");for(String k:new String[]{"task_id","worker_generation","scope_token","app_uid","app_pid","app_start_ticks","leader_pid","leader_start_ticks","pgid","boot_id"})exact.append(k).append('=').append(receipt.get(k)).append('\n');
            need(Arrays.equals(exact.toString().getBytes(StandardCharsets.US_ASCII),identity),"BUSINESS_GENERATION_IDENTITY_BYTES");
        }
        private void requireOnlyBoundModelPaths()throws Exception{
            TreeSet<String> required=new TreeSet<String>();required.add(modelPrefix+"app-session-receipt.json");required.add(modelPrefix+"native-session-result.json");required.add(modelPrefix+"worker-generation.identity");
            JSONObject g=object(model("app-session-receipt.json")).getJSONObject("worker_generation_cleanup");required.add(modelPrefix+"generation-cleanup-"+string(g,"cleanup_nonce")+".json");
            for(String f:manifest.taskFiles())if(f.matches("step-[0-9]+-model-[0-9]+\\.json")){
                String run=string(object(task(f)),"run_id");for(String leaf:new String[]{"app-receipt.json","native-result.json","raw-text.txt"})required.add("runs/"+run+"/"+leaf);
            }
            TreeSet<String> actual=new TreeSet<String>();for(String p:originals.keySet())if(p.startsWith("runs/"))actual.add(p);need(required.equals(actual),"BUSINESS_RUN_INPUT_SET");
        }
        private void requireControl(JSONObject result,JSONObject owner)throws Exception{
            JSONObject current=object(original(CONTROL)),origin=object(original(manifest.originSummary));
            requireControlIdentity(origin);need("blocked".equals(string(origin,"status"))&&number(origin,"steps")==steps&&same(origin.getJSONObject("background_request"),owner.getJSONObject("background_request"))
                    &&string(origin,"task_authorization_sha256").equals(string(result,"task_authorization_sha256")),"BUSINESS_ORIGINAL_CONTROL");
            no(origin,"completion_verified","model_reported_success");JSONObject ref=origin.getJSONObject("task_result_reference"),d=manifest.descriptor(taskPrefix+"result.json");
            need("hepta.session-terminal-evidence.v1".equals(string(origin,"terminal_evidence_schema"))&&"hepta.session-task-result-reference.v1".equals(string(ref,"schema"))
                    &&taskId.equals(string(ref,"task_id"))&&(taskPrefix+"result.json").equals(string(ref,"relative_path"))&&number(ref,"bytes")==number(d,"bytes")
                    &&string(ref,"sha256").equals(string(d,"sha256"))&&number(ref,"file_device")==number(d,"device")&&number(ref,"file_inode")==number(d,"inode")
                    &&number(ref,"file_uid")==ownerUid&&number(ref,"file_mode")==number(d,"mode")&&number(ref,"file_nlink")==1,"BUSINESS_RESULT_REFERENCE");no(ref,"grants_tool_authority");
            requireControlIdentity(current);
            if(!CONTROL.equals(manifest.originSummary)){
                need("interrupted".equals(string(current,"status"))&&manifest.originSummary.equals("session-recovery/control-session.json."+ProfileIdentity.sha(original(manifest.originSummary))+".json"),"BUSINESS_STARTUP_ARCHIVE");
                JSONObject recovery=current.getJSONObject("startup_recovery");need("hepta.session-recovery.v1".equals(string(recovery,"schema"))&&"blocked_interrupted".equals(string(recovery,"decision"))
                        &&"blocked".equals(string(recovery,"previous_status"))&&ProfileIdentity.sha(original(manifest.originSummary)).equals(string(recovery,"previous_session_sha256"))
                        &&LATCH.equals(string(recovery,"interruption_latch"))&&recovery.get("read_error")==JSONObject.NULL,"BUSINESS_STARTUP_CHAIN");
                yes(recovery,"interruption_latch_observed","interruption_latch_synced");no(recovery,"recovery_pending_barrier_observed","automatic_resume","native_cleanup_independently_observed");
                JSONArray preserved=recovery.getJSONArray("preserved_records");need(preserved.length()==1,"BUSINESS_STARTUP_ARCHIVE_SET");JSONObject p=preserved.getJSONObject(0);
                need(CONTROL.equals(string(p,"original_name"))&&number(p,"bytes")==original(manifest.originSummary).length&&ProfileIdentity.sha(original(manifest.originSummary)).equals(string(p,"sha256"))
                        &&privatePathEnds(string(p,"path"),manifest.originSummary),"BUSINESS_STARTUP_ARCHIVE_REFERENCE");
                need(originals.containsKey(LATCH),"BUSINESS_STARTUP_LATCH_MISSING");
            }else need("blocked".equals(string(current,"status")),"BUSINESS_CURRENT_CONTROL");
            if(originals.containsKey(LATCH)){
                JSONObject latch=object(original(LATCH));need("hepta.session-interruption-latch.v1".equals(string(latch,"schema"))&&number(latch,"app_uid")==ownerUid,"BUSINESS_LATCH_OWNER");yes(latch,"blocked");no(latch,"cleanup_known","automatic_resume");
                JSONObject reason=latch.getJSONObject("recovery_reason");need(ProfileIdentity.sha(original(manifest.originSummary)).equals(string(reason,"previous_session_sha256")),"BUSINESS_LATCH_ORIGIN");
            }
        }
        private void requireControlIdentity(JSONObject c)throws Exception{
            need("hepta.local-session.v1".equals(string(c,"schema"))&&taskId.equals(string(c,"task_id"))&&number(c,"app_uid")==ownerUid&&ownerSha256.equals(string(c,"instruction_sha256")),"BUSINESS_CONTROL_IDENTITY");
            yes(c,"blocked");no(c,"running","pending","cleanup_known","external_model","automatic_resume");
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
            JSONObject j=object(original(JOURNAL));
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
        public void requireFence(long now,int boot)throws Exception{need(boot==requestBoot&&boot==oldBoot&&now>=started&&now<deadline&&now>expires+EXPIRY_GRACE_MS,"BUSINESS_BOOT_TTL_OR_DEADLINE");}
        public byte[] original(String relative)throws Exception{byte[] b=originals.get(relative);need(b!=null,"BUSINESS_INPUT_MISSING");return b.clone();}
        public String proofSchema(){return SCHEMA;}
        public String source(){return SOURCE;}
        public JSONObject controller()throws Exception{return manifest.controller();}
        public String wire()throws Exception{return manifest.wire();}
        public JSONObject inputHashes()throws Exception{JSONObject out=new JSONObject();for(String p:originals.keySet()){byte[] b=originals.get(p);out.put(p,new JSONObject().put("bytes",b.length).put("sha256",ProfileIdentity.sha(b)));}return out;}
        public byte[] archiveBytes()throws Exception{
            ByteArrayOutputStream raw=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(raw);out.writeUTF("hepta.public-profile-business-originals.v1");
            put(out,canonical(manifest.json()).getBytes(StandardCharsets.UTF_8));out.writeInt(originals.size());for(String p:originals.keySet()){out.writeUTF(p);put(out,originals.get(p));}out.flush();
            need(raw.size()<=MAX_BUNDLE+MAX_MANIFEST+MAX_FILES*512+4096,"BUSINESS_ARCHIVE_BOUND");return raw.toByteArray();
        }
    }
    public static Request request(Manifest manifest,Map<String,byte[]> files)throws Exception{return new Request(manifest,files);}
    public static boolean privatePathEnds(String path,String relative){return ("/data/data/"+CONTROLLER+"/files/"+relative).equals(path)||("/data/user/0/"+CONTROLLER+"/files/"+relative).equals(path);}
    public static JSONObject validate(JSONObject value,Request r,long now,int boot)throws Exception{
        need(r!=null,"BUSINESS_REQUEST_MISSING");r.requireFence(now,boot);
        keys(value,"schema","source","request_id","task_id","generation","owner_uid","owner_sha256","journal_sha256","manifest_sha256","originals_sha256",
                "public_scope_wire","public_scope_sha256","profile_target_wire","target_sha256","display_name","old_boot_count","current_boot_count","lease_expires_elapsed_ms",
                "request_started_elapsed_ms","started_elapsed_ms","finished_elapsed_ms","deadline_elapsed_ms","current_controller","before","after","current_absence_verified",
                "recovery_interval_physical_unchanged","foreign_dormant_history_preserved","cleanup_known","automatic_resume","broker_release_response","business_steps",
                "model_requests","model_generation","historical_model_exit_verified","historical_broker_release_observed","business_dispatch_absent_in_original_receipts",
                "recorded_owned_identity","rewrites_business_outcome","acknowledges_control_session");
        need(SCHEMA.equals(string(value,"schema"))&&SOURCE.equals(string(value,"source"))&&r.requestId.equals(string(value,"request_id"))&&r.taskId.equals(string(value,"task_id"))
                &&r.generation.equals(string(value,"generation"))&&number(value,"owner_uid")==r.ownerUid&&r.ownerSha256.equals(string(value,"owner_sha256"))
                &&r.journalSha256.equals(string(value,"journal_sha256"))&&r.manifest.sha256.equals(string(value,"manifest_sha256"))&&r.originalsSha256.equals(string(value,"originals_sha256"))
                &&r.publicScope.wire().equals(string(value,"public_scope_wire"))&&r.publicScope.sha256.equals(string(value,"public_scope_sha256"))&&r.target.wire().equals(string(value,"profile_target_wire"))
                &&r.target.sha256.equals(string(value,"target_sha256"))&&r.displayName.equals(string(value,"display_name"))&&same(r.controller(),value.getJSONObject("current_controller"))
                &&same(r.recordedOwnedIdentity(),value.getJSONObject("recorded_owned_identity")),"BUSINESS_PROOF_BINDING");
        need(number(value,"business_steps")==r.steps&&number(value,"model_requests")==r.modelRequests&&r.modelGeneration.equals(string(value,"model_generation")),"BUSINESS_PROOF_HISTORY");
        yes(value,"current_absence_verified","recovery_interval_physical_unchanged","foreign_dormant_history_preserved","cleanup_known","historical_model_exit_verified","historical_broker_release_observed");
        no(value,"automatic_resume","broker_release_response","business_dispatch_absent_in_original_receipts","rewrites_business_outcome","acknowledges_control_session");
        need(number(value,"old_boot_count")==r.oldBoot&&number(value,"current_boot_count")==boot&&number(value,"lease_expires_elapsed_ms")==r.expires
                &&number(value,"request_started_elapsed_ms")==r.started&&number(value,"deadline_elapsed_ms")==r.deadline,"BUSINESS_PROOF_CLOCK");
        long begin=number(value,"started_elapsed_ms"),end=number(value,"finished_elapsed_ms");need(begin>=r.started&&end>=begin&&end<=now&&end<r.deadline,"BUSINESS_PROOF_CLOCK");
        JSONObject first=value.getJSONObject("before"),last=value.getJSONObject("after");sample(first,r,begin,end);sample(last,r,begin,end);
        need(number(first,"finished_elapsed_ms")<=number(last,"started_elapsed_ms")&&same(first.getJSONObject("physical"),last.getJSONObject("physical"))
                &&number(first.getJSONObject("process"),"self_pid")==number(last.getJSONObject("process"),"self_pid")
                &&number(first.getJSONObject("process"),"self_start_ticks")==number(last.getJSONObject("process"),"self_start_ticks"),"BUSINESS_DOUBLE_SAMPLE");
        long age=(number(last,"finished_elapsed_ms")-number(first,"started_elapsed_ms"))/1000+2;
        PublicProfileRecentHistory.requireSameEvidence(first.getJSONObject("recents"),last.getJSONObject("recents"),r.target,age);
        return object(value.toString().getBytes(StandardCharsets.UTF_8));
    }
    private static void sample(JSONObject s,Request r,long begin,long end)throws Exception{
        ProfilePrelaunchRecovery.keys(s,"started_elapsed_ms","finished_elapsed_ms","process","live","recents","displays","physical","target_sha256");
        long a=number(s,"started_elapsed_ms"),b=number(s,"finished_elapsed_ms");need(a>=begin&&b>=a&&b<=end&&r.target.sha256.equals(string(s,"target_sha256")),"PUBLIC_RECOVERY_SAMPLE_CLOCK");
        JSONObject p=s.getJSONObject("process");ProfilePrelaunchRecovery.keys(p,"complete","old_creator_absent","started_elapsed_ms","finished_elapsed_ms","self_pid","self_start_ticks","process_count","inspected_count","inventory_sha256","model_worker_absent");
        need(Boolean.TRUE.equals(p.get("model_worker_absent"))&&Boolean.TRUE.equals(p.get("complete"))&&Boolean.TRUE.equals(p.get("old_creator_absent"))&&number(p,"started_elapsed_ms")>=a
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
    public static void requireController(JSONObject c,int uid)throws Exception{PublicProfileAbsenceRecovery.requireController(c,uid);}
    public static JSONObject object(byte[] b)throws Exception{return ProfilePrelaunchRecovery.object(b);}
    public static String string(JSONObject o,String k)throws Exception{return ProfilePrelaunchRecovery.string(o,k);}
    public static long number(JSONObject o,String k)throws Exception{return ProfilePrelaunchRecovery.number(o,k);}
    private static long numberAt(JSONArray a,int i)throws Exception{Object v=a.get(i);need(v instanceof Integer||v instanceof Long,"BUSINESS_INTEGER_ARRAY");return ((Number)v).longValue();}
    public static void need(boolean b,String error)throws IOException{if(!b)throw new IOException(error);}
    public static void keys(JSONObject o,String... names)throws Exception{ProfilePrelaunchRecovery.keys(o,names);}
    private static void yes(JSONObject o,String... names)throws Exception{for(String name:names)need(Boolean.TRUE.equals(o.get(name)),"BUSINESS_EXPECTED_TRUE_"+name);}
    private static void no(JSONObject o,String... names)throws Exception{for(String name:names)need(Boolean.FALSE.equals(o.get(name)),"BUSINESS_EXPECTED_FALSE_"+name);}
    public static boolean same(Object a,Object b)throws Exception{return canonical(a).equals(canonical(b));}
    /** Android's JSONObject stores these two performance rates as binary doubles.
     * Their nested app receipt can render the same bits with a shorter decimal.
     * No clock, count, identity, authority field or other profile value uses this rule. */
    public static boolean sameNativeRequestReceipt(JSONObject nativeValue,JSONObject appValue)throws Exception{
        JSONObject left=object(nativeValue.toString().getBytes(StandardCharsets.UTF_8)),right=object(appValue.toString().getBytes(StandardCharsets.UTF_8));
        JSONObject lp=left.getJSONObject("profile"),rp=right.getJSONObject("profile");
        for(String key:new String[]{"prefill_tokens_per_second","decode_tokens_per_second"}){
            Object a=lp.get(key),b=rp.get(key);
            if(!(a instanceof Number)||!(b instanceof Number))return false;
            double x=((Number)a).doubleValue(),y=((Number)b).doubleValue();
            if(!Double.isFinite(x)||!Double.isFinite(y)||Double.doubleToLongBits(x)!=Double.doubleToLongBits(y))return false;
            lp.put(key,0);rp.put(key,0);
        }
        return same(left,right);
    }
    public static String canonical(Object value)throws Exception{
        if(value==JSONObject.NULL)return "null";
        if(value instanceof JSONObject){JSONObject o=(JSONObject)value;TreeSet<String> names=new TreeSet<String>();Iterator<String> i=o.keys();while(i.hasNext())names.add(i.next());StringBuilder out=new StringBuilder("{");
            for(String k:names){if(out.length()>1)out.append(',');out.append(JSONObject.quote(k)).append(':').append(canonical(o.get(k)));}return out.append('}').toString();}
        if(value instanceof JSONArray){JSONArray a=(JSONArray)value;StringBuilder out=new StringBuilder("[");for(int i=0;i<a.length();i++){if(i>0)out.append(',');out.append(canonical(a.get(i)));}return out.append(']').toString();}
        if(value instanceof String)return JSONObject.quote((String)value);
        if(value instanceof Boolean||value instanceof Integer||value instanceof Long)return value.toString();
        // Immutable native receipts also contain finite decimal performance values.
        // All authority/clock/identity fields still use the strict integer accessor.
        if(value instanceof Number){
            need(Double.isFinite(((Number)value).doubleValue()),"BUSINESS_NONFINITE_JSON");
            java.math.BigDecimal n=new java.math.BigDecimal(value.toString()).stripTrailingZeros();
            return n.scale()<=0?n.toPlainString():n.toString();
        }
        need(false,"BUSINESS_JSON_TYPE");return null;
    }
    private static JSONObject without(JSONObject in,String... keys)throws Exception{JSONObject out=object(in.toString().getBytes(StandardCharsets.UTF_8));for(String k:keys)out.remove(k);return out;}
    private static void put(DataOutputStream out,byte[] raw)throws Exception{out.writeInt(raw.length);out.write(raw);}
}
