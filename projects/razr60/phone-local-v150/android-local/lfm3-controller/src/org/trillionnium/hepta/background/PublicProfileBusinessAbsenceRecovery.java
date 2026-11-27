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
    public static final String RETAINED_BUSINESS_SOURCE="fresh_public_profile_absence_after_unconfirmed_business_close";
    public static final String RETAINED_MODEL_DONE_SOURCE="fresh_public_profile_absence_after_verified_model_done_cleanup_failure";
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
                String path=names.next();requireRelative(path,taskId);JSONObject d=files.getJSONObject(path);requireDescriptor(d,ownerUid,originalLimit(path));
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
        if(path.matches("runs/[0-9a-f]{32}/vlm-task-(?:terminal|pending)\\.json")||
                path.matches("runs/[0-9a-f]{32}/vlm/[0-9a-f]{32}/(?:app-receipt\\.json|app-delivery\\.json|native-result\\.json|owner\\.json|raw\\.txt)"))known=true;
        need(known,"BUSINESS_PATH_NOT_ALLOWLISTED");
    }
    /** Build paths from typed identifiers. Recorded absolute paths are only cross-checks. */
    public static java.util.Set<String> visualModelPaths(JSONObject aggregate,String task,String logical)throws Exception {
        need(task.matches("[0-9a-f]{32}")&&logical.matches("[0-9a-f]{32}")&&!task.equals(logical)
                &&"hepta.vlm.task-aggregate.v1".equals(string(aggregate,"schema"))
                &&logical.equals(string(aggregate,"task_generation"))&&task.equals(string(aggregate,"task_id")),"BUSINESS_VISUAL_AGGREGATE_ID");
        JSONArray rows=aggregate.getJSONArray("requests");
        need(rows.length()>0&&rows.length()<=256,"BUSINESS_VISUAL_COUNT");
        TreeSet<String> paths=new TreeSet<String>(),ids=new TreeSet<String>();
        ids.add(task);ids.add(logical);
        String prefix="runs/"+logical+"/";
        paths.add(prefix+"vlm-task-terminal.json");paths.add(prefix+"vlm-task-pending.json");
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);
            String generation=string(row,"generation"),request=string(row,"request_id"),nonce=string(row.getJSONObject("generation_cleanup"),"cleanup_nonce");
            need(generation.matches("[0-9a-f]{32}")&&request.matches("[0-9a-f]{32}")&&nonce.matches("[0-9a-f]{32}")
                    &&ids.add(generation)&&ids.add(request)&&ids.add(nonce),"BUSINESS_VISUAL_REQUEST_ID");
            String worker="runs/"+generation+"/",round=worker+"vlm/"+request+"/";
            paths.add(worker+"worker-generation.identity");paths.add(worker+"generation-cleanup-"+nonce+".json");
            for(String leaf:new String[]{"app-receipt.json","app-delivery.json","native-result.json","owner.json","raw.txt"})paths.add(round+leaf);
        }
        return Collections.unmodifiableSet(paths);
    }

    public static boolean leaf(String name){return name!=null&&name.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,199}")&&!name.contains("..");}
    /** Task screenshots use the same 8 MiB bound as the observation producer. */
    public static int originalLimit(String relative){
        return relative.matches("control-tasks/[0-9a-f]{32}/[0-9a-f]{32}\\.png")?8*1024*1024:MAX_ORIGINAL;
    }
    public static void requireDescriptor(JSONObject d,int uid)throws Exception{requireDescriptor(d,uid,MAX_ORIGINAL);}
    public static void requireDescriptor(JSONObject d,int uid,int limit)throws Exception{
        keys(d,"bytes","sha256","device","inode","uid","mode","nlink","mtime_seconds","mtime_nanos","ctime_seconds","ctime_nanos");
        need(number(d,"bytes")>=0&&number(d,"bytes")<=limit&&ProfileIdentity.hash(string(d,"sha256"))
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
        public final boolean retainedBeforeFirstModel,retainedAfterBusiness,historicalBrokerExitObserved;
        public final boolean retainedModelDoneCleanupFailure;
        private final boolean closingResponseHistory;
        public final Integer historicalBrokerExitCode;
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
            String journalState=string(journal,"state");
            need("CLEANUP_UNKNOWN".equals(journalState)||"CLOSING".equals(journalState),"BUSINESS_LEASE_STATE");
            yes(journal,"profile_launch_attempted","profile_isolation_required","owned_task_retirement_required");
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
            closingResponseHistory="CLOSING".equals(string(cleanup.getJSONObject("last_broker_response"),"state"));
            String cleanupState=string(cleanup,"state");
            need("ACTIVE".equals(string(bootstrap,"state"))
                    &&("CLEANUP_UNKNOWN".equals(journalState)&&"CLEANUP_UNKNOWN".equals(cleanupState)
                        ||closingResponseHistory&&"CLOSING".equals(journalState)&&"CLOSING".equals(cleanupState)),
                    "BUSINESS_BACKGROUND_STATE");
            yes(bootstrap,"spawn_attempted");no(bootstrap,"retired");yes(cleanup,"retired","spawn_attempted");no(cleanup,"cleanup_known");
            need(cleanup.get("broker_process_exit_observed") instanceof Boolean,"BUSINESS_BROKER_EXIT_TYPE");
            historicalBrokerExitObserved=cleanup.getBoolean("broker_process_exit_observed");
            if(historicalBrokerExitObserved){long code=number(cleanup,"broker_process_exit_code");need(code>=0&&code<=255,"BUSINESS_BROKER_EXIT_RANGE");historicalBrokerExitCode=(int)code;}
            else{need(cleanup.get("broker_process_exit_code")==JSONObject.NULL,"BUSINESS_UNOBSERVED_EXIT_CODE");historicalBrokerExitCode=null;}
            retainedBeforeFirstModel=number(result,"steps")==0&&!historicalBrokerExitObserved;
            retainedAfterBusiness=number(result,"steps")>0&&(!historicalBrokerExitObserved||historicalBrokerExitCode!=0);
            retainedModelDoneCleanupFailure=retainedAfterBusiness&&Boolean.TRUE.equals(result.get("model_reported_success"));
            if(closingResponseHistory){
                need(retainedAfterBusiness&&!retainedBeforeFirstModel
                        &&"hepta.retained-profile-cleanup-bootstrap.v1".equals(string(journal,"retained_cleanup_schema"))
                        &&ProfileIdentity.hash(string(journal,"retained_cleanup_token_sha256"))
                        &&BrokerProtocol.retainedCleanupSocket(generation).equals(string(journal,"retained_cleanup_socket")),
                        "RETAINED_CLOSING_NOT_BUSINESS_CUSTODY");
            }else need("CLEANUP_UNKNOWN".equals(journalState),"BUSINESS_CLOSING_WITHOUT_FAILED_CLOSE");
            if(retainedBeforeFirstModel){
                no(cleanup,"broker_process_exit_observed");
                need(cleanup.get("broker_process_exit_code")==JSONObject.NULL,"BEFORE_MODEL_HISTORICAL_EXIT");
            }else if(retainedAfterBusiness){
                // A nonzero exit, including an independently observed maintenance
                // exit137, is a failed old broker fact. It never means release.
                need(!historicalBrokerExitObserved||historicalBrokerExitCode>0,"RETAINED_BUSINESS_HISTORICAL_EXIT");
            }else{
                yes(cleanup,"broker_process_exit_observed");
                need(number(cleanup,"broker_process_exit_code")==0,"BUSINESS_BROKER_EXIT");
            }
            JSONObject broker=object(task("background-broker-"+generation+".json")),finalBroker=cleanup.getJSONObject("broker_output");requireBroker(broker);requireBroker(finalBroker);
            need(same(broker,finalBroker)&&Boolean.TRUE.equals(broker.get("persisted")),"BUSINESS_BROKER_RECEIPT");byte[] output=task("background-broker-"+generation+".bin");
            need(number(broker,"stored_bytes")==output.length&&number(broker,"observed_bytes")==output.length&&ProfileIdentity.sha(output).equals(string(broker,"stored_sha256")),"BUSINESS_BROKER_BYTES");
            requireBootstrapPrefix(bootstrap.getJSONObject("broker_output"),broker,output);
            JSONObject owned=retainedBeforeFirstModel?retainedOrigin(bootstrap,cleanup,output):retainedAfterBusiness?retainedBusinessOrigin(bootstrap,cleanup,output):postBusinessOrigin(bootstrap,cleanup,output);ownedRootTaskId=(int)number(owned,"root_task_id");ownedLeafTaskId=(int)number(owned,"leaf_task_id");ownedLeafTaskToken=string(owned,"leaf_task_token");
            long count=number(result,"steps");need((count>0||retainedBeforeFirstModel)&&count>=0&&count<=256&&taskId.equals(string(result,"task_id"))&&"blocked".equals(string(result,"status")),"BUSINESS_TERMINAL");steps=(int)count;
            no(result,"cleanup_known","completion_verified","external_model","automatic_replay","controller_completion_requested");
            if(retainedModelDoneCleanupFailure)yes(result,"model_reported_success");else no(result,"model_reported_success");
            for(String k:new String[]{"observation_read_worker_pending_at_terminal","action_worker_pending_at_terminal","native_cancel_worker_pending_at_terminal"})no(result,k);
            if(!retainedModelDoneCleanupFailure)requireIncompleteModelDisposition(result);
            need(result.get("completion_actor")==JSONObject.NULL&&result.get("profile_permission_preparation")==JSONObject.NULL
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
            if(retainedBeforeFirstModel){requireNoModelOriginal(result,broker);modelRequests=0;}
            else if(originals.containsKey(modelPrefix+"vlm-task-terminal.json")){
                modelRequests=requireVisualClose(result.getJSONObject("model_session"),broker);
            }else{
                modelRequests=requireNormalModelClose(result.getJSONObject("model_session"),broker);
                requireOnlyBoundModelPaths();
            }
            if(retainedModelDoneCleanupFailure)requireModelDoneCleanupFailure(result,owner);
            requireControl(result,owner);
            journalSha256=ProfileIdentity.sha(original(JOURNAL));originalsSha256=ProfileIdentity.sha(canonical(inputHashes()));requireFence(started,requestBoot);
        }
        public byte[] task(String leaf)throws Exception{return original(taskPrefix+leaf);}
        public byte[] model(String leaf)throws Exception{return original(modelPrefix+leaf);}
        /** A verified read-only model claim followed by a failed retained close is
         * an origin for cleanup only. It never upgrades the old business outcome. */
        private void requireModelDoneCleanupFailure(JSONObject result,JSONObject owner)throws Exception{
            need(retainedAfterBusiness&&!retainedBeforeFirstModel&&"com.xiaomi.shop".equals(target.packageName)
                    &&"success".equals(string(result,"model_done_status"))&&!originals.containsKey(modelPrefix+"vlm-task-terminal.json"),
                    "BUSINESS_MODEL_DONE_CLEANUP_KIND");
            no(result,"model_done_synthesized","goal_independently_verified");
            String prefix=String.format(java.util.Locale.ROOT,"step-%02d-",steps);
            JSONObject recorded=object(task(prefix+"action.json")),action=recorded.getJSONObject("action");
            String run=string(recorded,"model_run_id"),observation=string(action,"observation_id"),auth=string(result,"task_authorization_sha256");
            need(run.matches("[0-9a-f]{32}")&&observation.matches("[0-9a-f]{32}")&&"done".equals(string(action,"action"))
                    &&"success".equals(string(action,"status"))&&target.packageName.equals(string(action,"package"))
                    &&string(result,"model_done_summary").equals(string(action,"summary"))&&auth.equals(string(recorded,"task_authorization_sha256"))
                    &&recorded.get("ime_submit")==JSONObject.NULL&&recorded.get("fixed_intent")==JSONObject.NULL,"BUSINESS_MODEL_DONE_ACTION");
            yes(recorded,"accepted","done_success_eligible","model_issued");no(recorded,"dispatched","stale");
            JSONObject execution=recorded.getJSONObject("action_execution");
            need(same(execution,result.getJSONObject("last_action_execution"))&&run.equals(string(execution,"model_run_id"))
                    &&observation.equals(string(execution,"observation_id"))&&auth.equals(string(execution,"authorization_sha256"))
                    &&execution.get("api_accepted")==JSONObject.NULL&&execution.get("retirement_reason")==JSONObject.NULL,"BUSINESS_MODEL_DONE_EXECUTION");
            yes(execution,"worker_drained","callback_published","callback_authority_current");
            no(execution,"effect_entered","effect_returned","retired","automatic_redispatch");
            int matches=0;
            for(String leaf:manifest.taskFiles()){
                if(!leaf.startsWith(prefix+"model-")||!leaf.matches("step-[0-9]+-model-[0-9]+\\.json"))continue;
                JSONObject model=object(task(leaf));if(!run.equals(string(model,"run_id")))continue;
                need(ownerSha256.equals(string(model,"original_instruction_sha256"))&&observation.equals(string(model,"observation_id"))
                        &&same(action,object(string(model,"raw_text").getBytes(StandardCharsets.UTF_8))),"BUSINESS_MODEL_DONE_RAW");
                matches++;
            }
            need(matches==1,"BUSINESS_MODEL_DONE_RAW");
            JSONObject check=object(task(prefix+"completion-check.json")),completion=result.getJSONObject("completion_evidence");
            need("hepta.task-completion.v1".equals(string(check,"schema"))&&"native_product_price".equals(string(check,"kind"))
                    &&taskId.equals(string(check,"task_id"))&&ownerSha256.equals(string(check,"owner_sha256"))
                    &&generation.equals(string(check,"background_generation"))&&displayId==number(check,"display_id")
                    &&"controller_observation_checks_not_model_claims".equals(string(check,"source"))
                    &&number(check,"check_step")==steps&&run.equals(string(check,"check_model_run_id"))
                    &&check.get("identity_failure")==JSONObject.NULL&&check.getJSONArray("missing").length()==0,"BUSINESS_MODEL_DONE_CHECK");
            yes(check,"completion_verified","model_reported_success","accepted_as_completed","final_observation_stable");
            no(check,"retry_allowed","grants_tool_authority","writes_required_for_unknown_or_read_only_goal");
            need("hepta.native-app-terminal-completion.v1".equals(string(completion,"schema"))&&"native_product_price".equals(string(completion,"kind"))
                    &&taskId.equals(string(completion,"task_id"))&&ownerSha256.equals(string(completion,"owner_sha256"))
                    &&generation.equals(string(completion,"background_generation"))&&displayId==number(completion,"display_id")
                    &&auth.equals(string(completion,"authorization_sha256"))&&completion.get("identity_failure")==JSONObject.NULL
                    &&completion.get("completion_actor")==JSONObject.NULL&&completion.get("controller_native_parent_session_bound")==JSONObject.NULL
                    &&completion.get("profile_cleanup")==JSONObject.NULL,"BUSINESS_MODEL_DONE_TERMINAL");
            yes(completion,"one_terminal_attempt","action_domain_retired","same_final_native_result_snapshot","model_success_claim_verified",
                    "observation_chain_verified","native_normal0_parent_session_bound","scope_rechecked_after_worker_exit",
                    "installed_app_rechecked_after_cleanup","owner_rechecked");
            no(completion,"completion_verified","business_verified","all_cleanup_known","background_released",
                    "terminal_binding_and_cleanup_verified","profile_cleanup_bound_to_final_window","cancelled","grants_tool_authority",
                    "model_done_synthesized","controller_completion_requested");
            need(completion.getJSONArray("missing").length()==1&&"native_final_task_identity_or_query_or_cleanup_missing".equals(completion.getJSONArray("missing").get(0)),
                    "BUSINESS_MODEL_DONE_MISSING");
            for(String key:new String[]{"kind","owner_sha256","contract_sha256","source","task_id","contract","native_app","proofs","model_success_claims",
                    "public_native_result","display_id","background_generation"})need(same(check.get(key),completion.get(key)),"BUSINESS_MODEL_DONE_CHECK_BINDING");
            JSONObject terminal=completion.getJSONObject("terminal_native_completion");
            Iterator<String> terminalKeys=terminal.keys();while(terminalKeys.hasNext()){
                String key=terminalKeys.next();need(same(terminal.get(key),completion.get(key)),"BUSINESS_MODEL_DONE_TERMINAL_BINDING");
            }
            need("hepta.native-app-terminal-completion.v1".equals(string(terminal,"schema"))&&terminal.has("model_success_claim_verified")
                    &&terminal.has("business_verified")&&terminal.has("worker_receipt_sha256")&&terminal.has("profile_cleanup"),"BUSINESS_MODEL_DONE_TERMINAL_BINDING");
            JSONObject targetEvidence=owner.getJSONObject("task_authorization").getJSONObject("execution_target");
            JSONObject publicResult=completion.getJSONObject("public_native_result"),retired=object(task("native-app-retired.json"));
            for(JSONObject row:new JSONObject[]{completion,publicResult,retired}){
                need(taskId.equals(string(row,"task_id"))&&ownerSha256.equals(string(row,"owner_sha256"))&&auth.equals(string(row,"authorization_sha256"))
                        &&string(targetEvidence,"target_sha256").equals(string(row,"execution_target_sha256"))
                        &&same(targetEvidence.get("profile_target"),row.get("profile_target"))
                        &&target.sha256.equals(string(row.getJSONObject("profile_target"),"target_identity_sha256")),"BUSINESS_MODEL_DONE_OWNER_BINDING");
            }
            need("hepta.native-xiaomi-displayed-product-price.v1".equals(string(publicResult,"schema"))
                    &&"hepta.native-app-session.v1".equals(string(retired,"schema"))&&retired.get("invalid_reason")==JSONObject.NULL,"BUSINESS_MODEL_DONE_RETIRED");
            no(publicResult,"business_verified_before_terminal","external_model");
            yes(retired,"action_domain_retired","accepted_completion_candidate");no(retired,"pending_action","invalid");
            JSONObject frame=publicResult.getJSONObject("current_frame"),after=object(task(prefix+"after.json")),before=object(task(prefix+"before.json"));
            need("hepta.native-app-observation.v1".equals(string(frame,"schema"))&&taskId.equals(string(frame,"task_id"))
                    &&ownerSha256.equals(string(frame,"owner_sha256"))&&auth.equals(string(frame,"task_authorization_sha256"))
                    &&string(result,"final_observation_id").equals(string(frame,"observation_id"))&&target.packageName.equals(string(frame,"package"))
                    &&generation.equals(string(frame,"background_generation"))&&displayId==number(frame,"display_id")
                    &&observation.equals(string(before,"observation_id"))&&target.packageName.equals(string(before,"package")),"BUSINESS_MODEL_DONE_FRAME");
            for(String key:new String[]{"observation_id","package","captured_elapsed_ms","window_id","app_tree_sha256","observation_state_sha256"})
                need(same(frame.get(key),after.get(key)),"BUSINESS_MODEL_DONE_FRAME_BINDING");
            JSONObject capture=frame.getJSONObject("capture"),publication=after.getJSONObject("capture");
            need(same(capture,after.getJSONObject("ax_capture")),"BUSINESS_MODEL_DONE_CAPTURE");
            Iterator<String> captureKeys=capture.keys();while(captureKeys.hasNext()){
                String key=captureKeys.next();need(same(capture.get(key),publication.get(key)),"BUSINESS_MODEL_DONE_CAPTURE");
            }
            String receipt=string(frame,"observation_id")+"-native-ax.json";
            need("native_ax".equals(string(capture,"kind"))&&"hepta.native-ax-capture.v1".equals(string(capture,"receipt_schema"))
                    &&receipt.equals(string(capture,"receipt_file"))&&number(capture,"receipt_bytes")==task(receipt).length
                    &&ProfileIdentity.sha(task(receipt)).equals(string(capture,"receipt_sha256")),"BUSINESS_MODEL_DONE_CAPTURE");
            yes(capture,"full_two_censuses");no(capture,"business_completion_verified","grants_action_authority","publication_refreshes_capture_age","screenshot_present");
            yes(frame,"actual_collection_complete","window_metadata_observed");no(frame,"nodes_truncated","screenshots_used_as_text");
            JSONObject window=frame.getJSONObject("actual_profile_window");
            need(same(window,completion.getJSONObject("final_actual_profile_window"))
                    &&"hepta.profile-window-ownership.v1".equals(string(window,"schema"))&&generation.equals(string(window,"generation"))
                    &&target.sha256.equals(string(window,"target_identity_sha256"))&&number(window,"display_id")==displayId
                    &&number(window,"task_id")==ownedLeafTaskId&&number(window,"parent_task_id")==ownedRootTaskId
                    &&ownedLeafTaskToken.equals(string(window,"task_token_id"))&&number(window,"full_uid")==target.fullUid
                    &&number(window,"user_id")==target.profile.userId&&number(window,"user_serial")==target.profile.serial,"BUSINESS_MODEL_DONE_WINDOW");
            no(window,"serialized_token_is_authority","grants_action_authority");
            long captured=number(after,"captured_elapsed_ms"),drained=number(execution,"worker_drained_elapsed_ms");
            need(number(before,"captured_elapsed_ms")>=created&&number(before,"captured_elapsed_ms")<=number(execution,"queued_elapsed_ms")
                    &&drained<=captured&&captured<=number(result,"terminal_decided_elapsed_ms"),"BUSINESS_MODEL_DONE_CLOCK");
            need(taskId.equals(string(completion,"worker_task_id"))&&modelGeneration.equals(string(completion,"worker_generation"))
                    &&ProfileIdentity.sha(model("app-session-receipt.json")).equals(string(completion,"worker_receipt_sha256")),
                    "BUSINESS_MODEL_DONE_WORKER");
        }
        private void requireIncompleteModelDisposition(JSONObject result)throws Exception{
            if(result.get("model_done_status")==JSONObject.NULL)return;
            need(steps>0&&"failure".equals(result.get("model_done_status")),"BUSINESS_MODEL_DISPOSITION");
            no(result,"model_done_synthesized");
            String prefix=String.format(java.util.Locale.ROOT,"step-%02d-",steps);
            JSONObject controller=object(task(prefix+"controller-terminal.json")),action=controller.getJSONObject("action");
            String observation=string(result,"final_observation_id"),run=string(controller,"model_run_id");
            need("hepta.controller-incomplete-terminal.v1".equals(string(controller,"schema"))&&"controller".equals(string(controller,"actor"))
                    &&taskId.equals(string(controller,"task_id"))&&number(controller,"step")==steps&&"failed".equals(string(controller,"terminal_status"))
                    &&observation.matches("[0-9a-f]{32}")&&observation.equals(string(controller,"observation_id"))&&run.matches("[0-9a-f]{32}")
                    &&string(result,"task_authorization_sha256").equals(string(controller,"task_authorization_sha256"))
                    &&controller.get("action_execution")==JSONObject.NULL,"BUSINESS_MODEL_TERMINAL_BINDING");
            yes(controller,"model_issued","accepted","terminal_accepted");
            no(controller,"dispatched","service_perform_called","stale","business_completion_verified");
            need("done".equals(string(action,"action"))&&"failure".equals(string(action,"status"))&&target.packageName.equals(string(action,"package"))
                    &&observation.equals(string(action,"observation_id"))&&string(result,"model_done_summary").equals(string(action,"summary")),
                    "BUSINESS_MODEL_TERMINAL_ACTION");
            int matches=0;
            for(String leaf:manifest.taskFiles()){
                if(!leaf.startsWith(prefix+"model-")||!leaf.matches("step-[0-9]+-model-[0-9]+\\.json"))continue;
                JSONObject model=object(task(leaf));
                if(!run.equals(string(model,"run_id")))continue;
                need(ownerSha256.equals(string(model,"original_instruction_sha256"))&&observation.equals(string(model,"observation_id"))
                        &&same(action,object(string(model,"raw_text").getBytes(StandardCharsets.UTF_8))),"BUSINESS_MODEL_TERMINAL_RECEIPT");
                matches++;
            }
            need(matches==1,"BUSINESS_MODEL_TERMINAL_RECEIPT");
            long begin=number(controller,"controller_started_elapsed_ms"),end=number(controller,"controller_consumed_elapsed_ms");
            need(created<=begin&&begin<=end&&end<=number(result,"terminal_decided_elapsed_ms"),"BUSINESS_MODEL_TERMINAL_CLOCK");
        }
        private long requireLastAction(JSONObject result,long terminal)throws Exception{
            if(result.get("last_action_execution")==JSONObject.NULL)return created;
            JSONObject a=result.getJSONObject("last_action_execution");need("hepta.action-execution.v1".equals(string(a,"schema"))&&taskId.equals(string(a,"task_id"))
                    &&generation.equals(string(a,"background_generation"))&&number(a,"display_id")==displayId,"BUSINESS_LAST_ACTION_IDENTITY");
            yes(a,"worker_drained","callback_published");no(a,"automatic_redispatch");
            long queued=number(a,"queued_elapsed_ms"),drained=number(a,"worker_drained_elapsed_ms");need(queued>=created&&drained>=queued&&drained<=terminal,"BUSINESS_LAST_ACTION_CLOCK");
            need(a.get("effect_entered") instanceof Boolean&&a.get("effect_returned") instanceof Boolean,"BUSINESS_LAST_ACTION_TYPE");
            if(Boolean.TRUE.equals(a.get("effect_entered")))yes(a,"effect_returned");return drained;
        }
        private JSONObject retainedOrigin(JSONObject bootstrap,JSONObject cleanup,byte[] output)throws Exception{
            int half=output.length/2;
            need(half>1&&output.length==2*half&&output[half-1]=='\n'&&output[output.length-1]=='\n'
                    &&Arrays.equals(Arrays.copyOf(output,half),Arrays.copyOfRange(output,half,output.length)),"RETAINED_BROKER_RECORDS");
            for(int i=0;i<half-1;i++)need(output[i]!='\n'&&output[i]!='\r',"RETAINED_BROKER_RECORD_BOUNDARY");
            JSONObject terminal=object(Arrays.copyOf(output,half-1)),first=bootstrap.getJSONObject("last_broker_response"),last=cleanup.getJSONObject("last_broker_response");
            requireHistoricalResponse(first,bootstrap.getJSONObject("app_display_readback"));
            need("launch".equals(string(first,"operation"))&&Boolean.TRUE.equals(first.get("dispatched")),"RETAINED_BOOTSTRAP_LAUNCH");
            need("hepta.background-broker-terminal.v1".equals(string(terminal,"schema"))&&"client_close".equals(string(terminal,"reason"))
                    &&"CLEANUP_UNKNOWN".equals(string(terminal,"state"))&&generation.equals(string(terminal,"generation"))
                    &&displayId==number(terminal,"display_id")&&publicScope.sha256.equals(string(terminal,"display_scope_sha256"))
                    &&terminal.get("owned_single_task")==JSONObject.NULL&&terminal.get("boot_count_read_retirement_failure")==JSONObject.NULL,"RETAINED_BROKER_TERMINAL");
            yes(terminal,"public_scope_admission_retired","profile_custody_retained");no(terminal,"release_confirmed");
            need(number(last,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION&&ProfileIdentity.uuid(string(last,"request_id"))
                    &&"close".equals(string(last,"operation"))&&"CLEANUP_NOT_CONFIRMED".equals(string(last,"error"))
                    &&"CLEANUP_UNKNOWN".equals(string(last,"state"))&&displayName.equals(string(last,"display_name"))
                    &&generation.equals(string(last,"generation"))&&displayId==number(last,"display_id")&&expires==number(last,"expires_elapsed_ms")
                    &&publicScope.sha256.equals(string(last,"display_scope_sha256")),"RETAINED_CLOSE_RESPONSE");
            yes(last,"public_scope_admission_retired","public_scope_closing","profile_custody_retained");no(last,"ok","dispatched");
            need(target.wire().equals(string(last,"profile_target_wire"))&&last.get("public_own_group_readback_wire")==JSONObject.NULL,"RETAINED_CLOSE_PROFILE");
            JSONObject openRead=bootstrap.getJSONObject("app_display_readback"),lastRead=cleanup.getJSONObject("app_display_readback");
            String[] volatileReadFields={"broker_request_id","broker_readback_sha256","observed_started_elapsed_ms","observed_ended_elapsed_ms"};
            need(same(without(openRead,volatileReadFields),without(lastRead,volatileReadFields))
                    &&ProfileIdentity.uuid(string(lastRead,"broker_request_id"))&&ProfileIdentity.hash(string(lastRead,"broker_readback_sha256"))
                    &&number(lastRead,"observed_started_elapsed_ms")>=number(openRead,"observed_ended_elapsed_ms")
                    &&number(lastRead,"observed_ended_elapsed_ms")>=number(lastRead,"observed_started_elapsed_ms")
                    &&number(lastRead,"observed_ended_elapsed_ms")<expires,"RETAINED_LAST_APP_READBACK");

            JSONObject end=terminal.getJSONObject("profile_cleanup"),begin=first.getJSONObject("profile_cleanup");
            need(same(end,last.getJSONObject("profile_cleanup"))&&same(terminal.getJSONObject("profile_last_leaf_validation"),last.getJSONObject("profile_last_leaf_validation"))
                    &&same(terminal.getJSONObject("public_surface_detach"),last.getJSONObject("public_surface_detach")),"RETAINED_CLOSE_BINDING");
            JSONObject detach=terminal.getJSONObject("public_surface_detach");
            yes(detach,"admission_irrevocably_retired","worker_finished");no(detach,"provides_task_or_display_cleanup_proof","allows_input_or_model_resumption");
            need("API_RETURNED_UNVERIFIED".equals(string(detach,"state")),"RETAINED_SURFACE_NOT_PROOF");
            need("hepta.profile-task-cleanup.v1".equals(string(begin,"schema"))&&generation.equals(string(begin,"generation"))
                    &&number(begin,"display_id")==displayId&&target.sha256.equals(string(begin,"target_sha256"))
                    &&number(begin,"user_id")==target.profile.userId&&number(begin,"user_serial")==target.profile.serial&&number(begin,"full_uid")==target.fullUid
                    &&same(without(begin,"identity_unknown","public_foreign_recent_history"),without(end,"identity_unknown","public_foreign_recent_history")),"RETAINED_TASK_BINDING");
            no(begin,"identity_unknown","cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present");yes(end,"identity_unknown");
            JSONArray tasks=begin.getJSONArray("owned_tasks");need(tasks.length()==1,"RETAINED_TASK_COUNT");JSONObject owned=tasks.getJSONObject(0);
            long root=number(owned,"parent_task_id"),leaf=number(owned,"task_id");String token=string(owned,"task_token_id");
            need(root>0&&root<=Integer.MAX_VALUE&&leaf>0&&leaf<=Integer.MAX_VALUE&&root!=leaf&&ProfileIdentity.uuid(token)
                    &&number(owned,"user_id")==target.profile.userId&&number(owned,"user_serial")==target.profile.serial&&number(owned,"full_uid")==target.fullUid,"RETAINED_TASK_OWNER");
            no(owned,"live_absent","recents_absent");requireHistoricalLeaf(first.getJSONObject("profile_last_leaf_validation"),root,leaf);
            requireHistoricalLeaf(terminal.getJSONObject("profile_last_leaf_validation"),root,leaf);
            JSONObject before=begin.getJSONObject("public_foreign_recent_history"),after=end.getJSONObject("public_foreign_recent_history");
            requireHistoricalHistory(before,root,leaf,false);requireHistoricalHistory(after,root,leaf,true);
            for(String key:new String[]{"schema","target_sha256","baseline_elapsed_ms","baseline_raw_sha256","baseline_task_ids","owned_task_ids","protected_history_sha256"})
                need(same(before.get(key),after.get(key)),"RETAINED_HISTORY_BINDING");
            return new JSONObject().put("root_task_id",root).put("leaf_task_id",leaf).put("leaf_task_token",token);
        }
        /** Preserve an actual failed retained broker after completed model work.
         * These records establish origin only. Current native process/task/display
         * absence remains mandatory and is never inferred from any old flag. */
        /** Ordinary retained origins compare every complete capture before
         * projecting the already validated optional phase diagnostic. This
         * package-visible pure comparator creates no cleanup or input authority. */
        static JSONObject retainedBusinessCaptureFields(JSONObject terminal,JSONObject last)throws Exception{
            JSONObject end=terminal.getJSONObject("profile_cleanup");
            need(same(end,last.getJSONObject("profile_cleanup"))&&same(terminal.getJSONObject("profile_last_leaf_validation"),last.getJSONObject("profile_last_leaf_validation"))
                    &&same(terminal.getJSONObject("public_surface_detach"),last.getJSONObject("public_surface_detach")),"RETAINED_BUSINESS_CAPTURE_BINDING");
            return releasedCleanupFieldView(end);
        }
        private JSONObject retainedBusinessOrigin(JSONObject bootstrap,JSONObject cleanup,byte[] output)throws Exception{
            JSONObject terminal=retainedBusinessTerminal(output),first=bootstrap.getJSONObject("last_broker_response"),last=cleanup.getJSONObject("last_broker_response");
            requireHistoricalResponse(first,bootstrap.getJSONObject("app_display_readback"));
            need("launch".equals(string(first,"operation"))&&Boolean.TRUE.equals(first.get("dispatched")),"RETAINED_BUSINESS_LAUNCH");
            need("hepta.background-broker-terminal.v1".equals(string(terminal,"schema"))&&"CLEANUP_UNKNOWN".equals(string(terminal,"state"))
                    &&generation.equals(string(terminal,"generation"))&&displayId==number(terminal,"display_id")
                    &&publicScope.sha256.equals(string(terminal,"display_scope_sha256"))&&terminal.get("owned_single_task")==JSONObject.NULL
                    &&terminal.get("boot_count_read_retirement_failure")==JSONObject.NULL,"RETAINED_BUSINESS_TERMINAL");
            yes(terminal,"public_scope_admission_retired","profile_custody_retained");no(terminal,"release_confirmed");
            String reason=string(terminal,"reason");need("client_close".equals(reason)||reason.matches("[A-Z0-9_]{1,96}"),"RETAINED_BUSINESS_REASON");
            need(number(last,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION&&ProfileIdentity.uuid(string(last,"request_id"))
                    &&(closingResponseHistory?"CLOSING":"CLEANUP_UNKNOWN").equals(string(last,"state"))&&generation.equals(string(last,"generation"))
                    &&displayId==number(last,"display_id")&&displayName.equals(string(last,"display_name"))&&expires==number(last,"expires_elapsed_ms")
                    &&publicScope.sha256.equals(string(last,"display_scope_sha256"))&&target.wire().equals(string(last,"profile_target_wire"))
                    &&string(last,"operation").matches("[a-z_]{1,64}")&&last.get("public_own_group_readback_wire")==JSONObject.NULL,"RETAINED_BUSINESS_FAILED_RESPONSE");
            yes(last,"public_scope_admission_retired","public_scope_closing","profile_custody_retained");no(last,"ok","dispatched");
            String error=string(last,"error");
            need((!closingResponseHistory&&"PUBLIC_SCOPE_RETIRED".equals(error))
                    ||"close".equals(string(last,"operation"))&&"CLEANUP_NOT_CONFIRMED".equals(error),
                    "RETAINED_BUSINESS_RESPONSE_ERROR");
            if(last.has("terminal_reason"))need(reason.equals(string(last,"terminal_reason")),"RETAINED_BUSINESS_TERMINAL_REASON");
            JSONObject openRead=bootstrap.getJSONObject("app_display_readback"),lastRead=cleanup.getJSONObject("app_display_readback");
            String[] volatileReadFields={"broker_request_id","broker_readback_sha256","observed_started_elapsed_ms","observed_ended_elapsed_ms"};
            need(same(without(openRead,volatileReadFields),without(lastRead,volatileReadFields))
                    &&ProfileIdentity.uuid(string(lastRead,"broker_request_id"))&&ProfileIdentity.hash(string(lastRead,"broker_readback_sha256"))
                    &&number(lastRead,"observed_started_elapsed_ms")>=number(openRead,"observed_ended_elapsed_ms")
                    &&number(lastRead,"observed_ended_elapsed_ms")>=number(lastRead,"observed_started_elapsed_ms")
                    &&number(lastRead,"observed_ended_elapsed_ms")<expires,"RETAINED_BUSINESS_LAST_READBACK");
            JSONObject begin=first.getJSONObject("profile_cleanup"),end=terminal.getJSONObject("profile_cleanup");
            if(closingResponseHistory){
                need(same(terminal.getJSONObject("profile_last_leaf_validation"),last.getJSONObject("profile_last_leaf_validation"))
                        &&same(terminal.getJSONObject("public_surface_detach"),last.getJSONObject("public_surface_detach")),"RETAINED_BUSINESS_CAPTURE_BINDING");
                if(!same(end,last.getJSONObject("profile_cleanup")))requireClosingUnknownProgress(terminal,last);
            }else{
                end=retainedBusinessCaptureFields(terminal,last);
            }
            keys(closingResponseHistory?releasedCleanupFieldView(end):end,"schema","generation","display_id","target_sha256","user_id","user_serial","full_uid","cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown","owned_tasks","public_foreign_recent_history","recents_absence_scope");
            for(String key:new String[]{"schema","generation","display_id","target_sha256","user_id","user_serial","full_uid","recents_absence_scope"})
                need(same(begin.get(key),end.get(key)),"RETAINED_BUSINESS_CUSTODY_IDENTITY");
            need("hepta.profile-task-cleanup.v1".equals(string(end,"schema"))&&generation.equals(string(end,"generation"))&&number(end,"display_id")==displayId
                    &&target.sha256.equals(string(end,"target_sha256"))&&number(end,"user_id")==target.profile.userId&&number(end,"user_serial")==target.profile.serial
                    &&number(end,"full_uid")==target.fullUid,"RETAINED_BUSINESS_CUSTODY_OWNER");
            for(String key:new String[]{"cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown"})
                need(end.get(key) instanceof Boolean,"RETAINED_BUSINESS_CUSTODY_FLAGS");
            no(begin,"cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown");
            JSONArray oldRows=begin.getJSONArray("owned_tasks"),rows=end.getJSONArray("owned_tasks");need(oldRows.length()==1&&rows.length()==1,"RETAINED_BUSINESS_OWNED_COUNT");
            JSONObject owned=rows.getJSONObject(0),old=oldRows.getJSONObject(0);
            keys(owned,"task_id","parent_task_id","task_token_id","user_id","user_serial","full_uid","live_absent","recents_absent");
            need(same(without(owned,"live_absent","recents_absent"),without(old,"live_absent","recents_absent"))
                    &&owned.get("live_absent") instanceof Boolean&&owned.get("recents_absent") instanceof Boolean,"RETAINED_BUSINESS_OWNED_BINDING");
            no(old,"live_absent","recents_absent");
            long root=number(owned,"parent_task_id"),leaf=number(owned,"task_id");String token=string(owned,"task_token_id");
            need(root>0&&root<=Integer.MAX_VALUE&&leaf>0&&leaf<=Integer.MAX_VALUE&&root!=leaf&&ProfileIdentity.uuid(token)
                    &&number(owned,"user_id")==target.profile.userId&&number(owned,"user_serial")==target.profile.serial&&number(owned,"full_uid")==target.fullUid,"RETAINED_BUSINESS_OWNED_IDENTITY");
            requireHistoricalLeaf(first.getJSONObject("profile_last_leaf_validation"),root,leaf);requireHistoricalLeaf(terminal.getJSONObject("profile_last_leaf_validation"),root,leaf);
            JSONObject prior=begin.getJSONObject("public_foreign_recent_history"),history=end.getJSONObject("public_foreign_recent_history");
            requireHistoricalHistory(prior,root,leaf,false);
            for(String key:new String[]{"schema","target_sha256","baseline_elapsed_ms","baseline_raw_sha256","baseline_task_ids","owned_task_ids"})
                need(same(prior.get(key),history.get(key)),"RETAINED_BUSINESS_HISTORY_ORIGIN");
            need(number(history,"current_elapsed_ms")>=number(history,"baseline_elapsed_ms")&&number(history,"current_elapsed_ms")<=started,"RETAINED_BUSINESS_HISTORY_CLOCK");
            for(String key:new String[]{"foreign_dormant_history_preserved","history_refusal_latched","owned_target_absent"})need(history.get(key) instanceof Boolean,"RETAINED_BUSINESS_HISTORY_FLAG");
            no(history,"serialized_task_ids_grant_authority");
            for(String key:new String[]{"current_raw_sha256","nonowned_history_sha256"})need(ProfileIdentity.hash(string(history,key)),"RETAINED_BUSINESS_HISTORY_HASH");
            boolean refused=history.getBoolean("history_refusal_latched");
            need(refused?history.get("history_refusal_reason") instanceof String&&string(history,"history_refusal_reason").matches("[A-Z0-9_]{1,96}")
                    :history.get("history_refusal_reason")==JSONObject.NULL,"RETAINED_BUSINESS_HISTORY_REFUSAL");
            if(refused)no(history,"foreign_dormant_history_preserved");
            if("hepta.public-profile-history-custody.v2".equals(string(history,"schema"))){
                need("nonphysical_and_unresolved_recents".equals(string(history,"history_preservation_scope")),"RETAINED_BUSINESS_HISTORY_SCOPE");
                for(String key:new String[]{"nonphysical_history_preserved","unrelated_physical_history_changes_observed","recents_presentation_changes_observed"})
                    need(history.get(key) instanceof Boolean,"RETAINED_BUSINESS_HISTORY_FLAG");
                no(history,"physical_history_frozen");if(refused)no(history,"nonphysical_history_preserved");
                for(String key:new String[]{"protected_history_sha256","current_protected_history_sha256"})need(ProfileIdentity.hash(string(history,key)),"RETAINED_BUSINESS_HISTORY_HASH");
                need(same(prior.get("protected_history_sha256"),history.get("protected_history_sha256")),"RETAINED_BUSINESS_HISTORY_BASELINE");
            }
            JSONObject detach=terminal.getJSONObject("public_surface_detach");yes(detach,"admission_irrevocably_retired","worker_finished");
            no(detach,"provides_task_or_display_cleanup_proof","allows_input_or_model_resumption");
            need("API_RETURNED_UNVERIFIED".equals(string(detach,"state")),"RETAINED_BUSINESS_SURFACE_NOT_ABSENCE");
            return new JSONObject().put("root_task_id",root).put("leaf_task_id",leaf).put("leaf_task_token",token);
        }
        private JSONObject retainedBusinessTerminal(byte[] output)throws Exception{
            if(closingResponseHistory)return retainedClosingTerminals(output);
            int newline=-1;for(int i=0;i<output.length;i++)if(output[i]=='\n'){newline=i;break;}
            need(newline>0&&output.length%(newline+1)==0,"RETAINED_BUSINESS_TERMINAL_BOUNDARY");int records=output.length/(newline+1);
            need(records==1||records==2,"RETAINED_BUSINESS_TERMINAL_COUNT");
            for(int i=0;i<newline;i++)need(output[i]!='\r',"RETAINED_BUSINESS_TERMINAL_BOUNDARY");
            if(records==2)need(Arrays.equals(Arrays.copyOf(output,newline+1),Arrays.copyOfRange(output,newline+1,output.length)),"RETAINED_BUSINESS_TERMINAL_CHANGED");
            return object(Arrays.copyOf(output,newline));
        }
        /** A failed close reply can precede the broker's quarantine publication.
         * Keep both originals: only the exact false-to-true unknown transition
         * is admitted, never an absence or release assertion. */
        private void requireClosingUnknownProgress(JSONObject terminal,JSONObject response)throws Exception{
            need(closingResponseHistory,"RETAINED_BUSINESS_CAPTURE_BINDING");
            JSONObject before=response.getJSONObject("profile_cleanup"),after=terminal.getJSONObject("profile_cleanup");
            need(same(without(before,"identity_unknown"),without(after,"identity_unknown")),
                    "RETAINED_CLOSING_UNKNOWN_FIELDS_CHANGED");
            no(before,"identity_unknown","cleanup_known","live_tasks_absent","recents_tasks_absent");
            yes(after,"identity_unknown");no(after,"cleanup_known","live_tasks_absent","recents_tasks_absent");
            JSONObject prior=response.getJSONObject("profile_cleanup_diagnostics"),current=terminal.getJSONObject("profile_cleanup_diagnostics");
            String[] diagnosticKeys={"schema","first_failure","provides_cleanup_proof","allows_input_or_model_resumption","diagnostics_grant_authority"};
            keys(prior,diagnosticKeys);keys(current,diagnosticKeys);
            need("hepta.profile-cleanup-diagnostics.v1".equals(string(current,"schema"))
                    &&same(without(prior,"first_failure"),without(current,"first_failure"))
                    &&prior.get("first_failure")==JSONObject.NULL,"RETAINED_CLOSING_FAILURE_BINDING");
            no(current,"provides_cleanup_proof","allows_input_or_model_resumption","diagnostics_grant_authority");
            JSONObject failure=current.getJSONObject("first_failure");
            keys(failure,"phase","code","cleanup_started_elapsed_ms","task_reads_deadline_elapsed_ms","observed_elapsed_ms");
            long began=number(failure,"cleanup_started_elapsed_ms"),limit=number(failure,"task_reads_deadline_elapsed_ms");
            long observed=number(failure,"observed_elapsed_ms");
            need("TASK_RETIRE".equals(string(failure,"phase"))&&"PROFILE_CLEANUP_DEADLINE".equals(string(failure,"code"))
                    &&created<=began&&began==number(terminal.getJSONObject("public_surface_detach"),"began_elapsed_ms")
                    &&began<limit&&limit<observed&&observed<=started,"RETAINED_CLOSING_FAILURE_CLOCK_OR_KIND");
        }
        /** One complete retired snapshot, or a bounded pair spanning the last
         * normal cleanup read. Return only the first close-bound snapshot as
         * history; neither record is a fresh absence capability. */
        private JSONObject retainedClosingTerminals(byte[] output)throws Exception{
            need(retainedAfterBusiness&&!retainedBeforeFirstModel&&output.length>0&&output.length<=65536,
                    "RETAINED_CLOSING_TERMINAL_SCOPE");
            int firstEnd=-1,secondEnd=-1;
            for(int i=0;i<output.length;i++){
                need(output[i]!='\r',"RETAINED_CLOSING_TERMINAL_BOUNDARY");
                if(output[i]=='\n'){if(firstEnd<0)firstEnd=i;else if(secondEnd<0)secondEnd=i;
                    else throw new IOException("RETAINED_CLOSING_TERMINAL_COUNT");}
            }
            need(firstEnd>0&&(secondEnd<0?firstEnd==output.length-1
                    :secondEnd>firstEnd+1&&secondEnd==output.length-1),"RETAINED_CLOSING_TERMINAL_COUNT");
            JSONObject first=object(Arrays.copyOf(output,firstEnd));
            String[] terminalKeys={"schema","generation","state","display_id","reason","release_confirmed",
                    "boot_count_read_retirement_failure","owned_single_task","profile_cleanup","profile_cleanup_diagnostics",
                    "profile_last_leaf_validation","profile_first_root_refusal","profile_permission_first_read_mismatch",
                    "profile_custody_retained","display_scope_sha256","public_scope_admission_retired",
                    "public_surface_detach","public_screen_lease","public_policy_diagnostics"};
            keys(first,terminalKeys);
            need("client_close".equals(string(first,"reason")),"RETAINED_CLOSING_TERMINAL_IDENTITY_CHANGED");
            if(secondEnd<0)return first;
            JSONObject second=object(Arrays.copyOfRange(output,firstEnd+1,secondEnd));keys(second,terminalKeys);
            need(same(without(first,"profile_cleanup"),without(second,"profile_cleanup")),
                    "RETAINED_CLOSING_TERMINAL_IDENTITY_CHANGED");
            JSONObject before=first.getJSONObject("profile_cleanup"),after=second.getJSONObject("profile_cleanup");
            if(same(first,second))return first;
            need(!before.has("normal_cleanup_phase")&&after.has("normal_cleanup_phase"),
                    "RETAINED_CLOSING_PHASE_NOT_SINGLE_COMPLETION");
            JSONObject fields=releasedCleanupFieldView(after);
            need(same(without(before,"public_foreign_recent_history"),without(fields,"public_foreign_recent_history")),
                    "RETAINED_CLOSING_CUSTODY_CHANGED");
            JSONObject old=before.getJSONObject("public_foreign_recent_history"),last=after.getJSONObject("public_foreign_recent_history");
            String[] historyKeys={"schema","target_sha256","foreign_dormant_history_preserved","history_refusal_latched",
                    "history_refusal_reason","baseline_elapsed_ms","current_elapsed_ms","baseline_raw_sha256","current_raw_sha256",
                    "nonowned_history_sha256","baseline_task_ids","owned_task_ids","owned_target_absent","serialized_task_ids_grant_authority",
                    "history_preservation_scope","physical_history_frozen","unrelated_physical_history_changes_observed",
                    "protected_history_sha256","current_protected_history_sha256","nonphysical_history_preserved","recents_presentation_changes_observed"};
            keys(old,historyKeys);keys(last,historyKeys);
            need("hepta.public-profile-history-custody.v2".equals(string(old,"schema"))
                    &&same(without(old,"current_elapsed_ms","current_raw_sha256","owned_target_absent"),
                            without(last,"current_elapsed_ms","current_raw_sha256","owned_target_absent")),
                    "RETAINED_CLOSING_HISTORY_IDENTITY_CHANGED");
            no(old,"owned_target_absent","history_refusal_latched");yes(last,"owned_target_absent");
            yes(old,"nonphysical_history_preserved");no(old,"serialized_task_ids_grant_authority","physical_history_frozen");
            long beforeAt=number(old,"current_elapsed_ms"),afterAt=number(last,"current_elapsed_ms");
            need(created<=beforeAt&&beforeAt<afterAt&&afterAt<=started
                    &&ProfileIdentity.hash(string(old,"current_raw_sha256"))&&ProfileIdentity.hash(string(last,"current_raw_sha256"))
                    &&!string(old,"current_raw_sha256").equals(string(last,"current_raw_sha256")),
                    "RETAINED_CLOSING_HISTORY_CLOCK_OR_HASH");
            JSONObject phase=after.getJSONObject("normal_cleanup_phase");
            yes(phase,"read_convergence_activated","failed");
            JSONObject failure=first.getJSONObject("profile_cleanup_diagnostics").getJSONObject("first_failure");
            need(number(phase,"original_task_reads_deadline_elapsed_ms")==number(failure,"task_reads_deadline_elapsed_ms")
                    &&number(phase,"bounded_convergence_deadline_elapsed_ms")<number(failure,"observed_elapsed_ms")
                    &&number(failure,"observed_elapsed_ms")<=started,"RETAINED_CLOSING_PHASE_FAILURE_BINDING");
            long leafBegin=number(phase,"leaf_effect_entered_elapsed_ms"),leafEnd=number(phase,"leaf_effect_returned_elapsed_ms");
            long sample=number(phase,"last_sample_started_elapsed_ms"),readDeadline=number(phase,"original_task_reads_deadline_elapsed_ms");
            long convergence=number(phase,"bounded_convergence_deadline_elapsed_ms");
            need(beforeAt<=leafBegin&&leafBegin<=leafEnd&&leafEnd<=afterAt&&afterAt<=sample
                    &&sample<readDeadline&&readDeadline<=convergence&&convergence<started,
                    "RETAINED_CLOSING_PHASE_ORDER");
            for(String key:new String[]{"root_effect_entered_elapsed_ms","root_effect_returned_elapsed_ms",
                    "display_effect_entered_elapsed_ms","display_effect_returned_elapsed_ms"})
                need(number(phase,key)==-1,"RETAINED_CLOSING_UNCONFIRMED_EFFECT_ENTERED");
            return first;
        }
        private void requireNoModelOriginal(JSONObject result,JSONObject broker)throws Exception{
            JSONObject session=result.getJSONObject("model_session"),app=object(model("app-session-receipt.json"));
            need(taskId.equals(string(session,"task_id"))&&ProfileIdentity.sha(model("app-session-receipt.json")).equals(string(session,"app_receipt_sha256"))
                    &&"hepta.local-model.task-session.v1".equals(string(app,"schema"))&&taskId.equals(string(app,"task_id"))
                    &&modelGeneration.equals(string(app,"worker_generation"))&&ownerUid==number(app,"app_uid")&&number(broker,"app_pid")==number(app,"app_pid")
                    &&"not_started".equals(string(app,"cleanup_classification"))&&number(app,"requests_sent")==0&&number(app,"requests_accepted")==0
                    &&app.get("exit_code")==JSONObject.NULL&&session.get("exit_code")==JSONObject.NULL&&app.get("worker_generation_cleanup")==JSONObject.NULL
                    &&app.getJSONObject("native_session_receipt").length()==0,"BEFORE_MODEL_RECEIPT");
            no(session,"process_started","process_exit_observed");yes(session,"receipt_valid");
            yes(app,"cleanup_known","native_session_binding_valid","generation_cleanup_known","generation_unforced");
            no(app,"process_started","process_exit_observed","force_destroy_sent","parent_force_destroy_sent","cancel_requested","automatic_restart","cross_task_reuse");
            JSONObject cancel=app.getJSONObject("owned_worker_cancellation");need(taskId.equals(string(cancel,"task_id"))&&modelGeneration.equals(string(cancel,"worker_generation"))
                    &&number(cancel,"term_destroy_attempts")==0&&number(cancel,"force_destroy_attempts")==0,"BEFORE_MODEL_CANCELLATION");
            no(cancel,"requested","termination_started","process_bound","process_exit_observed");
            need(result.get("last_action_execution")==JSONObject.NULL&&result.get("final_observation_id")==JSONObject.NULL,"BEFORE_MODEL_EFFECT");
            JSONObject retired=object(task("native-app-retired.json")),binding=object(task("native-app-binding.json"));
            for(JSONObject row:new JSONObject[]{retired,binding})need(taskId.equals(string(row,"task_id"))&&ownerSha256.equals(string(row,"owner_sha256"))
                    &&string(result,"task_authorization_sha256").equals(string(row,"authorization_sha256"))
                    &&target.sha256.equals(string(row.getJSONObject("profile_target"),"target_identity_sha256")),"BEFORE_MODEL_NATIVE_OWNER");
            need(displayId==number(binding,"display_id")&&generation.equals(string(binding,"background_generation")),"BEFORE_MODEL_NATIVE_DISPLAY");
            yes(retired,"action_domain_retired");no(retired,"pending_action","accepted_completion_candidate","invalid");
            JSONObject progress=retired.getJSONObject("progress");need(number(progress,"actual_model_actions")==0&&progress.get("pending")==JSONObject.NULL
                    &&progress.getJSONArray("transitions").length()==0,"BEFORE_MODEL_NATIVE_ACTIVITY");
            JSONObject gate=result.getJSONObject("task_authorization");need(gate.getJSONArray("found_packages").length()==0&&gate.getJSONObject("last_check").length()==0,"BEFORE_MODEL_GATE");
            for(String path:manifest.paths())if(path.startsWith("runs/"))need(path.equals(modelPrefix+"app-session-receipt.json"),"BEFORE_MODEL_GENERATION_MEMBERSHIP");
            for(String leaf:manifest.taskFiles())need(!leaf.startsWith("step-")&&!leaf.startsWith("ime-submit-")&&!leaf.startsWith("fixed-intent-")
                    &&!leaf.startsWith("controller-completion-"),"BEFORE_MODEL_EFFECT_FILE");
        }
        /** A stored close reply is already RELEASED, so it cannot be validated as
         * the preceding ACTIVE display readback. This additional origin is history
         * only: exit/EOF, complete originals and fresh double absence remain required. */
        private JSONObject postBusinessOrigin(JSONObject bootstrap,JSONObject cleanup,byte[] output)throws Exception{
            if("RELEASED".equals(string(cleanup.getJSONObject("last_broker_response"),"state")))
                return releasedBusinessOrigin(bootstrap,cleanup,output);
            return businessOrigin(bootstrap,cleanup,output);
        }
        private JSONObject releasedBusinessOrigin(JSONObject bootstrap,JSONObject cleanup,byte[] output)throws Exception{
            need(historicalBrokerExitObserved&&historicalBrokerExitCode!=null&&historicalBrokerExitCode==0
                    &&!retainedBeforeFirstModel&&!retainedAfterBusiness,"BUSINESS_RELEASED_CLOSE_EXIT");
            JSONObject terminal=object(output);
            need("hepta.background-broker-terminal.v1".equals(string(terminal,"schema"))&&generation.equals(string(terminal,"generation"))&&number(terminal,"display_id")==displayId
                    &&"RELEASED".equals(string(terminal,"state"))&&publicScope.sha256.equals(string(terminal,"display_scope_sha256"))
                    &&terminal.get("boot_count_read_retirement_failure")==JSONObject.NULL&&terminal.get("owned_single_task")==JSONObject.NULL,"BUSINESS_HISTORICAL_TERMINAL");
            yes(terminal,"release_confirmed","public_scope_admission_retired");no(terminal,"profile_custody_retained");
            String reason=string(terminal,"reason");
            need("client_close".equals(reason),"BUSINESS_RELEASED_CLOSE_REASON");
            JSONObject first=bootstrap.getJSONObject("last_broker_response"),last=cleanup.getJSONObject("last_broker_response");
            requireHistoricalResponse(first,bootstrap.getJSONObject("app_display_readback"));
            need("launch".equals(string(first,"operation"))&&Boolean.TRUE.equals(first.get("dispatched")),"BUSINESS_RELEASED_CLOSE_LAUNCH");
            requireReleasedResponse(last,terminal,bootstrap.getJSONObject("app_display_readback"),cleanup.getJSONObject("app_display_readback"));
            need(number(bootstrap.getJSONObject("app_display_readback"),"observed_ended_elapsed_ms")<=number(cleanup.getJSONObject("app_display_readback"),"observed_ended_elapsed_ms"),"BUSINESS_RESPONSE_CLOCK");
            JSONObject cleaned=releasedCleanupFieldView(terminal.getJSONObject("profile_cleanup")),history=cleaned.getJSONObject("public_foreign_recent_history");
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
            for(JSONObject response:new JSONObject[]{first}){
                JSONObject previous=releasedCleanupFieldView(response.getJSONObject("profile_cleanup"));JSONArray rows=previous.getJSONArray("owned_tasks");
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
        private void requireReleasedResponse(JSONObject last,JSONObject terminal,JSONObject firstRead,JSONObject lastRead)throws Exception{
            need(number(last,"version")==BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION&&ProfileIdentity.uuid(string(last,"request_id"))
                    &&generation.equals(string(last,"generation"))&&displayId==number(last,"display_id")&&displayName.equals(string(last,"display_name"))
                    &&publicScope.sha256.equals(string(last,"display_scope_sha256"))&&"RELEASED".equals(string(last,"state"))
                    &&"close".equals(string(last,"operation"))&&expires==number(last,"expires_elapsed_ms")&&target.wire().equals(string(last,"profile_target_wire"))
                    &&string(terminal,"reason").equals(string(last,"terminal_reason"))&&last.get("public_own_group_readback_wire")==JSONObject.NULL,
                    "BUSINESS_RELEASED_CLOSE_RESPONSE");
            yes(last,"ok","profile_cleanup_known","public_scope_admission_retired","public_scope_closing","always_unlocked");
            no(last,"dispatched","profile_custody_retained","profile_current_identity_verified","capture_secure");
            need("hide".equals(string(last,"ime_policy")),"BUSINESS_RELEASED_CLOSE_FLAGS");
            for(String key:new String[]{"profile_cleanup","profile_last_leaf_validation","public_surface_detach","profile_cleanup_diagnostics",
                    "profile_first_root_refusal","profile_permission_first_read_mismatch","public_policy_diagnostics"})
                need(same(terminal.get(key),last.get(key)),"BUSINESS_RELEASED_CLOSE_TERMINAL_BINDING");
            // The app readback is the last successful ACTIVE read, not a read of
            // the destroyed display. Preserve its full identity and monotonicity.
            String[] changing={"broker_request_id","broker_readback_sha256","observed_started_elapsed_ms","observed_ended_elapsed_ms"};
            need(same(without(firstRead,changing),without(lastRead,changing))
                    &&ProfileIdentity.uuid(string(lastRead,"broker_request_id"))&&ProfileIdentity.hash(string(lastRead,"broker_readback_sha256"))
                    &&number(lastRead,"observed_started_elapsed_ms")>=number(firstRead,"observed_ended_elapsed_ms")
                    &&number(lastRead,"observed_ended_elapsed_ms")>=number(lastRead,"observed_started_elapsed_ms")
                    &&number(lastRead,"observed_ended_elapsed_ms")<expires,"BUSINESS_RELEASED_CLOSE_LAST_READBACK");
        }
        /** Validate the optional diagnostic vocabulary before making a field view.
         * Original bytes and the complete close/terminal comparison retain it; no
         * diagnostic flag is used as cleanup, mutation, or current absence authority. */
        private static JSONObject releasedCleanupFieldView(JSONObject value)throws Exception{
            if(!value.has("normal_cleanup_phase"))return value;
            JSONObject phase=value.getJSONObject("normal_cleanup_phase");
            keys(phase,"schema","original_task_reads_deadline_elapsed_ms","bounded_convergence_deadline_elapsed_ms",
                    "maximum_census_to_effect_age_ms","read_convergence_activated","failed","last_sample_started_elapsed_ms",
                    "leaf_effect_entered_elapsed_ms","leaf_effect_returned_elapsed_ms","root_effect_entered_elapsed_ms",
                    "root_effect_returned_elapsed_ms","display_effect_entered_elapsed_ms","display_effect_returned_elapsed_ms",
                    "business_admission_restored","serialized_evidence_is_authority");
            need("hepta.profile-normal-cleanup-phase.v1".equals(string(phase,"schema"))
                    &&number(phase,"maximum_census_to_effect_age_ms")==1500
                    &&phase.get("read_convergence_activated") instanceof Boolean&&phase.get("failed") instanceof Boolean,
                    "BUSINESS_RELEASED_PHASE_SHAPE");
            no(phase,"business_admission_restored","serialized_evidence_is_authority");
            for(String key:new String[]{"original_task_reads_deadline_elapsed_ms","bounded_convergence_deadline_elapsed_ms"})
                need(number(phase,key)>0,"BUSINESS_RELEASED_PHASE_CLOCK");
            for(String key:new String[]{"last_sample_started_elapsed_ms","leaf_effect_entered_elapsed_ms","leaf_effect_returned_elapsed_ms",
                    "root_effect_entered_elapsed_ms","root_effect_returned_elapsed_ms","display_effect_entered_elapsed_ms","display_effect_returned_elapsed_ms"})
                need(number(phase,key)>=-1,"BUSINESS_RELEASED_PHASE_CLOCK");
            return without(value,"normal_cleanup_phase");
        }
        private JSONObject businessOrigin(JSONObject bootstrap,JSONObject cleanup,byte[] output)throws Exception{
            JSONObject terminal=object(output);
            need("hepta.background-broker-terminal.v1".equals(string(terminal,"schema"))&&generation.equals(string(terminal,"generation"))&&number(terminal,"display_id")==displayId
                    &&"RELEASED".equals(string(terminal,"state"))&&publicScope.sha256.equals(string(terminal,"display_scope_sha256"))
                    &&terminal.get("boot_count_read_retirement_failure")==JSONObject.NULL&&terminal.get("owned_single_task")==JSONObject.NULL,"BUSINESS_HISTORICAL_TERMINAL");
            yes(terminal,"release_confirmed","public_scope_admission_retired");no(terminal,"profile_custody_retained");
            String reason=string(terminal,"reason");
            need("client_close".equals(reason)||reason.matches("[A-Z0-9_]{1,96}"),"BUSINESS_TERMINAL_REASON");
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
        private void requireVisualStamp(JSONObject stamp,String path)throws Exception{
            byte[] bytes=original(path);
            need(privatePathEnds(string(stamp,"path"),path)&&number(stamp,"bytes")==bytes.length
                    &&ProfileIdentity.sha(bytes).equals(string(stamp,"sha256")),"BUSINESS_VISUAL_ORIGINAL_CHANGED");
        }

        private int requireVisualClose(JSONObject projection,JSONObject broker)throws Exception{
            JSONObject aggregate=object(model("vlm-task-terminal.json"));
            java.util.Set<String> required=visualModelPaths(aggregate,taskId,modelGeneration);
            TreeSet<String> actual=new TreeSet<String>();
            for(String path:originals.keySet())if(path.startsWith("runs/"))actual.add(path);
            need(actual.equals(required),"BUSINESS_VISUAL_INPUT_SET");
            need(taskId.equals(string(projection,"task_id"))&&modelGeneration.equals(string(projection,"worker_generation"))
                    &&number(projection,"exit_code")==0&&ProfileIdentity.sha(model("vlm-task-terminal.json")).equals(string(projection,"app_receipt_sha256")),"BUSINESS_VISUAL_PROJECTION");
            yes(projection,"process_started","process_exit_observed","receipt_valid");
            need("logical_task_reservation".equals(string(aggregate,"generation_semantics"))&&number(aggregate,"aggregate_exit_code")==0
                    &&"all_serial_requests_accepted_with_actual_exit_zero_and_generation_cleanup".equals(string(aggregate,"aggregate_exit_zero_semantics")),"BUSINESS_VISUAL_FINISH");
            yes(aggregate,"serial_generations","process_started","all_started_process_exits_observed","cleanup_known","all_request_bindings_valid");
            no(aggregate,"cancel_requested","native_task_session_receipt_fabricated","automatic_retry","automatic_restart","cross_task_reuse","external_model","business_completion_verified");
            long submitted=number(aggregate,"finisher_submitted_monotonic_ns"),deadline=number(aggregate,"finisher_deadline_monotonic_ns"),published=number(aggregate,"published_monotonic_ns");
            need(submitted>0&&deadline>submitted&&published>=submitted&&published<=deadline,"BUSINESS_VISUAL_FINISH_CLOCK");
            requireVisualStamp(aggregate.getJSONObject("original_pending"),modelPrefix+"vlm-task-pending.json");
            JSONObject pending=object(model("vlm-task-pending.json"));
            need("hepta.vlm.task-pending.v1".equals(string(pending,"schema"))&&taskId.equals(string(pending,"task_id"))
                    &&modelGeneration.equals(string(pending,"task_generation"))&&number(pending,"app_uid")==ownerUid
                    &&number(pending,"app_pid")==number(broker,"app_pid"),"BUSINESS_VISUAL_PENDING");
            yes(pending,"pending","serial_generations");no(pending,"cleanup_known","automatic_resume","automatic_retry");
            java.util.Map<String,JSONObject> stepsByRequest=new TreeMap<String,JSONObject>();
            for(String f:manifest.taskFiles())if(f.matches("step-[0-9]+-model-[0-9]+\\.json")){
                JSONObject step=object(task(f));String id=string(step,"run_id");
                need(stepsByRequest.put(id,step)==null&&ownerSha256.equals(string(step,"original_instruction_sha256")),"BUSINESS_VISUAL_STEP");
            }
            JSONArray rows=aggregate.getJSONArray("requests");
            for(int i=0;i<rows.length();i++){
                JSONObject row=rows.getJSONObject(i);
                String request=string(row,"request_id"),worker=string(row,"generation");
                JSONObject step=stepsByRequest.remove(request);
                need(step!=null&&string(step,"observation_id").equals(string(row,"observation_id")),"BUSINESS_VISUAL_STEP_MISSING");
                requireVisualRound(row,step,broker,worker,request);
            }
            need(stepsByRequest.isEmpty(),"BUSINESS_VISUAL_STEP_EXTRA");
            return rows.length();
        }

        private void requireVisualRound(JSONObject row,JSONObject step,JSONObject broker,String worker,String request)throws Exception{
            String workerPath="runs/"+worker+"/",path=workerPath+"vlm/"+request+"/";
            need("hepta.vlm.serial-generation-summary.v1".equals(string(row,"schema"))&&taskId.equals(string(row,"task_id"))
                    &&modelGeneration.equals(string(row,"task_generation"))&&ownerSha256.equals(string(row,"owner_sha256"))
                    &&generation.equals(string(row,"background_generation"))&&number(row,"actual_exit_code")==0
                    &&row.get("delivery_rejection")==JSONObject.NULL,"BUSINESS_VISUAL_ROUND");
            yes(row,"process_started","process_exit_observed","cleanup_known","native_contract_valid","success_callback_returned");
            requireVisualStamp(row.getJSONObject("app_receipt"),path+"app-receipt.json");
            requireVisualStamp(row.getJSONObject("native_receipt"),path+"native-result.json");
            requireVisualStamp(row.getJSONObject("delivery_receipt"),path+"app-delivery.json");
            JSONObject app=object(original(path+"app-receipt.json")),nativeReceipt=object(original(path+"native-result.json")),delivery=object(original(path+"app-delivery.json"));
            for(String k:new String[]{"task_id","task_generation","generation","request_id","owner_sha256","observation_id","background_generation","scope_token"})
                need(same(row.get(k),app.get(k))&&same(row.get(k),delivery.get(k)),"BUSINESS_VISUAL_REQUEST_BINDING");
            for(String k:new String[]{"task_id","generation","request_id","scope_token"})
                need(same(row.get(k),nativeReceipt.get(k)),"BUSINESS_VISUAL_NATIVE_BINDING");
            byte[] ownerBytes=original(path+"owner.json");
            JSONObject frameOwner=object(ownerBytes);
            requireVisualStamp(app.getJSONObject("original_inputs").getJSONObject("owner.json"),path+"owner.json");
            need("hepta.vlm.current-frame.v1".equals(string(frameOwner,"schema"))
                    &&ProfileIdentity.sha(ownerBytes).equals(string(nativeReceipt,"owner_sha256"))
                    &&ownerSha256.equals(string(frameOwner,"task_owner_sha256"))
                    &&same(frameOwner,nativeReceipt.getJSONObject("current_frame"))
                    &&target.packageName.equals(string(frameOwner,"package_name"))&&displayId==number(frameOwner,"display_id")
                    &&string(frameOwner,"image_sha256").equals(string(nativeReceipt,"image_sha256")),"BUSINESS_VISUAL_FRAME_OWNER");
            for(String k:new String[]{"task_id","generation","request_id","scope_token","observation_id","background_generation"})
                need(same(row.get(k),frameOwner.get(k)),"BUSINESS_VISUAL_FRAME_SCOPE");
            need("hepta.vlm.app-request.v1".equals(string(app,"schema"))&&"hepta.vlm.request-delivery.v1".equals(string(delivery,"schema"))
                    &&"hepta.vlm.result.v1".equals(string(nativeReceipt,"schema"))&&same(nativeReceipt,app.getJSONObject("native_receipt"))
                    &&number(app,"actual_exit_code")==0&&number(nativeReceipt,"native_return_code")==0
                    &&number(nativeReceipt,"app_uid")==ownerUid&&number(nativeReceipt,"app_pid")==number(broker,"app_pid")
                    &&number(nativeReceipt,"worker_pid")>1&&row.getJSONObject("app_receipt").getString("sha256").equals(string(delivery,"app_receipt_sha256"))
                    &&delivery.get("failure")==JSONObject.NULL,"BUSINESS_VISUAL_DELIVERY");
            yes(delivery,"success_admitted","cleanup_known");no(delivery,"callback_already_delivered","model_output_dispatched");
            yes(app,"process_started","process_exit_observed","cleanup_known","native_contract_valid","serial_generations");
            no(app,"timeout_observed","log_limit_observed","automatic_retry","automatic_restart","automatic_device_fallback","external_model","actions_dispatched","business_completion_verified");
            yes(nativeReceipt,"generation_completed","full_multimodal_admission_passed","parent_verified_before","parent_verified_after");
            no(nativeReceipt,"automatic_device_fallback","actions_dispatched","action_authorized","business_completion_verified","process_exit_observed","cleanup_known");
            String observation=string(row,"observation_id");
            need(observation.matches("[0-9a-f]{32}")&&ProfileIdentity.sha(task(observation+".png")).equals(string(nativeReceipt,"image_sha256")),"BUSINESS_VISUAL_FRAME");
            byte[] raw=original(path+"raw.txt");
            requireVisualStamp(app.getJSONObject("native_sidecars").getJSONObject("raw.txt"),path+"raw.txt");
            need(Arrays.equals(raw,string(step,"raw_text").getBytes(StandardCharsets.UTF_8))&&number(nativeReceipt,"raw_bytes")==raw.length
                    &&ProfileIdentity.sha(raw).equals(string(nativeReceipt,"raw_sha256")),"BUSINESS_VISUAL_OUTPUT");
            JSONObject cancel=app.getJSONObject("cancellation");
            need("hepta.owned-worker-cancellation.v1".equals(string(cancel,"schema"))&&taskId.equals(string(cancel,"task_id"))
                    &&worker.equals(string(cancel,"worker_generation"))&&number(cancel,"term_destroy_attempts")==0&&number(cancel,"force_destroy_attempts")==0
                    &&cancel.get("signal_error")==JSONObject.NULL,"BUSINESS_VISUAL_CANCEL");
            yes(cancel,"process_bound");no(cancel,"requested","term_destroy_returned","force_destroy_returned");
            JSONObject g=row.getJSONObject("generation_cleanup");String nonce=string(g,"cleanup_nonce");
            need(same(g,app.getJSONObject("generation_cleanup"))&&same(g.get("scope_token"),row.get("scope_token"))
                    &&privatePathEnds(string(g,"identity_file"),workerPath+"worker-generation.identity")
                    &&privatePathEnds(string(g,"native_receipt_file"),workerPath+"generation-cleanup-"+nonce+".json"),"BUSINESS_VISUAL_GENERATION_BINDING");
            requireGenerationEvidence(g,worker,workerPath,number(nativeReceipt,"app_pid"),number(nativeReceipt,"worker_pid"),
                    number(app,"finisher_submitted_monotonic_ns"),number(app,"finisher_deadline_monotonic_ns"));
        }

        private int requireNormalModelClose(JSONObject projection,JSONObject broker)throws Exception{
            JSONObject session=object(model("app-session-receipt.json")),nativeSession=object(model("native-session-result.json"));
            long appPid=number(session,"app_pid"),count=number(session,"requests_sent");need((count>0||retainedBeforeFirstModel)&&count>=0&&count<=256,"BUSINESS_MODEL_COUNT");
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
            requireGenerationEvidence(session.getJSONObject("worker_generation_cleanup"),modelGeneration,modelPrefix,
                    number(session,"app_pid"),number(nativeSession,"pid"),number(session,"finisher_submitted_monotonic_ns"),number(session,"finisher_deadline_monotonic_ns"));
        }
        private void requireGenerationEvidence(JSONObject g,String worker,String prefix,long appPid,long workerPid,long finishStart,long finishDeadline)throws Exception{
            String nonce=string(g,"cleanup_nonce");need(nonce.matches("[0-9a-f]{32}"),"BUSINESS_GENERATION_NONCE");
            byte[] identity=original(prefix+"worker-generation.identity"),raw=original(prefix+"generation-cleanup-"+nonce+".json");JSONObject receipt=object(raw);
            need("hepta.worker-generation.app-cleanup.v1".equals(string(g,"schema"))&&taskId.equals(string(g,"task_id"))&&worker.equals(string(g,"worker_generation"))
                    &&number(g,"app_uid")==ownerUid&&number(g,"app_pid")==appPid&&ProfileIdentity.sha(identity).equals(string(g,"identity_sha256"))
                    &&ProfileIdentity.sha(raw).equals(string(g,"native_receipt_sha256"))&&same(receipt,g.getJSONObject("native_cleanup")),"BUSINESS_GENERATION_RAW_BINDING");
            yes(g,"direct_process_exit_observed","helper_started","helper_exit_observed","cleanup_known","descendant_force_known","generation_unforced");no(g,"helper_force_destroy_sent","helper_currently_alive","descendant_force_used","automatic_retry","escaped_sessions_proven_absent");
            need(number(g,"helper_exit_code")==0&&g.get("error")==JSONObject.NULL&&"pinned_sdk_inheriting_process_group_and_generation_markers".equals(string(g,"scope"))
                    &&number(g,"finisher_submitted_monotonic_ns")==finishStart&&number(g,"finisher_deadline_monotonic_ns")==finishDeadline,"BUSINESS_GENERATION_CLOSE");
            for(String k:new String[]{"task_id","worker_generation","scope_token","app_uid","app_pid","app_start_ticks","boot_id","identity_sha256","cleanup_nonce"})need(same(g.get(k),receipt.get(k)),"BUSINESS_GENERATION_IDENTITY");
            need("hepta.worker-generation.cleanup.v1".equals(string(receipt,"schema"))&&number(receipt,"leader_pid")==workerPid&&number(receipt,"pgid")==workerPid
                    &&number(receipt,"term_attempts")==0&&number(receipt,"kill_attempts")==0&&receipt.getJSONArray("targets").length()==0,"BUSINESS_GENERATION_UNFORCED");
            long submitted=number(g,"submitted_monotonic_ns"),deadline=number(g,"deadline_monotonic_ns"),begin=number(receipt,"started_monotonic_ns"),end=number(receipt,"ended_monotonic_ns");
            need(submitted>=finishStart&&deadline>submitted&&deadline-submitted<=4000000000L
                    &&deadline<=finishDeadline&&begin>=submitted&&begin<deadline&&end>=begin&&end<=deadline
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
            no(origin,"completion_verified");
            if(retainedModelDoneCleanupFailure)yes(origin,"model_reported_success");else no(origin,"model_reported_success");
            if(origin.has("terminal_evidence_schema")||origin.has("task_result_reference")){
                JSONObject ref=origin.getJSONObject("task_result_reference"),d=manifest.descriptor(taskPrefix+"result.json");
                need("hepta.session-terminal-evidence.v1".equals(string(origin,"terminal_evidence_schema"))&&"hepta.session-task-result-reference.v1".equals(string(ref,"schema"))
                        &&taskId.equals(string(ref,"task_id"))&&(taskPrefix+"result.json").equals(string(ref,"relative_path"))&&number(ref,"bytes")==number(d,"bytes")
                        &&string(ref,"sha256").equals(string(d,"sha256"))&&number(ref,"file_device")==number(d,"device")&&number(ref,"file_inode")==number(d,"inode")
                        &&number(ref,"file_uid")==ownerUid&&number(ref,"file_mode")==number(d,"mode")&&number(ref,"file_nlink")==1,"BUSINESS_RESULT_REFERENCE");no(ref,"grants_tool_authority");
            }else{
                // The session writer embeds its complete completion evidence while it fits the journal.
                JSONObject completion=origin.getJSONObject("completion_evidence");
                need("hepta.native-app-terminal-completion.v1".equals(string(completion,"schema"))
                        &&ownerSha256.equals(string(completion,"owner_sha256"))&&taskId.equals(string(completion,"task_id"))
                        &&same(completion,result.getJSONObject("completion_evidence"))
                        &&same(origin.getJSONObject("task_authorization"),owner.getJSONObject("task_authorization"))
                        &&privatePathEnds(string(origin,"evidence_directory"),taskPrefix.substring(0,taskPrefix.length()-1))
                        &&same(origin.get("state"),result.get("summary")),"BUSINESS_INLINE_CONTROL_BINDING");
                for(String k:new String[]{"status","steps","completion_verified","goal_independently_verified","model_reported_success",
                        "cleanup_known","external_model","expected_scope_sha256","actual_scope_sha256"})
                    need(same(origin.get(k),result.get(k)),"BUSINESS_INLINE_CONTROL_RESULT");
                yes(origin,"background_lease_unreleased");no(origin,"web_helper_lease_unreleased");
            }
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
                    &&Boolean.valueOf(retainedAfterBusiness?historicalBrokerExitObserved:!retainedBeforeFirstModel).equals(b.get("eof_seen"))&&Boolean.FALSE.equals(b.get("read_failed"))&&Boolean.FALSE.equals(b.get("overflow"))
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
        public String source(){return retainedBeforeFirstModel?"fresh_public_profile_absence_after_unconfirmed_pre_model_close":retainedModelDoneCleanupFailure?RETAINED_MODEL_DONE_SOURCE:retainedAfterBusiness?RETAINED_BUSINESS_SOURCE:SOURCE;}
        public boolean retainedCurrentAbsenceRequired(){return retainedBeforeFirstModel||retainedAfterBusiness;}
        public JSONObject originalHistoryRefusal()throws Exception{
            need(retainedAfterBusiness,"RETAINED_BUSINESS_HISTORY_NOT_APPLICABLE");
            return retainedBusinessTerminal(task("background-broker-"+generation+".bin")).getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history");
        }
        public JSONObject historicalBrokerProcess()throws Exception{
            return new JSONObject().put("exit_observed",historicalBrokerExitObserved).put("exit_code",historicalBrokerExitCode==null?JSONObject.NULL:historicalBrokerExitCode)
                    .put("output_eof_seen",object(task("background-broker-"+generation+".json")).getBoolean("eof_seen"))
                    .put("normal_release_observed",!retainedCurrentAbsenceRequired());
        }
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
        keys(r.retainedAfterBusiness?without(value,"original_history_refusal","historical_broker_process"):value,"schema","source","request_id","task_id","generation","owner_uid","owner_sha256","journal_sha256","manifest_sha256","originals_sha256",
                "public_scope_wire","public_scope_sha256","profile_target_wire","target_sha256","display_name","old_boot_count","current_boot_count","lease_expires_elapsed_ms",
                "request_started_elapsed_ms","started_elapsed_ms","finished_elapsed_ms","deadline_elapsed_ms","current_controller","before","after","current_absence_verified",
                "recovery_interval_physical_unchanged","foreign_dormant_history_preserved","cleanup_known","automatic_resume","broker_release_response","business_steps",
                "model_requests","model_generation","historical_model_exit_verified","historical_broker_release_observed","business_dispatch_absent_in_original_receipts",
                "recorded_owned_identity","rewrites_business_outcome","acknowledges_control_session");
        need(SCHEMA.equals(string(value,"schema"))&&r.source().equals(string(value,"source"))&&r.requestId.equals(string(value,"request_id"))&&r.taskId.equals(string(value,"task_id"))
                &&r.generation.equals(string(value,"generation"))&&number(value,"owner_uid")==r.ownerUid&&r.ownerSha256.equals(string(value,"owner_sha256"))
                &&r.journalSha256.equals(string(value,"journal_sha256"))&&r.manifest.sha256.equals(string(value,"manifest_sha256"))&&r.originalsSha256.equals(string(value,"originals_sha256"))
                &&r.publicScope.wire().equals(string(value,"public_scope_wire"))&&r.publicScope.sha256.equals(string(value,"public_scope_sha256"))&&r.target.wire().equals(string(value,"profile_target_wire"))
                &&r.target.sha256.equals(string(value,"target_sha256"))&&r.displayName.equals(string(value,"display_name"))&&same(r.controller(),value.getJSONObject("current_controller"))
                &&same(r.recordedOwnedIdentity(),value.getJSONObject("recorded_owned_identity")),"BUSINESS_PROOF_BINDING");
        need(number(value,"business_steps")==r.steps&&number(value,"model_requests")==r.modelRequests&&r.modelGeneration.equals(string(value,"model_generation")),"BUSINESS_PROOF_HISTORY");
        yes(value,"current_absence_verified","recovery_interval_physical_unchanged","foreign_dormant_history_preserved","cleanup_known");
        need(Boolean.valueOf(!r.retainedBeforeFirstModel).equals(value.get("historical_model_exit_verified"))
                &&Boolean.valueOf(!r.retainedCurrentAbsenceRequired()).equals(value.get("historical_broker_release_observed"))
                &&Boolean.valueOf(r.retainedBeforeFirstModel).equals(value.get("business_dispatch_absent_in_original_receipts")),"BUSINESS_HISTORICAL_STATUS");
        if(r.retainedAfterBusiness)need(same(r.originalHistoryRefusal(),value.getJSONObject("original_history_refusal"))
                &&same(r.historicalBrokerProcess(),value.getJSONObject("historical_broker_process")),"RETAINED_BUSINESS_HISTORY_REWRITTEN");
        no(value,"automatic_resume","broker_release_response","rewrites_business_outcome","acknowledges_control_session");
        need(number(value,"old_boot_count")==r.oldBoot&&number(value,"current_boot_count")==boot&&number(value,"lease_expires_elapsed_ms")==r.expires
                &&number(value,"request_started_elapsed_ms")==r.started&&number(value,"deadline_elapsed_ms")==r.deadline,"BUSINESS_PROOF_CLOCK");
        long begin=number(value,"started_elapsed_ms"),end=number(value,"finished_elapsed_ms");need(begin>=r.started&&end>=begin&&end<=now&&end<r.deadline,"BUSINESS_PROOF_CLOCK");
        JSONObject first=value.getJSONObject("before"),last=value.getJSONObject("after");sample(first,r,begin,end);sample(last,r,begin,end);
        need(number(first,"finished_elapsed_ms")<=number(last,"started_elapsed_ms")&&same(first.getJSONObject("physical"),last.getJSONObject("physical"))
                &&number(first.getJSONObject("process"),"self_pid")==number(last.getJSONObject("process"),"self_pid")
                &&number(first.getJSONObject("process"),"self_start_ticks")==number(last.getJSONObject("process"),"self_start_ticks"),"BUSINESS_DOUBLE_SAMPLE");
        if(r.retainedCurrentAbsenceRequired())need(string(first,"firmware_fingerprint_sha256").equals(string(last,"firmware_fingerprint_sha256")),"RETAINED_FIRMWARE_CHANGED");
        long age=(number(last,"finished_elapsed_ms")-number(first,"started_elapsed_ms"))/1000+2;
        PublicProfileRecentHistory.requireSameRecoveryEvidence(first.getJSONObject("recents"),last.getJSONObject("recents"),r.target,age);
        return object(value.toString().getBytes(StandardCharsets.UTF_8));
    }
    private static void sample(JSONObject s,Request r,long begin,long end)throws Exception{
        ProfilePrelaunchRecovery.keys(r.retainedCurrentAbsenceRequired()?without(s,"firmware_fingerprint_sha256"):s,"started_elapsed_ms","finished_elapsed_ms","process","live","recents","displays","physical","target_sha256");
        if(r.retainedCurrentAbsenceRequired())need(ProfileIdentity.hash(string(s,"firmware_fingerprint_sha256")),"RETAINED_FIRMWARE_IDENTITY");
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
            ProfilePrelaunchRecovery.keys(r.retainedAfterBusiness?without(displays,"including_disabled"):displays,"complete","count","snapshot_sha256","exact_name_absent","recorded_id_absent");
            if(r.retainedAfterBusiness)yes(displays,"including_disabled");
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
        JSONObject physical=s.getJSONObject("physical");ProfilePrelaunchRecovery.keys(physical,"schema","0","1");
        need(PublicOwnGroupPhysicalFence.BUSINESS_RECOVERY_SCHEMA.equals(string(physical,"schema")),"BUSINESS_PHYSICAL_IDENTITY_SCHEMA");
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
