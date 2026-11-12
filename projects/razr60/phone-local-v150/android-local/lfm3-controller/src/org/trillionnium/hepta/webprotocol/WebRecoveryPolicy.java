package org.trillionnium.hepta.webprotocol;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Pure replay of native Android observations. A caller assertion is not an OS observation. */
public final class WebRecoveryPolicy {
    private WebRecoveryPolicy() { }
    public static final String PROBE_SCHEMA="hepta.web-helper.retirement-probe.v1";
    public static final String DECISION_SCHEMA="hepta.web-helper.retirement-decision.v1";
    public static final int MAX_DISPLAYS=64,MAX_EXIT_RECORDS=32;
    public static final long MAX_PROBE_MS=3000;
    public static JSONObject evaluate(JSONObject prior,JSONObject observed)throws Exception{
        JSONObject answer=new JSONObject().put("schema",DECISION_SCHEMA).put("verified",false)
                .put("kind",JSONObject.NULL).put("reason","incomplete_retirement_evidence")
                .put("old_cleanup_methods_verified",false).put("direct_old_window_query_performed",false)
                .put("business_verified",false);
        try{
            String schema=text(prior,"schema");
            need(schema.equals("hepta.web-helper.lease-journal.v1")||schema.equals("hepta.web-helper.lease-journal.v2"),"unsupported prior journal");
            need(text(prior,"state").equals("active")||text(prior,"state").equals("unknown"),"prior state is not an unresolved lease");
            JSONObject binding=prior.getJSONObject("binding");
            need(WebEvidenceBinding.sha256(binding).equals(text(prior,"binding_sha256")),"prior binding hash differs");
            JSONObject bg=binding.getJSONObject("background"),helper=binding.getJSONObject("helper_identity");
            int oldBoot=integer(bg,"boot_count"),oldDisplay=integer(bg,"display_id"),oldPid=integer(prior,"helper_pid");
            int uid=integer(helper,"uid"),oldWindow=integer(prior,"window_id");
            String oldName=text(bg,"display_name"),generation=text(bg,"generation");
            need(oldBoot>=0&&oldDisplay>0&&oldPid>0&&uid>=10000&&oldWindow>=0
                    &&WebEvidenceProtocol.HELPER_PACKAGE.equals(text(helper,"package"))
                    &&WebEvidenceProtocol.uuid(generation)&&oldName.equals("hepta-bg-"+generation)
                    &&WebEvidenceProtocol.uuid(text(prior,"webview_instance")),"prior identity incomplete");
            exact(observed,"schema","current_boot_count_before","current_boot_count_after","started_elapsed_ms","ended_elapsed_ms",
                    "current_process","active_bound_view_count","pending_capture_count","displays_before","displays_after",
                    "direct_old_display_before","direct_old_display_after","exit_records","exit_records_status","errors");
            need(observed.getJSONArray("errors").length()==0,"native probe reported an unavailable observation");
            need(PROBE_SCHEMA.equals(text(observed,"schema")),"probe schema differs");
            int boot=integer(observed,"current_boot_count_before");
            need(boot>=oldBoot&&boot==integer(observed,"current_boot_count_after"),"boot unknown, regressed or changed during probe");
            long begin=number(observed,"started_elapsed_ms"),end=number(observed,"ended_elapsed_ms");
            need(begin>0&&end>=begin&&end-begin<=MAX_PROBE_MS,"probe elapsed bracket invalid");
            JSONObject process=observed.getJSONObject("current_process");
            processShape(process);
            need(integer(process,"uid")==uid&&integer(process,"pid")>0
                    &&WebEvidenceProtocol.HELPER_PACKAGE.equals(text(process,"process_name"))
                    &&integer(process,"boot_count")==boot&&number(process,"recorded_elapsed_ms")<=begin,"current process identity differs");
            need(integer(observed,"active_bound_view_count")==0&&integer(observed,"pending_capture_count")==0,"current owned work still exists");
            need(observed.get("direct_old_display_before")==JSONObject.NULL&&observed.get("direct_old_display_after")==JSONObject.NULL,"old display ID is still accessible");
            displaysAbsent(observed.getJSONArray("displays_before"),oldDisplay,oldName);
            displaysAbsent(observed.getJSONArray("displays_after"),oldDisplay,oldName);
            String kind;
            JSONObject exitMatch=null;
            if(boot>oldBoot){
                need("not_required_boot_changed".equals(text(observed,"exit_records_status"))
                        &&observed.getJSONArray("exit_records").length()==0,"unexpected reboot probe shape");
                kind="boot_changed";
            }else{
                JSONObject oldProcess=prior.optJSONObject("process_identity"),oldDisplayProbe=prior.optJSONObject("display_before");
                need(oldProcess!=null&&oldDisplayProbe!=null,"same_boot_requires_recorded_process_summary_and_public_display");
                processShape(oldProcess);
                exact(oldDisplayProbe,"display_id","name","flags","valid");
                need(integer(oldProcess,"pid")==oldPid&&integer(oldProcess,"uid")==uid
                        &&integer(oldProcess,"boot_count")==oldBoot
                        &&WebEvidenceProtocol.HELPER_PACKAGE.equals(text(oldProcess,"process_name"))
                        &&Boolean.TRUE.equals(oldProcess.get("state_summary_registered")),"prior process summary was not registered");
                String summary=text(oldProcess,"state_summary_hex");
                need(summary.matches("[0-9a-f]{2,256}")&&summary.length()%2==0,"prior process summary shape");
                need(!summary.equals(text(process,"state_summary_hex")),"old and current process summary must differ");
                need(integer(oldDisplayProbe,"display_id")==oldDisplay&&oldName.equals(text(oldDisplayProbe,"name"))
                        &&Boolean.TRUE.equals(oldDisplayProbe.get("valid"))
                        &&(integer(oldDisplayProbe,"flags")&4)==0,"prior display was not observed publicly accessible");
                need("queried".equals(text(observed,"exit_records_status")),"process exit query unavailable");
                JSONArray exits=observed.getJSONArray("exit_records");need(exits.length()<=MAX_EXIT_RECORDS,"exit record budget");
                int matches=0;
                for(int i=0;i<exits.length();i++){
                    JSONObject row=exits.getJSONObject(i);
                    exact(row,"pid","real_uid","package_uid","process_name","reason","status","timestamp_ms","state_summary_hex");
                    integer(row,"reason");integer(row,"status");
                    need(integer(row,"pid")>0&&integer(row,"real_uid")>=0&&integer(row,"package_uid")>=0
                            &&text(row,"process_name").length()<=256&&number(row,"timestamp_ms")>=0,"invalid native exit record");
                    Object recordedSummary=row.get("state_summary_hex");
                    need(recordedSummary==JSONObject.NULL||(recordedSummary instanceof String
                            &&((String)recordedSummary).matches("[0-9a-f]{0,256}")&&((String)recordedSummary).length()%2==0),"invalid exit summary");
                    if(integer(row,"pid")==oldPid&&integer(row,"real_uid")==uid&&integer(row,"package_uid")==uid
                            &&WebEvidenceProtocol.HELPER_PACKAGE.equals(text(row,"process_name"))
                            &&summary.equals(row.opt("state_summary_hex"))&&number(row,"timestamp_ms")>0){
                        matches++;exitMatch=row;
                    }
                }
                need(matches==1,"one exact native process-exit record required");
                kind="matched_process_exit";
            }
            answer.put("verified",true).put("kind",kind).put("reason","original_process_and_owned_display_no_longer_present")
                    .put("old_boot_count",oldBoot).put("current_boot_count",boot)
                    .put("old_pid",oldPid).put("old_display_id",oldDisplay).put("old_display_name",oldName).put("old_window_id",oldWindow)
                    .put("current_owned_view_absent",true).put("old_display_absent_in_accessible_scope",true)
                    .put("old_window_absence_basis",kind.equals("boot_changed")?"old_boot_ended_and_original_display_absent":"exact_original_process_exited_and_original_public_display_absent")
                    .put("matched_exit_info",exitMatch==null?JSONObject.NULL:exitMatch);
        }catch(Exception rejected){answer.put("reason",bounded(rejected.getMessage()));}
        return answer;
    }
    /**
     * Replays the complete immutable FD payload. Normal close and recovered retirement are
     * deliberately separate proof types; this never asserts that old cleanup calls ran.
     */
    public static JSONObject evaluateRecord(JSONObject record)throws Exception{
        JSONObject answer=new JSONObject().put("schema","hepta.web-helper.retirement-record-verdict.v1")
                .put("retirement_verified",false).put("reason","incomplete_recovery_record")
                .put("old_cleanup_methods_verified",false).put("business_verified",false);
        try{
            exact(record,"schema","request_json_utf8","request_sha256","binding","binding_sha256",
                    "prior_journal_utf8","prior_journal_bytes","prior_journal_sha256","preserved_prior_record",
                    "original_cleanup","actual_controller_identity","actual_helper_identity",
                    "native_probe_before","native_probe_after","storage_retirement","completed_elapsed_ms",
                    "old_cleanup_methods_verified","business_verified");
            need("hepta.web-helper.recovered-retirement.v1".equals(text(record,"schema"))
                    &&Boolean.FALSE.equals(record.get("old_cleanup_methods_verified"))
                    &&Boolean.FALSE.equals(record.get("business_verified")),"recovery record scope differs");
            String priorRaw=text(record,"prior_journal_utf8"),requestRaw=text(record,"request_json_utf8");
            byte[] priorBytes=priorRaw.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            need(priorBytes.length>0&&priorBytes.length<=65536&&priorBytes.length==number(record,"prior_journal_bytes")
                    &&digest(priorBytes).equals(text(record,"prior_journal_sha256")),"original journal bytes/hash differ");
            need(digest(requestRaw.getBytes(java.nio.charset.StandardCharsets.UTF_8)).equals(text(record,"request_sha256")),"request hash differs");
            JSONObject prior=new JSONObject(priorRaw),request=new JSONObject(requestRaw);
            exact(request,"schema","request_nonce","task_id","controller_session_nonce","deadline_elapsed_ms","reason");
            need("hepta.web-helper.close.v2".equals(text(request,"schema"))
                    &&text(request,"request_nonce").matches("[0-9a-f]{64}")
                    &&text(request,"task_id").matches("[0-9a-f]{32}")
                    &&text(request,"controller_session_nonce").matches("[0-9a-f]{64}")
                    &&Arrays.asList("normal","cancelled","error").contains(text(request,"reason")),"fresh close request shape differs");
            JSONObject binding=record.getJSONObject("binding");
            String bindingHash=WebEvidenceBinding.sha256(binding);
            need(bindingHash.equals(text(record,"binding_sha256"))&&bindingHash.equals(text(prior,"binding_sha256"))
                    &&bindingHash.equals(WebEvidenceBinding.sha256(prior.getJSONObject("binding")))
                    &&text(request,"task_id").equals(text(binding,"task_id"))
                    &&text(request,"controller_session_nonce").equals(text(binding,"controller_session_nonce")),"original task/session/binding differs");
            need(prior.has("cleanup")&&same(prior.get("cleanup"),record.get("original_cleanup")),"original cleanup facts were changed or absent");
            JSONObject preserved=record.getJSONObject("preserved_prior_record");
            exact(preserved,"name","bytes","sha256");
            need(text(preserved,"name").equals("unresolved-journal-"+text(record,"prior_journal_sha256")+".json")
                    &&number(preserved,"bytes")==priorBytes.length
                    &&text(preserved,"sha256").equals(text(record,"prior_journal_sha256")),"preserved journal reference differs");
            need(same(binding.getJSONObject("controller_identity"),record.getJSONObject("actual_controller_identity"))
                    &&same(binding.getJSONObject("helper_identity"),record.getJSONObject("actual_helper_identity")),
                    "actual installed identities differ from the recorded lease");
            JSONObject before=record.getJSONObject("native_probe_before"),after=record.getJSONObject("native_probe_after");
            JSONObject first=evaluate(prior,before),last=evaluate(prior,after);
            need(Boolean.TRUE.equals(first.get("verified"))&&Boolean.TRUE.equals(last.get("verified"))
                    &&text(first,"kind").equals(text(last,"kind"))
                    &&number(first,"current_boot_count")==number(last,"current_boot_count")
                    &&same(before.getJSONObject("current_process"),after.getJSONObject("current_process")),
                    "native process/display evidence is not stable across recovery");
            long completed=number(record,"completed_elapsed_ms"),deadline=number(request,"deadline_elapsed_ms");
            need(number(before,"ended_elapsed_ms")<=number(after,"started_elapsed_ms")
                    &&number(after,"ended_elapsed_ms")<=completed&&completed<=deadline
                    &&deadline-number(before,"started_elapsed_ms")<=10000,"recovery does not fit the one close deadline");
            JSONObject storage=record.getJSONObject("storage_retirement");
            boolean storageVerified;
            if(binding.has("storage_profile_name")){
                WebStorageEvidence.requireRetirement(binding,storage);
                need(number(before,"ended_elapsed_ms")<=number(storage,"started_elapsed_ms")
                        &&number(storage,"ended_elapsed_ms")<=number(after,"started_elapsed_ms"),
                        "storage cleanup is outside the native probe bracket");
                storageVerified=true;
            }else{
                exact(storage,"schema","kind","profile_name","clear_invoked","storage_retirement_verified");
                need("hepta.web-helper.recovery-storage-legacy.v1".equals(text(storage,"schema"))
                        &&"legacy_profile_unrecorded".equals(text(storage,"kind"))
                        &&storage.get("profile_name")==JSONObject.NULL
                        &&Boolean.FALSE.equals(storage.get("clear_invoked"))
                        &&Boolean.FALSE.equals(storage.get("storage_retirement_verified"))
                        &&"boot_changed".equals(text(first,"kind")),"legacy storage scope requires an actual reboot and remains unknown");
                storageVerified=false;
            }
            answer.put("retirement_verified",true).put("reason","old_lease_retirement_independently_replayed")
                    .put("kind",text(first,"kind")).put("binding_sha256",bindingHash)
                    .put("prior_journal_sha256",text(record,"prior_journal_sha256"))
                    .put("recorded_profile_retirement_verified",storageVerified)
                    .put("decision_before",first).put("decision_after",last);
        }catch(Exception rejected){answer.put("reason",bounded(rejected.getMessage()));}
        return answer;
    }

    /**
     * A separate proof: this authorized attachment never dispatched WebView construction,
     * profile assignment, page loading or capture. No old destroy/clear call is inferred.
     * The caller must still authenticate the Binder sender and exact FD bytes.
     */
    public static JSONObject evaluateUnstartedRecord(JSONObject record)throws Exception{
        JSONObject answer=new JSONObject().put("schema","hepta.web-helper.unstarted-retirement-verdict.v1")
                .put("retirement_verified",false).put("reason","incomplete_unstarted_record")
                .put("old_cleanup_methods_verified",false).put("storage_cleanup_called",false)
                .put("business_verified",false);
        try{
            JSONObject binding,request,initial;String kind;
            if(WebEvidenceProtocol.UNSTARTED_SCHEMA.equals(text(record,"schema"))){
                validateInitialUnstarted(record);initial=record;binding=record.getJSONObject("binding");
                request=new JSONObject(text(record,"request_json_utf8"));kind="never_started";
            }else{
                exact(record,"schema","request_json_utf8","request_sha256","binding_sha256",
                        "initial_record_utf8","initial_record_bytes","initial_record_sha256",
                        "actual_controller_identity","actual_helper_identity","current_process_identity",
                        "started_elapsed_ms","completed_elapsed_ms","active_bound_view_count","pending_capture_count",
                        "old_cleanup_methods_verified","business_verified");
                need(WebEvidenceProtocol.UNSTARTED_CONFIRMATION_SCHEMA.equals(text(record,"schema"))
                        &&Boolean.FALSE.equals(record.get("old_cleanup_methods_verified"))
                        &&Boolean.FALSE.equals(record.get("business_verified")),"unstarted confirmation scope differs");
                String original=text(record,"initial_record_utf8");
                byte[] bytes=original.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                need(bytes.length>0&&bytes.length<=WebEvidenceProtocol.MAX_UNSTARTED_RECORD_BYTES
                        &&number(record,"initial_record_bytes")==bytes.length
                        &&digest(bytes).equals(text(record,"initial_record_sha256")),"initial unstarted bytes/hash differ");
                initial=new JSONObject(original);
                need(WebEvidenceProtocol.UNSTARTED_SCHEMA.equals(text(initial,"schema")),"confirmation cannot chain another confirmation");
                validateInitialUnstarted(initial);binding=initial.getJSONObject("binding");
                request=unstartedClose(record,binding);
                JSONObject firstRequest=new JSONObject(text(initial,"request_json_utf8"));
                JSONObject attach=new JSONObject(text(initial,"attach_request_json_utf8"));
                need(!text(request,"request_nonce").equals(text(firstRequest,"request_nonce"))
                        &&!text(request,"request_nonce").equals(text(attach,"request_nonce")),"confirmation nonce is not fresh");
                need(WebEvidenceBinding.sha256(binding).equals(text(record,"binding_sha256"))
                        &&same(binding.getJSONObject("controller_identity"),record.getJSONObject("actual_controller_identity"))
                        &&same(binding.getJSONObject("helper_identity"),record.getJSONObject("actual_helper_identity")),"confirmation immutable identity differs");
                JSONObject process=record.getJSONObject("current_process_identity");processShape(process);
                need(integer(process,"uid")==integer(binding.getJSONObject("helper_identity"),"uid")
                        &&integer(process,"pid")>0&&WebEvidenceProtocol.HELPER_PACKAGE.equals(text(process,"process_name"))
                        &&integer(process,"boot_count")>=integer(binding.getJSONObject("background"),"boot_count"),
                        "confirmation current helper process differs");
                long begin=number(record,"started_elapsed_ms"),end=number(record,"completed_elapsed_ms");
                unstartedDeadline(request,begin,end);
                need(number(process,"recorded_elapsed_ms")<=begin
                        &&integer(record,"active_bound_view_count")==0&&integer(record,"pending_capture_count")==0,
                        "confirmation overlaps owned work or predates current process");
                kind="confirmed_never_started";
            }
            answer.put("retirement_verified",true).put("reason","matching_authorized_attachment_never_started_owned_web_resources")
                    .put("kind",kind).put("binding_sha256",WebEvidenceBinding.sha256(binding))
                    .put("task_id",text(binding,"task_id")).put("controller_session_nonce",text(binding,"controller_session_nonce"))
                    .put("request_nonce",text(request,"request_nonce")).put("owned_resources_never_started",true)
                    .put("prior_journal_sha256",text(initial,"prior_journal_sha256"));
        }catch(Exception rejected){answer.put("reason",bounded(rejected.getMessage()));}
        return answer;
    }
    private static void validateInitialUnstarted(JSONObject record)throws Exception{
        exact(record,"schema","request_json_utf8","request_sha256","binding","binding_sha256",
                "attach_request_json_utf8","attach_request_sha256","attach_bound_elapsed_ms",
                "prior_journal_utf8","prior_journal_bytes","prior_journal_sha256","preserved_prior_record",
                "original_cleanup","actual_controller_identity","actual_helper_identity",
                "process_identity_before","process_identity_after","resource_fence_before","resource_fence_after",
                "started_elapsed_ms","completed_elapsed_ms","old_cleanup_methods_verified","business_verified");
        need(WebEvidenceProtocol.UNSTARTED_SCHEMA.equals(text(record,"schema"))
                &&Boolean.FALSE.equals(record.get("old_cleanup_methods_verified"))
                &&Boolean.FALSE.equals(record.get("business_verified")),"initial unstarted scope differs");
        JSONObject binding=record.getJSONObject("binding"),bg=binding.getJSONObject("background");
        String bindingHash=WebEvidenceBinding.sha256(binding);
        need(bindingHash.equals(text(record,"binding_sha256")),"unstarted binding hash differs");
        JSONObject attach=boundedObject(record,"attach_request_json_utf8","attach_request_sha256",WebEvidenceProtocol.MAX_REQUEST_BYTES);
        exactSet(attach,WebEvidenceProtocol.requestKeys(WebEvidenceProtocol.ATTACH));
        need(WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.ATTACH).equals(text(attach,"schema"))
                &&WebEvidenceProtocol.hex64(text(attach,"request_nonce"))
                &&bindingHash.equals(WebEvidenceBinding.sha256(WebEvidenceBinding.fromAttach(attach))),
                "original authorized attach/binding differs");
        need(WebEvidenceProtocol.hex32(text(binding,"task_id"))&&WebEvidenceProtocol.hex64(text(binding,"controller_session_nonce"))
                &&digest(text(binding,"owner").getBytes(java.nio.charset.StandardCharsets.UTF_8)).equals(text(binding,"owner_sha256")),
                "unstarted owner/task/session shape differs");
        JSONObject helper=binding.getJSONObject("helper_identity"),controller=binding.getJSONObject("controller_identity");
        exactSet(helper,WebEvidenceProtocol.IDENTITY_KEYS);exactSet(controller,WebEvidenceProtocol.IDENTITY_KEYS);
        need(WebEvidenceProtocol.HELPER_PACKAGE.equals(text(helper,"package"))
                &&WebEvidenceProtocol.CONTROLLER_PACKAGE.equals(text(controller,"package"))
                &&number(helper,"version_code")==WebEvidenceProtocol.HELPER_VERSION_CODE
                &&integer(helper,"uid")>=10000&&integer(controller,"uid")>=10000
                &&WebEvidenceProtocol.SIGNER_SHA256.equals(text(helper,"signer_sha256"))
                &&WebEvidenceProtocol.SIGNER_SHA256.equals(text(controller,"signer_sha256"))
                &&same(helper,record.getJSONObject("actual_helper_identity"))
                &&same(controller,record.getJSONObject("actual_controller_identity")),"unstarted installed identities differ");
        JSONObject request=unstartedClose(record,binding);
        need(!text(attach,"request_nonce").equals(text(request,"request_nonce")),"close cannot reuse attach nonce");
        String priorRaw=text(record,"prior_journal_utf8");byte[] priorBytes=priorRaw.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        need(priorBytes.length>0&&priorBytes.length<=65536&&priorBytes.length==number(record,"prior_journal_bytes")
                &&digest(priorBytes).equals(text(record,"prior_journal_sha256")),"original unknown journal bytes/hash differ");
        JSONObject prior=new JSONObject(priorRaw);
        need(WebEvidenceProtocol.JOURNAL_SCHEMA.equals(text(prior,"schema"))&&"unknown".equals(text(prior,"state"))
                &&bindingHash.equals(text(prior,"binding_sha256"))
                &&same(binding,prior.getJSONObject("binding"))&&number(prior,"navigation_epoch")==0
                &&text(record,"attach_request_json_utf8").equals(text(prior,"attach_request_json_utf8"))
                &&text(record,"attach_request_sha256").equals(text(prior,"attach_request_sha256"))
                &&text(record,"attach_request_sha256").equals(text(prior.getJSONObject("consumed_requests"),text(attach,"request_nonce"))),
                "original unknown journal does not bind this exact attach");
        JSONObject preserved=record.getJSONObject("preserved_prior_record");
        exact(preserved,"name","bytes","sha256");
        need(text(preserved,"name").equals("unresolved-journal-"+text(record,"prior_journal_sha256")+".json")
                &&number(preserved,"bytes")==priorBytes.length&&text(preserved,"sha256").equals(text(record,"prior_journal_sha256")),
                "unknown original was not retained by exact reference");
        JSONObject cleanup=record.getJSONObject("original_cleanup");exactSet(cleanup,WebEvidenceProtocol.CLEANUP_KEYS);
        need(same(cleanup,prior.get("cleanup"))&&Boolean.TRUE.equals(cleanup.get("active_view_absent")),"original no-resource cleanup differs");
        for(String key:WebEvidenceProtocol.CLEANUP_KEYS)if(!"active_view_absent".equals(key))
            need(Boolean.FALSE.equals(cleanup.get(key)),"unstarted record cannot assert destroy/stop/capture-retire/storage-clear calls");
        need(prior.get("storage_isolation")==JSONObject.NULL,"unstarted journal already has a profile");
        JSONObject first=record.getJSONObject("process_identity_before"),last=record.getJSONObject("process_identity_after");
        processShape(first);processShape(last);
        need(same(first,last)&&same(first,prior.getJSONObject("process_identity"))
                &&integer(first,"pid")==integer(prior,"helper_pid")&&integer(first,"pid")>0
                &&integer(first,"uid")==integer(helper,"uid")&&WebEvidenceProtocol.HELPER_PACKAGE.equals(text(first,"process_name"))
                &&integer(first,"boot_count")==integer(bg,"boot_count"),"unstarted original process identity differs");
        long begin=number(record,"started_elapsed_ms"),end=number(record,"completed_elapsed_ms"),bound=number(record,"attach_bound_elapsed_ms");
        unstartedDeadline(request,begin,end);
        need(number(first,"recorded_elapsed_ms")<=bound&&bound<=begin
                &&bound==number(prior,"attach_bound_elapsed_ms")&&number(bg,"created_elapsed_ms")<=bound
                &&bound<=number(attach,"deadline_elapsed_ms")&&number(attach,"deadline_elapsed_ms")<=number(bg,"expires_elapsed_ms"),
                "original attach time is not within its authorized lease");
        JSONObject before=record.getJSONObject("resource_fence_before"),after=record.getJSONObject("resource_fence_after");
        unstartedFence(before,binding,prior,begin,end);unstartedFence(after,binding,prior,begin,end);
        need(number(before,"observed_elapsed_ms")<=number(after,"observed_elapsed_ms")
                &&number(before,"activity_created_elapsed_ms")<=bound
                &&number(before,"activity_created_elapsed_ms")==number(after,"activity_created_elapsed_ms"),
                "unstarted UI bracket changed");
    }
    private static JSONObject boundedObject(JSONObject record,String rawKey,String hashKey,int limit)throws Exception{
        String raw=text(record,rawKey);byte[] bytes=raw.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        need(bytes.length>0&&bytes.length<=limit&&digest(bytes).equals(text(record,hashKey)),"original request bytes/hash differ");
        return new JSONObject(raw);
    }
    private static JSONObject unstartedClose(JSONObject record,JSONObject binding)throws Exception{
        JSONObject request=boundedObject(record,"request_json_utf8","request_sha256",WebEvidenceProtocol.MAX_REQUEST_BYTES);
        exactSet(request,WebEvidenceProtocol.requestKeys(WebEvidenceProtocol.CLOSE));
        need(WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.CLOSE).equals(text(request,"schema"))
                &&WebEvidenceProtocol.hex64(text(request,"request_nonce"))
                &&text(binding,"task_id").equals(text(request,"task_id"))
                &&text(binding,"controller_session_nonce").equals(text(request,"controller_session_nonce"))
                &&Arrays.asList("normal","cancelled","error").contains(text(request,"reason")),"matching close request required");
        return request;
    }
    private static void unstartedDeadline(JSONObject request,long begin,long end)throws Exception{
        long deadline=number(request,"deadline_elapsed_ms");
        need(begin>0&&end>=begin&&end<=deadline&&deadline-begin<=WebEvidenceProtocol.MAX_RPC_FUTURE_MS
                &&end-begin<=MAX_PROBE_MS,"unstarted evidence exceeds fresh close deadline");
    }
    private static void unstartedFence(JSONObject fence,JSONObject binding,JSONObject prior,long begin,long end)throws Exception{
        exact(fence,"schema","observed_elapsed_ms","activity_created_elapsed_ms","planned_webview_instance",
                "placeholder_window_id","owned_display_id","bound_page","retired",
                "resource_creation_dispatched","profile_assignment_dispatched","load_dispatch_count","capture_dispatch_count",
                "webview_present","capture_present","profile_present","preparing","live_webview_count","pending_capture_count");
        need(WebEvidenceProtocol.UNSTARTED_FENCE_SCHEMA.equals(text(fence,"schema"))
                &&number(fence,"observed_elapsed_ms")>=begin&&number(fence,"observed_elapsed_ms")<=end
                &&number(fence,"activity_created_elapsed_ms")>=number(binding.getJSONObject("background"),"created_elapsed_ms")
                &&text(fence,"planned_webview_instance").equals(text(prior,"webview_instance"))
                &&WebEvidenceProtocol.uuid(text(fence,"planned_webview_instance"))
                &&integer(fence,"placeholder_window_id")==integer(prior,"window_id")&&integer(prior,"window_id")>=0
                &&integer(fence,"owned_display_id")==integer(binding.getJSONObject("background"),"display_id")
                &&integer(fence,"owned_display_id")>0&&Boolean.TRUE.equals(fence.get("bound_page"))
                &&Boolean.TRUE.equals(fence.get("retired")),"unstarted placeholder/fence identity differs");
        for(String key:new String[]{"resource_creation_dispatched","profile_assignment_dispatched","webview_present","capture_present","profile_present","preparing"})
            need(Boolean.FALSE.equals(fence.get(key)),"unstarted fence includes dispatched or active resource");
        for(String key:new String[]{"load_dispatch_count","capture_dispatch_count","live_webview_count","pending_capture_count"})
            need(number(fence,key)==0,"unstarted fence includes owned work");
    }
    private static void exactSet(JSONObject value,Set<String> keys)throws Exception{
        need(value.length()==keys.size(),"unexpected exact JSON keys");
        java.util.Iterator<String> it=value.keys();while(it.hasNext())need(keys.contains(it.next()),"unexpected exact JSON key");
    }

    private static boolean same(Object a,Object b)throws Exception{
        JSONObject left=new JSONObject().put("value",a==null?JSONObject.NULL:a);
        JSONObject right=new JSONObject().put("value",b==null?JSONObject.NULL:b);
        return WebEvidenceBinding.sha256(left).equals(WebEvidenceBinding.sha256(right));
    }
    private static String digest(byte[] bytes)throws Exception{
        byte[] raw=java.security.MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder out=new StringBuilder();for(byte b:raw)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static void processShape(JSONObject process)throws Exception{
        exact(process,"schema","pid","uid","process_name","boot_count","recorded_elapsed_ms","state_summary_hex",
                "state_summary_registered","state_summary_registration_error");
        need("hepta.web-helper.process-identity.v1".equals(text(process,"schema"))
                &&number(process,"recorded_elapsed_ms")>0,"process identity schema/time invalid");
        String token=text(process,"state_summary_hex");
        need(token.matches("[0-9a-f]{2,256}")&&token.length()%2==0,"process summary shape invalid");
        Object registered=process.get("state_summary_registered"),error=process.get("state_summary_registration_error");
        need(registered instanceof Boolean,"process summary registration must be a boolean");
        need(Boolean.TRUE.equals(registered)?error==JSONObject.NULL:error instanceof String,"process summary registration/error inconsistent");
    }
    private static void displaysAbsent(JSONArray rows,int oldId,String oldName)throws Exception{
        need(rows.length()>0&&rows.length()<=MAX_DISPLAYS,"display snapshot unavailable or over budget");
        Set<Integer> ids=new HashSet<Integer>();boolean defaultSeen=false;
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);exact(row,"display_id","name","flags","valid");
            int id=integer(row,"display_id");String name=text(row,"name");
            need(id>=0&&ids.add(id)&&name.length()<=256&&Boolean.TRUE.equals(row.get("valid")),"display snapshot invalid");
            need(id!=oldId&&!oldName.equals(name),"old display ID/name is still present");
            if(id==0)defaultSeen=true;
        }
        need(defaultSeen,"working physical-display enumeration required");
    }
    private static void exact(JSONObject o,String... fields)throws Exception{
        Set<String> wanted=new HashSet<String>(Arrays.asList(fields));need(o.length()==wanted.size(),"unexpected record fields");
        java.util.Iterator<String> keys=o.keys();while(keys.hasNext())need(wanted.contains(keys.next()),"unknown record field");
    }
    private static String text(JSONObject o,String key)throws Exception{Object x=o.get(key);need(x instanceof String,"string required: "+key);return (String)x;}
    private static int integer(JSONObject o,String key)throws Exception{long x=number(o,key);need(x>=Integer.MIN_VALUE&&x<=Integer.MAX_VALUE,"integer range: "+key);return (int)x;}
    private static long number(JSONObject o,String key)throws Exception{Object x=o.get(key);need(x instanceof Integer||x instanceof Long,"integer required: "+key);return ((Number)x).longValue();}
    private static void need(boolean condition,String reason){if(!condition)throw new IllegalArgumentException(reason);}
    private static String bounded(String reason){if(reason==null)return "invalid_retirement_evidence";return reason.length()>240?reason.substring(0,240):reason;}
}
