package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Evidence for a bounded supported goal, separate from tool authority and model claims.
 * This class cannot dispatch an action, change OWNER, grant a tool or replay an intent. */
public final class TaskCompletionGate {
    public static final String SCHEMA="hepta.task-completion.v1";
    public static final int MAX_REJECTED_SUCCESS=2;
    public static final String NOTES="notes_save_list_reopen", WEB="web_search_results", UNKNOWN="unverified_goal";
    private static final String NOTE_PREFIX="(?:打开\\s*Moto\\s*笔记(?:（com\\.motorola\\.stylus）|\\(com\\.motorola\\.stylus\\))?[，,]\\s*)?新建(?:一条|一个)?(?:笔记|备忘录)[，,]\\s*";
    private static final String NOTE_TAIL="保存这条新笔记[，,]然后回到笔记列表[，,]重新打开它并停留在正文完整可见的页面[。.]";
    private static final String NOTE_LIMITS="(?:不要修改或删除已有笔记[，,]不分享或发送[。.]?)?";
    // These anchored, documented forms cover one goal. Unconsumed clauses never
    // become a second model-chosen goal or a weakened success criterion.
    private static final Pattern NOTE_LINE=Pattern.compile("^\\s*(?:请)?"+NOTE_PREFIX+"正文完整写入以下一行[：:]([^\\r\\n]+?) "+NOTE_TAIL+NOTE_LIMITS+"\\s*$");
    private static final Pattern NOTE_QUOTED=Pattern.compile("^\\s*(?:请)?"+NOTE_PREFIX+"正文为[：:]?[“]([^“”\\r\\n]+)[”][，, ]*"+NOTE_TAIL+NOTE_LIMITS+"\\s*$");
    public static final class Contract {
        public final String kind,ownerSha256,contractSha256,body,bodySha256,recognition;
        public final int bodyStartUtf16,bodyEndUtf16;
        private Contract(String owner,String kind,String body,String recognition){
            this(owner,kind,body,recognition,-1,-1);
        }
        private Contract(String owner,String kind,String body,String recognition,int start,int end){
            this.kind=kind;this.body=body;this.recognition=recognition;ownerSha256=hash(owner);
            bodyStartUtf16=start;bodyEndUtf16=end;
            bodySha256=body==null?null:hash(body);
            contractSha256=hash(SCHEMA+"\n"+ownerSha256+"\n"+kind+"\n"+(bodySha256==null?"":bodySha256)+"\n"+recognition);
        }
        public static Contract parse(String owner,TaskAuthorization authorization){
            if(authorization==null)throw new IllegalArgumentException("owner authorization required");
            authorization.requireOwner(owner);
            Matcher line=NOTE_LINE.matcher(owner),quoted=NOTE_QUOTED.matcher(owner);
            String body=null,form=null;
            if(line.matches()){body=line.group(1);form="literal_single_line_save_list_reopen.v1";}
            else if(quoted.matches()){body=quoted.group(1);form="quoted_single_note_save_list_reopen.v1";}
            if(body!=null){
                try{org.trillionnium.hepta.background.FixedIntentTools.forAction("notes.create").validatePayload(body);}
                catch(IllegalArgumentException invalid){return new Contract(owner,UNKNOWN,null,"unsupported_literal_body");}
                return new Contract(owner,NOTES,body,form);
            }
            NotesOwnerIntent.Result note=NotesOwnerIntent.parse(owner);
            if(note.supported&&note.saveAndReopenRequested&&!note.draftOnly)
                return new Contract(owner,NOTES,note.body,NotesOwnerIntent.SCHEMA+"/"+note.recognition,
                        note.bodyStartUtf16,note.bodyEndUtf16);
            // A method hint never grants success: no web-result provider exists.
            // Only unquoted OWNER text is considered, never screen or model data.
            String plain=unquoted(owner);
            if(plain.contains("web.search")||plain.contains("网页查询")||plain.contains("网页搜索"))
                return new Contract(owner,WEB,null,"explicit_web_method_no_result_provider");
            return new Contract(owner,UNKNOWN,null,"no_complete_supported_owner_contract");
        }
        public Map<String,Object> evidence(){
            Map<String,Object> o=new LinkedHashMap<String,Object>();o.put("schema",SCHEMA);o.put("kind",kind);
            o.put("owner_sha256",ownerSha256);o.put("contract_sha256",contractSha256);o.put("recognition",recognition);
            o.put("expected_body_sha256",bodySha256);o.put("source","immutable_owner_contract");
            if(bodyStartUtf16>=0){o.put("body_source_start_utf16",bodyStartUtf16);o.put("body_source_end_utf16",bodyEndUtf16);
                o.put("note_persistence_verification_policy","save_list_reopen");o.put("body_rewritten",false);}
            o.put("model_may_change_goal",false);o.put("grants_tool_authority",false);return o;
        }
    }
    public static final class Check {
        public final boolean verified,retryAllowed;public final Map<String,Object> evidence;
        private Check(boolean verified,boolean retry,Map<String,Object> evidence){this.verified=verified;retryAllowed=retry;this.evidence=Collections.unmodifiableMap(evidence);}
    }
    public final String taskId;public final Contract contract;
    private final TaskAuthorization authorization;
    private NotesCompletionEvidence.Installed installed;
    private boolean domainBound,identityInvalid,launchProved,editorObserved,listObserved,reopened,webDispatched,priorVisibleBodyCollision;
    private int displayId=-1,rejectedSuccess;private String generation,identityFailure,editorObservationId;
    private final List<Map<String,Object>> proofs=new ArrayList<Map<String,Object>>();
    private final List<Map<String,Object>> claims=new ArrayList<Map<String,Object>>();
    private int parentCreateStep;
    private String parentCreateRun,parentCreateAttempt,parentCreateBefore,parentCreateAfter,reopenActor;
    private NotesCreateWorkflow.Grant workflowGrant;
    private boolean workflowProofConsumed,workflowCompletionAccepted;
    private String workflowVerifiedObservationId;
    private Map<String,Object> workflowEvidence;
    public TaskCompletionGate(String task,String owner,TaskAuthorization authorization){
        require(id(task),"task identity required");taskId=task;contract=Contract.parse(owner,authorization);this.authorization=authorization;
    }
    public void bindInstalled(NotesCompletionEvidence.Installed value){
        require(installed==null&&!launchProved,"installed completion identity already bound");installed=value;
    }
    public void invalidateInstalled(String reason){identityInvalid=true;identityFailure=reason==null?"installed_identity_unavailable":reason;}
    public void observed(NotesCompletionEvidence.Frame frame){
        if(!domainShape(frame))return;
        if(!domainBound){displayId=frame.displayId;generation=frame.backgroundGeneration;domainBound=true;}
        if(!sameDomain(frame)){identityInvalid=true;identityFailure="observation_display_generation_changed";return;}
        if(!NOTES.equals(contract.kind)||!launchProved||identityInvalid||installed==null)return;
        if(!editorObserved&&body(frame).matched){
            editorObserved=true;editorObservationId=frame.observationId;
            proofs.add(proof("editor_body_observed",0,null,frame,frame));
        }
        // Saving may become observable after an app switch or a later reobserve.
        // The current complete list is evidence; no particular navigation API or
        // accepted action is itself a save acknowledgement. Prior task-bound
        // create/body proof and the later model click/reopened body remain required.
        if(editorObserved&&!listObserved){
            NotesCompletionEvidence.ListEvidence list=NotesCompletionEvidence.list(frame,contract.body);
            if(list.matched){
                listObserved=true;Map<String,Object> p=proof("post_create_observed_list",0,null,null,frame);
                p.put("editor_observation_id",editorObservationId);p.put("list_body_evidence",list.evidence());
                proofs.add(p);
            }
        }
    }
    public void action(int step,String run,ActionDecision action,boolean accepted,boolean dispatched,boolean stale,
                       NotesCompletionEvidence.Frame before,NotesCompletionEvidence.Frame after,Map<String,Object> fixed){
        require(step>0&&step<=20&&id(run)&&action!=null&&before!=null&&after!=null,"actual bounded model/action observations required");
        require(action.toolChildOrigin==null,"tool children require their separate parent-bound proof path");
        require(action.observationId.equals(before.observationId),"action must bind its actual before observation");
        observed(before);
        if(!domainShape(before)||!domainShape(after)){observed(after);return;}
        if(!sameDomain(before)||!sameDomain(after)){identityInvalid=true;identityFailure="action_display_generation_changed";return;}
        if(!accepted||!dispatched||stale){observed(after);return;}
        if("web.search".equals(action.action)&&fixedMatches(action,run,before,fixed,false)){
            webDispatched=true;proofs.add(proof("web_query_dispatch_only",step,run,before,after));
        }
        if(!NOTES.equals(contract.kind)){observed(after);return;}
        NotesCompletionEvidence.BodyEvidence beforeBody=body(before),afterBody=body(after);
        NotesCompletionEvidence.ListEvidence beforeList=NotesCompletionEvidence.list(before,contract.body),afterList=NotesCompletionEvidence.list(after,contract.body);
        // A pre-existing full body in the actual before editor/list cannot prove
        // that the new draft, rather than an old identical item, was persisted.
        // The nonunique result comes only after the provider has validated the
        // real list scope and found multiple complete executable body matches.
        boolean beforeListBody=beforeList.matched||"complete_body_list_item_is_not_unique".equals(beforeList.missing);
        if("notes.create".equals(action.action)&&contract.body.equals(action.text)&&!launchProved
                &&fixedMatches(action,run,before,fixed,true)&&(beforeBody.matched||beforeListBody)){
            priorVisibleBodyCollision=true;Map<String,Object> p=proof("prior_visible_body_collision",step,run,before,after);
            p.put("before_editor_body_matched",beforeBody.matched);p.put("before_list_body_evidence",beforeList.evidence());
            p.put("unobserved_prior_notes_known",false);proofs.add(p);
        }
        if("notes.create".equals(action.action)&&contract.body.equals(action.text)&&!launchProved
                &&fixedMatches(action,run,before,fixed,true)&&!beforeBody.matched&&!beforeListBody&&!priorVisibleBodyCollision){
            launchProved=true;Map<String,Object> p=proof("model_bound_notes_launch",step,run,before,after);
            p.put("attempt_id",fixed.get("attempt_id"));p.put("payload_sha256",contract.bodySha256);proofs.add(p);
            parentCreateStep=step;parentCreateRun=run;parentCreateAttempt=(String)fixed.get("attempt_id");
            parentCreateBefore=before.observationId;parentCreateAfter=after.observationId;
        }else if(editorObserved&&!listObserved&&("back".equals(action.action)||"click".equals(action.action))
                &&NotesCompletionEvidence.NOTES.equals(action.packageName)&&beforeBody.matched&&afterList.matched){
            listObserved=true;Map<String,Object> p=proof("editor_to_observed_list",step,run,before,after);
            p.put("list_body_evidence",afterList.evidence());proofs.add(p);
        }else if(listObserved&&!reopened&&"click".equals(action.action)&&NotesCompletionEvidence.NOTES.equals(action.packageName)
                &&beforeList.matched&&Objects.equals(beforeList.item.nodeId,action.nodeId)
                &&Objects.equals(beforeList.item.label,action.nodeLabel)&&afterBody.matched){
            reopened=true;reopenActor="model";Map<String,Object> p=proof("same_observed_list_item_reopened",step,run,before,after);
            p.put("node_id",action.nodeId);p.put("node_label",action.nodeLabel);p.put("body_raw_exact",afterBody.rawExact);
            p.put("list_body_evidence",beforeList.evidence());proofs.add(p);
        }
        observed(after);
    }
    /** Declares the supported high-level mode; it adds no authority. Draft-only,
     * unknown goals and insufficient primitive permissions retain draft behavior. */
    public boolean notesCreateWorkflowRequested(TaskAuthorization.Frame frame){
        return frame!=null&&frame.authorization==authorization&&taskId.equals(frame.taskId)
                &&NOTES.equals(contract.kind)&&contract.body!=null&&contract.body.length()<95
                &&frame.allows("notes.create")&&frame.allows("back")&&frame.allows("click");
    }
    public NotesCreateWorkflow.Grant notesCreateWorkflow(int step,String run,ActionDecision parent,
            NotesCreateWorkflow.Observation created,TaskAuthorization.Frame frame){
        if(!notesCreateWorkflowRequested(frame)||workflowGrant!=null||parent==null||parent.toolChildOrigin!=null
                ||!"notes.create".equals(parent.action)||step!=parentCreateStep||!Objects.equals(run,parentCreateRun)
                ||!Objects.equals(parent.observationId,parentCreateBefore)||!contract.body.equals(parent.text)
                ||created==null||!Objects.equals(created.frame.observationId,parentCreateAfter)
                ||!launchProved||!editorObserved||identityInvalid||priorVisibleBodyCollision||installed==null||!sameDomain(created.frame)
                ||!body(created.frame).matched)return null;
        workflowGrant=new NotesCreateWorkflow.Grant(taskId,step,run,parentCreateBefore,parentCreateAfter,parentCreateAttempt,
                contract,authorization,installed,displayId,generation);
        return workflowGrant;
    }
    /** Consumes a real in-process child chain separately from model-click proof.
     * Serialized workflow_verified/model text can never call this path. */
    public boolean notesCreateWorkflowCompleted(NotesCreateWorkflow.Result result,NotesCompletionEvidence.Frame current){
        require(result!=null&&workflowGrant!=null&&result.grant==workflowGrant&&!workflowProofConsumed,
                "workflow result belongs to another or consumed parent");
        workflowProofConsumed=true;workflowEvidence=result.evidence();observed(current);
        boolean good=NOTES.equals(contract.kind)&&!identityInvalid&&installed==workflowGrant.installed
                &&launchProved&&editorObserved&&sameDomain(current)&&body(current).matched
                &&result.stableReadback!=null&&current.observationId.equals(result.stableReadback.frame.observationId)
                &&result.completeFor(workflowGrant);
        workflowCompletionAccepted=good;if(!good)return false;
        workflowVerifiedObservationId=current.observationId;
        listObserved=true;reopened=true;reopenActor="tool_child";
        Map<String,Object> p=proof("tool_child_same_observed_list_item_reopened",workflowGrant.parentStep,
                workflowGrant.parentRunId,result.initial.frame,result.stableReadback.frame);
        p.put("actor_kind","tool_child");p.put("model_issued",false);p.put("workflow_id",workflowGrant.workflowId);
        p.put("parent_fixed_intent_attempt_id",workflowGrant.attemptId);p.put("workflow_evidence",workflowEvidence);proofs.add(p);
        return true;
    }
    /** Controller-owned completion is available only for this consumed parent
     * workflow and its actual stable readback. It is not a model success claim. */
    public boolean controllerWorkflowReady(NotesCompletionEvidence.Frame current){
        return workflowCompletionAccepted&&workflowProofConsumed&&workflowGrant!=null
                &&current!=null&&Objects.equals(workflowVerifiedObservationId,current.observationId)&&verified(current);
    }
    public String controllerCompletionSummary(){return "已保存并重新打开这条笔记，正文核对一致。";}
    public Check successClaim(int step,String run,NotesCompletionEvidence.Frame current){return successClaim(step,run,current,true);}
    public Check successClaim(int step,String run,NotesCompletionEvidence.Frame current,boolean finalObservationStable){
        require(step>0&&step<=20&&id(run),"completion claim native identity required");observed(current);
        boolean verified=finalObservationStable&&verified(current);Map<String,Object> claim=proof("native_done_success_claim",step,run,current,current);
        claim.put("completion_verified",verified);claims.add(claim);
        if(!verified)rejectedSuccess++;
        Map<String,Object> value=evidence(current);value.put("check_step",step);value.put("check_model_run_id",run);
        value.put("model_reported_success",true);value.put("accepted_as_completed",verified);value.put("final_observation_stable",finalObservationStable);
        if(!finalObservationStable){List<String> absent=new ArrayList<String>(missing(current));absent.add("final_observation_changed_reobserve");value.put("missing",absent);}
        value.put("retry_allowed",!verified&&rejectedSuccess<MAX_REJECTED_SUCCESS);
        return new Check(verified,!verified&&rejectedSuccess<MAX_REJECTED_SUCCESS,value);
    }
    public boolean verified(NotesCompletionEvidence.Frame current){
        return NOTES.equals(contract.kind)&&domainBound&&!identityInvalid&&installed!=null
                &&launchProved&&editorObserved&&listObserved&&reopened&&sameDomain(current)&&body(current).matched;
    }
    /** Read-only existing evidence for an execution restriction. This grants no action
     * and does not alter any completion transition or provider predicate. */
    public static final class NotesPhase {
        public final boolean domainValid,launchProved,editorObserved,listObserved,reopened,currentBody;
        public final String currentListItem;
        private NotesPhase(boolean valid,boolean launch,boolean editor,boolean list,boolean reopened,
                           boolean currentBody,String item){
            domainValid=valid;launchProved=launch;editorObserved=editor;listObserved=list;
            this.reopened=reopened;this.currentBody=currentBody;currentListItem=item;
        }
        /** Current provider facts, independent of the cumulative task phase. */
        public String currentSurface(){
            if(!domainValid)return "unverified";
            if(currentBody&&currentListItem==null)return "verified_note_editor";
            if(!currentBody&&currentListItem!=null)return "verified_note_list";
            return "unverified";
        }
    }
    public NotesPhase notesPhase(NotesCompletionEvidence.Frame current){
        boolean valid=NOTES.equals(contract.kind)&&domainBound&&!identityInvalid&&installed!=null&&sameDomain(current);
        NotesCompletionEvidence.ListEvidence list=valid?NotesCompletionEvidence.list(current,contract.body):null;
        return new NotesPhase(valid,launchProved,editorObserved,listObserved,reopened,
                valid&&body(current).matched,list!=null&&list.matched?list.item.nodeId:null);
    }
    public Map<String,Object> prompt(NotesCompletionEvidence.Frame current){
        Map<String,Object> o=new LinkedHashMap<String,Object>();o.put("schema",SCHEMA);o.put("kind",contract.kind);
        o.put("owner_sha256",contract.ownerSha256);o.put("contract_sha256",contract.contractSha256);
        o.put("source","controller_observation_checks_not_model_claims");o.put("completion_verified",verified(current));
        o.put("missing",missing(current));o.put("rejected_success_claims",rejectedSuccess);o.put("max_rejected_success_claims",MAX_REJECTED_SUCCESS);
        if(NOTES.equals(contract.kind)){
            o.put("notes_launch_observed",launchProved);o.put("editor_body_observed",editorObserved);o.put("list_observed",listObserved);
            o.put("prior_visible_body_collision",priorVisibleBodyCollision);o.put("unobserved_prior_notes_known",false);
            o.put("same_list_item_reopened",reopened);
            if(reopenActor!=null)o.put("reopen_actor_kind",reopenActor);
            if(workflowEvidence!=null){o.put("notes_create_workflow_verified",workflowCompletionAccepted);
                o.put("notes_create_workflow_stop_reason",workflowEvidence.get("stop_reason"));}
            o.put("progress_scope","cumulative_task_evidence_not_current_screen");
            NotesPhase facts=notesPhase(current);
            o.put("current_surface",facts.currentSurface());o.put("current_list_item_node_id",facts.currentListItem);
            o.put("current_editor_body_matched",facts.currentBody);
        }else if(WEB.equals(contract.kind))o.put("web_query_dispatched",webDispatched);
        o.put("writes_required_for_unknown_or_read_only_goal",false);o.put("grants_tool_authority",false);return o;
    }
    public Map<String,Object> evidence(NotesCompletionEvidence.Frame current){
        Map<String,Object> o=prompt(current);o.put("task_id",taskId);o.put("contract",contract.evidence());
        o.put("proofs",new ArrayList<Map<String,Object>>(proofs));o.put("model_success_claims",new ArrayList<Map<String,Object>>(claims));
        o.put("identity_failure",identityFailure);o.put("display_id",domainBound?displayId:null);o.put("background_generation",generation);
        if(workflowEvidence!=null)o.put("notes_create_workflow",workflowEvidence);
        o.put("persistent_storage_bytes_verified",false);o.put("new_database_item_identity_verified",false);
        if(NOTES.equals(contract.kind)){NotesCompletionEvidence.BodyEvidence v=body(current);o.put("current_editor_raw_exact",v.rawExact);o.put("current_body_evidence",bodyEvidence(v));
            NotesCompletionEvidence.ListEvidence list=NotesCompletionEvidence.list(current,contract.body);o.put("current_list_match",list.matched);o.put("current_list_missing",list.missing);
            o.put("current_list_evidence",list.evidence());}
        return o;
    }
    public String completionSummary(){return "已核验本次正文进入笔记编辑器、返回列表并点击同一可访问正文条目重新打开；列表视觉裁切与存储原始字节未核验。";}
    public String incompleteSummary(){
        if(NOTES.equals(contract.kind))return "未完成验证：缺少本次笔记保存、列表或同一条目重新打开的完整证据。";
        if(WEB.equals(contract.kind))return webDispatched?"已发起网页查询，但尚无实际结果证明，任务部分完成。":"未确认网页查询及结果，任务未验证完成。";
        return "模型提出结束，但本次目标没有可用的完成验证，任务部分完成；请核对实际状态。";
    }
    private List<String> missing(NotesCompletionEvidence.Frame current){
        List<String> out=new ArrayList<String>();
        if(identityInvalid)out.add("observation_or_installed_identity_invalid");
        if(NOTES.equals(contract.kind)){
            if(installed==null)out.add("installed_notes_identity_unavailable");
            if(priorVisibleBodyCollision)out.add("preexisting_visible_body_cannot_prove_new_note_saved");
            if(!launchProved)out.add("model_bound_notes_create_with_owner_body_missing");
            if(!editorObserved)out.add("actual_editor_body_missing");
            if(!listObserved)out.add("save_then_real_list_with_unique_body_item_missing");
            if(!reopened)out.add("model_click_same_list_item_then_reopened_body_missing");
            if(!body(current).matched)out.add("current_editor_body_missing");
        }else if(WEB.equals(contract.kind)){
            if(!webDispatched)out.add("model_bound_web_query_dispatch_missing");out.add("web_results_provider_unavailable");
        }else out.add("complete_owner_goal_verifier_unavailable");
        return Collections.unmodifiableList(out);
    }
    private static Map<String,Object> bodyEvidence(NotesCompletionEvidence.BodyEvidence value){
        Map<String,Object> o=new LinkedHashMap<String,Object>();o.put("matched",value.matched);o.put("raw_exact",value.rawExact);
        o.put("persistent_bytes_verified",value.persistentBytesVerified);o.put("node_id",value.nodeId);o.put("action_label",value.actionLabel);
        o.put("raw_text_sha256",value.rawTextSha256);o.put("body_sha256",value.bodySha256);o.put("trailing_lf_count",value.trailingLfCount);
        o.put("match_rule",value.matchRule);o.put("missing",value.missing);return o;
    }
    private NotesCompletionEvidence.BodyEvidence body(NotesCompletionEvidence.Frame frame){return NotesCompletionEvidence.editor(frame,contract.body,installed);}
    private boolean sameDomain(NotesCompletionEvidence.Frame frame){return domainShape(frame)&&domainBound&&frame.displayId==displayId&&Objects.equals(frame.backgroundGeneration,generation);}
    private static boolean domainShape(NotesCompletionEvidence.Frame frame){
        return frame!=null&&frame.metadataObserved&&frame.windowType==1&&frame.windowId>=0&&frame.displayId>=0
                &&(frame.displayId==0?frame.backgroundGeneration==null:frame.backgroundGeneration!=null&&frame.backgroundGeneration.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }
    @SuppressWarnings("unchecked") private boolean fixedMatches(ActionDecision action,String run,NotesCompletionEvidence.Frame before,Map<String,Object> fixed,boolean note){
        if(fixed==null||!"hepta.fixed-intent-result.v1".equals(fixed.get("schema"))||!taskId.equals(fixed.get("task_id"))
                ||!run.equals(fixed.get("model_run_id"))||!before.observationId.equals(fixed.get("observation_id"))
                ||!before.packageName.equals(fixed.get("source_package"))||!number(fixed.get("source_window_id"),before.windowId)
                ||!number(fixed.get("display_id"),before.displayId)||!Objects.equals(before.backgroundGeneration,fixed.get("background_generation"))
                ||!action.action.equals(fixed.get("action"))||!Boolean.TRUE.equals(fixed.get("attempt_consumed"))
                ||!Boolean.TRUE.equals(fixed.get("dispatch_attempted"))||!Boolean.TRUE.equals(fixed.get("api_accepted"))
                ||!Boolean.FALSE.equals(fixed.get("automatic_retry_allowed"))||!"launch_accepted".equals(fixed.get("result")))return false;
        String payload=note?action.text:action.query;if(payload==null||!hash(payload).equals(fixed.get("payload_sha256")))return false;
        Object ordinal=fixed.get("attempt_ordinal");
        if(!(ordinal instanceof Number)||((Number)ordinal).intValue()<1||((Number)ordinal).intValue()>2
                ||!hash(taskId+"|"+((Number)ordinal).intValue()+"|"+action.action+"|"+hash(payload)).equals(fixed.get("attempt_id")))return false;
        Object t=fixed.get("target");if(!(t instanceof Map))return false;Map<String,Object> target=(Map<String,Object>)t;
        org.trillionnium.hepta.background.FixedIntentTools.Profile profile=org.trillionnium.hepta.background.FixedIntentTools.forAction(action.action);
        if(profile==null||!profile.packageName.equals(action.packageName)||!profile.packageName.equals(target.get("package"))
                ||!(profile.packageName+"/"+profile.className).equals(target.get("component"))||!action.action.equals(target.get("action"))||!(target.get("app_label") instanceof String)
                ||!Objects.equals(ObservedAppLabels.project((String)target.get("app_label")),action.appLabel))return false;
        for(String key:new String[]{"exported","activity_enabled","application_enabled","declared_intent_filter_matched","ordinary_caller_permission_checked"})if(!Boolean.TRUE.equals(target.get(key)))return false;
        Object uid=target.get("target_uid");if(!(uid instanceof Number)||((Number)uid).intValue()<10000||((Number)uid).intValue()>=90000)return false;
        return !note||(installed!=null&&!identityInvalid&&number(uid,installed.uid)&&contract.bodySha256.equals(fixed.get("payload_sha256")));
    }
    private static Map<String,Object> proof(String kind,int step,String run,NotesCompletionEvidence.Frame before,NotesCompletionEvidence.Frame after){
        Map<String,Object> o=new LinkedHashMap<String,Object>();o.put("kind",kind);o.put("step",step);o.put("model_run_id",run);
        o.put("before_observation_id",before==null?null:before.observationId);o.put("after_observation_id",after==null?null:after.observationId);
        return o;
    }
    private static boolean number(Object value,int expected){return value instanceof Number&&((Number)value).longValue()==expected;}
    private static boolean id(String v){return v!=null&&v.matches("[0-9a-f]{32}");}
    private static void require(boolean b,String why){if(!b)throw new IllegalArgumentException("completion: "+why);}
    private static String hash(String value){return ObservedImeEnter.hash(value);}
    private static String unquoted(String s){StringBuilder out=new StringBuilder(s);char close=0;for(int i=0;i<s.length();i++){char c=s.charAt(i);if(close==0){if(c=='“'||c=='‘'||c=='\"'||c=='\''){close=c=='“'?'”':c=='‘'?'’':c;out.setCharAt(i,' ');}}else{out.setCharAt(i,' ');if(c==close)close=0;}}return out.toString();}
}
