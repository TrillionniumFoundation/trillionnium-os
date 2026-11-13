package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Bounded children of an actual model-issued notes.create, not model decisions.
 * The fixed intent still proves only draft_opened. This class never creates a
 * note, types text, chooses an unlabeled control, changes OWNER, or grants a tool.
 * Its IO must use the same live service/phase/scope dispatch gates as model IO. */
public final class NotesCreateWorkflow {
    public static final String SCHEMA="hepta.notes-create-workflow.v1";
    public static final String CHILD_SCHEMA="hepta.tool-child.v1";
    public static final int MAX_BACK=2,MAX_CHILDREN=3;
    public static final long MAX_WORKFLOW_MS=45000;
    private NotesCreateWorkflow(){}

    /** Metadata copied from one actual PhoneObservation, never inferred from text. */
    public static final class Observation {
        public final NotesCompletionEvidence.Frame frame;
        public final String treeSha256;
        public final int rotation;
        public Observation(NotesCompletionEvidence.Frame frame,String treeSha256,int rotation){
            require(frame!=null&&isId(frame.observationId)&&isSha(treeSha256)&&rotation>=0&&rotation<=3,
                    "actual observation identity required");
            this.frame=frame;this.treeSha256=treeSha256;this.rotation=rotation;
        }
        public boolean stableWith(Observation other){
            return other!=null&&frame.packageName.equals(other.frame.packageName)
                    &&frame.windowId==other.frame.windowId&&frame.displayId==other.frame.displayId
                    &&Objects.equals(frame.backgroundGeneration,other.frame.backgroundGeneration)
                    &&rotation==other.rotation&&treeSha256.equals(other.treeSha256);
        }
        public Map<String,Object> evidence(){
            Map<String,Object> o=map();o.put("observation_id",frame.observationId);o.put("package",frame.packageName);
            o.put("window_id",frame.windowId);o.put("display_id",frame.displayId);
            o.put("background_generation",frame.backgroundGeneration);o.put("tree_sha256",treeSha256);o.put("rotation",rotation);return o;
        }
    }

    /** Only the task completion gate mints this after its real parent launch/body.
     * A grant is object-bound and single use; serialized hashes are evidence, not capabilities. */
    public static final class Grant {
        public final String taskId,parentRunId,parentObservationId,createdObservationId,attemptId,workflowId;
        public final String ownerSha256,contractSha256,authorizationSha256,bodySha256;
        public final int parentStep,displayId;
        public final String generation;
        final String body;
        final NotesCompletionEvidence.Installed installed;
        final TaskAuthorization authorization;
        private boolean consumed,retired;
        private int issued;
        private ChildCall current;
        Grant(String task,int step,String run,String beforeId,String afterId,String attempt,
              TaskCompletionGate.Contract contract,TaskAuthorization authorization,
              NotesCompletionEvidence.Installed installed,int display,String generation){
            require(isId(task)&&step>0&&step<=20&&isId(run)&&isId(beforeId)&&isId(afterId)&&isSha(attempt),"parent identity required");
            require(contract!=null&&TaskCompletionGate.NOTES.equals(contract.kind)&&contract.body!=null
                    &&contract.body.length()<95&&authorization!=null&&installed!=null,"supported complete parent contract required");
            taskId=task;parentStep=step;parentRunId=run;parentObservationId=beforeId;createdObservationId=afterId;attemptId=attempt;
            this.authorization=authorization;authorizationSha256=authorization.sha256;ownerSha256=contract.ownerSha256;
            contractSha256=contract.contractSha256;body=contract.body;bodySha256=contract.bodySha256;this.installed=installed;
            displayId=display;this.generation=generation;workflowId=hash(task+"|"+run+"|"+attempt+"|"+contractSha256);
        }
        private synchronized void consume(Observation initial){
            require(!consumed&&!retired&&createdObservationId.equals(initial.frame.observationId),"workflow grant used or wrong initial frame");
            require(authorization.allows("notes.create")&&authorization.allows("back")&&authorization.allows("click"),"workflow child authority missing");
            require(body(initial),"created body required before workflow");consumed=true;
        }
        private synchronized ChildCall issue(String action,Observation before){
            require(consumed&&!retired&&current==null&&issued<MAX_CHILDREN,"workflow child grant unavailable");
            require(domain(before)&&authorization.allows(action),"child outside original owner/domain");
            String node=null,label=null;
            if("back".equals(action))require(body(before),"Back requires current created body");
            else if("click".equals(action)){
                NotesCompletionEvidence.ListEvidence list=list(before);require(list.matched,"unique complete list item required");
                node=list.item.nodeId;label=list.item.label;
            }else throw new IllegalArgumentException("workflow primitive not supported");
            current=new ChildCall(this,++issued,action,before.frame.observationId,node,label);return current;
        }
        private synchronized void finish(ChildCall child){
            require(current==child&&child.grant==this&&!child.finished,"wrong or repeated child completion");
            child.finished=true;current=null;
        }
        private synchronized void retire(){retired=true;}
        private synchronized void requireChild(ChildCall child){
            require(consumed&&!retired&&current==child&&!child.finished,"workflow child retired or replaced");
        }
        boolean domain(Observation o){
            NotesCompletionEvidence.Frame f=o==null?null:o.frame;
            return f!=null&&f.metadataObserved&&f.windowType==1&&f.windowId>=0&&!f.nodesTruncated
                    &&NotesCompletionEvidence.NOTES.equals(f.packageName)&&f.displayId==displayId
                    &&Objects.equals(generation,f.backgroundGeneration)
                    &&(displayId==0?generation==null:displayId>0&&generation!=null&&generation.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
        }
        boolean body(Observation o){return domain(o)&&NotesCompletionEvidence.editor(o.frame,body,installed).matched;}
        NotesCompletionEvidence.ListEvidence list(Observation o){return NotesCompletionEvidence.list(o==null?null:o.frame,body);}
        public synchronized Map<String,Object> evidence(){
            Map<String,Object> o=map();o.put("schema",SCHEMA);o.put("workflow_id",workflowId);o.put("task_id",taskId);
            o.put("parent_step",parentStep);o.put("parent_model_run_id",parentRunId);o.put("parent_observation_id",parentObservationId);
            o.put("created_observation_id",createdObservationId);o.put("parent_fixed_intent_attempt_id",attemptId);
            o.put("owner_sha256",ownerSha256);o.put("contract_sha256",contractSha256);o.put("task_authorization_sha256",authorizationSha256);
            o.put("body_sha256",bodySha256);o.put("target_package",installed.packageName);o.put("target_uid",installed.uid);
            o.put("target_apk_sha256",installed.apkHashes);o.put("display_id",displayId);o.put("background_generation",generation);
            o.put("grant_consumed",consumed);o.put("grant_retired",retired);o.put("grants_tool_authority",false);return o;
        }
    }

    /** An internal request cannot be parsed from the model's JSON. The service
     * consumes its entry once and checks it again immediately before each effect. */
    public static final class ChildCall implements ActionDecision.ToolChildOrigin {
        final Grant grant;
        public final int ordinal;
        public final String id,action,observationId,nodeId,nodeLabel;
        private boolean serviceEntered,finished;
        private ChildCall(Grant grant,int ordinal,String action,String observation,String node,String label){
            this.grant=grant;this.ordinal=ordinal;this.action=action;observationId=observation;nodeId=node;nodeLabel=label;
            id=hash(grant.workflowId+"|"+ordinal+"|"+action+"|"+observation+"|"+(node==null?"":node));
        }
        public ActionDecision decision(){return ActionDecision.toolChild(this,action,observationId,NotesCompletionEvidence.NOTES,nodeId,nodeLabel);}
        @Override public void enterService(String task,String authorizationSha,String run,String observation){
            synchronized(grant){
                grant.requireChild(this);require(!serviceEntered&&task.equals(grant.taskId)&&authorizationSha.equals(grant.authorizationSha256)
                        &&run.equals(grant.parentRunId)&&observationId.equals(observation),"child service identity or single-entry gate failed");
                serviceEntered=true;
            }
        }
        @Override public void requireDispatch(String task,String authorizationSha,String run,ActionDecision value){
            synchronized(grant){
                grant.requireChild(this);require(serviceEntered&&value!=null&&value.toolChildOrigin==this
                        &&ActionDecision.TOOL_CHILD_SCHEMA.equals(value.actionSchema)&&task.equals(grant.taskId)
                        &&authorizationSha.equals(grant.authorizationSha256)&&run.equals(grant.parentRunId)
                        &&action.equals(value.action)&&observationId.equals(value.observationId)
                        &&NotesCompletionEvidence.NOTES.equals(value.packageName)&&Objects.equals(nodeId,value.nodeId)
                        &&Objects.equals(nodeLabel,value.nodeLabel),"child dispatch binding changed");
            }
        }
        @Override public Map<String,Object> evidence(){
            synchronized(grant){
                Map<String,Object> o=new LinkedHashMap<String,Object>(grant.evidence());o.put("schema",CHILD_SCHEMA);
                o.put("child_id",id);o.put("child_ordinal",ordinal);o.put("actor_kind","tool_child");o.put("model_issued",false);
                o.put("action",action);o.put("observation_id",observationId);o.put("node_id",nodeId);o.put("node_label",nodeLabel);
                o.put("service_entered",serviceEntered);o.put("automatic_retry_allowed",false);return o;
            }
        }
        private boolean callbackMatches(Dispatch d){
            if(d==null||!d.liveLeaseVerified||d.serviceProof==null||!serviceEntered)return false;
            Map<String,Object> p=d.serviceProof;
            return CHILD_SCHEMA.equals(p.get("schema"))&&"tool_child".equals(p.get("actor_kind"))&&Boolean.FALSE.equals(p.get("model_issued"))
                    &&id.equals(p.get("child_id"))&&grant.workflowId.equals(p.get("workflow_id"))&&grant.taskId.equals(p.get("task_id"))
                    &&grant.parentRunId.equals(p.get("parent_model_run_id"))&&grant.attemptId.equals(p.get("parent_fixed_intent_attempt_id"))
                    &&grant.parentObservationId.equals(p.get("parent_observation_id"))&&grant.createdObservationId.equals(p.get("created_observation_id"))
                    &&number(p.get("parent_step"),grant.parentStep)&&number(p.get("child_ordinal"),ordinal)
                    &&grant.ownerSha256.equals(p.get("owner_sha256"))
                    &&grant.authorizationSha256.equals(p.get("task_authorization_sha256"))&&grant.contractSha256.equals(p.get("contract_sha256"))
                    &&grant.bodySha256.equals(p.get("body_sha256"))&&observationId.equals(p.get("observation_id"))
                    &&action.equals(p.get("action"))&&Objects.equals(nodeId,p.get("node_id"))&&Objects.equals(nodeLabel,p.get("node_label"))
                    &&grant.installed.packageName.equals(p.get("target_package"))&&number(p.get("target_uid"),grant.installed.uid)
                    &&grant.installed.apkHashes.equals(p.get("target_apk_sha256"))&&number(p.get("display_id"),grant.displayId)
                    &&Objects.equals(grant.generation,p.get("background_generation"))&&Boolean.FALSE.equals(p.get("grants_tool_authority"))
                    &&Boolean.TRUE.equals(p.get("grant_consumed"))&&Boolean.TRUE.equals(p.get("service_entered"))
                    &&Boolean.FALSE.equals(p.get("grant_retired"))&&Boolean.FALSE.equals(p.get("automatic_retry_allowed"));
        }
    }
    public static final class Dispatch {
        public final boolean accepted,dispatched,stale,liveLeaseVerified;
        public final String detail;
        public final Map<String,Object> serviceProof;
        public Dispatch(boolean accepted,boolean dispatched,boolean stale,String detail,boolean liveLeaseVerified,Map<String,Object> proof){
            this.accepted=accepted;this.dispatched=dispatched;this.stale=stale;this.detail=detail;this.liveLeaseVerified=liveLeaseVerified;
            serviceProof=proof==null?null:Collections.unmodifiableMap(new LinkedHashMap<String,Object>(proof));
        }
    }
    public static final class ChildRecord {
        public final ChildCall call;public final Observation before,after;public final Dispatch dispatch;
        private ChildRecord(ChildCall call,Observation before,Observation after,Dispatch dispatch){
            this.call=call;this.before=before;this.after=after;this.dispatch=dispatch;
        }
        boolean bound(){return call.finished&&call.callbackMatches(dispatch)&&dispatch.accepted&&dispatch.dispatched&&!dispatch.stale
                &&call.observationId.equals(before.frame.observationId)&&call.grant.domain(before)&&call.grant.domain(after);}
        public Map<String,Object> evidence(){
            Map<String,Object> o=map();o.put("child",call.evidence());o.put("before",before.evidence());o.put("after",after==null?null:after.evidence());
            o.put("accepted",dispatch.accepted);o.put("dispatched",dispatch.dispatched);o.put("stale",dispatch.stale);
            o.put("detail",dispatch.detail);o.put("live_lease_verified",dispatch.liveLeaseVerified);o.put("service_child_receipt",dispatch.serviceProof);return o;
        }
    }
    public interface IO {
        /** Must check cancellation/deadline/actual installed identity and archive the raw observation. */
        Observation observe() throws Exception;
        /** Durable once-only parent/child journal, before any child side effect. */
        void checkpoint(String name,Map<String,Object> evidence) throws Exception;
        /** Must use normal live authorization/phase/scope/domain/no-effect checks. No JSON parsing. */
        Dispatch dispatch(ChildCall child,Observation before) throws Exception;
        void recorded(ChildRecord record) throws Exception;
    }
    public static final class Result {
        final Grant grant;public final Observation initial,current,stableReadback;
        public final List<ChildRecord> children;public final String stopReason;
        private Result(Grant grant,Observation initial,Observation current,Observation stable,List<ChildRecord> children,String reason){
            this.grant=grant;this.initial=initial;this.current=current;stableReadback=stable;
            this.children=Collections.unmodifiableList(new ArrayList<ChildRecord>(children));stopReason=reason;
        }
        /** Pure replay of the actual child chain, not trust in an IO success flag. */
        boolean completeFor(Grant expected){
            if(grant!=expected||!grant.consumed||!grant.retired||stopReason!=null||!grant.body(initial)
                    ||!grant.body(current)||!grant.body(stableReadback)||!current.stableWith(stableReadback)
                    ||children.isEmpty()||children.size()>MAX_CHILDREN)return false;
            int backs=0,clicks=0;Observation last=null;
            for(int i=0;i<children.size();i++){
                ChildRecord r=children.get(i);
                if(r.call.grant!=grant||r.call.ordinal!=i+1||!r.bound())return false;
                if(last!=null&&!last.frame.observationId.equals(r.before.frame.observationId))return false;
                if("back".equals(r.call.action)){
                    if(clicks!=0||++backs>MAX_BACK||!grant.body(r.before))return false;
                    if(!grant.body(r.after)&&!grant.list(r.after).matched)return false;
                }else if("click".equals(r.call.action)){
                    NotesCompletionEvidence.ListEvidence list=grant.list(r.before);
                    if(++clicks!=1||i!=children.size()-1||!list.matched||!list.item.nodeId.equals(r.call.nodeId)
                            ||!list.item.label.equals(r.call.nodeLabel)||!grant.body(r.after))return false;
                }else return false;
                last=r.after;
            }
            return clicks==1&&last!=null&&last.frame.observationId.equals(current.frame.observationId);
        }
        public Map<String,Object> evidence(){
            Map<String,Object> o=grant.evidence();o.put("actor_kind","tool_workflow");o.put("model_issued",false);
            o.put("fixed_intent_outcome_unchanged","draft_opened");o.put("workflow_verified",completeFor(grant));o.put("stop_reason",stopReason);
            o.put("initial",initial.evidence());o.put("current",current==null?null:current.evidence());
            o.put("stable_readback",stableReadback==null?null:stableReadback.evidence());
            List<Map<String,Object>> records=new ArrayList<Map<String,Object>>();for(ChildRecord r:children)records.add(r.evidence());o.put("children",records);
            o.put("model_done_synthesized",false);o.put("persistent_storage_bytes_verified",false);return o;
        }
    }
    public static Result run(Grant grant,Observation initial,IO io)throws Exception{
        require(grant!=null&&io!=null,"workflow grant and IO required");
        List<ChildRecord> records=new ArrayList<ChildRecord>();Observation current=initial,stable=null;String reason=null;
        try{
            grant.consume(initial);io.checkpoint("grant-consumed",grant.evidence());
            current=io.observe();
            if(!grant.body(current)&&!(grant.domain(current)&&grant.list(current).matched))
                return new Result(grant,initial,current,null,records,"fresh_created_body_or_unique_list_unavailable");
            int backs=0;
            while(true){
                require(grant.domain(current),"workflow observation left its Notes domain");
                NotesCompletionEvidence.ListEvidence list=grant.list(current);
                String action;
                if(list.matched)action="click";
                else if(grant.body(current)&&backs<MAX_BACK){action="back";backs++;}
                else{reason="created_body_or_unique_list_unavailable_within_navigation_bound";break;}
                ChildCall child=grant.issue(action,current);io.checkpoint("child-"+child.ordinal+"-planned",child.evidence());
                Dispatch dispatch=io.dispatch(child,current);
                require(dispatch!=null,"workflow child returned no receipt");grant.finish(child);
                if(!dispatch.accepted||!dispatch.dispatched||dispatch.stale||!child.callbackMatches(dispatch)){
                    ChildRecord failed=new ChildRecord(child,current,null,dispatch);records.add(failed);io.recorded(failed);
                    // The parent fixed-intent success is preserved. No child retry or completion promotion.
                    reason="child_not_verified_no_retry";break;
                }
                Observation after=io.observe();ChildRecord row=new ChildRecord(child,current,after,dispatch);
                records.add(row);io.recorded(row);current=after;
                if("click".equals(action)){
                    if(!grant.body(current)){reason="reopened_full_body_missing";break;}
                    stable=io.observe();if(!grant.body(stable)||!current.stableWith(stable))reason="reopened_body_not_stable";
                    break;
                }
                if(!grant.body(current)&&!(grant.domain(current)&&grant.list(current).matched)){
                    reason="left_created_editor_without_unique_verified_list";break;
                }
            }
        }finally{grant.retire();}
        return new Result(grant,initial,current,stable,records,reason);
    }
    private static boolean isId(String s){return s!=null&&s.matches("[0-9a-f]{32}");}
    private static boolean isSha(String s){return s!=null&&s.matches("[0-9a-f]{64}");}
    private static boolean number(Object v,int expected){return (v instanceof Integer||v instanceof Long)&&((Number)v).longValue()==expected;}
    private static Map<String,Object> map(){return new LinkedHashMap<String,Object>();}
    private static String hash(String s){return ObservedImeEnter.hash(s);}
    private static void require(boolean good,String reason){if(!good)throw new IllegalStateException("notes_create_workflow: "+reason);}
}
