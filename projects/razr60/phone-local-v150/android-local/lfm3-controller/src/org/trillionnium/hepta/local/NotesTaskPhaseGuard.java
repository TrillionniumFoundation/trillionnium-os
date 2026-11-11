package org.trillionnium.hepta.local;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.trillionnium.hepta.background.FixedIntentTarget;

/** Task-local restrictions for the existing exact new-note contract. Never a
 * planner, permission grant, persistence verifier, intent replay or UI action. */
public final class NotesTaskPhaseGuard {
    public static final String SCHEMA="hepta.notes-task-phase.v1";
    public final String taskId;
    public final TaskAuthorization authorization;
    public final TaskCompletionGate.Contract contract;
    private Domain current;
    private boolean retired;

    public NotesTaskPhaseGuard(String taskId,TaskAuthorization authorization){
        require(taskId!=null&&taskId.matches("[0-9a-f]{32}")&&authorization!=null,"task and immutable authorization required");
        this.taskId=taskId;this.authorization=authorization;
        contract=TaskCompletionGate.Contract.parse(authorization.immutableOwner(),authorization);
    }
    public boolean supported(){return TaskCompletionGate.NOTES.equals(contract.kind);}
    public synchronized void retire(){retired=true;current=null;}

    public synchronized Projection prepare(TaskCompletionGate completion,NotesCompletionEvidence.Frame frame){
        require(!retired&&frame!=null&&frame.observationId!=null&&frame.observationId.matches("[0-9a-f]{32}"),"live observed frame required");
        if(completion!=null)require(taskId.equals(completion.taskId)
                &&contract.contractSha256.equals(completion.contract.contractSha256),"foreign completion contract");
        TaskCompletionGate.NotesPhase facts=completion==null?null:completion.notesPhase(frame);
        String phase="unrestricted";boolean create=false;String item=null;
        // A restriction may survive identity invalidation; an invalid frame can
        // never use those historical facts to acquire a recovery click.
        boolean ownedBody=supported()&&facts!=null&&facts.launchProved&&facts.editorObserved;
        if(supported()){
            phase="observation_required";
            if(facts!=null&&facts.domainValid){
                if(!facts.launchProved){phase="create_required";create=true;}
                else if(!facts.editorObserved)phase="await_created_editor";
                else if(facts.reopened&&facts.currentBody)phase="verify_reopened_editor";
                else if(facts.listObserved&&facts.currentListItem!=null){phase="reopen_saved_item";item=facts.currentListItem;}
                else if(!facts.listObserved&&facts.currentBody)phase="leave_created_editor";
                else if(ownedBody&&!facts.listObserved&&facts.currentListItem!=null){phase="recover_created_editor";item=facts.currentListItem;}
            }
        }
        return new Projection(this,frame,phase,create,item,ownedBody);
    }
    /** Only the final budgeted action domain is published. A repair replaces it;
     * a late decision cannot borrow an older or another task's domain. */
    public synchronized void publish(Domain domain){
        require(!retired&&domain!=null&&domain.projection.owner==this,"foreign or retired domain");current=domain;
    }
    public synchronized void requireCurrent(ActionDecision action){
        require(!retired,"task retired");
        // Legacy service tests/uses for unknown goals retain their original gates.
        // A supported new-note goal always requires an explicitly published frame.
        if(current==null){require(!supported(),"supported task has no published action domain");return;}
        current.requireAction(action);
    }
    public synchronized void requireCurrent(Domain expected,ActionDecision action)throws ActionDecision.InvalidActionException{
        try{require(!retired&&expected!=null&&expected==current,"action domain retired or replaced");expected.requireAction(action);}
        catch(IllegalStateException denied){throw new ActionDecision.InvalidActionException(denied.getMessage());}
    }
    private static void require(boolean ok,String why){if(!ok)throw new IllegalStateException("notes_task_phase: "+why);}

    public static final class Projection {
        private final NotesTaskPhaseGuard owner;
        public final String phase,observationId,packageName,backgroundGeneration;
        public final int displayId;
        private final boolean createAllowed;
        private final String listItem;
        private final boolean ownedBody;
        private Projection(NotesTaskPhaseGuard owner,NotesCompletionEvidence.Frame frame,String phase,boolean create,String item,boolean ownedBody){
            this.owner=owner;this.phase=phase;observationId=frame.observationId;packageName=frame.packageName;
            displayId=frame.displayId;backgroundGeneration=frame.backgroundGeneration;createAllowed=create;listItem=item;this.ownedBody=ownedBody;
        }
        public Set<String> clicks(Set<String> supplied){
            Set<String> out=new TreeSet<String>(supplied);
            if(!owner.supported()||"leave_created_editor".equals(phase))return out;
            if("reopen_saved_item".equals(phase)||"recover_created_editor".equals(phase))out.retainAll(Collections.singleton(listItem));else out.clear();
            return out;
        }
        /** Once this task's body was observed, an open can only return to Notes
         * from another app. Reopening Notes while already there can bypass the
         * editor-to-list transition and repeat the recovery cycle.
         * The caller still intersects actual catalogue, authorization and scope. */
        public Set<String> openPackages(Set<String> supplied){
            Set<String> out=new TreeSet<String>(supplied);
            if(ownedBody){
                if(NotesCompletionEvidence.NOTES.equals(packageName))out.clear();
                else out.retainAll(Collections.singleton(NotesCompletionEvidence.NOTES));
            }
            return out;
        }
        /** This literal-body contract supplies its entire text once through
         * notes.create; later replacement/submit never belongs to its workflow. */
        public Set<String> edits(Set<String> supplied){return owner.supported()?new TreeSet<String>():new TreeSet<String>(supplied);}
        public <T> Map<String,T> submits(Map<String,T> supplied){return owner.supported()?new TreeMap<String,T>():new TreeMap<String,T>(supplied);}
        public Map<String,FixedIntentTarget> fixedTargets(Map<String,FixedIntentTarget> supplied){
            if(supplied==null)return null;
            Map<String,FixedIntentTarget> out=new TreeMap<String,FixedIntentTarget>(supplied);
            out.keySet().retainAll(owner.authorization.allowedTools);
            if(owner.supported()&&!createAllowed)out.remove("notes.create");return out;
        }
        public Map<String,String> exactPayloads(Map<String,FixedIntentTarget> supplied){
            Map<String,String> out=new TreeMap<String,String>();
            if(owner.supported()&&createAllowed&&supplied!=null&&supplied.containsKey("notes.create"))out.put("notes.create",owner.contract.body);
            return Collections.unmodifiableMap(out);
        }
        public Domain bind(Set<String> clicks,Set<String> edits,Set<String> submits,Map<String,FixedIntentTarget> fixed,Set<String> opens){
            require((clicks.isEmpty()||owner.authorization.allowedTools.contains("click"))
                    &&(edits.isEmpty()||owner.authorization.allowedTools.contains("type"))
                    &&(submits.isEmpty()||owner.authorization.allowedTools.contains("submit"))
                    &&(opens.isEmpty()||owner.authorization.allowedTools.contains("open"))
                    &&(fixed==null||owner.authorization.allowedTools.containsAll(fixed.keySet())),"domain exceeds immutable tool authorization");
            require(clicks(clicks).equals(clicks)&&edits(edits).equals(edits),"domain includes removed node capability");
            require(openPackages(opens).equals(opens),"domain includes removed open package");
            require(!owner.supported()||submits.isEmpty(),"new-note domain includes submit");
            require(!owner.supported()||createAllowed||fixed==null||!fixed.containsKey("notes.create"),"unavailable create included");
            return new Domain(this,clicks,edits,submits,fixed,opens);
        }
        public Map<String,Object> evidence(){
            Map<String,Object> o=new LinkedHashMap<String,Object>();o.put("schema",SCHEMA);o.put("task_id",owner.taskId);
            o.put("owner_sha256",owner.contract.ownerSha256);o.put("contract_sha256",owner.contract.contractSha256);
            o.put("supported",owner.supported());o.put("phase",phase);o.put("observation_id",observationId);
            o.put("display_id",displayId);o.put("background_generation",backgroundGeneration);o.put("grants_tool_authority",false);
            o.put("automatic_dispatch",false);
            if(owner.supported()){
                o.put("expected_body_sha256",owner.contract.bodySha256);
                o.put("direct_text_replacement_allowed",false);o.put("notes_create_expected_text",createAllowed?owner.contract.body:null);
                o.put("open_restricted_to_notes_after_owned_body",ownedBody);
                o.put("next_goal",nextGoal());
            }
            return o;
        }
        private String nextGoal(){
            if("create_required".equals(phase))return "由模型选择可用 notes.create，逐字传入 OWNER 正文；当前已有编辑器不能当成本次新笔记。";
            if("await_created_editor".equals(phase))return "新建入口已派发，等待并观察本次正文；入口接受不等于正文已出现或保存。";
            if("leave_created_editor".equals(phase))return "本次正文已观察。下一目标是离开编辑器并观察真实笔记列表；可选择 back，可能先关闭输入法，须复查。正文、标题或分类不是保存按钮；back 被接受不等于保存。";
            if("recover_created_editor".equals(phase))return "当前列表有本任务已写正文的唯一匹配条目。由模型点击该条目恢复编辑器；恢复不是完成证明，随后仍须离开编辑器、观察列表并重新打开同一条目核对正文。";
            if("reopen_saved_item".equals(phase))return "由模型点击当前列表中已核验的同一正文条目，随后重新观察完整正文。";
            if("verify_reopened_editor".equals(phase))return "已观察同一条目重新打开；核对当前完整正文后由模型选择 done。";
            return "当前没有足以允许笔记编辑的本任务证据；复查观察，无法确认时报告 partial 或 failure。";
        }
    }
    public static final class Domain {
        public final Projection projection;
        public final Set<String> clickIds,editIds,submitIds,fixedActions,openPackages;
        private Domain(Projection p,Set<String> clicks,Set<String> edits,Set<String> submits,Map<String,FixedIntentTarget> fixed,Set<String> opens){
            projection=p;clickIds=immutable(clicks);editIds=immutable(edits);submitIds=immutable(submits);
            fixedActions=immutable(fixed==null?Collections.<String>emptySet():fixed.keySet());openPackages=immutable(opens);
        }
        public void requireAction(ActionDecision action){
            require(action!=null&&projection.observationId.equals(action.observationId),"action belongs to another observation");
            if("open".equals(action.action))require(openPackages.contains(action.packageName),"open absent from current permitted domain");
            if("click".equals(action.action))require(action.nodeId!=null&&clickIds.contains(action.nodeId),"click absent from current permitted domain");
            if("type".equals(action.action))require(action.nodeId!=null&&editIds.contains(action.nodeId),"type absent from current permitted domain");
            if("submit".equals(action.action))require(action.nodeId!=null&&submitIds.contains(action.nodeId),"submit absent from current permitted domain");
            if(projection.owner.supported()&&"notes.create".equals(action.action)){
                require(projection.createAllowed&&fixedActions.contains("notes.create"),"new-note entry unavailable in current phase");
                require(projection.owner.contract.body.equals(action.text),"new-note payload differs from immutable OWNER body");
            }
        }
        public void requireCurrent(ActionDecision action)throws ActionDecision.InvalidActionException{projection.owner.requireCurrent(this,action);}
        private static Set<String> immutable(Set<String> values){return Collections.unmodifiableSet(new TreeSet<String>(values));}
    }
}
