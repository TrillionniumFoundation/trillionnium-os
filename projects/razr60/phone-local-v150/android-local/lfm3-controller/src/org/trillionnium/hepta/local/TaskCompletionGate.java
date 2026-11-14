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
        /** The exact selection-owned goal, never reparsed from model or screen text. */
        public final NativeAppGoal nativeGoal;
        public final String executionTargetSha256;
        private Contract(String owner,String kind,String body,String recognition){
            this(owner,kind,body,recognition,-1,-1);
        }
        private Contract(String owner,String kind,String body,String recognition,int start,int end){
            this(owner,kind,body,recognition,start,end,null);
        }
        private Contract(String owner,String kind,String body,String recognition,int start,int end,BackgroundTaskTarget target){
            this.kind=kind;this.body=body;this.recognition=recognition;ownerSha256=hash(owner);
            nativeGoal=target==null?null:target.nativeGoal;
            executionTargetSha256=target==null?null:target.targetSha256;
            if(target!=null){
                target.requireOwner(owner);
                require(target.explicitSelection&&!target.webHelper(),"native contract requires the actual explicit native target");
                if(nativeGoal!=null){nativeGoal.requireBinding(owner,target.packageName);require(kind.equals(nativeGoal.kind),"native contract kind differs");}
            }
            bodyStartUtf16=start;bodyEndUtf16=end;
            bodySha256=body==null?null:hash(body);
            contractSha256=hash(SCHEMA+"\n"+ownerSha256+"\n"+kind+"\n"+(bodySha256==null?"":bodySha256)+"\n"+recognition
                    +(target==null?"":"\n"+target.targetSha256+"\n"+(nativeGoal==null?"":nativeGoal.contractSha256)));
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
            org.trillionnium.hepta.local.web.WebFlightGoal flight=org.trillionnium.hepta.local.web.WebFlightGoal.parse(owner);
            if(flight!=null)return new Contract(owner,WEB,null,flight.naturalReadOnlyIntent?
                    "natural_csair_flight_owner.v1":"official_csair_flight_owner.v1");
            org.trillionnium.hepta.local.web.WebShoppingGoal shopping=org.trillionnium.hepta.local.web.WebShoppingGoal.parse(owner);
            if(shopping!=null)return new Contract(owner,WEB,null,"official_mi_product_owner.v1");
            // A method hint never grants success: no web-result provider exists.
            // Only unquoted OWNER text is considered, never screen or model data.
            String plain=unquoted(owner);
            if(plain.contains("web.search")||plain.contains("网页查询")||plain.contains("网页搜索"))
                return new Contract(owner,WEB,null,"explicit_web_method_no_result_provider");
            return new Contract(owner,UNKNOWN,null,"no_complete_supported_owner_contract");
        }
        private static Contract forExplicitTarget(String owner,TaskAuthorization authorization,BackgroundTaskTarget target){
            Contract original=parse(owner,authorization);
            if(target==null||target.webHelper()||(NOTES.equals(original.kind)&&NotesCompletionEvidence.NOTES.equals(target.packageName)))return original;
            target.requireOwner(owner);
            NativeAppGoal goal=target.nativeGoal;
            // Unsupported native instructions retain UNKNOWN. A pure legacy Web
            // recognizer cannot turn the explicitly selected native App into Web.
            return new Contract(owner,goal==null?UNKNOWN:goal.kind,null,
                    goal==null?"explicit_native_app_no_complete_supported_goal":goal.recognition,-1,-1,target);
        }
        public Map<String,Object> evidence(){
            Map<String,Object> o=new LinkedHashMap<String,Object>();o.put("schema",SCHEMA);o.put("kind",kind);
            o.put("owner_sha256",ownerSha256);o.put("contract_sha256",contractSha256);o.put("recognition",recognition);
            o.put("expected_body_sha256",bodySha256);o.put("source","immutable_owner_contract");
            if(bodyStartUtf16>=0){o.put("body_source_start_utf16",bodyStartUtf16);o.put("body_source_end_utf16",bodyEndUtf16);
                o.put("note_persistence_verification_policy","save_list_reopen");o.put("body_rewritten",false);}
            if(executionTargetSha256!=null){
                o.put("execution_target_sha256",executionTargetSha256);o.put("route",BackgroundTaskTarget.NATIVE_APP);
                o.put("native_app_goal",nativeGoal==null?null:nativeGoal.evidence());
            }
            o.put("model_may_change_goal",false);o.put("grants_tool_authority",false);return o;
        }
    }
    public static final class Check {
        public final boolean verified,retryAllowed;public final Map<String,Object> evidence;
        private Check(boolean verified,boolean retry,Map<String,Object> evidence){this.verified=verified;retryAllowed=retry;this.evidence=Collections.unmodifiableMap(evidence);}
    }
    public final String taskId;public final Contract contract;
    private final TaskAuthorization authorization;
    private final BackgroundTaskTarget.SelectionBinding executionSelection;
    private final BackgroundTaskTarget executionTarget;
    private NotesCompletionEvidence.Installed installed;
    private boolean domainBound,identityInvalid,launchProved,editorObserved,listObserved,reopened,webDispatched,priorVisibleBodyCollision;
    private int displayId=-1,rejectedSuccess;private String generation,identityFailure,editorObservationId;
    private final List<Map<String,Object>> proofs=new ArrayList<Map<String,Object>>();
    private final List<Map<String,Object>> claims=new ArrayList<Map<String,Object>>();
    public static final int NOTES_EDITOR_MAX_OBSERVATIONS=4;
    public static final long NOTES_EDITOR_READINESS_MS=15000;
    private int actionOrdinal,parentCreateActionOrdinal;
    private String parentCreateAfterSourceSha;
    private int parentCreateStep;
    private String parentCreateRun,parentCreateAttempt,parentCreateBefore,parentCreateAfter,reopenActor;
    private NotesCreateWorkflow.Grant workflowGrant;
    private boolean workflowProofConsumed,workflowCompletionAccepted;
    private String workflowVerifiedObservationId;
    private Map<String,Object> workflowEvidence;
    private WebTaskDomain webDomain;
    private NativeAppSession nativeSession;
    // Completion is a historical, read-only result, not a retained action domain.
    // Only successClaim may create a candidate. The real Session consumes it once
    // before retirement, and only its authenticated ordinary CLOSE may seal it.
    private WebTaskDomain claimedWebDomain;
    private WebCompletionSnapshot webCompletionCandidate;
    private WebCloseAttempt pendingWebClose;
    private ClosedWebCompletion closedWebCompletion;
    private boolean webCloseStarted,webTerminalConsumed;
    private long webClearSequence;

    private static final class WebCompletionSnapshot {
        final String task,owner,contract,authorization,observation,frameSha,binding,instance,generation,run;
        final int step,display,window;final long epoch;
        final Map<String,Object> page,result;
        WebCompletionSnapshot(TaskCompletionGate gate,WebTaskDomain domain,NotesCompletionEvidence.Frame frame,int step,String run){
            task=gate.taskId;owner=gate.contract.ownerSha256;contract=gate.contract.contractSha256;
            authorization=gate.authorization.sha256;observation=frame.observationId;frameSha=webFrameSha(frame);
            require(frameSha!=null&&frame.displayId>0&&frame.backgroundGeneration!=null,"complete final native observation required");
            page=immutableMap(domain.evidence());result=immutableMap(domain.resultRecord());
            binding=requiredText(page,"binding_sha256");instance=requiredText(page,"webview_instance");
            generation=frame.backgroundGeneration;display=frame.displayId;window=frame.windowId;
            epoch=requiredInteger(page,"navigation_epoch");this.step=step;this.run=run;
            require(hex64(binding)&&hex64(requiredText(page,"contract_sha256"))&&epoch>=0
                    &&task.equals(page.get("task_id"))&&owner.equals(page.get("owner_sha256"))
                    &&authorization.equals(page.get("authorization_sha256"))
                    &&observation.equals(page.get("observation_id"))&&generation.equals(page.get("background_generation"))
                    &&requiredInteger(page,"display_id")==display&&requiredInteger(page,"window_id")==window,
                    "verified provider identity differs from its native final observation");
            require(task.equals(result.get("task_id"))&&owner.equals(result.get("owner_sha256"))
                    &&page.get("contract_sha256").equals(result.get("contract_sha256"))
                    &&binding.equals(result.get("binding_sha256"))&&instance.equals(result.get("webview_instance"))
                    &&epoch==requiredInteger(result,"navigation_epoch")
                    &&observation.equals(result.get("observation_id"))
                    &&Objects.equals(page.get("observation_state_sha256"),result.get("observation_state_sha256"))
                    &&requiredInteger(result,"display_id")==display&&requiredInteger(result,"window_id")==window
                    &&Boolean.FALSE.equals(result.get("business_verified")),
                    "actual read-only result differs from its verified provider record");
        }
    }
    static final class WebCloseAttempt {
        private final TaskCompletionGate gate;private final Object lease;
        private final WebCompletionSnapshot snapshot;private final long expectedClearSequence;
        private boolean consumed;
        private WebCloseAttempt(TaskCompletionGate gate,Object lease,WebCompletionSnapshot snapshot,long expectedClearSequence){
            this.gate=gate;this.lease=lease;this.snapshot=snapshot;this.expectedClearSequence=expectedClearSequence;
        }
    }
    private static final class ClosedWebCompletion {
        final Object lease;final WebCompletionSnapshot snapshot;final String callbackSha;
        ClosedWebCompletion(Object lease,WebCompletionSnapshot snapshot,String callbackSha){
            this.lease=lease;this.snapshot=snapshot;this.callbackSha=callbackSha;
        }
    }
    /** Called once by the live Session immediately before its existing clear.
     * A missing, changed, errored or cancelled claim retires without a candidate. */
    synchronized WebCloseAttempt beginWebClose(Object lease,WebTaskDomain current,String actualTask,String binding,String reason){
        if(webCloseStarted){abortWebClose(pendingWebClose);return null;}
        webCloseStarted=true;closedWebCompletion=null;
        WebCompletionSnapshot candidate=webCompletionCandidate;WebTaskDomain claimed=claimedWebDomain;
        webCompletionCandidate=null;claimedWebDomain=null;
        if(!WEB.equals(contract.kind)||lease==null||!"normal".equals(reason)||identityInvalid
                ||webTerminalConsumed||candidate==null||current==null||current!=webDomain||current!=claimed
                ||!taskId.equals(actualTask)||!candidate.binding.equals(binding))return null;
        try{
            if(!candidate.page.equals(immutableMap(current.evidence()))
                    ||!candidate.result.equals(immutableMap(current.resultRecord())))return null;
        }catch(RuntimeException invalid){return null;}
        pendingWebClose=new WebCloseAttempt(this,lease,candidate,webClearSequence+1);
        return pendingWebClose;
    }
    /** The caller has already verified the actual typed CLOSE and persisted
     * journal.closeKnown. A recovery/unstarted/unknown close is never this proof. */
    synchronized boolean webCloseKnown(WebCloseAttempt attempt,Object lease,String actualTask,String binding,
            String status,String instance,long epoch,int display,int window,String callbackSha){
        boolean good=attempt!=null&&attempt==pendingWebClose&&attempt.gate==this&&!attempt.consumed
                &&attempt.lease==lease&&webCloseStarted&&!webTerminalConsumed&&webDomain==null
                &&webClearSequence==attempt.expectedClearSequence&&!identityInvalid
                &&taskId.equals(actualTask)&&attempt.snapshot.binding.equals(binding)
                &&"closed".equals(status)&&attempt.snapshot.instance.equals(instance)
                &&attempt.snapshot.epoch==epoch&&attempt.snapshot.display==display&&attempt.snapshot.window==window
                &&hex64(callbackSha);
        if(attempt!=null)attempt.consumed=true;
        pendingWebClose=null;closedWebCompletion=null;
        if(!good)return false;
        closedWebCompletion=new ClosedWebCompletion(lease,attempt.snapshot,callbackSha);return true;
    }
    /** Unknown or failed closes consume the candidate permanently, including
     * callbacks that arrive after cancellation or a later reconciliation. */
    synchronized void abortWebClose(WebCloseAttempt attempt){
        if(attempt!=null)attempt.consumed=true;
        if(pendingWebClose!=null)pendingWebClose.consumed=true;
        pendingWebClose=null;closedWebCompletion=null;claimedWebDomain=null;webCompletionCandidate=null;
    }
    /** The only post-retirement completion path. Inputs come from the actual
     * controller cleanup objects; model/JSON claims cannot construct the private
     * closed proof. This consumes the terminal attempt even when a check fails. */
    synchronized Check terminalWebCheck(Object lease,NotesCompletionEvidence.Frame current,TaskAuthorization.Frame owner,
            int step,String modelRun,boolean modelSuccess,boolean allCleanupKnown,boolean helperReleased,
            boolean backgroundReleased,boolean scopeRechecked,boolean cancelled,
            boolean processStarted,boolean processExitObserved,Integer exitCode,boolean receiptValid,
            String workerTask,String workerGeneration,String workerReceiptSha){
        ClosedWebCompletion closed=closedWebCompletion;closedWebCompletion=null;
        boolean first=!webTerminalConsumed;webTerminalConsumed=true;
        boolean snapshot=first&&WEB.equals(contract.kind)&&closed!=null&&closed.lease==lease
                &&pendingWebClose==null&&webCloseStarted&&webDomain==null&&!identityInvalid&&sameDomain(current)
                &&closed.snapshot.task.equals(taskId)&&closed.snapshot.owner.equals(contract.ownerSha256)
                &&closed.snapshot.contract.equals(contract.contractSha256)&&closed.snapshot.authorization.equals(authorization.sha256)
                &&Objects.equals(closed.snapshot.frameSha,webFrameSha(current))
                &&step==closed.snapshot.step&&Objects.equals(modelRun,closed.snapshot.run);
        boolean ownerBound=owner!=null&&owner.authorization==authorization&&taskId.equals(owner.taskId)&&owner.successAllowed();
        boolean nativeBound=processStarted&&processExitObserved&&Integer.valueOf(0).equals(exitCode)&&receiptValid
                &&taskId.equals(workerTask)&&id(workerGeneration)&&hex64(workerReceiptSha);
        boolean verified=snapshot&&modelSuccess&&allCleanupKnown&&helperReleased&&backgroundReleased
                &&scopeRechecked&&ownerBound&&!cancelled&&nativeBound;
        Map<String,Object> value=evidence(current),terminal=new LinkedHashMap<String,Object>();
        terminal.put("schema","hepta.web-terminal-completion.v1");terminal.put("task_id",taskId);
        terminal.put("owner_sha256",contract.ownerSha256);terminal.put("contract_sha256",contract.contractSha256);
        terminal.put("authorization_sha256",authorization.sha256);terminal.put("one_terminal_attempt",first);
        terminal.put("closed_result_snapshot_verified",snapshot);terminal.put("live_action_domain_retired",webDomain==null&&webCloseStarted);
        terminal.put("model_success_claim_verified_before_close",snapshot);terminal.put("all_cleanup_known",allCleanupKnown);
        terminal.put("helper_released",helperReleased);terminal.put("background_released",backgroundReleased);
        terminal.put("scope_rechecked_after_worker_exit",scopeRechecked);terminal.put("owner_rechecked_after_worker_exit",ownerBound);
        terminal.put("cancelled",cancelled);terminal.put("native_parent_session_bound",nativeBound);
        terminal.put("worker_task_id",workerTask);terminal.put("worker_generation",workerGeneration);
        terminal.put("worker_receipt_sha256",workerReceiptSha);terminal.put("terminal_verified",verified);
        terminal.put("grants_tool_authority",false);terminal.put("business_verified",false);
        if(snapshot){
            WebCompletionSnapshot result=closed.snapshot;
            terminal.put("binding_sha256",result.binding);terminal.put("webview_instance",result.instance);
            terminal.put("navigation_epoch",result.epoch);terminal.put("display_id",result.display);terminal.put("window_id",result.window);
            terminal.put("background_generation",result.generation);terminal.put("final_observation_id",result.observation);
            terminal.put("final_observation_sha256",result.frameSha);terminal.put("accepted_model_run_id",result.run);
            terminal.put("accepted_model_step",result.step);terminal.put("actual_close_callback_canonical_sha256",closed.callbackSha);
            value.put("official_page",result.page);
            Map<String,Object> publicResult=new LinkedHashMap<String,Object>(result.result);
            publicResult.put("completion_gate_accepted",verified);publicResult.put("action_domain_retired",true);
            value.put("public_web_result",immutableMap(publicResult));
        }
        value.put("completion_verified",verified);value.put("live_observation_verified",false);
        value.put("observation_chain_verified",snapshot);value.put("terminal_binding_and_cleanup_verified",verified);
        value.put("terminal_web_completion",immutableMap(terminal));
        List<String> absent=new ArrayList<String>(missing(current));
        if(!verified)absent.add("closed_web_terminal_binding_or_cleanup_missing");
        value.put("missing",verified?Collections.<String>emptyList():Collections.unmodifiableList(absent));
        return new Check(verified,false,immutableMap(value));
    }
    private static String requiredText(Map<String,Object> value,String key){
        Object item=value.get(key);require(item instanceof String&&!((String)item).isEmpty(),"required provider text "+key);return (String)item;
    }
    private static long requiredInteger(Map<String,Object> value,String key){
        Object item=value.get(key);require(item instanceof Integer||item instanceof Long,"required provider integer "+key);return ((Number)item).longValue();
    }
    private static boolean hex64(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    private static Map<String,Object> immutableMap(Map<String,Object> value){
        @SuppressWarnings("unchecked") Map<String,Object> copy=(Map<String,Object>)immutableValue(value,0,new int[]{50000});
        return copy;
    }
    private static Object immutableValue(Object value,int depth,int[] budget){
        require(depth<=64&&--budget[0]>=0,"bounded immutable result evidence required");
        if(value==null||value instanceof String||value instanceof Boolean
                ||value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long
                ||value instanceof java.math.BigInteger||value instanceof java.math.BigDecimal)return value;
        if(value instanceof Double){require(!Double.isNaN((Double)value)&&!Double.isInfinite((Double)value),"finite result number");return value;}
        if(value instanceof Float){require(!Float.isNaN((Float)value)&&!Float.isInfinite((Float)value),"finite result number");return value;}
        if(value instanceof Map){
            Map<String,Object> copy=new LinkedHashMap<String,Object>();
            for(Map.Entry<?,?> entry:((Map<?,?>)value).entrySet()){
                require(entry.getKey() instanceof String,"result evidence keys must be text");
                copy.put((String)entry.getKey(),immutableValue(entry.getValue(),depth+1,budget));
            }return Collections.unmodifiableMap(copy);
        }
        if(value instanceof List){
            List<Object> copy=new ArrayList<Object>();
            for(Object item:(List<?>)value)copy.add(immutableValue(item,depth+1,budget));
            return Collections.unmodifiableList(copy);
        }
        throw new IllegalArgumentException("completion: unsupported mutable result evidence type");
    }
    static String webFrameSha(NotesCompletionEvidence.Frame frame){
        if(!domainShape(frame)||!id(frame.observationId)||frame.packageName==null||frame.nodesTruncated||frame.nodes==null)return null;
        StringBuilder value=new StringBuilder("hepta.web-final-native-frame.v1");
        webField(value,frame.observationId);webField(value,frame.packageName);webField(value,frame.windowId);
        webField(value,frame.displayId);webField(value,frame.backgroundGeneration);webField(value,frame.windowType);
        webField(value,frame.metadataObserved);webField(value,frame.nodesTruncated);webField(value,frame.nodes.size());
        for(NotesCompletionEvidence.Node node:frame.nodes){
            if(node==null||node.childText==null)return null;
            webField(value,node.id);webField(value,node.packageName);webField(value,node.text);webField(value,node.label);
            webField(value,node.viewId);webField(value,node.inputTextSha256);webField(value,node.left);webField(value,node.top);
            webField(value,node.right);webField(value,node.bottom);webField(value,node.editable);webField(value,node.clickable);
            webField(value,node.scrollable);webField(value,node.enabled);webField(value,node.password);
            webField(value,node.observedAppTreeSignature);webField(value,node.childText.fingerprint);webField(value,node.childText.visited);
        }
        return hash(value.toString());
    }
    private static void webField(StringBuilder out,Object value){
        if(value==null){out.append("|-1:");return;}String text=String.valueOf(value);out.append('|').append(text.length()).append(':').append(text);
    }
    synchronized void bindWebDomain(WebTaskDomain value){
        if(webCloseStarted){abortWebClose(pendingWebClose);throw new IllegalArgumentException("completion: web action domain is retired");}
        webCompletionCandidate=null;claimedWebDomain=null;
        require(value!=null&&WEB.equals(contract.kind)&&taskId.equals(value.taskId)
                &&contract.ownerSha256.equals(value.ownerSha)&&authorization.sha256.equals(value.authorizationSha),
                "web observation does not belong to the current immutable authorization");
        webDomain=value;
    }
    synchronized void clearWebDomain(){
        webDomain=null;claimedWebDomain=null;webCompletionCandidate=null;webClearSequence++;
        if(pendingWebClose==null)closedWebCompletion=null;
    }
    WebTaskDomain webDomainFor(NotesCompletionEvidence.Frame frame){
        if(!"official_csair_flight_owner.v1".equals(contract.recognition)
                &&!"natural_csair_flight_owner.v1".equals(contract.recognition)
                &&!"official_mi_product_owner.v1".equals(contract.recognition))return null;
        require(!webCloseStarted&&webDomain!=null&&frame!=null&&webDomain.observationId.equals(frame.observationId)
                &&webDomain.generation.equals(frame.backgroundGeneration)&&webDomain.displayId==frame.displayId
                &&webDomain.windowId==frame.windowId,"current official page evidence is unavailable");
        return webDomain;
    }
    public TaskCompletionGate(String task,String owner,TaskAuthorization authorization){
        this(task,owner,authorization,null);
    }
    TaskCompletionGate(String task,String owner,TaskAuthorization authorization,BackgroundTaskTarget.SelectionBinding selection){
        require(id(task)&&authorization!=null,"task identity and owner authorization required");
        authorization.requireCompletionSelection(selection);
        executionSelection=selection;executionTarget=selection==null?null:selection.executionTarget();
        taskId=task;contract=Contract.forExplicitTarget(owner,authorization,executionTarget);this.authorization=authorization;
    }
    /** Compatibility only for the inactive Notes phase on the same explicitly
     * selected native task. It never equates two contracts or grants Notes tools. */
    boolean boundNonNotesNativeContract(TaskAuthorization actual){
        if(actual!=authorization||executionSelection==null||executionTarget==null
                ||executionTarget.webHelper()||!executionTarget.explicitSelection
                ||NOTES.equals(contract.kind)||WEB.equals(contract.kind))return false;
        authorization.requireCompletionSelection(executionSelection);
        return executionSelection.executionTarget()==executionTarget
                &&executionTarget.ownerSha256.equals(contract.ownerSha256)
                &&authorization.instructionSha256.equals(contract.ownerSha256)
                &&executionTarget.targetSha256.equals(contract.executionTargetSha256)
                &&executionTarget.nativeGoal==contract.nativeGoal
                &&(contract.nativeGoal==null?UNKNOWN.equals(contract.kind):contract.nativeGoal.kind.equals(contract.kind));
    }
    NativeAppGoal nativeGoal(){
        if(executionTarget==null||executionTarget.webHelper())return null;
        authorization.requireCompletionSelection(executionSelection);
        return contract.nativeGoal;
    }
    void bindNativeSession(NativeAppSession value){
        require(nativeSession==null&&value!=null&&contract.nativeGoal!=null&&boundNonNotesNativeContract(authorization)
                &&value.goal==contract.nativeGoal&&value.target==executionTarget&&value.selection==executionSelection
                &&value.authorization.authorization==authorization&&taskId.equals(value.taskId),
                "native completion requires the same immutable task/Selection/goal/session");
        nativeSession=value;
    }
    NativeAppDomain nativeDomainFor(NotesCompletionEvidence.Frame frame){
        if(contract.nativeGoal==null)return null;
        require(nativeSession!=null&&!identityInvalid,"current native provider session unavailable");
        return nativeSession.domainFor(frame);
    }
    synchronized Check terminalNativeCheck(NativeAppSession actual,NotesCompletionEvidence.Frame frame,TaskAuthorization.Frame owner,
            int step,String run,boolean modelSuccess,boolean allCleanupKnown,boolean backgroundReleased,
            boolean scopeRechecked,boolean installedRechecked,boolean cancelled,boolean processStarted,boolean processExitObserved,
            Integer exitCode,boolean receiptValid,String workerTask,String workerGeneration,String workerReceiptSha){
        if(actual==null||actual!=nativeSession||contract.nativeGoal==null||!boundNonNotesNativeContract(authorization)){
            Map<String,Object> absent=evidence(frame);absent.put("completion_verified",false);absent.put("terminal_binding_and_cleanup_verified",false);
            absent.put("missing",Collections.singletonList("same_native_provider_session_missing"));return new Check(false,false,immutableMap(absent));
        }
        Map<String,Object> terminal=actual.terminal(frame,owner,step,run,modelSuccess&&!identityInvalid,allCleanupKnown,
                backgroundReleased,scopeRechecked,installedRechecked,cancelled,processStarted,processExitObserved,exitCode,
                receiptValid,workerTask,workerGeneration,workerReceiptSha);
        boolean passed=Boolean.TRUE.equals(terminal.get("completion_verified"));Map<String,Object> out=evidence(frame);
        out.putAll(terminal);out.put("terminal_native_completion",terminal);out.put("contract",contract.evidence());return new Check(passed,false,immutableMap(out));
    }
    public void bindInstalled(NotesCompletionEvidence.Installed value){
        require(installed==null&&!launchProved,"installed completion identity already bound");installed=value;
    }
    public synchronized void invalidateInstalled(String reason){identityInvalid=true;identityFailure=reason==null?"installed_identity_unavailable":reason;}
    public synchronized void observed(NotesCompletionEvidence.Frame frame){
        if(WEB.equals(contract.kind)){
            if(webCloseStarted)abortWebClose(pendingWebClose);
            else if(webCompletionCandidate!=null&&!Objects.equals(webCompletionCandidate.frameSha,webFrameSha(frame))){
                webCompletionCandidate=null;claimedWebDomain=null;
            }
        }
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
    public synchronized void action(int step,String run,ActionDecision action,boolean accepted,boolean dispatched,boolean stale,
                       NotesCompletionEvidence.Frame before,NotesCompletionEvidence.Frame after,Map<String,Object> fixed){
        require(step>0&&step<=20&&id(run)&&action!=null&&before!=null&&after!=null,"actual bounded model/action observations required");
        require(action.toolChildOrigin==null,"tool children require their separate parent-bound proof path");
        require(action.observationId.equals(before.observationId),"action must bind its actual before observation");
        actionOrdinal++;
        if(WEB.equals(contract.kind)){webCompletionCandidate=null;claimedWebDomain=null;}
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
            parentCreateBefore=before.observationId;parentCreateAfter=after.observationId;parentCreateActionOrdinal=actionOrdinal;parentCreateAfterSourceSha=webFrameSha(after);
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
    /** A separately recorded bounded read sequence may become ready after the
     * original create-after. The original action proof/id is never rewritten.
     * Only the most recent actual parent can acquire this one-use child grant. */
    public synchronized NotesCreateWorkflow.Grant notesCreateWorkflowAfterReadiness(int step,String run,ActionDecision parent,
            List<NotesCreateWorkflow.Observation> reads,TaskAuthorization.Frame frame,long started,long finished){
        if(!notesCreateWorkflowRequested(frame)||workflowGrant!=null||parent==null||parent.toolChildOrigin!=null
                ||!"notes.create".equals(parent.action)||step!=parentCreateStep||!Objects.equals(run,parentCreateRun)
                ||!Objects.equals(parent.observationId,parentCreateBefore)||!contract.body.equals(parent.text)
                ||parentCreateActionOrdinal!=actionOrdinal||reads==null||reads.size()<2||reads.size()>NOTES_EDITOR_MAX_OBSERVATIONS
                ||started<0||finished<started||finished-started>NOTES_EDITOR_READINESS_MS
                ||!launchProved||!editorObserved||identityInvalid||priorVisibleBodyCollision||installed==null)return null;
        NotesCreateWorkflow.Observation first=reads.get(0),ready=reads.get(reads.size()-1);
        if(first==null||ready==null||!Objects.equals(first.frame.observationId,parentCreateAfter)
                ||parentCreateAfterSourceSha==null||!parentCreateAfterSourceSha.equals(webFrameSha(first.frame))
                ||body(first.frame).matched||!body(ready.frame).matched)return null;
        java.util.Set<String> ids=new java.util.HashSet<String>();List<Map<String,Object>> frames=new ArrayList<Map<String,Object>>();
        for(NotesCreateWorkflow.Observation read:reads){
            if(read==null||!domainShape(read.frame)||!sameDomain(read.frame)
                    ||read.frame.windowId!=first.frame.windowId||read.rotation!=first.rotation
                    ||!NotesCompletionEvidence.NOTES.equals(read.frame.packageName)||!id(read.frame.observationId)
                    ||!ids.add(read.frame.observationId))return null;
            Map<String,Object> f=new LinkedHashMap<String,Object>();f.put("observation_id",read.frame.observationId);
            f.put("window_id",read.frame.windowId);f.put("app_tree_sha256",read.treeSha256);f.put("rotation",read.rotation);frames.add(f);
        }
        workflowGrant=new NotesCreateWorkflow.Grant(taskId,step,run,parentCreateBefore,parentCreateAfter,ready.frame.observationId,parentCreateAttempt,
                contract,authorization,installed,displayId,generation);
        Map<String,Object> p=proof("notes_created_editor_readiness",step,run,first.frame,ready.frame);
        p.put("original_create_after_observation_id",parentCreateAfter);p.put("original_create_after_unchanged",true);
        p.put("readonly_observations",frames);p.put("observation_count",reads.size());p.put("elapsed_ms",finished-started);
        p.put("new_effects_dispatched",0);p.put("grants_from_client_cache_reset",false);
        p.put("workflow_initial_observation_id",ready.frame.observationId);proofs.add(p);
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
    public synchronized Check successClaim(int step,String run,NotesCompletionEvidence.Frame current,boolean finalObservationStable){
        return successClaim(step,run,current,finalObservationStable,null);
    }
    synchronized Check successClaim(int step,String run,NotesCompletionEvidence.Frame current,boolean finalObservationStable,
            WebShoppingQuote.Completion quoteCompletion){
        require(step>0&&step<=20&&id(run),"completion claim native identity required");observed(current);
        boolean quoteRequired=WEB.equals(contract.kind)&&webDomain!=null&&webDomain.shopping!=null&&webDomain.shopping.searchQuote!=null;
        boolean quoteScope=quoteCompletion!=null&&quoteCompletion.consume(this,webDomain,current,run);
        boolean finalReadAccepted=quoteRequired?quoteScope:finalObservationStable;
        boolean verified=finalReadAccepted&&verified(current);
        if(contract.nativeGoal!=null)verified=verified&&nativeSession!=null
                &&nativeSession.acceptSuccess(step,run,current,finalObservationStable)!=null;
        Map<String,Object> claim=proof("native_done_success_claim",step,run,current,current);
        claim.put("original_whole_tree_stable",finalObservationStable);claim.put("search_quote_scope_required",quoteRequired);
        claim.put("search_quote_scope_verified",quoteRequired&&quoteScope);
        if(quoteRequired&&quoteScope)claim.put("search_quote_completion_scope",quoteCompletion.summary());
        claim.put("completion_verified",verified);claims.add(claim);
        if(WEB.equals(contract.kind)){
            webCompletionCandidate=null;claimedWebDomain=null;
            if(verified&&!webCloseStarted){
                webCompletionCandidate=new WebCompletionSnapshot(this,webDomain,current,step,run);claimedWebDomain=webDomain;
            }
        }
        if(!verified)rejectedSuccess++;
        Map<String,Object> value=evidence(current);value.put("check_step",step);value.put("check_model_run_id",run);
        value.put("model_reported_success",true);value.put("accepted_as_completed",verified);value.put("final_observation_stable",finalObservationStable);
        value.put("search_quote_scope_required",quoteRequired);value.put("search_quote_scope_verified",quoteRequired&&quoteScope);
        if(!finalReadAccepted){List<String> absent=new ArrayList<String>(missing(current));
            absent.add(quoteRequired?"typed_search_quote_final_read_missing":"final_observation_changed_reobserve");value.put("missing",absent);}
        value.put("retry_allowed",!verified&&rejectedSuccess<MAX_REJECTED_SUCCESS);
        return new Check(verified,!verified&&rejectedSuccess<MAX_REJECTED_SUCCESS,value);
    }
    public synchronized boolean verified(NotesCompletionEvidence.Frame current){
        if(contract.nativeGoal!=null)return domainBound&&!identityInvalid&&sameDomain(current)&&nativeSession!=null&&nativeSession.ready(current);
        if(WEB.equals(contract.kind))return !webCloseStarted&&domainBound&&!identityInvalid&&sameDomain(current)&&webDomain!=null
                &&webDomain.observationId.equals(current.observationId)
                &&webDomain.generation.equals(current.backgroundGeneration)&&webDomain.displayId==current.displayId
                &&webDomain.windowId==current.windowId&&webDomain.resultReady();
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
        }else if(contract.nativeGoal!=null){
            o.put("native_app",nativeSession==null?Collections.singletonMap("missing","native_provider_session_unavailable"):nativeSession.promptEvidence());
        }else if(WEB.equals(contract.kind)){
            o.put("web_query_dispatched",webDispatched||webDomain!=null&&webDomain.queryDispatched());
            if(webDomain!=null)o.put("official_page",webDomain.promptEvidence());
        }
        o.put("writes_required_for_unknown_or_read_only_goal",false);o.put("grants_tool_authority",false);return o;
    }
    public Map<String,Object> evidence(NotesCompletionEvidence.Frame current){
        Map<String,Object> o=prompt(current);o.put("task_id",taskId);o.put("contract",contract.evidence());
        if(WEB.equals(contract.kind)&&webDomain!=null)o.put("official_page",webDomain.evidence());
        if(contract.nativeGoal!=null&&nativeSession!=null){o.put("native_app_session",nativeSession.evidence());
            if(verified(current))o.put("public_native_result",nativeSession.resultRecord());}
        o.put("proofs",new ArrayList<Map<String,Object>>(proofs));o.put("model_success_claims",new ArrayList<Map<String,Object>>(claims));
        o.put("identity_failure",identityFailure);o.put("display_id",domainBound?displayId:null);o.put("background_generation",generation);
        if(workflowEvidence!=null)o.put("notes_create_workflow",workflowEvidence);
        o.put("persistent_storage_bytes_verified",false);o.put("new_database_item_identity_verified",false);
        if(WEB.equals(contract.kind)&&webDomain!=null&&webDomain.resultReady()){
            Map<String,Object> result=new LinkedHashMap<String,Object>(webDomain.resultRecord());
            result.put("completion_gate_accepted",verified(current));o.put("public_web_result",result);
        }
        if(NOTES.equals(contract.kind)){NotesCompletionEvidence.BodyEvidence v=body(current);o.put("current_editor_raw_exact",v.rawExact);o.put("current_body_evidence",bodyEvidence(v));
            NotesCompletionEvidence.ListEvidence list=NotesCompletionEvidence.list(current,contract.body);o.put("current_list_match",list.matched);o.put("current_list_missing",list.missing);
            o.put("current_list_evidence",list.evidence());}
        return o;
    }
    public String completionSummary(){
        if(contract.nativeGoal!=null&&nativeSession!=null&&nativeSession.resultRecord()!=null){
            Object summary=nativeSession.resultRecord().get("display_summary");require(summary instanceof String,"typed native result summary missing");return (String)summary;
        }
        if(WEB.equals(contract.kind)&&webDomain!=null&&webDomain.resultReady()){
            Map<String,Object> value=webDomain.resultRecord();
            if("natural_csair_flight_owner.v1".equals(contract.recognition)||"official_csair_flight_owner.v1".equals(contract.recognition)){
                require("hepta.csair-displayed-flight-result.v1".equals(value.get("schema"))
                        &&value.get("display_summary") instanceof String,"typed current flight result summary required");
                return (String)value.get("display_summary");
            }
            if(WebShoppingQuote.SCHEMA.equals(value.get("schema"))){
                require(value.get("display_summary") instanceof String,"typed current search-card quote summary required");
                return (String)value.get("display_summary");
            }
            return "已核对小米官网的 "+value.get("model_raw")+" 页面展示价：人民币 "+value.get("amount_decimal")+" 元。";
        }
        return "已核验本次正文进入笔记编辑器、返回列表并点击同一可访问正文条目重新打开；列表视觉裁切与存储原始字节未核验。";
    }
    public String incompleteSummary(){
        if(contract.nativeGoal!=null)return "原生应用查询尚未通过本次任务的目标字段、实际模型操作链与当前页面核验，未确认完成。";
        if(NOTES.equals(contract.kind))return "未完成验证：缺少本次笔记保存、列表或同一条目重新打开的完整证据。";
        if("official_mi_product_owner.v1".equals(contract.recognition))return "尚未取得同一商品详情页、公开价和原生模型导航的完整证据，商品查询未验证完成。";
        if(WEB.equals(contract.kind))return webDispatched||webDomain!=null&&webDomain.queryDispatched()?"已发起网页查询，但尚无实际结果证明，任务部分完成。":"未确认网页查询及结果，任务未验证完成。";
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
            if("official_mi_product_owner.v1".equals(contract.recognition)){
                if(webDomain==null)out.add("current_bound_product_page_missing");
                else if(!verified(current))out.add("same_product_native_result_and_actual_model_navigation_missing");
            }else{
                if(!webDispatched&&(webDomain==null||!webDomain.queryDispatched()))out.add("model_bound_web_query_dispatch_missing");
                if("natural_csair_flight_owner.v1".equals(contract.recognition)||"official_csair_flight_owner.v1".equals(contract.recognition)){
                    if(!verified(current))out.add("actual_same_record_flight_results_not_yet_verified");
                }
                else out.add("web_results_provider_unavailable");
            }
        }else if(contract.nativeGoal!=null){
            if(nativeSession==null)out.add("same_native_provider_session_missing");else out.addAll(nativeSession.missing());
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
