package org.trillionnium.hepta.local;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONObject;

/** One explicit planning/navigation prelude on the already owned native task.
 * No Android nodes live here. Neither planning data nor a pure role comparison
 * can be dispatched through the old click/type/scroll/done entry point. */
final class NativeSearchSession {
    interface ObservationCallback {
        void onPlanning(NativeSearchPlanning value);void onError(String detail);
        default void onLoadingReadRetryAvailable(String detail,HeptaAccessibilityService.NativeSearchReadRetryProof proof){onError(detail);}
        default boolean acceptsSamplingReadRetry(){return false;}
        default void onSamplingReadRetryAvailable(String detail,HeptaAccessibilityService.NativeSearchSamplingExhaustionProof proof){
            try{onError(detail);}finally{proof.close();}
        }
    }
    interface ActionCallback {
        void onResult(HeptaAccessibilityService.ActionOutcome value);
        default void onNoEffectReplanAvailable(HeptaAccessibilityService.ActionOutcome value,
                HeptaAccessibilityService.NativeSearchNoEffectReplanProof proof){onResult(value);}
    }
    final Object controller;
    final NativeAppSession nativeTask;
    final BackgroundSession background;
    final TaskAuthorization.Gate authorization;
    final BackgroundTaskTarget.SelectionBinding selection;
    final NativeAppGoal goal;
    final String taskId;
    // Two models (55 s each), two 8 s actions, and four existing 12 s read caps:
    // initial, existing loading successor, one post-D successor, final input handoff.
    static final long CHAIN_LIMIT_MS=174000L;
    final long startedElapsed,taskDeadlineElapsed,chainDeadlineElapsed;
    private final Map<String,Object> binding;
    private boolean retired,navigationEffectRecorded,navigationObserved;
    private Offer offered;
    private Attempt attempted;
    private Attempt closedSuccessorAttempt;
    private HeptaAccessibilityService.NativeSearchNoEffectReplanProof successorProof;
    private String successorReceiptSha;
    private boolean successorOffered;

    NativeSearchSession(Object controller,NativeAppSession task,BackgroundSession background,long started,long taskDeadline)throws Exception{
        need(controller!=null&&task!=null&&background!=null&&started>=0&&taskDeadline>started,"actual controller/native task/background/deadline required");
        need(eligible(task)&&task.selection==background.selection&&task.taskId.equals(background.taskId)
                &&task.generation.equals(background.generation)&&task.displayId==background.displayId(),"same explicit owned native background");
        need(background.profileTarget()!=null&&task.installed.profileTarget!=null
                &&background.profileTarget().same(task.installed.profileTarget),"same installed profile target required");
        this.controller=controller;nativeTask=task;this.background=background;authorization=task.authorization;
        selection=task.selection;goal=task.goal;taskId=task.taskId;startedElapsed=started;taskDeadlineElapsed=taskDeadline;
        chainDeadlineElapsed=Math.min(taskDeadline,started>Long.MAX_VALUE-CHAIN_LIMIT_MS?Long.MAX_VALUE:started+CHAIN_LIMIT_MS);
        authorization.requireNativeSearchIntent(selection,goal);
        Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("task_id",taskId);e.put("owner_sha256",goal.ownerSha256);
        e.put("target_sha256",task.target.targetSha256);e.put("authorization_sha256",authorization.authorization.sha256);
        e.put("selection_sha256",task.selectionSha);e.put("installed_set_sha256",task.installed.apkSetSha256);e.put("goal_sha256",goal.contractSha256);
        e.put("background_generation",task.generation);e.put("package",goal.packageName);e.put("display_id",task.displayId);
        e.put("profile_target_sha256",task.installed.profileTarget.sha256);e.put("profile_user_id",task.installed.profileTarget.profile.userId);
        e.put("profile_user_serial",task.installed.profileTarget.profile.serial);e.put("profile_full_uid",task.installed.profileTarget.fullUid);
        binding=NativeAppEvidence.immutableMap(e);task.bindSearchPlanning(this);requireLive(started);
    }
    static boolean eligible(NativeAppSession task){return task!=null&&NativeAppGoal.PRODUCT_PRICE.equals(task.goal.kind)
            &&NativeAppGoal.XIAOMI_PACKAGE.equals(task.goal.packageName)&&NativeAppGoal.PRODUCT_MODEL.equalsIgnoreCase(task.goal.productModel)
            &&task.installed.profileTarget!=null;}
    synchronized void requireLive(long now){
        need(!retired&&now>=startedElapsed&&now<taskDeadlineElapsed&&now<chainDeadlineElapsed,"search Session retired/expired/clock mismatch");
        authorization.requireNativeSearchIntent(selection,goal);
        need(nativeTask.authorization==authorization&&nativeTask.selection==selection&&background.selection==selection
                &&nativeTask.goal==goal&&selection.executionTarget()==nativeTask.target
                &&taskId.equals(background.taskId)&&nativeTask.generation.equals(background.generation)
                &&nativeTask.displayId==background.displayId()&&nativeTask.installed.profileTarget.same(background.profileTarget()),"actual task/Gate/Selection/background object binding changed");
        nativeTask.requireSearchPlanningCurrent(this);
    }
    synchronized void requireBeforeFirstPlanning(long now){
        requireLive(now);need(offered==null&&attempted==null&&successorProof==null&&closedSuccessorAttempt==null&&!successorOffered&&!navigationEffectRecorded&&!navigationObserved,
                "loading read recovery cannot cross a planning Offer, model intent or navigation effect");
    }
    Map<String,Object> binding(){return binding;}
    void verifyInstalled()throws Exception{nativeTask.verifyInstalled();}
    synchronized Offer offer(NativeSearchPlanning planning,long now){
        requireLive(now);need(offered==null&&attempted==null&&planning!=null,"one actual planning Offer only");
        need(NativeSearchPlanning.equal(binding,planning.binding)&&planning.timing.requestStarted>=startedElapsed
                &&planning.timing.requestDeadline<=chainDeadlineElapsed&&planning.publication!=null&&planning.publishedElapsed<=now&&planning.persistedElapsed<=now
                &&now-planning.capturedElapsed<=2000,"planning receipt not current for the same Session");
        offered=new Offer(this,planning);return offered;
    }

    /** The same task remains bound; only one proved-unentered attempt may retire
     * into a separate full planning/model sequence. Old Offers/runs stay spent. */
    void acceptNoEffectForReplan(Attempt attempt,HeptaAccessibilityService.ActionOutcome outcome,
            String receiptSha,HeptaAccessibilityService.NativeSearchNoEffectReplanProof proof,long now)throws Exception{
        synchronized(this){requireLive(now);need(successorProof==null&&closedSuccessorAttempt==null&&!successorOffered
                &&attempt!=null&&attempt==attempted&&attempt.offer==offered&&!navigationEffectRecorded&&!navigationObserved,
                "one current first no-effect search outcome required");}
        need(outcome!=null&&!outcome.accepted&&!outcome.dispatched&&outcome.stale&&NativeAppEvidence.sha(receiptSha),
                "durable failed undispatched search outcome required");
        proof.requireOriginal(this,attempt,now,false);proof.requireOutcome(outcome);
        nativeTask.recordSearchNavigationNoEffect(this,attempt,receiptSha,proof,now);
        proof.requireOriginal(this,attempt,now,false);proof.requireOutcome(outcome);
        synchronized(this){requireLive(now);need(attempt==attempted&&successorProof==null,"search outcome superseded during durable receipt");
        attempt.closeForSuccessor();closedSuccessorAttempt=attempt;successorProof=proof;successorReceiptSha=receiptSha;}
    }
    synchronized void requireFreshPlanningAfterNoEffect(HeptaAccessibilityService.NativeSearchNoEffectReplanProof proof,long now){
        requireLive(now);need(proof!=null&&proof==successorProof&&closedSuccessorAttempt!=null
                &&attempted==closedSuccessorAttempt&&offered==closedSuccessorAttempt.offer&&!successorOffered
                &&!navigationEffectRecorded&&!navigationObserved,"same single no-effect planning successor required");
        closedSuccessorAttempt.requireClosedForSuccessor();
        nativeTask.requireSearchNoEffectRecorded(this,closedSuccessorAttempt,successorReceiptSha);
    }
    synchronized Offer offerAfterNoEffect(NativeSearchPlanning planning,
            HeptaAccessibilityService.NativeSearchNoEffectReplanProof proof,long now){
        requireFreshPlanningAfterNoEffect(proof,now);proof.requirePublishedPlanning(this,planning);
        need(planning!=null&&!planning.id.equals(closedSuccessorAttempt.offer.planning.id)
                &&NativeSearchPlanning.equal(binding,planning.binding)&&planning.timing.requestStarted>=startedElapsed
                &&planning.timing.requestDeadline<=chainDeadlineElapsed&&planning.publication!=null
                &&planning.publishedElapsed<=now&&planning.persistedElapsed<=now&&now-planning.capturedElapsed<=2000,
                "new full planning receipt required after the old drained search attempt");
        offered=new Offer(this,planning);attempted=null;successorOffered=true;return offered;
    }
    synchronized boolean freshOfferFor(Attempt old,Offer value){
        return !retired&&successorOffered&&old!=null&&old==closedSuccessorAttempt
                &&successorProof!=null&&value!=null&&value==offered&&value!=old.offer&&value.session==this;
    }
    synchronized void requireNoEffectCandidate(Attempt value,long now){
        requireLive(now);need(successorProof==null&&closedSuccessorAttempt==null&&!successorOffered
                &&value!=null&&value==attempted&&value.offer==offered&&!navigationEffectRecorded&&!navigationObserved,
                "no second search replanning authority");
        value.requireUnclaimedRevalidated(now);
    }
    synchronized void requireModelPlanning(DecisionGrammar grammar,long now){
        requireLive(now);need(offered!=null&&attempted==null&&grammar!=null
                &&NativeSearchDecision.SCHEMA.equals(grammar.schema)&&offered.planning.id.equals(grammar.observationId)
                &&goal.packageName.equals(grammar.currentPackage),"actual current search Offer grammar required");
        offered.requireForGrammar(grammar.authorization);nativeTask.requireSearchModelPlanning(this,offered);
    }

    synchronized void requireOffer(Offer offer){need(!retired&&offer!=null&&offer==offered&&offer.session==this,"actual current Offer required");}
    synchronized void retire(){retired=true;if(attempted!=null)attempted.close();}
    synchronized boolean navigationEffectRecorded(){return navigationEffectRecorded;}
    synchronized void navigationObserved(NativeAppEvidence.Frame frame)throws Exception{
        need(navigationEffectRecorded&&!navigationObserved&&frame!=null,"navigation effect must precede the actual search-input observation");
        nativeTask.requireSearchNavigationObserved(this,frame);navigationObserved=true;
    }

    static final class Offer {
        final NativeSearchSession session;
        final NativeSearchPlanning planning;
        private Offer(NativeSearchSession session,NativeSearchPlanning planning){this.session=session;this.planning=planning;}
        /** In-memory grammar contract only. The real call chain separately samples its original deadline. */
        void requireForGrammar(TaskAuthorization.Frame frame){
            session.requireOffer(this);session.authorization.requireNativeSearchIntent(session.selection,session.goal);
            need(frame!=null&&frame.belongsTo(session.authorization)&&frame.authorization==session.authorization.authorization&&frame.taskId.equals(session.taskId)
                    &&NativeSearchPlanning.equal(frame.evidence(),session.authorization.frame().evidence()),"grammar must use the current actual Gate frame");
            need(session.attempted==null,"planning Offer already consumed");
        }
        DecisionGrammar grammar(){TaskAuthorization.Frame frame=session.authorization.frame();requireForGrammar(frame);return DecisionGrammar.createNativeSearchAuthorized(this,frame);}
        Map<String,Object> promptEvidence(){
            requireForGrammar(session.authorization.frame());Map<String,Object> e=new LinkedHashMap<String,Object>();
            e.put("schema",NativeSearchDecision.SCHEMA);e.put("capture_kind",NativeSearchPlanning.KIND);e.put("planning_only",true);
            e.put("full_tree_equal",planning.fullTreeEqual);e.put("observation_id",planning.id);e.put("package",planning.packageName);
            e.put("phase","home_search");e.put("role_id",planning.role.roleId);e.put("role",NativeSearchRole.ROLE);
            e.put("offered_action",NativeSearchDecision.ACTION);e.put("purpose","打开当前搜索输入框；不选择轮播提示词");
            e.put("hint_is_owner_query",false);e.put("owner_product_model",session.goal.productModel);
            e.put("query_entered",false);e.put("price_observed",false);e.put("business_complete",false);
            e.put("generic_actions_available",false);e.put("screenshot_observed",false);
            e.put("planning_as_of_B",true);e.put("no_event_neutrality_claim",true);e.put("current_full_tree_claimed",false);
            Map<String,Object> context=new LinkedHashMap<String,Object>();
            context.put("entry_label",boundedContext(planning.second.node(planning.role.targetPath).label));
            context.put("hint_description",boundedContext(planning.second.node(planning.role.targetPath+"/0").desc));
            context.put("term_text",boundedContext(planning.second.node(planning.role.targetPath+"/0/0").text));
            context.put("B_census_sha256",planning.second.sha);context.put("B_captured_elapsed_ms",planning.capturedElapsed);
            context.put("hint_is_owner_query",false);context.put("full_B_in_private_receipt",true);
            context.put("model_projection","bounded_actual_search_context_from_B_only");e.put("historical_search_context",context);
            e.put("receipt_sha256",planning.receiptSha256);return NativeAppEvidence.immutableMap(e);
        }
        private static Map<String,Object> boundedContext(String value){
            need(value!=null,"actual B search context missing");int count=value.codePointCount(0,value.length());
            String projection=count<=256?value:value.substring(0,value.offsetByCodePoints(0,256));
            Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("text",projection);e.put("truncated",count>256);
            e.put("original_code_points",count);e.put("original_utf8_sha256",NativeAppEvidence.hash(value));return NativeAppEvidence.immutableMap(e);
        }
        Attempt reserve(NativeSearchDecision decision,String modelRunId,long started,long deadline)throws Exception{
            final Attempt value;
            synchronized(session){
                session.requireLive(started);session.requireOffer(this);requireForGrammar(session.authorization.frame());
                need(session.attempted==null&&decision!=null&&NativeAppEvidence.id(modelRunId)
                        &&planning.id.equals(decision.observationId)&&planning.packageName.equals(decision.packageName)
                        &&planning.role.roleId.equals(decision.roleId),"new real model intent must select this exact Offer");
                need(started>=planning.persistedElapsed&&started-planning.capturedElapsed<=90000&&deadline>started
                        &&deadline-started<=8000&&deadline<=session.chainDeadlineElapsed,"original observation age/8s action/task deadline");
                session.authorization.checkNativeSearchIntent(session.selection,session.goal,modelRunId,planning.id,planning.role.roleId);
                value=new Attempt(this,decision,modelRunId,started,deadline);session.attempted=value;
            }
            // No file/installed verification while holding the Stop-visible Session lock.
            // A racing retirement still fences HA before any effect; no action is replayed.
            session.nativeTask.reserveSearchNavigation(session,value);return value;
        }
    }
    static final class Attempt {
        final NativeSearchSession session;final Offer offer;final NativeSearchDecision decision;
        final String modelRunId;final long startedElapsed,deadlineElapsed;
        private int state;private boolean claimed,closedForSuccessor,finalCensusResampled;private NativeSearchRole revalidation;private long revalidatedElapsed;
        private Attempt(Offer offer,NativeSearchDecision decision,String run,long started,long deadline){
            this.offer=offer;session=offer.session;this.decision=decision;modelRunId=run;startedElapsed=started;deadlineElapsed=deadline;
        }
        void requireLive(long now){session.requireLive(now);session.requireOffer(offer);
            synchronized(this){need(session.attempted==this&&state<2&&now>=startedElapsed&&now<deadlineElapsed,"original one-use search Attempt unavailable");}}
        void verifyInstalled()throws Exception{session.verifyInstalled();}
        void requireUnvalidatedRead(long now){requireLive(now);synchronized(this){
            need(state==0&&!claimed&&revalidation==null,"current C reads require the original unclaimed, unvalidated Attempt");}}
        /** Pure C/D proof is retained only for this already reserved intent. It
         * does not replace HA's C original NodeRef, D latest full signature,
         * actual ancestor/window reread, or final event/ownership fence. */
        NativeSearchRole revalidate(NativeActionSnapshotCheck.Snapshot current,NativeActionSnapshotCheck.Snapshot latest,long now){
            requireLive(now);need(current!=null&&latest!=null,"current full C/D pair required");
            for(Map.Entry<String,Object> field:session.binding.entrySet())need(NativeSearchPlanning.equal(field.getValue(),current.env.get(field.getKey()))
                    &&NativeSearchPlanning.equal(field.getValue(),latest.env.get(field.getKey())),"current census Session identity differs: "+field.getKey());
            need(offer.planning.id.equals(current.env.get("origin_observation_id"))&&offer.planning.id.equals(latest.env.get("origin_observation_id")),"current census not bound to this Offer");
            long c=((Number)current.env.get("captured_elapsed_ms")).longValue(),d=((Number)latest.env.get("captured_elapsed_ms")).longValue();
            need(startedElapsed<=c&&c<=d&&d<=now,"current actual C/D clocks precede the Attempt");
            NativeSearchRole proof=NativeSearchRole.compare(current,latest);offer.planning.role.requireSameRole(proof);
            synchronized(this){need(state==0&&revalidation==null,"one full current C/D proof only");revalidation=proof;revalidatedElapsed=now;}
            return proof;
        }
        /** Only HA's actual final preclaim content fence may discard its old
         * complete proof. State/claim/run/deadline never reset; fresh C/D must
         * subsequently pass the original revalidate method before one claim. */
        void discardRevalidationForFinalCensus(HeptaAccessibilityService.NativeSearchFinalCensusResampleProof proof,long now){
            need(proof!=null,"actual final-census producer capability required");
            requireUnclaimedRevalidated(now);final NativeSearchRole previous;
            synchronized(this){need(!finalCensusResampled,"one complete census replacement only");previous=revalidation;}
            // Do not acquire Session/service/event locks while holding the Attempt lock.
            proof.consume(this,previous,now);requireLive(now);
            synchronized(this){
                need(state==0&&!claimed&&!closedForSuccessor&&!finalCensusResampled&&revalidation==previous,
                        "old proof must remain current and unclaimed through discard");
                finalCensusResampled=true;revalidation=null;revalidatedElapsed=-1;
            }
        }
        /** Must be adjacent to the shared ActionExecutionState.enterEffect;
         * both one-use checks must succeed before the one Android call. */
        void requireUnclaimedRevalidated(long now){
            requireLive(now);synchronized(this){need(state==0&&!claimed&&revalidation!=null&&!closedForSuccessor,
                    "actual unclaimed revalidated search Attempt required");}
        }
        private void closeForSuccessor(){
            synchronized(this){need(state==0&&!claimed&&revalidation!=null&&!closedForSuccessor,
                    "only an unclaimed search Attempt may close for a successor");closedForSuccessor=true;state=2;}
        }
        void requireClosedForSuccessor(){
            synchronized(this){need(state==2&&!claimed&&closedForSuccessor&&revalidation!=null,
                    "old search Attempt was not irrevocably closed for one successor");}
        }
        void claim(long now){requireLive(now);synchronized(this){need(state==0&&!claimed&&revalidation!=null&&now>=revalidatedElapsed,"one fresh revalidated search claim required");state=1;claimed=true;}}
        synchronized void close(){state=2;}
        synchronized Map<String,Object> evidence(){Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema","hepta.native-search-attempt.v1");
            e.put("task_id",session.taskId);e.put("model_run_id",modelRunId);e.put("action",decision.evidence());e.put("planning_receipt_sha256",offer.planning.receiptSha256);
            e.put("authorization_sha256",session.authorization.authorization.sha256);e.put("role_id",offer.planning.role.roleId);
            e.put("started_elapsed_ms",startedElapsed);e.put("deadline_elapsed_ms",deadlineElapsed);e.put("state",state);e.put("claimed",claimed);
            e.put("revalidation",revalidation==null?null:revalidation.evidence());e.put("final_census_resampled",finalCensusResampled);e.put("automatic_redispatch",false);e.put("query_or_price_verified",false);
            return NativeAppEvidence.immutableMap(e);}
    }

    void acceptOutcome(Attempt attempt,HeptaAccessibilityService.ActionOutcome outcome,String actualReceiptSha,long now)throws Exception{
        requireLive(now);need(attempt==attempted&&attempt!=null&&outcome!=null&&NativeAppEvidence.sha(actualReceiptSha),"same actual navigation outcome/receipt");
        need(outcome.accepted&&outcome.dispatched&&!outcome.stale&&outcome.actionExecution!=null
                &&outcome.taskAuthorization!=null&&outcome.taskAuthorization.optBoolean("callback_lease_current",false)
                &&!outcome.taskAuthorization.optBoolean("callback_cancelled",true),"search navigation not dispatched with current authority: "+outcome.detail);
        synchronized(attempt){need(attempt.claimed&&attempt.state==1&&attempt.revalidation!=null,"actual once-claimed C/D search intent required");}
        JSONObject e=outcome.actionExecution;
        need("hepta.action-execution.v1".equals(e.optString("schema",""))&&taskId.equals(e.optString("task_id",""))
                &&attempt.modelRunId.equals(e.optString("model_run_id",""))&&attempt.offer.planning.id.equals(e.optString("observation_id",""))
                &&authorization.authorization.sha256.equals(e.optString("authorization_sha256",""))
                &&nativeTask.generation.equals(e.optString("background_generation",""))&&e.optInt("display_id",-1)==nativeTask.displayId
                &&e.optLong("queued_elapsed_ms",-1)==attempt.startedElapsed&&e.optLong("deadline_elapsed_ms",-1)==attempt.deadlineElapsed
                &&e.optBoolean("effect_entered",false)&&e.optBoolean("effect_returned",false)&&e.optBoolean("api_accepted",false)
                &&e.optBoolean("worker_drained",false)&&e.optBoolean("callback_published",false)&&e.optBoolean("callback_authority_current",false)
                &&!e.optBoolean("retired",true),"actual shared action lifecycle does not prove a current drained single effect");
        need(now<attempt.deadlineElapsed,"navigation outcome is late");
        nativeTask.recordSearchNavigationEffect(this,attempt,actualReceiptSha,NativeSearchPlanning.map(e),now);
        synchronized(this){navigationEffectRecorded=true;}attempt.close();
    }
    private static void need(boolean value,String why){if(!value)throw new IllegalStateException("native search Session: "+why);}
}
