package org.trillionnium.hepta.local;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.trillionnium.hepta.background.WindowOwnership;

/** One immutable native-App query task. This class has no Android dispatch,
 * coordinate, network, model, restart or retry API. Every transition consumes
 * the original controller's actual model decision and action receipt. */
final class NativeAppSession {
    static final String SCHEMA="hepta.native-app-session.v1";
    static final long OBSERVED_TRANSITION_MS=15000;
    static final int MAX_OBSERVATIONS=96,MAX_ACTIONS=20;
    static final long PRODUCT_HOME_LOADING_MS=15000;
    static final int MAX_PRODUCT_HOME_LOADING_WAITS=2;
    interface Journal {void write(String leaf,Map<String,Object> value)throws Exception;}
    interface InstalledVerifier {void verify()throws Exception;}
    final String taskId,selectionSha,generation;
    final int displayId;
    final TaskAuthorization.Gate authorization;
    final BackgroundTaskTarget.SelectionBinding selection;
    final BackgroundTaskTarget target;
    final NativeAppGoal goal;
    final NativeAppEvidence.Installed installed;
    private final Journal journal;
    private final InstalledVerifier installedVerifier;
    private final Map<String,String> observations=new LinkedHashMap<String,String>();
    private final List<Map<String,Object>> transitions=new ArrayList<Map<String,Object>>();
    private final Set<LocalDate> queryAttempts=new TreeSet<LocalDate>(),dateAttempts=new TreeSet<LocalDate>();
    private final Set<String> usedRuns=new TreeSet<String>();
    private NativeAppDomain current;
    private NativeCtripFlightPage.Page flight;
    private NativeXiaomiProductPage.Page product;
    private Attempt inFlight,pending,lastDone;
    private Attempt recoverableStaleAttempt;
    private int ordinal,observationOrdinal,productHomeLoadingWaits;
    private long productHomeLoadingSince=-1;
    private boolean retired,terminalConsumed,invalid,productQueryAttempted,productModalExitAttempted;
    private boolean productLoginExitReserved;
    private String productLoginProposalObservation;
    private boolean flightLoginExitAttempted;
    private boolean flightLoginReturnedToForm;
    private String flightLoginProposalObservation;
    private String invalidReason;
    private String reservationReobserveId;
    private long reservationReobserveAfter;
    private LocalDate calendarProposedDate,confirmedFormDate,lastQueryDate;
    private Map<String,Object> calendarInspection,calendarYearProof,lastQueryProof,productQueryProof,productOpenProof;
    private String productSemantic;
    private SuccessClaim acceptedClaim;
    // Separate planning/navigation state; never an old executable Frame or pending click.
    private NativeSearchSession searchPlanning;
    private NativeSearchSession.Attempt searchNavigationAttempt;
    private Map<String,Object> searchNavigationEffect;
    private boolean searchNavigationObserved,searchNavigationReleased;
    private int searchNavigationOrdinal;
    private String searchNoEffectReceiptSha;
    private long searchNavigationEffectElapsed=-1;
    // The actual LTC runTask creates one Session; re-observation reuses it.
    // This field is never reset by close, failed journaling or a new Offer wrapper.
    private CalendarOffer calendarDateOffer;
    private CalendarSelectionEvidence calendarSelection;

    /** Controller wake-up only. Implementations must hand control back to the
     * ordinary task worker; this interface has no observation or input method. */
    interface CalendarModelSignal {
        void onModelReady();
        void onModelFailure(String detail,boolean modelCleanupKnown);
    }
    private static final class CalendarModelArrival {
        final VlmInferenceAdapter.AcceptedRequest accepted;
        final long receivedElapsed,actionDeadlineElapsed;
        private CalendarModelArrival(VlmInferenceAdapter.AcceptedRequest accepted,long received,long deadline){
            this.accepted=accepted;receivedElapsed=received;actionDeadlineElapsed=deadline;
        }
    }
    /** Registered model provenance only. A later fresh producer and the actual
     * action-slot/input bridge remain necessary; no CalendarPermit exists here. */
    static final class CalendarModelRequest {
        private final CalendarOffer offer;
        private final CalendarModelArrival arrival;
        private final NativeCalendarDateIntent intent;
        private final Map<String,Object> registrationAttempt;
        private boolean freshReadAttempted;
        private CalendarFreshRead freshRead;
        final long registeredElapsed;
        private CalendarModelRequest(CalendarOffer offer,CalendarModelArrival arrival,
                NativeCalendarDateIntent intent,Map<String,Object> attempted,long registered){
            this.offer=offer;this.arrival=arrival;this.intent=intent;
            registrationAttempt=NativeAppEvidence.immutableMap(attempted);registeredElapsed=registered;
        }
        String modelRunId(){return arrival.accepted.requestId();}
        String rawText(){return arrival.accepted.rawText();}
        Map<String,Object> intentEvidence(){return intent.evidence();}
        void requireForFreshObservation()throws Exception{
            synchronized(offer){
                need(offer.modelRequest==this,"the actually registered original model request is required");
                offer.session.requireCalendarModelOwner(offer);
                arrival.accepted.requireBound(offer.requireModelProducer(),offer.source.image,offer.grammar);
                offer.requireArrivalDeadline(arrival,registeredElapsed);
            }
        }
        /** Reserves the single fresh-read attempt before I/O. No new budget,
         * model call, observation fallback or failed-read retry is admitted. */
        CalendarFreshRead beginFreshObservation(BackgroundSession background)throws Exception{
            synchronized(offer){
                if(freshReadAttempted){
                    if(freshRead!=null)freshRead.close();else offer.close();
                    throw new IllegalStateException("calendar fresh-read attempt already spent");
                }
                freshReadAttempted=true;
                try{
                    requireForFreshObservation();
                    need(background!=null&&background.selection==offer.session.selection
                            &&offer.session.taskId.equals(background.taskId)&&offer.session.generation.equals(background.generation)
                            &&offer.session.displayId==background.displayId(),"same owned background required");
                    long begun=offer.requireArrivalDeadline(arrival,registeredElapsed);
                    Map<String,Object> record=NativeAppEvidence.map();
                    record.put("schema","hepta.native-calendar-fresh-read-attempt.v1");
                    record.put("task_id",offer.session.taskId);record.put("model_request",evidence());
                    record.put("started_elapsed_ms",begun);record.put("original_action_deadline_elapsed_ms",arrival.actionDeadlineElapsed);
                    record.put("original_task_deadline_elapsed_ms",offer.taskDeadlineElapsed);
                    record.put("fresh_read_slot_consumed",true);record.put("input_attempted",false);
                    offer.session.journal.write("native-calendar-fresh-read-attempt.json",NativeAppEvidence.immutableMap(record));
                    requireForFreshObservation();offer.requireArrivalDeadline(arrival,begun);
                    CalendarFreshRead read=new CalendarFreshRead(this,background,begun);freshRead=read;
                    read.requireOriginal(offer.session,background);return read;
                }catch(Exception refused){offer.close();throw refused;}
            }
        }
        Map<String,Object> evidence(){Map<String,Object> e=NativeAppEvidence.map();
            e.put("schema","hepta.native-calendar-model-request.v1");
            e.put("registration_attempt",registrationAttempt);e.put("registered_elapsed_ms",registeredElapsed);
            e.put("model_run_id",arrival.accepted.requestId());e.put("intent",intent.evidence());
            e.put("model_received_elapsed_ms",arrival.receivedElapsed);
            e.put("original_action_deadline_elapsed_ms",arrival.actionDeadlineElapsed);
            e.put("original_task_deadline_elapsed_ms",offer.taskDeadlineElapsed);
            e.put("model_receipt_registered",true);e.put("fresh_capture_consumed",false);
            e.put("calendar_permit_issued",false);e.put("android_dispatch_authority",false);
            e.put("date_selection_verified",false);return NativeAppEvidence.immutableMap(e);}
    }
    /** Sole newly captured observation request, issued on the controller worker.
     * The ordinary model/Offer budget was already spent. This class has no input
     * method; the real HA producer must bind its private published-frame proof. */
    static final class CalendarFreshRead implements AutoCloseable {
        private final CalendarModelRequest model;
        final NativeAppSession session;
        final BackgroundSession background;
        final NativeAppGoal goal;
        final LocalRuntimeConfig runtime;
        final LocalInference.CurrentFrame originalImage;
        final long startedElapsed,modelReceivedElapsed,deadlineElapsed,taskDeadlineElapsed;
        private boolean acceptanceAttempted,closed,producerSubmissionConsumed;
        private HeptaAccessibilityService producerService;
        private CalendarPermit permit;
        private CalendarFreshRead(CalendarModelRequest model,BackgroundSession background,long started){
            this.model=model;this.background=background;session=model.offer.session;goal=session.goal;
            runtime=model.offer.runtime;originalImage=model.offer.source.image;startedElapsed=started;
            modelReceivedElapsed=model.arrival.receivedElapsed;deadlineElapsed=model.arrival.actionDeadlineElapsed;
            taskDeadlineElapsed=model.offer.taskDeadlineElapsed;
        }
        /** A private read object may submit only one actual HA observation.
         * This method only spends a slot; it cannot construct publication proof. */
        void claimObservationProducer(HeptaAccessibilityService actual){
            synchronized(model.offer){
                if(producerSubmissionConsumed){close();throw new IllegalStateException("calendar producer submission already spent");}
                producerSubmissionConsumed=true;
                try{
                    need(!closed&&!model.offer.closed()&&model.freshRead==this&&actual!=null,
                            "live original calendar read and actual producer required");
                    producerService=actual;
                }catch(RuntimeException refused){close();throw refused;}
            }
        }
        boolean producerRetired(HeptaAccessibilityService actual){
            synchronized(model.offer){return closed||model.offer.closed()||!producerSubmissionConsumed
                    ||producerService!=actual||model.freshRead!=this;}
        }
        void requireProducerIdentity(HeptaAccessibilityService actual){
            need(!producerRetired(actual),"actual one-use calendar observation producer changed or retired");
        }
        void registerInputTracking(HeptaAccessibilityService actual,HeptaAccessibilityService.CalendarFreshObservation proof){
            synchronized(model.offer){
                requireProducerIdentity(actual);actual.registerNativeCalendarInputTracking(this,proof);
            }
        }
        void requireInputTrackingRegistration(HeptaAccessibilityService actual){
            need(Thread.holdsLock(model.offer),"calendar tracker registration requires the original read lock");
            requireProducerIdentity(actual);
        }
        /** Pure publication/currentness fence. Full original-file and installed
         * checks remain in requireOriginal on the controller worker. */
        void requirePublicationOwner(NativeAppSession actual,BackgroundSession actualBackground,long now){
            synchronized(model.offer){
                CalendarOffer offer=model.offer;session.live();
                need(!closed&&!offer.closed()&&model.freshRead==this&&offer.modelRequest==model
                        &&session.calendarDateOffer==offer&&actual==session&&actualBackground==background
                        &&session.current==offer.originalDomain&&session.current.frame==offer.source.facts
                        &&session.inFlight==null&&session.pending==null&&session.recoverableStaleAttempt==null
                        &&session.reservationReobserveId==null&&now>=startedElapsed
                        &&now<deadlineElapsed&&now<taskDeadlineElapsed,
                        "original calendar publication owner or deadline is no longer current");
                session.requireCalendarOwner(session.authorization.frame());
                requireCalendarRuntime(offer.inference,offer.runtime);offer.requireModelProducer();
            }
        }
        void requireOriginal(NativeAppSession actual,BackgroundSession actualBackground)throws Exception{
            synchronized(model.offer){
                need(!closed&&model.freshRead==this&&actual==session&&actualBackground==background,
                        "the same private fresh-read request and owned background are required");
                model.requireForFreshObservation();
                need(background!=null&&background.selection==session.selection
                        &&session.taskId.equals(background.taskId)&&session.generation.equals(background.generation)
                        &&session.displayId==background.displayId()&&background.profileTarget()!=null
                        &&session.installed.profileTarget.same(background.profileTarget()),
                        "calendar fresh read cannot migrate to another selection, lease or profile");
                background.requireActive();model.offer.requireArrivalDeadline(model.arrival,startedElapsed);
            }
        }
        /** Worker only. The named HA type has a private production constructor;
         * it is deliberately not supplied by a map, callback boolean or test port.
         * This proposal cannot be applied until that real producer is reviewed. */
        CalendarPermit acceptFreshObservation(HeptaAccessibilityService.CalendarFreshObservation actual)throws Exception{
            synchronized(model.offer){
                if(acceptanceAttempted){close();throw new IllegalStateException("calendar fresh publication already consumed");}
                acceptanceAttempted=true;
                try{
                    requireOriginal(session,background);need(actual!=null,"actual fresh publication proof required");
                    actual.requireBound(this);
                    NativeCalendarDateEnvelope fresh=actual.readEnvelope(this);
                    session.requireFrame(fresh.facts);
                    NativeCalendarDateProtocol.Consumption consumed=model.offer.protocol.consumeFresh(fresh,model.offer.clock);
                    Map<String,Object> record=NativeAppEvidence.map();
                    record.put("schema","hepta.native-calendar-permit-attempt.v1");
                    record.put("task_id",session.taskId);record.put("original_model_request",model.evidence());
                    record.put("fresh_read",evidence());record.put("actual_publication",actual.evidence());
                    record.put("protocol_consumption",consumed.evidence());
                    record.put("permit_attempt_consumed",true);record.put("action_slot_acquired",false);
                    record.put("input_attempted",false);record.put("date_selection_verified",false);
                    session.journal.write("native-calendar-permit-attempt.json",NativeAppEvidence.immutableMap(record));
                    // Keep the original private model proof, old pixel provenance
                    // and a separate current fresh producer check after all I/O.
                    requireOriginal(session,background);actual.requireBound(this);
                    fresh.requireUnchangedOriginal();
                    long sealed=model.offer.requireArrivalDeadline(model.arrival,consumed.consumedElapsed);
                    requireFreshAt(fresh,sealed);
                    CalendarPermit result=new CalendarPermit(this,actual,consumed,record,sealed);
                    permit=result;return result;
                }catch(Exception refused){close();throw refused;}
            }
        }
        private static void requireFreshAt(NativeCalendarDateEnvelope fresh,long now){
            need(now>=fresh.facts.capturedElapsedMs
                    &&now-fresh.facts.capturedElapsedMs<=NativeCalendarDateEnvelope.FRESH_CAPTURE_MS,
                    "fresh calendar capture expired before permit publication");
            fresh.facts.profileWindow.requireMatches(fresh.profile,fresh.facts.generation,fresh.facts.displayId,
                    fresh.facts.windowId,fresh.facts.profileWindow.taskId,now);
        }
        Map<String,Object> evidence(){
            Map<String,Object> e=NativeAppEvidence.map();e.put("schema","hepta.native-calendar-fresh-read.v1");
            e.put("task_id",session.taskId);e.put("model_run_id",model.arrival.accepted.requestId());
            e.put("fresh_read_started_elapsed_ms",startedElapsed);e.put("model_received_elapsed_ms",modelReceivedElapsed);
            e.put("original_action_deadline_elapsed_ms",deadlineElapsed);e.put("original_task_deadline_elapsed_ms",taskDeadlineElapsed);
            e.put("same_private_background_object",true);e.put("fresh_read_attempts",1);
            e.put("grants_android_dispatch",false);return NativeAppEvidence.immutableMap(e);
        }
        @Override public void close(){synchronized(model.offer){
            closed=true;model.offer.close();
            if(producerService!=null)producerService.retireNativeCalendarInputTracking(this);
        }}
    }
    /** Private model/fresh-publication capability. Its single action producer,
     * durable input claim and post-effect read are separate, non-renewable slots. */
    static final class CalendarPermit implements AutoCloseable {
        private final CalendarFreshRead read;
        private final HeptaAccessibilityService.CalendarFreshObservation publication;
        private final NativeCalendarDateProtocol.Consumption consumption;
        private final Map<String,Object> attempt;
        private HeptaAccessibilityService actionProducer;
        private HeptaAccessibilityService.CalendarInputAttempt inputAttempt;
        private boolean actionProducerConsumed,inputConsumed,selectionReadConsumed,selectionConsumed;
        private Map<String,Object> inputRecord;
        private String inputRecordSha,permitRecordSha;
        final long sealedElapsed,deadlineElapsed;
        private CalendarPermit(CalendarFreshRead read,HeptaAccessibilityService.CalendarFreshObservation publication,
                NativeCalendarDateProtocol.Consumption consumption,Map<String,Object> attempt,long sealed){
            this.read=read;this.publication=publication;this.consumption=consumption;
            this.attempt=NativeAppEvidence.immutableMap(attempt);sealedElapsed=sealed;deadlineElapsed=read.deadlineElapsed;
        }
        NativeAppSession session(){return read.session;}
        BackgroundSession background(){return read.background;}
        long taskDeadlineElapsed(){return read.taskDeadlineElapsed;}
        String modelRunId(){return read.model.arrival.accepted.requestId();}
        NativeCalendarDateIntent intent(){return read.model.intent;}
        NativeCalendarDateEnvelope fresh(){return consumption.fresh;}
        PhoneObservation observationFor(LocalTaskController controller)throws Exception{
            return publication.observationFor(controller,read);
        }
        boolean actionRetired(){synchronized(read.model.offer){return read.closed||read.model.offer.closed();}}
        PhoneObservation observationForAction(HeptaAccessibilityService actual,LocalTaskController controller){
            return publication.observationForAction(actual,controller,read);
        }
        void requireActionCurrent(HeptaAccessibilityService actual,LocalTaskController controller){
            publication.requireActionCurrentPure(actual,controller,read);
        }
        void retireInputTracking(){publication.retireInputTracking();}

        void claimActionProducer(HeptaAccessibilityService actual,LocalTaskController controller){
            synchronized(read.model.offer){
                if(actionProducerConsumed){close();throw new IllegalStateException("calendar action producer already consumed");}
                actionProducerConsumed=true;actionProducer=actual;
                try{
                    read.requireProducerIdentity(actual);
                    publication.requireActionIssuer(actual,controller,read);
                    requirePureOwner(actual,read.model.offer.clock.elapsedRealtime());
                }catch(RuntimeException refused){close();throw refused;}
            }
        }
        private void requirePureOwner(HeptaAccessibilityService actual,long now){
            need(actionProducerConsumed&&actionProducer==actual&&read.permit==this,
                    "same one-use actual calendar action producer required");
            read.requireProducerIdentity(actual);read.requirePublicationOwner(read.session,read.background,now);
            need(now>=sealedElapsed&&now<deadlineElapsed&&now<read.taskDeadlineElapsed,
                    "original calendar action/task deadline expired");
        }
        void requireInputPure(HeptaAccessibilityService actual,HeptaAccessibilityService.CalendarInputAttempt own,long now){
            synchronized(read.model.offer){
                requirePureOwner(actual,now);
                need(inputConsumed&&inputAttempt==own&&inputRecord!=null&&NativeAppEvidence.sha(inputRecordSha)
                        &&NativeAppEvidence.sha(permitRecordSha)&&!selectionReadConsumed,
                        "same durable one-use input claim is required");
                CalendarFreshRead.requireFreshAt(consumption.fresh,now);
            }
        }
        void requireForAction(NativeAppSession session,BackgroundSession background)throws Exception{
            synchronized(read.model.offer){
                need(read.permit==this,"the original private calendar permit is required");
                read.requireOriginal(session,background);publication.requireBound(read);
                consumption.fresh.requireUnchangedOriginal();
                long now=read.model.offer.requireArrivalDeadline(read.model.arrival,sealedElapsed);
                CalendarFreshRead.requireFreshAt(consumption.fresh,now);
            }
        }
        /** Runs on the original action worker. The HA object below can only be
         * privately constructed for its actual shared-slot ActionWork. */
        Map<String,Object> consumeInput(HeptaAccessibilityService.CalendarInputAttempt actual)throws Exception{
            synchronized(read.model.offer){
                if(inputConsumed){close();throw new IllegalStateException("calendar input claim already consumed");}
                inputConsumed=true;inputAttempt=actual;
                try{
                    need(actual!=null,"private actual calendar input attempt required");actual.requirePermitProducer(this,false);
                    requireForAction(read.session,read.background);
                    permitRecordSha=readRecord("native-calendar-permit-attempt.json",attempt);
                    Map<String,Object> record=NativeAppEvidence.map();
                    record.put("schema","hepta.native-calendar-input-attempt.v1");record.put("task_id",read.session.taskId);
                    record.put("model_run_id",modelRunId());record.put("goal_sha256",read.goal.contractSha256);
                    record.put("date",read.goal.departureDate.toString());record.put("permit_sha256",permitRecordSha);
                    record.put("fresh_observation",consumption.fresh.facts.evidence());record.put("intent",intent().evidence());
                    record.put("actual_action_execution",actual.executionBeforeInput());
                    record.put("claim_requested_elapsed_ms",read.model.offer.requireArrivalDeadline(read.model.arrival,sealedElapsed));
                    record.put("original_action_deadline_elapsed_ms",deadlineElapsed);record.put("original_task_deadline_elapsed_ms",read.taskDeadlineElapsed);
                    record.put("permit_consumed",true);record.put("input_attempted",false);record.put("replay_allowed",false);
                    record.put("model_grounding_is_date_proof",false);record.put("date_selection_verified",false);
                    inputRecord=NativeAppEvidence.immutableMap(record);
                    read.session.journal.write("native-calendar-input-attempt.json",inputRecord);
                    inputRecordSha=readRecord("native-calendar-input-attempt.json",inputRecord);
                    actual.requirePermitProducer(this,false);requireForAction(read.session,read.background);
                    long now=read.model.offer.requireArrivalDeadline(read.model.arrival,sealedElapsed);
                    requireInputPure(actionProducer,actual,now);
                    return inputValues();
                }catch(Exception refused){close();throw refused;}
            }
        }
        private String readRecord(String leaf,Map<String,Object> expected)throws Exception{
            java.io.File path=new java.io.File(consumption.fresh.image.image.getCanonicalFile().getParentFile(),leaf);
            MobiMindPrivateFiles.Read value=MobiMindPrivateFiles.read(path,2*1024*1024,true);
            byte[] exact=new org.json.JSONObject(expected).toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            need(java.util.Arrays.equals(exact,value.bytes),"calendar private journal bytes changed or were not durably written");
            value.unchangedPath();return MobiMindContract.sha(value.bytes);
        }
        void requireInputOriginal(HeptaAccessibilityService.CalendarInputAttempt actual)throws Exception{
            synchronized(read.model.offer){
                need(actual==inputAttempt,"same original input attempt required");actual.requirePermitProducer(this,false);
                requireForAction(read.session,read.background);
                need(permitRecordSha.equals(readRecord("native-calendar-permit-attempt.json",attempt))
                        &&inputRecordSha.equals(readRecord("native-calendar-input-attempt.json",inputRecord)),
                        "calendar permit/input original changed");
                requireInputPure(actionProducer,actual,read.model.offer.requireArrivalDeadline(read.model.arrival,sealedElapsed));
            }
        }
        private Map<String,Object> inputValues(){
            NativeAppEvidence.Frame f=consumption.fresh.facts;NativeCalendarDateIntent.Rect r=intent().cell;
            Map<String,Object> e=NativeAppEvidence.map();e.put("package",f.packageName);e.put("window_id",f.windowId);
            e.put("task_id",f.profileWindow.taskId);e.put("deadline_elapsed_ms",deadlineElapsed);
            e.put("owner_task_id",read.session.taskId);e.put("goal_sha256",read.goal.contractSha256);
            e.put("date",read.goal.departureDate.toString());e.put("observation_id",f.observationId);
            e.put("screen_sha256",consumption.fresh.pngSha256);e.put("permit_sha256",permitRecordSha);
            e.put("attempt_record_sha256",inputRecordSha);e.put("display_width",f.width);e.put("display_height",f.height);
            e.put("display_rotation",f.rotation);e.put("left",r.left);e.put("top",r.top);e.put("right",r.right);e.put("bottom",r.bottom);
            need(e.size()==18,"closed calendar input field set differs");return NativeAppEvidence.immutableMap(e);
        }
        void claimSelectionRead(HeptaAccessibilityService.CalendarActionResult actual)throws Exception{
            synchronized(read.model.offer){
                if(selectionReadConsumed){close();throw new IllegalStateException("calendar selection read already consumed");}
                selectionReadConsumed=true;
                try{requireSelectionOriginal(actual);}
                catch(Exception refused){close();throw refused;}
            }
        }
        void requireSelectionOwner(HeptaAccessibilityService.CalendarActionResult actual,long now){
            synchronized(read.model.offer){
                requirePureOwner(actionProducer,now);
                need(selectionReadConsumed&&!selectionConsumed&&inputConsumed&&inputAttempt!=null&&actual!=null,
                        "one original post-effect calendar selection read required");
                actual.requireSuccessfulOriginal(this,inputAttempt);
            }
        }
        /** Post-effect provenance is historical. It re-reads the exact old files,
         * but never asks an old fresh Phone to still be the current publication.
         * Currentness belongs exclusively to the independently new FORM producer. */
        void requireSelectionOriginal(HeptaAccessibilityService.CalendarActionResult actual)throws Exception{
            synchronized(read.model.offer){
                requireSelectionOwner(actual,read.model.offer.requireArrivalDeadline(read.model.arrival,sealedElapsed));
                read.model.offer.session.requireCalendarModelOwner(read.model.offer);
                read.model.arrival.accepted.requireBound(read.model.offer.inference,read.model.offer.source.image,read.model.offer.grammar);
                need(permitRecordSha.equals(readRecord("native-calendar-permit-attempt.json",attempt))
                        &&inputRecordSha.equals(readRecord("native-calendar-input-attempt.json",inputRecord)),
                        "calendar original journals changed after input");
                MobiMindPrivateFiles.Read png=MobiMindPrivateFiles.read(consumption.fresh.image.image,8*1024*1024,true);
                need(consumption.fresh.pngSha256.equals(MobiMindContract.sha(png.bytes)),"original fresh PNG changed after input");
                png.unchangedPath();publication.requireRecordedOriginal(read);
                requireSelectionOwner(actual,read.model.offer.requireArrivalDeadline(read.model.arrival,sealedElapsed));
            }
        }
        CalendarSelectionEvidence acceptSelection(HeptaAccessibilityService.CalendarSelectionObservation actual)throws Exception{
            synchronized(read.model.offer){
                need(!selectionConsumed,"calendar selection evidence already consumed");selectionConsumed=true;
                try{
                    need(actual!=null&&selectionReadConsumed,"actual private new FORM publication required");
                    // Reserve before any I/O, while still permitting this single original verifier.
                    actual.requireBound(this);requireSelectionOriginalForAcceptance(actual.result);
                    NativeAppEvidence.Frame after=actual.frame;
                    Map<String,Object> assessment=read.model.offer.protocol.assessForm(consumption,after,read.model.offer.clock.elapsedRealtime());
                    need(Boolean.TRUE.equals(assessment.get("target_month_day_and_route_passengers_match")),
                            "actual new FORM does not confirm the requested month/day, route and passengers");
                    need(after.capturedElapsedMs>actual.result.confirmedElapsed,
                            "FORM must be captured after the one confirmed calendar input pair");
                    Map<String,Object> e=NativeAppEvidence.map();e.put("schema","hepta.native-calendar-selection-evidence.v1");
                    e.put("task_id",read.session.taskId);e.put("requested_date",read.goal.departureDate.toString());
                    e.put("original_calendar_inspection",read.model.offer.originalCalendarInspection);
                    e.put("year_observed_in_calendar",read.model.offer.source.observedMonth.getYear());
                    e.put("year_independently_observed_in_form",false);e.put("fresh_form_assessment",assessment);
                    e.put("actual_calendar_action",actual.result.evidence());e.put("actual_form_publication",actual.evidence());
                    e.put("single_effect_causal_chain",true);e.put("model_grounding_is_date_proof",false);
                    e.put("date_selection_verified",true);e.put("query_executed",false);e.put("business_verified",false);
                    e.put("selection_verified_elapsed_ms",read.model.offer.requireArrivalDeadline(read.model.arrival,after.capturedElapsedMs));
                    Map<String,Object> sealed=NativeAppEvidence.immutableMap(e);
                    read.session.journal.write("native-calendar-selection-evidence.json",sealed);
                    String sha=readRecord("native-calendar-selection-evidence.json",sealed);
                    actual.requireBound(this);requireSelectionOriginalForAcceptance(actual.result);
                    long now=read.model.offer.requireArrivalDeadline(read.model.arrival,after.capturedElapsedMs);
                    need(now>=after.capturedElapsedMs&&now-after.capturedElapsedMs<=NativeCalendarDateEnvelope.FRESH_CAPTURE_MS,
                            "new FORM expired during selection persistence");
                    CalendarSelectionEvidence proof=new CalendarSelectionEvidence(read.session,this,after,sealed,sha);
                    read.session.calendarYearProof=sealed;read.session.confirmedFormDate=read.goal.departureDate;
                    read.session.calendarProposedDate=null;read.session.calendarInspection=null;
                    read.session.observed(after);
                    read.session.transitions.add(sealed);read.session.calendarSelection=proof;close();return proof;
                }catch(Exception refused){read.session.invalidate("calendar_selection_not_verified");close();throw refused;}
            }
        }
        private void requireSelectionOriginalForAcceptance(HeptaAccessibilityService.CalendarActionResult actual)throws Exception{
            // The single reserved verification is allowed; no second reader/consumer can enter.
            need(selectionConsumed,"selection verification was not reserved");
            actual.requireSuccessfulOriginal(this,inputAttempt);
            read.model.offer.session.requireCalendarModelOwner(read.model.offer);
            read.model.arrival.accepted.requireBound(read.model.offer.inference,read.model.offer.source.image,read.model.offer.grammar);
            need(permitRecordSha.equals(readRecord("native-calendar-permit-attempt.json",attempt))
                    &&inputRecordSha.equals(readRecord("native-calendar-input-attempt.json",inputRecord)),
                    "calendar originals changed during selection verification");
            publication.requireRecordedOriginal(read);
            read.model.offer.requireArrivalDeadline(read.model.arrival,sealedElapsed);
        }
        void requireSelectionPublication(HeptaAccessibilityService.CalendarActionResult actual,long now){
            synchronized(read.model.offer){
                requirePureOwner(actionProducer,now);need(selectionReadConsumed&&inputAttempt!=null,
                        "original selection read required");actual.requireSuccessfulOriginal(this,inputAttempt);
            }
        }
        Map<String,Object> evidence(){
            Map<String,Object> e=NativeAppEvidence.map();e.put("schema","hepta.native-calendar-permit.v1");
            e.put("attempt",attempt);e.put("sealed_elapsed_ms",sealedElapsed);
            e.put("original_action_deadline_elapsed_ms",deadlineElapsed);e.put("original_task_deadline_elapsed_ms",read.taskDeadlineElapsed);
            e.put("private_model_and_fresh_capture_bound",true);e.put("calendar_dispatch_claim_issued",inputConsumed&&inputRecordSha!=null);
            e.put("grants_android_dispatch",false);e.put("input_attempted",false);e.put("date_selection_verified",false);
            return NativeAppEvidence.immutableMap(e);
        }
        @Override public void close(){publication.retireInputTracking();read.close();}
    }
    /** Calendar date only. It is neither a query result nor a business success claim. */
    static final class CalendarSelectionEvidence {
        final NativeAppSession session;final NativeAppEvidence.Frame frame;final String recordSha256;
        private final CalendarPermit permit;private final Map<String,Object> value;
        private CalendarSelectionEvidence(NativeAppSession session,CalendarPermit permit,NativeAppEvidence.Frame frame,
                Map<String,Object> value,String sha){
            this.session=session;this.permit=permit;this.frame=frame;this.value=value;recordSha256=sha;
        }
        Map<String,Object> evidence(){return value;}
    }

    /** Original model-input Offer; later model registration still grants no input. */
    static final class CalendarOffer implements AutoCloseable {
        final NativeAppSession session;
        final NativeCalendarDateEnvelope source;
        final NativeCalendarDateProtocol protocol;
        final LocalInference inference;
        final LocalRuntimeConfig runtime;
        final long offeredElapsed,taskDeadlineElapsed;
        final LocalDate priorObservedFormDate;
        final Map<String,Object> originalCalendarInspection;
        private final NativeAppDomain originalDomain;
        private final NativeCalendarDateProtocol.Clock clock;
        private DecisionGrammar grammar;
        private boolean grammarIssued,closed;
        private boolean callbackIssued,callbackDelivered,modelRegistrationConsumed;
        private CalendarModelArrival modelArrival;
        private CalendarModelRequest modelRequest;
        private VlmInferenceAdapter modelProducer;
        private RuntimeInferenceAdapter.CalendarModelBinding modelBinding;
        private CalendarOffer(NativeAppSession session,NativeCalendarDateEnvelope source,
                LocalInference inference,NativeAppDomain domain,NativeCalendarDateProtocol.Clock clock,long now,long deadline){
            this.session=session;this.source=source;this.inference=inference;runtime=inference.configuration();
            originalDomain=domain;this.clock=clock;offeredElapsed=now;taskDeadlineElapsed=deadline;
            priorObservedFormDate=session.calendarProposedDate;
            originalCalendarInspection=NativeAppEvidence.immutableMap(session.calendarInspection);
            protocol=new NativeCalendarDateProtocol(source);
        }
        synchronized DecisionGrammar grammar()throws Exception{
            TaskAuthorization.Frame frame=session.authorization.frame();
            if(grammar==null)grammar=DecisionGrammar.createNativeCalendarAuthorized(this,frame);
            else requireForGrammar(frame);
            return grammar;
        }
        void requireForGrammar(TaskAuthorization.Frame frame)throws Exception{
            session.requireCalendarOffer(this,frame);
        }
        synchronized void claimGrammar(TaskAuthorization.Frame frame)throws Exception{
            requireForGrammar(frame);need(!grammarIssued,"calendar Offer grammar was already minted");grammarIssued=true;
        }
        /** The Adapter supplies its opaque proof. Only its receipt and the real
         * callback-arrival clock are captured here, then a signal is delivered.
         * No parsing, file write, observation, claim or effect runs in callback. */
        synchronized VlmInferenceAdapter.AcceptedRequestCallback modelCallback(final CalendarModelSignal signal)throws Exception{
            requireForGrammar(session.authorization.frame());
            need(grammarIssued&&grammar!=null&&!callbackIssued&&signal!=null,
                    "one actual Adapter callback for the original grammar required");
            if(inference instanceof RuntimeInferenceAdapter){
                modelBinding=((RuntimeInferenceAdapter)inference).bindCalendarModel(session.taskId,runtime);
                modelProducer=modelBinding.requireCurrent(session.taskId,runtime);
            }else{
                need(inference instanceof VlmInferenceAdapter,"actual visual Adapter producer required");
                modelProducer=(VlmInferenceAdapter)inference;
            }
            callbackIssued=true;requireModelProducer();
            return new VlmInferenceAdapter.AcceptedRequestCallback(){
                public void onSuccess(String raw,String run){onFailure("opaque accepted visual request required",false);}
                public void onFailure(String detail,boolean cleanup){
                    synchronized(CalendarOffer.this){callbackDelivered=true;close();}
                    signal.onModelFailure(detail,cleanup);
                }
                public void onAcceptedRequest(VlmInferenceAdapter.AcceptedRequest proof){
                    try{
                        synchronized(CalendarOffer.this){
                            need(!closed&&!callbackDelivered&&proof!=null,"one original calendar callback receipt required");
                            requireModelProducer();callbackDelivered=true;long arrived=clock.elapsedRealtime();
                            need(arrived>=offeredElapsed&&arrived<taskDeadlineElapsed,"original task clock expired at calendar callback");
                            long end=Math.min(taskDeadlineElapsed,Math.addExact(arrived,NativeCalendarDateProtocol.ACTION_MS));
                            need(end>arrived,"no original calendar action budget remains");
                            modelArrival=new CalendarModelArrival(proof,arrived,end);
                        }
                        signal.onModelReady();
                    }catch(Exception refused){
                        close();signal.onModelFailure("calendar model receipt delivery refused",false);
                    }
                }
            };
        }
        /** Keep the original task router as the owner and validate its exact
         * captured binding before naming the private receipt's actual producer. */
        private VlmInferenceAdapter requireModelProducer(){
            need(callbackIssued&&modelProducer!=null,"original calendar model producer required");
            if(modelBinding!=null){
                need(inference instanceof RuntimeInferenceAdapter
                        &&modelBinding.requireCurrent(session.taskId,runtime)==modelProducer,
                        "original runtime binding and visual delegate required");
            }else need(inference==modelProducer&&modelProducer.configuration()==runtime,
                    "original direct visual Adapter required");
            return modelProducer;
        }
        /** Called by the ordinary controller worker after callback delivery.
         * The captured arrival+8s deadline is never restarted at registration. */
        synchronized CalendarModelRequest registerModelReply()throws Exception{
            need(!closed&&callbackIssued&&callbackDelivered&&modelArrival!=null&&!modelRegistrationConsumed,
                    "one delivered private model receipt required");
            modelRegistrationConsumed=true;
            try{
                CalendarModelArrival actual=modelArrival;
                session.requireCalendarModelOwner(this);requireArrivalDeadline(actual,actual.receivedElapsed);
                actual.accepted.requireBound(requireModelProducer(),source.image,grammar);
                need(session.usedRuns.add(actual.accepted.requestId())&&++session.ordinal<=MAX_ACTIONS,
                        "same model run already consumed or native task action budget exhausted");
                NativeCalendarDateIntent intent=protocol.propose(actual.accepted.rawText(),actual.accepted.requestId(),
                        actual.receivedElapsed,actual.actionDeadlineElapsed,taskDeadlineElapsed);
                long requested=requireArrivalDeadline(actual,actual.receivedElapsed);
                Map<String,Object> record=NativeAppEvidence.map();
                record.put("schema","hepta.native-calendar-model-registration-attempt.v1");
                record.put("task_id",session.taskId);record.put("ordinal",session.ordinal);
                record.put("original_offer",evidence());record.put("accepted_request",actual.accepted.evidence());
                record.put("intent",intent.evidence());record.put("model_received_elapsed_ms",actual.receivedElapsed);
                record.put("original_action_deadline_elapsed_ms",actual.actionDeadlineElapsed);
                record.put("original_task_deadline_elapsed_ms",taskDeadlineElapsed);
                record.put("registration_requested_elapsed_ms",requested);
                record.put("model_slot_consumed",true);record.put("fresh_capture_consumed",false);
                record.put("calendar_permit_issued",false);record.put("android_dispatch_authority",false);
                // Existing Journal writes a create-only private task artifact.
                // Any failure leaves the offer/model slot consumed and closed.
                session.journal.write("native-calendar-model-registration.json",NativeAppEvidence.immutableMap(record));
                session.requireCalendarModelOwner(this);
                actual.accepted.requireBound(requireModelProducer(),source.image,grammar);
                long completed=requireArrivalDeadline(actual,requested);
                CalendarModelRequest accepted=new CalendarModelRequest(this,actual,intent,record,completed);
                modelRequest=accepted;return accepted;
            }catch(Exception refused){close();throw refused;}
        }
        private long requireArrivalDeadline(CalendarModelArrival actual,long lower){
            long now=clock.elapsedRealtime();need(actual!=null&&now>=actual.receivedElapsed&&now>=lower
                    &&now<actual.actionDeadlineElapsed&&now<taskDeadlineElapsed,
                    "original callback/action/task deadline expired or clock moved backwards");return now;
        }
        @Override public synchronized void close(){closed=true;protocol.close();}
        synchronized boolean closed(){return closed;}
        Map<String,Object> evidence(){Map<String,Object> e=NativeAppEvidence.map();
            e.put("schema","hepta.native-calendar-session-offer.v1");e.put("task_id",session.taskId);
            e.put("source",source.evidence());e.put("offered_elapsed_ms",offeredElapsed);
            e.put("requested_departure_date",session.goal.departureDate.toString());
            e.put("prior_observed_form_date",priorObservedFormDate.toString());
            e.put("prior_form_date_source","original_FORM_month_day_plus_observed_calendar_year");
            e.put("calendar_inspection",originalCalendarInspection);e.put("requested_date_selected",false);
            e.put("original_task_deadline_elapsed_ms",taskDeadlineElapsed);e.put("grammar_sha256",protocol.grammarSha256);
            e.put("task_global_single_offer",true);e.put("model_receipt_registered",false);
            e.put("calendar_permit_issued",false);e.put("android_dispatch_authority",false);
            return NativeAppEvidence.immutableMap(e);}
    }
    CalendarOffer offerCalendarDate(NativeCalendarDateEnvelope source,LocalInference inference,
            NativeCalendarDateProtocol.Clock clock,long taskDeadlineElapsed)throws Exception{
        live();verifyInstalled();need(source!=null&&source.goal==goal&&clock!=null&&current!=null
                &&source.facts==current.frame&&calendarDateOffer==null&&inFlight==null&&pending==null
                &&recoverableStaleAttempt==null&&reservationReobserveId==null&&calendarInspection!=null
                &&calendarProposedDate!=null&&source.facts.evidence().equals(calendarInspection.get("after"))
                &&source.observedMonth.equals(goal.departureDate.withDayOfMonth(1))
                &&lastQueryProof==null&&queryAttempts.isEmpty()&&dateAttempts.isEmpty()
                &&installed.profileTarget!=null&&source.profile.same(installed.profileTarget),
                "one original prequery native calendar Offer required");
        requireFrame(source.facts);current.requireCalendarDateSource(source);requireCalendarRuntime(inference,null);
        TaskAuthorization.Frame frame=authorization.frame();requireCalendarOwner(frame);
        long now=clock.elapsedRealtime();need(now>=source.facts.capturedElapsedMs
                &&now-source.facts.capturedElapsedMs<=NativeCalendarDateEnvelope.FRESH_CAPTURE_MS
                &&taskDeadlineElapsed>now,"live original calendar and task deadline required");
        CalendarOffer offer=new CalendarOffer(this,source,inference,current,clock,now,taskDeadlineElapsed);
        calendarDateOffer=offer; // Never cleared: an exception cannot create another Offer.
        try{
            offer.requireForGrammar(frame);
            journal.write("native-calendar-date-offer.json",offer.evidence());return offer;
        }catch(Exception refused){offer.close();throw refused;}
    }
    private void requireCalendarOffer(CalendarOffer offer,TaskAuthorization.Frame frame)throws Exception{
        live();need(offer!=null&&offer.session==this&&calendarDateOffer==offer&&!offer.closed()
                &&current==offer.originalDomain&&current.frame==offer.source.facts&&inFlight==null&&pending==null,
                "the exact live original Calendar Offer is required");
        requireFrame(offer.source.facts);current.requireCalendarDateSource(offer.source);requireCalendarOwner(frame);
        requireCalendarRuntime(offer.inference,offer.runtime);verifyInstalled();offer.source.requireUnchangedOriginal();
        long now=offer.clock.elapsedRealtime();need(now>=offer.offeredElapsed&&now<offer.taskDeadlineElapsed
                &&now>=offer.source.facts.capturedElapsedMs
                &&now-offer.source.facts.capturedElapsedMs<=NativeCalendarDateEnvelope.FRESH_CAPTURE_MS,
                "calendar grammar requires the still-fresh source and original task clock");
    }
    /** Post-model identity/lifetime validation deliberately does not reuse the
     * original two-second image-admission rule. It does not claim current pixels.
     * The later fresh-observation producer must independently supply new pixels. */
    private void requireCalendarModelOwner(CalendarOffer offer)throws Exception{
        live();need(offer!=null&&calendarDateOffer==offer&&offer.session==this&&!offer.closed()
                &&offer.grammarIssued&&offer.grammar!=null&&current==offer.originalDomain
                &&current.frame==offer.source.facts&&inFlight==null&&pending==null
                &&recoverableStaleAttempt==null&&reservationReobserveId==null
                &&calendarInspection!=null&&calendarInspection.equals(offer.originalCalendarInspection)
                &&calendarProposedDate!=null&&calendarProposedDate.equals(offer.priorObservedFormDate)
                &&offer.source.goal==goal&&installed.profileTarget!=null&&offer.source.profile.same(installed.profileTarget),
                "original calendar Session/Selection/Goal/domain/inspection must remain live");
        requireFrame(offer.source.facts);current.requireCalendarDateSource(offer.source);
        requireCalendarOwner(authorization.frame());requireCalendarRuntime(offer.inference,offer.runtime);offer.requireModelProducer();
        verifyInstalled();offer.source.requireUnchangedOriginal();
        long now=offer.clock.elapsedRealtime();need(now>=offer.offeredElapsed&&now<offer.taskDeadlineElapsed,
                "original calendar task lifetime expired");
    }
    private void requireCalendarOwner(TaskAuthorization.Frame frame){
        authorization.authorization.requireExecutionSelection(selection);
        need(frame!=null&&frame.belongsTo(authorization)&&frame.authorization==authorization.authorization
                &&taskId.equals(frame.taskId)&&NativeCtripFlightPage.supported(goal)
                &&goal.toolCeiling.contains("click")&&frame.allows("click"),
                "calendar intent cannot replace the actual Gate or bypass a click deny");
    }
    private static void requireCalendarRuntime(LocalInference inference,LocalRuntimeConfig original){
        need(inference!=null&&inference.acceptsObservedImage()&&inference.modelOutputDispatchAllowed(),
                "explicit visual tools adapter required");LocalRuntimeConfig value=inference.configuration();
        need(value!=null&&(original==null||value==original)&&value.profile==ModelProfile.GUI_OWL_4B
                &&!value.visualObservationOnly&&"npu".equals(value.compute)&&value.contextTokens==8192&&value.threads==4,
                "only the same GUI-Owl tools configuration may receive a calendar Offer");
    }



    NativeAppSession(String task,TaskAuthorization.Gate auth,BackgroundTaskTarget.SelectionBinding selected,
            NativeAppEvidence.Installed installed,String selectionSha,String generation,int display,
            InstalledVerifier verifier,Journal journal)throws Exception{
        need(NativeAppEvidence.id(task)&&auth!=null&&task.equals(auth.taskId)&&selected!=null&&selected.executionTarget()!=null,"same task and Selection required");
        auth.authorization.requireCompletionSelection(selected);BackgroundTaskTarget t=selected.executionTarget();
        need(t.explicitSelection&&!t.webHelper()&&BackgroundTaskTarget.NATIVE_APP.equals(t.route)&&t.nativeGoal!=null
                &&t.effectivePackages.size()==1&&t.effectivePackages.contains(t.packageName),"recognized explicit singleton native route required");
        t.requireOwner(auth.authorization.immutableOwner());
        need(t.nativeGoal.ownerSha256.equals(auth.authorization.instructionSha256)&&t.nativeGoal.packageName.equals(t.packageName),"same immutable native goal required");
        need(NativeAppEvidence.sha(selectionSha)&&NativeAppEvidence.backgroundGeneration(generation)&&display>0&&verifier!=null&&journal!=null,"actual background lease and journal required");
        requireInstalled(t.nativeGoal,installed);
        need(t.profileTarget==null?installed.profileTarget==null:t.profileTarget.same(installed.profileTarget),
                "selected profile and independently verified installation differ");verifier.verify();
        taskId=task;authorization=auth;selection=selected;target=t;goal=t.nativeGoal;this.installed=installed;
        this.selectionSha=selectionSha;this.generation=generation;displayId=display;installedVerifier=verifier;this.journal=journal;
        Map<String,Object> e=base();e.put("installed_app",installed.evidence());e.put("selection_projection_sha256",selectionSha);
        e.put("goal",goal.evidence());e.put("background_generation",generation);e.put("display_id",display);
        e.put("model_actions_required",true);e.put("screenshots_used_as_text",false);e.put("automatic_actions_or_replay",false);
        e.put("query_result_verified",false);journal.write("native-app-binding.json",e);
    }
    void bindSearchPlanning(NativeSearchSession session){
        live();need(session!=null&&session.nativeTask==this&&searchPlanning==null&&current==null&&observations.isEmpty()
                &&inFlight==null&&pending==null&&ordinal==0&&NativeSearchSession.eligible(this),"one explicit initial native search planning Session required");
        searchPlanning=session;
    }
    void requireSearchPlanningCurrent(NativeSearchSession session){
        live();need(session!=null&&searchPlanning==session&&session.nativeTask==this&&session.authorization==authorization
                &&session.selection==selection&&session.goal==goal,"actual native search Session differs");
    }
    void reserveSearchNavigation(NativeSearchSession session,NativeSearchSession.Attempt attempt)throws Exception{
        requireSearchPlanningCurrent(session);need(current==null&&inFlight==null&&pending==null
                &&searchNavigationEffect==null&&attempt!=null&&attempt.session==session
                &&(searchNavigationAttempt==null||searchNavigationReleased&&session.freshOfferFor(searchNavigationAttempt,attempt.offer))
                &&usedRuns.add(attempt.modelRunId)&&++ordinal<=MAX_ACTIONS,"one new model search navigation attempt required");
        searchNavigationAttempt=attempt;searchNavigationReleased=false;searchNavigationOrdinal++;
        Map<String,Object> e=base();e.put("schema","hepta.native-search-reservation.v1");e.put("attempt",attempt.evidence());
        e.put("model_issued",true);e.put("automatic_replay",false);e.put("navigation_only",true);e.put("query_or_price_verified",false);
        journal.write(searchNavigationOrdinal==1?"native-search-navigation-attempt.json":
                String.format(java.util.Locale.ROOT,"native-search-navigation-attempt-%02d.json",searchNavigationOrdinal),e);
    }

    void requireSearchModelPlanning(NativeSearchSession session,NativeSearchSession.Offer offer){
        requireSearchPlanningCurrent(session);need(current==null&&inFlight==null&&pending==null&&searchNavigationEffect==null
                &&offer!=null&&offer.session==session&&(searchNavigationAttempt==null
                ||searchNavigationReleased&&session.freshOfferFor(searchNavigationAttempt,offer)),
                "current first or explicitly released fresh search Offer required before the model");
    }
    void recordSearchNavigationNoEffect(NativeSearchSession session,NativeSearchSession.Attempt attempt,String receiptSha,
            HeptaAccessibilityService.NativeSearchNoEffectReplanProof proof,long now)throws Exception{
        requireSearchPlanningCurrent(session);need(searchNavigationAttempt==attempt&&attempt!=null&&attempt.session==session
                &&searchNavigationOrdinal==1&&!searchNavigationReleased&&searchNoEffectReceiptSha==null
                &&searchNavigationEffect==null&&current==null&&inFlight==null&&pending==null
                &&NativeAppEvidence.sha(receiptSha)&&proof!=null,"one original no-effect search reservation required");
        proof.requireOriginal(session,attempt,now,false);attempt.requireUnclaimedForRetirement(now);
        Map<String,Object> e=base();e.put("schema","hepta.native-search-no-effect-retirement.v1");
        e.put("attempt",attempt.evidence());e.put("failed_action_receipt_sha256",receiptSha);e.put("no_effect_proof",proof.evidence());
        e.put("recorded_elapsed_ms",now);e.put("old_model_run_remains_consumed",true);e.put("action_ordinal_preserved",ordinal);
        e.put("fresh_planning_and_new_model_required",true);e.put("automatic_redispatch",false);e.put("business_verified",false);
        journal.write("native-search-no-effect-retirement-01.json",e);
        searchNoEffectReceiptSha=receiptSha;searchNavigationReleased=true;
    }
    void requireSearchNoEffectRecorded(NativeSearchSession session,NativeSearchSession.Attempt attempt,String receiptSha){
        requireSearchPlanningCurrent(session);need(attempt!=null&&searchNavigationAttempt==attempt&&searchNavigationReleased
                &&searchNavigationOrdinal==1&&receiptSha!=null&&receiptSha.equals(searchNoEffectReceiptSha)
                &&searchNavigationEffect==null&&current==null&&inFlight==null&&pending==null,
                "durable old search outcome and unchanged reservation required");
    }

    void recordSearchNavigationEffect(NativeSearchSession session,NativeSearchSession.Attempt attempt,String receiptSha,
            Map<String,Object> execution,long at)throws Exception{
        requireSearchPlanningCurrent(session);need(searchNavigationAttempt==attempt&&attempt!=null&&attempt.session==session
                &&searchNavigationEffect==null&&current==null&&NativeAppEvidence.sha(receiptSha)&&execution!=null
                &&at>=attempt.startedElapsed&&at<attempt.deadlineElapsed,"same first typed navigation effect required");
        Map<String,Object> e=base();e.put("schema","hepta.native-search-navigation-effect.v1");e.put("attempt",attempt.evidence());
        e.put("action_receipt_sha256",receiptSha);e.put("action_execution",execution);e.put("recorded_elapsed_ms",at);
        e.put("navigation_only",true);e.put("fresh_search_input_still_required",true);e.put("query_or_price_verified",false);
        Map<String,Object> sealed=NativeAppEvidence.immutableMap(e);journal.write("native-search-navigation-effect.json",sealed);
        searchNavigationEffect=sealed;searchNavigationEffectElapsed=at;
    }
    private void observeSearchNavigation(NativeAppEvidence.Frame frame)throws Exception{
        if(searchPlanning==null||searchNavigationObserved)return;
        need(searchNavigationAttempt!=null&&searchNavigationEffect!=null&&current==null&&inFlight==null&&pending==null
                &&frame.capturedElapsedMs>=searchNavigationEffectElapsed,"fresh observed input must follow the actual typed navigation effect");
        need(product!=null&&product.quote==null&&product.missing.isEmpty()
                &&java.util.Arrays.asList("search_input","search_submit","search_suggestion").contains(product.phase),
                "typed navigation did not produce a fresh actual native search-input contract");
        Map<String,Object> e=base();e.put("schema","hepta.native-search-navigation-observed.v1");e.put("effect",searchNavigationEffect);
        e.put("fresh_frame",frame.evidence());e.put("provider",product.evidence());e.put("navigation_only",true);
        e.put("fresh_search_contract_phase",product.phase);e.put("query_or_result_proof_created",false);e.put("business_transition_verified",false);
        Map<String,Object> sealed=NativeAppEvidence.immutableMap(e);journal.write("native-search-navigation-observed.json",sealed);
        transitions.add(sealed);searchNavigationObserved=true;
    }
    void requireSearchNavigationObserved(NativeSearchSession session,NativeAppEvidence.Frame frame){
        requireSearchPlanningCurrent(session);need(searchNavigationObserved&&searchNavigationEffect!=null&&current!=null
                &&frame!=null&&current.frame.sameSource(frame),"actual same Session search-input handoff not verified");
    }
    private static void requireInstalled(NativeAppGoal goal,NativeAppEvidence.Installed value){
        need(value!=null&&goal.packageName.equals(value.packageName)&&value.apkHashes.size()==1,"complete admitted native APK identity required");
        if(NativeCtripFlightPage.supported(goal))need(value.versionCode==NativeCtripFlightPage.VERSION_CODE
                &&NativeCtripFlightPage.BASE_APK_SHA256.equals(value.apkHashes.get("base")),"Ctrip provider APK/version differs");
        else if(NativeAppGoal.PRODUCT_PRICE.equals(goal.kind)&&NativeAppGoal.XIAOMI_PACKAGE.equals(goal.packageName))
            need(value.versionCode==20261010L&&"95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373".equals(value.apkHashes.get("base")),"Xiaomi provider APK/version differs");
        else throw new IllegalArgumentException("native App provider not implemented for this immutable goal");
    }
    private void live(){need(!retired&&!invalid,"native task retired or invalid: "+invalidReason);authorization.ready();
        authorization.authorization.requireCompletionSelection(selection);need(selection.executionTarget()==target&&target.nativeGoal==goal,"native Selection object changed");
        need(target.profileTarget==null?installed.profileTarget==null:target.profileTarget.same(installed.profileTarget),
                "native profile Selection changed");}
    void verifyInstalled()throws Exception{installedVerifier.verify();}
    NativeAppDomain domain(){live();need(current!=null,"current native observation missing");return current;}
    NativeAppDomain domainFor(NotesCompletionEvidence.Frame frame){NativeAppDomain d=domain();
        need(frame!=null&&d.frame.observationId.equals(frame.observationId)&&d.frame.completionFrameSha.equals(TaskCompletionGate.webFrameSha(frame)),"native action domain is not the current actual frame");return d;}
    private void requireFrame(NativeAppEvidence.Frame f){need(f!=null&&taskId.equals(f.taskId)&&goal.ownerSha256.equals(f.ownerSha)
                &&target.targetSha256.equals(f.targetSha)&&authorization.authorization.sha256.equals(f.authorizationSha)
                &&selectionSha.equals(f.selectionSha)&&goal.packageName.equals(f.packageName)&&generation.equals(f.generation)
                &&displayId==f.displayId,"native observation task/owner/target/authorization/lease differs");
        if(f.capture!=null){
            Map<String,Object> bound=NativeAppEvidence.map();bound.put("native_goal_sha256",goal.contractSha256);
            f.capture.requireBinding(bound);
            if(f.capture.formHistory())need(NativeCtripFlightPage.supported(goal)&&installed.profileTarget!=null,
                    "historical form requires the supported installed Ctrip profile");
        }
        NativeAppEvidence.requireProfileTarget(installed.profileTarget,f.profileWindow);
        if(f.profileWindow!=null)f.profileWindow.requireMatches(installed.profileTarget,generation,displayId,f.windowId,
                f.profileWindow.taskId,f.capturedElapsedMs);
    }

    /** Called only after the corresponding full PhoneObservation bytes have
     * been written create-only. A later frame never replaces an earlier one. */
    void observed(NativeAppEvidence.Frame frame)throws Exception{
        live();requireFrame(frame);verifyInstalled();
        if(reservationReobserveId!=null)need(!reservationReobserveId.equals(frame.observationId)&&frame.capturedElapsedMs>=reservationReobserveAfter,
                "drained stale outcome requires a newly captured observation");
        String old=observations.get(frame.observationId);
        if(old!=null){need(old.equals(frame.sourceRecordSha)&&current!=null&&current.frame.sameSource(frame),"observation ID reused or old frame replayed");return;}
        need(inFlight==null,"native observation cannot advance before its action outcome");
        need(++observationOrdinal<=MAX_OBSERVATIONS,"native observation budget exhausted");
        if(current!=null)need(frame.capturedElapsedMs>=current.frame.capturedElapsedMs,"native observation clock moved backwards");
        observations.put(frame.observationId,frame.sourceRecordSha);acceptedClaim=null;
        flight=NativeCtripFlightPage.supported(goal)?NativeCtripFlightPage.inspect(goal,frame):null;
        if(frame.capture!=null&&frame.capture.formHistory())need(flight!=null&&NativeCtripFlightPage.FORM.equals(flight.phase),
                "historical form cannot become results, calendar, login or business evidence");
        product=NativeAppGoal.XIAOMI_PACKAGE.equals(goal.packageName)?NativeXiaomiProductPage.inspect(goal,frame):null;
        observeSearchNavigation(frame);
        if(product!=null&&NativeXiaomiProductPage.HOME_LOADING.equals(product.phase)&&productHomeLoadingSince<0)
            productHomeLoadingSince=frame.capturedElapsedMs;
        if(pending!=null)advancePending(frame);
        current=buildDomain(frame);
        Map<String,Object> e=base();e.put("frame",frame.evidence());e.put("provider",flight!=null?flight.evidence():product.evidence());
        e.put("domain",current.evidence());e.put("progress",progress());
        journal.write(String.format(java.util.Locale.ROOT,"native-app-page-%04d.json",observationOrdinal),e);
        reservationReobserveId=null;reservationReobserveAfter=0;
    }
    private NativeAppDomain buildDomain(NativeAppEvidence.Frame frame){
        Set<String> clicks=new TreeSet<String>();Map<String,String> edits=new TreeMap<String,String>(),purposes=new TreeMap<String,String>();
        Map<String,Object> view=NativeAppEvidence.map(),result=null;List<String> missing=new ArrayList<String>();boolean back=false;
        String phase=flight!=null?flight.phase:product.phase;
        if(!frame.metadataObserved||frame.windowType!=1||!frame.collectionComplete||frame.nodesTruncated){missing.add("complete_actual_native_application_frame_required");}
        else if(flight!=null&&flightLoginReturnedToForm){
            // This is a proved navigation destination, never a flight-result proof.
            // The one login exit has been spent; do not query or enter login again.
            view.put("login_returned_to_form_without_target_result",true);
            view.put("actual_return_destination",NativeCtripFlightPage.FORM);
            view.put("query_or_result_proof_created",false);
            view.put("credentials_or_agreement_actions_available",false);
            view.put("next_goal","本任务实际查询后出现登录页面；唯一一次返回已观察到机票表单，尚未取得目标日期的完整航班结果。只能结束 failure 或 partial 并说明本次未完成；不能再次查询、登录、返回、等待或声称查票成功。");
            missing.add("native_ctrip_login_returned_to_form_without_target_result");
        }
        else if(NativeCtripFlightPage.FIRST_LAUNCH_PRIVACY.equals(phase)){
            boolean queryAttempted=!queryAttempts.isEmpty()||lastQueryProof!=null;
            view.put("observed_first_launch_privacy",true);view.put("initialization_required",true);
            view.put("flight_query_attempted",queryAttempted);view.put("credentials_or_agreement_actions_available",false);
            view.put("next_goal",queryAttempted
                    ?"当前显示携程首次启动指引，尚未取得可核验的机票结果。结束 partial 或 failure，如实报告初始化阻碍。"
                    :"携程首次启动指引尚未完成，未执行机票查询。结束 partial 或 failure，如实报告初始化阻碍。");
            missing.add(flight.missing);
        }
        else if(NativeCtripFlightPage.LOGIN_REQUIRED.equals(phase)){
            NativeAppEvidence.Node loginReturn=NativeCtripFlightPage.loginReturnControl(flight);
            boolean mayReturn=pending==null&&!flightLoginExitAttempted&&loginReturn!=null
                    &&calendarYearProof!=null&&lastQueryProof!=null&&lastQueryDate!=null&&queryAttempts.contains(lastQueryDate);
            view.put("observed_login_page",true);view.put("requires_user_handling",!mayReturn);
            view.put("login_exit_attempted",flightLoginExitAttempted);
            view.put("credentials_or_agreement_actions_available",false);
            view.put("public_browsing_requires_login_verified",false);
            if(mayReturn){
                grant(clicks,purposes,loginReturn,NativeCtripFlightPage.LOGIN_EXIT);
                view.put("login_return_control",loginReturn.fact("description"));
                view.put("last_explicit_query_date",lastQueryDate.toString());
                view.put("next_goal","本任务已在携程实际执行查询并观察到对应日期结果页，当前为登录页面。可由本次模型选择当前明确的返回控件一次，再观察实际结果，或如实结束 failure。不能登录、输入账号、接受协议、注册或选择其他登录方式；返回本身不代表查询完成。");
                missing.add("native_ctrip_login_bounded_return_available");
            }else{
                view.put("next_goal","当前携程登录页面没有可用的一次返回权限；尚未取得可核验的机票结果。结束 partial 或 failure，如实报告当前阻碍，不能声称公开浏览必定要求登录。");
                missing.add(flight.missing);
            }
        }
        else if(NativeXiaomiProductPage.HOME_LOADING.equals(phase)){
            view.putAll(product.modelView());
            long elapsed=frame.capturedElapsedMs-productHomeLoadingSince;
            boolean waiting=productHomeLoadingSince>=0&&elapsed>=0&&elapsed<PRODUCT_HOME_LOADING_MS
                    &&productHomeLoadingWaits<MAX_PRODUCT_HOME_LOADING_WAITS;
            if(!waiting)phase=NativeXiaomiProductPage.HOME_LOADING_EXHAUSTED;
            view.put("loading_wait_only",waiting);view.put("loading_wait_attempts",productHomeLoadingWaits);
            view.put("loading_max_wait_attempts",MAX_PRODUCT_HOME_LOADING_WAITS);
            view.put("loading_observation_budget_ms",PRODUCT_HOME_LOADING_MS);
            view.put("loading_remaining_observed_ms",Math.max(0L,PRODUCT_HOME_LOADING_MS-elapsed));
            view.put("next_goal",waiting?"首页仅有导航栏，内容尚未就绪；由模型调用 wait，再读取新的实际页面。"
                    :"首页内容等待预算已耗尽；根据当前未就绪证据结束 failure，不能声称查询成功。");
            missing.add(waiting?"native_home_content_loading":"native_home_loading_budget_exhausted");
        }
        else if(NativeXiaomiProductPage.LOGIN.equals(phase)){
            view.put("observed_login_page",true);view.put("login_exit_reserved",productLoginExitReserved);
            view.put("credentials_or_agreement_actions_available",false);
            view.put("public_browsing_requires_login_verified",false);
            if(productLoginExitReserved){
                phase=NativeXiaomiProductPage.LOGIN_BLOCKED;
                view.put("next_goal","返回请求的一次操作预算已占用，当前仍为或再次进入小米账号登录页面；结束 failure，说明查询尚未完成、需要用户处理当前登录页面，不能声称公开浏览必定要求登录。");
                missing.add("native_login_after_reserved_exit_requires_user");
            }else if(pending==null){
                for(String id:product.clickIds)grant(clicks,purposes,frame.byId.get(id),NativeXiaomiProductPage.LOGIN_EXIT);
                view.put("next_goal","当前完整页面为小米账号登录；可由本次模型选择当前明确的返回控件一次，再读取实际页面，或结束 failure。不能输入账号、接受协议或使用其他登录方式。");
                missing.add("native_login_page_observed");
            }else{
                phase=NativeXiaomiProductPage.LOGIN_BLOCKED;
                view.put("next_goal","当前登录页面的前序操作尚未确认；结束 failure，说明查询未完成，需要用户处理当前页面。");
                missing.add("native_login_with_unresolved_transition");
            }
        }
        else if(pending!=null){missing.add("waiting_for_actual_post_action_page");view.put("pending_purpose",pending.purpose);}
        else if(flight!=null){
            view.put("from",goal.fromCity);view.put("to",goal.toCity);view.put("requested_departure_date",goal.departureDate.toString());
            view.put("adults",goal.adults);view.put("calendar_year_proved",calendarYearProof!=null);
            view.put("last_explicit_query_date",lastQueryDate==null?null:lastQueryDate.toString());
            if(NativeCtripFlightPage.HOME.equals(phase))grant(clicks,purposes,flight.homeFlight,"open_flight_form");
            else if(NativeCtripFlightPage.FORM.equals(phase)){
                view.put("observed_form_date",flight.form.date.text);view.put("observed_passengers","1成人/0儿童/0婴儿");
                if(calendarYearProof==null){grant(clicks,purposes,flight.form.date,"inspect_departure_year");missing.add("actual_calendar_year_round_trip_missing");}
                else if(confirmedFormDate!=null&&flight.form.matches(confirmedFormDate)&&queryAttempts.size()<2&&!queryAttempts.contains(confirmedFormDate)){
                    grant(clicks,purposes,flight.form.query,"query_observed_form");view.put("query_date",confirmedFormDate.toString());
                    view.put("exploratory_non_target_query",!goal.departureDate.equals(confirmedFormDate));
                }else missing.add("new_proved_form_date_or_query_budget_missing");
            }else if(NativeCtripFlightPage.CALENDAR.equals(phase)){
                view.put("calendar_month_headers",flight.calendarMonths);back=true;purposes.put("back","return_from_calendar");
                view.put("next_goal",calendarInspection!=null&&calendarProposedDate!=null
                        ?"已观察本次日期控件打开的日历年月标题；当前未暴露可选择的日期节点。由模型选择现有 back 返回表单以核对日期，不能等待出一个可猜测的日期坐标；尚未选择或证明目标出发日期。"
                        :"当前日历未暴露可选择的日期节点。由模型选择现有 back 返回表单并重新观察；不能猜测日期坐标，也不能把日历标题当作已选择目标日期。");
                missing.add("native_day_cells_unavailable_no_coordinate_permission");
            }else if(NativeCtripFlightPage.OVERLAY.equals(phase)){
                back=true;purposes.put("back","dismiss_research_sheet");missing.add("overlay_blocks_all_underlying_results");
            }else if(NativeCtripFlightPage.RESULTS.equals(phase)){
                LocalDate shown=lastQueryDate==null?null:flight.displayedMonthDay(lastQueryDate);view.put("observed_departure_date",shown==null?null:shown.toString());
                if(lastQueryProof!=null&&goal.departureDate.equals(lastQueryDate)&&goal.departureDate.equals(shown)){
                    if(!flight.quotes.isEmpty()){
                        result=flightResult(frame);List<Map<String,Object>> quotes=new ArrayList<Map<String,Object>>();for(NativeCtripFlightPage.Quote q:flight.quotes){if(quotes.size()==3)break;quotes.add(q.modelView());}
                        view.put("current_displayed_economy_cards",quotes);view.put("additional_visible_admitted_cards",Math.max(0,flight.quotes.size()-quotes.size()));
                    }else{
                        missing.add("native_target_query_waiting_for_complete_cards");
                        view.put("next_goal","本任务已在目标日期表单执行查询，当前结果日期相同，但尚无完整可核验的航班卡片；可 wait 后读取新页面，或如实结束未完成。");
                    }
                }else if(lastQueryProof==null||shown==null){back=true;purposes.put("back","verify_form_after_result_date");missing.add("same_task_explicit_query_missing");}
                else if(goal.departureDate.equals(shown)){back=true;purposes.put("back","verify_form_after_result_date");missing.add("target_date_form_and_explicit_query_required");}
                else{
                    Map<String,LocalDate> dates=flight.resolvedDates(lastQueryDate);String chosen=null;long best=Long.MAX_VALUE;
                    long distance=java.time.temporal.ChronoUnit.DAYS.between(shown,goal.departureDate);
                    for(Map.Entry<String,LocalDate> e:dates.entrySet()){
                        long progress=java.time.temporal.ChronoUnit.DAYS.between(shown,e.getValue());long remaining=Math.abs(java.time.temporal.ChronoUnit.DAYS.between(e.getValue(),goal.departureDate));
                        if(progress!=0&&Long.signum(progress)==Long.signum(distance)&&remaining<Math.abs(distance)&&remaining<best&&!dateAttempts.contains(e.getValue())){chosen=e.getKey();best=remaining;}
                    }
                    if(chosen!=null){grant(clicks,purposes,frame.byId.get(chosen),"navigate_departure_date:"+dates.get(chosen));view.put("actual_date_target",dates.get(chosen).toString());}
                    else missing.add("no_current_native_date_target_toward_owner_date");
                }
                if(result==null&&flight.missing!=null)missing.add(flight.missing);
            }else missing.add(flight.missing==null?"native_flight_page_unrecognized":flight.missing);
        }else if(NativeXiaomiProductPage.OPTIONAL_LOCATION.equals(phase)){
            view.putAll(product.modelView());view.put("product_modal_exit_attempted",productModalExitAttempted);
            view.put("modal_exit_requires_fresh_home",true);view.put("location_enable_action_available",false);
            boolean mayDecline=optionalLocationInstallation()&&!productModalExitAttempted&&!productQueryAttempted
                    &&productQueryProof==null&&productOpenProof==null;
            view.put("decline_action_available",mayDecline);
            if(mayDecline){
                for(String id:product.clickIds)grant(clicks,purposes,frame.byId.get(id),NativeXiaomiProductPage.DECLINE_LOCATION);
                view.put("next_goal","当前完整页面是小米商城的可选定位提示。当前动作域仅允许你选择明确的「暂不开启」控件一次，再读取实际页面；不能选择「开启定位」、授予系统权限或猜坐标。只有新的实际 home_search 页面才能继续查询；本次拒绝提示本身不是查询或价格结果。");
            }else{
                view.put("click_node_ids",Collections.emptyList());view.put("purposes",Collections.emptyMap());
                missing.add("one_pinned_profile_prequery_location_decline_unavailable");
            }
            missing.addAll(product.missing);
        }else if(NativeXiaomiProductPage.IMAGE_MODAL.equals(phase)){
            // This permits one navigation attempt, not an interpretation of the images.
            // The same installed App, task, Selection, lease and current frame remain mandatory.
            view.putAll(product.modelView());view.put("product_modal_exit_attempted",productModalExitAttempted);
            view.put("modal_exit_requires_fresh_home",true);
            if(!productModalExitAttempted&&!productQueryAttempted&&productQueryProof==null&&productOpenProof==null){
                back=true;purposes.put("back","dismiss_image_modal_once");
                view.put("next_goal","当前图片内容未分类，但当前动作域已允许一次 back 导航。由你选择现有 back 一次尝试返回，然后读取新页面；不必先识别图片内容或继续等待，不能猜无标签图片的用途或点击坐标。只有新的实际 home_search 页面才能继续查询；back 派发本身不是查询或价格结果。");
            }else missing.add("one_prequery_modal_exit_attempt_unavailable");
            missing.addAll(product.missing);
        }else{
            view.putAll(product.modelView());
            for(String id:product.clickIds){String purpose=product.purposes.get(id);
                if("open_exact_product".equals(purpose)&&productQueryProof==null)continue;
                if(("submit_exact_suggestion".equals(purpose)||"submit_product_query".equals(purpose))&&productQueryAttempted)continue;
                grant(clicks,purposes,frame.byId.get(id),purpose);
            }
            for(Map.Entry<String,String> e:product.editValues.entrySet()){edits.put(e.getKey(),e.getValue());purposes.put(e.getKey(),product.purposes.get(e.getKey()));}
            if(product.quote!=null&&"detail_display".equals(product.quote.kind)){
                if(productOpenProof!=null&&productSemantic!=null&&productSemantic.equals(product.quote.semanticFingerprint))result=productResult(frame);
                else{back=true;purposes.put("back","return_to_owned_product_search");missing.add("actual_model_query_and_same_card_detail_navigation_required");}
            }
            if(product.quote!=null&&"search_card".equals(product.quote.kind)&&productQueryProof==null){back=true;purposes.put("back","return_to_owned_product_search");}
            missing.addAll(product.missing);
        }
        Map<String,Object> recovery=recoverableStaleView(frame,phase,clicks,purposes);
        if(recovery!=null)view.put("recoverable_pre_effect_stale",recovery);
        if(result==null&&missing.isEmpty())missing.add("native_query_action_chain_not_complete");
        return new NativeAppDomain(frame,phase,clicks,edits,purposes,back,view,result,missing);
    }
    /** Descriptive recovery context only; every new action still needs the current
     * Domain, a new model run, the full Service comparison and its one-effect guard. */
    private Map<String,Object> recoverableStaleView(NativeAppEvidence.Frame frame,String phase,
            Set<String> clicks,Map<String,String> purposes){
        Attempt a=recoverableStaleAttempt;
        if(a==null||a.receipt==null||pending!=null||!a.before.phase.equals(phase)
                ||a.before.frame.observationId.equals(frame.observationId)||frame.capturedElapsedMs<a.finished
                ||!frame.metadataObserved||frame.windowType!=1||!frame.collectionComplete||frame.nodesTruncated)return null;
        NativeAppEvidence.Frame old=a.before.frame;
        if(!old.metadataObserved||old.windowType!=1||old.windowId!=frame.windowId||old.rotation!=frame.rotation
                ||old.width!=frame.width||old.height!=frame.height||old.left!=frame.left||old.top!=frame.top
                ||old.right!=frame.right||old.bottom!=frame.bottom)return null;
        NativeAppEvidence.Node original=old.byId.get(a.action.nodeId),fresh=null;
        if(original==null||!original.direct()||original.signature==null)return null;
        for(String id:clicks)if(a.purpose.equals(purposes.get(id))){
            NativeAppEvidence.Node n=frame.byId.get(id);
            if(fresh!=null||n==null||!n.direct()||!n.enabled||n.password||!n.clickable||n.editable
                    ||!original.path.equals(n.path)||!original.signature.equals(n.signature)
                    ||!original.packageName.equals(n.packageName)||!original.className.equals(n.className)
                    ||!original.viewId.equals(n.viewId)||!original.label.equals(n.label)
                    ||original.left!=n.left||original.top!=n.top||original.right!=n.right||original.bottom!=n.bottom)return null;
            fresh=n;
        }
        if(fresh==null)return null;
        Map<String,Object> value=NativeAppEvidence.map();value.put("schema","hepta.native-stale-recovery-context.v1");
        value.put("previous_step",a.step);value.put("previous_model_run_id",a.run);
        value.put("previous_observation_id",old.observationId);value.put("purpose",a.purpose);
        value.put("previous_action_effect_entered",false);value.put("worker_drained",true);
        value.put("durable_action_record_sha256",a.receipt.get("step_action_record_sha256"));
        value.put("current_observation_id",frame.observationId);value.put("current_node_id",fresh.id);
        value.put("current_frame_record_sha256",frame.sourceRecordSha);value.put("same_target_ref_sha256",fresh.signature);
        value.put("new_model_decision_required",true);value.put("previous_node_id_reusable",false);
        value.put("automatic_redispatch",false);value.put("business_verified",false);value.put("grants_tool_authority",false);
        return value;
    }
    /** Opaque eligibility for one controller-owned fresh observation attempt.
     * It is never an action token, read completion, or proof of a live Service lease. */
    static final class ReadRecoveryPermit {
        private final NativeAppSession session;private final Attempt attempt;
        private ReadRecoveryPermit(NativeAppSession session,Attempt attempt){this.session=session;this.attempt=attempt;}
        void requireCurrent(){session.requireReadRecovery(attempt);}
        Map<String,Object> evidence(){
            requireCurrent();Map<String,Object> value=session.base();
            value.put("schema","hepta.native-stale-read-recovery-permit.v1");
            value.put("original_model_run_id",attempt.run);value.put("original_observation_id",attempt.before.frame.observationId);
            value.put("original_action_sha256",attempt.guard.actionSha);value.put("purpose",attempt.purpose);
            value.put("original_frame_record_sha256",attempt.before.frame.sourceRecordSha);
            value.put("action_record_sha256",attempt.receipt.get("step_action_record_sha256"));
            value.put("window_id",attempt.before.frame.windowId);value.put("display_id",session.displayId);
            value.put("background_generation",session.generation);value.put("drained_outcome_elapsed_ms",attempt.finished);
            value.put("fresh_observation_and_new_model_decision_required",true);value.put("grants_action_authority",false);
            value.put("grants_service_read_authority",false);value.put("business_verified",false);return NativeAppEvidence.immutableMap(value);
        }
    }
    ReadRecoveryPermit observationRecoveryPermit(ActionDecision action,String runId,String observationId){
        Attempt a=recoverableStaleAttempt;if(a==null)return null;
        need(a.action==action&&a.run.equals(runId)&&a.before.frame.observationId.equals(observationId),
                "read recovery belongs to the original model action and observation");
        requireReadRecovery(a);return new ReadRecoveryPermit(this,a);
    }
    private void requireReadRecovery(Attempt a){
        live();need(a!=null&&a==recoverableStaleAttempt&&a.before==current&&inFlight==null&&pending==null
                &&a.journaled&&a.receipt!=null&&a.finished>=a.started
                &&Boolean.TRUE.equals(a.receipt.get("pre_effect_stale_recovery_available"))
                &&a.guard!=null&&a.guard.state.get()==2
                &&a.before.frame.observationId.equals(reservationReobserveId)&&reservationReobserveAfter==a.finished,
                "read recovery lost its durable unentered Attempt or current reobservation barrier");
        requireFrame(a.before.frame);
    }
    /** Read eligibility after one real, drained navigation effect. It cannot
     * replay that effect or extend the original pending-transition clock. */
    static final class PostEffectReadPermit {
        private final NativeAppSession session;private final Attempt attempt;
        private final java.util.concurrent.atomic.AtomicInteger admissions=new java.util.concurrent.atomic.AtomicInteger();
        private PostEffectReadPermit(NativeAppSession session,Attempt attempt){this.session=session;this.attempt=attempt;}
        void requireCurrent(){session.requirePostEffectRead(attempt);}
        long transitionDeadline(){requireCurrent();return attempt.finished+OBSERVED_TRANSITION_MS;}
        void requireOwner(NativeAppSession owner,Object authorization,String task,Object selection,String generation,int displayId){
            requireCurrent();need(owner==session&&authorization==session.authorization&&session.taskId.equals(task)
                    &&selection==session.selection&&session.generation.equals(generation)&&displayId==session.displayId,
                    "post-effect read belongs to another private Session or background");
        }
        void admit(boolean retry){
            requireCurrent();need(admissions.compareAndSet(retry?1:0,retry?2:1),"post-effect read admission already consumed");
        }
        boolean admitted(boolean retry){return admissions.get()==(retry?2:1);}
        Map<String,Object> evidence(){
            requireCurrent();Map<String,Object> value=session.base();value.put("schema","hepta.native-post-effect-read-permit.v1");
            value.put("original_model_run_id",attempt.run);value.put("original_observation_id",attempt.before.frame.observationId);
            value.put("original_action_sha256",attempt.guard.actionSha);value.put("purpose",attempt.purpose);
            value.put("action_record_sha256",attempt.receipt.get("step_action_record_sha256"));
            value.put("entered_execution_projection_sha256",attempt.enteredExecutionSha);
            value.put("operation_id",attempt.enteredOperation);value.put("drained_outcome_elapsed_ms",attempt.finished);
            value.put("original_transition_deadline_elapsed_ms",transitionDeadline());
            value.put("effect_entered",true);value.put("worker_drained",true);value.put("action_replayed",false);
            value.put("grants_action_authority",false);value.put("business_verified",false);return NativeAppEvidence.immutableMap(value);
        }
    }
    PostEffectReadPermit postEffectReadPermit(ActionDecision action,String run,String observation){
        Attempt a=pending;if(a==null||!a.postEffectReadEligible)return null;
        need(a.action==action&&a.run.equals(run)&&a.before.frame.observationId.equals(observation),
                "post-effect read must follow the same accepted action");
        requirePostEffectRead(a);need(!a.postEffectPermitIssued,"post-effect read context already issued");
        a.postEffectPermitIssued=true;return new PostEffectReadPermit(this,a);
    }
    private void requirePostEffectRead(Attempt a){
        live();need(a!=null&&a==pending&&a.before==current&&inFlight==null&&a.journaled&&a.outcomeJournaled
                &&a.postEffectReadEligible&&a.guard!=null&&a.guard.state.get()==2
                &&NativeCtripFlightPage.supported(goal)&&NativeActionSnapshotCheck.OPEN.equals(a.purpose)
                &&a.receipt!=null&&Boolean.TRUE.equals(a.receipt.get("accepted"))
                &&Boolean.TRUE.equals(a.receipt.get("dispatched"))&&Boolean.FALSE.equals(a.receipt.get("stale"))
                &&Boolean.TRUE.equals(a.receipt.get("post_effect_read_recovery_available"))
                &&NativeAppEvidence.sha(a.enteredExecutionSha)&&NativeAppEvidence.id(a.enteredOperation)
                &&a.finished>=a.started&&a.finished<=Long.MAX_VALUE-OBSERVED_TRANSITION_MS,
                "post-effect read lost its durable private pending navigation");
        requireFrame(a.before.frame);
    }
    /** Read-only identity of one durable accepted transition. It has no action
     * admission, retry entitlement or method that can renew the original clock. */
    static final class PendingObservation {
        private final NativeAppSession session;private final Attempt attempt;private final long deadline;
        private PendingObservation(NativeAppSession session,Attempt attempt){
            this.session=session;this.attempt=attempt;deadline=session.pendingObservationDeadline(attempt);
        }
        boolean required(){
            session.live();need(session.pending==null||session.pending==attempt,"pending transition identity changed");
            if(session.pending==null)return false;session.pendingObservationDeadline(attempt);return true;
        }
        void requireOwner(NativeAppSession owner,Object authorization,String task,Object selection,String generation,int displayId){
            session.live();need(owner==session&&authorization==session.authorization&&session.taskId.equals(task)
                    &&selection==session.selection&&session.generation.equals(generation)&&displayId==session.displayId,
                    "pending observation belongs to another Session or background");
            need(session.inFlight==null&&(session.pending==null||session.pending==attempt),"pending observation crossed an action");
        }
        long deadline(){return deadline;}
        String originalRun(){return attempt.run;}
        Map<String,Object> evidence(){
            session.live();Map<String,Object> value=session.base();value.put("schema","hepta.native-pending-observation.v1");
            value.put("original_model_run_id",attempt.run);value.put("original_observation_id",attempt.before.frame.observationId);
            value.put("purpose",attempt.purpose);value.put("action_record_sha256",attempt.receipt.get("step_action_record_sha256"));
            value.put("dispatch_finished_elapsed_ms",attempt.finished);value.put("original_transition_deadline_elapsed_ms",deadline);
            value.put("action_replayed",false);value.put("grants_action_authority",false);value.put("business_verified",false);
            return NativeAppEvidence.immutableMap(value);
        }
    }
    private long pendingObservationDeadline(Attempt attempt){
        live();need(attempt!=null&&pending==attempt&&current!=null&&inFlight==null&&attempt.journaled&&attempt.outcomeJournaled
                &&attempt.receipt!=null&&Boolean.TRUE.equals(attempt.receipt.get("accepted"))
                &&Boolean.TRUE.equals(attempt.receipt.get("dispatched"))&&Boolean.FALSE.equals(attempt.receipt.get("stale"))
                &&(attempt.guard==null||attempt.guard.state.get()==2)&&attempt.finished>=attempt.started
                &&attempt.finished<=Long.MAX_VALUE-OBSERVED_TRANSITION_MS,"pending read requires its durable closed action outcome");
        requireFrame(current.frame);return attempt.finished+OBSERVED_TRANSITION_MS;
    }
    PendingObservation pendingObservation(){live();return pending==null?null:new PendingObservation(this,pending);}
    long boundedObservationDeadline(long taskDeadline,long now){
        // No pending transition adds no new condition to the original one-read
        // failure diagnostic; its Service/task authorization remains mandatory.
        if(pending==null)return taskDeadline;
        live();
        long end=pendingObservationDeadline(pending);need(now>=pending.finished,"pending observation clock precedes outcome");
        if(now>=end){invalidate("actual_native_transition_observation_deadline");live();}
        return Math.min(taskDeadline,end);
    }
    void requireModelPlanning(){live();need(calendarDateOffer==null||calendarSelection!=null,"calendar one-use model/input/selection chain has not completed");need(searchNavigationAttempt==null||searchNavigationObserved,"native search navigation requires a fresh actual input observation before another model decision");need(pending==null&&inFlight==null,"pending native transition requires observation before another model request");}

    private static void grant(Set<String> ids,Map<String,String> purposes,NativeAppEvidence.Node node,String purpose){need(node!=null&&purpose!=null,"actual query target and purpose required");ids.add(node.id);purposes.put(node.id,purpose);}

    /** The new prompt branch is qualified only for the actual managed-profile
     * build. Existing user0 paths and image-modal Back permissions are unchanged.
     * Live selection/profile/window and installed-verifier checks remain required. */
    private boolean optionalLocationInstallation(){
        return installed.profileTarget!=null&&NativeAppGoal.XIAOMI_PACKAGE.equals(installed.packageName)
                &&installed.versionCode==20261010L&&installed.apkHashes.size()==1
                &&"95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373".equals(installed.apkHashes.get("base"))
                &&"com.xiaomi.shop/com.xiaomi.shop2.activity.MainActivity".equals(installed.profileTarget.component)
                &&installed.profileTarget.signerSha256.equals(Collections.singleton(
                        "c9009d01ebf9f5d0302bc71b2fe9aa9a47a432bba17308a3111b75d7b2149025"));
    }

    /** A private Session Attempt supplies authority; the pure comparator does not.
     * All non-atomic fields are frozen on the controller after its original
     * attempt journal completed. The worker never advances/reads Session state. */
    static final class ActionGuard {
        final ActionDecision action;final String run,purpose;
        final NativeAppEvidence.Frame frame;final NativeAppEvidence.Node targetNode;
        final BackgroundTaskTarget.SelectionBinding selection;final BackgroundTaskTarget target;
        final TaskAuthorization.Gate authorization;final NativeAppGoal goal;
        final NativeAppEvidence.Installed installed;
        final long issued,deadline,attemptStarted;
        final Map<String,Object> identity,queryHistory;
        final String actionSha,historySha;
        private final InstalledVerifier verifier;
        // close and claim have one linearization point, not two independent flags.
        private final java.util.concurrent.atomic.AtomicInteger state=new java.util.concurrent.atomic.AtomicInteger(0);
        // A normal Controller await may close an unclaimed guard before the
        // durable outcome is written. This one-use digest preserves that exact
        // handoff; it never makes a closed guard usable by an effect worker.
        private static final class UnenteredAwaitReceipt {
            final Map<String,Object> execution;final String sha;
            final java.util.concurrent.atomic.AtomicBoolean cancelled;
            UnenteredAwaitReceipt(Map<String,Object> value,java.util.concurrent.atomic.AtomicBoolean token){
                execution=NativeAppEvidence.immutableMap(value);sha=NativeAppEvidence.fingerprint(execution);cancelled=token;
            }
        }
        private final java.util.concurrent.atomic.AtomicReference<UnenteredAwaitReceipt> unenteredAwaitReceipt=
                new java.util.concurrent.atomic.AtomicReference<UnenteredAwaitReceipt>();
        private static final class EnteredAwaitReceipt {
            final Map<String,Object> execution;final String sha;
            final java.util.concurrent.atomic.AtomicBoolean cancelled;
            EnteredAwaitReceipt(Map<String,Object> value,java.util.concurrent.atomic.AtomicBoolean token){
                execution=NativeAppEvidence.immutableMap(value);sha=NativeAppEvidence.fingerprint(execution);cancelled=token;
            }
        }
        private final java.util.concurrent.atomic.AtomicReference<EnteredAwaitReceipt> enteredAwaitReceipt=
                new java.util.concurrent.atomic.AtomicReference<EnteredAwaitReceipt>();
        private ActionGuard(NativeAppSession session,Attempt attempt,long issued,long deadline){
            action=attempt.action;run=attempt.run;purpose=attempt.purpose;frame=attempt.before.frame;
            targetNode=frame.byId.get(action.nodeId);selection=session.selection;target=session.target;
            authorization=session.authorization;goal=session.goal;installed=session.installed;verifier=session.installedVerifier;
            this.issued=issued;this.deadline=deadline;attemptStarted=attempt.started;
            need(targetNode!=null&&targetNode.direct()&&targetNode.label.equals(action.nodeLabel)
                    &&targetNode.selected!=null&&targetNode.checkable!=null&&targetNode.checked!=null,
                    "original retained target/path/selection tuple required");
            Map<String,Object> id=NativeAppEvidence.map();id.put("task_id",session.taskId);
            id.put("owner_sha256",goal.ownerSha256);id.put("target_sha256",target.targetSha256);
            id.put("authorization_sha256",authorization.authorization.sha256);id.put("selection_sha256",session.selectionSha);
            id.put("installed_set_sha256",installed.apkSetSha256);id.put("goal_sha256",goal.contractSha256);
            id.put("background_generation",session.generation);id.put("origin_observation_id",frame.observationId);
            NativeAppEvidence.requireProfileTarget(installed.profileTarget,frame.profileWindow);
            if(frame.profileWindow!=null)id.putAll(NativeAppEvidence.profileActionIdentity(frame.profileWindow));
            identity=NativeAppEvidence.immutableMap(id);
            Map<String,Object> a=NativeAppEvidence.map();a.put("action_schema",action.actionSchema);a.put("action",action.action);
            a.put("observation_id",action.observationId);a.put("package",action.packageName);a.put("node_id",action.nodeId);
            a.put("node_label",action.nodeLabel);a.put("text",action.text);a.put("model_run_id",run);
            a.put("ordinal",attempt.ordinal);a.put("step",attempt.step);a.put("before_source_sha256",frame.sourceRecordSha);
            actionSha=NativeAppEvidence.fingerprint(a);
            if(NativeActionSnapshotCheck.QUERY.equals(purpose)){
                need(attempt.date!=null&&attempt.date.equals(session.confirmedFormDate)&&session.calendarYearProof!=null
                        &&attempt.flight==session.flight&&attempt.flight.form!=null&&attempt.flight.form.matches(attempt.date)
                        &&session.queryAttempts.contains(attempt.date)&&session.queryAttempts.size()<=2,
                        "same already-consumed query Attempt/date/year history required");
                Map<String,Object> history=NativeAppEvidence.map();history.put("date",attempt.date.toString());
                history.put("calendar_year_round_trip",session.calendarYearProof);
                history.put("form_before",attempt.flight.form.evidence());history.put("before_source_sha256",frame.sourceRecordSha);
                history.put("model_run_id",run);history.put("ordinal",attempt.ordinal);history.put("step",attempt.step);
                history.put("original_query_budget_already_consumed",true);
                queryHistory=NativeAppEvidence.immutableMap(history);historySha=NativeAppEvidence.fingerprint(queryHistory);
            }else{queryHistory=null;historySha=null;}
        }
        void requireOpen(ActionDecision expected,String expectedRun,long now){
            need(state.get()==0&&action==expected&&run.equals(expectedRun)&&now>=issued&&now<deadline,
                    "native Attempt guard retired, replaced, claimed or expired");
        }
        void verifyInstalled()throws Exception{verifier.verify();}
        // Hash the actual composite signature, including scroll/IME/input freshness.
        NativeActionSnapshotCheck.Intent intent(String originalFullSignature){
            return new NativeActionSnapshotCheck.Intent(purpose,goal.packageName,targetNode.path,targetNode.label,
                    NativeAppEvidence.hash(originalFullSignature),run,action.nodeId,actionSha,historySha,identity,issued,deadline);
        }
        void claim(ActionDecision expected,String expectedRun,long now){
            need(action==expected&&run.equals(expectedRun)&&now>=issued&&now<deadline
                    &&state.compareAndSet(0,1),"native Attempt closed or already claimed; no second effect");
        }
        void requireClaimed(){need(state.get()==1,"native Attempt closed before effect entry");}
        synchronized void close(){state.getAndSet(2);unenteredAwaitReceipt.set(null);enteredAwaitReceipt.set(null);}
        synchronized void closeAfterUnenteredAwait(Map<String,Object> execution,java.util.concurrent.atomic.AtomicBoolean cancelled){
            boolean sealed=false;
            try{
                if(execution==null||cancelled==null||cancelled.get())return;
                UnenteredAwaitReceipt receipt=new UnenteredAwaitReceipt(execution,cancelled);
                if(!cancelled.get()&&state.compareAndSet(0,2)){unenteredAwaitReceipt.set(receipt);sealed=true;}
            }finally{
                state.getAndSet(2);
                enteredAwaitReceipt.set(null);
                if(!sealed||cancelled==null||cancelled.get())unenteredAwaitReceipt.set(null);
            }
        }
        synchronized void closeAfterEnteredAwait(Map<String,Object> execution,java.util.concurrent.atomic.AtomicBoolean cancelled){
            boolean sealed=false;
            try{
                if(execution==null||cancelled==null||cancelled.get()||!NativeActionSnapshotCheck.OPEN.equals(purpose)
                        ||!Boolean.TRUE.equals(execution.get("effect_entered"))||!Boolean.TRUE.equals(execution.get("effect_returned"))
                        ||!Boolean.TRUE.equals(execution.get("api_accepted"))||!Boolean.TRUE.equals(execution.get("worker_drained"))
                        ||!Boolean.TRUE.equals(execution.get("callback_published"))||!Boolean.TRUE.equals(execution.get("callback_authority_current")))return;
                EnteredAwaitReceipt receipt=new EnteredAwaitReceipt(execution,cancelled);
                if(!cancelled.get()&&state.compareAndSet(1,2)){enteredAwaitReceipt.set(receipt);sealed=true;}
            }finally{
                state.getAndSet(2);unenteredAwaitReceipt.set(null);
                if(!sealed||cancelled==null||cancelled.get())enteredAwaitReceipt.set(null);
            }
        }
        private boolean consumeEnteredOutcome(Map<String,Object> execution){
            if(state.get()!=2||execution==null)return false;
            EnteredAwaitReceipt sealed=enteredAwaitReceipt.get();
            if(sealed==null||sealed.cancelled.get()||!sealed.execution.equals(execution)
                    ||!sealed.sha.equals(NativeAppEvidence.fingerprint(execution)))return false;
            return enteredAwaitReceipt.compareAndSet(sealed,null)&&!sealed.cancelled.get();
        }
        private boolean consumeUnenteredOutcome(Map<String,Object> execution){
            if(state.get()==0)return true;
            if(state.get()!=2||execution==null)return false;
            UnenteredAwaitReceipt sealed=unenteredAwaitReceipt.get();
            if(sealed==null||sealed.cancelled.get()||!sealed.execution.equals(execution)
                    ||!sealed.sha.equals(NativeAppEvidence.fingerprint(execution)))return false;
            return unenteredAwaitReceipt.compareAndSet(sealed,null)&&!sealed.cancelled.get();
        }
        Map<String,Object> evidence(){Map<String,Object> e=NativeAppEvidence.map();e.put("purpose",purpose);
            e.put("model_run_id",run);e.put("action_sha256",actionSha);e.put("query_history_sha256",historySha);
            e.put("attempt_started_elapsed_ms",attemptStarted);e.put("issued_elapsed_ms",issued);e.put("deadline_elapsed_ms",deadline);
            e.put("state",Integer.valueOf(state.get()));e.put("single_atomic_claim",true);return e;}
    }
    ActionGuard actionGuard(ActionDecision action,String run,String observation,long issued,long deadline)throws ActionDecision.InvalidActionException{
        live();Attempt a=inFlight;
        need(a!=null&&a.journaled&&a.action==action&&a.run.equals(run)&&a.before==current
                &&a.before.frame.observationId.equals(observation)&&a.started<=issued,
                "guard requires the same journaled in-flight original Attempt");
        if(a.before.frame.capture!=null&&a.before.frame.capture.formHistory()&&!java.util.Arrays.asList("wait","done").contains(action.action))need("click".equals(action.action)
                &&(NativeActionSnapshotCheck.YEAR.equals(a.purpose)||NativeActionSnapshotCheck.QUERY.equals(a.purpose)),
                "history effect requires the original date/query native Guard");
        if(!"click".equals(action.action)||!java.util.Arrays.asList(NativeActionSnapshotCheck.OPEN,
                NativeActionSnapshotCheck.YEAR,NativeActionSnapshotCheck.QUERY,NativeActionSnapshotCheck.SEARCH,NativeActionSnapshotCheck.SEARCH_ICON).contains(a.purpose))return null;
        need(action.toolChildOrigin==null&&a.guard==null&&deadline>issued&&deadline-issued<=8000,
                "one original native action worker budget required");
        current.requireCurrent(action);requireFrame(a.before.frame);
        a.guard=new ActionGuard(this,a,issued,deadline);return a.guard;
    }

    private static final class Attempt {
        final int ordinal,step;final String run,purpose;final ActionDecision action;final NativeAppDomain before;
        final NativeCtripFlightPage.Page flight;final NativeXiaomiProductPage.Page product;final long started;
        final LocalDate date;long finished;Map<String,Object> receipt;boolean journaled;ActionGuard guard;
        boolean outcomeJournaled,postEffectReadEligible,postEffectPermitIssued;String enteredExecutionSha,enteredOperation;
        Attempt(int ordinal,int step,String run,ActionDecision action,NativeAppDomain before,String purpose,
                NativeCtripFlightPage.Page flight,NativeXiaomiProductPage.Page product,long started,LocalDate date){
            this.ordinal=ordinal;this.step=step;this.run=run;this.action=action;this.before=before;this.purpose=purpose;
            this.flight=flight;this.product=product;this.started=started;this.date=date;
        }
        Map<String,Object> evidence(){Map<String,Object> e=NativeAppEvidence.map();e.put("ordinal",ordinal);e.put("step",step);e.put("model_run_id",run);
            e.put("action",action.action);e.put("purpose",purpose);e.put("node_id",action.nodeId);e.put("node_label",action.nodeLabel);
            e.put("literal_type_text",action.text);e.put("done_status",action.status);e.put("before",before.frame.evidence());
            e.put("dispatch_started_elapsed_ms",started);e.put("dispatch_finished_elapsed_ms",finished==0?null:Long.valueOf(finished));
            e.put("expected_date",date==null?null:date.toString());e.put("actual_action_receipt",receipt);
            if(guard!=null)e.put("native_action_guard",guard.evidence());return e;}
    }
    void beforeModelAction(int step,ActionDecision action,String run,long now)throws Exception{
        live();verifyInstalled();need(reservationReobserveId==null,"drained stale outcome requires fresh observation before another model action");
        if(calendarDateOffer!=null&&calendarSelection==null)need(action!=null&&"done".equals(action.action)
                &&("failure".equals(action.status)||"partial".equals(action.status)),
                "an unconnected calendar Offer admits only incomplete termination through the legacy route");
        need(current!=null&&inFlight==null&&step>0&&step<=MAX_ACTIONS&&NativeAppEvidence.id(run)&&usedRuns.add(run),"one actual bounded model action required");
        current.requireCurrent(action);authorization.frame().requireDecision(action);need(++ordinal<=MAX_ACTIONS,"native action budget exhausted");
        if(NativeXiaomiProductPage.HOME_LOADING.equals(current.phase))
            need("wait".equals(action.action)&&++productHomeLoadingWaits<=MAX_PRODUCT_HOME_LOADING_WAITS,"bounded model-issued home loading wait required");
        String purpose="back".equals(action.action)?current.purposes.get("back"):action.nodeId==null?action.action:current.purposes.get(action.nodeId);
        LocalDate date=null;
        if("query_observed_form".equals(purpose)){need(confirmedFormDate!=null&&flight!=null&&flight.form!=null&&flight.form.matches(confirmedFormDate)
                    &&calendarYearProof!=null&&queryAttempts.size()<2&&queryAttempts.add(confirmedFormDate),"one explicit query per proved date, maximum two");date=confirmedFormDate;}
        else if(purpose!=null&&purpose.startsWith("navigate_departure_date:")){date=LocalDate.parse(purpose.substring("navigate_departure_date:".length()));
            need(lastQueryProof!=null&&date.equals(flight.resolvedDates(lastQueryDate).get(action.nodeId))&&dateAttempts.add(date),"one actual date-strip proposal per date");}
        else if("verify_form_after_result_date".equals(purpose))date=flight==null||lastQueryDate==null?null:flight.displayedMonthDay(lastQueryDate);
        else if("submit_exact_suggestion".equals(purpose)||"submit_product_query".equals(purpose)){need(!productQueryAttempted,"native product query already attempted");productQueryAttempted=true;}
        else if("dismiss_image_modal_once".equals(purpose)){
            need(product!=null&&NativeXiaomiProductPage.IMAGE_MODAL.equals(product.phase)
                    &&!productModalExitAttempted&&!productQueryAttempted&&productQueryProof==null&&productOpenProof==null,
                    "one prequery image-modal Back proposal required");
            productModalExitAttempted=true; // Consumed even if the actual dispatch is later stale.
        }
        else if(NativeXiaomiProductPage.DECLINE_LOCATION.equals(purpose)){
            need(optionalLocationInstallation()&&product!=null&&NativeXiaomiProductPage.OPTIONAL_LOCATION.equals(product.phase)
                    &&"click".equals(action.action)&&pending==null&&product.clickIds.size()==1&&product.clickIds.contains(action.nodeId)
                    &&!productModalExitAttempted&&!productQueryAttempted&&productQueryProof==null&&productOpenProof==null,
                    "one model click on the exact pinned optional-location decline control required");
            productModalExitAttempted=true; // Shared budget; stale/rejected/unknown never authorizes a replay.
        }
        else if(NativeCtripFlightPage.LOGIN_EXIT.equals(purpose)){
            NativeAppEvidence.Node loginReturn=NativeCtripFlightPage.loginReturnControl(flight);
            requireFrame(current.frame);
            need("click".equals(action.action)&&pending==null&&!flightLoginExitAttempted&&loginReturn!=null
                    &&loginReturn.id.equals(action.nodeId)&&calendarYearProof!=null&&lastQueryProof!=null
                    &&lastQueryDate!=null&&queryAttempts.contains(lastQueryDate),
                    "one model proposal for the observed Ctrip return after an actual query/result chain required");
            flightLoginExitAttempted=true;flightLoginProposalObservation=current.frame.observationId;
            date=lastQueryDate; // Consumed even if dispatch is later stale, rejected or unknown.
        }
        else if(NativeXiaomiProductPage.LOGIN_EXIT.equals(purpose)){
            need(product!=null&&NativeXiaomiProductPage.LOGIN.equals(product.phase)&&pending==null
                    &&!productLoginExitReserved&&!current.frame.observationId.equals(productLoginProposalObservation),
                    "one fresh model proposal for the actual native login return control required");
            productLoginExitReserved=true;productLoginProposalObservation=current.frame.observationId;
        }
        if(!"wait".equals(action.action)&&!"done".equals(action.action)){acceptedClaim=null;lastDone=null;
            if(!"open_exact_product".equals(purpose)){productOpenProof=null;productSemantic=null;}}
        inFlight=new Attempt(ordinal,step,run,action,current,purpose,flight,product,now,date);
        Map<String,Object> e=base();e.put("attempt",inFlight.evidence());e.put("same_owner_authorization",authorization.frame().evidence());e.put("dispatch_occurred",false);
        journal.write(String.format(java.util.Locale.ROOT,"native-app-attempt-%02d.json",ordinal),e);
        inFlight.journaled=true;recoverableStaleAttempt=null;
    }
    /** Boolean-only legacy callers cannot prove that an effect never entered. */
    void modelActionOutcome(ActionDecision action,String run,boolean accepted,boolean dispatched,boolean stale,String receiptSha,long finished)throws Exception{
        modelActionOutcome(action,run,accepted,dispatched,stale,receiptSha,finished,null);
    }
    void modelActionOutcome(ActionDecision action,String run,boolean accepted,boolean dispatched,boolean stale,String receiptSha,long finished,
            Map<String,Object> actionExecution)throws Exception{
        live();Attempt a=inFlight;need(a!=null&&a.action==action&&a.run.equals(run)&&finished>=a.started&&NativeAppEvidence.sha(receiptSha),"same native action and durable receipt required");
        boolean recovery=!accepted&&!dispatched&&stale&&provedUnenteredGuardedAction(a,actionExecution,finished);
        boolean postEffect=accepted&&dispatched&&!stale&&provedEnteredGuardedAction(a,actionExecution,finished);
        boolean release=recovery&&NativeActionSnapshotCheck.QUERY.equals(a.purpose)
                &&a.date!=null&&queryAttempts.contains(a.date);
        boolean loginRelease=!accepted&&!dispatched&&stale&&NativeXiaomiProductPage.LOGIN_EXIT.equals(a.purpose)
                &&productLoginExitReserved&&a.guard==null&&provedUnenteredAction(a,actionExecution,finished)
                &&actionExecution.get("native_action_guard")==null;
        boolean dateRelease=!accepted&&!dispatched&&stale&&provedUnenteredDateNavigation(a,actionExecution,finished);
        if(a.guard!=null)a.guard.close();
        Map<String,Object> outcome=NativeAppEvidence.map();outcome.put("accepted",accepted);outcome.put("dispatched",dispatched);outcome.put("stale",stale);
        outcome.put("step_action_record_sha256",receiptSha);outcome.put("model_issued",true);
        outcome.put("query_reservation_released",release);
        outcome.put("login_exit_reservation_released",loginRelease);
        outcome.put("date_reservation_released",dateRelease);
        outcome.put("pre_effect_stale_recovery_available",recovery);
        if(postEffect){
            outcome.put("post_effect_read_recovery_available",true);
            outcome.put("post_effect_execution_projection_sha256",NativeAppEvidence.fingerprint(actionExecution));
        }
        if(recovery){
            Map<String,Object> proof=NativeAppEvidence.map();proof.put("schema","hepta.native-stale-recovery-proof.v1");
            proof.put("action_execution_projection_sha256",NativeAppEvidence.fingerprint(actionExecution));
            proof.put("original_observation_id",a.before.frame.observationId);proof.put("original_model_run_id",a.run);
            proof.put("operation_id",actionExecution.get("operation_id"));proof.put("worker_drained",true);
            proof.put("effect_entered",false);proof.put("guard_unclaimed",true);
            proof.put("fresh_observation_and_new_model_decision_required",true);
            proof.put("automatic_redispatch",false);proof.put("business_verified",false);outcome.put("pre_effect_stale_recovery",proof);
        }
        if(release){
            Map<String,Object> proof=NativeAppEvidence.map();proof.put("schema","hepta.native-query-reservation-release.v1");
            proof.put("date",a.date.toString());proof.put("action_execution_projection_sha256",NativeAppEvidence.fingerprint(actionExecution));
            proof.put("original_observation_id",a.before.frame.observationId);proof.put("original_model_run_id",a.run);
            proof.put("operation_id",actionExecution.get("operation_id"));proof.put("worker_drained",true);proof.put("effect_entered",false);
            proof.put("fresh_observation_and_new_model_decision_required",true);proof.put("automatic_redispatch",false);
            proof.put("business_verified",false);outcome.put("query_reservation_release",proof);
        }
        if(loginRelease){
            Map<String,Object> proof=NativeAppEvidence.map();proof.put("schema","hepta.native-login-exit-reservation-release.v1");
            proof.put("action_execution_projection_sha256",NativeAppEvidence.fingerprint(actionExecution));
            proof.put("original_observation_id",a.before.frame.observationId);proof.put("original_model_run_id",a.run);
            proof.put("operation_id",actionExecution.get("operation_id"));proof.put("worker_drained",true);proof.put("effect_entered",false);
            proof.put("fresh_observation_and_new_model_decision_required",true);proof.put("automatic_redispatch",false);
            proof.put("business_verified",false);outcome.put("login_exit_reservation_release",proof);
        }
        if(dateRelease){
            Map<String,Object> proof=NativeAppEvidence.map();proof.put("schema","hepta.native-date-reservation-release.v1");
            proof.put("date",a.date.toString());proof.put("purpose",a.purpose);proof.put("node_id",a.action.nodeId);
            proof.put("action_execution_projection_sha256",NativeAppEvidence.fingerprint(actionExecution));
            proof.put("original_observation_id",a.before.frame.observationId);proof.put("original_model_run_id",a.run);
            proof.put("operation_id",actionExecution.get("operation_id"));proof.put("worker_drained",true);proof.put("effect_entered",false);
            proof.put("fresh_observation_and_new_model_decision_required",true);proof.put("automatic_redispatch",false);
            proof.put("query_or_result_proof_created",false);proof.put("business_verified",false);
            outcome.put("date_reservation_release",proof);
        }
        a.finished=finished;a.receipt=NativeAppEvidence.immutableMap(outcome);
        Map<String,Object> e=base();e.put("attempt",a.evidence());journal.write(String.format(java.util.Locale.ROOT,"native-app-outcome-%02d.json",a.ordinal),e);a.outcomeJournaled=true;inFlight=null;
        // Only the durable receipt above releases a reservation. The old frame
        // and old model run stay unusable; neither a result nor an action is made.
        if(release){queryAttempts.remove(a.date);requireReobservationAfterReleasedReservation(a,finished);}
        if(loginRelease){productLoginExitReserved=false;requireReobservationAfterReleasedReservation(a,finished);}
        if(dateRelease){dateAttempts.remove(a.date);requireReobservationAfterReleasedReservation(a,finished);}
        if(recovery){recoverableStaleAttempt=a;requireReobservationAfterReleasedReservation(a,finished);}
        if(stale&&!dispatched)return;
        if(!accepted||stale){invalidate("native_action_receipt_not_accepted");return;}
        if("wait".equals(action.action))return;
        if("done".equals(action.action)){lastDone=a;return;}
        need(dispatched,"native action effect not dispatched");
        need(pending==null,"new native action while preceding transition unresolved");pending=a;
        if(postEffect){a.enteredExecutionSha=NativeAppEvidence.fingerprint(actionExecution);a.enteredOperation=(String)actionExecution.get("operation_id");a.postEffectReadEligible=true;}
    }
    /** An exact Controller close-and-seal handoff is mandatory; JSON alone,
     * a normal closed guard or the unentered receipt never qualifies. */
    private boolean provedEnteredGuardedAction(Attempt a,Map<String,Object> x,long finished){
        ActionGuard g=a.guard;
        if(!NativeCtripFlightPage.supported(goal)||!NativeActionSnapshotCheck.OPEN.equals(a.purpose)
                ||!"click".equals(a.action.action)||a.action.toolChildOrigin!=null||a.before!=current||pending!=null
                ||g==null||g.action!=a.action||g.frame!=a.before.frame||x==null)return false;
        if(!"hepta.action-execution.v1".equals(x.get("schema"))||!"serial_action_worker".equals(x.get("execution_kind"))
                ||!(x.get("operation_id") instanceof String)||!NativeAppEvidence.id((String)x.get("operation_id"))
                ||!taskId.equals(x.get("task_id"))||!a.run.equals(x.get("model_run_id"))
                ||!a.before.frame.observationId.equals(x.get("observation_id"))
                ||!authorization.authorization.sha256.equals(x.get("authorization_sha256"))
                ||executionNumber(x,"window_id")!=a.before.frame.windowId||executionNumber(x,"display_id")!=displayId
                ||!generation.equals(x.get("background_generation"))||!Boolean.FALSE.equals(x.get("retired"))
                ||!x.containsKey("retirement_reason")||x.get("retirement_reason")!=null
                ||!Boolean.TRUE.equals(x.get("effect_entered"))||!Boolean.TRUE.equals(x.get("effect_returned"))
                ||!Boolean.TRUE.equals(x.get("api_accepted"))||!Boolean.TRUE.equals(x.get("worker_drained"))
                ||!Boolean.TRUE.equals(x.get("callback_published"))||!Boolean.TRUE.equals(x.get("callback_authority_current"))
                ||!Boolean.FALSE.equals(x.get("automatic_redispatch")))return false;
        long queued=executionNumber(x,"queued_elapsed_ms"),drained=executionNumber(x,"worker_drained_elapsed_ms");
        if(queued<a.started||queued<g.issued||g.deadline<=queued||g.deadline-queued>8000
                ||executionNumber(x,"deadline_elapsed_ms")!=g.deadline||drained<queued||drained>finished||finished>=g.deadline)return false;
        Object raw=x.get("native_action_guard");if(!(raw instanceof Map<?,?>))return false;
        Map<?,?> guard=(Map<?,?>)raw;
        return a.purpose.equals(guard.get("purpose"))&&a.run.equals(guard.get("model_run_id"))
                &&g.actionSha.equals(guard.get("action_sha256"))&&guard.containsKey("query_history_sha256")
                &&g.historySha==null&&guard.get("query_history_sha256")==null
                &&executionNumber(guard,"attempt_started_elapsed_ms")==a.started
                &&executionNumber(guard,"issued_elapsed_ms")==g.issued&&executionNumber(guard,"deadline_elapsed_ms")==g.deadline
                &&executionNumber(guard,"state")==1&&Boolean.TRUE.equals(guard.get("single_atomic_claim"))
                &&g.consumeEnteredOutcome(x);
    }
    /** Service lifetime facts bound to this exact private Attempt; no JSON/model claim supplies authority. */
    private boolean provedUnenteredAction(Attempt a,Map<String,Object> x,long finished){
        if(a.before!=current||pending!=null||x==null)return false;
        if(!"hepta.action-execution.v1".equals(x.get("schema"))||!"serial_action_worker".equals(x.get("execution_kind"))
                ||!(x.get("operation_id") instanceof String)||!NativeAppEvidence.id((String)x.get("operation_id"))
                ||!taskId.equals(x.get("task_id"))||!a.run.equals(x.get("model_run_id"))
                ||!a.before.frame.observationId.equals(x.get("observation_id"))
                ||!authorization.authorization.sha256.equals(x.get("authorization_sha256"))
                ||executionNumber(x,"window_id")!=a.before.frame.windowId||executionNumber(x,"display_id")!=displayId
                ||!generation.equals(x.get("background_generation")))return false;
        if(!Boolean.FALSE.equals(x.get("retired"))||!x.containsKey("retirement_reason")||x.get("retirement_reason")!=null
                ||!Boolean.FALSE.equals(x.get("effect_entered"))||!Boolean.FALSE.equals(x.get("effect_returned"))
                ||!x.containsKey("api_accepted")||x.get("api_accepted")!=null
                ||!Boolean.TRUE.equals(x.get("worker_drained"))||!Boolean.TRUE.equals(x.get("callback_published"))
                ||!Boolean.TRUE.equals(x.get("callback_authority_current"))||!Boolean.FALSE.equals(x.get("automatic_redispatch")))return false;
        long queued=executionNumber(x,"queued_elapsed_ms"),drained=executionNumber(x,"worker_drained_elapsed_ms");
        long deadline=executionNumber(x,"deadline_elapsed_ms");
        return queued>=a.started&&deadline>queued&&deadline-queued<=8000
                &&drained>=queued&&drained<=finished&&finished<deadline;
    }
    /** Release only this exact visible date proposal when its serial worker is
     * proved drained before entering an effect. This cannot retry an unknown or
     * entered action, replenish an action/query/login budget, or create a query
     * proof; the caller journals before release and requires a new observation. */
    private boolean provedUnenteredDateNavigation(Attempt a,Map<String,Object> x,long finished){
        return a.guard==null&&a.date!=null&&a.flight!=null&&NativeCtripFlightPage.RESULTS.equals(a.flight.phase)
                &&lastQueryProof!=null&&lastQueryDate!=null&&dateAttempts.contains(a.date)
                &&("navigate_departure_date:"+a.date).equals(a.purpose)&&"click".equals(a.action.action)
                &&a.purpose.equals(a.before.purposes.get(a.action.nodeId))
                &&a.date.equals(a.flight.resolvedDates(lastQueryDate).get(a.action.nodeId))
                &&provedUnenteredAction(a,x,finished)&&x.get("native_action_guard")==null;
    }
    private boolean provedUnenteredGuardedAction(Attempt a,Map<String,Object> x,long finished){
        ActionGuard g=a.guard;
        if(!java.util.Arrays.asList(NativeActionSnapshotCheck.OPEN,NativeActionSnapshotCheck.YEAR,
                NativeActionSnapshotCheck.QUERY,NativeActionSnapshotCheck.SEARCH,NativeActionSnapshotCheck.SEARCH_ICON).contains(a.purpose)
                ||g==null||g.action!=a.action||g.frame!=a.before.frame||!provedUnenteredAction(a,x,finished))return false;
        if(executionNumber(x,"queued_elapsed_ms")<g.issued||executionNumber(x,"deadline_elapsed_ms")!=g.deadline)return false;
        Object raw=x.get("native_action_guard");if(!(raw instanceof Map<?,?>))return false;
        Map<?,?> guard=(Map<?,?>)raw;
        return a.purpose.equals(guard.get("purpose"))&&a.run.equals(guard.get("model_run_id"))
                &&g.actionSha.equals(guard.get("action_sha256"))&&guard.containsKey("query_history_sha256")
                &&java.util.Objects.equals(g.historySha,guard.get("query_history_sha256"))
                &&executionNumber(guard,"attempt_started_elapsed_ms")==a.started
                &&executionNumber(guard,"issued_elapsed_ms")==g.issued&&executionNumber(guard,"deadline_elapsed_ms")==g.deadline
                &&executionNumber(guard,"state")==0&&Boolean.TRUE.equals(guard.get("single_atomic_claim"))
                &&g.consumeUnenteredOutcome(x);
    }
    private void requireReobservationAfterReleasedReservation(Attempt a,long finished){
        reservationReobserveId=a.before.frame.observationId;reservationReobserveAfter=finished;
    }
    private static long executionNumber(Map<?,?> value,String key){
        Object number=value.get(key);return number instanceof Long||number instanceof Integer?((Number)number).longValue():-1;
    }
    private void advancePending(NativeAppEvidence.Frame frame){
        Attempt a=pending;need(a!=null&&a.receipt!=null&&frame.capturedElapsedMs>=a.finished,"post-action native frame precedes outcome");
        if(frame.capturedElapsedMs-a.finished>OBSERVED_TRANSITION_MS){invalidate("actual_native_transition_observation_deadline");return;}
        boolean complete=false;Map<String,Object> proof=NativeAppEvidence.map();proof.put("attempt",a.evidence());proof.put("after",frame.evidence());
        if(flight!=null){
            String p=a.purpose;
            if("inspect_departure_year".equals(p)&&NativeCtripFlightPage.CALENDAR.equals(flight.phase)&&a.flight.form!=null){
                LocalDate proposed=null;Map<String,Object> header=null;
                for(Map<String,Object> m:flight.calendarMonths)if(((Integer)m.get("month")).intValue()==a.flight.form.month){
                    need(proposed==null,"calendar has ambiguous source year for the selected form month");
                    proposed=LocalDate.of(((Integer)m.get("year")).intValue(),a.flight.form.month,a.flight.form.day);header=m;}
                need(proposed!=null&&flight.calendarYearHeadersAdmitted(),"actual same-month calendar title required");
                proof.put("calendar_month_header",header);proof.put("form_before",a.flight.form.evidence());proof.put("year_source","actual_native_calendar_month_title_after_model_date_control");
                proof.put("owner_year_used_as_observed_value",false);calendarProposedDate=proposed;calendarInspection=NativeAppEvidence.immutableMap(proof);complete=true;
            }else if("return_from_calendar".equals(p)&&NativeCtripFlightPage.FORM.equals(flight.phase)){
                if(calendarProposedDate!=null&&calendarInspection!=null&&flight.form.matches(calendarProposedDate)){
                    proof.put("inspection",calendarInspection);proof.put("form_after",flight.form.evidence());proof.put("proved_departure_date",calendarProposedDate.toString());
                    calendarYearProof=NativeAppEvidence.immutableMap(proof);confirmedFormDate=calendarProposedDate;
                }
                calendarProposedDate=null;calendarInspection=null;complete=true;
            }else if("query_observed_form".equals(p)&&NativeCtripFlightPage.RESULTS.equals(flight.phase)&&a.date.equals(flight.displayedMonthDay(a.date))){
                proof.put("calendar_year_round_trip",calendarYearProof);proof.put("query_form",a.flight.form.evidence());proof.put("query_date",a.date.toString());
                proof.put("result_date_strip",dateEvidence(flight));lastQueryDate=a.date;lastQueryProof=NativeAppEvidence.immutableMap(proof);complete=true;
            }else if(p!=null&&p.startsWith("navigate_departure_date:")&&NativeCtripFlightPage.RESULTS.equals(flight.phase)
                    &&a.date.equals(flight.displayedMonthDay(lastQueryDate))){proof.put("actual_result_date_strip",dateEvidence(flight));proof.put("proved_date",a.date.toString());complete=true;}
            else if("verify_form_after_result_date".equals(p)&&NativeCtripFlightPage.FORM.equals(flight.phase)){
                confirmedFormDate=a.date!=null&&calendarYearProof!=null&&flight.form.matches(a.date)?a.date:null;
                proof.put("form_after",flight.form.evidence());proof.put("proved_departure_date",confirmedFormDate==null?null:confirmedFormDate.toString());complete=true;
            }else if(NativeCtripFlightPage.LOGIN_EXIT.equals(p)&&a.flight!=null
                    &&NativeCtripFlightPage.LOGIN_REQUIRED.equals(a.flight.phase)&&NativeCtripFlightPage.RESULTS.equals(flight.phase)
                    &&a.date!=null&&a.date.equals(lastQueryDate)&&lastQueryProof!=null
                    &&a.date.equals(flight.displayedMonthDay(a.date))
                    &&NativeAppEvidence.sameProfileOwner(a.before.frame.profileWindow,frame.profileWindow)){
                proof.put("navigation_only",true);proof.put("query_or_result_proof_created",false);
                proof.put("prior_actual_query_proof_sha256",NativeAppEvidence.fingerprint(lastQueryProof));
                proof.put("returned_query_date",a.date.toString());complete=true;
            }else if(NativeCtripFlightPage.LOGIN_EXIT.equals(p)&&a.flight!=null
                    &&NativeCtripFlightPage.LOGIN_REQUIRED.equals(a.flight.phase)&&NativeCtripFlightPage.FORM.equals(flight.phase)
                    &&installed.profileTarget!=null&&frame.capture!=null&&frame.capture.nativeText()
                    &&frame.metadataObserved&&frame.windowType==1&&frame.collectionComplete&&!frame.nodesTruncated
                    &&a.date!=null&&a.date.equals(lastQueryDate)&&lastQueryProof!=null&&flight.form.matches(a.date)
                    &&NativeAppEvidence.sameProfileOwner(a.before.frame.profileWindow,frame.profileWindow)){
                // The full typed post-effect census proves only where the one
                // return arrived. It does not promote history to current result
                // authority, renew a clock, or reset any proposal/query budget.
                proof.put("navigation_only",true);proof.put("query_or_result_proof_created",false);
                proof.put("business_transition_verified",false);proof.put("login_exit_ended_without_target_result",true);
                proof.put("actual_return_destination",NativeCtripFlightPage.FORM);proof.put("form_after",flight.form.evidence());
                proof.put("prior_actual_query_proof_sha256",NativeAppEvidence.fingerprint(lastQueryProof));
                proof.put("returned_form_date",a.date.toString());flightLoginReturnedToForm=true;complete=true;
            }else if("open_flight_form".equals(p)&&NativeCtripFlightPage.FORM.equals(flight.phase))complete=true;
            else if("dismiss_research_sheet".equals(p)&&!NativeCtripFlightPage.OVERLAY.equals(flight.phase)&&!NativeCtripFlightPage.UNAVAILABLE.equals(flight.phase))complete=true;
        }else{
            if(NativeXiaomiProductPage.LOGIN.equals(product.phase)&&!NativeXiaomiProductPage.DECLINE_LOCATION.equals(a.purpose)){
                proof.put("login_interrupted_navigation",true);proof.put("business_transition_verified",false);
                proof.put("query_or_result_proof_created",false);complete=true;
            }else if(NativeXiaomiProductPage.LOGIN_EXIT.equals(a.purpose)&&a.product!=null
                    &&NativeXiaomiProductPage.LOGIN.equals(a.product.phase)&&"home_search".equals(product.phase)){
                proof.put("navigation_only",true);proof.put("query_or_result_proof_created",false);complete=true;
            }else if("dismiss_image_modal_once".equals(a.purpose)&&a.product!=null
                    &&NativeXiaomiProductPage.IMAGE_MODAL.equals(a.product.phase)&&"home_search".equals(product.phase)){
                proof.put("navigation_only",true);proof.put("query_or_result_proof_created",false);complete=true;
            }else if(NativeXiaomiProductPage.DECLINE_LOCATION.equals(a.purpose)&&a.product!=null
                    &&NativeXiaomiProductPage.OPTIONAL_LOCATION.equals(a.product.phase)&&"home_search".equals(product.phase)){
                proof.put("navigation_only",true);proof.put("query_or_result_proof_created",false);
                proof.put("optional_location_decline_observed",true);proof.put("system_permission_result_claimed",false);complete=true;
            }else if(("submit_exact_suggestion".equals(a.purpose)||"submit_product_query".equals(a.purpose))&&product.quote!=null&&"search_card".equals(product.quote.kind)){
                proof.put("search_result_quote",product.quote.evidence());productQueryProof=NativeAppEvidence.immutableMap(proof);complete=true;
            }else if("open_exact_product".equals(a.purpose)&&product.quote!=null&&"detail_display".equals(product.quote.kind)){
                need(productQueryProof!=null&&a.product.quote!=null&&"search_card".equals(a.product.quote.kind)
                        &&a.product.quote.amountDecimal.equals(product.quote.amountDecimal)&&a.product.quote.currency.equals(product.quote.currency),"same queried product/card and displayed price required");
                proof.put("query",productQueryProof);proof.put("search_card",a.product.quote.evidence());proof.put("detail",product.quote.evidence());
                productOpenProof=NativeAppEvidence.immutableMap(proof);productSemantic=product.quote.semanticFingerprint;complete=true;
            }else if(a.product!=null&&"home_search".equals(a.product.phase)
                    &&(NativeActionSnapshotCheck.SEARCH.equals(a.purpose)
                    ||NativeXiaomiProductPage.SEARCH_ICON.equals(a.purpose)&&a.product.searchIconNavigationCandidate)){
                complete=java.util.Arrays.asList("search_input","search_submit","search_suggestion").contains(product.phase);
                if(complete){
                    proof.put("navigation_only",true);proof.put("fresh_search_contract_phase",product.phase);
                    proof.put("query_or_result_proof_created",false);proof.put("business_transition_verified",false);
                }
            }else if("set_product_query".equals(a.purpose)||"return_to_owned_product_search".equals(a.purpose)){
                complete=!"unrecognized_native_page".equals(product.phase)&&!"observation_unavailable".equals(product.phase)
                        &&!NativeXiaomiProductPage.HOME_LOADING.equals(product.phase);
            }
        }
        if(complete){transitions.add(NativeAppEvidence.immutableMap(proof));pending=null;}
    }
    private static List<Map<String,Object>> dateEvidence(NativeCtripFlightPage.Page page){List<Map<String,Object>> out=new ArrayList<Map<String,Object>>();for(NativeCtripFlightPage.DateCell d:page.dates)out.add(d.evidence());return out;}
    private Map<String,Object> flightResult(NativeAppEvidence.Frame f){
        Map<String,Object> out=resultBase(f,"hepta.native-ctrip-displayed-flight-result.v1");out.put("from_city",goal.fromCity);out.put("to_city",goal.toCity);
        out.put("departure_date",goal.departureDate.toString());out.put("adults",1);out.put("children",0);out.put("infants",0);
        out.put("calendar_year_round_trip",calendarYearProof);out.put("same_task_target_date_explicit_query",lastQueryProof);
        out.put("current_date_strip",dateEvidence(flight));List<Map<String,Object>> cards=new ArrayList<Map<String,Object>>();for(NativeCtripFlightPage.Quote q:flight.quotes)cards.add(q.evidence());out.put("displayed_cards",cards);
        out.put("tax_and_fee_status","not_stated_in_observed_card");out.put("lowest_of_all_flights_claimed",false);out.put("availability_or_checkout_price_verified",false);
        StringBuilder s=new StringBuilder("携程原生应用当前展示 ").append(goal.departureDate).append(' ').append(goal.fromCity).append("到").append(goal.toCity).append("，1名成人经济舱：");
        for(int i=0;i<Math.min(3,flight.quotes.size());i++){NativeCtripFlightPage.Quote q=flight.quotes.get(i);if(i>0)s.append("；");s.append(q.flightNumber).append(' ').append(q.departureTime).append('–').append(q.arrivalTime).append(' ').append(q.departureAirport).append('→').append(q.arrivalAirport).append("，人民币").append(q.amountDecimal).append("元");if(!q.displayTags.isEmpty())s.append("，").append(q.displayTags);}
        s.append("。这是所见航班卡报价；税费及最终结算价未在本次观测中确认。");out.put("display_summary",s.toString());return out;
    }
    private Map<String,Object> productResult(NativeAppEvidence.Frame f){Map<String,Object> out=resultBase(f,"hepta.native-xiaomi-displayed-product-price.v1");
        out.put("model",goal.productModel);out.put("actual_query_and_card_navigation",productOpenProof);out.put("detail_quote",product.quote.evidence());
        out.put("display_summary","小米商城原生应用当前展示 "+product.quote.modelRaw+"：人民币"+product.quote.amountDecimal+"元。已从本次搜索结果进入同商品详情核对；未下单，最终结算和库存未确认。");return out;}
    private Map<String,Object> resultBase(NativeAppEvidence.Frame f,String schema){Map<String,Object> e=base();e.put("schema",schema);e.put("goal",goal.evidence());
        e.put("installed_app",installed.evidence());e.put("current_frame",f.evidence());e.put("business_verified_before_terminal",false);e.put("external_model",false);return e;}
    private Map<String,Object> progress(){Map<String,Object> e=NativeAppEvidence.map();e.put("actual_model_actions",ordinal);e.put("typed_search_navigation_observed",searchNavigationObserved);e.put("typed_search_navigation_pending",searchPlanning!=null&&!searchNavigationObserved);e.put("calendar_year_proved",calendarYearProof!=null);
        e.put("proved_form_date",confirmedFormDate==null?null:confirmedFormDate.toString());e.put("last_query_date",lastQueryDate==null?null:lastQueryDate.toString());
        List<String> dates=new ArrayList<String>();for(LocalDate d:queryAttempts)dates.add(d.toString());e.put("explicit_query_attempt_dates",dates);
        e.put("product_modal_exit_attempted",productModalExitAttempted);
        e.put("product_login_exit_reserved",productLoginExitReserved);
        e.put("product_login_proposal_observation",productLoginProposalObservation);
        e.put("flight_login_exit_attempted",flightLoginExitAttempted);e.put("flight_login_returned_to_form",flightLoginReturnedToForm);
        e.put("flight_login_proposal_observation",flightLoginProposalObservation);
        e.put("product_home_loading_since_elapsed_ms",productHomeLoadingSince<0?null:Long.valueOf(productHomeLoadingSince));
        e.put("product_home_loading_wait_attempts",productHomeLoadingWaits);
        e.put("product_query_observed",productQueryProof!=null);e.put("product_detail_navigation_observed",productOpenProof!=null);e.put("pending",pending==null?null:pending.evidence());e.put("transitions",transitions);return e;}
    private Map<String,Object> base(){Map<String,Object> e=NativeAppEvidence.map();e.put("schema",SCHEMA);e.put("task_id",taskId);
        e.put("owner_sha256",goal.ownerSha256);e.put("execution_target_sha256",target.targetSha256);e.put("authorization_sha256",authorization.authorization.sha256);
        if(installed.profileTarget!=null)e.put("profile_target",installed.profileTarget.evidence());return e;}
    private void invalidate(String reason){if(inFlight!=null&&inFlight.guard!=null)inFlight.guard.close();
        if(calendarDateOffer!=null)calendarDateOffer.close();
        invalid=true;invalidReason=reason;acceptedClaim=null;}

    static final class SuccessClaim {
        final NativeAppSession session;final int step;final String run,frameSha,observation;final Map<String,Object> result;
        final WindowOwnership profileWindow;
        private SuccessClaim(NativeAppSession s,int step,String run,NativeAppEvidence.Frame frame,Map<String,Object> result){
            session=s;this.step=step;this.run=run;frameSha=frame.completionFrameSha;observation=frame.observationId;
            profileWindow=frame.profileWindow;this.result=NativeAppEvidence.immutableMap(result);
        }
    }
    boolean ready(NotesCompletionEvidence.Frame frame){return !retired&&!invalid&&!flightLoginReturnedToForm&&current!=null&&current.resultReady
            &&(current.frame.capture==null||!current.frame.capture.formHistory())&&frame!=null
            &&current.frame.observationId.equals(frame.observationId)&&current.frame.completionFrameSha.equals(TaskCompletionGate.webFrameSha(frame))&&pending==null&&inFlight==null;}
    SuccessClaim acceptSuccess(int step,String run,NotesCompletionEvidence.Frame frame,boolean finalWholeTreeStable){
        live();acceptedClaim=null;
        if(flightLoginReturnedToForm||current!=null&&current.frame.capture!=null&&current.frame.capture.formHistory())return null;
        if(!finalWholeTreeStable||!ready(frame)||lastDone==null||lastDone.step!=step||!lastDone.run.equals(run)
                ||!"success".equals(lastDone.action.status)||!lastDone.before.resultReady
                ||!lastDone.before.frame.treeSha.equals(current.frame.treeSha)||lastDone.before.frame.windowId!=current.frame.windowId
                ||lastDone.before.frame.rotation!=current.frame.rotation
                ||!NativeAppEvidence.sameProfileWindow(lastDone.before.frame.profileWindow,current.frame.profileWindow))return null;
        acceptedClaim=new SuccessClaim(this,step,run,current.frame,current.resultRecord());return acceptedClaim;
    }
    void retire()throws Exception{if(retired)return;retired=true;
        if(inFlight!=null&&inFlight.guard!=null)inFlight.guard.close();
        if(calendarDateOffer!=null)calendarDateOffer.close();
        Map<String,Object> e=base();e.put("action_domain_retired",true);e.put("pending_action",inFlight!=null||pending!=null);
        e.put("invalid",invalid);e.put("invalid_reason",invalidReason);e.put("accepted_completion_candidate",acceptedClaim!=null);
        e.put("progress",progress());journal.write("native-app-retired.json",e);
    }
    Map<String,Object> terminal(NotesCompletionEvidence.Frame frame,TaskAuthorization.Frame owner,int step,String run,
            boolean modelSuccess,boolean cleanup,boolean backgroundReleased,boolean scopeRechecked,boolean installedRechecked,
            boolean cancelled,boolean processStarted,boolean processExitObserved,Integer exitCode,boolean receiptValid,
            String workerTask,String workerGeneration,String workerReceiptSha){
        return terminal(frame,owner,step,run,modelSuccess,cleanup,backgroundReleased,scopeRechecked,installedRechecked,
                cancelled,processStarted,processExitObserved,exitCode,receiptValid,workerTask,workerGeneration,workerReceiptSha,null);
    }
    Map<String,Object> terminal(NotesCompletionEvidence.Frame frame,TaskAuthorization.Frame owner,int step,String run,
            boolean modelSuccess,boolean cleanup,boolean backgroundReleased,boolean scopeRechecked,boolean installedRechecked,
            boolean cancelled,boolean processStarted,boolean processExitObserved,Integer exitCode,boolean receiptValid,
            String workerTask,String workerGeneration,String workerReceiptSha,Map<String,Object> profileCleanup){
        SuccessClaim claim=acceptedClaim;acceptedClaim=null;boolean first=!terminalConsumed;terminalConsumed=true;
        boolean snapshot=first&&retired&&!invalid&&claim!=null&&claim.session==this&&claim.step==step&&claim.run.equals(run)
                &&frame!=null&&claim.observation.equals(frame.observationId)&&claim.frameSha.equals(TaskCompletionGate.webFrameSha(frame))
                &&frame.displayId==displayId&&generation.equals(frame.backgroundGeneration)&&inFlight==null&&pending==null
                &&current!=null&&NativeAppEvidence.sameProfileWindow(claim.profileWindow,current.frame.profileWindow)
                &&(installed.profileTarget==null?claim.profileWindow==null:claim.profileWindow!=null
                    &&installed.profileTarget.sha256.equals(claim.profileWindow.targetSha256)
                    &&installed.profileTarget.profile.userId==claim.profileWindow.userId
                    &&installed.profileTarget.profile.serial==claim.profileWindow.userSerial
                    &&installed.profileTarget.fullUid==claim.profileWindow.fullUid);
        boolean ownerBound=owner!=null&&owner.authorization==authorization.authorization&&taskId.equals(owner.taskId)&&owner.successAllowed();
        boolean nativeBound=processStarted&&processExitObserved&&Integer.valueOf(0).equals(exitCode)&&receiptValid
                &&taskId.equals(workerTask)&&NativeAppEvidence.id(workerGeneration)&&NativeAppEvidence.sha(workerReceiptSha);
        boolean profileBound=profileCleanupBound(installed.profileTarget,claim==null?null:claim.profileWindow,profileCleanup);
        boolean passed=snapshot&&modelSuccess&&cleanup&&backgroundReleased&&scopeRechecked&&installedRechecked&&ownerBound&&!cancelled&&nativeBound&&profileBound;
        Map<String,Object> e=base();e.put("schema","hepta.native-app-terminal-completion.v1");e.put("one_terminal_attempt",first);
        e.put("action_domain_retired",retired);e.put("same_final_native_result_snapshot",snapshot);e.put("model_success_claim_verified",snapshot);
        e.put("all_cleanup_known",cleanup);e.put("background_released",backgroundReleased);e.put("scope_rechecked_after_worker_exit",scopeRechecked);
        e.put("installed_app_rechecked_after_cleanup",installedRechecked);e.put("owner_rechecked",ownerBound);e.put("cancelled",cancelled);
        e.put("native_normal0_parent_session_bound",nativeBound);e.put("worker_task_id",workerTask);e.put("worker_generation",workerGeneration);e.put("worker_receipt_sha256",workerReceiptSha);
        if(installed.profileTarget!=null){
            e.put("profile_cleanup_bound_to_final_window",profileBound);
            e.put("final_actual_profile_window",claim==null||claim.profileWindow==null?null:claim.profileWindow.evidence());
            e.put("profile_cleanup",profileBound?NativeAppEvidence.immutableMap(profileCleanup):null);
        }
        e.put("completion_verified",passed);e.put("business_verified",passed);e.put("terminal_binding_and_cleanup_verified",passed);
        e.put("observation_chain_verified",snapshot);e.put("actual_query_transitions",transitions);e.put("public_native_result",claim==null?null:claim.result);
        e.put("missing",passed?Collections.emptyList():Collections.singletonList("native_final_task_identity_or_query_or_cleanup_missing"));return NativeAppEvidence.immutableMap(e);
    }
    /** Consumes only the broker/session's actual retirement projection, never an expected profile or a live-window token. */
    static boolean profileCleanupBound(org.trillionnium.hepta.background.ProfileTarget expected,
            WindowOwnership frame,Map<String,Object> cleanup){
        if(expected==null)return frame==null&&cleanup==null;
        try{
            if(frame==null||cleanup==null)return false;
            NativeAppEvidence.requireProfileTarget(expected,frame);
            Set<String> fields=new TreeSet<String>(java.util.Arrays.asList("schema","generation","display_id","target_sha256",
                    "user_id","user_serial","full_uid","cleanup_known","live_tasks_absent","recents_tasks_absent",
                    "foreign_tasks_present","identity_unknown","owned_tasks","display_absence_observed"));
            if(!cleanup.keySet().equals(fields)||!"hepta.profile-task-cleanup.v1".equals(cleanup.get("schema"))
                    ||!frame.generation.equals(cleanup.get("generation"))||!expected.sha256.equals(cleanup.get("target_sha256"))
                    ||!profileNumber(cleanup.get("display_id"),frame.displayId)||!profileNumber(cleanup.get("user_id"),frame.userId)
                    ||!profileNumber(cleanup.get("user_serial"),frame.userSerial)||!profileNumber(cleanup.get("full_uid"),frame.fullUid))return false;
            for(String name:java.util.Arrays.asList("cleanup_known","live_tasks_absent","recents_tasks_absent","display_absence_observed"))
                if(!Boolean.TRUE.equals(cleanup.get(name)))return false;
            for(String name:java.util.Arrays.asList("foreign_tasks_present","identity_unknown"))
                if(!Boolean.FALSE.equals(cleanup.get(name)))return false;
            Object values=cleanup.get("owned_tasks");if(!(values instanceof List<?>))return false;
            List<?> rows=(List<?>)values;if(rows.isEmpty()||rows.size()>32)return false;
            Set<String> rowFields=new TreeSet<String>(java.util.Arrays.asList("task_id","parent_task_id","task_token_id",
                    "user_id","user_serial","full_uid","live_absent","recents_absent"));
            Set<Long> tasks=new TreeSet<Long>();Set<String> tokens=new TreeSet<String>();int matches=0;
            for(Object value:rows){
                if(!(value instanceof Map<?,?>))return false;Map<?,?> row=(Map<?,?>)value;
                if(!row.keySet().equals(rowFields)||!profileNumber(row.get("user_id"),frame.userId)
                        ||!profileNumber(row.get("user_serial"),frame.userSerial)||!profileNumber(row.get("full_uid"),frame.fullUid)
                        ||!Boolean.TRUE.equals(row.get("live_absent"))||!Boolean.TRUE.equals(row.get("recents_absent")))return false;
                Object task=row.get("task_id"),parent=row.get("parent_task_id"),token=row.get("task_token_id");
                if(!(task instanceof Integer||task instanceof Long)||!(parent instanceof Integer||parent instanceof Long)
                        ||((Number)task).longValue()<=0||((Number)task).longValue()>Integer.MAX_VALUE
                        ||((Number)parent).longValue()<=0||((Number)parent).longValue()>Integer.MAX_VALUE
                        ||((Number)task).longValue()==((Number)parent).longValue()||!(token instanceof String)
                        ||!((String)token).matches("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
                        ||!tasks.add(((Number)task).longValue())||!tokens.add((String)token))return false;
                if(profileNumber(task,frame.taskId)&&profileNumber(parent,frame.parentTaskId)&&frame.taskTokenId.equals(token))matches++;
            }
            return matches==1;
        }catch(RuntimeException malformed){return false;}
    }
    private static boolean profileNumber(Object value,long expected){
        return (value instanceof Integer||value instanceof Long)&&((Number)value).longValue()==expected;
    }
    Map<String,Object> evidence(){Map<String,Object> e=base();e.put("progress",progress());e.put("invalid",invalid);e.put("invalid_reason",invalidReason);e.put("action_domain_retired",retired);
        e.put("current_domain",current==null?null:current.evidence());return e;}
    Map<String,Object> promptEvidence(){return current==null?Collections.<String,Object>singletonMap("missing","current_native_observation_missing"):current.promptEvidence();}
    Map<String,Object> resultRecord(){return current==null?null:current.resultRecord();}
    List<String> missing(){return current==null?Collections.singletonList("current_native_observation_missing"):current.missing;}
    private static void need(boolean value,String reason){NativeAppEvidence.need(value,reason);}
}

