package org.trillionnium.hepta.local;

import java.util.List;
import java.util.Map;

/** Type-only Android/installed-App/session boundary for pre-existing non-native
 * host suites. No instance can be created and every operation throws.
 * New native provider/session gates must compile the actual production class. */
final class NativeAppSession {
    final String taskId=null;
    // Type-only lease fields for the actual mode binder; no Session can be constructed.
    final String generation=null;
    final int displayId=-1;
    final NativeAppGoal goal=null;
    // Required only by the exact new eligibility predicate; construction still always throws.
    final NativeAppEvidence.Installed installed=null;
    final BackgroundTaskTarget target=null;
    final BackgroundTaskTarget.SelectionBinding selection=null;
    final TaskAuthorization.Gate authorization=null;
    interface Journal {void write(String leaf,Map<String,Object> value)throws Exception;}
    interface InstalledVerifier {void verify()throws Exception;}
    private NativeAppSession(){throw unavailable();}
    NativeAppSession(String task,TaskAuthorization.Gate auth,BackgroundTaskTarget.SelectionBinding selected,
            NativeAppEvidence.Installed installed,String selectionSha,String generation,int display,
            InstalledVerifier verifier,Journal journal)throws Exception{throw unavailable();}
    /** Type-only new API; these legacy cases cannot create or claim a native Attempt. */
    static final class ActionGuard {
        final String purpose=null;final NativeAppGoal goal=null;final NativeAppEvidence.Node targetNode=null;
        NativeActionSnapshotCheck.Intent intent(String ref){throw unavailable();}
        private ActionGuard(){throw unavailable();}
        void requireClaimed(){throw unavailable();}
        void close(){throw unavailable();}
        void closeAfterUnenteredAwait(Map<String,Object> execution,java.util.concurrent.atomic.AtomicBoolean cancelled){throw unavailable();}
        void closeAfterEnteredAwait(Map<String,Object> execution,java.util.concurrent.atomic.AtomicBoolean cancelled){throw unavailable();}
        Map<String,Object> evidence(){throw unavailable();}
    }
    static final class ReadRecoveryPermit {
        private ReadRecoveryPermit(){throw unavailable();}
        void requireCurrent(){throw unavailable();}
        Map<String,Object> evidence(){throw unavailable();}
    }
    static final class PostEffectReadPermit {
        private PostEffectReadPermit(){throw unavailable();}
        void requireCurrent(){throw unavailable();}
        long transitionDeadline(){throw unavailable();}
        void requireOwner(NativeAppSession owner,Object authorization,String task,Object selection,String generation,int displayId){throw unavailable();}
        void admit(boolean retry){throw unavailable();}
        boolean admitted(boolean retry){throw unavailable();}
        Map<String,Object> evidence(){throw unavailable();}
    }
    /** Type-only pending-read surface for the complete legacy Controller compile.
     * No context, deadline, frame or capability can be produced by this boundary. */
    static final class PendingObservation {
        private PendingObservation(){throw unavailable();}
        boolean required(){throw unavailable();}
        void requireOwner(NativeAppSession owner,Object authorization,String task,Object selection,String generation,int displayId){throw unavailable();}
        long deadline(){throw unavailable();}
        String originalRun(){throw unavailable();}
        Map<String,Object> evidence(){throw unavailable();}
    }
    PendingObservation pendingObservation(){throw unavailable();}
    long boundedObservationDeadline(long taskDeadline,long now){throw unavailable();}
    NativeAppDomain domain(){throw unavailable();}
    PostEffectReadPermit postEffectReadPermit(ActionDecision action,String run,String observation){throw unavailable();}
    ReadRecoveryPermit observationRecoveryPermit(ActionDecision action,String run,String observation){throw unavailable();}
    ActionGuard actionGuard(ActionDecision action,String run,String observation,long issued,long deadline)throws ActionDecision.InvalidActionException{throw unavailable();}
    void requireModelPlanning(){throw unavailable();}
    void verifyInstalled()throws Exception{throw unavailable();}
    void observed(NativeAppEvidence.Frame frame)throws Exception{throw unavailable();}
    void beforeModelAction(int step,ActionDecision action,String run,long now)throws Exception{throw unavailable();}
    void modelActionOutcome(ActionDecision action,String run,boolean accepted,boolean dispatched,
            boolean stale,String receiptSha,long finished)throws Exception{throw unavailable();}
    void modelActionOutcome(ActionDecision action,String run,boolean accepted,boolean dispatched,
            boolean stale,String receiptSha,long finished,Map<String,Object> actionExecution)throws Exception{throw unavailable();}
    void retire()throws Exception{throw unavailable();}
    private static UnsupportedOperationException unavailable(){
        return new UnsupportedOperationException("Native App session is not executed by legacy host suites");
    }
    NativeAppDomain domainFor(NotesCompletionEvidence.Frame frame){throw unavailable();}
    boolean ready(NotesCompletionEvidence.Frame frame){throw unavailable();}
    Object acceptSuccess(int step,String run,NotesCompletionEvidence.Frame frame,boolean stable){throw unavailable();}
    Map<String,Object> promptEvidence(){throw unavailable();}
    Map<String,Object> evidence(){throw unavailable();}
    Map<String,Object> resultRecord(){throw unavailable();}
    List<String> missing(){throw unavailable();}
    Map<String,Object> terminal(NotesCompletionEvidence.Frame frame,TaskAuthorization.Frame owner,
            int step,String run,boolean modelSuccess,boolean allCleanupKnown,boolean backgroundReleased,
            boolean scopeRechecked,boolean installedRechecked,boolean cancelled,boolean processStarted,
            boolean processExitObserved,Integer exitCode,boolean receiptValid,String workerTask,
            String workerGeneration,String workerReceiptSha){throw unavailable();}
    Map<String,Object> terminal(NotesCompletionEvidence.Frame frame,TaskAuthorization.Frame owner,
            int step,String run,boolean modelSuccess,boolean allCleanupKnown,boolean backgroundReleased,
            boolean scopeRechecked,boolean installedRechecked,boolean cancelled,boolean processStarted,
            boolean processExitObserved,Integer exitCode,boolean receiptValid,String workerTask,
            String workerGeneration,String workerReceiptSha,Map<String,Object> profileCleanup){throw unavailable();}
}

