package org.trillionnium.hepta.local;

import java.util.List;
import java.util.Map;

/** Type-only Android/installed-App/session boundary for pre-existing non-native
 * host suites. No instance can be created and every operation throws.
 * New native provider/session gates must compile the actual production class. */
final class NativeAppSession {
    final String taskId=null;
    final NativeAppGoal goal=null;
    final BackgroundTaskTarget target=null;
    final BackgroundTaskTarget.SelectionBinding selection=null;
    final TaskAuthorization.Gate authorization=null;
    interface Journal {void write(String leaf,Map<String,Object> value)throws Exception;}
    interface InstalledVerifier {void verify()throws Exception;}
    private NativeAppSession(){throw unavailable();}
    NativeAppSession(String task,TaskAuthorization.Gate auth,BackgroundTaskTarget.SelectionBinding selected,
            NativeAppEvidence.Installed installed,String selectionSha,String generation,int display,
            InstalledVerifier verifier,Journal journal)throws Exception{throw unavailable();}
    void verifyInstalled()throws Exception{throw unavailable();}
    void observed(NativeAppEvidence.Frame frame)throws Exception{throw unavailable();}
    void beforeModelAction(int step,ActionDecision action,String run,long now)throws Exception{throw unavailable();}
    void modelActionOutcome(ActionDecision action,String run,boolean accepted,boolean dispatched,
            boolean stale,String receiptSha,long finished)throws Exception{throw unavailable();}
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
}
