package org.trillionnium.hepta.local;

import android.app.Application;

public final class LocalProbeApplication extends Application {
    private LocalModelEngine model;
    private LocalTaskSession tasks;
    private MobiMindModelEngine visualDiagnostic;
    private UiVenusModelEngine uiVenusDiagnostic;
    private LocalModelEngine.RecoveryBarrier recoveryBarrier;
    private LocalModelEngine.RecoveryReservation controlRecoveryAttempt;
    private boolean controlRecoveryCallbackFailed;
    private boolean reconcilingRecoveryClose;
    private boolean initialized;

    @Override public void onCreate() {
        super.onCreate();
        initializeSessions();
    }

    public synchronized LocalModelEngine modelEngine() {
        initializeSessions();
        return model;
    }

    public synchronized LocalTaskSession taskSession() {
        initializeSessions();
        return tasks;
    }

    public synchronized MobiMindModelEngine mobiMindDiagnostic() {
        initializeSessions();
        return visualDiagnostic;
    }

    public synchronized UiVenusModelEngine uiVenusDiagnostic() {
        initializeSessions();
        return uiVenusDiagnostic;
    }

    private static void recoveryMainThread(){
        if(android.os.Looper.myLooper()!=android.os.Looper.getMainLooper())
            throw new IllegalStateException("control recovery must run on the app main thread");
    }
    private boolean otherDiagnosticsClean(){
        return !visualDiagnostic.isBlocked()&&!visualDiagnostic.isBusy()
                &&!uiVenusDiagnostic.isBlocked()&&!uiVenusDiagnostic.isBusy();
    }
    private boolean controlRecoveryEligible(){
        return !tasks.isRunning()&&otherDiagnosticsClean()
                &&(tasks.isBlocked()||recoveryBarrier!=null);
    }


    /** Reconcile an actual close receipt, never just the earlier commit intent. */
    private void reconcileControlRecoveryClose(){
        LocalModelEngine.RecoveryReservation reservation=controlRecoveryAttempt;
        if(reconcilingRecoveryClose||controlRecoveryCallbackFailed||reservation==null||!reservation.isCloseFinished())return;
        if(!reservation.belongsTo(recoveryBarrier)){
            controlRecoveryCallbackFailed=true;
            return;
        }
        if(reservation.wasReleased()){
            recoveryBarrier=null;
            controlRecoveryAttempt=null;
            return;
        }
        reconcilingRecoveryClose=true;
        try{
            tasks.recoveryLeaseRetained();
            controlRecoveryAttempt=null;
        }catch(RuntimeException failure){
            // Keep both references and deny another borrow if the blocked-state callback failed.
            controlRecoveryCallbackFailed=true;
        }finally{
            reconcilingRecoveryClose=false;
        }
    }
    private void recoveryClosed(final LocalModelEngine.RecoveryBarrier barrier,
            final LocalModelEngine.RecoveryReservation reservation){
        Runnable reconcile=new Runnable(){@Override public void run(){
            synchronized(LocalProbeApplication.this){
                if(recoveryBarrier==barrier&&controlRecoveryAttempt==reservation)
                    reconcileControlRecoveryClose();
            }
        }};
        if(android.os.Looper.myLooper()==android.os.Looper.getMainLooper())reconcile.run();
        else{
            // If the main looper refuses the post, keep the references. A later main-thread
            // eligibility/reservation entry can reconcile the immutable close receipt.
            new android.os.Handler(android.os.Looper.getMainLooper()).post(reconcile);
        }
    }

    /** Never acknowledges a journal or releases a slot; it may reconcile an already closed attempt. */
    public synchronized boolean canAcknowledgeControlRecovery(){
        recoveryMainThread();initializeSessions();reconcileControlRecoveryClose();
        if(controlRecoveryCallbackFailed||controlRecoveryAttempt!=null||!controlRecoveryEligible())return false;
        return recoveryBarrier==null?!model.isBusy():model.canReserveRecovery(recoveryBarrier);
    }

    /** Only an explicit control confirmation can borrow this Application's aggregate barrier. */
    public synchronized LocalModelEngine.RecoveryReservation reserveControlRecovery(){
        recoveryMainThread();initializeSessions();reconcileControlRecoveryClose();
        if(controlRecoveryCallbackFailed||controlRecoveryAttempt!=null||!controlRecoveryEligible())
            throw new IllegalStateException("control recovery or another diagnostic is not quiescent");
        if(recoveryBarrier==null)recoveryBarrier=model.reserveRecoveryBarrier();
        final LocalModelEngine.RecoveryBarrier barrier=recoveryBarrier;
        LocalModelEngine.RecoveryReservation reservation=model.reserveRecovery(barrier);
        controlRecoveryAttempt=reservation;
        try{
            reservation.setCloseListener(closed -> recoveryClosed(barrier,closed));
            return reservation;
        }catch(RuntimeException failure){
            reservation.close();
            throw failure;
        }
    }

    /**
     * The callback freshly verifies persisted READY proof and installs the new idle session.
     * Any exception or cancellation leaves the barrier retained when the reservation closes.
     */
    public synchronized void completeControlRecovery(LocalModelEngine.RecoveryReservation reservation,
            RecoveryJournalTransaction.Proof proof,Runnable installNewSession){
        recoveryMainThread();initializeSessions();
        LocalModelEngine.RecoveryBarrier barrier=recoveryBarrier;
        if(reservation==null||reservation!=controlRecoveryAttempt||controlRecoveryCallbackFailed
                ||proof==null||installNewSession==null||barrier==null||!controlRecoveryEligible())
            throw new IllegalStateException("control recovery completion is not eligible");
        reservation.requireOwnedBy(barrier);
        RecoveryJournalTransaction.Acknowledgement ack=proof.acknowledgement;
        if(ack==null||ack.uid!=android.os.Process.myUid()||ack.uid!=getApplicationInfo().uid
                ||!reservation.transactionId().equals(ack.transactionId)
                ||ack.sessionId==null||ack.sessionId.equals(ack.transactionId)
                ||!ack.sessionId.matches("[0-9a-f]{32}")
                ||proof.newIdleSha256==null||!proof.newIdleSha256.matches("[0-9a-f]{64}")
                ||proof.commitSha256==null||!proof.commitSha256.matches("[0-9a-f]{64}"))
            throw new IllegalStateException("recovery proof belongs to another confirmation");
        installNewSession.run();
        if(tasks.isRunning()||!otherDiagnosticsClean())
            throw new IllegalStateException("another session changed during control recovery installation");
        reservation.requireOwnedBy(barrier);
        reservation.commit(barrier);
        // Keep Application ownership until close actually releases, or returns, this barrier.
    }

    private synchronized void initializeSessions() {
        if (initialized) return;
        if (model != null) throw new IllegalStateException("session initialization was interrupted");
        model = new LocalModelEngine(this);
        tasks = new LocalTaskSession(this, model);
        visualDiagnostic = new MobiMindModelEngine(this, model);
        uiVenusDiagnostic = new UiVenusModelEngine(this, model);
        DiagnosticStartupGate gate = new DiagnosticStartupGate(tasks.isBlocked(), visualDiagnostic.isBlocked(), uiVenusDiagnostic.isBlocked());
        gate.apply(() -> recoveryBarrier = model.reserveRecoveryBarrier());
        initialized = true;
    }

    @Override public void onTerminate() {
        if (visualDiagnostic != null) visualDiagnostic.close();
        if (uiVenusDiagnostic != null) uiVenusDiagnostic.close();
        if (model != null) model.close();
        super.onTerminate();
    }
}
