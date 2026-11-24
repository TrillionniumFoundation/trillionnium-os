package org.trillionnium.hepta.local;

import android.app.Application;

public final class LocalProbeApplication extends Application {
    private LocalModelEngine model;
    private LocalTaskSession tasks;
    private LocalModelSettings modelSettings;
    private LocalModelImport modelImport;
    private MobiMindModelEngine visualDiagnostic;
    private UiVenusModelEngine uiVenusDiagnostic;
    private volatile BackgroundPermissionSession backgroundPermission;
    private volatile boolean permissionInitialized;
    private LocalModelEngine.RecoveryBarrier recoveryBarrier;
    private LocalModelEngine.RecoveryReservation controlRecoveryAttempt;
    private BackgroundRecoveryReservation backgroundRecoveryAttempt;
    private boolean backgroundRecoveryCloseFailed;
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
    public synchronized BackgroundPermissionSession backgroundPermissionPreparation(){initializeSessions();return backgroundPermission;}
    /** Does not initialize recursively when queried by the model constructor/startup inspection. */
    boolean permissionPreparationBlocksWork(){return !permissionInitialized||backgroundPermission==null||backgroundPermission.blocksOtherWork();}
    static boolean permissionPreparationBlocks(android.content.Context context){
        android.content.Context app=context.getApplicationContext();
        return !(app instanceof LocalProbeApplication)||((LocalProbeApplication)app).permissionPreparationBlocksWork();
    }
    static void requirePermissionPreparationIdle(android.content.Context context){
        if(permissionPreparationBlocks(context))throw new IllegalStateException("后台权限准备仍在运行或其进程退出未确认");
    }
    void prepareBackgroundPermissionFromOwnerButton(){
        recoveryMainThread();initializeSessions();
        if(tasks.isRunning()||tasks.isBlocked()||tasks.isRecovering()||tasks.hasBackgroundLease()||model.isBusy()||!otherDiagnosticsClean())
            throw new IllegalStateException("请先结束当前任务、诊断或原后台空间；权限准备不会清除这些状态");
        backgroundPermission.startFromOwnerButton();
    }

    synchronized LocalModelSettings modelSettings(){initializeSessions();return modelSettings;}
    synchronized LocalModelImport modelImport(){initializeSessions();return modelImport;}
    boolean canImportLocalModel(){
        recoveryMainThread();initializeSessions();
        try{requireModelImportIdle(HeptaAccessibilityService.connected());
            return !modelImport.isBusy()&&!modelSettings.isBusy()&&model.settingsAdmissionAvailable(false);
        }catch(RuntimeException unavailable){return false;}
    }
    void requireModelImportIdle(HeptaAccessibilityService expected){
        recoveryMainThread();initializeSessions();
        if(HeptaAccessibilityService.connected()!=expected||(expected!=null&&!expected.modelSettingsIdle())
                ||tasks.isRunning()||tasks.isBlocked()||tasks.isRecovering()||tasks.hasBackgroundLease()
                ||!otherDiagnosticsClean()||recoveryBarrier!=null||controlRecoveryAttempt!=null||controlRecoveryCallbackFailed)
            throw new IllegalStateException("请先结束任务并清理后台空间，再导入模型文件");
    }
    boolean canChangeLocalModelSettings(boolean restore){
        recoveryMainThread();initializeSessions();
        try{
            requireModelSettingsIdle(HeptaAccessibilityService.connected());
            return !modelSettings.isBusy()&&(!restore||modelSettings.restoreAvailable())&&model.settingsAdmissionAvailable(restore);
        }catch(RuntimeException unavailable){return false;}
    }
    void requireModelSettingsIdle(HeptaAccessibilityService expected){
        recoveryMainThread();initializeSessions();
        if(expected==null||HeptaAccessibilityService.connected()!=expected||!expected.modelSettingsIdle()
                ||tasks.isRunning()||tasks.isBlocked()||tasks.isRecovering()||tasks.hasBackgroundLease()
                ||!otherDiagnosticsClean()||recoveryBarrier!=null||controlRecoveryAttempt!=null||controlRecoveryCallbackFailed)
            throw new IllegalStateException("任务、后台空间、模型队列或屏幕读写尚未空闲；模型设置未开始");
    }

    private static void recoveryMainThread(){
        if(android.os.Looper.myLooper()!=android.os.Looper.getMainLooper())
            throw new IllegalStateException("control recovery must run on the app main thread");
    }
    private boolean otherDiagnosticsClean(){
        return !permissionPreparationBlocksWork()&&!visualDiagnostic.isBlocked()&&!visualDiagnostic.isBusy()
                &&!uiVenusDiagnostic.isBlocked()&&!uiVenusDiagnostic.isBusy();
    }
    private boolean controlRecoveryEligible(){
        return !tasks.isRunning()&&otherDiagnosticsClean()
                &&backgroundRecoveryAttempt==null&&!backgroundRecoveryCloseFailed
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

    /** Read-only explanation after the UI has queried the existing admission gate. */
    synchronized String controlRecoveryUnavailableReason(){
        recoveryMainThread();initializeSessions();
        if(controlRecoveryCallbackFailed)return "上次恢复的收尾状态未确认，当前不能建立新会话。详情见高级诊断。";
        if(controlRecoveryAttempt!=null)return "上次中断核验仍在收尾，完成后才能建立新会话。";
        if(tasks.isRunning())return "当前任务仍在运行，请先停止任务并等待退出。";
        if(permissionPreparationBlocksWork())return "后台权限核验仍在运行或退出未确认，请先处理后台权限状态。";
        if(visualDiagnostic.isBusy()||visualDiagnostic.isBlocked())return "本地视觉诊断仍在运行或退出未确认，请先处理该诊断。";
        if(uiVenusDiagnostic.isBusy()||uiVenusDiagnostic.isBlocked())return "UiVenus 诊断仍在运行或退出未确认，请先处理该诊断。";
        if(backgroundRecoveryAttempt!=null)return "后台空间核验仍在收尾，完成后才能确认中断。";
        if(backgroundRecoveryCloseFailed)return "后台空间核验的收尾状态未确认，当前不能建立新会话。详情见高级诊断。";
        if(!tasks.isBlocked()&&recoveryBarrier==null)return "当前没有待确认的中断会话。";
        if(recoveryBarrier==null?model.isBusy():!model.canReserveRecovery(recoveryBarrier))
            return "本地推理或进程核验尚未空闲，当前不能建立新会话。";
        return null;
    }

    /**
     * A background-absence check borrows the same no-child process slot, but can
     * only return it to the original interrupted-session barrier. It has no
     * commit, child attachment, journal acknowledgement or task-resume API.
     */
    final class BackgroundRecoveryReservation implements AutoCloseable {
        private final LocalModelEngine.RecoveryBarrier barrier;
        private final LocalModelEngine.RecoveryReservation reservation;
        private boolean closed;
        private BackgroundRecoveryReservation(LocalModelEngine.RecoveryBarrier barrier,
                LocalModelEngine.RecoveryReservation reservation){
            this.barrier=barrier;this.reservation=reservation;
        }
        /** May run on the serial recovery worker; every admission remains exclusive. */
        void check(){
            synchronized(LocalProbeApplication.this){
                if(closed||backgroundRecoveryAttempt!=this||recoveryBarrier!=barrier
                        ||backgroundRecoveryCloseFailed||controlRecoveryAttempt!=null
                        ||controlRecoveryCallbackFailed||!tasks.isBlocked()||tasks.isRunning()
                        ||!otherDiagnosticsClean()||modelSettings.isBusy()||modelImport.isBusy())
                    throw new IllegalStateException("background recovery no longer owns a drained blocked session");
                model.requireBackgroundRecoveryQuiescent(reservation);
            }
        }
        /** Failure and success both retain the barrier for a separate owner acknowledgement. */
        @Override public void close(){
            synchronized(LocalProbeApplication.this){
                if(closed)return;
                closed=true;
                boolean returned=false;
                try{
                    boolean same=backgroundRecoveryAttempt==this&&recoveryBarrier==barrier;
                    reservation.close();
                    if(!same||!model.backgroundRecoveryReturnedToBarrier(reservation))
                        throw new IllegalStateException("background recovery did not return its original barrier");
                    returned=true;
                }finally{
                    if(returned)backgroundRecoveryAttempt=null;
                    else backgroundRecoveryCloseFailed=true;
                }
            }
        }
    }

    /** Called only by the ordinary cleanup owner path, on the main thread. */
    synchronized BackgroundRecoveryReservation reserveBackgroundRecovery(){
        recoveryMainThread();initializeSessions();
        if(backgroundRecoveryAttempt!=null||backgroundRecoveryCloseFailed
                ||controlRecoveryAttempt!=null||controlRecoveryCallbackFailed
                ||!tasks.isBlocked()||tasks.isRunning()||!otherDiagnosticsClean()
                ||modelSettings.isBusy()||modelImport.isBusy())
            throw new IllegalStateException("background recovery or another local operation is not quiescent");
        if(recoveryBarrier==null)recoveryBarrier=model.reserveRecoveryBarrier();
        final LocalModelEngine.RecoveryReservation reservation=model.reserveRecovery(recoveryBarrier);
        final BackgroundRecoveryReservation value=new BackgroundRecoveryReservation(recoveryBarrier,reservation);
        backgroundRecoveryAttempt=value;
        try{value.check();return value;}
        catch(RuntimeException error){
            try{value.close();}catch(RuntimeException close){error.addSuppressed(close);}
            throw error;
        }
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
        backgroundPermission = new BackgroundPermissionSession(this,model);
        permissionInitialized = true;
        DiagnosticStartupGate gate = new DiagnosticStartupGate(tasks.isBlocked(), visualDiagnostic.isBlocked(), uiVenusDiagnostic.isBlocked());
        gate.apply(() -> recoveryBarrier = model.reserveRecoveryBarrier());
        initialized = true;
        modelSettings = new LocalModelSettings(this,model);
        modelImport = new LocalModelImport(this,model);
    }

    @Override public void onTerminate() {
        if(modelImport!=null)modelImport.close();
        if(modelSettings!=null)modelSettings.close();
        if(backgroundPermission!=null)backgroundPermission.close();
        if (visualDiagnostic != null) visualDiagnostic.close();
        if (uiVenusDiagnostic != null) uiVenusDiagnostic.close();
        if (model != null) model.close();
        super.onTerminate();
    }
}

