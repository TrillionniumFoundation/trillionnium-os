package org.trillionnium.hepta.local;

import android.app.Application;

/** Application lifetime owner: Activity instances do not create independent model workers. */
public final class LocalProbeApplication extends Application {
    private LocalModelEngine model;
    private LocalTaskSession tasks;
    private MobiMindModelEngine visualDiagnostic;
    private UiVenusModelEngine uiVenusDiagnostic;
    private LocalModelEngine.ExternalRunLease recoveryBarrier;
    private boolean initialized;
    @Override public void onCreate() {
        super.onCreate();
        // Inspect every old session before an Activity/service can reserve the shared slot.
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
        initializeSessions();return uiVenusDiagnostic;
    }
    /** All inspections complete synchronously before any accessor exposes the shared broker. */
    private synchronized void initializeSessions() {
        if (initialized) return;
        if (model != null) throw new IllegalStateException("session initialization was interrupted");
        model=new LocalModelEngine(this);
        tasks=new LocalTaskSession(this,model);
        visualDiagnostic=new MobiMindModelEngine(this,model);
        uiVenusDiagnostic=new UiVenusModelEngine(this,model);
        DiagnosticStartupGate gate=new DiagnosticStartupGate(tasks.isBlocked(),visualDiagnostic.isBlocked(),uiVenusDiagnostic.isBlocked());
        gate.apply(() -> recoveryBarrier=model.reserveExternal(java.util.UUID.randomUUID().toString().replace("-","")));
        initialized=true;
    }
    @Override public void onTerminate() {
        if (visualDiagnostic != null) visualDiagnostic.close();
        if (uiVenusDiagnostic != null) uiVenusDiagnostic.close();
        if (model != null) model.close();
        super.onTerminate();
    }
}
