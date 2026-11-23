package org.trillionnium.hepta.local;

import android.app.Application;

/** Application lifetime owner: Activity instances do not create independent model workers. */
public final class LocalProbeApplication extends Application {
    private LocalModelEngine model;
    private LocalTaskSession tasks;
    private MobiMindModelEngine visualDiagnostic;
    @Override public void onCreate() {
        super.onCreate();
        // Inspect a previous visual diagnostic before any Activity or service can
        // reserve the shared local-model process slot. Never replay an old request.
        mobiMindDiagnostic();
    }
    public synchronized LocalModelEngine modelEngine() {
        if (model == null) model = new LocalModelEngine(this);
        return model;
    }
    public synchronized LocalTaskSession taskSession() {
        if (tasks == null) tasks = new LocalTaskSession(this, modelEngine());
        return tasks;
    }
    public synchronized MobiMindModelEngine mobiMindDiagnostic() {
        if (visualDiagnostic == null) visualDiagnostic = new MobiMindModelEngine(this, modelEngine());
        return visualDiagnostic;
    }
    @Override public void onTerminate() {
        if (visualDiagnostic != null) visualDiagnostic.close();
        if (model != null) model.close();
        super.onTerminate();
    }
}
