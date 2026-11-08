package org.trillionnium.hepta.localprobe;

import android.app.Application;

/** Application lifetime owner: Activity instances do not create independent model workers. */
public final class LocalProbeApplication extends Application {
    private LocalModelEngine model;
    private LocalTaskSession tasks;
    public synchronized LocalModelEngine modelEngine() {
        if (model == null) model = new LocalModelEngine(this);
        return model;
    }
    public synchronized LocalTaskSession taskSession() {
        if (tasks == null) tasks = new LocalTaskSession(this, modelEngine());
        return tasks;
    }
    @Override public void onTerminate() {
        if (model != null) model.close();
        super.onTerminate();
    }
}
