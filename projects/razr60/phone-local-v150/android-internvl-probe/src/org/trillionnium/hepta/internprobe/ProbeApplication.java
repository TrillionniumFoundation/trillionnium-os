package org.trillionnium.hepta.internprobe;

import android.app.Application;

/** One diagnostic engine for the application lifetime; Activities never own its process. */
public final class ProbeApplication extends Application {
    private LocalModelEngine engine;
    public synchronized LocalModelEngine modelEngine(){
        if(engine==null)engine=new LocalModelEngine(this);
        return engine;
    }
}
