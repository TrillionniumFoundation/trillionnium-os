package org.trillionnium.hepta.gpuprobe;
import android.app.Application;
/** One engine survives Activity recreation; stop retains the owned Process handle. */
public final class GpuProbeApplication extends Application {
    private LocalModelEngine engine;
    @Override public void onCreate(){super.onCreate();engine=new LocalModelEngine(this);}
    public LocalModelEngine engine(){return engine;}
}
