package org.trillionnium.hepta.local;
public final class MobiMindModelEngine {
    static boolean initialBlocked;
    boolean blocked=initialBlocked,busy;
    public MobiMindModelEngine(android.content.Context ignored,LocalModelEngine engine){}
    public boolean isBlocked(){return blocked;}
    public boolean isBusy(){return busy;}
    public void close(){}
}
