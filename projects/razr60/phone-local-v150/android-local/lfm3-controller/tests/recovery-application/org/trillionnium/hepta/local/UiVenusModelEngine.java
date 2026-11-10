package org.trillionnium.hepta.local;
public final class UiVenusModelEngine {
    static boolean initialBlocked;
    boolean blocked=initialBlocked,busy;
    public UiVenusModelEngine(android.content.Context ignored,LocalModelEngine engine){}
    public boolean isBlocked(){return blocked;}
    public boolean isBusy(){return busy;}
    public void close(){}
}
