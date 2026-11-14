package org.trillionnium.hepta.local;
public final class LocalTaskSession {
    static boolean initialBlocked=true;
    boolean blocked=initialBlocked,running,recovering,backgroundLease;
    int retainedCalls;
    boolean failRetained;
    Runnable duringRetained;
    public LocalTaskSession(android.content.Context ignored,LocalModelEngine engine){}
    public boolean isBlocked(){return blocked;}
    public boolean isRunning(){return running;}
    public boolean isRecovering(){return recovering;}
    public boolean hasBackgroundLease(){return backgroundLease;}
    void recoveryLeaseRetained(){
        retainedCalls++;blocked=true;
        if(duringRetained!=null)duringRetained.run();
        if(failRetained)throw new IllegalStateException("injected retained callback failure");
    }
}
