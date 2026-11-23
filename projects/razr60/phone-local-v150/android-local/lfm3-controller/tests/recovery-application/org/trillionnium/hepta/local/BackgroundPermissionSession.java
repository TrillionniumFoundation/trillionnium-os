package org.trillionnium.hepta.local;

/** Explicit state fixture. Does not run the production permission Session or spawn su. */
public final class BackgroundPermissionSession {
    static boolean initialBlocked;
    boolean blocked=initialBlocked,running,closed;
    int starts;
    LocalModelEngine.ExternalRunLease lease;
    private final LocalModelEngine model;
    BackgroundPermissionSession(android.content.Context ignored,LocalModelEngine model){this.model=model;}
    public boolean isBlocked(){return blocked;}
    public boolean isRunning(){return running;}
    public boolean blocksOtherWork(){return blocked||running;}
    void startFromOwnerButton(){
        if(closed||blocksOtherWork()||model.isBusy())throw new IllegalStateException("permission fixture occupied");
        // Exact production ExternalRunLease owns the slot; only Session lifecycle/IO is fake.
        lease=model.reserveExternal(java.util.UUID.randomUUID().toString().replace("-",""));
        running=true;starts++;
    }
    void observeNoStartAndPublishTerminal(){
        if(lease==null)throw new IllegalStateException("no owned fixture reservation");
        lease.releaseAfterTerminalPublication(true);lease=null;running=false;
    }
    public void close(){closed=true;if(lease!=null)lease.cancel();}
}
