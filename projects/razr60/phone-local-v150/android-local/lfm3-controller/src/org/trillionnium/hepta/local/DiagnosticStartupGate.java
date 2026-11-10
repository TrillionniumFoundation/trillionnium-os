package org.trillionnium.hepta.local;

/** One Application-level reservation after every session has been inspected. No replay or reset. */
public final class DiagnosticStartupGate {
    public interface Reservation {void hold();}
    private boolean applied;
    private final boolean blocked;
    public DiagnosticStartupGate(boolean controlBlocked,boolean mobiBlocked,boolean venusBlocked){
        blocked=controlBlocked||mobiBlocked||venusBlocked;
    }
    public boolean isBlocked(){return blocked;}
    public synchronized void apply(Reservation reservation){
        if(reservation==null)throw new IllegalArgumentException("reservation required");
        if(applied)throw new IllegalStateException("startup gate already applied");
        // Mark before the callback: a failed reservation is not permission to attempt a second lease.
        applied=true;if(blocked)reservation.hold();
    }
}
