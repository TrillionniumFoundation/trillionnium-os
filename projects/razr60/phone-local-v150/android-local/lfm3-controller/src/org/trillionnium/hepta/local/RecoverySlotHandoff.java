package org.trillionnium.hepta.local;

/**
 * Transfers an occupied no-child recovery slot without an intervening empty shared slot.
 * This is ownership only: it does not prove an old native exit or an Android process census.
 */
public final class RecoverySlotHandoff<T> {
    public interface Slot<T> {
        T get();
        boolean compareAndSet(T expected,T replacement);
    }
    private final Slot<T> shared,local;
    private final T barrier;
    private Attempt current;
    private boolean poisoned,completed;

    private RecoverySlotHandoff(Slot<T> shared,Slot<T> local,T barrier){
        if(shared==null||local==null||shared==local||barrier==null)
            throw new IllegalArgumentException("distinct slots and barrier are required");
        this.shared=shared;this.local=local;this.barrier=barrier;
    }

    /** Called only after all journal owners have been constructed and classified. */
    public static <T> RecoverySlotHandoff<T> acquire(Slot<T> shared,Slot<T> local,T barrier){
        RecoverySlotHandoff<T> owner=new RecoverySlotHandoff<T>(shared,local,barrier);
        if(!shared.compareAndSet(null,barrier))
            throw new IllegalStateException("another owner already holds the shared slot");
        if(!local.compareAndSet(null,barrier))
            throw owner.fail(null,"local recovery barrier ownership changed");
        return owner;
    }

    public synchronized boolean canBorrow(){
        return !poisoned&&!completed&&current==null
                &&shared.get()==barrier&&local.get()==barrier;
    }

    /** The caller supplies a fresh, uncancelled handle; an arbitrary external lease is never borrowed. */
    public synchronized Attempt borrow(T handle){
        if(handle==null||handle==barrier)throw new IllegalArgumentException("fresh recovery handle required");
        if(!canBorrow()){
            if(!poisoned&&!completed&&current==null)
                throw fail(null,"recovery barrier identity changed before handoff");
            throw new IllegalStateException("recovery barrier is unavailable");
        }
        Attempt attempt=new Attempt(handle);
        current=attempt;
        if(!shared.compareAndSet(barrier,handle))
            throw fail(handle,"shared recovery handoff ownership changed");
        if(!local.compareAndSet(barrier,handle))
            throw fail(handle,"local recovery handoff ownership changed");
        return attempt;
    }

    private boolean owns(Attempt attempt){
        return !poisoned&&!completed&&current==attempt&&!attempt.closed
                &&shared.get()==attempt.handle&&local.get()==attempt.handle;
    }

    private IllegalStateException fail(T handle,String message){
        poisoned=true;
        // Never overwrite a foreign non-null owner. If a failed CAS revealed an empty slot,
        // close that empty slot again. A violated ownership invariant is never made reusable.
        retain(shared,handle);retain(local,handle);
        return new IllegalStateException(message);
    }
    private void retain(Slot<T> slot,T handle){
        T observed=slot.get();
        if(observed==null||observed==handle)slot.compareAndSet(observed,barrier);
    }

    public final class Attempt implements AutoCloseable {
        private final T handle;
        private boolean committed,closed;
        private Attempt(T handle){this.handle=handle;}
        public boolean isOwned(){
            synchronized(RecoverySlotHandoff.this){return owns(this);}
        }
        public void requireOwned(){
            synchronized(RecoverySlotHandoff.this){
                if(!owns(this))throw fail(handle,"recovery attempt no longer owns both slots");
            }
        }
        /** Only the Application may authorize this after real proof verification and state installation. */
        public void commit(){
            synchronized(RecoverySlotHandoff.this){
                if(!owns(this))throw fail(handle,"cannot commit a lost recovery attempt");
                committed=true;
            }
        }
        public boolean wasReleased(){
            synchronized(RecoverySlotHandoff.this){
                return closed&&committed&&completed&&current==null;
            }
        }
        /** A cancellation or engine closure takes precedence over a prepared release. */
        public void retainBarrierOnClose(){
            synchronized(RecoverySlotHandoff.this){
                if(!closed)committed=false;
            }
        }
        @Override public void close(){
            synchronized(RecoverySlotHandoff.this){
                if(closed)return;
                if(!owns(this)){closed=true;throw fail(handle,"cannot close a lost recovery attempt");}
                closed=true;
                T replacement=committed?null:barrier;
                // The global slot stays occupied while the local cancellation view changes.
                if(!local.compareAndSet(handle,replacement))
                    throw fail(handle,"local recovery completion ownership changed");
                if(!shared.compareAndSet(handle,replacement))
                    throw fail(handle,"shared recovery completion ownership changed");
                current=null;
                if(committed)completed=true;
            }
        }
    }
}
