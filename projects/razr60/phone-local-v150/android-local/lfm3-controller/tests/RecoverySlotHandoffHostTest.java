import org.trillionnium.hepta.local.RecoverySlotHandoff;
import java.util.concurrent.atomic.AtomicReference;

/** Faults exercise the production ownership state machine, not an Android/procfs substitute. */
public final class RecoverySlotHandoffHostTest {
    private static int cases,assertions;
    private static final class Token {
        final String label;
        Token(String label){this.label=label;}
        @Override public boolean equals(Object other){return other instanceof Token;}
        @Override public int hashCode(){return 1;}
    }
    private static final class Slot implements RecoverySlotHandoff.Slot<Token> {
        final AtomicReference<Token> value=new AtomicReference<Token>();
        int casCalls,failAt=-1,emptyPublications;
        Token faultValue;
        boolean releaseAllowed;
        Slot sharedWitness;
        boolean localChangedWhileSharedEmpty;
        @Override public Token get(){return value.get();}
        @Override public boolean compareAndSet(Token expected,Token replacement){
            casCalls++;
            if(casCalls==failAt)value.set(faultValue);
            if(sharedWitness!=null&&sharedWitness.get()==null)localChangedWhileSharedEmpty=true;
            boolean ok=value.compareAndSet(expected,replacement);
            if(ok&&replacement==null&&!releaseAllowed)emptyPublications++;
            return ok;
        }
        void faultNext(Token replacement){failAt=casCalls+1;faultValue=replacement;}
    }
    private static final class Fixture {
        final Slot shared=new Slot(),local=new Slot();
        final Token barrier=new Token("barrier");
        final RecoverySlotHandoff<Token> handoff;
        Fixture(){
            handoff=RecoverySlotHandoff.acquire(shared,local,barrier);
            local.sharedWitness=shared;
        }
        void held(Token token){same(shared.get(),token,"shared owner");same(local.get(),token,"local owner");}
        void closed(){check(shared.get()!=null,"shared remains closed");check(shared.emptyPublications==0,"no unauthorized shared empty publication");}
        void releaseAllowed(){shared.releaseAllowed=true;local.releaseAllowed=true;}
    }
    private interface Checked {void run();}
    private static void check(boolean yes,String message){assertions++;if(!yes)throw new AssertionError(message);}
    private static void same(Object a,Object b,String message){check(a==b,message);}
    private static void throwsState(Checked work){
        boolean seen=false;try{work.run();}catch(IllegalStateException expected){seen=true;}
        check(seen,"expected ownership rejection");
    }
    private static void throwsArgument(Checked work){
        boolean seen=false;try{work.run();}catch(IllegalArgumentException expected){seen=true;}
        check(seen,"expected argument rejection");
    }
    private static void run(String name,Checked test){test.run();cases++;System.out.println("PASS "+name);}
    public static void main(String[] args){
        run("aggregate_barrier_blocks_competitors",()->{
            Fixture f=new Fixture();f.held(f.barrier);
            check(!f.shared.compareAndSet(null,new Token("competitor")),"competitor denied");f.closed();
        });
        run("shared_owner_not_overwritten_on_acquisition",()->{
            Slot s=new Slot(),l=new Slot();Token foreign=new Token("foreign");s.value.set(foreign);
            throwsState(()->RecoverySlotHandoff.acquire(s,l,new Token("barrier")));
            same(s.get(),foreign,"foreign shared retained");same(l.get(),null,"no local claim");
        });
        run("local_acquisition_conflict_keeps_shared_closed",()->{
            Slot s=new Slot(),l=new Slot();Token foreign=new Token("foreign"),barrier=new Token("barrier");l.value.set(foreign);
            throwsState(()->RecoverySlotHandoff.acquire(s,l,barrier));
            same(s.get(),barrier,"new shared barrier retained");same(l.get(),foreign,"foreign local retained");
        });
        run("invalid_acquisition_changes_neither_slot",()->{
            Slot s=new Slot(),l=new Slot();
            throwsArgument(()->RecoverySlotHandoff.acquire(s,l,null));
            throwsArgument(()->RecoverySlotHandoff.acquire(s,s,new Token("b")));
            same(s.get(),null,"shared unchanged");same(l.get(),null,"local unchanged");
        });
        run("borrow_has_no_empty_shared_interval",()->{
            Fixture f=new Fixture();Token h=new Token("first");
            RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(h);f.held(h);
            check(a.isOwned(),"attempt owned");check(!f.local.localChangedWhileSharedEmpty,"handoff never opens shared");
            f.closed();a.close();f.held(f.barrier);check(f.handoff.canBorrow(),"failure is retryable");
        });
        run("fresh_handle_identity_required",()->{
            Fixture f=new Fixture();throwsArgument(()->f.handoff.borrow(null));throwsArgument(()->f.handoff.borrow(f.barrier));
            f.held(f.barrier);check(f.handoff.canBorrow(),"bad argument leaves barrier reusable");
        });
        run("one_attempt_at_a_time",()->{
            Fixture f=new Fixture();Token h=new Token("first");RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(h);
            throwsState(()->f.handoff.borrow(new Token("second")));f.held(h);check(a.isOwned(),"first still owned");a.close();f.closed();
        });
        run("failed_attempt_returns_original_barrier",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("first"));
            a.close();a.close();f.held(f.barrier);check(f.handoff.canBorrow(),"same barrier reusable");f.closed();
        });
        run("closed_old_attempt_cannot_release_retry",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt old=f.handoff.borrow(new Token("old"));old.close();
            Token fresh=new Token("fresh");RecoverySlotHandoff<Token>.Attempt next=f.handoff.borrow(fresh);
            old.close();f.held(fresh);check(next.isOwned(),"fresh attempt survives old close");next.close();f.closed();
        });
        run("cancellation_revokes_prepared_release",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("cancelled"));
            a.commit();a.retainBarrierOnClose();a.close();f.held(f.barrier);f.closed();
            RecoverySlotHandoff<Token>.Attempt retry=f.handoff.borrow(new Token("fresh_uncancelled"));
            check(retry.isOwned(),"fresh retry admitted");retry.close();f.held(f.barrier);
        });
        run("committed_release_opens_only_after_local_change",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("approved"));a.commit();
            check(a.isOwned(),"commit alone retains ownership");f.releaseAllowed();a.close();
            same(f.local.get(),null,"local released");same(f.shared.get(),null,"shared released");
            check(!f.local.localChangedWhileSharedEmpty,"local transitions while shared occupied");
            check(!f.handoff.canBorrow(),"completed barrier cannot be reused");
        });
        run("old_successful_close_does_not_clear_new_owner",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("approved"));a.commit();f.releaseAllowed();a.close();
            Token foreign=new Token("new_model");f.shared.value.set(foreign);f.local.value.set(foreign);a.close();a.retainBarrierOnClose();f.held(foreign);
        });
        run("equal_but_distinct_handles_are_not_ownership",()->{
            Fixture f=new Fixture();Token h=new Token("a"),foreign=new Token("equal_but_different");
            RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(h);check(h.equals(foreign),"fixture equality");
            f.shared.value.set(foreign);check(!a.isOwned(),"ownership uses identity");
            throwsState(()->a.requireOwned());same(f.shared.get(),foreign,"foreign not overwritten");same(f.local.get(),f.barrier,"local retained");
        });
        run("foreign_shared_before_borrow_is_denied",()->{
            Fixture f=new Fixture();Token foreign=new Token("foreign");f.shared.value.set(foreign);
            throwsState(()->f.handoff.borrow(new Token("request")));same(f.shared.get(),foreign,"foreign preserved");f.closed();
        });
        run("foreign_local_before_borrow_is_denied",()->{
            Fixture f=new Fixture();Token foreign=new Token("foreign");f.local.value.set(foreign);
            throwsState(()->f.handoff.borrow(new Token("request")));same(f.local.get(),foreign,"foreign preserved");f.closed();
        });
        run("shared_handoff_cas_conflict_never_steals_foreign",()->{
            Fixture f=new Fixture();Token foreign=new Token("foreign");f.shared.faultNext(foreign);
            throwsState(()->f.handoff.borrow(new Token("request")));same(f.shared.get(),foreign,"foreign retained");
            same(f.local.get(),f.barrier,"local barrier retained");check(!f.handoff.canBorrow(),"fault poisons barrier");f.closed();
        });
        run("local_handoff_cas_conflict_returns_shared_barrier",()->{
            Fixture f=new Fixture();Token foreign=new Token("foreign");f.local.faultNext(foreign);
            throwsState(()->f.handoff.borrow(new Token("request")));same(f.shared.get(),f.barrier,"shared restored");
            same(f.local.get(),foreign,"foreign local retained");check(!f.handoff.canBorrow(),"fault poisons barrier");f.closed();
        });
        run("shared_handoff_unexpected_empty_is_reclosed",()->{
            Fixture f=new Fixture();f.shared.faultNext(null);
            throwsState(()->f.handoff.borrow(new Token("request")));f.held(f.barrier);
            check(!f.handoff.canBorrow(),"unknown identity is not reusable");f.closed();
        });
        run("local_handoff_unexpected_empty_is_reclosed",()->{
            Fixture f=new Fixture();f.local.faultNext(null);
            throwsState(()->f.handoff.borrow(new Token("request")));f.held(f.barrier);f.closed();
        });
        run("lost_shared_owner_on_close_keeps_foreign_and_barrier",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("request"));
            Token foreign=new Token("foreign");f.shared.value.set(foreign);throwsState(()->a.close());
            same(f.shared.get(),foreign,"foreign shared kept");same(f.local.get(),f.barrier,"local barrier kept");a.close();f.closed();
        });
        run("lost_local_owner_on_close_keeps_foreign_and_barrier",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("request"));
            Token foreign=new Token("foreign");f.local.value.set(foreign);throwsState(()->a.close());
            same(f.local.get(),foreign,"foreign local kept");same(f.shared.get(),f.barrier,"shared barrier kept");f.closed();
        });
        run("rollback_local_cas_failure_retains_global_barrier",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("request"));
            Token foreign=new Token("foreign");f.local.faultNext(foreign);throwsState(()->a.close());
            same(f.shared.get(),f.barrier,"shared barrier kept");same(f.local.get(),foreign,"foreign kept");f.closed();
        });
        run("rollback_shared_cas_failure_does_not_open_slot",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("request"));
            Token foreign=new Token("foreign");f.shared.faultNext(foreign);throwsState(()->a.close());
            same(f.shared.get(),foreign,"foreign kept");same(f.local.get(),f.barrier,"local barrier kept");f.closed();
        });
        run("committed_local_cas_failure_retains_barrier",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("request"));a.commit();
            Token foreign=new Token("foreign");f.local.faultNext(foreign);throwsState(()->a.close());
            same(f.shared.get(),f.barrier,"shared barrier kept");same(f.local.get(),foreign,"foreign kept");f.closed();
        });
        run("committed_shared_cas_failure_recloses_local_slot",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("request"));a.commit();f.releaseAllowed();
            Token foreign=new Token("foreign");f.shared.faultNext(foreign);throwsState(()->a.close());
            same(f.shared.get(),foreign,"foreign kept");same(f.local.get(),f.barrier,"local empty reclosed");
            check(!f.handoff.canBorrow(),"fault remains closed");
        });
        run("committed_shared_unexpected_empty_is_reclosed",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("request"));a.commit();f.releaseAllowed();
            f.shared.faultNext(null);throwsState(()->a.close());f.held(f.barrier);check(!f.handoff.canBorrow(),"fault remains closed");
        });
        run("lost_ownership_cannot_commit",()->{
            Fixture f=new Fixture();RecoverySlotHandoff<Token>.Attempt a=f.handoff.borrow(new Token("request"));
            f.shared.value.set(null);throwsState(()->a.commit());f.held(f.barrier);f.closed();
        });
        run("empty_shared_before_borrow_is_reclosed",()->{
            Fixture f=new Fixture();f.shared.value.set(null);
            throwsState(()->f.handoff.borrow(new Token("request")));f.held(f.barrier);
            check(!f.handoff.canBorrow(),"lost initial barrier remains poisoned");f.closed();
        });
        run("empty_local_before_borrow_is_reclosed",()->{
            Fixture f=new Fixture();f.local.value.set(null);
            throwsState(()->f.handoff.borrow(new Token("request")));f.held(f.barrier);
            check(!f.handoff.canBorrow(),"lost initial barrier remains poisoned");f.closed();
        });
        System.out.println("PASS cases="+cases+" assertions="+assertions);
    }
}
