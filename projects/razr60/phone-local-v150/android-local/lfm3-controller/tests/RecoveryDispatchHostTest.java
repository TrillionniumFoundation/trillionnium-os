import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import org.trillionnium.hepta.local.RecoveryDispatch;

public final class RecoveryDispatchHostTest {
    static int assertions;
    static void check(boolean yes,String label){assertions++;if(!yes)throw new AssertionError(label);}
    static final Executor DIRECT=Runnable::run;
    static final class Lease implements RecoveryDispatch.Lease {int closes;boolean fail;public void close(){closes++;if(fail)throw new IllegalStateException("injected close failure");}}
    static void normalAndErrors()throws Exception{
        Lease good=new Lease();final int[] done={0};
        RecoveryDispatch.start(()->good,DIRECT,DIRECT,()->42,(value,failure)->{check(value==42&&failure==null,"normal result");check(good.closes==0,"lease held through UI callback");done[0]++;});
        check(good.closes==1&&done[0]==1,"normal closes once");
        Lease work=new Lease();RecoveryDispatch.start(()->work,DIRECT,DIRECT,()->{throw new Exception("work");},(value,failure)->check(failure!=null,"work failure delivered"));check(work.closes==1,"work exception closes");
        Lease callback=new Lease();RecoveryDispatch.start(()->callback,DIRECT,DIRECT,()->1,(value,failure)->{throw new Exception("UI callback");});check(callback.closes==1,"UI callback exception closes");
        Lease duplicate=new Lease();final int[] ran={0},callbacks={0};Executor twice=r->{r.run();r.run();};
        RecoveryDispatch.start(()->duplicate,twice,twice,()->{ran[0]++;return 1;},(v,e)->callbacks[0]++);
        check(ran[0]==1&&callbacks[0]==1&&duplicate.closes==1,"duplicate executor callback cannot replay transaction or release twice");
        for(boolean worker:new boolean[]{true,false}){
            Lease l=new Lease();Executor reject=r->{throw new RejectedExecutionException("submit");};boolean threw=false;
            try{RecoveryDispatch.start(()->l,worker?reject:DIRECT,worker?DIRECT:reject,()->1,(v,e)->{});}catch(RejectedExecutionException expected){threw=true;}
            check(threw&&l.closes==1,(worker?"worker":"UI")+" submission failure closes own lease");
        }
        final int[] acquireCalls={0};boolean acquireFailed=false;
        try{RecoveryDispatch.start(()->{acquireCalls[0]++;throw new Exception("not owner");},DIRECT,DIRECT,()->1,(v,e)->{throw new AssertionError("callback without lease");});}catch(Exception expected){acquireFailed=true;}
        check(acquireFailed&&acquireCalls[0]==1,"acquire failure never starts work");
        Lease fatal=new Lease();boolean fatalThrown=false;
        try{RecoveryDispatch.start(()->fatal,DIRECT,DIRECT,()->{throw new AssertionError("fatal");},(v,e)->{});}catch(AssertionError expected){fatalThrown=true;}
        check(fatalThrown&&fatal.closes==1,"fatal worker error still releases before propagation");
        Lease close=new Lease();close.fail=true;boolean closeThrown=false;
        try{RecoveryDispatch.start(()->close,DIRECT,DIRECT,()->1,(v,e)->{});}catch(IllegalStateException expected){closeThrown=true;}
        check(closeThrown&&close.closes==1,"release error is not retried against another owner");
        Lease unrelated=new Lease();check(unrelated.closes==0,"unrelated lease untouched");
    }
    public static void main(String[] args)throws Exception{normalAndErrors();System.out.println("RecoveryDispatchHostTest assertions="+assertions+" PASS");}
}
