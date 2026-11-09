import org.trillionnium.hepta.local.ObservationStabilityGate;
import org.trillionnium.hepta.local.ObservationStabilityGate.FrameKey;
import org.trillionnium.hepta.local.ObservationStabilityGate.Result;

/** Four focused contracts for time, observed identity, missing roots and retirement. */
public final class ObservationStabilityHostTest {
    private static void expect(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static FrameKey key(String pkg,int id,int rotation,int left,int right,String digest,boolean truncated){
        return new FrameKey(pkg,id,rotation,left,0,right,2400,digest,truncated);
    }
    private static FrameKey stable(){return key("example.app",7,0,0,1080,"complete-observed-digest",false);}
    private static void stableAndChangingFrames(){
        ObservationStabilityGate gate=new ObservationStabilityGate(1000,11000);
        FrameKey a=key("example.app",7,0,200,1280,"complete-observed-digest",false),b=stable();
        expect(gate.sample(1000,a,true)==Result.WAIT,"first frame cannot be stable");
        expect(gate.sample(1199,a,true)==Result.WAIT,"short adjacent reads cannot be stable");
        expect(gate.sample(1200,b,true)==Result.WAIT,"changed animation bounds restart evidence");
        expect(gate.sample(1399,b,true)==Result.WAIT,"new bounds need the entire gap");
        expect(gate.sample(1400,b,true)==Result.READY,"same observed bounds/tree after gap");
        for(FrameKey changed:new FrameKey[]{key("other.app",7,0,0,1080,"complete-observed-digest",false),
                key("example.app",8,0,0,1080,"complete-observed-digest",false),
                key("example.app",7,1,0,1080,"complete-observed-digest",false),
                key("example.app",7,0,0,1080,"focus-or-ime-or-content-or-metadata-changed",false),
                key("example.app",7,0,0,1080,"complete-observed-digest",true)}){
            expect(!b.equals(changed),"every existing identity component/truncation stays relevant");
        }
    }
    private static void transientRootIsBusy(){
        ObservationStabilityGate gate=new ObservationStabilityGate(0,10000);FrameKey a=stable();
        expect(gate.sample(0,a,true)==Result.WAIT,"first root");
        expect(gate.sample(200,null,true)==Result.WAIT,"missing root is never READY");
        expect(gate.sample(400,a,true)==Result.WAIT,"missing root clears earlier evidence");
        expect(gate.sample(600,a,true)==Result.READY,"two fresh roots after absence");
        ObservationStabilityGate absent=new ObservationStabilityGate(0,10000);
        expect(absent.sample(1999,null,true)==Result.WAIT,"absence may wait only inside fixed bound");
        expect(absent.sample(2000,null,true)==Result.EXPIRED,"absence cannot wait forever");
    }
    private static void originalDeadlinesNeverExtend(){
        ObservationStabilityGate gate=new ObservationStabilityGate(0,10000);
        expect(gate.sample(1900,stable(),true)==Result.WAIT,"late first frame");
        gate.resetEvidence();
        expect(gate.sample(2000,stable(),true)==Result.EXPIRED,"reset does not renew settle deadline");
        ObservationStabilityGate shortTask=new ObservationStabilityGate(0,150);
        expect(shortTask.sample(0,stable(),true)==Result.WAIT,"task has less than a full gap");
        expect(shortTask.sample(150,stable(),true)==Result.EXPIRED,"task deadline dominates");
        ObservationStabilityGate capture=new ObservationStabilityGate(0,900);
        capture.sample(0,stable(),true);expect(capture.sample(200,stable(),true)==Result.READY,"capture is eligible");
        expect(capture.requestAlive(899,true),"screenshot may complete before unchanged request deadline");
        expect(!capture.requestAlive(900,true),"late screenshot cannot publish");
        expect(!capture.requestAlive(100,true),"clock rollback cannot refresh old capture");
    }
    private static void cancellationAndRetirement(){
        ObservationStabilityGate gate=new ObservationStabilityGate(0,10000);
        gate.sample(0,stable(),true);
        expect(gate.sample(200,stable(),false)==Result.CANCELLED,"cancelled/unowned task never becomes READY");
        expect(!gate.requestAlive(200,false),"cancel blocks late publication");
        gate.retire();
        expect(gate.sample(400,stable(),true)==Result.CANCELLED,"old request cannot be reused by new task");
        expect(!gate.requestAlive(400,true),"retired capture remains invalid");
    }
    public static void main(String[] args){
        stableAndChangingFrames();transientRootIsBusy();originalDeadlinesNeverExtend();cancellationAndRetirement();
        System.out.println("4 focused observation stability contracts passed");
    }
}
