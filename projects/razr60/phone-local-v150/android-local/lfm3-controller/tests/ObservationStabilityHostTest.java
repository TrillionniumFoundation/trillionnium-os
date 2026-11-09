import org.trillionnium.hepta.local.ObservationStabilityGate;
import org.trillionnium.hepta.local.ObservationStabilityGate.FrameKey;
import org.trillionnium.hepta.local.ObservationStabilityGate.Result;

/** Eight contracts for bounded transitions, complete identity, late capture and retirement. */
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
    private static void delayedTransitionBeyondTwoSeconds(){
        ObservationStabilityGate gate=new ObservationStabilityGate(1000,11000);
        expect(gate.sample(1000,null,true)==Result.WAIT,"a transition may temporarily have no active root");
        expect(gate.sample(3000,null,true)==Result.WAIT,"the old two-second boundary is not the caller deadline");
        FrameKey arrived=stable();
        expect(gate.sample(3200,arrived,true)==Result.WAIT,"an arrived root after a delayed transition is still only one sample");
        expect(gate.sample(3399,arrived,true)==Result.WAIT,"the same full 200 ms gap remains mandatory");
        expect(gate.sample(3400,arrived,true)==Result.READY,"a transition lasting more than two seconds can settle inside the original deadline");
    }
    private static void transientRootIsBusy(){
        ObservationStabilityGate gate=new ObservationStabilityGate(0,10000);FrameKey a=stable();
        expect(gate.sample(0,a,true)==Result.WAIT,"first root");
        expect(gate.sample(200,null,true)==Result.WAIT,"missing root is never READY");
        expect(gate.sample(400,a,true)==Result.WAIT,"missing root clears earlier evidence");
        expect(gate.sample(600,a,true)==Result.READY,"two fresh roots after absence");
        ObservationStabilityGate absent=new ObservationStabilityGate(0,20000);
        expect(absent.sample(9999,null,true)==Result.WAIT,"absence may wait only inside fixed bound");
        expect(absent.sample(10000,null,true)==Result.EXPIRED,"absence cannot wait forever even with a longer caller deadline");
    }
    private static void captureMismatchResamplesWithoutOldEvidence(){
        ObservationStabilityGate gate=new ObservationStabilityGate(0,10000);
        expect(gate.sample(0,stable(),true)==Result.WAIT,"initial capture sample");
        expect(gate.sample(200,stable(),true)==Result.READY,"initial capture is eligible");
        expect(gate.requestAlive(2400,true),"capture processing may consume more than two seconds");
        gate.resetEvidence();
        FrameKey changed=key("example.app",7,0,0,1080,"changed-after-capture-or-save",false);
        expect(gate.sample(2500,changed,true)==Result.WAIT,"mismatched screenshot cannot reuse the earlier stable pair");
        expect(gate.sample(2699,changed,true)==Result.WAIT,"retry must obtain a fresh complete gap");
        expect(gate.sample(2700,changed,true)==Result.READY,"fresh matching evidence can settle after the old two-second cap");
    }
    private static void continuousChangesExpire(){
        ObservationStabilityGate gate=new ObservationStabilityGate(1000,21000);
        FrameKey last=null;
        for(long now=1000;now<11000;now+=200){
            last=key("example.app",7,0,0,1080,"changing-observed-digest-"+now,false);
            expect(gate.sample(now,last,true)==Result.WAIT,"continuous changes never qualify as a stable frame");
        }
        expect(gate.sample(11000,last,true)==Result.EXPIRED,"even a final matching frame cannot cross the original ten-second cap");
        expect(gate.nextSampleDelay(11000)==0,"expired sampling cannot schedule a fresh waiting window");
    }
    private static void originalDeadlinesNeverExtend(){
        ObservationStabilityGate gate=new ObservationStabilityGate(0,20000);
        expect(gate.sample(9800,stable(),true)==Result.WAIT,"late first frame");
        gate.resetEvidence();
        expect(gate.sample(9999,stable(),true)==Result.WAIT,"reset drops the late sample rather than reusing its elapsed gap");
        expect(gate.sample(10000,stable(),true)==Result.EXPIRED,"reset does not renew the independent settle cap");
        ObservationStabilityGate shortTask=new ObservationStabilityGate(0,150);
        expect(shortTask.sample(0,stable(),true)==Result.WAIT,"task has less than a full gap");
        expect(shortTask.sample(150,stable(),true)==Result.EXPIRED,"task deadline dominates");
        ObservationStabilityGate resetShort=new ObservationStabilityGate(1000,3600);
        expect(resetShort.sample(3200,stable(),true)==Result.WAIT,"short original caller window");
        resetShort.resetEvidence();
        expect(resetShort.sample(3400,stable(),true)==Result.WAIT,"reset cannot borrow a previous sample");
        expect(resetShort.sample(3600,stable(),true)==Result.EXPIRED,"a full gap ending exactly at the caller deadline is too late");
        ObservationStabilityGate capture=new ObservationStabilityGate(0,900);
        capture.sample(0,stable(),true);expect(capture.sample(200,stable(),true)==Result.READY,"capture is eligible");
        expect(capture.requestAlive(899,true),"screenshot may complete before unchanged request deadline");
        expect(!capture.requestAlive(900,true),"late screenshot cannot publish");
        expect(!capture.requestAlive(100,true),"clock rollback cannot refresh old capture");
    }
    private static void lateCaptureStillUsesCallerDeadline(){
        ObservationStabilityGate gate=new ObservationStabilityGate(0,10000);
        expect(gate.sample(8800,stable(),true)==Result.WAIT,"late first capture sample");
        expect(gate.sample(9000,stable(),true)==Result.READY,"a capture may start late in the original window");
        expect(gate.requestAlive(9999,true),"remaining capture time is bounded by the caller");
        expect(!gate.requestAlive(10000,true),"starting capture at nine seconds cannot grant another five seconds");
        expect(!gate.requestAlive(14000,true),"the later per-capture watchdog cannot make an expired request alive");
    }
    private static void cancellationAndRetirement(){
        ObservationStabilityGate gate=new ObservationStabilityGate(0,10000);
        gate.sample(0,stable(),true);
        expect(gate.sample(200,stable(),false)==Result.CANCELLED,"cancelled/unowned task never becomes READY");
        expect(!gate.requestAlive(200,false),"cancel or lost owner blocks late publication");
        expect(gate.sample(10000,stable(),false)==Result.CANCELLED,"cancel or lost owner wins even when the time budget has also expired");
        gate.retire();gate.resetEvidence();
        expect(gate.sample(400,stable(),true)==Result.CANCELLED,"reset cannot reuse a retired request for a new task");
        expect(!gate.requestAlive(400,true),"retired capture remains invalid");
    }
    public static void main(String[] args){
        stableAndChangingFrames();delayedTransitionBeyondTwoSeconds();transientRootIsBusy();
        captureMismatchResamplesWithoutOldEvidence();continuousChangesExpire();originalDeadlinesNeverExtend();
        lateCaptureStillUsesCallerDeadline();cancellationAndRetirement();
        System.out.println("8 focused observation stability contracts passed");
    }
}
