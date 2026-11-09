/* Host template. The test inserts the exact production method and receipt boundary.
 * This deliberately does not compile Android or claim to run Accessibility APIs. */
import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class ActionDeadlineHarness {
    private final AtomicBoolean cancelled=new AtomicBoolean();
    private final HeptaAccessibilityService service=new HeptaAccessibilityService(this);
    private JSONObject receipt;
    private int receiptCount,continued;
    private static final long DEADLINE=2000;

    /*__AWAIT_ACTION__*/
    /*__CHECK_ACTIVE__*/
    private static final class Stopped extends Exception {private static final long serialVersionUID=1L;}
    private static final class CleanupUnknown extends Exception {private static final long serialVersionUID=1L;CleanupUnknown(String m){super(m);}}

    private HeptaAccessibilityService.ActionOutcome invoke()throws Exception{
        String taskId="original-task",decisionRunId="original-model-run";
        PhoneObservation before=new PhoneObservation();ActionDecision action=new ActionDecision();
        PromptFrame frame=new PromptFrame();long deadline=DEADLINE;File evidence=null;int steps=1;
        /*__CALLER_RECEIPT_BOUNDARY__*/
        continued++;return outcome;
    }
    private static String answerJson(ActionDecision action){return "{}";}
    private void record(File directory,String name,JSONObject value){
        require("step-01-action.json".equals(name),"original step receipt identity");
        receipt=value;receiptCount++;
        if(service.recordTime>=0)SystemClock.now=service.recordTime;
        if(service.stopDuringRecord)cancelled.set(true);
    }
    private static final class SystemClock {
        static long now=1000;
        static long elapsedRealtime(){return now;}
    }
    /* Deterministic scheduling boundary. It models ready/not-ready and a delayed
     * waiter; the production await argument is checked, not actually slept. */
    private static final class CountDownLatch {
        static long resumeTime=-1,lastTimeout=-1;
        private long count;
        CountDownLatch(long count){this.count=count;}
        void countDown(){if(count>0)count--;}
        boolean await(long timeout,TimeUnit unit)throws InterruptedException{
            require(unit==TimeUnit.MILLISECONDS,"original receipt wait unit");
            lastTimeout=timeout;
            if(resumeTime>=0)SystemClock.now=resumeTime;
            return count==0;
        }
    }
    private static final class JSONObject {
        final Map<String,Object> values=new LinkedHashMap<String,Object>();
        JSONObject(){}
        JSONObject(String ignored){}
        JSONObject put(String key,Object value){values.put(key,value);return this;}
    }
    private static final class PhoneObservation {}
    private static final class ActionDecision {}
    private static final class ObservedTargetLabels {}
    private static final class PromptFrame {final ObservedTargetLabels targets=new ObservedTargetLabels();}
    private static final class ActionPolicy {static boolean isReadOnlyDiscovery(ActionDecision ignored){return false;}}

    private static final class HeptaAccessibilityService {
        interface Cancellation {boolean isCancelled();}
        interface ActionCallback {void onResult(ActionOutcome result);}
        static final class ActionOutcome {
            final boolean accepted,dispatched,stale;final String detail;
            ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail){
                this.accepted=accepted;this.dispatched=dispatched;this.stale=stale;this.detail=detail;
            }
        }
        final ActionDeadlineHarness owner;
        Cancellation retainedCancellation;ActionCallback retainedCallback;ActionOutcome originalOutcome;
        long dispatchTime=-1,callbackTime=-1,recordTime=-1;
        boolean stopAtDispatch,stopAtCallback,stopDuringRecord,noCallback,duplicate,throwAtPerform;
        int calls,effects;
        HeptaAccessibilityService(ActionDeadlineHarness owner){this.owner=owner;}
        void perform(String id,PhoneObservation observation,ActionDecision decision,ObservedTargetLabels targets,
                     Cancellation cancel,ActionCallback callback){
            require("original-task".equals(id),"original task identity");
            calls++;retainedCancellation=cancel;retainedCallback=callback;
            if(throwAtPerform)throw new IllegalStateException("host injected perform failure");
            if(dispatchTime>=0)SystemClock.now=dispatchTime;
            if(stopAtDispatch)owner.cancelled.set(true);
            if(cancel.isCancelled())originalOutcome=new ActionOutcome(false,false,false,"cancelled before effect");
            else {effects++;originalOutcome=new ActionOutcome(true,true,false,"actual first outcome");}
            if(noCallback)return;
            if(callbackTime>=0)SystemClock.now=callbackTime;
            if(stopAtCallback)owner.cancelled.set(true);
            callback.onResult(originalOutcome);
            if(duplicate)callback.onResult(new ActionOutcome(false,false,true,"duplicate must not overwrite"));
        }
    }

    private static void require(boolean value,String message){if(!value)throw new AssertionError(message);}
    private Exception invokeCaught(){
        try{invoke();return null;}catch(Exception error){return error;}
    }
    private void realReceipt(boolean accepted,boolean dispatched){
        require(receiptCount==1&&receipt!=null,"one actual receipt retained");
        require(Boolean.valueOf(accepted).equals(receipt.values.get("accepted")),"actual accepted must be retained");
        require(Boolean.valueOf(dispatched).equals(receipt.values.get("dispatched")),"actual dispatched must be retained");
        require("original-model-run".equals(receipt.values.get("model_run_id")),"receipt model identity retained");
        require(Boolean.TRUE.equals(receipt.values.get("model_issued")),"model issued evidence retained");
    }
    private void check(String scenario)throws Exception{
        if("normal".equals(scenario)){
            invoke();require(service.effects==1&&continued==1,"normal bounded action still continues");realReceipt(true,true);
        }else if("entry-deadline".equals(scenario)){
            SystemClock.now=DEADLINE;require(invokeCaught()!=null,"entry at deadline rejects");
            require(service.calls==0&&service.effects==0,"deadline entry must not submit");
        }else if("queued-deadline".equals(scenario)||"queued-after-deadline".equals(scenario)){
            service.dispatchTime="queued-deadline".equals(scenario)?DEADLINE:DEADLINE+1;
            Exception error=invokeCaught();
            require(service.effects==0,"queued expired action must not dispatch");
            require(error!=null,"expired queued action terminates");realReceipt(false,false);
            require(continued==0,"expired queued action cannot continue");
        }else if("callback-deadline".equals(scenario)||"callback-after-deadline".equals(scenario)){
            service.callbackTime="callback-deadline".equals(scenario)?DEADLINE:DEADLINE+1;
            require(invokeCaught()!=null,"late callback is evidence only");
            require(service.effects==1&&continued==0,"earlier effect retained without continuation");realReceipt(true,true);
        }else if("waiter-after-deadline".equals(scenario)){
            CountDownLatch.resumeTime=DEADLINE;
            require(invokeCaught()!=null,"waiter cannot resume authority at deadline");realReceipt(true,true);
            require(continued==0,"late waiter cannot continue");
        }else if("record-deadline".equals(scenario)){
            service.recordTime=DEADLINE;
            require(invokeCaught()!=null,"receipt persistence cannot extend task authority");realReceipt(true,true);
            require(continued==0,"deadline during persistence stops continuation");
        }else if("stop-queued".equals(scenario)){
            service.stopAtDispatch=true;
            require(invokeCaught() instanceof Stopped,"queued stop remains stopped");
            require(service.effects==0&&continued==0,"stop blocks effect and continuation");realReceipt(false,false);
        }else if("stop-callback".equals(scenario)||"stop-record".equals(scenario)){
            service.stopAtCallback="stop-callback".equals(scenario);service.stopDuringRecord="stop-record".equals(scenario);
            require(invokeCaught() instanceof Stopped,"stop at receipt boundary remains stopped");
            require(service.effects==1&&continued==0,"known effect retained but stop forbids continuation");realReceipt(true,true);
        }else if("duplicate-first-wins".equals(scenario)){
            service.duplicate=true;HeptaAccessibilityService.ActionOutcome result=invoke();
            require("actual first outcome".equals(result.detail),"first real callback wins");realReceipt(true,true);
        }else if("retire-success".equals(scenario)){
            invoke();cancelled.set(false);
            require(service.retainedCancellation.isCancelled(),"completed attempt cannot regain authority");
        }else if("timeout-unknown".equals(scenario)){
            service.noCallback=true;require(invokeCaught() instanceof CleanupUnknown,"missing receipt retains CleanupUnknown");
            require(CountDownLatch.lastTimeout==8000,"original eight-second acknowledgement bound preserved");
            require(cancelled.get()&&receiptCount==0&&continued==0,"unknown effect is not a fabricated receipt or clean continuation");
            cancelled.set(false);
            require(service.retainedCancellation.isCancelled(),"timeout retirement survives shared flag reset");
            service.retainedCallback.onResult(service.originalOutcome);
            require(receiptCount==0&&continued==0,"late callback cannot revive returned wait or claim cleanup");
        }else if("perform-failure-retired".equals(scenario)){
            service.throwAtPerform=true;require(invokeCaught()!=null,"perform exception preserved");
            require(service.retainedCancellation.isCancelled(),"throwing attempt remains retired");
        }else throw new AssertionError("unknown scenario "+scenario);
        if(service.calls>0&&!service.throwAtPerform)require(CountDownLatch.lastTimeout==8000,"receipt cleanup window unchanged");
        System.out.println("PASS "+scenario+" effects="+service.effects+" receipts="+receiptCount+" continued="+continued);
    }
    public static void main(String[] args)throws Exception{new ActionDeadlineHarness().check(args[0]);}
}
