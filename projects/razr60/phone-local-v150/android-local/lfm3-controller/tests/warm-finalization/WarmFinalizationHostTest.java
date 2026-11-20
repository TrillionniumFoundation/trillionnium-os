package org.trillionnium.hepta.local;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Exercises real extracted finalization decisions with an endTask barrier. */
public final class WarmFinalizationHostTest {
    private static int cases;
    private static final String SUMMARY="model outcome before close";
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static LocalInference.TaskCleanup proof(boolean known,boolean valid,Integer exit){
        return new LocalInference.TaskCleanup(known,true,known,exit,
                "11111111111111111111111111111111","33333333333333333333333333333333",valid,"receipt-hash");
    }
    private static final class Close implements LocalInference {
        final CountDownLatch entered=new CountDownLatch(1),release;
        final LocalInference.TaskCleanup proof;
        final boolean throwsOnClose;
        volatile int cancellations,closeCalls;
        Close(LocalInference.TaskCleanup proof,boolean blocking,boolean throwsOnClose){
            this.proof=proof;this.release=new CountDownLatch(blocking?1:0);this.throwsOnClose=throwsOnClose;
        }
        @Override public void cancelTask(){cancellations++;}
        @Override public LocalInference.TaskCleanup endTask(){
            closeCalls++;entered.countDown();
            try{if(!release.await(2,TimeUnit.SECONDS))throw new AssertionError("test close barrier timed out");}
            catch(InterruptedException error){Thread.currentThread().interrupt();throw new AssertionError(error);}
            if(throwsOnClose)throw new IllegalStateException("injected close exception");
            return proof;
        }
    }
    private static void expect(String label,ControllerFinalizationFixture.Outcome actual,String status,
                               boolean success,boolean cleanup,boolean blocked){
        check(status.equals(actual.status),label+": expected "+status+", got "+actual.status);
        check(actual.modelSuccess==success,label+": success flag differs");
        check(actual.cleanupKnown==cleanup,label+": cleanup proof differs");
        check(actual.blocked==blocked,label+": slot/admission block differs");
        cases++;
    }
    private static ControllerFinalizationFixture.Outcome direct(LocalInference.TaskCleanup proof,String status,
                                                               boolean success,boolean cleanup,boolean blocked){
        Close close=new Close(proof,false,false);
        ControllerFinalizationFixture.Outcome result=new ControllerFinalizationFixture(close).finish(status,SUMMARY,success,cleanup,blocked);
        check(close.closeCalls==1,"endTask must execute exactly once");return result;
    }
    private static ControllerFinalizationFixture.Outcome stoppedDuringClose(LocalInference.TaskCleanup proof,
            final String status,final boolean success,final boolean cleanup,final boolean blocked)throws Exception{
        final Close close=new Close(proof,true,false);
        final ControllerFinalizationFixture controller=new ControllerFinalizationFixture(close);
        final AtomicReference<ControllerFinalizationFixture.Outcome> result=new AtomicReference<>();
        final AtomicReference<Throwable> failure=new AtomicReference<>();
        Thread finalizer=new Thread(new Runnable(){@Override public void run(){
            try{result.set(controller.finish(status,SUMMARY,success,cleanup,blocked));}
            catch(Throwable error){failure.set(error);}
        }},"controlled-finalizer");
        finalizer.start();
        try{check(close.entered.await(2,TimeUnit.SECONDS),"endTask must be in progress");controller.stop();controller.awaitCancellation();}
        finally{close.release.countDown();}
        finalizer.join(3000);
        check(!finalizer.isAlive(),"Stop during close must not deadlock");
        check(failure.get()==null,"finalizer failed: "+failure.get());
        check(close.cancellations==1,"production Stop must cancel the current task");
        check(close.closeCalls==1,"Stop must not replay endTask");
        return result.get();
    }
    public static void main(String[] args)throws Exception{
        expect("valid close",direct(proof(true,true,0),"model_reported_done",true,true,false),"model_reported_done",true,true,false);
        expect("invalid receipt after actual exit",direct(proof(true,false,0),"model_reported_done",true,true,false),"failed",false,true,false);
        expect("nonzero close",direct(proof(true,false,74),"model_reported_done",true,true,false),"failed",false,true,false);
        expect("Stop during invalid close",stoppedDuringClose(proof(true,false,143),"model_reported_done",true,true,false),"cancelled",false,true,false);
        expect("Stop while clean close completes",stoppedDuringClose(proof(true,true,0),"model_reported_done",true,true,false),"cancelled",false,true,false);
        expect("unconfirmed exit",direct(proof(false,false,null),"model_reported_done",true,true,false),"blocked",false,false,true);
        expect("Stop with unconfirmed exit",stoppedDuringClose(proof(false,false,null),"model_reported_done",true,true,false),"blocked",false,false,true);
        ControllerFinalizationFixture.Outcome actionUnknown=stoppedDuringClose(proof(true,false,143),"blocked",false,false,true);
        expect("unknown action outcome remains blocked",actionUnknown,"blocked",false,false,true);
        check(SUMMARY.equals(actionUnknown.summary),"model cleanup must preserve unknown action reason");
        ControllerFinalizationFixture.Outcome existingFailure=direct(LocalInference.TaskCleanup.noWorker(),"failed",false,true,false);
        expect("failure before worker start",existingFailure,"failed",false,true,false);
        check(SUMMARY.equals(existingFailure.summary),"unrelated failure reason must be preserved");
        expect("partial valid close",direct(proof(true,true,0),"partial",false,true,false),"partial",false,true,false);
        expect("partial invalid close",direct(proof(true,false,74),"partial",false,true,false),"failed",false,true,false);
        expect("Stop during partial close",stoppedDuringClose(proof(true,false,143),"partial",false,true,false),"cancelled",false,true,false);
        Close throwsClose=new Close(null,false,true);
        expect("close exception",new ControllerFinalizationFixture(throwsClose).finish("model_reported_done",SUMMARY,true,true,false),"blocked",false,false,true);
        System.out.println("PASS cases="+cases+" exact production finalization and Stop; Android/model/phone not tested");
    }
}
