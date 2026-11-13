package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Actual extracted service ownership/read methods; fake Android nodes and blocking IO only.
 * No native node, phone, task admission, page proof, action Permit, or business success is supplied. */
public final class FlightObservationWorkerHostTest {
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private interface Case { void run()throws Exception; }
    private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void test(String name,Case work)throws Exception{
        HeptaAccessibilityService.fixtureReset();
        try{work.run();names.add(name);}finally{HeptaAccessibilityService.fixtureShutdown();}
    }
    private static void waitFor(CountDownLatch latch,String why)throws Exception{
        check(latch.await(2,TimeUnit.SECONDS),why);
    }
    private static void join(Thread thread)throws Exception{thread.join(2000);check(!thread.isAlive(),"bounded caller exited");}
    private static void drained()throws Exception{
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
        while(HeptaAccessibilityService.fixtureBusy()&&System.nanoTime()<end)Thread.yield();
        check(!HeptaAccessibilityService.fixtureBusy(),"actual worker finally returned capacity");
    }
    private static void blocked(boolean deadline)throws Exception{
        final HeptaAccessibilityService service=new HeptaAccessibilityService();
        final HeptaAccessibilityService.FakeNode node=new HeptaAccessibilityService.FakeNode();
        final HeptaAccessibilityService.FlightObservationSnapshot source=service.fixtureSnapshot(node);
        final AtomicBoolean cancelled=new AtomicBoolean();
        final CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),actualReturn=new CountDownLatch(1);
        final AtomicReference<Throwable> error=new AtomicReference<Throwable>();
        final AtomicBoolean returned=new AtomicBoolean();
        Thread caller=new Thread(new Runnable(){public void run(){
            try{
                service.fixtureRead(new Callable<Boolean>(){public Boolean call()throws Exception{
                    entered.countDown();release.await();
                    check(!node.recycled.get(),"in-flight reader still owns live local NodeRef");actualReturn.countDown();return Boolean.TRUE;
                }},cancelled,HeptaAccessibilityService.fixtureNow()+(deadline?150:5000),source);
                returned.set(true);
            }catch(Throwable expected){error.set(expected);}finally{source.close();}
        }},"bounded-read-caller");
        caller.start();waitFor(entered,"real worker entered fake blocked IPC");
        check(HeptaAccessibilityService.fixtureBusy(),"real worker occupies shared read capacity");
        if(!deadline)cancelled.set(true);
        try{
            join(caller);check(error.get() instanceof IllegalStateException&&!returned.get(),"expired/cancelled caller receives no proof");
            check(HeptaAccessibilityService.fixtureClosed(source),"caller finally retired source authority");
            check(HeptaAccessibilityService.fixtureBusy()&&!node.recycled.get(),"timeout neither drains worker nor recycles its borrowed node");
            boolean refused=false;
            try{service.fixtureRead(()->Boolean.TRUE,new AtomicBoolean(),HeptaAccessibilityService.fixtureNow()+1000,null);}
            catch(IllegalStateException occupied){refused=true;}
            check(refused,"replacement read cannot bypass occupied process capacity");
            boolean borrowRefused=false;try{HeptaAccessibilityService.fixtureBorrow(source);}catch(IllegalStateException retired){borrowRefused=true;}
            check(borrowRefused,"retired snapshot cannot grant new reader authority");
        }finally{release.countDown();}
        waitFor(actualReturn,"blocked IPC really returned");drained();
        check(node.recycles.get()==1,"last real reader releases the node exactly once");source.close();
        check(node.recycles.get()==1,"late duplicate close remains idempotent");
    }
    public static void main(String[] args)throws Exception{
        check(args.length==1,"one new output file required");Path out=Paths.get(args[0]);check(!Files.exists(out),"create-only result");
        test("unborrowed_close_recycles_once",()->{
            HeptaAccessibilityService s=new HeptaAccessibilityService();HeptaAccessibilityService.FakeNode n=new HeptaAccessibilityService.FakeNode();
            HeptaAccessibilityService.FlightObservationSnapshot p=s.fixtureSnapshot(n);p.close();p.close();check(n.recycles.get()==1,"close once");
        });
        test("last_of_two_borrows_owns_recycle",()->{
            HeptaAccessibilityService s=new HeptaAccessibilityService();HeptaAccessibilityService.FakeNode n=new HeptaAccessibilityService.FakeNode();
            HeptaAccessibilityService.FlightObservationSnapshot p=s.fixtureSnapshot(n);HeptaAccessibilityService.fixtureBorrow(p);HeptaAccessibilityService.fixtureBorrow(p);p.close();
            check(n.recycles.get()==0,"owner retirement cannot release active readers");HeptaAccessibilityService.fixtureRelease(p);
            check(n.recycles.get()==0,"first reader is not last owner");HeptaAccessibilityService.fixtureRelease(p);check(n.recycles.get()==1,"last reader releases");
        });
        test("timeout_does_not_recycle_blocked_reader_or_free_capacity",()->blocked(true));
        test("cancellation_does_not_recycle_blocked_reader_or_free_capacity",()->blocked(false));
        test("queued_abandonment_releases_only_when_worker_runs",()->{
            final HeptaAccessibilityService s=new HeptaAccessibilityService();final HeptaAccessibilityService.FakeNode n=new HeptaAccessibilityService.FakeNode();
            final HeptaAccessibilityService.FlightObservationSnapshot p=s.fixtureSnapshot(n);final CountDownLatch queueBlocked=new CountDownLatch(1),release=new CountDownLatch(1);
            final AtomicBoolean invoked=new AtomicBoolean();final AtomicReference<Throwable> error=new AtomicReference<Throwable>();
            HeptaAccessibilityService.fixtureQueue(new Runnable(){public void run(){queueBlocked.countDown();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}}});
            waitFor(queueBlocked,"IO queue control entered");
            Thread caller=new Thread(()->{try{s.fixtureRead(()->{invoked.set(true);return Boolean.TRUE;},new AtomicBoolean(),HeptaAccessibilityService.fixtureNow()+150,p);}
                catch(Throwable failure){error.set(failure);}finally{p.close();}});
            try{caller.start();join(caller);check(error.get() instanceof IllegalStateException,"queued caller expired");
                check(HeptaAccessibilityService.fixtureBusy()&&!n.recycled.get(),"queued borrow remains fenced");}
            finally{release.countDown();}
            drained();check(!invoked.get()&&n.recycles.get()==1,"abandoned callable never enters IO; real dequeue finally releases borrow");
        });
        test("rejected_submission_releases_borrow_without_entering_io",()->{
            HeptaAccessibilityService s=new HeptaAccessibilityService();HeptaAccessibilityService.FakeNode n=new HeptaAccessibilityService.FakeNode();
            HeptaAccessibilityService.FlightObservationSnapshot p=s.fixtureSnapshot(n);AtomicBoolean invoked=new AtomicBoolean();HeptaAccessibilityService.fixtureReject();
            boolean refused=false;try{s.fixtureRead(()->{invoked.set(true);return Boolean.TRUE;},new AtomicBoolean(),HeptaAccessibilityService.fixtureNow()+1000,p);}
            catch(java.util.concurrent.RejectedExecutionException expected){refused=true;}finally{p.close();}
            check(refused&&!invoked.get()&&!HeptaAccessibilityService.fixtureBusy()&&n.recycles.get()==1,"definitive queue rejection has no in-flight reader");
        });
        test("worker_failure_releases_borrow_and_preserves_failure",()->{
            HeptaAccessibilityService s=new HeptaAccessibilityService();HeptaAccessibilityService.FakeNode n=new HeptaAccessibilityService.FakeNode();
            HeptaAccessibilityService.FlightObservationSnapshot p=s.fixtureSnapshot(n);boolean refused=false;
            try{s.fixtureRead(()->{throw new IllegalArgumentException("synthetic read refusal");},new AtomicBoolean(),HeptaAccessibilityService.fixtureNow()+1000,p);}
            catch(IllegalArgumentException expected){refused="synthetic read refusal".equals(expected.getMessage());}finally{p.close();}
            check(refused&&!HeptaAccessibilityService.fixtureBusy()&&n.recycles.get()==1,"failed reader drains and does not return proof");
        });
        test("late_unclaimed_snapshot_is_closed",()->{
            HeptaAccessibilityService s=new HeptaAccessibilityService();HeptaAccessibilityService.FakeNode n=new HeptaAccessibilityService.FakeNode();AtomicBoolean cancelled=new AtomicBoolean();boolean refused=false;
            try{s.fixtureRead(()->{HeptaAccessibilityService.FlightObservationSnapshot value=s.fixtureSnapshot(n);cancelled.set(true);return value;},cancelled,HeptaAccessibilityService.fixtureNow()+1000,null);}
            catch(IllegalStateException expected){refused=true;}
            drained();check(refused&&n.recycles.get()==1,"unclaimed produced snapshot closed by actual reader finally");
        });
        test("normal_return_keeps_owner_until_close",()->{
            HeptaAccessibilityService s=new HeptaAccessibilityService();HeptaAccessibilityService.FakeNode n=new HeptaAccessibilityService.FakeNode();HeptaAccessibilityService.FlightObservationSnapshot p=s.fixtureSnapshot(n);
            check(Boolean.TRUE.equals(s.fixtureRead(()->Boolean.TRUE,new AtomicBoolean(),HeptaAccessibilityService.fixtureNow()+1000,p)),"normal result delivered");
            check(!HeptaAccessibilityService.fixtureBusy()&&!n.recycled.get(),"worker returned only its own borrow");p.close();check(n.recycles.get()==1,"caller still owns final close");
        });
        test("cancelled_before_submit_has_zero_io",()->{
            HeptaAccessibilityService s=new HeptaAccessibilityService();AtomicBoolean invoked=new AtomicBoolean();boolean refused=false;
            try{s.fixtureRead(()->{invoked.set(true);return Boolean.TRUE;},new AtomicBoolean(true),HeptaAccessibilityService.fixtureNow()+1000,null);}
            catch(IllegalStateException expected){refused=true;}
            check(refused&&!invoked.get()&&!HeptaAccessibilityService.fixtureBusy(),"pre-cancelled read never enters queue");
        });
        test("expired_before_submit_has_zero_io",()->{
            HeptaAccessibilityService s=new HeptaAccessibilityService();AtomicBoolean invoked=new AtomicBoolean();boolean refused=false;
            try{s.fixtureRead(()->{invoked.set(true);return Boolean.TRUE;},new AtomicBoolean(),HeptaAccessibilityService.fixtureNow()-1,null);}
            catch(IllegalStateException expected){refused=true;}
            check(refused&&!invoked.get()&&!HeptaAccessibilityService.fixtureBusy(),"expired read never enters queue");
        });
        test("main_thread_cannot_wait_for_read_worker",()->{
            HeptaAccessibilityService s=new HeptaAccessibilityService();boolean refused=false;HeptaAccessibilityService.fixtureMain(true);
            try{s.fixtureRead(()->Boolean.TRUE,new AtomicBoolean(),HeptaAccessibilityService.fixtureNow()+1000,null);}
            catch(IllegalStateException expected){refused=true;}finally{HeptaAccessibilityService.fixtureMain(false);}
            check(refused&&!HeptaAccessibilityService.fixtureBusy(),"main wait refused before admission");
        });
        StringBuilder cases=new StringBuilder();for(String name:names){if(cases.length()>0)cases.append(',');cases.append('"').append(name).append('"');}
        String json="{\"schema\":\"hepta.flight-observation-worker-synthetic.v1\",\"all_pass\":true,\"cases\":"+names.size()+",\"assertions\":"+assertions
                +",\"case_names\":["+cases+"],\"synthetic_android_io\":true,\"actual_service_method_extraction\":true,\"full_service_or_binder_tested\":false,\"phone_operations\":0,\"business_verified\":false}";
        Files.write(out,(json+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);System.out.println(json);
    }
}
