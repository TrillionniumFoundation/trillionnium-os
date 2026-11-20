package org.trillionnium.hepta.background;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Actual production state machine; explicit inert Surface ports, no Android or device. */
public final class PublicSurfaceRetirementHostTest {
    private static int cases,assertions;
    interface Work{void run()throws Exception;}
    static void yes(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    static void test(String name,Work work)throws Exception{work.run();cases++;System.out.println("PASS "+name);}
    static void await(CountDownLatch latch)throws Exception{yes(latch.await(2,TimeUnit.SECONDS),"worker did not reach boundary");}
    static void join(Thread worker)throws Exception{worker.join(2000);yes(!worker.isAlive(),"worker stalled");}
    static boolean flag(PublicOwnGroupSurfaceRetirement r,String key){return Boolean.TRUE.equals(r.evidence().get(key));}
    static PublicOwnGroupSurfaceRetirement requested(){PublicOwnGroupSurfaceRetirement r=new PublicOwnGroupSurfaceRetirement();yes(r.request(100),"initial request refused");return r;}
    static PublicOwnGroupSurfaceRetirement.OwnedSurface port(String source,AtomicInteger calls){return new PublicOwnGroupSurfaceRetirement.OwnedSurface(){
        public String prepare(){return source;}public void detach(PublicOwnGroupSurfaceRetirement.ApiEntry entry){entry.beforeCall();calls.incrementAndGet();}};}
    static void unverified(PublicOwnGroupSurfaceRetirement r){yes(r.retired(),"retirement lost");yes(!flag(r,"surface_stopped_verified"),"surface proof fabricated");
        yes(!flag(r,"provides_task_or_display_cleanup_proof")&&!flag(r,"allows_input_or_model_resumption"),"cleanup or resumption authority fabricated");}
    public static void main(String[] args)throws Exception{
        test("no work before retirement",()->{PublicOwnGroupSurfaceRetirement r=new PublicOwnGroupSurfaceRetirement();AtomicInteger n=new AtomicInteger();
            r.run(port("FROZEN_FRAMEWORK_IDENTITY",n),()->100);yes(n.get()==0&&!r.retired(),"unrequested mutation");});
        test("returned API remains unverified and admission is irreversible",()->{PublicOwnGroupSurfaceRetirement r=requested();AtomicInteger n=new AtomicInteger();
            r.run(port("FROZEN_FRAMEWORK_IDENTITY",n),()->200);yes(n.get()==1&&flag(r,"api_attempted")&&flag(r,"api_returned"),"entry missing");
            yes(!r.request(300),"second request reset lifetime");unverified(r);});
        test("actual initial handle can request stop before first full policy",()->{PublicOwnGroupSurfaceRetirement r=requested();AtomicInteger n=new AtomicInteger();
            r.run(port("CREATE_RETURNED_HANDLE_ONLY",n),()->200);yes(n.get()==1,"initial own handle never stopped");unverified(r);});
        test("unproven serialized identity cannot enter adapter",()->{PublicOwnGroupSurfaceRetirement r=requested();AtomicInteger n=new AtomicInteger();
            r.run(port("JSON_DISPLAY_ID",n),()->200);yes(n.get()==0&&!flag(r,"api_attempted"),"wire authority accepted");unverified(r);});
        test("failed final handle validation is not an API attempt",()->{PublicOwnGroupSurfaceRetirement r=requested();r.run(new PublicOwnGroupSurfaceRetirement.OwnedSurface(){
            public String prepare(){return "FROZEN_FRAMEWORK_IDENTITY";}
            public void detach(PublicOwnGroupSurfaceRetirement.ApiEntry entry){throw new IllegalStateException("handle changed before entry");}},()->200);
            yes(flag(r,"adapter_entered")&&!flag(r,"api_attempted")&&!flag(r,"api_returned"),"adapter entry confused with actual API entry");unverified(r);});
        test("adapter returning without API entry is never a returned API",()->{PublicOwnGroupSurfaceRetirement r=requested();r.run(new PublicOwnGroupSurfaceRetirement.OwnedSurface(){
            public String prepare(){return "FROZEN_FRAMEWORK_IDENTITY";}public void detach(PublicOwnGroupSurfaceRetirement.ApiEntry entry){}},()->200);
            yes(!flag(r,"api_attempted")&&!flag(r,"api_returned"),"unexecuted API recorded");unverified(r);});
        test("throwing actual API keeps attempted but unknown",()->{PublicOwnGroupSurfaceRetirement r=requested();r.run(new PublicOwnGroupSurfaceRetirement.OwnedSurface(){
            public String prepare(){return "FROZEN_FRAMEWORK_IDENTITY";}
            public void detach(PublicOwnGroupSurfaceRetirement.ApiEntry entry){entry.beforeCall();throw new IllegalStateException("Binder failed");}},()->200);
            yes(flag(r,"api_attempted")&&!flag(r,"api_returned"),"API failure flags incorrect");unverified(r);});
        test("concurrent repeated normal shutdown enters one API",()->{PublicOwnGroupSurfaceRetirement r=requested();AtomicInteger n=new AtomicInteger();Thread[] threads=new Thread[12];
            for(int i=0;i<threads.length;i++){threads[i]=new Thread(()->r.run(port("FROZEN_FRAMEWORK_IDENTITY",n),()->200));threads[i].start();}
            for(Thread thread:threads)join(thread);yes(n.get()==1,"duplicate shutdown API");unverified(r);});
        test("watchdog records a stalled identity read without waiting",()->{PublicOwnGroupSurfaceRetirement r=requested();AtomicLong now=new AtomicLong(200);AtomicInteger n=new AtomicInteger();
            CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
            Thread t=new Thread(()->r.run(new PublicOwnGroupSurfaceRetirement.OwnedSurface(){public String prepare()throws Exception{entered.countDown();release.await();return "FROZEN_FRAMEWORK_IDENTITY";}
                public void detach(PublicOwnGroupSurfaceRetirement.ApiEntry entry){entry.beforeCall();n.incrementAndGet();}},now::get));t.start();await(entered);now.set(1700);r.observeDeadline(now.get());
            yes(flag(r,"deadline_exceeded"),"independent deadline blocked");release.countDown();join(t);yes(n.get()==0,"expired identity admitted a new API");unverified(r);});
        test("late return from stalled API never clears timeout",()->{PublicOwnGroupSurfaceRetirement r=requested();AtomicLong now=new AtomicLong(200);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
            Thread t=new Thread(()->r.run(new PublicOwnGroupSurfaceRetirement.OwnedSurface(){public String prepare(){return "FROZEN_FRAMEWORK_IDENTITY";}
                public void detach(PublicOwnGroupSurfaceRetirement.ApiEntry entry)throws Exception{entry.beforeCall();entered.countDown();release.await();}},now::get));t.start();await(entered);
            now.set(1700);r.observeDeadline(now.get());yes(flag(r,"api_attempted")&&flag(r,"deadline_exceeded"),"API stall not observable");release.countDown();join(t);
            yes(flag(r,"api_returned")&&"DEADLINE_UNVERIFIED".equals(r.evidence().get("state")),"late return promoted timeout");unverified(r);});
        test("create returned after unknown shutdown can detach once without clearing unknown",()->{PublicOwnGroupSurfaceRetirement r=requested();AtomicInteger n=new AtomicInteger();
            r.run(null,()->1700);yes(flag(r,"deadline_exceeded")&&!flag(r,"api_attempted"),"initial no-handle state incorrect");
            r.runLateCreated(port("CREATE_RETURNED_HANDLE_ONLY",n),()->1800);yes(n.get()==1&&flag(r,"api_returned")&&flag(r,"deadline_exceeded"),"late actual handle not stopped");
            r.runLateCreated(port("CREATE_RETURNED_HANDLE_ONLY",n),()->1900);yes(n.get()==1,"late handle retried actual API");unverified(r);});
        test("late create adapter cannot use a replacement policy identity",()->{PublicOwnGroupSurfaceRetirement r=requested();AtomicInteger n=new AtomicInteger();
            r.runLateCreated(port("FROZEN_FRAMEWORK_IDENTITY",n),()->1700);yes(n.get()==0&&!flag(r,"api_attempted"),"late create identity substituted");unverified(r);});
        test("normal and late create race still enter one API",()->{PublicOwnGroupSurfaceRetirement r=requested();AtomicInteger n=new AtomicInteger();CountDownLatch prepared=new CountDownLatch(2),release=new CountDownLatch(1);
            PublicOwnGroupSurfaceRetirement.OwnedSurface p=new PublicOwnGroupSurfaceRetirement.OwnedSurface(){public String prepare()throws Exception{prepared.countDown();release.await();return "CREATE_RETURNED_HANDLE_ONLY";}
                public void detach(PublicOwnGroupSurfaceRetirement.ApiEntry entry){entry.beforeCall();n.incrementAndGet();}};
            Thread a=new Thread(()->r.run(p,()->200)),b=new Thread(()->r.runLateCreated(p,()->200));a.start();b.start();await(prepared);release.countDown();join(a);join(b);
            yes(n.get()==1&&flag(r,"api_returned"),"competing handle deliveries duplicated or lost API");unverified(r);});
        test("scheduler failure is terminal evidence rather than fake stop",()->{PublicOwnGroupSurfaceRetirement r=requested();r.workerUnavailable(new IllegalStateException("scheduler"),200);
            yes("WORKER_UNAVAILABLE_UNVERIFIED".equals(r.evidence().get("state"))&&!flag(r,"api_attempted"),"schedule failure hidden");unverified(r);});
        test("evidence cannot be used to reset state",()->{PublicOwnGroupSurfaceRetirement r=requested();Map<String,Object> value=r.evidence();
            try{value.put("allows_input_or_model_resumption",true);throw new AssertionError("mutable evidence");}catch(UnsupportedOperationException expected){assertions++;}unverified(r);});
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+assertions+",\"all_pass\":true,\"phone_contacted\":false,\"android_binder_or_surface_executed\":false}");
    }
}
