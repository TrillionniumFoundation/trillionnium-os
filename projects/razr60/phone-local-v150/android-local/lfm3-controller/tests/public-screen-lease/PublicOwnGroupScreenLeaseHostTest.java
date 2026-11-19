package org.trillionnium.hepta.background;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Executes the production lease state machine with explicit clock/power/display ports.
 * The 8-second policy is a test model of the observed timeout, not an Android power test. */
public final class PublicOwnGroupScreenLeaseHostTest {
    static final String GEN="5bd0794d-bdaf-48ef-8dbf-f63c6befca85";
    static int checks;
    static final List<String> names=new ArrayList<String>();
    interface Work { void run() throws Exception; }
    static void yes(boolean ok,String reason){checks++;if(!ok)throw new AssertionError(reason);}
    static void test(String name,Work work)throws Exception{work.run();names.add(name);}
    static void refuse(Work work)throws Exception{
        try{work.run();throw new AssertionError("invalid lease admitted");}catch(IOException expected){checks++;}
    }
    static final class Clock implements PublicOwnGroupScreenLease.Clock {volatile long now=1000;public long now(){return now;}}
    static final class Port implements PublicOwnGroupScreenLease.Port {
        final Clock clock;volatile boolean held;boolean failRelease,failAcquire;
        int id=210,type=5,flags=7040,uid=0,group=2,main=0,cover=1,members=1,state=2,reads;
        volatile int acquires,releases;
        int acquiredFlags,acquiredDisplay;long timeout;String unique="virtual:owned",name="hepta-bg-"+GEN,pkg="com.android.shell";
        boolean valid=true;long afterFirstRead=-1;CountDownLatch entered,proceed;
        final int physicalMainState=1,physicalCoverState=2;
        Port(Clock clock){this.clock=clock;}
        public PublicOwnGroupScreenLease.Snapshot read(){
            if(clock.now>=9000&&!held)state=1;
            PublicOwnGroupScreenLease.Snapshot result=new PublicOwnGroupScreenLease.Snapshot(id,type,flags,uid,group,main,cover,
                    members,state,name,unique,pkg,valid);
            if(reads++==0&&afterFirstRead>=0)clock.now=afterFirstRead;
            return result;
        }
        public void acquire(int flags,int display,long remaining)throws Exception{
            acquires++;acquiredFlags=flags;acquiredDisplay=display;timeout=remaining;
            if(entered!=null){entered.countDown();if(!proceed.await(2,TimeUnit.SECONDS))throw new IOException("test timeout");}
            held=true;if(failAcquire)throw new IOException("acquire returned unknown after entry");
        }
        public boolean held(){return held;}
        public void release()throws IOException{releases++;if(failRelease)throw new IOException("release unknown");held=false;}
    }
    static PublicOwnGroupScreenLease lease(Clock clock)throws Exception{return new PublicOwnGroupScreenLease(GEN,21000,clock);}
    static void released(PublicOwnGroupScreenLease lease,Port port)throws Exception{
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
        while(System.nanoTime()<until&&!Boolean.TRUE.equals(lease.evidence().get("release_returned")))Thread.yield();
        yes(Boolean.TRUE.equals(lease.evidence().get("release_returned"))&&!port.held,"owned token was not released");
    }
    static void invalid(String name,java.util.function.Consumer<Port> change)throws Exception{
        test(name,()->{Clock c=new Clock();Port p=new Port(c);change.accept(p);PublicOwnGroupScreenLease l=lease(c);
            refuse(()->l.acquire(p));yes(p.acquires==0,"invalid display reached the power API");});
    }
    public static void main(String[] args)throws Exception{
        test("unleased display model reproduces observed eight second timeout",()->{
            Clock c=new Clock();Port p=new Port(c);c.now=9001;
            yes(p.read().state==1&&p.acquires==0,"unleased timeout model did not sleep");
        });
        test("exact isolated screen survives timeout without touching either physical group",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);l.acquire(p);c.now=12000;l.requireActive();
            yes(p.state==2&&p.held,"lease did not protect owned display past eight seconds");
            yes(p.physicalMainState==1&&p.physicalCoverState==2,"physical power changed");
            yes(p.acquiredFlags==0xa&&p.acquiredDisplay==210&&p.timeout==20000,"wake or unscoped flags / wrong expiry");
            c.now=21000;l.observeDeadline(c.now);released(l,p);refuse(l::requireActive);
            yes(p.read().state==1,"expired display remained held");
        });
        invalid("main display refused",p->p.id=0);
        invalid("cover display refused",p->p.id=1);
        invalid("main power group refused",p->p.group=0);
        invalid("cover power group refused",p->p.group=1);
        invalid("unknown physical group refused",p->p.cover=-1);
        invalid("another virtual display sharing the group refused",p->p.members=2);
        invalid("unknown group membership refused",p->p.members=0);
        invalid("wrong owner refused",p->p.uid=2000);
        invalid("wrong generation refused",p->p.name="hepta-bg-replacement");
        invalid("wrong flags refused",p->p.flags|=4);
        invalid("physical display type refused",p->p.type=1);
        invalid("invalid display object refused",p->p.valid=false);
        invalid("already off display is never woken",p->p.state=1);
        test("expired request refuses before any acquire",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);c.now=21000;
            refuse(()->l.acquire(p));yes(p.acquires==0,"expired acquire entered");
        });
        test("deadline crossed during scope census refuses before acquire",()->{
            Clock c=new Clock();Port p=new Port(c);p.afterFirstRead=21000;PublicOwnGroupScreenLease l=lease(c);
            refuse(()->l.acquire(p));yes(p.acquires==0,"late census acquired lock");
        });
        test("duplicate acquire never renews the absolute lifetime",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);l.acquire(p);c.now=2000;
            refuse(()->l.acquire(p));yes(p.acquires==1&&p.timeout==20000,"lease was renewed");l.retire();released(l,p);
        });
        test("cleanup before create permanently refuses late acquire",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);l.retire();
            refuse(()->l.acquire(p));yes(p.acquires==0,"late acquire passed retirement");
        });
        test("cleanup racing blocked acquire releases the late returned exact token",()->{
            Clock c=new Clock();Port p=new Port(c);p.entered=new CountDownLatch(1);p.proceed=new CountDownLatch(1);
            PublicOwnGroupScreenLease l=lease(c);AtomicReference<Throwable> result=new AtomicReference<Throwable>();
            Thread t=new Thread(()->{try{l.acquire(p);}catch(Throwable error){result.set(error);}});t.start();
            yes(p.entered.await(2,TimeUnit.SECONDS),"not inside actual acquire port");
            long start=System.nanoTime();l.retire();yes(System.nanoTime()-start<TimeUnit.MILLISECONDS.toNanos(250),"retirement blocked watchdog");
            p.proceed.countDown();t.join(2000);yes(!t.isAlive()&&result.get() instanceof IOException,"late acquire became active");
            released(l,p);yes(p.acquires==1&&p.releases==1,"late token was released incorrectly");
        });
        test("unknown acquire still retires only the attempted owned token",()->{
            Clock c=new Clock();Port p=new Port(c);p.failAcquire=true;PublicOwnGroupScreenLease l=lease(c);
            refuse(()->l.acquire(p));released(l,p);yes(p.acquires==1&&p.releases==1,"unknown acquire left held token");
        });
        test("same display integer with replaced unique identity retires old token",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);l.acquire(p);p.unique="virtual:replacement";
            refuse(l::requireActive);released(l,p);yes(p.acquires==1,"reused display obtained a new lease");
        });
        test("physical group joining after activation retires before another admission",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);l.acquire(p);p.cover=2;
            refuse(l::requireActive);released(l,p);
        });
        test("lost held state never authorizes active work",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);l.acquire(p);p.held=false;
            refuse(l::requireActive);released(l,p);
        });
        test("quarantine retirement releases power without claiming task cleanup",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);l.acquire(p);l.retire();released(l,p);
            Map<String,Object> e=l.evidence();yes(Boolean.FALSE.equals(e.get("grants_cleanup_or_business_success")),"screen release invented cleanup");
            refuse(l::requireActive);
        });
        test("release failure remains unknown and cannot reactivate or retry",()->{
            Clock c=new Clock();Port p=new Port(c);p.failRelease=true;PublicOwnGroupScreenLease l=lease(c);l.acquire(p);l.retire();
            long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(p.releases==0&&System.nanoTime()<end)Thread.yield();
            yes(p.releases==1&&!Boolean.TRUE.equals(l.evidence().get("release_returned")),"unknown release promoted");
            refuse(l::requireActive);l.retire();yes(p.releases==1,"unknown release retried");
        });
        test("lifetime cannot exceed the original broker maximum",()->{
            Clock c=new Clock();refuse(()->new PublicOwnGroupScreenLease(GEN,c.now+600001,c));
        });
        test("actual census includes disabled foreign displays without freezing physical power",()->{
            PublicScreenCensusFixture f=new PublicScreenCensusFixture();f.service.ids=new int[]{0,1,210,211};
            f.service.rows.put(211,new PublicScreenCensusFixture.Info(211,5,3,1));
            f.screenSnapshot(210,"hepta-bg-"+GEN).requireIsolatedOn(GEN);
            yes(f.service.enumerations==2&&f.service.directReads==4,"incomplete direct Binder census");
        });
        test("disabled display sharing the group is refused by actual census",()->{
            PublicScreenCensusFixture f=new PublicScreenCensusFixture();f.service.ids=new int[]{0,1,210,211};
            f.service.rows.put(211,new PublicScreenCensusFixture.Info(211,5,2,1));
            refuse(()->f.screenSnapshot(210,"hepta-bg-"+GEN).requireIsolatedOn(GEN));
        });
        test("actual census rejects duplicate logical display ids",()->{
            PublicScreenCensusFixture f=new PublicScreenCensusFixture();f.service.ids=new int[]{0,1,210,210};
            refuse(()->f.screenSnapshot(210,"hepta-bg-"+GEN));
        });
        test("actual census rejects a missing cover display",()->{
            PublicScreenCensusFixture f=new PublicScreenCensusFixture();f.service.ids=new int[]{0,210,211};
            f.service.rows.put(211,new PublicScreenCensusFixture.Info(211,5,3,1));
            refuse(()->f.screenSnapshot(210,"hepta-bg-"+GEN));
        });
        test("actual census rejects unknown disabled display information",()->{
            PublicScreenCensusFixture f=new PublicScreenCensusFixture();f.service.ids=new int[]{0,1,210,211};
            refuse(()->f.screenSnapshot(210,"hepta-bg-"+GEN));
        });
        test("actual census rejects membership changing during read",()->{
            PublicScreenCensusFixture f=new PublicScreenCensusFixture();f.service.ending=new int[]{0,1,210,211};
            refuse(()->f.screenSnapshot(210,"hepta-bg-"+GEN));
        });
        test("actual census rejects mismatched direct display id",()->{
            PublicScreenCensusFixture f=new PublicScreenCensusFixture();f.service.rows.get(210).displayId=211;
            refuse(()->f.screenSnapshot(210,"hepta-bg-"+GEN));
        });
        test("actual census rejects same-id replacement of unique display",()->{
            PublicScreenCensusFixture f=new PublicScreenCensusFixture();f.service.rows.get(210).uniqueId="replacement";
            refuse(()->f.screenSnapshot(210,"hepta-bg-"+GEN));
        });
        test("actual census rejects already sleeping created display",()->{
            PublicScreenCensusFixture f=new PublicScreenCensusFixture();f.service.rows.get(210).state=1;
            refuse(()->f.screenSnapshot(210,"hepta-bg-"+GEN).requireIsolatedOn(GEN));
        });
        StringBuilder json=new StringBuilder("{\"schema\":\"hepta.public-screen-lease-host.v1\",\"all_pass\":true,\"cases\":")
                .append(names.size()).append(",\"assertions\":").append(checks)
                .append(",\"phone_operations\":0,\"android_power_api_executed\":false,\"case_names\":[");
        for(int i=0;i<names.size();i++){if(i>0)json.append(',');json.append('"').append(names.get(i)).append('"');}
        System.out.println(json.append("]}"));
    }
}
