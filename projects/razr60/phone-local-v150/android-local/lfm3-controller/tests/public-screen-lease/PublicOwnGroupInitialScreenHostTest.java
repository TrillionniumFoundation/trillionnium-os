package org.trillionnium.hepta.background;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Initial display readiness, using the production lease and extracted complete Binder census.
 * No Android power service, Phone operation, display wake or real three-second delay is used. */
public final class PublicOwnGroupInitialScreenHostTest {
    static final String GEN="5bd0794d-bdaf-48ef-8dbf-f63c6befca85";
    static int checks;
    static final List<String> names=new ArrayList<String>();
    interface Work { void run() throws Exception; }
    static void yes(boolean ok,String reason){checks++;if(!ok)throw new AssertionError(reason);}
    static void test(String name,Work work)throws Exception{work.run();names.add(name);}
    static void refuse(String reason,Work work)throws Exception{
        try{work.run();throw new AssertionError("invalid initial display admitted");}
        catch(IOException expected){yes(reason.equals(expected.getMessage()),"wrong refusal: "+expected);}
    }
    static final class Clock implements PublicOwnGroupScreenLease.Clock {
        volatile long now=1000;
        public long now(){return now;}
    }
    static final class Port implements PublicOwnGroupScreenLease.Port {
        final Clock clock;
        int state=1,uid=0,group=2,cover=1,reads,pauses,acquires,releases;
        long slept,remaining;boolean held;String unique="virtual:owned";
        Work beforeRead,afterRead,onPause,onAcquire;
        PublicScreenCensusFixture census;
        Port(Clock clock){this.clock=clock;}
        public PublicOwnGroupScreenLease.Snapshot read()throws Exception{
            reads++;if(beforeRead!=null)beforeRead.run();
            PublicOwnGroupScreenLease.Snapshot value=census==null?
                new PublicOwnGroupScreenLease.Snapshot(210,5,7040,uid,group,0,cover,1,state,
                    "hepta-bg-"+GEN,unique,"com.android.shell",true):census.screenSnapshot(210,"hepta-bg-"+GEN);
            if(afterRead!=null)afterRead.run();return value;
        }
        public void acquire(int flags,int display,long duration)throws Exception{
            if(flags!=0xa||display!=210)throw new AssertionError("unscoped or wake flags");
            acquires++;remaining=duration;held=true;if(onAcquire!=null)onAcquire.run();
        }
        public boolean held(){return held;}
        public void release(){releases++;held=false;}
        PublicOwnGroupScreenLease.InitialWait waiter(){return millis->{
            if(millis<=0||millis>25)throw new AssertionError("wait exceeded bounded remaining budget");
            pauses++;slept+=millis;clock.now+=millis;if(onPause!=null)onPause.run();
        };}
    }
    static PublicOwnGroupScreenLease lease(Clock clock)throws Exception{
        return new PublicOwnGroupScreenLease(GEN,21000,clock);
    }
    static long originalDeadline(long request,long expires,long now){
        return PublicScreenInitializationFixture.deadline(request,expires,now);
    }
    static void released(PublicOwnGroupScreenLease lease,Port port)throws Exception{
        lease.retire();long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
        while(!Boolean.TRUE.equals(lease.evidence().get("release_returned"))&&System.nanoTime()<end)Thread.yield();
        yes(port.releases==1&&!port.held&&Boolean.TRUE.equals(lease.evidence().get("release_returned")),
                "the attempted exact token was not released");
    }
    public static void main(String[] args)throws Exception{
        test("original immediate acquire rejects the transient unknown display",()->{
            Clock c=new Clock();Port p=new Port(c);p.state=0;PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_NOT_ON",()->l.acquire(p));
            yes(p.reads==1&&p.acquires==0&&p.pauses==0,"old strict behavior changed");
        });
        test("already on initial display still has a fresh acquire and confirm census",()->{
            Clock c=new Clock();Port p=new Port(c);p.state=2;PublicOwnGroupScreenLease l=lease(c);
            l.acquireInitiallyOn(p,4000,p.waiter());
            yes(p.reads==3&&p.pauses==0&&p.acquires==1&&p.remaining==20000,"fresh ON or absolute expiry missing");
            released(l,p);
        });
        test("unknown then off then on uses the complete actual Binder census every time",()->{
            Clock c=new Clock();Port p=new Port(c);p.census=new PublicScreenCensusFixture();
            p.census.service.rows.get(210).state=0;
            p.onPause=()->p.census.service.rows.get(210).state=p.pauses==1?1:2;
            PublicOwnGroupScreenLease l=lease(c);l.acquireInitiallyOn(p,4000,p.waiter());
            yes(p.reads==5&&p.census.service.enumerations==10&&p.census.service.directReads==15,
                    "readiness reused or omitted the full includeDisabled census");
            yes(p.acquires==1&&p.slept==50&&p.remaining==19950,"initial readiness changed the lifetime");
            Map<String,Object> e=l.evidence();
            yes(Integer.valueOf(3).equals(e.get("initial_readiness_census_count"))
                    &&Integer.valueOf(0).equals(e.get("initial_first_display_state"))
                    &&Integer.valueOf(2).equals(e.get("initial_last_display_state"))
                    &&Long.valueOf(1050).equals(e.get("initial_on_observed_elapsed_ms")),"actual state history missing");
            yes(p.census.service.rows.get(0).state==1&&p.census.service.rows.get(1).state==2,
                    "physical power changed");released(l,p);
        });
        test("original three second create RPC wins over the five second upper bound",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);
            long end=originalDeadline(4000,21000,1000);
            yes(end==4000&&originalDeadline(10000,21000,1000)==6000,"extracted production deadline differs");
            refuse("PUBLIC_SCREEN_INITIAL_DEADLINE_EXPIRED",()->l.acquireInitiallyOn(p,end,p.waiter()));
            yes(c.now==4000&&p.slept==3000&&p.reads==120&&p.acquires==0,"create received a fresh or longer budget");
        });
        test("session expiry remains an earlier initialization bound",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);
            long end=originalDeadline(4000,1050,1000);
            refuse("PUBLIC_SCREEN_INITIAL_DEADLINE_EXPIRED",()->l.acquireInitiallyOn(p,end,p.waiter()));
            yes(end==1050&&c.now==1050&&p.slept==50&&p.acquires==0,"session bound was extended");
        });
        test("time spent in create is deducted and the last pause uses only the remainder",()->{
            Clock c=new Clock();long end=originalDeadline(4000,21000,c.now);c.now=3990;
            Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_INITIAL_DEADLINE_EXPIRED",()->l.acquireInitiallyOn(p,end,p.waiter()));
            yes(p.pauses==1&&p.slept==10&&c.now==4000&&p.acquires==0,"create time was refunded");
        });
        test("already expired initialization refuses without a scope read",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_INITIAL_DEADLINE_INVALID",()->l.acquireInitiallyOn(p,1000,p.waiter()));
            yes(p.reads==0&&p.acquires==0,"expired request touched power");
        });
        test("a new five second plus budget is refused",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_INITIAL_DEADLINE_INVALID",()->l.acquireInitiallyOn(p,6001,p.waiter()));
            yes(p.reads==0&&p.acquires==0,"unbounded initial request admitted");
        });
        test("initial budget cannot exceed the original lease lifetime",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=new PublicOwnGroupScreenLease(GEN,2000,c);
            refuse("PUBLIC_SCREEN_INITIAL_DEADLINE_INVALID",()->l.acquireInitiallyOn(p,2001,p.waiter()));
            yes(p.reads==0&&p.acquires==0,"session expiry bypassed");
        });
        test("a late on census cannot authorize a power call",()->{
            Clock c=new Clock();Port p=new Port(c);p.state=2;p.afterRead=()->c.now=4000;
            PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_INITIAL_DEADLINE_EXPIRED",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            yes(p.reads==1&&p.acquires==0,"late ON was accepted");
        });
        test("on readiness followed by off fresh acquisition read is refused",()->{
            Clock c=new Clock();Port p=new Port(c);p.state=2;p.afterRead=()->p.state=1;
            PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_NOT_ON",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            yes(p.reads==2&&p.acquires==0,"stale ON was reused");
        });
        test("on readiness followed by a replaced unique display is refused",()->{
            Clock c=new Clock();Port p=new Port(c);p.state=2;p.afterRead=()->p.unique="virtual:replacement";
            PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_INITIAL_IDENTITY_CHANGED",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            yes(p.reads==2&&p.acquires==0,"replacement acquired old display authority");
        });
        test("acquire returning after the create deadline releases its exact late token",()->{
            Clock c=new Clock();Port p=new Port(c);p.state=2;p.onAcquire=()->c.now=4000;
            PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_INITIAL_DEADLINE_EXPIRED",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            released(l,p);yes(p.acquires==1&&Boolean.TRUE.equals(l.evidence().get("admission_retired")),"late acquire became active");
        });
        test("post acquire confirmation crossing the create deadline also releases",()->{
            Clock c=new Clock();Port p=new Port(c);p.state=2;p.afterRead=()->{if(p.reads==3)c.now=4000;};
            PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_INITIAL_DEADLINE_EXPIRED",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            released(l,p);yes(p.acquires==1&&p.reads==3,"late confirmation accepted");
        });
        test("same display integer changing unique identity during wait is refused",()->{
            Clock c=new Clock();Port p=new Port(c);p.onPause=()->p.unique="virtual:replacement";
            PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_INITIAL_IDENTITY_CHANGED",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            yes(p.pauses==1&&p.acquires==0,"identity failure was retried");
        });
        test("disabled additional physical display is refused by the next complete census",()->{
            Clock c=new Clock();Port p=new Port(c);p.census=new PublicScreenCensusFixture();p.census.service.rows.get(210).state=1;
            p.onPause=()->{p.census.service.ids=new int[]{0,1,210,211};
                p.census.service.rows.put(211,new PublicScreenCensusFixture.Info(211,1,2,1));};
            PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_UNREVIEWED_PHYSICAL_DISPLAY",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            yes(p.pauses==1&&p.acquires==0,"disabled physical group member ignored");
        });
        test("missing direct display information is never treated as readiness",()->{
            Clock c=new Clock();Port p=new Port(c);p.census=new PublicScreenCensusFixture();p.census.service.rows.get(210).state=1;
            p.onPause=()->p.census.service.rows.remove(1);PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_CENSUS_UNAVAILABLE",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            yes(p.pauses==1&&p.acquires==0,"unknown census was retried");
        });
        test("dozing and other noninitial states are refused without a wait",()->{
            for(int state:new int[]{-1,3,4,5,6}){
                Clock c=new Clock();Port p=new Port(c);p.state=state;PublicOwnGroupScreenLease l=lease(c);
                refuse("PUBLIC_SCREEN_INITIAL_STATE_REFUSED",()->l.acquireInitiallyOn(p,4000,p.waiter()));
                yes(p.pauses==0&&p.acquires==0,"sleeping or unsupported display was waited on");
            }
        });
        test("owner change during initial wait is refused immediately",()->{
            Clock c=new Clock();Port p=new Port(c);p.onPause=()->p.uid=2000;PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_IDENTITY_INVALID",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            yes(p.pauses==1&&p.acquires==0,"owner mismatch was retried");
        });
        test("a physical display joining the selected group is refused immediately",()->{
            Clock c=new Clock();Port p=new Port(c);p.onPause=()->p.cover=2;PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_GROUP_NOT_ISOLATED",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            yes(p.pauses==1&&p.acquires==0,"physical group acquired screen authority");
        });
        test("a second initial acquire cannot renew either deadline",()->{
            Clock c=new Clock();Port p=new Port(c);p.state=2;PublicOwnGroupScreenLease l=lease(c);
            l.acquireInitiallyOn(p,4000,p.waiter());c.now=2000;
            refuse("PUBLIC_SCREEN_LEASE_ALREADY_ATTEMPTED",()->l.acquireInitiallyOn(p,5000,p.waiter()));
            yes(p.acquires==1&&Long.valueOf(4000).equals(l.evidence().get("initial_readiness_deadline_elapsed_ms")),
                    "duplicate attempt changed initialization expiry");released(l,p);
        });
        test("retirement latches while readiness is paused without waiting for the API gate",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);
            CountDownLatch waiting=new CountDownLatch(1),resume=new CountDownLatch(1);
            AtomicReference<Throwable> result=new AtomicReference<Throwable>();
            Thread t=new Thread(()->{try{l.acquireInitiallyOn(p,4000,millis->{waiting.countDown();
                if(!resume.await(2,TimeUnit.SECONDS))throw new IOException("test wait timeout");c.now+=millis;});}
                catch(Throwable error){result.set(error);}});t.start();
            yes(waiting.await(2,TimeUnit.SECONDS),"readiness never entered wait");
            long begin=System.nanoTime();l.retire();
            yes(System.nanoTime()-begin<TimeUnit.MILLISECONDS.toNanos(250),"retirement waited for the acquisition gate");
            resume.countDown();t.join(2000);
            yes(!t.isAlive()&&result.get() instanceof IOException&&p.acquires==0&&p.releases==0,
                    "retired initialization acquired power");
        });
        test("interrupted readiness cannot silently acquire or repeat the attempt",()->{
            Clock c=new Clock();Port p=new Port(c);PublicOwnGroupScreenLease l=lease(c);
            try{l.acquireInitiallyOn(p,4000,millis->{throw new InterruptedException("test interrupt");});
                throw new AssertionError("interrupted wait continued");}
            catch(InterruptedException expected){checks++;}
            yes(p.acquires==0&&Boolean.TRUE.equals(l.evidence().get("admission_retired")),"interruption did not retire");
            refuse("PUBLIC_SCREEN_LEASE_ALREADY_ATTEMPTED",()->l.acquireInitiallyOn(p,4000,p.waiter()));
        });
        test("a clock reversing during the scope read cannot extend readiness",()->{
            Clock c=new Clock();Port p=new Port(c);p.state=2;p.afterRead=()->c.now=999;PublicOwnGroupScreenLease l=lease(c);
            refuse("PUBLIC_SCREEN_INITIAL_CLOCK_REVERSED",()->l.acquireInitiallyOn(p,4000,p.waiter()));
            yes(p.acquires==0&&p.pauses==0,"reversed time accepted");
        });
        test("virtual peer joining during automatic readiness preserves the original budget",()->{
            Clock c=new Clock();Port p=new Port(c);p.census=new PublicScreenCensusFixture();p.census.service.rows.get(210).state=1;
            p.onPause=()->{p.census.service.ids=new int[]{0,1,210,211};
                p.census.service.rows.put(211,new PublicScreenCensusFixture.Info(211,5,2,1));
                p.census.service.rows.get(210).state=2;};
            PublicOwnGroupScreenLease l=lease(c);l.acquireInitiallyOn(p,4000,p.waiter());
            yes(p.pauses==1&&p.acquires==1&&p.remaining==19975,"virtual peer renewed or blocked readiness");
            yes(p.census.screenSnapshot(210,"hepta-bg-"+GEN).groupMembers==2,"shared group omitted from evidence");
            released(l,p);
        });
        StringBuilder json=new StringBuilder("{\"schema\":\"hepta.public-screen-initial-readiness-host.v1\",\"all_pass\":true,\"cases\":")
                .append(names.size()).append(",\"assertions\":").append(checks)
                .append(",\"phone_operations\":0,\"android_power_api_executed\":false,\"case_names\":[");
        for(int i=0;i<names.size();i++){if(i>0)json.append(',');json.append('"').append(names.get(i)).append('"');}
        System.out.println(json.append("]}"));
    }
}
