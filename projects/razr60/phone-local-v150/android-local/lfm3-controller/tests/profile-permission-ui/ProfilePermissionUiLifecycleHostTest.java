package org.trillionnium.hepta.local;

import android.os.Looper;
import android.os.SystemClock;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.trillionnium.hepta.background.ProfileTarget;

/** Runs production ProfilePermissionUiSession and core with explicit inert
 * Binder/A11y substitutions. Checks real worker/visibility/journal lifecycle. */
public final class ProfilePermissionUiLifecycleHostTest {
    static final NativeAppGoal GOAL=NativeAppGoal.parse("查询2026年11月25日北京到上海的单程机票，1名成人",ProfileTarget.CTRIP);
    static String dump;static int cases,checks,ids;
    interface Checked {void run()throws Exception;}
    interface Condition {boolean ready()throws Exception;}
    static void yes(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    static void until(Condition condition,String why)throws Exception{
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        while(!condition.ready()){if(System.nanoTime()>=deadline)throw new AssertionError(why);Thread.sleep(2);}
    }
    static void signal(CountDownLatch latch,String why)throws Exception{yes(latch.await(3,TimeUnit.SECONDS),why);}
    static void test(String name,Checked action)throws Exception{action.run();yes(!ProfilePermissionUiSession.workPending(),"worker leaked after "+name);cases++;System.out.println("PASS "+name);}
    static final class Rig {
        final String id=String.format("%032x",++ids);final HeptaAccessibilityService service=new HeptaAccessibilityService();
        final ProfilePermissionUiSession ui=new ProfilePermissionUiSession(service);
        final AtomicBoolean cancel=new AtomicBoolean();final BackgroundSession bg;
        final File evidence;final Object activity=new Object();
        volatile Throwable failure;volatile boolean finished;Thread caller;
        Rig()throws Exception{bg=new BackgroundSession(dump,GOAL.ownerSha256);evidence=Files.createTempDirectory("permission-ui-host-").toFile();}
        void start(){start(SystemClock.elapsedRealtime()+10000);}
        void start(final long deadline){
            caller=new Thread(new Runnable(){public void run(){try{ui.prepare(id,GOAL,new TaskAuthorization.Gate(),new QualificationScopeConfig.Bound(),bg,evidence,
                    new HeptaAccessibilityService.Cancellation(){public boolean isCancelled(){return cancel.get();}},deadline);}
                catch(Throwable error){failure=error;}finally{finished=true;}}},"synthetic-controller");caller.setDaemon(true);caller.start();
        }
        ProfilePermissionUiSession.Presentation preview()throws Exception{
            until(()->ui.current()!=null&&ui.current().message.length()>0,"preview was not published");return ui.current();
        }
        boolean button()throws Exception{
            ProfilePermissionUiSession.Presentation p=preview();ui.ownerVisibility(activity,p,true);return ui.denyFromOwnerButton(p,activity);
        }
        void stop(){cancel.set(true);ui.retire(id,"test_stop");}
        void joined()throws Exception{until(()->finished,"controller waiter did not return");caller.join(100);until(()->!ProfilePermissionUiSession.workPending(),"worker did not drain");}
        void success()throws Exception{joined();yes(failure==null,"unexpected failure: "+failure);}
        void failed()throws Exception{joined();yes(failure!=null,"expected controlled failure");}
        void checkNoInput(){yes(bg.clicks.get()==0,"unexpected permission input");}
    }
    static void lateReady()throws Exception{
        test("confirmed late optional location uses same reservation and freshly confirms app",()->{
            Rig r=new Rig();r.bg.state="APP_READY";r.bg.confirmations.add("PERMISSION_PENDING");
            r.start();r.success();yes(r.bg.clicks.get()==1,"late optional location skipped");
            yes(r.bg.confirmationCalls.get()==2,"fresh app confirmation missing");
            yes(new File(r.evidence,"profile-permission-deny-result.json").isFile(),"missing late deny receipt");
        });
        test("late waiting settles to the existing app with no input",()->{
            Rig r=new Rig();r.bg.state="APP_READY";r.bg.advanceWaiting=true;r.bg.confirmations.add("WAITING");
            r.start();r.success();r.checkNoInput();yes(r.bg.confirmationCalls.get()==2,"expected one fresh confirmation");
        });
        test("permission arrives on ordinary read preceding final RPC",()->{
            Rig r=new Rig();r.bg.sampled.add("APP_READY");r.bg.sampled.add("PERMISSION_PENDING");
            r.start();r.success();yes(r.bg.clicks.get()==1&&r.bg.confirmationCalls.get()==1,"lost pending pre-confirmation read");
        });
        test("second changing confirmation fails without another dispatch",()->{
            Rig r=new Rig();r.bg.state="APP_READY";r.bg.advanceWaiting=true;
            r.bg.confirmations.add("WAITING");r.bg.confirmations.add("PERMISSION_PENDING");
            r.start();r.failed();r.checkNoInput();yes(r.bg.confirmationCalls.get()==2,"second deferral touched again");
        });
        test("unknown confirmation does not authorize a permission input",()->{
            Rig r=new Rig();r.bg.state="APP_READY";r.bg.confirmations.add("UNAVAILABLE");
            r.start();r.failed();r.checkNoInput();yes(r.bg.observations.get()==0,"unverified permission read");
        });
        test("a second permission after reserved input never retries the deny",()->{
            Rig r=new Rig();r.bg.confirmations.add("PERMISSION_PENDING");r.start();r.failed();
            yes(r.bg.clicks.get()==1&&r.bg.confirmationCalls.get()==1,"repeated deny or confirmation");
            yes(new File(r.evidence,"profile-permission-deny-result.json").isFile(),"missing first result");
        });
        test("late unknown permission retains original owner visibility rule",()->{
            Rig r=new Rig();r.bg.location=false;r.bg.state="APP_READY";r.bg.confirmations.add("PERMISSION_PENDING");
            r.start();ProfilePermissionUiSession.Presentation p=r.preview();
            yes(!r.ui.denyFromOwnerButton(p,r.activity),"hidden callback admitted");r.stop();r.failed();r.checkNoInput();
        });
        test("late waiting expires under the original deadline",()->{
            Rig r=new Rig();r.bg.state="APP_READY";r.bg.confirmations.add("WAITING");
            r.start(SystemClock.elapsedRealtime()+250);r.failed();r.checkNoInput();
            yes(r.bg.confirmationCalls.get()==1,"waiting started a fresh confirmation budget");
        });
    }
    static void runAll()throws Exception{
        lateReady();
        test("ordinary app ready needs no permission preview or input",()->{
            Rig r=new Rig();r.bg.state="APP_READY";r.start();r.success();r.checkNoInput();yes(r.bg.observations.get()==0,"read permission tree unnecessarily");
        });
        test("literal route optional location publishes durable state and denies fully hidden",()->{
            Rig r=new Rig();r.start();r.success();yes(r.bg.clicks.get()==1,"optional deny missing");
            yes(new File(r.evidence,"profile-permission-preview.json").isFile(),"preview not durable");
            yes(!r.ui.evidence(r.id).getBoolean("visible_pixels_verified"),"fabricated pixels");
            yes(!r.ui.evidence(r.id).getBoolean("owner_visible_choice_registered"),"fabricated owner button");
        });
        test("unknown permission never auto denies and hidden UI cannot submit owner choice",()->{
            Rig r=new Rig();r.bg.location=false;r.start();ProfilePermissionUiSession.Presentation p=r.preview();
            yes(!r.ui.denyFromOwnerButton(p,r.activity),"hidden owner choice admitted");r.stop();r.failed();r.checkNoInput();
        });
        test("visible current ordinary button admits exactly one manual denial",()->{
            Rig r=new Rig();r.bg.location=false;r.start();ProfilePermissionUiSession.Presentation p=r.preview();
            r.ui.ownerVisibility(r.activity,p,true);yes(r.ui.denyFromOwnerButton(p,r.activity),"visible denial refused");
            yes(!r.ui.denyFromOwnerButton(p,r.activity),"same owner callback replayed");r.success();yes(r.bg.clicks.get()==1,"manual input count");
        });
        test("different Activity cannot borrow the visible owner identity",()->{
            Rig r=new Rig();r.bg.location=false;r.start();ProfilePermissionUiSession.Presentation p=r.preview();r.ui.ownerVisibility(r.activity,p,true);
            yes(!r.ui.denyFromOwnerButton(p,new Object()),"foreign Activity callback admitted");r.stop();r.failed();r.checkNoInput();
        });
        test("focus loss after durable reservation invalidates final manual input",()->{
            Rig r=new Rig();r.bg.location=false;r.bg.beforeInput=new CountDownLatch(1);r.bg.releaseInput=new CountDownLatch(1);
            r.start();yes(r.button(),"manual button missing");signal(r.bg.beforeInput,"worker never reached input boundary");
            r.ui.ownerVisibility(r.activity,null,false);r.bg.releaseInput.countDown();r.failed();r.checkNoInput();
            yes(r.ui.evidence(r.id).getBoolean("attempt_reserved"),"uncertain reservation lost");
        });
        test("regaining focus creates a different identity and cannot revive spent choice",()->{
            Rig r=new Rig();r.bg.location=false;r.bg.beforeInput=new CountDownLatch(1);r.bg.releaseInput=new CountDownLatch(1);
            r.start();yes(r.button(),"manual button missing");signal(r.bg.beforeInput,"input boundary missing");
            r.ui.ownerVisibility(r.activity,null,false);r.ui.ownerVisibility(r.activity,r.ui.current(),true);
            r.bg.releaseInput.countDown();r.failed();r.checkNoInput();
        });
        test("cancelled blocked read keeps admission until actual worker return",()->{
            Rig r=new Rig();r.bg.readEntered=new CountDownLatch(1);r.bg.releaseRead=new CountDownLatch(1);r.start();signal(r.bg.readEntered,"read not entered");
            r.stop();until(()->r.finished,"cancel did not return controller waiter");yes(ProfilePermissionUiSession.workPending(),"blocked read released admission early");
            Rig replacement=new Rig();replacement.bg.state="APP_READY";replacement.start();until(()->replacement.finished,"overlap admission check hung");
            yes(replacement.failure!=null&&replacement.bg.reads.get()==0,"replacement worker overlapped blocked old read");
            r.bg.releaseRead.countDown();r.failed();r.checkNoInput();
        });
        test("stop during blocked pre-input call prevents late click and keeps worker pending",()->{
            Rig r=new Rig();r.bg.beforeInput=new CountDownLatch(1);r.bg.releaseInput=new CountDownLatch(1);r.start();signal(r.bg.beforeInput,"input guard not entered");
            r.stop();until(()->r.finished,"cancel waiter stuck");yes(ProfilePermissionUiSession.workPending(),"pre-input call drained falsely");
            r.bg.releaseInput.countDown();r.failed();r.checkNoInput();
        });
        test("stop after input entry retains a late receipt without replay or success",()->{
            Rig r=new Rig();r.bg.afterEntered=new CountDownLatch(1);r.bg.releaseEntered=new CountDownLatch(1);r.start();signal(r.bg.afterEntered,"effect not entered");
            r.stop();until(()->r.finished,"cancel waiter stuck");yes(ProfilePermissionUiSession.workPending(),"entered call drained falsely");
            r.bg.releaseEntered.countDown();r.failed();yes(r.bg.clicks.get()==1,"entered effect replayed or erased");
            yes(new File(r.evidence,"profile-permission-deny-result.json").isFile(),"late effect evidence lost");
        });
        test("scope retirement during final blocked input refuses the old lease",()->{
            Rig r=new Rig();r.bg.beforeInput=new CountDownLatch(1);r.bg.releaseInput=new CountDownLatch(1);r.start();signal(r.bg.beforeInput,"effect boundary missing");
            r.service.current=false;r.bg.releaseInput.countDown();r.failed();r.checkNoInput();
        });
        test("failed durable reservation spends attempt and prevents any input",()->{
            Rig r=new Rig();MobiMindPrivateFiles.failLeaf="profile-permission-deny-attempt.json";
            try{r.start();r.failed();r.checkNoInput();yes(r.ui.evidence(r.id).getBoolean("attempt_reserved"),"failed reservation not retained");}
            finally{MobiMindPrivateFiles.failLeaf=null;}
        });
        test("lost result write after input never retries and remains a failed task",()->{
            Rig r=new Rig();MobiMindPrivateFiles.failLeaf="profile-permission-deny-result.json";
            try{r.start();r.failed();yes(r.bg.clicks.get()==1,"uncertain effect count differs");
                yes(!r.ui.evidence(r.id).getBoolean("attempt_result_written"),"invented result receipt");}
            finally{MobiMindPrivateFiles.failLeaf=null;}
        });
        test("fresh deadline cannot reuse durable preview for same retired task",()->{
            Rig r=new Rig();r.start();r.success();int original=r.bg.clicks.get();r.finished=false;r.failure=null;r.bg.state="PERMISSION_PENDING";r.bg.active=true;
            r.start(SystemClock.elapsedRealtime()+11000);r.failed();yes(r.bg.clicks.get()==original,"same task replayed after deadline reset");
        });
        test("original deadline expiry cannot drain a blocked read or accept a new worker",()->{
            Rig r=new Rig();r.bg.readEntered=new CountDownLatch(1);r.bg.releaseRead=new CountDownLatch(1);r.start(SystemClock.elapsedRealtime()+120);
            signal(r.bg.readEntered,"bounded read not entered");until(()->r.finished,"deadline waiter did not return");
            yes(ProfilePermissionUiSession.workPending(),"deadline fabricated worker exit");r.bg.releaseRead.countDown();r.failed();r.checkNoInput();
        });
    }
    public static void main(String[] args){
        int code=1;
        try{Looper.initializeMain();dump=new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8);runAll();
            System.out.println("{\"cases\":"+cases+",\"assertions\":"+checks+",\"all_pass\":true,\"production_ui_session_executed\":true,\"android_adapter_executed\":false,\"phone_contacted\":false}");code=0;}
        catch(Throwable failure){failure.printStackTrace();}
        finally{System.exit(code);}
    }
}
