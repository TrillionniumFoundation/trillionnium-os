package org.trillionnium.hepta.background;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;

/** Executes the extracted production policy guard and failure audit against failing host ports.
 * It does not replace the Android framework or claim any phone/runtime qualification. */
public final class PublicPolicyDiagnosticsHostTest {
    static int checks,cases;
    static final List<String> names=new ArrayList<String>();
    interface Work{void run()throws Exception;}
    static void yes(boolean value,String reason){checks++;if(!value)throw new AssertionError(reason);}
    static void one(String name,Work work)throws Exception{work.run();names.add(name);cases++;}
    static final class BrokerProtocol {
        static final class Refusal extends Exception {
            private static final long serialVersionUID=1L;
            final String code;
            Refusal(String code){super(code);this.code=code;}
        }
    }
    static final class SystemClock {static long elapsedRealtime(){return 1000;}}
    static final class KeyguardManager {boolean locked,deviceLocked;boolean isKeyguardLocked(){return locked;}boolean isDeviceLocked(){return deviceLocked;}}
    static final class Config{Object publicOwnGroupScope=new Object(),profileTarget;String generation="host-only";}
    static final class Probe{
        final List<String> calls=new ArrayList<String>();String failAt;Exception failure;
        void check(String operation)throws Exception{calls.add(operation);if(operation.equals(failAt))throw failure;}
    }
    static final class PublicOwnGroupFramework{
        final Probe p;PublicOwnGroupFramework(Probe p){this.p=p;}
        void read(String generation,int display,String name)throws Exception{p.check("framework.read");}
        void preflight()throws Exception{p.check("framework.preflight");}
    }
    static final class ScreenLease{final Probe p;ScreenLease(Probe p){this.p=p;}void requireActive()throws Exception{p.check("screen.lease");}}
    static final class TaskSnapshot{}
    static final class PublicOwnGroupTaskFence{
        static final class Census{}
        final Probe p;PublicOwnGroupTaskFence(Probe p){this.p=p;}
        void observe(Census census,int display,long time)throws Exception{p.check("task.fence");}
    }
    static final class BackgroundTaskOrganizer{
        static PublicOwnGroupTaskFence.Census publicTaskLocations(Object activityTasks)throws Exception{
            ((Probe)activityTasks).check("task.census");return new PublicOwnGroupTaskFence.Census();
        }
    }
    static final class NotesReader{final Probe p;NotesReader(Probe p){this.p=p;}Object frame()throws Exception{p.check("notes.frame");return new Object();}}
    static final class NotesCustody{final Probe p;NotesCustody(Probe p){this.p=p;}void observe(Object frame,long time)throws Exception{p.check("notes.custody");}}
    static final class NotesAudit{int calls;void runtime(Exception e,long time){calls++;}}

/* INSERT_PRODUCTION_AUDIT */

    static final class Harness{
        final Probe p=new Probe();final Config config=new Config();
        final AtomicBoolean publicAdmissionRetired=new AtomicBoolean();
        final PublicPolicyFailureAudit publicPolicyFailures=new PublicPolicyFailureAudit();
        PublicOwnGroupFramework publicOwnGroupFramework=new PublicOwnGroupFramework(p);
        boolean publicOwnGroupDisplayReady=true;int displayId=42;String displayName="host-only",state="ACTIVE";
        ScreenLease publicScreenLease=new ScreenLease(p);
        PublicOwnGroupTaskFence publicTaskFence=new PublicOwnGroupTaskFence(p);
        Object activityTasks=p;NotesCustody publicNotesCustody=new NotesCustody(p);
        NotesReader publicNotesReader=new NotesReader(p);NotesAudit publicNotesReadFailures=new NotesAudit();
        long lastUnlockedCheck=-1;KeyguardManager keyguard=new KeyguardManager();
        TaskSnapshot snapshot()throws Exception{p.check("task.snapshot");return new TaskSnapshot();}
        void verifyLaunchedLocations(TaskSnapshot snapshot)throws Exception{p.check("personal.location");}

/* INSERT_PRODUCTION_GUARD */

        BrokerProtocol.Refusal refused()throws Exception{
            try{requireUnlocked();throw new AssertionError("failed policy admitted");}
            catch(BrokerProtocol.Refusal refusal){return refusal;}
        }
        Map<?,?> failure(){return (Map<?,?>)publicPolicyFailures.evidence().get("first_failure");}
    }

    static final List<String> ORDER=Arrays.asList("framework.read","screen.lease","task.snapshot","personal.location","task.census","task.fence","notes.frame","notes.custody");
    static String phase(String operation){
        if(operation.startsWith("framework."))return operation.endsWith("read")?"FRAMEWORK_READ":"FRAMEWORK_PREFLIGHT";
        if(operation.equals("screen.lease"))return "SCREEN_LEASE";
        if(operation.equals("task.snapshot")||operation.equals("personal.location"))return "PERSONAL_TASK_LOCATION";
        if(operation.startsWith("task."))return "TASK_LOCATION_CENSUS";
        return "NOTES_FRAME_AND_CUSTODY";
    }
    static String serialized(PublicPolicyFailureAudit audit){return new JSONObject(audit.evidence()).toString();}
    public static void main(String[] args)throws Exception{
        one("successful public guard retains every check and order",()->{
            Harness h=new Harness();h.requireUnlocked();
            yes(h.p.calls.equals(ORDER),"operation order changed");yes(h.lastUnlockedCheck==1000,"successful clock missing");
            yes(h.failure()==null,"success produced failure");yes(h.publicNotesReadFailures.calls==0,"success produced notes failure");
        });
        one("profile mode skips personal package locations only",()->{
            Harness h=new Harness();h.config.profileTarget=new Object();h.requireUnlocked();
            yes(h.p.calls.equals(Arrays.asList("framework.read","screen.lease","task.census","task.fence","notes.frame","notes.custody")),"profile check order changed");
        });
        one("preflight and pre-active paths preserve original guards",()->{
            Harness h=new Harness();h.publicOwnGroupDisplayReady=false;h.displayId=-1;h.publicNotesReader=null;h.requireUnlocked();
            yes(h.p.calls.equals(Collections.singletonList("framework.preflight")),"preflight branch changed");
            h=new Harness();h.state="CREATED";h.publicNotesCustody=null;h.requireUnlocked();
            yes(!h.p.calls.contains("screen.lease")&&!h.p.calls.contains("notes.frame"),"inactive gates changed");
        });
        for(String operation:ORDER)one("unexpected failure at "+operation+" remains fail closed",()->{
            Harness h=new Harness();h.p.failAt=operation;h.p.failure=new IOException("private owner content 000000-secret");
            yes("PUBLIC_SCOPE_POLICY_UNAVAILABLE".equals(h.refused().code),"generic refusal changed");
            yes(h.p.calls.equals(ORDER.subList(0,ORDER.indexOf(operation)+1)),"checks retried or continued after failure");
            yes(h.lastUnlockedCheck==-1,"failure advanced admission clock");
            Map<?,?> row=h.failure();yes(phase(operation).equals(row.get("phase")),"incorrect operation phase");
            yes("java.io.IOException".equals(row.get("exception_class"))&&"IO_FAILURE".equals(row.get("category")),"exception classification missing");
            yes(!serialized(h.publicPolicyFailures).contains("private")&&!serialized(h.publicPolicyFailures).contains("secret"),"message leaked");
            yes(h.publicNotesReadFailures.calls==1,"original notes audit changed");
        });
        one("preflight failure has its own diagnostic phase",()->{
            Harness h=new Harness();h.publicOwnGroupDisplayReady=false;h.p.failAt="framework.preflight";h.p.failure=new IllegalAccessException("private");
            yes("PUBLIC_SCOPE_POLICY_UNAVAILABLE".equals(h.refused().code),"preflight refusal changed");
            yes("FRAMEWORK_PREFLIGHT".equals(h.failure().get("phase"))&&"FRAMEWORK_REFLECTION_ACCESS_DENIED".equals(h.failure().get("category")),"preflight diagnostics differ");
        });
        for(String operation:ORDER)one("typed policy refusal unchanged at "+operation,()->{
            Harness h=new Harness();h.p.failAt=operation;BrokerProtocol.Refusal original=new BrokerProtocol.Refusal("HOST_TYPED_REFUSAL");
            h.p.failure=original;yes(h.refused()==original,"typed refusal replaced");yes(h.failure()==null,"typed refusal reclassified");
            yes(h.publicNotesReadFailures.calls==0,"typed refusal audited as unexpected");yes(h.lastUnlockedCheck==-1,"typed refusal changed clock");
        });
        one("retired and unavailable framework refuse before framework operations",()->{
            Harness h=new Harness();h.publicAdmissionRetired.set(true);
            yes("PUBLIC_SCOPE_RETIRED".equals(h.refused().code)&&h.p.calls.isEmpty()&&h.failure()==null,"retirement gate changed");
            h=new Harness();h.publicOwnGroupFramework=null;
            yes("PUBLIC_SCOPE_FRAMEWORK_UNAVAILABLE".equals(h.refused().code)&&h.p.calls.isEmpty()&&h.failure()==null,"framework gate changed");
        });
        one("reflection cause is bounded and private text is absent",()->{
            Harness h=new Harness();h.p.failAt="framework.read";
            h.p.failure=new InvocationTargetException(new InvocationTargetException(new SecurityException("token SECRET phone account")));
            h.refused();Map<?,?> row=h.failure();
            yes("java.lang.reflect.InvocationTargetException".equals(row.get("exception_class")),"wrapper class missing");
            yes("java.lang.SecurityException".equals(row.get("cause_class"))&&Integer.valueOf(2).equals(row.get("reflection_wrapper_count")),"nested cause missing");
            yes("FRAMEWORK_PERMISSION_DENIED".equals(row.get("category"))&&!serialized(h.publicPolicyFailures).contains("SECRET"),"unsafe cause classification");
        });
        String[] reasonTokens={"PUBLIC_SCREEN_NOT_ON","PUBLIC_SCREEN_LEASE_NOT_HELD","PUBLIC_SCREEN_LEASE_RETIRED","PUBLIC_SCREEN_LIFETIME_IDENTITY_CHANGED"};
        for(String token:reasonTokens)one("fixed screen category "+token,()->{
            Harness h=new Harness();h.p.failAt="screen.lease";h.p.failure=new IOException(token);h.refused();
            yes(token.equals(h.failure().get("category")),"fixed screen category not retained");
            h=new Harness();h.p.failAt="screen.lease";h.p.failure=new IOException(token+" SECRET");
            h.refused();yes("IO_FAILURE".equals(h.failure().get("category"))&&!serialized(h.publicPolicyFailures).contains("SECRET"),"nonexact message retained");
        });
        one("first failure cannot be replaced by cleanup or later checks",()->{
            Harness h=new Harness();h.p.failAt="framework.read";h.p.failure=new IOException("original");h.refused();
            Map<?,?> first=h.failure();h.p.failAt="screen.lease";h.p.failure=new IOException("PUBLIC_SCREEN_LEASE_RETIRED");h.refused();
            yes(first==h.failure()&&"FRAMEWORK_READ".equals(h.failure().get("phase")),"first failure overwritten");
            try{h.publicPolicyFailures.evidence().put("diagnostics_grant_authority",true);throw new AssertionError("mutable audit");}
            catch(UnsupportedOperationException expected){checks++;}
            yes(Boolean.FALSE.equals(h.publicPolicyFailures.evidence().get("diagnostics_grant_authority"))&&Boolean.FALSE.equals(h.publicPolicyFailures.evidence().get("provides_cleanup_proof")),"diagnostics grant authority");
        });
        one("concurrent audits preserve one complete first record",()->{
            PublicPolicyFailureAudit audit=new PublicPolicyFailureAudit();CountDownLatch go=new CountDownLatch(1);
            Thread a=new Thread(()->{try{go.await();audit.record(PublicPolicyFailureAudit.Phase.FRAMEWORK_READ,new SecurityException("secret-a"),1);}catch(InterruptedException e){throw new AssertionError(e);}});
            Thread b=new Thread(()->{try{go.await();audit.record(PublicPolicyFailureAudit.Phase.SCREEN_LEASE,new IOException("PUBLIC_SCREEN_NOT_ON"),2);}catch(InterruptedException e){throw new AssertionError(e);}});
            a.start();b.start();go.countDown();a.join(2000);b.join(2000);yes(!a.isAlive()&&!b.isAlive(),"audit threads did not finish");
            Map<?,?> row=(Map<?,?>)audit.evidence().get("first_failure");String before=serialized(audit);
            audit.record(PublicPolicyFailureAudit.Phase.NOTES_FRAME_AND_CUSTODY,new Exception("secret-c"),3);
            yes(before.equals(serialized(audit)),"concurrent first record changed");
            yes(("FRAMEWORK_READ".equals(row.get("phase"))&&"FRAMEWORK_PERMISSION_DENIED".equals(row.get("category")))
                    ||("SCREEN_LEASE".equals(row.get("phase"))&&"PUBLIC_SCREEN_NOT_ON".equals(row.get("category"))),"torn diagnostic record");
        });
        one("deep reflection causes have a hard bound",()->{
            Exception cause=new IOException("SECRET");for(int i=0;i<20;i++)cause=new InvocationTargetException(cause);
            PublicPolicyFailureAudit audit=new PublicPolicyFailureAudit();audit.record(PublicPolicyFailureAudit.Phase.FRAMEWORK_READ,cause,1);
            Map<?,?> row=(Map<?,?>)audit.evidence().get("first_failure");
            yes(Integer.valueOf(8).equals(row.get("reflection_wrapper_count"))&&!serialized(audit).contains("SECRET"),"unbounded wrapper walk");
        });
        one("diagnostic exception cannot replace the original refusal",()->{
            Harness h=new Harness();h.p.failAt="screen.lease";h.p.failure=new IOException(){private static final long serialVersionUID=1L;
                @Override public String getMessage(){throw new IllegalStateException("private");}};
            yes("PUBLIC_SCOPE_POLICY_UNAVAILABLE".equals(h.refused().code),"diagnostic changed fail closed code");
            yes(h.lastUnlockedCheck==-1,"diagnostic changed admission");
        });
        one("existing response message path receives only fixed diagnostic labels",()->{
            Harness h=new Harness();yes(h.publicPolicyFailures.summary().isEmpty(),"empty audit acquired message");
            h.p.failAt="screen.lease";h.p.failure=new IOException("PUBLIC_SCREEN_NOT_ON");h.refused();
            String text=h.publicPolicyFailures.summary();
            yes(text.contains("SCREEN_LEASE")&&text.contains("PUBLIC_SCREEN_NOT_ON")&&text.contains("后台屏幕未保持亮屏"),"fixed phase and readable reason missing");
            h=new Harness();h.p.failAt="task.census";h.p.failure=new IOException("private account SECRET");h.refused();
            text=h.publicPolicyFailures.summary();yes(text.contains("TASK_LOCATION_CENSUS")&&text.contains("IO_FAILURE")&&!text.contains("SECRET")&&!text.contains("private"),"response message leaked exception text");
        });
        one("private display keyguard behavior is retained",()->{
            Harness h=new Harness();h.config.publicOwnGroupScope=null;h.keyguard.locked=true;
            yes("DEVICE_LOCKED".equals(h.refused().code)&&h.failure()==null&&h.p.calls.isEmpty(),"private keyguard changed");
            h=new Harness();h.config.publicOwnGroupScope=null;h.keyguard=null;
            yes("KEYGUARD_UNAVAILABLE".equals(h.refused().code),"private null keyguard changed");
        });
        JSONObject result=new JSONObject().put("schema","hepta.public-policy-diagnostics-host.v1").put("all_pass",true)
                .put("cases",cases).put("assertions",checks).put("case_names",names).put("phone_operations",0)
                .put("extracted_production_guard_executed",true).put("android_framework_executed",false)
                .put("startup_race_reproduced",false).put("phone_runtime_qualified",false);
        Files.write(Paths.get(args[0]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("cases="+cases+" assertions="+checks);
    }
}
