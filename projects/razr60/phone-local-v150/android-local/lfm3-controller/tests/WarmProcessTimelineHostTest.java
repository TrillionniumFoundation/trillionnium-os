import org.trillionnium.hepta.local.WarmProcessSession;
import org.trillionnium.hepta.local.WarmProcessTimeline;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Production lifecycle tests; protocol peers are synthetic, never a model or phone. */
public final class WarmProcessTimelineHostTest {
    private static final String G="11111111111111111111111111111111";
    private static final String T="22222222222222222222222222222222";
    private static final String R="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static int assertions;
    private static void check(boolean value,String message){
        assertions++;if(!value)throw new AssertionError(message);
    }
    private static final class Tracked extends Process {
        final Process child;int destroys,forces;
        Tracked(Process child){this.child=child;}
        public OutputStream getOutputStream(){return child.getOutputStream();}
        public InputStream getInputStream(){return child.getInputStream();}
        public InputStream getErrorStream(){return child.getErrorStream();}
        public int waitFor()throws InterruptedException{return child.waitFor();}
        public boolean waitFor(long timeout,TimeUnit unit)throws InterruptedException{return child.waitFor(timeout,unit);}
        public int exitValue(){return child.exitValue();}
        public boolean isAlive(){return child.isAlive();}
        public void destroy(){destroys++;child.destroy();}
        public Process destroyForcibly(){forces++;child.destroyForcibly();return this;}
    }
    private static final class Controlled extends Process {
        boolean alive=true;final boolean forceTerminates;int destroys,forces;
        Controlled(boolean forceTerminates){this.forceTerminates=forceTerminates;}
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public InputStream getInputStream(){return new ByteArrayInputStream(new byte[0]);}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public int waitFor(){return exitValue();}
        public boolean waitFor(long timeout,TimeUnit unit){return !alive;}
        public int exitValue(){if(alive)throw new IllegalThreadStateException("still alive");return 137;}
        public boolean isAlive(){return alive;}
        public void destroy(){destroys++;}
        public Process destroyForcibly(){forces++;if(forceTerminates)alive=false;return this;}
    }
    private static Tracked child(String mode)throws Exception{
        return new Tracked(new ProcessBuilder(System.getProperty("java.home")+"/bin/java",
                "-cp",System.getProperty("java.class.path"),WarmProcessTimelineHostTest.class.getName(),
                "child",mode).redirectError(ProcessBuilder.Redirect.INHERIT).start());
    }
    private static void peer(String mode)throws Exception{
        if("early".equals(mode))return;
        String pid=ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
        System.out.println("HEPTA_WARM_READY "+G+" "+T+" "+pid);System.out.flush();
        BufferedReader input=new BufferedReader(new InputStreamReader(System.in,"US-ASCII"));
        for(String line;(line=input.readLine())!=null;){
            String[] p=line.split(" ");
            if("CLOSE".equals(p[0])){
                if("close-hang".equals(mode))Thread.sleep(20000);
                return;
            }
            if("stall".equals(mode)){Thread.sleep(20000);return;}
            System.out.println("HEPTA_WARM_DONE "+G+" "+T+" "+p[3]+" "+p[4]+" 0");
            System.out.flush();
        }
    }
    private static Map<?,?> event(Map<String,Object> snapshot,String key){
        Object value=snapshot.get(key);
        check(value instanceof Map<?,?>,key+" event exists");
        return (Map<?,?>)value;
    }
    private static void source(Map<String,Object> snapshot,String key,String expected){
        check(expected.equals(event(snapshot,key).get("source")),key+" source");
    }
    private static void counts(WarmProcessTimeline timeline,int destroys,int forces){
        Map<String,Object> value=timeline.snapshot();
        check(Integer.valueOf(destroys).equals(value.get("destroy_invocation_count")),"destroy calls match actual Process invocations");
        check(Integer.valueOf(forces).equals(value.get("destroy_forcibly_invocation_count")),"force calls match actual Process invocations");
    }
    private static void identityAndClock(WarmProcessTimeline timeline){
        Map<String,Object> value=timeline.snapshot();
        check("hepta.parent-process-timeline.v1".equals(value.get("schema")),"timeline schema");
        check(G.equals(value.get("worker_generation"))&&T.equals(value.get("task_id")),"exact task/generation binding");
        check("System.nanoTime".equals(value.get("clock"))&&"nanoseconds".equals(value.get("units")),"monotonic clock and units");
        check("parent_warm_task_timeline_creation".equals(value.get("origin")),"explicit relative origin");
        check("same_parent_process_only".equals(value.get("clock_scope")),"no cross-clock comparison");
        check(Boolean.FALSE.equals(value.get("signal_delivery_proven"))&&Boolean.FALSE.equals(value.get("exit_cause_inferred")),"no unsupported signal or causal claim");
        long snapshot=((Long)value.get("snapshot_elapsed_ns")).longValue();
        String[] keys={"first_cancel_requested","first_destroy_invoked","first_destroy_forcibly_invoked","first_exit_observed"};
        for(String key:keys){
            Object raw=value.get(key);
            if(raw==null)continue;
            Map<?,?> item=(Map<?,?>)raw;
            long elapsed=((Long)item.get("elapsed_ns")).longValue();
            check(elapsed>=0&&elapsed<=snapshot,key+" within snapshot");
            check(((Integer)item.get("sequence")).intValue()>0,key+" sequence");
        }
    }
    private static void naturalClose()throws Exception{
        Tracked p=child("good");WarmProcessTimeline timeline=new WarmProcessTimeline(G,T);
        WarmProcessSession s=new WarmProcessSession(p,G,T,timeline);
        WarmProcessSession.Reply reply=s.exchange(R,32,1000);
        check(reply.status==0&&reply.sequence==1&&p.isAlive(),"request completion preserves warm process");
        check(timeline.snapshot().get("first_exit_observed")==null,"request is not process exit");
        WarmProcessSession.Cleanup end=s.finish();
        check(end.exitObserved&&Integer.valueOf(0).equals(end.exitCode)&&!end.forceSent,"natural exit remains successful");
        Map<String,Object> value=timeline.snapshot();
        check(value.get("first_cancel_requested")==null&&value.get("first_destroy_invoked")==null
                &&value.get("first_destroy_forcibly_invoked")==null,"natural close has null cancel/signal events");
        source(value,"first_exit_observed","graceful_close_wait");
        check(Integer.valueOf(0).equals(event(value,"first_exit_observed").get("exit_code")),"actual exit code recorded");
        check(p.destroys==0&&p.forces==0,"instrumentation adds no natural-close signal");
        counts(timeline,p.destroys,p.forces);identityAndClock(timeline);
    }
    private static void requestDeadline()throws Exception{
        Tracked p=child("stall");WarmProcessTimeline timeline=new WarmProcessTimeline(G,T);
        WarmProcessSession s=new WarmProcessSession(p,G,T,timeline);
        try{s.exchange(R,32,1000);throw new AssertionError("deadline accepted");}
        catch(WarmProcessSession.Failure expected){
            check(expected.timedOut&&expected.cleanup.exitObserved&&!p.isAlive(),"deadline terminal unchanged");
            check(!expected.cleanup.forceSent,"cooperative deadline process needs no force");
        }
        Map<String,Object> first=timeline.snapshot();
        source(first,"first_cancel_requested","request_deadline");
        source(first,"first_destroy_invoked","request_deadline");
        check(p.destroys==2&&p.forces==0,"baseline cancel plus termination invocations retained exactly");
        WarmProcessSession.Cleanup end=s.finish();
        check(end.exitObserved&&!end.forceSent,"deadline cleanup retained");
        check(first.get("first_cancel_requested").equals(timeline.snapshot().get("first_cancel_requested")),"deadline first-wins");
        check(p.destroys==2&&p.forces==0,"observed cleanup adds no signal");
        counts(timeline,p.destroys,p.forces);identityAndClock(timeline);
    }
    private static void closeDeadline()throws Exception{
        Tracked p=child("close-hang");WarmProcessTimeline timeline=new WarmProcessTimeline(G,T);
        WarmProcessSession s=new WarmProcessSession(p,G,T,timeline);s.exchange(R,32,1000);
        WarmProcessSession.Cleanup end=s.finish();
        check(end.exitObserved&&!end.forceSent&&!p.isAlive(),"close-timeout exit retained");
        Map<String,Object> value=timeline.snapshot();
        check(value.get("first_cancel_requested")==null,"graceful close timeout does not invent explicit cancel");
        source(value,"first_destroy_invoked","close_wait_expired");
        check(p.destroys==1&&p.forces==0,"baseline graceful-close deadline sends exactly one destroy");
        counts(timeline,p.destroys,p.forces);identityAndClock(timeline);
    }
    private static void repeatedCancelAndForce(){
        Controlled p=new Controlled(true);WarmProcessTimeline timeline=new WarmProcessTimeline(G,T);
        WarmProcessSession s=new WarmProcessSession(p,G,T,timeline);
        s.cancel();Map<String,Object> first=timeline.snapshot();s.cancel();
        WarmProcessSession.Cleanup end=s.finish();
        check(end.exitObserved&&Integer.valueOf(137).equals(end.exitCode)&&end.forceSent,"force terminal preserved");
        check(p.destroys==4&&p.forces==1,"two cancels plus existing finish/termination calls, exactly one force");
        Map<String,Object> value=timeline.snapshot();
        check(first.get("first_cancel_requested").equals(value.get("first_cancel_requested")),"first cancel preserved");
        check(first.get("first_destroy_invoked").equals(value.get("first_destroy_invoked")),"first destroy preserved");
        source(value,"first_cancel_requested","session_cancel");
        source(value,"first_destroy_forcibly_invoked","force_wait_expired");
        check(s.finish().forceSent&&p.destroys==4&&p.forces==1,"later finish preserves prior force without extra invocation");
        counts(timeline,p.destroys,p.forces);identityAndClock(timeline);
    }
    private static void unknownExit(){
        Controlled p=new Controlled(false);WarmProcessTimeline timeline=new WarmProcessTimeline(G,T);
        WarmProcessSession.Cleanup end=new WarmProcessSession(p,G,T,timeline).finish();
        check(!end.exitObserved&&end.exitCode==null&&end.forceSent,"unobserved exit remains unknown");
        check(timeline.snapshot().get("first_exit_observed")==null,"unknown exit timestamp stays null");
        check(p.destroys==1&&p.forces==1,"unknown termination retains existing call counts");
        counts(timeline,p.destroys,p.forces);identityAndClock(timeline);
    }
    private static void exitBeforeCancel()throws Exception{
        Tracked p=child("early");
        check(p.waitFor(5000,TimeUnit.MILLISECONDS),"child exits before parent cancellation");
        WarmProcessTimeline timeline=new WarmProcessTimeline(G,T);
        WarmProcessSession s=new WarmProcessSession(p,G,T,timeline);s.cancel();
        check(p.destroys==0,"cancel does not signal already dead process");
        check(timeline.snapshot().get("first_exit_observed")==null,"external wait does not fabricate session observation");
        WarmProcessSession.Cleanup end=s.finish();
        check(end.exitObserved&&Integer.valueOf(0).equals(end.exitCode)&&!end.forceSent,"early natural exit remains exit zero");
        check(p.destroys==1&&p.forces==0,"existing unconditional termination invocation is preserved even after early exit");
        Map<String,Object> value=timeline.snapshot();
        source(value,"first_cancel_requested","session_cancel");
        source(value,"first_destroy_invoked","termination");
        check(Boolean.FALSE.equals(value.get("exit_cause_inferred")),"late observation cannot establish actual exit ordering");
        counts(timeline,p.destroys,p.forces);identityAndClock(timeline);
    }
    private static void ownerBindingAndAbsence(){
        WarmProcessTimeline timeline=new WarmProcessTimeline(G,T);Map<String,Object> value=timeline.snapshot();
        check(value.get("first_cancel_requested")==null&&value.get("first_destroy_invoked")==null
                &&value.get("first_destroy_forcibly_invoked")==null&&value.get("first_exit_observed")==null,"absent events are null");
        timeline.cancelRequested(WarmProcessTimeline.Source.OWNER_HANDLE_CANCEL);
        check(timeline.snapshot().get("first_destroy_invoked")==null,"prelaunch cancellation has no signal");
        try{
            new WarmProcessSession(new Controlled(false),G,R,timeline);
            throw new AssertionError("cross-task timeline accepted");
        }catch(IllegalArgumentException expected){check(true,"cross-task timeline rejected");}
        identityAndClock(timeline);
    }
    public static void main(String[] args)throws Exception{
        if(args.length==2&&"child".equals(args[0])){peer(args[1]);return;}
        naturalClose();requestDeadline();closeDeadline();repeatedCancelAndForce();unknownExit();exitBeforeCancel();ownerBindingAndAbsence();
        System.out.println("WarmProcessTimeline: "+assertions+" assertions PASS; production lifecycle, synthetic peer only; phone_tested=false");
    }
}
