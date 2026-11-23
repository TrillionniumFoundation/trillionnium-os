package org.trillionnium.hepta.background;

import android.app.*;
import android.content.ComponentName;
import android.os.Binder;
import android.os.IBinder;
import android.os.SystemClock;
import android.window.IWindowOrganizerController;
import android.window.WindowContainerToken;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.json.JSONObject;

/** Complete production Reader/Organizer/Custody; framework rows, Binder objects and clock are synthetic. */
public final class NotesAfterReleaseReaderHostTest {
    private static int assertions;
    private static final List<String> CASES=new ArrayList<String>();
    private interface Work {void run()throws Exception;}
    private interface Hook {void read(Rig rig,int count);}
    private static void yes(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(String name,Work work)throws Exception{work.run();CASES.add(name);System.out.println("PASS "+name);}
    private static String reason(Throwable error){
        for(int i=0;i<12&&error.getCause()!=null;i++)error=error.getCause();
        return String.valueOf(error.getMessage());
    }
    private static Exception rejects(String code,Work work)throws Exception{
        try{work.run();throw new AssertionError("incomplete released-display evidence accepted");}
        catch(Exception error){yes(code==null||reason(error).contains(code),"wrong refusal "+reason(error)+" expected "+code);return error;}
    }
    private static final class Rig implements IActivityTaskManager {
        final NotesTaskInfoReaderHostTest.Env data=new NotesTaskInfoReaderHostTest.Env();
        final Object[] samples=new Object[3];final List<String> trace=new ArrayList<String>();
        final PublicPersonalNotesReader reader;
        final PublicPersonalNotesCustody custody;final PublicPersonalNotesCustody.ReleasedRead released;
        long deadline=100000;int allReads;Hook hook;
        Rig()throws Exception{this(1);}
        Rig(int tasks)throws Exception{
            samples[0]=data.rehydrate("before_all_roots",true);
            samples[1]=data.rehydrate("after_all_roots",true);
            samples[2]=data.rehydrate("before_all_roots",true);
            for(int index=1;index<tasks;index++){
                int id=1464+index;IBinder binder=new Binder();
                for(int phase=0;phase<3;phase++)add(phase,id,binder);
                TaskInfo own=data.row(NotesTaskInfoReaderHostTest.captured.getJSONObject("owned_display_roots")
                        .getJSONArray("rows").getJSONObject(0),false);
                own.taskId=id;own.token=new WindowContainerToken(binder);data.list(1).add(own);
            }
            reader=new PublicPersonalNotesReader(data.context,this,205,()->deadline);
            custody=prepareReleased(this);released=custody.releasedRead();
        }
        void add(int phase,int id,IBinder binder)throws Exception{
            for(Object value:data.rehydrate("before_all_roots",true))if(value instanceof TaskInfo&&((TaskInfo)value).taskId==1464){
                ActivityTaskManager.RootTaskInfo root=(ActivityTaskManager.RootTaskInfo)value;
                root.taskId=id;root.childTaskIds[0]=id;root.token=new WindowContainerToken(binder);rows(phase).add(root);return;
            }
            throw new AssertionError("synthetic additional root unavailable");
        }
        void drop(int id){for(int phase=0;phase<3;phase++)rows(phase).removeIf(
                value->value instanceof TaskInfo&&((TaskInfo)value).taskId==id);}

        @Override public Object getAllRootTaskInfos(){
            int count=++allReads;trace.add("all");if(hook!=null)hook.read(this,count);
            return samples[(count-1)%3];
        }
        @Override public IWindowOrganizerController getWindowOrganizerController(){return data.controller;}
        @SuppressWarnings("unchecked") List<Object> rows(int phase){return (List<Object>)samples[phase];}
        ActivityTaskManager.RootTaskInfo row(int phase){
            for(Object value:rows(phase))if(value instanceof TaskInfo&&((TaskInfo)value).taskId==1464)
                return (ActivityTaskManager.RootTaskInfo)value;
            throw new AssertionError("authored target row missing");
        }
        void empty(){for(int phase=0;phase<3;phase++)rows(phase).removeIf(
                value->value instanceof TaskInfo&&((TaskInfo)value).displayId==205);}
        void reset(){allReads=0;trace.clear();data.rootReads=0;data.childrenCalls=0;data.mutations=0;}
        void deletedDisplay(){
            data.onOwnRead=()->{throw new IllegalStateException("SIMULATED_DELETED_DISPLAY_QUERY");};
        }
        PublicPersonalNotesCustody.Frame frame()throws Exception{return reader.frameAfterRelease(released);}
        void noDisplayQuery(){
            yes(data.rootReads==0,"released display was queried through getRootTasks");
            yes(data.childrenCalls==0&&data.mutations==0,"reader performed a task/display mutation or child query");
        }
    }
    private static PublicOwnGroupPhysicalFence.RecentCensus recents()throws Exception{
        return PublicOwnGroupPhysicalFence.inspectRecents(PublicPhysicalAuditHostTest.recents(false));
    }
    private static PublicPersonalNotesCustody prepareReleased(Rig r)throws Exception{
        NotesTaskInfoReaderHostTest.Env initial=new NotesTaskInfoReaderHostTest.Env();initial.empty();
        PublicPersonalNotesCustody.Frame empty=initial.frame();
        PublicPersonalNotesCustody custody=new PublicPersonalNotesCustody(
                "11111111-1111-4111-8111-111111111111",String.join("",Collections.nCopies(64,"a")),
                10382,empty.global,recents());
        custody.beforeCreate();custody.bindDisplay(205);custody.markLaunch();
        PublicPersonalNotesCustody.Frame before=r.reader.frame();custody.observe(before,before.end);
        custody.retireAdmission();before=r.reader.frame();custody.prepareRelease(before,recents(),before.end);
        custody.enterRelease();custody.releaseReturned();r.reset();r.deletedDisplay();return custody;
    }
    private static void absence(PublicPersonalNotesCustody custody,PublicPersonalNotesCustody.Frame frame,
            boolean actualDisplayAbsent)throws Exception{
        custody.observeAbsence(frame.global,recents(),frame,actualDisplayAbsent,frame.begin,frame.end,frame.end);
    }
    private static void mutate(Rig r,int phase,String field){
        TaskInfo t=r.row(phase);
        if("null-token".equals(field))t.token=null;
        else if("null-cookies".equals(field))t.launchCookies=null;
        else if("null-intent".equals(field))t.baseIntent=null;
        else if("null-top-info".equals(field))t.topActivityInfo=null;
        else if("intent".equals(field))t.baseIntent.setComponent(new ComponentName("com.other.app","com.other.app.Main"));
        else if("real".equals(field))t.realActivity=new ComponentName("com.other.app","com.other.app.Main");
        else if("orig".equals(field))t.origActivity=new ComponentName("com.other.app","com.other.app.Main");
        else NotesTaskInfoReaderHostTest.change(t,field);
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("bundled synthetic input required");
        byte[] raw=Files.readAllBytes(Paths.get(args[0]));
        yes(raw.length==NotesTaskInfoReaderHostTest.SYNTHETIC_BYTES
                &&NotesTaskInfoReaderHostTest.SYNTHETIC_SHA.equals(NotesTaskInfoReaderHostTest.digest(raw)),"fixture provenance changed");
        NotesTaskInfoReaderHostTest.captured=new JSONObject(new String(raw,StandardCharsets.UTF_8));
        NotesTaskInfoReaderHostTest.actualCapture=false;
        test("ordinary frame retains the deleted-display refusal",()->{
            Rig r=new Rig();r.deletedDisplay();
            rejects("SIMULATED_DELETED_DISPLAY_QUERY",()->r.reader.frame());
            yes(r.data.rootReads==1&&r.allReads==1,"ordinary reader was changed");
            yes(r.data.childrenCalls==0&&r.data.mutations==0,"ordinary refusal mutated tasks");
        });
        test("after release uses three complete global censuses and zero display queries",()->{
            Rig r=new Rig();r.deletedDisplay();PublicPersonalNotesCustody.Frame frame=r.frame();
            yes(r.allReads==3&&r.trace.equals(Arrays.asList("all","all","all")),"not three complete reads");
            yes(frame.roots.size()==1&&frame.global.allIds.contains(1464),"residue disappeared from the frame");
            BackgroundOwnedSingleTask.Task actual=frame.roots.get(0).task;
            yes(actual.token==r.row(0).token.asBinder()&&actual.token==r.row(1).token.asBinder()
                    &&actual.token==r.row(2).token.asBinder(),"actual Binder was synthesized");
            yes(actual.id==1464&&actual.uid==10382&&actual.display==205&&actual.user==0,"actual identity changed");
            r.noDisplayQuery();
        });
        test("complete empty global frame preserves all unrelated roots",()->{
            Rig r=new Rig();r.empty();r.deletedDisplay();PublicPersonalNotesCustody.Frame frame=r.frame();
            yes(frame.roots.isEmpty()&&!frame.global.allIds.contains(1464)&&frame.global.roots.size()==4,"empty frame lost global evidence");
            yes(r.allReads==3,"empty result did not read all three censuses");r.noDisplayQuery();
        });
        for(final int phase:new int[]{0,1,2})for(final String field:new String[]{
                "token","uid","top-uid","user","display","parent","component","cookie","intent","real","orig",
                "null-token","null-cookies","null-intent","null-top-info"}){
            test("global phase "+phase+" rejects changed "+field,()->{
                Rig r=new Rig();r.deletedDisplay();mutate(r,phase,field);
                rejects(null,()->r.frame());yes(r.allReads<=3,"identity or malformed field was retried");r.noDisplayQuery();
            });
        }
        for(final int phase:new int[]{0,1,2})for(final String field:new String[]{
                "null","non-list","null-row","missing-child-array","parallel-length","bad-bounds","duplicate-root","missing-root"}){
            test("complete phase "+phase+" refuses "+field,()->{
                Rig r=new Rig();r.deletedDisplay();
                if("null".equals(field))r.samples[phase]=null;
                else if("non-list".equals(field))r.samples[phase]="not-a-list";
                else if("null-row".equals(field))r.rows(phase).add(null);
                else if("missing-child-array".equals(field))r.row(phase).childTaskIds=null;
                else if("parallel-length".equals(field))r.row(phase).childTaskNames=new String[0];
                else if("bad-bounds".equals(field))r.row(phase).childTaskBounds[0]=null;
                else if("duplicate-root".equals(field))r.rows(phase).add(r.row(phase));
                else r.rows(phase).remove(r.row(phase));
                rejects(null,()->r.frame());yes(r.allReads<=("missing-root".equals(field)?6:3),"incomplete global census was retried");r.noDisplayQuery();
            });
        }
        test("unrelated global malformed row cannot be skipped for empty own display",()->{
            Rig r=new Rig();r.empty();r.deletedDisplay();
            ((ActivityTaskManager.RootTaskInfo)r.rows(1).get(0)).childTaskIds=null;
            rejects("PROFILE_CHILD_ARRAYS_UNAVAILABLE",()->r.frame());r.noDisplayQuery();
        });
        for(final int failureRead:new int[]{1,2,3})test("global read exception "+failureRead+" never becomes empty",()->{
            Rig r=new Rig();r.empty();r.deletedDisplay();
            r.hook=(x,count)->{if(count==failureRead)throw new IllegalStateException("SIMULATED_GLOBAL_READ_FAILURE");};
            Exception error=rejects("SIMULATED_GLOBAL_READ_FAILURE",()->r.frame());
            PublicPersonalNotesReader.FailureAudit audit=new PublicPersonalNotesReader.FailureAudit();
            audit.cleanup(error,SystemClock.now);
            JSONObject evidence=new JSONObject(audit.evidence());
            yes(!evidence.isNull("first_cleanup_failure")&&!evidence.getBoolean("provides_cleanup_proof"),"exception became absence proof");
            yes(r.allReads==failureRead,"exception read was repeated");r.noDisplayQuery();
        });
        test("global root bound remains enforced",()->{
            Rig r=new Rig();r.deletedDisplay();r.samples[0]=new ArrayList<Object>(Collections.nCopies(257,r.row(0)));
            rejects("PROFILE_ROOT_QUERY_INCOMPLETE",()->r.frame());r.noDisplayQuery();
        });
        test("same identity presentation may settle only through a complete new triple",()->{
            Rig r=new Rig();r.deletedDisplay();
            r.hook=(x,count)->{if(count==3)for(int phase=0;phase<3;phase++)x.row(phase).isVisible=!x.row(phase).isVisible;};
            PublicPersonalNotesCustody.Frame frame=r.frame();
            yes(r.allReads==6&&frame.roots.size()==1,"presentation convergence skipped a full triple");
            yes(frame.roots.get(0).task.token==r.row(0).token.asBinder(),"settled frame replaced Binder");r.noDisplayQuery();
        });
        test("continuous presentation drift stops after three complete triples",()->{
            Rig r=new Rig();r.deletedDisplay();r.row(1).isVisible=!r.row(1).isVisible;
            Exception error=rejects("NOTES_ROOT_TASKINFO_CHANGED",()->r.frame());
            yes(error instanceof PublicPersonalNotesReader.TaskInfoReadFailure&&r.allReads==9,"retry bound changed");
            JSONObject detail=new JSONObject(((PublicPersonalNotesReader.TaskInfoReadFailure)error).evidence);
            yes(detail.getInt("sample_attempt")==3&&"activity_state".equals(detail.getString("comparison_kind")),"actual changed pair diagnostic missing");
            yes(!detail.getBoolean("serialized_fields_grant_authority"),"diagnostic became authority");r.noDisplayQuery();
        });
        for(final String field:new String[]{"token","cookie","uid","disappearance"})test(
                "disappearance".equals(field)?"presentation retry then disappearance still requires a fresh third triple":
                "settled retry cannot replace original "+field,()->{
            Rig r=new Rig();r.deletedDisplay();
            r.hook=(x,count)->{
                if(count==3)for(int phase=0;phase<3;phase++)x.row(phase).isVisible=!x.row(phase).isVisible;
                if(count==4){
                    if("disappearance".equals(field)){x.empty();return;}
                    IBinder binder=new Binder();
                    for(int phase=0;phase<3;phase++){
                        TaskInfo row=x.row(phase);
                        if("token".equals(field))row.token=new WindowContainerToken(binder);
                        else if("cookie".equals(field))row.launchCookies.add(binder);
                        else row.effectiveUid++;
                    }
                }
            };
            if("disappearance".equals(field)){
                PublicPersonalNotesCustody.Frame frame=r.frame();
                yes(r.allReads==9&&frame.roots.isEmpty()&&!r.custody.known(),"presentation and disappearance reused old evidence");
            }else{
                rejects(null,()->r.frame());yes(r.allReads==6,"changed retained census was resampled again");
            }
            r.noDisplayQuery();
        });
        test("deadline before first census causes no read",()->{
            Rig r=new Rig();r.deletedDisplay();r.deadline=SystemClock.now;
            rejects("NOTES_TASK_READ_DEADLINE",()->r.frame());yes(r.allReads==0,"expired request read tasks");r.noDisplayQuery();
        });
        test("outer deadline is rechecked after complete triple",()->{
            Rig r=new Rig();r.deletedDisplay();r.hook=(x,count)->{if(count==3)SystemClock.now=x.deadline;};
            rejects("NOTES_TASK_READ_DEADLINE",()->r.frame());yes(r.allReads==3,"deadline was renewed");r.noDisplayQuery();
        });
        test("1500 ms frame bound remains independent of outer deadline",()->{
            Rig r=new Rig();r.deletedDisplay();r.hook=(x,count)->{if(count==3)SystemClock.now+=1600;};
            rejects("NOTES_TASK_FRAME_INVALID",()->r.frame());yes(r.allReads==3,"frame age was renewed");r.noDisplayQuery();
        });
        test("retry cannot reset original frame age",()->{
            Rig r=new Rig();r.deletedDisplay();
            r.hook=(x,count)->{if(count==3){for(int phase=0;phase<3;phase++)x.row(phase).isVisible=!x.row(phase).isVisible;SystemClock.now+=1501;}};
            rejects("NOTES_TASK_FRAME_INVALID",()->r.frame());yes(r.allReads==3,"old frame was discarded with a fresh deadline");r.noDisplayQuery();
        });
        for(final String field:new String[]{"uid","source","enabled"})test("installation "+field+" rechecked after triple",()->{
            Rig r=new Rig();r.deletedDisplay();
            r.hook=(x,count)->{if(count==3){
                if("uid".equals(field))x.data.context.pm.installed.uid++;
                else if("source".equals(field))x.data.context.pm.installed.sourceDir="/different.apk";
                else x.data.context.pm.installed.enabled=false;
            }};
            rejects("NOTES_INSTALLATION_CHANGED",()->r.frame());r.noDisplayQuery();
        });
        test("owned residue remains pending before two later complete absences",()->{
            Rig r=new Rig();PublicPersonalNotesCustody custody=r.custody;
            PublicPersonalNotesCustody.Frame present=r.frame();absence(custody,present,true);
            yes(!custody.known()&&custody.retain()&&((Number)custody.evidence().get("pending_owned_reads")).intValue()==1,"residue became cleanup");
            r.empty();PublicPersonalNotesCustody.Frame first=r.frame();absence(custody,first,true);
            yes(!custody.known()&&((Number)custody.evidence().get("absence_reads")).intValue()==1,"one absence became cleanup");
            PublicPersonalNotesCustody.Frame second=r.frame();absence(custody,second,true);
            yes(custody.known()&&!custody.retain(),"second complete absence did not close custody");r.noDisplayQuery();
        });
        test("empty activity residue remains a real pending task",()->{
            Rig r=new Rig();PublicPersonalNotesCustody custody=r.custody;
            for(int phase=0;phase<3;phase++)NotesTaskInfoReaderHostTest.emptyActivities(r.row(phase));
            PublicPersonalNotesCustody.Frame frame=r.frame();absence(custody,frame,true);
            yes(frame.roots.size()==1&&frame.roots.get(0).task.activities==0&&!custody.known(),"empty activities became absence");
            r.noDisplayQuery();
        });
        test("coherent replacement Binder cannot take over retained custody",()->{
            Rig r=new Rig();PublicPersonalNotesCustody custody=r.custody;IBinder binder=new Binder();
            for(int phase=0;phase<3;phase++)r.row(phase).token=new WindowContainerToken(binder);
            rejects("NOTES_ROOT_TASKINFO_CHANGED",()->r.frame());
            yes(!custody.known()&&custody.retain(),"replacement task closed custody");r.noDisplayQuery();
        });
        test("new coherent task after release cannot enter custody",()->{
            Rig r=new Rig();PublicPersonalNotesCustody custody=r.custody;
            for(int phase=0;phase<3;phase++){ActivityTaskManager.RootTaskInfo row=r.row(phase);row.taskId=1465;row.childTaskIds[0]=1465;}
            rejects(null,()->r.frame());yes(r.allReads<=3,"unretained task was retried");
            yes(!custody.known()&&custody.retain(),"new task entered released custody");r.noDisplayQuery();
        });
        test("escaped retained task in complete global census is not absent",()->{
            Rig r=new Rig();PublicPersonalNotesCustody custody=r.custody;
            for(int phase=0;phase<3;phase++)r.row(phase).displayId=0;
            rejects(null,()->r.frame());yes(r.allReads<=3,"escaped retained task was discarded");
            yes(!custody.known()&&custody.retain(),"escaped task became cleanup");r.noDisplayQuery();
        });
        test("actual display absence remains mandatory for a complete empty frame",()->{
            Rig r=new Rig();PublicPersonalNotesCustody custody=r.custody;r.empty();
            PublicPersonalNotesCustody.Frame frame=r.frame();
            rejects("NOTES_ABSENCE_READ_UNAVAILABLE",()->absence(custody,frame,false));
            yes(!custody.known(),"frame implied display absence");r.noDisplayQuery();
        });
        test("failed read after one absence cannot complete cleanup",()->{
            Rig r=new Rig();PublicPersonalNotesCustody custody=r.custody;r.empty();
            absence(custody,r.frame(),true);yes(!custody.known(),"first absence marked known");
            r.hook=(x,count)->{throw new IllegalStateException("SIMULATED_GLOBAL_READ_FAILURE");};
            Exception error=rejects("SIMULATED_GLOBAL_READ_FAILURE",()->r.frame());
            custody.unresolved(error.getMessage());
            yes(!custody.known()&&custody.retain()&&((Number)custody.evidence().get("absence_reads")).intValue()==1,"read exception counted as second absence");
            r.noDisplayQuery();
        });

        test("released-read constructor is opaque and before-release capture is refused",()->{
            int declared=0;
            for(java.lang.reflect.Constructor<?> constructor:PublicPersonalNotesCustody.ReleasedRead.class.getDeclaredConstructors())
                if(!constructor.isSynthetic()){
                    yes(java.lang.reflect.Modifier.isPrivate(constructor.getModifiers()),"released evidence can be freely constructed");declared++;
                }
            yes(declared==1&&PublicPersonalNotesCustody.ReleasedRead.class.getConstructors().length==0,
                    "released snapshot gained an ordinary public constructor");
            NotesTaskInfoReaderHostTest.Env initial=new NotesTaskInfoReaderHostTest.Env();initial.empty();
            PublicPersonalNotesCustody.Frame baseline=initial.frame();
            PublicPersonalNotesCustody custody=new PublicPersonalNotesCustody(
                    "11111111-1111-4111-8111-111111111111",String.join("",Collections.nCopies(64,"a")),
                    10382,baseline.global,recents());
            rejects(null,()->custody.releasedRead());
            custody.beforeCreate();custody.bindDisplay(205);custody.markLaunch();
            rejects(null,()->custody.releasedRead());
            NotesTaskInfoReaderHostTest.Env ordinary=new NotesTaskInfoReaderHostTest.Env();
            PublicPersonalNotesCustody.Frame before=ordinary.frame();custody.observe(before,before.end);
            custody.retireAdmission();before=ordinary.frame();custody.prepareRelease(before,recents(),before.end);
            rejects(null,()->custody.releasedRead());custody.enterRelease();
            rejects(null,()->custody.releasedRead());custody.releaseReturned();
            yes(custody.releasedRead()!=null&&!custody.known(),"read binding invented cleanup");
        });
        test("null released-read binding causes no framework read",()->{
            Rig r=new Rig();rejects(null,()->r.reader.frameAfterRelease(null));
            yes(r.allReads==0,"null release authority read framework");r.noDisplayQuery();
        });
        test("released-read scope cannot authorize a different display",()->{
            Rig r=new Rig();PublicPersonalNotesReader other=new PublicPersonalNotesReader(r.data.context,r,206,()->r.deadline);
            rejects(null,()->other.frameAfterRelease(r.released));
            yes(r.allReads==0,"wrong display scope read framework");r.noDisplayQuery();
        });
        test("released-read scope cannot authorize a different installed UID",()->{
            Rig r=new Rig();r.data.context.pm.installed.uid++;
            PublicPersonalNotesReader other=new PublicPersonalNotesReader(r.data.context,r,205,()->r.deadline);
            rejects(null,()->other.frameAfterRelease(r.released));
            yes(r.allReads==0,"wrong UID scope read framework");r.noDisplayQuery();
        });
        test("full monotonic disappearance discards old triple before stable empty frame",()->{
            Rig r=new Rig();
            r.hook=(x,count)->{if(count==3)x.empty();};
            PublicPersonalNotesCustody.Frame frame=r.frame();
            yes(r.allReads==6&&frame.roots.isEmpty(),"disappearance reused a mixed triple");
            yes(!r.custody.known(),"empty frame alone granted cleanup");r.noDisplayQuery();
        });
        test("partial monotonic disappearance keeps remaining retained task pending",()->{
            Rig r=new Rig(2);
            r.hook=(x,count)->{if(count==2)x.drop(1465);};
            PublicPersonalNotesCustody.Frame frame=r.frame();absence(r.custody,frame,true);
            yes(r.allReads==6&&frame.roots.size()==1&&frame.roots.get(0).task.id==1464,"partial removal did not fully resample");
            yes(!r.custody.known()&&r.custody.retain(),"remaining task became cleanup");r.noDisplayQuery();
        });
        test("continuous monotonic shrink stops at the original three-triple bound",()->{
            Rig r=new Rig(3);
            r.hook=(x,count)->{if(count==3)x.drop(1466);else if(count==6)x.drop(1465);else if(count==9)x.drop(1464);};
            rejects(null,()->r.frame());yes(r.allReads==9,"disappearance added an unbounded fourth triple");
            yes(!r.custody.known(),"exhausted disappearance became cleanup");r.noDisplayQuery();
        });
        test("intra-triple disappearance and reappearance is refused as ABA",()->{
            Rig r=new Rig();r.rows(1).remove(r.row(1));
            rejects(null,()->r.frame());yes(r.allReads<=3,"ABA was retried");r.noDisplayQuery();
        });
        test("cross-triple reappearance is refused even with the original Binder",()->{
            Rig r=new Rig();List<List<Object>> original=new ArrayList<List<Object>>();
            for(int phase=0;phase<3;phase++)original.add(new ArrayList<Object>(r.rows(phase)));
            r.hook=(x,count)->{
                if(count==3)x.empty();
                else if(count==4)for(int phase=0;phase<3;phase++)x.samples[phase]=new ArrayList<Object>(original.get(phase));
            };
            rejects(null,()->r.frame());yes(r.allReads<=6,"cross-triple ABA was resampled");
            yes(!r.custody.known(),"reappearance granted cleanup");r.noDisplayQuery();
        });
        test("unretained new row cannot disappear through the fresh-empty path",()->{
            Rig r=new Rig();r.add(0,1465,new Binder());
            rejects(null,()->r.frame());yes(r.allReads<=3,"unretained first row was discarded");r.noDisplayQuery();
        });
        test("transient unretained addition in the middle remains rejected",()->{
            Rig r=new Rig();r.add(1,1465,new Binder());
            rejects(null,()->r.frame());yes(r.allReads<=3,"transient addition was discarded");r.noDisplayQuery();
        });
        test("same-identity shrinking set cannot hide a changed remaining Binder",()->{
            Rig r=new Rig(2);r.row(1).token=new WindowContainerToken(new Binder());
            r.rows(1).removeIf(value->value instanceof TaskInfo&&((TaskInfo)value).taskId==1465);
            r.rows(2).removeIf(value->value instanceof TaskInfo&&((TaskInfo)value).taskId==1465);
            rejects(null,()->r.frame());yes(r.allReads<=3,"shrinking set hid replacement identity");r.noDisplayQuery();
        });
        test("intermediate escape cannot disappear into a later empty census",()->{
            Rig r=new Rig();r.row(1).displayId=0;
            r.rows(2).remove(r.row(2));
            rejects(null,()->r.frame());yes(r.allReads<=3,"escaped task was discarded as disappearance");
            yes(!r.custody.known(),"escaped sample became cleanup");r.noDisplayQuery();
        });
        test("disappearance retry preserves original deadline",()->{
            Rig r=new Rig();r.hook=(x,count)->{if(count==3){x.empty();SystemClock.now=x.deadline;}};
            rejects("NOTES_TASK_READ_DEADLINE",()->r.frame());yes(r.allReads==3,"disappearance renewed deadline");r.noDisplayQuery();
        });
        test("disappearance retry preserves original 1500 ms frame bound",()->{
            Rig r=new Rig();r.hook=(x,count)->{if(count==3){x.empty();SystemClock.now+=1600;}};
            rejects("NOTES_TASK_FRAME_INVALID",()->r.frame());yes(r.allReads==3,"disappearance renewed frame age");r.noDisplayQuery();
        });

        JSONObject result=new JSONObject().put("schema","hepta.notes-after-release-reader-host.v1")
                .put("all_pass",true).put("cases",CASES.size()).put("assertions",assertions).put("case_names",CASES)
                .put("complete_production_reader_organizer_custody",true).put("framework_and_binder_fixtures_synthetic",true)
                .put("fixture_sha256",NotesTaskInfoReaderHostTest.digest(raw)).put("phone_operations",0)
                .put("android_runtime",false).put("hardware_qualification_claimed",false);
        System.out.println(result.toString());
    }
}
