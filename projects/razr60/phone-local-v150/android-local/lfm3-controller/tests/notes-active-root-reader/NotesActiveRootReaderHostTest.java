package org.trillionnium.hepta.background;

import android.app.ActivityTaskManager;
import android.app.TaskInfo;
import android.content.ComponentName;
import android.graphics.Rect;
import android.os.Binder;
import android.os.IBinder;
import android.os.SystemClock;
import android.window.WindowContainerToken;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

/** Complete production Reader/Custody; only the pre-existing Android/Binder/time
 * endpoints are synthetic. The 569 archive records a 2/2/1 set shape, not the
 * TaskInfo rows below. No current retired broker, cleanup or action is exercised. */
public final class NotesActiveRootReaderHostTest {
    private static final int A=4601,B=4602,C=4603,D=4604;
    private static final String PKG=NotesTaskInfoReaderHostTest.PKG,COMP=NotesTaskInfoReaderHostTest.COMP;
    private static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    private static int checks;
    private static Rig current;
    private interface Work {void run()throws Exception;}
    private interface Hook {void run(Rig rig,int attempt)throws Exception;}
    private static void check(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    private static int[] ids(int count){return Arrays.copyOf(new int[]{A,B,C,D},count);}
    private static int[][] triple(int before,int own,int after){return new int[][]{ids(before),ids(own),ids(after)};}
    private static int[][] sets(int[] before,int[] own,int[] after){return new int[][]{before,own,after};}
    private static Set<Integer> keys(int... values){Set<Integer> out=new LinkedHashSet<Integer>();for(int v:values)out.add(v);return out;}
    private static String cause(Throwable error){
        while(error.getCause()!=null)error=error.getCause();
        return error.getClass().getName()+": "+String.valueOf(error.getMessage());
    }
    private static Exception refuses(String expected,Work work)throws Exception{
        try{work.run();}catch(Exception failure){
            check(expected==null||cause(failure).contains(expected),"actual refusal differs: "+cause(failure));
            return failure;
        }
        throw new AssertionError("actual production read unexpectedly returned a Frame");
    }
    private static JSONObject rowTemplate(int phase){
        String name=phase==0?"before_all_roots":phase==1?"owned_display_roots":"after_all_roots";
        JSONArray rows=NotesTaskInfoReaderHostTest.captured.getJSONObject(name).getJSONArray("rows");
        for(int i=0;i<rows.length();i++)if(rows.getJSONObject(i).getJSONObject("displayId").getInt("value")==205)return rows.getJSONObject(i);
        throw new AssertionError("complete owned template absent");
    }
    private static final class Rig {
        final NotesTaskInfoReaderHostTest.Env env;
        final PublicPersonalNotesCustody custody;
        final PublicOwnGroupPhysicalFence.RecentCensus recents;
        final Map<Integer,IBinder> tokens=new LinkedHashMap<Integer,IBinder>();
        final List<List<Object>> phaseRows=new ArrayList<List<Object>>();
        final List<List<List<Integer>>> observedTriples=new ArrayList<List<List<Integer>>>();
        final Set<Integer> originallyOwned;
        PublicPersonalNotesCustody.Frame ownedFrame,refreshFrame,returned;
        Map<String,Object> custodyAtEntry;
        Hook beforeHook,ownHook,afterHook;
        int initialAll,initialRoots,attempts;
        long entryClock;
        List<int[][]> script;
        Rig(int count)throws Exception{this(count,true);}
        Rig(int count,boolean observe)throws Exception{
            NotesTaskInfoReaderHostTest.Env baseline=new NotesTaskInfoReaderHostTest.Env();baseline.empty();
            PublicPersonalNotesCustody.Frame first=baseline.frame();
            recents=PublicOwnGroupPhysicalFence.inspectRecents(PublicPhysicalAuditHostTest.recents(false));
            custody=new PublicPersonalNotesCustody("11111111-1111-4111-8111-111111111111",
                    String.join("",Collections.nCopies(64,"a")),10382,first.global,recents);
            custody.beforeCreate();custody.bindDisplay(205);custody.markLaunch();
            env=new NotesTaskInfoReaderHostTest.Env();
            for(int id:new int[]{A,B,C,D,4701})tokens.put(id,new Binder());
            for(int p=0;p<3;p++)phaseRows.add(new ArrayList<Object>());
            set(triple(count,count,count));
            ownedFrame=env.reader.frame();
            if(observe)custody.observe(ownedFrame,ownedFrame.end);
            originallyOwned=observe?keys(ids(count)):Collections.<Integer>emptySet();current=this;
            check(baseline.childrenCalls==0&&baseline.mutations==0,"baseline has no child lookup or mutation");
        }
        private static Set<Integer> keys(int[] ids){Set<Integer> out=new LinkedHashSet<Integer>();for(int id:ids)out.add(id);return out;}
        void set(int[][] shape)throws Exception{
            for(int p=0;p<3;p++){
                List<Object> rows=env.rehydrate(p==0?"before_all_roots":p==1?"owned_display_roots":"after_all_roots",p!=1);
                rows.removeIf(x->x instanceof TaskInfo&&((TaskInfo)x).displayId==205);
                for(int id:shape[p]){
                    TaskInfo task=env.row(rowTemplate(p),p!=1);task.taskId=id;
                    IBinder token=tokens.get(id);if(token==null){token=new Binder();tokens.put(id,token);}
                    task.token=new WindowContainerToken(token);
                    if(p!=1)((ActivityTaskManager.RootTaskInfo)task).childTaskIds=new int[]{id};
                    rows.add(task);
                }
                phaseRows.set(p,rows);
            }
            env.before=phaseRows.get(0);env.own=phaseRows.get(1);env.after=phaseRows.get(2);
        }
        TaskInfo task(int phase,int id){
            for(Object item:phaseRows.get(phase))if(item instanceof TaskInfo&&((TaskInfo)item).taskId==id)return (TaskInfo)item;
            throw new AssertionError("synthetic row absent: "+phase+"/"+id);
        }
        ActivityTaskManager.RootTaskInfo root(int phase,int id){return (ActivityTaskManager.RootTaskInfo)task(phase,id);}
        void all(String field)throws Exception{
            IBinder replacement=new Binder();
            for(int p=0;p<3;p++){
                TaskInfo task=task(p,A);
                if("token".equals(field))task.token=new WindowContainerToken(replacement);
                else if("cookie".equals(field))task.launchCookies.add(replacement);
                else if("intent".equals(field))task.baseIntent.setComponent(new ComponentName(PKG,PKG+".edit.NoteEditorActivity"));
                else if("real".equals(field))task.realActivity=new ComponentName(PKG,PKG+".edit.NoteEditorActivity");
                else if("orig".equals(field))task.origActivity=new ComponentName(PKG,PKG+".edit.NoteEditorActivity");
                else NotesTaskInfoReaderHostTest.change(task,field);
            }
        }
        void callback(Hook hook){
            if(hook!=null)try{hook.run(this,attempts);}catch(Exception failure){throw new AssertionError("fixture setup failed",failure);}
        }
        void arm(int[][]... shapes){
            script=Arrays.asList(shapes);initialAll=env.allReads;initialRoots=env.rootReads;
            custodyAtEntry=custody.evidence();entryClock=SystemClock.now;
            env.onBeforeRead=()->{
                attempts++;check(attempts<=3&&attempts<=script.size(),"no fourth or unspecified triple");
                try{set(script.get(attempts-1));}catch(Exception failure){throw new AssertionError("fixture setup failed",failure);}
                callback(beforeHook);
                List<List<Integer>> values=new ArrayList<List<Integer>>();
                for(int[] part:script.get(attempts-1)){List<Integer> list=new ArrayList<Integer>();for(int id:part)list.add(id);values.add(list);}
                observedTriples.add(values);
            };
            env.onOwnRead=()->callback(ownHook);
            env.onAfterRead=()->callback(afterHook);
        }
        PublicPersonalNotesCustody.Frame read()throws Exception{
            returned=env.reader.frame(custody);return returned;
        }
        int reads(){return env.rootReads-initialRoots;}
        int globals(){return env.allReads-initialAll;}
        void noNewAuthority(){
            Map<String,Object> evidence=custody.evidence();
            check(env.childrenCalls==0&&env.mutations==0,"no child task lookup or mutation");
            check(!custody.known()&&custody.retain(),"ordinary frame is not cleanup evidence");
            check(((Number)evidence.get("absence_reads")).intValue()==0,"no absence proof");
            check(!evidence.containsKey("token_retirement"),"no task-removal plan minted");
        }
        void unchangedCustody(){
            Map<String,Object> e=custody.evidence();
            check(e.equals(custodyAtEntry),"Reader cannot edit custody observations, release flags or failure latch");
            check(((List<?>)e.get("actual_observed_tasks")).size()==originallyOwned.size(),"removed roots remain retained identities");
        }
        void accepted(int count,int expectedTriples)throws Exception{
            PublicPersonalNotesCustody.Frame frame=read();
            Set<Integer> actual=new LinkedHashSet<Integer>();for(PublicPersonalNotesCustody.Node node:frame.roots)actual.add(node.task.id);
            check(actual.equals(keys(ids(count))),"Frame only contains the final fresh full triple");
            check(reads()==expectedTriples&&globals()==2*expectedTriples,"each attempt performs both ATM reads and organizer read");
            check(frame.begin==entryClock&&frame.end-frame.begin<=1500,"original frame begin and total budget retained");
            for(PublicPersonalNotesCustody.Node node:frame.roots){
                TaskInfo finalTask=task(1,node.task.id);
                check(node.task.token==finalTask.token.asBinder()&&node.task.visible==finalTask.isVisible
                        &&node.task.activities==finalTask.numActivities,"Frame uses fresh final organizer values");
                check(node.children.isEmpty()&&frame.global.leaves.get(node.task.id).parent==node.task.id,"original sole-leaf validator");
            }
            unchangedCustody();noNewAuthority();
        }
        Map<String,Object> record(){
            Map<String,Object> e=new LinkedHashMap<String,Object>();
            e.put("complete_triples_attempted",attempts);e.put("organizer_reads",reads());e.put("global_reads",globals());
            e.put("injected_sets",observedTriples);e.put("frame_returned",returned!=null);
            e.put("entry_clock",entryClock);e.put("final_clock",SystemClock.now);
            e.put("frame_begin",returned==null?null:returned.begin);e.put("frame_end",returned==null?null:returned.end);
            e.put("custody_before",custodyAtEntry);e.put("custody_after",custody.evidence());
            e.put("mutations",env.mutations);e.put("get_child_tasks_calls",env.childrenCalls);
            return e;
        }
    }
    private static void one(String name,Work work){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);int before=checks;current=null;
        try{work.run();if(current!=null)current.noNewAuthority();row.put("passed",true);}
        catch(Throwable failure){row.put("passed",false);StringWriter text=new StringWriter();failure.printStackTrace(new PrintWriter(text));row.put("error",text.toString());}
        finally{Thread.interrupted();if(current!=null)row.put("evidence",current.record());row.put("assertions",checks-before);results.add(row);}
    }
    private static void cases(){
        one("active_shrink_2_2_1_then_fresh_1_1_1",()->{Rig r=new Rig(2);r.arm(triple(2,2,1),triple(1,1,1));r.accepted(1,2);});
        one("active_shrink_2_1_1_then_fresh_1_1_1",()->{Rig r=new Rig(2);r.arm(triple(2,1,1),triple(1,1,1));r.accepted(1,2);});
        one("active_shrink_two_discarded_triples_then_third_stable",()->{Rig r=new Rig(3);r.arm(triple(3,3,2),triple(2,2,1),triple(1,1,1));r.accepted(1,3);});
        one("active_shrink_to_fresh_empty_is_not_cleanup",()->{Rig r=new Rig(2);r.arm(triple(2,2,1),triple(1,1,0),triple(0,0,0));r.accepted(0,3);});
        one("active_shrink_fresh_state_replaces_discarded_values",()->{
            Rig r=new Rig(2);r.beforeHook=(x,n)->{if(n==2)for(int p=0;p<3;p++){x.task(p,A).isVisible=true;x.task(p,A).numActivities=2;}};
            r.arm(triple(2,2,1),triple(1,1,1));r.accepted(1,2);check(r.returned.roots.get(0).task.visible,"fresh values are visible");
        });
        one("active_shrink_third_transition_exhausts_original_three",()->{
            Rig r=new Rig(4);r.arm(triple(4,4,3),triple(3,3,2),triple(2,2,1));
            Exception failure=refuses("NOTES_ROOT_CENSUS_CHANGED",()->r.read());
            check(failure.getClass().getName().equals(PublicPersonalNotesReader.class.getName()+"$CensusChanged"),"actual typed within-sample failure retained");
            check(r.reads()==3&&r.globals()==6,"no fourth triple");r.unchangedCustody();
        });
        for(final String mode:Arrays.asList("new_first","new_middle","new_after","same_count_swap","resurrection_stable","resurrection_middle","between_samples_loss")){
            one("active_shrink_rejects_"+mode,()->{
                Rig r=new Rig(2);
                if("new_first".equals(mode))r.arm(sets(new int[]{A,B,4701},new int[]{A,B},new int[]{A}));
                else if("new_middle".equals(mode))r.arm(sets(new int[]{A,B},new int[]{A,B,4701},new int[]{A}));
                else if("new_after".equals(mode))r.arm(sets(new int[]{A,B},new int[]{A},new int[]{A,4701}));
                else if("same_count_swap".equals(mode))r.arm(sets(new int[]{A,B},new int[]{A,4701},new int[]{A,4701}));
                else if("resurrection_stable".equals(mode))r.arm(triple(2,2,1),triple(2,2,2));
                else if("resurrection_middle".equals(mode))r.arm(triple(2,2,1),sets(new int[]{A},new int[]{A,B},new int[]{A}));
                else r.arm(triple(2,2,1),triple(0,0,0));
                refuses(null,()->r.read());check(r.reads()<=2&&r.returned==null,"no mixed or resurrected Frame");r.unchangedCustody();
            });
        }
        for(final String field:Arrays.asList("token","uid","user","display","parent","cookie","intent","real","orig")){
            one("active_shrink_preserves_entry_identity_"+field,()->{
                Rig r=new Rig(2);r.beforeHook=(x,n)->{if(n==2)x.all(field);};r.arm(triple(2,2,1),triple(1,1,1));
                refuses(null,()->r.read());check(r.reads()==2&&r.returned==null,"internally equal replacement still rejected");r.unchangedCustody();
            });
        }
        for(final String mode:Arrays.asList("escape_display_0","escape_display_1","leaf_user","extra_leaf","foreign_notes")){
            one("active_shrink_complete_global_"+mode,()->{
                Rig r=new Rig(2);r.beforeHook=(x,n)->{
                    if("escape_display_0".equals(mode)||"escape_display_1".equals(mode)){
                        if(n==2){int display="escape_display_0".equals(mode)?0:1;
                            for(int phase:new int[]{0,2}){
                                TaskInfo escaped=x.env.row(rowTemplate(phase),true);escaped.taskId=B;escaped.displayId=display;
                                escaped.token=new WindowContainerToken(x.tokens.get(B));
                                ((ActivityTaskManager.RootTaskInfo)escaped).childTaskIds=new int[]{B};
                                x.phaseRows.get(phase).add(escaped);
                            }
                        }
                    }else if("leaf_user".equals(mode))x.root(0,B).childTaskUserIds[0]=10;
                    else if("extra_leaf".equals(mode)){
                        ActivityTaskManager.RootTaskInfo root=x.root(0,A);root.childTaskIds=new int[]{A,4801};root.childTaskUserIds=new int[]{0,0};
                        root.childTaskNames=new String[]{COMP,COMP};root.childTaskBounds=new Rect[]{new Rect(0,0,100,200),new Rect(0,0,100,200)};
                    }else{
                        TaskInfo t=x.env.row(rowTemplate(0),true);t.taskId=4701;t.displayId=0;((ActivityTaskManager.RootTaskInfo)t).childTaskIds=new int[]{4701};x.phaseRows.get(0).add(t);
                    }
                };
                boolean escaped=mode.startsWith("escape_display_");
                if(escaped)r.arm(triple(2,2,1),triple(1,1,1));else r.arm(triple(2,2,1));
                refuses(escaped?"NOTES_OBSERVED_TASK_ESCAPED":null,()->r.read());
                check(r.reads()==(escaped?2:1)&&r.returned==null,"complete global proof rejects a retained escaped task or other invalid triple");r.unchangedCustody();
            });
        }
        for(final String state:Arrays.asList("null","unobserved","retired","unknown","prepared","entered","returned","observation_in_future")){
            one("active_shrink_requires_active_entry_"+state,()->{
                Rig r=new Rig(2,!"unobserved".equals(state));
                if("retired".equals(state))r.custody.retireAdmission();
                if("unknown".equals(state))r.custody.unresolved("synthetic pre-existing unknown");
                if(Arrays.asList("prepared","entered","returned").contains(state)){
                    r.custody.retireAdmission();r.custody.prepareRelease(r.ownedFrame,r.recents,SystemClock.now);
                    if(!"prepared".equals(state))r.custody.enterRelease();
                    if("returned".equals(state))r.custody.releaseReturned();
                }
                if("observation_in_future".equals(state)){SystemClock.now=r.ownedFrame.end-1;SystemClock.step=0;}
                r.arm(triple(2,2,1));
                if("null".equals(state))refuses("NOTES_ROOT_CENSUS_CHANGED",()->r.env.reader.frame());
                else refuses("NOTES_ROOT_CENSUS_CHANGED",()->r.read());
                check(r.reads()==1&&r.returned==null,"no new retry outside active entry");r.unchangedCustody();
            });
        }
        one("active_shrink_scope_snapshot_rejects_wrong_display_and_uid",()->{
            Rig r=new Rig(2);
            check(r.custody.activeRead(206,10382,SystemClock.now)==null&&r.custody.activeRead(205,10383,SystemClock.now)==null,"real ActiveRead scope check");
            check(r.custody.activeRead(205,10382,SystemClock.now)!=null,"same actual custody positive control");
            r.arm(triple(2,2,1),triple(1,1,1));r.accepted(1,2);
        });
        for(final String event:Arrays.asList("observe_during_first","launch_during_first","retire_before_second","unknown_during_second","retire_before_return")){
            one("active_shrink_entry_snapshot_invalidated_"+event,()->{
                Rig r=new Rig(2);r.refreshFrame=r.env.reader.frame();
                r.beforeHook=(x,n)->{
                    if(n==1&&"observe_during_first".equals(event))x.custody.observe(x.refreshFrame,SystemClock.now);
                    if(n==1&&"launch_during_first".equals(event))x.custody.markLaunch();
                    if(n==2&&"unknown_during_second".equals(event))x.custody.unresolved("synthetic changed state");
                };
                r.afterHook=(x,n)->{
                    if(n==1&&"retire_before_second".equals(event))x.custody.retireAdmission();
                    if(n==2&&"retire_before_return".equals(event))x.custody.retireAdmission();
                };
                r.arm(triple(2,2,1),triple(1,1,1));
                refuses("NOTES_ACTIVE_READ_RETIRED_OR_CHANGED",()->r.read());
                check(r.returned==null&&r.reads()<=2,"later state cannot refresh the frame-entry capability");
            });
        }
        for(final String at:Arrays.asList("entry","first_after","second_after","frame_age")){
            one("active_shrink_original_budget_"+at,()->{
                Rig r=new Rig(2);
                if("entry".equals(at))r.env.deadline=SystemClock.now;
                r.afterHook=(x,n)->{
                    if((n==1&&"first_after".equals(at))||(n==2&&"second_after".equals(at)))SystemClock.now=x.env.deadline;
                    if(n==1&&"frame_age".equals(at))SystemClock.now+=1501;
                };
                r.arm(triple(2,2,1),triple(1,1,1));
                refuses("frame_age".equals(at)?"NOTES_TASK_FRAME_INVALID":"NOTES_TASK_READ_DEADLINE",()->r.read());
                check(r.returned==null&&r.reads()<=2,"no renewed deadline or allowance");r.unchangedCustody();
            });
        }
        for(final String bad:Arrays.asList("null_global","null_organizer","missing_children","framework_exception","interrupt_delay")){
            one("active_shrink_unknown_is_not_permission_"+bad,()->{
                Rig r=new Rig(2);r.beforeHook=(x,n)->{
                    if("null_global".equals(bad))x.env.before=null;
                    else if("null_organizer".equals(bad))x.env.own=null;
                    else if("missing_children".equals(bad))x.root(0,A).childTaskIds=null;
                };
                if("framework_exception".equals(bad))r.beforeHook=(x,n)->{x.env.onOwnRead=()->{throw new IllegalStateException("synthetic framework throws");};};
                if("interrupt_delay".equals(bad))r.afterHook=(x,n)->Thread.currentThread().interrupt();
                r.arm(triple(2,2,1),triple(1,1,1));
                refuses(null,()->r.read());check(r.returned==null&&r.reads()<=1,"unknown or interruption never supplies a retry");r.unchangedCustody();
            });
        }
        one("active_shrink_final_activity_state_uses_remaining_attempt",()->{
            Rig r=new Rig(2);r.beforeHook=(x,n)->{if(n==2)x.task(1,A).isVisible=true;};
            r.arm(triple(2,2,1),triple(1,1,1),triple(1,1,1));r.accepted(1,3);
        });
        one("active_shrink_final_activity_state_exhaustion",()->{
            Rig r=new Rig(2);r.beforeHook=(x,n)->{if(n>=2)x.task(1,A).isVisible=true;};
            r.arm(triple(2,2,1),triple(1,1,1),triple(1,1,1));
            refuses("NOTES_ROOT_TASKINFO_CHANGED",()->r.read());check(r.reads()==3&&r.globals()==6,"shared maximum of three");r.unchangedCustody();
        });
        one("active_shrink_activity_retry_cannot_hide_between_sample_loss",()->{
            Rig r=new Rig(2);r.beforeHook=(x,n)->{if(n==1)x.task(1,A).isVisible=true;};
            r.arm(triple(2,2,2),triple(1,1,1));refuses("NOTES_ROOT_CENSUS_CHANGED",()->r.read());
            check(r.reads()==2&&r.returned==null,"complete unknown transition is not a within-sample shrink");r.unchangedCustody();
        });
        one("active_shrink_unrelated_non_notes_physical_state_is_not_frozen",()->{
            Rig r=new Rig(2);r.beforeHook=(x,n)->{
                for(int phase:new int[]{0,2})for(Object value:x.phaseRows.get(phase)){
                    TaskInfo task=(TaskInfo)value;if(task.displayId==0&&!PKG.equals(task.baseActivity==null?null:task.baseActivity.getPackageName()))task.isVisible=!task.isVisible;
                }
            };
            r.arm(triple(2,2,1),triple(1,1,1));r.accepted(1,2);
        });
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IOException("fixed synthetic input and new result path required");
        byte[] bytes=Files.readAllBytes(Paths.get(args[0]));
        if(bytes.length!=NotesTaskInfoReaderHostTest.SYNTHETIC_BYTES
                ||!NotesTaskInfoReaderHostTest.SYNTHETIC_SHA.equals(NotesTaskInfoReaderHostTest.digest(bytes)))
            throw new IOException("unchanged complete synthetic TaskInfo fixture required");
        NotesTaskInfoReaderHostTest.actualCapture=false;
        NotesTaskInfoReaderHostTest.captured=new JSONObject(new String(bytes,StandardCharsets.UTF_8));
        cases();
        boolean pass=true;List<String> names=new ArrayList<String>();for(Map<String,Object> r:results){pass&=Boolean.TRUE.equals(r.get("passed"));names.add((String)r.get("name"));}
        check(new LinkedHashSet<String>(names).size()==names.size(),"unique case names");
        JSONObject out=new JSONObject().put("schema","hepta.notes-active-root-reader-cases.v1").put("all_pass",pass)
                .put("cases",results.size()).put("assertions",checks).put("case_names",names).put("results",results)
                .put("phone_operations",0).put("android_runtime",false).put("framework_and_binder_fixtures_synthetic",true)
                .put("full_production_reader_and_custody",true).put("private_active_read_constructor_replaced",false)
                .put("current_569_recovery_claimed",false).put("cleanup_proof_produced",false).put("back_redispatches",0)
                .put("original_569_full_taskinfo_reconstructed",false).put("actual_569_shape_only",new JSONArray("[2,2,1]"))
                .put("maximum_frame_ms",1500).put("maximum_complete_triples",3);
        Path path=Paths.get(args[1]);Files.write(path,(out.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
        System.out.println(out.toString());if(!pass)System.exit(1);
    }
}
