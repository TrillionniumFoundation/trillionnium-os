package org.trillionnium.hepta.background;

import android.app.ActivityTaskManager;
import android.app.TaskInfo;
import android.content.ComponentName;
import android.os.Binder;
import android.os.IBinder;
import android.os.SystemClock;
import android.window.WindowContainerToken;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** The 569 broker recorded topology and identity-equality labels, not complete
 * TaskInfo rows. We replay that topology through the complete production reader
 * with the existing explicit synthetic Android fields and inert Binder objects.
 * Neither a serialized hashCode nor a host pass is ownership or dispatch proof. */
public final class NotesActiveCensusHostTest {
    private static final String PKG=NotesTaskInfoReaderHostTest.PKG;
    private static final String EDITOR=PKG+".note.text.TextNoteActivity";
    private static final int SURVIVOR=1464,DEPARTING=1465,DISPLAY=205,UID=10382;
    private static final String GENERATION="11111111-1111-4111-8111-111111111111";
    private static final String SCOPE=String.join("",Collections.nCopies(64,"a"));
    private static NotesTaskInfoReaderHostTest.Env e;
    private static PublicPersonalNotesCustody c;
    private static PublicPersonalNotesCustody.Frame original;
    private static JSONObject projection;
    private static int checks;
    private static String lastRefusal;
    private static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    private interface Work{void run()throws Exception;}
    private static void yes(boolean value){checks++;if(!value)throw new AssertionError("active census boundary");}
    private static void refuses(Work work)throws Exception{
        try{work.run();}catch(Exception expected){lastRefusal=NotesTaskInfoReaderHostTest.cause(expected);yes(true);return;}
        throw new AssertionError("incomplete or unowned frame accepted");
    }
    private static void test(String name,Work work){
        int before=checks;String error=null;
        try{
            e=new NotesTaskInfoReaderHostTest.Env();c=null;original=null;lastRefusal=null;work.run();
            yes(e.childrenCalls==0&&e.mutations==0);
        }catch(Throwable failure){error=failure.getClass().getName()+": "+NotesTaskInfoReaderHostTest.cause(failure);}
        Map<String,Object> row=new java.util.LinkedHashMap<String,Object>();
        row.put("name",name);row.put("passed",error==null);row.put("assertions",checks-before);
        row.put("error",error==null?JSONObject.NULL:error);row.put("refusal_reason",lastRefusal==null?JSONObject.NULL:lastRefusal);results.add(row);
    }
    private static JSONObject sourceRow(String phase){
        JSONArray rows=NotesTaskInfoReaderHostTest.captured.getJSONObject(phase).getJSONArray("rows");
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);
            if(row.getJSONObject("taskId").getInt("value")==SURVIVOR)return row;
        }
        throw new AssertionError("synthetic source row missing");
    }
    private static void addRoot(int id)throws Exception{
        IBinder token=new Binder();
        for(int phase=0;phase<3;phase++){
            boolean global=phase!=1;
            String label=phase==0?"before_all_roots":phase==1?"owned_display_roots":"after_all_roots";
            TaskInfo row=e.row(sourceRow(label),global);row.taskId=id;
            row.token=new WindowContainerToken(token);
            ComponentName component=new ComponentName(PKG,EDITOR);
            row.baseIntent.setComponent(component);row.baseActivity=component;row.realActivity=component;row.topActivity=component;row.origActivity=null;
            if(row.topActivityInfo!=null)row.topActivityInfo.name=EDITOR;
            if(global){
                ActivityTaskManager.RootTaskInfo root=(ActivityTaskManager.RootTaskInfo)row;
                root.childTaskIds=new int[]{id};root.childTaskNames=new String[]{PKG+"/"+EDITOR};
            }
            e.list(phase).add(row);
        }
    }
    private static TaskInfo task(int phase,int id){
        for(Object row:e.list(phase))if(row instanceof TaskInfo&&((TaskInfo)row).taskId==id)return(TaskInfo)row;
        throw new AssertionError("fixture task missing: "+id);
    }
    private static void remove(int phase,int id){e.list(phase).removeIf(row->row instanceof TaskInfo&&((TaskInfo)row).taskId==id);}
    private static void removeAll(int id){for(int phase=0;phase<3;phase++)remove(phase,id);}
    private static void prepare(int roots)throws Exception{
        for(int i=1;i<roots;i++)addRoot(SURVIVOR+i);
        NotesTaskInfoReaderHostTest.Env initial=new NotesTaskInfoReaderHostTest.Env();initial.empty();
        PublicPersonalNotesCustody.Frame baseline=initial.frame();
        PublicOwnGroupPhysicalFence.RecentCensus recents=PublicOwnGroupPhysicalFence.inspectRecents(PublicPhysicalAuditHostTest.recents(false));
        c=new PublicPersonalNotesCustody(GENERATION,SCOPE,UID,baseline.global,recents);
        c.beforeCreate();c.bindDisplay(DISPLAY);c.markLaunch();if(roots>1)c.markLaunch();
        original=e.frame();c.observe(original,original.end);
        yes(((List<?>)c.evidence().get("actual_observed_tasks")).size()==roots);
        yes(!c.known()&&c.retain());
        e.allReads=0;e.rootReads=0;e.trace.clear();
    }
    private static void disappear(boolean inMiddle){
        if(inMiddle)remove(1,DEPARTING);remove(2,DEPARTING);
        e.onBeforeRead=()->{if(e.allReads>=3)removeAll(DEPARTING);};
    }
    private static PublicPersonalNotesCustody.Frame active()throws Exception{return e.reader.frame(c);}
    private static void coherentOne(PublicPersonalNotesCustody.Frame frame,int expectedReads){
        yes(frame.roots.size()==1&&frame.roots.get(0).task.id==SURVIVOR);
        yes(frame.roots.get(0).task.token==task(0,SURVIVOR).token.asBinder());
        yes(frame.global.allIds.contains(SURVIVOR)&&!frame.global.allIds.contains(DEPARTING));
        yes(e.rootReads==expectedReads&&e.allReads==expectedReads*2);
        yes(frame.end-frame.begin<=1500);
        yes(!c.known()&&c.retain()&&Boolean.FALSE.equals(c.evidence().get("release_api_entered")));
        yes(((List<?>)c.evidence().get("actual_observed_tasks")).size()==2);
    }
    private static void moveDisappearingGlobal(int display){
        ActivityTaskManager.RootTaskInfo root=(ActivityTaskManager.RootTaskInfo)task(2,DEPARTING);
        root.displayId=display;
    }
    public static void main(String[] args)throws Exception{
        NotesTaskInfoReaderHostTest.actualCapture=false;
        NotesTaskInfoReaderHostTest.captured=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),java.nio.charset.StandardCharsets.UTF_8));
        projection=new JSONObject(new String(Files.readAllBytes(Paths.get(args[1])),java.nio.charset.StandardCharsets.UTF_8));
        test("recorded_569_two_two_one_discard_then_coherent_actual_reader",()->{
            yes(projection.getString("schema").equals("hepta.notes-active-census-recorded-topology.v1"));
            yes(projection.getJSONArray("before").toList().equals(Arrays.asList("survivor","departing")));
            yes(projection.getJSONArray("middle").toList().equals(Arrays.asList("survivor","departing")));
            yes(projection.getJSONArray("after").toList().equals(Arrays.asList("survivor")));
            yes(!projection.getBoolean("serialized_tokens_grant_authority"));
            prepare(2);disappear(false);PublicPersonalNotesCustody.Frame frame=active();coherentOne(frame,2);
            c.observe(frame,frame.end);yes(((List<?>)c.evidence().get("actual_observed_tasks")).size()==2);
            yes(!c.known()&&c.retain());
        });
        test("known_two_one_one_discard_then_coherent_actual_reader",()->{
            prepare(2);disappear(true);coherentOne(active(),2);
        });
        test("contraction_between_discarded_activity_samples_requires_third_complete_read",()->{
            prepare(2);task(1,SURVIVOR).isVisible=!task(0,SURVIVOR).isVisible;
            e.onBeforeRead=()->{if(e.allReads>=3){removeAll(DEPARTING);for(int p=0;p<3;p++)task(p,SURVIVOR).isVisible=false;}};
            coherentOne(active(),3);
        });
        test("unrelated_physical_root_change_does_not_expand_owned_fence",()->{
            prepare(2);disappear(false);
            int foreign=-1;for(Object row:e.list(2))if(row instanceof TaskInfo&&((TaskInfo)row).displayId==0){foreign=((TaskInfo)row).taskId;break;}
            yes(foreign>0);remove(2,foreign);coherentOne(active(),2);
        });
        test("coherent_active_frame_keeps_original_single_read_path",()->{
            prepare(2);PublicPersonalNotesCustody.Frame frame=active();
            yes(frame.roots.size()==2&&e.rootReads==1&&e.allReads==2);yes(!c.known());
        });
        test("authorized_new_root_in_coherent_frame_keeps_existing_registration_path",()->{
            prepare(1);c.markLaunch();addRoot(DEPARTING);
            PublicPersonalNotesCustody.Frame frame=active();yes(frame.roots.size()==2&&e.rootReads==1&&e.allReads==2);
            c.observe(frame,frame.end);yes(((List<?>)c.evidence().get("actual_observed_tasks")).size()==2);
            yes(!c.known()&&c.retain());
        });
        test("no_custodian_cannot_spend_active_disappearance_permission",()->{
            prepare(2);disappear(false);refuses(()->e.frame());yes(e.rootReads==1);
        });
        test("unobserved_target_root_cannot_create_active_permission",()->{
            prepare(2);
            NotesTaskInfoReaderHostTest.Env initial=new NotesTaskInfoReaderHostTest.Env();initial.empty();
            PublicPersonalNotesCustody.Frame base=initial.frame();
            c=new PublicPersonalNotesCustody(GENERATION,SCOPE,UID,base.global,PublicOwnGroupPhysicalFence.inspectRecents(PublicPhysicalAuditHostTest.recents(false)));
            c.beforeCreate();c.bindDisplay(DISPLAY);c.markLaunch();disappear(false);refuses(()->active());yes(e.rootReads==1);
        });
        test("previously_unresolved_custodian_never_revives",()->{
            prepare(2);c.unresolved("ORIGINAL_UNKNOWN");disappear(false);refuses(()->active());
            yes(Boolean.TRUE.equals(c.evidence().get("identity_unknown"))&&"ORIGINAL_UNKNOWN".equals(c.evidence().get("failure")));
        });
        test("retired_custodian_cannot_read_active_transition",()->{
            prepare(2);c.retireAdmission();disappear(false);refuses(()->active());yes(e.rootReads==1&&!c.known());
        });
        test("retirement_during_first_triple_prevents_retry_and_publication",()->{
            prepare(2);disappear(false);e.onAfterRead=c::retireAdmission;refuses(()->active());yes(e.rootReads==1);
        });
        test("unknown_during_first_triple_prevents_retry_and_publication",()->{
            prepare(2);disappear(false);e.onAfterRead=()->c.unresolved("LATE_UNKNOWN");refuses(()->active());yes(e.rootReads==1);
            yes("LATE_UNKNOWN".equals(c.evidence().get("failure")));
        });
        test("new_launch_during_first_triple_invalidates_frozen_owner",()->{
            prepare(2);disappear(false);e.onAfterRead=c::markLaunch;refuses(()->active());yes(e.rootReads==1);
        });
        test("new_observation_during_first_triple_invalidates_frozen_owner",()->{
            prepare(2);disappear(false);e.onAfterRead=()->{
                long now=SystemClock.elapsedRealtime();
                c.observe(new PublicPersonalNotesCustody.Frame(original.global,original.roots,now,now),now);
            };
            refuses(()->active());yes(e.rootReads==1);
        });
        test("same_timestamp_new_observed_root_invalidates_closed_identity_map",()->{
            prepare(2);addRoot(1466);
            PublicPersonalNotesCustody.Frame three=e.frame();
            PublicPersonalNotesCustody.Frame sameTime=new PublicPersonalNotesCustody.Frame(three.global,three.roots,original.begin,original.end);
            removeAll(1466);e.allReads=0;e.rootReads=0;e.trace.clear();disappear(false);
            e.onAfterRead=()->c.observe(sameTime,SystemClock.elapsedRealtime());
            refuses(()->active());yes(e.rootReads==1);
            yes(lastRefusal.contains("NOTES_ACTIVE_READ_UNAVAILABLE"));
            yes(((List<?>)c.evidence().get("actual_observed_tasks")).size()==3);
        });
        test("retirement_during_final_coherent_triple_cannot_publish",()->{
            prepare(2);disappear(false);e.onAfterRead=()->{if(e.allReads>=4)c.retireAdmission();};
            refuses(()->active());yes(e.rootReads==2);yes(lastRefusal.contains("NOTES_ACTIVE_READ_UNAVAILABLE"));
        });
        test("root_empty_is_not_active_absence_or_cleanup_proof",()->{
            prepare(2);remove(1,DEPARTING);remove(2,DEPARTING);remove(2,SURVIVOR);
            refuses(()->active());yes(e.rootReads==1&&!c.known());
        });
        test("new_unobserved_root_is_not_discarded_as_motion",()->{
            prepare(2);addRoot(1466);disappear(false);refuses(()->active());yes(e.rootReads==1);
        });
        test("middle_growth_is_not_monotone_disappearance",()->{
            prepare(2);remove(0,DEPARTING);remove(2,DEPARTING);refuses(()->active());yes(e.rootReads==1);
        });
        test("removed_root_reappearance_during_retry_is_refused",()->{
            prepare(2);final Object old=task(2,DEPARTING);remove(2,DEPARTING);
            e.onBeforeRead=()->{if(e.allReads>=3){e.list(2).add(old);}};
            refuses(()->active());yes(e.rootReads==2);
        });
        for(final int display:new int[]{0,1,206})test("departing_task_on_display_"+display+"_is_escape_not_absence",()->{
            prepare(2);moveDisappearingGlobal(display);refuses(()->active());yes(e.rootReads==1);
        });
        test("departing_id_as_foreign_leaf_is_not_absent",()->{
            prepare(2);disappear(false);
            ActivityTaskManager.RootTaskInfo foreign=null;
            for(Object row:e.list(2))if(row instanceof ActivityTaskManager.RootTaskInfo&&((TaskInfo)row).displayId==0){foreign=(ActivityTaskManager.RootTaskInfo)row;break;}
            yes(foreign!=null);foreign.childTaskIds=new int[]{DEPARTING};foreign.childTaskUserIds=new int[]{0};
            foreign.childTaskNames=new String[]{PKG+"/"+EDITOR};foreign.childTaskBounds=new android.graphics.Rect[]{new android.graphics.Rect(0,0,10,10)};
            refuses(()->active());yes(e.rootReads==1);
        });
        for(final String field:new String[]{"token","cookie","uid","user","display","parent","component"})test("survivor_original_"+field+"_must_remain_exact",()->{
            prepare(2);disappear(false);
            for(int phase=0;phase<3;phase++)NotesTaskInfoReaderHostTest.change(task(phase,SURVIVOR),field);
            refuses(()->active());yes(e.rootReads==1&&!c.known());
        });
        test("departing_original_token_must_be_known_before_discard",()->{
            prepare(2);disappear(false);IBinder replacement=new Binder();
            task(0,DEPARTING).token=new WindowContainerToken(replacement);task(1,DEPARTING).token=new WindowContainerToken(replacement);
            refuses(()->active());yes(e.rootReads==1);
        });
        test("survivor_coherent_replacement_after_discard_is_still_refused",()->{
            prepare(2);disappear(false);IBinder replacement=new Binder();
            e.onBeforeRead=()->{if(e.allReads>=3){removeAll(DEPARTING);for(int p=0;p<3;p++)task(p,SURVIVOR).token=new WindowContainerToken(replacement);}};
            refuses(()->active());yes(e.rootReads==2);
        });
        test("malformed_global_census_remains_unknown",()->{
            prepare(2);disappear(false);((ActivityTaskManager.RootTaskInfo)task(2,SURVIVOR)).childTaskIds=null;
            refuses(()->active());yes(e.rootReads==1);
        });
        test("partial_organizer_read_never_becomes_disappearance",()->{
            prepare(2);disappear(false);e.own=null;refuses(()->active());yes(e.rootReads==1);
        });
        test("original_outer_deadline_prevents_retry",()->{
            prepare(2);disappear(false);e.onAfterRead=()->SystemClock.now=e.deadline;
            refuses(()->active());yes(e.rootReads==1);
        });
        test("original_1500ms_frame_budget_prevents_retry",()->{
            prepare(2);disappear(false);e.onAfterRead=()->SystemClock.now+=1600;
            refuses(()->active());yes(e.rootReads==1);
        });
        test("three_complete_samples_are_absolute_contraction_budget",()->{
            prepare(4);remove(2,1467);
            e.onBeforeRead=()->{
                if(e.allReads==3){removeAll(1467);remove(2,1466);}
                if(e.allReads==5){removeAll(1466);remove(2,DEPARTING);}
            };
            refuses(()->active());yes(e.rootReads==3&&e.allReads==6);yes(!c.known()&&c.retain());
        });
        test("active_snapshot_constructor_is_private_and_has_no_release_or_input_port",()->{
            Class<?> type=Class.forName("org.trillionnium.hepta.background.PublicPersonalNotesCustody$ActiveRead");
            int declared=0;
            for(java.lang.reflect.Constructor<?> constructor:type.getDeclaredConstructors()){
                if(constructor.isSynthetic()){
                    // --release 8 emits a package-private compiler bridge for
                    // the enclosing owner to invoke its nested private ctor.
                    yes(!java.lang.reflect.Modifier.isPublic(constructor.getModifiers())
                            &&!java.lang.reflect.Modifier.isProtected(constructor.getModifiers()));
                }else{
                    declared++;yes(java.lang.reflect.Modifier.isPrivate(constructor.getModifiers()));
                    yes(Arrays.equals(constructor.getParameterTypes(),new Class<?>[]{PublicPersonalNotesCustody.class}));
                }
            }
            yes(declared==1);
            for(java.lang.reflect.Method method:type.getDeclaredMethods())
                yes(!Arrays.asList("remove","release","close","dispatch","launch","reset","serialize").contains(method.getName()));
        });
        boolean passed=true;for(Map<String,Object> row:results)passed&=Boolean.TRUE.equals(row.get("passed"));
        JSONObject result=new JSONObject().put("schema","hepta.notes-active-census-host.v1").put("all_pass",passed)
            .put("cases",results.size()).put("assertions",checks).put("case_results",results)
            .put("framework_and_binder_fixtures_synthetic",true).put("recorded_topology_replayed",true)
            .put("complete_recorded_taskinfo_claimed",false).put("serialized_tokens_grant_authority",false)
            .put("maximum_complete_samples",3).put("maximum_frame_ms",1500).put("phone_operations",0)
            .put("dispatch_calls",0).put("intent_redispatches",0).put("new_cleanup_authority",false);
        System.out.println(result);if(!passed)System.exit(1);
    }
}
