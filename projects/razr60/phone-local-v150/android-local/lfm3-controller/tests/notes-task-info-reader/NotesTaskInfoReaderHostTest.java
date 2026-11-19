package org.trillionnium.hepta.background;

import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.graphics.Rect;
import android.os.*;
import android.window.*;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import org.json.*;

/** Executes both complete production reflection adapters. A bundled synthetic
 * task-shape fixture is the default; an archived capture is an explicit mode.
 * Both use inert Android classes and synthetic Binder objects.
 * No serialized token, fixture clock or host success grants phone authority. */
public final class NotesTaskInfoReaderHostTest {
    static final String RAW_SHA="e0c6a2c1eee8d0d490df7ffd381149ffa443ab4c756bd4fdc41f960ef115db9c";
    static final String SYNTHETIC_SHA="8b44610ab210e5882d5de0cb61583992ccb626ed021b63af277f47407c3af201";
    static final int SYNTHETIC_BYTES=18714;
    static boolean actualCapture;
    static final String PKG="com.motorola.stylus",COMP=PKG+"/"+PKG+".manager.NoteManagerActivity";
    static JSONObject captured;
    static int cases,checks;
    static final List<String> names=new ArrayList<String>();
    static Env e;
    interface Work {void run()throws Exception;}
    static void yes(boolean ok){checks++;if(!ok)throw new AssertionError("Notes reflection boundary");}
    static String cause(Throwable t){for(int i=0;i<12&&t.getCause()!=null;i++)t=t.getCause();return String.valueOf(t.getMessage());}
    static void refuses(String code,Work work)throws Exception {
        try{work.run();}catch(Exception expected){yes(code==null||cause(expected).contains(code));return;}
        throw new AssertionError("unproved Notes frame accepted: "+code);
    }
    static void test(String name,Work work)throws Exception {
        e=new Env();work.run();yes(e.childrenCalls==0&&e.mutations==0);
        cases++;names.add(name);System.out.println("PASS "+name);
    }
    static Object value(JSONObject row,String name)throws Exception {
        JSONObject f=row.getJSONObject(name);
        if(!f.getBoolean("available"))throw new IOException("actual capture field unavailable: "+name);
        return f.isNull("value")?null:f.get("value");
    }
    static int integer(JSONObject row,String name)throws Exception {
        Object v=value(row,name);if(!(v instanceof Integer))throw new IOException("actual integer type");return (Integer)v;
    }
    static boolean bool(JSONObject row,String name)throws Exception {
        Object v=value(row,name);if(!(v instanceof Boolean))throw new IOException("actual bool type");return (Boolean)v;
    }
    static ComponentName component(Object object){
        if(object==null)return null;JSONObject j=(JSONObject)object;
        return new ComponentName(j.getString("package"),j.getString("class"));
    }
    static ApplicationInfo application(JSONObject j){
        ApplicationInfo info=new ApplicationInfo();info.uid=j.getInt("uid");
        info.packageName=j.getString("package");info.enabled=j.getBoolean("enabled");
        info.sourceDir=j.getString("source_dir");return info;
    }
    static String nullable(JSONObject j,String k){return j.isNull(k)?null:j.getString(k);}
    static int[] ints(Object object){
        if(object==null)return null;JSONArray a=(JSONArray)object;int[] out=new int[a.length()];
        for(int i=0;i<out.length;i++)out[i]=a.getInt(i);return out;
    }
    static String[] strings(Object object){
        if(object==null)return null;JSONArray a=(JSONArray)object;String[] out=new String[a.length()];
        for(int i=0;i<out.length;i++)out[i]=a.isNull(i)?null:a.getString(i);return out;
    }
    public static final class Env implements IActivityTaskManager {
        Object before,own,after;
        final Context context=new Context();
        final Map<Integer,IBinder> syntheticBinders=new HashMap<Integer,IBinder>();
        final List<String> trace=new ArrayList<String>();
        int allReads,rootReads,childrenCalls,mutations;
        long deadline=100000;
        Runnable onOwnRead,onAfterRead;
        final PublicPersonalNotesReader reader;
        final ITaskOrganizerController organizer=new ITaskOrganizerController(){
            public Object getRootTasks(int display,int[] types){
                yes(display==205&&types==null);rootReads++;trace.add("roots:205");
                if(onOwnRead!=null)onOwnRead.run();return own;
            }
            public Object getChildTasks(WindowContainerToken token,int[] types){
                childrenCalls++;throw new AssertionError("ordinary Notes getChildTasks must never execute");
            }
            public void createRootTask(int d,int m,IBinder c,boolean top){mutations++;throw new AssertionError("create forbidden");}
            public boolean deleteRootTask(WindowContainerToken t){mutations++;throw new AssertionError("delete forbidden");}
        };
        final IWindowOrganizerController controller=new IWindowOrganizerController(){
            public ITaskOrganizerController getTaskOrganizerController(){return organizer;}
            public void applyTransaction(WindowContainerTransaction t){mutations++;throw new AssertionError("transaction forbidden");}
        };
        Env()throws Exception {
            SystemClock.now=10000;SystemClock.step=1;Build.VERSION.SDK_INT=36;
            before=rehydrate("before_all_roots",true);own=rehydrate("owned_display_roots",false);
            after=rehydrate("after_all_roots",true);
            context.pm.installed=application(captured.getJSONObject("owned_display_roots").getJSONArray("rows")
                    .getJSONObject(0).getJSONObject("topActivityInfo").getJSONObject("value").getJSONObject("application_info"));
            reader=new PublicPersonalNotesReader(context,this,205,()->deadline);
        }
        IBinder binder(JSONObject j)throws Exception{
            if(j.getBoolean("serialized_identity_grants_authority"))throw new IOException("captured token must not grant authority");
            int key=j.getInt("same_process_equality_index");
            IBinder b=syntheticBinders.get(key);
            if(b==null){b=new Binder();syntheticBinders.put(key,b);}return b;
        }
        TaskInfo row(JSONObject j,boolean global)throws Exception{
            TaskInfo t=global?new ActivityTaskManager.RootTaskInfo():new ActivityManager.RunningTaskInfo();
            t.taskId=integer(j,"taskId");t.displayId=integer(j,"displayId");t.userId=integer(j,"userId");
            t.parentTaskId=integer(j,"parentTaskId");t.effectiveUid=integer(j,"effectiveUid");t.numActivities=integer(j,"numActivities");
            t.isRunning=bool(j,"isRunning");t.isVisible=bool(j,"isVisible");
            t.baseActivity=component(value(j,"baseActivity"));t.topActivity=component(value(j,"topActivity"));
            t.realActivity=component(value(j,"realActivity"));t.origActivity=component(value(j,"origActivity"));
            Object rawIntent=value(j,"baseIntent");
            if(rawIntent!=null){JSONObject b=(JSONObject)rawIntent;t.baseIntent=new Intent(nullable(b,"action"))
                    .setFlags(b.getInt("flags")).setComponent(component(b.isNull("component")?null:b.getJSONObject("component")));}
            Object rawInfo=value(j,"topActivityInfo");
            if(rawInfo!=null){
                JSONObject a=(JSONObject)rawInfo;ActivityInfo info=new ActivityInfo();info.packageName=a.getString("package");
                info.name=a.getString("name");info.targetActivity=nullable(a,"target_activity");
                info.enabled=a.getBoolean("enabled");info.exported=a.getBoolean("exported");
                info.applicationInfo=a.isNull("application_info")?null:application(a.getJSONObject("application_info"));t.topActivityInfo=info;
            }
            Object tok=value(j,"token");
            t.token=tok==null?null:new WindowContainerToken(binder(((JSONObject)tok).getJSONObject("binder")));
            Object cookies=value(j,"launchCookies");
            if(cookies!=null){t.launchCookies=new ArrayList<IBinder>();JSONArray a=(JSONArray)cookies;
                for(int i=0;i<a.length();i++)t.launchCookies.add(binder(a.getJSONObject(i)));}
            if(global){
                ActivityTaskManager.RootTaskInfo r=(ActivityTaskManager.RootTaskInfo)t;
                r.visible=bool(j,"visible");r.childTaskIds=ints(value(j,"childTaskIds"));
                r.childTaskUserIds=ints(value(j,"childTaskUserIds"));r.childTaskNames=strings(value(j,"childTaskNames"));
                Object bounds=value(j,"childTaskBounds");
                if(bounds!=null){JSONArray a=(JSONArray)bounds;r.childTaskBounds=new Rect[a.length()];
                    for(int i=0;i<a.length();i++){JSONArray v=a.getJSONArray(i);if(v.length()!=4)throw new IOException("actual rectangle");
                        r.childTaskBounds[i]=new Rect(v.getInt(0),v.getInt(1),v.getInt(2),v.getInt(3));}}
            }else {
                for(String absent:new String[]{"visible","childTaskIds","childTaskUserIds","childTaskNames","childTaskBounds"})
                    if(j.getJSONObject(absent).getBoolean("available"))throw new IOException("RunningTaskInfo capture shape changed");
            }
            return t;
        }
        List<Object> rehydrate(String phase,boolean global)throws Exception{
            JSONObject s=captured.getJSONObject(phase);JSONArray rows=s.getJSONArray("rows");
            if(!(actualCapture?"CAPTURED":"SYNTHETIC_DERIVED").equals(s.getString("status"))||s.getBoolean("returned_null")||s.getInt("count")!=rows.length())
                throw new IOException("incomplete original capture");
            List<Object> result=new ArrayList<Object>();for(int i=0;i<rows.length();i++)result.add(row(rows.getJSONObject(i),global));return result;
        }
        public Object getAllRootTaskInfos(){int index=allReads++;trace.add("all");if(index%2==1&&onAfterRead!=null)onAfterRead.run();return index%2==0?before:after;}
        public IWindowOrganizerController getWindowOrganizerController(){return controller;}
        @SuppressWarnings("unchecked") List<Object> list(int p){return (List<Object>)(p==0?before:p==1?own:after);}
        TaskInfo task(int p){for(Object o:list(p))if(o instanceof TaskInfo&&((TaskInfo)o).taskId==1464)return (TaskInfo)o;throw new AssertionError("target row missing in fixture");}
        ActivityTaskManager.RootTaskInfo root(int p){return (ActivityTaskManager.RootTaskInfo)task(p);}
        void empty(){for(int p=0;p<3;p++)list(p).removeIf(o->o instanceof TaskInfo&&((TaskInfo)o).displayId==205);}
        PublicPersonalNotesCustody.Frame frame()throws Exception{return reader.frame();}
    }
    static void change(TaskInfo t,String field){
        if("token".equals(field))t.token=new WindowContainerToken(new Binder());
        else if("uid".equals(field))t.effectiveUid++;
        else if("top-uid".equals(field))t.topActivityInfo.applicationInfo.uid++;
        else if("user".equals(field))t.userId=10;
        else if("display".equals(field))t.displayId=206;
        else if("parent".equals(field))t.parentTaskId=1234;
        else if("component".equals(field))t.baseActivity=new ComponentName("com.other.app","com.other.app.Main");
        else if("cookie".equals(field))t.launchCookies.add(new Binder());
        else if("visibility".equals(field))t.isVisible=!t.isVisible;
        else if("running".equals(field))t.isRunning=!t.isRunning;
        else if("activities".equals(field))t.numActivities++;
        else throw new AssertionError(field);
    }
    static BackgroundTaskOrganizer adapter()throws Exception{
        Field f=PublicPersonalNotesReader.class.getDeclaredField("reader");f.setAccessible(true);return (BackgroundTaskOrganizer)f.get(e.reader);
    }
    static String digest(byte[] b)throws Exception{
        byte[] d=MessageDigest.getInstance("SHA-256").digest(b);StringBuilder s=new StringBuilder();
        for(byte v:d)s.append(String.format(Locale.ROOT,"%02x",v&255));return s.toString();
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2||!("actual_archived_capture".equals(args[1])||"synthetic_derived_fixture".equals(args[1])))
            throw new IOException("exact input path and explicit provenance mode required");
        actualCapture="actual_archived_capture".equals(args[1]);
        byte[] raw=Files.readAllBytes(Paths.get(args[0]));
        String expectedSha=actualCapture?RAW_SHA:SYNTHETIC_SHA;
        if(raw.length!=(actualCapture?44577:SYNTHETIC_BYTES)||!expectedSha.equals(digest(raw)))
            throw new IOException("exact fixture bytes changed");
        captured=new JSONObject(new String(raw,StandardCharsets.UTF_8));
        if(!actualCapture&&(!"hepta.notes-task-info-synthetic-derived-fixture.v1".equals(captured.getString("schema"))
                ||!"synthetic_derived_task_shapes".equals(captured.getString("fixture_kind"))
                ||captured.getBoolean("original_capture_replayed")||!RAW_SHA.equals(captured.getString("source_capture_sha256"))
                ||captured.getInt("source_capture_bytes")!=44577))throw new IOException("derived fixture provenance");
        if(!captured.getBoolean("read_only")||captured.getBoolean("display_or_task_mutation")
                ||captured.getBoolean("release_or_recovery_authority")||captured.getInt("target_display")!=205
                ||captured.getInt("expected_task")!=1464||captured.getInt("expected_uid")!=10382)throw new IOException("actual capture contract");
        test("three-sample input uses complete original reflection adapters",()->{
            PublicPersonalNotesCustody.Frame f=e.frame();yes(f.roots.size()==1);
            BackgroundOwnedSingleTask.Task t=f.roots.get(0).task;
            yes(t.id==1464&&t.display==205&&t.uid==10382&&t.topUid==10382&&t.user==0&&t.parent==-1);
            yes(f.roots.get(0).children.isEmpty()&&f.global.leaves.get(1464).parent==1464);
            yes(t.token==e.task(0).token.asBinder()&&t.token==e.task(1).token.asBinder()&&t.token==e.task(2).token.asBinder());
            yes(COMP.equals(t.base)&&COMP.equals(t.top)&&COMP.equals(t.real));
            yes(e.trace.equals(Arrays.asList("all","roots:205","all"))&&e.allReads==2&&e.rootReads==1);
        });
        test("visible and isVisible fields retain their different meanings",()->{
            yes(e.root(0).visible&&!e.task(0).isVisible);PublicPersonalNotesCustody.Frame f=e.frame();
            yes(!f.roots.get(0).task.visible);ProfileTaskPolicy.Root r=null;for(ProfileTaskPolicy.Root x:f.global.roots)if(x.id==1464)r=x;
            yes(r!=null&&r.visible);refuses(null,()->ActivityManager.RunningTaskInfo.class.getField("childTaskIds"));
        });
        test("stable same-UID editor top is admitted without inventing child arrays",()->{
            for(int p=0;p<3;p++){TaskInfo t=e.task(p);t.topActivity=new ComponentName(PKG,PKG+".edit.NoteEditorActivity");t.topActivityInfo.name=PKG+".edit.NoteEditorActivity";}
            yes(e.frame().roots.get(0).task.top.endsWith("NoteEditorActivity"));
        });
        test("complete empty own-display admission has zero leaves",()->{e.empty();PublicPersonalNotesCustody.Frame f=e.frame();yes(f.roots.isEmpty()&&!f.global.allIds.contains(1464));yes(f.global.roots.size()==4);});
        for(final int phase:new int[]{0,1,2})for(final String field:new String[]{"token","uid","top-uid","user","display","parent","component","cookie","visibility","running","activities"})
            test("three-read phase "+phase+" rejects changed "+field,()->{change(e.task(phase),field);refuses(null,()->e.frame());});
        test("global null response remains unknown",()->{e.before=null;refuses("PROFILE_ROOT_QUERY_INCOMPLETE",()->e.frame());});
        test("global non-list response remains unknown",()->{e.after="not-a-list";refuses("PROFILE_ROOT_QUERY_INCOMPLETE",()->e.frame());});
        test("organizer null response retains original generic rows refusal",()->{e.own=null;refuses("OWNED_TASK_ROWS_UNAVAILABLE",()->e.frame());});
        test("generic rows null is not converted to an empty list",()->{
            Method m=BackgroundTaskOrganizer.class.getDeclaredMethod("rows",Object.class);m.setAccessible(true);
            refuses("OWNED_TASK_ROWS_UNAVAILABLE",()->m.invoke(adapter(),new Object[]{null}));
        });
        test("null global row fails complete census",()->{e.list(0).add(null);refuses("PROFILE_ROOT_QUERY_INCOMPLETE",()->e.frame());});
        test("null organizer row fails real TaskInfo parsing",()->{e.list(1).set(0,null);refuses("OWNED_TASK_ROW_NULL",()->e.frame());});
        test("missing global child arrays cannot prove leaf",()->{e.root(0).childTaskIds=null;refuses("PROFILE_CHILD_ARRAYS_UNAVAILABLE",()->e.frame());});
        test("parallel array length mismatch cannot prove leaf",()->{e.root(2).childTaskUserIds=new int[0];refuses("PROFILE_CHILD_ARRAYS_INCOMPLETE",()->e.frame());});
        test("zero global leaves is not an empty child proof",()->{
            ActivityTaskManager.RootTaskInfo t=e.root(0);t.childTaskIds=new int[0];t.childTaskUserIds=new int[0];t.childTaskNames=new String[0];t.childTaskBounds=new Rect[0];
            refuses("NOTES_ROOT_IS_NOT_PROVEN_SOLE_LEAF",()->e.frame());
        });
        test("nested child is not ordinary root equals leaf",()->{e.root(0).childTaskIds[0]=1465;refuses("NOTES_ROOT_IS_NOT_PROVEN_SOLE_LEAF",()->e.frame());});
        test("extra leaf on a target root is refused",()->{
            ActivityTaskManager.RootTaskInfo t=e.root(2);t.childTaskIds=new int[]{1464,1465};t.childTaskUserIds=new int[]{0,0};
            t.childTaskNames=new String[]{COMP,COMP};t.childTaskBounds=new Rect[]{new Rect(0,0,1224,2992),new Rect(0,0,1224,2992)};
            refuses("NOTES_ROOT_IS_NOT_PROVEN_SOLE_LEAF",()->e.frame());
        });
        test("leaf actual user cannot be copied from root user",()->{e.root(2).childTaskUserIds[0]=10;refuses("NOTES_ROOT_IS_NOT_PROVEN_SOLE_LEAF",()->e.frame());});
        test("leaf name needs exact actual component",()->{e.root(0).childTaskNames[0]=PKG;refuses("NOTES_ROOT_IS_NOT_PROVEN_SOLE_LEAF",()->e.frame());});
        test("leaf geometry is not defaulted",()->{e.root(0).childTaskBounds[0]=null;refuses("PROFILE_CHILD_BOUNDS_UNAVAILABLE",()->e.frame());});
        test("duplicate global root IDs remain invalid",()->{e.list(2).add(e.task(2));refuses("PROFILE_GLOBAL_ROOT_DUPLICATE",()->e.frame());});
        test("extra duplicate organizer root is refused",()->{e.list(1).add(e.task(1));refuses("NOTES_ROOT_IDENTITY_UNAVAILABLE",()->e.frame());});
        test("root disappears between independent samples",()->{e.list(2).remove(e.task(2));refuses("NOTES_ROOT_CENSUS_CHANGED",()->e.frame());});
        test("empty middle cannot erase positively observed root",()->{e.list(1).clear();refuses("NOTES_ROOT_CENSUS_CHANGED",()->e.frame());});
        test("global root bound stays 256",()->{Object r=e.task(0);e.before=new ArrayList<Object>(Collections.nCopies(257,r));refuses("PROFILE_ROOT_QUERY_INCOMPLETE",()->e.frame());});
        test("generic actual row bound stays 2048",()->{Object r=e.task(1);e.own=new ArrayList<Object>(Collections.nCopies(2049,r));refuses("OWNED_TASK_ROWS_UNAVAILABLE",()->e.frame());});
        test("Notes own root bound stays 32",()->{Object r=e.task(1);e.own=new ArrayList<Object>(Collections.nCopies(33,r));refuses("NOTES_ROOT_CENSUS_UNAVAILABLE",()->e.frame());});
        test("global leaf bound stays 2048",()->{ActivityTaskManager.RootTaskInfo r=e.root(0);r.childTaskIds=new int[2049];r.childTaskUserIds=new int[2049];r.childTaskNames=new String[2049];r.childTaskBounds=new Rect[2049];Arrays.fill(r.childTaskBounds,new Rect(0,0,1,1));refuses("PROFILE_CHILD_ARRAYS_INCOMPLETE",()->e.frame());});
        test("unknown cookie field is rejected by original rows",()->{e.task(1).launchCookies=null;refuses("OWNED_TASK_COOKIES_INVALID",()->e.frame());});
        test("missing top UID cannot be inferred from installed package",()->{e.task(1).topActivityInfo=null;refuses("OWNED_TASK_TOP_UID_UNKNOWN",()->e.frame());});
        test("missing real activity is not synthesized",()->{e.task(1).realActivity=null;refuses("NOTES_ROOT_UID_OR_COMPONENT_UNAVAILABLE",()->e.frame());});
        test("deadline before any census has no framework reads",()->{e.deadline=SystemClock.now;refuses("NOTES_TASK_READ_DEADLINE",()->e.frame());yes(e.trace.isEmpty());});
        test("deadline crossed during census refuses final result",()->{e.onOwnRead=()->SystemClock.now=e.deadline;refuses("NOTES_TASK_READ_DEADLINE",()->e.frame());});
        test("frame bound remains 1500 ms despite a longer outer deadline",()->{e.onOwnRead=()->SystemClock.now+=1600;refuses("NOTES_TASK_FRAME_INVALID",()->e.frame());});
        test("installed UID is freshly rechecked after census",()->{e.onAfterRead=()->e.context.pm.installed.uid++;refuses("NOTES_INSTALLATION_CHANGED",()->e.frame());});
        test("installed source path is freshly rechecked",()->{e.onAfterRead=()->e.context.pm.installed.sourceDir="/different.apk";refuses("NOTES_INSTALLATION_CHANGED",()->e.frame());});
        test("disabled installed package cannot be accepted",()->{e.onAfterRead=()->e.context.pm.installed.enabled=false;refuses("NOTES_INSTALLATION_CHANGED",()->e.frame());});
        test("physical display zero is never accepted",()->refuses("NOTES_OWN_DISPLAY_INVALID",()->new PublicPersonalNotesReader(e.context,e,0,()->e.deadline)));
        test("cover display one is never accepted",()->refuses("NOTES_OWN_DISPLAY_INVALID",()->new PublicPersonalNotesReader(e.context,e,1,()->e.deadline)));
        test("census emptiness after synthetic release still needs two policy samples",()->{
            Env initial=new Env();initial.empty();PublicPersonalNotesCustody.Frame baseline=initial.frame();
            PublicOwnGroupPhysicalFence.RecentCensus recents=PublicOwnGroupPhysicalFence.inspectRecents(PublicPhysicalAuditHostTest.recents(false));
            PublicPersonalNotesCustody c=new PublicPersonalNotesCustody("11111111-1111-4111-8111-111111111111",String.join("",Collections.nCopies(64,"a")),10382,baseline.global,recents);
            c.beforeCreate();c.bindDisplay(205);c.markLaunch();PublicPersonalNotesCustody.Frame f=e.frame();c.observe(f,f.end);
            c.retireAdmission();f=e.frame();c.prepareRelease(f,recents,f.end);c.enterRelease();c.releaseReturned();yes(!c.known());
            e.empty();f=e.frame();c.observeAbsence(f.global,recents,true,f.begin,f.end,f.end);yes(!c.known());
            f=e.frame();c.observeAbsence(f.global,recents,true,f.begin,f.end,f.end);yes(c.known()&&!c.retain());
            yes(initial.childrenCalls==0&&initial.mutations==0);
        });
        JSONObject result=new JSONObject().put("schema","hepta.notes-task-info-reader-host.v2").put("all_pass",true)
                .put("cases",cases).put("assertions",checks).put("case_names",names)
                .put("input_mode",args[1]).put("input_sha256",digest(raw)).put("archived_capture_replayed",actualCapture)
                .put("actual_capture_sha256",actualCapture?RAW_SHA:JSONObject.NULL).put("reference_capture_sha256",RAW_SHA)
                .put("input_values_rehydrated",true).put("synthetic_binder_tokens",true).put("framework_and_clock_fixtures_synthetic",true)
                .put("complete_production_reflection_adapters",true).put("get_child_tasks_calls",0).put("mutation_calls",0)
                .put("phone_operations",0).put("hardware_qualification_claimed",false);
        System.out.println(result.toString());
    }
}
