package org.trillionnium.hepta.background;

import android.app.ActivityTaskManager.RootTaskInfo;
import android.app.IActivityTaskManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.os.Binder;
import android.os.IBinder;
import android.os.SystemClock;
import android.window.ITaskOrganizerController;
import android.window.IWindowOrganizerController;
import android.window.WindowContainerToken;
import android.window.WindowContainerTransaction;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual recorded TaskInfo fields, synthetic local Binder/PM/clock/dump ports.
 * No captured Binder identity is an effect capability; this test has no WCT path. */
public final class NotesTaskInfoSemanticsHostTest {
    private static JSONObject fixture;
    private static int cases,assertions;
    private static final List<String> names=new ArrayList<String>();
    interface Work { void run() throws Exception; }
    private static void check(boolean value){assertions++;if(!value)throw new AssertionError("actual TaskInfo semantics");}
    private static String cause(Throwable value){while(value.getCause()!=null)value=value.getCause();return String.valueOf(value.getMessage());}
    private static void test(String name,Work work)throws Exception{work.run();cases++;names.add(name);System.out.println("PASS "+name);}
    private static void refuses(String code,Work work)throws Exception{
        try{work.run();}catch(Exception failure){check(cause(failure).contains(code));return;}
        throw new AssertionError("unproved census accepted: "+code);
    }
    private static String text(JSONObject row,String key){return row.isNull(key)?null:row.getString(key);}
    private static ComponentName component(String value){return value==null?null:ComponentName.unflattenFromString(value);}

    private static final class Port implements IActivityTaskManager {
        final List<RootTaskInfo> roots=new ArrayList<RootTaskInfo>(),running=new ArrayList<RootTaskInfo>(),children=new ArrayList<RootTaskInfo>();
        final Map<Integer,IBinder> binders=new LinkedHashMap<Integer,IBinder>();
        final Map<Integer,RootTaskInfo> rootById=new LinkedHashMap<Integer,RootTaskInfo>(),leafById=new LinkedHashMap<Integer,RootTaskInfo>();
        int effects,childQueries;
        ProfileTaskPolicy.Snapshot expected;
        PublicPersonalNotesRetirementAdapter adapter;
        Port()throws Exception{
            JSONArray rows=fixture.getJSONArray("rows");
            for(int i=0;i<rows.length();i++){
                JSONObject data=rows.getJSONObject(i);RootTaskInfo row=decode(data);
                String query=data.getString("query");
                if("all_roots".equals(query)){roots.add(row);rootById.put(row.taskId,row);}
                else if("running_tasks".equals(query)){running.add(row);leafById.put(row.taskId,row);}
                else if("actual_root_3_children".equals(query)){children.add(row);leafById.put(row.taskId,row);}
                else throw new AssertionError("unknown actual read");
            }
            check(roots.size()==6&&running.size()==5&&children.size()==2);
            for(RootTaskInfo root:roots){
                int n=root.childTaskIds.length;root.childTaskUserIds=new int[n];root.childTaskNames=new String[n];root.childTaskBounds=new android.graphics.Rect[n];
                for(int i=0;i<n;i++){
                    RootTaskInfo leaf=leafById.get(root.childTaskIds[i]);if(leaf==null)leaf=rootById.get(root.childTaskIds[i]);check(leaf!=null);
                    root.childTaskUserIds[i]=leaf.userId;
                    root.childTaskNames[i]=leaf.topActivity==null?"unknown":leaf.topActivity.getPackageName()+"/"+leaf.topActivity.getClassName();
                    // Bounds and child-name formatting are authored IO ports, not recorded full snapshots.
                    root.childTaskBounds[i]=new android.graphics.Rect(0,0,100,100);
                }
            }
        }
        private IBinder token(JSONObject row){
            int key=row.getInt("local_index");IBinder value=binders.get(key);if(value==null){value=new Binder();binders.put(key,value);}return value;
        }
        private RootTaskInfo decode(JSONObject data){
            RootTaskInfo row=new RootTaskInfo();row.taskId=data.getInt("taskId");row.displayId=data.getInt("displayId");
            row.userId=data.getInt("userId");row.parentTaskId=data.getInt("parentTaskId");row.effectiveUid=data.getInt("effectiveUid");
            row.numActivities=data.getInt("numActivities");row.isRunning=data.getBoolean("isRunning");row.isVisible=data.getBoolean("isVisible");row.visible=row.isVisible;
            row.baseIntent=new Intent();String intent=text(data,"base_intent_component");if(intent!=null)row.baseIntent.setComponent(component(intent));
            row.baseActivity=component(text(data,"baseActivity"));row.topActivity=component(text(data,"topActivity"));
            row.realActivity=component(text(data,"realActivity"));row.origActivity=component(text(data,"origActivity"));
            row.token=new WindowContainerToken(token(data.getJSONObject("token_binder")));row.launchCookies=new ArrayList<IBinder>();
            JSONArray cookies=data.getJSONArray("launch_cookies");for(int i=0;i<cookies.length();i++)row.launchCookies.add(token(cookies.getJSONObject(i)));
            if(!data.isNull("topActivityInfo")){
                JSONObject info=data.getJSONObject("topActivityInfo");ActivityInfo value=new ActivityInfo();
                value.packageName=text(info,"packageName");value.name=text(info,"name");value.targetActivity=text(info,"targetActivity");
                if(info.getBoolean("applicationInfo_present")){
                    ApplicationInfo app=new ApplicationInfo();app.packageName=text(info,"applicationInfo_packageName");app.uid=info.getInt("applicationInfo_uid");value.applicationInfo=app;
                }
                row.topActivityInfo=value;
            }
            if(data.has("childTaskIds")){
                JSONArray ids=data.getJSONArray("childTaskIds");row.childTaskIds=new int[ids.length()];for(int i=0;i<ids.length();i++)row.childTaskIds[i]=ids.getInt(i);
            }else row.childTaskIds=new int[]{row.taskId};
            return row;
        }
        @Override public Object getAllRootTaskInfos(){return new ArrayList<RootTaskInfo>(roots);}
        @Override public Object getTasks(int max,boolean visible,boolean extras,int display){
            check(max==2049&&!visible&&extras&&display==-1);return new ArrayList<RootTaskInfo>(running);
        }
        @Override public IWindowOrganizerController getWindowOrganizerController(){return new IWindowOrganizerController(){
            public void applyTransaction(WindowContainerTransaction value){effects++;throw new AssertionError("read-only census has no effect");}
            public ITaskOrganizerController getTaskOrganizerController(){return new ITaskOrganizerController(){
                public Object getRootTasks(int display,int[] types){check(display==7&&types==null);return Collections.emptyList();}
                public Object getChildTasks(WindowContainerToken parent,int[] types){
                    childQueries++;check(types==null&&parent.asBinder()==rootById.get(3).token.asBinder());return new ArrayList<RootTaskInfo>(children);
                }
                public void createRootTask(int display,int mode,IBinder cookie,boolean top){effects++;throw new AssertionError("no creation");}
                public boolean deleteRootTask(WindowContainerToken value){effects++;throw new AssertionError("no root deletion");}
            };}
        };}
        @SuppressWarnings("unchecked")
        Map<Integer,BackgroundOwnedSingleTask.Task> census()throws Exception{
            NotesTokenRetirementHostTest.World environment=new NotesTokenRetirementHostTest.World(0);
            PublicPersonalNotesReader reader=new PublicPersonalNotesReader(environment.context,this,7,()->environment.deadline);
            adapter=new PublicPersonalNotesRetirementAdapter(environment.context,this,new Object(),environment.displays,reader,
                    new PublicOwnGroupFramework(),7,"fixture-owned",NotesTokenRetirementHostTest.UID,environment.deadline,()->{});
            expected=BackgroundTaskOrganizer.profileSnapshot(this);
            Method method=PublicPersonalNotesRetirementAdapter.class.getDeclaredMethod("actualTasks",ProfileTaskPolicy.Snapshot.class);
            method.setAccessible(true);
            return (Map<Integer,BackgroundOwnedSingleTask.Task>)method.invoke(adapter,expected);
        }
        String recents(){
            StringBuilder out=new StringBuilder("ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\nmRecentsUid=1000\nmRecentsComponent=ComponentInfo{com.example.recents/.Main}\nmFreezeTaskListReordering=false\nmFreezeTaskListReorderingPendingTimeout=false\n  Recent tasks:\n");
            int index=0;for(RootTaskInfo row:running){
                String pkg=row.baseIntent.getComponent().getPackageName();
                out.append(PublicPhysicalAuditHostTest.row(index++,row.taskId,row.userId,row.effectiveUid,row.displayId,Integer.toHexString(row.taskId),pkg)
                        .replace("    lastDisplayId=","    lastActiveTime=2000 (inactive for 0s)\n    lastDisplayId="));
            }
            out.append("  Visible recent tasks (most recent first):\n");index=0;
            for(RootTaskInfo row:running)out.append(PublicPhysicalAuditHostTest.visible(index++,row.taskId,row.userId,row.displayId,row.baseIntent.getComponent().getPackageName()));
            return out.toString();
        }
        PublicPersonalNotesRetirement.Sample sample(Map<Integer,BackgroundOwnedSingleTask.Task> actual){
            long begin=SystemClock.elapsedRealtime();BackgroundOwnedSingleTask.Task own=actual.get(1909);check(own!=null);
            PublicPersonalNotesCustody.Frame frame=new PublicPersonalNotesCustody.Frame(expected,
                    Collections.singletonList(new PublicPersonalNotesCustody.Node(own,Collections.emptyList())),begin+1,begin+2);
            Map<Integer,String> physical=new LinkedHashMap<Integer,String>();physical.put(0,NotesTokenRetirementHostTest.SHA);physical.put(1,NotesTokenRetirementHostTest.SHA);
            return new PublicPersonalNotesRetirement.Sample(frame,recents(),actual,physical,begin,begin+3,574,NotesTokenRetirementHostTest.UID);
        }
    }
    private static void rejected(Port port,String code)throws Exception{refuses(code,port::census);check(port.effects==0);}
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("one recorded-field fixture required");
        fixture=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        check("hepta.notes-taskinfo-recorded-fields.v1".equals(fixture.getString("schema"))&&fixture.getJSONArray("rows").length()==13);
        test("actual13 fields preserve both alias forms and ordinary missing parent",()->{
            Port p=new Port();RootTaskInfo root=p.rootById.get(1),leaf=p.leafById.get(1095);
            check(root.topActivity.getClassName().equals(root.topActivityInfo.name));
            check(!leaf.topActivity.getClassName().equals(leaf.topActivityInfo.name)&&leaf.topActivity.getClassName().equals(leaf.topActivityInfo.targetActivity));
            Map<Integer,BackgroundOwnedSingleTask.Task> actual=p.census();p.sample(actual);
            check(actual.size()==10&&p.childQueries==1&&p.effects==0);
            check(actual.get(1095).parent==-1&&actual.get(1094).parent==-1&&actual.get(1).uid==0&&actual.get(1093).uid==0);
            check(actual.get(4).parent==3&&actual.get(5).parent==3&&actual.get(4).activities==0&&actual.get(5).activities==0);
            check(actual.get(1909).display==574&&actual.get(1909).uid==10382);
        });
        test("alias missing target cannot explain the running component",()->{Port p=new Port();p.leafById.get(1095).topActivityInfo.targetActivity=null;rejected(p,"TOP_IDENTITY");});
        test("alias empty target refused",()->{Port p=new Port();p.leafById.get(1095).topActivityInfo.targetActivity="";rejected(p,"TOP_IDENTITY");});
        test("alias wrong target refused",()->{Port p=new Port();p.leafById.get(1095).topActivityInfo.targetActivity="com.example.Wrong";rejected(p,"TOP_IDENTITY");});
        test("alias application package mismatch refused",()->{Port p=new Port();p.leafById.get(1095).topActivityInfo.applicationInfo.packageName="com.example.foreign";rejected(p,"TOP_IDENTITY");});
        test("alias cross package component refused",()->{Port p=new Port();p.leafById.get(1095).topActivity=component("com.example.other/com.android.launcher3.uioverrides.QuickstepLauncher");rejected(p,"TOP_IDENTITY");});
        test("nonempty top without ActivityInfo remains unknown",()->{Port p=new Port();p.leafById.get(1095).topActivityInfo=null;rejected(p,"TOP_UID_MISSING");});
        test("ambiguous complete root membership refused",()->{Port p=new Port();RootTaskInfo r=p.rootById.get(1093);r.childTaskIds=new int[]{1095};rejected(p,"GLOBAL_LEAF_DUPLICATE");});
        test("ordinary leaf crossing display refused",()->{Port p=new Port();p.leafById.get(1095).displayId=1;rejected(p,"ORDINARY_FOREIGN_IDENTITY");});
        test("ordinary leaf crossing user refused",()->{Port p=new Port();p.leafById.get(1095).userId=10;rejected(p,"ORDINARY_FOREIGN_IDENTITY");});
        test("ordinary leaf with Notes effective UID refused",()->{Port p=new Port();p.leafById.get(1095).effectiveUid=10382;rejected(p,"ORDINARY_FOREIGN_IDENTITY");});
        test("ordinary leaf with Notes top UID refused",()->{Port p=new Port();p.leafById.get(1095).topActivityInfo.applicationInfo.uid=10382;rejected(p,"ORDINARY_FOREIGN_IDENTITY");});
        test("ordinary root with Notes effective UID refused",()->{Port p=new Port();p.rootById.get(1).effectiveUid=10382;rejected(p,"ORDINARY_FOREIGN_IDENTITY");});
        test("ordinary root and leaf cannot reuse one Binder",()->{Port p=new Port();p.leafById.get(1095).token=p.rootById.get(1).token;rejected(p,"ORDINARY_FOREIGN_IDENTITY");});
        test("ordinary membership cannot admit owned display",()->{
            Port p=new Port();p.rootById.get(1).displayId=7;p.leafById.get(1095).displayId=7;
            rejected(p,"ORDINARY_FOREIGN_IDENTITY");
        });
        test("missing organizer child never becomes guessed empty UID",()->{Port p=new Port();p.children.remove(0);rejected(p,"CHILD_CENSUS_INCOMPLETE");});
        test("actual empty organizer child changed parent refused",()->{Port p=new Port();p.children.get(0).parentTaskId=1;rejected(p,"CHILD_PARENT_CHANGED");});
        test("duplicate actual token outside ordinary pair refused by sample",()->{
            Port p=new Port();p.leafById.get(1094).token=p.leafById.get(1095).token;
            Map<Integer,BackgroundOwnedSingleTask.Task> actual=p.census();refuses("ACTUAL_TASK_INVALID",()->p.sample(actual));check(p.effects==0);
        });
        JSONObject report=new JSONObject().put("schema","hepta.notes-taskinfo-semantics-host.v1").put("all_pass",true)
                .put("cases",cases).put("assertions",assertions).put("case_names",names).put("recorded_field_rows",13)
                .put("actual_alias_and_parent_values_used",true).put("raw_parent_values_preserved",true)
                .put("binder_pm_clock_root_child_projection_and_history_io_synthetic",true)
                .put("phone_operations",0).put("hardware_qualification_claimed",false).put("cleanup_authority_claimed",false);
        System.out.println(report.toString());
    }
}
