package org.trillionnium.hepta.background;

import android.app.ActivityTaskManager.RootTaskInfo;
import android.app.IActivityTaskManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.hardware.display.DisplayManager;
import android.os.Binder;
import android.os.IBinder;
import android.os.SystemClock;
import android.window.ITaskOrganizerController;
import android.window.IWindowOrganizerController;
import android.window.WindowContainerToken;
import android.window.WindowContainerTransaction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.json.JSONObject;

/** Complete new production coordinator and WCT adapter, actual existing reader
 * and strict parsers. Android Binder/PM/clock/dump IO below is authored, inert
 * host data. No success here is a phone cleanup or hardware qualification. */
public final class NotesTokenRetirementHostTest {
    static final String PKG="com.motorola.stylus",COMP=PKG+"/"+PKG+".Main";
    static final String GEN="11111111-1111-4111-8111-111111111111",SHA=String.join("",Collections.nCopies(64,"a"));
    static final int UID=10382;
    public static World current;
    private static int cases,checks;
    private static final List<String> names=new ArrayList<String>();
    interface Work {void run()throws Exception;}
    static void yes(boolean value){checks++;if(!value)throw new AssertionError("Notes token retirement boundary");}
    static String cause(Throwable t){while(t.getCause()!=null)t=t.getCause();return String.valueOf(t.getMessage());}
    static void refuses(String code,Work work)throws Exception{try{work.run();}catch(Exception expected){
        yes(code==null||cause(expected).contains(code));return;}throw new AssertionError("unproved token effect accepted: "+code);}
    static void test(String name,Work work)throws Exception{work.run();cases++;names.add(name);System.out.println("PASS "+name);}
    static ComponentName component(String value){return ComponentName.unflattenFromString(value);}

    public static final class World implements IActivityTaskManager {
        public final Context context=new Context();
        public final DisplayManager displays=new DisplayManager();
        final LinkedHashMap<Integer,RootTaskInfo> live=new LinkedHashMap<Integer,RootTaskInfo>(),recent=new LinkedHashMap<Integer,RootTaskInfo>();
        final List<Integer> effects=new ArrayList<Integer>();
        final Map<Integer,IBinder> originals=new LinkedHashMap<Integer,IBinder>();
        final PublicPersonalNotesCustody custody;
        final PublicPersonalNotesReader reader;
        final PublicPersonalNotesRetirementAdapter adapter;
        PublicPersonalNotesRetirement retirement;
        int calls,handleChecks,forbidden,actualReads,deadlineAdvance,childQueries;
        boolean throwBefore,throwAfter,pending,originalHandle=true,missingRunningLeaf,skipRoot;
        String physicalSuffix="",historySuffix="",hiddenPrefix="";
        int focusedTask=100,physicalEpoch=2000;
        java.util.function.UnaryOperator<String> recentTransform;
        Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> deviceFacts=PublicPhysicalAuditHostTest.displays();
        final java.util.Set<Integer> ordinaryNestedLeaves=new java.util.LinkedHashSet<Integer>();
        Consumer<World> beforeEffect,beforeRootRead,beforeRunningRead,afterEffect;
        PublicPersonalNotesRetirement.Effect observedEffect;
        boolean nullChildren;
        long deadline;
        final ITaskOrganizerController organizer=new ITaskOrganizerController(){
            public Object getRootTasks(int display,int[] types){yes(display==7&&types==null);List<RootTaskInfo> rows=new ArrayList<RootTaskInfo>();
                for(RootTaskInfo row:live.values())if(row.displayId==7)rows.add(row);return rows;}
            public Object getChildTasks(WindowContainerToken token,int[] types){childQueries++;yes(types==null);
                if(nullChildren)return null;
                // Actual AOSP contract: only this authored organizer-created
                // foreign parent is readable. The ordinary Notes roots refuse.
                RootTaskInfo parent=null;for(int id:new int[]{3,4,5}){RootTaskInfo row=live.get(id);if(row!=null&&row.token.asBinder()==token.asBinder())parent=row;}
                if(parent==null)return null;
                List<RootTaskInfo> rows=new ArrayList<RootTaskInfo>();for(RootTaskInfo row:live.values())if(row.parentTaskId==parent.taskId)rows.add(row);return rows;}
            public void createRootTask(int display,int mode,IBinder cookie,boolean top){forbidden++;throw new AssertionError("no create");}
            public boolean deleteRootTask(WindowContainerToken token){forbidden++;throw new AssertionError("no root delete");}
        };
        final IWindowOrganizerController controller=new IWindowOrganizerController(){
            public ITaskOrganizerController getTaskOrganizerController(){return organizer;}
            public void applyTransaction(WindowContainerTransaction transaction){
                calls++;yes(transaction.selected!=null);Integer selected=null;
                for(Map.Entry<Integer,IBinder> row:originals.entrySet())if(row.getValue()==transaction.selected.asBinder())selected=row.getKey();
                yes(selected!=null&&selected>=300&&live.containsKey(selected)&&!effects.contains(selected));effects.add(selected);
                if(throwBefore)throw new IllegalStateException("fixture Binder before-effect ambiguity");
                if(!pending){live.remove(selected);recent.remove(selected);}
                if(deadlineAdvance>0)SystemClock.now+=deadlineAdvance;
                if(afterEffect!=null)afterEffect.accept(World.this);
                if(throwAfter)throw new IllegalStateException("fixture Binder after-effect ambiguity");
            }
        };
        World(int count)throws Exception{this(count,null);}
        World(int count,Consumer<World> initial)throws Exception{
            current=this;SystemClock.now=10000;SystemClock.step=1;
            ApplicationInfo app=new ApplicationInfo();app.uid=UID;app.enabled=true;app.packageName=PKG;app.sourceDir="/fixture/notes.apk";context.pm.installed=app;
            add(100,0,10367,"ctrip.android.view/ctrip.android.view.Main");add(101,1,10368,"com.example.cover/com.example.cover.Main");
            if(initial!=null)initial.accept(this);
            custody=new PublicPersonalNotesCustody(GEN,SHA,UID,BackgroundTaskOrganizer.profileSnapshot(this),PublicOwnGroupPhysicalFence.inspectRecents(recents()));
            custody.beforeCreate();custody.bindDisplay(7);custody.markLaunch();
            for(int i=0;i<count;i++)add(300+i,7,UID,COMP);
            deadline=SystemClock.now+1400;
            reader=new PublicPersonalNotesReader(context,this,7,()->deadline);
            custody.observe(reader.frame(),SystemClock.elapsedRealtime());custody.retireAdmission();
            adapter=new PublicPersonalNotesRetirementAdapter(context,this,new Object(),displays,reader,new PublicOwnGroupFramework(),
                    7,"fixture-owned",UID,deadline,()->{handleChecks++;if(!originalHandle)throw new IllegalStateException("original handle changed");});
        }
        void add(int id,int display,int uid,String comp){RootTaskInfo row=row(id,display,uid,comp);live.put(id,row);recent.put(id,row);originals.put(id,row.token.asBinder());}
        RootTaskInfo row(int id,int display,int uid,String comp){
            RootTaskInfo row=new RootTaskInfo();row.taskId=id;row.displayId=display;row.userId=0;row.parentTaskId=-1;row.effectiveUid=uid;row.numActivities=1;
            row.isRunning=true;row.isVisible=display!=1;row.visible=display!=1;row.baseActivity=row.topActivity=row.realActivity=component(comp);
            row.baseIntent=new Intent().setComponent(component(comp));row.token=new WindowContainerToken(new Binder());row.launchCookies=new ArrayList<IBinder>();
            ActivityInfo info=new ActivityInfo();info.packageName=component(comp).getPackageName();info.name=component(comp).getClassName();
            ApplicationInfo app=new ApplicationInfo();app.packageName=info.packageName;app.uid=uid;app.sourceDir="/fixture/app.apk";app.enabled=true;info.applicationInfo=app;row.topActivityInfo=info;
            row.childTaskIds=new int[]{id};row.childTaskUserIds=new int[]{0};row.childTaskNames=new String[]{comp};row.childTaskBounds=new android.graphics.Rect[]{new android.graphics.Rect(0,0,100,100)};return row;
        }
        @Override public Object getAllRootTaskInfos(){actualReads++;if(beforeRootRead!=null)beforeRootRead.accept(this);List<RootTaskInfo> rows=new ArrayList<RootTaskInfo>();for(RootTaskInfo row:live.values())if(row.parentTaskId<0&&!ordinaryNestedLeaves.contains(row.taskId))rows.add(row);if(skipRoot&&!rows.isEmpty())rows.remove(rows.size()-1);return rows;}
        @Override public Object getTasks(int max,boolean visible,boolean extras,int display){
            if(beforeRunningRead!=null)beforeRunningRead.accept(this);
            yes(max==2049&&!visible&&extras&&display==-1);List<RootTaskInfo> rows=new ArrayList<RootTaskInfo>();
            for(RootTaskInfo row:live.values())if(row.numActivities>0&&row.childTaskIds.length==1&&row.childTaskIds[0]==row.taskId&&!(missingRunningLeaf&&row.taskId==100))rows.add(row);return rows;
        }
        @Override public IWindowOrganizerController getWindowOrganizerController(){return controller;}
        String recents(){
            StringBuilder out=new StringBuilder("ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\nmRecentsUid=1000\nmRecentsComponent=ComponentInfo{com.example.recents/.Main}\nmFreezeTaskListReordering=false\nmFreezeTaskListReorderingPendingTimeout=false\n"+hiddenPrefix+"  Recent tasks:\n");int index=0;
            for(RootTaskInfo row:recent.values()){
                String pkg=row.baseIntent.getComponent().getPackageName();String raw=PublicPhysicalAuditHostTest.row(index++,row.taskId,0,row.effectiveUid,row.displayId,Integer.toHexString(row.taskId),pkg);
                int epoch=row.displayId==0||row.displayId==1?physicalEpoch:2000;
                raw=raw.replace("    lastDisplayId=","    lastActiveTime="+epoch+" (inactive for 0s)\n    lastDisplayId=");out.append(raw);
            }
            out.append("  Visible recent tasks (most recent first):\n");index=0;
            for(RootTaskInfo row:recent.values())out.append(PublicPhysicalAuditHostTest.visible(index++,row.taskId,0,row.displayId,row.baseIntent.getComponent().getPackageName())
                    .replace("lastActiveTime=2000","lastActiveTime="+(row.displayId==0||row.displayId==1?physicalEpoch:2000)));
            String raw=out.toString()+historySuffix;return recentTransform==null?raw:recentTransform.apply(raw);
        }
        String activities(){StringBuilder text=new StringBuilder("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n");
            for(int display:new int[]{0,1,7}){text.append("Display #").append(display).append(" (activities from top to bottom):\n");
                for(RootTaskInfo row:live.values())if(row.displayId==display&&row.parentTaskId<0&&!ordinaryNestedLeaves.contains(row.taskId))appendTask(text,row,1);}
            text.append("\nActivityTaskSupervisor state:\n  SleepTokens=[]\n");return text.toString();}
        void appendTask(StringBuilder text,RootTaskInfo row,int depth){String token=Integer.toHexString(row.taskId),indent=String.join("",Collections.nCopies(depth*2," "));
            text.append(indent).append("* Task{").append(token).append(" #").append(row.taskId).append(" type=standard U=0 visible=true sz=1}\n");
            if(row.numActivities>0&&row.childTaskIds.length==1&&row.childTaskIds[0]==row.taskId)text.append(indent).append("  * Hist #0: ActivityRecord{").append(token).append("a u0 ")
                    .append(row.baseIntent.getComponent().getPackageName()).append('/').append(row.baseIntent.getComponent().getClassName()).append(" t").append(row.taskId).append("}\n");
            for(RootTaskInfo child:live.values())if(child.parentTaskId==row.taskId
                    ||child.taskId!=row.taskId&&ordinaryNestedLeaves.contains(child.taskId)&&java.util.Arrays.stream(row.childTaskIds).anyMatch(id->id==child.taskId))
                appendTask(text,child,depth+1);
        }
        String windows(){
            RootTaskInfo row=live.get(focusedTask);if(row==null)throw new AssertionError("synthetic focused task missing");
            String component=row.baseIntent.getComponent().getPackageName()+"/"+row.baseIntent.getComponent().getClassName();
            return "WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)\n  Display: mDisplayId=0 (ownFocus=false)\n"
                +"  mCurrentFocus=Window{ad u0 "+component+"}\n  mFocusedApp=ActivityRecord{"+Integer.toHexString(row.taskId)+"a u0 "+component+" t"+row.taskId+"}\n"
                +"  mImeInputTarget="+(physicalSuffix.isEmpty()?"null":physicalSuffix)+"\n  Display: mDisplayId=1 (ownFocus=false)\n  mCurrentFocus=null\n  mFocusedApp=null\n";
        }
        void run()throws Exception{
            PublicPersonalNotesRetirement.Port port=new PublicPersonalNotesRetirement.Port(){
                public PublicPersonalNotesRetirement.Sample read()throws Exception{return adapter.read();}
                public PublicPersonalNotesRetirement.Sample readAfter(PublicPersonalNotesRetirement.Effect effect)throws Exception{return adapter.readAfter(effect);}
                public long now(){return adapter.now();}public void awaitRead()throws Exception{adapter.awaitRead();}
                public void remove(PublicPersonalNotesRetirement.Effect effect)throws Exception{observedEffect=effect;if(beforeEffect!=null)beforeEffect.accept(World.this);adapter.remove(effect);}
            };
            retirement=new PublicPersonalNotesRetirement(custody,port,deadline);retirement.retire();yes(forbidden==0);
        }
        JSONObject evidence(){return new JSONObject(custody.evidence()).getJSONObject("token_retirement");}
        void nestedEmptyShell(){
            RootTaskInfo root=row(3,0,0,"com.android.shell/com.android.shell.Empty");empty(root);
            root.childTaskIds=new int[]{5,4};root.childTaskUserIds=new int[]{0,0};root.childTaskNames=new String[]{"unknown","unknown"};
            root.childTaskBounds=new android.graphics.Rect[]{new android.graphics.Rect(0,0,100,100),new android.graphics.Rect(0,0,100,100)};
            live.put(3,root);originals.put(3,root.token.asBinder());
            for(int id:new int[]{5,4}){RootTaskInfo child=row(id,0,0,"com.android.shell/com.android.shell.Empty");empty(child);child.parentTaskId=3;
                live.put(id,child);originals.put(id,child.token.asBinder());}
        }
        void empty(RootTaskInfo row){row.numActivities=0;row.isRunning=false;row.isVisible=false;row.visible=false;row.baseActivity=null;row.topActivity=null;row.topActivityInfo=null;row.childTaskNames=new String[]{"unknown"};}
        void nestedRunningShell(){nestedEmptyShell();RootTaskInfo root=live.get(3);root.childTaskIds=new int[]{6,7};
            root.childTaskNames=new String[]{"com.example.foreign/com.example.foreign.Main","com.example.foreign/com.example.foreign.Main"};
            root.numActivities=2;
            for(int i=0;i<2;i++){RootTaskInfo row=row(6+i,0,11000+i,"com.example.foreign/com.example.foreign.Main");row.parentTaskId=4+i;live.put(row.taskId,row);originals.put(row.taskId,row.token.asBinder());
                RootTaskInfo parent=live.get(4+i);parent.numActivities=1;parent.childTaskIds=new int[]{row.taskId};parent.childTaskNames=new String[]{"com.example.foreign/com.example.foreign.Main"};}
        }
        void released()throws Exception{
            retirement.beforeRelease(adapter.now());custody.enterRelease(adapter.now());custody.releaseReturned();
            for(int i=0;i<2;i++){
                PublicPersonalNotesRetirement.Sample sample=adapter.readReleased(custody.releasedRead());retirement.afterRelease(sample,adapter.now());
                custody.observeAbsence(sample.frame.global,sample.recents,true,sample.begin,sample.end,adapter.now());
            }
        }
    }
    public static Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> facts(){return current.deviceFacts;}
    public static String dump(String[] args){if(args.length!=2||!"-a".equals(args[0]))throw new AssertionError("fixed dump args");
        if("activities".equals(args[1]))return current.activities();if("displays".equals(args[1]))return current.windows();
        if("recents".equals(args[1]))return current.recents();throw new AssertionError("unknown dump");}
    /** Authored prelaunch control for the actual detached-current fixture only.
     * Original input bytes are never edited. All foreign row bodies survive. */
    static String withoutSelectedRecent(String raw,int selected){
        String internal="  Recent tasks:\n",visible="  Visible recent tasks (most recent first):\n";
        int begin=raw.indexOf(internal),end=raw.indexOf(visible);String rows=raw.substring(begin+internal.length(),end);
        java.util.regex.Pattern pattern=java.util.regex.Pattern.compile("(?m)^  \\* Recent #([0-9]+): (Task\\{[0-9a-f]+ #([0-9]+) [^{}\\r\\n]+\\})$");
        List<java.util.regex.Matcher> heads=new ArrayList<java.util.regex.Matcher>();java.util.regex.Matcher scan=pattern.matcher(rows);
        while(scan.find()){java.util.regex.Matcher saved=pattern.matcher(rows);yes(saved.find(scan.start()));heads.add(saved);}
        StringBuilder out=new StringBuilder(raw.substring(0,begin+internal.length()));int index=0;
        for(int i=0;i<heads.size();i++){java.util.regex.Matcher h=heads.get(i);if(Integer.parseInt(h.group(3))!=selected)
            out.append("  * Recent #").append(index++).append(": ").append(h.group(2)).append(rows.substring(h.end(),i+1<heads.size()?heads.get(i+1).start():rows.length()));}
        out.append(visible);String vis=raw.substring(end+visible.length());heads=PublicOwnGroupPhysicalFence.visibleRecentHeaders(vis);index=0;
        for(int i=0;i<heads.size();i++){java.util.regex.Matcher h=heads.get(i);String body=vis.substring(h.end(),i+1<heads.size()?heads.get(i+1).start():vis.length());
            java.util.regex.Matcher id=java.util.regex.Pattern.compile("(?m)^    id=([0-9]+) userId=").matcher(body);yes(id.find());
            if(Integer.parseInt(id.group(1))!=selected)out.append("  * RecentTaskInfo #").append(index++).append(':').append(body);}
        PublicOwnGroupPhysicalFence.RecentCensus parsed=PublicOwnGroupPhysicalFence.inspectRecents(out.toString());yes(!parsed.allIds.contains(selected));return out.toString();
    }
    public static void main(String[] args)throws Exception{
        test("two actual attached root-leaf wrappers retire once before release",()->{World w=new World(2);w.run();
            yes(w.effects.equals(Arrays.asList(300,301))&&w.evidence().getInt("pre_release_absence_reads")==2&&!w.custody.known());
            w.released();yes(w.custody.known()&&w.calls==2);refuses(null,w.custody::enterRelease);});
        test("zero attached members still require both pre and post release absences",()->{World w=new World(0);w.run();yes(w.calls==0);w.released();yes(w.custody.known());});
        test("actual empty ordinary root fills RunningTasks deliberate omission",()->{World w=new World(1);RootTaskInfo row=w.live.get(300);
            row.numActivities=0;row.isRunning=false;row.isVisible=false;row.visible=false;row.baseActivity=null;row.topActivity=null;row.topActivityInfo=null;
            w.run();yes(w.calls==1);w.released();yes(w.custody.known());});
        test("observed shell root3 empty leaves5and4 are read without authority",()->{World w=new World(2);w.nestedEmptyShell();w.run();
            yes(w.childQueries>0&&w.effects.equals(Arrays.asList(300,301))&&w.live.containsKey(3)&&w.live.containsKey(4)&&w.live.containsKey(5));w.released();yes(w.custody.known());});
        test("all running leaves still require actual intermediate organizer ancestors",()->{World w=new World(1);w.nestedRunningShell();w.run();
            yes(w.childQueries>=3&&w.calls==1&&w.live.containsKey(4)&&w.live.containsKey(5)&&w.live.containsKey(6)&&w.live.containsKey(7));w.released();yes(w.custody.known());});
        test("null organizer child query never invents empty-leaf UID",()->{World w=new World(1);w.nestedEmptyShell();w.nullChildren=true;refuses(null,w::run);yes(w.calls==0);});
        test("nested empty same UID leaf refuses before any effect",()->{World w=new World(1);w.nestedEmptyShell();w.live.get(4).effectiveUid=UID;refuses(null,w::run);yes(w.calls==0);});
        test("changed nested empty ancestor remains foreign identity",()->{World w=new World(1);w.nestedEmptyShell();w.beforeEffect=x->x.live.get(4).parentTaskId=100;refuses(null,w::run);yes(w.calls==0);});
        test("detached recent-only member forbids token and VD effect",()->{World w=new World(1);w.live.remove(300);refuses("DETACHED",w::run);yes(w.calls==0);refuses(null,w.custody::enterRelease);});
        test("foreign same effective UID has no token authority",()->{World w=new World(1);w.add(500,9,UID,"com.example.foreign/com.example.foreign.Main");refuses(null,w::run);yes(w.calls==0);});
        test("foreign top activity sharing Notes UID also refuses",()->{World w=new World(1);w.live.get(100).topActivityInfo.applicationInfo.uid=UID;refuses(null,w::run);yes(w.calls==0);});
        test("changed original Binder is rejected before WCT",()->{World w=new World(1);w.beforeEffect=x->x.live.get(300).token=new WindowContainerToken(new Binder());refuses(null,w::run);yes(w.calls==0);});
        test("changed original cookies are rejected before WCT",()->{World w=new World(1);w.beforeEffect=x->x.live.get(300).launchCookies.add(new Binder());refuses(null,w::run);yes(w.calls==0);});
        test("non-leaf root with a child never reaches broad REMOVE_TASK",()->{World w=new World(1);w.live.get(300).childTaskIds=new int[]{302};refuses(null,w::run);yes(w.calls==0&&w.forbidden==0);});
        test("owned root moved onto main refuses",()->{World w=new World(1);w.beforeEffect=x->x.live.get(300).displayId=0;refuses(null,w::run);yes(w.calls==0);});
        test("unrelated physical IME change permits original token dispatch",()->{World w=new World(1);w.beforeEffect=x->x.physicalSuffix="Window{ae u0 input}";w.run();w.released();yes(w.calls==1&&w.custody.known());});
        test("foreign complete recent body change blocks final dispatch",()->{World w=new World(1);w.beforeEffect=x->x.historySuffix="foreign tail changed\n";refuses(null,w::run);yes(w.calls==0);});
        test("owned handle replacement blocks final dispatch",()->{World w=new World(1);w.beforeEffect=x->x.originalHandle=false;refuses(null,w::run);yes(w.calls==0);});
        test("late final sample consumes no new effect",()->{World w=new World(1);w.beforeEffect=x->SystemClock.now=x.deadline;refuses(null,w::run);yes(w.calls==0);});
        test("PM shared UID forbids possible process cleanup",()->{World w=new World(1);w.beforeEffect=x->x.context.pm.aliases=new String[]{PKG,"com.example.shared"};refuses("SHARED_UID",w::run);yes(w.calls==0);});
        test("Binder before-effect throw consumes token and retains unknown",()->{World w=new World(1);w.throwBefore=true;refuses(null,w::run);
            yes(w.calls==1&&w.evidence().getJSONArray("attempted_task_ids").length()==1&&w.evidence().getJSONArray("returned_task_ids").length()==0);
            refuses(null,w.retirement::retire);refuses(null,w.custody::enterRelease);yes(!w.custody.known()&&w.live.containsKey(300));});
        test("Binder after-effect throw cannot become historical cleanup success",()->{World w=new World(1);w.throwAfter=true;refuses(null,w::run);
            yes(w.calls==1&&!w.live.containsKey(300)&&!w.custody.known());refuses(null,w.retirement::retire);refuses(null,w.custody::enterRelease);});
        test("successful return with residual task consumes once and retains VD",()->{World w=new World(1);w.pending=true;refuses(null,w::run);
            yes(w.calls==1&&w.evidence().getJSONArray("returned_task_ids").length()==1&&!w.custody.known());refuses(null,w.custody::enterRelease);});
        test("first task gone but deadline prevents second call and release",()->{World w=new World(2);w.deadlineAdvance=2000;refuses(null,w::run);
            yes(w.calls==1&&!w.live.containsKey(300)&&w.live.containsKey(301));refuses(null,w.custody::enterRelease);});
        test("retirement reentry never resets once bits",()->{World w=new World(1);w.run();refuses(null,w.retirement::retire);
            refuses(null,()->w.custody.prepareTokenRetirement(w.reader.frame(),PublicOwnGroupPhysicalFence.inspectRecents(w.recents()),w.adapter.now(),w.deadline));yes(w.calls==1);});
        test("ready plan cannot release after original cleanup deadline",()->{World w=new World(1);w.run();SystemClock.now=w.deadline;
            refuses(null,()->w.retirement.beforeRelease(w.adapter.now()));refuses(null,()->w.custody.enterRelease(w.adapter.now()));
            refuses(null,w.custody::enterRelease);yes(!w.custody.known()&&!new JSONObject(w.custody.evidence()).getBoolean("release_api_entered"));});
        test("post-release unrelated physical IME change preserves cleanup",()->{World w=new World(1);w.run();w.physicalSuffix="Window{ae u0 input}";w.released();yes(w.custody.known());});
        test("display absence includes disabled logical displays",()->{
            android.hardware.display.IDisplayManager.currentIds=new int[]{0,1,7};yes(!PublicPersonalNotesRetirementAdapter.displayAbsent(7,"fixture-owned"));
            android.hardware.display.IDisplayManager.currentIds=new int[]{0,1};yes(PublicPersonalNotesRetirementAdapter.displayAbsent(7,"fixture-owned"));});
        if(args.length==1)test("actual50af detached recent requires maintenance without WCT",()->{
            String raw=new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8);
            PublicOwnGroupPhysicalFence.RecentCensus recents=PublicOwnGroupPhysicalFence.inspectRecents(raw);
            yes(recents.records.containsKey(1903)&&recents.records.get(1903).uid==UID&&recents.records.get(1903).display==568);
            World w=new World(0);PublicPersonalNotesCustody c=new PublicPersonalNotesCustody(GEN,SHA,UID,BackgroundTaskOrganizer.profileSnapshot(w),
                    PublicOwnGroupPhysicalFence.inspectRecents(withoutSelectedRecent(raw,1903)));c.beforeCreate();c.bindDisplay(568);c.markLaunch();
            BackgroundOwnedSingleTask.Task task=new BackgroundOwnedSingleTask.Task(1903,568,0,-1,UID,UID,1,new Binder(),Collections.emptyList(),COMP,COMP,COMP,COMP,null,true,true);
            ProfileTaskPolicy.Root root=new ProfileTaskPolicy.Root(1903,568,0,1,true,COMP,COMP,new int[]{1903},new int[]{0},new String[]{COMP},new int[][]{{0,0,100,100}});
            List<ProfileTaskPolicy.Root> roots=new ArrayList<ProfileTaskPolicy.Root>(BackgroundTaskOrganizer.profileSnapshot(w).roots);roots.add(root);
            long begin=SystemClock.elapsedRealtime();c.observe(new PublicPersonalNotesCustody.Frame(new ProfileTaskPolicy.Snapshot(roots),
                    Collections.singletonList(new PublicPersonalNotesCustody.Node(task,Collections.emptyList())),begin,begin+1),begin+1);c.retireAdmission();
            long t=begin+3;PublicPersonalNotesCustody.Frame absent=new PublicPersonalNotesCustody.Frame(BackgroundTaskOrganizer.profileSnapshot(w),Collections.emptyList(),t,t+1);
            refuses("DETACHED",()->c.prepareTokenRetirement(absent,recents,t+1,t+1000));yes(w.calls==0);refuses(null,c::enterRelease);
        });
        JSONObject report=new JSONObject().put("schema","hepta.notes-token-retirement-host.v1").put("all_pass",true).put("cases",cases).put("assertions",checks)
                .put("case_names",names).put("phone_operations",0).put("framework_io_synthetic",true).put("new_production_bodies_executed",true)
                .put("physical_dump_io_and_display_handle_ports_synthetic",true).put("hardware_qualification_claimed",false);
        System.out.println(report.toString());
    }
}
