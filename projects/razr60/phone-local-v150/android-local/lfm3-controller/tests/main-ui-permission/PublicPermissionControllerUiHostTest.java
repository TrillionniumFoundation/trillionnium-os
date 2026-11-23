package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import android.app.ActivityTaskManager;
import android.app.IActivityTaskManager;
import android.app.TaskInfo;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.os.Binder;
import android.os.IBinder;
import android.window.IWindowOrganizerController;
import android.window.ITaskOrganizerController;
import android.window.WindowContainerToken;
import android.window.WindowContainerTransaction;

/** Complete production policy/parser/read-only reflection with inert framework
 * records. This is host regression, never Android/phone qualification. */
public final class PublicPermissionControllerUiHostTest {
    private static int cases,assertions,mutations;
    private static final List<String> names=new ArrayList<String>();
    private static final String C=PublicPermissionControllerUi.COMPONENT,P="org.trillionnium.hepta.local";
    private static final String OWNER=ProfileIdentity.sha("owner"),SCOPE=ProfileIdentity.sha("scope");
    private static final String GEN="12345678-1234-4234-8234-123456789abc";
    interface Work {void run()throws Exception;}
    static void yes(boolean b,String m){assertions++;if(!b)throw new AssertionError(m);}
    static void test(String n,Work w)throws Exception{w.run();cases++;names.add(n);System.out.println("PASS "+n);}
    static void refuse(Work w)throws Exception{try{w.run();throw new AssertionError("invalid identity accepted");}
        catch(IllegalArgumentException expected){assertions++;}
        catch(java.io.IOException expected){assertions++;}
        catch(BrokerProtocol.Refusal expected){assertions++;}}
    static PublicPermissionControllerUi.Locator locator(){return PublicPermissionControllerUi.fromMainActivityButton(10481,2020,100,0,9900,OWNER);}
    static PublicPermissionControllerUi.Session session(){return new PublicPermissionControllerUi.Session(SCOPE,GEN,OWNER,10481,10,10000,100000);}
    static PublicPermissionControllerUi.Task task(Object token,int id,int display,int parent,int uid,String component){
        return new PublicPermissionControllerUi.Task(id,display,0,parent,uid,uid,1,token,component,component,component,component,null,true,true);}
    static PublicPermissionControllerUi.Bound bound(){return PublicPermissionControllerUi.bind(locator(),session(),10481,2020,task(new Object(),100,0,-1,10481,C),7,10100);}
    static String activities(){return PublicPhysicalAuditHostTest.activities()
            .replace("A=10367:ctrip.android.view U=0","A=10481:"+P+" U=0")
            .replace("{ab u0 ctrip.android.view/.Home t100}","{ab u0 "+P+"/.MainActivity t100}");}
    static String windows(){return PublicPhysicalAuditHostTest.windows()
            .replace("{ad u0 ctrip.android.view/ctrip.android.view.Home}","{ad u0 "+C+"}")
            .replace("{ab u0 ctrip.android.view/.Home t100}","{ab u0 "+P+"/.MainActivity t100}");}
    static String recents(){String old=PublicPhysicalAuditHostTest.row(0,100,0,10367,0,"aa",ProfileTarget.CTRIP);
        String fresh=PublicPhysicalAuditHostTest.row(0,100,0,10481,0,"aa",P).replace(P+"/.Main",P+"/.MainActivity");
        return PublicPhysicalAuditHostTest.recents(true).replace(old,fresh)
                .replace(PublicPhysicalAuditHostTest.visible(0,100,0,0,ProfileTarget.CTRIP),
                        PublicPhysicalAuditHostTest.visible(0,100,0,0,P).replace(P+"/.Main",P+"/.MainActivity"));}
    static Map<Integer,String> capture(PublicPermissionControllerUi.Bound b,String a,String w,String r){
        return PublicOwnGroupPhysicalFence.captureControllerInitialization(a,w,r,PublicPhysicalAuditHostTest.displays(),10,b);}
    static byte[] request(String operation,String locator){
        String json="{\"version\":"+BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION+",\"request_id\":\""+GEN+"\",\"generation\":\""+GEN
                +"\",\"deadline_elapsed_ms\":12000,\"op\":\""+operation+"\",\"package\":\""+ProfileTarget.CTRIP
                +"\",\"target_sha256\":\""+ProfileIdentity.sha("target")+"\",\"display_scope_sha256\":\""+SCOPE+"\""
                +(locator==null?"":",\"controller_ui_locator\":\""+locator+"\"")+"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }
    static ActivityTaskManager.RootTaskInfo root(int id,boolean child){
        ActivityTaskManager.RootTaskInfo r=new ActivityTaskManager.RootTaskInfo();fill(r,id,child?-1:-1);r.visible=true;
        r.childTaskIds=new int[]{child?100:id};r.childTaskUserIds=new int[]{0};r.childTaskNames=new String[]{C};
        r.childTaskBounds=new android.graphics.Rect[]{new android.graphics.Rect(0,0,1224,2992)};return r;
    }
    static void fill(TaskInfo r,int id,int parent){
        r.taskId=id;r.displayId=0;r.userId=0;r.parentTaskId=parent;r.effectiveUid=10481;r.numActivities=1;
        r.isRunning=true;r.isVisible=true;r.token=new WindowContainerToken(new Binder());r.launchCookies=new ArrayList<IBinder>();
        ComponentName c=ComponentName.unflattenFromString(C);r.baseActivity=c;r.topActivity=c;r.realActivity=c;r.origActivity=null;
        r.baseIntent=new Intent().setComponent(c);r.topActivityInfo=new ActivityInfo();r.topActivityInfo.packageName=P;
        r.topActivityInfo.name=P+".MainActivity";r.topActivityInfo.applicationInfo=new ApplicationInfo();
        r.topActivityInfo.applicationInfo.packageName=P;r.topActivityInfo.applicationInfo.uid=10481;
    }
    public static final class Platform implements IActivityTaskManager,IWindowOrganizerController,ITaskOrganizerController {
        final List<ActivityTaskManager.RootTaskInfo> roots=new ArrayList<ActivityTaskManager.RootTaskInfo>();
        final List<TaskInfo> children=new ArrayList<TaskInfo>();int reads,childReads;
        public Object getAllRootTaskInfos(){reads++;return roots;}
        public IWindowOrganizerController getWindowOrganizerController(){return this;}
        public ITaskOrganizerController getTaskOrganizerController(){return this;}
        public Object getRootTasks(int display,int[] types){throw new AssertionError("unused root lookup");}
        public Object getChildTasks(WindowContainerToken token,int[] types){childReads++;return children;}
        public void createRootTask(int display,int mode,IBinder cookie,boolean top){mutations++;throw new AssertionError("mutation");}
        public boolean deleteRootTask(WindowContainerToken token){mutations++;throw new AssertionError("mutation");}
        public void applyTransaction(WindowContainerTransaction t){mutations++;throw new AssertionError("mutation");}
    }
    public static void main(String[] args)throws Exception {
        test("original strict capture still rejects physical Hepta MainActivity",()->refuse(()->PublicOwnGroupPhysicalFence.capture(
                activities(),windows(),recents(),PublicPhysicalAuditHostTest.displays(),10)));
        test("complete MainActivity focus dump crosses typed production capture",()->{
            Map<Integer,String> v=capture(bound(),activities(),windows(),recents());yes(v.size()==2,"both physical displays");
            yes(v.equals(capture(bound(),activities(),windows(),recents())),"stable complete capture");});
        test("controller raw identity remains in fingerprint",()->{
            Map<Integer,String> v=capture(bound(),activities(),windows(),recents());
            yes(!v.equals(capture(bound(),activities().replace("Task{aa #100","Task{af #100"),windows(),recents())),"controller row was excluded");});
        test("socket caller UID and PID are separately mandatory",()->{
            refuse(()->PublicPermissionControllerUi.bind(locator(),session(),10482,2020,task(new Object(),100,0,-1,10481,C),7,10100));
            refuse(()->PublicPermissionControllerUi.bind(locator(),session(),10481,2021,task(new Object(),100,0,-1,10481,C),7,10100));});
        test("same package cannot replace actual full UID or component",()->{
            refuse(()->PublicPermissionControllerUi.bind(locator(),session(),10481,2020,task(new Object(),100,0,-1,10482,C),7,10100));
            refuse(()->PublicPermissionControllerUi.bind(locator(),session(),10481,2020,task(new Object(),100,0,-1,10481,P+"/"+P+".Other"),7,10100));});
        test("held token replacement is rejected and refusal remains latched",()->{
            PublicPermissionControllerUi.Bound b=bound();refuse(()->b.recheck(task(new Object(),100,0,-1,10481,C),10101));
            yes(Boolean.FALSE.equals(b.evidence().get("observation_valid")),"failed evidence must serialize honestly");
            refuse(()->capture(b,activities(),windows(),recents()));});
        test("retained parent and locator task cannot be reused",()->{
            Object token=new Object();PublicPermissionControllerUi.Task first=task(token,100,0,-1,10481,C);
            PublicPermissionControllerUi.Bound b=PublicPermissionControllerUi.bind(locator(),session(),10481,2020,first,7,10100);
            refuse(()->b.recheck(task(token,100,0,2,10481,C),10101));
            refuse(()->PublicPermissionControllerUi.bind(locator(),session(),10481,2020,task(token,101,0,-1,10481,C),7,10100));});
        test("source cannot move into owned or another physical display",()->{
            refuse(()->PublicPermissionControllerUi.bind(locator(),session(),10481,2020,task(new Object(),100,7,-1,10481,C),7,10100));
            refuse(()->PublicPermissionControllerUi.bind(locator(),session(),10481,2020,task(new Object(),100,1,-1,10481,C),7,10100));});
        test("second physical Hepta instance never inherits source exemption",()->{
            String second=activities().replace("* Hist #0: ActivityRecord{bb u0 com.example.cover/.Main t101}",
                    "* Hist #0: ActivityRecord{bb u0 "+P+"/.MainActivity t101}");
            refuse(()->capture(bound(),second,windows(),recents()));});
        test("focused window and focused activity must be exact source",()->{
            refuse(()->capture(bound(),activities(),windows().replace("t100}","t101}"),recents()));
            refuse(()->capture(bound(),activities(),windows().replace(C+"}",P+"/"+P+".Other}"),recents()));});
        test("dedicated target profile still cannot appear on physical display",()->refuse(()->capture(bound(),
                activities().replace("U=0 visible=true sz=1","U=10 visible=true sz=1").replace("{ab u0","{ab u10"),windows(),recents())));
        test("recents UID root and component must agree with held source",()->{
            refuse(()->capture(bound(),activities(),windows(),recents().replace("effectiveUid=10481","effectiveUid=10482")));
            refuse(()->capture(bound(),activities(),windows(),recents().replace("taskId=100 rootTaskId=100","taskId=100 rootTaskId=999")));
            refuse(()->capture(bound(),activities(),windows(),recents().replace(P+"/.MainActivity",P+"/.Other")));});
        test("model or screen source marker and malformed locator are refused",()->{
            refuse(()->PublicPermissionControllerUi.Locator.fromWire(locator().wire().replace("main_activity_user_button","model_output")));
            refuse(()->PublicPermissionControllerUi.Locator.fromWire(locator().wire()+"|extra"));
            yes(PublicPermissionControllerUi.Locator.fromWire(locator().wire()).wire().equals(locator().wire()),"canonical locator");});
        test("locator protocol is limited to public profile prepare",()->{
            yes(BrokerProtocol.Request.parse(request("prepare",locator().wire())).controllerUi!=null,"prepare locator missing");
            yes(BrokerProtocol.Request.parse(request("prepare",null)).controllerUi==null,"original prepare changed");
            refuse(()->BrokerProtocol.Request.parse(request("launch",locator().wire())));});
        test("scope owner age and future clock cannot manufacture admission",()->{
            PublicPermissionControllerUi.Locator other=PublicPermissionControllerUi.fromMainActivityButton(10481,2020,100,0,9900,ProfileIdentity.sha("other"));
            refuse(()->PublicPermissionControllerUi.bind(other,session(),10481,2020,task(new Object(),100,0,-1,10481,C),7,10100));
            refuse(()->PublicPermissionControllerUi.bind(locator(),session(),10481,2020,task(new Object(),100,0,-1,10481,C),7,26000));
            refuse(()->PublicPermissionControllerUi.bind(locator(),session(),10481,2020,task(new Object(),100,0,-1,10481,C),7,9999));});
        test("full Binder root TaskInfo is resolved by actual identity",()->{
            Platform p=new Platform();p.roots.add(root(100,false));
            PublicPermissionControllerUi.Task t=BackgroundTaskOrganizer.readOnlyControllerTask(p,100,0,()->50000);
            yes(t.token==p.roots.get(0).token.asBinder()&&t.uid==10481&&t.topUid==10481,"actual task was replaced");
            yes(p.reads==1&&p.childReads==0,"root path only reads original census");});
        test("child source resolution reads exact parent token without mutation",()->{
            Platform p=new Platform();p.roots.add(root(1,true));TaskInfo child=new TaskInfo();fill(child,100,1);p.children.add(child);
            PublicPermissionControllerUi.Task t=BackgroundTaskOrganizer.readOnlyControllerTask(p,100,0,()->50000);
            yes(t.token==child.token.asBinder()&&t.parent==1&&p.childReads==1,"child task provenance");});
        test("missing or contradictory complete Binder task census refuses",()->{
            Platform p=new Platform();p.roots.add(root(100,false));p.roots.get(0).topActivityInfo.applicationInfo.uid=10482;
            PublicPermissionControllerUi.Task t=BackgroundTaskOrganizer.readOnlyControllerTask(p,100,0,()->50000);
            refuse(()->PublicPermissionControllerUi.bind(locator(),session(),10481,2020,t,7,10100));
            refuse(()->BackgroundTaskOrganizer.readOnlyControllerTask(p,999,0,()->50000));
            p.roots.get(0).token=null;refuse(()->BackgroundTaskOrganizer.readOnlyControllerTask(p,100,0,()->50000));});
        test("typed observation grants no physical input or serialized authority",()->{
            Map<String,Object> e=bound().evidence();yes(Boolean.FALSE.equals(e.get("physical_input_authorized")),"physical input");
            yes(Boolean.FALSE.equals(e.get("serialized_locator_grants_authority")),"serialized authority");yes(mutations==0,"host mutation called");});
        System.out.println(new org.json.JSONObject().put("schema","hepta.main-ui-permission-host.v1").put("all_pass",true)
                .put("cases",cases).put("assertions",assertions).put("case_names",names).put("phone_operations",0)
                .put("framework_and_binder_synthetic",true).put("android_main_screen_executed",false).put("mutation_calls",mutations));
    }
}
