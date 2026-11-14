package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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

/** Executes the complete production coordinator. Framework calls alone are explicit host doubles. */
public final class OwnedSingleTaskHostTest {
    private static final String GEN="12345678-1234-1234-1234-123456789012";
    private static final String REQ="22345678-1234-1234-1234-123456789012";
    private static final int FLAGS=0x18000000;
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private static String fixtureRecents,fixtureActivities;
    private interface Work {void run() throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Work work)throws Exception{work.run();names.add(name);}
    private static void rejected(String code,Work work)throws Exception{
        try{work.run();throw new AssertionError("expected refusal "+code);}
        catch(BackgroundOwnedSingleTask.Refusal error){check(code.equals(error.code),code+" != "+error.code);}
    }
    private static BackgroundOwnedTaskPolicy.Activity activity(){return activity(2,0,0,10485,true,null,null);}
    private static BackgroundOwnedTaskPolicy.Activity activity(int mode,int doc,int flags,int uid,boolean exported,String alias,String permission){
        return new BackgroundOwnedTaskPolicy.Activity(BackgroundOwnedSingleTask.PACKAGE,BackgroundOwnedSingleTask.COMPONENT,
            uid,mode,doc,flags,true,true,exported,alias,permission,"/data/app/installed/base.apk");
    }
    private static BackgroundOwnedSingleTask session(Mock p)throws Exception{return new BackgroundOwnedSingleTask(p,GEN,REQ,7,activity(),FLAGS);}
    private static BackgroundOwnedSingleTask started(Mock p)throws Exception{
        BackgroundOwnedSingleTask s=session(p);s.prepare();s.beforeDispatch();p.launch();s.accepted(0);return s;
    }
    private static BackgroundOwnedSingleTask observed(Mock p)throws Exception{
        BackgroundOwnedSingleTask s=started(p);check(s.observe(),"fresh leaf visible");return s;
    }
    private static OwnedTaskSnapshotProjection.RootInfo snapshotRoot(Mock p){
        return new OwnedTaskSnapshotProjection.RootInfo(p.outer.id,7,new int[]{p.anchor.id,p.app.id},
            new String[]{"unknown",BackgroundOwnedSingleTask.COMPONENT},BackgroundOwnedSingleTask.COMPONENT,1,true);
    }
    private static OwnedTaskSnapshotProjection snapshot(Mock p,BackgroundOwnedSingleTask s)throws Exception{
        return new OwnedTaskSnapshotProjection(s,snapshotRoot(p));
    }
    private static void brokerRejected(String code,Work work)throws Exception{
        try{work.run();throw new AssertionError("expected broker refusal "+code);}
        catch(BrokerProtocol.Refusal error){check(code.equals(error.code),code+" != "+error.code);}
    }

    private static final class Row {
        int id,display=7,user,parent=-1,uid,topUid=-1,activities;
        Object token=new Object();List<Object> cookies=new ArrayList<Object>();
        String intent,base,top,real,orig;boolean running,visible;
        Row(int id,Object cookie){this.id=id;cookies.add(cookie);}
        BackgroundOwnedSingleTask.Task value(){return new BackgroundOwnedSingleTask.Task(id,display,user,parent,uid,topUid,
            activities,token,cookies,intent,base,top,real,orig,running,visible);}
    }
    private static final class Mock implements BackgroundOwnedSingleTask.Platform {
        final Map<Integer,Row> rows=new LinkedHashMap<Integer,Row>();
        final List<String> operations=new ArrayList<String>();
        final Set<Integer> extraLive=new LinkedHashSet<Integer>(Arrays.asList(10));
        String recents=fixtureRecents,activities=fixtureActivities;
        int next=100,creates,guards;boolean guardFails,staleRecent,omitLeaf;
        Object boundToken,boundCookie;int boundId;Row outer,anchor,app;
        @Override public Object newCookie(){return new Object();}
        @Override public void guard()throws Exception{guards++;if(guardFails)throw new BackgroundOwnedSingleTask.Refusal("CURRENT_GUARD_REJECTED");}
        @Override public List<BackgroundOwnedSingleTask.Task> roots(){
            ArrayList<BackgroundOwnedSingleTask.Task> out=new ArrayList<BackgroundOwnedSingleTask.Task>();
            for(Row r:rows.values())if(r.parent==-1)out.add(r.value());return out;
        }
        @Override public List<BackgroundOwnedSingleTask.Task> children(Object token){
            Row p=find(token);if(p==null)return null;
            ArrayList<BackgroundOwnedSingleTask.Task> out=new ArrayList<BackgroundOwnedSingleTask.Task>();
            for(Row r:rows.values())if(r.parent==p.id)out.add(r.value());return out;
        }
        @Override public Set<Integer> liveTaskIds(){Set<Integer> out=new LinkedHashSet<Integer>(extraLive);out.addAll(rows.keySet());return out;}
        @Override public Set<Integer> liveLeafTaskIds(){
            Set<Integer> out=new LinkedHashSet<Integer>(extraLive);out.addAll(rows.keySet());
            for(Row r:rows.values())if(r.parent!=-1)out.remove(r.parent);
            if(omitLeaf&&app!=null)out.remove(app.id);return out;
        }
        @Override public String activitiesDump(){return activities;}
        @Override public String recentsDump(){
            if(staleRecent&&app!=null)return rawRecent(app.id,BackgroundOwnedSingleTask.PACKAGE);
            return recents;
        }
        @Override public void createRoot(Object cookie){
            Row r=new Row(next++,cookie);rows.put(r.id,r);creates++;operations.add("create:"+r.id);
            if(outer==null)outer=r;else if(anchor==null)anchor=r;
        }
        @Override public void reparentEmpty(Object child,Object parent){
            Row c=find(child),p=find(parent);check(c!=null&&p!=null&&c.activities==0&&p.activities==0,"only new empty tokens reparent");
            c.parent=p.id;operations.add("reparent:"+c.id+":"+p.id);
        }
        @Override public void bindLaunch(Object root,int id,Object cookie){boundToken=root;boundId=id;boundCookie=cookie;operations.add("bind:"+id);}
        void launch(){
            check(boundToken==outer.token&&boundId==outer.id,"explicit root token and id");
            check(!liveLeafTaskIds().contains(boundId),"launchTaskId is non-leaf, no global reuse search");
            app=new Row(next++,boundCookie);app.parent=outer.id;app.uid=10485;app.topUid=10485;app.activities=1;
            app.intent=BackgroundOwnedSingleTask.COMPONENT;app.base=app.intent;app.top=app.intent;app.real=app.intent;
            app.running=true;app.visible=true;rows.put(app.id,app);outer.activities=1;outer.running=true;outer.top=app.top;outer.base=app.base;
            operations.add("launch-new:"+app.id);
        }
        Row find(Object token){for(Row r:rows.values())if(r.token==token)return r;return null;}
        @Override public void removeOwnedLeaf(Object token){
            Row r=find(token);check(r==app&&r.parent==outer.id&&r.uid==10485,"remove only held new leaf token");
            operations.add("remove-leaf:"+r.id);rows.remove(r.id);outer.activities=0;outer.running=false;outer.base=null;outer.top=null;
        }
        @Override public boolean deleteOwnedContainer(Object token){
            Row r=find(token);check(r==anchor||r==outer,"delete only new owned container token");
            operations.add("delete-container:"+r.id);rows.remove(r.id);return true;
        }
    }
    private static String rawRecent(int id,String pkg){return "ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\n"
        +"mRecentsUid=10001\nmRecentsComponent=x\nmFreezeTaskListReordering=false\nmFreezeTaskListReorderingPendingTimeout=false\n"
        +"  Recent tasks:\n  * Recent #0: Task{abc #"+id+" type=standard A=10485:"+pkg+"}\n"
        +"    userId=0 effectiveUid=u0a485 mCallingPackage="+pkg+"\n    Activities=[]\n"
        +"    taskId="+id+" rootTaskId="+id+"\n";}

    public static void main(String[] args)throws Exception{
        Path fixtures=Paths.get(args[0]),out=Paths.get(args[1]);
        fixtureRecents=new String(Files.readAllBytes(fixtures.resolve("recents-shape.txt")),StandardCharsets.UTF_8);
        fixtureActivities=new String(Files.readAllBytes(fixtures.resolve("activities-shape.txt")),StandardCharsets.UTF_8);
        test("complete_new_leaf_and_exact_token_cleanup",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);
            check(p.creates==2,"two containers");s.retire();check(s.absent(),"both live and raw-recents absence");
            check(p.extraLive.contains(10),"unrelated task retained");check(Boolean.TRUE.equals(s.evidence().get("leaf_removal_platform_kill_process_argument")),"platform killProcess explicitly recorded");});
        test("old_standard_policy_stays_admitted",()->{BackgroundOwnedTaskPolicy.Plan p=BackgroundOwnedTaskPolicy.choose(GEN,7,BackgroundOwnedSingleTask.PACKAGE,activity(0,0,0,10485,true,null,null),FLAGS);check(p.eligible&&p.newDocumentRequested,"original document contract");});
        test("old_single_task_policy_stays_rejected",()->{check(!BackgroundOwnedTaskPolicy.choose(GEN,7,BackgroundOwnedSingleTask.PACKAGE,activity(),FLAGS).eligible,"old policy not relaxed");});
        test("only_known_native_home_eligible",()->{check(BackgroundOwnedSingleTask.eligible(activity(),FLAGS),"actual mode2 home");check(!BackgroundOwnedSingleTask.eligible(new BackgroundOwnedTaskPolicy.Activity("example.other","example.other/.Main",10485,2,0,0,true,true,true,null,null,"/data/app/base.apk"),FLAGS),"unknown provider excluded");});
        test("standard_mode_not_rerouted",()->{check(!BackgroundOwnedSingleTask.eligible(activity(0,0,0,10485,true,null,null),FLAGS),"standard separate");});
        test("single_instance_not_admitted",()->{check(!BackgroundOwnedSingleTask.eligible(activity(3,0,0,10485,true,null,null),FLAGS),"singleInstance rejected");});
        test("document_mode_not_admitted",()->{check(!BackgroundOwnedSingleTask.eligible(activity(2,1,0,10485,true,null,null),FLAGS),"document mode rejected");});
        test("reparentable_manifest_rejected",()->{check(!BackgroundOwnedSingleTask.eligible(activity(2,0,0x40,10485,true,null,null),FLAGS),"reparent flag");});
        test("relinquishable_identity_rejected",()->{check(!BackgroundOwnedSingleTask.eligible(activity(2,0,0x1000,10485,true,null,null),FLAGS),"identity flag");});
        test("alias_rejected",()->{check(!BackgroundOwnedSingleTask.eligible(activity(2,0,0,10485,true,".Other",null),FLAGS),"alias");});
        test("permission_entry_rejected",()->{check(!BackgroundOwnedSingleTask.eligible(activity(2,0,0,10485,true,null,"custom.permission"),FLAGS),"permission");});
        test("nonexported_entry_rejected",()->{check(!BackgroundOwnedSingleTask.eligible(activity(2,0,0,10485,false,null,null),FLAGS),"exported");});
        test("system_uid_rejected",()->{check(!BackgroundOwnedSingleTask.eligible(activity(2,0,0,1000,true,null,null),FLAGS),"system uid");});
        test("flag_reuse_or_clear_rejected",()->{check(!BackgroundOwnedSingleTask.eligible(activity(),FLAGS|0x04000000),"clear top");check(!BackgroundOwnedSingleTask.eligible(activity(),0x10000000),"multiple required");});
        test("empty_home_no_query_authorization",()->{check(BackgroundOwnedSingleTask.ACTION.equals("com.xiaomi.shop.action_show_home"),"registered home action");});
        test("existing_target_activity_rejects_before_mutation",()->{Mock p=new Mock();p.activities=p.activities.replace("example.other/.Main","com.xiaomi.shop/.Hidden");rejected("APP_ALREADY_HAS_TASK",()->session(p).prepare());check(p.creates==0,"no mutation");});
        test("detached_target_recent_rejects_before_mutation",()->{Mock p=new Mock();p.recents=rawRecent(77,BackgroundOwnedSingleTask.PACKAGE);rejected("APP_ALREADY_HAS_TASK",()->session(p).prepare());check(p.creates==0,"no create");});
        test("market_uri_does_not_claim_target_task",()->{Mock p=new Mock();p.activities=p.activities.replace("  TaskOrganizerController:","      Intent { dat=market://details?id=com.xiaomi.shop cmp=example.other/.Store }\n  TaskOrganizerController:");BackgroundOwnedSingleTask s=session(p);s.prepare();check(p.creates==2,"market data is not component");});
        test("truncated_activities_dump_rejected",()->{Mock p=new Mock();p.activities="ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n";rejected("ACTIVITIES_DUMP_TAIL_INCOMPLETE",()->session(p).prepare());check(p.creates==0,"zero create");});
        test("truncated_recent_record_rejected",()->{String b=fixtureRecents.substring(0,fixtureRecents.indexOf("    taskId="));rejected("RECENTS_TASK_DETAIL_INCOMPLETE",()->BackgroundOwnedSingleTask.RecentTasks.parse(b));});
        test("noncontiguous_raw_recents_rejected",()->{rejected("RECENTS_NONCONTIGUOUS_ORDINAL",()->BackgroundOwnedSingleTask.RecentTasks.parse(fixtureRecents.replace("Recent #0:","Recent #2:")));});
        test("malformed_raw_recent_header_rejected",()->{rejected("RECENTS_TASK_HEADER_INVALID",()->BackgroundOwnedSingleTask.RecentTasks.parse(fixtureRecents.replace("Task{f9f8788 #41","Task{f9f8788 id41")));});
        test("raw_recents_uid_detail_required",()->{rejected("RECENTS_UID_DETAIL_INVALID",()->BackgroundOwnedSingleTask.RecentTasks.parse(fixtureRecents.replace(" effectiveUid=u0a367","")));});
        test("raw_recents_id_crosscheck_required",()->{rejected("RECENTS_ID_DETAIL_INVALID",()->BackgroundOwnedSingleTask.RecentTasks.parse(fixtureRecents.replace("taskId=41 rootTaskId=41","taskId=42 rootTaskId=41")));});
        test("empty_raw_recent_list_supported",()->{String text=rawRecent(1,"example.other");text=text.substring(0,text.indexOf("  Recent tasks:"));check(BackgroundOwnedSingleTask.RecentTasks.parse(text).ids.isEmpty(),"empty unfiltered list");});
        test("complete_shape_retains_detached_recent",()->{check(BackgroundOwnedSingleTask.RecentTasks.parse(fixtureRecents).ids.contains(41),"hasTask=false does not erase recent id");});
        test("current_guard_prevents_create",()->{Mock p=new Mock();p.guardFails=true;rejected("CURRENT_GUARD_REJECTED",()->session(p).prepare());check(p.creates==0,"no create");});
        test("created_id_preexisted_rejected",()->{Mock p=new Mock();p.next=41;rejected("OWNED_CREATED_ID_PREEXISTED",()->session(p).prepare());check(!p.operations.toString().contains("bind:"),"no launch binding");});
        test("prepare_once_only",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();rejected("OWNED_TASK_CREATE_ALREADY_ATTEMPTED",s::prepare);check(p.creates==2,"no replay");});
        test("dispatch_once_only",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();s.beforeDispatch();rejected("OWNED_TASK_DISPATCH_ALREADY_ATTEMPTED",s::beforeDispatch);});
        test("anchor_loss_before_dispatch_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();p.rows.remove(p.anchor.id);rejected("OWNED_ANCHOR_NOT_UNIQUE",s::beforeDispatch);});
        test("anchor_token_replacement_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();p.anchor.token=new Object();rejected("OWNED_ANCHOR_IDENTITY_CHANGED",s::beforeDispatch);});
        test("anchor_uid_changed_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();p.anchor.uid=10485;rejected("OWNED_ANCHOR_IDENTITY_CHANGED",s::beforeDispatch);});
        test("anchor_cookie_loss_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();p.anchor.cookies.clear();rejected("OWNED_CONTAINER_NOT_PROVEN_EMPTY",s::beforeDispatch);});
        test("anchor_not_empty_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();p.anchor.activities=1;rejected("OWNED_CONTAINER_NOT_PROVEN_EMPTY",s::beforeDispatch);});
        test("anchor_wrong_parent_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();p.anchor.parent=999;rejected("OWNED_ANCHOR_NOT_UNIQUE",s::beforeDispatch);});
        test("root_display_changed_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();p.outer.display=0;rejected("OWNED_ROOT_IDENTITY_CHANGED",s::beforeDispatch);});
        test("root_cookie_replaced_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();p.outer.cookies.clear();rejected("OWNED_ROOT_IDENTITY_CHANGED",s::beforeDispatch);});
        test("root_uid_changed_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();p.outer.uid=10485;rejected("OWNED_CONTAINER_TASK_IDENTITY_CHANGED",s::beforeDispatch);});
        test("delivered_to_existing_top_not_fresh_success",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();s.beforeDispatch();rejected("OWNED_TASK_START_NOT_FRESH_SUCCESS",()->s.accepted(3));});
        test("task_to_front_not_fresh_success",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();s.beforeDispatch();rejected("OWNED_TASK_START_NOT_FRESH_SUCCESS",()->s.accepted(2));});
        test("waiting_for_new_leaf_not_ownership",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();s.beforeDispatch();s.accepted(0);check(!s.observe(),"no new leaf yet");check(Boolean.FALSE.equals(s.evidence().get("new_leaf_ownership_verified")),"no claim");});
        test("wrong_leaf_uid_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=started(p);p.app.uid=10486;rejected("OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN",s::observe);});
        test("wrong_top_activity_uid_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=started(p);p.app.topUid=10486;rejected("OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN",s::observe);});
        test("wrong_leaf_user_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=started(p);p.app.user=1;rejected("OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN",s::observe);});
        test("wrong_leaf_display_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=started(p);p.app.display=0;rejected("OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN",s::observe);});
        test("old_id_cannot_be_new_leaf",()->{Mock p=new Mock();p.extraLive.add(102);BackgroundOwnedSingleTask s=started(p);rejected("OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN",s::observe);});
        test("leaf_cookie_missing_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=started(p);p.app.cookies.clear();rejected("OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN",s::observe);});
        test("leaf_real_activity_mismatch_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=started(p);p.app.real=BackgroundOwnedSingleTask.PACKAGE+"/.Other";rejected("OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN",s::observe);});
        test("leaf_base_intent_mismatch_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=started(p);p.app.intent="example.other/.Main";rejected("OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN",s::observe);});
        test("foreign_top_activity_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=started(p);p.app.top="example.other/.Main";rejected("OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN",s::observe);});
        test("nonleaf_app_task_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=started(p);p.omitLeaf=true;rejected("OWNED_APP_TASK_NOT_LEAF",s::observe);});
        test("same_id_different_token_after_observation_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);p.app.token=new Object();rejected("OWNED_LEAF_IDENTITY_CHANGED",s::observe);});
        test("future_same_app_navigation_stays_bound",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);p.app.top=BackgroundOwnedSingleTask.PACKAGE+"/.Product";p.app.activities=2;check(s.observe(),"same root identity and uid");});
        test("completed_launch_deadline_not_reused_for_state",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);p.guardFails=true;check(s.observe(),"broker supplies fresh current-request guard");});
        test("extra_unknown_child_no_cleanup_removal",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);Row foreign=new Row(199,new Object());foreign.parent=p.outer.id;p.rows.put(199,foreign);rejected("OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN",s::retire);check(!p.operations.toString().contains("remove-leaf"),"no removal");check(!s.absent(),"unknown not clean");});
        test("changed_parent_does_not_authorize_cleanup",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);p.app.parent=999;rejected("OWNED_LEAF_NO_LONGER_ATTACHED",s::retire);check(!p.operations.toString().contains("remove-leaf"),"zero remove");});
        test("cleanup_requires_raw_recents_absence",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);p.staleRecent=true;s.retire();check(!s.absent(),"retained own recent is not clean");});
        test("cleanup_requires_live_id_absence",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);int id=p.app.id;s.retire();p.extraLive.add(id);check(!s.absent(),"live id blocks");});
        test("cleanup_once_no_retry",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);s.retire();int n=p.operations.size();rejected("OWNED_TASK_REMOVAL_ALREADY_ATTEMPTED",s::retire);check(p.operations.size()==n,"no repeated removal");});
        test("prepared_but_not_dispatched_containers_only_cleanup",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.prepare();s.retire();check(s.absent(),"empty owned containers released");check(!p.operations.toString().contains("remove-leaf"),"no app task removed");});
        test("unprepared_no_mutation_cleanup",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=session(p);s.retire();check(s.absent(),"nothing created");check(p.operations.isEmpty(),"no platform mutation");});
        test("owned_reconcile_without_broker_remains_unknown",()->{JSONObject j=new JSONObject().put("owned_task_retirement_required",true);check(!new OwnedTaskReconcileProjection(true).known(j,false,false),"no broker release");});
        test("owned_reconcile_expiry_or_boot_cannot_wash_unknown",()->{JSONObject j=new JSONObject().put("owned_task_retirement_required",true);check(!new OwnedTaskReconcileProjection(true).known(j,false,true),"noLateCreate cannot prove recents absence");});
        test("owned_reconcile_actual_broker_release_and_absence",()->{JSONObject j=new JSONObject().put("owned_task_retirement_required",true);check(new OwnedTaskReconcileProjection(true).known(j,true,false),"actual broker release plus app display absence");});
        test("owned_reconcile_display_still_present_rejected",()->{JSONObject j=new JSONObject().put("owned_task_retirement_required",true);check(!new OwnedTaskReconcileProjection(false).known(j,true,true),"display absence still mandatory");});
        test("standard_new_journal_retains_expiry_contract",()->{JSONObject j=new JSONObject().put("owned_task_retirement_required",false);check(new OwnedTaskReconcileProjection(true).known(j,false,true),"ordinary standard contract unchanged");});
        test("legacy_journal_retains_expiry_contract",()->{check(new OwnedTaskReconcileProjection(true).known(new JSONObject(),false,true),"old journal has no owned-task branch");});
        test("legacy_journal_without_expiry_stays_unknown",()->{check(!new OwnedTaskReconcileProjection(true).known(new JSONObject(),false,false),"old noLateCreate still required");});
        test("reconcile_string_boolean_not_coerced",()->{for(String value:new String[]{"true","false"}){try{new OwnedTaskReconcileProjection(true).known(new JSONObject().put("owned_task_retirement_required",value),true,true);throw new AssertionError("string accepted");}catch(java.io.IOException expected){check(true,"strict boolean");}}});
        test("reconcile_numeric_boolean_not_coerced",()->{try{new OwnedTaskReconcileProjection(true).known(new JSONObject().put("owned_task_retirement_required",0),true,true);throw new AssertionError("number accepted");}catch(java.io.IOException expected){check(true,"strict boolean");}});
        test("reconcile_json_null_not_missing_legacy",()->{try{new OwnedTaskReconcileProjection(true).known(new JSONObject().put("owned_task_retirement_required",JSONObject.NULL),true,true);throw new AssertionError("null accepted");}catch(java.io.IOException expected){check(true,"explicit null is not old journal");}});
        test("actual_snapshot_owned_empty_anchor_and_visible_top",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);OwnedTaskSnapshotProjection f=snapshot(p,s);check(BackgroundOwnedSingleTask.PACKAGE.equals(f.top(7)),"actual snapshot retains visible native top");f.requireNoOtherDisplay(BackgroundOwnedSingleTask.PACKAGE,7);});
        test("actual_snapshot_unknown_without_owned_coordinator_rejected",()->{Mock p=new Mock();observed(p);brokerRejected("TASK_COMPONENT_UNRESOLVED",()->snapshot(p,null).top(7));});
        test("actual_snapshot_wrong_anchor_id_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);OwnedTaskSnapshotProjection.RootInfo r=snapshotRoot(p);r.childTaskIds[0]=999;brokerRejected("TASK_COMPONENT_UNRESOLVED",()->new OwnedTaskSnapshotProjection(s,r).top(7));});
        test("actual_snapshot_wrong_root_or_display_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);OwnedTaskSnapshotProjection.RootInfo wrongRoot=snapshotRoot(p);wrongRoot.taskId=999;brokerRejected("TASK_COMPONENT_UNRESOLVED",()->new OwnedTaskSnapshotProjection(s,wrongRoot).top(7));OwnedTaskSnapshotProjection.RootInfo wrongDisplay=snapshotRoot(p);wrongDisplay.displayId=0;brokerRejected("TASK_COMPONENT_UNRESOLVED",()->new OwnedTaskSnapshotProjection(s,wrongDisplay).top(7));});
        test("actual_snapshot_fresh_anchor_uid_required",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);p.anchor.uid=10485;rejected("OWNED_ANCHOR_IDENTITY_CHANGED",()->snapshot(p,s).top(7));});
        test("actual_snapshot_fresh_anchor_token_required",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);p.anchor.token=new Object();rejected("OWNED_ANCHOR_IDENTITY_CHANGED",()->snapshot(p,s).top(7));});
        test("actual_snapshot_fresh_anchor_cookie_required",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);p.anchor.cookies.clear();rejected("OWNED_CONTAINER_NOT_PROVEN_EMPTY",()->snapshot(p,s).top(7));});
        test("actual_snapshot_fresh_anchor_empty_required",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);p.anchor.activities=1;rejected("OWNED_CONTAINER_NOT_PROVEN_EMPTY",()->snapshot(p,s).top(7));});
        test("actual_snapshot_fresh_root_token_required",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);p.outer.token=new Object();rejected("OWNED_ROOT_IDENTITY_CHANGED",()->snapshot(p,s).top(7));});
        test("actual_snapshot_anchor_must_remain_leaf",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);Row extra=new Row(199,new Object());extra.parent=p.anchor.id;p.rows.put(extra.id,extra);rejected("OWNED_ROOT_NOT_NONLEAF",()->snapshot(p,s).top(7));});
        test("actual_snapshot_duplicate_anchor_unknown_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);OwnedTaskSnapshotProjection.RootInfo r=snapshotRoot(p);r.childTaskIds=new int[]{p.anchor.id,p.anchor.id,p.app.id};r.childTaskNames=new String[]{"unknown","unknown",BackgroundOwnedSingleTask.COMPONENT};brokerRejected("TASK_COMPONENT_UNRESOLVED",()->new OwnedTaskSnapshotProjection(s,r).top(7));});
        test("actual_snapshot_extra_unknown_child_rejected",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);OwnedTaskSnapshotProjection.RootInfo r=snapshotRoot(p);r.childTaskIds=new int[]{p.anchor.id,p.app.id,199};r.childTaskNames=new String[]{"unknown",BackgroundOwnedSingleTask.COMPONENT,"unknown"};brokerRejected("TASK_COMPONENT_UNRESOLVED",()->new OwnedTaskSnapshotProjection(s,r).top(7));});
        test("actual_snapshot_unknown_literal_is_exact",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);OwnedTaskSnapshotProjection.RootInfo r=snapshotRoot(p);r.childTaskNames[0]=" unknown";brokerRejected("TASK_COMPONENT_UNRESOLVED",()->new OwnedTaskSnapshotProjection(s,r).top(7));});
        test("actual_snapshot_proof_has_no_guard_callback",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);int guards=p.guards;p.guardFails=true;check(BackgroundOwnedSingleTask.PACKAGE.equals(snapshot(p,s).top(7)),"fresh read does not re-enter snapshot location guard");check(p.guards==guards,"no guard callback from anchor proof");});
        test("actual_snapshot_main_display_package_guard_preserved",()->{Mock p=new Mock();BackgroundOwnedSingleTask s=observed(p);OwnedTaskSnapshotProjection.RootInfo main=new OwnedTaskSnapshotProjection.RootInfo(10,0,new int[]{10},new String[]{BackgroundOwnedSingleTask.COMPONENT},BackgroundOwnedSingleTask.COMPONENT,1,true);brokerRejected("APP_ALREADY_ON_MAIN_DISPLAY",()->new OwnedTaskSnapshotProjection(s,snapshotRoot(p),main).requireNoOtherDisplay(BackgroundOwnedSingleTask.PACKAGE,7));});
        test("actual_snapshot_old_empty_root_contract_preserved",()->{OwnedTaskSnapshotProjection.RootInfo empty=new OwnedTaskSnapshotProjection.RootInfo(10,7,new int[]{10},new String[]{"unknown"},null,0,false);check(new OwnedTaskSnapshotProjection(null,empty).top(7)==null,"original fully empty container predicate unchanged");});
        JSONObject result=new JSONObject().put("schema","hepta.owned-single-task-host.v1").put("cases",names.size())
            .put("assertions",assertions).put("case_names",new JSONArray(names)).put("all_pass",true)
            .put("framework_io_synthetic",true).put("android_capability_verified",false)
            .put("phone_operations",0).put("business_result_verified",false);
        Files.write(out.resolve("CASES.json"),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(result.toString());
    }
}
