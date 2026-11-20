package org.trillionnium.hepta.background;

import android.app.ActivityOptions;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.SystemClock;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.LongSupplier;
import org.json.JSONObject;

/** Actual read-only TaskInfo/UID/token and complete recents adapter.
 * It never calls the organizer's create/reparent/remove/bind methods. Both
 * organizer mutation guards are unconditionally throwing boundaries. */
final class PublicPersonalNotesReader {
    /** Exact rejected framework row. Serialized fields confer no task authority. */
    static class TaskInfoReadFailure extends IOException {
        private static final long serialVersionUID=1L;
        final Map<String,Object> evidence;
        TaskInfoReadFailure(String code,String stage,BackgroundOwnedSingleTask.Task task,int uid,int display){
            this(code,stage,task,uid,display,null,0,null);
        }
        TaskInfoReadFailure(String code,String stage,BackgroundOwnedSingleTask.Task task,int uid,int display,
                BackgroundOwnedSingleTask.Task previous,int attempt,String comparison){
            super(code);Map<String,Object> row=new LinkedHashMap<String,Object>();
            row.put("schema","hepta.notes-taskinfo-row-refusal.v1");row.put("stage",stage);
            row.put("reason",code);row.put("expected_uid",uid);row.put("expected_display_id",display);
            row.put("actual_row_available",task!=null);row.put("serialized_fields_grant_authority",false);
            if(task!=null)row.putAll(taskFields(task));
            if(previous!=null){
                Map<String,Object> old=taskFields(previous),current=taskFields(task);
                List<String> changed=new ArrayList<String>();
                for(String key:old.keySet())if(!Objects.equals(old.get(key),current.get(key)))changed.add(key);
                row.put("comparison_before",old);row.put("comparison_after",current);
                row.put("changed_fields",Collections.unmodifiableList(changed));row.put("sample_attempt",attempt);
                row.put("comparison_kind",comparison);
            }
            evidence=Collections.unmodifiableMap(row);
        }
    }
    /** A complete valid target row may change its activity state while Android
     * completes a launch. Only this typed, identity-preserving change is sampled
     * again; it never authorizes a second Intent or a partial/inconsistent frame. */
    private static final class ActivityStateChanged extends TaskInfoReadFailure {
        private static final long serialVersionUID=1L;
        ActivityStateChanged(String stage,BackgroundOwnedSingleTask.Task a,BackgroundOwnedSingleTask.Task b,
                int uid,int display,int attempt){
            super("NOTES_ROOT_TASKINFO_CHANGED",stage,b,uid,display,a,attempt,"activity_state");
        }
    }
    private static Map<String,Object> taskFields(BackgroundOwnedSingleTask.Task task){
        Map<String,Object> row=new LinkedHashMap<String,Object>();
        row.put("task_id",task.id);row.put("user_id",task.user);row.put("display_id",task.display);
        row.put("parent_id",task.parent);row.put("effective_uid",task.uid);row.put("top_uid",task.topUid);
        row.put("num_activities",task.activities);row.put("is_running",task.running);row.put("is_visible",task.visible);
        row.put("intent_component",nullable(task.intentComponent));row.put("base_activity",nullable(task.base));
        row.put("real_activity",nullable(task.real));row.put("top_activity",nullable(task.top));row.put("orig_activity",nullable(task.orig));
        row.put("token_present",task.token!=null);row.put("token_identity_in_reader",task.token==null?JSONObject.NULL:System.identityHashCode(task.token));
        List<Integer> cookies=new ArrayList<Integer>();for(Object cookie:task.cookies)cookies.add(System.identityHashCode(cookie));
        row.put("launch_cookie_identities_in_reader",Collections.unmodifiableList(cookies));
        return Collections.unmodifiableMap(row);
    }
    /** Keeps the first runtime refusal distinct from a later cleanup refusal. */
    static final class FailureAudit {
        private Map<String,Object> runtime,cleanup;
        synchronized void runtime(Throwable error,long now){if(runtime==null)runtime=failure(error,"runtime_policy_check",now);}
        synchronized void cleanup(Throwable error,long now){if(cleanup==null)cleanup=failure(error,"cleanup",now);}
        synchronized Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema","hepta.notes-taskinfo-diagnostics.v1");
            out.put("first_runtime_failure",nullable(runtime));out.put("first_cleanup_failure",nullable(cleanup));
            out.put("diagnostics_grant_authority",false);out.put("provides_cleanup_proof",false);return out;
        }
        private static Map<String,Object> failure(Throwable error,String phase,long now){
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("phase",phase);out.put("observed_elapsed_ms",now);
            out.put("exception_class",error.getClass().getName());out.put("reason",nullable(error.getMessage()));
            out.put("actual_root_read_failure",error instanceof TaskInfoReadFailure?((TaskInfoReadFailure)error).evidence:JSONObject.NULL);
            return Collections.unmodifiableMap(out);
        }
    }
    private static Object nullable(Object value){return value==null?JSONObject.NULL:value;}
    private final Context context;
    private final Object activities;
    private final BackgroundTaskOrganizer reader;
    private final LongSupplier deadline;
    final int uid;
    private final int display;
    private final String sourceDir;
    private static final int MAX_TASKINFO_SAMPLES=3;
    private static final long MAX_FRAME_MS=1500;
    PublicPersonalNotesReader(Context context,Object activities,int display,LongSupplier deadline)throws Exception{
        this.context=context;this.activities=activities;this.deadline=deadline;
        need(display>1,"NOTES_OWN_DISPLAY_INVALID");this.display=display;
        ApplicationInfo installed=context.getPackageManager().getApplicationInfo(PublicPersonalNotesCustody.PACKAGE,0);
        need(installed!=null&&installed.uid>=10000&&installed.uid<90000&&installed.enabled
                &&installed.sourceDir!=null&&installed.sourceDir.startsWith("/"),"NOTES_INSTALLATION_UNAVAILABLE");
        uid=installed.uid;sourceDir=installed.sourceDir;
        BackgroundTaskOrganizer.Check forbid=()->{throw new IOException("NOTES_READ_ADAPTER_MUTATION_FORBIDDEN");};
        reader=new BackgroundTaskOrganizer(activities,ActivityOptions.makeBasic().setLaunchDisplayId(display),display,forbid,forbid,deadline);
    }
    private static void need(boolean yes,String reason)throws IOException{if(!yes)throw new IOException(reason);}
    private void check()throws Exception{
        need(SystemClock.elapsedRealtime()<deadline.getAsLong(),"NOTES_TASK_READ_DEADLINE");
        ApplicationInfo current=context.getPackageManager().getApplicationInfo(PublicPersonalNotesCustody.PACKAGE,0);
        need(current!=null&&current.uid==uid&&current.enabled&&sourceDir.equals(current.sourceDir),"NOTES_INSTALLATION_CHANGED");
    }
    synchronized PublicPersonalNotesCustody.Frame frame()throws Exception{
        long begin=SystemClock.elapsedRealtime();check();
        // Ordinary Intent-created Notes roots are not organizer-created containers.
        // Android 16 getChildTasks() returns null for such tasks; null is not an
        // empty-child proof. Use two complete independent ATM leaf censuses around
        // the real organizer root TaskInfo query, without ever calling children().
        Map<Integer,BackgroundOwnedSingleTask.Task> identities=null;
        for(int attempt=1;attempt<=MAX_TASKINFO_SAMPLES;attempt++){
            check();need(SystemClock.elapsedRealtime()-begin<=MAX_FRAME_MS,"NOTES_TASK_FRAME_INVALID");
            BackgroundTaskOrganizer.ReadOnlyRootCensus before=reader.readOnlyRootCensus();
            List<BackgroundOwnedSingleTask.Task> actual=reader.roots();
            BackgroundTaskOrganizer.ReadOnlyRootCensus after=reader.readOnlyRootCensus();
            Map<Integer,BackgroundOwnedSingleTask.Task> first=index(before.displayRoots,"before_all_roots");
            Map<Integer,BackgroundOwnedSingleTask.Task> middle=index(actual,"owned_display_roots"),last=index(after.displayRoots,"after_all_roots");
            need(first.keySet().equals(middle.keySet())&&middle.keySet().equals(last.keySet()),"NOTES_ROOT_CENSUS_CHANGED");
            if(identities==null)identities=first;
            need(identities.keySet().equals(first.keySet()),"NOTES_ROOT_CENSUS_CHANGED");
            // Keep the first complete census's Binder identity through every
            // resample. A later coherent token/UID/cookie replacement is still
            // forbidden, even when the prior mismatch was only visibility.
            for(BackgroundOwnedSingleTask.Task task:actual){
                sameIdentity(identities.get(task.id),first.get(task.id),"resample_before",attempt);
                sameIdentity(identities.get(task.id),task,"resample_organizer",attempt);
                sameIdentity(identities.get(task.id),last.get(task.id),"resample_after",attempt);
            }
            try{
                List<PublicPersonalNotesCustody.Node> nodes=new ArrayList<PublicPersonalNotesCustody.Node>();
                for(BackgroundOwnedSingleTask.Task task:actual){
                    sameActualTask(first.get(task.id),task,"before_vs_organizer",attempt);
                    sameActualTask(task,last.get(task.id),"organizer_vs_after",attempt);
                    requireSoleLeaf(before.global,task);requireSoleLeaf(after.global,task);
                    nodes.add(new PublicPersonalNotesCustody.Node(task,Collections.<PublicPersonalNotesCustody.Node>emptyList()));
                }
                check();
                return new PublicPersonalNotesCustody.Frame(after.global,nodes,begin,SystemClock.elapsedRealtime());
            }catch(ActivityStateChanged changed){
                if(attempt==MAX_TASKINFO_SAMPLES)throw changed;
                check();need(SystemClock.elapsedRealtime()-begin<=MAX_FRAME_MS,"NOTES_TASK_FRAME_INVALID");
                Thread.sleep(20);
            }
        }
        throw new IOException("NOTES_ROOT_TASKINFO_CHANGED");
    }
    private Map<Integer,BackgroundOwnedSingleTask.Task> index(List<BackgroundOwnedSingleTask.Task> tasks,String stage)throws Exception{
        need(tasks!=null&&tasks.size()<=PublicPersonalNotesCustody.MAX_TASKS,"NOTES_ROOT_CENSUS_UNAVAILABLE");
        Map<Integer,BackgroundOwnedSingleTask.Task> out=new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>();
        for(BackgroundOwnedSingleTask.Task task:tasks){
            requireRoot(task!=null&&task.id>0&&task.display==display&&task.user==0&&task.parent<0
                    &&task.token!=null&&out.put(task.id,task)==null,"NOTES_ROOT_IDENTITY_UNAVAILABLE",stage,task);
            requireRoot((task.uid==uid&&(task.topUid==uid||(task.activities==0&&task.topUid==-1))
                    &&inPackage(task.intentComponent)&&inPackage(task.base)&&inPackage(task.real)
                    &&nullablePackage(task.top)&&nullablePackage(task.orig))||PublicPersonalNotesCustody.emptyActivityLeaf(task,uid),
                    "NOTES_ROOT_UID_OR_COMPONENT_UNAVAILABLE",stage,task);
        }
        return out;
    }
    private void requireRoot(boolean yes,String code,String stage,BackgroundOwnedSingleTask.Task task)throws IOException{
        if(!yes)throw new TaskInfoReadFailure(code,stage,task,uid,display);
    }
    private static boolean inPackage(String value){
        return value!=null&&value.startsWith(PublicPersonalNotesCustody.PACKAGE+"/");
    }
    private static boolean nullablePackage(String value){return value==null||inPackage(value);}
    private void sameIdentity(BackgroundOwnedSingleTask.Task a,BackgroundOwnedSingleTask.Task b,String stage,int attempt)throws Exception{
        if(!(a!=null&&b!=null&&a.id==b.id&&a.display==b.display&&a.user==b.user&&a.parent==b.parent
                &&a.uid==b.uid&&Objects.equals(a.token,b.token)&&a.cookies.equals(b.cookies)
                &&Objects.equals(a.intentComponent,b.intentComponent)&&Objects.equals(a.real,b.real)&&Objects.equals(a.orig,b.orig)))
            throw new TaskInfoReadFailure("NOTES_ROOT_TASKINFO_CHANGED",stage,b,uid,display,a,attempt,"immutable_identity");
    }
    private void sameActualTask(BackgroundOwnedSingleTask.Task a,BackgroundOwnedSingleTask.Task b,String stage,int attempt)throws Exception{
        sameIdentity(a,b,stage,attempt);
        if(!(a.topUid==b.topUid&&a.activities==b.activities&&a.running==b.running&&a.visible==b.visible
                &&Objects.equals(a.base,b.base)&&Objects.equals(a.top,b.top)))
            throw new ActivityStateChanged(stage,a,b,uid,display,attempt);
    }
    private void requireSoleLeaf(ProfileTaskPolicy.Snapshot global,BackgroundOwnedSingleTask.Task task)throws Exception{
        need(global!=null,"NOTES_GLOBAL_CENSUS_UNAVAILABLE");
        ProfileTaskPolicy.Root actualRoot=null;
        for(ProfileTaskPolicy.Root root:global.roots)if(root.id==task.id){
            need(actualRoot==null,"NOTES_GLOBAL_ROOT_DUPLICATE");actualRoot=root;
        }
        need(actualRoot!=null&&actualRoot.display==display&&actualRoot.user==0
                &&actualRoot.activities==task.activities&&Objects.equals(actualRoot.base,task.base)
                &&Objects.equals(actualRoot.top,task.top),"NOTES_GLOBAL_ROOT_DISAGREES");
        // RootTaskInfo.visible is shouldBeVisible(), whereas TaskInfo.isVisible is
        // a different actual framework field. Never equate or synthesize them.
        int leaves=0;
        for(ProfileTaskPolicy.Leaf leaf:global.leaves.values())if(leaf.parent==task.id){
            leaves++;
            String expected=task.orig!=null?task.orig:task.real;
            need(leaf.id==task.id&&leaf.display==display&&leaf.user==0
                    &&expected!=null&&expected.equals(leaf.name),"NOTES_ROOT_IS_NOT_PROVEN_SOLE_LEAF");
        }
        need(leaves==1,"NOTES_ROOT_IS_NOT_PROVEN_SOLE_LEAF");
    }
    ProfileTaskPolicy.Snapshot global()throws Exception{check();ProfileTaskPolicy.Snapshot value=BackgroundTaskOrganizer.profileSnapshot(activities);check();return value;}
    PublicOwnGroupPhysicalFence.RecentCensus recents()throws Exception{
        check();PublicOwnGroupPhysicalFence.RecentCensus value=PublicOwnGroupPhysicalFence.inspectRecents(BackgroundTaskOrganizer.profileRecents(deadline));check();return value;
    }
}
