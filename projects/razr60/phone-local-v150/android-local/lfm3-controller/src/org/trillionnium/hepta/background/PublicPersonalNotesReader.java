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
    private static final class CensusChanged extends IOException {
        private static final long serialVersionUID=1L;
        final Map<String,Object> evidence;
        CensusChanged(String code,String stage,int attempt,int display,Map<Integer,BackgroundOwnedSingleTask.Task> previous,
                Map<Integer,BackgroundOwnedSingleTask.Task> first,
                Map<Integer,BackgroundOwnedSingleTask.Task> middle,Map<Integer,BackgroundOwnedSingleTask.Task> last){
            super(code);
            Map<String,Object> value=new LinkedHashMap<String,Object>();
            value.put("schema","hepta.notes-root-census-refusal.v1");value.put("stage",stage);
            value.put("reason",code);value.put("sample_attempt",attempt);value.put("expected_display_id",display);
            value.put("previously_pinned_ids",previous==null?JSONObject.NULL:new ArrayList<Integer>(previous.keySet()));
            value.put("before_all_roots",rows(first));value.put("owned_display_roots",rows(middle));value.put("after_all_roots",rows(last));
            value.put("diagnostics_grant_authority",false);evidence=Collections.unmodifiableMap(value);
        }
        private static List<Map<String,Object>> rows(Map<Integer,BackgroundOwnedSingleTask.Task> tasks){
            List<Map<String,Object>> result=new ArrayList<Map<String,Object>>();
            for(BackgroundOwnedSingleTask.Task t:tasks.values()){
                Map<String,Object> row=new LinkedHashMap<String,Object>();
                row.put("task_id",t.id);row.put("user_id",t.user);row.put("display_id",t.display);row.put("effective_uid",t.uid);
                row.put("token_identity_in_reader",System.identityHashCode(t.token));row.put("launch_cookie_count",t.cookies.size());
                result.add(Collections.unmodifiableMap(row));
            }
            return Collections.unmodifiableList(result);
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
            out.put("actual_root_read_failure",error instanceof TaskInfoReadFailure?((TaskInfoReadFailure)error).evidence:
                    error instanceof CensusChanged?((CensusChanged)error).evidence:JSONObject.NULL);
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
    synchronized PublicPersonalNotesCustody.Frame frame()throws Exception{return frame(null);}
    synchronized PublicPersonalNotesCustody.Frame frame(PublicPersonalNotesCustody custody)throws Exception{
        long begin=SystemClock.elapsedRealtime();check();
        // Ordinary Intent-created Notes roots are not organizer-created containers.
        // Android 16 getChildTasks() returns null for such tasks; null is not an
        // empty-child proof. Use two complete independent ATM leaf censuses around
        // the real organizer root TaskInfo query, without ever calling children().
        Map<Integer,BackgroundOwnedSingleTask.Task> identities=null;
        BackgroundOwnedSingleTask.Task firstRoot=null;
        for(int attempt=1;attempt<=MAX_TASKINFO_SAMPLES;attempt++){
            check();need(SystemClock.elapsedRealtime()-begin<=MAX_FRAME_MS,"NOTES_TASK_FRAME_INVALID");
            BackgroundTaskOrganizer.ReadOnlyRootCensus before=reader.readOnlyRootCensus();
            List<BackgroundOwnedSingleTask.Task> actual=reader.roots();
            BackgroundTaskOrganizer.ReadOnlyRootCensus after=reader.readOnlyRootCensus();
            Map<Integer,BackgroundOwnedSingleTask.Task> first=index(before.displayRoots,"before_all_roots");
            Map<Integer,BackgroundOwnedSingleTask.Task> middle=index(actual,"owned_display_roots"),last=index(after.displayRoots,"after_all_roots");
            if(!first.keySet().equals(middle.keySet())||!middle.keySet().equals(last.keySet())){
                // Discard one complete bootstrap triple only for empty -> one new root.
                if(custody==null||attempt!=1||!first.isEmpty()||last.size()!=1
                        ||(!middle.isEmpty()&&!middle.keySet().equals(last.keySet())))
                    throw new CensusChanged("NOTES_ROOT_CENSUS_CHANGED","within_sample",attempt,display,identities,first,middle,last);
                BackgroundOwnedSingleTask.Task candidate=last.values().iterator().next();
                try{requireBootstrapCensus(before.global,candidate,false);requireBootstrapCensus(after.global,candidate,true);}
                catch(IOException conflict){
                    throw new CensusChanged(conflict.getMessage(),"bootstrap_global_census",attempt,display,identities,first,middle,last);
                }
                if(!middle.isEmpty())sameIdentity(middle.get(candidate.id),candidate,"bootstrap_first_token",attempt);
                if(!custody.claimFirstRootRead(candidate,display,uid,SystemClock.elapsedRealtime()))
                    throw new CensusChanged("NOTES_ROOT_CENSUS_CHANGED","bootstrap_unavailable",attempt,display,identities,first,middle,last);
                identities=last;firstRoot=candidate;
                check();need(SystemClock.elapsedRealtime()-begin<=MAX_FRAME_MS,"NOTES_TASK_FRAME_INVALID");
                Thread.sleep(20);continue;
            }
            if(identities==null)identities=first;
            if(!identities.keySet().equals(first.keySet()))
                throw new CensusChanged("NOTES_ROOT_CENSUS_CHANGED","between_samples",attempt,display,identities,first,middle,last);
            if(firstRoot!=null){
                need(custody.firstRootReadActive(firstRoot,display,uid,SystemClock.elapsedRealtime()),"NOTES_BOOTSTRAP_RETIRED");
                requireBootstrapCensus(before.global,first.get(firstRoot.id),true);
                requireBootstrapCensus(after.global,last.get(firstRoot.id),true);
            }
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
                if(firstRoot!=null)need(custody.firstRootReadActive(firstRoot,display,uid,SystemClock.elapsedRealtime()),"NOTES_BOOTSTRAP_RETIRED");
                return new PublicPersonalNotesCustody.Frame(after.global,nodes,begin,SystemClock.elapsedRealtime());
            }catch(ActivityStateChanged changed){
                if(attempt==MAX_TASKINFO_SAMPLES)throw changed;
                check();need(SystemClock.elapsedRealtime()-begin<=MAX_FRAME_MS,"NOTES_TASK_FRAME_INVALID");
                Thread.sleep(20);
            }
        }
        throw new IOException("NOTES_ROOT_TASKINFO_CHANGED");
    }
    private void requireBootstrapCensus(ProfileTaskPolicy.Snapshot census,BackgroundOwnedSingleTask.Task task,boolean present)throws Exception{
        need(census!=null,"NOTES_GLOBAL_CENSUS_UNAVAILABLE");
        int roots=0,leaves=0;
        for(ProfileTaskPolicy.Root root:census.roots){
            if(root.display==display){roots++;need(present&&root.id==task.id,"NOTES_BOOTSTRAP_GLOBAL_CONFLICT");}
            else need(root.id!=task.id&&!inPackage(root.base)&&!inPackage(root.top),"NOTES_BOOTSTRAP_GLOBAL_CONFLICT");
        }
        for(ProfileTaskPolicy.Leaf leaf:census.leaves.values()){
            if(leaf.display==display){leaves++;need(present&&leaf.id==task.id&&leaf.parent==task.id,"NOTES_BOOTSTRAP_GLOBAL_CONFLICT");}
            else need(leaf.id!=task.id&&leaf.parent!=task.id&&!inPackage(leaf.name),"NOTES_BOOTSTRAP_GLOBAL_CONFLICT");
        }
        need(roots==(present?1:0)&&leaves==roots,"NOTES_BOOTSTRAP_GLOBAL_CONFLICT");
        if(present)requireSoleLeaf(census,task);
    }
    /** Post-release sampling keeps the actual custody snapshot. Missing display
     * organizer calls are never made, and no failed/partial read becomes absence.
     * Only disappearance of these same retained tasks may discard a whole triple;
     * the original budget remains fixed and cleanup still needs two full absences. */
    synchronized PublicPersonalNotesCustody.Frame frameAfterRelease(PublicPersonalNotesCustody.ReleasedRead released)throws Exception{
        long begin=SystemClock.elapsedRealtime();check();
        need(released!=null,"NOTES_RELEASED_READ_UNAVAILABLE");released.requireScope(display,uid);
        java.util.Set<Integer> remaining=null;
        for(int attempt=1;attempt<=MAX_TASKINFO_SAMPLES;attempt++){
            check();need(SystemClock.elapsedRealtime()-begin<=MAX_FRAME_MS,"NOTES_TASK_FRAME_INVALID");
            BackgroundTaskOrganizer.ReadOnlyRootCensus before=reader.readOnlyRootCensus();
            BackgroundTaskOrganizer.ReadOnlyRootCensus middleCensus=reader.readOnlyRootCensus();
            BackgroundTaskOrganizer.ReadOnlyRootCensus after=reader.readOnlyRootCensus();
            Map<Integer,BackgroundOwnedSingleTask.Task> first=releasedIndex(before,released,"released_before",attempt);
            Map<Integer,BackgroundOwnedSingleTask.Task> middle=releasedIndex(middleCensus,released,"released_middle",attempt);
            Map<Integer,BackgroundOwnedSingleTask.Task> last=releasedIndex(after,released,"released_after",attempt);
            need(first.keySet().containsAll(middle.keySet())&&middle.keySet().containsAll(last.keySet())
                    &&(remaining==null||remaining.containsAll(first.keySet())),"NOTES_ROOT_CENSUS_CHANGED");
            boolean shrinking=!first.keySet().equals(middle.keySet())||!middle.keySet().equals(last.keySet())
                    ||(remaining!=null&&!remaining.equals(first.keySet()));
            remaining=new java.util.LinkedHashSet<Integer>(last.keySet());
            if(shrinking){
                need(attempt<MAX_TASKINFO_SAMPLES,"NOTES_ROOT_CENSUS_CHANGED");
                check();need(SystemClock.elapsedRealtime()-begin<=MAX_FRAME_MS,"NOTES_TASK_FRAME_INVALID");
                Thread.sleep(20);continue;
            }
            try{
                List<PublicPersonalNotesCustody.Node> nodes=new ArrayList<PublicPersonalNotesCustody.Node>();
                for(BackgroundOwnedSingleTask.Task task:middle.values()){
                    sameActualTask(first.get(task.id),task,"before_vs_global_middle",attempt);
                    sameActualTask(task,last.get(task.id),"global_middle_vs_after",attempt);
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
    private Map<Integer,BackgroundOwnedSingleTask.Task> releasedIndex(BackgroundTaskOrganizer.ReadOnlyRootCensus census,
            PublicPersonalNotesCustody.ReleasedRead released,String stage,int attempt)throws Exception{
        need(census!=null&&census.global!=null,"NOTES_GLOBAL_CENSUS_UNAVAILABLE");
        released.requireGlobal(census.global);
        Map<Integer,BackgroundOwnedSingleTask.Task> rows=index(census.displayRoots,stage);
        for(BackgroundOwnedSingleTask.Task task:rows.values()){
            sameIdentity(released.retained(task.id),task,stage,attempt);
            requireSoleLeaf(census.global,task);
        }
        return rows;
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
