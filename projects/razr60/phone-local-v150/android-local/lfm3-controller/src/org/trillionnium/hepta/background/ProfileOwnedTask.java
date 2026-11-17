package org.trillionnium.hepta.background;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * One new organizer root and one new profile app leaf. The root is only a container;
 * no launchTaskId/inTask bypass, existing-task reparent, global organizer or user switch is used.
 */
public final class ProfileOwnedTask {
    public interface Platform {
        ProfileTarget recheck(boolean requireReady)throws Exception;
        void guard()throws Exception;
        long now();
        Object newCookie();
        ProfileTaskPolicy.Snapshot snapshot()throws Exception;
        ProfileTaskPolicy.Recents recents()throws Exception;
        List<BackgroundOwnedSingleTask.Task> roots()throws Exception;
        List<BackgroundOwnedSingleTask.Task> children(Object token)throws Exception;
        void createRoot(Object cookie)throws Exception;
        void bindRoot(Object rootToken,Object launchCookie)throws Exception;
        void removeLeaf(Object token)throws Exception;
        boolean deleteRoot(Object token)throws Exception;
        void pause()throws Exception;
        default ProfilePermissionTransient.Proof permissionTransient(BackgroundOwnedSingleTask.Task root,
                BackgroundOwnedSingleTask.Task leaf)throws Exception{return null;}
    }
    private final Platform platform;
    private final ProfileTarget target;
    private final String generation,requestId;
    private final int display;
    private final Object rootCookie,launchCookie;
    private final Set<Integer> beforeIds=new LinkedHashSet<Integer>();
    private Map<Integer,ProfileTaskPolicy.Leaf> personal=Collections.emptyMap();
    private Map<String,Object> personalAudit=Collections.emptyMap();
    private volatile Map<String,Object> lastLeafValidation=Collections.emptyMap();
    private Map<String,Object> permissionEvidence=Collections.emptyMap();
    private BackgroundOwnedSingleTask.Task root,leaf;
    private String leafTokenId;
    private boolean rootAttempted,prepared,dispatchMarked,startAccepted,retiring,rootRemoved,leafRemoved;
    private boolean identityUnknown,foreignTasks,cleanupKnown,liveAbsent,recentsAbsent;
    private String recentsBeforeSha,recentsAfterSha;
    public ProfileOwnedTask(Platform platform,ProfileTarget target,String generation,String requestId,int display)throws Exception{
        need(platform!=null&&target!=null&&ProfileIdentity.uuid(generation)&&ProfileIdentity.uuid(requestId)&&display>0,
                "PROFILE_OWNED_ARGUMENTS_INVALID");
        this.platform=platform;this.target=target;this.generation=generation;this.requestId=requestId;this.display=display;
        rootCookie=platform.newCookie();launchCookie=platform.newCookie();
        need(rootCookie!=null&&launchCookie!=null&&!rootCookie.equals(launchCookie),"PROFILE_COOKIE_INVALID");
    }
    public synchronized void prepare()throws Exception{
        need(!rootAttempted&&!prepared,"PROFILE_LAUNCH_ALREADY_ATTEMPTED");
        platform.guard();actual(true);
        ProfileTaskPolicy.Snapshot before=platform.snapshot();before.requireDedicatedEmpty(target);
        ProfileTaskPolicy.Recents recents=platform.recents();recents.requireDedicatedEmpty(target);
        beforeIds.addAll(before.allIds);beforeIds.addAll(recents.ids);personal=before.personalTargets();
        personalAudit=before.personalAudit(personal);
        recentsBeforeSha=recents.sha256;
        need(checked(platform.roots()).isEmpty(),"PROFILE_DISPLAY_NOT_EMPTY");
        platform.guard();rootAttempted=true;platform.createRoot(rootCookie);
        List<BackgroundOwnedSingleTask.Task> roots=checked(platform.roots());
        need(roots.size()==1,"PROFILE_NEW_ROOT_NOT_UNIQUE");root=roots.get(0);
        requireRoot(root,false);
        need(!beforeIds.contains(root.id)&&checked(platform.children(root.token)).isEmpty(),"PROFILE_ROOT_PREEXISTED");
        requirePrepared();platform.guard();platform.bindRoot(root.token,launchCookie);prepared=true;
    }
    public synchronized void beforeDispatch()throws Exception{
        need(prepared&&!dispatchMarked&&!retiring,"PROFILE_LAUNCH_ALREADY_ATTEMPTED");
        platform.guard();actual(true);requirePrepared();
        platform.recents().requireDedicatedEmpty(target);platform.guard();dispatchMarked=true;
    }
    public synchronized void accepted(int result)throws Exception{
        need(dispatchMarked&&!startAccepted&&result==0,"PROFILE_START_NOT_FRESH_SUCCESS");startAccepted=true;
    }
    public synchronized boolean observe()throws Exception{
        need(startAccepted&&!retiring,"PROFILE_TASK_NOT_ACTIVE");
        return observeTree(true)!=null;
    }
    /** Read-only state coordination inside the caller's original request deadline.
     * A verified permission top is only a reason to read again, never a business
     * window or input grant. Ordinary observe/window and retirement stay separate. */
    public synchronized boolean observeStateUntil(long deadline)throws Exception{
        need(startAccepted&&!retiring,"PROFILE_TASK_NOT_ACTIVE");
        boolean permissionPending=false;
        while(true){
            platform.guard();
            need(platform.now()<deadline,permissionPending?"PROFILE_PERMISSION_SETUP_REQUIRED":"PROFILE_STATE_READ_DEADLINE");
            actual(true);
            need(platform.now()<deadline,permissionPending?"PROFILE_PERMISSION_SETUP_REQUIRED":"PROFILE_STATE_READ_DEADLINE");
            try{
                BackgroundOwnedSingleTask.Task current=observeTreeSample(true);
                platform.guard();
                need(platform.now()<deadline,"PROFILE_STATE_READ_DEADLINE");
                return current!=null;
            }catch(VerifiedPermissionPending pending){
                platform.guard();
                long now=platform.now();
                // The ordinary platform pause is 20 ms. Never start it without
                // room in this same deadline; a late return cannot become success.
                need(now<deadline&&deadline-now>20,"PROFILE_PERMISSION_SETUP_REQUIRED");
                permissionPending=true;platform.pause();
            }
        }
    }
    public synchronized WindowOwnership window(int windowId,int observedTaskId,long deadline)throws Exception{
        need(startAccepted&&!retiring&&windowId>=0&&observedTaskId>0,"PROFILE_WINDOW_REQUEST_INVALID");
        platform.guard();ProfileTarget fresh=actual(true);
        long at=platform.now();
        BackgroundOwnedSingleTask.Task current=observeTree(true);
        need(current!=null&&current.id==observedTaskId,"PROFILE_WINDOW_TASK_MISMATCH");
        platform.guard();need(platform.now()<deadline,"PROFILE_WINDOW_DEADLINE");
        return new WindowOwnership(fresh,generation,display,windowId,current.id,current.parent,
                leafTokenId,UUID.randomUUID().toString(),current.user,fresh.profile.serial,current.topUid,
                at,Math.min(deadline,at+10000));
    }
    public synchronized void retire(long deadline)throws Exception{
        need(!retiring,"PROFILE_RETIRE_ALREADY_ATTEMPTED");retiring=true;
        try{
            actual(false);
            if(!rootAttempted){
                platform.snapshot().requireDedicatedEmpty(target);platform.recents().requireDedicatedEmpty(target);
                need(checked(platform.roots()).isEmpty(),"PROFILE_FOREIGN_ROOT_ON_DISPLAY");
                liveAbsent=true;recentsAbsent=true;cleanupKnown=true;return;
            }
            need(root!=null,"PROFILE_ROOT_CREATE_UNRESOLVED");
            ProfileTaskPolicy.Snapshot global=platform.snapshot();personalAudit=global.personalAudit(personal);
            List<BackgroundOwnedSingleTask.Task> roots=checked(platform.roots());
            if(!roots.isEmpty()){
                need(roots.size()==1,"PROFILE_FOREIGN_ROOT_ON_DISPLAY");
                BackgroundOwnedSingleTask.Task currentRoot=roots.get(0);
                if(ProfilePermissionTransient.COMPONENT.equals(currentRoot.top))requireRootIdentity(currentRoot);
                else requireRoot(currentRoot,true);
                List<BackgroundOwnedSingleTask.Task> children=checked(platform.children(root.token));
                need(children.size()<=1,"PROFILE_FOREIGN_CHILD_TASK");
                if(!children.isEmpty()){
                    BackgroundOwnedSingleTask.Task candidate=children.get(0);
                    ProfilePermissionTransient.Proof permission=permissionForOwnedPair(currentRoot,candidate,global);
                    if(permission==null){requireRoot(currentRoot,true);requireLeaf(candidate,global);}
                    if(leaf==null){leaf=candidate;leafTokenId=UUID.randomUUID().toString();}
                    else need(sameTask(leaf,candidate),"PROFILE_LEAF_TOKEN_CHANGED");
                    global.requireOnlyOwned(target,display,root.id,leaf.id);
                    platform.recents().requireOnlyOwned(target,leaf.id);
                    if(permission!=null)permission.requireMatches(target,currentRoot,candidate,platform.now());
                    // Retained real WindowContainerToken only. No removal by arbitrary task ID.
                    platform.removeLeaf(leaf.token);leafRemoved=true;
                }else{
                    requireRoot(currentRoot,true);
                    global.requireDedicatedEmpty(target);
                    if(leaf!=null)need(!global.allIds.contains(leaf.id)&&!platform.recents().ids.contains(leaf.id),
                            "PROFILE_DETACHED_RECENT_LEAF_UNRESOLVED");
                }
                while(platform.now()<deadline){
                    actual(false);
                    ProfileTaskPolicy.Snapshot current=platform.snapshot();personalAudit=current.personalAudit(personal);
                    ProfileTaskPolicy.Recents recent=platform.recents();recentsAfterSha=recent.sha256;
                    recent.requireOnlyOwned(target,leaf==null?-1:leaf.id);
                    boolean noLeaf=(leaf==null||(!current.allIds.contains(leaf.id)&&!recent.ids.contains(leaf.id)));
                    if(noLeaf){
                        current.requireDedicatedEmpty(target);recent.requireDedicatedEmpty(target);
                        List<BackgroundOwnedSingleTask.Task> currentRoots=checked(platform.roots());
                        need(currentRoots.size()==1,"PROFILE_ROOT_CHANGED_DURING_RETIRE");
                        requireRoot(currentRoots.get(0),false);
                        need(checked(platform.children(root.token)).isEmpty(),"PROFILE_ROOT_CHILDREN_REMAIN");
                        need(platform.deleteRoot(root.token),"PROFILE_ROOT_DELETE_NOT_ACCEPTED");rootRemoved=true;break;
                    }
                    // Any unrelated profile leaf or task on this display vetoes further cleanup.
                    boolean liveLeafGone=leaf==null||!current.allIds.contains(leaf.id);
                    current.requireOnlyOwned(target,display,root.id,liveLeafGone?-1:leaf.id);
                    platform.pause();
                }
                need(rootRemoved,"PROFILE_LEAF_RETIRE_NOT_CONFIRMED");
            }else{
                need(!global.allIds.contains(root.id),"PROFILE_ROOT_MOVED_OUTSIDE_DISPLAY");
                if(leaf!=null)need(!global.allIds.contains(leaf.id),"PROFILE_LEAF_MOVED_OUTSIDE_DISPLAY");
            }
            while(platform.now()<deadline){
                if(absent())return;platform.pause();
            }
            need(false,"PROFILE_RETIRE_ABSENCE_UNCONFIRMED");
        }catch(Exception error){
            identityUnknown=true;
            if(error.getMessage()!=null&&error.getMessage().contains("FOREIGN"))foreignTasks=true;
            throw error;
        }
    }
    public synchronized boolean absent()throws Exception{
        if(identityUnknown||!retiring)return false;
        actual(false);ProfileTaskPolicy.Snapshot global=platform.snapshot();personalAudit=global.personalAudit(personal);
        ProfileTaskPolicy.Recents recent=platform.recents();recentsAfterSha=recent.sha256;
        global.requireDedicatedEmpty(target);recent.requireDedicatedEmpty(target);
        List<BackgroundOwnedSingleTask.Task> remaining=checked(platform.roots());
        if(!remaining.isEmpty()){
            need(rootRemoved&&remaining.size()==1,"PROFILE_FOREIGN_ROOT_ON_DISPLAY");
            requireRoot(remaining.get(0),false);
            need(checked(platform.children(root.token)).isEmpty(),"PROFILE_FOREIGN_CHILD_TASK");
            return false;
        }
        liveAbsent=(root==null||!global.allIds.contains(root.id))&&(leaf==null||!global.allIds.contains(leaf.id));
        recentsAbsent=(root==null||!recent.ids.contains(root.id))&&(leaf==null||!recent.ids.contains(leaf.id));
        cleanupKnown=liveAbsent&&recentsAbsent&&(!dispatchMarked||leaf!=null);
        return cleanupKnown;
    }
    public synchronized boolean cleanupKnown(){return cleanupKnown&&!identityUnknown&&!foreignTasks;}
    public synchronized boolean started(){return dispatchMarked;}
    public synchronized Map<String,Object> personalAudit(){return personalAudit;}
    /** Diagnostic readback only; neither serialized identifiers nor these booleans grant authority. */
    public Map<String,Object> lastLeafValidation(){return lastLeafValidation;}
    public synchronized Map<String,Object> cleanupEvidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema","hepta.profile-task-cleanup.v1");out.put("generation",generation);out.put("display_id",display);
        out.put("target_sha256",target.sha256);out.put("user_id",target.profile.userId);out.put("user_serial",target.profile.serial);
        out.put("full_uid",target.fullUid);out.put("cleanup_known",cleanupKnown());out.put("live_tasks_absent",liveAbsent);
        out.put("recents_tasks_absent",recentsAbsent);out.put("foreign_tasks_present",foreignTasks);out.put("identity_unknown",identityUnknown);
        List<Map<String,Object>> owned=new ArrayList<Map<String,Object>>();
        if(leaf!=null){
            Map<String,Object> item=new LinkedHashMap<String,Object>();item.put("task_id",leaf.id);item.put("parent_task_id",leaf.parent);
            item.put("task_token_id",leafTokenId);item.put("user_id",leaf.user);item.put("user_serial",target.profile.serial);
            item.put("full_uid",leaf.uid);item.put("live_absent",liveAbsent);item.put("recents_absent",recentsAbsent);owned.add(item);
        }
        out.put("owned_tasks",owned);return Collections.unmodifiableMap(out);
    }
    public synchronized Map<String,Object> evidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema","hepta.profile-owned-task.v1");out.put("generation",generation);out.put("request_id",requestId);
        out.put("target_sha256",target.sha256);out.put("display_id",display);out.put("prepared",prepared);
        out.put("dispatch_marked",dispatchMarked);out.put("start_fresh_success",startAccepted);
        out.put("root_create_attempted",rootAttempted);out.put("root_task_id",root==null?null:root.id);
        out.put("leaf_task_id",leaf==null?null:leaf.id);out.put("leaf_token_id",leafTokenId);
        out.put("root_removal_requested",rootRemoved);out.put("leaf_removal_requested",leafRemoved);
        out.put("recents_before_sha256",recentsBeforeSha);out.put("recents_after_sha256",recentsAfterSha);
        out.put("launch_task_id_override",false);out.put("preexisting_task_reparented",false);
        out.put("default_cross_profile_filters_modified",false);out.put("serialized_token_is_authority",false);
        out.put("personal_task_audit",personalAudit);
        out.put("last_leaf_validation",lastLeafValidation);
        out.put("permission_transient",permissionEvidence);
        out.put("cleanup",cleanupEvidence());return Collections.unmodifiableMap(out);
    }
    private ProfileTarget actual(boolean ready)throws Exception{
        ProfileTarget actual=platform.recheck(ready);
        need(target.same(actual),"PROFILE_INSTALLATION_IDENTITY_CHANGED");return actual;
    }
    private void requirePrepared()throws Exception{
        ProfileTaskPolicy.Snapshot global=platform.snapshot();
        global.requireDedicatedEmpty(target);personalAudit=global.personalAudit(personal);
        List<BackgroundOwnedSingleTask.Task> roots=checked(platform.roots());
        need(roots.size()==1,"PROFILE_PREPARED_ROOT_CHANGED");requireRoot(roots.get(0),false);
        need(checked(platform.children(root.token)).isEmpty(),"PROFILE_PREPARED_ROOT_NOT_EMPTY");
        global.requireOnlyOwned(target,display,root.id,-1);
    }
    private static final class VerifiedPermissionPending extends Exception {
        private static final long serialVersionUID=1L;
        private VerifiedPermissionPending(){}
    }
    private BackgroundOwnedSingleTask.Task observeTree(boolean visible)throws Exception{
        try{return observeTreeSample(visible);}
        catch(VerifiedPermissionPending pending){throw new ProfileTaskPolicy.Refusal("PROFILE_PERMISSION_SETUP_REQUIRED");}
    }
    private BackgroundOwnedSingleTask.Task observeTreeSample(boolean visible)throws Exception{
        ProfileTaskPolicy.Snapshot global=platform.snapshot();personalAudit=global.personalAudit(personal);
        List<BackgroundOwnedSingleTask.Task> roots=checked(platform.roots());
        need(roots.size()==1,"PROFILE_DISPLAY_ROOT_CHANGED");
        if(ProfilePermissionTransient.COMPONENT.equals(roots.get(0).top)){
            // A verified permission transient can retain ownership, never a business window.
            requireRootIdentity(roots.get(0));
            List<BackgroundOwnedSingleTask.Task> permissionChildren=checked(platform.children(root.token));
            need(permissionChildren.size()==1,"PROFILE_FOREIGN_CHILD_TASK");
            BackgroundOwnedSingleTask.Task candidate=permissionChildren.get(0);
            ProfilePermissionTransient.Proof permission=permissionForOwnedPair(roots.get(0),candidate,global);
            need(permission!=null,"PROFILE_ROOT_FOREIGN_ACTIVITY");
            if(leaf==null){leaf=candidate;leafTokenId=UUID.randomUUID().toString();}
            else need(sameTask(leaf,candidate),"PROFILE_LEAF_TOKEN_CHANGED");
            global.requireOnlyOwned(target,display,root.id,candidate.id);
            throw new VerifiedPermissionPending();
        }
        requireRoot(roots.get(0),true);
        List<BackgroundOwnedSingleTask.Task> children=checked(platform.children(root.token));
        need(children.size()<=1,"PROFILE_FOREIGN_CHILD_TASK");
        if(children.isEmpty()){
            need(leaf==null,"PROFILE_OWNED_LEAF_DISAPPEARED");
            global.requireOnlyOwned(target,display,root.id,-1);return null;
        }
        BackgroundOwnedSingleTask.Task candidate=children.get(0);requireLeaf(candidate,global);
        if(leaf==null){leaf=candidate;leafTokenId=UUID.randomUUID().toString();}
        else need(sameTask(leaf,candidate),"PROFILE_LEAF_TOKEN_CHANGED");
        global.requireOnlyOwned(target,display,root.id,candidate.id);
        if(visible&&(!candidate.running||!candidate.visible||candidate.activities<1))return null;
        return candidate;
    }
    private void requireRoot(BackgroundOwnedSingleTask.Task current,boolean mayHaveActivities)throws Exception{
        requireRootIdentity(current);
        if(!mayHaveActivities)need(current.activities==0&&!current.running&&!current.visible
                &&current.base==null&&current.top==null&&current.topUid==-1,"PROFILE_ROOT_NOT_EMPTY");
        else need((current.base==null||inPackage(current.base))&&(current.top==null||inPackage(current.top))
                &&(current.topUid==-1||current.topUid==target.fullUid),"PROFILE_ROOT_FOREIGN_ACTIVITY");
    }
    private void requireRootIdentity(BackgroundOwnedSingleTask.Task current)throws Exception{
        need(current!=null&&current.id>0&&current.token!=null&&current.display==display&&current.user==0
                &&current.parent==-1&&current.cookies.contains(rootCookie)&&current.intentComponent==null
                &&current.real==null&&current.orig==null,"PROFILE_ROOT_IDENTITY_CHANGED");
        if(root!=null)need(sameTask(root,current)&&root.uid==current.uid,"PROFILE_ROOT_TOKEN_CHANGED");
    }
    private void requireLeaf(BackgroundOwnedSingleTask.Task current,ProfileTaskPolicy.Snapshot global)throws Exception{
        requireLeaf(current,global,null,null);
    }
    private void requireLeaf(BackgroundOwnedSingleTask.Task current,ProfileTaskPolicy.Snapshot global,
            BackgroundOwnedSingleTask.Task currentRoot,ProfilePermissionTransient.Proof permission)throws Exception{
        // Typed fresh proof is the sole exception for a permission top; every stable identity
        // and retained-Binder rule below is the upstream validator, including its diagnostics.
        if(permission!=null)permission.requireMatches(target,currentRoot,current,platform.now());
        final boolean retained=leaf!=null;
        final boolean cookiePresent=current!=null&&current.cookies.contains(launchCookie);
        Map<String,Boolean> checks=new LinkedHashMap<String,Boolean>();
        checks.put("dispatch_marked",dispatchMarked);
        checks.put("task_info_present",current!=null);
        checks.put("task_id_positive",current!=null&&current.id>0);
        checks.put("task_id_differs_from_root",current!=null&&current.id!=root.id);
        checks.put("task_id_absent_before_launch",current!=null&&!beforeIds.contains(current.id));
        checks.put("actual_task_token_present",current!=null&&current.token!=null);
        checks.put("actual_task_token_differs_from_root",current!=null&&current.token!=null&&!root.token.equals(current.token));
        checks.put("display_matches",current!=null&&current.display==display);
        checks.put("user_matches",current!=null&&current.user==target.profile.userId);
        checks.put("parent_matches",current!=null&&current.parent==root.id);
        checks.put("full_uid_matches",current!=null&&current.uid==target.fullUid);
        checks.put("top_activity_info_uid_matches",current!=null&&current.topUid==target.fullUid);
        // Activity launch cookies are admission proof, not a durable Task identity. Once claimed,
        // only the retained actual token and exact task tuple can authorize another observation.
        // The retained leaf is never cleared or replaced, including after disappearance/refusal.
        checks.put("first_claim_launch_cookie",retained||cookiePresent);
        checks.put("intent_package_matches",current!=null&&inPackage(current.intentComponent));
        checks.put("base_package_matches",current!=null&&inPackage(current.base));
        checks.put("top_package_matches",current!=null&&inPackage(current.top));
        checks.put("real_package_matches",current!=null&&inPackage(current.real));
        checks.put("orig_package_matches",current!=null&&(current.orig==null||inPackage(current.orig)));
        boolean identity=true;
        for(Map.Entry<String,Boolean> check:checks.entrySet()){
            boolean provedPermissionTop=permission!=null&&("top_activity_info_uid_matches".equals(check.getKey())
                    ||"top_package_matches".equals(check.getKey()));
            if(!provedPermissionTop)identity&=check.getValue();
        }
        boolean retainedIdentity=!retained||sameTask(leaf,current);
        ProfileTaskPolicy.Leaf actual=global.leaves.get(current==null?-1:current.id);
        boolean complete=actual!=null&&current!=null&&actual.user==current.user
                &&actual.parent==root.id&&actual.display==display;
        String refusal=!identity?"PROFILE_NEW_LEAF_NOT_PROVEN":!retainedIdentity?"PROFILE_LEAF_TOKEN_CHANGED"
                :!complete?"PROFILE_LEAF_NOT_IN_COMPLETE_GLOBAL_SNAPSHOT":null;
        Map<String,Object> detail=new LinkedHashMap<String,Object>();
        detail.put("schema","hepta.profile-leaf-validation.v1");detail.put("observed_elapsed_ms",platform.now());
        detail.put("phase",retained?"retained_leaf":"first_claim");detail.put("valid",refusal==null);
        detail.put("refusal_code",refusal);detail.put("launch_cookie_present",cookiePresent);
        detail.put("retained_task_id",retained?leaf.id:null);
        detail.put("actual_task_token_equal_to_retained",retained&&current!=null?Objects.equals(leaf.token,current.token):null);
        detail.put("retained_task_identity_matches",retained?retainedIdentity:null);
        detail.put("complete_global_leaf_matches",complete);detail.put("checks",Collections.unmodifiableMap(checks));
        detail.put("observed_task_id",current==null?null:current.id);
        detail.put("observed_parent_id",current==null?null:current.parent);
        detail.put("observed_display_id",current==null?null:current.display);
        detail.put("observed_user_id",current==null?null:current.user);
        detail.put("observed_full_uid",current==null?null:current.uid);
        detail.put("observed_top_activity_info_uid",current==null?null:current.topUid);
        detail.put("serialized_token_is_authority",false);
        if(permission!=null){
            // Keep the actual target-top check values false; this is cleanup ownership only.
            detail.put("permission_transient_verified",true);detail.put("business_observation_allowed",false);
            detail.put("permission_input_allowed",false);detail.put("retirement_only",true);
        }
        lastLeafValidation=Collections.unmodifiableMap(detail);
        need(refusal==null,refusal);
    }
    private void requirePermissionLeafIdentity(BackgroundOwnedSingleTask.Task current,
            ProfileTaskPolicy.Snapshot global)throws Exception{
        // Read-only proof admission. A first claim still needs its own launch cookie; an
        // already retained leaf uses its exact actual Binder/tuple and is never re-claimed.
        need(dispatchMarked&&current!=null&&current.id>0&&current.id!=root.id&&!beforeIds.contains(current.id)
                &&current.token!=null&&!root.token.equals(current.token)&&current.display==display
                &&current.user==target.profile.userId&&current.parent==root.id&&current.uid==target.fullUid
                &&(leaf!=null||current.cookies.contains(launchCookie))
                &&inPackage(current.intentComponent)&&inPackage(current.base)
                &&inPackage(current.real)&&(current.orig==null||inPackage(current.orig)),"PROFILE_NEW_LEAF_NOT_PROVEN");
        if(leaf!=null)need(sameTask(leaf,current),"PROFILE_LEAF_TOKEN_CHANGED");
        ProfileTaskPolicy.Leaf actual=global.leaves.get(current.id);
        need(actual!=null&&actual.user==current.user&&actual.parent==root.id&&actual.display==display,
                "PROFILE_LEAF_NOT_IN_COMPLETE_GLOBAL_SNAPSHOT");
    }
    private ProfilePermissionTransient.Proof permissionForOwnedPair(BackgroundOwnedSingleTask.Task currentRoot,
            BackgroundOwnedSingleTask.Task candidate,ProfileTaskPolicy.Snapshot global)throws Exception{
        // A lone foreign leaf top remains an ordinary upstream refusal, including its error code.
        if(!ProfilePermissionTransient.COMPONENT.equals(currentRoot.top)
                ||!ProfilePermissionTransient.COMPONENT.equals(candidate.top))return null;
        requireRootIdentity(currentRoot);requirePermissionLeafIdentity(candidate,global);
        need((currentRoot.base==null||inPackage(currentRoot.base))
                &&currentRoot.topUid==candidate.topUid&&candidate.topUid/100000==target.profile.userId,
                "PROFILE_ROOT_FOREIGN_ACTIVITY");
        global.requireOnlyOwned(target,display,root.id,candidate.id);
        ProfilePermissionTransient.Proof proof=platform.permissionTransient(currentRoot,candidate);
        need(proof!=null,"PROFILE_PERMISSION_PROOF_UNAVAILABLE");
        requireLeaf(candidate,global,currentRoot,proof);
        permissionEvidence=proof.evidence();return proof;
    }
    private static List<BackgroundOwnedSingleTask.Task> checked(List<BackgroundOwnedSingleTask.Task> rows)throws Exception{
        need(rows!=null&&rows.size()<=2048,"PROFILE_TASK_QUERY_INCOMPLETE");
        Set<Integer> ids=new HashSet<Integer>();Set<Object> tokens=new HashSet<Object>();
        for(BackgroundOwnedSingleTask.Task row:rows)need(row!=null&&row.id>0&&row.token!=null
                &&row.activities>=0&&row.activities<=2048&&ids.add(row.id)&&tokens.add(row.token),"PROFILE_TASK_QUERY_INVALID");
        return rows;
    }
    private static boolean sameTask(BackgroundOwnedSingleTask.Task a,BackgroundOwnedSingleTask.Task b){
        return a!=null&&b!=null&&a.id==b.id&&a.user==b.user&&a.parent==b.parent&&a.display==b.display&&Objects.equals(a.token,b.token);
    }
    private boolean inPackage(String component){return component!=null&&component.startsWith(target.packageName+"/");}
    private static void need(boolean value,String reason)throws ProfileTaskPolicy.Refusal{ProfileTaskPolicy.need(value,reason);}
}
