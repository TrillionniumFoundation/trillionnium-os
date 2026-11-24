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
        default String publicRecentsDump()throws Exception{throw new IllegalStateException("PUBLIC_HISTORY_PLATFORM_UNAVAILABLE");}
        List<BackgroundOwnedSingleTask.Task> roots()throws Exception;
        List<BackgroundOwnedSingleTask.Task> children(Object token)throws Exception;
        void createRoot(Object cookie)throws Exception;
        void bindRoot(Object rootToken,Object launchCookie)throws Exception;
        void removeLeaf(Object token)throws Exception;
        boolean deleteRoot(Object token)throws Exception;
        void pause()throws Exception;
        default Map<String,Object> permissionReadMismatchEvidence(){return Collections.emptyMap();}
        default ProfilePermissionTransient.Proof permissionTransient(BackgroundOwnedSingleTask.Task root,
                BackgroundOwnedSingleTask.Task leaf)throws Exception{return null;}
    }
    /** Package-local public-mode observation seam. The default private path has
     * no dependency on public recents/JSON adapters and retains its strict gate. */
    interface PublicRecentHistory {
        void observe(String raw,ProfileTarget target,BackgroundOwnedSingleTask.Task root,
                BackgroundOwnedSingleTask.Task leaf,int display,long elapsed)throws Exception;
        Set<Integer> observedIds();
        Map<String,Object> evidence();
        default RetainedRecentHistory beginRetainedCleanup(String raw,ProfileTarget target,
                BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf,int display,long elapsed)throws Exception{
            throw new IllegalStateException("PROFILE_RETAINED_HISTORY_UNAVAILABLE");
        }
    }
    /** Fresh cleanup observations have their own baseline; the business latch is never reset. */
    interface RetainedRecentHistory {
        void observe(String raw,long elapsed)throws Exception;
        Set<Integer> observedIds();
        Map<String,Object> evidence();
    }
    private final Platform platform;
    private final ProfileTarget target;
    private final PublicRecentHistory publicHistory;
    private final String generation,requestId;
    private final int display;
    private final Object rootCookie,launchCookie;
    private final Set<Integer> beforeIds=new LinkedHashSet<Integer>();
    private Map<Integer,ProfileTaskPolicy.Leaf> personal=Collections.emptyMap();
    private Map<String,Object> personalAudit=Collections.emptyMap();
    private volatile Map<String,Object> lastLeafValidation=Collections.emptyMap();
    private volatile Map<String,Object> firstRootRefusal=Collections.emptyMap();
    private Map<String,Object> permissionEvidence=Collections.emptyMap();
    private BackgroundOwnedSingleTask.Task root,leaf;
    private String leafTokenId;
    private boolean rootAttempted,prepared,dispatchMarked,startAccepted,retiring,rootRemoved,leafRemoved;
    private boolean identityUnknown,foreignTasks,cleanupKnown,liveAbsent,recentsAbsent;
    private boolean retainedReleaseChecked,rootDeleteAttempted,leafRemoveAttempted,retainedCleanupClaimed;
    private String recentsBeforeSha,recentsAfterSha;
    public ProfileOwnedTask(Platform platform,ProfileTarget target,String generation,String requestId,int display)throws Exception{
        this(platform,target,generation,requestId,display,null);
    }
    public ProfileOwnedTask(Platform platform,ProfileTarget target,String generation,String requestId,int display,
            PublicRecentHistory publicHistory)throws Exception{
        need(platform!=null&&target!=null&&ProfileIdentity.uuid(generation)&&ProfileIdentity.uuid(requestId)&&display>0,
                "PROFILE_OWNED_ARGUMENTS_INVALID");
        this.platform=platform;this.target=target;this.generation=generation;this.requestId=requestId;this.display=display;
        this.publicHistory=publicHistory;need(publicHistory==null||display>1,"PUBLIC_HISTORY_DISPLAY_INVALID");
        rootCookie=platform.newCookie();launchCookie=platform.newCookie();
        need(rootCookie!=null&&launchCookie!=null&&!rootCookie.equals(launchCookie),"PROFILE_COOKIE_INVALID");
    }
    public synchronized void prepare()throws Exception{
        need(!rootAttempted&&!prepared,"PROFILE_LAUNCH_ALREADY_ATTEMPTED");
        platform.guard();actual(true);
        ProfileTaskPolicy.Snapshot before=platform.snapshot();before.requireDedicatedEmpty(target);
        ProfileTaskPolicy.Recents recents=readRecents();requireRecentEmpty(recents);
        beforeIds.addAll(before.allIds);beforeIds.addAll(recentIds(recents));personal=before.personalTargets(target);
        personalAudit=before.personalAudit(target,personal);
        recentsBeforeSha=recents.sha256;
        need(checked(platform.roots()).isEmpty(),"PROFILE_DISPLAY_NOT_EMPTY");
        platform.guard();if(publicHistory!=null)requireRecentEmpty(readRecents());rootAttempted=true;platform.createRoot(rootCookie);
        List<BackgroundOwnedSingleTask.Task> roots=checked(platform.roots());
        need(roots.size()==1,"PROFILE_NEW_ROOT_NOT_UNIQUE");root=roots.get(0);
        requireRoot(root,false);
        need(!beforeIds.contains(root.id)&&checked(platform.children(root.token)).isEmpty(),"PROFILE_ROOT_PREEXISTED");
        requirePrepared();platform.guard();if(publicHistory!=null)requireRecentEmpty(readRecents());platform.bindRoot(root.token,launchCookie);prepared=true;
    }
    public synchronized void beforeDispatch()throws Exception{
        need(prepared&&!dispatchMarked&&!retiring,"PROFILE_LAUNCH_ALREADY_ATTEMPTED");
        platform.guard();actual(true);requirePrepared();
        requireRecentEmpty(readRecents());platform.guard();dispatchMarked=true;
    }
    public synchronized void accepted(int result)throws Exception{
        need(dispatchMarked&&!startAccepted&&result==0,"PROFILE_START_NOT_FRESH_SUCCESS");startAccepted=true;
    }
    public synchronized boolean observe()throws Exception{
        need(startAccepted&&!retiring,"PROFILE_TASK_NOT_ACTIVE");
        return observeTree(true)!=null;
    }
    /** A separate owner-only preparation state. The private marker is created
     * only after the original complete permission proof; no text/error matching.
     * Ordinary observe/window never accept a permission top. */
    public synchronized String initializationState(long deadline)throws Exception{
        need(startAccepted&&!retiring,"PROFILE_TASK_NOT_ACTIVE");platform.guard();actual(true);
        need(platform.now()<deadline,"PROFILE_PERMISSION_READ_DEADLINE");
        String result;
        try{result=observeStateSample(true,deadline,"PROFILE_PERMISSION_READ_DEADLINE")==null?"WAITING":"APP_READY";}
        catch(VerifiedPermissionPending pending){result="PERMISSION_PENDING";}
        platform.guard();need(platform.now()<deadline,"PROFILE_PERMISSION_READ_DEADLINE");return result;
    }
    /** Read-only final preparation confirmation. Only an exact, already owned
     * permission-to-target transition may discard one mixed sample. It grants no
     * permission/window/input authority; the replacement graph is read in full. */
    public synchronized boolean confirmInitializationReady(long deadline)throws Exception{
        need(startAccepted&&!retiring,"PROFILE_TASK_NOT_ACTIVE");
        platform.guard();actual(true);need(platform.now()<deadline,"PROFILE_PERMISSION_READ_DEADLINE");
        BackgroundOwnedSingleTask.Task current;
        try{
            try{current=observeTreeSample(true);}
            catch(ProfilePermissionTransient.ReadChanged changed){
                ProfilePermissionTransient.ReadChanged pinned=changed.readyConfirmationExit(target);
                requireRootIdentity(pinned.exitedRoot);requireRootIdentity(pinned.root);
                need(leaf!=null&&sameTask(leaf,pinned.exitedLeaf)&&sameTask(leaf,pinned.leaf)
                        &&pinned.exitedLeaf.uid==target.fullUid&&pinned.leaf.uid==target.fullUid,
                        "PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ");
                platform.guard();actual(true);long now=platform.now();
                need(now<deadline&&deadline-now>20,"PROFILE_PERMISSION_READ_DEADLINE");
                platform.pause();platform.guard();actual(true);
                need(platform.now()<deadline,"PROFILE_PERMISSION_READ_DEADLINE");
                // No second retry: every field of the complete after-pair must
                // still match, followed by the normal global/recents/leaf checks.
                current=observeTreeSample(true,pinned);
            }
        }catch(VerifiedPermissionPending pending){
            platform.guard();actual(true);need(platform.now()<deadline,"PROFILE_PERMISSION_READ_DEADLINE");
            ProfileTaskPolicy.Refusal refused=new ProfileTaskPolicy.Refusal("PROFILE_PERMISSION_SETUP_REQUIRED");
            refused.initCause(pending);throw refused;
        }
        platform.guard();actual(true);need(platform.now()<deadline,"PROFILE_PERMISSION_READ_DEADLINE");
        return current!=null;
    }
    /** Only an actual complete retained-task permission observation carries this private cause. */
    public static boolean verifiedPermissionDuringConfirmation(ProfileTaskPolicy.Refusal refused){
        return refused!=null&&refused.getCause() instanceof VerifiedPermissionPending;
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
                BackgroundOwnedSingleTask.Task current=observeStateSample(true,deadline,"PROFILE_STATE_READ_DEADLINE");
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
    /** A separate, read-only permission identity. It never becomes WindowOwnership,
     * a business observation, or an input permit. The caller still needs a separate
     * owner-bound initialization policy and a live accessibility-window corroboration. */
    public synchronized PermissionRead permissionForInitialization(int windowId,int observedTaskId,long deadline)throws Exception{
        need(startAccepted&&!retiring&&windowId>=0&&observedTaskId>0,"PROFILE_PERMISSION_READ_INVALID");
        platform.guard();actual(true);
        need(platform.now()<deadline,"PROFILE_PERMISSION_READ_DEADLINE");
        ProfileTaskPolicy.Snapshot global=platform.snapshot();personalAudit=global.personalAudit(target,personal);
        List<BackgroundOwnedSingleTask.Task> roots=checked(platform.roots());
        need(roots.size()==1,"PROFILE_DISPLAY_ROOT_CHANGED");
        BackgroundOwnedSingleTask.Task currentRoot=roots.get(0);requireRootIdentity(currentRoot);
        List<BackgroundOwnedSingleTask.Task> children=checked(platform.children(root.token));
        need(children.size()==1,"PROFILE_FOREIGN_CHILD_TASK");
        BackgroundOwnedSingleTask.Task candidate=children.get(0);
        need(candidate.id==observedTaskId,"PROFILE_PERMISSION_WINDOW_TASK_MISMATCH");
        ProfilePermissionTransient.Proof proof=permissionForOwnedPair(currentRoot,candidate,global);
        need(proof!=null,"PROFILE_PERMISSION_PROOF_UNAVAILABLE");
        if(leaf==null){leaf=candidate;leafTokenId=UUID.randomUUID().toString();}
        else need(sameTask(leaf,candidate),"PROFILE_LEAF_TOKEN_CHANGED");
        requireRecentOnlyOwned(readRecents(),candidate.id);platform.guard();
        long now=platform.now();need(now<deadline,"PROFILE_PERMISSION_READ_DEADLINE");
        proof.requireMatches(target,currentRoot,candidate,now);
        return new PermissionRead(target,generation,windowId,currentRoot,candidate,leafTokenId,proof,now,deadline);
    }
    /** Private construction from this live owned task. There is deliberately no
     * fromWire/fromJson constructor and no flag that promotes the retirement proof. */
    public static final class PermissionRead {
        public final ProfileTarget target;
        public final String generation,leafTokenId,activityRecord,resultToActivityRecord;
        public final int displayId,windowId,rootTaskId,taskId,permissionUid;
        public final long observedElapsedMs,expiresElapsedMs;
        private final BackgroundOwnedSingleTask.Task root,leaf;
        private final ProfilePermissionTransient.Proof proof;
        private PermissionRead(ProfileTarget target,String generation,int windowId,
                BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf,String leafTokenId,
                ProfilePermissionTransient.Proof proof,long now,long deadline)throws Exception{
            this.target=target;this.generation=generation;this.windowId=windowId;this.root=root;this.leaf=leaf;
            this.leafTokenId=leafTokenId;this.proof=proof;displayId=leaf.display;rootTaskId=root.id;taskId=leaf.id;
            Map<String,Object> facts=proof.evidence();permissionUid=((Number)facts.get("permission_uid")).intValue();
            activityRecord=(String)facts.get("activity_record");resultToActivityRecord=(String)facts.get("result_to_activity_record");
            long proofStart=((Number)facts.get("observed_start_elapsed_ms")).longValue();
            observedElapsedMs=now;expiresElapsedMs=Math.min(deadline,proofStart+ProfilePermissionTransient.MAX_AGE_MS);
            requireFresh(now);
        }
        public void requireFresh(long now)throws Exception{
            need(now>=observedElapsedMs&&now<expiresElapsedMs,"PROFILE_PERMISSION_READ_STALE");
            proof.requireMatches(target,root,leaf,now);
        }
        public boolean sameOwnedTask(PermissionRead other){
            return other!=null&&target.same(other.target)&&generation.equals(other.generation)
                    &&displayId==other.displayId&&leafTokenId.equals(other.leafTokenId)
                    &&sameTask(root,other.root)&&sameTask(leaf,other.leaf);
        }
        public boolean sameRequest(PermissionRead other){
            return sameOwnedTask(other)&&windowId==other.windowId&&permissionUid==other.permissionUid
                    &&activityRecord.equals(other.activityRecord)&&resultToActivityRecord.equals(other.resultToActivityRecord);
        }
        public Map<String,Object> evidence(){
            Map<String,Object> value=new LinkedHashMap<String,Object>(proof.evidence());
            value.put("schema","hepta.profile-permission-initialization-read.v1");
            value.put("generation",generation);value.put("window_id",windowId);
            value.put("observed_elapsed_ms",observedElapsedMs);value.put("expires_elapsed_ms",expiresElapsedMs);
            value.put("business_observation_allowed",false);value.put("permission_input_allowed",false);
            value.put("serialized_evidence_is_authority",false);return Collections.unmodifiableMap(value);
        }
    }
    public synchronized void retire(long deadline)throws Exception{
        need(!retiring,"PROFILE_RETIRE_ALREADY_ATTEMPTED");retiring=true;
        try{
            actual(false);
            if(!rootAttempted){
                platform.snapshot().requireDedicatedEmpty(target);requireRecentEmpty(readRecents());
                need(checked(platform.roots()).isEmpty(),"PROFILE_FOREIGN_ROOT_ON_DISPLAY");
                liveAbsent=true;recentsAbsent=true;cleanupKnown=true;return;
            }
            need(root!=null,"PROFILE_ROOT_CREATE_UNRESOLVED");
            ProfileTaskPolicy.Snapshot global=platform.snapshot();personalAudit=global.personalAudit(target,personal);
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
                    requireRecentOnlyOwned(readRecents(),leaf.id);
                    if(permission!=null)permission.requireMatches(target,currentRoot,candidate,platform.now());
                    // Retained real WindowContainerToken only. No removal by arbitrary task ID.
                    leafRemoveAttempted=true;platform.removeLeaf(leaf.token);leafRemoved=true;
                }else{
                    requireRoot(currentRoot,true);
                    global.requireDedicatedEmpty(target);
                    if(leaf!=null)need(!global.allIds.contains(leaf.id)&&!recentIds(readRecents()).contains(leaf.id),
                            "PROFILE_DETACHED_RECENT_LEAF_UNRESOLVED");
                }
                while(platform.now()<deadline){
                    actual(false);
                    ProfileTaskPolicy.Snapshot current=platform.snapshot();personalAudit=current.personalAudit(target,personal);
                    ProfileTaskPolicy.Recents recent=readRecents();recentsAfterSha=recent.sha256;
                    requireRecentOnlyOwned(recent,leaf==null?-1:leaf.id);
                    boolean noLeaf=(leaf==null||(!current.allIds.contains(leaf.id)&&!recentIds(recent).contains(leaf.id)));
                    if(noLeaf){
                        current.requireDedicatedEmpty(target);requireRecentEmpty(recent);
                        List<BackgroundOwnedSingleTask.Task> currentRoots=checked(platform.roots());
                        need(currentRoots.size()==1,"PROFILE_ROOT_CHANGED_DURING_RETIRE");
                        requireRoot(currentRoots.get(0),false);
                        need(checked(platform.children(root.token)).isEmpty(),"PROFILE_ROOT_CHILDREN_REMAIN");
                        if(publicHistory!=null)requireRecentEmpty(readRecents());
                        rootDeleteAttempted=true;
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
        actual(false);ProfileTaskPolicy.Snapshot global=platform.snapshot();personalAudit=global.personalAudit(target,personal);
        ProfileTaskPolicy.Recents recent=readRecents();recentsAfterSha=recent.sha256;
        global.requireDedicatedEmpty(target);requireRecentEmpty(recent);
        List<BackgroundOwnedSingleTask.Task> remaining=checked(platform.roots());
        if(!remaining.isEmpty()){
            need(rootRemoved&&remaining.size()==1,"PROFILE_FOREIGN_ROOT_ON_DISPLAY");
            requireRoot(remaining.get(0),false);
            need(checked(platform.children(root.token)).isEmpty(),"PROFILE_FOREIGN_CHILD_TASK");
            return false;
        }
        liveAbsent=(root==null||!global.allIds.contains(root.id))&&(leaf==null||!global.allIds.contains(leaf.id));
        recentsAbsent=(root==null||!recentIds(recent).contains(root.id))&&(leaf==null||!recentIds(recent).contains(leaf.id));
        cleanupKnown=liveAbsent&&recentsAbsent&&(!dispatchMarked||leaf!=null);
        return cleanupKnown;
    }
    /** Owned by this broker only; the callback has no task launch, remove or input operation. */
    interface RetiredDisplay {
        default void beginFreshSample(long started,long deadline)throws Exception{}
        void requireState(boolean beforeRelease)throws Exception;
        void awaitAbsent()throws Exception;
        void releaseOriginalHandle()throws Exception;
        default void releaseOriginalHandle(long observedStarted,long deadline)throws Exception{releaseOriginalHandle();}
    }
    /** A private-construction proof for a separate cleanup interval. It does not
     * change the original task's cleanupKnown/identityUnknown/history fields. */
    static final class RetainedCleanupProof {
        private final ProfileOwnedTask owner;
        private final Map<String,Object> facts;
        private RetainedCleanupProof(ProfileOwnedTask owner,Map<String,Object> facts){
            this.owner=owner;this.facts=Collections.unmodifiableMap(new LinkedHashMap<String,Object>(facts));
        }
        Map<String,Object> evidence(){return facts;}
    }
    private static final class RetainedSample {
        final boolean rootLive,leafLive,rootRecent,leafRecent;
        final List<List<?>> outside;
        final long started;
        RetainedSample(boolean rootLive,boolean leafLive,boolean rootRecent,boolean leafRecent,List<List<?>> outside,long started){
            this.rootLive=rootLive;this.leafLive=leafLive;this.rootRecent=rootRecent;this.leafRecent=leafRecent;this.outside=outside;this.started=started;
        }
        boolean tasksAbsent(){return !rootLive&&!leafLive&&!rootRecent&&!leafRecent;}
        boolean leafAbsent(){return !leafLive&&!leafRecent;}
    }
    /** Cleanup-only access to this object's originally retained Binder capabilities.
     * Serialized IDs are never accepted. Each original or new effect is attempted
     * at most once, including a call that threw before its result was observed. */
    synchronized RetainedCleanupProof cleanupRetained(long deadline,RetiredDisplay handle)throws Exception{
        need(!retainedCleanupClaimed&&!retainedReleaseChecked&&publicHistory!=null&&retiring&&identityUnknown
                &&root!=null&&leaf!=null&&prepared&&dispatchMarked&&startAccepted&&handle!=null,
                "PROFILE_RETAINED_CLEANUP_NOT_ELIGIBLE");
        retainedCleanupClaimed=true;
        need(platform.now()<deadline&&deadline-platform.now()<=10000,"PROFILE_RETAINED_CLEANUP_DEADLINE");
        Map<String,Object> historical=new LinkedHashMap<String,Object>(publicHistory.evidence());
        long began=platform.now();
        handle.beginFreshSample(began,Math.min(deadline,began+1500));
        RetainedRecentHistory fresh=publicHistory.beginRetainedCleanup(platform.publicRecentsDump(),target,root,leaf,display,platform.now());
        requireRetainedFresh(began,deadline);
        RetainedSample current=retainedCleanupSample(fresh,null,deadline,handle,true);
        final List<List<?>> outside=current.outside;
        platform.pause();current=retainedCleanupSample(fresh,outside,deadline,handle,true);
        boolean leafAttempted=false,rootAttemptedNow=false,releaseAttempted=false;
        need(current.leafLive||!current.leafRecent,"PROFILE_RETAINED_RECENT_ONLY_REQUIRES_MAINTENANCE");
        if(current.leafLive){
            need(!leafRemoveAttempted,"PROFILE_RETAINED_LEAF_EFFECT_ALREADY_ATTEMPTED");
            retainedCleanupFinalPair(true,outside,current.started,deadline);
            requireRetainedFresh(current.started,deadline);
            leafAttempted=true;
            platform.removeLeaf(leaf.token);
        }
        while(!current.leafAbsent()){
            platform.pause();current=retainedCleanupSample(fresh,outside,deadline,handle,true);
        }
        // A second complete absence read excludes a detached, retained recent leaf.
        platform.pause();current=retainedCleanupSample(fresh,outside,deadline,handle,true);
        need(current.leafAbsent(),"PROFILE_RETAINED_LEAF_REAPPEARED");
        if(current.rootLive){
            need(!rootDeleteAttempted,"PROFILE_RETAINED_ROOT_EFFECT_ALREADY_ATTEMPTED");
            retainedCleanupFinalPair(false,outside,current.started,deadline);
            requireRetainedFresh(current.started,deadline);
            rootAttemptedNow=true;
            need(platform.deleteRoot(root.token),"PROFILE_RETAINED_ROOT_DELETE_NOT_ACCEPTED");
        }
        while(!current.tasksAbsent()){
            platform.pause();current=retainedCleanupSample(fresh,outside,deadline,handle,true);
        }
        platform.pause();current=retainedCleanupSample(fresh,outside,deadline,handle,true);
        need(current.tasksAbsent(),"PROFILE_RETAINED_TASK_REAPPEARED");
        handle.requireState(true);requireRetainedFresh(current.started,deadline);
        releaseAttempted=true;handle.releaseOriginalHandle(current.started,deadline);handle.awaitAbsent();
        for(int i=0;i<2;i++){
            platform.pause();current=retainedCleanupSample(fresh,outside,deadline,handle,false);
            need(current.tasksAbsent(),"PROFILE_RETAINED_POST_TASK_PRESENT");
        }
        need(historical.equals(publicHistory.evidence()),"PROFILE_RETAINED_ORIGINAL_HISTORY_CHANGED");
        Map<String,Object> facts=new LinkedHashMap<String,Object>();
        facts.put("schema","hepta.retained-profile-cleanup-interval.v1");facts.put("generation",generation);
        facts.put("target_sha256",target.sha256);facts.put("display_id",display);facts.put("root_task_id",root.id);facts.put("leaf_task_id",leaf.id);
        facts.put("started_elapsed_ms",began);facts.put("finished_elapsed_ms",platform.now());facts.put("deadline_elapsed_ms",deadline);
        facts.put("maximum_census_to_effect_age_ms",1500);facts.put("detached_recent_task_removal_supported",false);
        facts.put("leaf_remove_attempted",leafAttempted);facts.put("root_delete_attempted",rootAttemptedNow);
        facts.put("original_display_release_attempted",releaseAttempted);facts.put("current_tasks_absent",true);
        facts.put("current_display_absent",true);facts.put("outside_live_tasks_unchanged",true);
        facts.put("original_cleanup_known",cleanupKnown());facts.put("original_identity_unknown",identityUnknown);
        facts.put("original_history",Collections.unmodifiableMap(historical));facts.put("fresh_cleanup_history",fresh.evidence());
        facts.put("business_admission_restored",false);facts.put("old_failure_rewritten",false);facts.put("serialized_tokens_grant_authority",false);
        return new RetainedCleanupProof(this,facts);
    }
    private RetainedSample retainedCleanupSample(RetainedRecentHistory history,List<List<?>> baseline,long deadline,
            RetiredDisplay handle,boolean beforeRelease)throws Exception{
        long began=platform.now();need(began<deadline,"PROFILE_RETAINED_CLEANUP_DEADLINE");
        handle.beginFreshSample(began,Math.min(deadline,began+1500));actual(false);
        ProfileTaskPolicy.Snapshot all=platform.snapshot();List<BackgroundOwnedSingleTask.Task> roots=beforeRelease?
                checked(platform.roots()):Collections.<BackgroundOwnedSingleTask.Task>emptyList();
        boolean rootLive=!roots.isEmpty(),leafLive=false;
        if(rootLive){
            need(roots.size()==1,"PROFILE_RETAINED_FOREIGN_ROOT");BackgroundOwnedSingleTask.Task currentRoot=roots.get(0);
            requireRootIdentity(currentRoot);List<BackgroundOwnedSingleTask.Task> children=checked(platform.children(root.token));
            need(children.size()<=1,"PROFILE_RETAINED_FOREIGN_CHILD");
            if(!children.isEmpty()){
                BackgroundOwnedSingleTask.Task currentLeaf=children.get(0);
                need(sameTask(leaf,currentLeaf)&&leaf.uid==currentLeaf.uid,"PROFILE_RETAINED_LEAF_TOKEN_CHANGED");
                ProfilePermissionTransient.Proof permission=permissionForOwnedPair(currentRoot,currentLeaf,all);
                if(permission==null){requireRoot(currentRoot,true);requireLeaf(currentLeaf,all);}
                all.requireOnlyOwned(target,display,root.id,leaf.id);leafLive=true;
            }else{requireRoot(currentRoot,false);all.requireOnlyOwned(target,display,root.id,-1);all.requireDedicatedEmpty(target);
                need(!all.allIds.contains(leaf.id),"PROFILE_RETAINED_LEAF_MOVED");}
        }else{
            all.requireDedicatedEmpty(target);need(!all.allIds.contains(root.id)&&!all.allIds.contains(leaf.id),"PROFILE_RETAINED_TASK_MOVED");
            for(ProfileTaskPolicy.Root row:all.roots)need(row.display!=display,"PROFILE_RETAINED_FOREIGN_DISPLAY_TASK");
        }
        List<List<?>> outside=all.excludingRoot(root.id);
        need(baseline==null||baseline.equals(outside),"PROFILE_RETAINED_OUTSIDE_TASK_CHANGED");
        history.observe(platform.publicRecentsDump(),platform.now());Set<Integer> ids=history.observedIds();
        handle.requireState(beforeRelease);requireRetainedFresh(began,deadline);
        return new RetainedSample(rootLive,leafLive,ids.contains(root.id),ids.contains(leaf.id),outside,began);
    }
    private void retainedCleanupFinalPair(boolean requireLeafNow,List<List<?>> baseline,long observedStarted,long deadline)throws Exception{
        requireRetainedFresh(observedStarted,deadline);actual(false);
        ProfileTaskPolicy.Snapshot all=platform.snapshot();
        need(baseline.equals(all.excludingRoot(root.id)),"PROFILE_RETAINED_FINAL_OUTSIDE_CHANGED");
        List<BackgroundOwnedSingleTask.Task> roots=checked(platform.roots());need(roots.size()==1,"PROFILE_RETAINED_FINAL_ROOT_MISSING");
        requireRootIdentity(roots.get(0));List<BackgroundOwnedSingleTask.Task> children=checked(platform.children(root.token));
        if(requireLeafNow){
            need(children.size()==1&&sameTask(leaf,children.get(0))&&leaf.uid==children.get(0).uid,"PROFILE_RETAINED_FINAL_LEAF_CHANGED");
            ProfilePermissionTransient.Proof permission=permissionForOwnedPair(roots.get(0),children.get(0),all);
            if(permission==null){requireRoot(roots.get(0),true);requireLeaf(children.get(0),all);}
            all.requireOnlyOwned(target,display,root.id,leaf.id);
        }else{
            need(children.isEmpty(),"PROFILE_RETAINED_FINAL_ROOT_NOT_EMPTY");requireRoot(roots.get(0),false);
            all.requireDedicatedEmpty(target);all.requireOnlyOwned(target,display,root.id,-1);
        }
        requireRetainedFresh(observedStarted,deadline);
    }
    private void requireRetainedFresh(long observedStarted,long deadline)throws Exception{
        long now=platform.now();need(now>=observedStarted&&now<deadline&&now-observedStarted<1500,"PROFILE_RETAINED_CENSUS_STALE_OR_DEADLINE");
    }
    synchronized boolean ownsRetainedCleanupProof(RetainedCleanupProof proof){return proof!=null&&proof.owner==this&&retainedCleanupClaimed;}
    synchronized void closeRetainedEmptyDisplay(long deadline,RetiredDisplay displayHandle)throws Exception{
        need(!retainedReleaseChecked&&publicHistory!=null&&retiring&&identityUnknown&&!foreignTasks
                &&root!=null&&leaf!=null&&startAccepted&&dispatchMarked&&!rootDeleteAttempted,
                "PROFILE_RETAINED_EMPTY_NOT_ELIGIBLE");
        retainedReleaseChecked=true;
        List<List<?>> protectedFacts=retainedEmptySample(true,deadline,displayHandle);
        platform.pause();
        need(retainedEmptySample(true,deadline,displayHandle).equals(protectedFacts),"PROFILE_RETAINED_LIVE_CHANGED");
        need(platform.now()<deadline,"PROFILE_RETAINED_READ_DEADLINE");
        // No task removal is replayed. The sole authorized effect is the release of this
        // broker's original, verified destroy-content VD after its own empty root was reread.
        displayHandle.releaseOriginalHandle();
        displayHandle.awaitAbsent();
        for(int sample=0;sample<2;sample++){
            platform.pause();
            need(retainedEmptySample(false,deadline,displayHandle).equals(protectedFacts),"PROFILE_RETAINED_POST_CHANGED");
        }
        liveAbsent=true;recentsAbsent=true;cleanupKnown=true;identityUnknown=false;
    }
    private List<List<?>> retainedEmptySample(boolean before,long deadline,RetiredDisplay displayHandle)throws Exception{
        need(platform.now()<deadline,"PROFILE_RETAINED_READ_DEADLINE");
        actual(false);ProfileTaskPolicy.Snapshot all=platform.snapshot();
        all.requireDedicatedEmpty(target);
        need(!all.allIds.contains(leaf.id),"PROFILE_RETAINED_LEAF_LIVE");
        ProfileTaskPolicy.Recents recents=readRecents();requireRecentEmpty(recents);
        Set<Integer> recent=recentIds(recents);
        need(!recent.contains(root.id)&&!recent.contains(leaf.id),"PROFILE_RETAINED_TASK_IN_RECENTS");
        if(before){
            List<BackgroundOwnedSingleTask.Task> roots=checked(platform.roots());
            all.requireOnlyOwned(target,display,root.id,-1);
            need(roots.size()==1,"PROFILE_RETAINED_ROOT_NOT_UNIQUE");
            requireRoot(roots.get(0),false);
            need(checked(platform.children(root.token)).isEmpty(),"PROFILE_RETAINED_ROOT_HAS_CHILD");
        }else{
            need(!all.allIds.contains(root.id),"PROFILE_RETAINED_ROOT_LIVE");
            for(ProfileTaskPolicy.Root row:all.roots)need(row.display!=display,"PROFILE_RETAINED_DISPLAY_TASK");
        }
        displayHandle.requireState(before);
        need(platform.now()<deadline,"PROFILE_RETAINED_READ_DEADLINE");
        return all.excludingRoot(root.id);
    }
    synchronized boolean retainedAbsenceVerified(){return retainedReleaseChecked&&cleanupKnown()&&liveAbsent&&recentsAbsent;}
    public synchronized boolean cleanupKnown(){return cleanupKnown&&!identityUnknown&&!foreignTasks;}
    public synchronized boolean started(){return dispatchMarked;}
    public synchronized Map<String,Object> personalAudit(){return personalAudit;}
    /** Diagnostic readback only; neither serialized identifiers nor these booleans grant authority. */
    public Map<String,Object> lastLeafValidation(){return lastLeafValidation;}
    /** First rejected root sample only. It neither claims a task nor changes any admission rule. */
    public Map<String,Object> firstRootRefusal(){return firstRootRefusal;}
    /** First bounded platform sampling mismatch; it never grants task or input authority. */
    public Map<String,Object> firstPermissionReadMismatch(){return platform.permissionReadMismatchEvidence();}
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
        out.put("owned_tasks",owned);
        if(publicHistory!=null){Map<String,Object> history=publicHistory.evidence();out.put("public_foreign_recent_history",history);
            out.put("recents_absence_scope","hepta.public-profile-history-custody.v2".equals(history.get("schema"))
                    ?"owned_target_only_with_unrelated_physical_history_audited":"owned_target_only_with_foreign_history_preserved");}
        return Collections.unmodifiableMap(out);
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
        out.put("permission_first_read_mismatch",firstPermissionReadMismatch());
        if(publicHistory!=null)out.put("public_foreign_recent_history",publicHistory.evidence());
        out.put("cleanup",cleanupEvidence());return Collections.unmodifiableMap(out);
    }
    private ProfileTarget actual(boolean ready)throws Exception{
        ProfileTarget actual=platform.recheck(ready);
        need(target.same(actual),"PROFILE_INSTALLATION_IDENTITY_CHANGED");return actual;
    }
    private void requirePrepared()throws Exception{
        ProfileTaskPolicy.Snapshot global=platform.snapshot();
        global.requireDedicatedEmpty(target);personalAudit=global.personalAudit(target,personal);
        List<BackgroundOwnedSingleTask.Task> roots=checked(platform.roots());
        need(roots.size()==1,"PROFILE_PREPARED_ROOT_CHANGED");requireRoot(roots.get(0),false);
        need(checked(platform.children(root.token)).isEmpty(),"PROFILE_PREPARED_ROOT_NOT_EMPTY");
        global.requireOnlyOwned(target,display,root.id,-1);
        if(publicHistory!=null)requireRecentEmpty(readRecents());
    }
    private static final class VerifiedPermissionPending extends Exception {
        private static final long serialVersionUID=1L;
        private VerifiedPermissionPending(){}
    }
    private BackgroundOwnedSingleTask.Task observeTree(boolean visible)throws Exception{
        try{return observeTreeSample(visible);}
        catch(VerifiedPermissionPending pending){throw new ProfileTaskPolicy.Refusal("PROFILE_PERMISSION_SETUP_REQUIRED");}
    }
    /** Retry only a typed, identity-stable presentation change while reading init/state.
     * Every retry re-reads the complete graph. The first live pair stays pinned even
     * before the first leaf claim; ordinary window, permission input and cleanup do not retry. */
    private BackgroundOwnedSingleTask.Task observeStateSample(boolean visible,long deadline,String deadlineCode)throws Exception{
        ProfilePermissionTransient.ReadChanged pinned=null;
        for(int attempt=0;attempt<3;attempt++){
            try{return observeTreeSample(visible,pinned);}
            catch(ProfilePermissionTransient.ReadChanged changed){
                if(changed.exitedRoot!=null){
                    // A discarded permission-to-App pair is not a first claim or a proof.
                    // Both samples must retain this coordinator's actual owned capabilities.
                    requireRootIdentity(changed.exitedRoot);requireRootIdentity(changed.root);
                    need(leaf!=null&&sameTask(leaf,changed.exitedLeaf)&&sameTask(leaf,changed.leaf)
                            &&changed.exitedLeaf.uid==target.fullUid&&changed.leaf.uid==target.fullUid,
                            "PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ");
                }
                if(pinned==null)pinned=changed;else pinned.requireAttempt(changed);
                need(attempt<2,changed.code);
                platform.guard();long now=platform.now();
                need(now<deadline&&deadline-now>20,deadlineCode);platform.pause();
                platform.guard();actual(true);need(platform.now()<deadline,deadlineCode);
            }
        }
        throw new AssertionError("bounded state sampling exhausted");
    }
    private BackgroundOwnedSingleTask.Task observeTreeSample(boolean visible)throws Exception{
        return observeTreeSample(visible,null);
    }
    private BackgroundOwnedSingleTask.Task observeTreeSample(boolean visible,ProfilePermissionTransient.ReadChanged pinned)throws Exception{
        ProfileTaskPolicy.Snapshot global=platform.snapshot();personalAudit=global.personalAudit(target,personal);
        List<BackgroundOwnedSingleTask.Task> roots=checked(platform.roots());
        need(roots.size()==1,"PROFILE_DISPLAY_ROOT_CHANGED");
        if(pinned!=null)pinned.requireRoot(roots.get(0));
        if(ProfilePermissionTransient.COMPONENT.equals(roots.get(0).top)){
            // A verified permission transient can retain ownership, never a business window.
            requireRootIdentity(roots.get(0));
            List<BackgroundOwnedSingleTask.Task> permissionChildren=checked(platform.children(root.token));
            need(permissionChildren.size()==1,"PROFILE_FOREIGN_CHILD_TASK");
            BackgroundOwnedSingleTask.Task candidate=permissionChildren.get(0);
            if(pinned!=null)pinned.requireLeaf(candidate);
            ProfilePermissionTransient.Proof permission=permissionForOwnedPair(roots.get(0),candidate,global);
            requireRootActivity(permission!=null,"permission_root_without_verified_leaf",roots.get(0),candidate);
            if(leaf==null){leaf=candidate;leafTokenId=UUID.randomUUID().toString();}
            else need(sameTask(leaf,candidate),"PROFILE_LEAF_TOKEN_CHANGED");
            global.requireOnlyOwned(target,display,root.id,candidate.id);
            if(publicHistory!=null)requireRecentOnlyOwned(readRecents(),candidate.id);
            throw new VerifiedPermissionPending();
        }
        requireRoot(roots.get(0),true);
        List<BackgroundOwnedSingleTask.Task> children=checked(platform.children(root.token));
        need(children.size()<=1,"PROFILE_FOREIGN_CHILD_TASK");
        if(children.isEmpty()){
            if(pinned!=null)pinned.requireLeaf(null);
            need(leaf==null,"PROFILE_OWNED_LEAF_DISAPPEARED");
            global.requireOnlyOwned(target,display,root.id,-1);
            if(publicHistory!=null)requireRecentEmpty(readRecents());return null;
        }
        BackgroundOwnedSingleTask.Task candidate=children.get(0);
        if(pinned!=null)pinned.requireLeaf(candidate);
        requireLeaf(candidate,global);
        if(leaf==null){leaf=candidate;leafTokenId=UUID.randomUUID().toString();}
        else need(sameTask(leaf,candidate),"PROFILE_LEAF_TOKEN_CHANGED");
        global.requireOnlyOwned(target,display,root.id,candidate.id);
        if(publicHistory!=null)requireRecentOnlyOwned(readRecents(),candidate.id);
        if(visible&&(!candidate.running||!candidate.visible||candidate.activities<1))return null;
        return candidate;
    }
    private ProfileTaskPolicy.Recents readRecents()throws Exception{
        if(publicHistory==null)return platform.recents();
        String raw=platform.publicRecentsDump();ProfileTaskPolicy.Recents recent=ProfileTaskPolicy.Recents.parse(raw);
        publicHistory.observe(raw,target,root,leaf,display,platform.now());return recent;
    }
    public synchronized void verifyPublicRecentHistory()throws Exception{if(publicHistory!=null)readRecents();}
    private Set<Integer> recentIds(ProfileTaskPolicy.Recents recent){return publicHistory==null?recent.ids:publicHistory.observedIds();}
    private void requireRecentEmpty(ProfileTaskPolicy.Recents recent)throws Exception{
        if(publicHistory==null)recent.requireDedicatedEmpty(target);
        else need(leaf==null||!publicHistory.observedIds().contains(leaf.id),"PUBLIC_HISTORY_OWNED_TARGET_RECENT_REMAINS");
    }
    private void requireRecentOnlyOwned(ProfileTaskPolicy.Recents recent,int id)throws Exception{
        if(publicHistory==null)recent.requireOnlyOwned(target,id);
        else need(id<0||leaf!=null&&leaf.id==id,"PUBLIC_HISTORY_OWNED_TARGET_UNBOUND");
    }
    private void requireRoot(BackgroundOwnedSingleTask.Task current,boolean mayHaveActivities)throws Exception{
        requireRootIdentity(current);
        if(!mayHaveActivities)need(current.activities==0&&!current.running&&!current.visible
                &&current.base==null&&current.top==null&&current.topUid==-1,"PROFILE_ROOT_NOT_EMPTY");
        else requireRootActivity((current.base==null||inPackage(current.base))&&(current.top==null||inPackage(current.top))
                &&(current.topUid==-1||current.topUid==target.fullUid),"root_activity",current,null);
    }
    private void requireRootActivity(boolean allowed,String phase,BackgroundOwnedSingleTask.Task current,
            BackgroundOwnedSingleTask.Task candidate)throws Exception{
        if(!allowed&&firstRootRefusal.isEmpty()){
            Map<String,Object> detail=new LinkedHashMap<String,Object>();
            detail.put("schema","hepta.profile-first-root-refusal.v1");detail.put("phase",phase);
            detail.put("refusal_code","PROFILE_ROOT_FOREIGN_ACTIVITY");
            detail.put("generation",generation);detail.put("request_id",requestId);
            detail.put("target_sha256",target.sha256);detail.put("expected_display_id",display);
            detail.put("expected_target_user_id",target.profile.userId);detail.put("expected_target_full_uid",target.fullUid);
            detail.put("serialized_evidence_is_authority",false);detail.put("allows_input_or_model_resumption",false);
            try{
                detail.put("observed_elapsed_ms",platform.now());detail.put("during_retirement",retiring);
                detail.put("root",rootRefusalTask(current,root));
                detail.put("candidate_read_in_this_path",candidate!=null);
                detail.put("candidate",rootRefusalTask(candidate,leaf));
                detail.put("retained_leaf",rootRefusalTask(leaf,leaf));
                detail.put("retained_leaf_is_current_sample",false);
                detail.put("prior_leaf_validation",lastLeafValidation);
                Map<String,Object> checks=new LinkedHashMap<String,Object>();
                checks.put("root_base_package_or_null",current!=null&&(current.base==null||inPackage(current.base)));
                checks.put("root_top_package_or_null",current!=null&&(current.top==null||inPackage(current.top)));
                checks.put("root_top_uid_target_or_absent",current!=null&&(current.topUid==-1||current.topUid==target.fullUid));
                checks.put("root_top_is_permission_component",current!=null&&ProfilePermissionTransient.COMPONENT.equals(current.top));
                checks.put("candidate_top_is_permission_component",candidate!=null&&ProfilePermissionTransient.COMPONENT.equals(candidate.top));
                checks.put("root_and_candidate_top_uid_equal",current!=null&&candidate!=null&&current.topUid==candidate.topUid);
                checks.put("candidate_top_uid_is_target_user",candidate!=null&&candidate.topUid/100000==target.profile.userId);
                detail.put("checks",Collections.unmodifiableMap(checks));detail.put("diagnostic_capture_complete",true);
            }catch(RuntimeException unavailable){
                // Diagnostic failure must not replace the original refusal or obstruct owned cleanup.
                detail.put("diagnostic_capture_complete",false);
                detail.put("diagnostic_failure_type",unavailable.getClass().getName());
            }
            firstRootRefusal=Collections.unmodifiableMap(detail);
        }
        need(allowed,"PROFILE_ROOT_FOREIGN_ACTIVITY");
    }
    private Map<String,Object> rootRefusalTask(BackgroundOwnedSingleTask.Task current,
            BackgroundOwnedSingleTask.Task retained){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("present",current!=null);
        if(current==null)return Collections.unmodifiableMap(out);
        out.put("task_id",current.id);out.put("parent_task_id",current.parent);out.put("display_id",current.display);
        out.put("user_id",current.user);out.put("effective_uid",current.uid);out.put("top_activity_info_uid",current.topUid);
        out.put("num_activities",current.activities);out.put("running",current.running);out.put("visible",current.visible);
        out.put("actual_token_present",current.token!=null);out.put("retained_present",retained!=null);
        out.put("actual_token_equal_to_retained",retained!=null&&Objects.equals(retained.token,current.token));
        out.put("retained_identity_matches",retained!=null&&sameTask(retained,current)&&retained.uid==current.uid);
        out.put("root_cookie_present",current.cookies.contains(rootCookie));
        out.put("launch_cookie_present",current.cookies.contains(launchCookie));out.put("cookie_count",current.cookies.size());
        Map<String,Object> components=new LinkedHashMap<String,Object>();
        String[] names={"intent","base","top","real","orig"};
        String[] values={current.intentComponent,current.base,current.top,current.real,current.orig};
        for(int i=0;i<names.length;i++){
            String value=values[i];Map<String,Object> component=new LinkedHashMap<String,Object>();
            component.put("present",value!=null);component.put("utf16_length",value==null?0:value.length());
            component.put("truncated",value!=null&&value.length()>512);
            component.put("value",value==null?"":value.substring(0,Math.min(value.length(),512)));
            components.put(names[i],Collections.unmodifiableMap(component));
        }
        out.put("components",Collections.unmodifiableMap(components));out.put("serialized_token_is_authority",false);
        return Collections.unmodifiableMap(out);
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
        requireRootActivity((currentRoot.base==null||inPackage(currentRoot.base))
                &&currentRoot.topUid==candidate.topUid&&candidate.topUid/100000==target.profile.userId,
                "permission_pair",currentRoot,candidate);
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
