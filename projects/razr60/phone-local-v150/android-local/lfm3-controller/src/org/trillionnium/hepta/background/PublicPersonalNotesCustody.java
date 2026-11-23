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

/** Read-only Notes task accounting around release of this session's actual VD.
 * No task deletion, task-id action, permission change, or replay exists here.
 * Normal Notes NEW_TASK/MULTIPLE_TASK/NEW_DOCUMENT policy remains unchanged.
 * Unknown pre-release ownership retains the VD owner with admission retired.
 * Proven own residue may be polled within the existing cleanup deadline; any
 * changed owned token/UID, foreign task on our display or unresolved history
 * permanently stays unknown. Unrelated user-0 physical activity is audited.
 * A released display alone never establishes live/recents task absence. */
final class PublicPersonalNotesCustody {
    static final String PACKAGE="com.motorola.stylus",SCHEMA="hepta.public-personal-notes-cleanup.v2";
    static final int MAX_TASKS=32;
    static final class Node {
        final BackgroundOwnedSingleTask.Task task;
        final List<Node> children;
        Node(BackgroundOwnedSingleTask.Task task,List<Node> children){
            need(task!=null&&children!=null&&children.size()<=MAX_TASKS,"NOTES_TASK_NODE_INVALID");
            this.task=task;this.children=Collections.unmodifiableList(new ArrayList<Node>(children));
        }
    }
    static final class Frame {
        final ProfileTaskPolicy.Snapshot global;
        final List<Node> roots;
        final long begin,end;
        Frame(ProfileTaskPolicy.Snapshot global,List<Node> roots,long begin,long end){
            need(global!=null&&roots!=null&&roots.size()<=MAX_TASKS&&begin>=0&&end>=begin&&end-begin<=1500,
                    "NOTES_TASK_FRAME_INVALID");
            this.global=global;this.roots=Collections.unmodifiableList(new ArrayList<Node>(roots));this.begin=begin;this.end=end;
        }
    }
    private final String generation,scopeSha256;
    private final int uid;
    private final Set<Integer> initialIds;
    private final List<String> hiddenBaseline;
    private final List<String> fullHiddenBaseline;
    private final PublicOwnGroupPhysicalFence.RecentCensus initialRecents;
    private PublicOwnGroupPhysicalFence.RecentCensus releaseCensus,lastRecents;
    private final String initialRecentsSha;
    private final Map<Integer,BackgroundOwnedSingleTask.Task> observed=new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>();
    private final Map<Integer,PublicOwnGroupPhysicalFence.RecentRecord> releaseRecents=new LinkedHashMap<Integer,PublicOwnGroupPhysicalFence.RecentRecord>();
    private int display=-1,absenceReads,pendingReads;
    private boolean attempted,launched,retiring,releasePrepared,releaseAttempted,releaseReturned,unknown,known,physicalHistoryChanged,hiddenHistoryChanged,presentationChanged;
    private long lastObservation=-1,lastAbsence=-1;
    private int launchCount;
    private String bootstrapComponent;
    private boolean bootstrapReadUsed;
    private long bootstrapUntil;
    private String finalRecentsSha="",failure="",releaseHistory="",releaseRecentsSha="";

    PublicPersonalNotesCustody(String generation,String scopeSha,int uid,ProfileTaskPolicy.Snapshot initial,
            PublicOwnGroupPhysicalFence.RecentCensus recents){
        need(ProfileIdentity.uuid(generation)&&ProfileIdentity.hash(scopeSha)&&uid>=10000&&uid<90000
                &&initial!=null&&recents!=null,"NOTES_CUSTODY_BINDING_INVALID");
        this.generation=generation;scopeSha256=scopeSha;this.uid=uid;
        requireNoNotes(initial);requireNoNotes(recents);
        for(String label:recents.hiddenLabels.values())need(!targetHidden(label),"NOTES_ALREADY_HAS_HIDDEN_TASK");
        Set<Integer> ids=new LinkedHashSet<Integer>(initial.allIds);ids.addAll(recents.allIds);
        initialIds=Collections.unmodifiableSet(ids);initialRecents=lastRecents=recents;
        fullHiddenBaseline=Collections.unmodifiableList(new ArrayList<String>(recents.hiddenLabels.values()));
        hiddenBaseline=Collections.unmodifiableList(hiddenHistory(recents,true));
        initialRecentsSha=recents.rawSha256;
    }
    private static void need(boolean ok,String code){if(!ok)throw new IllegalStateException(code);}
    private static boolean pkg(String value){return value!=null&&(value.equals(PACKAGE)||value.startsWith(PACKAGE+"/"));}
    private static boolean nullablePkg(String value){return value==null||pkg(value);}
    /** Android 16 excludes finishing activities from TaskInfo's base/top/count.
     * This is a real, identity-bearing root, never an absent task or cleanup proof. */
    static boolean emptyActivityLeaf(BackgroundOwnedSingleTask.Task task,int expectedUid){
        return task!=null&&task.uid==expectedUid&&task.activities==0&&!task.running
                &&task.topUid==-1&&task.base==null&&task.top==null
                &&task.intentComponent!=null&&task.intentComponent.startsWith(PACKAGE+"/")
                &&task.real!=null&&task.real.startsWith(PACKAGE+"/")
                &&(task.orig==null||task.orig.startsWith(PACKAGE+"/"));
    }
    private boolean targetHidden(String label){return label.contains(PACKAGE)||label.contains("A="+uid+":");}
    private static void requireNoNotes(ProfileTaskPolicy.Snapshot snapshot){
        for(ProfileTaskPolicy.Root root:snapshot.roots)need(!pkg(root.base)&&!pkg(root.top),"NOTES_ALREADY_HAS_LIVE_TASK");
        for(ProfileTaskPolicy.Leaf leaf:snapshot.leaves.values())need(!pkg(leaf.name),"NOTES_ALREADY_HAS_LIVE_TASK");
    }
    private void requireNoNotes(PublicOwnGroupPhysicalFence.RecentCensus recents){
        for(PublicOwnGroupPhysicalFence.RecentRecord row:recents.records.values())
            need(row.uid!=uid&&!pkg(row.activity)&&!pkg(row.base),"NOTES_RECENTS_ABSENCE_UNPROVED");
    }
    synchronized void beforeCreate(){need(!attempted&&!unknown&&!retiring,"NOTES_CREATE_ALREADY_ATTEMPTED");attempted=true;}
    synchronized void bindDisplay(int value){need(attempted&&!unknown&&value>1&&(display<0||display==value),"NOTES_DISPLAY_BINDING_INVALID");display=value;}
    synchronized void markLaunch(){need(attempted&&display>1&&!unknown&&!retiring&&!releasePrepared,"NOTES_LAUNCH_CUSTODY_RETIRED");launched=true;launchCount++;bootstrapComponent=null;}
    /** Called only after the ordinary single Intent returned a framework success. */
    synchronized void acceptedOrdinaryLaunch(String component,long now){
        if(bootstrapComponent==null&&launchCount==1&&launched&&!retiring&&!unknown&&observed.isEmpty()&&pkg(component)){
            bootstrapComponent=component;bootstrapUntil=now+1500;
        }
    }
    synchronized boolean firstRootReadActive(BackgroundOwnedSingleTask.Task task,int actualDisplay,int actualUid,long now){
        return !retiring&&!releasePrepared&&!unknown&&launchCount==1&&launched&&observed.isEmpty()
                &&actualDisplay==display&&actualUid==uid&&now<=bootstrapUntil&&bootstrapComponent!=null
                &&task!=null&&task.display==display&&task.user==0&&task.uid==uid&&task.topUid==uid
                &&task.activities>0&&task.token!=null&&task.cookies.isEmpty()&&!initialIds.contains(task.id)
                &&bootstrapComponent.equals(task.intentComponent)&&bootstrapComponent.equals(task.real);
    }
    synchronized boolean claimFirstRootRead(BackgroundOwnedSingleTask.Task task,int actualDisplay,int actualUid,long now){
        if(bootstrapReadUsed||!firstRootReadActive(task,actualDisplay,actualUid,now))return false;
        bootstrapReadUsed=true;return true;
    }
    synchronized void observe(Frame frame,long now){
        if(retiring)return; // A late monitor read cannot reopen or overwrite retirement.
        try{observeChecked(frame,now);}catch(RuntimeException error){unresolved(error.getMessage());throw error;}
    }
    private void observeChecked(Frame frame,long now){
        observeChecked(frame,now,false);
    }
    private void observeChecked(Frame frame,long now,boolean afterRelease){
        need(!unknown&&(!releaseAttempted||(afterRelease&&releaseReturned))&&display>1&&frame!=null&&now>=frame.end&&now-frame.begin<=1500
                &&frame.end>=lastObservation,"NOTES_TASK_OBSERVATION_UNAVAILABLE");
        Map<Integer,BackgroundOwnedSingleTask.Task> actual=new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>();
        Set<Integer> actualRoots=new LinkedHashSet<Integer>(),actualLeaves=new LinkedHashSet<Integer>();
        for(Node root:frame.roots){need(actualRoots.add(root.task.id),"NOTES_ROOT_DUPLICATE");walk(root,-1,0,actual,actualLeaves);}
        Set<Integer> globalRoots=new LinkedHashSet<Integer>(),globalLeaves=new LinkedHashSet<Integer>();
        for(ProfileTaskPolicy.Root root:frame.global.roots)if(root.display==display){
            globalRoots.add(root.id);
        }
        for(ProfileTaskPolicy.Leaf leaf:frame.global.leaves.values())if(leaf.display==display)globalLeaves.add(leaf.id);
        need(actualRoots.equals(globalRoots)&&actualLeaves.equals(globalLeaves),"NOTES_GLOBAL_OWNED_TREE_DISAGREES");
        for(ProfileTaskPolicy.Root root:frame.global.roots)if(root.display!=display)
            need(!observed.containsKey(root.id),"NOTES_OBSERVED_TASK_ESCAPED");
        for(ProfileTaskPolicy.Leaf leaf:frame.global.leaves.values())if(leaf.display!=display)
            need(!observed.containsKey(leaf.id),"NOTES_OBSERVED_TASK_ESCAPED");
        for(Map.Entry<Integer,BackgroundOwnedSingleTask.Task> entry:actual.entrySet()){
            BackgroundOwnedSingleTask.Task old=observed.get(entry.getKey()),fresh=entry.getValue();
            need(!afterRelease||old!=null,"NOTES_NEW_TASK_AFTER_RELEASE");
            need(old==null||(Objects.equals(old.token,fresh.token)&&old.id==fresh.id&&old.user==fresh.user
                    &&old.uid==fresh.uid&&old.display==fresh.display&&old.parent==fresh.parent),"NOTES_TASK_TOKEN_OR_IDENTITY_CHANGED");
        }
        need(observed.size()+actual.size()<=MAX_TASKS*2,"NOTES_TASK_ACCOUNTING_BOUND");
        observed.putAll(actual);lastObservation=frame.end;
    }
    private void walk(Node node,int parent,int depth,Map<Integer,BackgroundOwnedSingleTask.Task> rows,Set<Integer> leaves){
        BackgroundOwnedSingleTask.Task task=node.task;
        need(depth<=4&&task.id>0&&task.display==display&&task.user==0&&task.token!=null&&!initialIds.contains(task.id)
                &&rows.size()<MAX_TASKS&&rows.put(task.id,task)==null,"NOTES_TASK_NOT_NEW_ON_OWN_DISPLAY");
        need(parent<0?task.parent<0:task.parent==parent,"NOTES_TASK_PARENT_CHANGED");
        if(node.children.isEmpty()){
            need((task.uid==uid&&(task.topUid==uid||(task.activities==0&&task.topUid==-1))
                    &&pkg(task.intentComponent)&&pkg(task.base)&&pkg(task.real)
                    &&nullablePkg(task.top)&&nullablePkg(task.orig))||emptyActivityLeaf(task,uid),
                    "NOTES_ACTUAL_LEAF_UID_OR_PACKAGE_UNKNOWN");
            leaves.add(task.id);
        }else{
            need((task.uid==0||task.uid==uid)&&nullablePkg(task.intentComponent)&&nullablePkg(task.base)
                    &&nullablePkg(task.real)&&nullablePkg(task.top)&&nullablePkg(task.orig),"NOTES_FOREIGN_CONTAINER");
            for(Node child:node.children)walk(child,task.id,depth+1,rows,leaves);
        }
    }
    synchronized void prepareRelease(Frame frame,PublicOwnGroupPhysicalFence.RecentCensus recents,long now){
        need(retiring&&!releasePrepared&&!releaseAttempted,"NOTES_RELEASE_ALREADY_PREPARED");
        try{
            observeChecked(frame,now);need(recents!=null,"NOTES_RELEASE_RECENTS_UNAVAILABLE");
            for(PublicOwnGroupPhysicalFence.RecentRecord row:recents.records.values()){
                if(observed.containsKey(row.task)){
                    requireOwnedRecent(row);releaseRecents.put(row.task,row);
                }else need(row.uid!=uid&&!pkg(row.activity)&&!pkg(row.base),"NOTES_UNOBSERVED_TASK_IN_RECENTS");
            }
            requireUnownedRecents(recents);
            for(Map.Entry<Integer,String> hidden:recents.hiddenLabels.entrySet())if(observed.containsKey(hidden.getKey())){
                PublicOwnGroupPhysicalFence.RecentRecord row=releaseRecents.get(hidden.getKey());
                need(row!=null&&row.label.equals(hidden.getValue()),"NOTES_RELEASE_HIDDEN_IDENTITY_UNKNOWN");
            }
            initialRecents.requirePhysicalIdentities(recents,observed.keySet(),uid);
            requireHiddenBaseline(recents);releaseHistory=protectedHistory(recents);
            physicalHistoryChanged|=!initialRecents.unrelatedPhysicalHistory(observed.keySet(),uid).equals(recents.unrelatedPhysicalHistory(observed.keySet(),uid));
            hiddenHistoryChanged|=!fullHiddenBaseline.equals(hiddenHistory(recents,false));
            presentationChanged|=!initialRecents.recentsPresentation().equals(recents.recentsPresentation());
            releaseCensus=lastRecents=recents;
            releaseRecentsSha=recents.rawSha256;releasePrepared=true;
        }catch(RuntimeException error){unresolved(error.getMessage());throw error;}
    }
    private void requireOwnedRecent(PublicOwnGroupPhysicalFence.RecentRecord row){
        need(row.user==0&&row.uid==uid&&row.display==display&&observed.containsKey(row.root)
                &&pkg(row.activity)&&pkg(row.base),"NOTES_RECENT_UID_OR_PACKAGE_CHANGED");
    }
    private List<String> hiddenHistory(PublicOwnGroupPhysicalFence.RecentCensus recents,boolean protectedOnly){
        List<String> unrelated=new ArrayList<String>();
        Set<Integer> physical=protectedOnly?recents.unrelatedPhysicalIds(observed.keySet(),uid):Collections.emptySet();
        for(Map.Entry<Integer,String> row:recents.hiddenLabels.entrySet())
            if(!observed.containsKey(row.getKey())&&!physical.contains(row.getKey()))unrelated.add(row.getValue());
        return unrelated;
    }
    private String protectedHistory(PublicOwnGroupPhysicalFence.RecentCensus recents){
        Set<Integer> excluded=new LinkedHashSet<Integer>(observed.keySet());
        excluded.addAll(recents.unrelatedPhysicalIds(observed.keySet(),uid));return recents.protectedRuntimeHistoryExcept(excluded);
    }
    private void requireHiddenBaseline(PublicOwnGroupPhysicalFence.RecentCensus recents){
        need(hiddenBaseline.equals(hiddenHistory(recents,true)),"NOTES_UNRESOLVED_HIDDEN_HISTORY_NOT_PRESERVED");
    }
    private void requireUnownedRecents(PublicOwnGroupPhysicalFence.RecentCensus recents){
        for(PublicOwnGroupPhysicalFence.RecentRecord row:recents.records.values())if(!observed.containsKey(row.task)){
            need(row.uid!=uid&&!pkg(row.activity)&&!pkg(row.base)&&!targetHidden(row.label)
                    &&row.display!=display&&!observed.containsKey(row.root),"NOTES_UNOBSERVED_TASK_IN_RECENTS");
            for(PublicOwnGroupPhysicalFence.RecentRecord owned:releaseRecents.values())
                need(!owned.token.equals(row.token),"NOTES_OWNED_RECENT_TOKEN_REUSED");
        }
        for(Map.Entry<Integer,String> hidden:recents.hiddenLabels.entrySet())if(!observed.containsKey(hidden.getKey())){
            need(!targetHidden(hidden.getValue()),"NOTES_UNOBSERVED_HIDDEN_TARGET");
            for(PublicOwnGroupPhysicalFence.RecentRecord owned:releaseRecents.values())
                need(!hidden.getValue().startsWith("Task{"+owned.token+" #"),"NOTES_OWNED_HIDDEN_TOKEN_REUSED");
        }
    }
    synchronized void retireAdmission(){retiring=true;}
    synchronized void enterRelease(){need(releasePrepared&&!unknown&&!releaseAttempted,"NOTES_RELEASE_NOT_ADMITTED");releaseAttempted=true;}
    synchronized void releaseReturned(){need(releaseAttempted&&!unknown,"NOTES_RELEASE_RETURN_UNBOUND");releaseReturned=true;}
    /** A private-constructor snapshot of actual released custody, never a wire
     * capability or an absence proof. The reader may only discard disappearing
     * members of this set; it cannot admit a new or replaced task. */
    static final class ReleasedRead {
        private final int display,uid;
        private final Map<Integer,BackgroundOwnedSingleTask.Task> tasks;
        private ReleasedRead(int display,int uid,Map<Integer,BackgroundOwnedSingleTask.Task> tasks){
            this.display=display;this.uid=uid;
            this.tasks=Collections.unmodifiableMap(new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>(tasks));
        }
        void requireScope(int display,int uid){need(this.display==display&&this.uid==uid,"NOTES_RELEASED_READ_SCOPE");}
        void requireGlobal(ProfileTaskPolicy.Snapshot global){
            need(global!=null,"NOTES_GLOBAL_CENSUS_UNAVAILABLE");
            for(ProfileTaskPolicy.Root root:global.roots)if(tasks.containsKey(root.id))
                need(root.display==display,"NOTES_OBSERVED_TASK_ESCAPED");
            for(ProfileTaskPolicy.Leaf leaf:global.leaves.values())if(tasks.containsKey(leaf.id))
                need(leaf.display==display,"NOTES_OBSERVED_TASK_ESCAPED");
        }
        BackgroundOwnedSingleTask.Task retained(int id){
            BackgroundOwnedSingleTask.Task task=tasks.get(id);
            need(task!=null,"NOTES_NEW_TASK_AFTER_RELEASE");return task;
        }
    }
    synchronized ReleasedRead releasedRead(){
        need(retiring&&releasePrepared&&releaseAttempted&&releaseReturned&&!unknown&&!known,
                "NOTES_RELEASED_READ_UNAVAILABLE");
        return new ReleasedRead(display,uid,observed);
    }
    synchronized boolean needsActualTasks(ProfileTaskPolicy.Snapshot live){
        need(live!=null,"NOTES_LIVE_CENSUS_UNAVAILABLE");
        for(int id:observed.keySet())if(live.allIds.contains(id))return true;
        for(ProfileTaskPolicy.Root root:live.roots)if(root.display==display)return true;
        for(ProfileTaskPolicy.Leaf leaf:live.leaves.values())if(leaf.display==display)return true;
        return false;
    }
    synchronized void observeAbsence(ProfileTaskPolicy.Snapshot live,PublicOwnGroupPhysicalFence.RecentCensus recents,
            boolean actualDisplayAbsent,long begin,long end,long now){
        observeAbsence(live,recents,null,actualDisplayAbsent,begin,end,now);
    }
    synchronized void observeAbsence(ProfileTaskPolicy.Snapshot live,PublicOwnGroupPhysicalFence.RecentCensus recents,
            Frame actualRemaining,boolean actualDisplayAbsent,long begin,long end,long now){
        try{
            need(!unknown&&releaseReturned&&actualDisplayAbsent&&live!=null&&recents!=null&&begin>=0&&end>=begin
                    &&now>=end&&now-begin<=1500&&begin>lastAbsence,"NOTES_ABSENCE_READ_UNAVAILABLE");
            boolean pending=needsActualTasks(live);
            if(pending){
                need(actualRemaining!=null&&actualRemaining.global==live,"NOTES_REMAINING_LIVE_IDENTITY_UNPROVED");
                observeChecked(actualRemaining,now,true);
            }else requireNoNotes(live);
            for(ProfileTaskPolicy.Root root:live.roots)if(root.display!=display)
                need(!pkg(root.base)&&!pkg(root.top),"NOTES_TASK_ESCAPED_AFTER_RELEASE");
            for(ProfileTaskPolicy.Leaf leaf:live.leaves.values())if(leaf.display!=display)
                need(!pkg(leaf.name),"NOTES_TASK_ESCAPED_AFTER_RELEASE");
            requireUnownedRecents(recents);
            releaseCensus.requirePhysicalIdentities(recents,observed.keySet(),uid);
            lastRecents.requirePhysicalIdentities(recents,observed.keySet(),uid);
            need(releaseHistory.equals(protectedHistory(recents)),"NOTES_PROTECTED_HISTORY_CHANGED_AFTER_RELEASE");
            requireHiddenBaseline(recents);
            for(int id:observed.keySet())if(recents.allIds.contains(id)){
                PublicOwnGroupPhysicalFence.RecentRecord frozen=releaseRecents.get(id),row=recents.records.get(id);
                need(frozen!=null,"NOTES_REMAINING_RECENT_IDENTITY_UNPROVED");
                if(row!=null){requireOwnedRecent(row);need(frozen.identity.equals(row.identity),"NOTES_REMAINING_RECENT_TOKEN_CHANGED");}
                String hidden=recents.hiddenLabels.get(id);
                if(hidden!=null)need(frozen.label.equals(hidden),"NOTES_REMAINING_HIDDEN_TOKEN_CHANGED");
                pending=true;
            }
            physicalHistoryChanged|=!lastRecents.unrelatedPhysicalHistory(observed.keySet(),uid).equals(recents.unrelatedPhysicalHistory(observed.keySet(),uid));
            hiddenHistoryChanged|=!hiddenHistory(lastRecents,false).equals(hiddenHistory(recents,false));
            presentationChanged|=!lastRecents.recentsPresentation().equals(recents.recentsPresentation());
            lastRecents=recents;lastAbsence=end;finalRecentsSha=recents.rawSha256;absenceReads++;
            if(pending){absenceReads=0;pendingReads++;return;}
            if(absenceReads>=2)known=true;
        }catch(RuntimeException error){unresolved(error.getMessage());throw error;}
    }
    synchronized void notCreated(){need(retiring&&!attempted&&!unknown,"NOTES_CREATE_MAY_HAVE_OCCURRED");known=true;}
    synchronized void unresolved(String reason){unknown=true;known=false;failure=reason==null?"NOTES_CLEANUP_UNKNOWN":reason;}
    synchronized boolean retain(){return attempted&&!known;}
    synchronized boolean known(){return known&&!unknown;}
    int expectedUid(){return uid;}
    synchronized boolean createAttempted(){return attempted;}
    synchronized Map<String,Object> evidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema",SCHEMA);out.put("generation",generation);
        out.put("scope_sha256",scopeSha256);out.put("package",PACKAGE);out.put("target_uid",uid);out.put("display_id",display);
        out.put("create_attempted",attempted);out.put("launch_dispatched",launched);out.put("pre_release_tasks_verified",releasePrepared);
        out.put("release_api_entered",releaseAttempted);out.put("release_api_returned",releaseReturned);
        out.put("absence_reads",absenceReads);out.put("pending_owned_reads",pendingReads);out.put("cleanup_known",known());out.put("identity_unknown",unknown);
        out.put("display_absence_verified",known()&&attempted);out.put("live_tasks_absent",known()&&attempted);
        out.put("all_recents_sections_absent",known()&&attempted);
        out.put("prior_hidden_history_preserved",known()&&attempted&&!hiddenHistoryChanged);
        out.put("history_preservation_scope","nonphysical_and_unresolved_recents");out.put("physical_history_frozen",false);
        out.put("history_preservation_interval","pre_release_to_absence");out.put("hidden_history_preservation_interval","initial_to_absence");
        out.put("unrelated_physical_history_changes_observed",physicalHistoryChanged);
        out.put("recents_presentation_changes_observed",presentationChanged);
        out.put("nonphysical_history_preserved",known()&&attempted);out.put("nonphysical_hidden_history_preserved",known()&&attempted);
        out.put("no_display_create_attempted",!attempted);out.put("custodian_retained",retain());out.put("failure",failure);
        out.put("initial_recents_sha256",initialRecentsSha);out.put("pre_release_recents_sha256",releaseRecentsSha);out.put("final_recents_sha256",finalRecentsSha);
        List<Map<String,Object>> tasks=new ArrayList<Map<String,Object>>();
        for(BackgroundOwnedSingleTask.Task task:observed.values()){
            Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("task_id",task.id);row.put("user_id",task.user);
            row.put("actual_effective_uid",task.uid);row.put("display_id",task.display);row.put("parent_id",task.parent);
            row.put("token_identity_in_broker",System.identityHashCode(task.token));row.put("serialized_token_grants_authority",false);tasks.add(row);
        }
        out.put("actual_observed_tasks",Collections.unmodifiableList(tasks));out.put("arbitrary_task_removal_used",false);
        out.put("force_stop_used",false);out.put("caller_flag_is_cleanup_proof",false);
        return Collections.unmodifiableMap(out);
    }
}
