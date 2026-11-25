package org.trillionnium.hepta.background;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Bounded pre-release retirement. The port has no launch, input, numeric task
 * removal, root deletion or force-stop operation. A return is never absence. */
final class PublicPersonalNotesRetirement {
    interface Port {
        Sample read() throws Exception;
        default Sample readAfter(Effect effect) throws Exception{return read();}
        void remove(Effect effect) throws Exception;
        long now();
        void awaitRead() throws Exception;
    }
    /** Complete physical observation with a separate immutable device identity.
     * Focus, IME, power, rotation and unrelated activities are observations only. */
    static final class Physical {
        final Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> devices;
        final Map<Integer,String> observed;
        Physical(Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> devices,Map<Integer,String> observed){
            need(devices!=null&&devices.size()==2&&observed!=null&&observed.size()==2,
                    "NOTES_RETIREMENT_PHYSICAL_INCOMPLETE");
            for(int id:new int[]{0,1})need(devices.get(id)!=null&&devices.get(id).id==id
                    &&ProfileIdentity.hash(observed.get(id)),"NOTES_RETIREMENT_PHYSICAL_INCOMPLETE");
            need(!devices.get(0).uniqueId.equals(devices.get(1).uniqueId),"NOTES_RETIREMENT_PHYSICAL_INCOMPLETE");
            this.devices=Collections.unmodifiableMap(new LinkedHashMap<Integer,PublicOwnGroupPhysicalFence.DisplayFacts>(devices));
            this.observed=Collections.unmodifiableMap(new LinkedHashMap<Integer,String>(observed));
        }
        void requireSameDevices(Physical after){
            need(after!=null,"NOTES_RETIREMENT_PHYSICAL_INCOMPLETE");
            requireSameDevices(devices,after.devices);
        }
        static void requireSameDevices(Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> before,
                Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> after){
            need(before!=null&&after!=null&&before.size()==2&&after.size()==2,"NOTES_RETIREMENT_PHYSICAL_INCOMPLETE");
            for(int id:new int[]{0,1}){
                PublicOwnGroupPhysicalFence.DisplayFacts a=before.get(id),b=after.get(id);
                need(a!=null&&b!=null&&a.id==id&&b.id==id&&a.type==b.type&&a.uniqueId.equals(b.uniqueId),
                        "NOTES_RETIREMENT_PHYSICAL_DEVICE_CHANGED");
            }
        }
    }
    static final class Sample {
        final PublicPersonalNotesCustody.Frame frame;
        final PublicOwnGroupPhysicalFence.RecentCensus recents;
        final History history;
        final Map<Integer,BackgroundOwnedSingleTask.Task> actualTasks;
        final Physical physical;
        final long begin,end;
        Sample(PublicPersonalNotesCustody.Frame frame,String rawRecents,
                Map<Integer,BackgroundOwnedSingleTask.Task> actualTasks,Physical physical,long begin,long end,
                int ownedDisplay,int ownedUid){
            need(ownedDisplay>1&&ownedUid>=10000&&frame!=null&&actualTasks!=null&&physical!=null&&begin>=0&&end>=begin&&end-begin<=1500
                    &&frame.begin>=begin&&frame.end<=end,"NOTES_RETIREMENT_SAMPLE_INCOMPLETE");
            need(actualTasks.size()<=ProfileTaskPolicy.MAX_LEAVES+ProfileTaskPolicy.MAX_ROOTS
                    &&actualTasks.keySet().containsAll(frame.global.allIds),"NOTES_RETIREMENT_ACTUAL_UID_CENSUS_INCOMPLETE");
            Set<Object> tokens=new LinkedHashSet<Object>();
            for(Map.Entry<Integer,BackgroundOwnedSingleTask.Task> entry:actualTasks.entrySet()){
                BackgroundOwnedSingleTask.Task task=entry.getValue();
                need(task!=null&&task.id==entry.getKey()&&task.token!=null&&tokens.add(task.token)&&task.uid>=0&&task.user>=0&&task.display>=0,
                        "NOTES_RETIREMENT_ACTUAL_TASK_INVALID");
                ProfileTaskPolicy.Leaf leaf=frame.global.leaves.get(task.id);
                if(leaf!=null)need(leaf.display==task.display&&leaf.user==task.user,"NOTES_RETIREMENT_LEAF_LOCATION_CHANGED");
            }
            Set<Integer> traversed=new LinkedHashSet<Integer>();
            for(ProfileTaskPolicy.Root root:frame.global.roots){
                BackgroundOwnedSingleTask.Task actual=actualTasks.get(root.id);
                need(actual!=null&&actual.parent<0&&actual.display==root.display&&actual.user==root.user,
                        "NOTES_RETIREMENT_ACTUAL_ROOT_LOCATION");traversed.add(root.id);
            }
            for(ProfileTaskPolicy.Leaf leaf:frame.global.leaves.values()){
                BackgroundOwnedSingleTask.Task node=actualTasks.get(leaf.id);Set<Integer> chain=new LinkedHashSet<Integer>();
                if(ordinaryForeignRootMember(frame.global,actualTasks,leaf,ownedDisplay,ownedUid)){
                    traversed.add(node.id);traversed.add(leaf.parent);continue;
                }
                while(node.id!=leaf.parent){
                    need(chain.size()<8&&chain.add(node.id)&&node.parent>0&&node.display==leaf.display,
                            "NOTES_RETIREMENT_ACTUAL_ANCESTRY");traversed.add(node.id);node=actualTasks.get(node.parent);
                    need(node!=null,"NOTES_RETIREMENT_ACTUAL_ANCESTOR_MISSING");
                }
                traversed.add(node.id);
            }
            need(traversed.equals(actualTasks.keySet()),"NOTES_RETIREMENT_UNCLASSIFIED_ACTUAL_TASK");
            this.frame=frame;history=new History(rawRecents,begin,end);recents=history.census;
            this.actualTasks=Collections.unmodifiableMap(new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>(actualTasks));
            this.physical=physical;this.begin=begin;this.end=end;
            requireRecentLiveIdentities(recents,frame.global,actualTasks,ownedUid);
        }
        boolean contains(int id){return frame.global.allIds.contains(id)||recents.allIds.contains(id);}
    }
    /** Constructed only by this coordinator. The adapter must submit a complete
     * new final read before entering the original custodian's single-use bit. */
    static final class Effect {
        private final PublicPersonalNotesRetirement owner;
        private final PublicPersonalNotesCustody.TokenEntry entry;
        private boolean callReturned;
        private PendingRead pending;
        private Sample absentBeforeCall;
        private Effect(PublicPersonalNotesRetirement owner,PublicPersonalNotesCustody.TokenEntry entry){this.owner=owner;this.entry=entry;}
        Object token(){return entry.token();}
        int id(){return entry.id();}
        void beforeCall(Sample actual,long now){owner.verify(actual,now,true);entry.beforeCall(actual.frame,actual.recents,now);}
        void returned(){entry.returned();callReturned=true;owner.lastReturnedEffect=this;}
        Sample finalRead(Port port)throws Exception{
            return owner.lastReturnedEffect==null?port.read():port.readAfter(owner.lastReturnedEffect);
        }
        boolean skipAbsent(Sample actual,long now){
            if(actual.contains(id()))return false;
            owner.verify(actual,now,true);absentBeforeCall=actual;return true;
        }
        PendingRead pendingRead(){
            need(callReturned&&owner.plan!=null&&owner.plan.attempted(id()),"NOTES_RETIREMENT_RETURNED_EFFECT_REQUIRED");
            if(pending==null)pending=new PendingRead(owner,this);
            pending.active();return pending;
        }
    }
    /** Private post-returned observation context. It can discard an inconsistent
     * read of the exact retiring set, but cannot supply a Sample, an Effect,
     * an absence count, a VD-release claim, or a new deadline. */
    static final class PendingRead implements PublicPersonalNotesReader.RetirementRead {
        private final PublicPersonalNotesRetirement owner;
        private final Effect effect;
        private Map<Integer,BackgroundOwnedSingleTask.Task> remaining;
        private ProfileTaskPolicy.Snapshot priorGlobal;
        private Map<Integer,List<List<?>>> priorOwnedGlobal;
        private PendingRead(PublicPersonalNotesRetirement owner,Effect effect){
            this.owner=owner;this.effect=effect;
            need(owner.last!=null,"NOTES_RETIREMENT_PRIOR_SAMPLE_REQUIRED");
            remaining=owned(owner.last.actualTasks);priorGlobal=owner.last.frame.global;
            priorOwnedGlobal=ownedRows(priorGlobal);active();
        }
        private void active(){
            need(effect.callReturned&&owner.started&&!owner.ready&&owner.plan!=null
                    &&owner.plan.attempted(effect.id()),"NOTES_RETIREMENT_RETURNED_EFFECT_REQUIRED");
            owner.plan.requirePendingRead(owner.port.now());
        }
        @Override public void requireScope(int display,int uid){
            active();need(display==owner.plan.display&&uid==owner.plan.uid,"NOTES_RETIREMENT_PENDING_SCOPE");
        }
        private Map<Integer,BackgroundOwnedSingleTask.Task> owned(Map<Integer,BackgroundOwnedSingleTask.Task> all){
            Map<Integer,BackgroundOwnedSingleTask.Task> out=new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>();
            for(Map.Entry<Integer,BackgroundOwnedSingleTask.Task> e:all.entrySet())if(owner.plan.ids.contains(e.getKey()))out.put(e.getKey(),e.getValue());
            return out;
        }
        private Map<Integer,List<List<?>>> ownedRows(ProfileTaskPolicy.Snapshot global){
            Map<Integer,List<List<?>>> out=new LinkedHashMap<Integer,List<List<?>>>();
            for(List<?> row:global.excludingRoot(-1)){
                int id=((Integer)row.get(0)).intValue();
                if(owner.plan.ids.contains(id))out.computeIfAbsent(id,k->new ArrayList<List<?>>()).add(row);
            }
            return out;
        }
        private void globalFacts(ProfileTaskPolicy.Snapshot global){
            owner.requireForeignGlobal(global);
            for(ProfileTaskPolicy.Root root:global.roots)if(owner.plan.ids.contains(root.id))
                need(root.display==owner.plan.display&&root.user==0,"NOTES_RETIREMENT_PENDING_TASK_MIGRATED");
            for(ProfileTaskPolicy.Leaf leaf:global.leaves.values())if(owner.plan.ids.contains(leaf.id)||owner.plan.ids.contains(leaf.parent))
                need(leaf.id==leaf.parent&&owner.plan.ids.contains(leaf.id)&&leaf.display==owner.plan.display&&leaf.user==0,
                        "NOTES_RETIREMENT_PENDING_TASK_MIGRATED");
        }
        private void monotoneGlobal(Map<Integer,List<List<?>>> next){
            need(priorOwnedGlobal.keySet().containsAll(next.keySet()),"NOTES_RETIREMENT_PENDING_TASK_REAPPEARED");
            for(Map.Entry<Integer,List<List<?>>> e:next.entrySet()){
                List<List<?>> a=priorOwnedGlobal.get(e.getKey()),b=e.getValue();
                need(a.size()==2&&b.size()==2&&a.get(0).size()==7&&b.get(0).size()==7
                        &&a.get(1).size()==5&&b.get(1).size()==5,"NOTES_RETIREMENT_PENDING_GLOBAL_INCOMPLETE");
                List<?> x=a.get(0),y=b.get(0),u=a.get(1),v=b.get(1);
                for(int k:new int[]{0,1,2})need(Objects.equals(x.get(k),y.get(k)),"NOTES_RETIREMENT_PENDING_TASK_MIGRATED");
                int before=((Integer)x.get(3)).intValue(),after=((Integer)y.get(3)).intValue();
                need(after<=before&&(!((Boolean)y.get(4)).booleanValue()||((Boolean)x.get(4)).booleanValue()),
                        "NOTES_RETIREMENT_PENDING_ACTIVITY_GREW");
                for(int k:new int[]{0,1,2,4})need(Objects.equals(u.get(k),v.get(k)),"NOTES_RETIREMENT_PENDING_CHILD_CHANGED");
                need(Objects.equals(v.get(0),v.get(1)),"NOTES_RETIREMENT_PENDING_NONLEAF");
                if(after==before)need(Objects.equals(x.get(5),y.get(5))&&Objects.equals(x.get(6),y.get(6))
                        &&Objects.equals(u.get(3),v.get(3)),"NOTES_RETIREMENT_PENDING_ACTIVITY_REPLACED");
                else need((y.get(5)==null||notes((String)y.get(5)))&&(y.get(6)==null||notes((String)y.get(6)))
                        &&(notes((String)v.get(3))||(after==0&&"unknown".equals(v.get(3)))),
                        "NOTES_RETIREMENT_PENDING_COMPONENT_CHANGED");
            }
        }
        void pair(BackgroundOwnedSingleTask.Task before,BackgroundOwnedSingleTask.Task after){
            active();need(before!=null&&after!=null&&owner.plan.ids.contains(before.id)&&before.id==after.id
                    &&PublicPersonalNotesCustody.sameTokenIdentity(owner.plan.tasks.get(before.id),before)
                    &&PublicPersonalNotesCustody.sameTokenIdentity(before,after),
                    "NOTES_RETIREMENT_PENDING_IDENTITY_CHANGED");
            need(after.activities<=before.activities&&(!after.running||before.running)&&(!after.visible||before.visible),
                    "NOTES_RETIREMENT_PENDING_ACTIVITY_GREW");
            if(after.activities==before.activities)need(after.topUid==before.topUid&&Objects.equals(after.base,before.base)
                    &&Objects.equals(after.top,before.top),"NOTES_RETIREMENT_PENDING_ACTIVITY_REPLACED");
            need((after.uid==owner.plan.uid&&after.topUid==owner.plan.uid&&after.activities>0
                    &&notes(after.intentComponent)&&notes(after.base)&&notes(after.real)&&(after.top==null||notes(after.top))
                    &&(after.orig==null||notes(after.orig)))||PublicPersonalNotesCustody.emptyActivityLeaf(after,owner.plan.uid),
                    "NOTES_RETIREMENT_PENDING_COMPONENT_CHANGED");
        }
        @Override public void observeCensus(ProfileTaskPolicy.Snapshot global,
                Map<Integer,BackgroundOwnedSingleTask.Task> rows,String stage)throws Exception{
            active();
            try{
                globalFacts(global);Map<Integer,List<List<?>>> nextGlobal=ownedRows(global);monotoneGlobal(nextGlobal);
                need(nextGlobal.keySet().equals(rows.keySet())&&remaining.keySet().containsAll(rows.keySet()),
                        "NOTES_RETIREMENT_PENDING_CENSUS_INCOMPLETE");
                for(BackgroundOwnedSingleTask.Task row:rows.values())pair(remaining.get(row.id),row);
                remaining=new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>(rows);
                priorOwnedGlobal=nextGlobal;priorGlobal=global;
            }catch(RuntimeException error){throw refusal(error.getMessage(),stage,priorGlobal,global,rows);}
        }
        void actual(ProfileTaskPolicy.Snapshot global,Map<Integer,BackgroundOwnedSingleTask.Task> rows)throws Exception{
            active();
            try{owner.requireForeignActual(rows);}
            catch(RuntimeException error){throw refusal(error.getMessage(),"actual_uid_and_binder",priorGlobal,global,owned(rows));}
            observeCensus(global,owned(rows),"actual_global_and_uid");
        }
        boolean facts(List<PublicPersonalNotesCustody.Frame> frames,String rawRecents,
                Physical physical,long begin,long end)throws Exception{
            active();long now=owner.port.now();
            need(begin>=owner.last.end&&end>=begin&&now>=end&&now-begin<=1500&&now<owner.deadline,
                    "NOTES_RETIREMENT_DEADLINE_OR_STALE");
            owner.baseline.physical.requireSameDevices(physical);
            need(frames!=null&&frames.size()==6,"NOTES_RETIREMENT_COMPLETE_BATCH_REQUIRED");
            History history=new History(rawRecents,begin,end);
            owner.requireHistory(history,begin,end);
            boolean pending=false;
            for(PublicPersonalNotesCustody.Frame frame:frames){
                need(frame.begin>=begin&&frame.end<=end,"NOTES_RETIREMENT_FRAME_OUTSIDE_BATCH");globalFacts(frame.global);
                pending|=owner.plan.verifyPendingRead(frame,history.census,now);
            }
            return pending;
        }
        PublicPersonalNotesReader.TaskInfoReadFailure refusal(String code,String stage,
                ProfileTaskPolicy.Snapshot before,ProfileTaskPolicy.Snapshot after,
                Map<Integer,BackgroundOwnedSingleTask.Task> actual){
            Map<String,Object> evidence=new LinkedHashMap<String,Object>();
            evidence.put("schema","hepta.notes-pending-retirement-read-refusal.v1");
            evidence.put("classification","post_returned_read_not_a_cleanup_or_action_proof");
            evidence.put("returned_effect_task_id",effect.id());evidence.put("effect_returned",effect.callReturned);
            evidence.put("original_deadline_elapsed_ms",owner.deadline);
            evidence.put("planned_owned_task_ids",new ArrayList<Integer>(owner.plan.ids));
            evidence.put("before_task_ids",before==null?Collections.emptyList():new ArrayList<Integer>(before.allIds));
            evidence.put("after_task_ids",after==null?Collections.emptyList():new ArrayList<Integer>(after.allIds));
            evidence.put("differing_global_root_ids",differing(before,after));
            List<Integer> changed=new ArrayList<Integer>();
            Set<Integer> all=new LinkedHashSet<Integer>(remaining.keySet());if(actual!=null)all.addAll(actual.keySet());
            for(int id:all)if(actual==null||!sameTask(remaining.get(id),actual.get(id)))changed.add(id);
            evidence.put("differing_owned_actual_task_ids",changed);
            evidence.put("diagnostics_grant_authority",false);
            return new PublicPersonalNotesReader.TaskInfoReadFailure(code,stage,evidence);
        }
        private static List<Integer> differing(ProfileTaskPolicy.Snapshot before,ProfileTaskPolicy.Snapshot after){
            Map<Integer,List<List<?>>> a=group(before),b=group(after);Set<Integer> ids=new LinkedHashSet<Integer>(a.keySet());ids.addAll(b.keySet());
            List<Integer> out=new ArrayList<Integer>();for(int id:ids)if(!Objects.equals(a.get(id),b.get(id)))out.add(id);return out;
        }
        private static Map<Integer,List<List<?>>> group(ProfileTaskPolicy.Snapshot global){
            Map<Integer,List<List<?>>> out=new LinkedHashMap<Integer,List<List<?>>>();
            if(global!=null)for(List<?> row:global.excludingRoot(-1))
                out.computeIfAbsent((Integer)row.get(0),k->new ArrayList<List<?>>()).add(row);
            return out;
        }
    }
    private final PublicPersonalNotesCustody custody;
    private final Port port;
    private final long deadline;
    private PublicPersonalNotesCustody.TokenPlan plan;
    private Sample baseline,last;
    private boolean started,ready;
    private Effect lastReturnedEffect;
    // Keep identities observed even in discarded read batches. A later restore
    // cannot erase a UID/Binder/location substitution seen by a complete read.
    private final Map<Integer,List<?>> physicalActualIdentities=new LinkedHashMap<Integer,List<?>>();
    private final Map<Object,Integer> physicalBinderOwners=new LinkedHashMap<Object,Integer>();
    private final Map<String,List<?>> physicalGlobalLocations=new LinkedHashMap<String,List<?>>();
    private final Map<Integer,PublicOwnGroupPhysicalFence.RecentRecord> physicalRecentIdentities=
            new LinkedHashMap<Integer,PublicOwnGroupPhysicalFence.RecentRecord>();
    PublicPersonalNotesRetirement(PublicPersonalNotesCustody custody,Port port,long deadline){
        need(custody!=null&&port!=null&&deadline>0,"NOTES_RETIREMENT_BINDING");this.custody=custody;this.port=port;this.deadline=deadline;
    }
    void retire() throws Exception {
        need(!started,"NOTES_RETIREMENT_REENTRY");started=true;
        try{
            baseline=port.read();fresh(baseline,port.now());
            plan=custody.prepareTokenRetirement(baseline.frame,baseline.recents,port.now(),deadline);
            verify(baseline,port.now(),false);
            // Two independent complete samples precede the first possible effect.
            Sample current=port.read();verify(current,port.now(),true);
            for(int id:plan.ids){
                if(!current.contains(id))continue;
                need(current.frame.global.allIds.contains(id),"NOTES_RETIREMENT_DETACHED_RECENT_REQUIRES_MAINTENANCE");
                Effect effect=new Effect(this,plan.entry(id));port.remove(effect);
                if(effect.absentBeforeCall!=null){current=effect.absentBeforeCall;continue;}
                need(plan.attempted(id),"NOTES_RETIREMENT_EFFECT_NOT_ENTERED");
                int reads=0;
                do{
                    need(++reads<=32,"NOTES_RETIREMENT_PENDING_READ_BOUND");
                    current=port.readAfter(effect);verify(current,port.now(),true);
                    if(current.contains(id))port.awaitRead();
                }while(current.contains(id));
            }
            plan.absent(current.frame,current.recents,port.now());
            current=port.read();verify(current,port.now(),true);
            plan.absent(current.frame,current.recents,port.now());ready=true;
        }catch(Exception error){custody.unresolved(error.getMessage());throw error;}
    }
    void afterRelease(Sample sample,long now){
        need(ready&&plan!=null,"NOTES_RETIREMENT_RELEASE_NOT_READY");
        verify(sample,now,false);
        for(int id:plan.ids)need(!sample.contains(id),"NOTES_RETIREMENT_POST_RELEASE_RESIDUE");
    }
    void beforeRelease(long now){
        need(ready&&last!=null,"NOTES_RETIREMENT_RELEASE_NOT_READY");fresh(last,now);
        for(int id:plan.ids)need(!last.contains(id),"NOTES_RETIREMENT_RELEASE_ABSENCE_REQUIRED");
    }
    private void fresh(Sample sample,long now){need(sample!=null&&now>=sample.end&&now-sample.begin<=1500&&now<deadline,
            "NOTES_RETIREMENT_DEADLINE_OR_STALE");}
    private void verify(Sample sample,long now,boolean advance){
        fresh(sample,now);need(plan!=null&&baseline!=null,"NOTES_RETIREMENT_PLAN_UNAVAILABLE");
        if(advance)need(last!=null&&sample!=last&&sample.begin>=last.end&&sample.end>last.end,"NOTES_RETIREMENT_SAMPLE_REPLAYED");
        baseline.physical.requireSameDevices(sample.physical);
        requireForeignGlobal(sample.frame.global);
        requireForeignActual(sample.actualTasks);
        requireHistory(sample.history,sample.begin,sample.end);
        if(!ready)plan.verify(sample.frame,sample.recents,now);
        last=sample;
    }
    private void requireForeignGlobal(ProfileTaskPolicy.Snapshot global){
        need(global!=null&&globalRows(baseline.frame.global,plan.ids).equals(globalRows(global,plan.ids)),
                "NOTES_RETIREMENT_FOREIGN_GLOBAL_CHANGED");
        Map<String,List<?>> current=physicalLocations(global,plan.ids);
        for(Map.Entry<String,List<?>> e:current.entrySet()){
            List<?> old=physicalGlobalLocations.get(e.getKey());
            need(old==null||old.equals(e.getValue()),"NOTES_RETIREMENT_PHYSICAL_TASK_LOCATION_CHANGED");
            physicalGlobalLocations.put(e.getKey(),e.getValue());
            need(physicalGlobalLocations.size()<=2*(ProfileTaskPolicy.MAX_LEAVES+ProfileTaskPolicy.MAX_ROOTS),
                    "NOTES_RETIREMENT_PHYSICAL_IDENTITY_BOUND");
        }
    }
    private void requireForeignActual(Map<Integer,BackgroundOwnedSingleTask.Task> rows){
        need(foreignActual(baseline.actualTasks).equals(foreignActual(rows)),"NOTES_RETIREMENT_FOREIGN_ACTUAL_CHANGED");
        for(BackgroundOwnedSingleTask.Task task:rows.values())if(!plan.ids.contains(task.id)){
            requireUnrelated(task,plan.uid);
            if(unrelatedPhysical(task,plan.uid)){
                List<?> identity=physicalIdentity(task),old=physicalActualIdentities.get(task.id);
                need(old==null||old.equals(identity),"NOTES_RETIREMENT_PHYSICAL_TASK_IDENTITY_CHANGED");
                Integer tokenOwner=physicalBinderOwners.get(task.token);
                need(tokenOwner==null||tokenOwner.intValue()==task.id,"NOTES_RETIREMENT_PHYSICAL_BINDER_REUSED");
                physicalActualIdentities.put(task.id,identity);physicalBinderOwners.put(task.token,task.id);
                need(physicalActualIdentities.size()<=ProfileTaskPolicy.MAX_LEAVES+ProfileTaskPolicy.MAX_ROOTS
                        &&physicalBinderOwners.size()<=ProfileTaskPolicy.MAX_LEAVES+ProfileTaskPolicy.MAX_ROOTS,
                        "NOTES_RETIREMENT_PHYSICAL_IDENTITY_BOUND");
            }else need(!physicalActualIdentities.containsKey(task.id),"NOTES_RETIREMENT_PHYSICAL_TASK_MIGRATED");
        }
    }
    private Map<Integer,List<?>> foreignActual(Map<Integer,BackgroundOwnedSingleTask.Task> rows){
        Map<Integer,List<?>> values=new LinkedHashMap<Integer,List<?>>();
        for(BackgroundOwnedSingleTask.Task task:rows.values())if(!plan.ids.contains(task.id)){
            requireUnrelated(task,plan.uid);
            if(!unrelatedPhysical(task,plan.uid))values.put(task.id,taskFields(task));
        }
        return values;
    }
    private void requireHistory(History history,long begin,long end){
        baseline.history.requireSame(history,plan.ids,plan.uid,Math.max(1,(end-baseline.begin+999)/1000+1));
        if(last!=null)last.history.requireSame(history,plan.ids,plan.uid,Math.max(1,(end-last.begin+999)/1000+1));
        Set<Integer> current=history.census.unrelatedPhysicalIds(plan.ids,plan.uid);
        for(PublicOwnGroupPhysicalFence.RecentRecord row:history.census.records.values()){
            PublicOwnGroupPhysicalFence.RecentRecord old=physicalRecentIdentities.get(row.task);
            if(old!=null)need(current.contains(row.task)&&old.token.equals(row.token)&&old.user==row.user
                    &&old.uid==row.uid&&old.root==row.root&&old.display==row.display,
                    "NOTES_RETIREMENT_PHYSICAL_RECENT_IDENTITY_CHANGED");
            if(current.contains(row.task))physicalRecentIdentities.put(row.task,row);
            need(physicalRecentIdentities.size()<=ProfileTaskPolicy.MAX_LEAVES,"NOTES_RETIREMENT_PHYSICAL_IDENTITY_BOUND");
        }
    }
    private static boolean physicalDisplay(int display){return display==0||display==1;}
    private static void requireUnrelated(BackgroundOwnedSingleTask.Task task,int uid){
        need(task!=null&&task.uid!=uid&&task.topUid!=uid&&!notes(task.intentComponent)&&!notes(task.base)
                &&!notes(task.top)&&!notes(task.real)&&!notes(task.orig),"NOTES_RETIREMENT_FOREIGN_SAME_UID_OR_PACKAGE");
    }
    static boolean unrelatedPhysical(BackgroundOwnedSingleTask.Task task,int uid){
        return task!=null&&physicalDisplay(task.display)&&task.user==0&&task.uid>=0&&task.uid<100000
                &&(task.topUid==-1||task.topUid>=0&&task.topUid<100000)&&task.uid!=uid&&task.topUid!=uid
                &&!notes(task.intentComponent)&&!notes(task.base)&&!notes(task.top)&&!notes(task.real)&&!notes(task.orig);
    }
    private static List<?> physicalIdentity(BackgroundOwnedSingleTask.Task task){
        return java.util.Arrays.asList(task.id,task.display,task.user,task.parent,task.uid,task.token,task.cookies,
                task.intentComponent,task.real,task.orig);
    }
    static void requireSamePhysicalTask(BackgroundOwnedSingleTask.Task a,BackgroundOwnedSingleTask.Task b,int uid){
        need(unrelatedPhysical(a,uid)&&unrelatedPhysical(b,uid)&&physicalIdentity(a).equals(physicalIdentity(b)),
                "NOTES_RETIREMENT_PHYSICAL_TASK_IDENTITY_CHANGED");
    }
    private static Set<Integer> physicalRoots(ProfileTaskPolicy.Snapshot global,Set<Integer> owned){
        need(global!=null&&owned!=null,"NOTES_RETIREMENT_GLOBAL_INCOMPLETE");
        Set<Integer> ids=new LinkedHashSet<Integer>();
        for(ProfileTaskPolicy.Root root:global.roots)if(physicalDisplay(root.display)&&root.user==0){
            need(!owned.contains(root.id)&&!notes(root.base)&&!notes(root.top),"NOTES_RETIREMENT_PHYSICAL_TARGET_PRESENT");
            boolean personal=true;
            for(ProfileTaskPolicy.Leaf leaf:global.leaves.values())if(leaf.parent==root.id){
                need(!owned.contains(leaf.id)&&!notes(leaf.name),"NOTES_RETIREMENT_PHYSICAL_TARGET_PRESENT");
                personal&=leaf.user==0&&leaf.display==root.display;
            }
            if(personal)ids.add(root.id);
        }
        return ids;
    }
    private static List<List<?>> globalRows(ProfileTaskPolicy.Snapshot global,Set<Integer> owned){
        Set<Integer> excluded=new LinkedHashSet<Integer>(owned);excluded.addAll(physicalRoots(global,owned));
        List<List<?>> rows=new ArrayList<List<?>>();
        for(List<?> row:global.excludingRoot(-1))if(!excluded.contains((Integer)row.get(0)))rows.add(row);
        return rows;
    }
    private static Map<String,List<?>> physicalLocations(ProfileTaskPolicy.Snapshot global,Set<Integer> owned){
        Set<Integer> physical=physicalRoots(global,owned);Map<String,List<?>> out=new LinkedHashMap<String,List<?>>();
        Map<Integer,ProfileTaskPolicy.Root> roots=new LinkedHashMap<Integer,ProfileTaskPolicy.Root>();
        Set<Integer> ids=new LinkedHashSet<Integer>(physical);
        for(ProfileTaskPolicy.Root root:global.roots)if(physical.contains(root.id))roots.put(root.id,root);
        for(ProfileTaskPolicy.Leaf leaf:global.leaves.values())if(physical.contains(leaf.parent))ids.add(leaf.id);
        for(int id:ids){
            ProfileTaskPolicy.Root root=roots.get(id);ProfileTaskPolicy.Leaf leaf=global.leaves.get(id);
            // One identity per numeric ID includes BOTH framework roles. An
            // ordinary leaf's TaskInfo parent=-1 cannot hide root membership.
            out.put("task:"+id,java.util.Arrays.asList(id,root!=null,root==null?-1:root.display,root==null?-1:root.user,
                    leaf==null?-1:leaf.parent,leaf==null?-1:leaf.display,leaf==null?-1:leaf.user));
        }
        return out;
    }
    /** Per-read comparison retains every nonphysical root/child field and checks
     * physical root membership. Actual UID/Binder rows are checked separately
     * before this batch can become a Sample or enter an original token effect. */
    static boolean sameReadGlobal(ProfileTaskPolicy.Snapshot before,ProfileTaskPolicy.Snapshot after){
        Set<Integer> none=Collections.emptySet();
        Map<String,List<?>> a=physicalLocations(before,none),b=physicalLocations(after,none);
        for(Map.Entry<String,List<?>> e:a.entrySet())if(b.containsKey(e.getKey()))
            need(e.getValue().equals(b.get(e.getKey())),"NOTES_RETIREMENT_PHYSICAL_TASK_LOCATION_CHANGED");
        return globalRows(before,none).equals(globalRows(after,none));
    }
    static boolean samePhysicalMembership(ProfileTaskPolicy.Snapshot before,ProfileTaskPolicy.Snapshot after){
        Set<Integer> none=Collections.emptySet();return physicalLocations(before,none).equals(physicalLocations(after,none));
    }
    private static void requireRecentLiveIdentities(PublicOwnGroupPhysicalFence.RecentCensus recents,
            ProfileTaskPolicy.Snapshot global,Map<Integer,BackgroundOwnedSingleTask.Task> actual,int uid){
        for(int id:recents.unrelatedPhysicalIds(Collections.<Integer>emptySet(),uid)){
            BackgroundOwnedSingleTask.Task task=actual.get(id);if(task==null)continue;
            PublicOwnGroupPhysicalFence.RecentRecord row=recents.records.get(id);
            ProfileTaskPolicy.Leaf leaf=global.leaves.get(id);
            int root=leaf==null?id:leaf.parent;
            need(unrelatedPhysical(task,uid)&&task.uid==row.uid&&task.user==row.user&&task.display==row.display
                    &&root==row.root,"NOTES_RETIREMENT_PHYSICAL_RECENT_LIVE_DISAGREES");
        }
    }
    /** TaskInfo exposes parentTaskId only for organizer-created parents. For a
     * foreign running leaf, the complete RootTaskInfo child arrays still give a
     * unique root membership. Keep its actual parent=-1; this is a read-only
     * census relation and can never admit an owned task or grant an effect. */
    static boolean ordinaryForeignRootMember(ProfileTaskPolicy.Snapshot global,
            Map<Integer,BackgroundOwnedSingleTask.Task> actual,ProfileTaskPolicy.Leaf leaf,int ownedDisplay,int ownedUid){
        BackgroundOwnedSingleTask.Task node=actual.get(leaf.id);
        if(node==null||node.id==leaf.parent||node.parent>=0)return false;
        need(node.parent==-1&&ownedDisplay>1&&ownedUid>=10000&&global.leaves.get(leaf.id)==leaf,
                "NOTES_RETIREMENT_ORDINARY_MEMBERSHIP_UNKNOWN");
        ProfileTaskPolicy.Root declared=null;
        for(ProfileTaskPolicy.Root root:global.roots){
            need(root.id!=leaf.id,"NOTES_RETIREMENT_ORDINARY_LEAF_IS_ROOT");
            if(root.id==leaf.parent){need(declared==null,"NOTES_RETIREMENT_ORDINARY_ROOT_AMBIGUOUS");declared=root;}
        }
        BackgroundOwnedSingleTask.Task root=actual.get(leaf.parent);
        need(declared!=null&&root!=null&&root.id==declared.id&&root.parent==-1
                &&node.id==leaf.id&&root.token!=null&&node.token!=null&&!Objects.equals(root.token,node.token)
                &&root.display==declared.display&&root.user==declared.user
                &&node.display==leaf.display&&node.user==leaf.user
                &&root.display==node.display&&root.user==node.user
                &&root.display!=ownedDisplay&&node.display!=ownedDisplay
                &&root.uid>=0&&node.uid>=0&&root.uid!=ownedUid&&node.uid!=ownedUid
                &&root.topUid!=ownedUid&&node.topUid!=ownedUid&&node.activities>0&&node.running,
                "NOTES_RETIREMENT_ORDINARY_FOREIGN_IDENTITY");
        for(BackgroundOwnedSingleTask.Task task:java.util.Arrays.asList(root,node))
            need(!notes(task.intentComponent)&&!notes(task.base)&&!notes(task.top)&&!notes(task.real)&&!notes(task.orig),
                    "NOTES_RETIREMENT_ORDINARY_NOTES_MEMBER_FORBIDDEN");
        return true;
    }
    static List<?> taskFields(BackgroundOwnedSingleTask.Task task){return java.util.Arrays.asList(task.id,task.display,task.user,task.parent,
            task.uid,task.topUid,task.activities,task.token,task.cookies,task.intentComponent,task.base,task.top,task.real,task.orig,task.running,task.visible);}
    static boolean sameTask(BackgroundOwnedSingleTask.Task first,BackgroundOwnedSingleTask.Task last){
        return first!=null&&last!=null&&taskFields(first).equals(taskFields(last));
    }
    private static boolean notes(String value){return value!=null&&(value.equals(PublicPersonalNotesCustody.PACKAGE)
            ||value.startsWith(PublicPersonalNotesCustody.PACKAGE+"/"));}
    private static void need(boolean ok,String code){if(!ok)throw new IllegalStateException(code);}

    static Map<String,Object> historyDiagnostic(Throwable error){
        return error!=null&&error.getClass()==IllegalStateException.class
                &&"NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED".equals(error.getMessage())
                &&error.getCause() instanceof History.Refusal?((History.Refusal)error.getCause()).evidence():null;
    }

    /** Preserve every nonowned internal/visible/hidden body and its ordering.
     * Only the displayed relative inactivity age may advance naturally. */
    private static final class History {
        private static final String INTERNAL="  Recent tasks:\n",VISIBLE="  Visible recent tasks (most recent first):\n";
        private static final Pattern HEAD=Pattern.compile("(?m)^  \\* Recent #([0-9]+): (Task\\{[0-9a-f]+ #([0-9]+) [^{}\\r\\n]+\\})$");
        private static final Pattern AGE=Pattern.compile("(?m)^    lastActiveTime=(0|[1-9][0-9]*) \\(inactive for (0|[1-9][0-9]*)s\\)$");
        final PublicOwnGroupPhysicalFence.RecentCensus census;
        private final String preamble,raw;
        private final long sampleBegin,sampleEnd;
        private final Map<Integer,String> internal=new LinkedHashMap<Integer,String>(),visible=new LinkedHashMap<Integer,String>();
        private final Map<Integer,Long> ages=new LinkedHashMap<Integer,Long>();
        History(String raw){this(raw,-1,-1);}
        History(String raw,long sampleBegin,long sampleEnd){
            this.raw=raw;this.sampleBegin=sampleBegin;this.sampleEnd=sampleEnd;
            census=PublicOwnGroupPhysicalFence.inspectRecents(raw);
            int start=raw.indexOf(INTERNAL),end=raw.indexOf(VISIBLE);boolean omitted=end<0;
            need(start>=0&&start==raw.lastIndexOf(INTERNAL)&&(omitted||(end>start&&end==raw.lastIndexOf(VISIBLE))),"NOTES_RETIREMENT_HISTORY_SECTIONS");
            if(omitted)end=raw.length();
            String prefix=raw.substring(0,start);
            preamble=prefix.replaceAll("(?m)^mHiddenTasks=\\[[^\\r\\n]*\\]\\n","")+"\nhidden_field="+prefix.contains("\nmHiddenTasks=");
            String rows=raw.substring(start+INTERNAL.length(),end);List<Matcher> heads=matches(HEAD,rows);
            for(int i=0;i<heads.size();i++){
                Matcher h=heads.get(i);int id=Integer.parseInt(h.group(3));PublicOwnGroupPhysicalFence.RecentRecord fact=census.records.get(id);
                need(Integer.parseInt(h.group(1))==i&&fact!=null&&fact.label.equals(h.group(2)),"NOTES_RETIREMENT_HISTORY_IDENTITY");
                String body=rows.substring(h.end(),i+1<heads.size()?heads.get(i+1).start():rows.length());
                Matcher age=one(AGE,body);ages.put(id,Long.parseLong(age.group(2)));
                String normalized=body.substring(0,age.start())+"    lastActiveTime="+age.group(1)+" (inactive for 0s)"+body.substring(age.end());
                need(internal.put(id,fact.label+"\n"+normalized)==null,"NOTES_RETIREMENT_HISTORY_DUPLICATE");
            }
            need(internal.keySet().equals(census.records.keySet()),"NOTES_RETIREMENT_HISTORY_MEMBERSHIP");
            String vis=omitted?"":raw.substring(end+VISIBLE.length());List<Matcher> vh=omitted?Collections.<Matcher>emptyList():PublicOwnGroupPhysicalFence.visibleRecentHeaders(vis);
            Pattern identity=Pattern.compile("(?m)^    id=([0-9]+) userId=([0-9]+) hasTask=(true|false) lastActiveTime=([0-9]+)$");
            for(int i=0;i<vh.size();i++){
                Matcher h=vh.get(i);need(Integer.parseInt(h.group(1))==i,"NOTES_RETIREMENT_VISIBLE_ORDER");
                String body=vis.substring(h.end(),i+1<vh.size()?vh.get(i+1).start():vis.length());Matcher match=one(identity,body);
                int id=Integer.parseInt(match.group(1));PublicOwnGroupPhysicalFence.RecentRecord fact=census.records.get(id);
                need(fact!=null&&fact.user==Integer.parseInt(match.group(2))&&visible.put(id,body)==null,"NOTES_RETIREMENT_VISIBLE_IDENTITY");
            }
        }
        private String foreign(Set<Integer> own){StringBuilder value=new StringBuilder();append(value,preamble);
            for(Map.Entry<Integer,String> row:internal.entrySet())if(!own.contains(row.getKey()))append(value,"internal|"+row.getValue());
            for(Map.Entry<Integer,String> row:visible.entrySet())if(!own.contains(row.getKey()))append(value,"visible|"+row.getValue());
            for(Map.Entry<Integer,String> row:census.hiddenLabels.entrySet())if(!own.contains(row.getKey()))append(value,"hidden|"+row.getValue());return value.toString();
        }
        private String runtimePreamble(){
            return preamble.replaceAll("(?m)^(mFreezeTaskListReordering(?:PendingTimeout)?)=(?:true|false)$","$1=false")
                    .replaceAll("(?m)^hidden_field=(?:true|false)$","hidden_field=complete_observation");
        }
        private Set<Integer> runtimeExcluded(Set<Integer> own,int uid){
            Set<Integer> excluded=new LinkedHashSet<Integer>(own);
            for(int id:census.unrelatedPhysicalIds(own,uid)){
                String body=internal.get(id);
                need(body!=null,"NOTES_RETIREMENT_HISTORY_IDENTITY");
                Pattern target=Pattern.compile("(?<![A-Za-z0-9_.])"+Pattern.quote(PublicPersonalNotesCustody.PACKAGE)
                        +"(?=$|[^A-Za-z0-9_.])");
                for(String part:java.util.Arrays.asList(body,visible.get(id),census.hiddenLabels.get(id)))
                    need(part==null||!target.matcher(part).find(),"NOTES_RETIREMENT_FOREIGN_SAME_UID_OR_PACKAGE");
                excluded.add(id);
            }
            return excluded;
        }
        private String protectedHistory(Set<Integer> own,int uid){
            Set<Integer> excluded=runtimeExcluded(own,uid);StringBuilder value=new StringBuilder();append(value,runtimePreamble());
            for(Map.Entry<Integer,String> row:internal.entrySet())if(!excluded.contains(row.getKey()))append(value,"internal|"+row.getValue());
            for(Map.Entry<Integer,String> row:visible.entrySet())if(!excluded.contains(row.getKey()))append(value,"visible|"+row.getValue());
            for(Map.Entry<Integer,String> row:census.hiddenLabels.entrySet())if(!excluded.contains(row.getKey()))append(value,"hidden|"+row.getValue());
            return value.toString();
        }
        void requireSame(History after,Set<Integer> own,int uid,long ageBudget){
            need(ageBudget>=0,"NOTES_RETIREMENT_HISTORY_SCOPE");
            if(after==null)throw new IllegalStateException("NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED",
                    new Refusal(this,null,own,uid,ageBudget));
            census.requirePhysicalIdentities(after.census,own,uid);
            if(!protectedHistory(own,uid).equals(after.protectedHistory(own,uid)))throw new IllegalStateException(
                    "NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED",new Refusal(this,after,own,uid,ageBudget));
            Set<Integer> excluded=runtimeExcluded(own,uid);
            for(Map.Entry<Integer,Long> row:ages.entrySet())if(!excluded.contains(row.getKey())){
                Long next=after.ages.get(row.getKey());need(next!=null&&next>=row.getValue()&&next-row.getValue()<=ageBudget,
                        "NOTES_RETIREMENT_HISTORY_AGE_CHANGED");}
        }

        /** Original rejected strings only. These records are diagnostics, never
         * replayable history, task authority, or cleanup evidence. */
        private static final class Refusal extends IllegalStateException {
            private static final long serialVersionUID=1L;
            private static final int MAX_PAIR_BYTES=32768;
            private final History before,after;
            private final Set<Integer> own;
            private final long ageBudget;
            private final int uid;
            Refusal(History before,History after,Set<Integer> own,int uid,long ageBudget){
                super("NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED");
                this.before=before;this.after=after;
                this.own=Collections.unmodifiableSet(new LinkedHashSet<Integer>(own));this.uid=uid;this.ageBudget=ageBudget;
            }
            Map<String,Object> evidence(){
                Map<String,Object> out=new LinkedHashMap<String,Object>();
                out.put("schema","hepta.notes-retirement-history-diagnostic.v1");
                out.put("reason",getMessage());out.put("diagnostics_grant_authority",false);
                out.put("release_evidence",false);out.put("model_input",false);
                out.put("owned_task_ids_excluded",new ArrayList<Integer>(own));
                out.put("history_preservation_scope","nonphysical_and_unresolved_recents");out.put("physical_history_frozen",false);
                out.put("baseline_resolved_physical_ids",new ArrayList<Integer>(before.census.unrelatedPhysicalIds(own,uid)));
                out.put("current_resolved_physical_ids",after==null?null:new ArrayList<Integer>(after.census.unrelatedPhysicalIds(own,uid)));
                out.put("relative_age_budget_seconds",ageBudget);
                byte[] left=bytes(before.raw),right=after==null?null:bytes(after.raw);
                out.put("baseline",rawRef(before,left));out.put("current",after==null?null:rawRef(after,right));
                out.put("baseline_foreign_sha256",sha(before.protectedHistory(own,uid)));
                out.put("current_foreign_sha256",after==null?null:sha(after.protectedHistory(own,uid)));
                out.put("first_difference",difference(before,after,own,uid));
                out.put("all_differences_enumerated",false);
                boolean complete=right!=null&&left.length<=MAX_PAIR_BYTES
                        &&right.length<=MAX_PAIR_BYTES-left.length;
                out.put("raw_pair_limit_bytes",MAX_PAIR_BYTES);out.put("raw_pair_complete",complete);
                out.put("raw_pair_omission_reason",complete?null:after==null?"current_history_unavailable":"raw_pair_byte_bound");
                if(complete)try{out.put("raw_pair",packed(left,right));}
                catch(java.io.IOException unavailable){
                    out.put("raw_pair_complete",false);out.put("raw_pair_omission_reason","diagnostic_encoding_unavailable");
                }
                return out;
            }
            private static Map<String,Object> packed(byte[] left,byte[] right)throws java.io.IOException{
                byte[] raw=new byte[left.length+right.length];
                System.arraycopy(left,0,raw,0,left.length);System.arraycopy(right,0,raw,left.length,right.length);
                java.io.ByteArrayOutputStream sink=new java.io.ByteArrayOutputStream();
                try(java.util.zip.GZIPOutputStream gzip=new java.util.zip.GZIPOutputStream(sink)){gzip.write(raw);}
                byte[] zipped=sink.toByteArray();Map<String,Object> pair=new LinkedHashMap<String,Object>();
                pair.put("encoding","gzip-base64-concatenated-original-utf8");
                pair.put("decoded_bytes",raw.length);pair.put("decoded_sha256",ProfileIdentity.sha(raw));
                pair.put("compressed_bytes",zipped.length);pair.put("compressed_sha256",ProfileIdentity.sha(zipped));
                pair.put("data",java.util.Base64.getEncoder().encodeToString(zipped));return pair;
            }
            private static Map<String,Object> rawRef(History value,byte[] raw){
                Map<String,Object> out=new LinkedHashMap<String,Object>();
                out.put("bytes",raw.length);out.put("sha256",value.census.rawSha256);
                out.put("sample_begin_elapsed_ms",value.sampleBegin);out.put("sample_end_elapsed_ms",value.sampleEnd);
                out.put("source","original_complete_retirement_recents_read");return out;
            }
            private static Map<String,Object> difference(History a,History b,Set<Integer> own,int uid){
                if(b==null)return detail("history",null,"current_unavailable",null,null);
                if(!a.runtimePreamble().equals(b.runtimePreamble()))return detail("preamble",null,"body_changed",a.runtimePreamble(),b.runtimePreamble());
                Set<Integer> ax=a.runtimeExcluded(own,uid),bx=b.runtimeExcluded(own,uid);
                Map<String,Object> found=section("internal",a.internal,b.internal,ax,bx);
                if(found==null)found=section("visible",a.visible,b.visible,ax,bx);
                if(found==null)found=section("hidden",a.census.hiddenLabels,b.census.hiddenLabels,ax,bx);
                return found==null?detail("foreign_projection",null,"not_localized",a.protectedHistory(own,uid),b.protectedHistory(own,uid)):found;
            }
            private static Map<String,Object> section(String name,Map<Integer,String> a,Map<Integer,String> b,Set<Integer> ax,Set<Integer> bx){
                List<Integer> left=new ArrayList<Integer>(),right=new ArrayList<Integer>();
                for(int id:a.keySet())if(!ax.contains(id))left.add(id);
                for(int id:b.keySet())if(!bx.contains(id))right.add(id);
                if(!left.equals(right)){
                    Map<String,Object> out=detail(name,null,"membership_or_order_changed",left.toString(),right.toString());
                    out.put("baseline_task_ids",new ArrayList<Integer>(left.subList(0,Math.min(32,left.size()))));
                    out.put("current_task_ids",new ArrayList<Integer>(right.subList(0,Math.min(32,right.size()))));
                    out.put("task_id_lists_complete",left.size()<=32&&right.size()<=32);
                    out.put("baseline_task_count",left.size());out.put("current_task_count",right.size());return out;
                }
                for(int id:left)if(!Objects.equals(a.get(id),b.get(id)))
                    return detail(name,id,"body_changed",a.get(id),b.get(id));
                return null;
            }
            private static Map<String,Object> detail(String section,Integer id,String kind,String a,String b){
                Map<String,Object> out=new LinkedHashMap<String,Object>();
                out.put("section",section);out.put("task_id",id);out.put("kind",kind);
                out.put("baseline_normalized_part_sha256",a==null?null:sha(a));
                out.put("current_normalized_part_sha256",b==null?null:sha(b));
                out.put("baseline_part_bytes",a==null?null:bytes(a).length);
                out.put("current_part_bytes",b==null?null:bytes(b).length);
                if(a!=null&&b!=null){
                    String[] left=a.split("\\n",-1),right=b.split("\\n",-1);int line=0;
                    while(line<left.length&&line<right.length&&left[line].equals(right[line]))line++;
                    out.put("first_differing_line_zero_based",line);
                    out.put("baseline_field_key",line<left.length?field(left[line]):"line_absent");
                    out.put("current_field_key",line<right.length?field(right[line]):"line_absent");
                    out.put("raw_values_in_summary",false);
                }
                return out;
            }
            private static String field(String line){
                String value=line.trim();int equals=value.indexOf('=');
                if(equals>0&&equals<=64){
                    String key=value.substring(0,equals);
                    if(key.matches("[A-Za-z][A-Za-z0-9_.]{0,63}"))return key;
                }
                return "unlabelled";
            }
            private static byte[] bytes(String value){return value.getBytes(java.nio.charset.StandardCharsets.UTF_8);}
            private static String sha(String value){return ProfileIdentity.sha(bytes(value));}
        }
        private static Matcher one(Pattern pattern,String text){Matcher first=pattern.matcher(text),other=pattern.matcher(text);
            need(first.find()&&other.find()&&!other.find(),"NOTES_RETIREMENT_HISTORY_FIELD");return first;}
        private static List<Matcher> matches(Pattern pattern,String text){List<Matcher> out=new ArrayList<Matcher>();Matcher scan=pattern.matcher(text);
            while(scan.find()){Matcher saved=pattern.matcher(text);need(saved.find(scan.start()),"NOTES_RETIREMENT_HISTORY_PATTERN");out.add(saved);}return out;}
        private static void append(StringBuilder out,String value){out.append(value.length()).append(':').append(value);}
    }
}
