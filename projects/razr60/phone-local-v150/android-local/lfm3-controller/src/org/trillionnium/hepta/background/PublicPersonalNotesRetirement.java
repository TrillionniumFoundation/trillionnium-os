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
        void remove(Effect effect) throws Exception;
        long now();
        void awaitRead() throws Exception;
    }
    static final class Sample {
        final PublicPersonalNotesCustody.Frame frame;
        final PublicOwnGroupPhysicalFence.RecentCensus recents;
        final History history;
        final Map<Integer,BackgroundOwnedSingleTask.Task> actualTasks;
        final Map<Integer,String> physical;
        final long begin,end;
        Sample(PublicPersonalNotesCustody.Frame frame,String rawRecents,
                Map<Integer,BackgroundOwnedSingleTask.Task> actualTasks,Map<Integer,String> physical,long begin,long end,
                int ownedDisplay,int ownedUid){
            need(ownedDisplay>1&&ownedUid>=10000&&frame!=null&&actualTasks!=null&&physical!=null&&physical.size()==2
                    &&physical.containsKey(0)&&physical.containsKey(1)&&begin>=0&&end>=begin&&end-begin<=1500
                    &&frame.begin>=begin&&frame.end<=end,"NOTES_RETIREMENT_SAMPLE_INCOMPLETE");
            for(String hash:physical.values())need(ProfileIdentity.hash(hash),"NOTES_RETIREMENT_PHYSICAL_INCOMPLETE");
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
            this.frame=frame;history=new History(rawRecents);recents=history.census;
            this.actualTasks=Collections.unmodifiableMap(new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>(actualTasks));
            this.physical=Collections.unmodifiableMap(new LinkedHashMap<Integer,String>(physical));this.begin=begin;this.end=end;
        }
        boolean contains(int id){return frame.global.allIds.contains(id)||recents.allIds.contains(id);}
    }
    /** Constructed only by this coordinator. The adapter must submit a complete
     * new final read before entering the original custodian's single-use bit. */
    static final class Effect {
        private final PublicPersonalNotesRetirement owner;
        private final PublicPersonalNotesCustody.TokenEntry entry;
        private Effect(PublicPersonalNotesRetirement owner,PublicPersonalNotesCustody.TokenEntry entry){this.owner=owner;this.entry=entry;}
        Object token(){return entry.token();}
        int id(){return entry.id();}
        void beforeCall(Sample actual,long now){owner.verify(actual,now,true);entry.beforeCall(actual.frame,actual.recents,now);}
        void returned(){entry.returned();}
    }
    private final PublicPersonalNotesCustody custody;
    private final Port port;
    private final long deadline;
    private PublicPersonalNotesCustody.TokenPlan plan;
    private Sample baseline,last;
    private boolean started,ready;
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
                need(plan.attempted(id),"NOTES_RETIREMENT_EFFECT_NOT_ENTERED");
                int reads=0;
                do{
                    need(++reads<=32,"NOTES_RETIREMENT_PENDING_READ_BOUND");
                    current=port.read();verify(current,port.now(),true);
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
        need(baseline.physical.equals(sample.physical),"NOTES_RETIREMENT_PHYSICAL_CHANGED");
        need(foreignGlobal(baseline).equals(foreignGlobal(sample)),"NOTES_RETIREMENT_FOREIGN_GLOBAL_CHANGED");
        need(foreignActual(baseline).equals(foreignActual(sample)),"NOTES_RETIREMENT_FOREIGN_ACTUAL_CHANGED");
        baseline.history.requireSame(sample.history,plan.ids,Math.max(1,(sample.end-baseline.begin+999)/1000+1));
        for(BackgroundOwnedSingleTask.Task task:sample.actualTasks.values())if(!plan.ids.contains(task.id))
            need(task.uid!=plan.uid&&task.topUid!=plan.uid&&!notes(task.intentComponent)&&!notes(task.base)
                    &&!notes(task.top)&&!notes(task.real)&&!notes(task.orig),"NOTES_RETIREMENT_FOREIGN_SAME_UID_OR_PACKAGE");
        if(!ready)plan.verify(sample.frame,sample.recents,now);
        last=sample;
    }
    private List<List<?>> foreignGlobal(Sample sample){
        List<ProfileTaskPolicy.Root> roots=new ArrayList<ProfileTaskPolicy.Root>();
        for(ProfileTaskPolicy.Root root:sample.frame.global.roots)if(!plan.ids.contains(root.id))roots.add(root);
        try{return new ProfileTaskPolicy.Snapshot(roots).excludingRoot(-1);}
        catch(ProfileTaskPolicy.Refusal refusal){throw new IllegalStateException("NOTES_RETIREMENT_FOREIGN_GLOBAL_INCOMPLETE",refusal);}
    }
    private Map<Integer,List<?>> foreignActual(Sample sample){Map<Integer,List<?>> values=new LinkedHashMap<Integer,List<?>>();
        for(BackgroundOwnedSingleTask.Task task:sample.actualTasks.values())if(!plan.ids.contains(task.id))values.put(task.id,taskFields(task));return values;
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

    /** Preserve every nonowned internal/visible/hidden body and its ordering.
     * Only the displayed relative inactivity age may advance naturally. */
    private static final class History {
        private static final String INTERNAL="  Recent tasks:\n",VISIBLE="  Visible recent tasks (most recent first):\n";
        private static final Pattern HEAD=Pattern.compile("(?m)^  \\* Recent #([0-9]+): (Task\\{[0-9a-f]+ #([0-9]+) [^{}\\r\\n]+\\})$");
        private static final Pattern AGE=Pattern.compile("(?m)^    lastActiveTime=(0|[1-9][0-9]*) \\(inactive for (0|[1-9][0-9]*)s\\)$");
        final PublicOwnGroupPhysicalFence.RecentCensus census;
        private final String preamble;
        private final Map<Integer,String> internal=new LinkedHashMap<Integer,String>(),visible=new LinkedHashMap<Integer,String>();
        private final Map<Integer,Long> ages=new LinkedHashMap<Integer,Long>();
        History(String raw){
            census=PublicOwnGroupPhysicalFence.inspectRecents(raw);
            int start=raw.indexOf(INTERNAL),end=raw.indexOf(VISIBLE);
            need(start>=0&&end>start&&start==raw.lastIndexOf(INTERNAL)&&end==raw.lastIndexOf(VISIBLE),"NOTES_RETIREMENT_HISTORY_SECTIONS");
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
            String vis=raw.substring(end+VISIBLE.length());List<Matcher> vh=PublicOwnGroupPhysicalFence.visibleRecentHeaders(vis);
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
        void requireSame(History after,Set<Integer> own,long ageBudget){
            need(after!=null&&foreign(own).equals(after.foreign(own)),"NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED");
            for(Map.Entry<Integer,Long> row:ages.entrySet())if(!own.contains(row.getKey())){
                Long next=after.ages.get(row.getKey());need(next!=null&&next>=row.getValue()&&next-row.getValue()<=ageBudget,
                        "NOTES_RETIREMENT_HISTORY_AGE_CHANGED");}
        }
        private static Matcher one(Pattern pattern,String text){Matcher first=pattern.matcher(text),other=pattern.matcher(text);
            need(first.find()&&other.find()&&!other.find(),"NOTES_RETIREMENT_HISTORY_FIELD");return first;}
        private static List<Matcher> matches(Pattern pattern,String text){List<Matcher> out=new ArrayList<Matcher>();Matcher scan=pattern.matcher(text);
            while(scan.find()){Matcher saved=pattern.matcher(text);need(saved.find(scan.start()),"NOTES_RETIREMENT_HISTORY_PATTERN");out.add(saved);}return out;}
        private static void append(StringBuilder out,String value){out.append(value.length()).append(':').append(value);}
    }
}
