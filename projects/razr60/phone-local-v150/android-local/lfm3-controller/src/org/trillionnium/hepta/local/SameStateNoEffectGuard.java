package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Additional task-local evidence, never action authority or a progress claim.
 * Keep one instance inside one owner task. Only confirmed unchanged open/node
 * click outcomes accumulate; the original RepeatActionGuard remains independent.
 */
public final class SameStateNoEffectGuard {
    public static final String SCHEMA="hepta.same-state-no-effect.v1";
    public static final int MAX_RECORDS=20;
    private String packageName;
    private ObservationState boundState;
    private final Set<String> opens=new TreeSet<String>();
    private final Set<String> clicks=new TreeSet<String>();

    /** Bind only to observed state. Unknown IME is never positive change evidence. */
    private void align(String currentPackage,ObservationState current) {
        if(currentPackage==null||currentPackage.isEmpty()||current==null)
            throw new IllegalArgumentException("observed package and state required");
        if(boundState==null||!currentPackage.equals(packageName)
                ||Boolean.TRUE.equals(current.changedFrom(boundState))) {
            opens.clear();clicks.clear();packageName=currentPackage;boundState=current;
        } else if(opens.isEmpty()&&clicks.isEmpty()) {
            boundState=current;
        }
    }

    public Snapshot snapshot(String currentPackage,ObservationState current) {
        align(currentPackage,current);
        return new Snapshot(currentPackage,opens,clicks);
    }

    /** False never authorizes anything; normal owner/freshness/policy gates still apply. */
    public boolean rejects(ActionDecision action,String currentPackage,ObservationState current) {
        if(action==null)throw new IllegalArgumentException("decision required");
        Snapshot blocked=snapshot(currentPackage,current);
        return "open".equals(action.action)?blocked.blockedOpenPackages.contains(action.packageName)
                :"click".equals(action.action)&&currentPackage.equals(action.packageName)
                    &&action.nodeId!=null&&blocked.blockedClickNodeIds.contains(action.nodeId);
    }

    /**
     * Caller supplies the actual accepted outcome and fresh before/after observations.
     * Rejected or stale outcomes never establish evidence. Reads/waits may reveal a
     * real changed state but cannot erase confirmed facts merely by being performed.
     */
    public void observed(ActionDecision action,String beforePackage,ObservationState before,
            String afterPackage,ObservationState after,boolean accepted,boolean dispatched,boolean stale) {
        if(action==null||before==null||after==null||beforePackage==null||afterPackage==null)
            throw new IllegalArgumentException("complete observed outcome required");
        if(!accepted||stale)return;
        align(afterPackage,after);
        if(!dispatched||!beforePackage.equals(afterPackage)
                ||!Boolean.FALSE.equals(after.changedFrom(before)))return;
        if("open".equals(action.action)) {
            add(opens,action.packageName);
        } else if("click".equals(action.action)&&action.nodeId!=null) {
            if(!beforePackage.equals(action.packageName))
                throw new IllegalArgumentException("click package differs from observed window");
            add(clicks,action.nodeId);
        }
        // No type-text, scroll-direction, back/home, wait, or done generalization.
    }

    private void add(Set<String> destination,String target) {
        if(destination.contains(target))return;
        if(opens.size()+clicks.size()>=MAX_RECORDS)
            throw new IllegalStateException("confirmed no-effect records exceed bounded task capacity");
        destination.add(target);
    }

    /** Immutable domain subtraction, tied to this frame's observed package. */
    public static final class Snapshot {
        public final String packageName;
        public final Set<String> blockedOpenPackages,blockedClickNodeIds;
        private Snapshot(String packageName,Set<String> opens,Set<String> clicks) {
            this.packageName=packageName;
            blockedOpenPackages=Collections.unmodifiableSet(new TreeSet<String>(opens));
            blockedClickNodeIds=Collections.unmodifiableSet(new TreeSet<String>(clicks));
        }
        public int size(){return blockedOpenPackages.size()+blockedClickNodeIds.size();}
        public Set<String> allowedOpenPackages(Set<String> supplied) {
            Set<String> result=new TreeSet<String>(supplied);result.removeAll(blockedOpenPackages);return result;
        }
        public Set<String> allowedClicks(Set<String> supplied) {
            Set<String> result=new TreeSet<String>(supplied);result.removeAll(blockedClickNodeIds);return result;
        }

        /** Compact references into the same final frame; never a new target source. */
        public CompactProjection compactProject(Set<String> shownApps,Map<String,String> shownLabels){
            List<String> appReferences=new ArrayList<String>(),nodeReferences=new ArrayList<String>();
            for(String target:blockedOpenPackages)if(shownApps.contains(target))appReferences.add(target);
            for(String target:blockedClickNodeIds)if(shownLabels.containsKey(target))nodeReferences.add(target);
            return new CompactProjection(appReferences,nodeReferences,size());
        }
        /** Only refer to packages/nodes still present in the final budgeted input. */
        public Projection project(Set<String> shownApps,Map<String,String> shownLabels) {
            List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();
            for(String target:blockedOpenPackages)if(shownApps.contains(target)) {
                Map<String,Object> row=new LinkedHashMap<String,Object>();
                row.put("action","open");row.put("package",target);
                rows.add(Collections.unmodifiableMap(row));
            }
            for(String target:blockedClickNodeIds)if(shownLabels.containsKey(target)) {
                Map<String,Object> row=new LinkedHashMap<String,Object>();
                row.put("action","click");row.put("package",packageName);
                row.put("node_label",shownLabels.get(target));row.put("node_id",target);
                rows.add(Collections.unmodifiableMap(row));
            }
            return new Projection(rows,size());
        }
    }


    public static final String COMPACT_SCHEMA="hepta.same-state-no-effect.v2";
    public static final class CompactProjection {
        public final List<String> openPackages,clickIds;
        public final int observed,omitted;
        private CompactProjection(List<String> opens,List<String> clicks,int observed){
            openPackages=Collections.unmodifiableList(new ArrayList<String>(opens));
            clickIds=Collections.unmodifiableList(new ArrayList<String>(clicks));
            this.observed=observed;omitted=observed-opens.size()-clicks.size();
        }
    }

    public static final class Projection {
        public final List<Map<String,Object>> rows;
        public final int observed,omitted;
        private Projection(List<Map<String,Object>> rows,int observed) {
            this.rows=Collections.unmodifiableList(new ArrayList<Map<String,Object>>(rows));
            this.observed=observed;this.omitted=observed-rows.size();
        }
    }
}
