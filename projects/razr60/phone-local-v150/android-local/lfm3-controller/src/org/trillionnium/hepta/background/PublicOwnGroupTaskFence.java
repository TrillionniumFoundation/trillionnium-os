package org.trillionnium.hepta.background;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Observational, one-session task-location guard. IDs never authorize a task mutation.
 * User activity on physical displays is allowed; the dedicated target profile
 * and task IDs actually observed on this owned VD must never escape to them.
 * Prior tasks may not be moved into this session's new display. */
final class PublicOwnGroupTaskFence {
    private final Set<Integer> initialIds,observedOnOwned=new LinkedHashSet<Integer>();
    private final int targetUser;
    private final String generation;
    private boolean retired;
    private int display=-1;
    private long observedAt;
    PublicOwnGroupTaskFence(ProfileTaskPolicy.Snapshot initial,int targetUser,String generation)throws BrokerProtocol.Refusal{
        need(initial!=null&&targetUser>=0&&ProfileIdentity.uuid(generation),"PUBLIC_TASK_FENCE_INITIAL_INVALID");
        initialIds=Collections.unmodifiableSet(new LinkedHashSet<Integer>(initial.allIds));
        this.targetUser=targetUser;this.generation=generation;
    }
    private static void need(boolean ok,String reason)throws BrokerProtocol.Refusal{if(!ok)throw new BrokerProtocol.Refusal(reason);}
    synchronized void observe(ProfileTaskPolicy.Snapshot actual,int ownedDisplay,long now)throws BrokerProtocol.Refusal{
        try{
            need(!retired&&actual!=null&&ownedDisplay>1&&now>=0,"PUBLIC_TASK_FENCE_UNAVAILABLE");
            need(display<0||display==ownedDisplay,"PUBLIC_TASK_FENCE_DISPLAY_CHANGED");
            Set<Integer> currentOwned=new LinkedHashSet<Integer>();
            for(ProfileTaskPolicy.Root root:actual.roots){
                location(root.id,root.display,root.user,ownedDisplay);
                if(root.display==ownedDisplay)currentOwned.add(root.id);
            }
            for(ProfileTaskPolicy.Leaf leaf:actual.leaves.values()){
                location(leaf.id,leaf.display,leaf.user,ownedDisplay);
                if(leaf.display==ownedDisplay)currentOwned.add(leaf.id);
            }
            Set<Integer> cumulative=new LinkedHashSet<Integer>(observedOnOwned);cumulative.addAll(currentOwned);
            need(cumulative.size()<=ProfileTaskPolicy.MAX_LEAVES*2,"PUBLIC_TASK_FENCE_BOUNDS");
            observedOnOwned.addAll(currentOwned);display=ownedDisplay;observedAt=now;
        }catch(BrokerProtocol.Refusal refused){retired=true;throw refused;}
    }
    private void location(int id,int actualDisplay,int user,int ownedDisplay)throws BrokerProtocol.Refusal{
        if(actualDisplay==0||actualDisplay==1)
            need(targetUser==0||user!=targetUser,"PUBLIC_TARGET_PROFILE_ON_PHYSICAL_DISPLAY");
        if(targetUser>0&&user==targetUser)need(actualDisplay==ownedDisplay,"PUBLIC_TARGET_PROFILE_ON_FOREIGN_DISPLAY");
        if(actualDisplay==ownedDisplay)need(!initialIds.contains(id),"PUBLIC_PREEXISTING_TASK_MOVED_TO_OWNED_DISPLAY");
        else need(!observedOnOwned.contains(id),"PUBLIC_OBSERVED_OWNED_TASK_ESCAPED");
    }
    synchronized Map<String,Object> evidence(){
        Map<String,Object> value=new LinkedHashMap<String,Object>();value.put("schema","hepta.public-own-group.task-location.v1");
        value.put("generation",generation);value.put("display_id",display);value.put("target_user_id",targetUser);
        value.put("observed_elapsed_ms",observedAt);value.put("initial_task_count",initialIds.size());
        value.put("observed_owned_task_ids",Collections.unmodifiableList(new java.util.ArrayList<Integer>(observedOnOwned)));
        value.put("retired",retired);value.put("physical_user_activity_frozen",false);
        value.put("recents_unchanged_claimed",false);value.put("task_mutation_authority",false);
        return Collections.unmodifiableMap(value);
    }
}
