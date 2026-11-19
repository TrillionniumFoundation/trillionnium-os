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
    /** Location-only census. Names retain their raw parallel-array shape but
     * never become App identity or a capability to act on a task. */
    private static final class Location {
        final int id,display,user;
        Location(int id,int display,int user){this.id=id;this.display=display;this.user=user;}
    }
    static final class LocationRoot {
        final Location root;
        final java.util.List<Location> children;
        LocationRoot(int id,int display,int user,int[] ids,int[] users,String[] names,int[][] bounds)throws BrokerProtocol.Refusal{
            need(id>0&&display>=0&&user>=0,"PUBLIC_TASK_LOCATION_ROOT_INVALID");
            need(ids!=null&&users!=null&&names!=null&&bounds!=null&&ids.length==users.length
                    &&ids.length==names.length&&ids.length==bounds.length&&ids.length<=ProfileTaskPolicy.MAX_LEAVES,
                    "PUBLIC_TASK_LOCATION_ARRAYS_INCOMPLETE");
            root=new Location(id,display,user);
            java.util.List<Location> copy=new java.util.ArrayList<Location>();Set<Integer> unique=new java.util.HashSet<Integer>();
            for(int i=0;i<ids.length;i++){
                need(ids[i]>0&&users[i]>=0&&unique.add(ids[i]),"PUBLIC_TASK_LOCATION_CHILD_IDENTITY_INVALID");
                need(names[i]!=null,"PUBLIC_TASK_LOCATION_CHILD_NAME_UNAVAILABLE");
                int[] b=bounds[i];need(b!=null&&b.length==4&&b[2]>=b[0]&&b[3]>=b[1],"PUBLIC_TASK_LOCATION_CHILD_BOUNDS_INVALID");
                for(int v:b)need(v>=-32768&&v<=32768,"PUBLIC_TASK_LOCATION_CHILD_BOUNDS_INVALID");
                copy.add(new Location(ids[i],display,users[i]));
            }
            children=Collections.unmodifiableList(copy);
        }
    }
    static final class Census {
        final java.util.List<Location> locations;
        Census(java.util.List<LocationRoot> roots)throws BrokerProtocol.Refusal{
            need(roots!=null&&!roots.isEmpty()&&roots.size()<=ProfileTaskPolicy.MAX_ROOTS,"PUBLIC_TASK_LOCATION_ROOT_QUERY_INCOMPLETE");
            java.util.List<Location> all=new java.util.ArrayList<Location>(),leaves=new java.util.ArrayList<Location>();
            Set<Integer> rootIds=new java.util.HashSet<Integer>(),leafIds=new java.util.HashSet<Integer>();
            for(LocationRoot row:roots){
                need(row!=null&&rootIds.add(row.root.id),"PUBLIC_TASK_LOCATION_ROOT_DUPLICATE");all.add(row.root);
                for(Location child:row.children){
                    need(leafIds.add(child.id)&&leaves.size()<ProfileTaskPolicy.MAX_LEAVES,"PUBLIC_TASK_LOCATION_LEAF_DUPLICATE_OR_BOUND");
                    leaves.add(child);
                }
            }
            all.addAll(leaves);locations=Collections.unmodifiableList(all);
        }
    }
    private static java.util.List<Location> locations(ProfileTaskPolicy.Snapshot actual){
        java.util.List<Location> rows=new java.util.ArrayList<Location>();
        for(ProfileTaskPolicy.Root root:actual.roots)rows.add(new Location(root.id,root.display,root.user));
        for(ProfileTaskPolicy.Leaf leaf:actual.leaves.values())rows.add(new Location(leaf.id,leaf.display,leaf.user));
        return rows;
    }
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
        observeLocations(actual==null?null:locations(actual),ownedDisplay,now);
    }
    synchronized void observe(Census actual,int ownedDisplay,long now)throws BrokerProtocol.Refusal{
        observeLocations(actual==null?null:actual.locations,ownedDisplay,now);
    }
    private void observeLocations(java.util.List<Location> actual,int ownedDisplay,long now)throws BrokerProtocol.Refusal{
        try{
            need(!retired&&actual!=null&&ownedDisplay>1&&now>=0,"PUBLIC_TASK_FENCE_UNAVAILABLE");
            need(display<0||display==ownedDisplay,"PUBLIC_TASK_FENCE_DISPLAY_CHANGED");
            Set<Integer> currentOwned=new LinkedHashSet<Integer>();
            for(Location row:actual){
                location(row.id,row.display,row.user,ownedDisplay);
                if(row.display==ownedDisplay)currentOwned.add(row.id);
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
