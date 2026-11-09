package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Exact supported scroll action names from one successfully read action list. */
public final class ObservedScrollActions {
    public static final String SCHEMA="hepta.observed-scroll-actions.v1";
    private static final List<String> ORDER=Collections.unmodifiableList(Arrays.asList(
            "forward","backward","up","down","left","right"));
    public static final ObservedScrollActions UNKNOWN=new ObservedScrollActions(false,Collections.<String>emptyList());
    public final boolean observed;
    public final List<String> directions;

    private ObservedScrollActions(boolean observed,List<String> directions){
        this.observed=observed;this.directions=Collections.unmodifiableList(new ArrayList<String>(directions));
    }
    /** Null means unavailable, never an inferred set from isScrollable. */
    public static ObservedScrollActions observed(Collection<String> names){
        if(names==null)return UNKNOWN;
        Set<String> supplied=new HashSet<String>();
        for(String name:names){
            if(name==null||!ORDER.contains(name))throw new IllegalArgumentException("unknown observed scroll direction");
            supplied.add(name);
        }
        List<String> result=new ArrayList<String>();for(String name:ORDER)if(supplied.contains(name))result.add(name);
        return new ObservedScrollActions(true,result);
    }
    public boolean hasAny(){return observed&&!directions.isEmpty();}
    public boolean allows(String direction){return observed&&directions.contains(direction);}
    /** This binds freshness, not the controller's existing visible-progress predicate. */
    public String fingerprintInput(){
        StringBuilder out=new StringBuilder(SCHEMA).append(observed?"|observed":"|unknown");
        for(String direction:directions)out.append('|').append(direction);
        return out.toString();
    }
    public String bindFreshness(String original){
        if(original==null)throw new IllegalArgumentException("original node signature required");
        return original+"\nscroll_actions="+fingerprintInput();
    }
}
