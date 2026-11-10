import org.trillionnium.hepta.local.ObservedScrollActions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** No Android or phone claims: explicit action-list state and immutable names. */
public final class ObservedScrollActionsHostTest {
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    public static void main(String[] args){
        ObservedScrollActions empty=ObservedScrollActions.observed(Collections.<String>emptyList());
        check(empty.observed&&!empty.hasAny(),"successfully read empty list grants no direction");
        check(!ObservedScrollActions.UNKNOWN.observed&&!ObservedScrollActions.UNKNOWN.hasAny(),"unavailable is not empty or a grant");
        check(ObservedScrollActions.observed(null)==ObservedScrollActions.UNKNOWN,"null cannot infer from a platform boolean");
        check(!empty.fingerprintInput().equals(ObservedScrollActions.UNKNOWN.fingerprintInput()),"known empty and unknown bind differently");

        List<String> original=new ArrayList<String>(Arrays.asList("left","forward","forward"));
        ObservedScrollActions actual=ObservedScrollActions.observed(original);original.clear();
        check(actual.directions.equals(Arrays.asList("forward","left")),"stable ordered immutable set from exact observed names");
        check(actual.allows("forward")&&!actual.allows("down")&&!actual.allows("backward"),"logical forward is not mapped to down or another direction");
        boolean immutable=false;try{actual.directions.add("down");}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"published directions immutable");
        for(List<String> invalid:Arrays.asList(Arrays.asList("diagonal"),Arrays.asList((String)null))){
            boolean rejected=false;try{ObservedScrollActions.observed(invalid);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"invalid named capability cannot enter a frame");
        }
        String oldSignature="original-app-tree-node-signature";
        ObservedScrollActions down=ObservedScrollActions.observed(Arrays.asList("down"));
        check(!actual.bindFreshness(oldSignature).equals(down.bindFreshness(oldSignature)),"direction changes invalidate target freshness");
        check(actual.bindFreshness(oldSignature).startsWith(oldSignature+"\n"),"original progress signature is a separate unchanged input");
        System.out.println("PASS 3 focused scroll state/identity groups; Android action collection not exercised");
    }
}
