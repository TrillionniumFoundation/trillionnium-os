import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.ImeVisibility;
import org.trillionnium.hepta.local.ObservationState;
import org.trillionnium.hepta.local.RepeatActionGuard;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Four focused cases: the candidate filter is exactly the pre-existing repeat predicate. */
public final class RepeatClickProjectionHostTest {
    private static final String OBS="f91c685bf5f04f5c9a6a3197eade1fed",PKG="com.example.app";
    public static void main(String[] args)throws Exception {
        onlyRejectedTarget(); actualProgressRestores(); unknownIsNotProgress(); discoveryPreserves();
        System.out.println("PASS 4 repeat-click projection cases; android_compiled=false; phone_tested=false");
    }
    private static void onlyRejectedTarget()throws Exception{
        RepeatActionGuard guard=new RepeatActionGuard();ObservationState state=state("tree",ImeVisibility.HIDDEN);
        ActionDecision first=click("n0");guard.observed(first,state,state);
        Set<String> shown=set("n0","n1"),allowed=guard.allowedClicks(shown,state);
        require(guard.rejects(first,state)&&"n0".equals(guard.blockedClickNodeId(state)),"only already rejected node is exposed");
        require(allowed.equals(set("n1"))&&shown.equals(set("n0","n1")),"remove exact click capability without altering supplied/visible nodes");
        require(!guard.rejects(click("n1"),state)&&guard.allowedClicks(set("n1"),state).equals(set("n1")),
                "a different target stays allowed and filtering never adds nodes");
    }
    private static void actualProgressRestores()throws Exception{
        RepeatActionGuard guard=new RepeatActionGuard();ObservationState old=state("tree",ImeVisibility.HIDDEN);
        ActionDecision click=click("n0");guard.observed(click,old,old);
        ObservationState changed=state("different-tree",ImeVisibility.HIDDEN);
        require(guard.blockedClickNodeId(changed)==null&&guard.allowedClicks(set("n0"),changed).contains("n0"),
                "actual tree change restores the original candidate");
        ObservationState imeChanged=state("tree",ImeVisibility.VISIBLE);
        require(guard.blockedClickNodeId(imeChanged)==null,"known input-method change keeps the existing progress rule");
    }
    private static void unknownIsNotProgress()throws Exception{
        RepeatActionGuard guard=new RepeatActionGuard();ObservationState unknown=state("tree",ImeVisibility.UNKNOWN);
        guard.observed(click("n0"),unknown,unknown);
        for(ImeVisibility current:new ImeVisibility[]{ImeVisibility.UNKNOWN,ImeVisibility.HIDDEN,ImeVisibility.VISIBLE}){
            ObservationState value=state("tree",current);
            require(guard.rejects(click("n0"),value)&&!guard.allowedClicks(set("n0","n1"),value).contains("n0"),
                    "unknown IME cannot undo a click rejected by the original guard");
        }
    }
    private static void discoveryPreserves()throws Exception{
        RepeatActionGuard guard=new RepeatActionGuard();ObservationState state=state("tree",ImeVisibility.HIDDEN);
        guard.observed(click("n0"),state,state);
        guard.observed(action("find_app",",\"query\":\"example\",\"offset\":0"),state,state);
        require("n0".equals(guard.blockedClickNodeId(state))&&!guard.allowedClicks(set("n0"),state).contains("n0"),
                "read-only discovery cannot erase the preceding blocked effect");
        guard.observed(action("wait",",\"duration_ms\":100"),state,state);
        require(guard.blockedClickNodeId(state)==null,"the existing wait-reset rule is unchanged");
    }
    private static ObservationState state(String tree,ImeVisibility ime){return new ObservationState(tree,ime);}
    private static ActionDecision click(String id)throws Exception{return action("click",",\"node_label\":\"visible\",\"node_id\":\""+id+"\"");}
    private static ActionDecision action(String action,String more)throws Exception{
        return ActionDecision.parse("{\"action\":\""+action+"\",\"observation_id\":\""+OBS+"\",\"package\":\""+PKG+"\""+more+"}");
    }
    private static Set<String> set(String... values){return new HashSet<String>(Arrays.asList(values));}
    private static void require(boolean passed,String why){if(!passed)throw new AssertionError(why);}
}
