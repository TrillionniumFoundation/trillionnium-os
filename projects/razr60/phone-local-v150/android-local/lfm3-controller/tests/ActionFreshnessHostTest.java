import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.ActionPolicy;

/** Navigation/catalogue tools tolerate unrelated changing readouts; node targets
 * and evidence-dependent completion keep the complete observation-tree gate. */
public final class ActionFreshnessHostTest {
    private static ActionDecision parse(String action,String extra)throws Exception {
        return ActionDecision.parse("{\"action\":\""+action+"\",\"observation_id\":\"0123456789abcdef0123456789abcdef\",\"package\":\"com.example.app\""+extra+"}");
    }
    private static void check(String action,String extra,boolean expected)throws Exception {
        if(ActionPolicy.requiresStableTree(parse(action,extra))!=expected)
            throw new AssertionError("unexpected tree requirement: "+action);
    }
    public static void main(String[] args)throws Exception {
        check("open","",false); check("home","",false);
        check("wait",",\"duration_ms\":100",false);
        check("find_app",",\"query\":\"calc\",\"offset\":0",false);
        check("back","",true); check("click",",\"node_label\":\"\",\"node_id\":\"n1\"",true);
        check("type",",\"node_label\":\"\",\"node_id\":\"n1\",\"text\":\"test\"",true);
        check("scroll",",\"node_label\":\"\",\"node_id\":\"n1\",\"direction\":\"down\"",true);
        check("done",",\"status\":\"success\",\"summary\":\"visible evidence\"",true);
        System.out.println("PASS 9 action-specific tree freshness contracts; live window verification remains in service");
    }
}
