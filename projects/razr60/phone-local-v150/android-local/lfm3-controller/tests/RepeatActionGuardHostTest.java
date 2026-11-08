import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.ActionPolicy;
import org.trillionnium.hepta.local.DecisionGrammar;
import org.trillionnium.hepta.local.ObservedTargetLabels;
import org.trillionnium.hepta.local.RepeatActionGuard;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Real parser, guard, policy and emitted grammar; no Android or inference. */
public final class RepeatActionGuardHostTest {
    private static final String OBS="f91c685bf5f04f5c9a6a3197eade1fed";
    private static final String CURRENT="com.example.launcher";
    private static final String TARGET="com.example.reader";
    private static final String OTHER="com.example.notes";
    private static int checks;

    public static void main(String[] args)throws Exception {
        Path out=Paths.get(args[0]);Files.createDirectories(out);
        Set<String> catalogue=set(TARGET,OTHER,CURRENT),nodes=set("n1");
        ActionDecision open=action("open",TARGET,"");
        ActionDecision home=action("home",CURRENT,"");
        ActionDecision wait=action("wait",CURRENT,",\"duration_ms\":100");
        ActionDecision discovery=action("find_app",CURRENT,",\"query\":\"reader\",\"offset\":0");
        RepeatActionGuard guard=new RepeatActionGuard();

        check(!guard.rejects(open,"A")&&guard.blockedOpenPackage("A")==null,"first open is not suppressed");
        guard.observed(open,"A","B");
        check(!guard.rejects(open,"B")&&guard.blockedOpenPackage("B")==null,"changed launch is not a new cooldown");
        emit(out,"repeat-before.gbnf",guard,catalogue,"B");
        guard.observed(open,"B","B");
        check(guard.rejects(open,"B")&&TARGET.equals(guard.blockedOpenPackage("B")),"unchanged repeated open is unavailable");
        ActionDecision changedDescription=ActionDecision.parse(json("open",TARGET,",\"reason\":\"different explanation\"")
                .replace(OBS,"00000000000000000000000000000000"));
        check(guard.rejects(changedDescription,"B"),"new observation id/reason cannot change effect identity");
        check(!guard.rejects(open,"C")&&guard.blockedOpenPackage("C")==null,"different actual tree is not blocked");
        Set<String> allowed=guard.allowedOpenPackages(catalogue,"B");
        check(catalogue.contains(TARGET)&&catalogue.size()==3,"filter does not rewrite catalogue or paging");
        check(!allowed.contains(TARGET)&&allowed.contains(OTHER)&&allowed.contains(CURRENT),"only exact blocked open package removed");
        check(!policy(open,allowed,nodes),"policy denies the same package omitted from grammar");
        check(policy(action("open",OTHER,""),allowed,nodes),"other shown launch stays available");
        check(!policy(action("open",CURRENT,""),allowed,nodes),"existing exact-current-package policy stays separate");
        check(policy(action("back",CURRENT,""),allowed,nodes),"model may choose navigation; guard does not choose it");
        emit(out,"repeat-blocked.gbnf",guard,catalogue,"B");
        check(guard.allowedOpenPackages(set(OTHER),"B").equals(set(OTHER)),"unshown blocked app grants no new package");

        guard.observed(discovery,"B","B");
        check(guard.rejects(open,"B")&&TARGET.equals(guard.blockedOpenPackage("B")),"read-only discovery preserves old guard");
        emit(out,"repeat-discovery-preserved.gbnf",guard,catalogue,"B");
        guard.observed(wait,"B","B");
        check(!guard.rejects(open,"B")&&guard.blockedOpenPackage("B")==null,"wait keeps its original reset semantics");

        guard.observed(open,"B","B");
        guard.observed(home,"B","C");
        check(!guard.rejects(open,"C")&&guard.allowedOpenPackages(catalogue,"C").contains(TARGET),"ordered open-home-open remains available");
        emit(out,"repeat-home-restored.gbnf",guard,catalogue,"C");
        guard.observed(open,"C","C");
        guard.observed(home,"C","C");
        check(!guard.rejects(open,"C")&&guard.blockedOpenPackage("C")==null,"even unchanged home replaces the old open key");
        check(guard.rejects(home,"C"),"unchanged navigation still has the original dispatch-time guard");

        ActionDecision click=action("click",CURRENT,",\"node_id\":\"n1\"");
        guard.observed(click,"C","C");
        check(guard.rejects(click,"C")&&guard.blockedOpenPackage("C")==null,"non-open guard remains at dispatch without masking opens");
        check(!guard.rejects(action("click",CURRENT,",\"node_id\":\"n2\""),"C"),"different node is a different effect");
        ActionDecision type=action("type",CURRENT,",\"node_id\":\"n1\",\"text\":\"first\"");
        guard.observed(type,"C","C");
        check(guard.rejects(type,"C"),"identical type effect stays guarded");
        check(!guard.rejects(action("type",CURRENT,",\"node_id\":\"n1\",\"text\":\"second\""),"C"),"changed type payload is not newly restricted");
        ActionDecision scroll=action("scroll",CURRENT,",\"node_id\":\"n1\",\"direction\":\"down\"");
        guard.observed(scroll,"C","C");
        check(!guard.rejects(action("scroll",CURRENT,",\"node_id\":\"n1\",\"direction\":\"up\""),"C"),"changed scroll direction keeps its identity");
        System.out.println("PASS "+checks+" repeat-guard/projection contracts; android_compiled=false; phone_tested=false");
    }

    private static void emit(Path out,String name,RepeatActionGuard guard,Set<String> catalogue,String tree)throws Exception {
        Set<String> allowed=guard.allowedOpenPackages(catalogue,tree);
        DecisionGrammar grammar=DecisionGrammar.create(OBS,CURRENT,allowed,set("n1"),set(),set(),labels(set("n1")));
        Files.write(out.resolve(name),grammar.text.getBytes(StandardCharsets.UTF_8));
    }
    private static boolean policy(ActionDecision action,Set<String> apps,Set<String> nodes)throws Exception {
        try{ActionPolicy.validateTextDecision(action,CURRENT,apps,labels(nodes));return true;}
        catch(ActionDecision.InvalidActionException expected){return false;}
    }
    private static String json(String name,String pkg,String extra){
        if(("click".equals(name)||"type".equals(name)||"scroll".equals(name))&&extra.contains("\"node_id\""))extra=",\"node_label\":\"\""+extra;
        return "{\"action\":\""+name+"\",\"observation_id\":\""+OBS+"\",\"package\":\""+pkg+"\""+extra+"}";
    }
    private static ObservedTargetLabels labels(Set<String> nodes){
        java.util.Map<String,String> values=new java.util.HashMap<String,String>();for(String node:nodes)values.put(node,"");
        return ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,CURRENT,values);
    }
    private static ActionDecision action(String name,String pkg,String extra)throws Exception{return ActionDecision.parse(json(name,pkg,extra));}
    private static Set<String> set(String... values){return new HashSet<String>(Arrays.asList(values));}
    private static void check(boolean value,String detail){checks++;if(!value)throw new AssertionError(detail);}
}
