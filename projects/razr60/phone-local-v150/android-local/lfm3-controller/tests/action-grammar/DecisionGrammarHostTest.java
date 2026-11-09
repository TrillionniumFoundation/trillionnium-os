import org.trillionnium.hepta.local.DecisionGrammar;
import org.trillionnium.hepta.local.ObservedTargetLabels;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public final class DecisionGrammarHostTest {
    /** Synthetic test capabilities are now explicit instead of implied by a node set. */
    private static java.util.Map<String,org.trillionnium.hepta.local.ObservedScrollActions> scrolls(java.util.Set<String> nodes){
        java.util.Map<String,org.trillionnium.hepta.local.ObservedScrollActions> out=new java.util.HashMap<String,org.trillionnium.hepta.local.ObservedScrollActions>();
        for(String node:nodes)out.put(node,org.trillionnium.hepta.local.ObservedScrollActions.observed(
                java.util.Arrays.asList("forward","backward","up","down","left","right")));
        return out;
    }

    private static final String OBS="f91c685bf5f04f5c9a6a3197eade1fed";
    private static int assertions;
    private static Set<String> set(String... values){return new HashSet<String>(Arrays.asList(values));}
    private static ObservedTargetLabels labels(String pkg,String... ids){
        java.util.Map<String,String> map=new java.util.HashMap<String,String>();for(String id:ids)map.put(id,"");
        return ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,pkg,map);
    }
    private static void check(boolean yes,String message){assertions++;if(!yes)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);
        DecisionGrammar all=DecisionGrammar.create(OBS,"com.example.launcher",
            set("com.android.settings","com.example.calc","com.example.launcher","android"),set("n1","n11"),set("n2"),scrolls(set("n3")),labels("com.example.launcher","n1","n11","n2","n3"));
        check(all.actions.size()==9&&all.actions.contains("find_app"),"all nine permitted branches including local discovery");
        check(all.text.contains(OBS),"observation bound in emitted GBNF");
        DecisionGrammar reordered=DecisionGrammar.create(OBS,"com.example.launcher",
            set("android","com.example.launcher","com.example.calc","com.android.settings"),set("n11","n1"),set("n2"),scrolls(set("n3")),labels("com.example.launcher","n3","n2","n11","n1"));
        check(all.text.equals(reordered.text)&&all.sha256.equals(reordered.sha256),"deterministic across set order");
        Files.write(out.resolve("all.gbnf"),all.text.getBytes(StandardCharsets.UTF_8));
        DecisionGrammar system=DecisionGrammar.create(OBS,"android",set("android"),set(),set(),scrolls(set()),labels("android"));
        check(system.actions.size()==5&&system.actions.contains("find_app")&&!system.actions.contains("open")&&!system.actions.contains("click"),"discovery remains available with no supplied apps/nodes");
        Files.write(out.resolve("system.gbnf"),system.text.getBytes(StandardCharsets.UTF_8));
        for(String bad:new String[]{"com.example\"root","com.example\nroot ::=","android.","http://example"}){
            boolean denied=false;try{DecisionGrammar.create(OBS,"android",set(bad),set(),set(),scrolls(set()),labels("android"));}catch(IllegalArgumentException expected){denied=true;}
            check(denied,"package cannot inject grammar");
        }
        for(String bad:new String[]{"n1\"","n1 | root","1","n-1"}){
            boolean denied=false;try{DecisionGrammar.create(OBS,"android",set(),set(bad),set(),scrolls(set()),labels("android"));}catch(IllegalArgumentException expected){denied=true;}
            check(denied,"node id cannot inject grammar");
        }
        boolean denied=false;try{DecisionGrammar.create("000","android",set(),set(),set(),scrolls(set()),labels("android"));}catch(IllegalArgumentException expected){denied=true;}
        check(denied,"observation cannot be omitted or fabricated format");
        java.util.Map<String,String> pairs=new java.util.LinkedHashMap<String,String>();
        pairs.put("n12","1");pairs.put("n13","2");pairs.put("n14","3");pairs.put("n3","除");pairs.put("n7","乘");
        pairs.put("n20","重复");pairs.put("n21","重复");pairs.put("n22","");pairs.put("n23","");
        pairs.put("n24","引号\"\\\n中文😀");pairs.put("n25","x\u0000y\u2028z\u2029");
        pairs.put("n26",ObservedTargetLabels.project("12345678901234567890123456789012345😀tail"));
        ObservedTargetLabels supplied=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,"com.example.launcher",pairs);
        DecisionGrammar labeled=DecisionGrammar.create(OBS,"com.example.launcher",set(),pairs.keySet(),set("n24"),scrolls(set("n20")),supplied);
        Files.write(out.resolve("labeled-targets.gbnf"),labeled.text.getBytes(StandardCharsets.UTF_8));
        check(labeled.targets==supplied,"the exact immutable prompt binding is retained");
        check(DecisionGrammar.SCHEMA.equals("hepta.observed-action-gbnf.v3-label-first"),"new schema is explicit");
        denied=false;try{DecisionGrammar.create(OBS,"android",set(),set("n1"),set(),scrolls(set()),labels("android"));}catch(IllegalArgumentException expected){denied=true;}
        check(denied,"capability cannot admit a node missing from the supplied projection");
        denied=false;try{DecisionGrammar.create(OBS,"android",set(),set(),set(),scrolls(set()),supplied);}catch(IllegalArgumentException expected){denied=true;}
        check(denied,"a different package cannot reuse the projection");
        System.out.println("PASS "+assertions+" grammar construction/binding assertions; native_grammar_tested=false");
    }
}
