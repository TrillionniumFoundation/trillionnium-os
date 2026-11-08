import org.trillionnium.hepta.local.DecisionGrammar;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public final class DecisionGrammarHostTest {
    private static final String OBS="f91c685bf5f04f5c9a6a3197eade1fed";
    private static int assertions;
    private static Set<String> set(String... values){return new HashSet<String>(Arrays.asList(values));}
    private static void check(boolean yes,String message){assertions++;if(!yes)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);
        DecisionGrammar all=DecisionGrammar.create(OBS,"com.example.launcher",
            set("com.android.settings","com.example.calc","com.example.launcher","android"),set("n1","n11"),set("n2"),set("n3"));
        check(all.actions.size()==9&&all.actions.contains("find_app"),"all nine permitted branches including local discovery");
        check(all.text.contains(OBS),"observation bound in emitted GBNF");
        DecisionGrammar reordered=DecisionGrammar.create(OBS,"com.example.launcher",
            set("android","com.example.launcher","com.example.calc","com.android.settings"),set("n11","n1"),set("n2"),set("n3"));
        check(all.text.equals(reordered.text)&&all.sha256.equals(reordered.sha256),"deterministic across set order");
        Files.write(out.resolve("all.gbnf"),all.text.getBytes(StandardCharsets.UTF_8));
        DecisionGrammar system=DecisionGrammar.create(OBS,"android",set("android"),set(),set(),set());
        check(system.actions.size()==5&&system.actions.contains("find_app")&&!system.actions.contains("open")&&!system.actions.contains("click"),"discovery remains available with no supplied apps/nodes");
        Files.write(out.resolve("system.gbnf"),system.text.getBytes(StandardCharsets.UTF_8));
        for(String bad:new String[]{"com.example\"root","com.example\nroot ::=","android.","http://example"}){
            boolean denied=false;try{DecisionGrammar.create(OBS,"android",set(bad),set(),set(),set());}catch(IllegalArgumentException expected){denied=true;}
            check(denied,"package cannot inject grammar");
        }
        for(String bad:new String[]{"n1\"","n1 | root","1","n-1"}){
            boolean denied=false;try{DecisionGrammar.create(OBS,"android",set(),set(bad),set(),set());}catch(IllegalArgumentException expected){denied=true;}
            check(denied,"node id cannot inject grammar");
        }
        boolean denied=false;try{DecisionGrammar.create("000","android",set(),set(),set(),set());}catch(IllegalArgumentException expected){denied=true;}
        check(denied,"observation cannot be omitted or fabricated format");
        System.out.println("PASS "+assertions+" grammar construction/binding assertions; native_grammar_tested=false");
    }
}
