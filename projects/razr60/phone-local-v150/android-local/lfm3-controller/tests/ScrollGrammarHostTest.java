import org.trillionnium.hepta.local.DecisionGrammar;
import org.trillionnium.hepta.local.ObservedScrollActions;
import org.trillionnium.hepta.local.ObservedTargetLabels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Actual production GBNF emitter; names below are explicit synthetic capabilities. */
public final class ScrollGrammarHostTest {
    private static final String OBS="f91c685bf5f04f5c9a6a3197eade1fed",PACKAGE="com.example.launcher";
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);
        Map<String,String> labels=new LinkedHashMap<String,String>();
        labels.put("n1","");labels.put("n2","");labels.put("n3","unknown");labels.put("n4","empty");
        ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,PACKAGE,labels);
        Map<String,ObservedScrollActions> actions=new LinkedHashMap<String,ObservedScrollActions>();
        actions.put("n2",ObservedScrollActions.observed(Arrays.asList("left","down")));
        actions.put("n1",ObservedScrollActions.observed(Arrays.asList("forward")));
        actions.put("n3",ObservedScrollActions.UNKNOWN);
        actions.put("n4",ObservedScrollActions.observed(Collections.<String>emptyList()));
        DecisionGrammar grammar=DecisionGrammar.create(OBS,PACKAGE,Collections.<String>emptySet(),
                Collections.<String>emptySet(),Collections.<String>emptySet(),actions,targets);
        check(grammar.allowsScroll("n1","forward")&&!grammar.allowsScroll("n1","down"),"directions cannot migrate between equal-label nodes");
        check(!grammar.allowsScroll("n3","down")&&!grammar.allowsScroll("n4","down"),"unknown/empty grants no branch");
        actions.clear();check(grammar.allowsScroll("n2","left"),"caller map mutation cannot change emitted domain");
        boolean immutable=false;try{grammar.scrollDirections.clear();}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"published node-direction map immutable");
        Files.write(out.resolve("scroll-directions.gbnf"),grammar.text.getBytes(StandardCharsets.UTF_8));
        actions.put("n3",ObservedScrollActions.UNKNOWN);actions.put("n4",ObservedScrollActions.observed(Collections.<String>emptyList()));
        DecisionGrammar none=DecisionGrammar.create(OBS,PACKAGE,Collections.<String>emptySet(),
                Collections.<String>emptySet(),Collections.<String>emptySet(),actions,targets);
        check(!none.actions.contains("scroll"),"platform-scrollable without actual directions has no grammar branch");
        Files.write(out.resolve("scroll-unavailable.gbnf"),none.text.getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS node-specific scroll grammar construction; no native grammar/model execution");
    }
}
