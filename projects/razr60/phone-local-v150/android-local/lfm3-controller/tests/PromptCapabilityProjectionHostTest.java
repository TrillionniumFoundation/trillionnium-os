import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.DecisionGrammar;
import org.trillionnium.hepta.local.ImeVisibility;
import org.trillionnium.hepta.local.ObservationState;
import org.trillionnium.hepta.local.ObservedScrollActions;
import org.trillionnium.hepta.local.ObservedTargetLabels;
import org.trillionnium.hepta.local.PromptActionDomain;
import org.trillionnium.hepta.local.RepeatActionGuard;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Regression: visible controls never advertise capabilities rejected by the real grammar. */
public final class PromptCapabilityProjectionHostTest {
    private static final String OBS="f91c685bf5f04f5c9a6a3197eade1fed",PKG="com.example.app";
    private static int checks;
    private static void require(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static final class Fixture {
        final String id,label,pkg;final boolean enabled,password,clickable,editable;
        final ObservedScrollActions scroll;
        Fixture(String id,String label,String pkg,boolean enabled,boolean password,boolean clickable,boolean editable,ObservedScrollActions scroll){
            this.id=id;this.label=label;this.pkg=pkg;this.enabled=enabled;this.password=password;
            this.clickable=clickable;this.editable=editable;this.scroll=scroll;
        }
    }
    public static void main(String[] args)throws Exception{
        ObservedScrollActions down=ObservedScrollActions.observed(Arrays.asList("down"));
        Fixture[] nodes={
            new Fixture("n1","repeat-input",PKG,true,false,true,true,ObservedScrollActions.UNKNOWN),
            new Fixture("n2","disabled-control",PKG,false,false,true,true,down),
            new Fixture("n3","password-control",PKG,true,true,true,true,down),
            new Fixture("n4","foreign-control","com.example.other",true,false,true,true,down),
            new Fixture("n5","real-scroll",PKG,true,false,false,false,down),
            new Fixture("n6","unknown-scroll",PKG,true,false,false,false,ObservedScrollActions.UNKNOWN),
            new Fixture("n7","empty-scroll",PKG,true,false,false,false,ObservedScrollActions.observed(Collections.<String>emptyList()))
        };
        Set<String> clicks=new LinkedHashSet<String>(),edits=new LinkedHashSet<String>();
        Map<String,ObservedScrollActions> scrolls=new LinkedHashMap<String,ObservedScrollActions>();
        Map<String,String> labels=new LinkedHashMap<String,String>();
        for(Fixture node:nodes){
            labels.put(node.id,node.label);
            if(!PromptActionDomain.eligible(PKG,node.pkg,node.enabled,node.password))continue;
            if(node.clickable)clicks.add(node.id);if(node.editable)edits.add(node.id);scrolls.put(node.id,node.scroll);
        }
        ObservationState state=new ObservationState("unchanged-tree",ImeVisibility.HIDDEN);
        RepeatActionGuard repeat=new RepeatActionGuard();
        ActionDecision click=ActionDecision.parse("{\"action\":\"click\",\"observation_id\":\""+OBS+"\",\"package\":\""+PKG+"\",\"node_label\":\"repeat-input\",\"node_id\":\"n1\"}");
        repeat.observed(click,state,state);clicks=repeat.allowedClicks(clicks,state);
        DecisionGrammar grammar=DecisionGrammar.create(OBS,PKG,Collections.<String>emptySet(),clicks,edits,scrolls,
                ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,PKG,labels));
        require("tf".equals(PromptActionDomain.promptFlags("n1",true,clicks,edits,scrolls)),"repeat-blocked click is hidden but real edit and focus remain");
        require(!grammar.actions.contains("click")&&grammar.actions.contains("type"),"real grammar has the same remaining effect kinds");
        for(String id:Arrays.asList("n2","n3","n4"))require("".equals(PromptActionDomain.promptFlags(id,false,clicks,edits,scrolls)),"ineligible node advertised an action: "+id);
        for(String label:Arrays.asList("disabled-control","password-control","foreign-control"))require(!grammar.text.contains(label),"ineligible label entered generated action grammar");
        require("s".equals(PromptActionDomain.promptFlags("n5",false,clicks,edits,scrolls)),"real scroll advertised");
        require(grammar.allowsScroll("n5","down")&&!grammar.allowsScroll("n5","up"),"only observed direction remains");
        require("".equals(PromptActionDomain.promptFlags("n6",false,clicks,edits,scrolls))&&!grammar.allowsScroll("n6","down"),"unknown scroll is not a capability");
        require("".equals(PromptActionDomain.promptFlags("n7",false,clicks,edits,scrolls))&&!grammar.allowsScroll("n7","down"),"empty scroll is not a capability");
        require(!PromptActionDomain.requiresRetention(PKG,PKG,false,false,true,true,down),"disabled observation need not be retained as an action target");
        require(PromptActionDomain.requiresRetention(PKG,PKG,true,false,true,true,ObservedScrollActions.UNKNOWN),"repeat-filtered current editable target remains in the observed domain");
        System.out.println("PASS "+checks+" prompt/grammar capability checks; phone_tested=false");
    }
}
