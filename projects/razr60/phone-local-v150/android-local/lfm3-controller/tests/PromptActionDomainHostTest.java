import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.trillionnium.hepta.local.ObservedScrollActions;
import org.trillionnium.hepta.local.PromptActionDomain;

public final class PromptActionDomainHostTest {
    private static int checks;
    private static void check(boolean condition,String message){checks++;if(!condition)throw new AssertionError(message);}
    public static void main(String[] ignored){
        Set<String> required=new LinkedHashSet<String>();
        for(int i=0;i<40;i++)if(PromptActionDomain.requiresRetention("sample.pkg","sample.pkg",true,false,true,false,ObservedScrollActions.UNKNOWN))required.add("item"+i);
        check(required.size()==40,"observed actionable domain has no 32-node cap");
        Set<String> shown=new LinkedHashSet<String>(required);PromptActionDomain.requireComplete(required,shown);
        shown.remove("item37");boolean rejected=false;try{PromptActionDomain.requireComplete(required,shown);}catch(IllegalStateException expected){rejected=true;}
        check(rejected,"missing any current target prevents admission");
        check(!PromptActionDomain.requiresRetention("sample.pkg","other.pkg",true,false,true,false,ObservedScrollActions.UNKNOWN),"foreign package adds no capability");
        check(!PromptActionDomain.requiresRetention("sample.pkg","sample.pkg",false,false,true,false,ObservedScrollActions.UNKNOWN),"disabled target adds no capability");
        check(!PromptActionDomain.requiresRetention("sample.pkg","sample.pkg",true,true,true,true,ObservedScrollActions.UNKNOWN),"password target adds no capability");
        check(!PromptActionDomain.requiresRetention("sample.pkg","sample.pkg",true,false,false,false,ObservedScrollActions.UNKNOWN),"unknown directions do not invent scrolling");
        check(PromptActionDomain.requiresRetention("sample.pkg","sample.pkg",true,false,false,false,ObservedScrollActions.observed(Arrays.asList("backward"))),"observed directional target is retained");
        System.out.println("PromptActionDomainHostTest: "+checks+" checks passed");
    }
}
