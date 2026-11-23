import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.ImeVisibility;
import org.trillionnium.hepta.local.ObservationState;
import org.trillionnium.hepta.local.RepeatActionGuard;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Real progress/guard code; no fake Android windows or inferred phone success. */
public final class ImeObservationHostTest {
    private static int checks;
    private static final String OBS="f91c685bf5f04f5c9a6a3197eade1fed";
    private static final String PACKAGE="com.example.reader";
    public static void main(String[] args)throws Exception {
        check(ImeVisibility.observed(true,true,true)==ImeVisibility.VISIBLE,"visible floating IME does not depend on focus or bottom geometry");
        check(ImeVisibility.observed(true,true,false)==ImeVisibility.HIDDEN,"complete target window list without IME proves hidden");
        check(ImeVisibility.observed(false,true,false)==ImeVisibility.UNKNOWN,"unavailable or incomplete windows do not prove hidden");
        check(ImeVisibility.observed(false,true,true)==ImeVisibility.UNKNOWN,"invalid metadata remains unknown");
        check(ImeVisibility.observed(true,false,false)==ImeVisibility.UNKNOWN,"target missing from snapshot is not hidden");
        check(ImeVisibility.observed(true,false,true)==ImeVisibility.UNKNOWN,"other-display IME is not target visibility");
        check(ImeVisibility.UNKNOWN.value()==null,"unknown serializes explicitly as null");
        check(Boolean.TRUE.equals(ImeVisibility.VISIBLE.value())&&Boolean.FALSE.equals(ImeVisibility.HIDDEN.value()),"known states preserve boolean meaning");

        ActionDecision back=action("back",PACKAGE),open=action("open","com.example.notes");
        ObservationState visible=state("same-app-tree",ImeVisibility.VISIBLE);
        ObservationState hidden=state("same-app-tree",ImeVisibility.HIDDEN);
        ObservationState unknown=state("same-app-tree",ImeVisibility.UNKNOWN);
        check(visible.appTreeSha256.equals(hidden.appTreeSha256),"IME-only transition preserves original app-tree identity");
        check(!visible.fingerprintInput().equals(hidden.fingerprintInput()),"known IME transition changes exact freshness input");
        check(!unknown.fingerprintInput().equals(visible.fingerprintInput())&&!unknown.fingerprintInput().equals(hidden.fingerprintInput()),"unknown distinct for exact freshness checks");
        check(Boolean.TRUE.equals(hidden.changedFrom(visible)),"IME close is real observed progress with same app tree");
        check(Boolean.TRUE.equals(visible.changedFrom(hidden)),"IME show is real observed progress");
        check(unknown.changedFrom(visible)==null&&hidden.changedFrom(unknown)==null,"losing or regaining visibility alone is unknown progress");

        RepeatActionGuard guard=new RepeatActionGuard();
        guard.observed(back,visible,hidden);
        check(!guard.rejects(back,hidden),"back which closed IME allows subsequent back on unchanged app tree");
        guard.observed(back,hidden,hidden);
        check(guard.rejects(back,hidden),"a further unchanged back is still rejected");
        guard.observed(back,visible,visible);
        check(guard.rejects(back,visible),"same visible IME and app tree do not loosen back guard");
        guard.observed(back,unknown,unknown);
        check(guard.rejects(back,unknown)&&guard.rejects(back,hidden)&&guard.rejects(back,visible),"unknown cannot reset a repeated action");
        guard.observed(back,visible,unknown);
        check(guard.rejects(back,hidden),"unobserved after-state is not credited as IME close");
        guard.observed(back,unknown,hidden);
        check(guard.rejects(back,hidden),"unknown before-state is not credited as IME close");

        for(ImeVisibility before:ImeVisibility.values())for(ImeVisibility after:ImeVisibility.values()){
            ObservationState a=state("same",before),b=state("same",after);
            boolean knownChange=before!=ImeVisibility.UNKNOWN&&after!=ImeVisibility.UNKNOWN&&before!=after;
            guard.observed(back,a,b);
            check(guard.rejects(back,b)!=knownChange,"all IME transition pairs preserve conservative repeat predicate");
        }
        guard.observed(back,unknown,state("different-app-tree",ImeVisibility.UNKNOWN));
        check(!guard.rejects(back,state("different-app-tree",ImeVisibility.UNKNOWN)),"actual app-tree change still proves progress with unknown IME");
        Set<String> apps=new HashSet<String>(Arrays.asList("com.example.notes",PACKAGE));
        guard.observed(open,hidden,hidden);
        check(!guard.allowedOpenPackages(apps,hidden).contains("com.example.notes"),"unchanged open remains omitted from candidates");
        check(!guard.allowedOpenPackages(apps,unknown).contains("com.example.notes"),"unknown visibility cannot re-enable a rejected open");
        check(guard.allowedOpenPackages(apps,visible).contains("com.example.notes"),"known new IME state is a real observed change");
        System.out.println("PASS "+checks+" input-method observation/progress contracts; android_compiled=false; phone_tested=false");
    }
    private static ObservationState state(String tree,ImeVisibility ime){return new ObservationState(tree,ime);}
    private static ActionDecision action(String action,String pkg)throws Exception {
        return ActionDecision.parse("{\"action\":\""+action+"\",\"observation_id\":\""+OBS+"\",\"package\":\""+pkg+"\"}");
    }
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
}
