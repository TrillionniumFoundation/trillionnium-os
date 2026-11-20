import org.trillionnium.hepta.local.ImeVisibility;
import org.trillionnium.hepta.local.ObservationState;
import org.trillionnium.hepta.local.ObservedWindowMetadata;
import java.util.Arrays;

/** Four focused cases for the actual metadata/freshness value class, without Android stubs. */
public final class ObservedWindowMetadataHostTest {
    private static final int[] ROOT={750,320,1212,610};
    public static void main(String[] args){
        missingWindow(); observedFields(); boundedText(); exactFreshness();
        System.out.println("PASS 4 active-window metadata cases; android_compiled=false; phone_tested=false");
    }
    private static void missingWindow(){
        int[] source=ROOT.clone();
        ObservedWindowMetadata value=ObservedWindowMetadata.unknown(source,"android.widget.PopupWindow");
        source[0]=0;int[] returned=value.rootBounds();returned[0]=0;
        require("unknown".equals(value.status)&&value.type==null&&value.title==null&&value.windowBounds()==null,
                "missing window must not manufacture application type/title/bounds");
        require(Arrays.equals(ROOT,value.rootBounds())&&"active_root_only".equals(ObservedWindowMetadata.SCOPE),
                "known root geometry remains immutable and does not imply full application coverage");
    }
    private static void observedFields(){
        int[] window={740,300,1220,630};
        ObservedWindowMetadata value=ObservedWindowMetadata.observed(ROOT,null,1,0,window,null);
        window[0]=0;
        require("observed".equals(value.status)&&value.type.intValue()==1&&value.displayId.intValue()==0,
                "retain raw Android type/display values without inferring a page or popup role");
        require(value.title==null&&value.rootClass==null&&!value.titleTruncated,
                "API null title/class remain unknown rather than app-name fallbacks");
        require(value.windowBounds()[0]==740&&!Arrays.equals(value.windowBounds(),value.rootBounds()),
                "window bounds and root bounds are independently observed");
        require(ObservedWindowMetadata.observed(ROOT,null,1,0,new int[]{0,0,0,0},null).windowBounds()==null,
                "empty API window bounds stay unknown");
    }
    private static void boundedText(){
        StringBuilder longTitle=new StringBuilder();
        for(int i=0;i<100;i++)longTitle.append("\uD83D\uDE00");
        ObservedWindowMetadata value=ObservedWindowMetadata.observed(ROOT,longTitle.toString(),1,0,ROOT,longTitle.toString());
        require(value.titleTruncated&&value.title.length()<=ObservedWindowMetadata.TITLE_LIMIT&&value.title.endsWith("…"),
                "window title is explicitly bounded/truncated");
        require(value.rootClassTruncated&&value.rootClass.length()<=ObservedWindowMetadata.CLASS_LIMIT,
                "root class is independently bounded");
        require(value.promptTitleTruncated()&&value.promptTitle().length()<=ObservedWindowMetadata.PROMPT_TITLE_LIMIT
                &&value.promptRootClassTruncated()&&value.promptRootClass().length()<=ObservedWindowMetadata.PROMPT_CLASS_LIMIT,
                "the model projection has an independent explicit tighter text budget");
        require(!Character.isHighSurrogate(value.title.charAt(value.title.length()-2)),"truncation must not split a surrogate pair");
    }
    private static void exactFreshness(){
        StringBuilder prefix=new StringBuilder();for(int i=0;i<120;i++)prefix.append('x');
        ObservedWindowMetadata a=ObservedWindowMetadata.observed(ROOT,"Root",1,0,ROOT,prefix+"a");
        ObservedWindowMetadata b=ObservedWindowMetadata.observed(ROOT,"Root",1,0,ROOT,prefix+"b");
        ObservationState state=new ObservationState("same-app-tree",ImeVisibility.HIDDEN);
        require(a.title.equals(b.title)&&!a.bindFreshness(state.fingerprintInput()).equals(b.bindFreshness(state.fingerprintInput())),
                "a changed title suffix still invalidates exact freshness after display truncation");
        require(!a.bindFreshness(state.fingerprintInput()).equals(ObservedWindowMetadata.unknown(ROOT,"Root").bindFreshness(state.fingerprintInput())),
                "metadata known/unknown change invalidates snapshot freshness");
        require(!a.bindFreshness(state.fingerprintInput()+"\nnode_focus=n0=false\n")
                .equals(a.bindFreshness(state.fingerprintInput()+"\nnode_focus=n0=true\n")),
                "focus changes collected with the same node IDs invalidate exact snapshot freshness");
        require(Boolean.FALSE.equals(state.changedFrom(state)),"metadata availability does not manufacture app-tree/IME progress");
    }
    private static void require(boolean passed,String why){if(!passed)throw new AssertionError(why);}
}
