import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.DecisionGrammar;
import org.trillionnium.hepta.local.ImeVisibility;
import org.trillionnium.hepta.local.ObservationState;
import org.trillionnium.hepta.local.ObservedScrollActions;
import org.trillionnium.hepta.local.ObservedTargetLabels;
import org.trillionnium.hepta.local.RepeatActionGuard;
import org.trillionnium.hepta.local.SameStateNoEffectGuard;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class SameStateNoEffectGuardHostTest {
    private static final String OBS="f91c685bf5f04f5c9a6a3197eade1fed",PKG="com.example.screen";
    private static final ObservationState A=new ObservationState("tree-a",ImeVisibility.HIDDEN);
    private static final ObservationState B=new ObservationState("tree-b",ImeVisibility.HIDDEN);
    private static final ObservationState VISIBLE=new ObservationState("tree-a",ImeVisibility.VISIBLE);
    private static final ObservationState UNKNOWN=new ObservationState("tree-a",ImeVisibility.UNKNOWN);
    private static int count;
    private static void check(boolean yes,String message){count++;if(!yes)throw new AssertionError(message);}
    private static ActionDecision click(String id)throws Exception{return parse("click",PKG,",\"node_label\":\"same label\",\"node_id\":\""+id+"\"");}
    private static ActionDecision parse(String kind,String pkg,String rest)throws Exception {
        return ActionDecision.parse("{\"action\":\""+kind+"\",\"observation_id\":\""+OBS+"\",\"package\":\""+pkg+"\""+rest+"}");
    }
    private static void record(SameStateNoEffectGuard guard,ActionDecision action,ObservationState before,ObservationState after) {
        guard.observed(action,PKG,before,PKG,after,true,true,false);
    }
    private static Set<String> set(String... values){return new HashSet<String>(Arrays.asList(values));}
    private static Map<String,String> labels() {
        Map<String,String> m=new HashMap<String,String>();m.put("n1","same label");m.put("n2","same label");m.put("n3","different");return m;
    }

    public static void main(String[] args)throws Exception {
        ActionDecision one=click("n1"),two=click("n2"),three=click("n3");
        if(args.length>0&&"--legacy-negative".equals(args[0])) {
            RepeatActionGuard old=new RepeatActionGuard();old.observed(one,A,A);old.observed(two,A,A);
            check(old.rejects(one,A)&&old.rejects(two,A),"both distinct confirmed no-effect clicks must remain blocked");
            throw new AssertionError("negative control unexpectedly satisfied cumulative contract");
        }
        SameStateNoEffectGuard g=new SameStateNoEffectGuard();
        check(!g.rejects(one,PKG,A),"first action has no invented failure");
        record(g,one,A,A);record(g,two,A,A);
        check(g.rejects(one,PKG,A)&&g.rejects(two,PKG,A),"both distinct confirmed no-effect clicks must remain blocked");
        check(!g.rejects(three,PKG,A),"a different observed target is not selected or denied by inference");
        Set<String> supplied=set("n1","n2","n3");
        SameStateNoEffectGuard.Snapshot snapshot=g.snapshot(PKG,A);
        check(snapshot.allowedClicks(supplied).equals(set("n3"))&&supplied.size()==3,"subtract all known clicks without modifying caller domain");
        check(snapshot.blockedClickNodeIds.size()==2,"duplicate labels do not merge distinct node identities");
        SameStateNoEffectGuard.Projection projection=snapshot.project(set(),labels());
        check(projection.rows.size()==2&&projection.omitted==0,"all visible blocked clicks represented");
        check("n1".equals(projection.rows.get(0).get("node_id"))&&"same label".equals(projection.rows.get(0).get("node_label")),"metadata uses current label/id pair");
        Map<String,String> subset=new HashMap<String,String>();subset.put("n3","different");
        check(snapshot.project(set(),subset).rows.isEmpty()&&snapshot.project(set(),subset).omitted==2,"budget omissions have count and no dangling node");
        boolean immutable=false;try{snapshot.blockedClickNodeIds.clear();}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"snapshot cannot mutate guard history");
        ActionDecision newer=ActionDecision.parse("{\"reason\":\"different narrative\",\"action\":\"click\",\"observation_id\":\"00000000000000000000000000000000\",\"package\":\""+PKG+"\",\"node_label\":\"same label\",\"node_id\":\"n1\"}");
        check(g.rejects(newer,PKG,A),"reason and new observation ID do not erase same-effect evidence");
        check(!g.rejects(one,"com.example.other",A),"different observed package clears rather than carries node IDs");
        check(!g.rejects(one,PKG,A),"returning package does not revive old epoch");
        record(g,one,A,A);g.snapshot(PKG,B);
        check(!g.rejects(one,PKG,A),"observed tree change clears permanently even on return");
        record(g,one,A,A);g.snapshot(PKG,VISIBLE);
        check(!g.rejects(one,PKG,A),"known IME change clears the epoch");
        record(g,one,A,A);
        check(g.rejects(one,PKG,UNKNOWN)&&g.rejects(one,PKG,A),"unknown IME is not evidence that known blocked actions became effective");
        SameStateNoEffectGuard uncertain=new SameStateNoEffectGuard();
        record(uncertain,one,UNKNOWN,UNKNOWN);
        check(!uncertain.rejects(one,PKG,A),"unknown outcome is not added as confirmed no-effect");
        g.observed(two,PKG,A,PKG,A,false,true,false);
        check(!g.rejects(two,PKG,A),"rejected outcome is not recorded");
        g.observed(two,PKG,A,PKG,A,true,false,false);
        check(!g.rejects(two,PKG,A),"undispatched outcome is not recorded");
        g.observed(two,PKG,A,PKG,A,true,true,true);
        check(!g.rejects(two,PKG,A),"stale outcome is not recorded");
        ActionDecision wait=parse("wait",PKG,",\"duration_ms\":100");
        ActionDecision find=parse("find_app",PKG,",\"query\":\"reader\",\"offset\":0");
        g.observed(wait,PKG,A,PKG,A,true,false,false);
        g.observed(find,PKG,A,PKG,A,true,false,false);
        check(g.rejects(one,PKG,A),"same-state wait/discovery cannot erase confirmed effects");
        g.observed(wait,PKG,A,PKG,B,true,false,false);
        check(!g.rejects(one,PKG,B),"fresh state change after wait clears");
        record(g,one,A,B);
        check(!g.rejects(one,PKG,B),"successful changed click is not blacklisted");
        check(!new SameStateNoEffectGuard().rejects(one,PKG,A),"new owner task starts without another task's records");

        SameStateNoEffectGuard opens=new SameStateNoEffectGuard();
        ActionDecision app1=parse("open","com.example.reader",""),app2=parse("open","com.example.notes","");
        record(opens,app1,A,A);record(opens,app2,A,A);
        Set<String> apps=set("com.example.reader","com.example.notes","com.example.other");
        check(opens.rejects(app1,PKG,A)&&opens.rejects(app2,PKG,A),"unchanged opens accumulate independently");
        check(opens.snapshot(PKG,A).allowedOpenPackages(apps).equals(set("com.example.other"))&&apps.size()==3,"open filtering neither grants nor mutates packages");
        check(opens.snapshot(PKG,A).project(set("com.example.reader"),labels()).omitted==1,"unshown blocked package has explicit omission");
        ActionDecision type=parse("type",PKG,",\"node_label\":\"same label\",\"node_id\":\"n1\",\"text\":\"first\"");
        ActionDecision otherType=parse("type",PKG,",\"node_label\":\"same label\",\"node_id\":\"n1\",\"text\":\"second\"");
        record(opens,type,A,A);
        check(!opens.rejects(type,PKG,A)&&!opens.rejects(otherType,PKG,A),"candidate does not generalize failed type into a field ban");
        check(opens.rejects(app1,PKG,A),"other unchanged tool does not erase tracked open facts");
        RepeatActionGuard original=new RepeatActionGuard();original.observed(type,A,A);
        check(original.rejects(type,A)&&!original.rejects(otherType,A),"original exact type guard remains available and unchanged");
        SameStateNoEffectGuard full=new SameStateNoEffectGuard();
        for(int i=0;i<SameStateNoEffectGuard.MAX_RECORDS;i++)record(full,click("n"+i),A,A);
        boolean bounded=false;try{record(full,click("n99"),A,A);}catch(IllegalStateException expected){bounded=true;}
        check(bounded&&full.rejects(click("n0"),PKG,A),"capacity stops without evicting a previously blocked action");
        if(args.length>0) {
            Path out=Paths.get(args[0]);Files.createDirectories(out);
            emit(out,"same-state-before.gbnf",new SameStateNoEffectGuard().snapshot(PKG,A));
            SameStateNoEffectGuard both=new SameStateNoEffectGuard();record(both,one,A,A);record(both,two,A,A);record(both,app1,A,A);record(both,app2,A,A);
            emit(out,"same-state-blocked.gbnf",both.snapshot(PKG,A));
            both.snapshot(PKG,B);emit(out,"same-state-changed.gbnf",both.snapshot(PKG,B));
        }
        System.out.println("PASS "+count+" cumulative no-effect contracts; android_compiled=false; phone_tested=false");
    }
    private static void emit(Path out,String name,SameStateNoEffectGuard.Snapshot blocked)throws Exception {
        Map<String,String> values=labels();
        ObservedTargetLabels target=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,PKG,values);
        Map<String,ObservedScrollActions> scrolls=Collections.emptyMap();
        DecisionGrammar grammar=DecisionGrammar.create(OBS,PKG,
          blocked.allowedOpenPackages(set("com.example.reader","com.example.notes","com.example.other")),
          blocked.allowedClicks(values.keySet()),set("n1"),scrolls,target);
        Files.write(out.resolve(name),grammar.text.getBytes(StandardCharsets.UTF_8));
    }
}
