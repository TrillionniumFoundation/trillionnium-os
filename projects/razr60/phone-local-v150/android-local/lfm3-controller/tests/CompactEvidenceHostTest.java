import java.util.*;
import org.trillionnium.hepta.local.*;

public final class CompactEvidenceHostTest {
    private static int count;
    private static void check(boolean value,String message){count++;if(!value)throw new AssertionError(message);}
    private static Map<String,Object> row(int step,String action,String from,String target,String to,boolean dispatched,Object change){
        Map<String,Object> r=new LinkedHashMap<String,Object>();
        r.put("step",Integer.valueOf(step));r.put("action",action);r.put("before_package",from);r.put("target_package",target);r.put("package_after",to);
        r.put("model_issued",Boolean.TRUE);r.put("accepted",Boolean.TRUE);r.put("dispatched",Boolean.valueOf(dispatched));r.put("stale",Boolean.FALSE);r.put("window_changed",change);
        return r;
    }
    private static Map<String,Object> query(int step,String text,String sha){
        Map<String,Object> r=row(step,"find_app","com.example.screen","com.example.screen","com.example.screen",false,Boolean.FALSE);
        r.put("read_only",Boolean.TRUE);r.put("query",text);r.put("offset",Integer.valueOf(0));
        r.put("find_returned",Integer.valueOf(1));r.put("find_matches",Integer.valueOf(1));r.put("find_catalogue_sha256",sha);return r;
    }
    private static Object dictionary(List<Object> values,Object index){int i=((Integer)index).intValue();return i<0?"absent":values.get(i);}
    private static boolean rejects(Runnable r){try{r.run();return false;}catch(IllegalArgumentException expected){return true;}}
    private static ActionDecision click(String id)throws Exception{
        return ActionDecision.parse("{\"action\":\"click\",\"observation_id\":\"0123456789abcdef0123456789abcdef\",\"package\":\"com.example.screen\",\"node_label\":\"fixture\",\"node_id\":\""+id+"\"}");
    }
    public static void main(String[] args)throws Exception{
        final String hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        List<Map<String,Object>> reads=new ArrayList<Map<String,Object>>();
        for(int i=1;i<=20;i++)reads.add(query(i,"fixture-query",hash));
        if(args.length>0&&"--legacy-negative".equals(args[0])){
            RecentActionProjection.CompactSequence old=RecentActionProjection.compactDispatched(reads,20);
            check(old.rows.size()==20,"readonly model calls must remain in the complete factual trace");
            throw new AssertionError("legacy negative unexpectedly passed");
        }
        RecentActionProjection.CompactEvents repeated=RecentActionProjection.compactEvents(reads,2);
        check(repeated.rows.size()==20&&repeated.observed==20,"twenty actual calls remain twenty rows");
        check(repeated.arguments.size()==1,"identical query arguments share dictionary without losing calls");
        check(repeated.states.size()==1,"identical actual status shares dictionary");
        check(repeated.detailOmittedSteps.isEmpty(),"full query has no invented omission");
        for(int i=0;i<20;i++){
            List<Object> r=repeated.rows.get(i);
            check(r.get(0).equals(Integer.valueOf(i+1))&&"find_app".equals(dictionary(repeated.actions,r.get(1))),"ordered readonly step retained");
        }
        Map<String,Object> provenance=RecentActionProjection.discoveryProvenance(reads,"fixture-query",0,hash);
        check("model_find_app".equals(provenance.get("source"))&&provenance.get("step").equals(Integer.valueOf(20)),"current page binds latest actual query");
        check(Boolean.TRUE.equals(provenance.get("model_issued"))&&provenance.get("returned").equals(Integer.valueOf(1)),"actual model-issued return count preserved");
        check(RecentActionProjection.discoveryProvenance(reads,"different",0,hash).get("model_issued")==null,"query mismatch never invents model origin");
        check("unbound".equals(RecentActionProjection.discoveryProvenance(reads,"fixture-query",1,hash).get("source")),"offset mismatch unbound");
        check("unbound".equals(RecentActionProjection.discoveryProvenance(reads,"fixture-query",0,hash.replace('a','b')).get("source")),"catalogue mismatch unbound");
        check(Boolean.FALSE.equals(RecentActionProjection.discoveryProvenance(Collections.<Map<String,Object>>emptyList(),"",0,hash).get("model_issued")),"initial catalogue is not a model query");
        reads.get(19).put("query","later-query");
        check("unbound".equals(RecentActionProjection.discoveryProvenance(reads,"fixture-query",0,hash).get("source")),"do not bind an older matching query over latest result");
        reads.get(19).put("stale",Boolean.TRUE);
        check(RecentActionProjection.discoveryProvenance(reads,"fixture-query",0,hash).get("step").equals(Integer.valueOf(19)),"stale read does not replace accepted current result");
        check(repeated.arguments.size()==1&&"fixture-query".equals(repeated.arguments.get(0).get("query")),"frozen argument snapshots ignore later history mutation");

        List<Map<String,Object>> nav=new ArrayList<Map<String,Object>>();
        nav.add(row(1,"open","com.example.home","com.example.a","com.example.a",true,Boolean.TRUE));
        nav.add(row(2,"open","com.example.a","com.example.b","com.example.b",true,Boolean.TRUE));
        nav.add(row(3,"back","com.example.b","com.example.b","com.example.a",true,Boolean.TRUE));
        for(int i=4;i<=20;i++){
            Map<String,Object> r=row(i,"scroll","com.example.a","com.example.a","com.example.a",true,i%3==0?null:Boolean.valueOf(i%2==0));
            r.put("direction",i%2==0?"down":"up");r.put("node_label","fixture-list");nav.add(r);
        }
        RecentActionProjection.CompactEvents compact=RecentActionProjection.compactEvents(nav,0);
        check(compact.rows.size()==20&&Integer.valueOf(0).equals(compact.jsonFields().get("omitted")),"detail pressure never removes early trace rows");
        for(int i=0;i<20;i++){
            List<Object> r=compact.rows.get(i);Map<String,Object> original=nav.get(i);
            check(Objects.equals(dictionary(compact.packages,r.get(2)),original.get("target_package"))
                &&Objects.equals(dictionary(compact.packages,r.get(3)),original.get("before_package"))
                &&Objects.equals(dictionary(compact.packages,r.get(4)),original.get("package_after")),"actual target/from/to order retained");
        }
        check("com.example.b".equals(dictionary(compact.packages,compact.rows.get(2).get(2)))
            &&"com.example.a".equals(dictionary(compact.packages,compact.rows.get(2).get(4))),"back destination not guessed from target");
        Map<String,Object> scrollArg=compact.arguments.get(((Integer)compact.rows.get(3).get(6)).intValue());
        check("down".equals(scrollArg.get("direction"))&&!scrollArg.containsKey("node_label"),"minimum scroll direction survives optional label omission");
        check(compact.detailOmittedSteps.size()==17&&compact.detailOmittedSteps.get(0).equals(Integer.valueOf(4)),"exact omitted-parameter steps");
        List<Object> unknown=compact.states.get(((Integer)compact.rows.get(5).get(5)).intValue());
        check(unknown.get(4)==null,"unknown change remains null");
        Map<String,Object> missing=row(1,"click","com.example.a","com.example.a","com.example.a",false,null);
        missing.remove("window_changed");missing.remove("package_after");missing.put("target_package",null);
        RecentActionProjection.CompactEvents absent=RecentActionProjection.compactEvents(Arrays.asList(missing),0);
        check("absent".equals(absent.states.get(0).get(4)),"absent status distinct from explicit unknown");
        check(absent.rows.get(0).get(4).equals(Integer.valueOf(-1))&&dictionary(absent.packages,absent.rows.get(0).get(2))==null,"absent package distinct from explicit null");
        Map<String,Object> rejected=row(1,"click","com.example.a","com.example.a","com.example.a",false,null);
        rejected.put("accepted",Boolean.FALSE);rejected.put("stale",Boolean.TRUE);rejected.put("node_id","n999");
        RecentActionProjection.CompactEvents rejection=RecentActionProjection.compactEvents(Arrays.asList(rejected),2);
        check(Boolean.FALSE.equals(rejection.states.get(0).get(1))&&Boolean.FALSE.equals(rejection.states.get(0).get(2))
                &&Boolean.TRUE.equals(rejection.states.get(0).get(3)),"rejected/stale/no-dispatch facts not promoted");
        check(rejection.arguments.isEmpty(),"historical node ID is not supplied as current authority");
        check(rejects(new Runnable(){public void run(){RecentActionProjection.compactEvents(Arrays.asList(row(2,"open","a","b","b",true,true),row(1,"back","b","b","a",true,true)),0);}}),"out-of-order trace rejected");
        final List<Map<String,Object>> excessive=new ArrayList<Map<String,Object>>(nav);excessive.add(row(21,"wait","a","a","a",false,false));
        check(rejects(new Runnable(){public void run(){RecentActionProjection.compactEvents(excessive,0);}}),"over-twenty trace rejects rather than evicts");
        Map<String,Object> invalid=row(1,"wait","a","a","a",false,null);invalid.put("window_changed","false");
        final List<Map<String,Object>> bad=Arrays.asList(invalid);
        check(rejects(new Runnable(){public void run(){RecentActionProjection.compactEvents(bad,0);}}),"string status never coerced to boolean");
        RecentActionProjection.CompactEvents minimalReads=RecentActionProjection.compactEvents(Arrays.asList(query(1,"exact-query",hash)),0);
        check(minimalReads.detailOmittedSteps.equals(Arrays.asList(Integer.valueOf(1)))&&!minimalReads.arguments.get(0).containsKey("query"),"query detail omission explicit");
        check(minimalReads.arguments.get(0).get("returned").equals(Integer.valueOf(1))&&minimalReads.rows.size()==1,"read-only call and actual result count retained");

        SameStateNoEffectGuard guard=new SameStateNoEffectGuard();
        ObservationState state=new ObservationState("fixture-state",ImeVisibility.HIDDEN);
        Set<String> allIds=new HashSet<String>();Map<String,String> labels=new HashMap<String,String>();
        for(int i=1;i<=20;i++){
            String id="n"+i;allIds.add(id);labels.put(id,"fixture");
            guard.observed(click(id),"com.example.screen",state,"com.example.screen",state,true,true,false);
        }
        SameStateNoEffectGuard.Snapshot snap=guard.snapshot("com.example.screen",state);
        SameStateNoEffectGuard.CompactProjection full=snap.compactProject(Collections.<String>emptySet(),labels);
        check(full.clickIds.size()==20&&full.observed==20&&full.omitted==0,"twenty compact targets preserve complete membership");
        Map<String,String> subset=new HashMap<String,String>();subset.put("n1","fixture");subset.put("n2","fixture");
        SameStateNoEffectGuard.CompactProjection partial=snap.compactProject(Collections.<String>emptySet(),subset);
        check(partial.clickIds.equals(Arrays.asList("n1","n2"))&&partial.omitted==18,"compact projection has no dangling node and exact omissions");
        check(snap.allowedClicks(allIds).isEmpty()&&allIds.size()==20,"compact display does not change real subtraction or caller domain");
        check(guard.rejects(click("n20"),"com.example.screen",state),"omitted display still rejected by complete executor-side guard");
        boolean immutable=false;try{full.clickIds.add("n21");}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"compact block snapshot immutable");
        System.out.println("CompactEvidenceHostTest passed "+count+" contracts");
    }
}
