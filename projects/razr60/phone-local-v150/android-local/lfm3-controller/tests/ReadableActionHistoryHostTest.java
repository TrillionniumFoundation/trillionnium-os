import org.trillionnium.hepta.local.RecentActionProjection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Regression: a calculator/cross-app trace stays understandable without losing action facts. */
public final class ReadableActionHistoryHostTest {
    private static int checks;
    private static void require(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Map<String,Object> row(Object... values){
        Map<String,Object> result=new LinkedHashMap<String,Object>();
        for(int i=0;i<values.length;i+=2)result.put((String)values[i],values[i+1]);
        return result;
    }
    private static void rejects(Runnable action,String reason){
        boolean rejected=false;try{action.run();}catch(IllegalArgumentException expected){rejected=true;}
        require(rejected,reason);
    }
    private static void fullTwentyStepTrace(){
        StringBuilder longText=new StringBuilder();for(int i=0;i<150;i++)longText.append("蓝牙");
        longText.append("\ud83d\ude00完整末尾");
        List<Map<String,Object>> history=new ArrayList<Map<String,Object>>();
        for(int step=1;step<=20;step++)history.add(row("step",step,"action",step==8?"type":"click",
                "node_label",step==8?"":String.valueOf(step%10),"node_id","n"+step,
                "before_package","com.example.calculator","target_package","com.example.calculator",
                "package_after","com.example.calculator","model_issued",true,"accepted",true,
                "dispatched",true,"stale",false,"window_changed",step%2==0,
                "ime_visible_before",null,"ime_visible_after",false,"observation_after","observed-"+step));
        history.get(7).put("type_text",longText.toString());
        RecentActionProjection.ReadableEvents result=RecentActionProjection.readableEvents(history);
        require(result.observed==20&&result.rows.size()==20,"all twenty original steps retained");
        for(int i=0;i<20;i++)require(result.rows.get(i).equals(history.get(i)),"facts changed at step "+(i+1));
        require(result.rows.get(7).get("type_text").equals(longText.toString()),"typed value must not shrink to eighty characters");
        require("".equals(result.rows.get(7).get("node_label")),"empty real label is not an absent label");
        require(result.rows.get(0).get("action") instanceof String,"actions remain names, not dictionary indexes");
        require(!result.rows.get(0).containsKey("goal_independently_verified"),"projection does not invent task success");
        history.get(0).put("node_label","later mutation");history.clear();
        require("1".equals(result.rows.get(0).get("node_label"))&&result.rows.size()==20,"snapshot cannot change with source history");
        boolean immutable=false;try{result.rows.get(0).put("dispatched",false);}catch(UnsupportedOperationException expected){immutable=true;}
        require(immutable,"published event maps are immutable");
        immutable=false;try{result.rows.clear();}catch(UnsupportedOperationException expected){immutable=true;}
        require(immutable,"published sequence is immutable");
    }
    private static void refusalsAndDiscoveryRemainFacts(){
        Map<String,Object> rejected=row("step",1,"action","click","node_label","旧目标","accepted",false,
                "dispatched",false,"stale",true,"action_rejected","observation_id mismatch; nothing dispatched");
        Map<String,Object> query=row("step",2,"action","find_app","query","计算器","offset",0,
                "read_only",true,"model_issued",true,"accepted",true,"dispatched",false,
                "find_returned",2,"find_matches",2,"find_catalogue_sha256","fixed-catalogue");
        Map<String,Object> unknown=row("step",4,"action","home","accepted",null,"window_changed",null,
                "before_package","com.example.app","package_after","com.example.launcher");
        List<Map<String,Object>> history=Arrays.asList(rejected,query,unknown);
        RecentActionProjection.ReadableEvents result=RecentActionProjection.readableEvents(history);
        for(int i=0;i<history.size();i++)require(result.rows.get(i).equals(history.get(i)),"refusal/discovery/unknown changed");
        require(!result.rows.get(2).containsKey("dispatched"),"missing dispatch is not converted to false");
        require(result.rows.get(2).containsKey("accepted")&&result.rows.get(2).get("accepted")==null,"explicit unknown retained");
        require(Integer.valueOf(4).equals(result.rows.get(2).get("step")),"a missing step is not fabricated or renumbered");
    }
    private static void malformedTraceFailsClosed(){
        rejects(new Runnable(){public void run(){RecentActionProjection.readableEvents(null);}},"null trace rejected");
        rejects(new Runnable(){public void run(){RecentActionProjection.readableEvents(Arrays.asList(row("step",2),row("step",1)));}},"reordering rejected");
        rejects(new Runnable(){public void run(){RecentActionProjection.readableEvents(Arrays.asList(row("step",1),row("step",1)));}},"duplicate step rejected");
        rejects(new Runnable(){public void run(){RecentActionProjection.readableEvents(Arrays.asList(row("step",1,"dispatched","true")));}},"string is not a boolean receipt");
        rejects(new Runnable(){public void run(){RecentActionProjection.readableEvents(Arrays.asList(row("step",1,"nested",Collections.singletonMap("action","open"))));}},"new nested fact is not silently summarized");
        final List<Map<String,Object>> tooMany=new ArrayList<Map<String,Object>>();
        for(int i=1;i<=21;i++)tooMany.add(row("step",i));
        rejects(new Runnable(){public void run(){RecentActionProjection.readableEvents(tooMany);}},"over-budget trace is not silently evicted");
    }
    public static void main(String[] args){
        fullTwentyStepTrace();refusalsAndDiscoveryRemainFacts();malformedTraceFailsClosed();
        System.out.println("PASS "+checks+" readable-history checks; phone_tested=false");
    }
}
