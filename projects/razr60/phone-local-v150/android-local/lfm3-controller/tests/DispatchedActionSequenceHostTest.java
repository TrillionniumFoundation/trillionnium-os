import org.trillionnium.hepta.local.RecentActionProjection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class DispatchedActionSequenceHostTest {
    private static int checks;
    private static void check(boolean value,String message){
        checks++;if(!value)throw new AssertionError(message);
    }
    private static Map<String,Object> row(int step,String action,Object dispatched){
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        value.put("step",Integer.valueOf(step));value.put("action",action);
        value.put("target_package","org.example.app");value.put("dispatched",dispatched);
        return value;
    }
    public static void main(String[] args){
        Map<String,Object> launch=row(1,"open",Boolean.TRUE);
        launch.put("exact_package_match",Boolean.TRUE);launch.put("window_changed",Boolean.TRUE);
        Map<String,Object> rejected=row(2,"click",Boolean.FALSE);rejected.put("action_rejected","stale");
        Map<String,Object> first=row(3,"click",Boolean.TRUE);first.put("node_label","Alpha");first.put("node_id","n12");
        Map<String,Object> discovery=row(4,"find_app",Boolean.FALSE);discovery.put("read_only",Boolean.TRUE);
        Map<String,Object> wait=row(5,"wait",Boolean.FALSE);
        Map<String,Object> second=row(6,"click",Boolean.TRUE);second.put("node_label","Beta");
        List<Map<String,Object>> original=Arrays.asList(launch,rejected,first,discovery,wait,second);
        List<Map<String,Object>> sequence=new ArrayList<Map<String,Object>>();
        for(Map<String,Object> entry:original){
            Map<String,Object> projected=RecentActionProjection.dispatched(entry);
            if(projected!=null)sequence.add(projected);
        }
        check(sequence.size()==3,"only actual dispatched rows belong to the sequence");
        check(sequence.get(0).get("step").equals(1)&&sequence.get(1).get("step").equals(3)&&sequence.get(2).get("step").equals(6),"source order and original step numbers retained");
        check("Alpha".equals(sequence.get(1).get("node_label"))&&"Beta".equals(sequence.get(2).get("node_label")),"actual target labels preserved");
        check("org.example.app".equals(sequence.get(0).get("target_package")),"package scope copied without relabeling");
        check(!sequence.get(0).containsKey("exact_package_match")&&!sequence.get(0).containsKey("window_changed"),"compact sequence does not imply progress");
        check(!sequence.get(1).containsKey("node_id")&&!sequence.get(1).containsKey("success"),"old ids grant no current capability and no success is invented");
        check(RecentActionProjection.dispatched(row(7,"click","true"))==null,"string true is not a dispatched receipt");
        check(RecentActionProjection.dispatched(row(7,"click",null))==null,"explicit unknown is not a dispatched receipt");
        Map<String,Object> missing=row(7,"click",Boolean.TRUE);missing.remove("dispatched");
        check(RecentActionProjection.dispatched(missing)==null,"missing dispatch remains unknown");

        Map<String,Object> typed=row(8,"type",Boolean.TRUE);typed.put("node_label","Entry");typed.put("type_text","exact\ntext");
        Map<String,Object> shortText=RecentActionProjection.dispatched(typed);
        check("exact\ntext".equals(shortText.get("type_text"))&&Boolean.FALSE.equals(shortText.get("type_text_truncated")),"exact short text and complete flag preserved");
        StringBuilder longValue=new StringBuilder();for(int i=0;i<79;i++)longValue.append('a');longValue.append("\ud83d\ude42").append("tail");
        typed.put("type_text",longValue.toString());
        Map<String,Object> longText=RecentActionProjection.dispatched(typed);
        check(Boolean.TRUE.equals(longText.get("type_text_truncated")),"truncated sequence value is explicit");
        String compact=(String)longText.get("type_text");
        check(compact.endsWith("\u2026")&&!Character.isHighSurrogate(compact.charAt(compact.length()-2)),"text clipping never splits a surrogate pair");
        check(longValue.toString().equals(typed.get("type_text")),"full original history is retained");
        typed.put("type_text",null);
        Map<String,Object> unknown=RecentActionProjection.dispatched(typed);
        check(unknown.containsKey("type_text")&&unknown.get("type_text")==null&&!unknown.containsKey("type_text_truncated"),"unknown text is not relabeled complete");
        Map<String,Object> scroll=row(9,"scroll",Boolean.TRUE);scroll.put("node_label","Rows");scroll.put("direction","backward");
        check("backward".equals(RecentActionProjection.dispatched(scroll).get("direction")),"observed direction retained without guessing swipe meaning");
        check(launch.size()==6&&first.get("node_id").equals("n12"),"projection does not mutate source history");
        Map<String,Object> back=row(10,"back",Boolean.TRUE);
        back.put("before_package","org.example.search");
        back.put("package_after","org.example.settings");
        Map<String,Object> observedPackages=RecentActionProjection.dispatched(back);
        check("org.example.search".equals(observedPackages.get("before_package")),"before package comes only from the real before-observation field");
        check("org.example.settings".equals(observedPackages.get("after_package")),"after package copies the real after-observation even when it differs from target");
        check(!observedPackages.get("after_package").equals(back.get("target_package")),"target package never substitutes for an observed destination");
        Map<String,Object> detailed=RecentActionProjection.project(back);
        check("org.example.search".equals(detailed.get("before_package"))&&"org.example.settings".equals(detailed.get("package_after")),"recent detail preserves observed before and original after fields");
        Map<String,Object> noPackages=RecentActionProjection.dispatched(row(11,"home",Boolean.TRUE));
        check(!noPackages.containsKey("before_package")&&!noPackages.containsKey("after_package"),"missing observed packages are never inferred from navigation");
        back.put("before_package",null);back.put("package_after",null);
        Map<String,Object> unknownPackages=RecentActionProjection.dispatched(back);
        check(unknownPackages.containsKey("before_package")&&unknownPackages.get("before_package")==null
                &&unknownPackages.containsKey("after_package")&&unknownPackages.get("after_package")==null,"explicit unknown packages remain unknown");
        System.out.println("DispatchedActionSequenceHostTest checks="+checks);
    }
}
