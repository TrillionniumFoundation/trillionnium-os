import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.trillionnium.hepta.local.CompactTaskHistory;

public final class CompactTaskHistoryHostTest {
    private static int checks;
    private static void check(boolean condition,String message){checks++;if(!condition)throw new AssertionError(message);}
    private static Map<String,Object> row(Object... pairs){Map<String,Object> r=new LinkedHashMap<String,Object>();for(int i=0;i<pairs.length;i+=2)r.put((String)pairs[i],pairs[i+1]);return r;}
    private static void rejects(Runnable action){boolean rejected=false;try{action.run();}catch(IllegalArgumentException expected){rejected=true;}check(rejected,"malformed table rejected");}
    public static void main(String[] ignored){
        List<Map<String,Object>> history=new ArrayList<Map<String,Object>>();
        history.add(row("step",1,"action","find_app","query","","offset",0,"read_only",true,"dispatched",false,"window_changed",null));
        history.add(row("step",2,"action","type","node_label","","type_text","","dispatched",true,"window_changed",false));
        history.add(row("step",3,"action_rejected","freshness changed","dispatched",false));
        List<Map<String,Object>> restored=CompactTaskHistory.decode(CompactTaskHistory.encode(history));
        check(history.equals(restored),"all fields including absence/null/false/empty/zero preserved");
        check(restored.get(0).containsKey("window_changed")&&restored.get(0).get("window_changed")==null,"unknown differs from absent");
        check(!restored.get(2).containsKey("window_changed"),"rejected row acquires no after evidence");
        check("".equals(restored.get(1).get("type_text")),"empty replacement is not dropped");
        history.clear();String label="Repeated visible field with arbitrary letters";
        for(int i=1;i<=20;i++)history.add(row("step",i,"action",i%2==0?"click":"wait","node_label",label,"dispatched",true,"detail","Observed action response, without a success inference"));
        Map<String,Object> table=CompactTaskHistory.encode(history);restored=CompactTaskHistory.decode(table);
        check(history.equals(restored)&&restored.size()==20,"all ordered repeated operations retained");
        check(((List<?>)table.get("refs")).contains(label),"repeated text encoded once");
        history.get(0).put("node_label","changed after encoding");
        check(label.equals(CompactTaskHistory.decode(table).get(0).get("node_label")),"encoded snapshot immutable from source map changes");
        final List<Map<String,Object>> bad=Arrays.asList(row("nested",Arrays.asList("invented")));
        rejects(new Runnable(){public void run(){CompactTaskHistory.encode(bad);}});
        final Map<String,Object> invalid=new LinkedHashMap<String,Object>(table);invalid.put("rows",Arrays.asList(Arrays.asList(Arrays.asList(-1))));
        rejects(new Runnable(){public void run(){CompactTaskHistory.decode(invalid);}});
        System.out.println("CompactTaskHistoryHostTest: "+checks+" checks passed");
    }
}
