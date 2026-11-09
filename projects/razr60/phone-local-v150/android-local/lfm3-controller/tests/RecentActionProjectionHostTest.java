import org.trillionnium.hepta.local.RecentActionProjection;
import java.util.LinkedHashMap;
import java.util.Map;

public final class RecentActionProjectionHostTest {
    private static Map<String,Object> row(Object... items) {
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        for(int i=0;i<items.length;i+=2)value.put((String)items[i],items[i+1]);
        return value;
    }
    private static void require(boolean condition,String reason) {
        if(!condition)throw new AssertionError(reason);
    }
    private static void typeAndEmptyLabel() {
        Map<String,Object> source=row("step",1,"action","type","node_id","n2","node_label","","type_text","","dispatched",true,"window_changed",false,"ime_visible_before",null,"ime_visible_after",false);
        Map<String,Object> projected=RecentActionProjection.project(source);
        require(projected.containsKey("node_label")&&"".equals(projected.get("node_label")),"empty actual target label lost");
        require("".equals(projected.get("type_text"))&&Boolean.FALSE.equals(projected.get("type_text_truncated")),"empty clear input must be complete");
        require(projected.containsKey("ime_visible_before")&&projected.get("ime_visible_before")==null,"explicit unknown lost");
        require(Boolean.FALSE.equals(projected.get("window_changed"))&&Boolean.FALSE.equals(projected.get("ime_visible_after")),"explicit false lost");
        require(!projected.containsKey("node_id")&&!projected.containsKey("exact_package_match"),"unrequested target-id field or irrelevant open field");
        StringBuilder text=new StringBuilder();for(int i=0;i<79;i++)text.append('a');text.append("\ud83d\ude00z");
        source.put("type_text",text.toString());projected=RecentActionProjection.project(source);
        require(Boolean.TRUE.equals(projected.get("type_text_truncated"))&&projected.get("type_text").equals(text.substring(0,79)+"…"),"original surrogate-safe text bound changed");
    }
    private static void discoveryValues() {
        Map<String,Object> source=row("step",2,"action","find_app","query","","offset",0,"read_only",true,"dispatched",false,"window_changed",false,"ime_visible_before",null,"ime_visible_after",null);
        Map<String,Object> projected=RecentActionProjection.project(source);
        require("".equals(projected.get("query"))&&Integer.valueOf(0).equals(projected.get("offset")),"empty discovery/first page dropped");
        require(Boolean.TRUE.equals(projected.get("read_only"))&&Boolean.FALSE.equals(projected.get("dispatched")),"query incorrectly presented as app dispatch");
        require(projected.containsKey("window_changed")&&projected.containsKey("ime_visible_before"),"discovery after-observation lost");
        require(!projected.containsKey("type_text")&&!projected.containsKey("node_label")&&!projected.containsKey("exact_package_match"),"irrelevant placeholders remain");
    }
    private static void rejectsAndOpenMismatch() {
        Map<String,Object> rejected=row("step",3,"action_rejected","stale: observed window changed","dispatched",false);
        require(RecentActionProjection.project(rejected).equals(rejected),"rejected row fabricated after-state evidence");
        Map<String,Object> missing=row("step",4,"action_rejected","observation_id mismatch; nothing dispatched");
        require(!RecentActionProjection.project(missing).containsKey("dispatched"),"missing receipt boolean was coerced");
        Map<String,Object> opened=row("step",5,"action","open","target_package","com.example.one","package_after","com.example.related","exact_package_match",false,"dispatched",true);
        require(RecentActionProjection.project(opened).equals(opened),"false exact package match or real target changed");
    }
    private static void sixRowsStayOrderedAndUnmodified() {
        String[] actions={"open","back","home","wait","click","find_app"};
        for(int i=0;i<actions.length;i++){
            Map<String,Object> source=row("step",i+10,"action",actions[i],"target_package","com.example.observed","dispatched",false,"package_after","com.example.after","window_changed",null,"ime_visible_before",false,"ime_visible_after",true,"detail","observed");
            Map<String,Object> before=new LinkedHashMap<String,Object>(source),p=RecentActionProjection.project(source);
            require(Integer.valueOf(i+10).equals(p.get("step"))&&actions[i].equals(p.get("action")),"row order/identity changed");
            require("com.example.observed".equals(p.get("target_package")),"existing package meaning changed");
            require(p.containsKey("window_changed")&&p.get("window_changed")==null,"unknown progress lost");
            require(source.equals(before),"private history mutated");
        }
    }
    public static void main(String[] args) {
        typeAndEmptyLabel();discoveryValues();rejectsAndOpenMismatch();sixRowsStayOrderedAndUnmodified();
        System.out.println("4 focused recent-projection contracts passed");
    }
}
