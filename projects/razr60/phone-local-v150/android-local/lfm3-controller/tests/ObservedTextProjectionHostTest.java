import org.trillionnium.hepta.local.ObservedTextProjection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class ObservedTextProjectionHostTest {
    private static int checks;
    private static void check(boolean value,String message){
        checks++;if(!value)throw new AssertionError(message);
    }
    private static Map<String,Object> field(String id,String text,String description,String view,int[] bounds,boolean focused,boolean enabled){
        return ObservedTextProjection.project(id,text,description,view,bounds,true,true,false,false,focused,enabled);
    }
    public static void main(String[] args){
        int[] originalBounds={10,20,310,120};
        Map<String,Object> empty=field("n8","","Search hint","widget:id/current",originalBounds,false,true);
        check("".equals(empty.get("text")),"empty observed value must be retained");
        check("Search hint".equals(empty.get("description")),"description is separate evidence");
        check("editable_text".equals(empty.get("role")),"role only follows observed editability");
        check("widget:id/current".equals(empty.get("view_id")),"view id is copied without semantic inference");
        check(Boolean.FALSE.equals(empty.get("focused"))&&Boolean.TRUE.equals(empty.get("enabled")),"explicit observed flags retained");
        originalBounds[0]=999;
        check(empty.get("bounds").equals(Arrays.asList(10,20,310,120)),"bounds must not alias caller storage");

        Map<String,Object> current=field("n9","sample value","A different hint","widget:id/arbitrary",new int[]{10,130,310,230},true,false);
        check("sample value".equals(current.get("text")),"current text is never replaced by description");
        check(Boolean.TRUE.equals(current.get("focused"))&&Boolean.FALSE.equals(current.get("enabled")),"disabled/editable does not gain permission");
        Map<String,Object> visible=ObservedTextProjection.project("n10","sample value","","widget:id/record",new int[]{10,0,310,15},false,false,false,false,false,true);
        check("noninteractive_text".equals(visible.get("role")),"same visible value does not imply current input or result");
        check("sample value".equals(visible.get("text")),"visible text is unchanged");
        check("widget:id/record".equals(visible.get("view_id")),"noninteractive identity retained");
        check(!visible.containsKey("result")&&!visible.containsKey("success")&&!visible.containsKey("action"),"projection invents no task semantics");
        check(!current.containsKey("action")&&!current.containsKey("node_label"),"metadata alone grants no executable target pair");

        check(ObservedTextProjection.project("n11","secret","secret hint","widget:id/private",new int[]{0,0,100,100},true,true,false,true,true,true)==null,"password value must not be projected");
        check(ObservedTextProjection.project("n12","Press","","",new int[]{0,0,100,100},true,false,false,false,false,true)==null,"a clickable label is not a current editable value");
        check(ObservedTextProjection.project("n13","List","","",new int[]{0,0,100,100},false,false,true,false,false,true)==null,"scrolling labels stay out of noninteractive text");
        check(ObservedTextProjection.project("n14","","","",new int[]{0,0,100,100},false,false,false,false,false,true)==null,"empty noninteractive node adds no text");
        Map<String,Object> descriptionOnly=ObservedTextProjection.project("n15","","Visible description","",new int[]{0,0,100,100},false,false,false,false,false,true);
        check("".equals(descriptionOnly.get("text"))&&"Visible description".equals(descriptionOnly.get("description")),"description-only static text keeps its origin");

        List<Map<String,Object>> observed=new ArrayList<Map<String,Object>>(Arrays.asList(empty,current,visible,descriptionOnly));
        Set<String> shown=new HashSet<String>(Arrays.asList("n9","n10"));
        List<Map<String,Object>> fields=ObservedTextProjection.select(observed,shown,"editable_text",Integer.MAX_VALUE);
        check(fields.size()==1&&"n9".equals(fields.get(0).get("node_id")),"budget selection excludes omitted editable ids");
        List<Map<String,Object>> staticText=ObservedTextProjection.select(observed,shown,"noninteractive_text",1);
        check(staticText.size()==1&&"n10".equals(staticText.get(0).get("node_id")),"visible metadata is bound to final node set");
        shown.remove("n9");
        check(ObservedTextProjection.select(observed,shown,"editable_text",Integer.MAX_VALUE).isEmpty(),"shrinking nodes leaves no dangling field id");
        check(ObservedTextProjection.select(observed,shown,"noninteractive_text",0).isEmpty(),"optional text limit is respected");
        check(observed.size()==4&&"sample value".equals(current.get("text")),"selection never changes original observations");
        check(fields.size()==1,"returned projection does not alias selection set");
        boolean immutable=false;
        try{current.put("text","changed");}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"observed field projection is immutable");
        boolean invalid=false;
        try{ObservedTextProjection.select(observed,shown,"primary_result",1);}catch(IllegalArgumentException expected){invalid=true;}
        check(invalid,"unobserved semantic role is rejected");
        invalid=false;
        try{field("n16","","","",new int[]{1,2,3},false,true);}catch(IllegalArgumentException expected){invalid=true;}
        check(invalid,"incomplete observed geometry is rejected");
        System.out.println("ObservedTextProjectionHostTest checks="+checks);
    }
}
