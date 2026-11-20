import org.trillionnium.hepta.local.ObservedTransitionProjection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Factual snapshot boundaries: stale identity, empty text, privacy, ambiguity and immutability. */
public final class ObservedTransitionProjectionHostTest {
    private static final String A="11111111111111111111111111111111",B="22222222222222222222222222222222";
    private static final String APP="com.example.editor";
    private static int checks;
    private static void require(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void rejects(Runnable call,String message){
        boolean rejected=false;try{call.run();}catch(IllegalArgumentException expected){rejected=true;}
        require(rejected,message);
    }
    private static ObservedTransitionProjection.Field field(String id,String view,String text){
        return ObservedTransitionProjection.field(APP,APP,id,view,text,true,false);
    }
    private static ObservedTransitionProjection.Snapshot snapshot(String id,boolean truncated,ObservedTransitionProjection.Field... fields){
        return ObservedTransitionProjection.snapshot(id,APP,truncated,null,false,null,Arrays.asList(fields));
    }
    private static Map<?,?> map(Object value){return (Map<?,?>)value;}
    private static List<?> list(Object value){return (List<?>)value;}
    public static void main(String[] args){
        ObservedTransitionProjection.Field empty=field("n1","widget:id/unclassified","");
        ObservedTransitionProjection.Field filled=field("n1","widget:id/unclassified","draft\n中🙂");
        ObservedTransitionProjection.Transition transition=ObservedTransitionProjection.between(4,snapshot(A,false,empty),snapshot(B,false,filled));
        Map<String,Object> projected=transition.forCurrent(B,APP);
        Map<?,?> before=map(projected.get("before")),after=map(projected.get("after"));
        require("".equals(map(list(before.get("editable_fields")).get(0)).get("text")),"empty before text is retained, not replaced with a label or hint");
        require("draft\n中🙂".equals(map(list(after.get("editable_fields")).get(0)).get("text")),"after text is copied without rewriting or truncation");
        require(A.equals(before.get("observation_id"))&&B.equals(after.get("observation_id")),"each value keeps its actual observation source");
        require(Integer.valueOf(4).equals(projected.get("step")),"transition links to the existing history step");
        require(!projected.containsKey("accepted")&&!projected.containsKey("dispatched")&&!projected.containsKey("stale"),"missing execution facts are not manufactured; original history remains authoritative");
        require(!projected.containsKey("progress")&&!projected.containsKey("success")&&!projected.containsKey("changed"),"two snapshots make no causal or task-completion claim");
        Map<?,?> afterField=map(list(after.get("editable_fields")).get(0));
        require(afterField.size()==3&&!afterField.containsKey("node_label")&&!afterField.containsKey("action"),"historical field metadata grants no executable target pair");
        rejects(new Runnable(){public void run(){transition.forCurrent(A,APP);}},"old snapshot cannot masquerade as current after a refresh");
        rejects(new Runnable(){public void run(){transition.forCurrent(B,"com.example.other");}},"current observation also binds its app package");

        require(ObservedTransitionProjection.field(APP,APP,"n2","id","hidden",true,true)==null,"password text is excluded");
        require(ObservedTransitionProjection.field(APP,"com.example.other","n2","id","foreign",true,false)==null,"foreign-app editable text is excluded");
        require(ObservedTransitionProjection.field(APP,APP,"n2","id","old visible record",false,false)==null,"noneditable visible text is not promoted into editable state");
        require(ObservedTransitionProjection.field(APP,APP,null,null,null,true,true)==null,"excluded password text needs no value inspection");

        List<ObservedTransitionProjection.Field> ambiguous=new ArrayList<ObservedTransitionProjection.Field>();
        ambiguous.add(field("n3","same_view_id","one"));ambiguous.add(field("n4","same_view_id","two"));
        ObservedTransitionProjection.Snapshot ambiguousSnapshot=ObservedTransitionProjection.snapshot(B,APP,true,null,false,null,ambiguous);
        ambiguous.clear();
        Map<?,?> ambiguousAfter=map(ObservedTransitionProjection.between(5,snapshot(A,false),ambiguousSnapshot).forCurrent(B,APP).get("after"));
        require(list(ambiguousAfter.get("editable_fields")).size()==2,"duplicate view IDs remain separate fields, never guessed correspondence");
        require(Boolean.TRUE.equals(ambiguousAfter.get("nodes_truncated")),"partial observation is not presented as a complete screen");
        require(list(map(ObservedTransitionProjection.between(6,snapshot(A,false),snapshot(B,true)).forCurrent(B,APP).get("after")).get("editable_fields")).isEmpty(),"no observed fields stays an empty list without invented text");
        boolean immutable=false;try{projected.put("step",99);}catch(UnsupportedOperationException expected){immutable=true;}
        require(immutable,"published transition is immutable");
        immutable=false;try{list(ambiguousAfter.get("editable_fields")).clear();}catch(UnsupportedOperationException expected){immutable=true;}
        require(immutable,"field snapshots do not alias caller collections");

        rejects(new Runnable(){public void run(){snapshot(B,false,field("n3","a","one"),field("n3","b","two"));}},"duplicate node IDs cannot ambiguously identify a field in one observation");
        rejects(new Runnable(){public void run(){ObservedTransitionProjection.field(APP,APP,"n3","id",null,true,false);}},"unknown text is not silently converted to empty");
        rejects(new Runnable(){public void run(){ObservedTransitionProjection.snapshot("old",APP,false,null,false,null,Collections.<ObservedTransitionProjection.Field>emptyList());}},"invalid observation identity is rejected");
        rejects(new Runnable(){public void run(){ObservedTransitionProjection.between(0,snapshot(A,false),snapshot(B,false));}},"a nonexistent step is not inferred");
        final ObservedTransitionProjection.Field other=ObservedTransitionProjection.field("com.example.other","com.example.other","n3","id","other",true,false);
        rejects(new Runnable(){public void run(){snapshot(B,false,other);}},"field from another snapshot package cannot be spliced into current state");
        ObservedTransitionProjection.Snapshot titled=ObservedTransitionProjection.snapshot(B,APP,false,"Observed child page",true,Boolean.FALSE,Collections.<ObservedTransitionProjection.Field>emptyList());
        Map<?,?> navigation=map(ObservedTransitionProjection.between(7,snapshot(A,false),titled).forCurrent(B,APP).get("after"));
        require("Observed child page".equals(map(navigation.get("window")).get("title")),"title is copied without assigning a page role");
        require(Boolean.TRUE.equals(map(navigation.get("window")).get("title_truncated")),"observed title truncation is retained");
        require(Boolean.FALSE.equals(navigation.get("ime_visible")),"observed hidden IME remains false");
        require(before.containsKey("ime_visible")&&before.get("ime_visible")==null,"unknown IME remains explicit null, not false");
        require(map(before.get("window")).containsKey("title")&&map(before.get("window")).get("title")==null,"unknown window title remains explicit null");
        require(!navigation.containsKey("page_role")&&!navigation.containsKey("goal_success"),"window title is not promoted to navigation success");
        System.out.println("ObservedTransitionProjectionHostTest checks="+checks+"; phone_tested=false");
    }
}
