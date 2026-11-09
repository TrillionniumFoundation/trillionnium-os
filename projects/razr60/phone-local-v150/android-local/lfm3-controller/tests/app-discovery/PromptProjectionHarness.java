import org.trillionnium.hepta.local.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Executes the exact production prompt methods at a host observation/JSON boundary.
 * It does not simulate a model, Android observation capture or action dispatch.
 * JSON objects below only provide the methods those production projections use.
 */
public final class PromptProjectionHarness {
    /*__SYSTEM__*/
    /*__HISTORY_LIMIT__*/
    /*__PROMPT_FRAME__*/
    /*__PROMPT__*/
    /*__HISTORY_FIELDS__*/
    /*__NODE_SCORE__*/
    /*__SEARCH_METADATA__*/

    static final class HeptaAccessibilityService {
        /*__LIMITED__*/
    }
    static final class Bounds {
        final int left,top,right,bottom;
        Bounds(int[] v){left=v[0];top=v[1];right=v[2];bottom=v[3];}
    }
    static final class PhoneObservation {
        final String id,packageName;
        final int width,height;
        final boolean nodesTruncated=false;
        final ObservationState state;
        final List<Node> nodes;
        final JSONObject window;
        PhoneObservation(String id,String pkg,int width,int height,ImeVisibility ime,JSONObject window,List<Node> nodes){
            this.id=id;this.packageName=pkg;this.width=width;this.height=height;this.window=window;this.nodes=nodes;
            this.state=new ObservationState("frozen-host-observation",ime);
        }
        JSONObject windowPromptJson(){return window;}
        static final class Node {
            final String id,packageName,text,description,viewId,label;
            final Bounds bounds;
            final boolean clickable,editable,scrollable,enabled=true,password=false,focused;
            final ObservedScrollActions scrollActions;
            Node(String id,String pkg,String label,String text,String description,String viewId,int[] bounds,String actions,ObservedScrollActions scroll){
                this.id=id;packageName=pkg;this.label=label;this.text=text;this.description=description;this.viewId=viewId;
                this.bounds=new Bounds(bounds);clickable=actions.contains("c");editable=actions.contains("t");
                scrollable=actions.contains("s");focused=actions.contains("f");scrollActions=scroll;
            }
            String label(){return label;}
        }
    }

    static final class JSONObject {
        static final Object NULL=new Object(){public String toString(){return "null";}};
        final Map<String,Object> values=new LinkedHashMap<String,Object>();
        JSONObject(){}
        JSONObject(Map<?,?> values){for(Map.Entry<?,?> row:values.entrySet())this.values.put((String)row.getKey(),wrap(row.getValue()));}
        JSONObject put(String key,Object value){if(value==null)values.remove(key);else values.put(key,wrap(value));return this;}
        Object get(String key){if(!values.containsKey(key))throw new IllegalArgumentException("missing "+key);return values.get(key);}
        Iterator<String> keys(){return values.keySet().iterator();}
        int length(){return values.size();}
        public String toString(){
            StringBuilder out=new StringBuilder("{");boolean first=true;
            for(Map.Entry<String,Object> row:values.entrySet()){
                if(!first)out.append(',');first=false;out.append(quote(row.getKey())).append(':').append(render(row.getValue()));
            }
            return out.append('}').toString();
        }
    }
    static final class JSONArray {
        final List<Object> values=new ArrayList<Object>();
        JSONArray(){}
        JSONArray(Object sequence){
            if(sequence instanceof Iterable<?>)for(Object v:(Iterable<?>)sequence)values.add(wrap(v));
            else if(sequence.getClass().isArray())for(int i=0;i<java.lang.reflect.Array.getLength(sequence);i++)values.add(wrap(java.lang.reflect.Array.get(sequence,i)));
            else throw new IllegalArgumentException("array required");
        }
        JSONArray put(Object value){values.add(wrap(value));return this;}
        JSONObject getJSONObject(int index){return (JSONObject)values.get(index);}
        int length(){return values.size();}
        public String toString(){StringBuilder out=new StringBuilder("[");for(Object value:values){if(out.length()>1)out.append(',');out.append(render(value));}return out.append(']').toString();}
    }
    static Object wrap(Object value){
        if(value==null)return JSONObject.NULL;
        if(value instanceof Map<?,?>)return new JSONObject((Map<?,?>)value);
        if(value instanceof Iterable<?>||value.getClass().isArray())return new JSONArray(value);
        return value;
    }
    static String render(Object value){return value instanceof String?quote((String)value):value.toString();}
    static String quote(String value){
        StringBuilder out=new StringBuilder("\"");
        for(int i=0;i<value.length();i++){
            char ch=value.charAt(i);
            switch(ch){
                case '"':out.append("\\\"");break;case '\\':out.append("\\\\");break;case '/':out.append("\\/");break;
                case '\b':out.append("\\b");break;case '\f':out.append("\\f");break;
                case '\n':out.append("\\n");break;case '\r':out.append("\\r");break;case '\t':out.append("\\t");break;
                default:if(ch<0x20)out.append(String.format(Locale.ROOT,"\\u%04x",(int)ch));else out.append(ch);
            }
        }
        return out.append('"').toString();
    }
    static void check(boolean yes,String why){if(!yes)throw new AssertionError(why);}
    static String repeated(char value,int count){char[] data=new char[count];Arrays.fill(data,value);return new String(data);}

    /*__FROZEN_INPUT__*/

    public static void main(String[] args)throws Exception{
        String scenario=args[0];
        PhoneObservation observation=frozenObservation();String owner=frozenOwner();
        Map<String,String> installed=new LinkedHashMap<String,String>();
        for(int i=0;i<54;i++)installed.put("com.example.synthetic"+i,"Synthetic "+i);
        installed.put(frozenTargetPackage(),frozenTargetLabel());
        if("truncated-page".equals(scenario)){
            installed.clear();for(int i=0;i<11;i++)installed.put("com.example.notes"+i,"便签 "+i+repeated('字',240));
        }
        AppCatalogueRanker catalogue=new AppCatalogueRanker(installed,owner);
        String term="truncated-page".equals(scenario)?"便签":frozenTargetLabel();
        if("initial".equals(scenario))term="";
        int offset=0,step=1;
        if("many-queries".equals(scenario)){term="synthetic";offset=6;step=19;}
        AppCatalogueRanker.Page page=catalogue.search(term,offset);
        ActionDecision action=ActionDecision.parse("{\"action\":\"find_app\",\"observation_id\":"+quote(observation.id)
                +",\"package\":"+quote(observation.packageName)+",\"query\":"+quote(term)+",\"offset\":"+offset+"}");
        AppSearchProvenance provenance=AppSearchProvenance.completedFindApp(page,action,step,true,false);
        JSONArray history=new JSONArray();
        int count="many-queries".equals(scenario)?19:1;
        for(int i=1;i<=count;i++)history.put(new JSONObject().put("step",i).put("action","find_app")
                .put("detail","查询完成；这是只读工具结果，不是应用已打开")
                .put("before_package",observation.packageName).put("target_package",observation.packageName)
                .put("package_after",observation.packageName).put("dispatched",false)
                .put("window_changed",false).put("ime_visible_before",false).put("ime_visible_after",false)
                .put("query",i==count?term:"earlier query "+i).put("offset",i==count?offset:0).put("read_only",true));
        if(Arrays.asList("frozen","owner-bound","over-budget","binding-mismatch").contains(scenario))history=new JSONArray().put(frozenHistory());
        if("initial".equals(scenario)){provenance=AppSearchProvenance.initialRanking(page);history=new JSONArray();}
        if("binding-mismatch".equals(scenario))page=catalogue.search(term,offset);
        if("owner-bound".equals(scenario))owner=owner+repeated('a',1600-owner.getBytes(StandardCharsets.UTF_8).length);
        if("truncated-page".equals(scenario))owner=owner+repeated('界',100);
        LocalRuntimeConfig config=new LocalRuntimeConfig("over-budget".equals(scenario)?ModelProfile.LFM3:ModelProfile.GEMMA4_E4B,"npu",4096,4);
        RepeatActionGuard guard=new RepeatActionGuard();
        /*__CALL_PROMPT__*/
        check(frame.text.endsWith("\nOWNER\n"+owner),"complete OWNER bytes unchanged");
        check(frame.budget.admitted,"actual production budget admits only legal prompt");
        check(frame.historyProjectionBytes<=HISTORY_PROJECTION_UTF8_LIMIT,"original history budget unchanged");
        check(frame.grammar.actions.contains("find_app"),"discovery action remains available");
        check(frame.sequenceObserved==0&&frame.sequenceShown==0,"readonly queries never become dispatched effects");
        check(frame.budget.profile==ModelProfile.GEMMA4_E4B,"same model budget profile");
        JSONObject report=new JSONObject().put("scenario",scenario).put("prompt",frame.text)
                .put("budget",frame.budgetJson()).put("grammar",frame.grammar.text)
                .put("system_utf8_bytes",SYSTEM.getBytes(StandardCharsets.UTF_8).length)
                .put("owner_unchanged",true).put("phone_tested",false);
        System.out.println(report.toString());
    }
}
