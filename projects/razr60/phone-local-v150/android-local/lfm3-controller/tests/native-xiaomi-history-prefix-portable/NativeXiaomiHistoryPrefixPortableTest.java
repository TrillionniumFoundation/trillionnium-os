package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONArray;
import org.json.JSONObject;

/** Portable synthetic history scenes derived from the existing public empty-input
 * fixture. This is not the later device failure or an Android action replay. */
public final class NativeXiaomiHistoryPrefixPortableTest {
    private static final List<Map<String,Object>> RESULTS=new ArrayList<Map<String,Object>>();
    private static JSONObject fixture,failed,ax;
    private static int assertions;
    interface Test { void run() throws Exception; }
    interface Change { void run(JSONObject a,JSONObject b) throws Exception; }
    private NativeXiaomiHistoryPrefixPortableTest() {}
    static void check(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    static JSONObject copy(JSONObject x){return new JSONObject(x.toString());}
    static void one(String name,Test test){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);row.put("input_kind","synthetic_history_from_existing_public_fixture");
        int begin=assertions;try{test.run();row.put("passed",true);}catch(Throwable e){
            row.put("passed",false);row.put("error",e.toString());java.io.StringWriter t=new java.io.StringWriter();e.printStackTrace(new java.io.PrintWriter(t));row.put("stack",t.toString());}
        row.put("assertions",assertions-begin);RESULTS.add(row);
    }
    static void denied(String message,Test test)throws Exception{
        boolean rejected=false;try{test.run();}catch(IllegalArgumentException|IllegalStateException e){
            rejected=true;check(e.getMessage()!=null&&e.getMessage().contains(message),"specific rejection: "+message+"; actual="+e.getMessage());}
        check(rejected,"counterfactual must be rejected");
    }
    static JSONObject source(String name){return new JSONObject(fixture.getJSONObject("source_files").getJSONObject(name).getString("raw_utf8"));}
    static JSONObject node(JSONObject s,String path){
        JSONArray a=s.getJSONArray("nodes");for(int i=0;i<a.length();i++){JSONObject n=a.getJSONObject(i);if(path.equals(n.getString("path")))return n;}
        throw new AssertionError("fixture node missing "+path);
    }
    static void canonical(Object value,StringBuilder out){
        if(value==null){out.append('n');return;}
        if(value instanceof String){String s=(String)value;out.append('s').append(s.getBytes(StandardCharsets.UTF_8).length).append(':').append(s);return;}
        if(value instanceof Boolean){out.append(Boolean.TRUE.equals(value)?'t':'f');return;}
        if(value instanceof Integer||value instanceof Long){out.append('i').append(value).append(';');return;}
        if(value instanceof List){out.append('[');for(Object x:(List<?>)value)canonical(x,out);out.append(']');return;}
        if(value instanceof Map){Map<String,Object> sorted=new TreeMap<String,Object>();
            for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())sorted.put((String)e.getKey(),e.getValue());
            out.append('{');for(Map.Entry<String,Object> e:sorted.entrySet()){canonical(e.getKey(),out);canonical(e.getValue(),out);}out.append('}');return;}
        throw new AssertionError("unknown fixture scalar");
    }
    static String windowHash(JSONObject x){StringBuilder b=new StringBuilder();canonical(x.toMap(),b);return NativeActionSnapshotCheck.hash(b.toString());}
    /** Same explicit envelope adapter as the established public fixture gate.
     * The subsequent inserted history nodes are synthetic and separately labelled. */
    static JSONObject endpoint(String side){
        JSONObject raw=failed.getJSONObject(side),read=raw.getJSONObject("read"),env=copy(raw.getJSONObject("identity"));
        env.put("installed_set_sha256",fixture.getJSONObject("profile_target_from_original_prompt").getString("apk_set_sha256"))
                .put("origin_observation_id",ax.getJSONObject("binding").getString("observation_id"))
                .put("window_metadata_sha256",raw.getString("window_metadata_sha256"))
                .put("reported_windows_sha256",windowHash(read.getJSONObject("reported_windows")))
                .put("reported_windows_complete",read.getBoolean("reported_windows_complete")).put("ime_visibility",read.getString("ime_visibility"))
                .put("captured_elapsed_ms",read.getLong("read_completed_elapsed_ms")).put("full_native_complete",read.getBoolean("native_observation_complete"))
                .put("visited",read.getInt("visited_nodes")).put("pending",read.getInt("pending_nodes_at_stop"))
                .put("node_omissions",read.getInt("nodes_omitted_by_node_limit")).put("text_omissions",read.getInt("nodes_omitted_by_text_limit"))
                .put("child_omissions",read.getInt("child_slots_omitted_by_traversal_limit"));
        return new JSONObject().put("envelope",env).put("nodes",new JSONArray(raw.getJSONArray("native_nodes").toString()));
    }
    static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject s){
        List<NativeActionSnapshotCheck.Node> nodes=new ArrayList<NativeActionSnapshotCheck.Node>();
        JSONArray raw=s.getJSONArray("nodes");for(int i=0;i<raw.length();i++)nodes.add(new NativeActionSnapshotCheck.Node(raw.getJSONObject(i).toMap()));
        return new NativeActionSnapshotCheck.Snapshot(s.getJSONObject("envelope").toMap(),nodes);
    }
    /** Valid-reference protocol for generated nodes; not an acceptance oracle. */
    static void resign(JSONObject value,String path)throws Exception{
        JSONObject raw=node(value,path);NativeActionSnapshotCheck.Snapshot s=snapshot(value);
        NativeActionSnapshotCheck.Node n=s.node(path);
        java.lang.reflect.Method base=NativeActionSnapshotCheck.class.getDeclaredMethod("searchHintBase",NativeActionSnapshotCheck.Node.class);
        java.lang.reflect.Method children=NativeActionSnapshotCheck.class.getDeclaredMethod("searchHintChildren",Map.class,NativeActionSnapshotCheck.Node.class);
        base.setAccessible(true);children.setAccessible(true);
        ObservedChildText.Result child=(ObservedChildText.Result)children.invoke(null,s.nodes,n);
        String full=child.bind((String)base.invoke(null,n))+"\nscroll_actions="+raw.getString("scroll_actions")
                +"\nime_enter="+raw.getString("ime_enter")+"|focused="+raw.getBoolean("focused")
                +"|full_input="+(raw.isNull("input_sha256")?"null":raw.getString("input_sha256"));
        raw.put("ref_signature_sha256",NativeActionSnapshotCheck.hash(full));
    }
    static JSONObject history(String side,int count)throws Exception{
        JSONObject s=endpoint(side),heading=copy(node(s,"0/6/0")),chip=copy(node(s,"0/6/2")),term=copy(node(s,"0/6/2/0"));
        JSONArray enclosure=node(s,"0/6").getJSONArray("bounds");
        int top=enclosure.getInt(1)+2,bottom=heading.getJSONArray("bounds").getInt(1)-2,mid=(top+bottom)/2;
        check(bottom-top>=16,"bounded synthetic space before old recommendation heading");
        JSONArray out=new JSONArray(),old=s.getJSONArray("nodes");int prefix=count+1;
        for(int i=0;i<old.length();i++){
            JSONObject n=copy(old.getJSONObject(i));String path=n.getString("path");
            if(path.startsWith("0/6/")){String[] segments=path.split("/");segments[2]=String.valueOf(Integer.parseInt(segments[2])+prefix);n.put("path",String.join("/",segments));}
            out.put(n);
        }
        s.put("nodes",out);node(s,"0/6").put("children",node(s,"0/6").getInt("children")+prefix);
        heading.put("path","0/6/0").put("text","搜索历史").put("label","搜索历史")
                .put("bounds",new JSONArray(Arrays.asList(54,top,234,mid-2)));out.put(heading);
        for(int i=0;i<count;i++){
            String p="0/6/"+(i+1),label=i==0?"电视":"净水器";
            JSONObject c=copy(chip),t=copy(term);
            c.put("path",p).put("label",label).put("bounds",new JSONArray(Arrays.asList(54+300*i,mid+2,320+300*i,bottom)));
            t.put("path",p+"/0").put("text",label).put("label",label)
                    .put("bounds",new JSONArray(Arrays.asList(60+300*i,mid+4,300+300*i,bottom-2)));
            out.put(c).put(t);
        }
        s.getJSONObject("envelope").put("visited",out.length());resign(s,"0/6/0");
        for(int i=0;i<count;i++){resign(s,"0/6/"+(i+1)+"/0");resign(s,"0/6/"+(i+1));}
        return s;
    }
    static NativeActionSnapshotCheck.Intent intent(JSONObject a,JSONObject b,String purpose,String path){
        Map<String,Object> env=a.getJSONObject("envelope").toMap(),identity=new TreeMap<String,Object>();
        for(String k:NativeActionSnapshotCheck.PROFILE_AUTHORITY)identity.put(k,env.get(k));
        JSONObject n=node(a,path);long now=b.getJSONObject("envelope").getLong("captured_elapsed_ms");
        return new NativeActionSnapshotCheck.Intent(purpose,"com.xiaomi.shop",path,n.getString("label"),n.getString("ref_signature_sha256"),
                "11111111111111111111111111111111","n1",NativeActionSnapshotCheck.hash("synthetic owner typing action"),null,
                identity,now-1,now+7999);
    }
    static Map<String,Object> compare(JSONObject a,JSONObject b){
        return NativeActionSnapshotCheck.compare(intent(a,b,NativeActionSnapshotCheck.SET_QUERY,"0/1"),snapshot(a),snapshot(b),b.getJSONObject("envelope").getLong("captured_elapsed_ms"));
    }
    static void noAuthority(Map<String,Object> p){
        for(String k:Arrays.asList("grants_action_authority","query_dispatched","business_completion_verified","grants_dispatch","business_verified","history_terms_are_query_or_result_evidence"))
            check(Boolean.FALSE.equals(p.get(k)),"no authority or result: "+k);
        check(Boolean.TRUE.equals(p.get("live_node_chain_window_and_one_effect_recheck_required")),"fresh live recheck remains");
    }
    static void mutate(String name,String reason,Change change){
        one(name,()->{JSONObject a=history("before",1),b=history("after",1);change.run(a,b);denied(reason,()->compare(a,b));});
    }
    static void cases(){
        for(final int count:new int[]{1,3})one("synthetic_fixed_history_prefix_"+count,()->{
            JSONObject a=history("before",count),b=history("after",count);Map<String,Object> p=compare(a,b);noAuthority(p);
            check(Integer.valueOf(count+1).equals(p.get("fixed_history_prefix_children")),"actual located synthetic prefix, not fixed one-term AX3000T");
        });
        mutate("history_changes_with_valid_references","change outside complete recommendation regions",(a,b)->{
            node(b,"0/6/1").put("label","空气净化器");node(b,"0/6/1/0").put("text","空气净化器").put("label","空气净化器");
            resign(b,"0/6/1/0");resign(b,"0/6/1");
        });
        mutate("wrong_recommendation_heading","actual recommendation section heading",(a,b)->node(b,"0/6/2").put("text","推荐"));
        mutate("duplicate_recommendation_heading","unique actual recommendation section heading",(a,b)->node(b,"0/6/0").put("text","猜你想搜"));
        mutate("query_field_changes","original unique exact query field",(a,b)->node(b,"0/1").put("text","changed query"));
        mutate("profile_owner_changes","binding changed",(a,b)->b.getJSONObject("envelope").put("owner_sha256",NativeActionSnapshotCheck.hash("synthetic different owner")));
        one("same_original_eight_second_deadline",()->{
            JSONObject a=history("before",1),b=history("after",1);NativeActionSnapshotCheck.Intent in=intent(a,b,NativeActionSnapshotCheck.SET_QUERY,"0/1");
            denied("original age/deadline/clock",()->NativeActionSnapshotCheck.compare(in,snapshot(a),snapshot(b),in.deadline));
        });
        one("observation_publication_does_not_gain_history_exception",()->{
            JSONObject a=history("before",1),b=history("after",1);
            denied("actual recommendation section heading",()->NativeXiaomiSearchInputObservation.compare(snapshot(a),snapshot(b)));
        });
        one("filled_submit_does_not_gain_history_exception",()->{
            JSONObject a=history("before",1),b=history("after",1);
            denied("original unique exact query field",()->NativeXiaomiSearchInputObservation.compareFilledQuery(snapshot(a),snapshot(b),"AX3000T"));
        });
        one("click_cannot_use_typing_exception",()->{
            JSONObject a=history("before",1),b=history("after",1);
            denied("fresh home only",()->NativeActionSnapshotCheck.compare(intent(a,b,NativeActionSnapshotCheck.SEARCH,"0/4"),snapshot(a),snapshot(b),b.getJSONObject("envelope").getLong("captured_elapsed_ms")));
        });
    }
    public static void main(String[] args)throws Exception{
        fixture=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        ax=source("a57e1dedb06a4e739823379bd472f953-native-ax.json");failed=source("failed-native-census.json");
        cases();boolean pass=true;List<String> names=new ArrayList<String>();for(Map<String,Object> r:RESULTS){pass&=Boolean.TRUE.equals(r.get("passed"));names.add((String)r.get("name"));}
        JSONObject report=new JSONObject().put("schema","hepta.xiaomi-history-prefix-portable.v1").put("all_pass",pass)
                .put("cases",RESULTS.size()).put("assertions",assertions).put("case_names",names).put("results",RESULTS)
                .put("all_history_scenes_synthetic",true).put("new_private_device_census_used",false)
                .put("phone_operations",0).put("android_execution",false).put("business_success_claimed",false);
        Path out=Paths.get(args[1]);Files.write(out,(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("cases="+RESULTS.size()+" assertions="+assertions+" all_pass="+pass);if(!pass)System.exit(1);
    }
}
