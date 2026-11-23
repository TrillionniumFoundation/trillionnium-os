package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;

/** Complete native comparison rejected its old frame. Not a Permit or a benign-change classification. */
final class WebNativeObservationChanged extends IllegalArgumentException {
    private static final long serialVersionUID=1L;
    final String nativePath,diagnostic;
    WebNativeObservationChanged(String prefix,String path){this(prefix,path,null);}
    WebNativeObservationChanged(String prefix,String path,String diagnostic){
        super(prefix+path);nativePath=path;
        this.diagnostic=diagnostic!=null&&diagnostic.length()<=4096?diagnostic:null;
    }

    private static final int STRUCTURE_MAX_ROWS=1024,STRUCTURE_MAX_DEPTH=16,
            STRUCTURE_MAX_ANCESTORS=24,STRUCTURE_MAX_OVERLAPS=8,STRUCTURE_MAX_BYTES=32768;
    private static final String STRUCTURE_SCHEMA="hepta.native-rejected-row-structure.v1";
    private static final String[] FLAGS={"visible","enabled","clickable","editable","password","scrollable","focused"};
    private static final Set<String> ROW_KEYS=new LinkedHashSet<String>(Arrays.asList(
            "path","parent_class","package","window_id","class","view_id","text","description","bounds",
            "visible","enabled","clickable","editable","password","scrollable","focused","children",
            "scroll_actions","ime_enter","input_sha256"));
    private static final Set<String> STRUCTURAL_KEYS=new LinkedHashSet<String>(Arrays.asList(
            "path","window_id","class","bounds","visible","enabled","clickable","editable","password",
            "scrollable","focused","children"));
    private static final Set<String> CLASSES=new LinkedHashSet<String>(Arrays.asList(
            "android.view.View","android.view.ViewGroup","android.webkit.WebView","android.widget.TextView",
            "android.widget.ImageView","android.widget.Button","android.widget.ImageButton","android.widget.EditText",
            "android.widget.CheckBox","android.widget.RadioButton","android.widget.Switch","android.widget.Spinner",
            "android.widget.ListView","android.widget.GridView","android.widget.ScrollView",
            "android.widget.HorizontalScrollView","android.widget.LinearLayout","android.widget.FrameLayout",
            "android.widget.RelativeLayout"));

    /** Pure, bounded metadata from the exact snapshots whose comparison already failed.
     * It does not read AccessibilityNodeInfo, classify a change as benign, or create authority.
     * All failures return fixed metadata; the caller must rethrow the original exception. */
    static String structureAfterFailure(WebNativeObservationChanged failure,JSONArray before,JSONArray after,String targetPath){
        try{
            if(failure==null||failure.diagnostic==null)return unavailable("original_diagnostic_missing");
            JSONObject original=new JSONObject(failure.diagnostic);
            require("hepta.native-row-change-diagnostic.v1".equals(original.get("schema"))
                    &&Boolean.TRUE.equals(original.get("available"))
                    &&failure.nativePath.equals(original.get("native_path")),"original_diagnostic_binding");
            path(failure.nativePath);path(targetPath);
            Map<String,JSONObject> a=index(before),b=index(after);
            require(a.keySet().equals(b.keySet()),"snapshot_membership");
            JSONObject x=a.get(failure.nativePath),y=b.get(failure.nativePath),ta=a.get(targetPath),tb=b.get(targetPath);
            require(x!=null&&y!=null&&ta!=null&&tb!=null,"selected_rows_missing");
            require(WebDomCanonical.sha256(x).equals(original.get("before_canonical_sha256"))
                    &&WebDomCanonical.sha256(y).equals(original.get("after_canonical_sha256")),"original_row_hash_binding");
            require(!WebDomCanonical.same(x,y),"original_row_unchanged");
            Set<String> ancestors=new LinkedHashSet<String>();
            addAncestors(a,b,failure.nativePath,ancestors);addAncestors(a,b,targetPath,ancestors);
            require(ancestors.size()<=STRUCTURE_MAX_ANCESTORS,"ancestor_limit");
            JSONArray chain=new JSONArray();
            for(String p:ancestors)chain.put(new JSONObject().put("path",p)
                    .put("failure_ancestor",ancestor(p,failure.nativePath)).put("selected_card_ancestor",ancestor(p,targetPath))
                    .put("before",structure(a.get(p))).put("after",structure(b.get(p))));
            JSONObject relation=new JSONObject().put("failure_is_selected_card",failure.nativePath.equals(targetPath))
                    .put("failure_is_selected_card_ancestor",ancestor(failure.nativePath,targetPath))
                    .put("failure_is_selected_card_descendant",ancestor(targetPath,failure.nativePath))
                    .put("common_ancestor_path",common(failure.nativePath,targetPath))
                    .put("before_positive_area_intersection",overlap(rect(x),rect(ta)))
                    .put("after_positive_area_intersection",overlap(rect(y),rect(tb)));
            JSONObject out=new JSONObject().put("schema",STRUCTURE_SCHEMA).put("available",true)
                    .put("source","private_snapshot_pair_after_original_comparison_rejection")
                    .put("native_path",failure.nativePath).put("selected_card_native_path",targetPath)
                    .put("selected_card_target_source","retained_unique_search_card_candidate")
                    .put("target_dom_native_bridge_verified",false)
                    .put("original_diagnostic_sha256",WebDomCanonical.sha256(original))
                    .put("before_canonical_sha256",original.get("before_canonical_sha256"))
                    .put("after_canonical_sha256",original.get("after_canonical_sha256"))
                    .put("failed_row_before",structure(x)).put("failed_row_after",structure(y))
                    .put("selected_card_before",structure(ta)).put("selected_card_after",structure(tb))
                    .put("path_and_rectangle_relationship",relation).put("ancestors",chain)
                    .put("ancestor_chains_complete",true)
                    .put("before_overlapping_observed_controls",controls(a,failure.nativePath,rect(x)))
                    .put("after_overlapping_observed_controls",controls(b,failure.nativePath,rect(y)))
                    .put("maximum_snapshot_rows",STRUCTURE_MAX_ROWS).put("maximum_path_depth",STRUCTURE_MAX_DEPTH)
                    .put("maximum_ancestor_rows",STRUCTURE_MAX_ANCESTORS).put("maximum_control_samples",STRUCTURE_MAX_OVERLAPS)
                    .put("maximum_output_bytes",STRUCTURE_MAX_BYTES)
                    .put("bounds_coordinate_space","original_native_getBoundsInScreen_pixels")
                    .put("intersections_prove_occlusion",false).put("dom_native_correspondence_verified",false)
                    .put("unobserved_actions_or_visual_overlays_verified",false).put("benign_change_verified",false)
                    .put("original_observation_rejected",true).put("contains_page_text",false)
                    .put("grants_action_capability",false);
            String raw=WebDomCanonical.canonical(out);
            return raw.getBytes(StandardCharsets.UTF_8).length<=STRUCTURE_MAX_BYTES?raw:unavailable("output_limit");
        }catch(Throwable diagnosticFailure){return unavailable("invalid_or_over_limit_metadata");}
    }
    private static Map<String,JSONObject> index(JSONArray rows)throws Exception{
        require(rows!=null&&rows.length()>0&&rows.length()<=STRUCTURE_MAX_ROWS,"snapshot_rows");
        Map<String,JSONObject> out=new LinkedHashMap<String,JSONObject>();
        Integer window=null;
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);Set<String> keys=new LinkedHashSet<String>();
            for(java.util.Iterator<String> it=row.keys();it.hasNext();)keys.add(it.next());
            require(keys.equals(ROW_KEYS),"row_field_namespace");
            String p=row.getString("path");require(p.matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,127}"),"snapshot_path");rect(row);
            int w=integer(row,"window_id");require(w>=0&&(window==null||window.intValue()==w),"window_binding");window=w;
            require(integer(row,"children")>=0&&integer(row,"children")<=STRUCTURE_MAX_ROWS,"child_count");
            for(String flag:FLAGS)require(row.get(flag) instanceof Boolean,"typed_flag");
            for(String key:new String[]{"parent_class","package","class","view_id","text","description","scroll_actions","ime_enter"}){
                Object v=row.get(key);require(v instanceof String&&((String)v).length()<=16384,"bounded_opaque_field");
            }
            Object input=row.get("input_sha256");
            require(input==JSONObject.NULL||input instanceof String&&((String)input).matches("[0-9a-f]{64}"),"input_digest");
            require(out.put(p,row)==null,"unique_native_path");
        }
        require(out.containsKey("0"),"native_root");
        return out;
    }
    private static JSONObject structure(JSONObject row)throws Exception{
        require(row!=null,"structure_row");
        String clazz=row.getString("class");JSONObject opaque=new JSONObject(),out=new JSONObject();
        for(String key:ROW_KEYS)if(!STRUCTURAL_KEYS.contains(key))opaque.put(key,row.get(key));
        out.put("row_canonical_sha256",WebDomCanonical.sha256(row))
                .put("non_structural_fields_sha256",WebDomCanonical.sha256(opaque))
                .put("class",CLASSES.contains(clazz)?clazz:"other")
                .put("class_sha256",WebDomCanonical.sha256Utf8(clazz))
                .put("window_id",integer(row,"window_id")).put("children",integer(row,"children"))
                .put("bounds",new JSONArray(rect(row)));
        for(String flag:FLAGS)out.put(flag,row.get(flag));
        return out;
    }
    private static JSONObject controls(Map<String,JSONObject> nodes,String failed,int[] box)throws Exception{
        JSONArray sample=new JSONArray();int count=0;
        for(Map.Entry<String,JSONObject> entry:nodes.entrySet()){
            if(entry.getKey().equals(failed))continue;
            JSONObject row=entry.getValue();
            if(!(row.getBoolean("clickable")||row.getBoolean("editable")||row.getBoolean("scrollable"))
                    ||!overlap(box,rect(row)))continue;
            count++;if(entry.getKey().matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,16}")&&sample.length()<STRUCTURE_MAX_OVERLAPS)
                sample.put(new JSONObject().put("path",entry.getKey()).put("structure",structure(row)));
        }
        return new JSONObject().put("definition","positive_area_intersection_with_clickable_editable_or_scrollable_rows")
                .put("visibility_or_enabled_filter_applied",false).put("failed_row_excluded",true)
                .put("count",count).put("samples",sample).put("omitted_count",count-sample.length())
                .put("samples_complete",count==sample.length());
    }
    private static void addAncestors(Map<String,JSONObject> a,Map<String,JSONObject> b,String child,Set<String> out)throws Exception{
        for(String p=parent(child);!p.isEmpty();p=parent(p)){
            require(a.containsKey(p)&&b.containsKey(p),"ancestor_missing");
            out.add(p);require(out.size()<=STRUCTURE_MAX_ANCESTORS,"ancestor_limit");
        }
    }
    private static int[] rect(JSONObject row)throws Exception{
        JSONArray a=row.getJSONArray("bounds");require(a.length()==4,"rect_shape");int[] r=new int[4];
        for(int i=0;i<4;i++){Object v=a.get(i);require(v instanceof Integer||v instanceof Long,"integer_rect");
            long n=((Number)v).longValue();require(n>=-32768&&n<=32768,"rect_range");r[i]=(int)n;}
        return r;
    }
    private static int integer(JSONObject row,String key)throws Exception{
        Object v=row.get(key);require(v instanceof Integer||v instanceof Long,"integer_field");
        long n=((Number)v).longValue();require(n>=Integer.MIN_VALUE&&n<=Integer.MAX_VALUE,"integer_range");return (int)n;
    }
    private static void path(String value){
        require(value!=null&&value.matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,16}"),"bounded_structural_path");
    }
    private static String parent(String path){int i=path.lastIndexOf('/');return i<0?"":path.substring(0,i);}
    private static boolean ancestor(String p,String q){return q.startsWith(p+"/");}
    private static String common(String a,String b){
        for(String p=a;!p.isEmpty();p=parent(p))if(p.equals(b)||ancestor(p,b))return p;return "";
    }
    private static boolean overlap(int[] a,int[] b){
        return a[0]<a[2]&&a[1]<a[3]&&b[0]<b[2]&&b[1]<b[3]
                &&Math.max(a[0],b[0])<Math.min(a[2],b[2])&&Math.max(a[1],b[1])<Math.min(a[3],b[3]);
    }
    private static String unavailable(String reason){
        return "{\"schema\":\""+STRUCTURE_SCHEMA+"\",\"available\":false,\"reason\":\""+reason
                +"\",\"original_observation_rejected\":true,\"contains_page_text\":false,\"grants_action_capability\":false}";
    }
    private static void require(boolean ok,String reason){if(!ok)throw new IllegalArgumentException(reason);}
}
