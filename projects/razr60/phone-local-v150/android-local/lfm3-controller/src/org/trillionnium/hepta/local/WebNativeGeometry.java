package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * Replays the owned WebView's four real native samples. This establishes a
 * stable native rectangle only; it never converts CSS geometry into a click.
 */
final class WebNativeGeometry {
    static final String SCHEMA="hepta.webview-geometry-bracket.v1";
    private static final String[] PHASES={"before_js1","after_js1","before_js2","after_js2"};
    final int displayId,windowId;
    final int[] bounds;
    final long firstSample,lastSample;
    final String fingerprint;
    private final String actualRaw;

    private WebNativeGeometry(JSONObject original,int display,int window,int[] bounds,
                              long first,long last,String stable)throws Exception{
        displayId=display;windowId=window;this.bounds=bounds.clone();
        firstSample=first;lastSample=last;fingerprint=sha(stable);actualRaw=original.toString();
    }

    /** Missing legacy geometry is not an action capability. Malformed new evidence is rejected. */
    static WebNativeGeometry read(JSONObject capture,JSONObject dom,int display,int window)throws Exception{
        if(!capture.has("capture_geometry"))return null;
        JSONObject geometry=capture.getJSONObject("capture_geometry");
        keys(geometry,"schema","samples","native_samples_equal","dom_equal_across_visual_callback",
                "ui_thread_bracket","get_scale_is_deprecated_racy_observation","css_to_screen_mapping_verified");
        need(SCHEMA.equals(string(geometry,"schema")),"native geometry schema");
        for(String key:new String[]{"native_samples_equal","dom_equal_across_visual_callback","ui_thread_bracket",
                "get_scale_is_deprecated_racy_observation"})need(Boolean.TRUE.equals(geometry.get(key)),"native geometry fact: "+key);
        need(Boolean.FALSE.equals(geometry.get("css_to_screen_mapping_verified")),"CSS mapping is not verified");
        need(display>0&&window>=0&&integer(capture,"display_id")==display
                &&integer(capture,"actual_window_id")==window,"actual geometry display/window");
        long started=integer(capture,"started_elapsed_ms"),ended=integer(capture,"ended_elapsed_ms");
        need(started>=0&&ended>=started&&ended-started<=3000,"bounded actual capture interval");
        int[] expected=rect(capture.getJSONArray("webview_bounds_screen_pixels"),true);
        JSONArray samples=geometry.getJSONArray("samples");need(samples.length()==4,"four ordered native samples");
        String firstStable=null;long first=-1,last=-1;
        for(int i=0;i<4;i++){
            JSONObject sample=samples.getJSONObject(i);keys(sample,"phase","native");
            need(PHASES[i].equals(string(sample,"phase")),"native geometry phase order");
            JSONObject nativeState=sample.getJSONObject("native");
            keys(nativeState,"sampled_elapsed_ms","display_id","actual_window_id","bounds_screen_pixels",
                    "global_visible_rect_pixels","global_visible_rect_source","scroll_pixels","padding_pixels",
                    "view_transform","webview_get_scale","scale_change_sequence","scale_changed_elapsed_ms",
                    "scale_callback_old","scale_callback_new","use_wide_viewport","load_with_overview_mode");
            long now=integer(nativeState,"sampled_elapsed_ms");
            need(now>=started&&now<=ended&&(last<0||now>=last),"native sample outside capture interval");
            if(i==0)first=now;last=now;
            need(integer(nativeState,"display_id")==display&&integer(nativeState,"actual_window_id")==window,
                    "native sample belongs to another window");
            int[] bounds=rect(nativeState.getJSONArray("bounds_screen_pixels"),true);
            need(Arrays.equals(expected,bounds),"native view rectangle changed");
            int[] visible=rect(nativeState.getJSONArray("global_visible_rect_pixels"),false);
            need("View.getGlobalVisibleRect; root-view coordinates".equals(string(nativeState,"global_visible_rect_source")),
                    "global visible rectangle provenance");
            // These coordinates have another origin. Only their dimensions are
            // compared; they are never treated as screen positions.
            need(visible[2]-visible[0]==bounds[2]-bounds[0]&&visible[3]-visible[1]==bounds[3]-bounds[1],
                    "native WebView is partly clipped");
            long[] scroll=integerArray(nativeState.getJSONArray("scroll_pixels"),2);
            long[] padding=integerArray(nativeState.getJSONArray("padding_pixels"),4);
            for(long value:padding)need(value==0,"unreviewed WebView padding");
            double[] transform=numberArray(nativeState.getJSONArray("view_transform"),5);
            need(transform[0]==1.0&&transform[1]==1.0&&transform[2]==0.0&&transform[3]==0.0&&transform[4]==0.0,
                    "unreviewed native transform");
            double scale=number(nativeState.get("webview_get_scale"));
            need(scale>0&&scale<=64,"actual native scale range");
            long sequence=integer(nativeState,"scale_change_sequence"),changed=integer(nativeState,"scale_changed_elapsed_ms");
            need(sequence>=0&&changed>=0&&changed<=now,"actual scale callback history");
            Object oldScale=nativeState.get("scale_callback_old"),newScale=nativeState.get("scale_callback_new");
            need((oldScale==JSONObject.NULL)==(newScale==JSONObject.NULL),"scale callback pair");
            if(oldScale==JSONObject.NULL)need(sequence==0&&changed==0,"missing actual scale callback values");
            else need(sequence>0&&changed>0&&number(oldScale)>0&&number(newScale)>0,"actual scale callback values");
            need(Boolean.TRUE.equals(nativeState.get("use_wide_viewport"))
                    &&Boolean.TRUE.equals(nativeState.get("load_with_overview_mode")),"actual viewport settings");
            JSONObject stable=new JSONObject();
            // A fixed key order and normalized finite numeric values allow an
            // exact cross-capture comparison without using binding's integer-only codec.
            stable.put("display",display).put("window",window).put("bounds",new JSONArray(bounds))
                    .put("visible_dimensions",new JSONArray(new int[]{visible[2]-visible[0],visible[3]-visible[1]}))
                    .put("visible_root_rectangle",new JSONArray(visible)).put("scroll",new JSONArray(scroll))
                    .put("padding",new JSONArray(padding)).put("transform",new JSONArray(transform))
                    .put("scale",scale).put("scale_sequence",sequence).put("scale_changed",changed)
                    .put("scale_old",oldScale==JSONObject.NULL?JSONObject.NULL:number(oldScale))
                    .put("scale_new",newScale==JSONObject.NULL?JSONObject.NULL:number(newScale));
            String current=stable.toString();
            if(firstStable==null)firstStable=current;else need(firstStable.equals(current),"native geometry changed across JS samples");
        }
        need(("hepta.fixed-top-document-dom.v2".equals(string(dom,"schema"))
                ||"hepta.fixed-top-document-dom.v3".equals(string(dom,"schema")))
                &&Boolean.FALSE.equals(dom.get("geometry_semantics_verified")),"actual viewport observer schema");
        JSONObject vv=dom.getJSONObject("visual_viewport");
        keys(vv,"width","height","offset_left","offset_top","page_left","page_top","scale");
        need(number(vv.get("width"))>0&&number(vv.get("height"))>0
                &&number(vv.get("scale"))>0&&number(vv.get("scale"))<=64,"actual visual viewport dimensions");
        for(String key:new String[]{"offset_left","offset_top","page_left","page_top"})number(vv.get(key));
        numberArray(dom.getJSONArray("viewport_css_pixels"),2);
        numberArray(dom.getJSONArray("layout_viewport_css_pixels"),2);
        numberArray(dom.getJSONArray("document_scroll_css_pixels"),2);
        numberArray(dom.getJSONArray("document_extent_css_pixels"),2);
        // DOM geometry is retained as an independent state guard. It is not a
        // formula for translating CSS positions or DPR into Android coordinates.
        JSONObject stable=new JSONObject().put("native",new JSONObject(firstStable))
                .put("visual_viewport",vv).put("viewport",dom.getJSONArray("viewport_css_pixels"))
                .put("layout_viewport",dom.getJSONArray("layout_viewport_css_pixels"))
                .put("document_scroll",dom.getJSONArray("document_scroll_css_pixels"))
                .put("document_extent",dom.getJSONArray("document_extent_css_pixels"));
        return new WebNativeGeometry(geometry,display,window,expected,first,last,stable.toString());
    }
    JSONObject evidence()throws Exception{
        return new JSONObject().put("schema","hepta.native-webview-geometry-replay.v1")
                .put("native_geometry_sha256",fingerprint).put("display_id",displayId).put("window_id",windowId)
                .put("native_bounds_screen_pixels",new JSONArray(bounds)).put("first_sample_elapsed_ms",firstSample)
                .put("last_sample_elapsed_ms",lastSample).put("source_geometry",new JSONObject(actualRaw))
                .put("css_to_screen_mapping_used",false).put("proves_action_or_occlusion",false);
    }
    boolean same(WebNativeGeometry other){return other!=null&&fingerprint.equals(other.fingerprint);}
    boolean contains(int left,int top,int right,int bottom){
        return left<right&&top<bottom&&bounds[0]<=left&&bounds[1]<=top&&right<=bounds[2]&&bottom<=bounds[3];
    }
    static int[] rect(JSONArray value,boolean screen)throws Exception{
        long[] raw=integerArray(value,4);int[] out=new int[4];
        for(int i=0;i<4;i++){need(raw[i]>=-32768&&raw[i]<=32768,"bounded native rectangle");out[i]=(int)raw[i];}
        need(out[0]<out[2]&&out[1]<out[3]&&(!screen||out[0]>=0&&out[1]>=0),"nonempty native rectangle");
        return out;
    }
    private static long[] integerArray(JSONArray values,int length)throws Exception{
        need(values.length()==length,"integer array shape");long[] out=new long[length];
        for(int i=0;i<length;i++){Object value=values.get(i);need(value instanceof Integer||value instanceof Long,"actual integer array value");out[i]=((Number)value).longValue();}
        return out;
    }
    private static double[] numberArray(JSONArray values,int length)throws Exception{
        need(values.length()==length,"numeric array shape");double[] out=new double[length];
        for(int i=0;i<length;i++)out[i]=number(values.get(i));return out;
    }
    private static double number(Object value){need(value instanceof Number,"actual numeric value");double n=((Number)value).doubleValue();
        need(!Double.isNaN(n)&&!Double.isInfinite(n),"finite numeric value");return n;}
    private static long integer(JSONObject value,String key)throws Exception{
        Object raw=value.get(key);need(raw instanceof Integer||raw instanceof Long,"actual integer: "+key);return ((Number)raw).longValue();
    }
    private static String string(JSONObject value,String key)throws Exception{
        Object raw=value.get(key);need(raw instanceof String,"actual string: "+key);return (String)raw;
    }
    private static void keys(JSONObject value,String...expected){
        Set<String> found=new HashSet<String>();Iterator<String> it=value.keys();while(it.hasNext())found.add(it.next());
        need(found.equals(new HashSet<String>(Arrays.asList(expected))),"exact geometry fields");
    }
    private static String sha(String value)throws Exception{
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder out=new StringBuilder();for(byte b:digest)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
    }
    private static void need(boolean ok,String why){if(!ok)throw new IllegalArgumentException(why);}
}
