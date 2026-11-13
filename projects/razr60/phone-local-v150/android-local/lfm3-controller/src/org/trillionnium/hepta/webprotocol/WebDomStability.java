package org.trillionnium.hepta.webprotocol;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Wire-v4 comparison of two complete fixed-observer DOM strings.
 * A scoped result never claims whole-page equality or invisible outside paint.
 * The fixed Mi policy can admit only an unchanged complete search-card region;
 * all outside differences remain explicit, and only its actual anchor is eligible.
 */
public final class WebDomStability {
    public static final String DOM_SCHEMA="hepta.fixed-top-document-dom.v4";
    public static final String PROOF_SCHEMA="hepta.web-helper.dom-stability.v2";
    public static final String FULL_SCOPE="full_raw_equality";
    public static final String REGION_SCOPE="mi_public_search_card_region_v1";
    private static final int MAX_BYTES=1024*1024,MAX_NODES=1536,MAX_DIFFERENCES=128;
    private WebDomStability(){}
    public static final class Result {
        public final boolean rawEqual;
        public final String comparisonScope,beforeRawSha256,afterRawSha256;
        public final WebMiActionRegion region;
        private final String immutableProof;
        private final Set<String> actualPaths;
        private final boolean shopping;
        private Result(boolean equal,String scope,String before,String after,JSONObject proof,
                       Set<String> paths,boolean mi,WebMiActionRegion selected)throws Exception{
            rawEqual=equal;comparisonScope=scope;beforeRawSha256=before;afterRawSha256=after;
            immutableProof=WebDomCanonical.canonical(proof);
            actualPaths=Collections.unmodifiableSet(new LinkedHashSet<String>(paths));
            shopping=mi;region=selected;
        }
        public JSONObject evidence()throws Exception{return new JSONObject(immutableProof);}
        /** This predicate only narrows a domain's independently authorized action. */
        public boolean permitsActionTargetPath(String path){
            if(path==null||!actualPaths.contains(path))return false;
            if(shopping)return region!=null&&region.permitsActionTargetPath(path);
            return rawEqual;
        }
    }
    public static Result evaluate(String beforeRaw,String afterRaw,String sitePolicyId)throws Exception{
        need(beforeRaw!=null&&afterRaw!=null&&bytes(beforeRaw)<=MAX_BYTES&&bytes(afterRaw)<=MAX_BYTES,
                "complete bounded original DOM pair required");
        JSONObject before=new JSONObject(beforeRaw),after=new JSONObject(afterRaw);
        Map<String,JSONObject> bn=index(before),an=index(after);
        need(bn.keySet().equals(an.keySet()),"complete DOM membership changed");
        boolean rawEqual=beforeRaw.equals(afterRaw),shopping=WebMiActionRegion.POLICY.equals(sitePolicyId);
        WebMiActionRegion first=null,last=null;String unavailable=null;
        if(shopping&&WebSitePolicy.INITIAL_URL.equals(text(before,"href"))&&WebSitePolicy.INITIAL_URL.equals(text(after,"href"))){
            try{
                first=WebMiActionRegion.read(before,bn);last=WebMiActionRegion.read(after,an);
                need(first.sameRegion(last),"complete product card/ancestor/style/hit evidence changed");
                checkClipObservationCrossReferences(before);checkClipObservationCrossReferences(after);
            }catch(Exception invalid){
                if(!rawEqual)throw invalid;
                first=null;last=null;unavailable=String.valueOf(invalid.getMessage());
                if(unavailable.length()>512)unavailable=unavailable.substring(0,512);
            }
        }
        String scope=FULL_SCOPE;JSONArray outsideRectangles=new JSONArray();
        if(!rawEqual){
            need(shopping&&first!=null&&last!=null,"mismatch has no compiled stable action-region proof");
            need(WebDomCanonical.same(metadata(before),metadata(after)),"URL/viewport/ready/truncation metadata changed");
            need(WebDomCanonical.same(before.getJSONObject("action_region_observations"),after.getJSONObject("action_region_observations")),
                    "region observation or occlusion evidence changed");
            JSONArray br=before.getJSONArray("nodes"),ar=after.getJSONArray("nodes");
            need(br.length()==ar.length(),"complete DOM size changed");
            for(int i=0;i<br.length();i++){
                JSONObject x=br.getJSONObject(i),y=ar.getJSONObject(i);
                String path=text(x,"path");need(path.equals(text(y,"path")),"complete DOM array identity changed");
                if(WebDomCanonical.same(x,y))continue;
                need(!first.containsPath(path)&&!first.isAncestorPath(path),"card or ancestor changed");
                need(WebDomCanonical.same(without(x,"rect_css_pixels"),without(y,"rect_css_pixels")),
                        "outside semantic data changed; this initial region policy admits geometry only");
                double[] xr=rect(x.getJSONArray("rect_css_pixels")),yr=rect(y.getJSONArray("rect_css_pixels"));
                need(!first.overlaps(xr)&&!last.overlaps(yr),"outside changed rectangle intersects the selected region");
                need(outsideRectangles.length()<32,"too many outside geometry changes");
                outsideRectangles.put(new JSONObject().put("node_array_index",i).put("dom_path",path)
                        .put("before",new JSONArray(x.getJSONArray("rect_css_pixels").toString()))
                        .put("after",new JSONArray(y.getJSONArray("rect_css_pixels").toString()))
                        .put("outside_selected_region",true).put("fully_clipped_claimed",false));
            }
            need(outsideRectangles.length()>0,"raw mismatch has no explicit outside geometry difference");
            scope=REGION_SCOPE;
        }
        JSONArray differences=new JSONArray();diff(before,after,"",differences,0);
        need(rawEqual||differences.length()>0,"nonidentical raw serialization alone is not a region proof");
        String beforeHash=WebDomCanonical.sha256Utf8(beforeRaw),afterHash=WebDomCanonical.sha256Utf8(afterRaw);
        JSONArray eligiblePaths=new JSONArray();
        if(shopping){if(last!=null)eligiblePaths.put(last.anchorPath);}
        else if(rawEqual){for(String path:an.keySet())eligiblePaths.put(path);}
        String targetPredicate=shopping?"selected_region_anchor_only":"actual_dom_membership_for_full_raw";
        JSONObject proof=new JSONObject().put("schema",PROOF_SCHEMA).put("dom_schema",DOM_SCHEMA)
                .put("site_policy_id",sitePolicyId).put("comparison_scope",scope).put("raw_dom_equal",rawEqual)
                .put("before_dom_sha256",beforeHash).put("after_dom_sha256",afterHash)
                .put("before_dom_utf8_bytes",bytes(beforeRaw)).put("after_dom_utf8_bytes",bytes(afterRaw))
                .put("both_complete_raw_dom_values_retained",true).put("all_json_differences",differences)
                .put("all_difference_count",differences.length()).put("outside_changed_rectangles",outsideRectangles)
                .put("region",last==null?JSONObject.NULL:last.evidence())
                .put("region_unavailable_reason",unavailable==null?JSONObject.NULL:unavailable)
                .put("target_predicate",targetPredicate).put("eligible_action_dom_paths",eligiblePaths)
                .put("eligible_paths_are_not_independent_action_authority",true)
                .put("scope_selected_by_compiled_task_policy",true).put("caller_supplied_selector_allowed",false)
                .put("whole_page_raw_equal",rawEqual).put("outside_visibility_inferred",false)
                .put("closed_shadow_contents_inspected",false).put("whole_page_pixel_visibility_verified",false)
                .put("grants_action_authority",false).put("business_verified",false);
        need(bytes(WebDomCanonical.canonical(proof))<=256*1024,"bounded complete stability proof");
        return new Result(rawEqual,scope,beforeHash,afterHash,proof,an.keySet(),shopping,last);
    }
    public static Result verify(String before,String after,String policy,JSONObject claimed)throws Exception{
        Result result=evaluate(before,after,policy);
        need(claimed!=null&&WebDomCanonical.same(result.evidence(),claimed),"claimed scope differs from both original DOMs");
        return result;
    }
    public static Map<String,JSONObject> index(JSONObject dom)throws Exception{
        need(DOM_SCHEMA.equals(text(dom,"schema"))&&"complete".equals(text(dom,"ready_state"))
                &&Boolean.FALSE.equals(dom.get("truncated"))&&dom.getJSONArray("truncation_reasons").length()==0,
                "complete untruncated DOM-v4 required; legacy raw pairs cannot prove new region semantics");
        JSONArray rows=dom.getJSONArray("nodes");need(rows.length()>0&&rows.length()<=MAX_NODES,"bounded complete DOM");
        Map<String,JSONObject> nodes=new LinkedHashMap<String,JSONObject>();
        for(int i=0;i<rows.length();i++){
            JSONObject node=rows.getJSONObject(i);String path=text(node,"path");
            need(path.matches("0(?:/[0-9]{1,5}){0,32}")&&!nodes.containsKey(path),"unique bounded actual DOM path");
            String expected=parent(path);Object actual=node.get("parent_path");
            need(expected==null?actual==JSONObject.NULL:expected.equals(actual),"real DOM parent path required");
            for(String key:new String[]{"tag","id","name","role","aria_label","aria_hidden","aria_modal","aria_selected","aria_checked","aria_pressed","text","item_type","item_prop"})
                text(node,key);
            for(String key:new String[]{"visible_in_viewport","disabled","hidden_attr","inert_attr","item_scope","iframe_contents_read"})
                need(node.get(key) instanceof Boolean,"typed raw DOM boolean: "+key);
            need(Boolean.FALSE.equals(node.get("iframe_contents_read")),"independent frame content is outside this observer scope");
            for(String key:new String[]{"href_raw","href_resolved","link_target","value","aria_disabled"}){
                Object value=node.get(key);need(value==JSONObject.NULL||value instanceof String&&((String)value).length()<=4096,"bounded raw node scalar: "+key);
            }
            rect(node.getJSONArray("rect_css_pixels"));nodes.put(path,node);
        }
        for(String path:nodes.keySet())if(!"0".equals(path))need(nodes.containsKey(parent(path)),"complete DOM ancestry required");
        Object visited=dom.get("visited");need((visited instanceof Integer||visited instanceof Long)&&((Number)visited).longValue()==rows.length(),"visited/record counts differ");
        return Collections.unmodifiableMap(nodes);
    }
    private static JSONObject metadata(JSONObject dom)throws Exception{
        JSONObject value=new JSONObject(WebDomCanonical.canonical(dom));
        value.remove("nodes");value.remove("action_region_observations");value.remove("clipping_context_observations");return value;
    }
    private static JSONObject without(JSONObject value,String key)throws Exception{
        JSONObject copy=new JSONObject(WebDomCanonical.canonical(value));copy.remove(key);return copy;
    }
    /** Clip observations are retained as raw data; they grant no hidden-content exemption. */
    private static void checkClipObservationCrossReferences(JSONObject dom)throws Exception{
        JSONObject clip=dom.getJSONObject("clipping_context_observations");
        need("hepta.raw-clip-context-observations.v1".equals(text(clip,"schema"))
                &&Boolean.FALSE.equals(clip.get("fully_clipped_inferred"))
                &&Boolean.FALSE.equals(clip.get("closed_shadow_contents_inspected"))
                &&Boolean.FALSE.equals(clip.get("grants_action_authority"))&&clip.get("complete") instanceof Boolean,
                "raw clip observations must not assert invisible content or authority");
        JSONArray contexts=clip.getJSONArray("style_contexts"),region=dom.getJSONObject("action_region_observations").getJSONArray("style_contexts");
        need(contexts.length()<=128,"bounded raw clip observations");Map<String,JSONObject> originals=new LinkedHashMap<String,JSONObject>();
        for(int i=0;i<region.length();i++){JSONObject row=region.getJSONObject(i);originals.put(text(row,"path"),row);}
        Set<String> seen=new LinkedHashSet<String>();
        for(int i=0;i<contexts.length();i++){
            JSONObject row=contexts.getJSONObject(i);String path=text(row,"path");need(seen.add(path),"unique raw clip style path");
            if(originals.containsKey(path))need(WebDomCanonical.same(row,originals.get(path)),"shared ancestor CSS changed within the fixed observation");
        }
    }
    private static void diff(Object before,Object after,String pointer,JSONArray out,int depth)throws Exception{
        need(depth<=64,"bounded difference depth");if(WebDomCanonical.same(before,after))return;
        if(before instanceof JSONObject&&after instanceof JSONObject){
            JSONObject a=(JSONObject)before,b=(JSONObject)after;Set<String> keys=new java.util.TreeSet<String>();
            Iterator<String> it=a.keys();while(it.hasNext())keys.add(it.next());it=b.keys();while(it.hasNext())keys.add(it.next());
            for(String key:keys){
                String path=pointer+"/"+key.replace("~","~0").replace("/","~1");
                if(!a.has(key)||!b.has(key))addDifference(out,path,a.has(key)?a.get(key):JSONObject.NULL,b.has(key)?b.get(key):JSONObject.NULL,
                        !a.has(key)?"add":"remove");
                else diff(a.get(key),b.get(key),path,out,depth+1);
            }return;
        }
        if(before instanceof JSONArray&&after instanceof JSONArray){
            JSONArray a=(JSONArray)before,b=(JSONArray)after;int length=Math.max(a.length(),b.length());
            for(int i=0;i<length;i++){
                if(i>=a.length()||i>=b.length())addDifference(out,pointer+"/"+i,i<a.length()?a.get(i):JSONObject.NULL,i<b.length()?b.get(i):JSONObject.NULL,
                        i>=a.length()?"add":"remove");
                else diff(a.get(i),b.get(i),pointer+"/"+i,out,depth+1);
            }return;
        }
        addDifference(out,pointer,before,after,"replace");
    }
    private static void addDifference(JSONArray out,String pointer,Object before,Object after,String operation)throws Exception{
        need(out.length()<MAX_DIFFERENCES,"complete JSON difference list exceeds bounded policy");
        need(bytes(WebDomCanonical.canonical(before))<=16384&&bytes(WebDomCanonical.canonical(after))<=16384,"individual raw difference exceeds bounded policy");
        out.put(new JSONObject().put("json_pointer",pointer).put("operation",operation)
                .put("before",before==null?JSONObject.NULL:before).put("after",after==null?JSONObject.NULL:after));
    }
    public static double[] rect(JSONArray array)throws Exception{
        need(array.length()==4,"four observed rectangle coordinates");double[] out=new double[4];
        for(int i=0;i<4;i++){Object value=array.get(i);need(value instanceof Number,"numeric observed rectangle");
            out[i]=((Number)value).doubleValue();need(Double.isFinite(out[i])&&Math.abs(out[i])<=100000000,"finite bounded rectangle");}
        need(out[2]>=out[0]&&out[3]>=out[1],"ordered observed rectangle");return out;
    }
    private static String text(JSONObject object,String key)throws Exception{
        Object value=object.get(key);need(value instanceof String&&((String)value).length()<=4096,"bounded raw string: "+key);return (String)value;
    }
    private static String parent(String path){int i=path.lastIndexOf('/');return i<0?null:path.substring(0,i);}
    private static int bytes(String raw){return raw.getBytes(StandardCharsets.UTF_8).length;}
    private static void need(boolean value,String message){if(!value)throw new IllegalArgumentException(message);}
}
