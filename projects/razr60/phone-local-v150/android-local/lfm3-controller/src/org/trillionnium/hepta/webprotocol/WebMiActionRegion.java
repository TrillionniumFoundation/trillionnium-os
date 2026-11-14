package org.trillionnium.hepta.webprotocol;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * One fixed, observed mainland-Mi search-card region. This is not a selector
 * supplied by a webpage/model, a detail-price result, or transaction authority.
 * Native AX identity/window/lease and native dispatch remain independent gates.
 */
public final class WebMiActionRegion {
    public static final String OBS_SCHEMA="hepta.mi-search-card-observations.v1";
    public static final String SCHEMA="hepta.mi-public-search-card-region.v1";
    public static final String SELECTION="fixed_AX3000T_white_observed_link_parent_card_v1";
    public static final String POLICY="mi_cn_ax3000t_read_v2";
    private static final String TITLE="Xiaomi路由器AX3000T 白色";
    private static final Pattern PRICE=Pattern.compile("^(?:0|[1-9][0-9]{0,7})(?:\\.[0-9]{1,2})?元$");
    private static final Pattern CONDITION=Pattern.compile("券|会员|补贴|定金|分期|每月|月供|预售|预约|满减|到手|折后|需登录|需领|秒杀|限时|首购|加入购物车|立即购买|下单|支付");
    public final String rootPath,anchorPath,modelPath,currentPricePath,comparisonPricePath;
    public final String hrefRaw,hrefResolved,linkTarget,modelLabel,observedVariant;
    public final String currentPriceRaw,comparisonPriceRaw,currentAmountDecimal,comparisonAmountDecimal;
    public final String fullRegionSha256,ancestorSha256,observationsSha256;
    private final String immutableEvidence;
    private final Set<String> regionPaths,ancestorPaths;
    private final double[] regionRect;
    private WebMiActionRegion(JSONObject candidate,JSONArray region,JSONArray ancestors,JSONObject observations,
                              Set<String> regionSet,Set<String> ancestorSet,double[] bounds)throws Exception{
        rootPath=text(candidate,"root_path");anchorPath=text(candidate,"anchor_path");modelPath=text(candidate,"model_path");
        currentPricePath=text(candidate,"current_price_path");comparisonPricePath=text(candidate,"comparison_price_path");
        hrefRaw=text(candidate,"href_raw");hrefResolved=text(candidate,"href_resolved");linkTarget=text(candidate,"link_target");
        modelLabel=text(candidate,"model_label");observedVariant=text(candidate,"observed_variant");
        currentPriceRaw=text(candidate,"current_price_raw");comparisonPriceRaw=text(candidate,"comparison_price_raw");
        currentAmountDecimal=amount(currentPriceRaw);comparisonAmountDecimal=amount(comparisonPriceRaw);
        fullRegionSha256=WebDomCanonical.sha256(region);ancestorSha256=WebDomCanonical.sha256(ancestors);
        observationsSha256=WebDomCanonical.sha256(observations);
        regionPaths=Collections.unmodifiableSet(new LinkedHashSet<String>(regionSet));
        ancestorPaths=Collections.unmodifiableSet(new LinkedHashSet<String>(ancestorSet));regionRect=bounds.clone();
        JSONObject evidence=new JSONObject().put("schema",SCHEMA).put("selection",SELECTION).put("site_policy_id",POLICY)
                .put("candidate",new JSONObject(WebDomCanonical.canonical(candidate)))
                .put("full_region_node_count",region.length()).put("full_region_sha256",fullRegionSha256)
                .put("ancestor_node_count",ancestors.length()).put("ancestor_sha256",ancestorSha256)
                .put("observations_sha256",observationsSha256).put("region_rect_css_pixels",new JSONArray(bounds))
                .put("observed_current_price_amount",currentAmountDecimal)
                .put("observed_comparison_price_amount",comparisonAmountDecimal).put("observed_currency","CNY")
                .put("current_price_context","search_card_only").put("comparison_price_context","del_descendant")
                .put("observed_top_document_hit_clear",true).put("top_document_rect_overlap_check",true)
                .put("native_ax_identity_verified",false).put("native_dispatch_verified",false)
                .put("closed_shadow_contents_inspected",false).put("whole_page_pixel_visibility_verified",false)
                .put("fully_unoccluded_claimed",false).put("detail_price_verified",false)
                .put("grants_action_authority",false).put("business_verified",false);
        immutableEvidence=WebDomCanonical.canonical(evidence);
    }
    public JSONObject evidence()throws Exception{return new JSONObject(immutableEvidence);}
    public boolean containsPath(String path){return regionPaths.contains(path);}
    public boolean isAncestorPath(String path){return ancestorPaths.contains(path);}
    /** Only the actual anchor is an action target, never a cart or region ancestor. */
    public boolean permitsActionTargetPath(String path){return anchorPath.equals(path)&&regionPaths.contains(path);}
    public boolean overlaps(double[] rect){return overlap(regionRect,rect);}
    public boolean sameRegion(WebMiActionRegion other)throws Exception{
        return other!=null&&immutableEvidence.equals(other.immutableEvidence);
    }
    public static WebMiActionRegion read(JSONObject dom)throws Exception{return read(dom,WebDomStability.index(dom));}
    static WebMiActionRegion read(JSONObject dom,Map<String,JSONObject> nodes)throws Exception{
        need(WebSitePolicy.INITIAL_URL.equals(text(dom,"href"))&&WebSitePolicy.ORIGIN.equals(text(dom,"origin")),
                "fixed observed Mi public search page required");
        JSONObject observations=dom.getJSONObject("action_region_observations");
        need(OBS_SCHEMA.equals(text(observations,"schema"))&&POLICY.equals(text(observations,"site_policy_id"))
                &&SELECTION.equals(text(observations,"selection"))&&"observed".equals(text(observations,"status"))
                &&integer(observations,"candidate_count")==1&&bool(observations,"complete")
                &&!bool(observations,"coordinates_used_for_input")&&!bool(observations,"closed_shadow_contents_inspected")
                &&!bool(observations,"pixel_visibility_claimed"),"complete fixed read-only region observations required");
        List<JSONObject> candidates=new ArrayList<JSONObject>();WebSitePolicy policy=WebSitePolicy.forExplicitDiagnostic();
        for(JSONObject anchor:nodes.values()){
            if(!"a".equals(text(anchor,"tag"))||!visible(anchor))continue;
            String path=text(anchor,"path"),parent=parent(path);
            if(parent==null||!nodes.containsKey(parent)||!"div".equals(text(nodes.get(parent),"tag")))continue;
            String raw=nullable(anchor,"href_raw"),resolved=nullable(anchor,"href_resolved"),target=nullable(anchor,"link_target");
            if(policy.observedProductLink(WebSitePolicy.INITIAL_URL,raw,resolved,target)==null)continue;
            List<JSONObject> models=new ArrayList<JSONObject>(),current=new ArrayList<JSONObject>(),comparison=new ArrayList<JSONObject>();
            int links=0,count=0;boolean forbidden=false;
            for(JSONObject node:nodes.values()){
                String npath=text(node,"path");if(!inside(parent,npath))continue;
                count++;String tag=text(node,"tag");
                if("a".equals(tag))links++;
                if(oneOf(tag,"button","input","select","textarea","iframe","frame","object","embed","canvas","video","svg")
                        ||"button".equals(text(node,"role"))||"dialog".equals(text(node,"role"))||"true".equals(text(node,"aria_modal")))forbidden=true;
                if(!visible(node))continue;
                String label=text(node,"text");
                if(CONDITION.matcher(label).find())forbidden=true;
                if(inside(path,npath)&&"h2".equals(tag)&&TITLE.equals(label))models.add(node);
                if(inside(path,npath)&&"span".equals(tag)&&PRICE.matcher(label.trim()).matches())
                    (underDeleted(npath,path,nodes)?comparison:current).add(node);
            }
            if(forbidden||count<4||count>64||links!=1||models.size()!=1||current.size()!=1||comparison.size()!=1)continue;
            candidates.add(new JSONObject().put("root_path",parent).put("anchor_path",path).put("model_path",text(models.get(0),"path"))
                    .put("current_price_path",text(current.get(0),"path")).put("comparison_price_path",text(comparison.get(0),"path"))
                    .put("model_label",TITLE).put("observed_variant","白色").put("href_raw",raw).put("href_resolved",resolved)
                    .put("link_target",target).put("current_price_raw",text(current.get(0),"text"))
                    .put("comparison_price_raw",text(comparison.get(0),"text")).put("price_context","search_card_only")
                    .put("detail_price_verified",false));
        }
        need(candidates.size()==1&&WebDomCanonical.same(candidates.get(0),observations.getJSONObject("candidate")),
                "unique complete fixed product card must independently match the observer");
        JSONObject candidate=candidates.get(0);String root=text(candidate,"root_path"),anchor=text(candidate,"anchor_path");
        JSONObject rootNode=nodes.get(root);double[] bounds=WebDomStability.rect(rootNode.getJSONArray("rect_css_pixels"));
        need(visible(rootNode)&&WebDomCanonical.same(rootNode.getJSONArray("rect_css_pixels"),nodes.get(anchor).getJSONArray("rect_css_pixels")),
                "observed complete card and its sole anchor rectangle must coincide");
        JSONArray viewport=dom.getJSONArray("viewport_css_pixels");need(viewport.length()==2,"actual viewport required");
        double width=number(viewport.get(0)),height=number(viewport.get(1));
        need(bounds[2]>bounds[0]&&bounds[3]>bounds[1]&&bounds[0]>=0&&bounds[1]>=0&&bounds[2]<=width&&bounds[3]<=height,
                "complete current card must be inside the observed CSS viewport");
        Set<String> regionSet=new LinkedHashSet<String>(),ancestorSet=new LinkedHashSet<String>();
        JSONArray region=new JSONArray(),ancestors=new JSONArray();
        List<String> foreign=new ArrayList<String>(),modals=new ArrayList<String>(),special=new ArrayList<String>();
        for(JSONObject node:nodes.values()){
            String path=text(node,"path");boolean member=inside(root,path),ancestor=!member&&inside(path,root);
            if(member){regionSet.add(path);region.put(node);}
            if(ancestor){ancestorSet.add(path);ancestors.put(node);}
            if((member||ancestor)&&(bool(node,"hidden_attr")||bool(node,"inert_attr")||bool(node,"disabled")
                    ||"true".equals(text(node,"aria_hidden"))))throw new IllegalArgumentException("region or ancestor explicitly hidden/inert/disabled");
            if(!visible(node))continue;
            if(oneOf(text(node,"tag"),"dialog")||oneOf(text(node,"role"),"dialog","alertdialog")||"true".equals(text(node,"aria_modal")))modals.add(path);
            if(overlap(bounds,WebDomStability.rect(node.getJSONArray("rect_css_pixels")))){
                if(!member&&!ancestor)foreign.add(path);
                if(member&&oneOf(text(node,"tag"),"iframe","frame","object","embed","canvas","video","svg"))special.add(path);
            }
        }
        need(equalList(foreign,observations.getJSONArray("foreign_overlap_paths"))&&foreign.isEmpty()
                &&equalList(modals,observations.getJSONArray("visible_modal_paths"))&&modals.isEmpty()
                &&equalList(special,observations.getJSONArray("special_paint_in_region_paths"))&&special.isEmpty(),
                "observed foreign overlap/modal/special paint blocks the action region");
        JSONObject top=observations.getJSONObject("top_layer");
        need(bool(top,"selector_api_available")&&top.getJSONArray("modal_paths").length()==0
                &&top.getJSONArray("popover_paths").length()==0&&!bool(top,"fullscreen_present")
                &&top.get("fullscreen_path")==JSONObject.NULL&&!bool(top,"closed_shadow_contents_inspected"),
                "observed top-layer activity or incomplete selector support blocks the region");
        Map<String,JSONObject> styles=new LinkedHashMap<String,JSONObject>();
        JSONArray contexts=observations.getJSONArray("style_contexts");need(contexts.length()<=128,"bounded region CSS context");
        Set<String> expected=new LinkedHashSet<String>(ancestorSet);expected.addAll(regionSet);
        for(int i=0;i<contexts.length();i++){
            JSONObject style=contexts.getJSONObject(i);String path=text(style,"path");
            need(expected.contains(path)&&!styles.containsKey(path),"unique real region CSS path");
            for(String key:new String[]{"position","display","visibility","opacity","overflow_x","overflow_y","overflow_clip_margin",
                    "transform","translate","rotate","scale","transform_style","zoom","perspective","filter","backdrop_filter",
                    "clip_path","mask_image","contain","content_visibility","will_change","pointer_events","isolation","mix_blend_mode"})text(style,key);
            need(!bool(style,"accessible_shadow_root_present")&&!bool(style,"closed_shadow_contents_inspected"),
                    "open shadow context is outside this top-document region schema");
            need(integer(style,"element_child_count")>=0,"observed element children required");
            // A hit can remain clickable under an opacity-zero ancestor. Read
            // all observed region/ancestor styles; hit testing is not paint proof.
            need(!"none".equals(text(style,"display"))&&"visible".equals(text(style,"visibility"))
                    &&finiteText(text(style,"opacity"))==1d&&"visible".equals(text(style,"content_visibility"))
                    &&"none".equals(text(style,"filter"))&&"none".equals(text(style,"backdrop_filter"))
                    &&"none".equals(text(style,"clip_path"))&&"none".equals(text(style,"mask_image"))
                    &&"normal".equals(text(style,"mix_blend_mode")),
                    "observed region/ancestor visibility or unsupported paint effect blocks reading");
            rejectObservedPseudoOverlay(style.getJSONObject("pseudo_before"));
            rejectObservedPseudoOverlay(style.getJSONObject("pseudo_after"));
            styles.put(path,style);
        }
        need(styles.keySet().equals(expected),"all region nodes and real ancestors require CSS observations");
        for(String p:new String[]{root,anchor,text(candidate,"model_path"),text(candidate,"current_price_path"),text(candidate,"comparison_price_path")}){
            JSONObject style=styles.get(p);
            need(visible(nodes.get(p))&&!"none".equals(text(style,"display"))&&"visible".equals(text(style,"visibility"))
                    &&finiteText(text(style,"opacity"))>0&&"visible".equals(text(style,"content_visibility")),
                    "actual label/anchor display state is not readable");
        }
        JSONArray tests=observations.getJSONArray("hit_tests");
        List<String> testPaths=Arrays.asList(anchor,text(candidate,"model_path"),text(candidate,"current_price_path"),text(candidate,"comparison_price_path"));
        need(tests.length()==testPaths.size(),"all fixed region hit observations required");
        double[][] ratios={{.5,.5},{.2,.2},{.8,.2},{.2,.8},{.8,.8}};
        for(int i=0;i<tests.length();i++){
            JSONObject test=tests.getJSONObject(i);String path=testPaths.get(i);
            need(path.equals(text(test,"dom_path"))&&WebDomCanonical.same(test.getJSONArray("rect_css_pixels"),nodes.get(path).getJSONArray("rect_css_pixels")),
                    "hit observation must bind the actual node rectangle");
            double[] r=WebDomStability.rect(test.getJSONArray("rect_css_pixels"));
            need(r[0]>=bounds[0]&&r[1]>=bounds[1]&&r[2]<=bounds[2]&&r[3]<=bounds[3]&&r[2]>r[0]&&r[3]>r[1],"fixed readable point rectangle inside card");
            JSONArray points=test.getJSONArray("points");need(points.length()==ratios.length,"all fixed hit points required");
            for(int j=0;j<ratios.length;j++){
                JSONObject point=points.getJSONObject(j);double x=number(point.get("x")),y=number(point.get("y"));
                need(Math.abs(x-(r[0]+(r[2]-r[0])*ratios[j][0]))<=0.000001
                        &&Math.abs(y-(r[1]+(r[3]-r[1])*ratios[j][1]))<=0.000001,"observed hit coordinates must be derived from fixed CSS test points");
                String hit=text(point,"top_path");JSONArray stack=point.getJSONArray("stack_paths");
                need(nodes.containsKey(hit)&&inside(anchor,hit)&&bool(point,"stack_complete")
                        &&stack.length()>0&&stack.length()<=64&&hit.equals(stack.get(0)),"actual top-document hit is absent, retargeted or obstructed");
                for(int k=0;k<stack.length();k++)need(stack.get(k) instanceof String&&nodes.containsKey(stack.getString(k)),"complete real DOM hit-stack paths");
            }
        }
        return new WebMiActionRegion(candidate,region,ancestors,observations,regionSet,ancestorSet,bounds);
    }
    private static void rejectObservedPseudoOverlay(JSONObject pseudo)throws Exception{
        String content=text(pseudo,"content"),display=text(pseudo,"display"),visibility=text(pseudo,"visibility");
        String position=text(pseudo,"position"),transform=text(pseudo,"transform");text(pseudo,"pointer_events");
        double opacity=finiteText(text(pseudo,"opacity"));
        boolean generated=!"none".equals(content)&&!"normal".equals(content)&&!"none".equals(display)
                &&!"hidden".equals(visibility)&&!"collapse".equals(visibility)&&opacity>0;
        need(!generated||(!oneOf(position,"absolute","fixed","sticky")&&"none".equals(transform)),
                "observed positioned/transformed generated content makes region occlusion unknown");
    }
    private static boolean underDeleted(String path,String stop,Map<String,JSONObject> nodes)throws Exception{
        for(String p=path;p!=null&&!p.equals(stop);p=parent(p))if("del".equals(text(nodes.get(p),"tag")))return true;return false;
    }
    private static boolean visible(JSONObject node)throws Exception{
        return node!=null&&bool(node,"visible_in_viewport")&&!bool(node,"hidden_attr")&&!bool(node,"inert_attr")
                &&!bool(node,"disabled")&&!"true".equals(text(node,"aria_hidden"));
    }
    private static boolean equalList(List<String> list,JSONArray actual)throws Exception{
        if(list.size()!=actual.length())return false;for(int i=0;i<list.size();i++)if(!list.get(i).equals(actual.get(i)))return false;return true;
    }
    private static String amount(String raw){String s=raw.trim();need(PRICE.matcher(s).matches(),"explicit CNY search-card amount required");return new BigDecimal(s.substring(0,s.length()-1)).stripTrailingZeros().toPlainString();}
    private static boolean inside(String root,String path){return path.equals(root)||path.startsWith(root+"/");}
    private static boolean overlap(double[] a,double[] b){return Math.max(a[0],b[0])<Math.min(a[2],b[2])&&Math.max(a[1],b[1])<Math.min(a[3],b[3]);}
    private static String parent(String path){int p=path.lastIndexOf('/');return p<0?null:path.substring(0,p);}
    private static boolean oneOf(String value,String... options){for(String option:options)if(option.equals(value))return true;return false;}
    private static String nullable(JSONObject object,String key)throws Exception{Object value=object.get(key);return value==JSONObject.NULL?null:text(object,key);}
    private static String text(JSONObject object,String key)throws Exception{
        Object value=object.get(key);need(value instanceof String&&((String)value).length()<=4096,"bounded raw string: "+key);return (String)value;
    }
    private static boolean bool(JSONObject object,String key)throws Exception{Object value=object.get(key);need(value instanceof Boolean,"typed boolean: "+key);return (Boolean)value;}
    private static long integer(JSONObject object,String key)throws Exception{Object value=object.get(key);need(value instanceof Integer||value instanceof Long,"integer: "+key);return ((Number)value).longValue();}
    private static double number(Object value){need(value instanceof Number,"observed number required");double n=((Number)value).doubleValue();need(Double.isFinite(n)&&Math.abs(n)<=9007199254740991d,"finite observed number required");return n;}
    private static double finiteText(String text){double value=Double.parseDouble(text);need(Double.isFinite(value),"finite CSS scalar");return value;}
    private static void need(boolean value,String message){if(!value)throw new IllegalArgumentException(message);}
}
